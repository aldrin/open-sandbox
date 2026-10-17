//! open-sandbox: Launch OpenCode against OpenRouter in a sandboxed
//! Apple container VM.
//!
//! External commands used:
//! - container --version
//! - container image inspect <image>
//! - container build -t <image> -f <containerfile> <context>
//! - container run --rm -it --cap-add <cap> -e <env> -m <memory> -c <cpus>
//!   -v <volume> [--mount type=bind,...,readonly] <image> <command>
//! - container network list
//! - container system dns list -q
//! - security find-generic-password -s <service> -w

use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Duration;

const SANDBOX_DIR: &str = ".open-sandbox";
const IMAGE_NAME_FILE: &str = "image-name";
const IMAGE_PREFIX: &str = "open-sandbox";
const DEFAULT_KEYCHAIN_SERVICE: &str = "openrouter-api-key";
const CONTAINER_CODE_DIR: &str = "/home/agent/code";
const KEY_ENV_VAR: &str = "OPENROUTER_API_KEY";
const TAVILY_ENV_VAR: &str = "TAVILY_API_KEY";
const TAVILY_KEYCHAIN_SERVICE: &str = "tavily-api-key";
const COLORTERM_ENV_VAR: &str = "COLORTERM";
const REQUIRED_CAP: &str = "CAP_NET_ADMIN";
const MLX_HOST: &str = "host.container.internal";
const HINT_RUN_INIT: &str = "Run 'open-sandbox init' first to initialize the workspace.";

const ASSETS: &[(&str, &str)] = &[
    ("Containerfile", include_str!("assets/Containerfile")),
    ("entrypoint.sh", include_str!("assets/entrypoint.sh")),
    ("egress-proxy.py", include_str!("assets/egress-proxy.py")),
    ("allowlist.txt", include_str!("assets/allowlist.txt")),
    ("opencode.json", include_str!("assets/opencode.json")),
    ("AGENTS.md", include_str!("assets/AGENTS.md")),
    ("cli.json", include_str!("assets/cli.json")),
    (
        "sandbox-checks.py",
        include_str!("assets/sandbox-checks.py"),
    ),
    ("sandbox-tools.py", include_str!("assets/sandbox-tools.py")),
    (
        "commands/verify.md",
        include_str!("assets/commands/verify.md"),
    ),
    (
        "commands/commit.md",
        include_str!("assets/commands/commit.md"),
    ),
];

/// Assets that enforce the security boundary itself.
///
/// Unlike the Containerfile and the allowlist, these are not meant to be
/// customized. A workspace copy that differs from the embedded one is a
/// workspace scaffolded by an older binary, and a hardening fix in a newer
/// binary would never reach the image: `build` copies the stale file and says
/// nothing. `build` refuses in that case, because a silently-old entrypoint is
/// exactly how the capability drop was lost once already.
const REQUIRED_ASSETS: &[&str] = &["entrypoint.sh", "egress-proxy.py"];

const USAGE: &str = "\
Launch OpenCode against OpenRouter in a sandboxed Apple container VM.

Usage: open-sandbox <COMMAND>

Commands:
  init    Initialize workspace with default Containerfile
  build   Build the sandbox container image
  run     Run OpenCode in the container
  status  Check workspace files, keys, container infrastructure, and the host model route
  help    Print this message

Options:
  -h, --help     Print help
  -V, --version  Print version

init options:
      --force                 Overwrite existing files in .open-sandbox/
      --name <NAME>           Container image name (default: open-sandbox-<dirname>)

run options:
      --cpus <N>              Number of CPUs, 2-8 (default: 2)
      --memory <N>            Memory in GB, 2-8 (default: 4)
      -- <ARGS>...            Pass the remaining arguments to OpenCode. Switch
                              models in-session with '/models'.
";

// ── Logging ─────────────────────────────────────────────────────────────────

fn debug_enabled() -> bool {
    matches!(
        env::var("OPEN_SANDBOX_DEBUG").as_deref(),
        Ok("1") | Ok("true")
    )
}

macro_rules! info {
    ($($arg:tt)*) => { eprintln!("INFO {}", format_args!($($arg)*)) };
}

macro_rules! debug {
    ($($arg:tt)*) => {
        if crate::debug_enabled() {
            eprintln!("DEBUG {}", format_args!($($arg)*))
        }
    };
}

// ── Command line ────────────────────────────────────────────────────────────

#[derive(Debug, PartialEq)]
enum Cmd {
    Init {
        force: bool,
        name: Option<String>,
    },
    Build,
    Run {
        cpus: u8,
        memory: u8,
        extra: Vec<String>,
    },
    Status,
    Help,
    Version,
}

/// Split `--flag=value` into two tokens so both spellings parse the same way.
/// Everything after a bare `--` is passed through untouched.
fn normalize(args: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(args.len());
    let mut passthrough = false;
    for arg in args {
        if passthrough {
            out.push(arg.clone());
            continue;
        }
        if arg == "--" {
            passthrough = true;
            out.push(arg.clone());
        } else if arg.starts_with("--") && arg.contains('=') {
            let (flag, value) = arg.split_once('=').expect("checked for '='");
            out.push(flag.to_string());
            out.push(value.to_string());
        } else {
            out.push(arg.clone());
        }
    }
    out
}

fn value_for(flag: &str, args: &[String], i: &mut usize) -> Result<String, String> {
    *i += 1;
    args.get(*i)
        .cloned()
        .ok_or_else(|| format!("{flag} requires a value"))
}

fn resource(flag: &str, raw: &str) -> Result<u8, String> {
    let n: u8 = raw
        .parse()
        .map_err(|_| format!("{flag} expects a number, got '{raw}'"))?;
    if !(2..=8).contains(&n) {
        return Err(format!("{flag} must be between 2 and 8, got {n}"));
    }
    Ok(n)
}

fn parse(args: &[String]) -> Result<Cmd, String> {
    let args = normalize(args);
    let Some(first) = args.first() else {
        return Ok(Cmd::Help);
    };

    match first.as_str() {
        "-h" | "--help" | "help" => return Ok(Cmd::Help),
        "-V" | "--version" => return Ok(Cmd::Version),
        _ => {}
    }

    let rest = &args[1..];
    match first.as_str() {
        "init" => {
            let mut force = false;
            let mut name = None;
            let mut i = 0;
            while i < rest.len() {
                match rest[i].as_str() {
                    "--force" => force = true,
                    "--name" => name = Some(value_for("--name", rest, &mut i)?),
                    "--keychain-service" => {
                        return Err("--keychain-service was removed; the OpenRouter key is \
                                    read from 'openrouter-api-key'."
                            .to_string())
                    }
                    other => return Err(format!("unexpected argument '{other}' for init")),
                }
                i += 1;
            }
            Ok(Cmd::Init { force, name })
        }

        "build" => match rest.first() {
            None => Ok(Cmd::Build),
            Some(other) => Err(format!("unexpected argument '{other}' for build")),
        },

        "status" => match rest.first() {
            None => Ok(Cmd::Status),
            Some(other) => Err(format!("unexpected argument '{other}' for status")),
        },

        "run" => {
            let mut cpus = 2u8;
            let mut memory = 4u8;
            let mut extra = Vec::new();
            let mut i = 0;
            while i < rest.len() {
                match rest[i].as_str() {
                    "--" => {
                        extra = rest[i + 1..].to_vec();
                        break;
                    }
                    "--model" => {
                        return Err("--model is no longer a run option; use '/models' to \
                                    switch models once OpenCode starts."
                            .to_string())
                    }
                    "--cpus" => cpus = resource("--cpus", &value_for("--cpus", rest, &mut i)?)?,
                    "--memory" => {
                        memory = resource("--memory", &value_for("--memory", rest, &mut i)?)?
                    }
                    other => return Err(format!("unexpected argument '{other}' for run")),
                }
                i += 1;
            }
            Ok(Cmd::Run {
                cpus,
                memory,
                extra,
            })
        }

        other => Err(format!("unknown command '{other}'\n\n{USAGE}")),
    }
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    match dispatch(&args) {
        Ok(code) => std::process::exit(code),
        Err(message) => {
            eprintln!("error: {message}");
            std::process::exit(1);
        }
    }
}

fn dispatch(args: &[String]) -> Result<i32, String> {
    match parse(args)? {
        Cmd::Help => {
            print!("{USAGE}");
            Ok(0)
        }
        Cmd::Version => {
            println!("open-sandbox {}", env!("CARGO_PKG_VERSION"));
            Ok(0)
        }
        Cmd::Init { force, name } => cmd_init(force, name.as_deref()).map(|_| 0),
        Cmd::Build => cmd_build().map(|_| 0),
        Cmd::Run {
            cpus,
            memory,
            extra,
        } => cmd_run(cpus, memory, &extra).map(|_| 0),
        Cmd::Status => cmd_status(),
    }
}

// ── Commands ────────────────────────────────────────────────────────────────

fn cmd_init(force: bool, name: Option<&str>) -> Result<(), String> {
    let cwd = current_dir()?;
    let sandbox_dir = cwd.join(SANDBOX_DIR);

    let image = match name {
        Some(n) => check_image_name(n)?.to_string(),
        None => default_image_name(&cwd)?,
    };

    init_sandbox(&sandbox_dir, force, &image)?;

    info!("Initialized workspace in {SANDBOX_DIR}/ (image: {image})");
    Ok(())
}

fn init_sandbox(sandbox_dir: &Path, force: bool, image: &str) -> Result<(), String> {
    if !force && sandbox_dir.join("Containerfile").exists() {
        return Err(format!(
            "{SANDBOX_DIR} already initialized. Use --force to overwrite."
        ));
    }

    write_file(&sandbox_dir.join(IMAGE_NAME_FILE), &format!("{image}\n"))?;

    for (name, content) in ASSETS {
        write_file(&sandbox_dir.join(name), content)?;
    }
    Ok(())
}

fn cmd_build() -> Result<(), String> {
    check_container_available()?;

    let sandbox_dir = current_dir()?.join(SANDBOX_DIR);
    let image = read_image(&sandbox_dir)?;

    let containerfile = sandbox_dir.join("Containerfile");
    if !containerfile.exists() {
        return Err(format!(
            "{SANDBOX_DIR}/Containerfile not found.\n{HINT_RUN_INIT}"
        ));
    }

    let missing = missing_assets(&sandbox_dir);
    if !missing.is_empty() {
        return Err(format!(
            "Missing from {SANDBOX_DIR}/: {}\n\n\
             This binary ships assets the workspace does not have. The Containerfile\n\
             copies them, so the build would fail without explaining why.\n\
             Run 'open-sandbox init --force' to update the workspace.",
            missing.join(", ")
        ));
    }

    let stale = stale_required_assets(&sandbox_dir);
    if !stale.is_empty() {
        return Err(format!(
            "Outdated in {SANDBOX_DIR}/: {}\n\n\
             These files enforce the sandbox boundary and differ from the copies in\n\
             this binary. Building would bake the old versions into the image, so a\n\
             hardening fix could go missing with nothing to show for it. The\n\
             Containerfile and allowlist are excluded: those are meant to be edited.\n\
             Run 'open-sandbox init --force' to update the workspace.",
            stale.join(", ")
        ));
    }

    info!("Building image '{image}'...");

    let status = Command::new("container")
        .args([
            "build",
            "-t",
            &image,
            "-f",
            path_str(&containerfile)?,
            path_str(&sandbox_dir)?,
        ])
        .status()
        .map_err(|e| format!("failed to execute 'container': {e}"))?;

    if !status.success() {
        return Err(format!("container build failed for '{image}'"));
    }

    info!("Image '{image}' built successfully");
    Ok(())
}

fn cmd_run(cpus: u8, memory: u8, extra: &[String]) -> Result<(), String> {
    check_container_available()?;

    let cwd = current_dir()?;
    let sandbox_dir = cwd.join(SANDBOX_DIR);
    let image = read_image(&sandbox_dir)?;
    let service = DEFAULT_KEYCHAIN_SERVICE;
    check_image_built(&image)?;

    let key = read_keychain_key(service)?;
    if !key.starts_with("sk-or-") {
        info!(
            "The value in keychain service '{service}' does not look like an OpenRouter key \
             (expected an 'sk-or-' prefix). Passing it through anyway."
        );
    }

    // Tavily is optional, so a missing key logs a hint rather than failing
    // the launch.
    let tavily = keychain_key(TAVILY_KEYCHAIN_SERVICE);
    if tavily.is_none() {
        info!(
            "No Tavily key in keychain service '{TAVILY_KEYCHAIN_SERVICE}'; web search will be \
             unavailable. Store one with:\n  \
             security add-generic-password -a \"$USER\" -s {TAVILY_KEYCHAIN_SERVICE} -w"
        );
    }

    let mut command = opencode_command();
    command.extend_from_slice(extra);

    // Forward the host terminal's truecolor capability, so OpenCode's theme
    // renders full syntax highlighting instead of falling back to 256 colors.
    // Absent is fine: the container keeps its own TERM as the fallback.
    let colorterm = env::var(COLORTERM_ENV_VAR).unwrap_or_default();

    // Git creates .git/hooks, but not every tool that makes a repository does.
    // Creating it here means there is always something to mount read-only.
    if cwd.join(".git").is_dir() {
        let hooks = cwd.join(".git/hooks");
        fs::create_dir_all(&hooks)
            .map_err(|e| format!("failed to create {}: {e}", hooks.display()))?;
        // The --mount spec is comma-separated, and has no escaping.
        if path_str(&cwd)?.contains(',') {
            return Err(format!(
                "the project path contains a comma, which 'container run --mount' cannot \
                 express: {}",
                cwd.display()
            ));
        }
    }

    let args = run_args(&cwd, &image, cpus, memory, &command);
    debug!("exec: container {} (keys passed via env)", args.join(" "));

    let error = Command::new("container")
        .args(&args)
        .env(KEY_ENV_VAR, key)
        .env(TAVILY_ENV_VAR, tavily.unwrap_or_default())
        .env(COLORTERM_ENV_VAR, colorterm)
        .exec();

    Err(format!("failed to exec 'container run': {error}"))
}

fn cmd_status() -> Result<i32, String> {
    let sandbox_dir = current_dir()?.join(SANDBOX_DIR);
    let image = read_image(&sandbox_dir);
    let mut report = Report::new();

    report.section("Workspace");
    if sandbox_dir.join("Containerfile").exists() {
        report.pass("Containerfile", "present");
    } else {
        report.fail("Containerfile", HINT_RUN_INIT);
    }
    for (name, embedded) in ASSETS {
        match fs::read_to_string(sandbox_dir.join(name)) {
            Ok(ref content) if content == embedded => report.pass(name, "matches"),
            Ok(_) => report.warn(name, "differs from the embedded asset"),
            Err(_) => report.fail(name, "missing"),
        }
    }
    match &image {
        Ok(value) => report.pass(IMAGE_NAME_FILE, value.as_str()),
        Err(error) => report.fail(IMAGE_NAME_FILE, first_line(error)),
    }

    report.section("Host");
    if cfg!(target_os = "macos") {
        report.pass("platform", format!("macOS {}", std::env::consts::ARCH));
    } else {
        report.fail(
            "platform",
            format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
        );
    }
    let container_ok = output_quiet("container", &["--version"])
        .map(|out| out.status.success())
        .unwrap_or(false);
    if container_ok {
        report.pass("container CLI", "found");
    } else {
        report.fail("container CLI", "not found");
    }
    if container_ok {
        match output_quiet("container", &["system", "status"]) {
            Some(out) => {
                let text = format!(
                    "{}{}",
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                );
                let lower = text.to_lowercase();
                if out.status.success()
                    && lower.contains("running")
                    && !lower.contains("not running")
                {
                    report.pass("container system", first_line(&text));
                } else {
                    report.warn("container system", first_line(&text));
                }
            }
            None => report.warn(
                "container system",
                "could not run 'container system status'",
            ),
        }
    }

    report.section("Keys");
    match keychain_key(DEFAULT_KEYCHAIN_SERVICE) {
        Some(key) if key.starts_with("sk-or-") => {
            report.pass(DEFAULT_KEYCHAIN_SERVICE, "present")
        }
        Some(_) => report.warn(
            DEFAULT_KEYCHAIN_SERVICE,
            "present but does not look like an OpenRouter key",
        ),
        None => report.fail(
            DEFAULT_KEYCHAIN_SERVICE,
            format!(
                "missing; store it with 'security add-generic-password -a \"$USER\" -s {DEFAULT_KEYCHAIN_SERVICE} -w'"
            ),
        ),
    }
    match keychain_key(TAVILY_KEYCHAIN_SERVICE) {
        Some(_) => report.pass(TAVILY_KEYCHAIN_SERVICE, "present"),
        None => report.warn(
            TAVILY_KEYCHAIN_SERVICE,
            "missing; web search will be unavailable",
        ),
    }

    report.section("Image");
    match &image {
        Ok(image) => {
            let built = output_quiet("container", &["image", "inspect", image.as_str()])
                .map(|out| out.status.success())
                .unwrap_or(false);
            if built {
                report.pass("image", image.as_str());
            } else {
                report.fail(
                    "image",
                    format!("'{image}' not built; run 'open-sandbox build'"),
                );
            }
        }
        Err(_) => report.warn("image", "skipped; image-name is missing"),
    }

    report.section("Route");
    let allowlist = fs::read_to_string(sandbox_dir.join("allowlist.txt")).ok();
    match &allowlist {
        Some(content) => {
            let entries: Vec<&str> = content
                .lines()
                .map(|line| line.split('#').next().unwrap_or("").trim())
                .filter(|line| !line.is_empty())
                .collect();
            for host in ["openrouter.ai", "models.dev"] {
                if entries.contains(&host) {
                    report.pass(host, "allowlisted");
                } else {
                    report.fail(host, "missing from allowlist");
                }
            }
            if entries.contains(&"mcp.tavily.com") {
                report.pass("mcp.tavily.com", "allowlisted");
            } else {
                report.warn("mcp.tavily.com", "missing from allowlist");
            }
        }
        None => report.fail("allowlist.txt", "missing"),
    }

    let port = match host_service_port(&sandbox_dir) {
        Ok(port) => port,
        Err(error) => {
            report.fail("host service", error);
            None
        }
    };
    if let Some(port) = port {
        report.pass("host service", format!("{MLX_HOST}:{port}"));
        match fs::read_to_string(sandbox_dir.join("opencode.json")) {
            Ok(config) => {
                let expected = format!("http://{MLX_HOST}:{port}/v1");
                if config.contains(&expected) {
                    report.pass("mlx baseURL", expected.as_str());
                } else {
                    report.fail("mlx baseURL", format!("expected {expected}"));
                }
                if config.contains("aisdk:@ai-sdk/openai-compatible") {
                    report.pass("mlx package", "openai-compatible");
                } else {
                    report.warn("mlx package", "expected aisdk:@ai-sdk/openai-compatible");
                }
                if external_directory_denied(&config) {
                    report.pass("external_directory", "denied");
                } else {
                    report.fail("external_directory", "deny rule missing");
                }
            }
            Err(_) => report.fail("opencode.json", "missing"),
        }
    } else if allowlist.is_some() {
        report.warn(
            "host service",
            format!("no {MLX_HOST}:<port> entry; local model route is off"),
        );
    }

    report.section("Host integration");
    let gateway = if container_ok {
        container_gateway()
    } else {
        None
    };
    match gateway {
        Some(address) => report.pass(
            "container network",
            format!("the Mac is {address}; the container maps {MLX_HOST} to it"),
        ),
        None if container_ok => report.warn(
            "container network",
            "could not read the default network; run 'container system start'",
        ),
        None => report.warn("container network", "skipped; container CLI not found"),
    }
    // Older setups reached the host through a --localhost DNS domain, whose
    // packet-filter rule turns off iCloud Private Relay. It is not needed now.
    if container_ok {
        if let Some(out) = output_quiet("container", &["system", "dns", "list", "-q"]) {
            let text = String::from_utf8_lossy(&out.stdout);
            if out.status.success() && text.lines().any(|line| line.trim() == MLX_HOST) {
                report.warn(
                    MLX_HOST,
                    format!(
                        "DNS domain is no longer needed and turns off iCloud Private Relay; \
                         remove it with 'sudo container system dns rm {MLX_HOST}'"
                    ),
                );
            }
        }
    }

    report.section("Local model");
    match (port, gateway) {
        (Some(port), Some(address)) => {
            match probe_http(
                address,
                MLX_HOST,
                port,
                "/v1/models",
                Duration::from_secs(3),
            ) {
                Ok(200) => report.pass(
                    "endpoint",
                    format!("{address}:{port}/v1/models returned 200"),
                ),
                Ok(code) => report.warn(
                    "endpoint",
                    format!("{address}:{port}/v1/models returned {code}"),
                ),
                Err(error) => report.warn("endpoint", format!("{address}:{port}: {error}")),
            }
        }
        (Some(_), None) => report.warn("endpoint", "skipped; container network address unknown"),
        (None, _) => report.warn("endpoint", "skipped; no host service port"),
    }

    println!(
        "\n{} passed, {} warnings, {} failed",
        report.passed, report.warnings, report.failed
    );
    Ok(if report.failed > 0 { 1 } else { 0 })
}

struct Report {
    passed: usize,
    warnings: usize,
    failed: usize,
}

impl Report {
    fn new() -> Self {
        Self {
            passed: 0,
            warnings: 0,
            failed: 0,
        }
    }

    fn section(&self, title: &str) {
        println!("\n{title}");
    }

    fn pass(&mut self, label: &str, detail: impl AsRef<str>) {
        self.passed += 1;
        print_report("PASS", label, detail.as_ref());
    }

    fn warn(&mut self, label: &str, detail: impl AsRef<str>) {
        self.warnings += 1;
        print_report("WARN", label, detail.as_ref());
    }

    fn fail(&mut self, label: &str, detail: impl AsRef<str>) {
        self.failed += 1;
        print_report("FAIL", label, detail.as_ref());
    }
}

fn print_report(tag: &str, label: &str, detail: &str) {
    if detail.is_empty() {
        println!("  {tag}  {label}");
    } else {
        println!("  {tag}  {label}  {detail}");
    }
}

fn first_line(text: &str) -> String {
    text.lines().next().unwrap_or("").trim().to_string()
}

/// True when a permission rule pairs the `external_directory` action with a
/// `deny` effect. The two must sit in the same rule object, so a deny
/// elsewhere in the file cannot satisfy this check.
fn external_directory_denied(config: &str) -> bool {
    let mut rest = config;
    while let Some(pos) = rest.find("\"external_directory\"") {
        let after = &rest[pos..];
        let Some(close) = after.find('}') else {
            return false;
        };
        if after[..=close].contains("\"deny\"") {
            return true;
        }
        rest = &after[close + 1..];
    }
    false
}

fn host_service_port(sandbox_dir: &Path) -> Result<Option<u16>, String> {
    let path = sandbox_dir.join("allowlist.txt");
    let content = fs::read_to_string(&path)
        .map_err(|error| format!("could not read {}: {error}", path.display()))?;
    let prefix = format!("{MLX_HOST}:");
    let mut ports = Vec::new();
    for line in content.lines() {
        let entry = line
            .split('#')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if let Some(rest) = entry.strip_prefix(&prefix) {
            let port: u16 = rest
                .parse()
                .map_err(|_| format!("invalid host service entry: {entry}"))?;
            ports.push(port);
        }
    }
    ports.sort_unstable();
    ports.dedup();
    match ports.as_slice() {
        [] => Ok(None),
        [port] => Ok(Some(*port)),
        _ => Err(format!("multiple {MLX_HOST} ports in the allowlist")),
    }
}

/// The Mac's address on the default container network, which containers use
/// as their default gateway. vmnet gives the host the first address in the
/// subnet, for example 192.168.64.1 in 192.168.64.0/24.
fn container_gateway() -> Option<Ipv4Addr> {
    let out = output_quiet("container", &["network", "list"])?;
    if !out.status.success() {
        return None;
    }
    gateway_from_network_list(&String::from_utf8_lossy(&out.stdout))
}

/// The first host address of the `default` row's subnet in
/// `container network list` output.
fn gateway_from_network_list(text: &str) -> Option<Ipv4Addr> {
    let row = text
        .lines()
        .find(|line| line.split_whitespace().next() == Some("default"))?;
    row.split_whitespace().find_map(|field| {
        let (address, prefix) = field.split_once('/')?;
        let address: Ipv4Addr = address.parse().ok()?;
        let prefix: u32 = prefix.parse().ok()?;
        if prefix > 30 {
            return None;
        }
        let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
        Some(Ipv4Addr::from((u32::from(address) & mask) + 1))
    })
}

/// GET `path` from the model server at `address` and return the status code.
/// `status` runs on the host, where the server listens on the container
/// network address; `host_header` is only the name sent in the Host header,
/// matching what the container uses.
fn probe_http(
    address: Ipv4Addr,
    host_header: &str,
    port: u16,
    path: &str,
    timeout: Duration,
) -> Result<u16, String> {
    let addr = SocketAddr::from((address, port));
    let mut stream =
        TcpStream::connect_timeout(&addr, timeout).map_err(|error| format!("connect: {error}"))?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|error| error.to_string())?;
    write!(
        stream,
        "GET {path} HTTP/1.0\r\nHost: {host_header}:{port}\r\n\r\n"
    )
    .map_err(|error| format!("write: {error}"))?;
    let mut buffer = [0u8; 1024];
    let read = stream
        .read(&mut buffer)
        .map_err(|error| format!("read: {error}"))?;
    let response = String::from_utf8_lossy(&buffer[..read]);
    let status = response.lines().next().unwrap_or("");
    status
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| format!("unexpected response: {status:?}"))
}

// ── Agent invocation ────────────────────────────────────────────────────────

/// The command line the container runs. Callers append OpenCode flags after
/// this prefix when arguments are passed through `--`.
///
/// OpenCode v2 normally starts a shared background server, which persists
/// `service.json` inside the root-owned, read-only config directory and fails
/// there with EACCES. Standalone mode keeps everything in the single process
/// that the container already isolates, and needs no write to the config dir.
fn opencode_command() -> Vec<String> {
    vec!["opencode".to_string(), "--standalone".to_string()]
}

fn run_args(cwd: &Path, image: &str, cpus: u8, memory: u8, command: &[String]) -> Vec<String> {
    let mut args = vec![
        "run".to_string(),
        "--rm".to_string(),
        "-it".to_string(),
        // The entrypoint needs CAP_NET_ADMIN to install the nftables ruleset;
        // without it `nft` fails with EPERM on netlink and the entrypoint
        // refuses to run. The capability belongs to the entrypoint alone: it
        // is spent before any agent code runs, and the privilege drop clears
        // it from every set, so the agent never holds it.
        "--cap-add".to_string(),
        REQUIRED_CAP.to_string(),
        "-e".to_string(),
        KEY_ENV_VAR.to_string(),
        "-e".to_string(),
        TAVILY_ENV_VAR.to_string(),
        "-e".to_string(),
        COLORTERM_ENV_VAR.to_string(),
        "-m".to_string(),
        format!("{memory}G"),
        "-c".to_string(),
        cpus.to_string(),
        "-v".to_string(),
        format!("{}:{CONTAINER_CODE_DIR}", cwd.display()),
    ];
    // Git hooks run on the host the next time the user runs git there, so the
    // agent gets the project's hooks read-only. A project without a .git
    // directory (or with a gitfile pointing elsewhere) has nothing to cover.
    let hooks = cwd.join(".git/hooks");
    if hooks.is_dir() {
        args.push("--mount".to_string());
        args.push(format!(
            "type=bind,source={},target={CONTAINER_CODE_DIR}/.git/hooks,readonly",
            hooks.display()
        ));
    }
    args.push(image.to_string());
    args.extend_from_slice(command);
    args
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn current_dir() -> Result<PathBuf, String> {
    env::current_dir().map_err(|e| format!("failed to get current directory: {e}"))
}

fn path_str(path: &Path) -> Result<&str, String> {
    path.to_str()
        .ok_or_else(|| format!("path is not valid UTF-8: {}", path.display()))
}

fn write_file(path: &Path, content: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create {}: {e}", parent.display()))?;
    }
    fs::write(path, content).map_err(|e| format!("failed to write {}: {e}", path.display()))
}

fn default_image_name(cwd: &Path) -> Result<String, String> {
    let dir_name = cwd
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("failed to determine project directory name")?;
    let sanitized: String = dir_name
        .to_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect();
    Ok(format!("{IMAGE_PREFIX}-{sanitized}"))
}

/// Read a one-line setting file from the workspace.
fn read_setting(sandbox_dir: &Path, name: &str) -> Result<String, String> {
    let path = sandbox_dir.join(name);
    let content = fs::read_to_string(&path)
        .map_err(|_| format!("{SANDBOX_DIR}/{name} not found.\n{HINT_RUN_INIT}"))?;
    let value = content.trim().to_string();
    if value.is_empty() {
        return Err(format!("{SANDBOX_DIR}/{name} is empty"));
    }
    Ok(value)
}

/// The image name from the workspace, checked before it reaches `container`.
///
/// The file is in the mounted project, so it is checked rather than trusted:
/// a stray value could start with '-' and be read as a flag.
fn read_image(sandbox_dir: &Path) -> Result<String, String> {
    let image = read_setting(sandbox_dir, IMAGE_NAME_FILE)?;
    check_image_name(&image)?;
    Ok(image)
}

fn check_image_name(name: &str) -> Result<&str, String> {
    let mut chars = name.chars();
    let valid = chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || "._/:-".contains(c));
    if valid {
        Ok(name)
    } else {
        Err(format!(
            "invalid image name '{name}': expected letters, digits, and . _ / : -, \
             starting with a letter or digit"
        ))
    }
}

/// Embedded assets that the workspace does not have on disk.
///
/// Only absence matters. Editing a scaffolded file is expected — the
/// Containerfile and the allowlist are meant to be customized — but a binary
/// upgrade can add an asset the Containerfile copies, and a workspace
/// scaffolded by an older binary has nothing at that path.
fn missing_assets(sandbox_dir: &Path) -> Vec<&'static str> {
    ASSETS
        .iter()
        .map(|(name, _)| *name)
        .filter(|name| !sandbox_dir.join(name).exists())
        .collect()
}

/// Security-critical assets whose on-disk copy differs from the embedded one.
///
/// Only REQUIRED_ASSETS are considered: the Containerfile and allowlist are
/// deliberately customizable, so a difference there is expected. Absence is not
/// reported here — `missing_assets` owns that — so a file that cannot be read
/// is left to the missing check rather than double-reported.
fn stale_required_assets(sandbox_dir: &Path) -> Vec<&'static str> {
    ASSETS
        .iter()
        .filter(|(name, _)| REQUIRED_ASSETS.contains(name))
        .filter(|(name, embedded)| {
            fs::read_to_string(sandbox_dir.join(name))
                .map(|content| content != *embedded)
                .unwrap_or(false)
        })
        .map(|(name, _)| *name)
        .collect()
}

fn output_quiet(program: &str, args: &[&str]) -> Option<Output> {
    Command::new(program).args(args).output().ok()
}

fn check_container_available() -> Result<(), String> {
    debug!("checking container CLI availability");
    if output_quiet("container", &["--version"]).is_none() {
        return Err("Apple container CLI not found.\n\n\
             Install it from: https://github.com/apple/container"
            .to_string());
    }
    Ok(())
}

fn check_image_built(image: &str) -> Result<(), String> {
    debug!("checking image '{image}' exists locally");
    let exists = output_quiet("container", &["image", "inspect", image])
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !exists {
        return Err(format!(
            "Image '{image}' not found locally.\n\n\
             Run 'open-sandbox build' to build it first."
        ));
    }
    Ok(())
}

fn keychain_key(service: &str) -> Option<String> {
    debug!("reading keychain service: {service}");
    output_quiet("security", &["find-generic-password", "-s", service, "-w"])
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
}

fn read_keychain_key(service: &str) -> Result<String, String> {
    keychain_key(service).ok_or_else(|| {
        format!(
            "No OpenRouter API key found in keychain service '{service}'.\n\n\
             Store one with:\n  \
             security add-generic-password -a \"$USER\" -s {service} -w"
        )
    })
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    /// A unique directory under the system temp dir, removed on drop.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> TempDir {
            let n = COUNTER.fetch_add(1, Ordering::SeqCst);
            let path =
                env::temp_dir().join(format!("open-sandbox-test-{}-{n}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).expect("create temp dir");
            TempDir(path)
        }

        fn sandbox(&self) -> PathBuf {
            self.0.join(SANDBOX_DIR)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    fn init(dir: &TempDir) -> PathBuf {
        let sandbox = dir.sandbox();
        init_sandbox(&sandbox, false, "open-sandbox-test").unwrap();
        sandbox
    }

    // ── init ────────────────────────────────────────────────────────

    #[test]
    fn init_creates_every_asset() {
        let dir = TempDir::new();
        let sandbox = init(&dir);
        for (name, _) in ASSETS {
            assert!(sandbox.join(name).exists(), "{name} missing after init");
        }
    }

    #[test]
    fn init_writes_settings_files() {
        let dir = TempDir::new();
        let sandbox = init(&dir);
        assert_eq!(
            read_setting(&sandbox, IMAGE_NAME_FILE).unwrap(),
            "open-sandbox-test"
        );
    }

    #[test]
    fn init_honours_custom_names() {
        let dir = TempDir::new();
        let sandbox = dir.sandbox();
        init_sandbox(&sandbox, false, "my-image").unwrap();
        assert_eq!(read_setting(&sandbox, IMAGE_NAME_FILE).unwrap(), "my-image");
    }

    #[test]
    fn init_refuses_if_already_initialized() {
        let dir = TempDir::new();
        init(&dir);
        assert!(init_sandbox(&dir.sandbox(), false, "x").is_err());
    }

    #[test]
    fn init_force_overwrites() {
        let dir = TempDir::new();
        let sandbox = init(&dir);
        fs::write(sandbox.join("Containerfile"), b"modified").unwrap();
        init_sandbox(&sandbox, true, "open-sandbox-test").unwrap();
        assert_eq!(
            fs::read_to_string(sandbox.join("Containerfile")).unwrap(),
            include_str!("assets/Containerfile")
        );
    }

    #[test]
    fn assets_match_after_init() {
        let dir = TempDir::new();
        let sandbox = init(&dir);
        for (name, embedded) in ASSETS {
            let content = fs::read_to_string(sandbox.join(name)).unwrap();
            assert_eq!(&content, embedded, "{name} differs after init");
        }
    }

    /// A workspace scaffolded by an older binary lacks newer assets; the
    /// Containerfile copies them, so `build` must say so before failing.
    #[test]
    fn missing_assets_detects_absent_file() {
        let dir = TempDir::new();
        let sandbox = init(&dir);
        assert!(missing_assets(&sandbox).is_empty());
        fs::remove_file(sandbox.join("egress-proxy.py")).unwrap();
        fs::remove_file(sandbox.join("commands/verify.md")).unwrap();
        assert_eq!(
            missing_assets(&sandbox),
            vec!["egress-proxy.py", "commands/verify.md"]
        );
    }

    /// Customizing a scaffolded file is expected and must not be reported.
    #[test]
    fn missing_assets_ignores_modification() {
        let dir = TempDir::new();
        let sandbox = init(&dir);
        fs::write(sandbox.join("allowlist.txt"), "example.com\n").unwrap();
        assert!(missing_assets(&sandbox).is_empty());
    }

    /// A hardened entrypoint in a newer binary must not be shadowed by a stale
    /// workspace copy, so a changed security asset blocks `build`.
    #[test]
    fn stale_required_assets_flags_outdated_boundary_files() {
        let dir = TempDir::new();
        let sandbox = init(&dir);
        assert!(stale_required_assets(&sandbox).is_empty());
        fs::write(sandbox.join("entrypoint.sh"), "#!/bin/bash\n").unwrap();
        fs::write(sandbox.join("egress-proxy.py"), "# old\n").unwrap();
        assert_eq!(
            stale_required_assets(&sandbox),
            vec!["entrypoint.sh", "egress-proxy.py"]
        );
    }

    /// The Containerfile and allowlist are meant to be customized; changing
    /// them must not block `build`.
    #[test]
    fn stale_required_assets_ignores_customizable_files() {
        let dir = TempDir::new();
        let sandbox = init(&dir);
        fs::write(sandbox.join("Containerfile"), "FROM scratch\n").unwrap();
        fs::write(sandbox.join("allowlist.txt"), "example.com\n").unwrap();
        assert!(stale_required_assets(&sandbox).is_empty());
    }

    /// Only boundary files are guarded, and a missing file is the missing
    /// check's concern, not this one.
    #[test]
    fn stale_required_assets_skips_absent_files() {
        let dir = TempDir::new();
        let sandbox = init(&dir);
        fs::remove_file(sandbox.join("entrypoint.sh")).unwrap();
        assert!(stale_required_assets(&sandbox).is_empty());
    }

    #[test]
    fn read_setting_reports_missing_and_empty() {
        let dir = TempDir::new();
        assert!(read_setting(&dir.0, IMAGE_NAME_FILE).is_err());
        fs::write(dir.0.join(IMAGE_NAME_FILE), "   \n").unwrap();
        assert!(read_setting(&dir.0, IMAGE_NAME_FILE).is_err());
    }

    // ── image naming ────────────────────────────────────────────────

    #[test]
    fn image_names_are_checked() {
        for good in ["open-sandbox-x", "registry.local:5000/team/img:v1.2"] {
            assert!(check_image_name(good).is_ok(), "{good}");
        }
        for bad in ["", "-it", "--rm", "img name", "img;rm", ".hidden"] {
            assert!(check_image_name(bad).is_err(), "{bad:?}");
        }
        let dir = TempDir::new();
        let sandbox = init(&dir);
        fs::write(sandbox.join(IMAGE_NAME_FILE), "--privileged\n").unwrap();
        assert!(read_image(&sandbox).is_err());
    }

    #[test]
    fn default_image_name_uses_directory() {
        assert_eq!(
            default_image_name(Path::new("/Users/me/my-project")).unwrap(),
            "open-sandbox-my-project"
        );
    }

    #[test]
    fn default_image_name_sanitizes() {
        assert_eq!(
            default_image_name(Path::new("/Users/me/My Project_v2")).unwrap(),
            "open-sandbox-my-project-v2"
        );
    }

    // ── opencode command ────────────────────────────────────────────

    /// The CLI no longer interprets model ids; OpenCode arguments, including
    /// `--model`, are passed through after `--`. OpenCode runs standalone
    /// because its shared background service tries to write service.json into
    /// the read-only config directory.
    #[test]
    fn opencode_command_runs_standalone() {
        assert_eq!(opencode_command(), vec!["opencode", "--standalone"]);
    }

    // ── run arguments ───────────────────────────────────────────────

    #[test]
    fn run_args_default() {
        let command = opencode_command();
        assert_eq!(
            run_args(
                Path::new("/Users/me/project"),
                "open-sandbox-project",
                2,
                4,
                &command
            ),
            args(&[
                "run",
                "--rm",
                "-it",
                "--cap-add",
                "CAP_NET_ADMIN",
                "-e",
                "OPENROUTER_API_KEY",
                "-e",
                "TAVILY_API_KEY",
                "-e",
                "COLORTERM",
                "-m",
                "4G",
                "-c",
                "2",
                "-v",
                "/Users/me/project:/home/agent/code",
                "open-sandbox-project",
                "opencode",
                "--standalone",
            ])
        );
    }

    #[test]
    fn run_args_custom_resources() {
        let a = run_args(Path::new("/tmp/test"), "img", 8, 6, &[]);
        let m = a.iter().position(|x| x == "-m").unwrap();
        let c = a.iter().position(|x| x == "-c").unwrap();
        assert_eq!(a[m + 1], "6G");
        assert_eq!(a[c + 1], "8");
    }

    #[test]
    fn run_args_mounts_the_project_at_the_container_path() {
        let a = run_args(Path::new("/Users/me/my project"), "img", 2, 4, &[]);
        let v = a.iter().position(|x| x == "-v").unwrap();
        assert_eq!(a[v + 1], "/Users/me/my project:/home/agent/code");
    }

    /// Without CAP_NET_ADMIN the entrypoint cannot install the nftables
    /// ruleset, so it fails closed and the container never starts. The grant
    /// has to survive any future edit to run_args.
    #[test]
    fn run_args_grant_the_capability_the_firewall_needs() {
        let a = run_args(Path::new("/tmp"), "img", 2, 4, &[]);
        let i = a.iter().position(|x| x == "--cap-add").expect("--cap-add");
        assert_eq!(a[i + 1], "CAP_NET_ADMIN");
        // It has to be a flag to 'container run', not an argument to OpenCode.
        assert!(i < a.iter().position(|x| x == "img").unwrap());
    }

    /// The key reaches the container through the environment, never the
    /// command line, so it cannot show up in a process listing.
    #[test]
    fn run_args_never_contain_the_key() {
        let a = run_args(Path::new("/tmp"), "img", 2, 4, &opencode_command());
        let e = a.iter().position(|x| x == "-e").unwrap();
        assert_eq!(a[e + 1], "OPENROUTER_API_KEY");
        assert_eq!(a[e + 3], "TAVILY_API_KEY");
        assert!(!a.iter().any(|x| x.starts_with("sk-or-")));
        assert!(!a.iter().any(|x| x.starts_with("tvly-")));
    }

    /// The host terminal's truecolor capability is forwarded as a variable
    /// name, so OpenCode renders full syntax highlighting when the host
    /// supports it while the image's own TERM stays the fallback.
    #[test]
    fn run_args_forward_terminal_color_capability() {
        let a = run_args(Path::new("/tmp"), "img", 2, 4, &[]);
        let e = a.iter().position(|x| x == "-e").unwrap();
        assert_eq!(a[e + 5], "COLORTERM");
        // Only the variable name may appear in argv, never a color value.
        assert!(!a
            .iter()
            .any(|x| x.contains("truecolor") || x.contains("256")));
    }

    #[test]
    fn run_args_put_the_command_after_the_image() {
        let command = opencode_command();
        let a = run_args(Path::new("/tmp"), "my-image", 2, 4, &command);
        let i = a.iter().position(|x| x == "my-image").unwrap();
        assert_eq!(&a[i + 1..], command.as_slice());
    }

    // ── argument parsing ────────────────────────────────────────────

    #[test]
    fn parse_defaults_to_help() {
        assert_eq!(parse(&[]).unwrap(), Cmd::Help);
        assert_eq!(parse(&args(&["--help"])).unwrap(), Cmd::Help);
        assert_eq!(parse(&args(&["-V"])).unwrap(), Cmd::Version);
    }

    #[test]
    fn parse_init_flags() {
        assert_eq!(
            parse(&args(&["init", "--force", "--name", "x"])).unwrap(),
            Cmd::Init {
                force: true,
                name: Some("x".into()),
            }
        );
    }

    #[test]
    fn parse_accepts_equals_form() {
        assert_eq!(
            parse(&args(&["init", "--name=x"])).unwrap(),
            Cmd::Init {
                force: false,
                name: Some("x".into()),
            }
        );
    }

    #[test]
    fn parse_run_flags() {
        assert_eq!(
            parse(&args(&["run", "--cpus", "4", "--memory", "8"])).unwrap(),
            Cmd::Run {
                cpus: 4,
                memory: 8,
                extra: vec![],
            }
        );
    }

    #[test]
    fn parse_run_passthrough_after_double_dash() {
        // Everything after '--' is handed to OpenCode rather than consumed on
        // the way past, including a model flag the sandbox no longer owns.
        let Cmd::Run { extra, .. } =
            parse(&args(&["run", "--", "--continue", "--model", "x"])).unwrap()
        else {
            panic!("expected a run command");
        };
        assert_eq!(extra, args(&["--continue", "--model", "x"]));
    }

    #[test]
    fn parse_rejects_bad_input() {
        assert!(parse(&args(&["run", "--model", "m"])).is_err());
        assert!(parse(&args(&["run", "--cpus", "1"])).is_err());
        assert!(parse(&args(&["run", "--cpus", "9"])).is_err());
        assert!(parse(&args(&["run", "--cpus"])).is_err());
        assert!(parse(&args(&["run", "--nope"])).is_err());
        assert!(parse(&args(&["init", "--keychain-service", "x"])).is_err());
        assert!(parse(&args(&["build", "extra"])).is_err());
        assert!(parse(&args(&["frobnicate"])).is_err());
    }

    // ── assets ──────────────────────────────────────────────────────

    /// Every file the Containerfile copies has to exist in ASSETS, or the
    /// build fails at COPY time with nothing explaining why.
    #[test]
    fn containerfile_only_copies_embedded_assets() {
        let containerfile = include_str!("assets/Containerfile");
        for line in containerfile.lines() {
            let line = line.trim();
            let Some(rest) = line.strip_prefix("COPY ") else {
                continue;
            };
            let source = rest.split_whitespace().next().unwrap();
            // A trailing slash is a directory copy, so it is covered as long as
            // some asset lives under it.
            let covered = match source.strip_suffix('/') {
                Some(dir) => ASSETS
                    .iter()
                    .any(|(name, _)| name.starts_with(&format!("{dir}/"))),
                None => ASSETS.iter().any(|(name, _)| *name == source),
            };
            assert!(
                covered,
                "Containerfile copies '{source}', which is not in ASSETS"
            );
        }
    }

    /// The entrypoint and the checks agree on where the proxy listens.
    #[test]
    fn proxy_port_is_consistent_across_assets() {
        assert!(include_str!("assets/entrypoint.sh").contains("PROXY_PORT=3128"));
        assert!(include_str!("assets/egress-proxy.py").contains("\"3128\""));
        assert!(include_str!("assets/sandbox-checks.py").contains("PROXY_PORT = 3128"));
    }

    /// OpenCode's config has to stay strict JSON, because sandbox-tools.py
    /// parses it with json.load — the schema permits JSONC comments but the
    /// verify script would fail on them. OpenRouter has to be the default
    /// provider, since the allowlist reaches no other hosted provider's API. A
    /// default model is pinned to DeepSeek Flash Latest, and the built-in title
    /// agent uses the same model because OpenCode's default lives on OpenCode
    /// Zen, which is neither enabled nor reachable. The two DeepSeek aliases
    /// are declared as catalog entries; the local model carries explicit limits
    /// because it is not in models.dev. Any OpenRouter model stays selectable
    /// mid-session with /models, and OpenCode flags pass through after `--`.
    #[test]
    fn opencode_config_pins_openrouter_defaults() {
        let config = include_str!("assets/opencode.json");
        // The only legitimate "//" in the file is inside the https:// schema
        // URL, so anything left over is a comment — including a trailing one,
        // which a line-leading check would miss.
        assert!(
            !config.replace("://", "").contains("//"),
            "opencode.json must stay comment-free for json.load in sandbox-tools.py"
        );
        assert!(config.contains("\"enabled_providers\""));
        assert!(config.contains("\"openrouter\""));
        assert!(
            config.contains("\"model\": \"openrouter/"),
            "the default model must be an OpenRouter model"
        );
        assert!(config.contains("\"agents\"") && config.contains("\"title\""));
        assert!(
            config.contains("\"model\": \"openrouter/~deepseek/deepseek-flash-latest\""),
            "the title agent must use the reachable OpenRouter Flash model"
        );
        assert!(
            config.contains("~deepseek/deepseek-flash-latest")
                && config.contains("~deepseek/deepseek-pro-latest"),
            "both DeepSeek aliases must be configured"
        );
        assert!(
            config.contains("\"limit\""),
            "the host model needs explicit limits; it is absent from models.dev"
        );
        assert!(
            config.contains(
                "\"apiKey\": \"{file:/home/agent/.local/share/opencode/openrouter-key}\""
            ),
            "the OpenRouter key must come from a file, not the environment"
        );
    }

    /// The CLI theme is pinned through cli.json, which is strict JSON and must
    /// use the v2 settings schema and name a shipped theme (unknown names
    /// silently fall back to the default).
    #[test]
    fn cli_json_pins_a_builtin_theme() {
        let cli = include_str!("assets/cli.json");
        assert!(
            !cli.replace("://", "").contains("//"),
            "cli.json must stay comment-free"
        );
        assert!(cli.contains("https://opencode.ai/v2/cli.json"));
        assert!(cli.contains("\"name\": \"vercel\""));
        assert!(cli.contains("\"mode\": \"dark\""));
    }

    /// The Mac-host model is a separate, explicitly enabled provider. Its
    /// model key stays `default_model`, so mlx_lm.server maps it to whatever
    /// checkpoint it was started with. Its `think` variant turns reasoning on
    /// for a request, over a server that runs with it off.
    #[test]
    fn opencode_config_exposes_the_host_model() {
        let config = include_str!("assets/opencode.json");
        assert!(config.contains("\"providers\""));
        assert!(config.contains("\"mlx\""));
        assert!(config.contains("\"default_model\""));
        assert!(config.contains("http://host.container.internal:27182/v1"));
        assert!(config.contains("aisdk:@ai-sdk/openai-compatible"));
        assert!(config.contains("\"limit\""));
        assert!(config.contains("\"id\": \"think\""));
        assert!(config.contains("\"chat_template_kwargs\": { \"enable_thinking\": true }"));
    }

    /// The allowlist is the whole egress policy; OpenRouter has to be on it.
    #[test]
    fn allowlist_permits_openrouter() {
        let allowlist = include_str!("assets/allowlist.txt");
        let active: Vec<&str> = allowlist
            .lines()
            .map(|l| l.split('#').next().unwrap().trim())
            .filter(|l| !l.is_empty())
            .collect();
        assert!(active.contains(&"openrouter.ai"));
        assert!(active.contains(&"models.dev"));
        assert!(active.contains(&"registry.npmjs.org"));
        assert!(active.contains(&"nodejs.org"));
    }

    /// A host:port entry is how the proxy distinguishes the local model server
    /// from ordinary internet traffic; it is the only place a non-public
    /// address is allowed.
    #[test]
    fn allowlist_permits_the_local_host_service() {
        let allowlist = include_str!("assets/allowlist.txt");
        let active: Vec<&str> = allowlist
            .lines()
            .map(|l| l.split('#').next().unwrap().trim())
            .filter(|l| !l.is_empty())
            .collect();
        assert!(active.contains(&"host.container.internal:27182"));
    }

    /// The npm registry is reachable now, so the blanket denies are gone. The
    /// mutating install commands are gated with "ask" the way cargo and uv are,
    /// and a dependency file an install would rewrite asks too.
    #[test]
    fn opencode_config_gates_npm_dependencies() {
        let config = include_str!("assets/opencode.json");
        assert!(
            !config.contains("\"npm*\": \"deny\""),
            "npm must not be denied wholesale now that the registry is allowlisted"
        );
        assert!(config.contains("\"action\": \"shell\""));
        assert!(config.contains("\"resource\": \"npm install*\""));
        assert!(config.contains("\"effect\": \"ask\""));
        assert!(config.contains("\"action\": \"edit\""));
        assert!(config.contains("\"resource\": \"**/pnpm-lock.yaml\""));
    }

    /// The Containerfile has to keep the supply-chain defaults in place: a
    /// one-week cooldown for npm, pnpm, and uv, pnpm failing closed on too-new
    /// versions, no trust downgrade, exotic transitive sources blocked, and npm
    /// lifecycle scripts disabled.
    #[test]
    fn containerfile_sets_dependency_safety_defaults() {
        let file = include_str!("assets/Containerfile");
        assert!(file.contains("minimumReleaseAge: 10080"));
        assert!(file.contains("minimumReleaseAgeStrict: true"));
        assert!(file.contains("trustPolicy: no-downgrade"));
        assert!(file.contains("blockExoticSubdeps: true"));
        assert!(file.contains("min-release-age=7"));
        assert!(file.contains("ignore-scripts=true"));
        assert!(file.contains("exclude-newer = \"7 days\""));
    }

    /// The wasm toolchain has to be baked in. The target's std is a rustup
    /// component, and static.rust-lang.org is not on the egress allowlist, so
    /// the agent cannot add it at runtime — an image without these lines can
    /// never compile to wasm.
    #[test]
    fn containerfile_installs_wasm_toolchain() {
        let file = include_str!("assets/Containerfile");
        assert!(file.contains("rustup target add wasm32-unknown-unknown"));
        assert!(file.contains("wasm-pack"));
        assert!(file.contains("wasm-bindgen-cli"));
    }

    #[test]
    fn containerfile_installs_opencode_v2() {
        let file = include_str!("assets/Containerfile");
        assert!(file.contains("https://opencode.ai/v2/install"));
        assert!(file.contains("--no-modify-path"));
        assert!(!file.contains("npm install -g opencode-ai"));
    }

    /// The config directory is root-owned and read-only, so OpenCode must not
    /// use its shared background service, which persists service.json there.
    #[test]
    fn containerfile_starts_opencode_standalone() {
        let file = include_str!("assets/Containerfile");
        assert!(file.contains("CMD [\"opencode\", \"--standalone\"]"));
    }

    /// V2 does not import the legacy auth.json on a fresh database. The
    /// OpenRouter key therefore reaches the provider through the file named by
    /// providers.openrouter.settings.apiKey, which the entrypoint writes.
    #[test]
    fn entrypoint_writes_the_openrouter_key_file() {
        let entrypoint = include_str!("assets/entrypoint.sh");
        assert!(entrypoint.contains("OPENROUTER_KEY_FILE"));
        assert!(entrypoint.contains("> \"$OPENROUTER_KEY_FILE\""));
        let config = include_str!("assets/opencode.json");
        assert!(config.contains("{file:/home/agent/.local/share/opencode/openrouter-key}"));
    }

    #[test]
    fn opencode_config_denies_external_directories() {
        let config = include_str!("assets/opencode.json");
        assert!(config.contains("\"action\": \"external_directory\""));
        assert!(config.contains("\"effect\": \"deny\""));
    }

    #[test]
    fn external_directory_check_correlates_action_and_effect() {
        let deny = r#"{ "action": "external_directory", "resource": "*", "effect": "deny" }"#;
        assert!(external_directory_denied(deny));

        let allow = r#"{ "action": "external_directory", "resource": "*", "effect": "allow" }"#;
        assert!(!external_directory_denied(allow));

        let elsewhere = r#"{ "action": "shell", "resource": "git push*", "effect": "deny" }"#;
        assert!(!external_directory_denied(elsewhere));
    }

    #[test]
    fn host_service_port_reads_the_allowlist() {
        let dir = TempDir::new();
        let path = dir.0.join("allowlist.txt");
        fs::write(&path, "openrouter.ai\nhost.container.internal:8080\n").unwrap();
        assert_eq!(host_service_port(&dir.0).unwrap(), Some(8080));

        fs::write(&path, "openrouter.ai\n# host.container.internal:8080\n").unwrap();
        assert_eq!(host_service_port(&dir.0).unwrap(), None);

        fs::write(
            &path,
            "host.container.internal:8080\nhost.container.internal:9090\n",
        )
        .unwrap();
        assert!(host_service_port(&dir.0).is_err());
    }

    /// Hooks run on the host, so a project's hooks are mounted read-only, as
    /// a flag to 'container run' rather than an argument to OpenCode.
    #[test]
    fn run_args_mount_git_hooks_read_only() {
        let dir = TempDir::new();
        fs::create_dir_all(dir.0.join(".git/hooks")).unwrap();
        let a = run_args(&dir.0, "img", 2, 4, &[]);
        let i = a.iter().position(|x| x == "--mount").expect("--mount");
        assert_eq!(
            a[i + 1],
            format!(
                "type=bind,source={}/.git/hooks,target=/home/agent/code/.git/hooks,readonly",
                dir.0.display()
            )
        );
        assert!(i < a.iter().position(|x| x == "img").unwrap());

        let none = TempDir::new();
        assert!(!run_args(&none.0, "img", 2, 4, &[]).contains(&"--mount".to_string()));
    }

    /// The firewall lets exactly one UID out, and that UID has to be the one
    /// the image creates for the proxy.
    #[test]
    fn proxy_uid_is_consistent_across_assets() {
        let entrypoint = include_str!("assets/entrypoint.sh");
        assert!(entrypoint.contains("PROXY_UID=900"));
        assert!(entrypoint.contains("meta skuid ${PROXY_UID} accept"));
        assert!(include_str!("assets/Containerfile").contains("useradd -r -u 900 "));
    }

    #[test]
    fn probe_http_reads_the_status_line() {
        use std::io::{Read, Write};
        use std::net::TcpListener;
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0u8; 512];
            let _ = stream.read(&mut buffer);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
        });

        assert_eq!(
            probe_http(
                Ipv4Addr::LOCALHOST,
                "host.container.internal",
                port,
                "/v1/models",
                Duration::from_secs(2)
            )
            .unwrap(),
            200
        );
        handle.join().unwrap();
    }

    #[test]
    fn gateway_is_the_first_address_of_the_default_network() {
        let list = "NETWORK  SUBNET\ndefault  192.168.64.0/24\nfoo      192.168.65.0/24\n";
        assert_eq!(
            gateway_from_network_list(list),
            Some(Ipv4Addr::new(192, 168, 64, 1))
        );
        let extra_columns = "NETWORK  STATE    SUBNET\ndefault  running  10.1.0.0/16\n";
        assert_eq!(
            gateway_from_network_list(extra_columns),
            Some(Ipv4Addr::new(10, 1, 0, 1))
        );
        assert_eq!(
            gateway_from_network_list("NETWORK  SUBNET\nfoo  192.168.65.0/24\n"),
            None
        );
        assert_eq!(gateway_from_network_list(""), None);
    }
}
