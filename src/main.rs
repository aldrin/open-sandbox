//! open-sandbox: Launch OpenCode against OpenRouter in a sandboxed
//! Apple container VM.
//!
//! External commands used:
//! - container --version
//! - container image inspect <image>
//! - container build -t <image> -f <containerfile> <context>
//! - container run --rm -it --cap-add <cap> -e <env> -m <memory> -c <cpus>
//!   -v <volume> <image> <command>
//! - security find-generic-password -s <service> -w

use std::env;
use std::fs;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const SANDBOX_DIR: &str = ".open-sandbox";
const IMAGE_NAME_FILE: &str = "image-name";
const KEYCHAIN_FILE: &str = "keychain-service";
const IMAGE_PREFIX: &str = "open-sandbox";
const DEFAULT_KEYCHAIN_SERVICE: &str = "openrouter-api-key";
const CONTAINER_CODE_DIR: &str = "/home/agent/code";
const KEY_ENV_VAR: &str = "OPENROUTER_API_KEY";
const TAVILY_ENV_VAR: &str = "TAVILY_API_KEY";
const TAVILY_KEYCHAIN_SERVICE: &str = "tavily-api-key";
const COLORTERM_ENV_VAR: &str = "COLORTERM";
const REQUIRED_CAP: &str = "CAP_NET_ADMIN";
const HINT_RUN_INIT: &str = "Run 'open-sandbox init' first to initialize the workspace.";

const ASSETS: &[(&str, &str)] = &[
    ("Containerfile", include_str!("assets/Containerfile")),
    ("entrypoint.sh", include_str!("assets/entrypoint.sh")),
    ("egress-proxy.py", include_str!("assets/egress-proxy.py")),
    ("allowlist.txt", include_str!("assets/allowlist.txt")),
    ("opencode.json", include_str!("assets/opencode.json")),
    ("AGENTS.md", include_str!("assets/AGENTS.md")),
    ("tui.json", include_str!("assets/tui.json")),
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
  status  Compare .open-sandbox/ files against the current binary's embedded assets
  help    Print this message

Options:
  -h, --help     Print help
  -V, --version  Print version

init options:
      --force                 Overwrite existing files in .open-sandbox/
      --name <NAME>           Container image name (default: open-sandbox-<dirname>)
      --keychain-service <S>  Keychain service holding the OpenRouter API key
                              (default: openrouter-api-key)

run options:
      --model <ID>            OpenRouter model to use; the 'openrouter/' prefix
                              is added if you leave it off. Omit to use the
                              configured default; switch with '/models'.
      --cpus <N>              Number of CPUs, 2-8 (default: 2)
      --memory <N>            Memory in GB, 2-8 (default: 4)
      -- <ARGS>...            Pass the remaining arguments to OpenCode
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
        keychain_service: Option<String>,
    },
    Build,
    Run {
        model: Option<String>,
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
            let mut keychain_service = None;
            let mut i = 0;
            while i < rest.len() {
                match rest[i].as_str() {
                    "--force" => force = true,
                    "--name" => name = Some(value_for("--name", rest, &mut i)?),
                    "--keychain-service" => {
                        keychain_service = Some(value_for("--keychain-service", rest, &mut i)?)
                    }
                    other => return Err(format!("unexpected argument '{other}' for init")),
                }
                i += 1;
            }
            Ok(Cmd::Init {
                force,
                name,
                keychain_service,
            })
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
            let mut model = None;
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
                    "--model" => model = Some(value_for("--model", rest, &mut i)?),
                    "--cpus" => cpus = resource("--cpus", &value_for("--cpus", rest, &mut i)?)?,
                    "--memory" => {
                        memory = resource("--memory", &value_for("--memory", rest, &mut i)?)?
                    }
                    other => return Err(format!("unexpected argument '{other}' for run")),
                }
                i += 1;
            }
            Ok(Cmd::Run {
                model,
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
    if let Err(message) = dispatch(&args) {
        eprintln!("error: {message}");
        std::process::exit(1);
    }
}

fn dispatch(args: &[String]) -> Result<(), String> {
    match parse(args)? {
        Cmd::Help => {
            print!("{USAGE}");
            Ok(())
        }
        Cmd::Version => {
            println!("open-sandbox {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Cmd::Init {
            force,
            name,
            keychain_service,
        } => cmd_init(force, name.as_deref(), keychain_service.as_deref()),
        Cmd::Build => cmd_build(),
        Cmd::Run {
            model,
            cpus,
            memory,
            extra,
        } => cmd_run(model.as_deref(), cpus, memory, &extra),
        Cmd::Status => cmd_status(),
    }
}

// ── Commands ────────────────────────────────────────────────────────────────

fn cmd_init(force: bool, name: Option<&str>, keychain_service: Option<&str>) -> Result<(), String> {
    let cwd = current_dir()?;
    let sandbox_dir = cwd.join(SANDBOX_DIR);

    let image = match name {
        Some(n) => n.to_string(),
        None => default_image_name(&cwd)?,
    };
    let service = keychain_service.unwrap_or(DEFAULT_KEYCHAIN_SERVICE);

    init_sandbox(&sandbox_dir, force, &image, service)?;

    info!("Initialized workspace in {SANDBOX_DIR}/ (image: {image}, keychain service: {service})");
    Ok(())
}

fn init_sandbox(
    sandbox_dir: &Path,
    force: bool,
    image: &str,
    keychain_service: &str,
) -> Result<(), String> {
    if !force && sandbox_dir.join("Containerfile").exists() {
        return Err(format!(
            "{SANDBOX_DIR} already initialized. Use --force to overwrite."
        ));
    }

    write_file(&sandbox_dir.join(IMAGE_NAME_FILE), &format!("{image}\n"))?;
    write_file(
        &sandbox_dir.join(KEYCHAIN_FILE),
        &format!("{keychain_service}\n"),
    )?;

    for (name, content) in ASSETS {
        write_file(&sandbox_dir.join(name), content)?;
    }
    Ok(())
}

fn cmd_build() -> Result<(), String> {
    check_container_available()?;

    let sandbox_dir = current_dir()?.join(SANDBOX_DIR);
    let image = read_setting(&sandbox_dir, IMAGE_NAME_FILE)?;

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

fn cmd_run(model: Option<&str>, cpus: u8, memory: u8, extra: &[String]) -> Result<(), String> {
    check_container_available()?;

    let cwd = current_dir()?;
    let sandbox_dir = cwd.join(SANDBOX_DIR);
    let image = read_setting(&sandbox_dir, IMAGE_NAME_FILE)?;
    let service = read_setting(&sandbox_dir, KEYCHAIN_FILE)?;
    check_image_built(&image)?;

    let key = read_keychain_key(&service)?;
    if !key.starts_with("sk-or-") {
        info!(
            "The value in keychain service '{service}' does not look like an OpenRouter key \
             (expected an 'sk-or-' prefix). Passing it through anyway."
        );
    }

    let tavily = read_optional_keychain_key(TAVILY_KEYCHAIN_SERVICE);
    if tavily.is_none() {
        info!(
            "No Tavily key in keychain service '{TAVILY_KEYCHAIN_SERVICE}'; web search will be \
             unavailable. Store one with:\n  \
             security add-generic-password -a \"$USER\" -s {TAVILY_KEYCHAIN_SERVICE} -w"
        );
    }

    let mut command = opencode_command(model);
    command.extend_from_slice(extra);

    // Forward the host terminal's truecolor capability, so OpenCode's theme
    // renders full syntax highlighting instead of falling back to 256 colors.
    // Absent is fine: the container keeps its own TERM as the fallback.
    let colorterm = env::var(COLORTERM_ENV_VAR).unwrap_or_default();

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

fn cmd_status() -> Result<(), String> {
    let sandbox_dir = current_dir()?.join(SANDBOX_DIR);

    if !sandbox_dir.join("Containerfile").exists() {
        return Err(format!("{SANDBOX_DIR}/ not initialized.\n{HINT_RUN_INIT}"));
    }

    let mut diffs = 0usize;
    for (name, embedded) in ASSETS {
        let path = sandbox_dir.join(name);
        match fs::read_to_string(&path) {
            Ok(ref content) if content == embedded => println!("  ok    {name}"),
            Ok(_) => {
                println!("  DIFF  {name}");
                diffs += 1;
            }
            Err(_) => {
                println!("  MISS  {name}");
                diffs += 1;
            }
        }
    }

    for name in [IMAGE_NAME_FILE, KEYCHAIN_FILE] {
        match read_setting(&sandbox_dir, name) {
            Ok(value) => println!("  ok    {name}  ({value})"),
            Err(_) => {
                println!("  MISS  {name}");
                diffs += 1;
            }
        }
    }

    if diffs > 0 {
        println!("\n{diffs} file(s) differ — run 'open-sandbox init --force' to update");
    } else {
        println!("\nAll files match");
    }

    Ok(())
}

// ── Agent invocation ────────────────────────────────────────────────────────

/// The command line the container runs.
///
/// OpenCode composes a model id as `provider/model`, so an OpenRouter model is
/// spelled `openrouter/anthropic/…`. Accept either spelling from the user and
/// pass on the one OpenCode expects. With no `--model` the flag is omitted
/// entirely, which leaves OpenCode to its own selection and leaves `/models`
/// free to change it mid-session.
fn opencode_command(model: Option<&str>) -> Vec<String> {
    let mut cmd = vec!["opencode".to_string()];
    if let Some(model) = model {
        cmd.push("--model".to_string());
        cmd.push(match model.starts_with("openrouter/") {
            true => model.to_string(),
            false => format!("openrouter/{model}"),
        });
    }
    cmd
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
        image.to_string(),
    ];
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

fn read_keychain_key(service: &str) -> Result<String, String> {
    debug!("reading keychain service: {service}");
    output_quiet("security", &["find-generic-password", "-s", service, "-w"])
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            format!(
                "No OpenRouter API key found in keychain service '{service}'.\n\n\
                 Store one with:\n  \
                 security add-generic-password -a \"$USER\" -s {service} -w"
            )
        })
}

/// Read a keychain entry that may legitimately be absent. Optional
/// integrations (Tavily) must not block `run`, so a missing key logs a hint and
/// moves on rather than failing the launch.
fn read_optional_keychain_key(service: &str) -> Option<String> {
    debug!("reading optional keychain service: {service}");
    output_quiet("security", &["find-generic-password", "-s", service, "-w"])
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
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
        init_sandbox(
            &sandbox,
            false,
            "open-sandbox-test",
            DEFAULT_KEYCHAIN_SERVICE,
        )
        .unwrap();
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
        assert_eq!(
            read_setting(&sandbox, KEYCHAIN_FILE).unwrap(),
            DEFAULT_KEYCHAIN_SERVICE
        );
    }

    #[test]
    fn init_honours_custom_names() {
        let dir = TempDir::new();
        let sandbox = dir.sandbox();
        init_sandbox(&sandbox, false, "my-image", "my-service").unwrap();
        assert_eq!(read_setting(&sandbox, IMAGE_NAME_FILE).unwrap(), "my-image");
        assert_eq!(read_setting(&sandbox, KEYCHAIN_FILE).unwrap(), "my-service");
    }

    #[test]
    fn init_refuses_if_already_initialized() {
        let dir = TempDir::new();
        init(&dir);
        assert!(init_sandbox(&dir.sandbox(), false, "x", "y").is_err());
    }

    #[test]
    fn init_force_overwrites() {
        let dir = TempDir::new();
        let sandbox = init(&dir);
        fs::write(sandbox.join("Containerfile"), b"modified").unwrap();
        init_sandbox(
            &sandbox,
            true,
            "open-sandbox-test",
            DEFAULT_KEYCHAIN_SERVICE,
        )
        .unwrap();
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

    /// No `--model` means no flag at all, so OpenCode picks for itself and
    /// stays free to switch models mid-session.
    #[test]
    fn opencode_command_omits_the_model_flag_when_unset() {
        assert_eq!(opencode_command(None), vec!["opencode"]);
    }

    /// Either spelling of an OpenRouter model reaches OpenCode as the fully
    /// qualified one it expects.
    #[test]
    fn opencode_command_passes_the_model_opencode_expects() {
        assert_eq!(
            opencode_command(Some("anthropic/x")),
            vec!["opencode", "--model", "openrouter/anthropic/x"]
        );
        assert_eq!(
            opencode_command(Some("openrouter/anthropic/x")),
            vec!["opencode", "--model", "openrouter/anthropic/x"]
        );
    }

    // ── run arguments ───────────────────────────────────────────────

    #[test]
    fn run_args_default() {
        let command = opencode_command(None);
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
        let a = run_args(Path::new("/tmp"), "img", 2, 4, &opencode_command(None));
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
        let command = opencode_command(Some("z"));
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
            parse(&args(&[
                "init",
                "--force",
                "--name",
                "x",
                "--keychain-service",
                "y"
            ]))
            .unwrap(),
            Cmd::Init {
                force: true,
                name: Some("x".into()),
                keychain_service: Some("y".into()),
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
                keychain_service: None,
            }
        );
    }

    #[test]
    fn parse_run_flags() {
        assert_eq!(
            parse(&args(&[
                "run", "--model", "m", "--cpus", "4", "--memory", "8"
            ]))
            .unwrap(),
            Cmd::Run {
                model: Some("m".into()),
                cpus: 4,
                memory: 8,
                extra: vec![],
            }
        );
    }

    #[test]
    fn parse_run_passthrough_after_double_dash() {
        // --model is a flag we own, so it proves everything after '--' is
        // handed to OpenCode rather than consumed on the way past.
        let Cmd::Run { extra, model, .. } =
            parse(&args(&["run", "--", "--continue", "--model", "x"])).unwrap()
        else {
            panic!("expected a run command");
        };
        assert_eq!(extra, args(&["--continue", "--model", "x"]));
        assert_eq!(model, None);
    }

    #[test]
    fn parse_rejects_bad_input() {
        assert!(parse(&args(&["run", "--model"])).is_err());
        assert!(parse(&args(&["run", "--cpus", "1"])).is_err());
        assert!(parse(&args(&["run", "--cpus", "9"])).is_err());
        assert!(parse(&args(&["run", "--cpus"])).is_err());
        assert!(parse(&args(&["run", "--nope"])).is_err());
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
    /// verify script would fail on them. OpenRouter has to be the only
    /// provider, since the allowlist reaches no other provider's API. A default
    /// model is pinned to DeepSeek Flash Latest, and the same model is set as
    /// small_model because OpenCode's built-in default lives on OpenCode Zen,
    /// which is neither enabled nor reachable — leaving it unset would break
    /// title generation. The two DeepSeek aliases are declared as plain catalog
    /// entries, so their limits come from models.dev rather than being
    /// re-pinned here. Any OpenRouter model stays selectable, per run with
    /// --model or mid-session with /models.
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
        assert!(
            config.contains("\"small_model\": \"openrouter/~deepseek/deepseek-flash-latest\""),
            "small_model must be the reachable OpenRouter Flash model"
        );
        assert!(
            config.contains("~deepseek/deepseek-flash-latest")
                && config.contains("~deepseek/deepseek-pro-latest"),
            "both DeepSeek aliases must be configured"
        );
        assert!(
            !config.contains("\"limit\""),
            "catalog models must not re-pin limits; OpenCode reads them from models.dev"
        );
    }

    /// The TUI theme is pinned through tui.json, which is strict JSON and must
    /// name a theme that actually ships with OpenCode (unknown names silently
    /// fall back). Night Owl is one of the built-ins.
    #[test]
    fn tui_json_pins_a_builtin_theme() {
        let tui = include_str!("assets/tui.json");
        assert!(
            !tui.replace("://", "").contains("//"),
            "tui.json must stay comment-free"
        );
        assert!(tui.contains("\"theme\": \"nightowl\""));
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
    }
}
