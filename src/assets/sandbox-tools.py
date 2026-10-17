#!/usr/bin/env python3
"""Checks that the container image has the expected agent and toolchain.

Run inside the container by asking the agent to execute it:

    python3 /usr/local/lib/open-sandbox/sandbox-tools.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

CONFIG_PATH = "/home/agent/.config/opencode/opencode.json"
AUTH_PATH = "/home/agent/.local/share/opencode/auth.json"
ALLOWLIST_PATH = "/etc/open-sandbox/allowlist.txt"

# ── Formatting ──────────────────────────────────────────────────────────

passed = 0
failed = 0


def check(ok: bool, description: str, detail: str = "") -> None:
    """Record and print one check."""
    global passed, failed
    if ok:
        passed += 1
        tag = "PASS"
    else:
        failed += 1
        tag = "FAIL"
    suffix = f"  {detail}" if detail else ""
    print(f"  {tag}  {description}{suffix}")


def heading(title: str) -> None:
    print(f"\n{title}\n")


def version_of(cmd: list[str]) -> tuple[bool, str]:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as e:
        return False, type(e).__name__
    text = (result.stdout.strip() or result.stderr.strip()).split("\n")[0]
    return result.returncode == 0, text


# ── 1. Agents ─────────────────────────────────────────────────────────

heading("Agent CLI is installed")

for cmd, label in [
    (["opencode", "--version"], "OpenCode"),
    (["node", "--version"], "Node.js"),
    (["npm", "--version"], "npm"),
]:
    ok, version = version_of(cmd)
    check(ok, label, version)


# ── 2. Toolchain ──────────────────────────────────────────────────────

heading("Development toolchain is available")

for cmd, label in [
    (["rustc", "--version"], "Rust compiler"),
    (["cargo", "--version"], "Cargo"),
    (["rust-analyzer", "--version"], "rust-analyzer"),
    (["cargo", "clippy", "--version"], "Clippy"),
    (["rustfmt", "--version"], "rustfmt"),
    (["wasm-pack", "--version"], "wasm-pack"),
    (["wasm-bindgen", "--version"], "wasm-bindgen"),
    (["python3", "--version"], "Python"),
    (["uv", "--version"], "uv"),
    (["basedpyright", "--version"], "basedpyright"),
    (["pnpm", "--version"], "pnpm"),
    (["tsc", "--version"], "TypeScript compiler"),
    (["biome", "--version"], "Biome"),
    (["typescript-language-server", "--version"], "TypeScript language server"),
    (["duckdb", "--version"], "DuckDB"),
    (["pandoc", "--version"], "Pandoc"),
    (["typst", "--version"], "Typst"),
    (["emacs", "--version"], "Emacs"),
    (["rg", "--version"], "ripgrep"),
    (["git", "--version"], "git"),
    (["nft", "--version"], "nftables"),
    (["setpriv", "--version"], "setpriv"),
]:
    ok, version = version_of(cmd)
    check(ok, label, version)

# wasm builds need the target's std, which rustup installs as a component
# rather than a crate. The image bakes it in; the agent cannot add it, since
# static.rust-lang.org is not on the egress allowlist.
try:
    installed = subprocess.run(
        ["rustup", "target", "list", "--installed"],
        capture_output=True,
        text=True,
        timeout=60,
    ).stdout
    check("wasm32-unknown-unknown" in installed, "wasm32-unknown-unknown target")
except (OSError, subprocess.SubprocessError) as e:
    check(False, "wasm32-unknown-unknown target", type(e).__name__)


# ── 3. Agent configuration ────────────────────────────────────────────
#
# OpenCode must find its config, its context file, and its credentials
# where the image put them. A missing auth file means the entrypoint did
# not run, which means the firewall did not either.

heading("OpenCode configuration is in place")

for path, label in [
    (CONFIG_PATH, "OpenCode config"),
    ("/home/agent/.config/opencode/AGENTS.md", "OpenCode context file"),
    ("/home/agent/.config/opencode/commands", "OpenCode commands"),
    ("/home/agent/.config/opencode/cli.json", "OpenCode CLI settings"),
    (AUTH_PATH, "OpenCode credentials"),
    ("/home/agent/.local/share/opencode/openrouter-key", "OpenRouter key file"),
    (ALLOWLIST_PATH, "Egress allowlist"),
]:
    check(os.path.exists(path), label, path)


heading("OpenCode is configured for OpenRouter and the host model")

# The credential files are the runtime effect here: the entrypoint writes them
# on every start, so their absence means the entrypoint did not run, which
# means the firewall did not either.
try:
    with open(AUTH_PATH) as f:
        auth = json.load(f)
    check(
        bool(auth.get("openrouter", {}).get("key")),
        "OpenCode has an openrouter credential",
        f"keys={list(auth)}",
    )
except (OSError, ValueError) as e:
    check(False, "OpenCode has an openrouter credential", f"{type(e).__name__}: {e}")


def host_service_port() -> int | None:
    """Return the port of the host.container.internal allowlist entry."""
    prefix = "host.container.internal:"
    try:
        with open(ALLOWLIST_PATH) as f:
            for line in f:
                entry = line.split("#", 1)[0].strip().lower()
                if entry.startswith(prefix):
                    return int(entry[len(prefix) :])
    except (OSError, ValueError):
        return None
    return None


# The checks below read the config the image shipped, so they report what
# OpenCode was *configured* to do, not what it resolved at runtime. What
# actually confines egress is the proxy, and sandbox-checks.py proves that
# by effect: any host off the allowlist is refused.
try:
    with open(CONFIG_PATH) as f:
        oc_config = json.load(f)

    providers = oc_config.get("enabled_providers", [])
    check(
        "openrouter" in providers and set(providers) <= {"openrouter", "mlx"},
        "openrouter is enabled; local mlx is the only other provider",
        f"enabled_providers={providers}",
    )

    openrouter = oc_config.get("providers", {}).get("openrouter", {})
    api_key = openrouter.get("settings", {}).get("apiKey", "")
    check(
        api_key == "{file:/home/agent/.local/share/opencode/openrouter-key}",
        "the openrouter key is read from its key file",
        f"apiKey={api_key or '<unset>'}",
    )

    port = host_service_port()
    mlx = oc_config.get("providers", {}).get("mlx", {})
    base_url = mlx.get("settings", {}).get("baseURL", "")
    if port is not None:
        expected_base_url = f"http://host.container.internal:{port}/v1"
        check(
            base_url == expected_base_url,
            "the mlx provider points at the allowlisted host integration address",
            f"baseURL={base_url or '<unset>'} expected={expected_base_url}",
        )
    if mlx:
        check(
            mlx.get("package") == "aisdk:@ai-sdk/openai-compatible",
            "the mlx provider uses the v2 OpenAI-compatible package",
            f"package={mlx.get('package', '<unset>')}",
        )

    # A default model is pinned so a session starts on DeepSeek Flash Latest
    # without a picker, and /models still switches it. Whatever is pinned has
    # to be an OpenRouter model: nothing else is reachable without the host
    # endpoint.
    model = str(oc_config.get("model", ""))
    check(
        model.startswith("openrouter/"),
        "the default model is an OpenRouter model",
        f"model={model or '<unpinned>'}",
    )
    title_model = str(oc_config.get("agents", {}).get("title", {}).get("model", ""))
    check(
        title_model.startswith("openrouter/"),
        "the title agent uses an OpenRouter model",
        f"model={title_model or '<unpinned>'}",
    )

    tavily = oc_config.get("mcp", {}).get("servers", {}).get("tavily", {})
    check(
        bool(tavily),
        "the Tavily MCP server is configured under mcp.servers",
        f"keys={list(oc_config.get('mcp', {}).get('servers', {}))}",
    )

    permissions = oc_config.get("permissions", [])
    check(
        any(
            isinstance(rule, dict)
            and rule.get("action") == "external_directory"
            and rule.get("effect") == "deny"
            for rule in permissions
        ),
        "external directory access is denied",
        f"rules={len(permissions)}",
    )
except (OSError, ValueError) as e:
    check(False, "OpenCode config is readable and valid JSON", f"{type(e).__name__}: {e}")


# ── 4. Environment ────────────────────────────────────────────────────

heading("Runtime environment is configured")

for var, expected in [
    ("CARGO_TARGET_DIR", "/home/agent/cargo-target"),
    ("FNM_DIR", "/home/agent/.local/share/fnm"),
    ("NPM_CONFIG_PREFIX", "/home/agent/.local"),
    ("PNPM_HOME", "/home/agent/.local/share/pnpm"),
    ("TMPDIR", "/tmp/agent"),
    ("EDITOR", "emacs"),
    ("TERM", "xterm-256color"),
    ("HOME", "/home/agent"),
]:
    val = os.environ.get(var)
    check(val == expected, f"{var}={expected}", f"actual={val}")


# ── 5. Dependency-install safety ──────────────────────────────────────
#
# A version published moments ago is the shape of most supply-chain attacks.
# npm, pnpm, and uv all wait a week before resolving a new version; pnpm
# additionally fails closed, refuses a trust downgrade, and blocks exotic
# transitive sources, while npm runs no lifecycle scripts at all.

heading("Dependency-install safety is configured")

for path, needle, label in [
    ("/home/agent/.npmrc", "min-release-age=7", "npm cooldown (7 days)"),
    ("/home/agent/.npmrc", "ignore-scripts=true", "npm lifecycle scripts disabled"),
    (
        "/home/agent/.config/pnpm/config.yaml",
        "minimumReleaseAge: 10080",
        "pnpm cooldown (7 days)",
    ),
    (
        "/home/agent/.config/pnpm/config.yaml",
        "minimumReleaseAgeStrict: true",
        "pnpm cooldown fails closed",
    ),
    (
        "/home/agent/.config/pnpm/config.yaml",
        "trustPolicy: no-downgrade",
        "pnpm refuses a trust downgrade",
    ),
    (
        "/home/agent/.config/pnpm/config.yaml",
        "blockExoticSubdeps: true",
        "pnpm blocks exotic transitive sources",
    ),
    (
        "/home/agent/.config/uv/uv.toml",
        'exclude-newer = "7 days"',
        "uv cooldown (7 days)",
    ),
]:
    try:
        with open(path) as f:
            check(needle in f.read(), label, path)
    except OSError as e:
        check(False, label, f"{type(e).__name__}: {e}")


# ── Summary ────────────────────────────────────────────────────────────

print(f"\n{'─' * 46}")
print(f"{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
