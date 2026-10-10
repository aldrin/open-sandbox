#!/usr/bin/env python3
"""Checks that the container image has the expected agent and toolchain.

Run inside the container by asking the agent to execute it:

    python3 ~/sandbox-tools.py
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
    (["python3", "--version"], "Python"),
    (["uv", "--version"], "uv"),
    (["basedpyright", "--version"], "basedpyright"),
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


# ── 3. Agent configuration ────────────────────────────────────────────
#
# OpenCode must find its config, its context file, and its credentials
# where the image put them. A missing auth file means the entrypoint did
# not run, which means the firewall did not either.

heading("OpenCode configuration is in place")

for path, label in [
    (CONFIG_PATH, "OpenCode config"),
    ("/home/agent/.config/opencode/AGENTS.md", "OpenCode context file"),
    ("/home/agent/.config/opencode/command", "OpenCode commands"),
    (AUTH_PATH, "OpenCode credentials"),
    (ALLOWLIST_PATH, "Egress allowlist"),
]:
    check(os.path.exists(path), label, path)


heading("OpenCode is pointed at OpenRouter")

# The auth file is the one thing here that is a runtime effect: the
# entrypoint writes it on every start, so its absence means the entrypoint
# did not run, which means the firewall did not either.
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

# The two below read the config the image shipped, so they report what
# OpenCode was *configured* to do, not what it resolved at runtime. What
# actually confines egress is the proxy, and sandbox-checks.py proves that
# by effect: any host off the allowlist is refused.
try:
    with open(CONFIG_PATH) as f:
        oc_config = json.load(f)

    check(
        oc_config.get("enabled_providers") == ["openrouter"],
        "openrouter is configured as the only provider",
        f"enabled_providers={oc_config.get('enabled_providers')}",
    )

    # A default model is pinned so a session starts on DeepSeek Flash Latest
    # without a picker, and /models or --model still switch it. Whatever is
    # pinned has to be an OpenRouter model: nothing else is reachable.
    model = str(oc_config.get("model", ""))
    check(
        model.startswith("openrouter/"),
        "the default model is an OpenRouter model",
        f"model={model or '<unpinned>'}",
    )
except (OSError, ValueError) as e:
    check(False, "OpenCode config is readable and valid JSON", f"{type(e).__name__}: {e}")


# ── 4. Environment ────────────────────────────────────────────────────

heading("Runtime environment is configured")

for var, expected in [
    ("CARGO_TARGET_DIR", "/home/agent/cargo-target"),
    ("TMPDIR", "/tmp/agent"),
    ("EDITOR", "emacs"),
    ("TERM", "xterm-256color"),
    ("HOME", "/home/agent"),
]:
    val = os.environ.get(var)
    check(val == expected, f"{var}={expected}", f"actual={val}")


# ── Summary ────────────────────────────────────────────────────────────

print(f"\n{'─' * 46}")
print(f"{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
