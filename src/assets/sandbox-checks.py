#!/usr/bin/env python3
"""Checks the isolation invariants of an open-sandbox container.

Run inside the container by asking the agent to execute it:

    python3 /usr/local/lib/open-sandbox/sandbox-checks.py

Everything here is probed from the agent's own position: as the unprivileged
'agent' user, with whatever environment the entrypoint handed over. Nothing is
read from the firewall's configuration, because the agent cannot read it — the
checks confirm the effect instead.

To run without the entrypoint (override it on the host):

    container run --rm -it --entrypoint /bin/bash -v ...  <image>
    python3 /usr/local/lib/open-sandbox/sandbox-checks.py
"""

from __future__ import annotations

import os
import pwd
import socket
import subprocess
import sys
from urllib.parse import urlparse

PROXY_HOST = "127.0.0.1"
PROXY_PORT = 3128
ALLOWLIST_PATH = "/etc/open-sandbox/allowlist.txt"

# ── Formatting ──────────────────────────────────────────────────────────

passed = 0
failed = 0
sections: dict[str, bool] = {}
_current_section = ""


def check(ok: bool, description: str, detail: str = "") -> None:
    """Record and print one invariant check."""
    global passed, failed
    if ok:
        passed += 1
        tag = "PASS"
    else:
        failed += 1
        tag = "FAIL"
        if _current_section:
            sections[_current_section] = False
    suffix = f"  {detail}" if detail else ""
    print(f"  {tag}  {description}{suffix}")


def heading(title: str, key: str = "") -> None:
    global _current_section
    _current_section = key
    if key:
        sections.setdefault(key, True)
    print(f"\n{title}\n")


# ── 1. Overview ───────────────────────────────────────────────────────
#
# Informational. This section never fails; it is here so the numbers below
# can be read against the environment they were produced in.

heading("Sandbox overview")

try:
    user = pwd.getpwuid(os.getuid()).pw_name
except KeyError:
    user = "<unknown>"

print("  Process:\n")
print(f"    user={user} uid={os.getuid()} gid={os.getgid()}")
print(f"    cwd={os.getcwd()}")

print("\n  Proxy environment:\n")
for var in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"):
    print(f"    {var}={os.environ.get(var, '<unset>')}")

print("\n  Allowlist:\n")
rules: list[str] = []
try:
    with open(ALLOWLIST_PATH) as f:
        rules = [
            line.split("#", 1)[0].strip()
            for line in f
            if line.split("#", 1)[0].strip()
        ]
    for rule in rules:
        print(f"    {rule}")
    print(f"\n    {len(rules)} rule(s) from {ALLOWLIST_PATH}")
except OSError as e:
    print(f"    WARN  could not read {ALLOWLIST_PATH}: {e}")

print("\n  Firewall visibility:\n")
_nft = subprocess.run(
    ["nft", "list", "ruleset"], capture_output=True, text=True
)
if _nft.returncode == 0:
    print("    nft list ruleset SUCCEEDED — this process has CAP_NET_ADMIN")
else:
    _msg = (_nft.stderr.strip() or "<no output>").split("\n")[0]
    print(f"    nft list ruleset refused: {_msg}")


# ── 2. Direct egress ─────────────────────────────────────────────────
#
# The nftables output chain drops everything the agent sends. DNS dies
# first, so the TCP probes use literal addresses to test the firewall
# rather than the resolver.

heading("Direct egress is blocked", "direct")

socket.setdefaulttimeout(5)


def dns_blocked(host: str) -> tuple[bool, str]:
    try:
        addr = socket.getaddrinfo(host, 443)[0][4][0]
        return False, f"resolved to {addr}"
    except Exception as e:
        return True, type(e).__name__


def tcp_blocked(host: str, port: int) -> tuple[bool, str]:
    try:
        socket.create_connection((host, port)).close()
        return False, "connected"
    except Exception as e:
        return True, type(e).__name__


for host in ["openrouter.ai", "github.com", "pypi.org"]:
    ok, detail = dns_blocked(host)
    check(ok, f"DNS unreachable: {host}", detail)

for host, port, label in [
    ("1.1.1.1", 53, "Cloudflare DNS"),
    ("8.8.8.8", 53, "Google DNS"),
    ("1.1.1.1", 443, "Cloudflare HTTPS"),
    ("9.9.9.9", 53, "Quad9 DNS"),
]:
    ok, detail = tcp_blocked(host, port)
    check(ok, f"TCP unreachable: {label} ({host}:{port})", detail)


# ── 3. Proxy allowlist ───────────────────────────────────────────────
#
# The proxy is the only way out. It must accept an allowlisted host on an
# allowlisted port and refuse everything else with 403.

heading("The proxy enforces the allowlist", "proxy")


def proxy_connect(target: str) -> tuple[int | None, str]:
    """Send a CONNECT for *target* and return (status code, status line)."""
    try:
        sock = socket.create_connection((PROXY_HOST, PROXY_PORT), timeout=20)
    except OSError as e:
        return None, f"{type(e).__name__}: {e}"
    try:
        sock.sendall(
            f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode()
        )
        line = b""
        while not line.endswith(b"\r\n") and len(line) < 512:
            chunk = sock.recv(1)
            if not chunk:
                break
            line += chunk
        status = line.decode("latin-1").strip()
        parts = status.split()
        code = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
        return code, status or "<no response>"
    except OSError as e:
        return None, f"{type(e).__name__}: {e}"
    finally:
        sock.close()


code, status = proxy_connect("openrouter.ai:443")
check(
    code == 200,
    "allowlisted host is reachable through the proxy (openrouter.ai:443)",
    status if code != 200 else "200 Connection established",
)

code, status = proxy_connect("example.com:443")
check(code == 403, "host outside the allowlist is refused (example.com:443)", status)

code, status = proxy_connect("openrouter.ai:22")
check(code == 403, "non-web port is refused (openrouter.ai:22)", status)

# If the workspace enables the Mac-host model, the proxy must route it. A 403
# means the allowlist or the non-public-address exception is missing; a 502
# means the route is allowed but the model server is not running.
host_rules = [rule for rule in rules if rule.startswith("host.container.internal:")]
if host_rules:
    target = host_rules[0]
    code, status = proxy_connect(target)
    check(
        code in (200, 502),
        f"local host service is routed through the proxy ({target})",
        status,
    )


heading("Proxy environment points at the proxy", "proxy_env")

for var in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
    val = os.environ.get(var, "")
    parsed = urlparse(val)
    routed = (
        parsed.scheme in ("http", "socks5", "socks5h")
        and parsed.hostname in ("localhost", "127.0.0.1", "::1")
        and parsed.port == PROXY_PORT
    )
    check(routed, f"{var} points at the local proxy", val or "<unset>")


# ── 4. Credentials ───────────────────────────────────────────────────
#
# The entrypoint writes the OpenRouter key to OpenCode's auth file and
# drops it from the environment before exec. It is readable at rest by
# this user — it has to be — but it should not be in the environment, and
# no other credential should be here at all.

heading("Credentials are not in the environment", "creds")

for var in (
    "OPENROUTER_API_KEY",
    "TAVILY_API_KEY",
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "NPM_TOKEN",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
):
    check(var not in os.environ, f"{var} is unset")


# ── 5. Filesystem ────────────────────────────────────────────────────


def check_writable(path: str, expect_writable: bool) -> None:
    """Probe whether *path* is writable and compare against expectation."""
    created_dir = False
    if not os.path.isdir(path):
        if not expect_writable:
            check(True, f"{path} is not writable", "does not exist")
            return
        try:
            os.makedirs(path, exist_ok=True)
            created_dir = True
        except OSError as e:
            check(False, f"{path} is writable", f"mkdir failed: {type(e).__name__}")
            return
    probe = os.path.join(path, ".sandbox-probe")
    try:
        with open(probe, "w") as f:
            f.write("test")
        os.remove(probe)
        if created_dir:
            os.rmdir(path)
        check(expect_writable, f"{path} is writable")
    except OSError as e:
        label = f"{path} is {'writable' if expect_writable else 'not writable'}"
        check(not expect_writable, label, type(e).__name__)


heading("System paths are not writable", "fs_ro")

for path in ["/etc", "/usr", "/usr/bin", "/var", "/usr/local/bin"]:
    check_writable(path, expect_writable=False)


heading("Work paths are writable", "fs_rw")

for path in [
    "/home/agent",
    "/home/agent/code",
    "/home/agent/cargo-target",
    os.environ.get("TMPDIR", "/tmp/agent"),
]:
    check_writable(path, expect_writable=True)


# ── 6. Configuration is read-only ────────────────────────────────────
#
# These files are root-owned, so this user cannot edit them. That guards
# against accidental edits. The OpenCode config sits in ~/.config, which this
# user owns, so a deliberate agent could still rename the directory aside and
# write its own; the firewall and proxy are what that cannot get around. The
# files under /etc and /usr/local are in root-owned directories as well.

heading("Agent configuration is read-only", "config")

for path in [
    ALLOWLIST_PATH,
    "/home/agent/.config/opencode",
    "/home/agent/.config/opencode/opencode.json",
    "/home/agent/.config/opencode/AGENTS.md",
    "/usr/local/bin/open-sandbox-entrypoint",
    "/usr/local/lib/open-sandbox",
    "/usr/local/lib/open-sandbox/egress-proxy.py",
    "/usr/local/lib/open-sandbox/sandbox-checks.py",
    "/usr/local/lib/open-sandbox/sandbox-tools.py",
]:
    try:
        st = os.stat(path)
    except OSError as e:
        check(False, f"{path} is root-owned and read-only", type(e).__name__)
        continue
    root_owned = st.st_uid == 0
    writable = os.access(path, os.W_OK)
    check(
        root_owned and not writable,
        f"{path} is root-owned and read-only",
        f"uid={st.st_uid} writable={writable}",
    )


# ── 7. Process and localhost ─────────────────────────────────────────

heading("Process is unprivileged", "process")

check(os.getuid() != 0, "not running as root", f"uid={os.getuid()}")
check(user == "agent", "running as the agent user", f"user={user}")


def proc_status() -> dict[str, str]:
    """Parse /proc/self/status into a dict, or {} if it cannot be read."""
    fields: dict[str, str] = {}
    try:
        with open("/proc/self/status") as f:
            for line in f:
                key, sep, value = line.partition(":")
                if sep:
                    fields[key.strip()] = value.strip()
    except OSError:
        pass
    return fields


_status = proc_status()

# The entrypoint drops every capability set and sets no-new-privs once the
# ruleset is installed. If it did not, a setuid-root binary would hand the
# agent back whatever the bounding set still carries — including NET_ADMIN,
# which would let it rewrite the firewall. Verify the effect, not the intent.
check(
    _status.get("NoNewPrivs") == "1",
    "no_new_privs is set",
    f"NoNewPrivs={_status.get('NoNewPrivs', '<unknown>')}",
)
for _cap, _label in [
    ("CapInh", "inheritable"),
    ("CapPrm", "permitted"),
    ("CapEff", "effective"),
    ("CapBnd", "bounding"),
]:
    _val = _status.get(_cap, "")
    check(
        _val == "0000000000000000",
        f"{_label} capability set is empty",
        f"{_cap}={_val or '<unknown>'}",
    )

heading("Localhost port binding works", "local_bind")

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    _, port = s.getsockname()
    s.close()
    check(True, "bind() to 127.0.0.1:0 succeeds", f"bound to 127.0.0.1:{port}")
except Exception as e:
    check(False, "bind() to 127.0.0.1:0 succeeds", f"{type(e).__name__}: {e}")


# ── 8. System file ownership ─────────────────────────────────────────
#
# Nothing in the system paths should belong to the agent. A tarball extracted
# with its archive's uid does exactly that, leaving a binary the agent can
# rewrite in a directory that is otherwise read-only.

heading("System files are root-owned", "ownership")

_uid = os.getuid()
_owned: list[str] = []
for _root in ["/usr", "/etc", "/opt", "/bin", "/sbin"]:
    for _dirpath, _dirnames, _filenames in os.walk(_root):
        for _name in _dirnames + _filenames:
            _path = os.path.join(_dirpath, _name)
            try:
                if os.lstat(_path).st_uid == _uid:
                    _owned.append(_path)
            except OSError:
                pass
check(
    not _owned,
    "no files outside the workdir are owned by the agent",
    f"{len(_owned)} owned by uid {_uid}: {', '.join(_owned[:5])}" if _owned else "none",
)


# ── Summary ────────────────────────────────────────────────────────────


def _ok(key: str) -> str:
    return "ok" if sections.get(key, False) else "FAIL"


_fs = "ok" if sections.get("fs_ro", False) and sections.get("fs_rw", False) else "FAIL"
_proxy = "ok" if sections.get("proxy", False) and sections.get("proxy_env", False) else "FAIL"

print(f"\n{'─' * 46}")
print(f"  Direct egress:  {_ok('direct'):4s}  DNS and raw TCP dropped")
print(f"  Proxy:          {_proxy:4s}  allowlist enforced, env routed")
print(f"  Credentials:    {_ok('creds'):4s}  not in the environment")
print(f"  Filesystem:     {_fs:4s}  system read-only, workdir writable")
print(f"  Configuration:  {_ok('config'):4s}  root-owned, read-only")
print(f"  Process:        {_ok('process'):4s}  unprivileged, no caps")
print(f"  Ownership:      {_ok('ownership'):4s}  system files root-owned")
print(f"  Localhost:      {_ok('local_bind'):4s}  bind() to 127.0.0.1 works")
print(f"{'─' * 46}")
print(f"{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
