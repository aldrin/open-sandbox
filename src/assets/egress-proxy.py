#!/usr/bin/env python3
"""Domain-allowlisting HTTP proxy for the open-sandbox container.

Runs as the 'egress' user (uid 900), the only UID the nftables ruleset lets
off the machine. The agent has no direct network access at all, so this
process is the sole path out, and it forwards only to hosts named in
/etc/open-sandbox/allowlist.txt.

Supports the two things a proxy client actually sends:

  CONNECT host:port      tunnels bytes after a 200, used for every https URL
  GET http://host/path   absolute-form plain HTTP, rewritten to origin form

Everything else is refused. Every decision is logged as a single JSON object
per line (JSON Lines) to stdout. The entrypoint redirects stdout to a file
inside the mounted project directory so the host can read it and query it with
DuckDB, e.g.:

  duckdb -c "SELECT * FROM read_json_auto('.open-sandbox/egress.jsonl')"
"""

from __future__ import annotations

import ipaddress
import json
import os
import select
import socket
import socketserver
import sys
import time
from urllib.parse import urlsplit

ALLOWLIST_PATH = os.environ.get("OPEN_SANDBOX_ALLOWLIST", "/etc/open-sandbox/allowlist.txt")
LISTEN_HOST = os.environ.get("OPEN_SANDBOX_PROXY_HOST", "127.0.0.1")
LISTEN_PORT = int(os.environ.get("OPEN_SANDBOX_PROXY_PORT", "3128"))

ALLOWED_PORTS = {80, 443}
CONNECT_TIMEOUT = 15.0
IDLE_TIMEOUT = 300.0
MAX_HEADER_BYTES = 32 * 1024
BUFSIZE = 65536


# ── Allowlist ───────────────────────────────────────────────────────────────


def load_allowlist(path: str) -> tuple[frozenset[str], tuple[str, ...]]:
    """Parse the allowlist into (exact names, suffix rules).

    A line starting with '.' is a suffix rule matching the domain and all of
    its subdomains. Any other line is an exact host name.
    """
    exact: set[str] = set()
    suffixes: list[str] = []
    try:
        with open(path) as f:
            lines = f.readlines()
    except OSError as e:
        emit("FATAL", "allowlist_read", path=path, error_type=type(e).__name__, error=str(e))
        raise SystemExit(1)

    for line in lines:
        entry = line.split("#", 1)[0].strip().lower().rstrip(".")
        if not entry:
            continue
        if entry.startswith("."):
            suffixes.append(entry)
        else:
            exact.add(entry)
    return frozenset(exact), tuple(suffixes)


def host_allowed(host: str, exact: frozenset[str], suffixes: tuple[str, ...]) -> bool:
    host = host.strip().lower().rstrip(".")
    # Strip an IPv6 literal's brackets so a bracketed address cannot slip past
    # a rule set that only ever names domains.
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if not host:
        return False
    if host in exact:
        return True
    return any(host == s[1:] or host.endswith(s) for s in suffixes)


def split_host_port(target: str, default_port: int) -> tuple[str, int]:
    """Split 'host:port', 'host', or '[v6]:port' into (host, port)."""
    if target.startswith("["):
        close = target.find("]")
        if close == -1:
            raise ValueError("unterminated IPv6 literal")
        host = target[: close + 1]
        rest = target[close + 1 :]
        port = int(rest[1:]) if rest.startswith(":") else default_port
        return host, port
    if target.count(":") == 1:
        host, _, port = target.partition(":")
        return host, int(port)
    return target, default_port


def is_public_ip(ip: object) -> bool:
    """True only for globally routable addresses.

    The proxy is the sole path off the machine, so it must not dial things the
    allowlist's DNS could theoretically nominate that are really loopback,
    link-local, private, reserved, unspecified, or multicast — the 169.254.0.0
    cloud-metadata range among them. Rejecting those here keeps an allowlisted
    name from ever becoming a pivot into the host's local network.
    """
    try:
        addr = ipaddress.ip_address(str(ip))
    except ValueError:
        return False
    # is_global alone is not enough: Python reports multicast addresses as
    # global, and dialing a multicast group is as wrong as dialing loopback.
    return addr.is_global and not addr.is_multicast


# ── Logging ─────────────────────────────────────────────────────────────────
#
# Every event is emitted as a single JSON object per line (JSON Lines). The
# common keys are:
#
#   ts        ISO-8601 UTC timestamp of the event
#   level     one of FATAL, ERROR, WARN, ALLOW, DENY, INFO
#   event     a stable machine-readable name for the kind of event
#
# Events that concern a specific request also carry the request's method, host,
# port, and (for plain HTTP) path. Denials carry a human-readable `detail` and,
# where known, a machine-comparable `reason`. `json.dumps` defaults to
# ensure_ascii=True, so any byte decoded as latin-1 from a client survives the
# JSON encoding without becoming invalid UTF-8.


def emit(level: str, event: str, **fields: object) -> None:
    """Write one JSON line for a single event.

    `fields` must be JSON-serialisable. Values that are not (a socket address,
    say) are stringified so a bad value never breaks the whole log stream.
    """
    record: dict[str, object] = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "level": level,
        "event": event,
    }
    for key, value in fields.items():
        try:
            json.dumps(value)
        except (TypeError, ValueError):
            value = str(value)
        record[key] = value
    sys.stdout.write(json.dumps(record, sort_keys=True) + "\n")
    sys.stdout.flush()


# ── Proxy ───────────────────────────────────────────────────────────────────


class Handler(socketserver.StreamRequestHandler):
    # Unbuffered, so that after parsing the request head there is nothing
    # stranded in a Python-side buffer and the raw socket can be relayed
    # directly.
    rbufsize = 0
    timeout = CONNECT_TIMEOUT

    allowlist: tuple[frozenset[str], tuple[str, ...]] = (frozenset(), ())

    def handle(self) -> None:
        try:
            self._handle()
        except (OSError, ValueError) as e:
            emit("ERROR", "handler_error", error_type=type(e).__name__, error=str(e))

    def _handle(self) -> None:
        request_line = self._read_line()
        if request_line is None:
            self._refuse(431, "Request Header Fields Too Large", "request line too long")
            return
        if not request_line:
            return

        parts = request_line.split()
        if len(parts) != 3:
            self._refuse(400, "Bad Request", f"malformed request line: {request_line!r}")
            return
        method, target, version = parts

        headers = self._read_headers()
        if headers is None:
            self._refuse(431, "Request Header Fields Too Large", "header block too large")
            return

        if method.upper() == "CONNECT":
            self._do_connect(target)
        elif "://" in target:
            self._do_plain(method, target, version, headers)
        else:
            self._refuse(
                400,
                "Bad Request",
                f"{method} {target}: not a proxy request (origin-form URI)",
            )

    # ── Request parsing ─────────────────────────────────────────────────

    def _read_line(self) -> str | None:
        raw = self.rfile.readline(MAX_HEADER_BYTES)
        if not raw:
            return ""
        if not raw.endswith(b"\n"):
            # Hit the size limit, or the peer dropped mid-line. Either way the
            # line is incomplete and must not be parsed as if it were valid.
            return None
        return raw.decode("latin-1").strip()

    def _read_headers(self) -> list[str] | None:
        headers: list[str] = []
        total = 0
        while True:
            raw = self.rfile.readline(MAX_HEADER_BYTES)
            if not raw:
                return headers
            total += len(raw)
            if total > MAX_HEADER_BYTES:
                return None
            line = raw.decode("latin-1").rstrip("\r\n")
            if not line:
                return headers
            headers.append(line)

    # ── CONNECT ─────────────────────────────────────────────────────────

    def _do_connect(self, target: str) -> None:
        try:
            host, port = split_host_port(target, 443)
        except ValueError as e:
            self._refuse(400, "Bad Request", f"CONNECT {target}: {e}")
            return

        if not self._permitted(host, port, f"CONNECT {target}"):
            return

        upstream = self._connect_upstream(host, port, f"CONNECT {target}")
        if upstream is None:
            return

        emit("ALLOW", "connect", method="CONNECT", host=host, port=port)
        self.connection.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        self._relay(upstream)

    # ── Plain HTTP ──────────────────────────────────────────────────────

    def _do_plain(self, method: str, target: str, version: str, headers: list[str]) -> None:
        url = urlsplit(target)
        if url.scheme != "http":
            self._refuse(400, "Bad Request", f"{method} {target}: unsupported scheme {url.scheme!r}")
            return

        host = url.hostname or ""
        try:
            port = url.port or 80
        except ValueError:
            self._refuse(400, "Bad Request", f"{method} {target}: invalid port")
            return
        if not self._permitted(host, port, f"{method} {target}"):
            return

        upstream = self._connect_upstream(host, port, f"{method} {target}")
        if upstream is None:
            return

        path = url.path or "/"
        if url.query:
            path = f"{path}?{url.query}"

        # Hop-by-hop headers must not be forwarded, and the response is relayed
        # as an opaque byte stream, so persistent connections are not an option.
        forwarded = [
            h
            for h in headers
            if h.split(":", 1)[0].strip().lower()
            not in (
                "proxy-connection",
                "proxy-authorization",
                "connection",
                "keep-alive",
                "te",
                "trailer",
                "upgrade",
            )
        ]
        forwarded.append("Connection: close")

        head = f"{method} {path} {version}\r\n" + "\r\n".join(forwarded) + "\r\n\r\n"
        emit("ALLOW", "request", method=method, host=host, port=port, path=path)
        upstream.sendall(head.encode("latin-1"))
        self._relay(upstream)

    # ── Shared ──────────────────────────────────────────────────────────

    def _permitted(self, host: str, port: int, what: str) -> bool:
        exact, suffixes = self.allowlist
        if port not in ALLOWED_PORTS:
            self._refuse(403, "Forbidden", f"{what}: port {port} is not proxied")
            return False
        if not host_allowed(host, exact, suffixes):
            self._refuse(403, "Forbidden", f"{what}: {host} is not in the allowlist")
            return False
        return True

    def _connect_upstream(self, host: str, port: int, what: str) -> socket.socket | None:
        try:
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except OSError as e:
            self._refuse(502, "Bad Gateway", f"{what}: {type(e).__name__}: {e}", quiet=True)
            emit("ERROR", "dns_failure", host=host, port=port,
                 error_type=type(e).__name__, error=str(e))
            return None

        candidates = [
            (family, socktype, proto, sa)
            for family, socktype, proto, _, sa in infos
            if is_public_ip(sa[0])
        ]
        if not candidates:
            self._refuse(502, "Bad Gateway", f"{what}: no public address", quiet=True)
            emit("DENY", "non_public_address", host=host, port=port)
            return None

        last_error: OSError | None = None
        for family, socktype, proto, sa in candidates:
            sock = socket.socket(family, socktype, proto)
            try:
                sock.settimeout(CONNECT_TIMEOUT)
                sock.connect(sa)
            except OSError as e:
                last_error = e
                sock.close()
                continue
            sock.settimeout(None)
            return sock

        self._refuse(502, "Bad Gateway", f"{what}: {type(last_error).__name__}: {last_error}", quiet=True)
        emit("ERROR", "connect_failure", host=host, port=port,
             error_type=type(last_error).__name__, error=str(last_error))
        return None

    def _refuse(self, code: int, reason: str, detail: str, quiet: bool = False) -> None:
        if not quiet:
            emit("DENY", "refused", status=code, reason=reason, detail=detail)
        body = f"open-sandbox: {detail}\n".encode()
        head = (
            f"HTTP/1.1 {code} {reason}\r\n"
            f"Content-Type: text/plain\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("latin-1")
        try:
            self.connection.sendall(head + body)
        except OSError:
            pass

    def _relay(self, upstream: socket.socket) -> None:
        client = self.connection
        client.settimeout(None)
        socks = [client, upstream]
        try:
            while socks:
                readable, _, errored = select.select(socks, [], socks, IDLE_TIMEOUT)
                if errored or not readable:
                    break
                for sock in readable:
                    peer = upstream if sock is client else client
                    try:
                        data = sock.recv(BUFSIZE)
                    except OSError:
                        return
                    if not data:
                        # One side is done sending. Half-close the other and
                        # keep draining until it finishes too.
                        try:
                            peer.shutdown(socket.SHUT_WR)
                        except OSError:
                            pass
                        socks.remove(sock)
                        break
                    try:
                        peer.sendall(data)
                    except OSError:
                        return
        finally:
            try:
                upstream.close()
            except OSError:
                pass


class ProxyServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main() -> int:
    exact, suffixes = load_allowlist(ALLOWLIST_PATH)
    Handler.allowlist = (exact, suffixes)

    rules = sorted(exact) + sorted(suffixes)
    emit("INFO", "startup",
         uid=os.getuid(), host=LISTEN_HOST, port=LISTEN_PORT,
         allowlist_path=ALLOWLIST_PATH, rule_count=len(rules), rules=", ".join(rules))
    if not rules:
        emit("WARN", "empty_allowlist")

    try:
        server = ProxyServer((LISTEN_HOST, LISTEN_PORT), Handler)
    except OSError as e:
        emit("FATAL", "bind_failure", host=LISTEN_HOST, port=LISTEN_PORT,
             error_type=type(e).__name__, error=str(e))
        return 1

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
