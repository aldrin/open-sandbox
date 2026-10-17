#!/usr/bin/env python3
"""Domain-allowlisting HTTP proxy for the open-sandbox container.

Runs as the 'egress' user (uid 900), the only UID the nftables ruleset lets
off the machine. The agent has no direct network access at all, so this
process is the sole path out, and it forwards only to hosts named in
/etc/open-sandbox/allowlist.txt.

An allowlist entry of the form 'host:port' is a host service: it is allowed
on that port only, and the proxy may dial a non-public address for it. That
is how a model server on the Mac host is reached at host.container.internal,
which the entrypoint maps to the Mac's container network address, without
opening private networks generally.

Supports the two things a proxy client actually sends:

  CONNECT host:port      tunnels bytes after a 200, used for every https URL
  GET http://host/path   absolute-form plain HTTP, rewritten to origin form

Everything else is refused, with a short plain-text reason the client can
show.

What this decides is which hosts the container connects to, by name and port.
It does not inspect what is sent: a CONNECT tunnel is relayed as opaque bytes,
so the TLS inside it is between the client and the server. Nor does it limit
where data ends up. An allowlisted service that fetches URLs on request, as
Tavily's extract tool does, reaches whatever the agent asks it to.

Nothing is logged. Only a failure to start is reported, on stderr.
"""

from __future__ import annotations

import ipaddress
import os
import select
import socket
import socketserver
import sys
from typing import NoReturn
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


def load_allowlist(
    path: str,
) -> tuple[frozenset[str], tuple[str, ...], dict[str, frozenset[int]], frozenset[str]]:
    """Parse the allowlist into (exact names, suffix rules, host services, bare hosts).

    A line starting with '.' is a suffix rule matching the domain and all of
    its subdomains. A line of the form 'host:port' is a host service: it
    matches that host on that port only, and the proxy may connect to a
    non-public address for it. Any other line is an exact host name on the
    default ports. A host named both with and without a port is reachable on
    the default ports and on its explicit service ports.
    """
    exact: set[str] = set()
    suffixes: list[str] = []
    services: dict[str, set[int]] = {}
    bare: set[str] = set()
    try:
        with open(path) as f:
            lines = f.readlines()
    except OSError as e:
        fail(f"cannot read the allowlist {path}: {e}")

    for line in lines:
        entry = line.split("#", 1)[0].strip().lower().rstrip(".")
        if not entry:
            continue
        if entry.startswith("."):
            suffixes.append(entry)
            continue
        host, port = parse_allowlist_entry(entry)
        exact.add(host)
        if port is not None:
            services.setdefault(host, set()).add(port)
        else:
            bare.add(host)
    return (
        frozenset(exact),
        tuple(suffixes),
        {host: frozenset(ports) for host, ports in services.items()},
        frozenset(bare),
    )


def parse_allowlist_entry(entry: str) -> tuple[str, int | None]:
    """Split an allowlist entry into (host, port), or (host, None).

    Only a trailing ':number' is a port, so a bare host and a bracketed IPv6
    literal are both treated as plain entries.
    """
    if entry.startswith("["):
        close = entry.find("]")
        rest = entry[close + 1 :] if close != -1 else ""
        if rest.startswith(":") and rest[1:].isdigit():
            return entry[: close + 1], int(rest[1:])
        return entry, None
    host, sep, port = entry.rpartition(":")
    if sep and port.isdigit():
        return host, int(port)
    return entry, None


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


def fail(message: str) -> NoReturn:
    print(f"egress-proxy: {message}", file=sys.stderr, flush=True)
    raise SystemExit(1)


# ── Proxy ───────────────────────────────────────────────────────────────────


class Handler(socketserver.StreamRequestHandler):
    # Unbuffered, so that after parsing the request head there is nothing
    # stranded in a Python-side buffer and the raw socket can be relayed
    # directly.
    rbufsize = 0
    timeout = CONNECT_TIMEOUT

    allowlist: tuple[
        frozenset[str], tuple[str, ...], dict[str, frozenset[int]], frozenset[str]
    ] = (frozenset(), (), {}, frozenset())

    def handle(self) -> None:
        try:
            self._handle()
        except (OSError, ValueError):
            # A broken client or upstream connection ends that connection only.
            pass

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
        # Hosts are matched case-insensitively, including host-service entries.
        host = host.lower()

        if not self._permitted(host, port, f"CONNECT {target}"):
            return

        upstream = self._connect_upstream(host, port, f"CONNECT {target}")
        if upstream is None:
            return

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
        upstream.sendall(head.encode("latin-1"))
        self._relay(upstream)

    # ── Shared ──────────────────────────────────────────────────────────

    def _permitted(self, host: str, port: int, what: str) -> bool:
        exact, suffixes, services, bare = self.allowlist
        service_ports = services.get(host)
        if service_ports is None:
            ports = set(ALLOWED_PORTS)
        else:
            ports = set(service_ports)
            if host in bare:
                ports |= set(ALLOWED_PORTS)
        if port not in ports:
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
            self._refuse(502, "Bad Gateway", f"{what}: {type(e).__name__}: {e}")
            return None

        # A host service (an explicit host:port entry) is reached at a
        # non-public address: the Mac's address on the container network.
        # Everything else must still resolve to a globally routable
        # address, so an allowlisted domain cannot become a pivot into a
        # private network.
        allow_non_public = host in self.allowlist[2]
        candidates = [
            (family, socktype, proto, sa)
            for family, socktype, proto, _, sa in infos
            if allow_non_public or is_public_ip(sa[0])
        ]
        if not candidates:
            self._refuse(403, "Forbidden", f"{what}: no public address")
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

        self._refuse(502, "Bad Gateway", f"{what}: {type(last_error).__name__}: {last_error}")
        return None

    def _refuse(self, code: int, reason: str, detail: str) -> None:
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
    Handler.allowlist = load_allowlist(ALLOWLIST_PATH)

    try:
        server = ProxyServer((LISTEN_HOST, LISTEN_PORT), Handler)
    except OSError as e:
        fail(f"cannot listen on {LISTEN_HOST}:{LISTEN_PORT}: {e}")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
