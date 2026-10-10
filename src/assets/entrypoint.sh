#!/bin/bash
# open-sandbox container entrypoint.
#
# Runs as root, in this order:
#
#   1. hands the OpenRouter key to OpenCode through its own auth file and
#      drops it from the environment the agent process will inherit
#   2. installs an nftables ruleset that denies every outbound packet except
#      the ones the proxy user sends
#   3. starts the domain-allowlisting proxy as that user
#   4. drops to the unprivileged 'agent' user and execs the agent CLI
#
# Every step is fail-closed. If the firewall cannot be installed or the proxy
# does not come up, the container exits instead of running an agent with
# unrestricted network access.

set -euo pipefail

AGENT_USER=agent
AGENT_HOME=/home/agent
PROXY_UID=900
PROXY_PORT=3128
PROXY_URL="http://127.0.0.1:${PROXY_PORT}"
# The proxy writes one JSON object per line (JSON Lines) to this file. It lives
# in the mounted project directory so the host can read it directly and query it
# with DuckDB. The directory and file are owned by 'egress' with mode 0700/0600,
# so the agent — a different UID — can neither read nor modify the log. Only the
# proxy (and root) can touch it.
LOG_DIR="${AGENT_HOME}/code/.open-sandbox/logs"
LOG_FILE="${LOG_DIR}/egress.jsonl"
AUTH_FILE="${AGENT_HOME}/.local/share/opencode/auth.json"
TAVILY_KEY_FILE="${AGENT_HOME}/.local/share/opencode/tavily-key"

die() { printf 'open-sandbox: %s\n' "$*" >&2; exit 1; }

# ── 1. Preconditions ────────────────────────────────────────────────────────

[ "$(id -u)" -eq 0 ] || die "entrypoint must start as root (uid is $(id -u))"

[ -n "${OPENROUTER_API_KEY:-}" ] ||
    die "OPENROUTER_API_KEY is not set. 'open-sandbox run' reads it from the macOS keychain and passes it in."

# The key is interpolated into JSON below. OpenRouter keys are ASCII
# alphanumerics with dashes; anything else is far more likely to be a
# quoting accident than a real credential.
case "$OPENROUTER_API_KEY" in
    *[!A-Za-z0-9_.-]*) die "OPENROUTER_API_KEY contains characters outside [A-Za-z0-9_.-]" ;;
esac

# ── 2. Credentials ──────────────────────────────────────────────────────────
#
# OpenCode reads a key from its own auth file, which takes priority over the
# environment. Writing the file here means the key never has to appear in the
# agent process environment, so it stays out of /proc/*/environ and out of any
# subprocess the agent spawns. It is still readable at rest by the agent user,
# which it has to be — the agent is the thing calling the API. The Tavily key
# gets the same treatment: it lands in a file that the MCP header substitutes
# via {file:...}, so no secret rides in the agent's environment.

umask 077

install -d -o "$AGENT_USER" -g "$AGENT_USER" -m 0700 "$(dirname "$AUTH_FILE")"

printf '{"openrouter":{"type":"api","key":"%s"}}\n' "$OPENROUTER_API_KEY" > "$AUTH_FILE"

chown "$AGENT_USER:$AGENT_USER" "$AUTH_FILE"
chmod 0600 "$AUTH_FILE"

# Tavily is optional, so an absent key becomes an empty file and an empty
# bearer token rather than a missing {file:...} target. No trailing newline,
# or the Authorization header gains an invalid line break.
printf '%s' "${TAVILY_API_KEY:-}" > "$TAVILY_KEY_FILE"
chown "$AGENT_USER:$AGENT_USER" "$TAVILY_KEY_FILE"
chmod 0600 "$TAVILY_KEY_FILE"

umask 022

# ── 3. Egress firewall ──────────────────────────────────────────────────────
#
# Output policy is drop. Loopback is accepted so the agent can reach the proxy
# and bind local dev servers. Only the proxy UID is allowed off the machine,
# which covers its DNS lookups as well as its TLS connections. Everything the
# agent sends directly — DNS, raw sockets, git over SSH — dies here with
# EPERM rather than reaching a network.

nft -f - <<'NFT' || die "failed to install the nftables ruleset; refusing to run without an egress firewall"
table inet open_sandbox {
    chain output {
        type filter hook output priority filter; policy drop;

        oifname "lo" accept
        ct state established,related accept
        meta skuid 900 accept

        counter comment "denied direct egress"
    }
}
NFT

nft list table inet open_sandbox >/dev/null 2>&1 ||
    die "nftables reported success but the ruleset is not present; refusing to run"

# ── 4. Allowlist proxy ──────────────────────────────────────────────────────

install -d -o "$PROXY_UID" -g "$PROXY_UID" -m 0700 "$LOG_DIR"
: > "$LOG_FILE"
chown "$PROXY_UID:$PROXY_UID" "$LOG_FILE"
chmod 0600 "$LOG_FILE"

# The log directory sits inside .open-sandbox/, which the agent owns. Without the
# sticky bit the agent could rename 'logs' out of the way and drop its own file
# there. The sticky bit stops a directory's owner from removing or renaming an
# entry it does not itself own, so 'logs' — owned by egress — becomes
# untouchable by the agent even though the agent owns the parent directory.
chmod u=rwx,g=rx,o=rx+t "$(dirname "$LOG_DIR")"

setpriv --reuid="$PROXY_UID" --regid="$PROXY_UID" --clear-groups \
    --inh-caps=-all --bounding-set=-all --no-new-privs \
    python3 /usr/local/lib/open-sandbox/egress-proxy.py >>"$LOG_FILE" 2>&1 &

for _ in $(seq 1 100); do
    if (exec 3<>"/dev/tcp/127.0.0.1/${PROXY_PORT}") 2>/dev/null; then
        exec 3>&- 2>/dev/null || true
        proxy_up=1
        break
    fi
    sleep 0.1
done

[ "${proxy_up:-}" = 1 ] || {
    sed 's/^/open-sandbox: proxy: /' "$LOG_FILE" >&2 || true
    die "the allowlist proxy did not start; refusing to run without it"
}

# ── 5. Drop privileges and run the agent ────────────────────────────────────
#
# The container is started with CAP_NET_ADMIN so the ruleset above could be
# installed. That capability is spent by now, so it is cleared from every set
# here — including the bounding set, which a uid change alone leaves intact.
# With no-new-privs on top, nothing the agent execs can reclaim it and rewrite
# the firewall.

agent_uid="$(id -u "$AGENT_USER")"
agent_gid="$(id -g "$AGENT_USER")"

# OpenCode's own outbound chatter is disabled at the source: no update check,
# no session sharing, no default-plugin or language-server downloads. The
# allowlist would block most of these anyway, but stopping the attempts keeps
# the egress log a record of real traffic instead of a stream of refusals. The
# models.dev catalog fetch is deliberately left on so the model list stays
# current; models.dev is allowlisted.
exec setpriv \
    --reuid="$agent_uid" --regid="$agent_gid" --init-groups \
    --inh-caps=-all --bounding-set=-all --no-new-privs \
    env -u OPENROUTER_API_KEY -u TAVILY_API_KEY \
        HOME="$AGENT_HOME" USER="$AGENT_USER" LOGNAME="$AGENT_USER" \
        HTTP_PROXY="$PROXY_URL" HTTPS_PROXY="$PROXY_URL" ALL_PROXY="$PROXY_URL" \
        http_proxy="$PROXY_URL" https_proxy="$PROXY_URL" all_proxy="$PROXY_URL" \
        NO_PROXY="localhost,127.0.0.1,::1" no_proxy="localhost,127.0.0.1,::1" \
        OPENCODE_DISABLE_AUTOUPDATE=true \
        OPENCODE_DISABLE_SHARE=true \
        OPENCODE_DISABLE_DEFAULT_PLUGINS=true \
        OPENCODE_DISABLE_LSP_DOWNLOAD=true \
        "$@"
