#!/bin/bash
# open-sandbox container entrypoint.
#
# Runs as root, in this order:
#
#   1. hands the OpenRouter key to OpenCode through its own auth file and
#      drops it from the environment the agent process will inherit
#   2. maps host.container.internal to the Mac, for a model served there
#   3. installs an nftables ruleset that denies every outbound packet except
#      the ones the proxy user sends
#   4. starts the domain-allowlisting proxy as that user
#   5. drops to the unprivileged 'agent' user and execs the agent CLI
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
# The proxy logs nothing; this only catches why it failed to start, and stays
# inside the container.
PROXY_ERR=/run/open-sandbox-proxy.err
AUTH_FILE="${AGENT_HOME}/.local/share/opencode/auth.json"
OPENROUTER_KEY_FILE="${AGENT_HOME}/.local/share/opencode/openrouter-key"
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
# OpenCode v2 takes the provider key from the file named by
# providers.openrouter.settings.apiKey, which opencode.json points at through
# {file:...}. The legacy auth.json is kept as well, for v1 and for tools that
# expect it. Both forms keep the key out of the agent process environment, so it
# stays out of /proc/*/environ and out of any subprocess the agent spawns. It is
# still readable at rest by the agent user, which it has to be — the agent is
# the thing calling the API. The Tavily key gets the same treatment: it lands in
# a file that the MCP header substitutes via {file:...}, so no secret rides in
# the agent's environment.

umask 077

install -d -o "$AGENT_USER" -g "$AGENT_USER" -m 0700 "$(dirname "$AUTH_FILE")"

printf '{"openrouter":{"type":"api","key":"%s"}}\n' "$OPENROUTER_API_KEY" > "$AUTH_FILE"

chown "$AGENT_USER:$AGENT_USER" "$AUTH_FILE"
chmod 0600 "$AUTH_FILE"

# No trailing newline: the provider hands this file's contents to an
# Authorization header, where a line break would be invalid.
printf '%s' "$OPENROUTER_API_KEY" > "$OPENROUTER_KEY_FILE"
chown "$AGENT_USER:$AGENT_USER" "$OPENROUTER_KEY_FILE"
chmod 0600 "$OPENROUTER_KEY_FILE"

# Tavily is optional, so an absent key becomes an empty file and an empty
# bearer token rather than a missing {file:...} target. No trailing newline,
# or the Authorization header gains an invalid line break.
printf '%s' "${TAVILY_API_KEY:-}" > "$TAVILY_KEY_FILE"
chown "$AGENT_USER:$AGENT_USER" "$TAVILY_KEY_FILE"
chmod 0600 "$TAVILY_KEY_FILE"

umask 022

# ── 3. The Mac's address ────────────────────────────────────────────────────
#
# The container's default gateway is the Mac itself (192.168.64.1 on the
# default network), so a model server listening there is reachable directly.
# Naming it host.container.internal keeps the allowlist entry and the mlx
# provider's baseURL independent of the subnet. Nothing here opens a path:
# the proxy still allows only the host:port entries in the allowlist. A
# missing route or an unwritable /etc/hosts only disables the local model.

gateway=""
while read -r _ destination hex _; do
    if [ "$destination" = 00000000 ] && [ "$hex" != 00000000 ]; then
        # /proc/net/route stores the address as little-endian hex.
        gateway=$(printf '%d.%d.%d.%d' \
            "0x${hex:6:2}" "0x${hex:4:2}" "0x${hex:2:2}" "0x${hex:0:2}")
        break
    fi
done < /proc/net/route

if [ -n "$gateway" ]; then
    printf '%s host.container.internal\n' "$gateway" >> /etc/hosts ||
        printf 'open-sandbox: could not map host.container.internal; the local model is unreachable\n' >&2
fi

# ── 4. Egress firewall ──────────────────────────────────────────────────────
#
# Output policy is drop. Loopback is accepted so the agent can reach the proxy
# and bind local dev servers. Only the proxy UID is allowed off the machine,
# which covers its DNS lookups as well as its TLS connections. Everything the
# agent sends directly — DNS, raw sockets, git over SSH — dies here with
# EPERM rather than reaching a network. The heredoc is unquoted so the rule
# names the same UID the proxy is started as below.

nft -f - <<NFT || die "failed to install the nftables ruleset; refusing to run without an egress firewall"
table inet open_sandbox {
    chain output {
        type filter hook output priority filter; policy drop;

        oifname "lo" accept
        ct state established,related accept
        meta skuid ${PROXY_UID} accept

        counter comment "denied direct egress"
    }
}
NFT

nft list table inet open_sandbox >/dev/null 2>&1 ||
    die "nftables reported success but the ruleset is not present; refusing to run"

# ── 5. Allowlist proxy ──────────────────────────────────────────────────────

setpriv --reuid="$PROXY_UID" --regid="$PROXY_UID" --clear-groups \
    --inh-caps=-all --bounding-set=-all --no-new-privs \
    python3 /usr/local/lib/open-sandbox/egress-proxy.py >/dev/null 2>"$PROXY_ERR" &

# The probe opens fd 3 in a subshell, so the subshell's exit closes it.
for _ in $(seq 1 100); do
    if (exec 3<>"/dev/tcp/127.0.0.1/${PROXY_PORT}") 2>/dev/null; then
        proxy_up=1
        break
    fi
    sleep 0.1
done

[ "${proxy_up:-}" = 1 ] || {
    sed 's/^/open-sandbox: proxy: /' "$PROXY_ERR" >&2 || true
    die "the allowlist proxy did not start; refusing to run without it"
}

# ── 6. Drop privileges and run the agent ────────────────────────────────────
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
setpriv_cmd=(
    setpriv
    --reuid="$agent_uid" --regid="$agent_gid" --init-groups
    --inh-caps=-all --bounding-set=-all --no-new-privs
)
agent_env=(
    env -u OPENROUTER_API_KEY -u TAVILY_API_KEY
    HOME="$AGENT_HOME" USER="$AGENT_USER" LOGNAME="$AGENT_USER"
    HTTP_PROXY="$PROXY_URL" HTTPS_PROXY="$PROXY_URL" ALL_PROXY="$PROXY_URL"
    http_proxy="$PROXY_URL" https_proxy="$PROXY_URL" all_proxy="$PROXY_URL"
    NO_PROXY="localhost,127.0.0.1,::1" no_proxy="localhost,127.0.0.1,::1"
    OPENCODE_DISABLE_AUTOUPDATE=true
    OPENCODE_DISABLE_SHARE=true
    OPENCODE_DISABLE_DEFAULT_PLUGINS=true
    OPENCODE_DISABLE_LSP_DOWNLOAD=true
)

exec "${setpriv_cmd[@]}" "${agent_env[@]}" "$@"
