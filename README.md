# open-sandbox

Coding agents are most useful when they can edit files and run commands on their own. You don't
want to give them access to everything on your machine, and you don't want to babysit every action
they take. `open-sandbox` runs [OpenCode](https://opencode.ai) against
[OpenRouter](https://openrouter.ai) in a lightweight Linux VM (via
[Apple Containers](https://github.com/apple/container) on macOS) with only your project directory
mounted. For Claude Code, see my [claude-sandbox](https://github.com/aldrin/claude-sandbox) instead.

> This is a personal tool with a permissive default configuration. Review
> the sandbox settings carefully before relying on it for your work.

The VM provides the isolation. The agent runs as an unprivileged user. A firewall drops all direct
egress by default. A domain-allowlisting proxy runs as the only UID the kernel lets off the machine,
and it forwards to the hosts in `.open-sandbox/allowlist.txt` and nothing else. Everything fails
closed. If the firewall or the proxy cannot start, the container does not start.

## Install

```bash
cargo install --git https://github.com/aldrin/open-sandbox.git
```

## Quick start

Store your OpenRouter API key in the macOS keychain once, then `init`, `build`, and `run` in a
project directory:

```bash
security add-generic-password -a "$USER" -s openrouter-api-key -w

open-sandbox init
open-sandbox build
open-sandbox run
```

`init` scaffolds `.open-sandbox/`. You can edit the files, and `init --force` rewrites them.
`build` ships the image, so start Apple Containers first with `container system start`. `run`
launches OpenCode with your project mounted at `/home/agent/code`. The container is destroyed on
exit.

Optionally store a [Tavily](https://tavily.com) key under the `tavily-api-key` service to enable the
web-search tools.

## Sandbox

The sandbox keeps the agent off the network. Only hosts on the allowlist are reachable, and only on
ports 80 and 443. The API key never appears in the agent's environment, because the entrypoint
writes it to OpenCode's auth file.

Keep these three limits in mind. The OpenRouter and Tavily keys stay readable by the agent at rest,
so scope them with spending limits. OpenCode's permission rules, such as the git deny and ask
settings, run inside the agent's own process. They prevent accidents. The firewall and the proxy
form the real boundary. The agent can also write to the git history in the mounted directory, so
treat the mount accordingly.

## Verifying

Run `/verify` inside the container to probe isolation, toolchain, and configuration. The proxy
writes one JSON object per request to `.open-sandbox/logs/egress.jsonl`, readable from the host and
queryable with DuckDB:

```bash
duckdb -c "SELECT * FROM read_json_auto('.open-sandbox/logs/egress.jsonl')"
```

## Customizing

`.open-sandbox/` holds the parts meant to be edited: the `Containerfile` (toolchain),
`allowlist.txt` (reachable domains), `opencode.json` (model and permissions), and `AGENTS.md`
(agent instructions). `status` reports files missing after a binary upgrade. It does not flag files
you edited. Every extra domain is a place the agent can send your code.
