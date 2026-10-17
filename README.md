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
open-sandbox status
open-sandbox run
```

`init` scaffolds `.open-sandbox/`. You can edit the files, and `init --force` rewrites them.
`build` ships the image, so start Apple Containers first with `container system start`. `status`
checks the workspace, keychain keys, container infrastructure, the container network, and the local
model endpoint. `run` launches OpenCode with your project mounted at `/home/agent/code`. The
container is destroyed on exit.

Optionally store a [Tavily](https://tavily.com) key under the `tavily-api-key` service to enable the
web-search tools.

## Local model on the Mac host

To use a model running on your Mac instead of OpenRouter, serve it with
[open-mlx](https://github.com/aldrin/open-mlx), which runs `mlx_lm.server` on
the Mac's container-network address at port 27182. The workspace is already
wired for it: the entrypoint maps `host.container.internal` to the Mac, the
allowlist permits `host.container.internal:27182`, and `opencode.json` defines
the `mlx` provider. In a session, run `/models` and choose
`mlx/default_model`; for a hard step, cycle to its `think` variant with the
`variant_cycle` keybind, which lets the model reason before it answers.

## Sandbox

The sandbox keeps the agent off the network. Ordinary allowlist entries are reachable only on ports
80 and 443; an explicit `host:port` entry is reachable only on that port. The API key never appears
in the agent's environment, because the entrypoint writes it to a key file that OpenCode reads
through its config.

Keep these limits in mind. The OpenRouter and Tavily keys stay readable by the agent at rest, so
scope them with spending limits. OpenCode's permission rules, such as the git deny and ask settings,
run inside the agent's own process. They prevent accidents. The firewall and the proxy form the real
boundary, and what they bound is which hosts the container connects to, not where data can end up.
The proxy does not look inside HTTPS, and an allowlisted service can fetch on the agent's behalf:
Tavily's extract tool reads any URL it is given. Leave the Tavily key unset if that matters.

The agent can write anything in the mounted project, and some files there act on the host. Git
hooks run on your Mac the next time you run git in the project, so `.git/hooks` is mounted
read-only. The rest of `.git` stays writable so the agent can stage changes; `.git/config` can also
name commands, and `.open-sandbox/` is what the next `build` bakes into the image, so look over
changes to either before you run git or `build`.

Files the image installs as root, such as the allowlist, the proxy, and OpenCode's config, are
read-only to the agent. That stops accidental edits. A deliberate agent could still rename
`~/.config/opencode` aside, since it owns `~/.config`; the firewall and proxy are what it cannot
get around.

OpenCode v2 does not run language servers itself. The image still installs `rust-analyzer`,
`basedpyright`, and `typescript-language-server` so the agent can use them explicitly.

## Verifying

Run `open-sandbox status` on the host to check the workspace, keychain keys, container
infrastructure, the container network, and the local model endpoint. Inside the container, run
`/verify` to probe isolation, toolchain, and configuration. The proxy keeps no log; a refused
request gets a short reason in its `403` response, which the agent sees.

## Customizing

`.open-sandbox/` holds the parts meant to be edited: the `Containerfile` (toolchain),
`allowlist.txt` (reachable domains), `opencode.json` (model and permissions), `cli.json` (terminal
settings), `commands/`, and `AGENTS.md` (agent instructions). `status` reports files missing after a
binary upgrade. It does not flag files you edited. Every extra domain is a place the agent can send
your code.
