# Sandbox Environment

**At the start of every session: read this entire file before doing any work.**
This is an ephemeral container — nothing outside `/home/agent/code` persists
between sessions. All operational knowledge lives here.

Ubuntu container VM running as the unprivileged user `agent`.
`/home/agent/code` is a persistent volume mount of the host project — work
there. Everything else in the container is ephemeral. Shell is bash.
Installed tooling: `git`, `rg` (ripgrep), `jq`, `gcc`, `make`; Rust (`cargo`,
`rustc`, `rust-analyzer`, `clippy`, `rustfmt`, `cargo-fuzz`, `cargo-llvm-cov`,
`wasm-pack`, `wasm-bindgen`);
Python (`python3`, `uv`, `basedpyright`); TypeScript (`node`, `pnpm`, `tsc`,
`biome`, `typescript-language-server`); `duckdb`; `pandoc` and `typst` for
document/PDF generation; `emacs`.

## Intent

Your role is to make code changes. The host user owns the git history and all
network operations. Focus on reading, editing, building, and testing code within
the mounted project directory.

## Network

You have no direct network access. Every packet you send is dropped by the
container firewall. The only way out is the HTTP proxy at
`http://127.0.0.1:3128`, which `HTTP_PROXY` and `HTTPS_PROXY` already point at,
and it forwards only to the domains listed in `/etc/open-sandbox/allowlist.txt`.

Read that file when you need to know what is reachable. If a fetch or an
install fails with `403` and `not in the allowlist`, that is the proxy, not a
broken network — say so and stop rather than looking for another route. Adding
a domain is the host user's decision.

## Web search

Tavily is available as MCP tools (search, extract, map, crawl) under the
`tavily` MCP server. When you need current web data, call those tools. Do not
`webfetch` arbitrary URLs — the proxy refuses anything off the allowlist — use
Tavily's extract tool to read a specific page instead.

## Commit messages

The host user owns the git history and signs their own commits, and this sandbox
holds none of their keys. So never run `git commit` — do not create commits.

When the user asks for one, stage the intended files with `git add` and propose
a succinct commit message they can commit on the host. Write it by these rules:

1. Separate subject from body with a blank line
2. Limit the subject line to 50 characters
3. Capitalize the subject line
4. Do not end the subject line with a period
5. Use the imperative mood in the subject line
6. Wrap the body at 72 characters
7. Use the body to explain what and why vs. how

Do not use conventional commit prefixes (feat:, fix:, chore:, etc.).
Avoid listing implementation details; the code speaks for itself.

## Dependencies

Always ask before adding a new dependency to any project. The user reviews all
dependencies before they are added. Cargo, pip, and the npm registry are on the
egress allowlist and gated by the agent's permission rules, but adding a
dependency is a review decision, not a network one.

## Rust

Binaries are at:
- debug: `/home/agent/cargo-target/debug/<name>`
- release: `/home/agent/cargo-target/release/<name>`

Never use `./target/` paths — `CARGO_TARGET_DIR` is set automatically.

Build WebAssembly for the browser or JS with the preinstalled
`wasm32-unknown-unknown` target: `cargo build --target wasm32-unknown-unknown`,
or drive the full js/npm bundle with `wasm-pack build`. The target's std ships
in the image, because `static.rust-lang.org` is not on the egress allowlist, so
`rustup target add` cannot run at runtime.

## Python

Use `uv` for all package management (`uv add`, `uv run`, `uv sync`). uv refuses
to resolve a distribution uploaded in the last week; escape a single package
with `exclude-newer-package` when a fix is urgent.

## TypeScript

Node LTS runs the show, managed by `fnm`; the package manager is `pnpm`. Add
dependencies with `pnpm add`, type-check with `tsc --noEmit`, and lint and
format with `biome`. Vite and Vitest are installed per project. Global tools
land in `~/.local/bin`, and the pnpm store and npm cache live under `~/.cache`,
so only project sources land on the mounted volume.

Dependency installs are hardened by default. Both pnpm and npm refuse to
resolve a version published in the last week; pnpm fails closed on too-new
versions, refuses a trust downgrade, and blocks exotic (git/tarball)
transitive sources; npm runs no lifecycle scripts. Override any of these only
for a specific, deliberate reason, and expect installs of very new packages to
fail until they are a week old.

## DuckDB

Prefer `duckdb` over loading data into Python with pandas or similar for
querying CSV, Parquet, JSON, or other data files.

## Commands

- `/verify` — run the sandbox isolation and toolchain checks
- `/commit` — draft a commit message for the staged changes
