<p align="center">
  <img src="assets/nuvek-core.svg" alt="nuvek-core icon" width="128" height="128">
</p>

# nuvek-core

[![CI](https://github.com/jean1880/nuvek-core/actions/workflows/ci.yml/badge.svg)](https://github.com/jean1880/nuvek-core/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/nuvek-core.svg)](https://crates.io/crates/nuvek-core)
[![docs.rs](https://img.shields.io/docsrs/nuvek-core)](https://docs.rs/nuvek-core)
[![Licence: MIT](https://img.shields.io/badge/licence-MIT-blue.svg)](LICENSE)

Portable building blocks for small operational tools in Rust: the timers, sync jobs, CLIs and
MCP servers that keep a self-hosted stack running.

**nuvek-core is mechanism.** It never names a host, a path, a person, or a product beyond the
protocol it speaks. Your binary decides where things are; the library does the work.

## Highlights

- Secret scrubbing and a secret-surface contract: drop commands that touch credentials before they reach a model, a log or a store.
- Bounded I/O: an HTTP client with a timeout, a hardened SSH runner and a `git` runner, each with capped output.
- Operational plumbing: a journald audit logger, `tracing` set-up and Prometheus textfile metrics.
- Opt-in features, so a tool that only redacts secrets does not build an HTTP stack.
- Service clients for ChromaDB, read-only Neo4j and Ollama in sibling crates.

This workspace holds four crates:

| Crate | What it is |
|---|---|
| `nuvek-core` | Environment primitives (blank is unset), a bounded HTTP client, a hardened SSH runner, secret scrubbing and the secret-surface contract, a journald audit logger, `tracing` set-up, Prometheus textfile metrics, a bounded `git` runner, MCP and agent-hook helpers, an OpenAI-compatible gateway client |
| `nuvek-chroma` | ChromaDB v2 client with Ollama embeddings, a scoped semantic cache and HyDE |
| `nuvek-neo4j` | Read-only Neo4j Bolt client with a client-side write-clause guard and bounded queries |
| `nuvek-ollama` | Ollama client: summarization, grammar-constrained JSON extraction, and closed-question decisions with log-probability confidence |

## Install

From crates.io, picking the features you need (see the table below):

```sh
cargo add nuvek-core --features ssh,net
cargo add nuvek-chroma
cargo add nuvek-neo4j
cargo add nuvek-ollama
```

Or in `Cargo.toml`, all four crates being at version 1:

```toml
nuvek-core = { version = "1", features = ["ssh", "net"] }
nuvek-chroma = "1"
nuvek-neo4j = "1"
nuvek-ollama = "1"
```

API documentation is on docs.rs: [nuvek-core](https://docs.rs/nuvek-core),
[nuvek-chroma](https://docs.rs/nuvek-chroma), [nuvek-neo4j](https://docs.rs/nuvek-neo4j),
[nuvek-ollama](https://docs.rs/nuvek-ollama).

Rust 1.90 or newer. Linux only (journald, Unix file modes, process groups).

## Quick start

```rust
use nuvek_core::{env::env_or, scrub};

fn main() -> std::process::ExitCode {
    // First thing in main: load the secret surfaces, and refuse to run without them.
    if let Err(e) = scrub::init() {
        eprintln!("secret surfaces: {e}");
        return std::process::ExitCode::FAILURE;
    }

    let command = "cat ~/.aws/credentials";
    if scrub::touches_secret_surface(command) {
        // Drop it: it never reaches a model, a log or a store.
    }
    let line = scrub::redact_config("db_password=hunter2 and more");
    assert!(!line.contains("hunter2"));

    // The binary names its own variables and defaults; the library never learns them.
    let chroma = env_or("MYTOOL_CHROMA_URL", "http://localhost:8000");
    println!("{chroma}");
    std::process::ExitCode::SUCCESS
}
```

## Feature flags (`nuvek-core`)

`env`, `error` and `util` are always present. Everything else is opt-in, so a tool that only
redacts secrets does not build an HTTP stack. Every feature gates a module and builds on its own.

| Feature | Default | Module | Adds |
|---|---|---|---|
| `scrub` | yes | `scrub` | `redact`, `redact_config`, `has_secret`, `Masker`, `gitleaks_clean`, `touches_secret_surface`, `init` |
| `log` | yes | `log` | `get_logger(name)`: the systemd journal plus stderr |
| `metrics` | yes | `metrics` | `Metrics::new(dir)`: Prometheus textfile counters |
| `git` | yes | `git` | Bounded `git -C` runner |
| `tracing` | yes | `tracing` | `init_tracing()`: a process-wide subscriber on stderr |
| `net` | no | `http` | `reqwest` client construction with a timeout |
| `ssh` | no | `ssh` | `Ssh::new(host, users)`: batch mode, bounded output and timeout |
| `mcp` | no | `mcp` | stdio MCP transport helpers |
| `hook` | no | `hook` | Agent-harness hook input and context-injection output |
| `digest` | no | `digest` | SHA-256 content keys |
| `gateway` | no | `gateway` | OpenAI-compatible chat-completions client with route counters (enables `net` and `metrics`) |

## Configuration: the secret-surface contract

`scrub::touches_secret_surface(text)` reports whether a command or tool input handles a secret.
Built-in surfaces (key files, `~/.ssh/`, `.env` files, cloud and registry credentials) are always
on. Your deployment adds its own from a TOML file, found through `$NUVEK_SECRET_SURFACES_FILE`,
`$XDG_CONFIG_HOME/nuvek/secret-surfaces.toml` or `~/.config/nuvek/secret-surfaces.toml`, and code
can register regex patterns. All layers are additive. Call `scrub::init()` first in `main` and exit
non-zero if it returns `Err`: there is no silent fallback.

The full reference (built-in list, entry syntax, wildcard rules and every `init()` failure) is in
[docs/secret-surfaces.md](docs/secret-surfaces.md).

## Related projects

nuvek-core is the shared library behind a family of small tools, all under
[jean1880](https://github.com/jean1880):

- [nuvek-cross-agent](https://github.com/jean1880/nuvek-cross-agent): delegate work between coding-agent CLIs
- [nuvek-agent-sync](https://github.com/jean1880/nuvek-agent-sync): render one agent configuration into several tools
- [nuvek-agent-config](https://github.com/jean1880/nuvek-agent-config): the shared source tree that `agent-sync` renders
- [nuvek-hive-board](https://github.com/jean1880/nuvek-hive-board): a message board for coordinating agent teams
- [nuvek-agent-terminal](https://github.com/jean1880/nuvek-agent-terminal): a terminal for running coding agents

## Support

If nuvek-core saves you time, you can support its development:

- [Ko-fi](https://ko-fi.com/jean1880)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security reports go through [SECURITY.md](SECURITY.md).

## Releases

Releases are cut by [release-plz](https://release-plz.dev/). Each push to `master` updates a
release pull request that bumps versions and the per-crate `CHANGELOG.md` files. Merging it
publishes the changed crates to crates.io and tags each one (`nuvek-core-v1.0.0`,
`nuvek-chroma-v1.0.0`, …) with a GitHub Release. No tag is made by hand.

## Licence

Released under the [MIT Licence](LICENSE). Copyright (c) 2026 Jean-Luc Desroches.
