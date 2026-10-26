# nuvek-core

[![crates.io](https://img.shields.io/crates/v/nuvek-core.svg)](https://crates.io/crates/nuvek-core)
[![docs.rs](https://img.shields.io/docsrs/nuvek-core)](https://docs.rs/nuvek-core)
[![Licence: MIT](https://img.shields.io/badge/licence-MIT-blue.svg)](https://github.com/jean1880/nuvek-core/blob/master/LICENSE)

Portable building blocks for small operational tools: environment primitives, a bounded HTTP
client, a hardened SSH runner, secret scrubbing and the secret-surface contract, a journald audit
logger, Prometheus textfile metrics, a bounded `git` runner, and MCP and agent-hook helpers. It
names no host, path or deployment; your binary supplies those.

```sh
cargo add nuvek-core --features ssh,net
```

Everything beyond `env`, `error` and `util` is behind a Cargo feature. The
[workspace README](https://github.com/jean1880/nuvek-core#readme) has the quick start, the feature
table, configuration and Support.

Licensed under the [MIT Licence](https://github.com/jean1880/nuvek-core/blob/master/LICENSE).
