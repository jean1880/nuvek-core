# nuvek-neo4j

[![crates.io](https://img.shields.io/crates/v/nuvek-neo4j.svg)](https://crates.io/crates/nuvek-neo4j)
[![docs.rs](https://img.shields.io/docsrs/nuvek-neo4j)](https://docs.rs/nuvek-neo4j)
[![Licence: MIT](https://img.shields.io/badge/licence-MIT-blue.svg)](https://github.com/jean1880/nuvek-core/blob/master/LICENSE)

A read-only Neo4j Bolt client. A client-side guard refuses write clauses before a query is sent,
and every query is bounded. Connection settings come from the caller's `Neo4jConfig`; connect
with `connect(&Neo4jConfig { .. })`.

```sh
cargo add nuvek-neo4j
```

The [workspace README](https://github.com/jean1880/nuvek-core#readme) has the quick start,
configuration and Support. Part of the nuvek-core workspace, licensed under
the [MIT Licence](https://github.com/jean1880/nuvek-core/blob/master/LICENSE).
