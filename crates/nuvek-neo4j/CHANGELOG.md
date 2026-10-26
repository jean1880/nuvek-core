# Changelog

All notable changes to `nuvek-neo4j` are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the crate follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-10-26

### Added

- First public release: a read-only Neo4j Bolt client with a client-side write-clause guard and
  bounded queries, published from the `nuvek-core` repository under the MIT licence. Connection
  settings come from the caller's `Neo4jConfig`.

[Unreleased]: https://github.com/jean1880/nuvek-core/compare/nuvek-neo4j-v1.0.0...HEAD
[1.0.0]: https://github.com/jean1880/nuvek-core/releases/tag/nuvek-neo4j-v1.0.0
