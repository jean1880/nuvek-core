# nuvek-ollama

[![crates.io](https://img.shields.io/crates/v/nuvek-ollama.svg)](https://crates.io/crates/nuvek-ollama)
[![docs.rs](https://img.shields.io/docsrs/nuvek-ollama)](https://docs.rs/nuvek-ollama)
[![Licence: MIT](https://img.shields.io/badge/licence-MIT-blue.svg)](https://github.com/jean1880/nuvek-core/blob/master/LICENSE)

A client for a local Ollama server: summarisation, grammar-constrained JSON extraction, and
closed-question decisions with log-probability confidence. The endpoint and model names come
from the caller's `LlmConfig`; build a client with `Llm::new(LlmConfig { .. })`.

```sh
cargo add nuvek-ollama
```

The [workspace README](https://github.com/jean1880/nuvek-core#readme) has the quick start,
configuration and Support. Part of the nuvek-core workspace, licensed under
the [MIT Licence](https://github.com/jean1880/nuvek-core/blob/master/LICENSE).
