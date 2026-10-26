# nuvek-chroma

[![crates.io](https://img.shields.io/crates/v/nuvek-chroma.svg)](https://crates.io/crates/nuvek-chroma)
[![docs.rs](https://img.shields.io/docsrs/nuvek-chroma)](https://docs.rs/nuvek-chroma)
[![Licence: MIT](https://img.shields.io/badge/licence-MIT-blue.svg)](https://github.com/jean1880/nuvek-core/blob/master/LICENSE)

A ChromaDB v2 client with Ollama embeddings, a scoped semantic cache and HyDE. Endpoints, models
and the tenant path come from the caller's `ChromaConfig`; build a client with
`Rag::new(ChromaConfig { .. })`.

```sh
cargo add nuvek-chroma
```

The [workspace README](https://github.com/jean1880/nuvek-core#readme) has the quick start,
configuration and Support. Part of the nuvek-core workspace, licensed under
the [MIT Licence](https://github.com/jean1880/nuvek-core/blob/master/LICENSE).
