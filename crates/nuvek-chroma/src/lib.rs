//! ChromaDB v2 client with Ollama embeddings, a semantic cache, and HyDE.
//!
//! Optimized for ChromaDB's v2 multi-tenant API. Collections are created with
//! `hnsw:space=cosine` so `nomic-embed-text`'s un-normalized vectors yield bounded 0–2
//! distances that the hit/cache thresholds expect.
//!
//! # Two layers in one crate
//!
//! The Chroma REST calls are a **client**; the semantic cache and HyDE are a **strategy** built on
//! top of it. They live in one crate so the `reqwest` connection pool is shared, but the split is
//! real: a caller that only wants `query_collection` never touches the cache path, and the cache's
//! tuning constants ([`DEFAULT_CACHE_THRESHOLD`], the prefix symmetry rule) are documented as
//! strategy, not as protocol.
//!
//! **Endpoints, models and the tenant path are the caller's** — see [`ChromaConfig`].
//!
//! ```no_run
//! # fn f() -> anyhow::Result<()> {
//! use nuvek_chroma::{Rag, ChromaConfig};
//! use nuvek_core::env::env_or;
//! let rag = Rag::new(ChromaConfig {
//!     chroma_base: env_or("CHROMA_URL", "http://localhost:8000"),
//!     ollama_base: env_or("OLLAMA_URL_BASE", "http://localhost:11434"),
//!     ..Default::default()
//! })?;
//! # Ok(()) }
//! ```

use anyhow::{Context, Result};
use md5::{Digest, Md5};
use nuvek_core::gateway::{attempt, Completion, Gateway};
use nuvek_core::metrics::Metrics;
use serde_json::{json, Value};
use std::time::Duration;

/// Re-exported so a consumer can build a [`ChromaConfig`] without naming the feature itself.
pub use nuvek_core::gateway::GatewayConfig;

/// Default Ollama embedding model (768-dim vectors); must match the corpus embedding path.
///
/// A model name, not a deployment address — so it is a usable default. Override it in
/// [`ChromaConfig`] when the corpus was embedded with something else.
///
/// **Changing this silently invalidates every collection.** A *dimensionality* change (nomic 768 →
/// mxbai 1024) fails loudly because Chroma rejects the insert. The dangerous case is a
/// same-dimension, different-vector-space swap — `bge-base-en` is also 768 — where every query
/// returns plausible neighbours at plausible distances and the thresholds fire on noise.
pub const EMBED_MODEL: &str = "nomic-embed-text:latest";

/// Default Ollama logic/generation model used for HyDE and `cached_generate`. Small on purpose:
/// it runs on the retrieval path, so latency matters. Choose models that fit alongside the
/// embedder; partial CPU placement increases latency.
pub const LOGIC_MODEL: &str = "qwen3.5:4b";

/// Default collection name backing the semantic cache.
pub const CACHE_COLLECTION: &str = "ai_semantic_cache";

/// Chroma's own v2 multi-tenant path segment.
///
/// A protocol default rather than a deployment one: it is what Chroma itself creates out of the
/// box. A deployment using a different tenant overrides it in [`ChromaConfig`].
pub const DB_ROOT: &str = "tenants/default_tenant/databases/default_database";
/// Default cosine-distance threshold below which a cache entry counts as a hit. Namespace scoping
/// and symmetric task prefixes reduce cross-task cache collisions, so a tight radius still lands
/// genuine hits.
pub const DEFAULT_CACHE_THRESHOLD: f64 = 0.08;

/// Maximum character length sent to Ollama embeddings endpoint in one request.
/// Nomic-embed-text has a hard physical batch limit of 2,048 tokens.
/// At ~3.5 chars/token, bounding to 6,000 chars ensures all embedding requests
/// stay safely below the 2,048-token limit and never trigger a batch overflow (HTTP 500).
pub const MAX_EMBED_CHARS: usize = 6_000;

/// How many times [`Rag::embedding`] halves an input the model rejected as too large.
/// 6,000 → 750 chars covers text down to ~0.4 chars/token.
const EMBED_SHRINK_RETRIES: usize = 3;

/// Ollama's answer to an input over the embedding model's limit: HTTP 500 with either
/// `input (N tokens) is too large to process` (batch size) or, from newer servers,
/// `the input length exceeds the context length`.
fn is_embed_overflow(status: u16, body: &str) -> bool {
    status == 500
        && (body.contains("too large to process") || body.contains("exceeds the context length"))
}

/// The first half of `text`, by chars (never splits a multi-byte char).
fn halve(text: &str) -> String {
    let n = text.chars().count() / 2;
    text.chars().take(n).collect()
}

/// nomic-embed-text task prefix for the cache. **Must be SYMMETRIC** (identical on write and
/// lookup): a semantic cache asks "have I answered this same prompt before?" — a like-for-like
/// similarity task, which is what `clustering:` is for. The asymmetric `search_query:`/
/// `search_document:` pair is for *retrieval* (query→document) and would embed the SAME text to
/// two different points, so an exact repeat would never land near distance 0 and the cache could
/// never hit. Deliberately scoped to the CACHE path ONLY: retrieval corpora are embedded
/// prefix-less, and prefixing them would break their own query/corpus symmetry until a full
/// re-embed.
const CACHE_PREFIX: &str = "clustering: ";

/// Well-known cache namespaces. Every caller MUST use these rather than a string literal — a typo
/// silently creates a private partition that can never hit, which looks like "the cache stopped
/// working" with no error.
pub mod ns {
    /// File and code summaries.
    pub const SUMMARIZE: &str = "summarize";
    /// Log root-cause analysis by a log-analysis consumer.
    pub const WATCHDOG_RCA: &str = "watchdog-rca";
    /// Every namespace a caller reads. A cache row in any other namespace is unreachable, and
    /// cache maintenance tooling may remove it, so a new namespace MUST be listed in this array.
    pub const ALL: &[&str] = &[SUMMARIZE, WATCHDOG_RCA];
}

// Per-call deadlines (embedding 30s, cache 10s, query 15s, collection ops 15s) instead of the
// client's blanket 60s fallback, so a slow backend fails fast rather than stalling the
// CACHE-FIRST path.
const EMBED_TIMEOUT: Duration = Duration::from_secs(30);
const CACHE_TIMEOUT: Duration = Duration::from_secs(10);
const QUERY_TIMEOUT: Duration = Duration::from_secs(15);
const COLLECTION_TIMEOUT: Duration = Duration::from_secs(15);
/// Ids per delete request. One request for a whole sweep (thousands of ids) outran its timeout.
pub const DELETE_BATCH: usize = 500;

/// Identity of a cache partition: WHICH task is caching, with WHICH model. Every lookup is
/// filtered to a matching scope, so two different tasks can never read each other's entries no
/// matter how close their embeddings land — the structural fix for cross-task false hits
/// (the same idea as scoping graph queries to one tenant label).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheScope<'a> {
    /// Caller/task identity, e.g. `summarize`, `watchdog-rca`, `mcp-cache`.
    pub namespace: &'a str,
    /// Generation model the cached answer came from.
    pub model: &'a str,
}

impl<'a> CacheScope<'a> {
    /// A scope for `namespace` answering with `model`.
    pub fn new(namespace: &'a str, model: &'a str) -> Self {
        Self { namespace, model }
    }

    /// Deterministic entry id, salted with the scope so distinct tasks can never collide on id
    /// even for an identical key.
    fn entry_id(&self, key: &str) -> String {
        let salted = format!("{}\0{}\0{}", self.namespace, self.model, key);
        format!("{:x}", Md5::digest(salted.as_bytes()))
    }

    /// Chroma `where` filter restricting a lookup to this scope.
    fn where_filter(&self) -> Value {
        json!({
            "$and": [
                { "namespace": { "$eq": self.namespace } },
                { "model": { "$eq": self.model } }
            ]
        })
    }
}

/// How [`Rag::cached_generate`] decides whether a prior answer applies.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CacheLookup {
    /// Nearest-1 by embedding within this cosine distance — for natural-language keys (log text,
    /// prompts), where a near-duplicate should reuse the answer.
    Semantic(f64),
    /// Exact key match by entry id. REQUIRED for opaque keys such as content hashes: an embedding
    /// model maps every hex digest to nearly the same point, so a semantic lookup hands one
    /// file's answer to another.
    Exact,
    /// No lookup: generate, then overwrite the entry for this key — a forced refresh.
    Refresh,
}

/// One retrieval result row.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Record {
    /// The stored document text.
    pub document: String,
    /// Chroma metadata attached to the document (JSON object, or null).
    pub metadata: Value,
    /// Cosine distance to the query (lower = closer); None if not returned.
    pub distance: Option<f64>,
}

/// Metadata keys naming where a document came from, most specific first (as a document chunker
/// typically writes them).
const LOCATION_KEYS: [&str; 3] = ["relative_path", "filename", "source"];

/// Where a document came from: its first non-empty `relative_path` / `filename` / `source`, or
/// `""` when none is set.
pub fn metadata_location(metadata: &Value) -> &str {
    LOCATION_KEYS
        .iter()
        .filter_map(|k| metadata.get(*k).and_then(Value::as_str))
        .find(|s| !s.is_empty())
        .unwrap_or("")
}

impl Record {
    /// Where this record came from: see [`metadata_location`].
    pub fn location(&self) -> &str {
        metadata_location(&self.metadata)
    }
}

/// Cosine distance (1 - cosine similarity), matching the collections' `hnsw:space=cosine`.
/// A degenerate zero-norm vector yields the maximum distance (1.0) rather than NaN.
pub fn cosine_distance(a: &[f64], b: &[f64]) -> f64 {
    let (mut dot, mut na, mut nb) = (0.0, 0.0, 0.0);
    for (x, y) in a.iter().zip(b.iter()) {
        dot += x * y;
        na += x * x;
        nb += y * y;
    }
    let denom = na.sqrt() * nb.sqrt();
    if denom == 0.0 {
        return 1.0;
    }
    1.0 - (dot / denom)
}

/// Merge hits from several queries into one nearest-first list of at most `limit`, keeping each
/// hit's tag (for example its collection). A hit without a distance can't be ranked and is dropped.
pub fn nearest_first<T>(mut hits: Vec<(Record, T)>, limit: usize) -> Vec<(Record, T)> {
    hits.retain(|(r, _)| r.distance.is_some());
    hits.sort_by(|(a, _), (b, _)| {
        a.distance
            .partial_cmp(&b.distance)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    hits.truncate(limit);
    hits
}

/// Everything the client needs. Endpoints have no defaults; models and the tenant path do,
/// because those describe the products rather than any deployment.
#[derive(Debug, Clone)]
pub struct ChromaConfig {
    /// ChromaDB base URL, e.g. `http://chroma.example.test:8000`. `/api/v2` is appended.
    pub chroma_base: String,
    /// Ollama base URL, e.g. `http://ollama.example.test:11434`. `/api` is appended.
    pub ollama_base: String,
    /// v2 multi-tenant path segment — see [`DB_ROOT`].
    pub db_root: String,
    /// Embedding model — see [`EMBED_MODEL`].
    pub embed_model: String,
    /// Logic/generation model for HyDE and `cached_generate` — see [`LOGIC_MODEL`].
    pub logic_model: String,
    /// Collection backing the semantic cache — see [`CACHE_COLLECTION`].
    pub cache_collection: String,
    /// Where to emit retrieval/cache telemetry. `None` disables it entirely.
    pub metrics: Option<Metrics>,
    /// LLM gateway tried ahead of direct Ollama for [`Rag::generate`] (spend attribution).
    /// Embeddings always go direct. `None` = always direct; the caller resolves it.
    pub gateway: Option<GatewayConfig>,
}

impl Default for ChromaConfig {
    fn default() -> Self {
        Self {
            chroma_base: String::new(),
            ollama_base: String::new(),
            db_root: DB_ROOT.into(),
            embed_model: EMBED_MODEL.into(),
            logic_model: LOGIC_MODEL.into(),
            cache_collection: CACHE_COLLECTION.into(),
            metrics: None,
            gateway: None,
        }
    }
}

/// Shared RAG client. Cheap to clone (reqwest::Client is an Arc internally).
#[derive(Clone)]
pub struct Rag {
    http: reqwest::Client,
    chroma_v2: String,
    ollama_api: String,
    db_root: String,
    /// Cached here so a single client cannot embed half a corpus with one model and half with
    /// another.
    embed_model: String,
    logic_model: String,
    cache_collection: String,
    metrics: Option<Metrics>,
    gateway: Option<Gateway>,
}

impl Rag {
    /// Build a RAG client with a shared connection pool and env-resolved endpoints.
    ///
    /// Note on error semantics: the low-level methods (`embedding`, `collection_id`,
    /// `check_semantic_cache`, `write_semantic_cache`, `query_collection`) return `Result`
    /// and propagate transport errors rather than degrading to `None`/`[]`. Callers that need
    /// fail-soft behaviour must handle the error
    /// (e.g. embedders log-and-skip; MCP query tools return an empty list). `cached_generate`
    /// already encapsulates fail-soft for the cache path.
    pub fn new(cfg: ChromaConfig) -> Result<Self> {
        let http =
            nuvek_core::http::client(Duration::from_secs(60)).context("building reqwest client")?;
        let gateway = cfg
            .gateway
            .map(Gateway::new)
            .transpose()
            .context("building gateway client")?;
        Ok(Rag {
            gateway,
            http,
            chroma_v2: format!("{}/api/v2", cfg.chroma_base.trim_end_matches('/')),
            ollama_api: format!("{}/api", cfg.ollama_base.trim_end_matches('/')),
            db_root: cfg.db_root,
            embed_model: cfg.embed_model,
            logic_model: cfg.logic_model,
            cache_collection: cfg.cache_collection,
            metrics: cfg.metrics,
        })
    }

    /// The embedding model this client uses. Callers that stamp provenance need it.
    #[must_use]
    pub fn embed_model(&self) -> &str {
        &self.embed_model
    }

    /// The logic/generation model this client uses.
    #[must_use]
    pub fn logic_model(&self) -> &str {
        &self.logic_model
    }

    /// The semantic-cache collection this client reads and writes.
    ///
    /// Load-bearing for tooling that inspects the cache: a doctor that looked at a *different*
    /// collection from the one the cache writes to would report a healthy cache that does not
    /// exist.
    #[must_use]
    pub fn cache_collection(&self) -> &str {
        &self.cache_collection
    }

    /// Names of the models installed on the Ollama server (`/api/tags`), e.g. `qwen3.5:4b`.
    pub async fn installed_models(&self) -> Result<Vec<String>> {
        let body: Value = self
            .http
            .get(format!("{}/tags", self.ollama_api))
            .timeout(QUERY_TIMEOUT)
            .send()
            .await
            .context("ollama tags request")?
            .error_for_status()
            .context("ollama tags status")?
            .json()
            .await
            .context("ollama tags body")?;
        Ok(body
            .get("models")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|m| m.get("name").and_then(Value::as_str).map(String::from))
                    .collect()
            })
            .unwrap_or_default())
    }

    fn collections_url(&self) -> String {
        format!("{}/{}/collections", self.chroma_v2, self.db_root)
    }

    /// Fetch an embedding vector from the local Ollama instance.
    ///
    /// Inputs are first cut to [`MAX_EMBED_CHARS`]. That is a char bound on a token limit, so it
    /// cannot be exact: dense text (JSON logs, hashes) can run close to 2 chars/token, so 5,000
    /// chars may exceed a model's batch limit. When Ollama rejects an input as over the model's batch limit,
    /// the text is halved and retried (up to `EMBED_SHRINK_RETRIES` times) — the prefix is kept,
    /// so a task prefix like `CACHE_PREFIX` survives.
    pub async fn embedding(&self, text: &str) -> Result<Vec<f64>> {
        let mut clean_text: String = text.chars().take(MAX_EMBED_CHARS).collect();
        let mut attempt = 0;
        loop {
            let resp = self
                .http
                .post(format!("{}/embeddings", self.ollama_api))
                .json(&json!({ "model": self.embed_model, "prompt": clean_text }))
                .timeout(EMBED_TIMEOUT)
                .send()
                .await
                .context("ollama embeddings request")?;
            let status = resp.status();
            if !status.is_success() {
                let err_body = resp.text().await.unwrap_or_default();
                if attempt < EMBED_SHRINK_RETRIES && is_embed_overflow(status.as_u16(), &err_body) {
                    attempt += 1;
                    clean_text = halve(&clean_text);
                    tracing::warn!(
                        "embedding input over the model's batch limit; retrying with the first {} chars",
                        clean_text.chars().count()
                    );
                    continue;
                }
                let detail: String = err_body.chars().take(200).collect();
                anyhow::bail!("ollama embeddings status {status}: {detail}");
            }
            let body: Value = resp.json().await.context("ollama embeddings body")?;
            let vec = body
                .get("embedding")
                .and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_f64()).collect::<Vec<_>>())
                .filter(|v| !v.is_empty())
                .context("ollama returned no embedding")?;
            return Ok(vec);
        }
    }

    /// Embed for the CACHE path with the symmetric [`CACHE_PREFIX`]. Both the write and the
    /// lookup go through here, so identical prompts embed to the same point (distance ≈ 0) and a
    /// repeat reliably hits. Only the cache uses this; corpora keep the prefix-less
    /// [`Self::embedding`].
    async fn cache_embedding(&self, text: &str) -> Result<Vec<f64>> {
        self.embedding(&format!("{CACHE_PREFIX}{text}")).await
    }

    /// Non-streaming Ollama text generation. `think`: `Some(false)` makes a reasoning model answer
    /// directly (its trace otherwise eats the context window and can leave `response` empty);
    /// `None` leaves the model's default, and is the only safe value for a caller that may be
    /// handed any model, since `Some(true)` errors on a model without a thinking mode.
    pub async fn generate(
        &self,
        model: &str,
        prompt: &str,
        think: Option<bool>,
        timeout: Duration,
    ) -> Result<String> {
        // Gateway first (attributed + tracked), direct on any failure, within the same budget.
        let req = Completion {
            model,
            system: None,
            prompt,
            think,
            max_tokens: None,
            temperature: None,
        };
        let (answer, direct_timeout) = attempt(self.gateway.as_ref(), &req, timeout).await;
        if let Some(a) = answer {
            return Ok(a.text);
        }
        let resp = self
            .http
            .post(format!("{}/generate", self.ollama_api))
            .json(&generate_payload(model, prompt, think))
            .timeout(direct_timeout)
            .send()
            .await
            .context("ollama generate request")?
            .error_for_status()
            .context("ollama generate status")?;
        let body: Value = resp.json().await.context("ollama generate body")?;
        Ok(body
            .get("response")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string())
    }

    /// Resolve a collection name to its ID **without creating it** — the read-only counterpart to
    /// [`Self::collection_id`]. `None` when the collection doesn't exist. Diagnostics must use
    /// this: create-on-miss is a surprising write for a tool that claims to only read.
    pub async fn find_collection_id(&self, name: &str) -> Result<Option<String>> {
        let list: Value = self
            .http
            .get(self.collections_url())
            .timeout(COLLECTION_TIMEOUT)
            .send()
            .await
            .context("listing collections")?
            .error_for_status()
            .context("listing collections status")?
            .json()
            .await
            .context("collections body")?;
        Ok(list.as_array().and_then(|arr| {
            arr.iter()
                .find(|col| col.get("name").and_then(|n| n.as_str()) == Some(name))
                .and_then(|col| col.get("id").and_then(|i| i.as_str()))
                .map(|id| id.to_string())
        }))
    }

    /// Resolve a collection name to its ID, creating it (cosine space) if missing.
    pub async fn collection_id(&self, name: &str) -> Result<String> {
        if let Some(id) = self.find_collection_id(name).await? {
            return Ok(id);
        }
        // Create with cosine space (see module docs).
        let payload = json!({
            "name": name,
            "metadata": { "description": name },
            "configuration": { "hnsw": { "space": "cosine" } }
        });
        let created: Value = self
            .http
            .post(self.collections_url())
            .json(&payload)
            .timeout(COLLECTION_TIMEOUT)
            .send()
            .await
            .context("creating collection")?
            .error_for_status()
            .context("creating collection status")?
            .json()
            .await
            .context("create-collection body")?;
        created
            .get("id")
            .and_then(|i| i.as_str())
            .map(|s| s.to_string())
            .context("created collection returned no id")
    }

    /// Check the semantic cache for a similar prior query **within `scope`**. Returns the cached
    /// answer or None. A different namespace/model can never match, however close the vectors.
    pub async fn check_semantic_cache(
        &self,
        query_text: &str,
        scope: CacheScope<'_>,
        threshold: f64,
    ) -> Result<Option<String>> {
        let col_id = self.collection_id(&self.cache_collection.clone()).await?;
        let vector = self.cache_embedding(query_text).await?;
        let url = format!(
            "{}/{}/collections/{}/query",
            self.chroma_v2, self.db_root, col_id
        );
        // The scope filter makes a cross-task hit structurally impossible, independent of
        // embedding proximity — the threshold is then only guarding same-task near-dupes.
        let payload = json!({
            "query_embeddings": [vector],
            "n_results": 1,
            "where": scope.where_filter(),
            "include": ["documents", "distances"]
        });
        let results: Value = self
            .http
            .post(url)
            .json(&payload)
            .timeout(CACHE_TIMEOUT)
            .send()
            .await
            .context("cache query request")?
            .error_for_status()
            .context("cache query status")?
            .json()
            .await
            .context("cache query body")?;
        let dist = results
            .get("distances")
            .and_then(|d| d.get(0))
            .and_then(|d| d.get(0))
            .and_then(|d| d.as_f64());
        if let Some(dist) = dist {
            if dist <= threshold {
                let doc = results
                    .get("documents")
                    .and_then(|d| d.get(0))
                    .and_then(|d| d.get(0))
                    .and_then(|d| d.as_str())
                    .map(|s| s.to_string());
                return Ok(doc);
            }
        }
        Ok(None)
    }

    /// Exact-key cache lookup **within `scope`**: fetches the entry whose id is
    /// `scope.entry_id(key)`, no embedding involved. The only correct lookup for opaque keys.
    pub async fn check_exact_cache(
        &self,
        key: &str,
        scope: CacheScope<'_>,
    ) -> Result<Option<String>> {
        let col_id = self.collection_id(&self.cache_collection.clone()).await?;
        let url = format!(
            "{}/{}/collections/{}/get",
            self.chroma_v2, self.db_root, col_id
        );
        let body: Value = self
            .http
            .post(url)
            .json(&json!({ "ids": [scope.entry_id(key)], "include": ["documents"] }))
            .timeout(CACHE_TIMEOUT)
            .send()
            .await
            .context("cache get request")?
            .error_for_status()
            .context("cache get status")?
            .json()
            .await
            .context("cache get body")?;
        Ok(first_document(&body))
    }

    /// Store a new entry in the semantic cache, tagged with `scope`
    /// (id = md5 of namespace + model + key, so tasks never collide).
    pub async fn write_semantic_cache(
        &self,
        query_text: &str,
        response_text: &str,
        scope: CacheScope<'_>,
    ) -> Result<()> {
        let col_id = self.collection_id(&self.cache_collection.clone()).await?;
        let vector = self.cache_embedding(query_text).await?;
        let entry_id = scope.entry_id(query_text);
        let url = format!(
            "{}/{}/collections/{}/upsert",
            self.chroma_v2, self.db_root, col_id
        );
        let payload = json!({
            "ids": [entry_id],
            "embeddings": [vector],
            "documents": [response_text],
            "metadatas": [{
                "timestamp": chrono::Utc::now().timestamp(),
                "source_script": "nuvek-core",
                "namespace": scope.namespace,
                "model": scope.model
            }]
        });
        self.http
            .post(url)
            .json(&payload)
            .timeout(CACHE_TIMEOUT)
            .send()
            .await
            .context("cache upsert request")?
            .error_for_status()
            .context("cache upsert status")?;
        Ok(())
    }

    /// Cache-first Ollama generation (CACHE-FIRST mandate). Returns (text, hit).
    /// `scope` is both the cache partition AND the generation model, so a cached answer can only
    /// ever be reused by the same task with the same model.
    /// Fail-soft: returns ("", false) on transport error so a caller never blocks on the LLM.
    /// `skip_if` vetoes caching a bad answer.
    pub async fn cached_generate(
        &self,
        scope: CacheScope<'_>,
        prompt: &str,
        cache_key: Option<&str>,
        lookup: CacheLookup,
        timeout: Duration,
        skip_if: Option<&dyn Fn(&str) -> bool>,
    ) -> (String, bool) {
        let key = cache_key.unwrap_or(prompt);
        let found = match lookup {
            CacheLookup::Semantic(threshold) => {
                Some(self.check_semantic_cache(key, scope, threshold).await)
            }
            CacheLookup::Exact => Some(self.check_exact_cache(key, scope).await),
            CacheLookup::Refresh => None,
        };
        // A refresh performed no lookup, so it records nothing. A failed lookup is an error, not a
        // miss, so a cache-backend outage does not read as a cold cache.
        match found {
            Some(Ok(Some(cached))) => {
                if let Some(m) = &self.metrics {
                    m.record_cache(true, None, scope.namespace);
                }
                return (cached, true);
            }
            Some(Ok(None)) => {
                if let Some(m) = &self.metrics {
                    m.record_cache(false, None, scope.namespace);
                }
            }
            Some(Err(e)) => {
                tracing::warn!("cache lookup failed ({}): {e}", scope.namespace);
                if let Some(m) = &self.metrics {
                    m.record_cache_error(scope.namespace);
                }
            }
            None => {}
        }
        // Think off: cached answers are compressions (summaries, RCA digests), which a reasoning
        // pass does not improve, and whose trace can exhaust the context and return nothing.
        let text = match self
            .generate(scope.model, prompt, Some(false), timeout)
            .await
        {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!("cached_generate error: {e}");
                return (String::new(), false);
            }
        };
        if !text.is_empty() && skip_if.map(|f| !f(&text)).unwrap_or(true) {
            let _ = self.write_semantic_cache(key, &text, scope).await;
        }
        (text, false)
    }

    /// Generate a hypothetical answer via the logic model, then embed it (HyDE). Falls back
    /// to embedding the raw query on generation failure.
    pub async fn hyde_embedding(&self, query_text: &str) -> Result<Vec<f64>> {
        let prompt = format!(
            "Generate a brief, technical answer to this question to help with semantic search: {query_text}"
        );
        match self
            .generate(
                &self.logic_model.clone(),
                &prompt,
                Some(false),
                Duration::from_secs(45),
            )
            .await
        {
            Ok(doc) if !doc.is_empty() => self.embedding(&doc).await,
            _ => self.embedding(query_text).await,
        }
    }

    /// Query a collection, returning matching documents + metadata. `where_filter` is an
    /// optional Chroma metadata filter; `use_hyde` trades a logic-model call for better recall.
    pub async fn query_collection(
        &self,
        query_text: &str,
        collection: &str,
        limit: usize,
        where_filter: Option<Value>,
        use_hyde: bool,
    ) -> Result<Vec<Record>> {
        let col_id = self.collection_id(collection).await?;
        let vector = if use_hyde {
            match self.hyde_embedding(query_text).await {
                Ok(v) => v,
                Err(_) => self.embedding(query_text).await?,
            }
        } else {
            self.embedding(query_text).await?
        };

        let mut payload = json!({
            "query_embeddings": [vector],
            "n_results": limit,
            "include": ["documents", "metadatas", "distances"]
        });
        if let Some(w) = where_filter {
            payload["where"] = w;
        }
        let url = format!(
            "{}/{}/collections/{}/query",
            self.chroma_v2, self.db_root, col_id
        );
        let results: Value = self
            .http
            .post(url)
            .json(&payload)
            .timeout(QUERY_TIMEOUT)
            .send()
            .await
            .context("collection query request")?
            .error_for_status()
            .context("collection query status")?
            .json()
            .await
            .context("collection query body")?;

        let docs = results
            .get("documents")
            .and_then(|d| d.get(0))
            .and_then(|d| d.as_array())
            .cloned()
            .unwrap_or_default();
        let metas = results
            .get("metadatas")
            .and_then(|d| d.get(0))
            .and_then(|d| d.as_array())
            .cloned()
            .unwrap_or_default();
        let dists = results
            .get("distances")
            .and_then(|d| d.get(0))
            .and_then(|d| d.as_array())
            .cloned()
            .unwrap_or_default();

        let mut records = Vec::new();
        for (i, doc) in docs.iter().enumerate() {
            records.push(Record {
                document: doc.as_str().unwrap_or("").to_string(),
                metadata: metas.get(i).cloned().unwrap_or(Value::Null),
                distance: dists.get(i).and_then(|d| d.as_f64()),
            });
        }
        if let Some(m) = &self.metrics {
            m.record_retrieval(
                collection,
                &records.iter().map(|r| r.distance).collect::<Vec<_>>(),
                "",
            );
        }
        Ok(records)
    }

    // --- Collection mutations, shared by embedding clients, so no binary re-implements the v2
    // upsert/get/delete URLs.

    /// Batch-upsert pre-embedded documents into a collection (one POST). Timeout scales with
    /// batch size (embedders send up to a few hundred at once).
    pub async fn upsert(&self, col_id: &str, docs: &[UpsertDoc]) -> Result<()> {
        if docs.is_empty() {
            return Ok(());
        }
        let payload = json!({
            "ids":        docs.iter().map(|d| &d.id).collect::<Vec<_>>(),
            "embeddings": docs.iter().map(|d| &d.embedding).collect::<Vec<_>>(),
            "metadatas":  docs.iter().map(|d| &d.metadata).collect::<Vec<_>>(),
            "documents":  docs.iter().map(|d| &d.document).collect::<Vec<_>>(),
        });
        let url = format!(
            "{}/{}/collections/{}/upsert",
            self.chroma_v2, self.db_root, col_id
        );
        self.http
            .post(url)
            .json(&payload)
            .timeout(Duration::from_secs(60))
            .send()
            .await
            .context("batch upsert request")?
            .error_for_status()
            .context("batch upsert status")?;
        Ok(())
    }

    /// Return every stored document id in a collection (for orphan detection).
    pub async fn all_ids(&self, col_id: &str) -> Result<Vec<String>> {
        let url = format!(
            "{}/{}/collections/{}/get",
            self.chroma_v2, self.db_root, col_id
        );
        let body: Value = self
            .http
            .post(url)
            .json(&json!({ "include": [] }))
            .timeout(Duration::from_secs(30))
            .send()
            .await
            .context("get-ids request")?
            .error_for_status()
            .context("get-ids status")?
            .json()
            .await
            .context("get-ids body")?;
        Ok(body
            .get("ids")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default())
    }

    /// Delete documents by id, [`DELETE_BATCH`] ids per request so a large sweep never outlives
    /// one request's timeout. No-op on an empty list (never a delete-everything). A failed batch
    /// stops the run with an error; the ids it and later batches held are still orphans, so the
    /// caller's next sweep retries them.
    pub async fn delete_ids(&self, col_id: &str, ids: &[String]) -> Result<()> {
        let url = format!(
            "{}/{}/collections/{}/delete",
            self.chroma_v2, self.db_root, col_id
        );
        for (n, batch) in ids.chunks(DELETE_BATCH).enumerate() {
            self.http
                .post(&url)
                .json(&json!({ "ids": batch }))
                .timeout(Duration::from_secs(30))
                .send()
                .await
                .with_context(|| format!("delete request (batch {})", n + 1))?
                .error_for_status()
                .with_context(|| format!("delete status (batch {})", n + 1))?;
        }
        Ok(())
    }

    /// Delete a whole collection by name (Chroma v2 `DELETE …/collections/{name}`). Irreversible:
    /// archive first, gate behind an explicit apply, and confirm with [`Rag::find_collection_id`].
    pub async fn delete_collection(&self, name: &str) -> Result<()> {
        if name.is_empty() {
            anyhow::bail!("refusing to delete a collection with an empty name");
        }
        let url = format!("{}/{}/collections/{}", self.chroma_v2, self.db_root, name);
        self.http
            .delete(url)
            .timeout(Duration::from_secs(30))
            .send()
            .await
            .context("delete-collection request")?
            .error_for_status()
            .context("delete-collection status")?;
        Ok(())
    }

    /// Metadata "get" by `where` filter (NOT a vector query) — the raw Chroma `/get` response
    /// with the requested `include` fields (e.g. `["metadatas","documents"]`). Used for
    /// scoped metadata fetches such as a session-start lookup. Bounded at 3s so a hook on the
    /// startup path fails fast.
    pub async fn get_where(
        &self,
        col_id: &str,
        where_filter: Value,
        include: &[&str],
    ) -> Result<Value> {
        let url = format!(
            "{}/{}/collections/{}/get",
            self.chroma_v2, self.db_root, col_id
        );
        let body: Value = self
            .http
            .post(url)
            .json(&json!({ "where": where_filter, "include": include }))
            .timeout(Duration::from_secs(3))
            .send()
            .await
            .context("get-where request")?
            .error_for_status()
            .context("get-where status")?
            .json()
            .await
            .context("get-where body")?;
        Ok(body)
    }

    /// Fetch every row in a collection (`/get` with no `where`). Chroma rejects an empty
    /// `where: {}` as an "Invalid where clause", so match-all means omitting the key entirely —
    /// hence a separate method rather than calling [`Self::get_where`] with `{}`.
    pub async fn get_all(&self, col_id: &str, include: &[&str]) -> Result<Value> {
        let url = format!(
            "{}/{}/collections/{}/get",
            self.chroma_v2, self.db_root, col_id
        );
        let body: Value = self
            .http
            .post(url)
            .json(&json!({ "include": include }))
            .timeout(QUERY_TIMEOUT)
            .send()
            .await
            .context("get-all request")?
            .error_for_status()
            .context("get-all status")?
            .json()
            .await
            .context("get-all body")?;
        Ok(body)
    }

    /// Fetch a single document's metadata object by its id (`/get` with `ids=[id]`). Returns
    /// `None` if the id is absent or its metadata is not an object. Used by the session distiller
    /// (exact-id reinforce) and the review (status flip / conflict check).
    pub async fn get_metadata_by_id(&self, col_id: &str, id: &str) -> Result<Option<Value>> {
        let url = format!(
            "{}/{}/collections/{}/get",
            self.chroma_v2, self.db_root, col_id
        );
        let body: Value = self
            .http
            .post(url)
            .json(&json!({ "ids": [id], "include": ["metadatas"] }))
            .timeout(QUERY_TIMEOUT)
            .send()
            .await
            .context("get-by-id request")?
            .error_for_status()
            .context("get-by-id status")?
            .json()
            .await
            .context("get-by-id body")?;
        let has_id = body
            .get("ids")
            .and_then(|v| v.as_array())
            .is_some_and(|a| !a.is_empty());
        let meta = body
            .get("metadatas")
            .and_then(|v| v.as_array())
            .and_then(|a| a.first())
            .cloned();
        match (has_id, meta) {
            (true, Some(m)) if m.is_object() => Ok(Some(m)),
            _ => Ok(None),
        }
    }

    /// Replace a single document's metadata object (`/update` with `ids=[id]`). The caller
    /// supplies the full metadata to store (Chroma merges by id).
    pub async fn update_metadata(&self, col_id: &str, id: &str, metadata: &Value) -> Result<()> {
        let url = format!(
            "{}/{}/collections/{}/update",
            self.chroma_v2, self.db_root, col_id
        );
        self.http
            .post(url)
            .json(&json!({ "ids": [id], "metadatas": [metadata] }))
            .timeout(QUERY_TIMEOUT)
            .send()
            .await
            .context("update-metadata request")?
            .error_for_status()
            .context("update-metadata status")?;
        Ok(())
    }

    /// Nearest neighbours to a PRE-COMPUTED embedding vector, optionally scope-filtered. Returns
    /// `(id, metadata, distance)` triples. Unlike [`Rag::query_collection`], the caller supplies the
    /// vector (the distiller normalizes to unit length before querying its L2 collection).
    pub async fn query_by_vector(
        &self,
        col_id: &str,
        vector: &[f64],
        n: usize,
        where_filter: Option<Value>,
    ) -> Result<Vec<(String, Value, Option<f64>)>> {
        let url = format!(
            "{}/{}/collections/{}/query",
            self.chroma_v2, self.db_root, col_id
        );
        let mut payload = json!({
            "query_embeddings": [vector],
            "n_results": n,
            "include": ["metadatas", "distances"],
        });
        if let Some(w) = where_filter {
            payload["where"] = w;
        }
        let body: Value = self
            .http
            .post(url)
            .json(&payload)
            .timeout(QUERY_TIMEOUT)
            .send()
            .await
            .context("query-by-vector request")?
            .error_for_status()
            .context("query-by-vector status")?
            .json()
            .await
            .context("query-by-vector body")?;
        let ids = first_row(&body, "ids");
        let metas = first_row(&body, "metadatas");
        let dists = first_row(&body, "distances");
        let mut out = Vec::new();
        for (i, rid) in ids.iter().enumerate() {
            let Some(rid) = rid.as_str() else { continue };
            let meta = metas.get(i).cloned().unwrap_or(Value::Null);
            let dist = dists.get(i).and_then(Value::as_f64);
            out.push((rid.to_string(), meta, dist));
        }
        Ok(out)
    }
}

/// Extract the first inner row of a Chroma batched response field (`field[0]`), or an empty
/// slice-like vec. Chroma nests per-query results one level deep (`ids: [[...]]`).
fn first_row(body: &Value, field: &str) -> Vec<Value> {
    body.get(field)
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default()
}

/// The document of the first row of a Chroma `/get` response, if the id was present.
fn first_document(body: &Value) -> Option<String> {
    let has_id = body
        .get("ids")
        .and_then(|v| v.as_array())
        .is_some_and(|a| !a.is_empty());
    if !has_id {
        return None;
    }
    body.get("documents")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .and_then(|d| d.as_str())
        .map(str::to_string)
}

/// Body for Ollama `/api/generate`. `think` is sent only when `Some`: absent means "model
/// default", which is not the same as `false` on a reasoning model.
fn generate_payload(model: &str, prompt: &str, think: Option<bool>) -> Value {
    let mut body = json!({ "model": model, "prompt": prompt, "stream": false });
    if let Some(t) = think {
        body["think"] = Value::Bool(t);
    }
    body
}

/// A pre-embedded document ready to upsert into a Chroma collection.
#[derive(Debug, Clone)]
pub struct UpsertDoc {
    /// Deterministic document id.
    pub id: String,
    /// The embedding vector (must match the collection's dimensionality).
    pub embedding: Vec<f64>,
    /// The document text.
    pub document: String,
    /// Metadata object attached to the document.
    pub metadata: Value,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(meta: Value, distance: Option<f64>) -> Record {
        Record {
            document: String::new(),
            metadata: meta,
            distance,
        }
    }

    #[test]
    fn cosine_distance_basics() {
        let a = vec![1.0, 0.0];
        assert!(cosine_distance(&a, &[1.0, 0.0]).abs() < 1e-9); // identical → 0
        assert!((cosine_distance(&a, &[0.0, 1.0]) - 1.0).abs() < 1e-9); // orthogonal → 1
        assert_eq!(cosine_distance(&a, &[0.0, 0.0]), 1.0); // zero-norm → max, not NaN
    }

    #[test]
    fn location_follows_chunker_precedence() {
        let all = json!({"relative_path": "a/b.md", "filename": "b.md", "source": "s"});
        assert_eq!(metadata_location(&all), "a/b.md");
        assert_eq!(
            metadata_location(&json!({"filename": "b.md", "source": "s"})),
            "b.md"
        );
        // An empty value is skipped, not returned.
        assert_eq!(
            metadata_location(&json!({"relative_path": "", "source": "s"})),
            "s"
        );
        assert_eq!(metadata_location(&json!({})), "");
        assert_eq!(metadata_location(&Value::Null), "");
        assert_eq!(rec(all, None).location(), "a/b.md");
    }

    #[test]
    fn nearest_first_merges_tagged_hits_and_drops_unranked() {
        let hits = vec![
            (rec(json!({"relative_path": "far"}), Some(0.6)), "a"),
            (rec(json!({"relative_path": "none"}), None), "a"),
            (rec(json!({"relative_path": "near"}), Some(0.1)), "b"),
            (rec(json!({"relative_path": "mid"}), Some(0.3)), "a"),
        ];
        let got: Vec<(String, &str)> = nearest_first(hits, 2)
            .into_iter()
            .map(|(r, t)| (r.location().to_string(), t))
            .collect();
        assert_eq!(
            got,
            vec![("near".to_string(), "b"), ("mid".to_string(), "a")]
        );
    }

    #[test]
    fn md5_cache_id_matches_python_hexdigest() {
        // Python: hashlib.md5(b"hello").hexdigest()
        let id = format!("{:x}", Md5::digest(b"hello"));
        assert_eq!(id, "5d41402abc4b2a76b9719d911017c592");
    }

    #[test]
    fn first_document_requires_a_matching_id() {
        let hit = json!({ "ids": ["abc"], "documents": ["summary"] });
        assert_eq!(first_document(&hit).as_deref(), Some("summary"));
        let miss = json!({ "ids": [], "documents": [] });
        assert_eq!(first_document(&miss), None);
    }

    #[test]
    fn entry_id_differs_for_distinct_hash_keys() {
        // The failure mode: two content hashes are "similar" to an embedder but must never
        // share a cache entry. Exact lookup keys on this id.
        let scope = CacheScope::new(ns::SUMMARIZE, "m");
        let a = scope.entry_id("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08");
        let b = scope.entry_id("60303ae22b998861bce3b28f33eec1be758a213c86c93c076dbe9f558c11c752");
        assert_ne!(a, b);
    }

    #[test]
    fn generate_payload_sends_think_only_when_set() {
        let off = generate_payload("m", "p", Some(false));
        assert_eq!(off["think"], Value::Bool(false));
        let default = generate_payload("m", "p", None);
        assert!(default.get("think").is_none());
        assert_eq!(default["stream"], Value::Bool(false));
    }

    /// Explicit values, not the environment: a library test that reached for a deployment's
    /// config would pass or fail depending on whose machine ran it.
    fn test_config() -> ChromaConfig {
        ChromaConfig {
            chroma_base: std::env::var("CHROMA_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:8000".into()),
            ollama_base: std::env::var("OLLAMA_URL_BASE")
                .unwrap_or_else(|_| "http://127.0.0.1:11434".into()),
            ..Default::default()
        }
    }

    #[test]
    fn client_builds() {
        assert!(Rag::new(test_config()).is_ok());
    }

    /// The endpoints have NO defaults; everything else does, and the defaults describe the
    /// products rather than any one deployment.
    #[test]
    fn config_defaults_name_products_not_deployments() {
        let c = ChromaConfig::default();
        assert!(c.chroma_base.is_empty(), "the endpoint is the caller's");
        assert!(c.ollama_base.is_empty(), "the endpoint is the caller's");
        assert_eq!(c.db_root, DB_ROOT);
        assert_eq!(c.embed_model, EMBED_MODEL);
        assert_eq!(c.cache_collection, CACHE_COLLECTION);
    }

    // Live round-trip: gated behind NUVEK_LIVE_TESTS=1 (needs a reachable Chroma + Ollama).
    #[tokio::test]
    async fn live_cache_roundtrip() {
        if std::env::var("NUVEK_LIVE_TESTS").as_deref() != Ok("1") {
            eprintln!("skipping live_cache_roundtrip (set NUVEK_LIVE_TESTS=1)");
            return;
        }
        let rag = Rag::new(test_config()).unwrap();
        let q = format!(
            "nuvek rust migration test {}",
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
        );
        let scope = CacheScope::new("test-ns-a", "test-model");
        rag.write_semantic_cache(&q, "cached answer", scope)
            .await
            .unwrap();
        let hit = rag
            .check_semantic_cache(&q, scope, DEFAULT_CACHE_THRESHOLD)
            .await
            .unwrap();
        assert_eq!(hit.as_deref(), Some("cached answer"));

        // Cross-namespace isolation: the SAME key under a different namespace must NOT hit,
        // however close the vectors land — this is the structural fix.
        let other = CacheScope::new("test-ns-b", "test-model");
        let cross = rag
            .check_semantic_cache(&q, other, DEFAULT_CACHE_THRESHOLD)
            .await
            .unwrap();
        assert_eq!(cross, None, "cross-namespace hit — scope filter failed");
    }

    #[test]
    fn cache_scope_id_is_salted_by_namespace_and_model() {
        let a = CacheScope::new("summarize", "m1");
        let b = CacheScope::new("watchdog-rca", "m1");
        let c = CacheScope::new("summarize", "m2");
        assert_ne!(
            a.entry_id("k"),
            b.entry_id("k"),
            "namespace must salt the id"
        );
        assert_ne!(a.entry_id("k"), c.entry_id("k"), "model must salt the id");
        assert_eq!(a.entry_id("k"), a.entry_id("k"), "id must be deterministic");
    }

    #[test]
    fn cache_scope_where_filter_pins_namespace_and_model() {
        let f = CacheScope::new("summarize", "m1").where_filter();
        let and = f
            .get("$and")
            .and_then(|v| v.as_array())
            .expect("$and array");
        assert_eq!(and.len(), 2);
        assert_eq!(and[0]["namespace"]["$eq"], "summarize");
        assert_eq!(and[1]["model"]["$eq"], "m1");
    }

    #[test]
    fn max_embed_chars_bounds_oversized_text() {
        let long_text = "a".repeat(10_000);
        let truncated: String = long_text.chars().take(MAX_EMBED_CHARS).collect();
        assert_eq!(truncated.len(), MAX_EMBED_CHARS);
        const { assert!(MAX_EMBED_CHARS <= 6_000) };
    }

    /// Ollama's real batch-limit error body must trigger the shrink-and-retry; other failures
    /// must not.
    #[test]
    fn embed_overflow_matches_only_the_batch_limit_error() {
        let real = r#"{"error":"input (2622 tokens) is too large to process. increase the physical batch size (current batch size: 2048)"}"#;
        assert!(is_embed_overflow(500, real));
        let context = r#"{"error":"the input length exceeds the context length"}"#;
        assert!(is_embed_overflow(500, context));
        assert!(!is_embed_overflow(500, r#"{"error":"model not found"}"#));
        assert!(!is_embed_overflow(400, real));
    }

    #[test]
    fn halve_is_char_safe() {
        assert_eq!(halve("éèêë"), "éè");
        assert_eq!(halve("abc"), "a");
        assert_eq!(halve(""), "");
    }
}
