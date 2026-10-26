//! Local Ollama client: summarization and grammar-constrained JSON extraction.
//!
//! Two calls, two models, intended to be used SEQUENTIALLY on a single GPU:
//! - [`Llm::summarize`] (fast/non-reasoning model) compresses long tool outputs before
//!   reasoning. Fail-soft: any error returns a truncated fallback so the pipeline never blocks.
//! - [`Llm::extract_json`] (advanced model) returns grammar-constrained JSON via Ollama's
//!   `format` = JSON-schema, so the model is *asked* for the exact shape and the output
//!   validates without regex scraping.
//! - [`Llm::decide`] / [`Llm::classify`] answer a closed question with a probability per label,
//!   read from the answer token's log-probabilities; failure is an error, never a default.
//!
//! **The endpoint and the model names are the caller's** — see [`LlmConfig`]. This module used to
//! resolve them from a shared config carrying one deployment's Ollama address.
//!
//! ```no_run
//! # fn f() -> anyhow::Result<()> {
//! use nuvek_ollama::{Llm, LlmConfig};
//! use nuvek_core::env::env_or;
//! let llm = Llm::new(LlmConfig {
//!     api_base: format!("{}/api", env_or("OLLAMA_URL_BASE", "http://localhost:11434")),
//!     summarize_model: env_or("MYTOOL_SUMMARIZE_MODEL", "qwen3.5:9b"),
//!     ..Default::default()
//! })?;
//! # Ok(()) }
//! ```

use nuvek_core::gateway::{attempt, Completion, Gateway, GatewayError};

/// Re-exported: [`Llm::generate_tier`] returns it.
pub use nuvek_core::gateway::Answer;

/// The gateway tiers a caller may address by name ([`Llm::generate_tier`]). They exist only on
/// the gateway, never on a model server.
pub const TIERS: [&str; 4] = ["fast", "standard", "code", "reasoning"];
use serde_json::{json, Value};
use std::time::Duration;

/// Re-exported so a consumer can build an [`LlmConfig`] without depending on the feature itself.
pub use nuvek_core::gateway::GatewayConfig;

/// The advanced extractor can be slow; a batch job can afford a long budget. Choose models that
/// fit alongside the embedder; partial CPU placement increases latency.
const EXTRACT_TIMEOUT: Duration = Duration::from_secs(600);
const SUMMARIZE_TIMEOUT: Duration = Duration::from_secs(120);
const DECIDE_TIMEOUT: Duration = Duration::from_secs(60);
const WARMUP_TIMEOUT: Duration = Duration::from_secs(120);
/// Max chars kept in the fail-soft summary fallback.
const FALLBACK_CHARS: usize = 600;

/// Raised on transport failure or empty/garbage model output — the caller fails-soft
/// (treats the session as unprocessed, no partial writes).
#[derive(Debug, thiserror::Error)]
pub enum LlmError {
    /// The HTTP request failed or returned a non-2xx status / unparseable body.
    #[error("{0}")]
    Transport(String),
    /// The model returned no usable content under the JSON-schema constraint.
    #[error("empty extract content from {0}")]
    EmptyContent(String),
    /// The model's answer token was not one of the labels, or no log-probabilities came back.
    #[error("no answer token among the labels from {0}")]
    NoAnswerToken(String),
    /// The caller's label set cannot be told apart by a first token.
    #[error("unusable label set: {0}")]
    BadLabels(String),
}

/// A yes/no verdict with the model's own probability for "yes".
///
/// `p_yes` is read from the log-probabilities of the first answer token and renormalised over
/// the label variants (`Yes`, `yes`, ` yes`, …). It is the model's confidence, not a calibrated
/// one: measure it against a golden set per model before banding decisions on it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Decision {
    /// `p_yes >= 0.5`.
    pub answer: bool,
    /// Probability mass on "yes" among the labels, in `[0, 1]`.
    pub p_yes: f64,
}

/// Alternatives Ollama returns per generated position.
const TOP_LOGPROBS: u32 = 10;
/// With thinking off only the first answer token is read; a few spare tokens cover a model
/// that leads with whitespace.
const DECIDE_NUM_PREDICT: u32 = 4;
/// With thinking on, the reasoning needs room before `</think>`: a reasoning model can spend
/// several hundred tokens on even a one-line question.
const DECIDE_THINK_NUM_PREDICT: u32 = 2048;
/// Ends a reasoning model's thinking. The logprobs array includes the thinking tokens, so the
/// answer is read after the last one of these.
const THINK_END: &str = "</think>";

fn token_text(entry: &Value) -> &str {
    entry.get("token").and_then(Value::as_str).unwrap_or("")
}

/// Reject a label set whose members a first token could not tell apart: fewer than two, a
/// blank, a duplicate, or one label a prefix of another (`no` / `none`).
fn validate_labels(labels: &[&str]) -> Result<(), LlmError> {
    if labels.len() < 2 {
        return Err(LlmError::BadLabels("need at least two labels".into()));
    }
    let lower: Vec<String> = labels.iter().map(|l| l.trim().to_lowercase()).collect();
    for (i, a) in lower.iter().enumerate() {
        if a.is_empty() {
            return Err(LlmError::BadLabels("blank label".into()));
        }
        for b in lower.iter().skip(i + 1) {
            if a.starts_with(b.as_str()) || b.starts_with(a.as_str()) {
                return Err(LlmError::BadLabels(format!(
                    "'{a}' and '{b}' share a prefix"
                )));
            }
        }
    }
    Ok(())
}

/// Probability per label (in `labels` order) from an Ollama `/generate` body, or `None` when
/// the answer token is not a label or the body carries no `logprobs`/`top_logprobs`.
///
/// INVARIANT: the answer's own mass is summed from `top_logprobs`, which only contains it
/// because decoding is greedy (`temperature: 0.0` in [`Llm::decide_payload`]). At a non-zero
/// temperature the sampled token can fall outside the top-k and its mass would silently vanish.
///
/// The answer token is the first non-blank token after the last `</think>` (or from the start
/// when there is no thinking). An alternative counts toward a label when its trimmed,
/// lower-cased text is a prefix of exactly that label; the masses are renormalised over the
/// labels, so tokens that are no label (`<think>`, `The`) never count as any answer.
fn label_distribution(body: &Value, labels: &[&str]) -> Option<Vec<f64>> {
    let lower: Vec<String> = labels.iter().map(|l| l.trim().to_lowercase()).collect();
    let match_label = |tok: &str| -> Option<usize> {
        let t = tok.trim().to_lowercase();
        if t.is_empty() {
            return None;
        }
        let mut hits = lower.iter().enumerate().filter(|(_, l)| l.starts_with(&t));
        match (hits.next(), hits.next()) {
            (Some((i, _)), None) => Some(i),
            _ => None,
        }
    };
    let lps = body.get("logprobs")?.as_array()?;
    let start = lps
        .iter()
        .rposition(|e| token_text(e).trim() == THINK_END)
        .map_or(0, |i| i + 1);
    let answer = lps
        .get(start..)?
        .iter()
        .find(|e| !token_text(e).trim().is_empty())?;
    match_label(token_text(answer))?;
    let mut mass = vec![0.0_f64; labels.len()];
    for alt in answer.get("top_logprobs")?.as_array()? {
        let Some(lp) = alt.get("logprob").and_then(Value::as_f64) else {
            continue;
        };
        if let Some(i) = match_label(token_text(alt)) {
            mass[i] += lp.exp();
        }
    }
    let total: f64 = mass.iter().sum();
    (total > 0.0).then(|| mass.into_iter().map(|m| m / total).collect())
}

/// A model resident in Ollama right now (`/api/ps`).
#[derive(Debug, Clone, PartialEq)]
pub struct Loaded {
    pub name: String,
    pub size_bytes: u64,
    /// How much of it sits in GPU memory. Less than `size_bytes` means Ollama is running part or
    /// all of it on the CPU — `0` is the whole-process CPU fallback that follows a GPU discovery
    /// timeout at startup, and it lasts until the process restarts.
    pub size_vram_bytes: u64,
    pub context_length: Option<u64>,
    pub expires_at: Option<String>,
}

impl Loaded {
    /// True when any part of the model is on the CPU.
    #[must_use]
    pub fn on_cpu(&self) -> bool {
        self.size_vram_bytes < self.size_bytes
    }
}

/// A model installed in Ollama (`/api/tags`).
#[derive(Debug, Clone, PartialEq)]
pub struct Installed {
    pub name: String,
    pub size_bytes: u64,
    pub parameter_size: Option<String>,
    pub quantization: Option<String>,
    pub modified_at: Option<String>,
}

/// One `/api/generate` answer.
#[derive(Debug, Clone, PartialEq)]
pub struct Generated {
    pub response: String,
    /// The reasoning, when `think` was on and the model returned it separately.
    pub thinking: Option<String>,
    /// `stop`, or `length` when `num_predict` ran out (a thinking model can spend it all thinking).
    pub done_reason: Option<String>,
    pub eval_count: Option<u64>,
    pub total_ms: Option<u64>,
}

fn opt_str(v: &Value, k: &str) -> Option<String> {
    v.get(k)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn parse_ps(body: &Value) -> Vec<Loaded> {
    body.get("models")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .map(|m| Loaded {
                    name: opt_str(m, "name").unwrap_or_default(),
                    size_bytes: m.get("size").and_then(Value::as_u64).unwrap_or(0),
                    size_vram_bytes: m.get("size_vram").and_then(Value::as_u64).unwrap_or(0),
                    context_length: m.get("context_length").and_then(Value::as_u64),
                    expires_at: opt_str(m, "expires_at"),
                })
                .collect()
        })
        .unwrap_or_default()
}

fn parse_tags(body: &Value) -> Vec<Installed> {
    body.get("models")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .map(|m| {
                    let d = m.get("details").cloned().unwrap_or(Value::Null);
                    Installed {
                        name: opt_str(m, "name").unwrap_or_default(),
                        size_bytes: m.get("size").and_then(Value::as_u64).unwrap_or(0),
                        parameter_size: opt_str(&d, "parameter_size"),
                        quantization: opt_str(&d, "quantization_level"),
                        modified_at: opt_str(m, "modified_at"),
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

fn parse_generated(body: &Value) -> Generated {
    Generated {
        response: body
            .get("response")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        thinking: opt_str(body, "thinking"),
        done_reason: opt_str(body, "done_reason"),
        eval_count: body.get("eval_count").and_then(Value::as_u64),
        total_ms: body
            .get("total_duration")
            .and_then(Value::as_u64)
            .map(|ns| ns / 1_000_000),
    }
}

/// Take at most `n` characters (never bytes) — a byte slice would panic on a multi-byte
/// UTF-8 boundary, and this runs on arbitrary tool output.
fn take_chars(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// Everything the client needs. No field names a deployment; the two model defaults are
/// properties of the models themselves, and both are overridable.
#[derive(Debug, Clone)]
pub struct LlmConfig {
    /// Ollama API root including `/api`, e.g. `http://localhost:11434/api`.
    pub api_base: String,
    /// Fast/non-reasoning model used by [`Llm::summarize`].
    ///
    /// Defaults to `qwen3.5:9b`. The default favours summary accuracy; benchmark alternatives on
    /// representative inputs. A summary exists so its reader does NOT go read the source — so a
    /// confident wrong summary is worse than a slow one, and worse than none.
    pub summarize_model: String,
    /// Advanced model used by [`Llm::extract_json`].
    pub extract_model: String,
    /// `num_predict` ceiling for extraction.
    pub extract_num_predict: u32,
    /// How long Ollama should hold a model resident, e.g. `"5m"`. Long enough to avoid cold
    /// reloads between sequential calls in a batch; short enough that a large summarizer frees
    /// the GPU for the embedder soon after the batch ends.
    pub keep_alive: String,
    /// LLM gateway to try ahead of direct Ollama for plain generations (spend attribution).
    /// `None` = always direct. The caller resolves it (e.g. `GatewayConfig::from_env` with its
    /// own variable names); this crate reads no environment.
    pub gateway: Option<GatewayConfig>,
}

impl Default for LlmConfig {
    fn default() -> Self {
        Self {
            api_base: String::new(),
            summarize_model: "qwen3.5:9b".into(),
            extract_model: "qwen3.5:9b".into(),
            extract_num_predict: 2048,
            keep_alive: "5m".into(),
            gateway: None,
        }
    }
}

/// Local Ollama client. Cheap to clone (`reqwest::Client` is an `Arc`).
#[derive(Clone)]
pub struct Llm {
    http: reqwest::Client,
    ollama_api: String,
    summarize_model: String,
    extract_model: String,
    extract_num_predict: u32,
    keep_alive: String,
    gateway: Option<Gateway>,
}

impl Llm {
    /// Build an Ollama client from the caller's settings.
    pub fn new(cfg: LlmConfig) -> anyhow::Result<Self> {
        let http = nuvek_core::http::client(EXTRACT_TIMEOUT)?;
        let gateway = cfg.gateway.map(Gateway::new).transpose()?;
        Ok(Self {
            http,
            ollama_api: cfg.api_base,
            summarize_model: cfg.summarize_model,
            extract_model: cfg.extract_model,
            extract_num_predict: cfg.extract_num_predict,
            keep_alive: cfg.keep_alive,
            gateway,
        })
    }

    /// Whether the client is configured to route completions through a gateway.
    #[must_use]
    pub fn has_gateway(&self) -> bool {
        self.gateway.is_some()
    }

    /// The resolved gateway completions URL, if configured.
    #[must_use]
    pub fn gateway_url(&self) -> Option<&str> {
        self.gateway.as_ref().map(Gateway::url)
    }

    /// Count a call that must go direct because the gateway cannot express it (Ollama
    /// log-probabilities, grammar-constrained `format`). No-op without a gateway.
    fn record_bypass(&self) {
        if let Some(g) = &self.gateway {
            g.record_direct("bypass");
        }
    }

    /// The resolved fast/summarize model name.
    #[must_use]
    pub fn summarize_model(&self) -> &str {
        &self.summarize_model
    }

    /// The resolved advanced/extract model name.
    #[must_use]
    pub fn extract_model(&self) -> &str {
        &self.extract_model
    }

    /// Load a model into VRAM ahead of a batch (one-time cost, not per-call).
    pub async fn warmup(&self, model: &str) -> Result<(), LlmError> {
        self.http
            .post(format!("{}/generate", self.ollama_api))
            .json(&json!({ "model": model, "prompt": "", "keep_alive": self.keep_alive }))
            .timeout(WARMUP_TIMEOUT)
            .send()
            .await
            .map_err(|e| LlmError::Transport(format!("warmup failed for {model}: {e}")))?;
        Ok(())
    }

    /// Compress a long tool output with the FAST model (LOCAL-FIRST). On ANY failure returns a
    /// truncated fallback so the pipeline never blocks on a summary.
    pub async fn summarize(&self, text: &str) -> String {
        let prompt = format!(
            "Summarize the following command/tool output in 2-3 sentences, keeping only \
             facts useful for understanding what happened. No preamble.\n\n{text}"
        );
        let payload = self.summarize_payload(&prompt);
        match self.generate_response(&payload, SUMMARIZE_TIMEOUT).await {
            Some(resp) if !resp.trim().is_empty() => resp.trim().to_string(),
            _ => take_chars(text, FALLBACK_CHARS), // fail-soft: never block extraction
        }
    }

    /// Summarize `text` under a caller-supplied `instruction` with the FAST model (LOCAL-FIRST).
    ///
    /// Unlike [`Llm::summarize`] (fixed prompt, truncation fallback), this returns `None` on any
    /// transport failure or empty output so the caller decides its own fallback — for example a
    /// document indexer that drops back to a regex-scraped description rather than dumping raw
    /// text. `instruction` is the full task framing; `text` is appended verbatim.
    pub async fn summarize_with(&self, instruction: &str, text: &str) -> Option<String> {
        self.summarize_with_model(&self.summarize_model, instruction, text)
            .await
    }

    /// Like [`Llm::summarize_with`] but with an explicit `model`, so a caller can pick a stronger
    /// model for inputs the fast one cannot handle (for example a larger model for long,
    /// table-heavy docs). `think` is disabled so a reasoning model returns the summary directly
    /// rather than chain-of-thought. Fail-soft: `None` on failure or empty output.
    pub async fn summarize_with_model(
        &self,
        model: &str,
        instruction: &str,
        text: &str,
    ) -> Option<String> {
        let prompt = format!("{instruction}\n\n{text}");
        let payload = json!({
            "model": model, "prompt": prompt, "stream": false,
            "think": false,
            "keep_alive": self.keep_alive, "options": { "temperature": 0.0 },
        });
        self.generate_response(&payload, SUMMARIZE_TIMEOUT)
            .await
            .map(|r| r.trim().to_string())
            .filter(|r| !r.is_empty())
    }

    /// Yes/no with a probability, on the FAST model with thinking off. Failure is an error,
    /// never a silent "no" — the old bool `yes_no` turned every failure into "no", which hid a
    /// thinking model's empty answers for three months.
    pub async fn decide(&self, question: &str) -> Result<Decision, LlmError> {
        self.decide_with(&self.summarize_model, question, false)
            .await
    }

    /// [`Llm::decide`] with an explicit model, and `think` on for a slower second opinion.
    pub async fn decide_with(
        &self,
        model: &str,
        question: &str,
        think: bool,
    ) -> Result<Decision, LlmError> {
        let dist = self
            .classify(model, question, &["yes", "no"], think)
            .await?;
        let p_yes = dist.first().copied().unwrap_or(0.0);
        Ok(Decision {
            answer: p_yes >= 0.5,
            p_yes,
        })
    }

    /// Probability per label, in `labels` order, read from the first answer token.
    ///
    /// The question should ask for exactly one of the labels. No `format` schema is sent:
    /// grammar masking is applied after the model's distribution, so under a schema the
    /// log-probabilities stop describing the answer.
    pub async fn classify(
        &self,
        model: &str,
        question: &str,
        labels: &[&str],
        think: bool,
    ) -> Result<Vec<f64>, LlmError> {
        validate_labels(labels)?;
        let payload = self.decide_payload(model, question, think);
        let timeout = if think {
            EXTRACT_TIMEOUT
        } else {
            DECIDE_TIMEOUT
        };
        // Direct by necessity: a gateway may not forward `logprobs` to Ollama.
        self.record_bypass();
        let body = self
            .post_json(&format!("{}/generate", self.ollama_api), &payload, timeout)
            .await
            .map_err(|e| LlmError::Transport(format!("decide transport failed ({model}): {e}")))?;
        label_distribution(&body, labels).ok_or_else(|| LlmError::NoAnswerToken(model.to_string()))
    }

    fn decide_payload(&self, model: &str, question: &str, think: bool) -> Value {
        let num_predict = if think {
            DECIDE_THINK_NUM_PREDICT
        } else {
            DECIDE_NUM_PREDICT
        };
        json!({
            "model": model, "prompt": question, "stream": false,
            "think": think,
            "logprobs": true, "top_logprobs": TOP_LOGPROBS,
            "keep_alive": self.keep_alive,
            // Greedy decoding is load-bearing: `label_distribution` reads the answer's own
            // probability out of `top_logprobs`, where only the argmax token is guaranteed.
            "options": { "temperature": 0.0, "num_predict": num_predict },
        })
    }

    /// `think` is OFF: the default model reasons, and without this a summary pays a full
    /// chain-of-thought pass first.
    fn summarize_payload(&self, prompt: &str) -> Value {
        json!({
            "model": self.summarize_model, "prompt": prompt, "stream": false,
            "think": false,
            "keep_alive": self.keep_alive, "options": { "temperature": 0.0 },
        })
    }

    /// Call the extract model with grammar-constrained JSON output (`format` = schema).
    ///
    /// Returns the raw JSON string (the caller validates it). Errors with [`LlmError`] on
    /// transport failure or empty content — the caller treats that session as unprocessed
    /// (fail-soft, no partial writes).
    pub async fn extract_json(
        &self,
        system: &str,
        user: &str,
        schema: &Value,
    ) -> Result<String, LlmError> {
        let payload = json!({
            "model": self.extract_model,
            "messages": [
                { "role": "system", "content": system },
                { "role": "user", "content": user },
            ],
            "format": schema,
            "stream": false,
            // think OFF: a reasoning pass under grammar-constrained decoding is pathologically
            // slow, worse still with partial CPU placement. The JSON-schema `format` already
            // constrains output shape.
            "think": false,
            "keep_alive": self.keep_alive,
            "options": { "temperature": 0.0, "num_predict": self.extract_num_predict },
        });
        // Direct: a gateway may not pass a grammar-constrained `format` through.
        self.record_bypass();
        let data = self
            .post_json(
                &format!("{}/chat", self.ollama_api),
                &payload,
                EXTRACT_TIMEOUT,
            )
            .await
            .map_err(|e| {
                LlmError::Transport(format!(
                    "extract transport failed ({}): {e}",
                    self.extract_model
                ))
            })?;
        let content = data
            .get("message")
            .and_then(|m| m.get("content"))
            .and_then(Value::as_str)
            .unwrap_or("");
        if content.trim().is_empty() {
            return Err(LlmError::EmptyContent(self.extract_model.clone()));
        }
        Ok(content.to_string())
    }

    /// The models resident right now, with how much of each is in GPU memory.
    pub async fn ps(&self) -> Result<Vec<Loaded>, LlmError> {
        let body = self
            .get_json(&format!("{}/ps", self.ollama_api))
            .await
            .map_err(|e| LlmError::Transport(format!("ps failed: {e}")))?;
        Ok(parse_ps(&body))
    }

    /// The models installed.
    pub async fn models(&self) -> Result<Vec<Installed>, LlmError> {
        let body = self
            .get_json(&format!("{}/tags", self.ollama_api))
            .await
            .map_err(|e| LlmError::Transport(format!("tags failed: {e}")))?;
        Ok(parse_tags(&body))
    }

    /// One non-streamed generation with `think` stated explicitly (a reasoning model's default is
    /// to think, which empties the answer under a small `num_predict`). Greedy decoding.
    pub async fn generate(
        &self,
        model: &str,
        prompt: &str,
        think: bool,
        num_predict: u32,
    ) -> Result<Generated, LlmError> {
        let payload = json!({
            "model": model, "prompt": prompt, "stream": false, "think": think,
            "keep_alive": self.keep_alive,
            "options": { "temperature": 0.0, "num_predict": num_predict },
        });
        let timeout = if think {
            EXTRACT_TIMEOUT
        } else {
            SUMMARIZE_TIMEOUT
        };
        let (answer, direct_timeout) =
            attempt(self.gateway.as_ref(), &completion_from(&payload), timeout).await;
        if let Some(a) = answer {
            return Ok(generated_from_gateway(a));
        }
        let body = self
            .post_json(
                &format!("{}/generate", self.ollama_api),
                &payload,
                direct_timeout,
            )
            .await
            .map_err(|e| LlmError::Transport(format!("generate failed ({model}): {e}")))?;
        Ok(parse_generated(&body))
    }

    /// One generation addressed to a gateway TIER (`fast`, `standard`, `code`, `reasoning`).
    ///
    /// Gateway-only, deliberately: a tier name means nothing to Ollama, so the usual direct
    /// fallback would send `code` to a server that has no such model. The gateway owns failover
    /// between configured deployments, and the returned [`Answer::model`] / [`Answer::backend`]
    /// say what actually answered.
    pub async fn generate_tier(
        &self,
        tier: &str,
        prompt: &str,
        think: bool,
        num_predict: u32,
    ) -> Result<Answer, LlmError> {
        if !TIERS.contains(&tier) {
            return Err(LlmError::Transport(format!(
                "unknown tier '{tier}'; valid tiers: {TIERS:?}"
            )));
        }
        let gateway = self.gateway.as_ref().ok_or_else(|| {
            LlmError::Transport(
                "no LLM gateway is configured, and tiers exist only on the gateway".into(),
            )
        })?;
        let req = Completion {
            model: tier,
            system: None,
            prompt,
            think: Some(think),
            max_tokens: Some(num_predict),
            temperature: Some(0.0),
        };
        // `reasoning` is a thinking model whatever `think` says, and a cold model load may need a
        // longer timeout: give both the long budget.
        let timeout = if think || tier == "reasoning" {
            EXTRACT_TIMEOUT
        } else {
            SUMMARIZE_TIMEOUT
        };
        gateway
            .complete_only(&req, timeout)
            .await
            .map_err(|e| match e {
                GatewayError::Empty => LlmError::Transport(format!(
                    "tier '{tier}' returned no answer — the token budget likely ran out while \
                     thinking; raise num_predict, or use think=false"
                )),
                other => LlmError::Transport(format!("tier '{tier}': {other}")),
            })
    }

    /// GET and return the decoded body, error on transport/status/parse failure.
    async fn get_json(&self, url: &str) -> anyhow::Result<Value> {
        let resp = self
            .http
            .get(url)
            .timeout(DECIDE_TIMEOUT)
            .send()
            .await?
            .error_for_status()?;
        Ok(resp.json().await?)
    }

    /// POST JSON and return the decoded body, error on transport/status/parse failure.
    async fn post_json(
        &self,
        url: &str,
        payload: &Value,
        timeout: Duration,
    ) -> anyhow::Result<Value> {
        let resp = self
            .http
            .post(url)
            .json(payload)
            .timeout(timeout)
            .send()
            .await?
            .error_for_status()?;
        Ok(resp.json().await?)
    }

    /// POST to `/generate` — through the gateway first when one is configured, falling back to
    /// direct Ollama — and pull the `response` string, or None on any failure (fail-soft).
    ///
    /// The worst case (gateway times out, then the fallback runs) stays within `timeout` — see
    /// [`attempt`]. A payload the gateway cannot express (`format`, `logprobs`) goes direct and is
    /// counted as a bypass.
    async fn generate_response(&self, payload: &Value, timeout: Duration) -> Option<String> {
        let direct_timeout = if self.gateway.is_some() && !gateway_can_express(payload) {
            self.record_bypass();
            timeout
        } else {
            let (answer, left) =
                attempt(self.gateway.as_ref(), &completion_from(payload), timeout).await;
            if let Some(a) = answer {
                return Some(a.text);
            }
            left
        };
        let data = self
            .post_json(
                &format!("{}/generate", self.ollama_api),
                payload,
                direct_timeout,
            )
            .await
            .ok()?;
        data.get("response")
            .and_then(Value::as_str)
            .map(str::to_string)
    }
}

/// A gateway [`Answer`] in Ollama's terms: `finish_reason` is the same word as `done_reason`
/// (`stop` / `length`), and `completion_tokens` is `eval_count`. The thinking trace and timing are
/// not part of the OpenAI answer, so they stay unknown.
fn generated_from_gateway(a: Answer) -> Generated {
    Generated {
        response: a.text,
        thinking: None,
        done_reason: a.finish_reason,
        eval_count: a.completion_tokens,
        total_ms: None,
    }
}

/// Whether an Ollama `/generate` payload can be sent through the OpenAI-compatible gateway
/// without losing meaning. `format` (grammar-constrained output) and `logprobs` cannot.
fn gateway_can_express(payload: &Value) -> bool {
    payload.get("format").is_none() && payload.get("logprobs").is_none()
}

/// Map an Ollama `/generate` payload onto a gateway [`Completion`]: model, prompt, system,
/// `think`, `options.num_predict` → `max_tokens`, `options.temperature`. `keep_alive` is
/// Ollama-side residency and has no gateway equivalent; the gateway's own config governs it.
fn completion_from(payload: &Value) -> Completion<'_> {
    let opt = |k: &str| payload.get("options").and_then(|o| o.get(k));
    Completion {
        model: payload.get("model").and_then(Value::as_str).unwrap_or(""),
        system: payload.get("system").and_then(Value::as_str),
        prompt: payload.get("prompt").and_then(Value::as_str).unwrap_or(""),
        think: payload.get("think").and_then(Value::as_bool),
        max_tokens: opt("num_predict")
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok()),
        temperature: opt("temperature").and_then(Value::as_f64),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn take_chars_is_char_safe() {
        // A byte slice at 3 would split the euro sign; char-based must not panic.
        assert_eq!(take_chars("€abc", 2), "€a");
        assert_eq!(take_chars("hello", 600), "hello");
        assert_eq!(take_chars("", 600), "");
    }

    /// A reasoning default model must not think on the fast paths: a decision would spend its
    /// token budget thinking and come back with no answer, and a summary would pay a reasoning
    /// pass.
    #[test]
    fn fast_payloads_disable_thinking() {
        let llm = Llm::new(LlmConfig::default()).expect("client builds");
        assert_eq!(llm.decide_payload("m", "q", false)["think"], json!(false));
        assert_eq!(llm.summarize_payload("p")["think"], json!(false));
    }

    fn fixture(name: &str) -> Value {
        let raw = match name {
            "off" => include_str!("../tests/fixtures/decide_think_off.json"),
            _ => include_str!("../tests/fixtures/decide_think_on.json"),
        };
        serde_json::from_str(raw).expect("fixture parses")
    }

    /// Real qwen3.5:4b answer, thinking off: `Yes` −0.238, `yes` −3.91, ` Yes`, ` yes` against
    /// `No` −1.69, `no` −5.11; `<think>`, `The`, `A`, `Answer` must not count.
    #[test]
    fn distribution_sums_variants_and_drops_non_labels() {
        let d = label_distribution(&fixture("off"), &["yes", "no"]).expect("labels found");
        assert!((d[0] - 0.8097).abs() < 1e-3, "p_yes = {}", d[0]);
        assert!((d[0] + d[1] - 1.0).abs() < 1e-9);
    }

    /// A CPU-only model fixture: an `/api/ps` answer where the model is resident with
    /// `size_vram: 0`, i.e. entirely on the CPU. That is exactly what `on_cpu` must flag.
    #[test]
    fn ps_flags_the_cpu_fallback() {
        let body: Value = serde_json::from_str(include_str!("../tests/fixtures/ps.json"))
            .expect("fixture parses");
        let loaded = parse_ps(&body);
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].name, "nomic-embed-text:latest");
        assert_eq!(loaded[0].size_vram_bytes, 0);
        assert!(loaded[0].on_cpu());
        let gpu = Loaded {
            size_vram_bytes: loaded[0].size_bytes,
            ..loaded[0].clone()
        };
        assert!(!gpu.on_cpu());
        assert!(parse_ps(&json!({ "models": [] })).is_empty());
    }

    #[test]
    fn tags_and_generate_parse() {
        let tags = parse_tags(
            &json!({ "models": [ { "name": "qwen3.5:9b", "size": 6594474711_u64,
            "details": { "parameter_size": "9.7B", "quantization_level": "Q4_K_M" } } ] }),
        );
        assert_eq!(tags[0].parameter_size.as_deref(), Some("9.7B"));
        let g = parse_generated(
            &json!({ "response": "", "thinking": "Okay", "done_reason": "length",
            "eval_count": 8, "total_duration": 2_500_000_000_u64 }),
        );
        assert_eq!(g.done_reason.as_deref(), Some("length"));
        assert_eq!(g.total_ms, Some(2500));
        assert_eq!(g.thinking.as_deref(), Some("Okay"));
    }

    /// Real qwen3.5:9b answer, thinking on: the answer is read after `</think>`, skipping the
    /// blank `\n\n` token whose alternatives include `yes`.
    #[test]
    fn distribution_reads_after_thinking() {
        let d = label_distribution(&fixture("on"), &["yes", "no"]).expect("labels found");
        assert!(d[0] > 0.95, "p_yes = {}", d[0]);
    }

    #[test]
    fn non_label_answer_is_none_not_no() {
        let body = json!({ "logprobs": [ { "token": "The", "logprob": -0.1,
            "top_logprobs": [ { "token": "The", "logprob": -0.1 }, { "token": "No", "logprob": -3.0 } ] } ] });
        assert_eq!(label_distribution(&body, &["yes", "no"]), None);
        assert_eq!(
            label_distribution(&json!({ "response": "yes" }), &["yes", "no"]),
            None
        );
    }

    #[test]
    fn labels_that_share_a_prefix_are_rejected() {
        assert!(validate_labels(&["yes", "no"]).is_ok());
        assert!(validate_labels(&["restart", "escalate", "ignore"]).is_ok());
        assert!(validate_labels(&["no", "none"]).is_err());
        assert!(validate_labels(&["yes", "Yes"]).is_err());
        assert!(validate_labels(&["yes"]).is_err());
        assert!(validate_labels(&["yes", " "]).is_err());
    }

    #[test]
    fn decide_payload_sends_logprobs_and_no_schema() {
        let llm = Llm::new(LlmConfig::default()).expect("client builds");
        let p = llm.decide_payload("m", "q", false);
        assert_eq!(p["logprobs"], json!(true));
        assert_eq!(p["think"], json!(false));
        assert!(
            p.get("format").is_none(),
            "a schema would mask the logprobs"
        );
        assert_eq!(llm.decide_payload("m", "q", true)["think"], json!(true));
    }

    /// The config carries model defaults; nothing here reads the environment.
    #[test]
    fn config_defaults_name_models_not_deployments() {
        let c = LlmConfig::default();
        assert_eq!(c.summarize_model, "qwen3.5:9b");
        assert_eq!(c.extract_model, "qwen3.5:9b");
        assert!(
            c.api_base.is_empty(),
            "the endpoint must have no default — it is the caller's"
        );
        assert!(c.gateway.is_none());
    }

    #[test]
    fn gateway_is_only_what_the_caller_supplies() {
        let direct = Llm::new(LlmConfig {
            api_base: "http://ollama.invalid:11434/api".into(),
            ..Default::default()
        })
        .expect("client builds");
        assert!(
            !direct.has_gateway(),
            "no env is read: no gateway unless given"
        );

        let routed = Llm::new(LlmConfig {
            api_base: "http://ollama.invalid:11434/api".into(),
            gateway: Some(GatewayConfig {
                base: "http://gateway.invalid:4000".into(),
                key: "test-key".into(),
                metrics: None,
                caller: None,
            }),
            ..Default::default()
        })
        .expect("client builds");
        assert_eq!(
            routed.gateway_url(),
            Some("http://gateway.invalid:4000/v1/chat/completions")
        );
    }

    #[test]
    fn completion_from_maps_ollama_fields() {
        let p = json!({
            "model": "qwen3.5:4b", "prompt": "hi", "system": "be brief", "think": false,
            "keep_alive": "5m", "options": { "temperature": 0.0, "num_predict": 128 },
        });
        let c = completion_from(&p);
        assert_eq!(c.model, "qwen3.5:4b");
        assert_eq!(c.prompt, "hi");
        assert_eq!(c.system, Some("be brief"));
        assert_eq!(c.think, Some(false));
        assert_eq!(c.max_tokens, Some(128));
        assert_eq!(c.temperature, Some(0.0));
    }

    #[test]
    fn a_gateway_answer_keeps_done_reason_and_eval_count() {
        let g = generated_from_gateway(Answer {
            text: "x".into(),
            finish_reason: Some("length".into()),
            completion_tokens: Some(64),
            prompt_tokens: None,
            model: None,
            backend: None,
            cache_hit: false,
        });
        assert_eq!(g.done_reason.as_deref(), Some("length"));
        assert_eq!(g.eval_count, Some(64));
    }

    #[tokio::test]
    async fn a_tier_without_a_gateway_errors_instead_of_asking_ollama() {
        let llm = Llm::new(LlmConfig {
            api_base: "http://127.0.0.1:9/api".into(),
            ..Default::default()
        })
        .expect("client builds");
        let err = llm
            .generate_tier("code", "p", false, 16)
            .await
            .expect_err("no gateway");
        assert!(err.to_string().contains("only on the gateway"), "{err}");
    }

    #[tokio::test]
    async fn an_unknown_tier_is_rejected_before_any_request() {
        let llm = Llm::new(LlmConfig {
            api_base: "http://127.0.0.1:9/api".into(),
            gateway: Some(GatewayConfig {
                base: "http://127.0.0.1:9".into(),
                key: "k".into(),
                metrics: None,
                caller: None,
            }),
            ..Default::default()
        })
        .expect("client builds");
        let err = llm
            .generate_tier("qwen3.5:9b", "p", false, 16)
            .await
            .expect_err("not a tier");
        assert!(err.to_string().contains("unknown tier"), "{err}");
    }

    #[test]
    fn format_and_logprobs_are_not_sent_through_the_gateway() {
        assert!(gateway_can_express(&json!({"model": "m", "prompt": "p"})));
        assert!(!gateway_can_express(&json!({"model": "m", "format": {}})));
        assert!(!gateway_can_express(
            &json!({"model": "m", "logprobs": true})
        ));
    }

    /// An unreachable gateway falls back to direct Ollama within the ORIGINAL budget.
    #[tokio::test]
    async fn a_dead_gateway_falls_back_without_doubling_the_timeout() {
        let llm = Llm::new(LlmConfig {
            // Nothing listens on port 9 on loopback: both paths fail fast.
            api_base: "http://127.0.0.1:9/api".into(),
            gateway: Some(GatewayConfig {
                base: "http://127.0.0.1:9".into(),
                key: "k".into(),
                metrics: None,
                caller: None,
            }),
            ..Default::default()
        })
        .expect("client builds");
        let started = std::time::Instant::now();
        let got = llm
            .generate_response(
                &json!({"model": "m", "prompt": "p"}),
                Duration::from_secs(4),
            )
            .await;
        assert!(got.is_none());
        assert!(started.elapsed() < Duration::from_secs(5));
    }
}
