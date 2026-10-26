//! OpenAI-compatible chat-completions client for an LLM gateway (LiteLLM, or anything speaking
//! `POST /v1/chat/completions`), tried AHEAD of a direct model-server call.
//!
//! A gateway centralises attribution and spend tracking, but it must never become a new single
//! point of failure for tools that worked without it. So the contract is fail-soft: [`Gateway::
//! complete`] returns an error the caller answers by falling back to its direct path, and every
//! outcome — gateway success, each kind of gateway failure, and a deliberate bypass — is counted
//! (`llm_route_calls_total{route,reason}`), because a fallback that is silent makes a dead gateway
//! look healthy: every call still succeeds, just not through it.
//!
//! Mechanism only: the base URL, the key and the variable names that hold them are the caller's.

use std::time::Duration;

use serde_json::{json, Value};

use crate::metrics::Metrics;

/// Where to send completions and how to authenticate. `Debug` is hand-written and redacts the
/// key, so a config can sit inside a `#[derive(Debug)]` struct without leaking it.
#[derive(Clone)]
pub struct GatewayConfig {
    /// Gateway base URL, with or without a trailing `/v1`.
    pub base: String,
    /// Bearer token (a per-caller virtual key, for attribution).
    pub key: String,
    /// Where route counters go; `None` disables them.
    pub metrics: Option<Metrics>,
    /// Who is calling, sent as request metadata (`metadata.caller`) and a request tag so the
    /// gateway can attribute calls that share one key. Defaults to the executable's name.
    pub caller: Option<String>,
}

impl std::fmt::Debug for GatewayConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GatewayConfig")
            .field("base", &self.base)
            .field("key", &"«redacted»")
            .field("metrics", &self.metrics.is_some())
            .field("caller", &self.caller)
            .finish()
    }
}

/// The running executable's name, as a caller label. `None` if it cannot be read or reduces to
/// nothing after [`caller_label`].
fn process_name() -> Option<String> {
    let exe = std::env::current_exe().ok()?;
    caller_label(&exe.file_stem()?.to_string_lossy())
}

/// A caller name made safe to use as a metric label value: lower-case `[a-z0-9_-]`, at most 64
/// characters; `None` when nothing is left. Label values come from our own binary names, but the
/// gateway turns them into Prometheus series, so the alphabet and length are bounded here.
fn caller_label(name: &str) -> Option<String> {
    let s: String = name
        .chars()
        .map(|c| c.to_ascii_lowercase())
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .take(64)
        .collect();
    (!s.is_empty()).then_some(s)
}

impl GatewayConfig {
    /// Resolve from environment variables the CALLER names, or `None` (route direct) when
    /// `disable_var` is `1`, no base is set, or the key is missing.
    ///
    /// `base_vars` are tried in order (e.g. a current name, then a legacy one). Blank is unset.
    #[must_use]
    pub fn from_env(base_vars: &[&str], key_var: &str, disable_var: &str) -> Option<Self> {
        if crate::env::env_var(disable_var).as_deref() == Some("1") {
            return None;
        }
        let base = base_vars.iter().find_map(|v| crate::env::env_var(v))?;
        let key = crate::env::env_var(key_var)?;
        Some(Self {
            base,
            key,
            metrics: None,
            caller: process_name(),
        })
    }

    /// Attach a metrics writer for route counters.
    #[must_use]
    pub fn with_metrics(mut self, metrics: Option<Metrics>) -> Self {
        self.metrics = metrics;
        self
    }

    /// Override the caller name (default: the executable's name). Sanitized by the same rule.
    #[must_use]
    pub fn with_caller(mut self, caller: &str) -> Self {
        self.caller = caller_label(caller);
        self
    }
}

/// One completion request, expressed in the caller's (Ollama-shaped) terms.
#[derive(Debug, Clone, Copy)]
pub struct Completion<'a> {
    pub model: &'a str,
    pub system: Option<&'a str>,
    pub prompt: &'a str,
    /// Sent as a top-level `think` field. A gateway such as LiteLLM forwards it to Ollama, where
    /// `false` stops a reasoning model's trace. `None` leaves the model default.
    pub think: Option<bool>,
    /// Maps from Ollama's `num_predict`.
    pub max_tokens: Option<u32>,
    pub temperature: Option<f64>,
}

/// Why a gateway call did not produce an answer. Each maps to a counter `reason`.
#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    #[error("gateway transport failed: {0}")]
    Transport(String),
    #[error("gateway returned HTTP {0}")]
    Status(u16),
    #[error("gateway response unparseable: {0}")]
    Parse(String),
    #[error("gateway returned an empty answer")]
    Empty,
}

impl GatewayError {
    /// The `reason` label this failure is counted under.
    #[must_use]
    pub fn reason(&self) -> &'static str {
        match self {
            GatewayError::Transport(_) => "transport",
            GatewayError::Status(_) => "status",
            GatewayError::Parse(_) => "parse",
            GatewayError::Empty => "empty",
        }
    }
}

/// `{base}/v1/chat/completions`, whether or not `base` already ends in `/v1`.
#[must_use]
pub fn completions_url(base: &str) -> String {
    let base = base.trim_end_matches('/');
    if base.ends_with("/v1") {
        format!("{base}/chat/completions")
    } else {
        format!("{base}/v1/chat/completions")
    }
}

/// The request body for one [`Completion`].
#[must_use]
pub fn chat_payload(req: &Completion<'_>) -> Value {
    let mut messages = Vec::new();
    if let Some(s) = req.system {
        messages.push(json!({ "role": "system", "content": s }));
    }
    messages.push(json!({ "role": "user", "content": req.prompt }));
    let mut body = json!({ "model": req.model, "messages": messages, "stream": false });
    if let Some(t) = req.think {
        body["think"] = Value::Bool(t);
    }
    if let Some(n) = req.max_tokens {
        body["max_tokens"] = json!(n);
    }
    if let Some(t) = req.temperature {
        body["temperature"] = json!(t);
    }
    body
}

/// Stamp the caller onto a request body: `metadata.caller` (which the gateway can expose as a
/// metric label) and a request tag (which it records per request). No caller, no change.
fn with_caller(mut body: Value, caller: Option<&str>) -> Value {
    if let Some(c) = caller {
        body["metadata"] = json!({ "caller": c });
        body["tags"] = json!([c]);
    }
    body
}

/// An authenticated gateway client. Cheap to clone. Never Debug: it holds a credential.
#[derive(Clone)]
pub struct Gateway {
    http: reqwest::Client,
    url: String,
    key: String,
    metrics: Option<Metrics>,
    caller: Option<String>,
}

impl Gateway {
    /// Build a client. Per-call timeouts are passed to [`Gateway::complete`].
    pub fn new(cfg: GatewayConfig) -> anyhow::Result<Self> {
        Ok(Self {
            http: crate::http::client(Duration::from_secs(300))?,
            url: completions_url(&cfg.base),
            key: cfg.key,
            metrics: cfg.metrics,
            caller: cfg.caller,
        })
    }

    /// The resolved completions URL.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// One non-streamed completion. Counts the outcome; on `Err` the caller falls back.
    ///
    /// An empty answer is an error ([`GatewayError::Empty`]), not a success: a reasoning model
    /// that spends its whole budget thinking returns empty `content`, and the direct path at least
    /// reports why (`done_reason`, the thinking) — while an empty "success" would be returned, or
    /// cached, as if it were an answer.
    pub async fn complete(
        &self,
        req: &Completion<'_>,
        timeout: Duration,
    ) -> Result<Answer, GatewayError> {
        let result = self.send(req, timeout).await;
        match &result {
            Ok(_) => self.record("gateway", "ok"),
            Err(e) => {
                tracing::warn!("LLM gateway failed ({e}); falling back to the direct path");
                self.record("direct", e.reason());
            }
        }
        result
    }

    /// One completion through the gateway with NO direct fallback — for a caller that addresses a
    /// gateway-only name (a tier such as `code`, which no model server knows). The gateway's own
    /// fallbacks still apply; [`Answer::model`] and [`Answer::backend`] say what actually answered.
    /// A failure is counted as `route="gateway"`, not `direct`: nothing fell back.
    pub async fn complete_only(
        &self,
        req: &Completion<'_>,
        timeout: Duration,
    ) -> Result<Answer, GatewayError> {
        let result = self.send(req, timeout).await;
        match &result {
            Ok(_) => self.record("gateway", "ok"),
            Err(e) => self.record("gateway", e.reason()),
        }
        result
    }

    /// Count a call the caller deliberately routed direct (`reason` e.g. `"bypass"` for a request
    /// the gateway cannot express, like Ollama log-probabilities).
    pub fn record_direct(&self, reason: &str) {
        self.record("direct", reason);
    }

    fn record(&self, route: &str, reason: &str) {
        if let Some(m) = &self.metrics {
            m.record_llm_route(route, reason);
        }
    }

    async fn send(&self, req: &Completion<'_>, timeout: Duration) -> Result<Answer, GatewayError> {
        let resp = self
            .http
            .post(&self.url)
            .bearer_auth(&self.key)
            .json(&with_caller(chat_payload(req), self.caller.as_deref()))
            .timeout(timeout)
            .send()
            .await
            // without_url: never put the endpoint (or anything in it) into an error string.
            .map_err(|e| GatewayError::Transport(e.without_url().to_string()))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(GatewayError::Status(status.as_u16()));
        }
        let header = |name: &str| {
            resp.headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        };
        let backend = header(BACKEND_HEADER);
        let cache_hit = header(CACHE_KEY_HEADER).is_some();
        let served_by = header(MODEL_NAME_HEADER);
        let body: Value = resp
            .json()
            .await
            .map_err(|e| GatewayError::Parse(e.without_url().to_string()))?;
        let mut answer = parse_answer(&body)?;
        answer.backend = backend;
        answer.cache_hit = cache_hit;
        answer.model = served_model(served_by, answer.model.take());
        Ok(answer)
    }
}

/// LiteLLM response header naming the deployment that served the call (its `api_base`).
pub const BACKEND_HEADER: &str = "x-litellm-model-api-base";
/// LiteLLM response header present only when the answer came from its cache.
pub const CACHE_KEY_HEADER: &str = "x-litellm-cache-key";
/// LiteLLM response header naming the deployment's underlying model (`provider/model`).
pub const MODEL_NAME_HEADER: &str = "x-litellm-model-name";

/// The model that actually served a call. The proxy restamps the body's `model` with the name the
/// client REQUESTED (a tier such as `code`), so the body alone cannot show what answered; the
/// [`MODEL_NAME_HEADER`] can. The body is the fallback for a gateway that does not send it.
fn served_model(header: Option<String>, body: Option<String>) -> Option<String> {
    header.filter(|h| !h.trim().is_empty()).or(body)
}

/// A gateway answer: the text plus what Ollama would have reported, in OpenAI terms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    pub text: String,
    /// `choices[0].finish_reason` — `stop`, or `length` when the token budget ran out (the same
    /// word Ollama uses for `done_reason`).
    pub finish_reason: Option<String>,
    /// `usage.completion_tokens` (Ollama's `eval_count`).
    pub completion_tokens: Option<u64>,
    /// `usage.prompt_tokens`.
    pub prompt_tokens: Option<u64>,
    /// The model that ANSWERED: [`MODEL_NAME_HEADER`] when the gateway sends it, else the body's
    /// `model` (which the proxy may restamp with the requested tier name).
    pub model: Option<String>,
    /// Which deployment served it ([`BACKEND_HEADER`]); `None` if the gateway does not say.
    pub backend: Option<String>,
    /// True when the answer came from the gateway's cache ([`CACHE_KEY_HEADER`] present).
    pub cache_hit: bool,
}

/// Pull an [`Answer`] out of a chat-completions body. Empty content is [`GatewayError::Empty`].
pub fn parse_answer(body: &Value) -> Result<Answer, GatewayError> {
    let text = body
        .pointer("/choices/0/message/content")
        .and_then(Value::as_str)
        .ok_or_else(|| GatewayError::Parse("no choices[0].message.content".into()))?
        .trim()
        .to_string();
    if text.is_empty() {
        return Err(GatewayError::Empty);
    }
    Ok(Answer {
        text,
        finish_reason: body
            .pointer("/choices/0/finish_reason")
            .and_then(Value::as_str)
            .map(str::to_string),
        completion_tokens: body
            .pointer("/usage/completion_tokens")
            .and_then(Value::as_u64),
        prompt_tokens: body.pointer("/usage/prompt_tokens").and_then(Value::as_u64),
        model: body
            .get("model")
            .and_then(Value::as_str)
            .map(str::to_string),
        // Headers, not body: filled in by `Gateway::send`.
        backend: None,
        cache_hit: false,
    })
}

/// Try the gateway (if any) and report how much of `total` the direct fallback may still use.
///
/// The gateway gets three quarters of the budget — a cold model load on the gateway's side should
/// not be cut off and then repeated directly — and the fallback gets whatever is ACTUALLY left, so
/// a fast failure (connection refused, 4xx) still leaves nearly the whole budget. The two together
/// never exceed `total`. `(Some(answer), _)` means done; `(None, budget)` means go direct.
pub async fn attempt(
    gateway: Option<&Gateway>,
    req: &Completion<'_>,
    total: Duration,
) -> (Option<Answer>, Duration) {
    let Some(g) = gateway else {
        return (None, total);
    };
    let started = std::time::Instant::now();
    match g.complete(req, total * 3 / 4).await {
        Ok(a) => (Some(a), Duration::ZERO),
        Err(_) => (None, total.saturating_sub(started.elapsed())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completions_url_handles_both_base_forms() {
        assert_eq!(
            completions_url("http://gw.invalid:4000"),
            "http://gw.invalid:4000/v1/chat/completions"
        );
        assert_eq!(
            completions_url("http://gw.invalid:4000/v1/"),
            "http://gw.invalid:4000/v1/chat/completions"
        );
    }

    #[test]
    fn payload_maps_every_field() {
        let p = chat_payload(&Completion {
            model: "m",
            system: Some("sys"),
            prompt: "hi",
            think: Some(false),
            max_tokens: Some(64),
            temperature: Some(0.0),
        });
        assert_eq!(p["model"], "m");
        assert_eq!(p["messages"][0]["role"], "system");
        assert_eq!(p["messages"][1]["content"], "hi");
        assert_eq!(p["think"], false);
        assert_eq!(p["max_tokens"], 64);
        assert_eq!(p["temperature"], 0.0);
        assert_eq!(p["stream"], false);
    }

    #[test]
    fn payload_omits_unset_fields() {
        let p = chat_payload(&Completion {
            model: "m",
            system: None,
            prompt: "hi",
            think: None,
            max_tokens: None,
            temperature: None,
        });
        assert_eq!(p["messages"].as_array().map(Vec::len), Some(1));
        assert!(p.get("think").is_none());
        assert!(p.get("max_tokens").is_none());
        assert!(p.get("temperature").is_none());
    }

    #[test]
    fn debug_never_prints_the_key() {
        let cfg = GatewayConfig {
            base: "http://gw.invalid".into(),
            key: "sk-supersecret".into(),
            metrics: None,
            caller: Some("summarize".into()),
        };
        let s = format!("{cfg:?}");
        assert!(!s.contains("supersecret"), "{s}");
        assert!(s.contains("gw.invalid"));
    }

    #[test]
    fn caller_is_stamped_as_metadata_and_tag_only_when_known() {
        let req = Completion {
            model: "m",
            system: None,
            prompt: "hi",
            think: None,
            max_tokens: None,
            temperature: None,
        };
        let p = with_caller(chat_payload(&req), Some("example-worker"));
        assert_eq!(p["metadata"]["caller"], "example-worker");
        assert_eq!(p["tags"], json!(["example-worker"]));
        let bare = with_caller(chat_payload(&req), None);
        assert!(bare.get("metadata").is_none() && bare.get("tags").is_none());
    }

    #[test]
    fn caller_labels_are_bounded_and_label_safe() {
        assert_eq!(
            caller_label("Example-Worker").as_deref(),
            Some("example-worker")
        );
        assert_eq!(caller_label("my tool\"}{x").as_deref(), Some("mytoolx"));
        assert_eq!(caller_label("é!").as_deref(), None);
        assert_eq!(caller_label(&"a".repeat(100)).map(|s| s.len()), Some(64));
        let cfg = GatewayConfig {
            base: "b".into(),
            key: "k".into(),
            metrics: None,
            caller: None,
        }
        .with_caller("Example-Hook");
        assert_eq!(cfg.caller.as_deref(), Some("example-hook"));
    }

    #[test]
    fn served_model_prefers_the_deployment_header_over_the_restamped_body() {
        let body = Some("code".to_string());
        assert_eq!(
            served_model(Some("ollama/qwen2.5-coder:14b".into()), body.clone()).as_deref(),
            Some("ollama/qwen2.5-coder:14b")
        );
        assert_eq!(served_model(None, body.clone()).as_deref(), Some("code"));
        assert_eq!(
            served_model(Some("  ".into()), body).as_deref(),
            Some("code")
        );
        assert_eq!(served_model(None, None), None);
    }

    #[test]
    fn parse_answer_maps_finish_reason_and_usage() {
        let a = parse_answer(&json!({
            "model": "qwen2.5-coder:14b",
            "choices": [{"message": {"content": " 4 "}, "finish_reason": "stop"}],
            "usage": {"completion_tokens": 2, "prompt_tokens": 27}
        }))
        .expect("answer");
        assert_eq!(a.text, "4");
        assert_eq!(a.finish_reason.as_deref(), Some("stop"));
        assert_eq!(a.completion_tokens, Some(2));
        assert_eq!(a.prompt_tokens, Some(27));
        assert_eq!(a.model.as_deref(), Some("qwen2.5-coder:14b"));
        assert_eq!(
            a.backend, None,
            "headers are filled in by send(), not the body"
        );
        assert!(!a.cache_hit);
    }

    #[test]
    fn an_empty_answer_is_an_error_so_the_caller_falls_back() {
        let e = parse_answer(&json!({
            "choices": [{"message": {"content": ""}, "finish_reason": "length"}]
        }))
        .expect_err("empty");
        assert_eq!(e.reason(), "empty");
        assert_eq!(
            parse_answer(&json!({"choices": []}))
                .expect_err("no content")
                .reason(),
            "parse"
        );
    }

    #[tokio::test]
    async fn attempt_without_a_gateway_leaves_the_whole_budget() {
        let req = Completion {
            model: "m",
            system: None,
            prompt: "p",
            think: None,
            max_tokens: None,
            temperature: None,
        };
        let (a, left) = attempt(None, &req, Duration::from_secs(9)).await;
        assert!(a.is_none());
        assert_eq!(left, Duration::from_secs(9));
    }

    #[tokio::test]
    async fn a_fast_gateway_failure_leaves_nearly_the_whole_budget() {
        let gw = Gateway::new(GatewayConfig {
            base: "http://127.0.0.1:9".into(),
            key: "k".into(),
            metrics: None,
            caller: None,
        })
        .expect("builds");
        let req = Completion {
            model: "m",
            system: None,
            prompt: "p",
            think: None,
            max_tokens: None,
            temperature: None,
        };
        let total = Duration::from_secs(20);
        let (a, left) = attempt(Some(&gw), &req, total).await;
        assert!(a.is_none());
        assert!(left <= total);
        assert!(
            left > Duration::from_secs(15),
            "refused fast, budget mostly intact: {left:?}"
        );
    }

    #[test]
    fn from_env_needs_base_and_key_and_honours_disable() {
        // Unique names so parallel tests cannot interfere.
        let (b, k, d) = (
            "NUVEK_GW_TEST_BASE_A",
            "NUVEK_GW_TEST_KEY_A",
            "NUVEK_GW_TEST_OFF_A",
        );
        // Test-only env mutation on names no other test touches.
        std::env::remove_var(b);
        std::env::remove_var(k);
        std::env::remove_var(d);
        assert!(GatewayConfig::from_env(&[b], k, d).is_none());
        std::env::set_var(b, "http://gw.invalid:4000");
        assert!(GatewayConfig::from_env(&[b], k, d).is_none(), "no key");
        std::env::set_var(k, "sk-test");
        assert!(GatewayConfig::from_env(&[b], k, d).is_some());
        std::env::set_var(d, "1");
        assert!(GatewayConfig::from_env(&[b], k, d).is_none(), "disabled");
    }

    #[tokio::test]
    async fn an_unreachable_gateway_is_a_transport_error() {
        let gw = Gateway::new(GatewayConfig {
            base: "http://127.0.0.1:9".into(),
            key: "k".into(),
            metrics: None,
            caller: None,
        })
        .expect("builds");
        let err = gw
            .complete(
                &Completion {
                    model: "m",
                    system: None,
                    prompt: "p",
                    think: None,
                    max_tokens: None,
                    temperature: None,
                },
                Duration::from_secs(2),
            )
            .await
            .expect_err("nothing listens on port 9");
        assert_eq!(err.reason(), "transport");
    }
}
