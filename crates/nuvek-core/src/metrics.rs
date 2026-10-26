//! Dependency-free Prometheus textfile telemetry.
//!
//! Writes node_exporter textfile-collector `.prom` files to a directory **the caller names**.
//! Fully best-effort and decoupled: if the dir is unwritable it silently no-ops, so a metrics
//! problem never breaks an indexer or query path. Every method in this module swallows errors.
//!
//! ```no_run
//! # use nuvek_core::{env::env_dir, metrics::{Metrics, Metric}};
//! let m = Metrics::new(env_dir("MYTOOL_TEXTFILE_DIR", ".mytool/metrics"));
//! m.write("indexer", &[Metric::new("indexer_files_total", 42.0).counter()]);
//! ```
//!
//! The directory is the caller's. Independent implementations can disagree about blank values and
//! fallback paths, and a writer disagreeing with its reader about the directory means metrics
//! written where nothing scrapes them, with nothing to say why. Constructing one [`Metrics`] at
//! startup and passing it down makes that disagreement structurally impossible.

use serde_json::{json, Map, Value};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

static WARNED: AtomicBool = AtomicBool::new(false);
// Monotonic suffix so two concurrent writers of the same job never collide on the tmp path
// (a dependency-free equivalent of `mkstemp`'s O_EXCL uniqueness).
static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

fn unique_tmp(dir: &std::path::Path, stem: &str) -> PathBuf {
    let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    dir.join(format!("{stem}.{}.{}.tmp", std::process::id(), seq))
}

/// A telemetry writer bound to one textfile-collector directory.
///
/// Construct it once at startup from whatever the binary decides the directory is, then pass it
/// to the code that emits. Cheap to clone.
#[derive(Debug, Clone)]
pub struct Metrics {
    dir: PathBuf,
    hit_distance: f64,
}

/// Cosine distance at or below which a retrieval counts as a HIT.
///
/// Distances above the configured threshold count as misses; calibrate it against representative
/// labelled queries. A loose threshold (such as 0.6) scores unrelated neighbours as hits and
/// inflates the reported hit rate.
///
/// Kept as a default rather than a required argument because it is a property of cosine retrieval
/// at this embedding scale, not of any one deployment — but override it with
/// [`Metrics::with_hit_distance`] if your corpus says otherwise.
pub const DEFAULT_HIT_DISTANCE: f64 = 0.38;

impl Metrics {
    /// A writer emitting into `dir`. The directory is created lazily on first write.
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            hit_distance: DEFAULT_HIT_DISTANCE,
        }
    }

    /// Override the retrieval hit threshold — see [`DEFAULT_HIT_DISTANCE`].
    #[must_use]
    pub fn with_hit_distance(mut self, d: f64) -> Self {
        self.hit_distance = d;
        self
    }

    /// The directory this writer emits into.
    pub fn dir(&self) -> &std::path::Path {
        &self.dir
    }
}

fn warn_once(msg: &str) {
    if !WARNED.swap(true, Ordering::Relaxed) {
        let _ = writeln!(std::io::stderr(), "[metrics] telemetry disabled: {msg}");
    }
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn safe_label(v: &Value) -> String {
    let s = match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    s.replace('\\', "_")
        .replace('"', "'")
        .replace('\n', " ")
        .chars()
        .take(120)
        .collect()
}

/// One Prometheus series to emit.
pub struct Metric {
    /// Metric family name (e.g. `context_cache_hits_total`).
    pub name: String,
    /// The sample value.
    pub value: f64,
    /// Label key/value pairs rendered as `{k="v",...}`.
    pub labels: Vec<(String, Value)>,
    /// `# HELP` text; defaults to the metric name when None.
    pub help: Option<String>,
    /// Metric type: `"gauge"` (default) or `"counter"`.
    pub kind: Option<String>,
}

impl Metric {
    pub fn new(name: &str, value: f64) -> Self {
        Metric {
            name: name.into(),
            value,
            labels: Vec::new(),
            help: None,
            kind: None,
        }
    }
    pub fn label(mut self, k: &str, v: impl Into<Value>) -> Self {
        self.labels.push((k.into(), v.into()));
        self
    }
    pub fn help(mut self, h: &str) -> Self {
        self.help = Some(h.into());
        self
    }
    pub fn counter(mut self) -> Self {
        self.kind = Some("counter".into());
        self
    }
}

impl Metrics {
    /// Atomically write a `<job>.prom` file, grouping series by metric name (the Prometheus
    /// text parser requires each metric family to be contiguous).
    pub fn write(&self, job: &str, metrics: &[Metric]) {
        if let Err(e) = self.write_inner(job, metrics) {
            warn_once(&e.to_string());
        }
    }
}

impl Metrics {
    fn write_inner(&self, job: &str, metrics: &[Metric]) -> std::io::Result<()> {
        let dir = self.dir.clone();
        fs::create_dir_all(&dir)?;
        // Preserve first-seen family order.
        let mut order: Vec<&str> = Vec::new();
        for m in metrics {
            if !order.contains(&m.name.as_str()) {
                order.push(&m.name);
            }
        }
        let mut lines: Vec<String> = Vec::new();
        for name in order {
            let series: Vec<&Metric> = metrics.iter().filter(|m| m.name == name).collect();
            let first = series[0];
            lines.push(format!(
                "# HELP {name} {}",
                first.help.clone().unwrap_or_else(|| name.to_string())
            ));
            lines.push(format!(
                "# TYPE {name} {}",
                first.kind.clone().unwrap_or_else(|| "gauge".into())
            ));
            for m in series {
                let lbl = if m.labels.is_empty() {
                    String::new()
                } else {
                    let inner: Vec<String> = m
                        .labels
                        .iter()
                        .map(|(k, v)| format!("{k}=\"{}\"", safe_label(v)))
                        .collect();
                    format!("{{{}}}", inner.join(","))
                };
                lines.push(format!("{name}{lbl} {}", m.value));
            }
        }
        let path = dir.join(format!("{job}.prom"));
        let tmp = unique_tmp(&dir, job);
        fs::write(&tmp, format!("{}\n", lines.join("\n")))?;
        fs::rename(&tmp, &path)?;
        Ok(())
    }
}

impl Metrics {
    fn events_path(&self, job: &str) -> PathBuf {
        self.dir.join(format!("{job}.events.jsonl"))
    }

    fn events_backup(&self, job: &str) -> PathBuf {
        self.dir.join(format!("{job}.events.jsonl.1"))
    }

    /// Append one JSONL event to `<job>.events.jsonl` (best-effort, single rolling backup past 5 MB).
    pub fn append_event(&self, job: &str, mut fields: Map<String, Value>) {
        let res = (|| -> std::io::Result<()> {
            fs::create_dir_all(&self.dir)?;
            let path = self.events_path(job);
            if let Ok(meta) = fs::metadata(&path) {
                if meta.len() > 5 * 1024 * 1024 {
                    let _ = fs::rename(&path, self.events_backup(job));
                }
            }
            let mut obj = Map::new();
            obj.insert("ts".into(), json!(now_secs()));
            obj.append(&mut fields);
            let mut f = fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)?;
            writeln!(f, "{}", Value::Object(obj))?;
            Ok(())
        })();
        if let Err(e) = res {
            warn_once(&e.to_string());
        }
    }

    /// Every event [`Metrics::append_event`] still holds for `job`, oldest first: the rotated
    /// backup, then the live file. Missing files and unparseable lines are skipped.
    #[must_use]
    pub fn read_events(&self, job: &str) -> Vec<Value> {
        [self.events_backup(job), self.events_path(job)]
            .iter()
            .filter_map(|p| fs::read_to_string(p).ok())
            .flat_map(|text| {
                text.lines()
                    .filter_map(|l| serde_json::from_str(l).ok())
                    .collect::<Vec<Value>>()
            })
            .collect()
    }
}

/// A small JSON state file (counters, dedupe markers): its contents, or `{}` when it is missing
/// or unreadable. Pair with [`store_json`].
pub fn load_json(path: &std::path::Path) -> Value {
    fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| json!({}))
}

/// Write a JSON state file atomically (temp file + rename), creating its directory. A concurrent
/// reader sees the old or the new contents, never a torn write.
pub fn store_json(path: &std::path::Path, ctr: &Value) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    fs::create_dir_all(dir)?;
    let stem = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("counter");
    let tmp = unique_tmp(dir, stem);
    fs::write(&tmp, serde_json::to_string(ctr)?)?;
    fs::rename(&tmp, path)?;
    Ok(())
}

impl Metrics {
    /// Record one retrieval (queries/hits per collection + last-top-distance gauge).
    /// A hit = nearest result within the configured hit distance. Best-effort.
    pub fn record_retrieval(&self, collection: &str, distances: &[Option<f64>], domain: &str) {
        let res = (|| -> std::io::Result<()> {
            let top = distances
                .iter()
                .filter_map(|d| *d)
                .fold(None::<f64>, |acc, d| Some(acc.map_or(d, |a| a.min(d))));
            let hit = top.map(|t| t <= self.hit_distance).unwrap_or(false);

            let mut ev = Map::new();
            ev.insert("collection".into(), json!(collection));
            ev.insert("domain".into(), json!(domain));
            ev.insert("top_distance".into(), json!(top));
            ev.insert("n".into(), json!(distances.len()));
            ev.insert("hit".into(), json!(hit));
            self.append_event("context_retrieval", ev);

            let path = self.dir.join("retrieval_counters.json");
            let mut ctr = load_json(&path);
            // A parsed-but-non-object counter file (corrupt/partial write, stale schema) must not
            // panic this best-effort path — reset to an empty object, like record_cache does.
            if !ctr.is_object() {
                ctr = json!({});
            }
            if let Some(obj) = ctr.as_object_mut() {
                let entry = obj
                    .entry(collection.to_string())
                    .or_insert_with(|| json!({"queries": 0, "hits": 0}));
                let q = entry["queries"].as_i64().unwrap_or(0) + 1;
                let h = entry["hits"].as_i64().unwrap_or(0) + if hit { 1 } else { 0 };
                *entry = json!({"queries": q, "hits": h});
            }
            store_json(&path, &ctr)?;

            let mut metrics = Vec::new();
            if let Some(obj) = ctr.as_object() {
                for (col, v) in obj {
                    metrics.push(
                        Metric::new(
                            "context_retrieval_queries_total",
                            v["queries"].as_f64().unwrap_or(0.0),
                        )
                        .label("collection", col.clone())
                        .counter()
                        .help("retrieval queries per collection"),
                    );
                    metrics.push(
                        Metric::new(
                            "context_retrieval_hits_total",
                            v["hits"].as_f64().unwrap_or(0.0),
                        )
                        .label("collection", col.clone())
                        .counter()
                        .help("retrievals with a near result"),
                    );
                }
            }
            if let Some(t) = top {
                metrics.push(
                    Metric::new(
                        "context_retrieval_last_top_distance",
                        (t * 10000.0).round() / 10000.0,
                    )
                    .label("collection", collection)
                    .help("most recent nearest distance"),
                );
            }
            self.write("context_retrieval", &metrics);
            Ok(())
        })();
        if let Err(e) = res {
            warn_once(&e.to_string());
        }
    }
}

/// Strip quoted spans, then collect the capitalised `:Label` tokens a Cypher query touches.
///
/// The query TEXT is never recorded: it is unbounded and, in some tenants, carries private
/// names. Labels are the analytic unit, are bounded by the schema, and are safe. Quoted spans go
/// first so a literal like `'Harbour: The Old Town'` cannot masquerade as a label; map keys
/// (`{type: 'summary'}`) are lowercase by convention and fall out naturally.
pub fn cypher_labels(cypher: &str) -> Vec<String> {
    let mut unquoted = String::with_capacity(cypher.len());
    let mut quote: Option<char> = None;
    // Inside a literal, a backslash escapes the next character. Without this, `'Ana\'s Notes'`
    // closes at the escaped quote and the REST OF THE LITERAL is scanned as schema — publishing
    // private content into telemetry, which is exactly what this function exists to prevent.
    // Names containing an apostrophe are ordinary in user data, so this is not a corner
    // case. (Doubled-quote escaping, `''`, needs no special handling: the quote re-opens and the
    // content is dropped either way.)
    let mut escaped = false;
    for c in cypher.chars() {
        match quote {
            Some(q) => {
                if escaped {
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else if c == q {
                    quote = None;
                }
            }
            None => {
                if c == '\'' || c == '"' || c == '`' {
                    quote = Some(c);
                } else {
                    unquoted.push(c);
                }
            }
        }
    }

    let mut found = std::collections::BTreeSet::new();
    let chars: Vec<char> = unquoted.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == ':' {
            let mut j = i + 1;
            while j < chars.len() && chars[j] == ' ' {
                j += 1;
            }
            if j < chars.len() && chars[j].is_ascii_uppercase() {
                let start = j;
                while j < chars.len() && (chars[j].is_alphanumeric() || chars[j] == '_') {
                    j += 1;
                }
                found.insert(chars[start..j].iter().collect::<String>());
                i = j;
                continue;
            }
        }
        i += 1;
    }
    // Bounded: a pathological query must not produce an unbounded label set in the event log.
    found.into_iter().take(8).collect()
}

impl Metrics {
    /// Record one live-graph query. `outcome` is the handler's own taxonomy — `rows`, `empty`,
    /// `blocked`, `connect_error`, `exec_error` — because a spike in refused writes and a spike in
    /// unreachable-graph are different incidents and the caller already tells them apart.
    ///
    /// Counters live in a file, not in memory: the MCP server is spawned per session, so an
    /// in-process counter would reset constantly. Best-effort — never fails the caller.
    pub fn record_graph_query(
        &self,
        outcome: &str,
        rows: usize,
        duration_ms: u64,
        labels: &[String],
    ) {
        let res = (|| -> std::io::Result<()> {
            let mut ev = Map::new();
            ev.insert("outcome".into(), json!(outcome));
            ev.insert("rows".into(), json!(rows));
            ev.insert("duration_ms".into(), json!(duration_ms));
            ev.insert("labels".into(), json!(labels));
            self.append_event("context_graph", ev);

            // Shape: {"<outcome>": n}
            let path = self.dir.join("graph_counters.json");
            let mut ctr = load_json(&path);
            if !ctr.is_object() {
                ctr = json!({});
            }
            let cur = ctr.get(outcome).and_then(Value::as_i64).unwrap_or(0) + 1;
            ctr[outcome] = json!(cur);
            store_json(&path, &ctr)?;

            let mut series = Vec::new();
            if let Some(obj) = ctr.as_object() {
                for (oc, n) in obj {
                    series.push(
                        Metric::new("context_graph_queries_total", n.as_f64().unwrap_or(0.0))
                            .counter()
                            .label("outcome", oc.as_str())
                            .help("live-graph queries by outcome"),
                    );
                }
            }
            series.push(
                Metric::new("context_graph_last_duration_ms", duration_ms as f64)
                    .help("duration of the most recent live-graph query"),
            );
            self.write("context_graph", &series);
            Ok(())
        })();
        if let Err(e) = res {
            warn_once(&e.to_string());
        }
    }
}

impl Metrics {
    /// Record one invocation of a context-injection hook. `outcome` is `skipped` (gate 1), `no_match`
    /// (gate 2 admitted nothing), `would_inject` (cleared both gates while dark) or `injected`.
    ///
    /// This hook is a FRESH PROCESS per prompt, so the counters must live in a file — an in-process
    /// counter would reset on every single prompt and `rate()` would be meaningless. `last_run_ts` is
    /// the load-bearing gauge: without it "no prompts today" and "the hook is dead" are the same
    /// picture. Best-effort — never fails the caller, which must never fail the prompt.
    ///
    /// `job` names the event stream, counter file, `.prom` job and every series prefix. Callers
    /// sharing a metrics dir need distinct jobs: a textfile collector concatenates every `.prom`,
    /// and a family defined in two files fails the whole scrape.
    pub fn record_prompt_context(
        &self,
        job: &str,
        outcome: &str,
        snippets: usize,
        top_distance: Option<f64>,
        chars: usize,
        duration_ms: u64,
    ) {
        let name = |suffix: &str| format!("{job}_{suffix}");
        let res = (|| -> std::io::Result<()> {
            let mut ev = Map::new();
            ev.insert("outcome".into(), json!(outcome));
            ev.insert("snippets".into(), json!(snippets));
            ev.insert("top_distance".into(), json!(top_distance));
            ev.insert("chars".into(), json!(chars));
            ev.insert("duration_ms".into(), json!(duration_ms));
            self.append_event(job, ev);

            // Shape: {"outcomes": {"<outcome>": n}, "injected_chars": n}
            let path = self.dir.join(format!("{job}_counters.json"));
            let mut ctr = load_json(&path);
            if !ctr.is_object() {
                ctr = json!({});
            }
            if !ctr.get("outcomes").map(Value::is_object).unwrap_or(false) {
                ctr["outcomes"] = json!({});
            }
            let cur = ctr["outcomes"]
                .get(outcome)
                .and_then(Value::as_i64)
                .unwrap_or(0)
                + 1;
            ctr["outcomes"][outcome] = json!(cur);
            let total_chars = ctr
                .get("injected_chars")
                .and_then(Value::as_i64)
                .unwrap_or(0)
                + chars as i64;
            ctr["injected_chars"] = json!(total_chars);
            store_json(&path, &ctr)?;

            let mut series = Vec::new();
            if let Some(obj) = ctr["outcomes"].as_object() {
                for (oc, n) in obj {
                    series.push(
                        Metric::new(&name("outcomes_total"), n.as_f64().unwrap_or(0.0))
                            .counter()
                            .label("outcome", oc.as_str())
                            .help("context-injection invocations by gate outcome"),
                    );
                }
            }
            series.push(
                Metric::new(&name("injected_chars_total"), total_chars as f64)
                    .counter()
                    .help("cumulative characters of context injected into prompts"),
            );
            series.push(
                Metric::new(&name("last_run_ts"), now_secs() as f64)
                    .help("epoch seconds of the last context-injection invocation"),
            );
            series.push(
                Metric::new(&name("last_duration_ms"), duration_ms as f64)
                    .help("duration of the most recent context-injection invocation"),
            );
            // Only meaningful when something was admitted; emitting 0 for a skip would look like a
            // perfect match and drag any percentile panel to the floor.
            if let Some(d) = top_distance {
                series.push(
                    Metric::new(&name("last_top_distance"), (d * 10000.0).round() / 10000.0)
                        .help("nearest admitted distance on the most recent injection"),
                );
            }
            self.write(job, &series);
            Ok(())
        })();
        if let Err(e) = res {
            warn_once(&e.to_string());
        }
    }
}

impl Metrics {
    /// Record one semantic-cache lookup for `namespace` (cumulative per-partition hit/miss counters).
    /// A hit = a cached answer reused → one Ollama logic call avoided. Best-effort.
    ///
    /// Counters are keyed by cache namespace and exported as `context_cache_{hits,misses}_total`
    /// carrying a **`namespace` label**, so per-partition hit rate is visible (a partition that never
    /// hits is the signature of a typo'd namespace). Aggregate views must `sum()` over the label.
    pub fn record_cache(&self, hit: bool, distance: Option<f64>, namespace: &str) {
        self.bump_cache(if hit { "hits" } else { "misses" }, distance, namespace);
    }

    /// Record a cache lookup that FAILED (backend unreachable, bad response) for `namespace`.
    /// Counted apart from misses, exported as `context_cache_errors_total`: folded into misses, a
    /// cache-backend outage would read as a cold cache.
    pub fn record_cache_error(&self, namespace: &str) {
        self.bump_cache("errors", None, namespace);
    }

    /// Shared body of the cache counters; `key` is `hits`, `misses` or `errors`.
    fn bump_cache(&self, key: &str, distance: Option<f64>, namespace: &str) {
        let res = (|| -> std::io::Result<()> {
            let mut ev = Map::new();
            ev.insert("hit".into(), json!(key == "hits"));
            ev.insert("error".into(), json!(key == "errors"));
            ev.insert("distance".into(), json!(distance));
            ev.insert("namespace".into(), json!(namespace));
            self.append_event("context_cache", ev);

            // Shape: {"<namespace>": {"hits": n, "misses": n, "errors": n}}; `errors` may be absent
            // in files written before it existed and reads as 0.
            let path = self.dir.join("cache_counters.json");
            let mut ctr = load_json(&path);
            if !ctr.is_object() {
                ctr = json!({});
            }
            // Migrate the pre-namespace flat {"hits","misses"} file under a `legacy` partition rather
            // than discarding the historical totals. Detect it by TYPE, not mere presence: the old
            // shape stores plain integers, whereas a partition legitimately NAMED "hits" holds an
            // object. A presence-only check would re-fire on that partition and wipe the whole file.
            let is_legacy_flat = matches!(ctr.get("hits"), Some(v) if v.is_i64())
                || matches!(ctr.get("misses"), Some(v) if v.is_i64());
            if is_legacy_flat {
                ctr = json!({ "legacy": {
                    "hits": ctr.get("hits").and_then(Value::as_i64).unwrap_or(0),
                    "misses": ctr.get("misses").and_then(Value::as_i64).unwrap_or(0),
                }});
            }
            let cur = ctr
                .get(namespace)
                .and_then(|p| p.get(key))
                .and_then(Value::as_i64)
                .unwrap_or(0)
                + 1;
            if !ctr.get(namespace).map(Value::is_object).unwrap_or(false) {
                ctr[namespace] = json!({"hits": 0, "misses": 0, "errors": 0});
            }
            ctr[namespace][key] = json!(cur);
            store_json(&path, &ctr)?;

            // One labelled series per partition.
            let mut series = Vec::new();
            if let Some(partitions) = ctr.as_object() {
                for (ns, counts) in partitions {
                    series.push(
                        Metric::new(
                            "context_cache_hits_total",
                            counts.get("hits").and_then(Value::as_f64).unwrap_or(0.0),
                        )
                        .counter()
                        .label("namespace", ns.as_str())
                        .help("semantic-cache hits (Ollama logic calls avoided)"),
                    );
                    series.push(
                        Metric::new(
                            "context_cache_misses_total",
                            counts.get("misses").and_then(Value::as_f64).unwrap_or(0.0),
                        )
                        .counter()
                        .label("namespace", ns.as_str())
                        .help("semantic-cache misses (Ollama logic call made)"),
                    );
                    series.push(
                        Metric::new(
                            "context_cache_errors_total",
                            counts.get("errors").and_then(Value::as_f64).unwrap_or(0.0),
                        )
                        .counter()
                        .label("namespace", ns.as_str())
                        .help("semantic-cache lookups that failed (backend error, not a miss)"),
                    );
                }
            }
            self.write("context_cache", &series);
            Ok(())
        })();
        if let Err(e) = res {
            warn_once(&e.to_string());
        }
    }
}

impl Metrics {
    /// Count one LLM call by `route` (`gateway` / `direct`) and `reason` (`ok`, or why it went
    /// direct: `transport`, `status`, `parse`, `bypass`, `unconfigured`). Exported cumulatively as
    /// `llm_route_calls_total{route,reason}`. Best-effort.
    ///
    /// The point is the ratio: a gateway that is down still lets every call succeed via the
    /// direct fallback, so only `direct` climbing against `gateway` shows that it is down.
    ///
    /// CEILING: load-modify-store on a JSON file, like the cache counters — two concurrent writers
    /// can lose an increment. Fine for a ratio; move to per-process `.prom` files summed in PromQL
    /// if exact counts ever matter.
    pub fn record_llm_route(&self, route: &str, reason: &str) {
        let res = (|| -> std::io::Result<()> {
            let path = self.dir.join("llm_route_counters.json");
            let mut ctr = load_json(&path);
            if !ctr.is_object() {
                ctr = json!({});
            }
            let key = format!("{route}|{reason}");
            let cur = ctr.get(&key).and_then(Value::as_i64).unwrap_or(0) + 1;
            ctr[key.as_str()] = json!(cur);
            store_json(&path, &ctr)?;

            let mut series = Vec::new();
            if let Some(all) = ctr.as_object() {
                for (k, n) in all {
                    let (r, why) = k.split_once('|').unwrap_or((k.as_str(), ""));
                    series.push(
                        Metric::new("llm_route_calls_total", n.as_f64().unwrap_or(0.0))
                            .counter()
                            .label("route", r)
                            .label("reason", why)
                            .help("LLM calls by route (gateway vs direct) and why"),
                    );
                }
            }
            self.write("llm_route", &series);
            Ok(())
        })();
        if let Err(e) = res {
            warn_once(&e.to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iso_dir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "nuvek-metrics-{}-{}-{}",
            tag,
            std::process::id(),
            now_secs()
        ));
        let _ = fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn llm_route_counters_accumulate_per_route_and_reason() {
        let dir = iso_dir("route");
        let m = Metrics::new(dir.clone());
        m.record_llm_route("gateway", "ok");
        m.record_llm_route("gateway", "ok");
        m.record_llm_route("direct", "transport");
        let prom = fs::read_to_string(dir.join("llm_route.prom")).expect("prom written");
        assert!(
            prom.contains(r#"llm_route_calls_total{route="gateway",reason="ok"} 2"#),
            "{prom}"
        );
        assert!(
            prom.contains(r#"llm_route_calls_total{route="direct",reason="transport"} 1"#),
            "{prom}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// The reader sees exactly what the writer wrote, the rotated backup included and first.
    #[test]
    fn read_events_returns_backup_then_live_in_order() {
        let dir = iso_dir("events");
        let m = Metrics::new(dir.clone());
        let ev = |k: &str| {
            let mut f = Map::new();
            f.insert("k".into(), json!(k));
            f
        };
        m.append_event("job", ev("old"));
        fs::rename(m.events_path("job"), m.events_backup("job")).unwrap();
        m.append_event("job", ev("new"));
        let got: Vec<String> = m
            .read_events("job")
            .iter()
            .filter_map(|v| v.get("k").and_then(Value::as_str).map(String::from))
            .collect();
        assert_eq!(got, vec!["old", "new"]);
        assert!(m.read_events("absent").is_empty());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn cypher_labels_extracts_node_labels_not_property_keys() {
        let q = "MATCH (c:Container)-[:DEPENDS_ON]->(n:Network) WHERE c.name = 'x' RETURN c";
        let got = cypher_labels(q);
        assert!(got.contains(&"Container".to_string()));
        assert!(got.contains(&"Network".to_string()));
        assert!(got.contains(&"DEPENDS_ON".to_string()));
        // Lowercase map keys are not labels.
        assert!(
            !cypher_labels("MATCH (cs:ContextSummary {type: 'summary'}) RETURN cs")
                .contains(&"type".to_string())
        );
    }

    #[test]
    fn cypher_labels_never_leaks_quoted_literals() {
        // A project name inside a string literal must not surface as a label.
        let q = "MATCH (n:Project) WHERE n.name = 'Harbour: The Old Town Survey' RETURN n";
        let got = cypher_labels(q);
        assert_eq!(got, vec!["Project".to_string()]);
        let q2 = r#"MATCH (n:Skill) WHERE n.info = "Foo: Bar" RETURN n"#;
        assert_eq!(cypher_labels(q2), vec!["Skill".to_string()]);
    }

    /// A backslash-escaped quote must NOT end the string. Neo4j supports `\'` in literals, and a
    /// project or person name containing an apostrophe is ordinary in user data — so
    /// a naive scanner exits the quote early and the rest of the literal gets read as schema.
    /// That would publish private content into telemetry, which this function exists to prevent.
    #[test]
    fn cypher_labels_survive_backslash_escaped_quotes() {
        let q = r"MATCH (n:Project) WHERE n.name = 'Ana\'s Notes: SecretProjectName' RETURN n";
        assert_eq!(cypher_labels(q), vec!["Project".to_string()]);
        let q2 = r#"MATCH (n:Skill) WHERE n.info = "a \"quoted\" Thing: Leaked" RETURN n"#;
        assert_eq!(cypher_labels(q2), vec!["Skill".to_string()]);
        // Doubled-quote escaping ('') must keep working too.
        let q3 = "MATCH (n:Container) WHERE n.name = 'it''s Fine: Nope' RETURN n";
        assert_eq!(cypher_labels(q3), vec!["Container".to_string()]);
    }

    #[test]
    fn cypher_labels_are_bounded_and_deduped() {
        let q = "MATCH (:A)--(:B)--(:C)--(:D)--(:E)--(:F)--(:G)--(:H)--(:I)--(:J)--(:A) RETURN 1";
        let got = cypher_labels(q);
        assert_eq!(got.len(), 8, "label set must stay bounded");
        assert_eq!(
            got.iter().collect::<std::collections::HashSet<_>>().len(),
            8
        );
    }

    #[test]
    fn write_metrics_groups_families_and_is_valid_prom() {
        let d = iso_dir("write");
        Metrics::new(&d).write(
            "unit",
            &[
                Metric::new("m_total", 1.0)
                    .label("c", "a")
                    .counter()
                    .help("h"),
                Metric::new("m_total", 2.0).label("c", "b").counter(),
            ],
        );
        let out = fs::read_to_string(d.join("unit.prom")).unwrap();
        assert!(out.contains("# HELP m_total h"));
        assert!(out.contains("# TYPE m_total counter"));
        assert!(out.contains("m_total{c=\"a\"} 1"));
        assert!(out.contains("m_total{c=\"b\"} 2"));
        // exactly one HELP line for the family
        assert_eq!(out.matches("# HELP m_total").count(), 1);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn cache_counters_accumulate_per_namespace() {
        let d = iso_dir("cache");
        Metrics::new(&d).record_cache(true, None, "summarize");
        Metrics::new(&d).record_cache(false, Some(0.2), "summarize");
        Metrics::new(&d).record_cache(true, None, "summarize");
        Metrics::new(&d).record_cache(true, None, "watchdog-rca");
        let ctr: Value =
            serde_json::from_str(&fs::read_to_string(d.join("cache_counters.json")).unwrap())
                .unwrap();
        assert_eq!(ctr["summarize"]["hits"], json!(2));
        assert_eq!(ctr["summarize"]["misses"], json!(1));
        // A second partition accumulates independently — that separation is the whole point.
        assert_eq!(ctr["watchdog-rca"]["hits"], json!(1));
        assert_eq!(ctr["watchdog-rca"]["misses"], json!(0));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn cache_errors_count_apart_from_misses() {
        // An unreachable cache backend must not read as a cold cache.
        let d = iso_dir("cacheerr");
        Metrics::new(&d).record_cache(false, None, "summarize");
        Metrics::new(&d).record_cache_error("summarize");
        Metrics::new(&d).record_cache_error("summarize");
        let ctr: Value =
            serde_json::from_str(&fs::read_to_string(d.join("cache_counters.json")).unwrap())
                .unwrap();
        assert_eq!(ctr["summarize"]["misses"], json!(1));
        assert_eq!(ctr["summarize"]["errors"], json!(2));
        let prom = fs::read_to_string(d.join("context_cache.prom")).unwrap_or_default();
        assert!(
            prom.contains("context_cache_errors_total"),
            "errors are exported"
        );
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn cache_errors_extend_a_counter_file_written_without_them() {
        // Files written before the `errors` bucket existed must keep their totals.
        let d = iso_dir("cacheerrold");
        fs::create_dir_all(&d).unwrap();
        fs::write(
            d.join("cache_counters.json"),
            r#"{"summarize":{"hits":4,"misses":9}}"#,
        )
        .unwrap();
        Metrics::new(&d).record_cache_error("summarize");
        let ctr: Value =
            serde_json::from_str(&fs::read_to_string(d.join("cache_counters.json")).unwrap())
                .unwrap();
        assert_eq!(ctr["summarize"]["hits"], json!(4));
        assert_eq!(ctr["summarize"]["misses"], json!(9));
        assert_eq!(ctr["summarize"]["errors"], json!(1));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn cache_counters_tolerate_partition_named_like_legacy_keys() {
        // A namespace literally called "hits" must not be mistaken for the pre-namespace flat file
        // on a LATER call — that would fold it into `legacy` and discard every other partition.
        let d = iso_dir("cachereserved");
        Metrics::new(&d).record_cache(true, None, "hits");
        Metrics::new(&d).record_cache(true, None, "summarize");
        let ctr: Value =
            serde_json::from_str(&fs::read_to_string(d.join("cache_counters.json")).unwrap())
                .unwrap();
        assert_eq!(
            ctr["hits"]["hits"],
            json!(1),
            "the 'hits' partition survives"
        );
        assert_eq!(
            ctr["summarize"]["hits"],
            json!(1),
            "and so does its sibling"
        );
        assert!(
            ctr.get("legacy").is_none(),
            "migration must not fire for a real partition"
        );
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn cache_counters_migrate_pre_namespace_file() {
        let d = iso_dir("cachemig");
        // iso_dir only sets PROM_TEXTFILE_DIR; the dir itself is created lazily on first write,
        // and this test seeds a file before any write happens.
        fs::create_dir_all(&d).unwrap();
        // The pre-namespace flat shape must not be silently dropped.
        fs::write(d.join("cache_counters.json"), r#"{"hits":7,"misses":3}"#).unwrap();
        Metrics::new(&d).record_cache(true, None, "summarize");
        let ctr: Value =
            serde_json::from_str(&fs::read_to_string(d.join("cache_counters.json")).unwrap())
                .unwrap();
        assert_eq!(ctr["legacy"]["hits"], json!(7));
        assert_eq!(ctr["legacy"]["misses"], json!(3));
        assert_eq!(ctr["summarize"]["hits"], json!(1));
        let _ = fs::remove_dir_all(&d);
    }

    /// The threshold is a constructor argument now, not an environment variable, so this test
    /// no longer mutates process-global state to exercise an override.
    #[test]
    fn retrieval_hit_detection() {
        let d = iso_dir("retr");
        Metrics::new(&d).with_hit_distance(0.6).record_retrieval(
            "agent-memory",
            &[Some(0.3), Some(0.9)],
            "dev",
        );
        let ctr: Value =
            serde_json::from_str(&fs::read_to_string(d.join("retrieval_counters.json")).unwrap())
                .unwrap();
        assert_eq!(ctr["agent-memory"]["queries"], json!(1));
        assert_eq!(ctr["agent-memory"]["hits"], json!(1)); // top 0.3 <= 0.6
        let _ = fs::remove_dir_all(&d);
    }

    /// The hook is a fresh process per prompt, so counters MUST accumulate across calls rather
    /// than reset; and a skip (no admitted match) must not emit a distance gauge, or a 0 would
    /// read as a perfect match and drag any percentile panel to the floor.
    #[test]
    fn prompt_context_counters_accumulate_and_skip_emits_no_distance() {
        let d = iso_dir("pctx");

        let job = "prompt_context";
        Metrics::new(&d).record_prompt_context(job, "skipped", 0, None, 0, 3);
        Metrics::new(&d).record_prompt_context(job, "injected", 2, Some(0.2777), 900, 51);
        Metrics::new(&d).record_prompt_context(job, "injected", 1, Some(0.3100), 400, 44);

        let ctr: Value = serde_json::from_str(
            &fs::read_to_string(d.join("prompt_context_counters.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(ctr["outcomes"]["injected"], json!(2), "counters accumulate");
        assert_eq!(ctr["outcomes"]["skipped"], json!(1));
        assert_eq!(ctr["injected_chars"], json!(1300), "chars are cumulative");

        let prom = fs::read_to_string(d.join("prompt_context.prom")).unwrap();
        assert!(prom.contains("prompt_context_outcomes_total{outcome=\"injected\"} 2"));
        assert!(prom.contains("prompt_context_last_run_ts"));
        assert!(prom.contains("prompt_context_last_top_distance 0.31"));

        // A trailing skip must leave the counters intact and drop the distance series.
        Metrics::new(&d).record_prompt_context(job, "skipped", 0, None, 0, 2);
        let prom = fs::read_to_string(d.join("prompt_context.prom")).unwrap();
        assert!(
            !prom.contains("prompt_context_last_top_distance"),
            "a skip must not emit a distance gauge"
        );

        let _ = fs::remove_dir_all(&d);
    }

    /// Two jobs in one directory must keep fully separate counters, files and series names. The
    /// exporter concatenates every `.prom`, so no family name may appear in both files.
    #[test]
    fn prompt_context_jobs_stay_disjoint() {
        let d = iso_dir("pctx-jobs");
        let m = Metrics::new(&d);
        m.record_prompt_context("prompt_context", "injected", 1, Some(0.2), 100, 5);
        m.record_prompt_context("prompt_context_agy", "skipped", 0, None, 0, 4);
        m.record_prompt_context("prompt_context_agy", "skipped", 0, None, 0, 4);

        let claude = fs::read_to_string(d.join("prompt_context.prom")).unwrap();
        let agy = fs::read_to_string(d.join("prompt_context_agy.prom")).unwrap();
        assert!(claude.contains("prompt_context_outcomes_total{outcome=\"injected\"} 1"));
        assert!(
            !claude.contains("skipped"),
            "the AGY runs must not touch Claude's counters"
        );
        assert!(agy.contains("prompt_context_agy_outcomes_total{outcome=\"skipped\"} 2"));

        let families = |text: &str| -> Vec<String> {
            text.lines()
                .filter_map(|l| l.strip_prefix("# TYPE "))
                .filter_map(|l| l.split_whitespace().next().map(String::from))
                .collect()
        };
        let claude_fams = families(&claude);
        for f in families(&agy) {
            assert!(
                !claude_fams.contains(&f),
                "family {f} defined in both files"
            );
        }
        let _ = fs::remove_dir_all(&d);
    }

    /// At the DEFAULT threshold, a distance in the noise band (0.40–0.43) must count as a MISS,
    /// while the relevant band (0.23–0.37) still counts as a hit. Without this the default could
    /// drift to a value that scores irrelevance as success.
    #[test]
    fn default_hit_threshold_rejects_the_noise_band() {
        let d = iso_dir("hitdist");

        Metrics::new(&d).record_retrieval("noise-band", &[Some(0.4203)], "dev");
        Metrics::new(&d).record_retrieval("good-band", &[Some(0.3170)], "dev");

        let ctr: Value =
            serde_json::from_str(&fs::read_to_string(d.join("retrieval_counters.json")).unwrap())
                .unwrap();
        assert_eq!(ctr["noise-band"]["queries"], json!(1));
        assert_eq!(
            ctr["noise-band"]["hits"],
            json!(0),
            "0.42 must not be a hit"
        );
        assert_eq!(ctr["good-band"]["hits"], json!(1), "0.32 must still hit");

        let _ = fs::remove_dir_all(&d);
    }

    // Regression: a parsed-but-non-object counter file must NOT panic the best-effort path
    // (was a `.expect()` that unwound straight through the error guard).
    #[test]
    fn corrupt_counter_file_does_not_panic() {
        let d = iso_dir("corrupt");
        fs::create_dir_all(&d).unwrap();
        // Valid JSON, but an array — not the object the code expects.
        fs::write(d.join("retrieval_counters.json"), "[1, 2, 3]").unwrap();
        // Must not panic, and must recover the file to a usable object.
        Metrics::new(&d).record_retrieval("c", &[Some(0.1)], "dev");
        let ctr: Value =
            serde_json::from_str(&fs::read_to_string(d.join("retrieval_counters.json")).unwrap())
                .unwrap();
        assert!(ctr.is_object());
        assert_eq!(ctr["c"]["queries"], json!(1));
        let _ = fs::remove_dir_all(&d);
    }
}
