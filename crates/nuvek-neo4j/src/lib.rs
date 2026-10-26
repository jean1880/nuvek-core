//! Read-only Neo4j access over Bolt (`neo4rs`).
//!
//! Read-only Cypher only — this crate is built for querying a graph that some other tool owns
//! and writes. `neo4rs 0.8` has no access-mode concept (unlike the Python driver's
//! `execute_read`, which the server enforces as Bolt `mode:'r'`), so this crate enforces
//! read-only with a client-side write-clause guard before every `execute`. It also bounds
//! `connect`/`query` with wall-clock timeouts, since `neo4rs` exposes no timeout knob and an
//! unreachable bolt port would otherwise hang the caller indefinitely.
//!
//! **The connection is the caller's.** The URI, user and password are always supplied by the
//! caller; the crate has no built-in address.
//!
//! ```no_run
//! # async fn f() -> anyhow::Result<()> {
//! use nuvek_neo4j::{connect, query_rows, Neo4jConfig};
//! let graph = connect(&Neo4jConfig {
//!     uri: std::env::var("NEO4J_HOST")?,
//!     user: std::env::var("NEO4J_USER")?,
//!     password: std::env::var("NEO4J_PASSWORD")?,
//!     ..Default::default()
//! }).await?;
//! let rows = query_rows(&graph, "MATCH (n:Service) RETURN n.name").await?;
//! # Ok(()) }
//! ```

use anyhow::{Context, Result};
use neo4rs::{query, BoltType, ConfigBuilder, Graph};
use std::sync::LazyLock;
use std::time::Duration;

pub use nuvek_core::error::NuvekError;

/// Default deadline for connect and for a single query (stream included).
///
/// A protocol-level default, not a deployment one: it bounds a Bolt round trip, and every caller
/// wants *some* deadline rather than an indefinite hang.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(20);

/// Everything needed to reach a Neo4j instance. No field has a deployment default.
#[derive(Debug, Clone, Default)]
pub struct Neo4jConfig {
    /// Bolt URI, e.g. `bolt://graph.example.test:7687`. A bare `host:port` is also accepted, which is
    /// what `neo4rs` itself resolves.
    pub uri: String,
    /// Username.
    pub user: String,
    /// Password. Never logged; never defaulted.
    pub password: String,
    /// Deadline for connect and for each query. `None` uses [`DEFAULT_TIMEOUT`].
    pub timeout: Option<Duration>,
}

impl Neo4jConfig {
    fn deadline(&self) -> Duration {
        self.timeout.unwrap_or(DEFAULT_TIMEOUT)
    }
}

/// Cypher write/DDL clauses that must never run on the read-only graph. Matched
/// case-insensitively as whole words.
///
/// `CALL` is in this set even though it is not itself a write clause. A caller may pass
/// MODEL-GENERATED Cypher, which an instruction smuggled into indexed content can steer — and with
/// APOC installed, `CALL apoc.load.json(...)` is a server-side fetch (SSRF from the Neo4j host)
/// while `CALL apoc.periodic.iterate(...)` executes writes from a STRING argument, bypassing a
/// clause blocklist entirely. APOC may not be installed; the client doesn't depend on it, and
/// refusing `CALL` keeps the guard sound if it is. `\b` keeps it from tripping on identifiers that
/// merely contain the letters (`recall_example`, `called`).
static WRITE_CLAUSE_RE: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(
        r"(?i)\b(CREATE|MERGE|DELETE|DETACH|SET|REMOVE|DROP|FOREACH|LOAD\s+CSV|CALL)\b",
    )
    .expect("WRITE_CLAUSE_RE is a valid compile-time constant")
});

/// Reject any Cypher containing a write/DDL clause. Enforces the read-only contract that
/// `neo4rs` cannot (other drivers offer an `execute_read` mode).
fn ensure_read_only(cypher: &str) -> Result<()> {
    if let Some(m) = WRITE_CLAUSE_RE.find(cypher) {
        return Err(NuvekError::WriteClauseRejected(m.as_str().to_uppercase()).into());
    }
    Ok(())
}

/// A connected, read-only graph client carrying the caller's deadline.
///
/// Holding the timeout alongside the connection is what keeps it from drifting back into a
/// module-level constant: a query cannot be issued without the settings it was opened with.
#[derive(Clone)]
pub struct Neo4j {
    graph: Graph,
    timeout: Duration,
}

impl Neo4j {
    /// Connect using the caller's settings.
    pub async fn connect(cfg: &Neo4jConfig) -> Result<Self> {
        Ok(Self {
            graph: connect(cfg).await?,
            timeout: cfg.deadline(),
        })
    }

    /// The underlying `neo4rs` handle, for callers that need the driver directly.
    pub fn graph(&self) -> &Graph {
        &self.graph
    }

    /// Run a **read-only** Cypher query, returning each row rendered as a JSON object
    /// (column name -> value). Rejects write clauses ([`NuvekError::WriteClauseRejected`]) and
    /// bounds execution by this client's timeout ([`NuvekError::Timeout`]).
    pub async fn query_rows(&self, cypher: &str) -> Result<Vec<serde_json::Value>> {
        self.query_rows_params(cypher, Vec::new()).await
    }

    /// [`Neo4j::query_rows`] with BOUND parameters. Prefer this whenever any part of the query
    /// derives from data — a filename, a metadata value, model output — instead of formatting it
    /// into the string. The guard runs on the template, and a parameter is a value the server
    /// never parses as Cypher, so neither half can smuggle a clause past the guard.
    pub async fn query_rows_params(
        &self,
        cypher: &str,
        params: Vec<(String, serde_json::Value)>,
    ) -> Result<Vec<serde_json::Value>> {
        run_query(&self.graph, cypher, params, self.timeout).await
    }
}

/// Connect using the caller's settings, bounded by the config's timeout.
pub async fn connect(cfg: &Neo4jConfig) -> Result<Graph> {
    let deadline = cfg.deadline();
    let config = ConfigBuilder::default()
        .uri(cfg.uri.clone())
        .user(cfg.user.clone())
        .password(cfg.password.clone())
        .build()
        .context("building neo4j config")?;
    tokio::time::timeout(deadline, Graph::connect(config))
        .await
        .map_err(|_| NuvekError::Timeout(deadline))?
        .context("connecting to neo4j bolt")
}

/// Run a **read-only** Cypher query against a handle the caller already holds, bounded by
/// [`DEFAULT_TIMEOUT`].
///
/// The free-function form exists for callers that hold a bare `neo4rs::Graph` (they connected
/// themselves, or they also issue writes through the driver). Callers that want their own deadline
/// should use [`Neo4j`] instead, which carries it.
pub async fn query_rows(graph: &Graph, cypher: &str) -> Result<Vec<serde_json::Value>> {
    run_query(graph, cypher, Vec::new(), DEFAULT_TIMEOUT).await
}

/// [`query_rows`] with BOUND parameters. Prefer this whenever any part of the query derives from
/// data — a filename, a metadata value, model output — instead of formatting it into the string.
/// The guard runs on the template, and a parameter is a value the server never parses as Cypher,
/// so neither half can smuggle a clause past it.
pub async fn query_rows_params(
    graph: &Graph,
    cypher: &str,
    params: Vec<(String, serde_json::Value)>,
) -> Result<Vec<serde_json::Value>> {
    run_query(graph, cypher, params, DEFAULT_TIMEOUT).await
}

/// Convert a JSON value to a Bolt parameter. Scalars and lists (which recurse, so a list of
/// lists is accepted) are values; a MAP is rejected, because a parameter is a value and anything
/// structural belongs in the query template where the read-only guard can see it.
fn bolt_param(value: serde_json::Value) -> Result<BoltType> {
    Ok(match value {
        serde_json::Value::String(s) => BoltType::from(s),
        serde_json::Value::Bool(b) => BoltType::from(b),
        serde_json::Value::Null => BoltType::Null(Default::default()),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                BoltType::from(i)
            } else if let Some(f) = n.as_f64() {
                BoltType::from(f)
            } else {
                anyhow::bail!("unrepresentable numeric cypher parameter: {n}")
            }
        }
        serde_json::Value::Array(items) => {
            let mut list = neo4rs::BoltList::default();
            for item in items {
                list.push(bolt_param(item)?);
            }
            BoltType::List(list)
        }
        other => anyhow::bail!("unsupported cypher parameter type: {other}"),
    })
}

/// The guarded, bounded query path shared by [`Neo4j`]'s methods.
async fn run_query(
    graph: &Graph,
    cypher: &str,
    params: Vec<(String, serde_json::Value)>,
    deadline: Duration,
) -> Result<Vec<serde_json::Value>> {
    ensure_read_only(cypher)?;
    let mut q = query(cypher);
    for (key, value) in params {
        q = q.param(&key, bolt_param(value)?);
    }
    tokio::time::timeout(deadline, async {
        let mut result = graph.execute(q).await.context("executing cypher")?;
        let mut rows = Vec::new();
        while let Some(row) = result.next().await.context("streaming cypher rows")? {
            // neo4rs Row -> its JSON representation keeps column names as keys.
            let json: serde_json::Value = row
                .to::<serde_json::Value>()
                .unwrap_or(serde_json::Value::Null);
            rows.push(json);
        }
        Ok::<_, anyhow::Error>(rows)
    })
    .await
    .map_err(|_| NuvekError::Timeout(deadline))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_only_guard_rejects_writes() {
        for bad in [
            "MATCH (n) DELETE n",
            "create (x:Foo)",
            "MATCH (n) SET n.x = 1",
            "MERGE (a:B)",
            "MATCH (n) DETACH DELETE n",
            "LOAD CSV FROM 'x' AS row RETURN row",
            "DROP INDEX foo",
            // CALL is the model-generated-Cypher surface: procedures reach the network and can
            // execute writes from a string argument, bypassing every clause above.
            "CALL apoc.load.json('http://169.254.169.254/')",
            "CALL apoc.periodic.iterate('MATCH (n) RETURN n', 'DELETE n', {})",
            "call db.labels()",
            "MATCH (n) CALL { WITH n RETURN n.name AS x } RETURN x",
        ] {
            let err = ensure_read_only(bad).unwrap_err();
            assert!(
                err.downcast_ref::<NuvekError>()
                    .map(|e| matches!(e, NuvekError::WriteClauseRejected(_)))
                    .unwrap_or(false),
                "expected WriteClauseRejected for: {bad}"
            );
        }
    }

    #[test]
    fn read_only_guard_allows_reads() {
        for ok in [
            "MATCH (n) RETURN count(n) AS nodes",
            "MATCH (a)-[r]->(b) RETURN a,r,b LIMIT 10",
            // 'settle' must not trip the SET word-boundary matcher
            "MATCH (n) WHERE n.name = 'settle' RETURN n",
            // 'created_at' property must not trip CREATE
            "MATCH (n) RETURN n.created_at",
            // …and the same word-boundary risk for CALL: 'recall'/'called' embed the letters.
            // \b already handles these; the cases document the intent so a future widening of
            // the pattern (dropping \b, or matching a substring) fails here instead of in prod.
            "MATCH (s:Skill {name: 'recall_example'}) RETURN s",
            "MATCH (n) WHERE n.note = 'called twice' RETURN n",
            // Typical report queries this guard has to keep working.
            "MATCH (c:Container)-[:DEPENDS_ON]->(d) RETURN c.name, d.name",
            "MATCH (p:Package {shared: true})<-[:DEPENDS_ON]-(q) RETURN q.name LIMIT 30",
        ] {
            assert!(ensure_read_only(ok).is_ok(), "expected read allowed: {ok}");
        }
    }

    #[test]
    fn params_cannot_smuggle_a_clause_past_the_guard() {
        // The guard runs on the TEMPLATE, so a write clause there is still rejected…
        assert!(
            ensure_read_only("MATCH (n) WHERE n.name = $x DELETE n").is_err(),
            "a write clause in the template must still be rejected"
        );
        // …while the same text as a parameter VALUE is inert — the server binds it, never parses
        // it as Cypher. This is the property that makes interpolation unnecessary.
        let smuggled = bolt_param(serde_json::json!("x' DETACH DELETE n //"))
            .expect("a string parameter is always representable");
        assert!(matches!(smuggled, BoltType::String(_)));
        assert!(ensure_read_only("MATCH (n) WHERE n.name = $x RETURN n").is_ok());
    }

    #[test]
    fn bolt_param_covers_the_scalar_shapes_and_rejects_structure() {
        assert!(matches!(
            bolt_param(serde_json::json!("s")).unwrap(),
            BoltType::String(_)
        ));
        assert!(matches!(
            bolt_param(serde_json::json!(7)).unwrap(),
            BoltType::Integer(_)
        ));
        assert!(matches!(
            bolt_param(serde_json::json!(1.5)).unwrap(),
            BoltType::Float(_)
        ));
        assert!(matches!(
            bolt_param(serde_json::json!(true)).unwrap(),
            BoltType::Boolean(_)
        ));
        assert!(matches!(
            bolt_param(serde_json::json!(null)).unwrap(),
            BoltType::Null(_)
        ));
        assert!(matches!(
            bolt_param(serde_json::json!(["a", "b"])).unwrap(),
            BoltType::List(_)
        ));
        // A map is structural, not a value — rejected rather than silently flattened.
        assert!(bolt_param(serde_json::json!({"a": 1})).is_err());
    }

    /// Live: proves neo4rs connects and runs read-only Cypher.
    ///
    /// Gated behind `NUVEK_LIVE_TESTS=1`, and the connection details come from the environment
    /// HERE, in the test — the library itself must not know where a Neo4j lives.
    #[tokio::test]
    async fn live_neo4j_count() {
        if std::env::var("NUVEK_LIVE_TESTS").as_deref() != Ok("1") {
            eprintln!("skipping live_neo4j_count (set NUVEK_LIVE_TESTS=1)");
            return;
        }
        let cfg = Neo4jConfig {
            uri: std::env::var("NEO4J_HOST").expect("NEO4J_HOST"),
            user: std::env::var("NEO4J_USER").unwrap_or_else(|_| "neo4j".into()),
            password: std::env::var("NEO4J_PASSWORD").expect("NEO4J_PASSWORD"),
            timeout: None,
        };
        let graph = connect(&cfg).await.expect("connect to neo4j");
        let rows = query_rows(&graph, "MATCH (n) RETURN count(n) AS nodes")
            .await
            .expect("count query");
        assert_eq!(rows.len(), 1);
        assert!(rows[0]["nodes"].as_i64().unwrap_or(0) > 0);
    }
}
