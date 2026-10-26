//! Shared `reqwest` client construction, so every tool gets identical transport defaults (the
//! workspace's rustls TLS and an explicit request timeout) instead of hand-rolling a builder — and
//! so no caller ships a `Client::new()` with no timeout, where a hung request blocks forever.
//! Per-call deadlines still layer on top via `.timeout(...)` at the request site.
//!
//! Fallible by design (library code never panics); binaries `?`/`.expect()` at startup.

use std::time::Duration;

/// An HTTP client with a default request `timeout` and rustls TLS.
pub fn client(timeout: Duration) -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder().timeout(timeout).build()
}

/// Like [`client`] but also sets a `User-Agent` (for APIs that require or log one).
pub fn client_with_agent(timeout: Duration, user_agent: &str) -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(timeout)
        .user_agent(user_agent)
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_clients() {
        assert!(client(Duration::from_secs(5)).is_ok());
        assert!(client_with_agent(Duration::from_secs(5), "nuvek-test/1.0").is_ok());
    }
}
