//! Process-wide `tracing` subscriber installation.
//!
//! Its own module rather than a function inside [`log`](crate::log), because it is a different
//! concern and a different lifetime: [`log::get_logger`](crate::log::get_logger) (journald) constructs a
//! value the caller owns, while this installs **process-global** state exactly once. Keeping them
//! together made the `tracing` feature gate a single function inside another module — invisible to
//! anything that reasons about the crate's public surface by module, which is how the dependency
//! graph models a feature.
//!
//! ```no_run
//! nuvek_core::tracing::init_tracing();
//! ```

/// Install a process-wide `tracing` subscriber that writes to **stderr** — never stdout, which is
/// the JSON-RPC channel for the MCP servers — honouring `RUST_LOG` (default `warn`).
///
/// Binaries should call this once at startup so library `tracing` events are actually emitted.
/// Idempotent-safe: a second call is a no-op, because the global default is already set.
///
/// A library normally must not install process-global state. This is the deliberate exception:
/// it is opt-in behind the `tracing` feature, `try_init`-idempotent, and offers exactly the
/// contract `tracing_subscriber` itself does. **Do not "fix" it into a hidden default** — a
/// library that installs a subscriber the caller did not ask for silently steals their logging.
pub fn init_tracing() {
    use tracing_subscriber::{fmt, EnvFilter};
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    let _ = fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The idempotence the doc promises: a second call must not panic, and must not replace the
    /// subscriber a host application already installed.
    #[test]
    fn init_is_idempotent() {
        init_tracing();
        init_tracing();
    }
}
