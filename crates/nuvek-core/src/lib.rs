//! nuvek-core — portable mechanism for small operational tools.
//!
//! # What belongs here
//!
//! > **nuvek-core is mechanism.** It may never name a host, a path, a person, or a product beyond
//! > the protocol it speaks. If a value would differ on someone else's machine, it does not belong
//! > here — it is a parameter.
//! >
//! > **Your deployment crate** is where those names live. It exists so code shared by several of
//! > your binaries has a home that is not the portable library.
//! >
//! > A module with exactly **one** consumer belongs in that consumer, not in either crate.
//!
//! That rule is load-bearing. A shared library that resolves its own config file, caches a
//! process-global config and ships a server address or home directory as built-in defaults makes
//! every consumer inherit a deployment it cannot override. That happens not because anyone decides
//! the library should own a server address, but because there is no stated test for what is
//! allowed in, and "several tools need it" is not one.
//!
//! The analogy that settles most cases: axios provides a request layer. It does not provide a
//! "connect to Google" API.
//!
//! # Modules
//!
//! - [`env`](mod@env) — environment-reading primitives. Blank is unset, values are trimmed, and **the
//!   caller names the variable**.
//! - [`http`] — shared `reqwest` client construction with an explicit timeout.
//! - `ssh` — hardened SSH exec against a host the caller supplies.
//! - [`scrub`] — token-shaped secret redaction and the secret-surface contract
//!   ([`scrub::init`]).
//! - [`log`] — leveled audit logger writing to the systemd journal, with a stderr copy.
//! - [`tracing`] — opt-in installation of a process-wide `tracing` subscriber.
//! - [`metrics`] — best-effort Prometheus textfile telemetry into a caller-supplied directory.
//! - [`git`] — bounded `git -C` runner.
//! - `digest` — SHA-256 content keys, for matching text across tools without storing it.
//! - `hook` — agent-harness (Claude Code / Antigravity) hook I/O: harness selection, workspace,
//!   and the context-injection output each harness parses.
//! - [`util`] — small shared helpers.
//! - [`error`] — typed errors callers may want to match on.
//!
//! # Features
//!
//! `env`, `error` and `util` are always present — they are the spine and cost nothing. Everything
//! else is opt-in: `net` (http), `ssh`, `scrub`, `log`, `metrics`, `git`, `tracing`, `mcp`, `hook`,
//! `digest`.
//! A tool that only redacts secrets should not build an HTTP stack. CI builds each feature alone,
//! because `--all-features` hides a module that compiles only when a sibling pulls its
//! dependency in.

pub mod env;
pub mod error;
pub mod util;

#[cfg(feature = "digest")]
pub mod digest;
#[cfg(feature = "gateway")]
pub mod gateway;
#[cfg(feature = "git")]
pub mod git;
#[cfg(feature = "hook")]
pub mod hook;
#[cfg(feature = "net")]
pub mod http;
#[cfg(feature = "log")]
pub mod log;
#[cfg(feature = "mcp")]
pub mod mcp;
#[cfg(feature = "metrics")]
pub mod metrics;
#[cfg(feature = "scrub")]
pub mod scrub;
#[cfg(feature = "ssh")]
pub mod ssh;
#[cfg(feature = "tracing")]
pub mod tracing;

pub use error::NuvekError;

/// Serializes tests that mutate the process-global environment.
///
/// Only [`env`](mod@env)'s own tests need this: reading the environment is that module's entire
/// purpose. `scrub::init`'s tests that need the environment run in a child process of their own
/// instead. Every other module takes its settings as arguments and its tests cannot race. If this
/// lock appears anywhere else in the crate, something has started reading the environment behind
/// its caller's back.
#[cfg(test)]
pub(crate) mod test_lock {
    use std::sync::{Mutex, MutexGuard};
    static ENV: Mutex<()> = Mutex::new(());
    /// Acquire the env lock, recovering from a poisoned mutex (a panicking test still
    /// leaves the env consistent enough for the next).
    pub fn env() -> MutexGuard<'static, ()> {
        ENV.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Runs one test in a fresh process of the test binary.
#[cfg(test)]
pub(crate) mod test_isolation {
    use std::process::{Command, Stdio};
    use std::time::Duration;

    /// Set in the child process, naming the one test it runs.
    const CHILD_ENV: &str = "NUVEK_TEST_ISOLATED_CHILD";

    /// Run `body` in a fresh process of this test binary, under a deadline.
    ///
    /// `test_path` is the test's full libtest name (`scrub::tests::foo`). For tests about
    /// process-wide state (globals, the environment, the process's own threads and file
    /// descriptors), which would race with every other test in-process. The child runs only this
    /// test (`--exact`), single-threaded, so it may set environment variables and count its own
    /// resources. The deadline also bounds a test whose failure mode is a hang.
    pub fn isolated(test_path: &str, body: impl FnOnce()) {
        if std::env::var_os(CHILD_ENV).is_some_and(|v| v == test_path) {
            body();
            return;
        }
        let exe = std::env::current_exe().expect("test binary path");
        let mut cmd = Command::new(exe);
        cmd.args(["--exact", test_path, "--test-threads=1", "--nocapture"])
            .env(CHILD_ENV, test_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let out = crate::util::command_output_timeout(cmd, Duration::from_secs(60))
            .expect("spawn the test binary")
            .unwrap_or_else(|| panic!("{test_path} did not finish within the deadline"));
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            out.status.success() && stdout.contains("1 passed"),
            "{test_path} failed in its own process:\n{stdout}\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
