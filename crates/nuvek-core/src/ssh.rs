//! Hardened SSH command runner.
//!
//! One implementation shared by every tool that needs live state on a remote host, so the
//! hardening (no password prompts, bounded timeout, ordered least-privileged-first users) can't
//! drift between callers.
//!
//! Hardening is not optional here: `BatchMode=yes` guarantees a missing key fails fast instead of
//! hanging on a prompt, and the call is wrapped in `command_output_timeout` so an unreachable host
//! can never wedge a timer-driven job. Users are tried least-privileged first.
//!
//! **The host and the user list are the caller's.** This module used to resolve a server address
//! and a user list from a shared config, so every consumer inherited one deployment's accounts:
//!
//! ```no_run
//! # fn f() -> anyhow::Result<()> {
//! use nuvek_core::{env::env_or, ssh::Ssh};
//! let server = Ssh::new(env_or("MYTOOL_HOST", "server.example.test"), ["deploy", "root"]);
//! let out = server.exec("docker ps")?;
//! # Ok(()) }
//! ```

use crate::util::command_output_timeout;
use std::process::{Command, Stdio};
use std::result::Result;
use std::time::Duration;

/// Default deadline for a read-only probe.
///
/// A protocol-shaped default: it bounds one SSH round trip so an unreachable host fails rather
/// than hanging. It is NOT correct for state-changing work — see [`Ssh::exec_timeout`].
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(20);

/// Why a remote command did not produce output.
///
/// Typed rather than a formatted string because callers act differently on each: a
/// [`SshError::Timeout`] against a host mid-rebuild is worth retrying, an
/// [`SshError::AuthFailed`] never is, and a [`SshError::CommandFailed`] means the host is fine and
/// the command is wrong. A caller reading a rendered message can only print it.
///
/// The distinction is load-bearing for state-changing callers: the SSH client giving up does NOT
/// stop the remote command, so a `Timeout` means "unknown, possibly still running" — never
/// "did not happen". Rolling back on a `Timeout` acts on a false premise.
#[derive(Debug, thiserror::Error)]
pub enum SshError {
    /// No user in the list could authenticate, or none was permitted to run the command.
    #[error("SSH to {host} failed for every user: {last_error}")]
    AuthFailed {
        /// The host that refused.
        host: String,
        /// The final user's stderr, trimmed.
        last_error: String,
    },

    /// Authentication succeeded; the remote command itself exited non-zero.
    #[error("remote command failed on {host}: {stderr}")]
    CommandFailed {
        /// The host the command ran on.
        host: String,
        /// stderr (or stdout when stderr was empty), trimmed.
        stderr: String,
    },

    /// The deadline elapsed. **The remote command may still be running.**
    #[error("SSH timeout to {host} (as {user}) after {timeout:?}")]
    Timeout {
        /// The host being contacted.
        host: String,
        /// The user in flight when the deadline elapsed.
        user: String,
        /// The deadline that elapsed.
        timeout: Duration,
    },

    /// The local `ssh` binary could not be run at all.
    #[error("could not run ssh locally")]
    Spawn(#[source] std::io::Error),

    /// A pipe the implementation requires was not established.
    #[error("ssh {0} was not piped")]
    PipeMissing(&'static str),
}

/// A remote host plus the ordered user list to try against it.
///
/// Construct once and pass it down. Holding the host and users together is what stops either
/// drifting back into a module-level constant.
#[derive(Debug, Clone)]
pub struct Ssh {
    host: String,
    users: Vec<String>,
    timeout: Duration,
}

impl Ssh {
    /// A client for `host`, trying `users` in order — least-privileged first.
    ///
    /// The trailing slash is stripped: this value is concatenated into `user@host`, and
    /// `deploy@10.0.0.1/` is not a host.
    pub fn new(
        host: impl Into<String>,
        users: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            host: host.into().trim_end_matches('/').to_string(),
            users: users.into_iter().map(Into::into).collect(),
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// Override the default per-command deadline.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// The host this client targets.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    fn user_refs(&self) -> Vec<&str> {
        self.users.iter().map(String::as_str).collect()
    }

    /// Run a read-only command, trying each user in turn. Returns stdout.
    ///
    /// Blocking — call from `spawn_blocking` inside async code. An auth failure falls through to
    /// the next user; a genuine command failure stops immediately rather than retrying as another
    /// user.
    pub fn exec(&self, remote_cmd: &str) -> Result<String, SshError> {
        exec_on_host(&self.host, &self.user_refs(), remote_cmd, self.timeout)
    }

    /// [`Ssh::exec`] with an explicit timeout, for commands that legitimately take minutes.
    ///
    /// The 20 s default is tuned for read-only probes and is correct for them. It is NOT correct
    /// for state-changing work: a container rebuild (image pull included) routinely exceeds it.
    /// Worse, the SSH client giving up does not stop the remote command — so a too-short timeout
    /// reports failure while the operation is still running, and a caller that "rolls back" on
    /// that error acts on a false premise. Callers doing slow remote work must pass a realistic
    /// budget.
    pub fn exec_timeout(&self, remote_cmd: &str, timeout: Duration) -> Result<String, SshError> {
        exec_on_host(&self.host, &self.user_refs(), remote_cmd, timeout)
    }

    /// [`Ssh::exec`] pinned to an explicit user list (tests, or a caller that must use one
    /// specific account).
    pub fn exec_as(&self, users: &[&str], remote_cmd: &str) -> Result<String, SshError> {
        exec_on_host(&self.host, users, remote_cmd, self.timeout)
    }

    /// Run a remote command with `input` fed to it on STDIN.
    ///
    /// Exists because a secret must never be an ARGUMENT. `/proc/<pid>/cmdline` is world-readable
    /// on the remote host as much as here, so `exec(&format!("echo {key} > file"))` publishes the
    /// credential to every process on the box for the life of the call. Piping it in means the
    /// value appears only in the remote process's stdin, which is not readable that way.
    ///
    /// The remote command itself is still an argument, so it must not contain the secret either —
    /// the intended shape is a command that READS stdin (`base64 -d > file`, `bash -s`).
    ///
    /// Blocking — call from `spawn_blocking` inside async code.
    pub fn exec_stdin(
        &self,
        remote_cmd: &str,
        input: &str,
        timeout: Duration,
    ) -> Result<String, SshError> {
        exec_on_host_stdin(&self.host, &self.user_refs(), remote_cmd, input, timeout)
    }
}

/// Should this failure be retried as the next (more privileged) user?
///
/// Covers BOTH cases the fallback exists for: SSH refusing the login at all, and a user who
/// authenticates fine but lacks rights to run the command (`mcp-service` outside the `docker`
/// group). Matching is case-insensitive on purpose — SSH says "Permission denied" while docker
/// says "permission denied" for its socket, and anchoring on SSH's capitalization alone would
/// treat the under-privileged case as a hard stop, never retrying it, contrary to the design.
fn is_auth_failure(err: &str) -> bool {
    let e = err.to_lowercase();
    e.contains("permission denied")
        || e.contains("publickey")
        || e.contains("access denied")
        || e.contains("not allowed")
}

/// `exec_on_host` with stdin, sharing its hardening and its user-fallback semantics.
///
/// Deliberately does NOT reuse `command_output_timeout`: that helper takes a `Command` and waits
/// on it, with no way to write to the child's stdin first.
///
/// Three things in this function are load-bearing:
///
/// * **The stdin write happens on its own thread.** Writing inline blocks once the pipe buffer
///   (~64 KiB) fills, and nothing is draining stdout/stderr at that moment — so a remote command
///   that produces output while still reading input deadlocks both sides forever. The module's
///   contract is that every subprocess is bounded, and an inline write silently broke it.
/// * **stdout and stderr are drained concurrently**, for the mirror-image reason: a child that
///   writes more than a pipe buffer blocks until someone reads.
/// * **The deadline starts before the write**, so a stalled write is covered by the timeout
///   rather than sitting outside it.
///
/// The stdin handle is dropped when the writer thread ends, closing it — required by every
/// intended caller, all of which read to EOF.
pub fn exec_on_host_stdin(
    host: &str,
    users: &[&str],
    remote_cmd: &str,
    input: &str,
    timeout: Duration,
) -> Result<String, SshError> {
    use std::io::{Read, Write};

    let mut last_err = String::new();
    for user in users {
        let deadline = std::time::Instant::now() + timeout;

        let mut child = Command::new("ssh")
            .args([
                "-o",
                "ConnectTimeout=5",
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=accept-new",
                &format!("{user}@{host}"),
                remote_cmd,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(SshError::Spawn)?;

        let mut si = child.stdin.take().ok_or(SshError::PipeMissing("stdin"))?;
        let mut so = child.stdout.take().ok_or(SshError::PipeMissing("stdout"))?;
        let mut se = child.stderr.take().ok_or(SshError::PipeMissing("stderr"))?;

        let payload = input.to_string();
        // A broken pipe here is not an error worth surfacing: it means the remote command exited
        // without consuming all of stdin, and its exit status is the real story.
        let writer = std::thread::spawn(move || {
            let _ = si.write_all(payload.as_bytes());
            let _ = si.flush();
        });
        let out_t = std::thread::spawn(move || {
            let mut b = Vec::new();
            let _ = so.read_to_end(&mut b);
            b
        });
        let err_t = std::thread::spawn(move || {
            let mut b = Vec::new();
            let _ = se.read_to_end(&mut b);
            b
        });

        let status = loop {
            match child.try_wait() {
                Err(e) => return Err(SshError::Spawn(e)),
                Ok(Some(s)) => break s,
                Ok(None) => {
                    if std::time::Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(SshError::Timeout {
                            host: host.to_string(),
                            user: (*user).to_string(),
                            timeout,
                        });
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        };

        // The child has exited, so both pipes are at EOF and these joins cannot block.
        let stdout = out_t.join().unwrap_or_default();
        let stderr = err_t.join().unwrap_or_default();
        let _ = writer.join();

        if status.success() {
            return Ok(String::from_utf8_lossy(&stdout).into_owned());
        }
        let stderr = String::from_utf8_lossy(&stderr);
        let msg = if stderr.trim().is_empty() {
            String::from_utf8_lossy(&stdout).into_owned()
        } else {
            stderr.into_owned()
        };
        last_err = msg.trim().to_string();
        if !is_auth_failure(&last_err) {
            return Err(SshError::CommandFailed {
                host: host.to_string(),
                stderr: last_err,
            });
        }
    }
    Err(SshError::AuthFailed {
        host: host.to_string(),
        last_error: last_err,
    })
}

/// Run a command on an ARBITRARY host with the same hardening [`Ssh`] uses.
///
/// A deployment usually has more than one SSH target, and a tool that touches another one should
/// not hand-roll its own `ssh` invocation and quietly lose `BatchMode` (which is what stops a
/// timer job hanging forever on a password prompt) or the output timeout.
///
/// Blocking — call from `spawn_blocking` inside async code.
pub fn exec_on_host(
    host: &str,
    users: &[&str],
    remote_cmd: &str,
    timeout: Duration,
) -> Result<String, SshError> {
    let mut last_err = String::new();
    for user in users {
        let mut cmd = Command::new("ssh");
        cmd.args([
            "-o",
            "ConnectTimeout=5",
            "-o",
            "BatchMode=yes", // never prompt: fail fast instead of hanging a timer job
            "-o",
            "StrictHostKeyChecking=accept-new",
            &format!("{user}@{host}"),
            remote_cmd,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
        match command_output_timeout(cmd, timeout) {
            Ok(Some(out)) if out.status.success() => {
                return Ok(String::from_utf8_lossy(&out.stdout).into_owned())
            }
            Ok(Some(out)) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                let msg = if stderr.trim().is_empty() {
                    String::from_utf8_lossy(&out.stdout).into_owned()
                } else {
                    stderr.into_owned()
                };
                last_err = msg.trim().to_string();
                // Auth/permission failure ⇒ try the next user. A real command error ⇒ stop, or we
                // would retry a broken command as root and misreport why it failed.
                if !is_auth_failure(&last_err) {
                    return Err(SshError::CommandFailed {
                        host: host.to_string(),
                        stderr: last_err,
                    });
                }
            }
            // A network-level timeout will recur identically for the next user — retrying only
            // doubles the worst-case stall for an unreachable host.
            Ok(None) => {
                return Err(SshError::Timeout {
                    host: host.to_string(),
                    user: (*user).to_string(),
                    timeout,
                })
            }
            Err(e) => return Err(SshError::Spawn(e)),
        }
    }
    Err(SshError::AuthFailed {
        host: host.to_string(),
        last_error: last_err,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_failures_fall_through_command_failures_do_not() {
        // SSH rejecting the login outright.
        assert!(is_auth_failure("Permission denied (publickey,password)."));
        assert!(is_auth_failure("user@host: Permission denied (publickey)."));
        // Authenticated, but not privileged to run the command — the case the fallback to a more
        // privileged user actually exists for. Lowercase, as docker emits it.
        assert!(is_auth_failure(
            "Got permission denied while trying to connect to the Docker daemon socket"
        ));
        // A genuine command failure must STOP, not be retried as root and misreported.
        assert!(!is_auth_failure(
            "docker: 'inspect' requires at least 1 argument"
        ));
        assert!(!is_auth_failure("bash: docker: command not found"));
        assert!(!is_auth_failure(""));
    }
}
