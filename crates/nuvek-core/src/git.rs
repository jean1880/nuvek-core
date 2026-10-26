//! Bounded `git -C <dir>` helper.
//!
//! For tools that drive atomic commits against a git-backed store. Wraps
//! [`crate::util::command_output_timeout`] so every caller shares one bounded, fail-closed exec
//! path instead of each re-deriving `std::process` timeout handling. The repository directory is
//! an argument on every call.

use crate::util::command_output_timeout;
use std::process::{Command, Stdio};
use std::time::Duration;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Outcome of a bounded git invocation. A spawn failure or timeout yields `success=false` with
/// empty streams (fail-closed) rather than panicking.
pub struct GitOutput {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

/// A git command runner pinned to one repository directory (`git -C <dir> …`).
#[derive(Clone)]
pub struct Git {
    dir: String,
}

impl Git {
    /// Bind a runner to a repository directory.
    pub fn new(dir: impl Into<String>) -> Self {
        Self { dir: dir.into() }
    }

    /// Run `git -C <dir> <args...>` with the default 30s wall-clock timeout.
    pub fn run(&self, args: &[&str]) -> GitOutput {
        self.run_timeout(args, DEFAULT_TIMEOUT)
    }

    /// Run `git -C <dir> <args...>` with an explicit wall-clock timeout.
    pub fn run_timeout(&self, args: &[&str], timeout: Duration) -> GitOutput {
        let mut cmd = Command::new("git");
        cmd.arg("-C")
            .arg(&self.dir)
            .args(args)
            // Unattended: a credential prompt would block until the timeout, or land on an
            // inherited terminal. Fail at once instead.
            .env("GIT_TERMINAL_PROMPT", "0")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        match command_output_timeout(cmd, timeout) {
            Ok(Some(out)) => GitOutput {
                success: out.status.success(),
                stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            },
            // Timed out (Ok(None)) or could not spawn (Err) → fail-closed.
            _ => GitOutput {
                success: false,
                stdout: String::new(),
                stderr: String::new(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_and_log_in_a_temp_repo() {
        let dir = std::env::temp_dir().join(format!("nuvek-git-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let git = Git::new(dir.to_string_lossy().into_owned());

        assert!(git.run(&["init", "-q"]).success);
        git.run(&["config", "user.email", "t@example.com"]);
        git.run(&["config", "user.name", "test"]);
        std::fs::write(dir.join("a.txt"), "hi").unwrap();
        assert!(git.run(&["add", "--", "a.txt"]).success);
        assert!(
            git.run(&["commit", "-m", "[example-worker] promote: x", "--", "a.txt"])
                .success
        );

        let log = git.run(&["log", "--grep", r"\[example-worker\]", "--format=%s"]);
        assert!(log.success);
        assert!(log.stdout.contains("[example-worker] promote: x"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn failed_command_reports_unsuccessful() {
        let git = Git::new("/nonexistent/path/xyz".to_string());
        assert!(!git.run(&["status"]).success);
    }
}
