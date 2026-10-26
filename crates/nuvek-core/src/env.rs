//! Environment-reading primitives. **Mechanism only — this module names nothing.**
//!
//! Every function in this module takes the variable name from its caller. nuvek-core does not know
//! that a Chroma URL lives in `CHROMA_URL`, or that there is a Chroma at all: the package using
//! the library owns that decision, along with the default to fall back to.
//!
//! # Why these are shared at all
//!
//! Reading an environment variable looks too trivial to share. Independent implementations can
//! disagree about blank values and fallback paths, and the disagreements are bugs, not style:
//!
//! * `std::env::var(..).ok()` counts a variable set to `""` as SET. A client reading a blank
//!   `EXAMPLE_API_KEY` as `Some("")` authenticates with an empty key, producing a 401
//!   indistinguishable from a wrong key.
//! * A hand-rolled `$HOME` lookup may fall back to `"."` or to some fixed home directory; the
//!   second silently reads and writes the wrong files.
//! * A blank `EXAMPLE_LOG_DIR` produces an empty path rather than the intended default.
//!
//! So the contract, in one place: **blank is unset, values are trimmed, and a default is only
//! used when the caller did not really supply one.** [`env_var_exact`] preserves nonblank values
//! for credential import, where trimming could silently change the credential.

use std::path::PathBuf;

/// Read an env var, treating blank as unset and trimming the value.
///
/// The one place the process environment is read. Everything else in the workspace should call
/// this rather than `std::env::var`, so "was it set?" has a single answer everywhere.
pub fn env_var(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

/// Read an environment value without trimming it; blank and non-Unicode values are unset.
/// Credential importers should validate the returned value and never print it.
pub fn env_var_exact(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

/// [`env_var`] with a fallback supplied by the caller.
///
/// This is the workhorse of the post-refactor design: a binary names its own variable and its own
/// default, and the library never learns either.
///
/// ```
/// # use nuvek_core::env::env_or;
/// const CHROMA_ENV: &str = "CHROMA_URL";
/// const CHROMA_DEFAULT: &str = "http://localhost:8000";
/// let url = env_or(CHROMA_ENV, CHROMA_DEFAULT);
/// assert!(url.starts_with("http"));
/// ```
pub fn env_or(name: &str, default: impl Into<String>) -> String {
    env_var(name).unwrap_or_else(|| default.into())
}

/// Parse an env var into any `FromStr` type, or `None` if unset, blank or unparseable.
///
/// Unparseable deliberately behaves as unset rather than as an error: these are operator
/// conveniences on tools that run unattended, and refusing to start because a tuning knob has a
/// typo is worse than using the default.
pub fn env_parse<T: std::str::FromStr>(name: &str) -> Option<T> {
    env_var(name).and_then(|v| v.parse().ok())
}

/// [`env_parse`] with a fallback.
pub fn env_parse_or<T: std::str::FromStr>(name: &str, default: T) -> T {
    env_parse(name).unwrap_or(default)
}

/// A boolean env var: `1`, `true`, `yes`, `on` (case-insensitive) are true; anything else false.
///
/// Not universal by design. A flag whose job is to *stop* writes (a dry-run switch) should stay
/// permissive so an unrecognised value leaves the safe state ON — this helper would turn it off
/// for a typo, which is the wrong direction. Those flags keep their own parsing.
pub fn env_flag(name: &str) -> bool {
    matches!(
        env_var(name).map(|v| v.to_ascii_lowercase()).as_deref(),
        Some("1" | "true" | "yes" | "on")
    )
}

/// A directory from an env var, falling back to `$HOME/<fallback>`.
///
/// The fallback is the CALLER's — `env_dir("MYTOOL_LOG_DIR", ".mytool/logs")`. The library
/// supplies the `$HOME`-relative resolution and the blank handling, nothing more.
pub fn env_dir(name: &str, home_relative_fallback: &str) -> PathBuf {
    match env_var(name) {
        Some(d) => PathBuf::from(expand_home(&d)),
        None => home_dir().join(home_relative_fallback),
    }
}

/// `$HOME`, or `.` when it is unset — never a panic.
///
/// One definition, so every caller falls back the same way. `.` is the safe fallback: a relative
/// path fails visibly, whereas someone else's home directory silently reads and writes the wrong
/// files.
pub fn home() -> String {
    env_var("HOME").unwrap_or_else(|| ".".to_string())
}

/// [`home`] as a `PathBuf`.
pub fn home_dir() -> PathBuf {
    PathBuf::from(home())
}

/// Expand a leading `~` using `$HOME`.
///
/// Automation wants absolute paths, but a path a human typed contains `~`. Expanding it at the
/// point of use keeps paths absolute without making anyone hardcode their own home directory.
pub fn expand_home(p: &str) -> String {
    match p.strip_prefix("~/") {
        Some(rest) => format!("{}/{rest}", home_dir().display()),
        None => p.to_string(),
    }
}

/// Drop a value that is present-but-blank, so it cannot beat a default.
///
/// Exported because callers building their own config need the same "explicitly empty is not a
/// value" rule that [`env_var`] applies to the environment. An empty string that survives into a
/// config is rarely inert: it produced `http://:8000` from a blank host, and a blank `git_owner`
/// inverted a retrieval filter entirely (`"".contains("")` is true for every string).
pub fn non_empty(v: Option<String>) -> Option<String> {
    v.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

/// Errors from reading a shell-sourced environment file.
#[derive(Debug, thiserror::Error)]
pub enum EnvFileError {
    /// The file could not be read. Carries the path so the caller can say which one.
    #[error("reading the environment file {path}")]
    Read {
        /// The path that failed.
        path: String,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },
}

/// Read a variable's value out of a shell-sourced env FILE, not the process environment.
///
/// These two diverge exactly when it matters most. An env file is what an exec'd process — an MCP
/// server, a systemd unit — will read at ITS next launch; the current process inherited its own
/// copy when it started. After a credential rotation the file is fresh and the running process is
/// stale, so a check that reads `std::env::var` reports a correctly-rotated file as STALE, and
/// would equally miss a genuinely stale one whose process copy happened to be fresh.
///
/// The path is the caller's — the library does not know where anyone keeps their env file.
///
/// The value is a secret: callers must fingerprint or compare, never print.
pub fn read_env_file(path: &str, name: &str) -> Result<Option<String>, EnvFileError> {
    let text = std::fs::read_to_string(path).map_err(|source| EnvFileError::Read {
        path: path.to_string(),
        source,
    })?;
    Ok(parse_env_file(&text, name))
}

/// The parsing half of [`read_env_file`], usable on text from anywhere.
///
/// Handles both `export NAME="value"` and a legacy bare `NAME=value`; surrounding quotes are
/// stripped. Returns `None` when the variable is absent; a blank value reads as absent, as
/// everywhere else in this module.
pub fn parse_env_file(text: &str, name: &str) -> Option<String> {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let body = line.strip_prefix("export ").unwrap_or(line).trim_start();
        // Anchored on `NAME=`, so `EXAMPLE_API_KEY_OLD` cannot satisfy a lookup for
        // `EXAMPLE_API_KEY` — a prefix match here would silently compare the wrong credential.
        let Some(rest) = body.strip_prefix(name) else {
            continue;
        };
        let Some(value) = rest.strip_prefix('=') else {
            continue;
        };
        let v = value.trim();
        let v = v
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .or_else(|| v.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')))
            .unwrap_or(v);
        let v = v.trim();
        if !v.is_empty() {
            return Some(v.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blank_env_is_treated_as_unset() {
        let _g = crate::test_lock::env();
        std::env::set_var("NUVEK_TEST_BLANK", "   ");
        assert_eq!(env_var("NUVEK_TEST_BLANK"), None);
        std::env::set_var("NUVEK_TEST_BLANK", " value ");
        assert_eq!(env_var("NUVEK_TEST_BLANK").as_deref(), Some("value"));
        std::env::remove_var("NUVEK_TEST_BLANK");
    }

    #[test]
    fn exact_env_preserves_content_but_treats_blank_as_unset() {
        let _g = crate::test_lock::env();
        let name = "NUVEK_TEST_EXACT";
        std::env::remove_var(name);
        assert_eq!(env_var_exact(name), None);
        std::env::set_var(name, " \t ");
        assert_eq!(env_var_exact(name), None);
        std::env::set_var(name, " synthetic_credential ");
        assert_eq!(
            env_var_exact(name).as_deref(),
            Some(" synthetic_credential ")
        );
        std::env::remove_var(name);
    }

    #[test]
    fn env_or_falls_back_to_the_callers_default() {
        let _g = crate::test_lock::env();
        std::env::remove_var("NUVEK_TEST_ABSENT");
        assert_eq!(env_or("NUVEK_TEST_ABSENT", "fallback"), "fallback");
        std::env::set_var("NUVEK_TEST_ABSENT", "set");
        assert_eq!(env_or("NUVEK_TEST_ABSENT", "fallback"), "set");
        std::env::remove_var("NUVEK_TEST_ABSENT");
    }

    #[test]
    fn env_parse_and_flag_treat_blank_as_unset() {
        let _g = crate::test_lock::env();
        std::env::set_var("NUVEK_TEST_N", "  ");
        assert_eq!(env_parse::<u64>("NUVEK_TEST_N"), None);
        assert_eq!(env_parse_or("NUVEK_TEST_N", 7u64), 7);
        std::env::set_var("NUVEK_TEST_N", "42");
        assert_eq!(env_parse_or("NUVEK_TEST_N", 7u64), 42);
        // Unparseable behaves as unset rather than as an error.
        std::env::set_var("NUVEK_TEST_N", "not-a-number");
        assert_eq!(env_parse_or("NUVEK_TEST_N", 7u64), 7);
        std::env::remove_var("NUVEK_TEST_N");

        for v in ["1", "true", "YES", "On"] {
            std::env::set_var("NUVEK_TEST_F", v);
            assert!(env_flag("NUVEK_TEST_F"), "{v} should be true");
        }
        for v in ["0", "false", "", "  ", "maybe"] {
            std::env::set_var("NUVEK_TEST_F", v);
            assert!(!env_flag("NUVEK_TEST_F"), "{v:?} should be false");
        }
        std::env::remove_var("NUVEK_TEST_F");
    }

    /// With `std::env::var(..).ok()`, a blank value produces an empty path rather than the
    /// default. The shared resolver treats it as unset.
    #[test]
    fn env_dir_treats_blank_as_unset() {
        let _g = crate::test_lock::env();
        std::env::set_var("HOME", "/users/someone");
        std::env::set_var("NUVEK_TEST_DIR", "   ");
        assert_eq!(
            env_dir("NUVEK_TEST_DIR", ".mytool/logs"),
            PathBuf::from("/users/someone/.mytool/logs")
        );
        std::env::set_var("NUVEK_TEST_DIR", "~/elsewhere");
        assert_eq!(
            env_dir("NUVEK_TEST_DIR", ".mytool/logs"),
            PathBuf::from("/users/someone/elsewhere")
        );
        std::env::remove_var("NUVEK_TEST_DIR");
    }

    #[test]
    fn tilde_expands_against_home() {
        let _g = crate::test_lock::env();
        std::env::set_var("HOME", "/users/someone");
        assert_eq!(expand_home("~/git/x"), "/users/someone/git/x");
        assert_eq!(expand_home("/absolute/x"), "/absolute/x");
    }

    #[test]
    fn non_empty_drops_blank_but_keeps_content() {
        assert_eq!(non_empty(Some("   ".into())), None);
        assert_eq!(non_empty(None), None);
        assert_eq!(non_empty(Some(" x ".into())).as_deref(), Some("x"));
    }

    /// The distinction the reader exists for, plus the prefix trap.
    #[test]
    fn env_file_parsing_handles_both_forms_and_anchors_the_name() {
        let text = "# comment\n\
                    export A=\"1\"\n\
                    LEGACY=bare\n\
                    export EXAMPLE_API_KEY_OLD=\"wrongone\"\n\
                    export EXAMPLE_API_KEY=\"rightone\"\n\
                    export BLANK=\"\"\n";
        assert_eq!(parse_env_file(text, "A").as_deref(), Some("1"));
        assert_eq!(parse_env_file(text, "LEGACY").as_deref(), Some("bare"));
        // A prefix match here would compare the WRONG credential and report a false result.
        assert_eq!(
            parse_env_file(text, "EXAMPLE_API_KEY").as_deref(),
            Some("rightone")
        );
        assert_eq!(parse_env_file(text, "BLANK"), None);
        assert_eq!(parse_env_file(text, "ABSENT"), None);
    }

    #[test]
    fn env_file_parsing_ignores_comments_and_single_quotes() {
        assert_eq!(
            parse_env_file("#export X=\"no\"\nexport X='yes'\n", "X").as_deref(),
            Some("yes")
        );
    }

    #[test]
    fn a_missing_env_file_is_an_error_naming_the_path() {
        let e = read_env_file("/nonexistent/definitely/not/here.env", "X")
            .expect_err("a missing file must be an error");
        assert!(e
            .to_string()
            .contains("/nonexistent/definitely/not/here.env"));
    }
}
