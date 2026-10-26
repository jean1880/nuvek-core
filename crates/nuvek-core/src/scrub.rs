//! Secret redaction — the fast in-process layer.
//!
//! Redacts token-shaped secrets only. Internal RFC 1918 IPs are intentionally NOT masked:
//! they are non-sensitive infrastructure context and masking them would gut infra usefulness.
//!
//! # The secret-surface contract
//!
//! [`touches_secret_surface`] decides whether a command or tool input handles a secret, so the
//! caller can drop it before it reaches a model or a store. What it knows comes from three
//! layers, all ORed together and all additive:
//!
//! 1. **Built-in surfaces**, always on: `*.key`/`*.pem` files, `~/.ssh/`, `.env`, `.env.*` and
//!    `<name>.env`, `~/.netrc`, `~/.aws/credentials`, `~/.config/gcloud/`,
//!    `~/.docker/config.json`, `~/.kube/config`, `~/.git-credentials`, `~/.pgpass`,
//!    `~/.cargo/credentials` (and `credentials.toml`), `~/.config/gh/hosts.yml`,
//!    `~/.vault-token`, `~/.gnupg/`, `ssh-keygen` and `git config …token`.
//! 2. **A config file** read by [`init`]: `$NUVEK_SECRET_SURFACES_FILE`, else
//!    `$XDG_CONFIG_HOME/nuvek/secret-surfaces.toml`, else `~/.config/nuvek/secret-surfaces.toml`.
//! 3. **Regex fragments** registered in code with [`extra_secret_surfaces`].
//!
//! Nothing can remove a built-in. Every binary that scans text calls [`init`] first in `main` and
//! exits non-zero if it returns an error:
//!
//! ```no_run
//! fn main() -> std::process::ExitCode {
//!     if let Err(e) = nuvek_core::scrub::init() {
//!         eprintln!("secret surfaces: {e}");
//!         return std::process::ExitCode::FAILURE;
//!     }
//!     // ... scan text ...
//!     std::process::ExitCode::SUCCESS
//! }
//! ```

use crate::util::command_output_timeout;
use fancy_regex::Regex as FancyRegex;
use regex::Regex;
use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{LazyLock, PoisonError, RwLock};
use std::time::Duration;

/// Upper bound on one `gitleaks` scan (30s), treated fail-closed on overrun.
const GITLEAKS_TIMEOUT: Duration = Duration::from_secs(30);

const PLACEHOLDER: &str = "«REDACTED-SECRET»";

/// Token-shaped secret signatures (known prefixes + PEM + JWT). No lookaround → plain `regex`.
/// Built via `concat!` — a trailing `\` inside a Rust *raw* string is literal, so the pieces
/// must join with no continuation characters.
///
/// Known ceiling: the unbounded `sk-[A-Za-z0-9]{20,}` branch also matches inside words such as
/// `disk-<20+ alnum>` (over-redaction, never a leak); a non-letter left boundary is the upgrade
/// path.
static SECRET_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(ghp_[A-Za-z0-9]{20,}",
        r"|gh[oprsu]_[A-Za-z0-9]{20,}",
        // Two branches: the alnum form catches `sk-` glued to a word (`KEY_sk-…`); the URL-safe
        // form catches LiteLLM-style keys carrying `-`/`_`, and its `\b` keeps hyphenated prose
        // (`disk-usage-…`) from matching once `-` is in the class.
        r"|sk-[A-Za-z0-9]{20,}",
        r"|\bsk-[A-Za-z0-9_\-]{20,}",
        r"|AIza[0-9A-Za-z_\-]{20,}",
        r"|AKIA[0-9A-Z]{16}",
        r"|xox[baprs]-[0-9A-Za-z\-]{10,}",
        r"|eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
        // A Discord webhook URL is its own credential: anyone holding it can post.
        r"|discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]{20,}",
        r"|-----BEGIN [A-Z ]*PRIVATE KEY-----)",
    ))
    .expect("SECRET_RE is a valid compile-time constant")
});

/// Secret-bearing SURFACES: matches the path/operation that handles secrets (not the value).
/// Uses lookaround → `fancy-regex`.
///
/// **Only universal surfaces belong here.** A key/PEM file, the well-known credential files of
/// common tools, `ssh-keygen` and `git config …token` mean the same thing on any machine.
/// Deployment-specific surfaces — one site's env-file name, one vendor's CLI — are the caller's to
/// add through the config file read by [`init`] or [`extra_secret_surfaces`]: baking them in made
/// a portable redactor that knew one deployment's filenames, and (worse) silently offered no
/// protection to anyone whose surfaces are named differently.
///
/// The credential-file branches share one left boundary, `(?<![\w.-])`: the dot that starts
/// `.ssh`, `.env` and the rest must begin a path component (`~/.ssh`, `./.env`, ` .netrc`), so
/// `process.env.HOME` and `foo.netrc` do not match. A home-relative file matches under any
/// prefix (`~/`, `$HOME/`, an absolute home path), because a command can spell `$HOME` any way.
static SECRET_SURFACE_RE: LazyLock<FancyRegex> = LazyLock::new(|| {
    FancyRegex::new(concat!(
        r"(?i)(?<![\w.])[\w./-]+\.(?:key|pem)(?![\w])",
        r"|ssh[_-]?keygen",
        r"|git\s+config\b[^\n]*token",
        // ~/.ssh and everything under it (keys, config, agent sockets).
        r"|(?<![\w.-])\.ssh(?:/|(?![\w.-]))",
        // .env and .env.<anything> (.env.local, .env.production); not .envrc.
        r"|(?<![\w.-])\.env(?:\.[\w.-]+)?(?!\w)",
        r"|(?<![\w.-])\.netrc(?!\w)",
        r"|(?<![\w.-])\.aws/credentials",
        r"|(?<![\w.-])\.config/gcloud(?:/|(?![\w.-]))",
        r"|(?<![\w.-])\.docker/config\.json",
        r"|(?<![\w.-])\.kube/config(?![\w-])",
        r"|(?<![\w.-])\.git-credentials(?![\w-])",
        r"|(?<![\w.-])\.pgpass(?![\w-])",
        r"|(?<![\w.-])\.cargo/credentials(?:\.toml)?(?![\w-])",
        r"|(?<![\w.-])\.config/gh/hosts\.ya?ml",
        r"|(?<![\w.-])\.vault-token(?![\w-])",
        r"|(?<![\w.-])\.gnupg(?:/|(?![\w.-]))",
        // A `<name>.env` file (prod.env, stack.env). It must be a whole path token, so property
        // access stays out: `process.env.HOME` and `env[...]` continue with `.`/`[`, a call
        // continues with `(`, and the two common JavaScript env objects are excluded by name.
        r"|(?<![\w.-])(?!(?:process|import\.meta)\.env)[\w-][\w.-]*\.env(?![\w.\[(-])",
    ))
    .expect("SECRET_SURFACE_RE is a valid compile-time constant")
});

/// Caller-registered extra secret surfaces, ORed into [`touches_secret_surface`].
///
/// Registered once at startup, before any scanning. Deliberately additive and one-way: this is a
/// fail-closed security boundary, so a caller may widen what counts as a secret surface but can
/// never narrow it, and a late registration cannot retroactively un-scan what already passed.
static EXTRA_SURFACES: std::sync::OnceLock<FancyRegex> = std::sync::OnceLock::new();

/// Surfaces loaded from the config file by [`init`], ORed into [`touches_secret_surface`].
///
/// Kept apart from [`EXTRA_SURFACES`] so the two never compete for one slot: whichever of
/// [`init`] and [`extra_secret_surfaces`] runs first, both stay in force. Every [`init`] call
/// unions its patterns into the store and recompiles; nothing is ever removed.
static CONFIG_SURFACES: SurfaceStore = SurfaceStore::new();

/// An additive set of secret-surface patterns and their compiled union.
///
/// The process uses one, [`CONFIG_SURFACES`]. It is a type rather than bare statics so tests can
/// run the same loading code against stores of their own, in parallel, without sharing state.
///
/// Config surfaces compile with the `regex` crate, not `fancy-regex`: its matching is linear in
/// the text and cannot fail, whereas a backtracking engine gives up on a long line full of
/// wildcard starting points, and giving up counts as a match (fail closed), which would drop
/// every long command. The boundaries that need lookaround elsewhere are written as consuming
/// classes here, which is equivalent for a yes/no match.
struct SurfaceStore {
    inner: RwLock<ConfigSurfaces>,
    /// Compiles the union. [`compile_union`] everywhere except tests, which substitute one that
    /// fails on demand to prove a failed recompile leaves the previous boundary in force.
    compile: fn(&str) -> Result<Regex, String>,
}

struct ConfigSurfaces {
    /// Every regex fragment loaded so far. A set, so loading the same file twice adds nothing.
    fragments: BTreeSet<String>,
    /// The union of `fragments`, compiled. `None` until a file names at least one surface.
    re: Option<Regex>,
}

fn compile_union(pattern: &str) -> Result<Regex, String> {
    Regex::new(pattern).map_err(|e| e.to_string())
}

impl SurfaceStore {
    const fn new() -> Self {
        Self::with_compiler(compile_union)
    }

    const fn with_compiler(compile: fn(&str) -> Result<Regex, String>) -> Self {
        Self {
            inner: RwLock::new(ConfigSurfaces {
                fragments: BTreeSet::new(),
                re: None,
            }),
            compile,
        }
    }

    /// Does `text` match any loaded surface?
    fn is_match(&self, text: &str) -> bool {
        // A poisoned lock still holds a consistent boundary: `load` replaces the compiled regex
        // only after it built a new one, so the last value written is whole.
        self.inner
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .re
            .as_ref()
            .is_some_and(|re| re.is_match(text))
    }
}

/// Register deployment-specific secret surfaces, e.g. `[r"\.myenv", r"vault-cli\s+unseal"]`.
///
/// Each pattern is a regex fragment; they are joined with `|` and matched case-insensitively.
/// Returns an error if the combined pattern does not compile, and `Ok(false)` if surfaces were
/// already registered (first registration wins — a second caller must not be able to replace a
/// security boundary another already relies on).
///
/// This is independent of [`init`]: surfaces registered here and surfaces from the config file
/// are both in force, whichever was set up first. Prefer the config file for paths; use this for
/// surfaces a path glob cannot express, such as a CLI subcommand.
pub fn extra_secret_surfaces<I, S>(patterns: I) -> Result<bool, Box<fancy_regex::Error>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let joined = patterns
        .into_iter()
        .map(|p| p.as_ref().to_string())
        .collect::<Vec<_>>()
        .join("|");
    if joined.is_empty() {
        return Ok(false);
    }
    let re = FancyRegex::new(&format!("(?i){joined}")).map_err(Box::new)?;
    Ok(EXTRA_SURFACES.set(re).is_ok())
}

/// Environment variable naming the secret-surface file explicitly.
pub const SURFACES_FILE_ENV: &str = "NUVEK_SECRET_SURFACES_FILE";

/// The secret-surface file's path below the configuration directory.
const SURFACES_FILE_RELATIVE: &str = "nuvek/secret-surfaces.toml";

/// Largest secret-surface file [`init`] will read. A surface list is a few lines; anything this
/// size is a mistake, not configuration.
pub const SURFACES_FILE_MAX_BYTES: u64 = 1024 * 1024;

/// Most `*`/`?` wildcards one entry may hold. A real surface needs few; an entry that is mostly
/// wildcards matches almost any command and is far more likely a mistake than a policy.
const MAX_WILDCARDS_PER_ENTRY: usize = 8;

/// Set once [`init`] has succeeded.
static INITIALISED: AtomicBool = AtomicBool::new(false);

/// Set once [`touches_secret_surface`] has warned that [`init`] was never called.
static WARNED_UNINITIALISED: AtomicBool = AtomicBool::new(false);

/// What [`init`] did. Safe to log: it holds paths and counts, never text that was scanned.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct InitReport {
    /// The file [`init`] looked for, or `None` when neither `$NUVEK_SECRET_SURFACES_FILE`,
    /// `$XDG_CONFIG_HOME` nor `$HOME` gave it a location.
    pub searched: Option<PathBuf>,
    /// The file that was read, or `None` when there was none (built-in surfaces only).
    pub source: Option<PathBuf>,
    /// Number of entries in the file's `surfaces` list.
    pub entries: usize,
    /// Number of patterns this call added. `0` when a previous call already loaded them all.
    pub new_patterns: usize,
}

/// Why [`init`] refused the secret-surface configuration.
///
/// Every variant means the operator asked for protection that is not in force. A caller must stop
/// (exit non-zero) rather than carry on with the built-in surfaces alone.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ScrubConfigError {
    /// `$NUVEK_SECRET_SURFACES_FILE` names a file that does not exist. Only the default location
    /// may be absent; an explicit path that is missing is almost always a typo.
    #[error("{SURFACES_FILE_ENV} names {}, which does not exist", path.display())]
    NotFound {
        /// The path the variable named.
        path: PathBuf,
    },
    /// The file exists but could not be read: permissions, a directory, a dangling symlink, or
    /// text that is not UTF-8.
    #[error("reading the secret-surface file {}: {source}", path.display())]
    Read {
        /// The file.
        path: PathBuf,
        /// The underlying I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The file is larger than [`SURFACES_FILE_MAX_BYTES`].
    #[error("the secret-surface file {} is larger than {limit} bytes", path.display())]
    TooLarge {
        /// The file.
        path: PathBuf,
        /// The limit it exceeded.
        limit: u64,
    },
    /// The file is not valid TOML, has a key other than `surfaces`, or `surfaces` is not a list
    /// of strings.
    #[error("parsing the secret-surface file {}: {message}", path.display())]
    Parse {
        /// The file.
        path: PathBuf,
        /// The TOML parser's message, which names the offending key or line.
        message: String,
    },
    /// One entry in `surfaces` is not a usable path or glob.
    #[error("the secret-surface file {} has an invalid entry #{index} {entry:?}: {reason}", path.display())]
    InvalidEntry {
        /// The file.
        path: PathBuf,
        /// Zero-based position in the `surfaces` list.
        index: usize,
        /// The entry as written.
        entry: String,
        /// What is wrong with it.
        reason: String,
    },
    /// The surfaces are valid one by one but their union does not compile (for instance, it
    /// exceeds the regex size limit).
    #[error("compiling the secret surfaces from {}: {message}", path.display())]
    Pattern {
        /// The file.
        path: PathBuf,
        /// The regex compiler's message.
        message: String,
    },
    /// `$NUVEK_SECRET_SURFACES_FILE` is set but unusable: blank, not UTF-8, or not an absolute
    /// path. A blank value is refused rather than read as unset, because it usually means a
    /// variable the operator meant to expand was empty.
    #[error("{SURFACES_FILE_ENV}={value:?} is unusable: {reason}")]
    InvalidLocation {
        /// The variable's value (lossily decoded if it was not UTF-8).
        value: String,
        /// What is wrong with it.
        reason: &'static str,
    },
}

/// The secret-surface file's format. Unknown keys are refused, so a misspelt `surface = [...]`
/// is an error rather than a file that silently protects nothing.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SurfacesFile {
    #[serde(default)]
    surfaces: Vec<String>,
}

/// Where the secret-surface file is, and whether the operator named it explicitly.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SurfacesLocation {
    path: PathBuf,
    explicit: bool,
}

/// Load the deployment's secret surfaces. Call it first in `main`, before any text is scanned.
///
/// The built-in surfaces (see [`touches_secret_surface`]) are always on. This adds the entries of
/// a TOML file, found at the first of:
///
/// 1. `$NUVEK_SECRET_SURFACES_FILE` (a leading `~/` is expanded);
/// 2. `$XDG_CONFIG_HOME/nuvek/secret-surfaces.toml` (only an absolute `$XDG_CONFIG_HOME` counts,
///    as the XDG specification requires);
/// 3. `$HOME/.config/nuvek/secret-surfaces.toml`.
///
/// ```toml
/// surfaces = ["~/.config/example-app/token", "/etc/example-app/*.secret"]
/// ```
///
/// Each entry is a path that starts with `~/` or `/` and names something (at least one letter or
/// digit). `*` matches within one path component, `**` across components (`**/` is zero or more
/// whole directories), and `?` one character, with at most eight wildcards per entry. Wildcards
/// match spaces, so a quoted or backslash-escaped file name is caught, and a literal space in an
/// entry also matches `\ `. Everything else is literal, and matching is case-insensitive. A
/// trailing `/` is optional: a directory entry covers everything under it. An entry matches
/// wherever its path appears in a command, with the same boundaries as the built-in surfaces, and
/// a `~/` entry matches under any spelling of the home directory.
///
/// The file must be a regular file (a symlink to one is fine). A FIFO, a device such as
/// `/dev/null`, or a directory is refused.
///
/// # Errors
///
/// A missing file at the default location (2 or 3) is not an error: only the built-ins apply.
/// Everything else that leaves configured protection out of force is a [`ScrubConfigError`]: a
/// `$NUVEK_SECRET_SURFACES_FILE` that is set but blank or relative, or names a file that does not
/// exist; a file that exists but is not a regular file, cannot be read, is too large, is not
/// valid UTF-8 or TOML, has an unknown key, or has an invalid entry. **The caller must exit
/// non-zero on an error**; there is no silent fallback to the defaults. `$HOME` and
/// `$XDG_CONFIG_HOME` are used whatever their encoding.
///
/// # Additive and idempotent
///
/// Configuration can only add surfaces; nothing removes a built-in. Calling `init` again is safe:
/// it reads the file again and adds whatever is new, so a repeat adds nothing. Surfaces from
/// [`extra_secret_surfaces`] stay in force whether they were registered before or after `init`.
pub fn init() -> Result<InitReport, ScrubConfigError> {
    // Paths are read as `OsString`, not through `env::env_var`: a home or config directory whose
    // name is not UTF-8 is still a directory, and treating it as unset would silently skip the
    // file. The explicit variable is read raw too, because SET-but-blank
    // (`NUVEK_SECRET_SURFACES_FILE=${UNSET_VAR}` in a unit file) is a mistake to report, not a
    // request for the default location.
    let home = path_var("HOME");
    let location = resolve_location(
        std::env::var_os(SURFACES_FILE_ENV),
        path_var("XDG_CONFIG_HOME"),
        home.clone(),
    )?;
    let report = CONFIG_SURFACES.load(location, home.as_deref())?;
    INITIALISED.store(true, Ordering::Release);
    Ok(report)
}

/// A directory from the environment as a path, whatever its encoding. Blank is unset.
fn path_var(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .filter(|v| !is_blank(v))
        .map(PathBuf::from)
}

fn is_blank(v: &std::ffi::OsStr) -> bool {
    v.as_bytes().iter().all(u8::is_ascii_whitespace)
}

/// Has [`init`] succeeded in this process?
///
/// [`touches_secret_surface`] still works without it, on the built-in surfaces alone, and logs a
/// warning once so a binary that forgot to call [`init`] is visible.
#[must_use]
pub fn is_initialised() -> bool {
    INITIALISED.load(Ordering::Acquire)
}

/// Pick the secret-surface file from the explicit variable, `$XDG_CONFIG_HOME` and `$HOME`.
///
/// `explicit` is the raw variable, in any encoding: `None` when unset.
fn resolve_location(
    explicit: Option<std::ffi::OsString>,
    xdg_config_home: Option<PathBuf>,
    home: Option<PathBuf>,
) -> Result<Option<SurfacesLocation>, ScrubConfigError> {
    if let Some(raw) = explicit {
        let invalid = |reason: &'static str| ScrubConfigError::InvalidLocation {
            value: raw.to_string_lossy().into_owned(),
            reason,
        };
        if is_blank(&raw) {
            return Err(invalid("it is set but blank"));
        }
        let path = match raw.as_bytes().strip_prefix(b"~/") {
            Some(rest) => match home.as_deref() {
                Some(h) => h.join(std::ffi::OsStr::from_bytes(rest)),
                None => return Err(invalid("it starts with `~/` but $HOME is unset")),
            },
            None => PathBuf::from(&raw),
        };
        if !path.is_absolute() {
            return Err(invalid("it must be an absolute path (or start with `~/`)"));
        }
        return Ok(Some(SurfacesLocation {
            path,
            explicit: true,
        }));
    }
    let config_dir = xdg_config_home
        .filter(|p| p.is_absolute())
        .or_else(|| home.map(|h| h.join(".config")));
    Ok(config_dir.map(|d| SurfacesLocation {
        path: d.join(SURFACES_FILE_RELATIVE),
        explicit: false,
    }))
}

impl SurfaceStore {
    /// Read, validate and register the file at `location`. `home` gives an absolute entry under
    /// the home directory its `~/` spelling too (only when the home path is UTF-8, as entries
    /// are).
    fn load(
        &self,
        location: Option<SurfacesLocation>,
        home: Option<&Path>,
    ) -> Result<InitReport, ScrubConfigError> {
        let mut report = InitReport {
            searched: location.as_ref().map(|l| l.path.clone()),
            source: None,
            entries: 0,
            new_patterns: 0,
        };
        let Some(location) = location else {
            return Ok(report);
        };
        let Some(text) = read_surfaces_file(&location)? else {
            return Ok(report);
        };
        let home = home.and_then(Path::to_str);
        let path = location.path;
        let file: SurfacesFile = toml::from_str(&text).map_err(|e| ScrubConfigError::Parse {
            path: path.clone(),
            message: e.to_string(),
        })?;

        let mut fragments = Vec::new();
        for (index, entry) in file.surfaces.iter().enumerate() {
            let invalid = |reason: String| ScrubConfigError::InvalidEntry {
                path: path.clone(),
                index,
                entry: entry.clone(),
                reason,
            };
            let entry_fragments = surface_fragments(entry, home).map_err(invalid)?;
            for f in entry_fragments {
                // Compile each fragment alone, so a bad one is reported against its own entry.
                Regex::new(&format!("(?i){f}"))
                    .map_err(|e| invalid(format!("does not compile as a pattern: {e}")))?;
                fragments.push(f);
            }
        }
        report.source = Some(path.clone());
        report.entries = file.surfaces.len();

        // One write lock covers read, union and swap, so concurrent loads cannot lose each
        // other's patterns.
        let mut store = self.inner.write().unwrap_or_else(PoisonError::into_inner);
        let mut union = store.fragments.clone();
        let before = union.len();
        union.extend(fragments);
        let added = union.len() - before;
        if added > 0 {
            let joined = union
                .iter()
                .map(|f| format!("(?:{f})"))
                .collect::<Vec<_>>()
                .join("|");
            let re = (self.compile)(&format!("(?i){joined}")).map_err(|message| {
                ScrubConfigError::Pattern {
                    path: path.clone(),
                    message,
                }
            })?;
            // Both fields are replaced only after the union compiled, so a failure leaves the
            // previous boundary fully in force.
            store.fragments = union;
            store.re = Some(re);
        }
        report.new_patterns = added;
        Ok(report)
    }
}

/// The file's text, or `None` when a default-location file is simply absent.
fn read_surfaces_file(location: &SurfacesLocation) -> Result<Option<String>, ScrubConfigError> {
    let path = &location.path;
    let read_err = |source| ScrubConfigError::Read {
        path: path.clone(),
        source,
    };
    // O_NONBLOCK: opening a FIFO for reading otherwise blocks until a writer appears, which would
    // hang startup. Regular files ignore the flag.
    let opened = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path);
    let file = match opened {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // A dangling symlink also reports NotFound, but something IS there: a link whose
            // target moved is a broken configuration, not an absent one. That holds for the file
            // and for every directory above it (a dotfiles link for `~/.config/nuvek`).
            let dangling = path.ancestors().any(|a| {
                std::fs::symlink_metadata(a).is_ok_and(|m| m.file_type().is_symlink())
                    && std::fs::metadata(a).is_err()
            });
            if dangling {
                return Err(read_err(e));
            }
            if location.explicit {
                return Err(ScrubConfigError::NotFound { path: path.clone() });
            }
            return Ok(None);
        }
        Err(e) => return Err(read_err(e)),
    };
    // Check what was OPENED (fstat on the descriptor), not the path, so nothing can be swapped in
    // between the check and the read. Only a regular file is configuration: a FIFO, a device
    // (a link to /dev/null reads as an empty, "valid" file) or a directory is refused.
    let meta = file.metadata().map_err(read_err)?;
    if !meta.file_type().is_file() {
        return Err(read_err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "not a regular file",
        )));
    }
    let mut bytes = Vec::new();
    file.take(SURFACES_FILE_MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(read_err)?;
    if bytes.len() as u64 > SURFACES_FILE_MAX_BYTES {
        return Err(ScrubConfigError::TooLarge {
            path: path.clone(),
            limit: SURFACES_FILE_MAX_BYTES,
        });
    }
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|e| read_err(std::io::Error::new(std::io::ErrorKind::InvalidData, e)))
}

/// Turn one `surfaces` entry into the regex fragments that detect it in a command.
///
/// A `~/rel` entry yields one fragment for `rel` wherever it appears after a path boundary, which
/// covers `~/rel`, `$HOME/rel`, `${HOME}/rel` and an absolute home path alike. An absolute entry
/// yields its absolute form, plus the home-relative form when it lies under `home`.
fn surface_fragments(entry: &str, home: Option<&str>) -> Result<Vec<String>, String> {
    let e = entry.trim();
    if e.is_empty() {
        return Err("it is empty".into());
    }
    if e.chars().any(char::is_control) {
        return Err("it contains a control character".into());
    }
    let mut fragments = Vec::new();
    if let Some(rel) = e.strip_prefix("~/") {
        fragments.push(path_fragment(rel)?);
    } else if e.starts_with('~') {
        return Err("only `~/` is supported, not `~` alone or `~user`".into());
    } else if e.starts_with('/') {
        let abs = e.trim_end_matches('/');
        fragments.push(path_fragment(abs)?);
        if let Some(h) = home
            .map(|h| h.trim_end_matches('/'))
            .filter(|h| !h.is_empty())
        {
            if let Some(rel) = abs.strip_prefix(h).and_then(|r| r.strip_prefix('/')) {
                fragments.push(path_fragment(rel)?);
            }
        }
    } else {
        return Err("it must be an absolute path or start with `~/`".into());
    }
    Ok(fragments)
}

/// One path or glob as a case-insensitive regex fragment (for the `regex` crate).
///
/// The boundaries match the built-in credential files: the path may not continue a word or a
/// filename on the left (start of text, or a character outside `[\w.-]`), and may not run on
/// into a longer name on the right (end of text, or a character outside `[\w-]`), so `token`
/// matches `token` and `token.bak` but not `tokens`.
///
/// Wildcards match spaces, because file names can contain them and a command may quote
/// (`"db prod.secret"`) or escape (`db\ prod.secret`) them; the cost is that a wildcard can also
/// run across two words of one line, which over-masks and never leaks. A wildcard never crosses
/// a newline, and `*` and `?` never cross a `/`. A literal space in an entry also matches its
/// backslash-escaped form.
fn path_fragment(path: &str) -> Result<String, String> {
    let p = path.trim_end_matches('/');
    // An entry with no letter or digit (`/`, `~/`, `/*`, `~/**`, `~/.`) would match nearly every
    // path in every command, which disables the scanner rather than protecting anything.
    if !p.chars().any(char::is_alphanumeric) {
        return Err("it names no file or directory (it would match every path)".into());
    }
    let mut body = String::new();
    let mut literal = String::new();
    let mut wildcards = 0usize;
    let mut chars = p.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '*' && c != '?' {
            literal.push(c);
            continue;
        }
        push_literal(&mut body, &literal);
        literal.clear();
        wildcards += 1;
        if wildcards > MAX_WILDCARDS_PER_ENTRY {
            return Err(format!(
                "it has more than {MAX_WILDCARDS_PER_ENTRY} wildcards"
            ));
        }
        // One filename character is a raw one or a backslash-escaped one (`\ ` for a space), so
        // `?` and `*` count `db\ prod` the same as a quoted `db prod`. An escaped `/` is still a
        // separator, never part of a name, so it is excluded from the escaped branch too.
        if c == '?' {
            body.push_str(r"(?:\\[^/\n]|[^/\n])");
            continue;
        }
        // A run of stars: one stays within a component, two or more cross components.
        let mut stars = 1;
        while chars.peek() == Some(&'*') {
            chars.next();
            stars += 1;
        }
        if stars == 1 {
            body.push_str(r"(?:\\[^/\n]|[^/\n])*");
        } else if chars.peek() == Some(&'/') {
            // `**/` is zero or more whole directories, so `a/**/b` also matches `a/b`.
            chars.next();
            body.push_str(r"(?:[^\n]*/)?");
        } else {
            body.push_str(r"[^\n]*");
        }
    }
    push_literal(&mut body, &literal);
    Ok(format!(r"(?:^|[^\w.-]){body}(?:$|[^\w-])"))
}

/// Append `literal` to a pattern, escaped, with each space also matching its shell-escaped form
/// (`\ `).
fn push_literal(body: &mut String, literal: &str) {
    for (i, part) in literal.split(' ').enumerate() {
        if i > 0 {
            body.push_str(r"\\? ");
        }
        body.push_str(&regex::escape(part));
    }
}

/// Replace any token-shaped secret with a placeholder. Idempotent, never raises.
#[must_use]
pub fn redact(text: &str) -> String {
    if text.is_empty() {
        return text.to_string();
    }
    SECRET_RE.replace_all(text, PLACEHOLDER).into_owned()
}

/// Configuration-shaped secrets that carry no token prefix, so [`redact`] cannot see them: a value
/// labelled as a secret by its key (`password: x`, `api_key=x`), the same in XML elements
/// (`<ApiKey>…</ApiKey>`, as the *arr apps write) and JSON members (`"token": "…"`), and raw
/// WireGuard keys (43 base64 chars + `=`), and the password in a URL's userinfo
/// (`postgresql://user:pass@host`). Universal shapes, not one deployment's names.
/// Over-masking an `auth: true` is the accepted cost of failing toward masking.
///
/// A key matches when it ENDS in a sensitive word, so compound names are caught (`sessionSecret`,
/// `vapidPrivate`, `db_password`, `x-api-key`). Matching is prefix-only on purpose: allowing a
/// suffix too would mask `passed: 3` and `"author": …`, which are common in logs and manifests.
/// `pass` is the exception: it is also an ordinary word ending (`bypass`, `compass`), so it
/// matches only alone or after a `_`/`-` separator (`db_pass`). Accepted cost: a camelCase
/// `dbPass` is not caught.
static CONFIG_SECRET_RES: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
    let key = r"(?:[A-Za-z0-9_-]*?(?:api[_-]?key|apikey|password|passwd|secret|token|private[_-]?key|private|preshared[_-]?key|auth)|(?:[A-Za-z0-9]*[_-])?pass)";
    let re = |p: String| Regex::new(&p).expect("CONFIG_SECRET_RES are valid compile-time patterns");
    vec![
        (
            re(format!(r#"(?i)("{key}"\s*:\s*)"[^"]*""#)),
            r#"$1"«REDACTED-SECRET»""#,
        ),
        (
            re(format!(r"(?i)(<{key}>)[^<]*(</)")),
            "${1}«REDACTED-SECRET»${2}",
        ),
        (
            re(format!(r#"(?i)(\b{key}\s*[:=]\s*)("[^"]*"|'[^']*'|\S+)"#)),
            "${1}«REDACTED-SECRET»",
        ),
        (re(r"[A-Za-z0-9+/]{43}=".into()), "«REDACTED-SECRET»"),
        // URL userinfo: keep scheme, user and host, mask only the password. The user may be empty
        // (`redis://:pw@host`). The password stops at `/?#`, which cannot appear unencoded in
        // userinfo, so `https://host:8080/path@x` is not mistaken for credentials.
        // CEILING: a raw (unencoded, RFC-invalid) `@` inside a password masks only up to that `@`;
        // taking the last `@` before the first `/` would close it if that shape ever appears.
        (
            re(r"(?i)\b([a-z][a-z0-9+.\-]*://[^\s:/@]*:)[^\s/?#@]+@".into()),
            "${1}«REDACTED-SECRET»@",
        ),
    ]
});

/// [`redact`], plus the configuration-shaped secrets it cannot see — for text that may be a config
/// file, a container environment, logs or a prompt. Idempotent, never raises.
///
/// RESIDUAL (known, accepted): a credential with neither a token prefix nor a secret-named key
/// (a bare high-entropy string on its own) is still invisible here; nothing pattern-based can tell
/// it from any other identifier.
#[must_use]
pub fn redact_config(text: &str) -> String {
    let mut t = redact(text);
    for (rx, rep) in CONFIG_SECRET_RES.iter() {
        t = rx.replace_all(&t, *rep).into_owned();
    }
    t
}

/// True if text contains a token-shaped secret (for quarantine decisions).
#[must_use]
pub fn has_secret(text: &str) -> bool {
    !text.is_empty() && SECRET_RE.is_match(text)
}

/// True if a tool command/input touches a known secret-bearing surface (fail-closed source
/// exclusion — the caller drops the whole segment so it never reaches a model or the store).
/// Checks the built-in universal surfaces, the config file loaded by [`init`], and anything
/// registered via [`extra_secret_surfaces`].
///
/// Without a successful [`init`] it checks the built-in surfaces alone and logs a warning once,
/// because a deployment's configured surfaces are then not in force.
#[must_use]
pub fn touches_secret_surface(text: &str) -> bool {
    if text.is_empty() {
        return false;
    }
    if !INITIALISED.load(Ordering::Acquire) && !WARNED_UNINITIALISED.swap(true, Ordering::AcqRel) {
        tracing::warn!(
            "nuvek_core::scrub::init() was not called: only the built-in secret surfaces apply"
        );
    }
    // FAIL-CLOSED: a fancy-regex evaluation error (e.g. a backtrack-limit overrun) means we
    // cannot prove the text is safe, so treat it as touching a secret surface (drop the segment).
    // `unwrap_or(false)` here would be fail-OPEN and silently leak the segment into the pipeline.
    if SECRET_SURFACE_RE.is_match(text).unwrap_or(true) {
        return true;
    }
    if EXTRA_SURFACES
        .get()
        .is_some_and(|re| re.is_match(text).unwrap_or(true))
    {
        return true;
    }
    CONFIG_SURFACES.is_match(text)
}

/// Write-boundary `gitleaks` scan of LLM-derived text. Returns true iff NO secret found.
/// FAIL-CLOSED: fast-regex hit, gitleaks finding, spawn failure, or a scan that overruns the
/// 30s `GITLEAKS_TIMEOUT` all yield false (quarantine).
#[must_use]
pub fn gitleaks_clean(text: &str) -> bool {
    if has_secret(text) {
        return false;
    }
    let Ok(mut tmp) = tempfile_txt() else {
        return false; // cannot prove clean ⇒ quarantine
    };
    if tmp.file.write_all(text.as_bytes()).is_err() {
        return false;
    }
    let _ = tmp.file.flush();
    let mut cmd = Command::new("gitleaks");
    cmd.args([
        "detect",
        "--no-git",
        "--source",
        &tmp.path,
        "--exit-code",
        "1",
        "--no-banner",
        "--redact",
    ])
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    // 0 = clean; 1 = finding; other/spawn-fail/timeout = error → dirty (fail-closed).
    match command_output_timeout(cmd, GITLEAKS_TIMEOUT) {
        Ok(Some(out)) => out.status.success(),
        Ok(None) | Err(_) => false, // timed out or could not spawn ⇒ quarantine
    }
}

struct TmpTxt {
    file: std::fs::File,
    path: String,
}
impl Drop for TmpTxt {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}
fn tempfile_txt() -> std::io::Result<TmpTxt> {
    let mut path = std::env::temp_dir();
    let unique = format!(
        "nuvek-scrub-{}-{}.txt",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );
    path.push(unique);
    // Mode 0600 (like `mkstemp`): the file may transiently hold LLM-derived text
    // the fast regex MISSED (that's why gitleaks re-scans it), so it must not be world-readable.
    let file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&path)?;
    Ok(TmpTxt {
        file,
        path: path.to_string_lossy().into_owned(),
    })
}

/// Shortest value worth masking — see [`Masker::is_maskable`].
const MIN_MASKABLE_LEN: usize = 8;

/// Characters that can appear inside a base64 run.
///
/// Covers BOTH alphabets — standard (`+`, `/`) and URL-safe (`-`, `_`) — because a credential
/// embedded in a URL or a JWT-adjacent field is commonly URL-safe encoded, and scanning only the
/// standard alphabet would let that form through untouched.
fn is_b64_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '-' | '_')
}

/// Decode a candidate run under either base64 alphabet, with and without padding.
///
/// Returns the decoded text only when it is valid UTF-8 — binary payloads cannot contain a
/// string secret in a form this can match, and treating them as text would be noise.
fn b64_decode_one(run: &str) -> Option<String> {
    use base64::Engine;
    const ENGINES: [&base64::engine::GeneralPurpose; 4] = [
        &base64::engine::general_purpose::STANDARD,
        &base64::engine::general_purpose::STANDARD_NO_PAD,
        &base64::engine::general_purpose::URL_SAFE,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
    ];
    ENGINES
        .iter()
        .find_map(|e| e.decode(run).ok())
        .and_then(|b| String::from_utf8(b).ok())
}

/// Decode a scanned run, tolerating a `key=` prefix fused onto the front of it.
///
/// `=` is a base64 character, so a run scanned out of `token=aGVsbG8=` starts at the `t` of
/// `token` and the whole thing fails to decode — silently letting a secret through in one of the
/// most common shapes there is. An `=` may only ever appear as TRAILING padding in valid base64,
/// so an interior one must be a delimiter: everything after it is retried as its own candidate.
/// Returns the byte offset in `run` where the decodable payload starts, plus its decoded text.
///
/// The offset matters: replacing the WHOLE run would also swallow the `key=` prefix that caused
/// the fusion, corrupting output that was never sensitive. Only the payload is replaced.
fn b64_decode_text(run: &str) -> Option<(usize, String)> {
    if let Some(d) = b64_decode_one(run) {
        return Some((0, d));
    }
    // Later delimiters first: the payload is whatever follows the LAST `key=`.
    let mut candidates: Vec<usize> = Vec::new();
    for (i, c) in run.char_indices() {
        if c == '=' && run[i + 1..].chars().any(|c2| c2 != '=') {
            candidates.push(i + 1);
        }
    }
    candidates.into_iter().rev().find_map(|start| {
        let tail = &run[start..];
        if tail.len() >= 12 {
            b64_decode_one(tail).map(|d| (start, d))
        } else {
            None
        }
    })
}

/// Percent-encode everything outside the RFC 3986 unreserved set.
///
/// Hand-rolled rather than pulling a dependency: the unreserved set is four characters plus
/// alphanumerics and is not going to change, and this keeps the shared spine's dependency
/// surface small.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        let c = b as char;
        if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '~') {
            out.push(c);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Exact-value masking for secrets whose values are KNOWN.
///
/// [`redact`] recognises secrets by SHAPE — it matches token prefixes (`ghp_`, `sk-`, `AIza`, …).
/// That is the only option when the values are unknown, and it has a permanent blind spot:
/// anything without a recognisable signature. A password out of an ansible vault, a generated
/// API key, a database credential — none carry a prefix, so all of them pass straight through.
///
/// When a caller CAN enumerate its secrets, this inverts the problem: it strikes exact values
/// wherever they appear, in any position or encoding, needing no signature. The same approach CI
/// systems use to mask secrets in build logs. Where a caller knows its values, prefer this and
/// keep [`redact`] as the backstop for everything it does not own.
///
/// The variable NAME is preserved in the placeholder (`«REDACTED:db_password»`) so output stays
/// diagnosable: a reader still sees that a line changed and which credential was involved,
/// without the value. Shape-matching cannot offer that.
///
/// Deliberately no `Debug` derive — a `Masker` holds plaintext secrets and must not be printable
/// into a log or trace by accident.
pub struct Masker {
    /// (value, name), sorted by value length DESCENDING so that when one secret contains
    /// another, the longer is replaced first and the remainder of it cannot leak.
    entries: Vec<(String, String)>,
}

impl Masker {
    /// Build from `(value, name)` pairs. Values failing [`Masker::is_maskable`] are dropped.
    ///
    /// Filtering here rather than at the call site means every caller gets the same guarantees:
    /// no caller can accidentally mask `true` and corrupt its own output.
    ///
    /// Each value is expanded into the ENCODINGS it realistically travels in — see
    /// `Masker::encodings`. A secret that reaches a log through a URL, a JSON body or an XML
    /// attribute is just as exposed as a raw one, and matching only the literal form is the
    /// blind spot that makes a value masker feel safe while leaking.
    #[must_use]
    pub fn new<I, V, N>(pairs: I) -> Self
    where
        I: IntoIterator<Item = (V, N)>,
        V: Into<String>,
        N: Into<String>,
    {
        let mut entries: Vec<(String, String)> = Vec::new();
        for (v, n) in pairs {
            let (raw, name): (String, String) = (v.into(), n.into());
            if !Self::is_maskable(&raw) {
                continue;
            }
            // Both the raw and TRIMMED forms are expanded. `is_maskable` judges the trimmed
            // value, so a YAML block scalar (`password: |`) parses to "secret\n", clears the
            // check, and would then be searched for WITH the trailing newline — which never
            // appears in rendered output. Storing only the raw form silently drops such a secret
            // from the mask set: under-masking, in exactly the case this type exists to cover.
            let trimmed = raw.trim();
            let mut sources = vec![raw.clone()];
            if trimmed != raw {
                sources.push(trimmed.to_string());
            }
            for form in sources.iter().flat_map(|s| Self::encodings(s)) {
                // An encoding that collapses to something trivial (or to another secret's exact
                // text) must still clear the same bar, or a variant could corrupt output that the
                // raw value was filtered out of.
                if Self::is_maskable(&form) {
                    entries.push((form, name.clone()));
                }
            }
        }
        // Longest first: when one entry contains another — which encodings routinely produce,
        // since a percent-encoded form embeds much of the raw one — the longer must be replaced
        // first or the remainder of it survives in the output.
        //
        // The secondary sort on the VALUE matters for correctness of the dedup below: `dedup_by`
        // only collapses ADJACENT equal items, so sorting on length alone lets two identical
        // values (two vault vars sharing one password) sit apart with a same-length third
        // between them and survive as duplicates.
        entries.sort_by(|a, b| b.0.len().cmp(&a.0.len()).then_with(|| a.0.cmp(&b.0)));
        entries.dedup_by(|a, b| a.0 == b.0);
        Self { entries }
    }

    /// Every textual form one secret realistically appears in.
    ///
    /// Deliberately enumerated rather than guessed at, and each entry earns its place from a real
    /// path a secret takes through a typical deployment:
    ///
    /// * **raw** — the value itself.
    /// * **XML-escaped** — a credential rendered into an XML config template whose value contains
    ///   `&` or `<` is escaped by the templating engine, so the raw form never appears.
    /// * **JSON-escaped** — an MCP server answers in JSON; a secret containing `"` or `\`
    ///   is escaped on the way out, and the raw form would not match.
    /// * **percent-encoded** — credentials embedded in URLs (`bolt://user:pass@host`, arr API
    ///   URLs) are percent-encoded by any well-behaved client.
    /// * **hex case variants** — hex digests and hex-shaped secrets get upper/lower-cased freely
    ///   by different tools, and case carries no meaning for hex.
    ///
    /// Base64 is NOT handled here, because the encoded form usually contains the secret joined to
    /// something else (`base64("user:pass")` for Basic auth) and cannot be derived from the value
    /// alone. [`Masker::mask`] handles that case by decoding base64-looking runs instead.
    #[must_use]
    fn encodings(value: &str) -> Vec<String> {
        let mut forms = vec![value.to_string()];

        let xml = value
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&apos;");
        forms.push(xml);

        // serde_json renders the escaped body plus surrounding quotes; the quotes are not part of
        // the value, so they are trimmed off.
        if let Ok(j) = serde_json::to_string(value) {
            forms.push(j.trim_matches('"').to_string());
        }

        forms.push(percent_encode(value));

        // Hex-shaped values only: case-folding anything else risks masking unrelated text that
        // merely differs in case from a secret.
        if value.len() >= MIN_MASKABLE_LEN && value.chars().all(|c| c.is_ascii_hexdigit()) {
            forms.push(value.to_ascii_lowercase());
            forms.push(value.to_ascii_uppercase());
        }

        forms.sort();
        forms.dedup();
        forms
    }

    /// Is this value safe to mask?
    ///
    /// Masking indiscriminately is worse than not masking: a secret store entry holding `8080` or
    /// `true` would blank every port and every boolean in the output and make it unreadable. Real
    /// credentials clear this comfortably. The floor is explicit so a deliberately short secret is
    /// a known gap rather than a surprise.
    #[must_use]
    pub fn is_maskable(s: &str) -> bool {
        let t = s.trim();
        if t.chars().count() < MIN_MASKABLE_LEN {
            return false;
        }
        if t.chars().all(|c| c.is_ascii_digit()) {
            return false;
        }
        !matches!(
            t.to_ascii_lowercase().as_str(),
            "true" | "false" | "yes" | "no" | "null" | "none" | "localhost" | "changed"
        )
    }

    /// Number of distinct values masked. Safe to log — a count, never a value.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Replace every occurrence of every known value with `«REDACTED:<name>»`.
    ///
    /// Apply this to a WHOLE stream before any truncation or line filtering, or a value can
    /// survive by being split across a boundary.
    ///
    /// Covers the literal value, its `Masker::encodings`, and base64 blobs that DECODE to
    /// something containing a secret — which is how a credential travels in an
    /// `Authorization: Basic` header, where the encoded text shares no substring with the value.
    #[must_use]
    pub fn mask(&self, text: &str) -> String {
        let mut out = self.mask_literal(text);
        out = self.mask_base64(&out);
        out
    }

    /// Literal + encoded-form replacement.
    fn mask_literal(&self, text: &str) -> String {
        let mut out = text.to_string();
        for (value, name) in &self.entries {
            if out.contains(value.as_str()) {
                out = out.replace(value.as_str(), &format!("«REDACTED:{name}»"));
            }
        }
        out
    }

    /// Replace any base64-looking run whose DECODED bytes contain a known secret.
    ///
    /// `Authorization: Basic dXNlcjpwYXNz` is the motivating case: the encoded text shares no
    /// substring with the password, so literal matching cannot see it. Decoding candidate runs
    /// and checking their contents does.
    ///
    /// Only runs long enough to plausibly carry a secret are considered, and a run is replaced
    /// only when it decodes to valid UTF-8 containing a known value — so ordinary base64 (an
    /// image, a digest, a token that is not ours) is left untouched.
    fn mask_base64(&self, text: &str) -> String {
        if self.entries.is_empty() {
            return text.to_string();
        }
        let mut out = String::with_capacity(text.len());
        let mut rest = text;
        while let Some(start) = rest.find(|c: char| is_b64_char(c)) {
            let (head, tail) = rest.split_at(start);
            out.push_str(head);
            let end = tail.find(|c: char| !is_b64_char(c)).unwrap_or(tail.len());
            let (run, remainder) = tail.split_at(end);
            // Decode ONCE and reuse the result for both the hit test and the name; decoding twice
            // was pure waste on every matching run.
            //
            // A base64 payload carrying a credential is comfortably longer than this floor, which
            // keeps ordinary words out of the decode path entirely.
            let matched = if run.len() >= 12 {
                b64_decode_text(run).and_then(|(start, decoded)| {
                    self.entries
                        .iter()
                        .find(|(v, _)| decoded.contains(v.as_str()))
                        .map(|(_, n)| (start, n.clone()))
                })
            } else {
                None
            };
            match matched {
                // Keep everything before the payload: that is the `key=` prefix the base64
                // scanner fused on, and it is not sensitive.
                Some((start, name)) => {
                    out.push_str(&run[..start]);
                    out.push_str(&format!("«REDACTED-BASE64:{name}»"));
                }
                None => out.push_str(run),
            }
            rest = remainder;
        }
        out.push_str(rest);
        out
    }

    /// [`Masker::mask`] followed by [`redact`] — exact values first, then shape-based backstop.
    #[must_use]
    pub fn mask_and_redact(&self, text: &str) -> String {
        redact(&self.mask(text))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_config_covers_labelled_and_structured_secrets() {
        assert!(!redact_config("password: hunter2").contains("hunter2"));
        assert!(!redact_config("token=abc123xyz").contains("abc123xyz"));
        let xml = redact_config("<ApiKey>0123456789abcdef</ApiKey>");
        assert!(
            !xml.contains("0123456789abcdef") && xml.ends_with("</ApiKey>"),
            "{xml}"
        );
        assert!(!redact_config(r#"{"apiKey": "s3cr3t"}"#).contains("s3cr3t"));
        let wg = "aBcD".repeat(10) + "abc=";
        assert!(!redact_config(&wg).contains(&wg));
        assert!(!redact_config("x ghp_AAAAAAAAAAAAAAAAAAAAAAAA y").contains("ghp_AAAA"));
        assert_eq!(redact_config("ordinary log line"), "ordinary log line");
        // `pass` must not eat an ordinary word that merely starts with it.
        assert_eq!(redact_config("passthrough = true"), "passthrough = true");
        let once = redact_config("password: x and <Token>y</Token>");
        assert_eq!(redact_config(&once), once, "idempotent");
    }

    /// Compound key names: a web app's settings.json leaked `sessionSecret` and `vapidPrivate` because
    /// only keys EQUAL to a sensitive word matched. A key ending in one now matches too.
    #[test]
    fn redact_config_masks_compound_secret_keys() {
        let json = r#"{"clientId": "cd81-id", "sessionSecret": "fe5e-sess", "vapidPrivate": "-rxo-vap", "vapidPublic": "BOP-pub", "client_secret": "cs-val", "dbPassword": "dbp-val", "name": "ExampleApp"}"#; // gitleaks:allow
        let out = redact_config(json);
        for leaked in ["fe5e-sess", "-rxo-vap", "cs-val", "dbp-val"] {
            assert!(!out.contains(leaked), "{leaked} survived: {out}");
        }
        // Identifiers and public halves are not secrets and must survive.
        for kept in ["cd81-id", "BOP-pub", "ExampleApp"] {
            assert!(out.contains(kept), "{kept} was masked: {out}");
        }
        assert!(!redact_config("sessionSecret=abc").contains("abc"));
        assert!(!redact_config("<VapidPrivate>k</VapidPrivate>").contains(">k<"));
        // The removed explicit alternatives are subsumed by prefix + word.
        assert!(!redact_config("access_token=at-val").contains("at-val"));
        assert!(!redact_config("refresh-token: rt-val").contains("rt-val"));
        assert!(!redact_config("db_pass=dp-val").contains("dp-val"));
        // Prefix-only: a sensitive word followed by more letters is not a secret key.
        assert_eq!(redact_config("tests passed: 3"), "tests passed: 3");
        assert_eq!(redact_config(r#"{"author": "jd"}"#), r#"{"author": "jd"}"#);
        // `pass` as an ordinary word ending is not a key.
        assert_eq!(redact_config("bypass: true"), "bypass: true");
        assert_eq!(redact_config("compass=north"), "compass=north");
        assert_eq!(redact_config(&out), out, "idempotent on compound keys");
    }

    #[test]
    fn redact_config_masks_url_userinfo_password() {
        let url = "postgresql://litellm:9f8e7d6c5b4a@postgres:5432/litellm"; // gitleaks:allow
        let out = redact_config(url);
        assert!(!out.contains("9f8e7d6c5b4a"), "{out}");
        assert_eq!(
            out,
            "postgresql://litellm:«REDACTED-SECRET»@postgres:5432/litellm"
        );
        assert_eq!(redact_config(&out), out, "idempotent");
        // A URL without userinfo, and a host:port, are left alone.
        assert_eq!(
            redact_config("http://litellm:4000/v1"),
            "http://litellm:4000/v1"
        );
        assert_eq!(redact_config("bolt://nas:7687"), "bolt://nas:7687");
        // host:port followed by an `@` in the path or query is not userinfo.
        assert_eq!(redact_config("http://h:80/a@b"), "http://h:80/a@b");
        assert_eq!(
            redact_config("http://litellm:4000/v1?email=a@b"),
            "http://litellm:4000/v1?email=a@b"
        );
        // Empty username (the standard Redis form) is still masked.
        let redis = redact_config("redis://:s3cretpw@redis:6379/0"); // gitleaks:allow
        assert_eq!(redis, "redis://:«REDACTED-SECRET»@redis:6379/0");
    }

    #[test]
    fn redacts_github_and_openai_tokens() {
        let s = "token ghp_abcdefghijklmnopqrstuvwxyz0123 and sk-abcdefghijklmnopqrstuvwx here";
        let out = redact(s);
        assert!(!out.contains("ghp_abcdefghij"));
        assert!(!out.contains("sk-abcdefghij"));
        assert!(out.contains(PLACEHOLDER));
        assert!(has_secret(s));
    }

    // Guards every alternative in SECRET_RE — the concat! seams are where a mangled
    // continuation (the original bug) silently dropped later branches.
    #[test]
    fn redacts_all_secret_families() {
        // These are fabricated / documented-example fixtures that exist to prove the scrubber
        // DETECTS each pattern; `gitleaks:allow` tells the pre-commit scanner they're not real.
        let cases = [
            "AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ012345", // Google API key (gitleaks:allow test fixture)
            "AKIAIOSFODNN7EXAMPLE", // AWS access key id (gitleaks:allow test fixture)
            "xoxb-123456789012-abcdefghijklmnop", // Slack bot token (gitleaks:allow test fixture)
            "eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0NTY.SflKxwRJSMeKKF", // JWT (gitleaks:allow test fixture)
            "-----BEGIN RSA PRIVATE KEY-----", // PEM header (gitleaks:allow test fixture)
            "https://discord.com/api/webhooks/1234567890/AbCdEfGhIjKlMnOpQrStUvWxYz_0123-xyz", // Discord webhook (gitleaks:allow test fixture)
        ];
        for c in cases {
            assert!(has_secret(c), "should detect secret in: {c}");
            assert!(!redact(c).contains(c), "should redact: {c}");
        }
    }

    #[test]
    fn redacts_url_safe_sk_keys_but_not_hyphenated_words() {
        let key = "sk-X2ab_cd-EfGhIjKlMnOpQr_s"; // gitleaks:allow — invented fixture
        let s = format!("OPENAI_API_KEY={key} done");
        assert!(has_secret(&s));
        let out = redact(&s);
        assert!(
            !out.contains("_cd-EfGh") && !out.contains("Qr_s"),
            "tail leaked: {out}"
        );
        // `sk-` glued to a word char (no `\b`) must still be caught by the alnum branch.
        let glued = "OPENAI_sk-abcdefghijklmnopqrstuvwx"; // gitleaks:allow — invented fixture
        assert!(has_secret(glued));
        assert!(!redact(glued).contains("abcdefghij"));
        let prose = "see the disk-usage-report-for-the-nas-array and risk-assessment-notes";
        assert!(!has_secret(prose));
        assert_eq!(redact(prose), prose);
    }

    #[test]
    fn redact_is_idempotent_and_keeps_rfc1918() {
        let s = "connect to 10.20.30.40:8000 with AIzaSyABCDEFGHIJKLMNOPQRSTUVWXYZ012345";
        let first = redact(s);
        let second = redact(&first);
        assert_eq!(first, second);
        assert!(first.contains("10.20.30.40")); // internal IP preserved on purpose
    }

    #[test]
    fn ordinary_text_is_untouched() {
        let s = "just some normal code: let x = compute(skip_list);";
        assert_eq!(redact(s), s);
        assert!(!has_secret(s));
    }

    /// Only surfaces that mean the same thing on any machine are built in.
    #[test]
    fn detects_universal_secret_surfaces() {
        assert!(touches_secret_surface(
            "scp server:/etc/ssl/private/star.key ."
        ));
        assert!(touches_secret_surface("openssl rsa -in cert.pem"));
        assert!(touches_secret_surface("ssh-keygen -t ed25519"));
        assert!(touches_secret_surface("git config user.token abc"));
        assert!(!touches_secret_surface("edit main.rs and keyboard.py")); // 'key' mid-word, no .key file
        assert!(!touches_secret_surface("plain sentence"));
    }

    /// The well-known credential files of common tools are built in, under any home spelling.
    #[test]
    fn common_credential_files_are_built_in_surfaces() {
        for hit in [
            "cat ~/.ssh/id_ed25519",
            "ls -la ~/.ssh",
            "scp $HOME/.ssh/config host:",
            "cat .env",
            "source ./.env.local",
            "cp /srv/app/.env.production /tmp/",
            "cat ~/.netrc",
            "cat ~/.aws/credentials",
            "ls ~/.config/gcloud/",
            "cat ~/.config/gcloud/application_default_credentials.json",
            "jq . ~/.docker/config.json",
            "cat ~/.kube/config",
            "KUBECONFIG=~/.kube/config.prod kubectl get pods",
            "openssl x509 -in server.PEM",
        ] {
            assert!(touches_secret_surface(hit), "should be a surface: {hit}");
        }
        for miss in [
            "direnv allow .envrc",
            "console.log(process.env.HOME)",
            "std::env::var(\"X\")",
            "ssh deploy@host uptime",
            "kubectl get pods",
            "docker compose up",
            "cargo build --features env",
            "edit ~/.config/example-app/settings.toml",
        ] {
            assert!(
                !touches_secret_surface(miss),
                "should not be a surface: {miss}"
            );
        }
    }

    /// Each further credential file, with a near miss that must stay clear of it.
    #[test]
    fn more_credential_files_are_built_in_surfaces() {
        for (hit, miss) in [
            ("cat ~/.git-credentials", "git credential-cache exit"),
            ("cat ~/.pgpass", "psql --no-password -h db.example.test"),
            ("cat ~/.cargo/credentials", "cat ~/.cargo/config.toml"),
            ("cat ~/.cargo/credentials.toml", "cargo login --help"),
            ("cat ~/.config/gh/hosts.yml", "cat ~/.config/gh/config.yml"),
            ("cat $HOME/.vault-token", "vault token lookup"),
            ("ls ~/.gnupg/private-keys-v1.d", "gpg --list-keys"),
            ("tar czf b.tgz ~/.gnupg", "cat ~/.gnupg-notes.txt"),
            (
                "docker compose --env-file prod.env up",
                "console.log(process.env)",
            ),
            (
                "cp /srv/stack/stack.env /tmp/",
                "const e = import.meta.env;",
            ),
            ("source 'app.env'", "std::env::var(\"APP\")"),
            ("cat ~/deploy/prod.env", "direnv allow .envrc"),
            ("cat prod.env", "let v = process.env[key];"),
            ("cat prod.env", "Deno.env.get(\"X\")"),
            ("cat prod.env", "my.environment.yml"),
        ] {
            assert!(touches_secret_surface(hit), "should be a surface: {hit}");
            assert!(
                !touches_secret_surface(miss),
                "should not be a surface: {miss}"
            );
        }
    }

    /// The `<name>.env` branch scans one long token in linear time: a long word must not run into
    /// the backtrack limit, which would fail closed and drop the whole segment.
    #[test]
    fn a_long_token_does_not_trip_the_backtrack_limit() {
        let long = "a".repeat(50_000);
        assert!(!touches_secret_surface(&format!("echo {long}")));
        assert!(touches_secret_surface(&format!("cat {long}.env")));
    }

    /// A fresh directory under the system temp dir. Never `$HOME`.
    fn scratch_dir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "nuvek-scrub-test-{tag}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("create scratch dir");
        dir
    }

    fn write_file(dir: &Path, name: &str, contents: &str) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, contents).expect("write fixture");
        p
    }

    /// Load `file` (named explicitly, as `$NUVEK_SECRET_SURFACES_FILE` would) into `store`.
    ///
    /// Tests that do not need the process-wide state use a store of their own, so they can run
    /// in parallel without seeing each other's patterns.
    fn load_into(
        store: &SurfaceStore,
        file: &Path,
        home: Option<&Path>,
    ) -> Result<InitReport, ScrubConfigError> {
        store.load(
            Some(SurfacesLocation {
                path: file.to_path_buf(),
                explicit: true,
            }),
            home,
        )
    }

    fn load_default_at(
        store: &SurfaceStore,
        config_dir: &Path,
    ) -> Result<InitReport, ScrubConfigError> {
        let location = resolve_location(None, Some(config_dir.to_path_buf()), None)
            .expect("a default location");
        store.load(location, None)
    }

    /// Run `body` in a fresh process, for tests about process-wide state ([`init`],
    /// [`is_initialised`], the [`extra_secret_surfaces`] slot, the environment), which would race
    /// with every other test in-process. See [`crate::test_isolation::isolated`].
    fn isolated(name: &str, body: impl FnOnce()) {
        crate::test_isolation::isolated(&format!("scrub::tests::{name}"), body);
    }

    /// In an [`isolated`] child: point `$HOME` at `home` and name `file` explicitly, then [`init`].
    fn init_in_child(file: &Path, home: &Path) -> Result<InitReport, ScrubConfigError> {
        std::env::set_var("HOME", home);
        std::env::set_var(SURFACES_FILE_ENV, file);
        init()
    }

    /// Does `entry` (compiled on its own, outside the process-wide store) match `text`?
    fn entry_matches(entry: &str, home: Option<&str>, text: &str) -> bool {
        let joined = surface_fragments(entry, home)
            .expect("valid entry")
            .iter()
            .map(|f| format!("(?:{f})"))
            .collect::<Vec<_>>()
            .join("|");
        Regex::new(&format!("(?i){joined}"))
            .expect("compiles")
            .is_match(text)
    }

    /// `extra_secret_surfaces` FIRST, then `init`: both stay in force, never a silent drop.
    /// Also proves the slot is one-shot and that nothing is a surface until registered.
    #[test]
    fn isolated_extra_then_init_keeps_both() {
        isolated("isolated_extra_then_init_keeps_both", || {
            assert!(!touches_secret_surface("cat ~/.example-deploy-env"));
            assert!(
                extra_secret_surfaces([r"\.example-deploy-env", r"vault-cli\s+unseal"])
                    .expect("valid"),
                "first registration must win"
            );
            assert!(touches_secret_surface("cat ~/.example-deploy-env"));
            assert!(touches_secret_surface("vault-cli unseal --key 1"));
            assert!(touches_secret_surface("ssh-keygen -t ed25519"));
            assert!(!touches_secret_surface("plain sentence"));
            // A later caller cannot replace a boundary already in force.
            assert!(
                !extra_secret_surfaces([r"something-else"]).expect("valid"),
                "a second registration must not take effect"
            );
            assert!(touches_secret_surface("cat ~/.example-deploy-env"));

            let text = "cat ~/.config/example-union/token";
            assert!(!touches_secret_surface(text));
            let dir = scratch_dir("extra-then-init");
            let file = write_file(
                &dir,
                "surfaces.toml",
                "surfaces = [\"~/.config/example-union/token\"]\n",
            );
            let report = init_in_child(&file, &dir).expect("valid config");
            assert_eq!(report.source.as_deref(), Some(file.as_path()));
            assert!(touches_secret_surface(text), "config surface missing");
            assert!(
                touches_secret_surface("cat ~/.example-deploy-env"),
                "init dropped the extra_secret_surfaces registration"
            );
            assert!(touches_secret_surface("vault-cli unseal"));
            assert!(touches_secret_surface("cat ~/.ssh/id_rsa"));
            let _ = std::fs::remove_dir_all(&dir);
        });
    }

    /// `init` FIRST, then `extra_secret_surfaces`: the registration still takes effect and the
    /// configured surfaces survive it.
    #[test]
    fn isolated_init_then_extra_keeps_both() {
        isolated("isolated_init_then_extra_keeps_both", || {
            let dir = scratch_dir("init-then-extra");
            let file = write_file(
                &dir,
                "surfaces.toml",
                "surfaces = [\"~/.config/example-order/token\"]\n",
            );
            init_in_child(&file, &dir).expect("valid config");
            assert!(touches_secret_surface("cat ~/.config/example-order/token"));
            assert!(!touches_secret_surface("vault-cli unseal"));
            assert!(
                extra_secret_surfaces([r"vault-cli\s+unseal"]).expect("valid"),
                "registration after init must still take effect"
            );
            assert!(touches_secret_surface("vault-cli unseal"));
            assert!(
                touches_secret_surface("cat ~/.config/example-order/token"),
                "extra_secret_surfaces dropped the configured surfaces"
            );
            let _ = std::fs::remove_dir_all(&dir);
        });
    }

    /// Mirrors the registration test for the config file, through the real entry point and the
    /// environment variable: a deployment's env file is not a surface until the file read by
    /// `init` names it, and is one afterwards, alongside every built-in.
    #[test]
    fn isolated_init_config_names_a_deployment_env_file() {
        isolated("isolated_init_config_names_a_deployment_env_file", || {
            let text = "source ~/.example_deploy_env && run";
            assert!(
                !touches_secret_surface(text),
                "unprotected before init names it"
            );
            let dir = scratch_dir("mirror");
            let file = write_file(
                &dir,
                "surfaces.toml",
                "# a deployment's env file\nsurfaces = [\"~/.example_deploy_env\"]\n",
            );
            let report = init_in_child(&file, &dir).expect("valid config");
            assert_eq!(report.entries, 1);
            assert_eq!(report.new_patterns, 1);
            assert!(touches_secret_surface(text), "protected after init");
            // The same file under every spelling of the home directory.
            assert!(touches_secret_surface("cat $HOME/.example_deploy_env"));
            assert!(touches_secret_surface("cat ${HOME}/.example_deploy_env"));
            assert!(touches_secret_surface(
                "cat /users/someone/.example_deploy_env"
            ));
            // But not a different file that merely shares a prefix.
            assert!(!touches_secret_surface("cat ~/.example_deploy_envelope"));
            // Config only adds: every built-in is still there.
            for builtin in [
                "cat ~/.ssh/id_ed25519",
                "cat .env",
                "cat ~/.netrc",
                "cat ~/.aws/credentials",
                "cat ~/.kube/config",
                "openssl rsa -in a.pem",
                "ssh-keygen",
            ] {
                assert!(touches_secret_surface(builtin), "built-in lost: {builtin}");
            }
            let _ = std::fs::remove_dir_all(&dir);
        });
    }

    /// `is_initialised` is false in a fresh process (where scanning still works on the
    /// built-ins), stays false after a failed `init`, and turns true after a successful one.
    #[test]
    fn isolated_is_initialised_tracks_init() {
        isolated("isolated_is_initialised_tracks_init", || {
            assert!(!is_initialised());
            assert!(touches_secret_surface("cat ~/.ssh/id_rsa"));
            let dir = scratch_dir("initialised");
            let bad = write_file(&dir, "bad.toml", "surfaces = [\"relative\"]\n");
            assert!(init_in_child(&bad, &dir).is_err());
            assert!(!is_initialised(), "a failed init must not count");
            let good = write_file(&dir, "good.toml", "surfaces = []\n");
            init_in_child(&good, &dir).expect("valid");
            assert!(is_initialised());
            let _ = std::fs::remove_dir_all(&dir);
        });
    }

    /// Config only adds: what a file names is in force, with the right boundaries.
    #[test]
    fn a_loaded_file_widens_the_store() {
        let store = SurfaceStore::new();
        let dir = scratch_dir("additive");
        let file = write_file(
            &dir,
            "surfaces.toml",
            "surfaces = [\"~/.config/example-app/token\", \"/etc/example-additive/\"]\n",
        );
        assert!(!store.is_match("cat ~/.config/example-app/token"));
        load_into(&store, &file, None).expect("valid config");
        assert!(store.is_match("cat ~/.config/example-app/token"));
        assert!(store.is_match("cat ~/.config/example-app/token.bak"));
        assert!(!store.is_match("cat ~/.config/example-app/tokens"));
        assert!(store.is_match("ls /etc/example-additive"));
        assert!(store.is_match("cat /etc/example-additive/db.conf"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Loading twice is safe: the second load re-reads the file and adds nothing new.
    #[test]
    fn loading_is_idempotent() {
        let store = SurfaceStore::new();
        let dir = scratch_dir("idem");
        let file = write_file(
            &dir,
            "surfaces.toml",
            "surfaces = [\"~/.config/example-idem/token\"]\n",
        );
        let first = load_into(&store, &file, None).expect("first");
        assert_eq!(first.new_patterns, 1);
        let second = load_into(&store, &file, None).expect("second");
        assert_eq!(second.new_patterns, 0, "a repeat must add nothing");
        assert_eq!(second.entries, 1);
        assert!(store.is_match("cat ~/.config/example-idem/token"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A load rejected for a bad entry leaves what was loaded before fully in force.
    #[test]
    fn a_failed_load_keeps_the_previous_surfaces() {
        let store = SurfaceStore::new();
        let dir = scratch_dir("keep");
        let good = write_file(
            &dir,
            "good.toml",
            "surfaces = [\"~/.config/example-keep/token\"]\n",
        );
        load_into(&store, &good, None).expect("valid");
        let bad = write_file(&dir, "bad.toml", "surfaces = [\"relative/path\"]\n");
        assert!(load_into(&store, &bad, None).is_err());
        assert!(store.is_match("cat ~/.config/example-keep/token"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The accumulated UNION failing to compile (each entry was fine alone) is a `Pattern` error,
    /// and neither the compiled boundary nor the fragment set changes.
    #[test]
    fn a_union_that_fails_to_compile_leaves_the_store_unchanged() {
        // No hyphens in the marker: entries are regex-escaped, which escapes `-`.
        fn fail_on_marker(pattern: &str) -> Result<Regex, String> {
            if pattern.contains("exampleunionbreaker") {
                Err("union too large".into())
            } else {
                compile_union(pattern)
            }
        }
        let store = SurfaceStore::with_compiler(fail_on_marker);
        let dir = scratch_dir("union-fail");
        let good = write_file(
            &dir,
            "good.toml",
            "surfaces = [\"~/.config/example-first/token\"]\n",
        );
        load_into(&store, &good, None).expect("valid");
        let breaking = write_file(
            &dir,
            "breaking.toml",
            "surfaces = [\"~/.config/exampleunionbreaker/token\"]\n",
        );
        let err = load_into(&store, &breaking, None).expect_err("union compile fails");
        assert!(
            matches!(err, ScrubConfigError::Pattern { .. }),
            "got {err:?}"
        );
        assert!(store.is_match("cat ~/.config/example-first/token"));
        assert!(!store.is_match("cat ~/.config/exampleunionbreaker/token"));
        let fragments = store
            .inner
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .fragments
            .len();
        assert_eq!(fragments, 1, "the failed load must not add its fragments");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Loads racing on one store lose nothing: each one's patterns are all in force afterwards.
    #[test]
    fn concurrent_loads_are_all_kept() {
        let store = SurfaceStore::new();
        let dir = scratch_dir("concurrent");
        let files: Vec<PathBuf> = (0..8)
            .map(|i| {
                write_file(
                    &dir,
                    &format!("s{i}.toml"),
                    &format!("surfaces = [\"~/.config/example-race-{i}/token\"]\n"),
                )
            })
            .collect();
        // Every thread parses its file, then waits, so all eight reach the store at once.
        let barrier = std::sync::Barrier::new(files.len());
        std::thread::scope(|s| {
            for f in &files {
                let (store, barrier) = (&store, &barrier);
                s.spawn(move || {
                    barrier.wait();
                    load_into(store, f, None).expect("valid")
                });
            }
        });
        for i in 0..8 {
            assert!(
                store.is_match(&format!("cat ~/.config/example-race-{i}/token")),
                "load {i} was lost"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// No file at the default location: built-ins only, and that is Ok.
    #[test]
    fn a_missing_default_file_is_ok() {
        let dir = scratch_dir("missing-default");
        let report =
            load_default_at(&SurfaceStore::new(), &dir).expect("missing default file is fine");
        assert_eq!(
            report.searched,
            Some(dir.join("nuvek/secret-surfaces.toml"))
        );
        assert_eq!(report.source, None);
        assert_eq!(report.entries, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A file the operator named explicitly must exist: a typo must never silently mean
    /// "built-ins only".
    #[test]
    fn a_missing_explicit_file_is_an_error() {
        let dir = scratch_dir("missing-explicit");
        let err =
            load_into(&SurfaceStore::new(), &dir.join("absent.toml"), None).expect_err("must fail");
        assert!(
            matches!(err, ScrubConfigError::NotFound { .. }),
            "got {err:?}"
        );
        assert!(err.to_string().contains(SURFACES_FILE_ENV));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Set but blank (an unexpanded variable in a unit file) or relative is refused, never read
    /// as "use the default location".
    #[test]
    fn a_blank_or_relative_explicit_variable_is_an_error() {
        for value in ["", "   ", "relative/surfaces.toml"] {
            let err = resolve_location(
                Some(value.into()),
                None,
                Some(PathBuf::from("/users/someone")),
            )
            .expect_err("must fail");
            assert!(
                matches!(err, ScrubConfigError::InvalidLocation { .. }),
                "{value:?}: got {err:?}"
            );
        }
    }

    /// The same, through the real entry point and environment variable.
    #[test]
    fn isolated_a_blank_explicit_variable_fails_init() {
        isolated("isolated_a_blank_explicit_variable_fails_init", || {
            std::env::set_var(SURFACES_FILE_ENV, "  ");
            let err = init().expect_err("blank must fail");
            assert!(
                matches!(err, ScrubConfigError::InvalidLocation { .. }),
                "got {err:?}"
            );
        });
    }

    #[test]
    fn malformed_toml_is_an_error() {
        let store = SurfaceStore::new();
        let dir = scratch_dir("malformed");
        let file = write_file(&dir, "surfaces.toml", "surfaces = [\"~/.unclosed\"\n");
        let err = load_into(&store, &file, None).expect_err("must fail");
        assert!(matches!(err, ScrubConfigError::Parse { .. }), "got {err:?}");
        // A list of non-strings is a type error, also refused.
        let file = write_file(&dir, "numbers.toml", "surfaces = [1, 2]\n");
        let err = load_into(&store, &file, None).expect_err("must fail");
        assert!(matches!(err, ScrubConfigError::Parse { .. }), "got {err:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Bytes that are not UTF-8 are a read error, not an empty or partial file.
    #[test]
    fn non_utf8_file_contents_are_an_error() {
        let dir = scratch_dir("non-utf8");
        let file = dir.join("surfaces.toml");
        std::fs::write(&file, b"surfaces = [\"~/.config/x\xff\"]\n").expect("write");
        let err = load_into(&SurfaceStore::new(), &file, None).expect_err("must fail");
        assert!(matches!(err, ScrubConfigError::Read { .. }), "got {err:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A misspelt key must not be read as a file that protects nothing.
    #[test]
    fn an_unknown_key_is_an_error() {
        let dir = scratch_dir("unknown-key");
        let file = write_file(
            &dir,
            "surfaces.toml",
            "surface = [\"~/.config/example-typo/token\"]\n",
        );
        let store = SurfaceStore::new();
        let err = load_into(&store, &file, None).expect_err("must fail");
        assert!(matches!(err, ScrubConfigError::Parse { .. }), "got {err:?}");
        assert!(err.to_string().contains("unknown field"), "{err}");
        let file = write_file(&dir, "env.toml", "surfaces = []\nenv_vars = [\"X\"]\n");
        assert!(load_into(&store, &file, None).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Every unusable entry is refused, and the error points at the entry.
    #[test]
    fn invalid_entries_are_errors() {
        let dir = scratch_dir("invalid");
        for (i, bad) in [
            r#""""#,
            r#""   ""#,
            r#""relative/path""#,
            r#""~""#,
            r#""~alice/.netrc""#,
            r#""/""#,
            r#""~/""#,
            r#""/*""#,
            r#""~/**""#,
            r#""~/.""#,
            r#""~/.*""#,
            r#""/etc/x\nfoo""#,
            r#""/a?/b?/c?/d?/e?/f?/g?/h?/i?""#,
        ]
        .iter()
        .enumerate()
        {
            let file = write_file(
                &dir,
                &format!("bad{i}.toml"),
                &format!("surfaces = [\"~/.config/example-ok/a\", {bad}]\n"),
            );
            match load_into(&SurfaceStore::new(), &file, None) {
                Err(ScrubConfigError::InvalidEntry { index, .. }) => {
                    assert_eq!(index, 1, "wrong index for {bad}");
                }
                other => panic!("{bad} should be an invalid entry, got {other:?}"),
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Exists but cannot be read: a directory, or a symlink whose target is gone.
    #[test]
    fn an_unreadable_file_is_an_error() {
        let store = SurfaceStore::new();
        let dir = scratch_dir("unreadable");
        let as_dir = dir.join("surfaces.toml");
        std::fs::create_dir_all(&as_dir).expect("mkdir");
        let err = load_into(&store, &as_dir, None).expect_err("a directory is not a file");
        assert!(matches!(err, ScrubConfigError::Read { .. }), "got {err:?}");

        // At the DEFAULT location too: only a truly absent file is "defaults only".
        let config = dir.join("xdg");
        std::fs::create_dir_all(config.join("nuvek")).expect("mkdir");
        std::os::unix::fs::symlink(
            dir.join("moved-away.toml"),
            config.join("nuvek/secret-surfaces.toml"),
        )
        .expect("symlink");
        let err = load_default_at(&store, &config).expect_err("dangling symlink");
        assert!(matches!(err, ScrubConfigError::Read { .. }), "got {err:?}");

        // A dangling link for the directory above the file is just as broken.
        let config2 = dir.join("xdg2");
        std::fs::create_dir_all(&config2).expect("mkdir");
        std::os::unix::fs::symlink(dir.join("moved-dotfiles"), config2.join("nuvek"))
            .expect("symlink");
        let err = load_default_at(&store, &config2).expect_err("dangling parent symlink");
        assert!(matches!(err, ScrubConfigError::Read { .. }), "got {err:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A FIFO at the config path would block a plain open until a writer appeared, hanging
    /// startup. It is refused at once. Run in its own process under a deadline, so a regression
    /// fails the test instead of hanging the suite.
    #[test]
    fn isolated_a_fifo_is_refused_without_blocking() {
        isolated("isolated_a_fifo_is_refused_without_blocking", || {
            let dir = scratch_dir("fifo");
            let fifo = dir.join("surfaces.toml");
            let made = Command::new("mkfifo")
                .arg(&fifo)
                .status()
                .expect("run mkfifo");
            assert!(made.success(), "mkfifo failed");
            let err = load_into(&SurfaceStore::new(), &fifo, None).expect_err("a FIFO is refused");
            assert!(matches!(err, ScrubConfigError::Read { .. }), "got {err:?}");
            let _ = std::fs::remove_dir_all(&dir);
        });
    }

    /// A link to `/dev/null` reads as an empty, valid file that protects nothing. It is refused,
    /// because what was opened is a device, not a regular file.
    #[test]
    fn isolated_a_link_to_dev_null_is_refused() {
        isolated("isolated_a_link_to_dev_null_is_refused", || {
            let dir = scratch_dir("devnull");
            let link = dir.join("surfaces.toml");
            std::os::unix::fs::symlink("/dev/null", &link).expect("symlink");
            let err =
                load_into(&SurfaceStore::new(), &link, None).expect_err("a device is refused");
            assert!(matches!(err, ScrubConfigError::Read { .. }), "got {err:?}");
            // A symlink to a REGULAR file is still fine.
            let real = write_file(&dir, "real.toml", "surfaces = []\n");
            let ok_link = dir.join("ok.toml");
            std::os::unix::fs::symlink(&real, &ok_link).expect("symlink");
            load_into(&SurfaceStore::new(), &ok_link, None).expect("link to a regular file");
            let _ = std::fs::remove_dir_all(&dir);
        });
    }

    #[test]
    fn an_oversized_file_is_an_error() {
        let dir = scratch_dir("large");
        let mut body = String::from("# padding\n");
        while (body.len() as u64) <= SURFACES_FILE_MAX_BYTES {
            body.push_str("# ................................................................\n");
        }
        let file = write_file(&dir, "surfaces.toml", &body);
        let err = load_into(&SurfaceStore::new(), &file, None).expect_err("must fail");
        assert!(
            matches!(err, ScrubConfigError::TooLarge { .. }),
            "got {err:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_empty_file_is_ok_and_adds_nothing() {
        let dir = scratch_dir("empty");
        let file = write_file(&dir, "surfaces.toml", "");
        let report = load_into(&SurfaceStore::new(), &file, None).expect("empty is valid");
        assert_eq!(report.entries, 0);
        assert_eq!(report.new_patterns, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A home or config directory whose name is not UTF-8 is still used: the default file is
    /// found and read, never silently skipped.
    #[test]
    fn non_utf8_home_and_config_dirs_are_used() {
        let raw = |b: &[u8]| PathBuf::from(std::ffi::OsStr::from_bytes(b));
        let home = raw(b"/users/caf\xe9");
        assert_eq!(
            resolve_location(None, None, Some(home.clone())).expect("resolvable"),
            Some(SurfacesLocation {
                path: home.join(".config/nuvek/secret-surfaces.toml"),
                explicit: false,
            })
        );
        let xdg = raw(b"/srv/conf\xff");
        assert_eq!(
            resolve_location(None, Some(xdg.clone()), Some(home.clone())).expect("resolvable"),
            Some(SurfacesLocation {
                path: xdg.join("nuvek/secret-surfaces.toml"),
                explicit: false,
            })
        );
        // `~/` in the explicit variable expands against a non-UTF-8 home, too.
        assert_eq!(
            resolve_location(Some("~/s.toml".into()), None, Some(home.clone()))
                .expect("resolvable"),
            Some(SurfacesLocation {
                path: home.join("s.toml"),
                explicit: true,
            })
        );

        // And a real file under a non-UTF-8 directory name is loaded.
        let dir = scratch_dir("non-utf8-dir");
        let mut name = dir.clone().into_os_string();
        name.push(std::ffi::OsStr::from_bytes(b"/conf\xff"));
        let config = PathBuf::from(name);
        std::fs::create_dir_all(config.join("nuvek")).expect("mkdir");
        std::fs::write(
            config.join("nuvek/secret-surfaces.toml"),
            "surfaces = [\"~/.config/example-nonutf8/token\"]\n",
        )
        .expect("write");
        let store = SurfaceStore::new();
        let report = load_default_at(&store, &config).expect("loads");
        assert!(report.source.is_some(), "the file was skipped");
        assert!(store.is_match("cat ~/.config/example-nonutf8/token"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Through the real entry point: `$HOME`, `$XDG_CONFIG_HOME` and the explicit variable set to
    /// non-UTF-8 values in the environment itself are all honoured, never treated as unset.
    #[test]
    fn isolated_init_honours_non_utf8_environment_values() {
        isolated("isolated_init_honours_non_utf8_environment_values", || {
            let dir = scratch_dir("non-utf8-env");
            let child = |name: &[u8]| {
                let mut p = dir.clone().into_os_string();
                p.push("/");
                p.push(std::ffi::OsStr::from_bytes(name));
                PathBuf::from(p)
            };
            let home = child(b"home\xe9");
            let xdg = child(b"conf\xff");
            std::fs::create_dir_all(&home).expect("mkdir home");
            std::fs::create_dir_all(xdg.join("nuvek")).expect("mkdir xdg");
            std::env::set_var("HOME", home.as_os_str());

            // The default location under a non-UTF-8 XDG_CONFIG_HOME.
            std::fs::write(
                xdg.join("nuvek/secret-surfaces.toml"),
                "surfaces = [\"~/.config/example-xdg-nonutf8/token\"]\n",
            )
            .expect("write");
            std::env::remove_var(SURFACES_FILE_ENV);
            std::env::set_var("XDG_CONFIG_HOME", xdg.as_os_str());
            let report = init().expect("init with a non-UTF-8 XDG_CONFIG_HOME");
            assert_eq!(
                report.source.as_deref(),
                Some(xdg.join("nuvek/secret-surfaces.toml").as_path())
            );
            assert!(touches_secret_surface(
                "cat ~/.config/example-xdg-nonutf8/token"
            ));

            // The default location under a non-UTF-8 HOME, with XDG_CONFIG_HOME unset.
            std::fs::create_dir_all(home.join(".config/nuvek")).expect("mkdir");
            std::fs::write(
                home.join(".config/nuvek/secret-surfaces.toml"),
                "surfaces = [\"~/.config/example-home-nonutf8/token\"]\n",
            )
            .expect("write");
            std::env::remove_var("XDG_CONFIG_HOME");
            let report = init().expect("init with a non-UTF-8 HOME");
            assert!(report.source.is_some(), "the default file was skipped");
            assert!(touches_secret_surface(
                "cat ~/.config/example-home-nonutf8/token"
            ));

            // An explicit, non-UTF-8 NUVEK_SECRET_SURFACES_FILE.
            let explicit = child(b"explicit\xfe.toml");
            std::fs::write(
                &explicit,
                "surfaces = [\"~/.config/example-explicit-nonutf8/token\"]\n",
            )
            .expect("write");
            std::env::set_var(SURFACES_FILE_ENV, explicit.as_os_str());
            let report = init().expect("init with a non-UTF-8 explicit path");
            assert_eq!(report.source.as_deref(), Some(explicit.as_path()));
            assert!(touches_secret_surface(
                "cat ~/.config/example-explicit-nonutf8/token"
            ));
            let _ = std::fs::remove_dir_all(&dir);
        });
    }

    #[test]
    fn the_file_location_follows_env_then_xdg_then_home() {
        let home = Some(PathBuf::from("/users/someone"));
        let explicit = |p: &str| SurfacesLocation {
            path: PathBuf::from(p),
            explicit: true,
        };
        let default = |p: &str| SurfacesLocation {
            path: PathBuf::from(p),
            explicit: false,
        };
        let resolve = |e: Option<&str>, x: Option<&str>, h: Option<PathBuf>| {
            resolve_location(e.map(Into::into), x.map(PathBuf::from), h).expect("resolvable")
        };
        assert_eq!(
            resolve(Some("/srv/s.toml"), Some("/xdg"), home.clone()),
            Some(explicit("/srv/s.toml"))
        );
        assert_eq!(
            resolve(Some("~/s.toml"), None, home.clone()),
            Some(explicit("/users/someone/s.toml"))
        );
        assert_eq!(
            resolve(None, Some("/xdg"), home.clone()),
            Some(default("/xdg/nuvek/secret-surfaces.toml"))
        );
        // A relative XDG_CONFIG_HOME is invalid by the specification and ignored.
        assert_eq!(
            resolve(None, Some("relative"), home.clone()),
            Some(default("/users/someone/.config/nuvek/secret-surfaces.toml"))
        );
        assert_eq!(
            resolve(None, None, home),
            Some(default("/users/someone/.config/nuvek/secret-surfaces.toml"))
        );
        assert_eq!(resolve(None, None, None), None);
        // `~/` with no $HOME cannot be resolved, and is refused rather than guessed.
        assert!(matches!(
            resolve_location(Some("~/s.toml".into()), None, None),
            Err(ScrubConfigError::InvalidLocation { .. })
        ));
        // A non-UTF-8 explicit path is a path like any other.
        let raw = std::ffi::OsStr::from_bytes(b"/srv/s\xff.toml").to_os_string();
        assert_eq!(
            resolve_location(Some(raw.clone()), None, None).expect("resolvable"),
            Some(SurfacesLocation {
                path: PathBuf::from(raw),
                explicit: true,
            })
        );
    }

    #[test]
    fn globs_match_one_component_or_many() {
        let e = "/etc/example-app/*.secret";
        assert!(entry_matches(e, None, "cat /etc/example-app/db.secret"));
        assert!(entry_matches(e, None, "cat '/etc/example-app/db.secret'"));
        assert!(!entry_matches(
            e,
            None,
            "cat /etc/example-app/sub/db.secret"
        ));
        assert!(!entry_matches(e, None, "cat /etc/example-app/db.secretive"));
        assert!(!entry_matches(
            e,
            None,
            "cat /opt/etc/example-app/db.secret"
        ));
        let deep = "/etc/example-app/**/*.secret";
        assert!(entry_matches(
            deep,
            None,
            "cat /etc/example-app/a/b/db.secret"
        ));
        // `**/` is zero or more directories, so the file directly inside matches too.
        assert!(entry_matches(deep, None, "cat /etc/example-app/db.secret"));
        // A run of three or more stars is the same as two.
        assert!(entry_matches(
            "/etc/example-app/***/*.secret",
            None,
            "cat /etc/example-app/db.secret"
        ));
        // A trailing `**` crosses components.
        assert!(entry_matches(
            "/srv/example-app/**",
            None,
            "cat /srv/example-app/x/y"
        ));
        let q = "~/.config/example-app/token?";
        assert!(entry_matches(q, None, "cat ~/.config/example-app/token1"));
        assert!(!entry_matches(q, None, "cat ~/.config/example-app/token"));
        // Regex metacharacters in an entry are literal.
        let lit = "~/.config/example+app/(token)";
        assert!(entry_matches(
            lit,
            None,
            "cat ~/.config/example+app/(token)"
        ));
        assert!(!entry_matches(lit, None, "cat ~/.config/exampleeapp/token"));
        // Matching is case-insensitive, like every other surface.
        assert!(entry_matches(
            "~/.config/example-app/token",
            None,
            "cat ~/.CONFIG/Example-App/TOKEN"
        ));
        // Multi-byte paths are handled.
        assert!(entry_matches(
            "~/.config/café/clé",
            None,
            "cat ~/.config/café/clé"
        ));
    }

    /// File and directory names can contain spaces. A wildcard that stopped at whitespace let a
    /// quoted or backslash-escaped name walk past a configured surface.
    #[test]
    fn globs_match_names_with_spaces() {
        let e = "/etc/example-app/*.secret";
        for hit in [
            r#"cat "/etc/example-app/db prod.secret""#,
            "cat '/etc/example-app/db prod.secret'",
            r"cat /etc/example-app/db\ prod.secret",
        ] {
            assert!(entry_matches(e, None, hit), "missed: {hit}");
        }
        // `?` is one filename character: raw, quoted, or backslash-escaped.
        let q = "/etc/example-app/db?prod.secret";
        for hit in [
            r#"cat "/etc/example-app/db prod.secret""#,
            "cat '/etc/example-app/db prod.secret'",
            r"cat /etc/example-app/db\ prod.secret",
            "cat /etc/example-app/db_prod.secret",
        ] {
            assert!(entry_matches(q, None, hit), "missed: {hit}");
        }
        assert!(!entry_matches(
            q,
            None,
            "cat /etc/example-app/db/prod.secret"
        ));
        // An escaped `/` is still a separator: neither `?` nor `*` crosses it.
        assert!(!entry_matches(
            q,
            None,
            r"cat /etc/example-app/db\/prod.secret"
        ));
        assert!(!entry_matches(
            "/etc/example-app/*.secret",
            None,
            r"cat /etc/example-app/sub\/db.secret"
        ));
        assert!(!entry_matches(
            q,
            None,
            "cat /etc/example-app/dbprod.secret"
        ));
        // `*` stays inside one component, spaces or not.
        assert!(!entry_matches(
            e,
            None,
            r#"cat "/etc/example-app/my dir/db.secret""#
        ));
        let deep = "/srv/example-app/**/credentials";
        for hit in [
            r#"cat "/srv/example-app/my dir/credentials""#,
            r"cat /srv/example-app/my\ dir/sub\ dir/credentials",
            "cat /srv/example-app/credentials",
        ] {
            assert!(entry_matches(deep, None, hit), "missed: {hit}");
        }
        // A literal space in an entry matches the name quoted or escaped.
        let spaced = "~/.config/Example App/token";
        assert!(entry_matches(
            spaced,
            None,
            r#"cat "$HOME/.config/Example App/token""#
        ));
        assert!(entry_matches(
            spaced,
            None,
            r"cat ~/.config/Example\ App/token"
        ));
        // A wildcard never crosses a newline.
        assert!(!entry_matches(
            "/etc/example-app/*.secret",
            None,
            "cat /etc/example-app/x\necho y.secret"
        ));
    }

    /// Wildcards are bounded, so a wildcard-led pattern over a long, many-word line still
    /// evaluates (an evaluation error would fail closed and drop the line) and stays fast.
    #[test]
    fn wildcard_patterns_stay_linear_on_long_lines() {
        let store = SurfaceStore::new();
        let dir = scratch_dir("linear");
        let file = write_file(
            &dir,
            "surfaces.toml",
            "surfaces = [\"~/*.secret\", \"/srv/example-app/**/credentials\"]\n",
        );
        load_into(&store, &file, None).expect("valid");
        let line = "word ".repeat(10_000);
        let start = std::time::Instant::now();
        assert!(!store.is_match(&line));
        assert!(store.is_match(&format!("{line} cat ~/db.secret")));
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "took {:?}",
            start.elapsed()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An absolute entry under the home directory also matches its `~/` spelling.
    #[test]
    fn an_absolute_entry_under_home_also_matches_its_tilde_form() {
        let e = "/users/someone/.config/example-app/token";
        let home = Some("/users/someone");
        assert!(entry_matches(
            e,
            home,
            "cat /users/someone/.config/example-app/token"
        ));
        assert!(entry_matches(e, home, "cat ~/.config/example-app/token"));
        assert!(entry_matches(
            e,
            home,
            "cat $HOME/.config/example-app/token"
        ));
        // Without knowing the home directory, only the absolute form applies.
        assert!(!entry_matches(e, None, "cat ~/.config/example-app/token"));
        // A home that is merely a prefix of another directory does not count.
        assert_eq!(
            surface_fragments("/users/someoneelse/.x", home)
                .expect("valid")
                .len(),
            1
        );
    }

    /// An invented 32-character hex credential, assembled from parts so no scanner mistakes the
    /// source for a real secret.
    const HEX_FIXTURE: &str = concat!("0f1e2d3c", "4b5a6978", "8796a5b4", "c3d2e1f0");

    /// The gap `redact` cannot close: an unprefixed credential has no signature to match. This is
    /// the shape in which a rendered vault value can leak through deployment-tool output.
    #[test]
    fn redact_alone_cannot_catch_an_unprefixed_secret() {
        let secret = HEX_FIXTURE;
        assert_eq!(
            redact(secret),
            secret,
            "documents the blind spot Masker exists to close"
        );
    }

    #[test]
    fn masker_replaces_a_known_value_and_names_it() {
        let m = Masker::new([(HEX_FIXTURE, "neo4j_password")]);
        let got = m.mask(&format!("auth=neo4j/{HEX_FIXTURE} ok"));
        assert!(!got.contains(HEX_FIXTURE), "got: {got}");
        assert!(got.contains("«REDACTED:neo4j_password»"));
        // Context survives, so the line stays diagnosable.
        assert!(got.starts_with("auth=neo4j/"));
    }

    /// Shape-independence is the point: masked anywhere, in any surrounding text.
    #[test]
    fn masker_is_position_independent() {
        let m = Masker::new([("supersecretvalue", "v")]);
        assert!(!m
            .mask("prefix supersecretvalue suffix")
            .contains("supersecretvalue"));
        assert!(!m
            .mask("{\"k\":\"supersecretvalue\"}")
            .contains("supersecretvalue"));
    }

    /// When one secret contains another, the longer must go first or its tail leaks.
    #[test]
    fn masker_handles_overlapping_values_longest_first() {
        let m = Masker::new([("supersecret", "short"), ("supersecretvalue", "long")]);
        let got = m.mask("token=supersecretvalue");
        assert!(got.contains("«REDACTED:long»"), "got: {got}");
        assert!(
            !got.contains("value"),
            "tail of the longer secret leaked: {got}"
        );
    }

    /// Trivial values are dropped at construction: masking `true` or a port would corrupt output.
    #[test]
    fn masker_refuses_trivial_values() {
        for s in [
            "8080",
            "true",
            "false",
            "yes",
            "no",
            "abc",
            "1234567",
            "123456789012345",
        ] {
            assert!(!Masker::is_maskable(s), "{s} must not be maskable");
        }
        assert!(Masker::new([("true", "x"), ("8080", "y")]).is_empty());
    }

    /// A masker must never eat a sha256 digest — deploy tooling is built on reporting them.
    #[test]
    fn masker_leaves_unrelated_content_alone() {
        let m = Masker::new([(HEX_FIXTURE, "p")]);
        let line =
            "neo4j:latest@sha256:dca31d0d938dd8bb199c8846abedd897c3a07ddb629eca46a8009ac9e87aece2";
        assert_eq!(m.mask(line), line);
    }

    /// The combined helper closes both halves: exact value AND prefixed token.
    #[test]
    fn mask_and_redact_covers_both_layers() {
        let m = Masker::new([(HEX_FIXTURE, "p")]);
        let got = m.mask_and_redact(&format!(
            "vault={HEX_FIXTURE} gh=ghp_abcdefghijklmnopqrstuvwxyz0123"
        ));
        assert!(!got.contains(HEX_FIXTURE), "got: {got}");
        assert!(
            !got.contains("ghp_abcdefghijklmnopqrstuvwxyz0123"),
            "got: {got}"
        );
    }

    #[test]
    fn masking_is_idempotent() {
        let m = Masker::new([("supersecretvalue", "v")]);
        let once = m.mask("token=supersecretvalue");
        assert_eq!(m.mask(&once), once);
    }

    // --- encoding coverage: a secret is just as exposed however it was encoded on the way out ---

    /// A credential containing `&` is XML-escaped when rendered into a template, so the raw form
    /// never appears in the output.
    #[test]
    fn xml_escaped_secrets_are_masked() {
        let m = Masker::new([("pa&ss<word>value", "db_password")]);
        let got = m.mask("<Config>pa&amp;ss&lt;word&gt;value</Config>");
        assert!(!got.contains("ss&lt;word"), "got: {got}");
        assert!(got.contains("«REDACTED:db_password»"), "got: {got}");
    }

    /// An MCP server answers in JSON, which escapes quotes and backslashes.
    #[test]
    fn json_escaped_secrets_are_masked() {
        let secret = r#"pass"with\slash"#;
        let m = Masker::new([(secret, "api_key")]);
        let body = serde_json::to_string(&serde_json::json!({ "k": secret })).expect("json");
        let got = m.mask(&body);
        assert!(!got.contains(r#"pass\"with"#), "got: {got}");
        assert!(got.contains("«REDACTED:api_key»"), "got: {got}");
    }

    /// Credentials inside URLs are percent-encoded by any well-behaved client.
    #[test]
    fn percent_encoded_secrets_are_masked() {
        let m = Masker::new([("p@ss w0rd!value", "bolt_password")]);
        let got = m.mask("bolt://user:p%40ss%20w0rd%21value@nas:7687");
        assert!(!got.contains("p%40ss"), "got: {got}");
        assert!(got.contains("«REDACTED:bolt_password»"), "got: {got}");
    }

    /// Hex-shaped secrets get case-folded freely by different tools; case carries no meaning.
    #[test]
    fn hex_secrets_are_masked_in_either_case() {
        let m = Masker::new([(HEX_FIXTURE, "p")]);
        assert!(m
            .mask(&format!("X {} Y", HEX_FIXTURE.to_uppercase()))
            .contains("«REDACTED:p»"));
        assert!(m
            .mask(&format!("x {HEX_FIXTURE} y"))
            .contains("«REDACTED:p»"));
    }

    /// Non-hex values must NOT be case-folded, or unrelated text differing only in case is eaten.
    #[test]
    fn non_hex_secrets_are_not_case_folded() {
        let m = Masker::new([("SuperSecretWord", "v")]);
        let got = m.mask("supersecretword");
        assert_eq!(
            got, "supersecretword",
            "case-folding a non-hex value over-masks"
        );
    }

    /// Authorization: Basic — the encoded text shares NO substring with the password, so literal
    /// matching cannot see it. This is the case that makes decode-and-check worth the complexity.
    #[test]
    fn base64_basic_auth_carrying_a_secret_is_masked() {
        use base64::Engine;
        let secret = "supersecretpassword";
        let blob = base64::engine::general_purpose::STANDARD.encode(format!("user:{secret}"));
        // Precondition: the encoded form really does not contain the raw secret.
        assert!(!blob.contains(secret));
        let m = Masker::new([(secret, "basic_auth")]);
        let got = m.mask(&format!("Authorization: Basic {blob}"));
        assert!(!got.contains(&blob), "got: {got}");
        assert!(got.contains("«REDACTED-BASE64:basic_auth»"), "got: {got}");
    }

    /// Base64 that decodes to something harmless must survive — otherwise ordinary payloads,
    /// digests and unrelated tokens get eaten and the tool becomes unusable.
    #[test]
    fn unrelated_base64_is_left_alone() {
        use base64::Engine;
        let blob = base64::engine::general_purpose::STANDARD.encode("hello world, nothing secret");
        let m = Masker::new([("supersecretpassword", "v")]);
        let line = format!("payload {blob}");
        assert_eq!(m.mask(&line), line);
    }

    /// Words and short tokens must not be dragged through the base64 decoder.
    #[test]
    fn ordinary_prose_is_not_mangled_by_the_base64_pass() {
        let m = Masker::new([("supersecretpassword", "v")]);
        let line = "TASK [example_role : Deploy hardened service templates] ok=7 changed=1";
        assert_eq!(m.mask(line), line);
    }

    /// An empty mask set must be a no-op, not an accidental filter.
    #[test]
    fn an_empty_masker_changes_nothing() {
        let m = Masker::new(Vec::<(String, String)>::new());
        let line = "Authorization: Basic dXNlcjpwYXNz";
        assert_eq!(m.mask(line), line);
    }

    /// Multi-byte input must not panic — the base64 scan splits on char boundaries.
    #[test]
    fn multibyte_text_is_handled() {
        let m = Masker::new([("supersecretpassword", "v")]);
        let line = "héllo wörld — château supersecretpassword ✅";
        let got = m.mask(line);
        assert!(!got.contains("supersecretpassword"), "got: {got}");
        assert!(got.contains("château"), "got: {got}");
    }

    /// A secret appearing many times is masked at every occurrence, not just the first.
    #[test]
    fn every_occurrence_is_masked() {
        let m = Masker::new([("supersecretvalue", "v")]);
        let got = m.mask("a supersecretvalue b supersecretvalue c");
        assert!(!got.contains("supersecretvalue"), "got: {got}");
        assert_eq!(got.matches("«REDACTED:v»").count(), 2);
    }

    /// A YAML block scalar (`password: |`) parses WITH a trailing newline. `is_maskable` judges
    /// the trimmed value, so it passes — and storing only the untrimmed form would then search
    /// for a string with a newline that never appears in rendered output, silently dropping the
    /// secret from the mask set. Under-masking, in exactly the case this type exists to cover.
    #[test]
    fn a_value_with_surrounding_whitespace_is_masked_in_its_trimmed_form() {
        let m = Masker::new([("  supersecretvalue\n", "block_scalar_password")]);
        let got = m.mask("token=supersecretvalue in the rendered output");
        assert!(!got.contains("supersecretvalue"), "got: {got}");
        assert!(
            got.contains("«REDACTED:block_scalar_password»"),
            "got: {got}"
        );
    }

    /// URL-safe base64 (`-`/`_`) is how a credential travels in a URL or JWT-adjacent field.
    /// Scanning only the standard alphabet would let that form through untouched.
    #[test]
    fn url_safe_base64_carrying_a_secret_is_masked() {
        use base64::Engine;
        let secret = "supersecretpassword";
        let blob = base64::engine::general_purpose::URL_SAFE.encode(format!("user:{secret}?~"));
        let m = Masker::new([(secret, "basic_auth")]);
        let got = m.mask(&format!("t={blob}"));
        assert!(
            !got.contains(&blob),
            "url-safe base64 was not masked: {got}"
        );
        // The `key=` prefix is not sensitive and must survive, or the masker corrupts output.
        assert!(got.starts_with("t="), "the key prefix was eaten: {got}");
    }

    /// `=` is itself a base64 character, so a run scanned out of `token=<blob>` starts at the `t`
    /// of `token` and fails to decode as a whole. An interior `=` can only be a delimiter (valid
    /// base64 pads only at the end), so the payload after it must still be found — this is one of
    /// the most common shapes a credential appears in.
    #[test]
    fn base64_fused_to_a_key_prefix_is_still_masked() {
        use base64::Engine;
        let secret = "supersecretpassword";
        let blob = base64::engine::general_purpose::STANDARD.encode(format!("user:{secret}"));
        let m = Masker::new([(secret, "basic_auth")]);
        let got = m.mask(&format!("authorization={blob}"));
        assert!(!got.contains(&blob), "fused base64 was not masked: {got}");
        assert!(got.starts_with("authorization="), "prefix eaten: {got}");
    }

    /// Two vault variables sharing one password must collapse to a single entry — `dedup_by` only
    /// removes ADJACENT equals, so the sort has to be total, not length-only.
    #[test]
    fn identical_values_under_different_names_are_deduped() {
        // Three same-length values, the duplicates deliberately not adjacent by insertion order.
        let m = Masker::new([
            ("supersecretvalue", "a"),
            ("anothersecretval", "b"),
            ("supersecretvalue", "c"),
        ]);
        // Two distinct values survive; the duplicate is collapsed rather than stored twice.
        assert_eq!(m.len(), 2, "duplicate value was not deduped");
    }

    /// Values that are only maskable in one encoding still get filtered on the trivial bar, so a
    /// variant cannot smuggle a corrupting match past `is_maskable`.
    #[test]
    fn trivial_values_produce_no_entries_in_any_encoding() {
        let m = Masker::new([("true", "t"), ("8080", "p"), ("<>", "x")]);
        assert!(m.is_empty());
        let line = "true 8080 <> &lt;&gt;";
        assert_eq!(m.mask(line), line);
    }
}
