//! Shared logger: journald, the system log.
//!
//! `get_logger(name)` gives a tool leveled log lines that land in the systemd journal under
//! `SYSLOG_IDENTIFIER=<name>`, so they are read the standard way:
//!
//! ```text
//! journalctl --user -t <name>            # everything this tool logged
//! journalctl --user -t <name> -p err     # its errors only
//! ```
//!
//! ```no_run
//! # use nuvek_core::log::get_logger;
//! let log = get_logger("indexer");
//! log.info("started");
//! ```
//!
//! **Where a line goes**, decided once when the logger is built:
//!
//! 1. The journal socket exists → each line is sent **natively** (`MESSAGE`, `PRIORITY`,
//!    `SYSLOG_IDENTIFIER`). This works for every kind of process — a timer's service, a hook or
//!    MCP server spawned by an agent, a CLI — because journald files a datagram by the sender's
//!    uid, and attaches `_SYSTEMD_USER_UNIT` when the sender runs inside a unit.
//! 2. The same line is also written to **stderr** (never stdout, which is a JSON-RPC channel for
//!    MCP servers), so a person or agent running a CLI still sees it — EXCEPT when stderr is
//!    itself connected to the journal (`JOURNAL_STREAM`), where it would be stored twice.
//! 3. No journal socket (a container, a host without systemd, CI) → stderr only.
//!
//! `NUVEK_LOG_SINK=stderr|journal|auto` overrides the choice (default `auto`). Tests and smoke
//! runs set `stderr` so they never write the live journal. The variable is named after
//! this library, like `RUST_LOG`, so it names no deployment.
//!
//! Logging never fails the caller: every send and write error is swallowed.
//!
//! The stderr line format is stable: `2000-01-01T00:00:00 INFO    example-worker | started`.

use chrono::Local;
use std::io::Write;
use std::os::unix::net::UnixDatagram;
use std::path::Path;

/// The journal's native-protocol socket (systemd.journal-fields(7), "native protocol").
const JOURNAL_SOCKET: &str = "/run/systemd/journal/socket";

/// Env var overriding where lines go: `stderr`, `journal` or `auto` (default).
pub const SINK_ENV: &str = "NUVEK_LOG_SINK";

/// Ceiling on one journal MESSAGE, in BYTES. The real limit on a native datagram is the socket's
/// send buffer (`wmem_default`, typically a few hundred KiB), so 48 KiB keeps every entry well
/// inside it on any sane host. A send that still fails (EMSGSIZE, journald stopped) falls back to
/// stderr — a line is never silently dropped. Upgrade path for bigger payloads: the memfd fd-passing variant of
/// the native protocol.
const MAX_MESSAGE_BYTES: usize = 48 * 1024;

#[derive(Clone, Copy)]
enum Level {
    Info,
    Warn,
    Error,
}

impl Level {
    /// syslog priority (journald `PRIORITY`).
    fn priority(self) -> u8 {
        match self {
            Level::Info => 6,
            Level::Warn => 4,
            Level::Error => 3,
        }
    }

    /// `%(levelname)-7s` label, kept from the old file format.
    fn label(self) -> &'static str {
        match self {
            Level::Info => "INFO",
            Level::Warn => "WARNING",
            Level::Error => "ERROR",
        }
    }
}

/// A configured logger. Writes are independent datagrams/lines, so it is safe to share by
/// reference across threads.
pub struct Logger {
    name: String,
    journal: Option<UnixDatagram>,
    /// Where datagrams go. The well-known socket in production; a temp socket in tests.
    socket_path: &'static Path,
    stderr: bool,
}

impl Logger {
    fn write(&self, level: Level, msg: &str) {
        // A failed send (full buffer, journald stopped) must never break the caller, and must not
        // lose the line either: it falls through to stderr even when stderr echo is suppressed.
        let sent = self.journal.as_ref().is_some_and(|sock| {
            sock.send_to(&encode(&self.name, level, msg), self.socket_path)
                .is_ok()
        });
        if self.stderr || !sent {
            let line = format!(
                "{} {:<7} {} | {}\n",
                Local::now().format("%Y-%m-%dT%H:%M:%S"),
                level.label(),
                self.name,
                msg
            );
            let _ = std::io::stderr().write_all(line.as_bytes());
        }
    }

    /// Log at INFO (priority 6).
    pub fn info(&self, msg: &str) {
        self.write(Level::Info, msg);
    }
    /// Log at WARNING (priority 4).
    pub fn warn(&self, msg: &str) {
        self.write(Level::Warn, msg);
    }
    /// Log at ERROR (priority 3).
    pub fn error(&self, msg: &str) {
        self.write(Level::Error, msg);
    }

    /// A logger that only writes stderr, whatever the environment. For tests.
    #[must_use]
    pub fn stderr_only(name: &str) -> Logger {
        Logger {
            name: name.to_string(),
            journal: None,
            socket_path: Path::new(JOURNAL_SOCKET),
            stderr: true,
        }
    }
}

/// Return a logger for the tool `name` (its journal `SYSLOG_IDENTIFIER`). See the module docs
/// for where lines go. Never fails: with no usable journal it degrades to stderr.
pub fn get_logger(name: &str) -> Logger {
    let sink = crate::env::env_var(SINK_ENV).unwrap_or_default();
    let socket_path = Path::new(JOURNAL_SOCKET);
    let journal = wants_journal(&sink, socket_path.exists())
        .then(UnixDatagram::unbound)
        .and_then(Result::ok);
    // Skip the stderr copy only when the journal really has the line AND stderr is the journal.
    let stderr = !(journal.is_some() && stderr_is_journal());
    Logger {
        name: name.to_string(),
        journal,
        socket_path,
        stderr,
    }
}

/// The sink decision: `stderr` → no journal, `journal` → journal, anything else (unset, `auto`,
/// a typo) → the journal exactly when its socket exists.
fn wants_journal(sink: &str, socket_exists: bool) -> bool {
    match sink.trim() {
        "stderr" => false,
        "journal" => true,
        _ => socket_exists,
    }
}

/// Whether fd 2 is the journal stream systemd connected (`JOURNAL_STREAM=<dev>:<ino>`).
fn stderr_is_journal() -> bool {
    let Some(stream) = crate::env::env_var("JOURNAL_STREAM") else {
        return false;
    };
    let Some(expected) = parse_journal_stream(&stream) else {
        return false;
    };
    stderr_dev_ino() == Some(expected)
}

/// `<dev>:<ino>` → the pair, as systemd.exec(5) documents `JOURNAL_STREAM`.
fn parse_journal_stream(v: &str) -> Option<(u64, u64)> {
    let (dev, ino) = v.trim().split_once(':')?;
    Some((dev.parse().ok()?, ino.parse().ok()?))
}

fn stderr_dev_ino() -> Option<(u64, u64)> {
    use std::os::fd::AsFd;
    use std::os::unix::fs::MetadataExt;
    let fd = std::io::stderr().as_fd().try_clone_to_owned().ok()?;
    let meta = std::fs::File::from(fd).metadata().ok()?;
    Some((meta.dev(), meta.ino()))
}

/// One native-protocol datagram. Every field uses the binary-safe form
/// (`KEY\n` + little-endian u64 length + value + `\n`), so newlines in a message are kept intact.
fn encode(name: &str, level: Level, msg: &str) -> Vec<u8> {
    let msg = fit(msg);
    let mut out = Vec::with_capacity(msg.len() + name.len() + 64);
    field(&mut out, "MESSAGE", msg.as_bytes());
    field(
        &mut out,
        "PRIORITY",
        level.priority().to_string().as_bytes(),
    );
    field(&mut out, "SYSLOG_IDENTIFIER", name.as_bytes());
    out
}

fn field(out: &mut Vec<u8>, key: &str, value: &[u8]) {
    out.extend_from_slice(key.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(&(value.len() as u64).to_le_bytes());
    out.extend_from_slice(value);
    out.push(b'\n');
}

/// `msg` cut to at most [`MAX_MESSAGE_BYTES`] bytes on a char boundary, with an ellipsis when it
/// was cut (the ellipsis is counted inside the limit).
fn fit(msg: &str) -> std::borrow::Cow<'_, str> {
    if msg.len() <= MAX_MESSAGE_BYTES {
        return std::borrow::Cow::Borrowed(msg);
    }
    let budget = MAX_MESSAGE_BYTES - '…'.len_utf8();
    let end = msg
        .char_indices()
        .map(|(i, c)| i + c.len_utf8())
        .take_while(|end| *end <= budget)
        .last()
        .unwrap_or(0);
    let mut cut = msg[..end].to_string();
    cut.push('…');
    std::borrow::Cow::Owned(cut)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decode a datagram back into (key, value) pairs — the inverse of `encode`, binary form only.
    fn decode(mut buf: &[u8]) -> Vec<(String, Vec<u8>)> {
        let mut out = Vec::new();
        while !buf.is_empty() {
            let nl = buf
                .iter()
                .position(|b| *b == b'\n')
                .expect("key terminator");
            let key = String::from_utf8(buf[..nl].to_vec()).expect("utf8 key");
            buf = &buf[nl + 1..];
            let len = u64::from_le_bytes(buf[..8].try_into().expect("8 bytes")) as usize;
            buf = &buf[8..];
            out.push((key, buf[..len].to_vec()));
            assert_eq!(buf[len], b'\n', "value terminator");
            buf = &buf[len + 1..];
        }
        out
    }

    #[test]
    fn a_multiline_multibyte_message_round_trips_with_priority_and_identifier() {
        let msg = "first line\nsecond: é ✓ 日本";
        let fields = decode(&encode("example_sync", Level::Error, msg));
        assert_eq!(
            fields,
            vec![
                ("MESSAGE".to_string(), msg.as_bytes().to_vec()),
                ("PRIORITY".to_string(), b"3".to_vec()),
                ("SYSLOG_IDENTIFIER".to_string(), b"example_sync".to_vec()),
            ]
        );
    }

    #[test]
    fn priorities_follow_syslog() {
        assert_eq!(Level::Info.priority(), 6);
        assert_eq!(Level::Warn.priority(), 4);
        assert_eq!(Level::Error.priority(), 3);
    }

    #[test]
    fn an_oversized_message_is_cut_by_bytes_on_a_char_boundary() {
        // 4-byte chars: a char cap would let this through at ~4x the byte budget.
        let long = "日本😀".repeat(MAX_MESSAGE_BYTES);
        let cut = fit(&long);
        assert!(cut.len() <= MAX_MESSAGE_BYTES, "{} bytes", cut.len());
        assert!(
            cut.len() > MAX_MESSAGE_BYTES - 8,
            "cut too early: {}",
            cut.len()
        );
        assert!(cut.ends_with('…'));
        assert_eq!(fit("short"), "short");
    }

    #[test]
    fn sink_selection() {
        assert!(!wants_journal("stderr", true));
        assert!(wants_journal("journal", false));
        assert!(wants_journal("", true));
        assert!(wants_journal("auto", true));
        assert!(!wants_journal("auto", false));
        assert!(!wants_journal(" stderr\n", true));
    }

    /// A temp datagram socket stands in for journald: the entry arrives as one encoded datagram.
    #[test]
    fn a_line_is_sent_as_one_native_datagram() {
        let dir = std::env::temp_dir().join(format!("nuvek-log-sock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path: &'static Path = Box::leak(dir.join("journal.sock").into_boxed_path());
        let server = UnixDatagram::bind(path).unwrap();
        let log = Logger {
            name: "unit".to_string(),
            journal: Some(UnixDatagram::unbound().unwrap()),
            socket_path: path,
            stderr: false,
        };
        log.warn("over\nthere");
        let mut buf = vec![0u8; 4096];
        let n = server.recv(&mut buf).unwrap();
        let fields = decode(&buf[..n]);
        assert_eq!(fields[0], ("MESSAGE".to_string(), b"over\nthere".to_vec()));
        assert_eq!(fields[1], ("PRIORITY".to_string(), b"4".to_vec()));
        assert_eq!(
            fields[2],
            ("SYSLOG_IDENTIFIER".to_string(), b"unit".to_vec())
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// No listener at the path: the send fails and the logger must not panic (it falls back to
    /// stderr, which this test cannot capture but exercises).
    #[test]
    fn a_failed_send_does_not_panic() {
        let log = Logger {
            name: "unit".to_string(),
            journal: Some(UnixDatagram::unbound().unwrap()),
            socket_path: Path::new("/nonexistent/nuvek-test.sock"),
            stderr: false,
        };
        log.error("dropped by the socket, kept on stderr");
    }

    #[test]
    fn journal_stream_parses_dev_and_inode() {
        assert_eq!(parse_journal_stream("8:12345"), Some((8, 12345)));
        assert_eq!(parse_journal_stream(" 0:7\n"), Some((0, 7)));
        assert_eq!(parse_journal_stream("garbage"), None);
        assert_eq!(parse_journal_stream("1:x"), None);
    }

    #[test]
    fn stderr_only_never_holds_a_journal_socket() {
        let log = Logger::stderr_only("unit");
        assert!(log.journal.is_none());
        assert!(log.stderr);
        log.info("hello"); // must not panic
    }
}
