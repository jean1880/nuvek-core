//! MCP transport utilities for standard I/O with legacy/modern handshake compatibility.
//!
//! Bridges differences between legacy MCP clients (like Claude Code, which begin with `initialize`)
//! and modern stateless MCP clients (like Antigravity / Gemini CLI, which probe with `server/discover`
//! before initializing).

use std::io::Cursor;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader};

/// Create a standard I/O transport pair that is cross-compatible with both legacy MCP clients
/// and modern clients probing with `server/discover`.
///
/// If a client sends `server/discover`, this transport intercepts the probe, immediately returns
/// `-32601 Method not found` to stdout, and seamlessly forwards the subsequent `initialize`
/// request to the underlying server.
pub async fn stdio() -> std::io::Result<(impl AsyncRead + Send + Unpin + 'static, tokio::io::Stdout)>
{
    let mut stdin = BufReader::new(tokio::io::stdin());
    let mut first_line = String::new();

    stdin.read_line(&mut first_line).await?;

    let initial_buf = if first_line.contains("\"server/discover\"") {
        let id = serde_json::from_str::<serde_json::Value>(&first_line)
            .ok()
            .and_then(|v| v.get("id").cloned())
            .unwrap_or(serde_json::Value::Number(1.into()));

        let err_response = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "error": {
                "code": -32601,
                "message": "Method not found"
            }
        });

        let mut stdout = tokio::io::stdout();
        stdout
            .write_all(format!("{err_response}\n").as_bytes())
            .await?;
        stdout.flush().await?;

        stdin.buffer().to_vec()
    } else {
        let mut buf = first_line.into_bytes();
        buf.extend_from_slice(stdin.buffer());
        buf
    };

    let reader = Cursor::new(initial_buf).chain(stdin.into_inner());
    Ok((reader, tokio::io::stdout()))
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_server_discover_detection() {
        let line = r#"{"jsonrpc":"2.0","id":42,"method":"server/discover","params":{}}"#;
        assert!(line.contains("\"server/discover\""));

        let val: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(val.get("id").and_then(|i| i.as_i64()), Some(42));
    }

    #[test]
    fn test_initialize_passthrough() {
        let line = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#;
        assert!(!line.contains("\"server/discover\""));
    }
}
