//! Agent-harness hook I/O shared by the context-injecting hooks: which harness invoked the hook,
//! where its session is working, and the JSON that injects context back into it.
//!
//! Two harnesses, two contracts:
//! - **Claude Code** reads `{"hookSpecificOutput":{"hookEventName","additionalContext"}}`, and its
//!   payload carries `cwd`.
//! - **Antigravity (AGY)** parses the result with protojson into its hook-result message, a
//!   repeated `HookInjectedStep` (a oneof of user/ephemeral/system/error message). The text sits
//!   in `HookSystemMessage.system_message`, so the nesting below is exact: a flat or
//!   string-valued `systemMessage` is rejected, and AGY then drops the whole result, logging
//!   only to its own CLI log. Its payload has no `cwd`, only `workspacePaths`.
//!
//! AGY documents none of this. The shape comes from its protojson unmarshal errors and its
//! binary's proto getters. Unit tests can only check our side; a real AGY session is the proof
//! that AGY accepts it.

use serde_json::{json, Value};

/// The harness that invoked the hook.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Harness {
    Claude,
    Agy,
    Codex,
}

impl Harness {
    /// `--format agy` (or `--format=agy`) selects AGY; anything else is Claude, whose hook
    /// entries pass no arguments.
    pub fn from_args(args: &[String]) -> Self {
        let codex = args
            .windows(2)
            .any(|w| w[0] == "--format" && w[1] == "codex")
            || args.iter().any(|a| a == "--format=codex");
        let agy = args.windows(2).any(|w| w[0] == "--format" && w[1] == "agy")
            || args.iter().any(|a| a == "--format=agy");
        if codex {
            Self::Codex
        } else if agy {
            Self::Agy
        } else {
            Self::Claude
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Agy => "agy",
            Self::Codex => "codex",
        }
    }

    /// The stdout JSON that injects `text` into the session. `event` is Claude's hook event
    /// name; AGY's result carries none.
    pub fn context_output(self, event: &str, text: &str) -> Value {
        match self {
            Self::Claude | Self::Codex => json!({
                "hookSpecificOutput": { "hookEventName": event, "additionalContext": text }
            }),
            Self::Agy => json!({
                "injectSteps": [ { "systemMessage": { "systemMessage": text } } ]
            }),
        }
    }
}

/// The session's working directory: Claude's `cwd`, else AGY's first `workspacePaths` entry.
pub fn workspace(payload: &Value) -> Option<&str> {
    payload.get("cwd").and_then(Value::as_str).or_else(|| {
        payload
            .get("workspacePaths")
            .and_then(Value::as_array)
            .and_then(|a| a.first())
            .and_then(Value::as_str)
    })
}

/// The payload's top-level key names, never values, for logging an undocumented input contract.
pub fn payload_keys(payload: &Value) -> String {
    match payload {
        Value::Object(m) => m.keys().cloned().collect::<Vec<_>>().join(","),
        Value::Null => "none".into(),
        _ => "non-object".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn only_an_explicit_format_agy_selects_agy() {
        assert_eq!(Harness::from_args(&argv(&[])), Harness::Claude);
        assert_eq!(
            Harness::from_args(&argv(&["--format", "agy"])),
            Harness::Agy
        );
        assert_eq!(Harness::from_args(&argv(&["--format=agy"])), Harness::Agy);
        assert_eq!(
            Harness::from_args(&argv(&["--format", "x"])),
            Harness::Claude
        );
        assert_eq!(Harness::from_args(&argv(&["agy"])), Harness::Claude);
    }

    #[test]
    fn context_output_matches_each_harness_contract() {
        let c = Harness::Claude.context_output("SessionStart", "t");
        assert_eq!(
            c,
            json!({"hookSpecificOutput":{"hookEventName":"SessionStart","additionalContext":"t"}})
        );
        let g = Harness::Agy.context_output("SessionStart", "t");
        assert_eq!(
            g,
            json!({"injectSteps":[{"systemMessage":{"systemMessage":"t"}}]})
        );
    }

    #[test]
    fn workspace_prefers_cwd_then_first_workspace_path() {
        assert_eq!(workspace(&json!({"cwd": "/a"})), Some("/a"));
        assert_eq!(
            workspace(&json!({"workspacePaths": ["/w", "/x"]})),
            Some("/w")
        );
        assert_eq!(
            workspace(&json!({"cwd": "/a", "workspacePaths": ["/w"]})),
            Some("/a")
        );
        assert_eq!(workspace(&json!({"workspacePaths": []})), None);
    }

    #[test]
    fn payload_keys_names_keys_never_values() {
        assert_eq!(
            payload_keys(&json!({"conversationId": "x", "cwd": "/secret"})),
            "conversationId,cwd"
        );
        assert_eq!(payload_keys(&Value::Null), "none");
        assert_eq!(payload_keys(&json!([1])), "non-object");
    }
}
