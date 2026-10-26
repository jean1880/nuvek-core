//! Content digests for matching text across tools without storing the text.

use sha2::{Digest, Sha256};

/// Lowercase hex SHA-256 of `text`.
#[must_use]
pub fn sha256_hex(text: &str) -> String {
    format!("{:x}", Sha256::digest(text.as_bytes()))
}

/// A stable key for a prompt: the digest of its whitespace-collapsed form, so the same prompt
/// matches after a receiver re-wraps or re-indents it. Lets one tool record what it sent and
/// another recognise it later, while neither stores the prompt itself.
#[must_use]
pub fn prompt_key(prompt: &str) -> String {
    sha256_hex(&prompt.split_whitespace().collect::<Vec<_>>().join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_matches_known_vector() {
        assert_eq!(
            sha256_hex("hello"),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn prompt_key_ignores_whitespace_layout_only() {
        assert_eq!(
            prompt_key("check  the\nrouter "),
            prompt_key("check the router")
        );
        assert_ne!(prompt_key("check the router"), prompt_key("check the nas"));
    }
}
