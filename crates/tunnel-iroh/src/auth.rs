//! Token-based authentication for iroh tunnel connections.
//!
//! Provides pre-shared token authentication for the iroh multi-source server.

use anyhow::{Context, Result};
use std::collections::HashSet;
use std::path::Path;

/// Load auth tokens from CLI arguments and/or a file.
///
/// # Arguments
/// * `cli_tokens` - Tokens specified via CLI `--auth-tokens` flags
/// * `file` - Optional path to a file containing tokens (one per line)
///
/// # Returns
/// A HashSet of all valid authentication tokens
///
/// # Errors
/// Returns an error if the file cannot be read
pub fn load_auth_tokens(cli_tokens: &[String], file: Option<&Path>) -> Result<HashSet<String>> {
    let mut tokens = HashSet::new();

    // Load from CLI arguments
    for token in cli_tokens {
        let trimmed = token.trim();
        if !trimmed.is_empty() && !trimmed.starts_with('#') {
            tokens.insert(trimmed.to_string());
        }
    }

    // Load from file if specified
    if let Some(file_path) = file {
        let file_tokens = load_auth_tokens_from_file(file_path)?;
        tokens.extend(file_tokens);
    }

    Ok(tokens)
}

/// Load authentication tokens from a file.
///
/// # File Format
/// - One token per line
/// - Lines starting with `#` are treated as comments
/// - Empty lines are ignored
/// - Inline comments (after token) are supported with `#`
///
/// # Example file:
/// ```text
/// # Authentication tokens
/// my-secret-token-1  # Client A
/// another-token-here  # Client B
/// ```
pub fn load_auth_tokens_from_file(path: &Path) -> Result<HashSet<String>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read auth tokens file: {}", path.display()))?;

    let mut tokens = HashSet::new();

    for line in content.lines() {
        let line = line.trim();

        // Skip empty lines and comment lines
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Handle inline comments: take only the part before #
        let token = line.split('#').next().unwrap_or(line).trim();

        if !token.is_empty() {
            tokens.insert(token.to_string());
        }
    }

    Ok(tokens)
}

/// Load a single auth token from a file.
///
/// # File Format
/// - First non-empty, non-comment line is the token
/// - Lines starting with `#` are treated as comments
/// - Empty lines are ignored
/// - Inline comments (after token) are supported with `#`
pub fn load_auth_token_from_file(path: &Path) -> Result<String> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read auth token file: {}", path.display()))?;

    for line in content.lines() {
        let line = line.trim();

        // Skip empty lines and comment lines
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Handle inline comments: take only the part before #
        let token = line.split('#').next().unwrap_or(line).trim();

        if !token.is_empty() {
            return Ok(token.to_string());
        }
    }

    anyhow::bail!(
        "No valid token found in file: {}",
        path.display()
    )
}

/// Check if a token is in the valid tokens set.
///
/// Returns true if the token is valid, false otherwise.
/// An empty valid_tokens set means no tokens are authorized.
#[inline]
pub fn is_token_valid(token: &str, valid_tokens: &HashSet<String>) -> bool {
    valid_tokens.contains(token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_load_from_file_with_comments() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "# This is a comment").unwrap();
        writeln!(file, "").unwrap();
        writeln!(file, "  # Another comment with leading space").unwrap();

        let result = load_auth_tokens_from_file(file.path()).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_load_from_file_with_tokens() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "# Auth tokens").unwrap();
        writeln!(file, "token1").unwrap();
        writeln!(file, "token2  # inline comment").unwrap();
        writeln!(file, "  token3  ").unwrap();

        let result = load_auth_tokens_from_file(file.path()).unwrap();
        assert_eq!(result.len(), 3);
        assert!(result.contains("token1"));
        assert!(result.contains("token2"));
        assert!(result.contains("token3"));
    }

    #[test]
    fn test_load_single_token_from_file() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "# My auth token").unwrap();
        writeln!(file, "").unwrap();
        writeln!(file, "my-secret-token  # comment").unwrap();
        writeln!(file, "ignored-second-token").unwrap();

        let result = load_auth_token_from_file(file.path()).unwrap();
        assert_eq!(result, "my-secret-token");
    }

    #[test]
    fn test_is_token_valid_empty_set_rejects_all() {
        let valid_tokens = HashSet::new();
        assert!(!is_token_valid("any-token", &valid_tokens));
    }

    #[test]
    fn test_is_token_valid_in_set() {
        let mut valid_tokens = HashSet::new();
        valid_tokens.insert("secret-token".to_string());

        assert!(is_token_valid("secret-token", &valid_tokens));
    }

    #[test]
    fn test_is_token_valid_not_in_set() {
        let mut valid_tokens = HashSet::new();
        valid_tokens.insert("token1".to_string());

        assert!(!is_token_valid("token2", &valid_tokens));
    }

    #[test]
    fn test_load_auth_tokens_cli_and_file() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "file-token").unwrap();

        let cli_tokens = vec!["cli-token".to_string()];
        let result = load_auth_tokens(&cli_tokens, Some(file.path())).unwrap();

        assert_eq!(result.len(), 2);
        assert!(result.contains("cli-token"));
        assert!(result.contains("file-token"));
    }
}
