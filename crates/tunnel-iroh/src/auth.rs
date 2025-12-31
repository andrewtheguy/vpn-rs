//! Token-based authentication for iroh tunnel connections.
//!
//! Provides pre-shared token authentication for the iroh multi-source server.
//!
//! ## Token Format
//! - Exactly 16 characters
//! - Allowed characters: A-Za-z0-9 and - _ . (hyphen, underscore, period)
//!
//! Generate tokens with: `openssl rand -hex 8` (produces 16 hex characters)

use anyhow::{Context, Result};
use std::collections::HashSet;
use std::path::Path;

/// Required length for authentication tokens.
pub const TOKEN_LENGTH: usize = 16;

/// Check if a character is valid for tokens.
/// Allowed: A-Za-z0-9 and - _ . (safe symbols that don't conflict with shell/TOML syntax)
#[inline]
fn is_valid_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.'
}

/// Validate token format.
///
/// Returns Ok(()) if valid, Err with description if invalid.
pub fn validate_token(token: &str) -> Result<()> {
    if token.len() != TOKEN_LENGTH {
        anyhow::bail!(
            "Token must be exactly {} characters, got {} characters",
            TOKEN_LENGTH,
            token.len()
        );
    }

    if let Some(invalid_char) = token.chars().find(|c| !is_valid_token_char(*c)) {
        anyhow::bail!(
            "Token contains invalid character '{}'. Allowed: A-Za-z0-9 and - _ .",
            invalid_char
        );
    }

    Ok(())
}

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
/// Returns an error if the file cannot be read or any token is invalid
pub fn load_auth_tokens(cli_tokens: &[String], file: Option<&Path>) -> Result<HashSet<String>> {
    let mut tokens = HashSet::new();

    // Load from CLI arguments
    for token in cli_tokens {
        let trimmed = token.trim();
        if !trimmed.is_empty() && !trimmed.starts_with('#') {
            validate_token(trimmed)
                .with_context(|| format!("Invalid token from CLI: '{}'", trimmed))?;
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
/// - One token per line (exactly 16 characters, alphanumeric + - _ .)
/// - Lines starting with `#` are treated as comments
/// - Empty lines are ignored
/// - Inline comments (after token) are supported with `#`
///
/// # Example file:
/// ```text
/// # Authentication tokens
/// a1b2c3d4e5f6g7h8  # Client A
/// x9y8z7w6v5u4t3s2  # Client B
/// ```
pub fn load_auth_tokens_from_file(path: &Path) -> Result<HashSet<String>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read auth tokens file: {}", path.display()))?;

    let mut tokens = HashSet::new();
    let mut line_num = 0;

    for line in content.lines() {
        line_num += 1;
        let line = line.trim();

        // Skip empty lines and comment lines
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Handle inline comments: take only the part before #
        let token = line.split('#').next().unwrap_or(line).trim();

        if !token.is_empty() {
            validate_token(token).with_context(|| {
                format!(
                    "Invalid token at {}:{}: '{}'",
                    path.display(),
                    line_num,
                    token
                )
            })?;
            tokens.insert(token.to_string());
        }
    }

    Ok(tokens)
}

/// Load a single auth token from a file.
///
/// # File Format
/// - First non-empty, non-comment line is the token (exactly 16 chars, alphanumeric + - _ .)
/// - Lines starting with `#` are treated as comments
/// - Empty lines are ignored
/// - Inline comments (after token) are supported with `#`
pub fn load_auth_token_from_file(path: &Path) -> Result<String> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read auth token file: {}", path.display()))?;

    let mut line_num = 0;

    for line in content.lines() {
        line_num += 1;
        let line = line.trim();

        // Skip empty lines and comment lines
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Handle inline comments: take only the part before #
        let token = line.split('#').next().unwrap_or(line).trim();

        if !token.is_empty() {
            validate_token(token).with_context(|| {
                format!(
                    "Invalid token at {}:{}: '{}'",
                    path.display(),
                    line_num,
                    token
                )
            })?;
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

    // Valid 16-character test tokens
    const TOKEN_A: &str = "abcdef1234567890";
    const TOKEN_B: &str = "0987654321fedcba";
    const TOKEN_C: &str = "a1b2c3d4e5f6g7h8";

    #[test]
    fn test_validate_token_valid() {
        assert!(validate_token("abcdef1234567890").is_ok()); // 16 chars alphanumeric
        assert!(validate_token("ABCDEF1234567890").is_ok()); // 16 chars uppercase
        assert!(validate_token("abc-def_123.4567").is_ok()); // 16 chars with symbols
    }

    #[test]
    fn test_validate_token_too_short() {
        let result = validate_token("short");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("exactly 16 characters"));
    }

    #[test]
    fn test_validate_token_too_long() {
        let result = validate_token("thisistoolongtoken");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("exactly 16 characters"));
    }

    #[test]
    fn test_validate_token_invalid_chars() {
        let result = validate_token("abc@def#123$456!");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid character"));
    }

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
        writeln!(file, "{}", TOKEN_A).unwrap();
        writeln!(file, "{}  # inline comment", TOKEN_B).unwrap();
        writeln!(file, "  {}  ", TOKEN_C).unwrap();

        let result = load_auth_tokens_from_file(file.path()).unwrap();
        assert_eq!(result.len(), 3);
        assert!(result.contains(TOKEN_A));
        assert!(result.contains(TOKEN_B));
        assert!(result.contains(TOKEN_C));
    }

    #[test]
    fn test_load_from_file_invalid_token() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "short").unwrap();

        let result = load_auth_tokens_from_file(file.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_load_single_token_from_file() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "# My auth token").unwrap();
        writeln!(file, "").unwrap();
        writeln!(file, "{}  # comment", TOKEN_A).unwrap();
        writeln!(file, "{}", TOKEN_B).unwrap(); // ignored

        let result = load_auth_token_from_file(file.path()).unwrap();
        assert_eq!(result, TOKEN_A);
    }

    #[test]
    fn test_load_single_token_invalid() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "bad").unwrap();

        let result = load_auth_token_from_file(file.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_is_token_valid_empty_set_rejects_all() {
        let valid_tokens = HashSet::new();
        assert!(!is_token_valid(TOKEN_A, &valid_tokens));
    }

    #[test]
    fn test_is_token_valid_in_set() {
        let mut valid_tokens = HashSet::new();
        valid_tokens.insert(TOKEN_A.to_string());

        assert!(is_token_valid(TOKEN_A, &valid_tokens));
    }

    #[test]
    fn test_is_token_valid_not_in_set() {
        let mut valid_tokens = HashSet::new();
        valid_tokens.insert(TOKEN_A.to_string());

        assert!(!is_token_valid(TOKEN_B, &valid_tokens));
    }

    #[test]
    fn test_load_auth_tokens_cli_and_file() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "{}", TOKEN_A).unwrap();

        let cli_tokens = vec![TOKEN_B.to_string()];
        let result = load_auth_tokens(&cli_tokens, Some(file.path())).unwrap();

        assert_eq!(result.len(), 2);
        assert!(result.contains(TOKEN_A));
        assert!(result.contains(TOKEN_B));
    }

    #[test]
    fn test_load_auth_tokens_cli_invalid() {
        let cli_tokens = vec!["short".to_string()];
        let result = load_auth_tokens(&cli_tokens, None);
        assert!(result.is_err());
    }
}
