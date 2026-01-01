//! Token-based authentication for iroh tunnel connections.
//!
//! Provides pre-shared token authentication for the iroh multi-source server.
//!
//! ## Token Format
//! - Exactly 18 characters
//! - Starts with lowercase 'i' (for iroh)
//! - Ends with a checksum character
//! - Middle 16 characters: A-Za-z0-9 and - _ . (hyphen, underscore, period)
//!
//! Generate tokens with: `tunnel-rs generate-token`

use anyhow::{Context, Result};
use std::collections::HashSet;
use std::path::Path;

/// Required length for authentication tokens.
pub const TOKEN_LENGTH: usize = 18;

/// Required prefix character for tokens.
pub const TOKEN_PREFIX: char = 'i';

/// Valid characters for the token body (excludes prefix and checksum).
const VALID_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.";

/// Check if a character is valid for the token body.
/// Allowed: A-Za-z0-9 and - _ . (safe symbols that don't conflict with shell/TOML syntax)
#[inline]
fn is_valid_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.'
}

/// Calculate checksum character for a token body.
///
/// Uses a simple weighted sum algorithm to detect transposition and single-char errors.
fn calculate_checksum(body: &str) -> char {
    let sum: u32 = body
        .chars()
        .enumerate()
        .map(|(i, c)| (c as u32) * ((i as u32) + 1))
        .sum();
    let index = (sum as usize) % VALID_CHARS.len();
    VALID_CHARS[index] as char
}

/// Generate a new authentication token.
///
/// Format: 'i' + 16 random chars + checksum = 18 characters total
pub fn generate_token() -> String {
    use rand::Rng;
    let mut rng = rand::rng();

    // Generate 16 random characters for the body
    let body: String = (0..16)
        .map(|_| {
            let idx = rng.random_range(0..VALID_CHARS.len());
            VALID_CHARS[idx] as char
        })
        .collect();

    // Calculate checksum
    let checksum = calculate_checksum(&body);

    // Combine: prefix + body + checksum
    format!("{}{}{}", TOKEN_PREFIX, body, checksum)
}

/// Validate token format.
///
/// Returns Ok(()) if valid, Err with description if invalid.
pub fn validate_token(token: &str) -> Result<()> {
    // Early ASCII check - all valid tokens are ASCII
    if !token.is_ascii() {
        anyhow::bail!("Token must contain only ASCII characters");
    }

    if token.len() != TOKEN_LENGTH {
        anyhow::bail!(
            "Token must be exactly {} characters, got {} characters",
            TOKEN_LENGTH,
            token.len()
        );
    }

    // Check prefix
    if !token.starts_with(TOKEN_PREFIX) {
        anyhow::bail!(
            "Token must start with '{}', got '{}'",
            TOKEN_PREFIX,
            token.chars().next().unwrap_or('?')
        );
    }

    // Check body characters (positions 1-16)
    let body = &token[1..17];
    if let Some(invalid_char) = body.chars().find(|c| !is_valid_token_char(*c)) {
        anyhow::bail!(
            "Token contains invalid character '{}'. Allowed: A-Za-z0-9 and - _ .",
            invalid_char
        );
    }

    // Verify checksum
    let expected_checksum = calculate_checksum(body);
    let actual_checksum = token.chars().last().unwrap();
    if actual_checksum != expected_checksum {
        anyhow::bail!("Token checksum is invalid");
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
/// - One token per line (18 chars: 'i' + 16 body + checksum)
/// - Lines starting with `#` are treated as comments
/// - Empty lines are ignored
/// - Inline comments (after token) are supported with `#`
///
/// # Example file:
/// ```text
/// # Authentication tokens (generate with: tunnel-rs generate-token)
/// ikAdvudu_ZxNXhNLCD  # Client A
/// iw3nLKic3oV7zmFJ8v  # Client B
/// ```
pub fn load_auth_tokens_from_file(path: &Path) -> Result<HashSet<String>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read auth tokens file: {}", path.display()))?;

    let mut tokens = HashSet::new();

    for (line_num, line) in content.lines().enumerate() {
        let line_num = line_num + 1; // 1-based line numbers
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
/// - First non-empty, non-comment line is the token (18 chars: 'i' + 16 body + checksum)
/// - Lines starting with `#` are treated as comments
/// - Empty lines are ignored
/// - Inline comments (after token) are supported with `#`
pub fn load_auth_token_from_file(path: &Path) -> Result<String> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read auth token file: {}", path.display()))?;

    for (line_num, line) in content.lines().enumerate() {
        let line_num = line_num + 1; // 1-based line numbers
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

    // Helper to create a valid test token with known body
    fn make_test_token(body: &str) -> String {
        assert_eq!(body.len(), 16, "Test body must be 16 chars");
        let checksum = calculate_checksum(body);
        format!("{}{}{}", TOKEN_PREFIX, body, checksum)
    }

    #[test]
    fn test_generate_token_format() {
        let token = generate_token();
        assert_eq!(token.len(), TOKEN_LENGTH);
        assert!(token.starts_with(TOKEN_PREFIX));
        assert!(validate_token(&token).is_ok());
    }

    #[test]
    fn test_generate_token_uniqueness() {
        let token1 = generate_token();
        let token2 = generate_token();
        assert_ne!(token1, token2);
    }

    #[test]
    fn test_validate_token_valid() {
        let token = generate_token();
        assert!(validate_token(&token).is_ok());
    }

    #[test]
    fn test_validate_token_too_short() {
        let result = validate_token("ishort");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("exactly 18 characters"));
    }

    #[test]
    fn test_validate_token_too_long() {
        let result = validate_token("ithisistoolongtokenXX");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("exactly 18 characters"));
    }

    #[test]
    fn test_validate_token_wrong_prefix() {
        // Valid length but wrong prefix
        let result = validate_token("xABCDEF1234567890Y");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("must start with 'i'"));
    }

    #[test]
    fn test_validate_token_invalid_chars() {
        let result = validate_token("iabc@def#123$456!X");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid character"));
    }

    #[test]
    fn test_validate_token_non_ascii() {
        // Token with non-ASCII characters (emoji, accented chars)
        let result = validate_token("i🔐secret_token!");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("ASCII"));

        let result = validate_token("iàbcdéf1234567890");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("ASCII"));
    }

    #[test]
    fn test_validate_token_bad_checksum() {
        // Valid format but wrong checksum
        let result = validate_token("iABCDEF1234567890X");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("checksum"));
    }

    #[test]
    fn test_checksum_detects_changes() {
        let token = generate_token();
        // Change one character in the body
        let mut chars: Vec<char> = token.chars().collect();
        chars[5] = if chars[5] == 'a' { 'b' } else { 'a' };
        let modified: String = chars.into_iter().collect();
        assert!(validate_token(&modified).is_err());
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
        let token_a = generate_token();
        let token_b = generate_token();
        let token_c = generate_token();

        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "# Auth tokens").unwrap();
        writeln!(file, "{}", token_a).unwrap();
        writeln!(file, "{}  # inline comment", token_b).unwrap();
        writeln!(file, "  {}  ", token_c).unwrap();

        let result = load_auth_tokens_from_file(file.path()).unwrap();
        assert_eq!(result.len(), 3);
        assert!(result.contains(&token_a));
        assert!(result.contains(&token_b));
        assert!(result.contains(&token_c));
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
        let token_a = generate_token();
        let token_b = generate_token();

        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "# My auth token").unwrap();
        writeln!(file, "").unwrap();
        writeln!(file, "{}  # comment", token_a).unwrap();
        writeln!(file, "{}", token_b).unwrap(); // ignored

        let result = load_auth_token_from_file(file.path()).unwrap();
        assert_eq!(result, token_a);
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
        let token = generate_token();
        let valid_tokens = HashSet::new();
        assert!(!is_token_valid(&token, &valid_tokens));
    }

    #[test]
    fn test_is_token_valid_in_set() {
        let token = generate_token();
        let mut valid_tokens = HashSet::new();
        valid_tokens.insert(token.clone());

        assert!(is_token_valid(&token, &valid_tokens));
    }

    #[test]
    fn test_is_token_valid_not_in_set() {
        let token_a = generate_token();
        let token_b = generate_token();
        let mut valid_tokens = HashSet::new();
        valid_tokens.insert(token_a.clone());

        assert!(!is_token_valid(&token_b, &valid_tokens));
    }

    #[test]
    fn test_load_auth_tokens_cli_and_file() {
        let token_a = generate_token();
        let token_b = generate_token();

        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "{}", token_a).unwrap();

        let cli_tokens = vec![token_b.clone()];
        let result = load_auth_tokens(&cli_tokens, Some(file.path())).unwrap();

        assert_eq!(result.len(), 2);
        assert!(result.contains(&token_a));
        assert!(result.contains(&token_b));
    }

    #[test]
    fn test_load_auth_tokens_cli_invalid() {
        let cli_tokens = vec!["short".to_string()];
        let result = load_auth_tokens(&cli_tokens, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_make_test_token_helper() {
        let token = make_test_token("ABCDEF1234567890");
        assert_eq!(token.len(), 18);
        assert!(token.starts_with('i'));
        assert!(validate_token(&token).is_ok());
    }
}
