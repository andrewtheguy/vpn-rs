//! Authentication module for iroh tunnel connections.
//!
//! Provides NodeId-based whitelist authentication for the iroh multi-source server.

use anyhow::{Context, Result};
use iroh::EndpointId;
use std::collections::HashSet;
use std::path::Path;

/// Load allowed client NodeIds from CLI arguments and/or a file.
///
/// # Arguments
/// * `cli_clients` - NodeIds specified via CLI `--allowed-clients` flags
/// * `file` - Optional path to a file containing NodeIds (one per line)
///
/// # Returns
/// A HashSet of all allowed EndpointIds
///
/// # Errors
/// Returns an error if any NodeId fails to parse or if the file cannot be read
pub fn load_allowed_clients(
    cli_clients: &[String],
    file: Option<&Path>,
) -> Result<HashSet<EndpointId>> {
    let mut allowed = HashSet::new();

    // Load from CLI arguments
    for node_id_str in cli_clients {
        let endpoint_id = parse_node_id(node_id_str.trim())
            .with_context(|| format!("Invalid --allowed-clients value: {}", node_id_str))?;
        allowed.insert(endpoint_id);
    }

    // Load from file if specified
    if let Some(file_path) = file {
        let file_clients = load_allowed_clients_from_file(file_path)?;
        allowed.extend(file_clients);
    }

    Ok(allowed)
}

/// Load allowed client NodeIds from a file.
///
/// # File Format
/// - One NodeId per line
/// - Lines starting with `#` are treated as comments
/// - Empty lines are ignored
/// - Inline comments (after NodeId) are supported with `#`
///
/// # Example file:
/// ```text
/// # Allowed clients
/// 2o3hsjnj3k4h5k6h7j8k9l0m1n2o3p4q5r6s7t8u9v0w1x2y3z4a5b  # Alice
/// 3k4j5l6k7j8k9l0m1n2o3p4q5r6s7t8u9v0w1x2y3z4a5b6c7d8e9f  # Bob
/// ```
pub fn load_allowed_clients_from_file(path: &Path) -> Result<HashSet<EndpointId>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read allowed clients file: {}", path.display()))?;

    let mut allowed = HashSet::new();

    for (line_num, line) in content.lines().enumerate() {
        let line = line.trim();

        // Skip empty lines and comment lines
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        // Handle inline comments: take only the part before #
        let node_id_str = line.split('#').next().unwrap_or(line).trim();

        if node_id_str.is_empty() {
            continue;
        }

        let endpoint_id = parse_node_id(node_id_str).with_context(|| {
            format!(
                "Invalid NodeId at {}:{}: {}",
                path.display(),
                line_num + 1,
                node_id_str
            )
        })?;

        allowed.insert(endpoint_id);
    }

    Ok(allowed)
}

/// Parse a NodeId string to an EndpointId.
///
/// NodeIds are 52-character base32-encoded Ed25519 public keys.
pub fn parse_node_id(s: &str) -> Result<EndpointId> {
    s.parse::<EndpointId>()
        .map_err(|e| anyhow::anyhow!("Invalid NodeId '{}': {}", s, e))
}

/// Check if a remote NodeId is in the allowed set.
///
/// Authentication is required - returns true only if the remote_id is in the allowed set.
/// An empty allowed set means no clients are authorized.
#[inline]
pub fn is_client_allowed(remote_id: &EndpointId, allowed: &HashSet<EndpointId>) -> bool {
    allowed.contains(remote_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_parse_node_id_invalid() {
        assert!(parse_node_id("invalid").is_err());
        assert!(parse_node_id("").is_err());
        assert!(parse_node_id("too_short").is_err());
    }

    #[test]
    fn test_load_from_file_with_comments() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "# This is a comment").unwrap();
        writeln!(file, "").unwrap();
        writeln!(file, "  # Another comment with leading space").unwrap();

        let result = load_allowed_clients_from_file(file.path()).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_is_client_allowed_empty_set_rejects_all() {
        let allowed = HashSet::new();
        // Generate a test EndpointId
        let secret = iroh::SecretKey::generate(&mut rand::rng());
        let id = secret.public();

        // Empty set means no clients are authorized (authentication is required)
        assert!(!is_client_allowed(&id, &allowed));
    }

    #[test]
    fn test_is_client_allowed_in_set() {
        let secret = iroh::SecretKey::generate(&mut rand::rng());
        let id = secret.public();

        let mut allowed = HashSet::new();
        allowed.insert(id);

        assert!(is_client_allowed(&id, &allowed));
    }

    #[test]
    fn test_is_client_allowed_not_in_set() {
        let secret1 = iroh::SecretKey::generate(&mut rand::rng());
        let secret2 = iroh::SecretKey::generate(&mut rand::rng());
        let id1 = secret1.public();
        let id2 = secret2.public();

        let mut allowed = HashSet::new();
        allowed.insert(id1);

        assert!(!is_client_allowed(&id2, &allowed));
    }
}
