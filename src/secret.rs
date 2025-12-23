//! Secret key generation and management commands.

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use iroh::SecretKey;
use nostr_sdk::ToBech32;
use std::path::PathBuf;

use crate::endpoint::{load_secret, secret_to_endpoint_id};
use crate::manual::nostr_signaling::generate_keypair;

/// Generate a new secret key file (base64 encoded) and output the EndpointId to stdout
pub fn generate_secret(output: PathBuf, force: bool) -> Result<()> {
    let secret = SecretKey::generate(&mut rand::rng());
    let secret_base64 = BASE64.encode(secret.to_bytes());
    let endpoint_id = secret_to_endpoint_id(&secret);

    if output.to_str() == Some("-") {
        println!("{}", secret_base64);
        eprintln!("EndpointId: {}", endpoint_id);
    } else {
        if output.exists() && !force {
            anyhow::bail!(
                "File already exists: {}. Use --force to overwrite.",
                output.display()
            );
        }

        if let Some(parent) = output.parent() {
            std::fs::create_dir_all(parent).context("Failed to create parent directory")?;
        }
        std::fs::write(&output, &secret_base64).context("Failed to write secret key file")?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&output)?.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(&output, perms)?;
        }

        eprintln!("Secret key saved to: {}", output.display());
        println!("{}", endpoint_id);
    }

    Ok(())
}

/// Show the EndpointId for an existing secret key file
pub fn show_id(secret_file: PathBuf) -> Result<()> {
    let secret = load_secret(&secret_file)?;
    let endpoint_id = secret_to_endpoint_id(&secret);
    println!("{}", endpoint_id);
    Ok(())
}

/// Generate a new nostr key file (nsec) and output the npub to stdout
pub fn generate_nostr_key(output: PathBuf, force: bool) -> Result<()> {
    let keys = generate_keypair();
    let nsec = keys.secret_key().to_bech32().context("Failed to encode nsec")?;
    let npub = keys.public_key().to_bech32().context("Failed to encode npub")?;

    if output.to_str() == Some("-") {
        println!("{}", nsec);
        eprintln!("npub: {}", npub);
    } else {
        if output.exists() && !force {
            anyhow::bail!(
                "File already exists: {}. Use --force to overwrite.",
                output.display()
            );
        }

        if let Some(parent) = output.parent() {
            std::fs::create_dir_all(parent).context("Failed to create parent directory")?;
        }
        std::fs::write(&output, &nsec).context("Failed to write nsec file")?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&output)?.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(&output, perms)?;
        }

        eprintln!("nsec saved to: {}", output.display());
        println!("{}", npub);
    }

    Ok(())
}
