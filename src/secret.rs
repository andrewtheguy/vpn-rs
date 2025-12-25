//! Secret key generation and management commands.

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use iroh::SecretKey;
use log::info;
#[cfg(feature = "ice")]
use nostr_sdk::{Keys, ToBech32};
use std::path::PathBuf;

use crate::iroh::endpoint::{load_secret, secret_to_endpoint_id};
#[cfg(feature = "ice")]
use crate::signaling::nostr::generate_keypair;

fn write_secret_to_output(
    output: &PathBuf,
    secret_content: &str,
    public_info: &str,
    force: bool,
    secret_label: &str,
) -> Result<()> {
    if output.to_str() == Some("-") {
        println!("{}", secret_content);
        eprintln!("{}", public_info);
        return Ok(());
    }

    if output.exists() && !force {
        anyhow::bail!(
            "File already exists: {}. Use --force to overwrite.",
            output.display()
        );
    }

    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent).context("Failed to create parent directory")?;
    }
    std::fs::write(output, secret_content).context("Failed to write secret key file")?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(output)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(output, perms)?;
    }

    info!("{} saved to: {}", secret_label, output.display());
    println!("{}", public_info);

    Ok(())
}

/// Generate a new secret key file (base64 encoded) and output the EndpointId to stdout
pub fn generate_secret(output: PathBuf, force: bool) -> Result<()> {
    let secret = SecretKey::generate(&mut rand::rng());
    let secret_base64 = BASE64.encode(secret.to_bytes());
    let endpoint_id = secret_to_endpoint_id(&secret);
    write_secret_to_output(
        &output,
        &secret_base64,
        &format!("EndpointId: {}", endpoint_id),
        force,
        "Secret key",
    )
}

/// Show the EndpointId for an existing secret key file
pub fn show_id(secret_file: PathBuf) -> Result<()> {
    let secret = load_secret(&secret_file)?;
    let endpoint_id = secret_to_endpoint_id(&secret);
    println!("{}", endpoint_id);
    Ok(())
}

/// Show the npub for an existing nsec key file
#[cfg(feature = "ice")]
pub fn show_npub(nsec_file: PathBuf) -> Result<()> {
    let content = std::fs::read_to_string(&nsec_file)
        .with_context(|| format!("Failed to read nsec file: {}", nsec_file.display()))?;
    let nsec = content.trim();
    if nsec.is_empty() {
        anyhow::bail!("nsec file is empty: {}", nsec_file.display());
    }
    let keys = Keys::parse(nsec)
        .context("Failed to parse private key (expected nsec or hex format)")?;
    let npub = keys.public_key().to_bech32().context("Failed to encode npub")?;
    println!("{}", npub);
    Ok(())
}

/// Generate a new nostr key file (nsec) and output the npub to stdout
#[cfg(feature = "ice")]
pub fn generate_nostr_key(output: PathBuf, force: bool) -> Result<()> {
    let keys = generate_keypair();
    let nsec = keys.secret_key().to_bech32().context("Failed to encode nsec")?;
    let npub = keys.public_key().to_bech32().context("Failed to encode npub")?;
    write_secret_to_output(
        &output,
        &nsec,
        &format!("npub: {}", npub),
        force,
        "nsec",
    )
}
