//! Secret key generation and management commands (nostr).

use anyhow::{Context, Result};
use log::info;
use nostr_sdk::{Keys, ToBech32};
use std::path::PathBuf;

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

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(output)
            .context("Failed to open secret key file")?;
        file.write_all(secret_content.as_bytes())
            .context("Failed to write secret key file")?;
    }

    #[cfg(not(unix))]
    {
        std::fs::write(output, secret_content).context("Failed to write secret key file")?;
    }

    info!("{} saved to: {}", secret_label, output.display());
    println!("{}", public_info);

    Ok(())
}

/// Show the npub for an existing nsec key file
pub fn show_npub(nsec_file: PathBuf) -> Result<()> {
    let content = std::fs::read_to_string(&nsec_file)
        .with_context(|| format!("Failed to read nsec file: {}", nsec_file.display()))?;
    let nsec = content.trim();
    if nsec.is_empty() {
        anyhow::bail!("nsec file is empty: {}", nsec_file.display());
    }
    let keys =
        Keys::parse(nsec).context("Failed to parse private key (expected nsec or hex format)")?;
    let npub = keys
        .public_key()
        .to_bech32()
        .context("Failed to encode npub")?;
    println!("{}", npub);
    Ok(())
}

/// Generate a new nostr key file (nsec) and output the npub to stdout
pub fn generate_nostr_key(output: PathBuf, force: bool) -> Result<()> {
    let keys = generate_keypair();
    let nsec = keys
        .secret_key()
        .to_bech32()
        .context("Failed to encode nsec")?;
    let npub = keys
        .public_key()
        .to_bech32()
        .context("Failed to encode npub")?;
    write_secret_to_output(&output, &nsec, &format!("npub: {}", npub), force, "nsec")
}
