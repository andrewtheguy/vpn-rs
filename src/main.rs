//! tunnel-rs
//!
//! Forwards TCP or UDP traffic through P2P connections.
//!
//! Four modes are available:
//!   - iroh-default: Uses iroh P2P discovery with relay fallback
//!   - iroh-manual:  Uses iroh with STUN-based manual signaling
//!   - custom:       Uses full ICE with manual signaling (best NAT traversal)
//!   - nostr:        Uses full ICE with Nostr-based signaling
//!
//! Usage:
//!   tunnel-rs sender iroh-default --source tcp://127.0.0.1:22
//!   tunnel-rs sender iroh-manual --source tcp://127.0.0.1:22
//!   tunnel-rs sender custom --source tcp://127.0.0.1:22
//!   tunnel-rs sender nostr --source tcp://127.0.0.1:22 --nsec <NSEC> --peer-npub <NPUB>
//!   tunnel-rs receiver iroh-default --node-id <NODE_ID> --target tcp://127.0.0.1:2222
//!   tunnel-rs receiver iroh-manual --target tcp://127.0.0.1:2222
//!   tunnel-rs receiver custom --target tcp://127.0.0.1:2222
//!   tunnel-rs receiver nostr --target tcp://127.0.0.1:2222 --nsec <NSEC> --peer-npub <NPUB>

mod config;
mod endpoint;
mod manual;
mod secret;
mod tunnel;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use config::{default_stun_servers, load_receiver_config, load_sender_config, ReceiverConfig, SenderConfig};
use nostr_sdk::ToBech32;
use std::path::PathBuf;

#[derive(Clone, Copy, ValueEnum, Default, Debug, PartialEq)]
pub enum Protocol {
    /// TCP tunneling
    #[default]
    Tcp,
    /// UDP tunneling
    Udp,
}

impl Protocol {
    fn from_str_opt(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "tcp" => Some(Protocol::Tcp),
            "udp" => Some(Protocol::Udp),
            _ => None,
        }
    }
}

fn parse_endpoint(value: &str) -> Result<(Protocol, String)> {
    let (scheme, addr) = value
        .split_once("://")
        .context("Expected endpoint in the form tcp://host:port or udp://host:port")?;
    if addr.is_empty() {
        anyhow::bail!("Endpoint is missing host:port (got '{}')", value);
    }
    if addr.contains('/') {
        anyhow::bail!("Endpoint must not include a path (got '{}')", value);
    }
    let protocol = Protocol::from_str_opt(scheme).context(
        "Invalid scheme. Use tcp://host:port or udp://host:port",
    )?;
    Ok((protocol, addr.to_string()))
}

fn normalize_optional_endpoint(value: Option<String>) -> Option<String> {
    value.and_then(|v| {
        if v.trim().is_empty() {
            None
        } else {
            Some(v)
        }
    })
}

// STUN precedence: --no-stun disables STUN entirely (CLI only). Otherwise, CLI list wins;
// config list wins next (even if empty, which disables STUN); if nothing specified, fall
// back to default public STUN servers.
fn resolve_stun_servers(
    cli_stun_servers: &[String],
    config_stun_servers: Option<Vec<String>>,
    no_stun: bool,
) -> Result<Vec<String>> {
    if no_stun {
        if !cli_stun_servers.is_empty() {
            anyhow::bail!("Cannot combine --no-stun with --stun-server");
        }
        return Ok(Vec::new());
    }
    if !cli_stun_servers.is_empty() {
        return Ok(cli_stun_servers.to_vec());
    }
    if let Some(servers) = config_stun_servers {
        return Ok(servers);
    }
    Ok(default_stun_servers())
}

#[derive(Parser)]
#[command(name = "tunnel-rs")]
#[command(version)]
#[command(about = "Forward TCP/UDP traffic through P2P connections")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run as sender (accepts connections and forwards to source)
    #[command(subcommand_negates_reqs = true)]
    Sender {
        /// Path to config file
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Load config from default location (~/.config/tunnel-rs/sender.toml)
        #[arg(long)]
        default_config: bool,

        #[command(subcommand)]
        mode: Option<SenderMode>,
    },
    /// Run as receiver (connects to sender and exposes local port)
    #[command(subcommand_negates_reqs = true)]
    Receiver {
        /// Path to config file
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Load config from default location (~/.config/tunnel-rs/receiver.toml)
        #[arg(long)]
        default_config: bool,

        #[command(subcommand)]
        mode: Option<ReceiverMode>,
    },
    /// Generate a new secret key file (for automation/setup)
    GenerateSecret {
        /// Path where to save the secret key file
        #[arg(short, long)]
        output: PathBuf,

        /// Overwrite existing file if it exists
        #[arg(long)]
        force: bool,
    },
    /// Show the EndpointId (node ID) for an existing secret key file
    ShowId {
        /// Path to the secret key file
        #[arg(short, long)]
        secret_file: PathBuf,
    },
    /// Generate a Nostr keypair for use with nostr mode
    GenerateNostrKey,
}

#[derive(Subcommand)]
enum SenderMode {
    /// Use iroh with automatic discovery (Pkarr/DNS/mDNS) and relay fallback
    #[command(name = "iroh-default")]
    IrohDefault {
        /// Source address to forward traffic to (tcp://host:port or udp://host:port)
        #[arg(short, long)]
        source: Option<String>,

        /// Path to secret key file for persistent identity
        #[arg(long)]
        secret_file: Option<PathBuf>,

        /// Custom relay server URL(s) for failover
        #[arg(long = "relay-url")]
        relay_urls: Vec<String>,

        /// Force all connections through the relay server (disables direct P2P)
        #[arg(long)]
        relay_only: bool,

        /// Custom DNS server URL for peer discovery
        #[arg(long)]
        dns_server: Option<String>,
    },
    /// Use iroh with STUN-based manual signaling (may fail on symmetric NAT)
    #[command(name = "iroh-manual")]
    IrohManual {
        /// Source address to forward traffic to (tcp://host:port or udp://host:port)
        #[arg(short, long)]
        source: Option<String>,

        /// STUN server (repeatable, e.g., stun.l.google.com:19302)
        #[arg(long = "stun-server")]
        stun_servers: Vec<String>,

        /// Disable STUN (no external infrastructure)
        #[arg(long)]
        no_stun: bool,
    },
    /// Full ICE with manual signaling - best NAT traversal (str0m+quinn)
    Custom {
        /// Source address to forward traffic to (tcp://host:port or udp://host:port)
        #[arg(short, long)]
        source: Option<String>,

        /// STUN server (repeatable, e.g., stun.l.google.com:19302)
        #[arg(long = "stun-server")]
        stun_servers: Vec<String>,

        /// Disable STUN (no external infrastructure)
        #[arg(long)]
        no_stun: bool,
    },
    /// Full ICE with Nostr-based signaling (WireGuard-like static keys)
    Nostr {
        /// Source address to forward traffic to (tcp://host:port or udp://host:port)
        #[arg(short, long)]
        source: Option<String>,

        /// Your Nostr private key (nsec or hex format)
        #[arg(long)]
        nsec: Option<String>,

        /// Peer's Nostr public key (npub or hex format)
        #[arg(long)]
        peer_npub: Option<String>,

        /// Nostr relay URL (repeatable)
        #[arg(long = "relay")]
        relays: Vec<String>,

        /// STUN server (repeatable, e.g., stun.l.google.com:19302)
        #[arg(long = "stun-server")]
        stun_servers: Vec<String>,

        /// Disable STUN (no external infrastructure)
        #[arg(long)]
        no_stun: bool,

        /// Interval in seconds to re-publish offer while waiting for answer (default: 10)
        #[arg(long, default_value = "10")]
        republish_interval: u64,

        /// Maximum time in seconds to wait for answer before giving up (default: 120)
        #[arg(long, default_value = "120")]
        max_wait: u64,
    },
}

#[derive(Subcommand)]
enum ReceiverMode {
    /// Use iroh with automatic discovery (Pkarr/DNS/mDNS) and relay fallback
    #[command(name = "iroh-default")]
    IrohDefault {
        /// EndpointId of the sender to connect to
        #[arg(short, long)]
        node_id: Option<String>,

        /// Local address to listen on (tcp://host:port or udp://host:port)
        #[arg(short, long)]
        target: Option<String>,

        /// Custom relay server URL(s) for failover
        #[arg(long = "relay-url")]
        relay_urls: Vec<String>,

        /// Force all connections through the relay server (disables direct P2P)
        #[arg(long)]
        relay_only: bool,

        /// Custom DNS server URL for peer discovery
        #[arg(long)]
        dns_server: Option<String>,
    },
    /// Use iroh with STUN-based manual signaling (may fail on symmetric NAT)
    #[command(name = "iroh-manual")]
    IrohManual {
        /// Local address to listen on (tcp://host:port or udp://host:port)
        #[arg(short, long)]
        target: Option<String>,

        /// STUN server (repeatable, e.g., stun.l.google.com:19302)
        #[arg(long = "stun-server")]
        stun_servers: Vec<String>,

        /// Disable STUN (no external infrastructure)
        #[arg(long)]
        no_stun: bool,
    },
    /// Full ICE with manual signaling - best NAT traversal (str0m+quinn)
    Custom {
        /// Local address to listen on (tcp://host:port or udp://host:port)
        #[arg(short, long)]
        target: Option<String>,

        /// STUN server (repeatable, e.g., stun.l.google.com:19302)
        #[arg(long = "stun-server")]
        stun_servers: Vec<String>,

        /// Disable STUN (no external infrastructure)
        #[arg(long)]
        no_stun: bool,
    },
    /// Full ICE with Nostr-based signaling (WireGuard-like static keys)
    Nostr {
        /// Local address to listen on (tcp://host:port or udp://host:port, or host:port for TCP, e.g., tcp://127.0.0.1:2222)
        #[arg(short, long)]
        target: Option<String>,

        /// Your Nostr private key (nsec or hex format)
        #[arg(long)]
        nsec: Option<String>,

        /// Peer's Nostr public key (npub or hex format)
        #[arg(long)]
        peer_npub: Option<String>,

        /// Nostr relay URL (repeatable)
        #[arg(long = "relay")]
        relays: Vec<String>,

        /// STUN server (repeatable, e.g., stun.l.google.com:19302)
        #[arg(long = "stun-server")]
        stun_servers: Vec<String>,

        /// Disable STUN (no external infrastructure)
        #[arg(long)]
        no_stun: bool,
    },
}

/// Load sender config based on flags. Returns (config, was_loaded_from_file).
fn resolve_sender_config(
    config: Option<PathBuf>,
    default_config: bool,
) -> Result<(SenderConfig, bool)> {
    if config.is_some() && default_config {
        anyhow::bail!("Cannot use both -c/--config and --default-config");
    }

    if let Some(path) = config {
        Ok((load_sender_config(Some(&path))?, true))
    } else if default_config {
        Ok((load_sender_config(None)?, true))
    } else {
        Ok((SenderConfig::default(), false))
    }
}

/// Load receiver config based on flags. Returns (config, was_loaded_from_file).
fn resolve_receiver_config(
    config: Option<PathBuf>,
    default_config: bool,
) -> Result<(ReceiverConfig, bool)> {
    if config.is_some() && default_config {
        anyhow::bail!("Cannot use both -c/--config and --default-config");
    }

    if let Some(path) = config {
        Ok((load_receiver_config(Some(&path))?, true))
    } else if default_config {
        Ok((load_receiver_config(None)?, true))
    } else {
        Ok((ReceiverConfig::default(), false))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    match args.command {
        Command::Sender {
            config,
            default_config,
            mode,
        } => {
            let (cfg, from_file) = resolve_sender_config(config.clone(), default_config)?;

            // Determine effective mode: CLI mode takes precedence, else read from config
            let effective_mode = match (&mode, &cfg.mode) {
                (Some(_), _) => mode.as_ref().map(|m| match m {
                    SenderMode::IrohDefault { .. } => "iroh-default",
                    SenderMode::IrohManual { .. } => "iroh-manual",
                    SenderMode::Custom { .. } => "custom",
                    SenderMode::Nostr { .. } => "nostr",
                }),
                (None, Some(m)) => Some(m.as_str()),
                (None, None) => None,
            };

            let effective_mode = effective_mode.context(
                "No mode specified. Either use a subcommand (iroh-default, iroh-manual, custom, nostr) or provide a config file with 'mode' field.",
            )?;

            // Validate config if loaded from file
            if from_file {
                cfg.validate(effective_mode)?;
            }

            // Get common values from config
            let source = normalize_optional_endpoint(cfg.source.clone());

            match effective_mode {
                "iroh-default" => {
                    let iroh_cfg = cfg.iroh_default();
                    // Override with CLI values if provided
                    let (source, secret_file, relay_urls, relay_only, dns_server) = match &mode {
                        Some(SenderMode::IrohDefault { source: s, secret_file: sf, relay_urls: r, relay_only: ro, dns_server: d }) => (
                            normalize_optional_endpoint(s.clone()).or(source),
                            sf.clone().or_else(|| iroh_cfg.and_then(|c| c.secret_file.clone())),
                            if r.is_empty() { iroh_cfg.and_then(|c| c.relay_urls.clone()).unwrap_or_default() } else { r.clone() },
                            *ro || iroh_cfg.and_then(|c| c.relay_only).unwrap_or(false),
                            d.clone().or_else(|| iroh_cfg.and_then(|c| c.dns_server.clone())),
                        ),
                        _ => (
                            source,
                            iroh_cfg.and_then(|c| c.secret_file.clone()),
                            iroh_cfg.and_then(|c| c.relay_urls.clone()).unwrap_or_default(),
                            iroh_cfg.and_then(|c| c.relay_only).unwrap_or(false),
                            iroh_cfg.and_then(|c| c.dns_server.clone()),
                        ),
                    };

                    let source = source.context(
                        "source is required. Provide via --source or in config file.",
                    )?;

                    let (protocol, target) = parse_endpoint(&source)
                        .with_context(|| format!("Invalid sender source '{}'", source))?;

                    match protocol {
                        Protocol::Udp => tunnel::run_udp_sender(target, secret_file, relay_urls, relay_only, dns_server).await,
                        Protocol::Tcp => tunnel::run_tcp_sender(target, secret_file, relay_urls, relay_only, dns_server).await,
                    }
                }
                "iroh-manual" => {
                    let manual_cfg = cfg.iroh_manual();
                    let (source, stun_servers) = match &mode {
                        Some(SenderMode::IrohManual { source: s, stun_servers: ss, no_stun }) => (
                            normalize_optional_endpoint(s.clone()).or(source),
                            resolve_stun_servers(ss, manual_cfg.and_then(|c| c.stun_servers.clone()), *no_stun)?,
                        ),
                        _ => (source, resolve_stun_servers(&[], manual_cfg.and_then(|c| c.stun_servers.clone()), false)?),
                    };

                    let source = source.context(
                        "source is required. Provide via --source or in config file.",
                    )?;

                    let (protocol, target) = parse_endpoint(&source)
                        .with_context(|| format!("Invalid sender source '{}'", source))?;

                    match protocol {
                        Protocol::Udp => tunnel::run_iroh_manual_udp_sender(target, stun_servers).await,
                        Protocol::Tcp => tunnel::run_iroh_manual_tcp_sender(target, stun_servers).await,
                    }
                }
                "custom" => {
                    let custom_cfg = cfg.custom();
                    let (source, stun_servers) = match &mode {
                        Some(SenderMode::Custom { source: s, stun_servers: ss, no_stun }) => (
                            normalize_optional_endpoint(s.clone()).or(source),
                            resolve_stun_servers(ss, custom_cfg.and_then(|c| c.stun_servers.clone()), *no_stun)?,
                        ),
                        _ => (source, resolve_stun_servers(&[], custom_cfg.and_then(|c| c.stun_servers.clone()), false)?),
                    };

                    let source = source.context(
                        "source is required. Provide via --source or in config file.",
                    )?;

                    let (protocol, target) = parse_endpoint(&source)
                        .with_context(|| format!("Invalid sender source '{}'", source))?;

                    match protocol {
                        Protocol::Udp => tunnel::run_manual_udp_sender(target, stun_servers).await,
                        Protocol::Tcp => tunnel::run_manual_tcp_sender(target, stun_servers).await,
                    }
                }
                "nostr" => {
                    let nostr_cfg = cfg.nostr();
                    let (source, stun_servers, nsec, peer_npub, relays, republish_interval, max_wait) = match &mode {
                        Some(SenderMode::Nostr { source: s, stun_servers: ss, no_stun, nsec: n, peer_npub: p, relays: r, republish_interval: ri, max_wait: mw }) => (
                            normalize_optional_endpoint(s.clone()).or(source),
                            resolve_stun_servers(ss, nostr_cfg.and_then(|c| c.stun_servers.clone()), *no_stun)?,
                            n.clone().or_else(|| nostr_cfg.and_then(|c| c.nsec.clone())),
                            p.clone().or_else(|| nostr_cfg.and_then(|c| c.peer_npub.clone())),
                            if r.is_empty() { nostr_cfg.and_then(|c| c.relays.clone()).unwrap_or_default() } else { r.clone() },
                            *ri,
                            *mw,
                        ),
                        _ => (
                            source,
                            resolve_stun_servers(&[], nostr_cfg.and_then(|c| c.stun_servers.clone()), false)?,
                            nostr_cfg.and_then(|c| c.nsec.clone()),
                            nostr_cfg.and_then(|c| c.peer_npub.clone()),
                            nostr_cfg.and_then(|c| c.relays.clone()).unwrap_or_default(),
                            10, // default republish interval
                            120, // default max wait
                        ),
                    };

                    let source = source.context(
                        "source is required. Provide via --source or in config file.",
                    )?;
                    let nsec = nsec.context(
                        "nsec is required. Provide via --nsec or in config file. Use 'tunnel-rs generate-nostr-key' to create one.",
                    )?;
                    let peer_npub = peer_npub.context(
                        "peer-npub is required. Provide via --peer-npub or in config file.",
                    )?;
                    if relays.is_empty() {
                        anyhow::bail!("At least one relay is required. Provide via --relay or in config file.");
                    }

                    let (protocol, target) = parse_endpoint(&source)
                        .with_context(|| format!("Invalid sender source '{}'", source))?;

                    match protocol {
                        Protocol::Udp => tunnel::run_nostr_udp_sender(target, stun_servers, nsec, peer_npub, relays, republish_interval, max_wait).await,
                        Protocol::Tcp => tunnel::run_nostr_tcp_sender(target, stun_servers, nsec, peer_npub, relays, republish_interval, max_wait).await,
                    }
                }
                _ => anyhow::bail!("Invalid mode '{}'. Use: iroh-default, iroh-manual, custom, or nostr", effective_mode),
            }
        }
        Command::Receiver {
            config,
            default_config,
            mode,
        } => {
            let (cfg, from_file) = resolve_receiver_config(config, default_config)?;

            // Determine effective mode: CLI mode takes precedence, else read from config
            let effective_mode = match (&mode, &cfg.mode) {
                (Some(_), _) => mode.as_ref().map(|m| match m {
                    ReceiverMode::IrohDefault { .. } => "iroh-default",
                    ReceiverMode::IrohManual { .. } => "iroh-manual",
                    ReceiverMode::Custom { .. } => "custom",
                    ReceiverMode::Nostr { .. } => "nostr",
                }),
                (None, Some(m)) => Some(m.as_str()),
                (None, None) => None,
            };

            let effective_mode = effective_mode.context(
                "No mode specified. Either use a subcommand (iroh-default, iroh-manual, custom, nostr) or provide a config file with 'mode' field.",
            )?;

            // Validate config if loaded from file
            if from_file {
                cfg.validate(effective_mode)?;
            }

            // Get common values from config
            let target = normalize_optional_endpoint(cfg.target.clone());

            match effective_mode {
                "iroh-default" => {
                    let iroh_cfg = cfg.iroh_default();
                    // Override with CLI values if provided
                    let (node_id, target, relay_urls, relay_only, dns_server) = match &mode {
                        Some(ReceiverMode::IrohDefault { node_id: n, target: t, relay_urls: r, relay_only: ro, dns_server: d }) => (
                            n.clone().or_else(|| iroh_cfg.and_then(|c| c.node_id.clone())),
                            normalize_optional_endpoint(t.clone()).or(target),
                            if r.is_empty() { iroh_cfg.and_then(|c| c.relay_urls.clone()).unwrap_or_default() } else { r.clone() },
                            *ro || iroh_cfg.and_then(|c| c.relay_only).unwrap_or(false),
                            d.clone().or_else(|| iroh_cfg.and_then(|c| c.dns_server.clone())),
                        ),
                        _ => (
                            iroh_cfg.and_then(|c| c.node_id.clone()),
                            target,
                            iroh_cfg.and_then(|c| c.relay_urls.clone()).unwrap_or_default(),
                            iroh_cfg.and_then(|c| c.relay_only).unwrap_or(false),
                            iroh_cfg.and_then(|c| c.dns_server.clone()),
                        ),
                    };

                    let node_id = node_id.context(
                        "node_id is required. Provide via --node-id or in config file.",
                    )?;
                    let target = target.context(
                        "target is required. Provide via --target or in config file.",
                    )?;

                    let (protocol, listen) = parse_endpoint(&target)
                        .with_context(|| format!("Invalid receiver target '{}'", target))?;

                    match protocol {
                        Protocol::Udp => tunnel::run_udp_receiver(node_id, listen, relay_urls, relay_only, dns_server).await,
                        Protocol::Tcp => tunnel::run_tcp_receiver(node_id, listen, relay_urls, relay_only, dns_server).await,
                    }
                }
                "iroh-manual" => {
                    let manual_cfg = cfg.iroh_manual();
                    let (target, stun_servers) = match &mode {
                        Some(ReceiverMode::IrohManual { target: t, stun_servers: s, no_stun }) => (
                            normalize_optional_endpoint(t.clone()).or(target),
                            resolve_stun_servers(s, manual_cfg.and_then(|c| c.stun_servers.clone()), *no_stun)?,
                        ),
                        _ => (target, resolve_stun_servers(&[], manual_cfg.and_then(|c| c.stun_servers.clone()), false)?),
                    };

                    let target: String = target.context(
                        "target is required. Provide via --target or in config file.",
                    )?;

                    let (protocol, listen) = parse_endpoint(&target)
                        .with_context(|| format!("Invalid receiver target '{}'", target))?;

                    match protocol {
                        Protocol::Udp => tunnel::run_iroh_manual_udp_receiver(listen, stun_servers).await,
                        Protocol::Tcp => tunnel::run_iroh_manual_tcp_receiver(listen, stun_servers).await,
                    }
                }
                "custom" => {
                    let custom_cfg = cfg.custom();
                    let (target, stun_servers) = match &mode {
                        Some(ReceiverMode::Custom { target: t, stun_servers: s, no_stun }) => (
                            normalize_optional_endpoint(t.clone()).or(target),
                            resolve_stun_servers(s, custom_cfg.and_then(|c| c.stun_servers.clone()), *no_stun)?,
                        ),
                        _ => (target, resolve_stun_servers(&[], custom_cfg.and_then(|c| c.stun_servers.clone()), false)?),
                    };

                    let target: String = target.context(
                        "target is required. Provide via --target or in config file.",
                    )?;

                    let (protocol, listen) = parse_endpoint(&target)
                        .with_context(|| format!("Invalid receiver target '{}'", target))?;

                    match protocol {
                        Protocol::Udp => tunnel::run_manual_udp_receiver(listen, stun_servers).await,
                        Protocol::Tcp => tunnel::run_manual_tcp_receiver(listen, stun_servers).await,
                    }
                }
                "nostr" => {
                    let nostr_cfg = cfg.nostr();
                    let (target, stun_servers, nsec, peer_npub, relays) = match &mode {
                        Some(ReceiverMode::Nostr { target: t, stun_servers: ss, no_stun, nsec: n, peer_npub: p, relays: r }) => (
                            normalize_optional_endpoint(t.clone()).or(target),
                            resolve_stun_servers(ss, nostr_cfg.and_then(|c| c.stun_servers.clone()), *no_stun)?,
                            n.clone().or_else(|| nostr_cfg.and_then(|c| c.nsec.clone())),
                            p.clone().or_else(|| nostr_cfg.and_then(|c| c.peer_npub.clone())),
                            if r.is_empty() { nostr_cfg.and_then(|c| c.relays.clone()).unwrap_or_default() } else { r.clone() },
                        ),
                        _ => (
                            target,
                            resolve_stun_servers(&[], nostr_cfg.and_then(|c| c.stun_servers.clone()), false)?,
                            nostr_cfg.and_then(|c| c.nsec.clone()),
                            nostr_cfg.and_then(|c| c.peer_npub.clone()),
                            nostr_cfg.and_then(|c| c.relays.clone()).unwrap_or_default(),
                        ),
                    };

                    let target = target.context(
                        "target is required. Provide via --target or in config file.",
                    )?;
                    let nsec = nsec.context(
                        "nsec is required. Provide via --nsec or in config file. Use 'tunnel-rs generate-nostr-key' to create one.",
                    )?;
                    let peer_npub = peer_npub.context(
                        "peer-npub is required. Provide via --peer-npub or in config file.",
                    )?;
                    if relays.is_empty() {
                        anyhow::bail!("At least one relay is required. Provide via --relay or in config file.");
                    }

                    // For nostr mode, target is just host:port (no protocol prefix)
                    let listen = target;

                    // Determine protocol from config or default to TCP
                    // In nostr mode we support both TCP and UDP via the target format
                    if listen.contains("://") {
                        let (protocol, addr) = parse_endpoint(&listen)
                            .with_context(|| format!("Invalid receiver target '{}'", listen))?;
                        match protocol {
                            Protocol::Udp => tunnel::run_nostr_udp_receiver(addr, stun_servers, nsec, peer_npub, relays).await,
                            Protocol::Tcp => tunnel::run_nostr_tcp_receiver(addr, stun_servers, nsec, peer_npub, relays).await,
                        }
                    } else {
                        // Default to TCP if no protocol specified
                        tunnel::run_nostr_tcp_receiver(listen, stun_servers, nsec, peer_npub, relays).await
                    }
                }
                _ => anyhow::bail!("Invalid mode '{}'. Use: iroh-default, iroh-manual, custom, or nostr", effective_mode),
            }
        }
        Command::GenerateSecret { output, force } => secret::generate_secret(output, force),
        Command::ShowId { secret_file } => secret::show_id(secret_file),
        Command::GenerateNostrKey => {
            use crate::manual::nostr_signaling::generate_keypair;
            let keys = generate_keypair();
            let nsec = keys.secret_key().to_bech32().context("Failed to encode nsec")?;
            let npub = keys.public_key().to_bech32().context("Failed to encode npub")?;
            println!("Nostr Keypair Generated");
            println!("========================");
            println!("Private key (nsec): {}", nsec);
            println!("Public key (npub):  {}", npub);
            println!();
            println!("Add to config file:");
            println!("[nostr]");
            println!("nsec = \"{}\"", nsec);
            println!("peer_npub = \"<peer's npub>\"");
            println!();
            println!("Or use CLI arguments:");
            println!("  --nsec {} \\", nsec);
            println!("  --peer-npub <peer's npub>");
            Ok(())
        }
    }
}
