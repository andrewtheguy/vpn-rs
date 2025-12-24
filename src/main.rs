//! tunnel-rs
//!
//! Forwards TCP or UDP traffic through P2P connections.
//! All modes use client-initiated source requests for consistent UX.
//!
//! Modes:
//!   - iroh:         Automatic iroh P2P discovery with relay fallback
//!   - iroh-manual:  Iroh with manual copy-paste signaling (client-first)
//!   - custom-manual: Full ICE with manual signaling (best NAT traversal)
//!   - nostr:        Full ICE with Nostr-based signaling
//!
//! Usage (iroh - automatic discovery):
//!   tunnel-rs server iroh --allowed-tcp 127.0.0.0/8 --allowed-udp 10.0.0.0/8
//!   tunnel-rs client iroh --node-id <NODE_ID> --source tcp://127.0.0.1:22 --target 127.0.0.1:2222
//!
//! Usage (manual modes - copy-paste signaling):
//!   tunnel-rs client iroh-manual --source tcp://127.0.0.1:22 --target 127.0.0.1:2222
//!   tunnel-rs server iroh-manual --allowed-tcp 127.0.0.0/8
//!
//!   tunnel-rs client custom-manual --source tcp://127.0.0.1:22 --target 127.0.0.1:2222
//!   tunnel-rs server custom-manual --allowed-tcp 127.0.0.0/8
//!
//! Usage (nostr - automated signaling):
//!   tunnel-rs server nostr --allowed-tcp 127.0.0.0/8 --nsec <NSEC> --peer-npub <NPUB>
//!   tunnel-rs client nostr --source tcp://127.0.0.1:22 --target 127.0.0.1:2222 --nsec <NSEC> --peer-npub <NPUB>

use tunnel_rs::config;
use tunnel_rs::custom;
use tunnel_rs::iroh;
use tunnel_rs::nostr;
use tunnel_rs::secret;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use config::{
    default_stun_servers, load_client_config, load_server_config, ClientConfig, ServerConfig,
};
use ::iroh::SecretKey;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;

use crate::iroh::endpoint::{load_secret, load_secret_from_string, secret_to_endpoint_id};

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

fn resolve_iroh_secret(
    secret: Option<String>,
    secret_file: Option<PathBuf>,
) -> Result<Option<SecretKey>> {
    match (secret, secret_file) {
        (Some(_), Some(_)) => {
            anyhow::bail!("Cannot combine --secret with --secret-file (or secret and secret_file in config).");
        }
        (Some(secret), None) => {
            let trimmed = secret.trim();
            if trimmed.is_empty() {
                anyhow::bail!("Inline secret is empty. Provide a base64-encoded secret key.");
            }
            let secret = load_secret_from_string(trimmed)
                .context("Invalid inline secret key (expected base64)")?;
            let endpoint_id = secret_to_endpoint_id(&secret);
            log::info!("Loaded identity from inline secret");
            log::info!("EndpointId: {}", endpoint_id);
            Ok(Some(secret))
        }
        (None, Some(path)) => {
            let secret = load_secret(&path)?;
            let endpoint_id = secret_to_endpoint_id(&secret);
            log::info!("Loaded identity from: {}", path.display());
            log::info!("EndpointId: {}", endpoint_id);
            Ok(Some(secret))
        }
        (None, None) => Ok(None),
    }
}

fn resolve_nostr_nsec(
    nsec: Option<String>,
    nsec_file: Option<PathBuf>,
) -> Result<Option<String>> {
    match (nsec, nsec_file) {
        (Some(_), Some(_)) => {
            anyhow::bail!("Cannot combine --nsec with --nsec-file (or nsec and nsec_file in config).");
        }
        (Some(nsec), None) => {
            let trimmed = nsec.trim();
            if trimmed.is_empty() {
                anyhow::bail!("nsec is empty. Provide a valid nsec or hex private key.");
            }
            log::info!("Loaded nsec from inline value");
            Ok(Some(trimmed.to_string()))
        }
        (None, Some(path)) => {
            let content = fs::read_to_string(&path)
                .with_context(|| format!("Failed to read nsec file: {}", path.display()))?;
            let trimmed = content.trim();
            if trimmed.is_empty() {
                anyhow::bail!("nsec file is empty: {}", path.display());
            }
            log::info!("Loaded nsec from file: {}", path.display());
            Ok(Some(trimmed.to_string()))
        }
        (None, None) => Ok(None),
    }
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
    /// Run as server (accepts connections and forwards to source)
    #[command(subcommand_negates_reqs = true)]
    Server {
        /// Path to config file
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Load config from default location (~/.config/tunnel-rs/server.toml)
        #[arg(long)]
        default_config: bool,

        #[command(subcommand)]
        mode: Option<ServerMode>,
    },
    /// Run as client (connects to server and exposes local port)
    #[command(subcommand_negates_reqs = true)]
    Client {
        /// Path to config file
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Load config from default location (~/.config/tunnel-rs/client.toml)
        #[arg(long)]
        default_config: bool,

        #[command(subcommand)]
        mode: Option<ClientMode>,
    },
    /// Generate a new iroh secret key file (for automation/setup)
    GenerateIrohKey {
        /// Path where to save the secret key file
        #[arg(short, long)]
        output: PathBuf,

        /// Overwrite existing file if it exists
        #[arg(long)]
        force: bool,
    },
    /// Show the iroh node ID (EndpointId) for an existing secret key file
    ShowIrohNodeId {
        /// Path to the secret key file
        #[arg(short, long)]
        secret_file: PathBuf,
    },
    /// Show the Nostr public key (npub) for an existing nsec file
    ShowNpub {
        /// Path to the nsec key file
        #[arg(short, long)]
        nsec_file: PathBuf,
    },
    /// Generate a Nostr keypair for use with nostr mode
    GenerateNostrKey {
        /// Path where to save the nsec key file
        #[arg(short, long)]
        output: PathBuf,

        /// Overwrite existing file if it exists
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand)]
enum ServerMode {
    /// Multi-source mode: iroh with automatic discovery and relay fallback (client requests source)
    #[command(name = "iroh")]
    Iroh {
        /// Allowed TCP source networks in CIDR notation (repeatable)
        /// E.g., --allowed-tcp 127.0.0.0/8 --allowed-tcp 192.168.0.0/16
        #[arg(long = "allowed-tcp")]
        allowed_tcp: Vec<String>,

        /// Allowed UDP source networks in CIDR notation (repeatable)
        /// E.g., --allowed-udp 10.0.0.0/8 --allowed-udp ::1/128
        #[arg(long = "allowed-udp")]
        allowed_udp: Vec<String>,

        /// Maximum concurrent sessions (default: 100)
        #[arg(long)]
        max_sessions: Option<usize>,

        /// Base64-encoded secret key for persistent identity
        #[arg(long)]
        secret: Option<String>,

        /// Path to secret key file for persistent identity
        #[arg(long)]
        secret_file: Option<PathBuf>,

        /// Custom relay server URL(s) for failover
        #[arg(long = "relay-url")]
        relay_urls: Vec<String>,

        /// Force all connections through the relay server (disables direct P2P).
        /// Only available with the 'test-utils' feature: cargo build --features test-utils
        #[cfg(feature = "test-utils")]
        #[arg(long)]
        relay_only: bool,

        /// Custom DNS server URL for peer discovery
        #[arg(long)]
        dns_server: Option<String>,
    },
    /// Client-initiated mode: iroh with STUN-based manual signaling (may fail on symmetric NAT)
    #[command(name = "iroh-manual")]
    IrohManual {
        /// Allowed TCP source networks in CIDR notation (repeatable)
        /// E.g., --allowed-tcp 127.0.0.0/8 --allowed-tcp 192.168.0.0/16
        #[arg(long = "allowed-tcp")]
        allowed_tcp: Vec<String>,

        /// Allowed UDP source networks in CIDR notation (repeatable)
        /// E.g., --allowed-udp 10.0.0.0/8 --allowed-udp ::1/128
        #[arg(long = "allowed-udp")]
        allowed_udp: Vec<String>,

        /// STUN server (repeatable, e.g., stun.l.google.com:19302)
        #[arg(long = "stun-server")]
        stun_servers: Vec<String>,

        /// Disable STUN (no external infrastructure)
        #[arg(long)]
        no_stun: bool,
    },
    /// Client-initiated mode: Full ICE with manual signaling - best NAT traversal (str0m+quinn)
    #[command(name = "custom-manual")]
    CustomManual {
        /// Allowed TCP source networks in CIDR notation (repeatable)
        /// E.g., --allowed-tcp 127.0.0.0/8 --allowed-tcp 192.168.0.0/16
        #[arg(long = "allowed-tcp")]
        allowed_tcp: Vec<String>,

        /// Allowed UDP source networks in CIDR notation (repeatable)
        /// E.g., --allowed-udp 10.0.0.0/8 --allowed-udp ::1/128
        #[arg(long = "allowed-udp")]
        allowed_udp: Vec<String>,

        /// STUN server (repeatable, e.g., stun.l.google.com:19302)
        #[arg(long = "stun-server")]
        stun_servers: Vec<String>,

        /// Disable STUN (no external infrastructure)
        #[arg(long)]
        no_stun: bool,
    },
    /// Full ICE with Nostr-based signaling (WireGuard-like static keys)
    Nostr {
        /// Allowed TCP source networks in CIDR notation (repeatable)
        /// E.g., --allowed-tcp 127.0.0.0/8 --allowed-tcp 192.168.0.0/16
        #[arg(long = "allowed-tcp")]
        allowed_tcp: Vec<String>,

        /// Allowed UDP source networks in CIDR notation (repeatable)
        /// E.g., --allowed-udp 10.0.0.0/8 --allowed-udp ::1/128
        #[arg(long = "allowed-udp")]
        allowed_udp: Vec<String>,

        /// Your Nostr private key (nsec or hex format)
        #[arg(long)]
        nsec: Option<String>,

        /// Path to file containing your Nostr private key (nsec or hex format)
        #[arg(long)]
        nsec_file: Option<PathBuf>,

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

        /// Maximum concurrent sessions (0 = unlimited, default: 10)
        #[arg(long, default_value = "10")]
        max_sessions: usize,
    },
}

#[derive(Subcommand)]
enum ClientMode {
    /// Multi-source mode: iroh with automatic discovery and relay fallback (requests source from server)
    #[command(name = "iroh")]
    Iroh {
        /// EndpointId of the server to connect to
        #[arg(short, long)]
        node_id: Option<String>,

        /// Source address to request from server (tcp://host:port or udp://host:port)
        /// The server must have this in its --allowed-tcp or --allowed-udp list
        #[arg(short, long)]
        source: Option<String>,

        /// Local address to listen on (e.g., 127.0.0.1:2222)
        #[arg(short, long)]
        target: Option<String>,

        /// Custom relay server URL(s) for failover
        #[arg(long = "relay-url")]
        relay_urls: Vec<String>,

        /// Force all connections through the relay server (disables direct P2P).
        /// Only available with the 'test-utils' feature: cargo build --features test-utils
        #[cfg(feature = "test-utils")]
        #[arg(long)]
        relay_only: bool,

        /// Custom DNS server URL for peer discovery
        #[arg(long)]
        dns_server: Option<String>,
    },
    /// Client-initiated mode: iroh with STUN-based manual signaling (may fail on symmetric NAT)
    #[command(name = "iroh-manual")]
    IrohManual {
        /// Source address to request from server (tcp://host:port or udp://host:port)
        /// The server must have this in its --allowed-tcp or --allowed-udp list
        #[arg(short, long)]
        source: Option<String>,

        /// Local address to listen on (e.g., 127.0.0.1:2222)
        #[arg(short, long)]
        target: Option<String>,

        /// STUN server (repeatable, e.g., stun.l.google.com:19302)
        #[arg(long = "stun-server")]
        stun_servers: Vec<String>,

        /// Disable STUN (no external infrastructure)
        #[arg(long)]
        no_stun: bool,
    },
    /// Client-initiated mode: Full ICE with manual signaling - best NAT traversal (str0m+quinn)
    #[command(name = "custom-manual")]
    CustomManual {
        /// Source address to request from server (tcp://host:port or udp://host:port)
        /// The server must have this in its --allowed-tcp or --allowed-udp list
        #[arg(short, long)]
        source: Option<String>,

        /// Local address to listen on (e.g., 127.0.0.1:2222)
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
        /// Local address to listen on (e.g., 127.0.0.1:2222 for TCP, udp://127.0.0.1:5353 for UDP)
        #[arg(short, long)]
        target: Option<String>,

        /// Source address to request from server (tcp://host:port or udp://host:port)
        /// The server must have this in its --allowed-tcp or --allowed-udp list
        #[arg(short, long)]
        source: Option<String>,

        /// Your Nostr private key (nsec or hex format)
        #[arg(long)]
        nsec: Option<String>,

        /// Path to file containing your Nostr private key (nsec or hex format)
        #[arg(long)]
        nsec_file: Option<PathBuf>,

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

        /// Interval in seconds to re-publish answer while waiting for connection (default: 5)
        #[arg(long, default_value = "5")]
        republish_interval: u64,

        /// Maximum time in seconds to wait for offer before giving up (default: 120)
        #[arg(long, default_value = "120")]
        max_wait: u64,
    },
    /// Full ICE with DCUtR signaling server (coordinated NAT hole punching)
    #[command(name = "dcutr")]
    DCUtR {
        /// Local address to listen on (e.g., 127.0.0.1:2222)
        #[arg(short, long)]
        target: Option<String>,

        /// Source address to request from peer (tcp://host:port or udp://host:port)
        #[arg(short, long)]
        source: Option<String>,

        /// DCUtR signaling server address (host:port)
        #[arg(long)]
        signaling_server: Option<String>,

        /// Target peer ID to connect to
        #[arg(long)]
        peer_id: Option<String>,

        /// Our client ID (auto-generated if not specified)
        #[arg(long)]
        client_id: Option<String>,

        /// STUN server (repeatable). Uses default servers if not specified.
        #[arg(long = "stun-server")]
        stun_servers: Vec<String>,

        /// Disable STUN (no external infrastructure)
        #[arg(long)]
        no_stun: bool,
    },
}

/// Load server config based on flags. Returns (config, was_loaded_from_file).
fn resolve_server_config(
    config: Option<PathBuf>,
    default_config: bool,
) -> Result<(ServerConfig, bool)> {
    if config.is_some() && default_config {
        anyhow::bail!("Cannot use both -c/--config and --default-config");
    }

    if let Some(path) = config {
        Ok((load_server_config(Some(&path))?, true))
    } else if default_config {
        Ok((load_server_config(None)?, true))
    } else {
        Ok((ServerConfig::default(), false))
    }
}

/// Load client config based on flags. Returns (config, was_loaded_from_file).
fn resolve_client_config(
    config: Option<PathBuf>,
    default_config: bool,
) -> Result<(ClientConfig, bool)> {
    if config.is_some() && default_config {
        anyhow::bail!("Cannot use both -c/--config and --default-config");
    }

    if let Some(path) = config {
        Ok((load_client_config(Some(&path))?, true))
    } else if default_config {
        Ok((load_client_config(None)?, true))
    } else {
        Ok((ClientConfig::default(), false))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn"))
        .filter_module("tunnel_rs", log::LevelFilter::Info)
        .try_init();
    let args = Args::parse();

    match args.command {
        Command::Server {
            config,
            default_config,
            mode,
        } => {
            let (cfg, from_file) = resolve_server_config(config.clone(), default_config)?;

            // Determine effective mode: CLI mode takes precedence, else read from config
            let effective_mode = match (&mode, &cfg.mode) {
                (Some(_), _) => mode.as_ref().map(|m| match m {
                    ServerMode::Iroh { .. } => "iroh",
                    ServerMode::IrohManual { .. } => "iroh-manual",
                    ServerMode::CustomManual { .. } => "custom-manual",
                    ServerMode::Nostr { .. } => "nostr",
                }),
                (None, Some(m)) => Some(m.as_str()),
                (None, None) => None,
            };

            let effective_mode = effective_mode.context(
                "No mode specified. Either use a subcommand (iroh, iroh-manual, custom-manual, nostr) or provide a config file with 'mode' field.",
            )?;

            // Validate config if loaded from file
            if from_file {
                cfg.validate(effective_mode)?;
            }

            match effective_mode {
                "iroh" => {
                    let iroh_cfg = cfg.iroh();
                    // Extract common fields (relay_only is CLI-only, requires test-utils feature)
                    let (allowed_tcp, allowed_udp, max_sessions, secret, secret_file, relay_urls, dns_server) = match &mode {
                        Some(ServerMode::Iroh { allowed_tcp: at, allowed_udp: au, max_sessions: ms, secret: se, secret_file: sf, relay_urls: r, dns_server: d, .. }) => {
                            let cfg_allowed = iroh_cfg.and_then(|c| c.allowed_sources.clone()).unwrap_or_default();
                            let cfg_secret = iroh_cfg.and_then(|c| c.secret.clone());
                            let cfg_secret_file = iroh_cfg.and_then(|c| c.secret_file.clone());
                            let (secret, secret_file) = if se.is_some() || sf.is_some() {
                                (se.clone(), sf.clone())
                            } else {
                                (cfg_secret, cfg_secret_file)
                            };
                            (
                                if at.is_empty() { cfg_allowed.tcp.clone() } else { at.clone() },
                                if au.is_empty() { cfg_allowed.udp.clone() } else { au.clone() },
                                ms.or_else(|| iroh_cfg.and_then(|c| c.max_sessions)),
                                secret,
                                secret_file,
                                if r.is_empty() { iroh_cfg.and_then(|c| c.relay_urls.clone()).unwrap_or_default() } else { r.clone() },
                                d.clone().or_else(|| iroh_cfg.and_then(|c| c.dns_server.clone())),
                            )
                        }
                        _ => {
                            let cfg_allowed = iroh_cfg.and_then(|c| c.allowed_sources.clone()).unwrap_or_default();
                            (
                                cfg_allowed.tcp,
                                cfg_allowed.udp,
                                iroh_cfg.and_then(|c| c.max_sessions),
                                iroh_cfg.and_then(|c| c.secret.clone()),
                                iroh_cfg.and_then(|c| c.secret_file.clone()),
                                iroh_cfg.and_then(|c| c.relay_urls.clone()).unwrap_or_default(),
                                iroh_cfg.and_then(|c| c.dns_server.clone()),
                            )
                        },
                    };
                    // relay_only: CLI-only, requires test-utils feature
                    #[cfg(feature = "test-utils")]
                    let relay_only = match &mode {
                        Some(ServerMode::Iroh { relay_only, .. }) => *relay_only,
                        _ => false,
                    };
                    #[cfg(not(feature = "test-utils"))]
                    let relay_only = false;

                    let secret = resolve_iroh_secret(secret, secret_file)?;

                    iroh::run_multi_source_server(allowed_tcp, allowed_udp, max_sessions, secret, relay_urls, relay_only, dns_server).await
                }
                "iroh-manual" => {
                    let manual_cfg = cfg.iroh_manual();
                    let (allowed_tcp, allowed_udp, stun_servers) = match &mode {
                        Some(ServerMode::IrohManual { allowed_tcp: at, allowed_udp: au, stun_servers: ss, no_stun }) => {
                            let cfg_allowed = manual_cfg.and_then(|c| c.allowed_sources.clone()).unwrap_or_default();
                            (
                                if at.is_empty() { cfg_allowed.tcp.clone() } else { at.clone() },
                                if au.is_empty() { cfg_allowed.udp.clone() } else { au.clone() },
                                resolve_stun_servers(ss, manual_cfg.and_then(|c| c.stun_servers.clone()), *no_stun)?,
                            )
                        },
                        _ => {
                            let cfg_allowed = manual_cfg.and_then(|c| c.allowed_sources.clone()).unwrap_or_default();
                            (
                                cfg_allowed.tcp.clone(),
                                cfg_allowed.udp.clone(),
                                resolve_stun_servers(&[], manual_cfg.and_then(|c| c.stun_servers.clone()), false)?,
                            )
                        },
                    };

                    if allowed_tcp.is_empty() && allowed_udp.is_empty() {
                        anyhow::bail!("At least one of --allowed-tcp or --allowed-udp is required for iroh-manual server");
                    }

                    iroh::run_iroh_manual_server(allowed_tcp, allowed_udp, stun_servers).await
                }
                "custom-manual" => {
                    let custom_cfg = cfg.custom_manual();
                    let (allowed_tcp, allowed_udp, stun_servers) = match &mode {
                        Some(ServerMode::CustomManual { allowed_tcp: at, allowed_udp: au, stun_servers: ss, no_stun }) => {
                            let cfg_allowed = custom_cfg.and_then(|c| c.allowed_sources.clone()).unwrap_or_default();
                            (
                                if at.is_empty() { cfg_allowed.tcp.clone() } else { at.clone() },
                                if au.is_empty() { cfg_allowed.udp.clone() } else { au.clone() },
                                resolve_stun_servers(ss, custom_cfg.and_then(|c| c.stun_servers.clone()), *no_stun)?,
                            )
                        },
                        _ => {
                            let cfg_allowed = custom_cfg.and_then(|c| c.allowed_sources.clone()).unwrap_or_default();
                            (
                                cfg_allowed.tcp.clone(),
                                cfg_allowed.udp.clone(),
                                resolve_stun_servers(&[], custom_cfg.and_then(|c| c.stun_servers.clone()), false)?,
                            )
                        },
                    };

                    if allowed_tcp.is_empty() && allowed_udp.is_empty() {
                        anyhow::bail!("At least one of --allowed-tcp or --allowed-udp is required for custom-manual server");
                    }

                    custom::run_manual_server(allowed_tcp, allowed_udp, stun_servers).await
                }
                "nostr" => {
                    let nostr_cfg = cfg.nostr();
                    let (allowed_tcp, allowed_udp, stun_servers, nsec, nsec_file, peer_npub, relays, republish_interval, max_wait, max_sessions) = match &mode {
                        Some(ServerMode::Nostr { allowed_tcp: at, allowed_udp: au, stun_servers: ss, no_stun, nsec: n, nsec_file: nf, peer_npub: p, relays: r, republish_interval: ri, max_wait: mw, max_sessions: ms }) => {
                            let cfg_allowed = nostr_cfg.and_then(|c| c.allowed_sources.clone()).unwrap_or_default();
                            let cfg_nsec = nostr_cfg.and_then(|c| c.nsec.clone());
                            let cfg_nsec_file = nostr_cfg.and_then(|c| c.nsec_file.clone());
                            let (nsec, nsec_file) = if n.is_some() || nf.is_some() {
                                (n.clone(), nf.clone())
                            } else {
                                (cfg_nsec, cfg_nsec_file)
                            };
                            (
                                if at.is_empty() { cfg_allowed.tcp.clone() } else { at.clone() },
                                if au.is_empty() { cfg_allowed.udp.clone() } else { au.clone() },
                                resolve_stun_servers(ss, nostr_cfg.and_then(|c| c.stun_servers.clone()), *no_stun)?,
                                nsec,
                                nsec_file,
                                p.clone().or_else(|| nostr_cfg.and_then(|c| c.peer_npub.clone())),
                                if r.is_empty() { nostr_cfg.and_then(|c| c.relays.clone()).unwrap_or_default() } else { r.clone() },
                                *ri,
                                *mw,
                                *ms,
                            )
                        },
                        _ => {
                            let cfg_allowed = nostr_cfg.and_then(|c| c.allowed_sources.clone()).unwrap_or_default();
                            (
                                cfg_allowed.tcp,
                                cfg_allowed.udp,
                                resolve_stun_servers(&[], nostr_cfg.and_then(|c| c.stun_servers.clone()), false)?,
                                nostr_cfg.and_then(|c| c.nsec.clone()),
                                nostr_cfg.and_then(|c| c.nsec_file.clone()),
                                nostr_cfg.and_then(|c| c.peer_npub.clone()),
                                nostr_cfg.and_then(|c| c.relays.clone()).unwrap_or_default(),
                                10, // default republish interval
                                120, // default max wait
                                nostr_cfg.and_then(|c| c.max_sessions).unwrap_or(10),
                            )
                        },
                    };

                    // Require at least one allowed network
                    if allowed_tcp.is_empty() && allowed_udp.is_empty() {
                        anyhow::bail!(
                            "At least one of --allowed-tcp or --allowed-udp must be specified for nostr server mode."
                        );
                    }

                    let nsec = resolve_nostr_nsec(nsec, nsec_file)?.context(
                        "nsec is required. Provide via --nsec/--nsec-file or in config file (nsec/nsec_file). Use 'tunnel-rs generate-nostr-key' to create one.",
                    )?;
                    let peer_npub = peer_npub.context(
                        "peer-npub is required. Provide via --peer-npub or in config file.",
                    )?;
                    let relays = if relays.is_empty() {
                        config::default_nostr_relays()
                    } else {
                        relays
                    };

                    // Run both TCP and UDP senders concurrently
                    nostr::run_nostr_server(allowed_tcp, allowed_udp, stun_servers, nsec, peer_npub, relays, republish_interval, max_wait, max_sessions).await
                }
                _ => anyhow::bail!("Invalid mode '{}'. Use: iroh, iroh-manual, custom-manual, or nostr", effective_mode),
            }
        }
        Command::Client {
            config,
            default_config,
            mode,
        } => {
            let (cfg, from_file) = resolve_client_config(config, default_config)?;

            // Determine effective mode: CLI mode takes precedence, else read from config
            let effective_mode = match (&mode, &cfg.mode) {
                (Some(_), _) => mode.as_ref().map(|m| match m {
                    ClientMode::Iroh { .. } => "iroh",
                    ClientMode::IrohManual { .. } => "iroh-manual",
                    ClientMode::CustomManual { .. } => "custom-manual",
                    ClientMode::Nostr { .. } => "nostr",
                    ClientMode::DCUtR { .. } => "dcutr",
                }),
                (None, Some(m)) => Some(m.as_str()),
                (None, None) => None,
            };

            let effective_mode = effective_mode.context(
                "No mode specified. Either use a subcommand (iroh, iroh-manual, custom-manual, nostr) or provide a config file with 'mode' field.",
            )?;

            // Validate config if loaded from file
            if from_file {
                cfg.validate(effective_mode)?;
            }

            match effective_mode {
                "iroh" => {
                    let iroh_cfg = cfg.iroh();
                    // Override with CLI values if provided
                    // Note: relay_only is CLI-only (not in config), requires test-utils feature
                    let (node_id, source, target, relay_urls, dns_server) = match &mode {
                        Some(ClientMode::Iroh { node_id: n, source: src, target: t, relay_urls: r, dns_server: d, .. }) => (
                            n.clone().or_else(|| iroh_cfg.and_then(|c| c.node_id.clone())),
                            normalize_optional_endpoint(src.clone()).or_else(|| iroh_cfg.and_then(|c| c.request_source.clone())),
                            t.clone().or_else(|| iroh_cfg.and_then(|c| c.target.clone())),
                            if r.is_empty() { iroh_cfg.and_then(|c| c.relay_urls.clone()).unwrap_or_default() } else { r.clone() },
                            d.clone().or_else(|| iroh_cfg.and_then(|c| c.dns_server.clone())),
                        ),
                        _ => (
                            iroh_cfg.and_then(|c| c.node_id.clone()),
                            iroh_cfg.and_then(|c| c.request_source.clone()),
                            iroh_cfg.and_then(|c| c.target.clone()),
                            iroh_cfg.and_then(|c| c.relay_urls.clone()).unwrap_or_default(),
                            iroh_cfg.and_then(|c| c.dns_server.clone()),
                        ),
                    };
                    // relay_only: CLI-only, requires test-utils feature
                    #[cfg(feature = "test-utils")]
                    let relay_only = match &mode {
                        Some(ClientMode::Iroh { relay_only, .. }) => *relay_only,
                        _ => false,
                    };
                    #[cfg(not(feature = "test-utils"))]
                    let relay_only = false;

                    let node_id = node_id.context(
                        "node_id is required. Provide via --node-id or in config file.",
                    )?;
                    let source = source.context(
                        "--source is required for iroh client mode. Specify the source to request from server (e.g., --source tcp://127.0.0.1:22)",
                    )?;
                    let target = target.context(
                        "--target is required. Provide the local address to listen on (e.g., --target 127.0.0.1:2222)",
                    )?;

                    iroh::run_multi_source_client(node_id, source, target, relay_urls, relay_only, dns_server).await
                }
                "iroh-manual" => {
                    let manual_cfg = cfg.iroh_manual();
                    let (source, target, stun_servers) = match &mode {
                        Some(ClientMode::IrohManual { source: src, target: t, stun_servers: s, no_stun }) => (
                            normalize_optional_endpoint(src.clone()).or_else(|| manual_cfg.and_then(|c| c.request_source.clone())),
                            t.clone().or_else(|| manual_cfg.and_then(|c| c.target.clone())),
                            resolve_stun_servers(s, manual_cfg.and_then(|c| c.stun_servers.clone()), *no_stun)?,
                        ),
                        _ => (
                            manual_cfg.and_then(|c| c.request_source.clone()),
                            manual_cfg.and_then(|c| c.target.clone()),
                            resolve_stun_servers(&[], manual_cfg.and_then(|c| c.stun_servers.clone()), false)?,
                        ),
                    };

                    let source: String = source.context(
                        "--source is required for iroh-manual client. Specify the source to request from server (e.g., --source tcp://127.0.0.1:22)",
                    )?;
                    let target: String = target.context(
                        "--target is required. Specify local address to listen on (e.g., --target 127.0.0.1:2222)",
                    )?;

                    // Validate source format early
                    let _ = parse_endpoint(&source)
                        .with_context(|| format!("Invalid source '{}'. Expected format: tcp://host:port or udp://host:port", source))?;

                    // Parse target as just host:port (no protocol prefix needed)
                    let listen: SocketAddr = target.parse()
                        .with_context(|| format!("Invalid target '{}'. Expected format: host:port (e.g., 127.0.0.1:2222)", target))?;

                    iroh::run_iroh_manual_client(source, listen, stun_servers).await
                }
                "custom-manual" => {
                    let custom_cfg = cfg.custom_manual();
                    let (source, target, stun_servers) = match &mode {
                        Some(ClientMode::CustomManual { source: src, target: t, stun_servers: s, no_stun }) => (
                            normalize_optional_endpoint(src.clone()).or_else(|| custom_cfg.and_then(|c| c.request_source.clone())),
                            t.clone().or_else(|| custom_cfg.and_then(|c| c.target.clone())),
                            resolve_stun_servers(s, custom_cfg.and_then(|c| c.stun_servers.clone()), *no_stun)?,
                        ),
                        _ => (
                            custom_cfg.and_then(|c| c.request_source.clone()),
                            custom_cfg.and_then(|c| c.target.clone()),
                            resolve_stun_servers(&[], custom_cfg.and_then(|c| c.stun_servers.clone()), false)?,
                        ),
                    };

                    let source: String = source.context(
                        "--source is required for custom-manual client. Specify the source to request from server (e.g., --source tcp://127.0.0.1:22)",
                    )?;
                    let target: String = target.context(
                        "--target is required. Specify local address to listen on (e.g., --target 127.0.0.1:2222)",
                    )?;

                    // Validate source format early
                    let _ = parse_endpoint(&source)
                        .with_context(|| format!("Invalid source '{}'. Expected format: tcp://host:port or udp://host:port", source))?;

                    // Parse target as just host:port (no protocol prefix needed)
                    let listen: SocketAddr = target.parse()
                        .with_context(|| format!("Invalid target '{}'. Expected format: host:port (e.g., 127.0.0.1:2222)", target))?;

                    custom::run_manual_client(source, listen, stun_servers).await
                }
                "nostr" => {
                    let nostr_cfg = cfg.nostr();
                    let (target, source, stun_servers, nsec, nsec_file, peer_npub, relays, republish_interval, max_wait) = match &mode {
                        Some(ClientMode::Nostr { target: t, source: src, stun_servers: ss, no_stun, nsec: n, nsec_file: nf, peer_npub: p, relays: r, republish_interval: ri, max_wait: mw }) => {
                            let cfg_nsec = nostr_cfg.and_then(|c| c.nsec.clone());
                            let cfg_nsec_file = nostr_cfg.and_then(|c| c.nsec_file.clone());
                            let (nsec, nsec_file) = if n.is_some() || nf.is_some() {
                                (n.clone(), nf.clone())
                            } else {
                                (cfg_nsec, cfg_nsec_file)
                            };
                            (
                                normalize_optional_endpoint(t.clone()).or_else(|| nostr_cfg.and_then(|c| c.target.clone())),
                                normalize_optional_endpoint(src.clone()).or_else(|| nostr_cfg.and_then(|c| c.request_source.clone())),
                                resolve_stun_servers(ss, nostr_cfg.and_then(|c| c.stun_servers.clone()), *no_stun)?,
                                nsec,
                                nsec_file,
                                p.clone().or_else(|| nostr_cfg.and_then(|c| c.peer_npub.clone())),
                                if r.is_empty() { nostr_cfg.and_then(|c| c.relays.clone()).unwrap_or_default() } else { r.clone() },
                                *ri,
                                *mw,
                            )
                        }
                        _ => (
                            nostr_cfg.and_then(|c| c.target.clone()),
                            nostr_cfg.and_then(|c| c.request_source.clone()),
                            resolve_stun_servers(&[], nostr_cfg.and_then(|c| c.stun_servers.clone()), false)?,
                            nostr_cfg.and_then(|c| c.nsec.clone()),
                            nostr_cfg.and_then(|c| c.nsec_file.clone()),
                            nostr_cfg.and_then(|c| c.peer_npub.clone()),
                            nostr_cfg.and_then(|c| c.relays.clone()).unwrap_or_default(),
                            5, // default republish interval
                            120, // default max wait
                        ),
                    };

                    let target = target.context(
                        "target is required. Provide via --target or in config file.",
                    )?;
                    let source = source.context(
                        "--source is required for nostr client mode. Specify the source to request from server (e.g., --source tcp://127.0.0.1:22)",
                    )?;
                    let nsec = resolve_nostr_nsec(nsec, nsec_file)?.context(
                        "nsec is required. Provide via --nsec/--nsec-file or in config file (nsec/nsec_file). Use 'tunnel-rs generate-nostr-key' to create one.",
                    )?;
                    let peer_npub = peer_npub.context(
                        "peer-npub is required. Provide via --peer-npub or in config file.",
                    )?;
                    let relays = if relays.is_empty() {
                        config::default_nostr_relays()
                    } else {
                        relays
                    };

                    // For nostr mode, target is just host:port (no protocol prefix)
                    let listen = target;

                    // Determine protocol from config or default to TCP
                    // In nostr mode we support both TCP and UDP via the target format
                    if listen.contains("://") {
                        let (protocol, addr) = parse_endpoint(&listen)
                            .with_context(|| format!("Invalid receiver target '{}'", listen))?;
                        match protocol {
                            Protocol::Udp => nostr::run_nostr_udp_client(addr, source, stun_servers, nsec, peer_npub, relays, republish_interval, max_wait).await,
                            Protocol::Tcp => nostr::run_nostr_tcp_client(addr, source, stun_servers, nsec, peer_npub, relays, republish_interval, max_wait).await,
                        }
                    } else {
                        // Default to TCP if no protocol specified
                        nostr::run_nostr_tcp_client(listen, source, stun_servers, nsec, peer_npub, relays, republish_interval, max_wait).await
                    }
                }
                "dcutr" => {
                    let (target, source, signaling_server, peer_id, client_id, stun_servers) = match &mode {
                        Some(ClientMode::DCUtR { target: t, source: src, signaling_server: ss, peer_id: pi, client_id: ci, stun_servers: stun, no_stun }) => (
                            t.clone(),
                            normalize_optional_endpoint(src.clone()),
                            ss.clone(),
                            pi.clone(),
                            ci.clone(),
                            resolve_stun_servers(stun, None, *no_stun)?,
                        ),
                        _ => (None, None, None, None, None, default_stun_servers()),
                    };

                    let target = target.context(
                        "--target is required for dcutr client mode. Specify the local address to listen on (e.g., --target 127.0.0.1:2222)",
                    )?;
                    let source = source.context(
                        "--source is required for dcutr client mode. Specify the source to request (e.g., --source tcp://127.0.0.1:22)",
                    )?;
                    let signaling_server = signaling_server.context(
                        "--signaling-server is required for dcutr mode. Specify the signaling server address (e.g., --signaling-server 1.2.3.4:9999)",
                    )?;
                    let peer_id = peer_id.context(
                        "--peer-id is required for dcutr mode. Specify the target peer ID to connect to.",
                    )?;

                    // Validate source format early
                    let (protocol, _) = parse_endpoint(&source)
                        .with_context(|| format!("Invalid source '{}'. Expected format: tcp://host:port or udp://host:port", source))?;

                    match protocol {
                        Protocol::Tcp => custom::run_dcutr_tcp_client(target, source, signaling_server, peer_id, client_id, stun_servers).await,
                        Protocol::Udp => custom::run_dcutr_udp_client(target, source, signaling_server, peer_id, client_id, stun_servers).await,
                    }
                }
                _ => anyhow::bail!("Invalid mode '{}'. Use: iroh, iroh-manual, custom-manual, nostr, or dcutr", effective_mode),
            }
        }
        Command::GenerateIrohKey { output, force } => secret::generate_secret(output, force),
        Command::ShowIrohNodeId { secret_file } => secret::show_id(secret_file),
        Command::ShowNpub { nsec_file } => secret::show_npub(nsec_file),
        Command::GenerateNostrKey { output, force } => secret::generate_nostr_key(output, force),
    }
}
