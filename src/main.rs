//! vpn-rs
//!
//! Single-purpose IP-over-TCP/UDP VPN tunnel. The VPN binds a loopback-only
//! socket (TCP by default, or UDP); a separate tunnel process ([tunnel-rs] /
//! [duopipe] / any loopback tunnel) forwards that loopback traffic across the
//! network and provides encryption and authentication. This binary is
//! responsible for VPN tunneling only.
//!
//! [tunnel-rs]: https://github.com/andrewtheguy/tunnel-rs
//! [duopipe]: https://github.com/andrewtheguy/duopipe

#[cfg(not(any(unix, target_os = "windows")))]
compile_error!("vpn-rs only supports Unix-like systems (Linux, macOS, BSD) and Windows");

mod vpn_core;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ipnet::{Ipv4Net, Ipv6Net};
use rand::Rng;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU32;
use std::path::PathBuf;

use crate::vpn_core::config::{VpnClientConfig, VpnServerConfig};
use crate::vpn_core::file_config::{
    load_vpn_client_config, load_vpn_server_config, ResolvedVpnClientConfig,
    ResolvedVpnServerConfig, Transport, VpnClientConfig as TomlClientConfig, VpnClientConfigBuilder,
    VpnServerConfig as TomlServerConfig,
};
use crate::vpn_core::tcp::bind_tcp_listener;
use crate::vpn_core::udp::bind_server_socket;
use crate::vpn_core::{TcpVpnServer, VpnClient, VpnServer};
use std::future::Future;
use std::time::Duration;

/// Maximum wall-clock runtime in test mode before the process stops itself.
///
/// Test mode relaxes the loopback security boundary, so a forgotten test
/// instance is a liability; cap it at 30 minutes.
const TEST_MODE_MAX_RUNTIME: Duration = Duration::from_secs(30 * 60);

/// Run `fut`, but in test mode stop automatically after [`TEST_MODE_MAX_RUNTIME`].
async fn run_with_test_mode_limit<F>(test_mode: bool, fut: F) -> Result<()>
where
    F: Future<Output = Result<()>>,
{
    if test_mode {
        tokio::select! {
            res = fut => res,
            _ = tokio::time::sleep(TEST_MODE_MAX_RUNTIME) => {
                log::warn!(
                    "Test mode runtime limit ({} minutes) reached; shutting down.",
                    TEST_MODE_MAX_RUNTIME.as_secs() / 60
                );
                Ok(())
            }
        }
    } else {
        fut.await
    }
}

#[derive(Parser)]
#[command(name = "vpn-rs")]
#[command(version)]
#[command(about = "Single-purpose IP-over-TCP/UDP VPN (loopback-only; bring your own tunnel)")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run as VPN server (binds a loopback socket and assigns IPs).
    ///
    /// Requires a config file. Use -c to specify a path or --default-config for
    /// ~/.config/vpn-rs/vpn_server.toml. See vpn_server.toml.example for format.
    Server {
        /// Config file path (required unless --default-config is used)
        #[arg(short = 'c', long)]
        config: Option<PathBuf>,

        /// Use default config path (~/.config/vpn-rs/vpn_server.toml)
        #[arg(long)]
        default_config: bool,

        /// Transport to carry VPN traffic: tcp (default) or udp. Overrides the
        /// config file's `transport` when set.
        #[arg(long, value_enum)]
        transport: Option<Transport>,

        /// Test mode: allow binding a non-loopback listen address (requires
        /// role = "testvpnserver"). Generates and prints a random test token
        /// that clients must supply with --test-token.
        #[arg(long)]
        test_mode: bool,
    },
    /// Run as VPN client (connects a loopback socket to the local tunnel).
    Client {
        /// Config file path
        #[arg(short = 'c', long)]
        config: Option<PathBuf>,

        /// Use default config path (~/.config/vpn-rs/vpn_client.toml)
        #[arg(long)]
        default_config: bool,

        /// Transport to carry VPN traffic: tcp (default) or udp. Overrides the
        /// config file's `transport` when set.
        #[arg(long, value_enum)]
        transport: Option<Transport>,

        /// Loopback address of the local tunnel endpoint (e.g. 127.0.0.1:5555)
        #[arg(short = 's', long)]
        server_addr: Option<String>,

        /// Additional IPv4 route CIDRs through the VPN (repeatable).
        /// Full tunnel: --route 0.0.0.0/0
        #[arg(long = "route")]
        routes: Vec<String>,

        /// IPv6 route CIDRs through the VPN (repeatable). Full tunnel: --route6 ::/0
        #[arg(long = "route6")]
        routes6: Vec<String>,

        /// Enable auto-reconnect (override config's auto_reconnect = false)
        #[arg(long, conflicts_with = "no_auto_reconnect")]
        auto_reconnect: bool,

        /// Disable auto-reconnect (exit on first disconnection)
        #[arg(long, conflicts_with = "auto_reconnect")]
        no_auto_reconnect: bool,

        /// Maximum reconnect attempts (unlimited if not specified)
        #[arg(long, conflicts_with = "no_auto_reconnect")]
        max_reconnect_attempts: Option<NonZeroU32>,

        /// Test mode: allow connecting to a non-loopback server address
        /// (requires role = "testvpnclient" if a config file is used and
        /// --test-token).
        #[arg(long)]
        test_mode: bool,

        /// Test-mode token printed by the server. Required with --test-mode.
        #[arg(long)]
        test_token: Option<String>,
    },
}

/// Resolve VPN server config from CLI and/or config file.
fn resolve_server_config(
    config: Option<PathBuf>,
    default_config: bool,
) -> Result<Option<TomlServerConfig>> {
    if let Some(path) = config {
        Ok(Some(load_vpn_server_config(Some(path.as_path()))?))
    } else if default_config {
        Ok(Some(load_vpn_server_config(None)?))
    } else {
        Ok(None)
    }
}

/// Resolve VPN client config from CLI and/or config file.
fn resolve_client_config(
    config: Option<PathBuf>,
    default_config: bool,
) -> Result<(Option<TomlClientConfig>, bool)> {
    if let Some(path) = config {
        Ok((Some(load_vpn_client_config(Some(path.as_path()))?), true))
    } else if default_config {
        Ok((Some(load_vpn_client_config(None)?), true))
    } else {
        Ok((None, false))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    log::info!("{} v{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));

    let args = Args::parse();

    match args.command {
        Command::Server {
            config,
            default_config,
            transport,
            test_mode,
        } => {
            if config.is_none() && !default_config {
                anyhow::bail!(
                    "VPN server requires a config file.\n\
                     Use -c <FILE> or --default-config (~/.config/vpn-rs/vpn_server.toml)\n\
                     See vpn_server.toml.example for format."
                );
            }

            let cfg = resolve_server_config(config, default_config)?
                .expect("resolve_server_config returns Some when config or default_config is set");
            cfg.validate(test_mode)?;

            let settings = cfg
                .settings()
                .ok_or_else(|| anyhow::anyhow!("Missing [server] section in config file"))?;
            let mut resolved = ResolvedVpnServerConfig::from_config(settings, test_mode)?;
            // CLI --transport overrides the config's transport when provided.
            if let Some(t) = transport {
                resolved.transport = t;
            }

            // In test mode, generate a random token clients must echo back, and
            // print it prominently so the operator can hand it to test clients.
            let test_token = if test_mode {
                let token = format!("{:032x}", rand::rng().random::<u128>());
                log::warn!(
                    "TEST MODE ENABLED (non-loopback binding allowed). \
                     Clients must connect with: --test-mode --test-token {token}"
                );
                Some(token)
            } else {
                None
            };

            run_with_test_mode_limit(test_mode, run_vpn_server(resolved, test_token)).await
        }
        Command::Client {
            config,
            default_config,
            transport,
            server_addr,
            routes,
            routes6,
            auto_reconnect,
            no_auto_reconnect,
            max_reconnect_attempts,
            test_mode,
            test_token,
        } => {
            if !test_mode && test_token.is_some() {
                anyhow::bail!("--test-token is only valid with --test-mode");
            }
            let test_token = if test_mode && test_token.is_none() {
                Some(prompt_for_test_token()?)
            } else {
                test_token
            };

            let (cfg, from_file) = resolve_client_config(config, default_config)?;
            if from_file
                && let Some(ref c) = cfg
            {
                c.validate(test_mode)?;
            }

            assert!(
                !(auto_reconnect && no_auto_reconnect),
                "both --auto-reconnect and --no-auto-reconnect were set (clap conflicts_with should prevent this)"
            );
            let auto_reconnect_opt = match (auto_reconnect, no_auto_reconnect) {
                (true, false) => Some(true),
                (false, true) => Some(false),
                (false, false) => None,
                (true, true) => unreachable!(),
            };

            let resolved = VpnClientConfigBuilder::new()
                .apply_defaults()
                .apply_config(cfg.as_ref().and_then(|c| c.settings()))
                .apply_cli(
                    server_addr,
                    routes,
                    routes6,
                    auto_reconnect_opt,
                    max_reconnect_attempts,
                )
                .apply_transport(transport)
                .apply_test_mode(test_mode, test_token)
                .build()?;

            run_with_test_mode_limit(resolved.test_mode, run_vpn_client(resolved)).await
        }
    }
}

/// Prompt the user to interactively enter the test-mode token.
///
/// Used when `--test-mode` is supplied without `--test-token`. Reads a single
/// line from stdin and trims surrounding whitespace.
fn prompt_for_test_token() -> Result<String> {
    use std::io::Write;

    print!("Enter the test token (printed by the test server): ");
    std::io::stdout().flush().context("Failed to flush stdout")?;

    let mut line = String::new();
    let n = std::io::stdin()
        .read_line(&mut line)
        .context("Failed to read test token from stdin")?;
    if n == 0 {
        anyhow::bail!("No test token provided (reached end of input)");
    }
    let token = line.trim().to_string();
    if token.is_empty() {
        anyhow::bail!("No test token provided");
    }
    Ok(token)
}

/// Run VPN server.
async fn run_vpn_server(
    resolved: ResolvedVpnServerConfig,
    test_token: Option<String>,
) -> Result<()> {
    let network: Option<Ipv4Net> = resolved
        .network
        .as_ref()
        .map(|n| n.parse())
        .transpose()
        .context("Invalid VPN network CIDR")?;
    let server_ip: Option<Ipv4Addr> = resolved
        .server_ip
        .as_ref()
        .map(|ip| ip.parse())
        .transpose()
        .context("Invalid server IP address")?;
    let network6: Option<Ipv6Net> = resolved
        .network6
        .as_ref()
        .map(|n| n.parse())
        .transpose()
        .context("Invalid IPv6 VPN network CIDR")?;
    let server_ip6: Option<Ipv6Addr> = resolved
        .server_ip6
        .as_ref()
        .map(|ip| ip.parse())
        .transpose()
        .context("Invalid server IPv6 address")?;

    let config = VpnServerConfig {
        transport: resolved.transport,
        listen: resolved.listen,
        network,
        network6,
        server_ip,
        server_ip6,
        mtu: resolved.mtu,
        max_clients: resolved.max_clients,
        client_timeout: resolved.client_timeout,
        max_datagram_size: resolved.max_datagram_size,
        drop_on_full: resolved.drop_on_full,
        client_channel_size: resolved.client_channel_size,
        tun_writer_channel_size: resolved.tun_writer_channel_size,
        inbound_worker_channel_size: resolved.inbound_worker_channel_size,
        recv_buffer_size: resolved.recv_buffer_size,
        send_buffer_size: resolved.send_buffer_size,
        disable_spoofing_check: resolved.disable_spoofing_check,
        test_mode: resolved.test_mode,
        test_token,
    };

    let proto = match config.transport {
        Transport::Tcp => "TCP",
        Transport::Udp => "UDP",
    };
    if resolved.test_mode {
        log::info!(
            "VPN server listening on {} {} (TEST MODE: non-loopback binding allowed)",
            proto,
            resolved.listen
        );
    } else {
        log::info!(
            "VPN server listening on loopback {} {} (reachable only via the local tunnel)",
            proto,
            resolved.listen
        );
    }

    match config.transport {
        Transport::Udp => {
            let socket = bind_server_socket(
                resolved.listen,
                resolved.test_mode,
                resolved.recv_buffer_size,
                resolved.send_buffer_size,
            )
            .await
            .with_context(|| format!("Failed to bind UDP socket {}", resolved.listen))?;

            let server = VpnServer::new(config)
                .await
                .context("Failed to create VPN server")?;
            server
                .run(socket)
                .await
                .map_err(|e| anyhow::anyhow!("VPN server error: {}", e))
        }
        Transport::Tcp => {
            let listener = bind_tcp_listener(resolved.listen, resolved.test_mode)
                .await
                .with_context(|| format!("Failed to bind TCP listener {}", resolved.listen))?;

            let server = TcpVpnServer::new(config)
                .await
                .context("Failed to create TCP VPN server")?;
            server
                .run(listener)
                .await
                .map_err(|e| anyhow::anyhow!("VPN server error: {}", e))
        }
    }
}

/// Run VPN client.
async fn run_vpn_client(resolved: ResolvedVpnClientConfig) -> Result<()> {
    let parsed_routes: Vec<Ipv4Net> = resolved
        .routes
        .iter()
        .map(|r| r.parse::<Ipv4Net>())
        .collect::<Result<Vec<_>, _>>()
        .context("Invalid route CIDR (e.g., 192.168.1.0/24)")?;
    let parsed_routes6: Vec<Ipv6Net> = resolved
        .routes6
        .iter()
        .map(|r| r.parse::<Ipv6Net>())
        .collect::<Result<Vec<_>, _>>()
        .context("Invalid route6 CIDR (e.g., ::/0 or fd00::/64)")?;

    if !parsed_routes.is_empty() {
        log::info!("Routing {} IPv4 CIDR(s) through VPN:", parsed_routes.len());
        for route in &parsed_routes {
            log::info!("  {}", route);
        }
    }
    if !parsed_routes6.is_empty() {
        log::info!("Routing {} IPv6 CIDR(s) through VPN:", parsed_routes6.len());
        for route6 in &parsed_routes6 {
            log::info!("  {}", route6);
        }
    }

    let config = VpnClientConfig {
        transport: resolved.transport,
        server_addr: resolved.server_addr,
        routes: parsed_routes,
        routes6: parsed_routes6,
        recv_buffer_size: resolved.recv_buffer_size,
        send_buffer_size: resolved.send_buffer_size,
        test_mode: resolved.test_mode,
        test_token: resolved.test_token,
    };

    let client = VpnClient::new(config)
        .map_err(|e| anyhow::anyhow!("Failed to create VPN client: {}", e))?;

    if resolved.auto_reconnect {
        client
            .run_with_reconnect(resolved.max_reconnect_attempts)
            .await
            .map_err(|e| anyhow::anyhow!("VPN connection error: {}", e))
    } else {
        log::info!("Auto-reconnect disabled, single connection attempt");
        client
            .connect()
            .await
            .map_err(|e| anyhow::anyhow!("VPN connection error: {}", e))
    }
}
