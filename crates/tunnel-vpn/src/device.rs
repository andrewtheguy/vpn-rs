//! TUN device creation and management.
//!
//! This module handles creating and managing TUN network interfaces
//! for VPN traffic.

use crate::error::{VpnError, VpnResult};
use ipnet::{Ipv4Net, Ipv6Net};
use std::net::{Ipv4Addr, Ipv6Addr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tun::{AbstractDevice, AsyncDevice, Configuration, DeviceReader, DeviceWriter};

/// TUN device configuration.
#[derive(Debug, Clone)]
pub struct TunConfig {
    /// Device name (e.g., "tun0"). If None, system assigns a name.
    pub name: Option<String>,
    /// IPv4 address for this end of the tunnel.
    pub address: Ipv4Addr,
    /// Netmask for the VPN network.
    pub netmask: Ipv4Addr,
    /// Destination/gateway IP (peer's VPN address).
    pub destination: Ipv4Addr,
    /// IPv6 address (optional, for dual-stack).
    pub address6: Option<Ipv6Addr>,
    /// IPv6 prefix length (usually 128 for /128 per client).
    pub prefix_len6: Option<u8>,
    /// MTU for the device (default: 1420 for WireGuard).
    pub mtu: u16,
}

impl TunConfig {
    /// Create a new TUN configuration.
    pub fn new(address: Ipv4Addr, netmask: Ipv4Addr, destination: Ipv4Addr) -> Self {
        Self {
            name: None,
            address,
            netmask,
            destination,
            address6: None,
            prefix_len6: None,
            mtu: 1420,
        }
    }

    /// Set the device name.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Set the MTU.
    pub fn with_mtu(mut self, mtu: u16) -> Self {
        self.mtu = mtu;
        self
    }

    /// Add IPv6 configuration for dual-stack.
    ///
    /// # Errors
    /// Returns an error if `prefix_len6` is greater than 128.
    pub fn with_ipv6(mut self, address6: Ipv6Addr, prefix_len6: u8) -> VpnResult<Self> {
        if prefix_len6 > 128 {
            return Err(VpnError::Config(format!(
                "Invalid IPv6 prefix length {}: must be 0-128",
                prefix_len6
            )));
        }
        self.address6 = Some(address6);
        self.prefix_len6 = Some(prefix_len6);
        Ok(self)
    }
}

/// A managed TUN device with async I/O.
pub struct TunDevice {
    /// The underlying async TUN device.
    device: AsyncDevice,
    /// Device name.
    name: String,
    /// Configured MTU.
    mtu: u16,
}

impl TunDevice {
    /// Create a new TUN device with the given configuration.
    pub fn create(config: TunConfig) -> VpnResult<Self> {
        let mut tun_config = Configuration::default();

        // Set IP configuration
        tun_config
            .address(config.address)
            .netmask(config.netmask)
            .destination(config.destination)
            .mtu(config.mtu)
            .up();

        // Set device name if specified
        if let Some(ref name) = config.name {
            #[allow(deprecated)]
            tun_config.name(name);
        }

        // Platform-specific configuration
        #[cfg(target_os = "linux")]
        tun_config.platform_config(|platform_config| {
            platform_config.ensure_root_privileges(true);
        });

        // Create the async device
        let device = tun::create_as_async(&tun_config)
            .map_err(|e| VpnError::TunDevice(format!("Failed to create TUN device: {}", e)))?;

        let name = device
            .tun_name()
            .map_err(|e| VpnError::TunDevice(format!("Failed to get TUN name: {}", e)))?;

        log::info!("Created TUN device: {} with IP {}", name, config.address);

        // Configure IPv6 address if specified (after device creation)
        if let (Some(addr6), Some(prefix)) = (config.address6, config.prefix_len6) {
            configure_tun_ipv6(&name, addr6, prefix)?;
            log::info!("Configured TUN IPv6: {}/{}", addr6, prefix);
        }

        Ok(Self {
            device,
            name,
            mtu: config.mtu,
        })
    }

    /// Get the device name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the MTU.
    pub fn mtu(&self) -> u16 {
        self.mtu
    }

    /// Get the buffer size for reading packets (MTU + packet info header).
    pub fn buffer_size(&self) -> usize {
        self.mtu as usize + tun::PACKET_INFORMATION_LENGTH
    }

    /// Split the device into read and write halves.
    /// Note: The tun crate returns (writer, reader) order from split().
    pub fn split(self) -> VpnResult<(TunReader, TunWriter)> {
        // Save buffer_size before moving self.device
        let buffer_size = self.buffer_size();

        let (writer, reader) = self
            .device
            .split()
            .map_err(|e| VpnError::TunDevice(format!("Failed to split TUN device: {}", e)))?;

        Ok((
            TunReader {
                reader,
                buffer_size,
            },
            TunWriter { writer },
        ))
    }

    /// Read a packet from the TUN device.
    pub async fn read(&mut self, buf: &mut [u8]) -> VpnResult<usize> {
        self.device.read(buf).await.map_err(VpnError::Network)
    }

    /// Write a packet to the TUN device.
    pub async fn write(&mut self, buf: &[u8]) -> VpnResult<usize> {
        self.device.write(buf).await.map_err(VpnError::Network)
    }
}

/// Read half of a split TUN device.
pub struct TunReader {
    reader: DeviceReader,
    buffer_size: usize,
}

impl TunReader {
    /// Get the recommended buffer size.
    pub fn buffer_size(&self) -> usize {
        self.buffer_size
    }

    /// Read a packet from the TUN device.
    pub async fn read(&mut self, buf: &mut [u8]) -> VpnResult<usize> {
        self.reader.read(buf).await.map_err(VpnError::Network)
    }
}

/// Write half of a split TUN device.
pub struct TunWriter {
    writer: DeviceWriter,
}

impl TunWriter {
    /// Write a packet to the TUN device.
    pub async fn write(&mut self, buf: &[u8]) -> VpnResult<usize> {
        self.writer.write(buf).await.map_err(VpnError::Network)
    }

    /// Write all bytes to the TUN device.
    pub async fn write_all(&mut self, buf: &[u8]) -> VpnResult<()> {
        self.writer.write_all(buf).await.map_err(VpnError::Network)
    }
}

/// Check if an error message indicates that a resource already exists.
///
/// Used for idempotent route/address operations. Handles various error formats:
/// - Linux iproute2: "RTNETLINK answers: File exists"
/// - macOS route: "route: writing to routing socket: File exists"
fn is_already_exists_error(stderr: &str) -> bool {
    let lower = stderr.to_lowercase();
    lower.contains("file exists") || lower.contains("eexist")
}

// ============================================================================
// Generic Route Trait and Implementations
// ============================================================================

/// Abstraction over concrete route types (IPv4/IPv6) that can be
/// programmatically added to and removed from the system routing table.
///
/// This trait is implemented by types that represent a single route entry
/// (for example, an IPv4 or IPv6 network/prefix). Implementations are
/// responsible for translating a route into the appropriate platform‑specific
/// command‑line arguments used by this module when configuring the TUN
/// interface.
///
/// # Design
///
/// `Route` is used by generic helper functions to:
///
/// - Add and remove routes for both IPv4 and IPv6 in a uniform way.
/// - Perform idempotent setup and rollback/cleanup when bringing interfaces
///   up or down.
/// - Produce human‑readable log messages via the [`Display`] bound.
///
/// The [`Copy`] bound is intentional: routes are small, value‑type
/// descriptors that are frequently passed by value, stored in collections
/// for potential rollback, and cloned when constructing error messages.
/// Requiring `Copy` keeps this ergonomic and ensures that implementations
/// remain lightweight (e.g., wrappers around `Ipv4Net`/`Ipv6Net` or similar
/// address/prefix types) rather than owning heap‑allocated state.
///
/// # When to implement
///
/// Implement this trait if you introduce a new route representation that
/// should participate in the shared add/remove/rollback logic in this
/// module—for example, to support an additional IP family or a different
/// way of encoding networks. Implementors must:
///
/// - Be cheap to copy (`Copy` + `Clone` semantics).
/// - Provide platform‑specific argument builders for macOS (`route` /
///   `networksetup`) and Linux (`ip route`).
///
/// Most consumers should not need to implement `Route` directly; instead they
/// use the existing concrete route types provided by this crate.
pub trait Route: std::fmt::Display + Copy {
    /// Label for log messages (e.g., "route" or "IPv6 route").
    const LABEL: &'static str;

    /// Build command args for adding a route on macOS.
    fn macos_add_args(&self, tun_name: &str) -> Vec<String>;

    /// Build command args for removing a route on macOS.
    fn macos_delete_args(&self, tun_name: &str) -> Vec<String>;

    /// Build command args for adding a route on Linux.
    fn linux_add_args(&self, tun_name: &str) -> Vec<String>;

    /// Build command args for removing a route on Linux.
    fn linux_delete_args(&self, tun_name: &str) -> Vec<String>;
}

impl Route for Ipv4Net {
    const LABEL: &'static str = "route";

    fn macos_add_args(&self, tun_name: &str) -> Vec<String> {
        vec![
            "add".into(),
            "-net".into(),
            self.network().to_string(),
            "-netmask".into(),
            self.netmask().to_string(),
            "-interface".into(),
            tun_name.into(),
        ]
    }

    fn macos_delete_args(&self, tun_name: &str) -> Vec<String> {
        vec![
            "delete".into(),
            "-net".into(),
            self.network().to_string(),
            "-netmask".into(),
            self.netmask().to_string(),
            "-interface".into(),
            tun_name.into(),
        ]
    }

    fn linux_add_args(&self, tun_name: &str) -> Vec<String> {
        vec![
            "route".into(),
            "add".into(),
            self.to_string(),
            "dev".into(),
            tun_name.into(),
        ]
    }

    fn linux_delete_args(&self, tun_name: &str) -> Vec<String> {
        vec![
            "route".into(),
            "del".into(),
            self.to_string(),
            "dev".into(),
            tun_name.into(),
        ]
    }
}

impl Route for Ipv6Net {
    const LABEL: &'static str = "IPv6 route";

    fn macos_add_args(&self, tun_name: &str) -> Vec<String> {
        vec![
            "add".into(),
            "-inet6".into(),
            self.to_string(),
            "-interface".into(),
            tun_name.into(),
        ]
    }

    fn macos_delete_args(&self, tun_name: &str) -> Vec<String> {
        vec![
            "delete".into(),
            "-inet6".into(),
            self.to_string(),
            "-interface".into(),
            tun_name.into(),
        ]
    }

    fn linux_add_args(&self, tun_name: &str) -> Vec<String> {
        vec![
            "-6".into(),
            "route".into(),
            "add".into(),
            self.to_string(),
            "dev".into(),
            tun_name.into(),
        ]
    }

    fn linux_delete_args(&self, tun_name: &str) -> Vec<String> {
        vec![
            "-6".into(),
            "route".into(),
            "del".into(),
            self.to_string(),
            "dev".into(),
            tun_name.into(),
        ]
    }
}

// ============================================================================
// Generic Route Operations
// ============================================================================

/// Handle the output of a route add command (generic version).
///
/// - On success: logs info message
/// - On failure with "route exists": logs warning, returns Ok (idempotent)
/// - On other failure: returns error
fn handle_route_add_output<R: Route>(
    output: std::process::Output,
    route: &R,
    tun_name: &str,
) -> VpnResult<()> {
    if output.status.success() {
        log::info!("Added {} {} via {}", R::LABEL, route, tun_name);
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let stderr_trimmed = stderr.trim();
    if is_already_exists_error(&stderr) {
        log::warn!(
            "{} {} already exists (treating as success): {}",
            R::LABEL,
            route,
            stderr_trimmed
        );
        Ok(())
    } else {
        Err(VpnError::TunDevice(format!(
            "Failed to add {} {}: {}",
            R::LABEL,
            route,
            stderr_trimmed
        )))
    }
}

/// Handle the output of a route remove command (generic, best-effort).
fn handle_route_remove_output<R: Route>(
    output: std::process::Output,
    route: &R,
    tun_name: &str,
) {
    if output.status.success() {
        log::info!("Removed {} {} via {}", R::LABEL, route, tun_name);
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        log::warn!("Failed to remove {} {}: {}", R::LABEL, route, stderr.trim());
    }
}

/// Add a route through the VPN TUN interface (generic version).
async fn add_route_generic<R: Route>(tun_name: &str, route: &R) -> VpnResult<()> {
    #[cfg(target_os = "macos")]
    {
        let args = route.macos_add_args(tun_name);
        let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let output = Command::new("route")
            .args(&args_ref)
            .output()
            .await
            .map_err(|e| VpnError::TunDevice(format!("Failed to execute route command: {}", e)))?;

        handle_route_add_output(output, route, tun_name)
    }

    #[cfg(target_os = "linux")]
    {
        let args = route.linux_add_args(tun_name);
        let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let output = Command::new("ip")
            .args(&args_ref)
            .output()
            .await
            .map_err(|e| {
                VpnError::TunDevice(format!("Failed to execute ip route command: {}", e))
            })?;

        handle_route_add_output(output, route, tun_name)
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (tun_name, route);
        Err(VpnError::TunDevice(
            "Route management not supported on this platform".into(),
        ))
    }
}

/// Remove a route from the system (generic async version).
async fn remove_route_generic<R: Route>(tun_name: &str, route: &R) -> VpnResult<()> {
    #[cfg(target_os = "macos")]
    {
        let args = route.macos_delete_args(tun_name);
        let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let output = Command::new("route")
            .args(&args_ref)
            .output()
            .await
            .map_err(|e| VpnError::TunDevice(format!("Failed to execute route command: {}", e)))?;

        handle_route_remove_output(output, route, tun_name);
    }

    #[cfg(target_os = "linux")]
    {
        let args = route.linux_delete_args(tun_name);
        let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let output = Command::new("ip")
            .args(&args_ref)
            .output()
            .await
            .map_err(|e| {
                VpnError::TunDevice(format!("Failed to execute ip route command: {}", e))
            })?;

        handle_route_remove_output(output, route, tun_name);
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (tun_name, route);
    }

    Ok(())
}

/// Remove a route from the system (generic blocking version for Drop).
fn remove_route_sync_generic<R: Route>(tun_name: &str, route: &R) {
    #[cfg(target_os = "macos")]
    {
        let args = route.macos_delete_args(tun_name);
        let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let result = std::process::Command::new("route").args(&args_ref).output();

        match result {
            Ok(output) if output.status.success() => {
                log::info!("Removed {} {} via {}", R::LABEL, route, tun_name);
            }
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                log::warn!("Failed to remove {} {}: {}", R::LABEL, route, stderr);
            }
            Err(e) => {
                log::warn!("Failed to execute route delete command: {}", e);
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        let args = route.linux_delete_args(tun_name);
        let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let result = std::process::Command::new("ip").args(&args_ref).output();

        match result {
            Ok(output) if output.status.success() => {
                log::info!("Removed {} {} via {}", R::LABEL, route, tun_name);
            }
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                log::warn!("Failed to remove {} {}: {}", R::LABEL, route, stderr);
            }
            Err(e) => {
                log::warn!("Failed to execute ip route del command: {}", e);
            }
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (tun_name, route);
    }
}

// ============================================================================
// IPv4 Route Public API (delegates to generic implementations)
// ============================================================================

/// Add a route through the VPN TUN interface.
///
/// If the route already exists, this is treated as idempotent success
/// (logs a warning and continues).
///
/// # Platform Support
/// - macOS: Uses `route add -net <cidr> -interface <tun_device>`
/// - Linux: Uses `ip route add <cidr> dev <tun_device>`
pub async fn add_route(tun_name: &str, route: &Ipv4Net) -> VpnResult<()> {
    add_route_generic(tun_name, route).await
}

/// Add multiple routes through the VPN TUN interface.
///
/// Returns a `RouteGuard` that automatically removes the routes when dropped.
/// If any route fails to add, previously added routes are rolled back.
pub async fn add_routes(tun_name: &str, routes: &[Ipv4Net]) -> VpnResult<RouteGuard> {
    let mut added: Vec<Ipv4Net> = Vec::with_capacity(routes.len());

    for route in routes {
        if let Err(e) = add_route(tun_name, route).await {
            // Rollback previously added routes
            log::warn!("Failed to add route {}, rolling back {} route(s)", route, added.len());
            for added_route in added.iter().rev() {
                if let Err(rollback_err) = remove_route(tun_name, added_route).await {
                    log::warn!("Rollback failed for route {}: {}", added_route, rollback_err);
                }
            }
            return Err(e);
        }
        added.push(*route);
    }
    Ok(RouteGuard::new(tun_name.to_string(), added))
}

/// Remove a route from the system (async version).
///
/// This is called during cleanup to remove routes added by add_route.
/// Best-effort: command failures are logged as warnings but don't return errors.
pub async fn remove_route(tun_name: &str, route: &Ipv4Net) -> VpnResult<()> {
    remove_route_generic(tun_name, route).await
}

/// Remove a route from the system (blocking version for Drop).
fn remove_route_sync(tun_name: &str, route: &Ipv4Net) {
    remove_route_sync_generic(tun_name, route);
}

/// Guard that automatically removes routes when dropped.
///
/// This ensures routes are cleaned up even if the VPN connection
/// terminates unexpectedly or the program panics.
pub struct RouteGuard {
    tun_name: String,
    routes: Vec<Ipv4Net>,
}

impl RouteGuard {
    /// Create a new RouteGuard (internal use only).
    fn new(tun_name: String, routes: Vec<Ipv4Net>) -> Self {
        Self { tun_name, routes }
    }

    /// Get the routes managed by this guard.
    pub fn routes(&self) -> &[Ipv4Net] {
        &self.routes
    }
}

impl Drop for RouteGuard {
    fn drop(&mut self) {
        if self.routes.is_empty() {
            return;
        }
        log::info!("Cleaning up {} route(s) via {}", self.routes.len(), self.tun_name);
        for route in self.routes.iter().rev() {
            remove_route_sync(&self.tun_name, route);
        }
    }
}

// ============================================================================
// IPv6 TUN and Route Management
// ============================================================================

/// Configure IPv6 address on TUN device (platform-specific).
#[cfg(target_os = "macos")]
fn configure_tun_ipv6(tun_name: &str, addr: Ipv6Addr, prefix_len: u8) -> VpnResult<()> {
    let output = std::process::Command::new("ifconfig")
        .args([
            tun_name,
            "inet6",
            "add",
            &addr.to_string(),
            "prefixlen",
            &prefix_len.to_string(),
        ])
        .output()
        .map_err(|e| VpnError::TunDevice(format!("Failed to configure IPv6: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(VpnError::TunDevice(format!(
            "IPv6 configuration failed: {}",
            stderr.trim()
        )));
    }

    Ok(())
}

/// Configure IPv6 address on TUN device (platform-specific).
#[cfg(target_os = "linux")]
fn configure_tun_ipv6(tun_name: &str, addr: Ipv6Addr, prefix_len: u8) -> VpnResult<()> {
    let output = std::process::Command::new("ip")
        .args([
            "-6",
            "addr",
            "add",
            &format!("{}/{}", addr, prefix_len),
            "dev",
            tun_name,
        ])
        .output()
        .map_err(|e| VpnError::TunDevice(format!("Failed to configure IPv6: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Treat "address already exists" as idempotent success
        if is_already_exists_error(&stderr) {
            log::warn!(
                "IPv6 address {}/{} already exists on {} (treating as success)",
                addr,
                prefix_len,
                tun_name
            );
            return Ok(());
        }
        return Err(VpnError::TunDevice(format!(
            "IPv6 configuration failed: {}",
            stderr.trim()
        )));
    }

    Ok(())
}

/// Configure IPv6 address on TUN device (unsupported platform stub).
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn configure_tun_ipv6(_tun_name: &str, _addr: Ipv6Addr, _prefix_len: u8) -> VpnResult<()> {
    Err(VpnError::TunDevice(
        "IPv6 configuration not supported on this platform".into(),
    ))
}

/// Add an IPv6 route through the VPN TUN interface.
///
/// If the route already exists, this is treated as idempotent success.
pub async fn add_route6(tun_name: &str, route: &Ipv6Net) -> VpnResult<()> {
    add_route_generic(tun_name, route).await
}

/// Remove an IPv6 route from the system (async version).
pub async fn remove_route6(tun_name: &str, route: &Ipv6Net) -> VpnResult<()> {
    remove_route_generic(tun_name, route).await
}

/// Remove an IPv6 route from the system (blocking version for Drop).
fn remove_route6_sync(tun_name: &str, route: &Ipv6Net) {
    remove_route_sync_generic(tun_name, route);
}

/// Add multiple IPv6 routes through the VPN TUN interface.
///
/// Returns a `Route6Guard` that automatically removes the routes when dropped.
/// If any route fails to add, previously added routes are rolled back.
pub async fn add_routes6(tun_name: &str, routes: &[Ipv6Net]) -> VpnResult<Route6Guard> {
    let mut added: Vec<Ipv6Net> = Vec::with_capacity(routes.len());

    for route in routes {
        if let Err(e) = add_route6(tun_name, route).await {
            // Rollback previously added routes
            log::warn!(
                "Failed to add IPv6 route {}, rolling back {} route(s)",
                route,
                added.len()
            );
            for added_route in added.iter().rev() {
                if let Err(rollback_err) = remove_route6(tun_name, added_route).await {
                    log::warn!(
                        "Rollback failed for IPv6 route {}: {}",
                        added_route,
                        rollback_err
                    );
                }
            }
            return Err(e);
        }
        added.push(*route);
    }
    Ok(Route6Guard::new(tun_name.to_string(), added))
}

/// Guard that automatically removes IPv6 routes when dropped.
///
/// This ensures routes are cleaned up even if the VPN connection
/// terminates unexpectedly or the program panics.
pub struct Route6Guard {
    tun_name: String,
    routes: Vec<Ipv6Net>,
}

impl Route6Guard {
    /// Create a new Route6Guard (internal use only).
    fn new(tun_name: String, routes: Vec<Ipv6Net>) -> Self {
        Self { tun_name, routes }
    }

    /// Get the routes managed by this guard.
    pub fn routes(&self) -> &[Ipv6Net] {
        &self.routes
    }
}

impl Drop for Route6Guard {
    fn drop(&mut self) {
        if self.routes.is_empty() {
            return;
        }
        log::info!(
            "Cleaning up {} IPv6 route(s) via {}",
            self.routes.len(),
            self.tun_name
        );
        for route in self.routes.iter().rev() {
            remove_route6_sync(&self.tun_name, route);
        }
    }
}
