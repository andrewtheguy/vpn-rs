//! TUN device creation and management.
//!
//! This module handles creating and managing TUN network interfaces
//! for VPN traffic.

use crate::error::{VpnError, VpnResult};
use ipnet::{Ipv4Net, Ipv6Net};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
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
    /// MTU for the device (default: 1440, accounts for QUIC/TLS overhead).
    pub mtu: u16,
}

/// Validate IPv6 prefix length (must be 0-128).
fn validate_prefix_len6(prefix_len6: u8) -> VpnResult<()> {
    if prefix_len6 > 128 {
        return Err(VpnError::Config(format!(
            "Invalid IPv6 prefix length {}: must be 0-128",
            prefix_len6
        )));
    }
    Ok(())
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
            mtu: 1440,
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
        validate_prefix_len6(prefix_len6)?;
        self.address6 = Some(address6);
        self.prefix_len6 = Some(prefix_len6);
        Ok(self)
    }

    /// Create IPv6-only TUN configuration.
    ///
    /// For IPv6-only VPN networks, this creates a TUN configuration with
    /// a unique placeholder IPv4 address in the link-local range (169.254.x.x)
    /// that satisfies the device creation requirements but won't interfere
    /// with real traffic.
    ///
    /// The placeholder IP is derived from the IPv6 address to ensure uniqueness
    /// when multiple IPv6-only TUN devices are created on the same host.
    ///
    /// # Errors
    /// Returns an error if `prefix_len6` is greater than 128.
    pub fn ipv6_only(address6: Ipv6Addr, prefix_len6: u8, mtu: u16) -> VpnResult<Self> {
        validate_prefix_len6(prefix_len6)?;
        // Use a link-local placeholder address that won't conflict with real traffic.
        // This satisfies TUN creation on platforms that require IPv4 (macOS/Windows
        // in tun 0.8.x), but won't affect IPv4 routing.
        //
        // Derive unique placeholder from IPv6 address to avoid conflicts when
        // multiple IPv6-only TUN devices exist on the same host.
        // In ipv6_only, we hash full octets so placeholder_ip/placeholder_netmask
        // are more unique than the previous last-two-bytes-only approach.
        let octets = address6.octets();
        // Hash all IPv6 bytes into two stable bytes, then ensure we stay in
        // the 169.254.1.1 - 169.254.254.254 range (avoiding reserved .0/.255
        // subnets and .0/.255 host addresses).
        let mut hash: u16 = 0x9e37;
        for (idx, byte) in octets.iter().enumerate() {
            hash = hash.rotate_left(5) ^ (*byte as u16).wrapping_add(idx as u16);
        }
        let third = ((hash as u8) % 254) + 1; // 1-254 (uniform distribution)
        let fourth = (((hash >> 8) as u8) % 254) + 1; // 1-254 (uniform distribution)
        let placeholder_ip = Ipv4Addr::new(169, 254, third, fourth);
        let placeholder_netmask = Ipv4Addr::new(255, 255, 255, 255);
        Ok(Self {
            name: None,
            address: placeholder_ip,
            netmask: placeholder_netmask,
            destination: placeholder_ip,
            address6: Some(address6),
            prefix_len6: Some(prefix_len6),
            mtu,
        })
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
/// - Windows netsh: "The object already exists" or "Element already exists"
fn is_already_exists_error(stderr: &str) -> bool {
    let lower = stderr.to_lowercase();
    lower.contains("file exists")
        || lower.contains("eexist")
        || lower.contains("object already exists")
        || lower.contains("element already exists")
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

    /// Build command args for adding a route on Windows.
    fn windows_add_args(&self, tun_name: &str) -> Vec<String>;

    /// Build command args for removing a route on Windows.
    fn windows_delete_args(&self, tun_name: &str) -> Vec<String>;
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

    fn windows_add_args(&self, tun_name: &str) -> Vec<String> {
        vec![
            "interface".into(),
            "ipv4".into(),
            "add".into(),
            "route".into(),
            format!("prefix={}", self),
            format!("interface={}", tun_name),
            "nexthop=0.0.0.0".into(),
            "store=active".into(),
        ]
    }

    fn windows_delete_args(&self, tun_name: &str) -> Vec<String> {
        vec![
            "interface".into(),
            "ipv4".into(),
            "delete".into(),
            "route".into(),
            format!("prefix={}", self),
            format!("interface={}", tun_name),
            "nexthop=0.0.0.0".into(),
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

    fn windows_add_args(&self, tun_name: &str) -> Vec<String> {
        vec![
            "interface".into(),
            "ipv6".into(),
            "add".into(),
            "route".into(),
            format!("prefix={}", self),
            format!("interface={}", tun_name),
            "nexthop=::".into(),
            "store=active".into(),
        ]
    }

    fn windows_delete_args(&self, tun_name: &str) -> Vec<String> {
        vec![
            "interface".into(),
            "ipv6".into(),
            "delete".into(),
            "route".into(),
            format!("prefix={}", self),
            format!("interface={}", tun_name),
            "nexthop=::".into(),
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
fn handle_route_remove_output<R: Route>(output: std::process::Output, route: &R, tun_name: &str) {
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

    #[cfg(target_os = "windows")]
    {
        let args = route.windows_add_args(tun_name);
        let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let output = Command::new("netsh")
            .args(&args_ref)
            .output()
            .await
            .map_err(|e| VpnError::TunDevice(format!("Failed to execute netsh command: {}", e)))?;

        handle_route_add_output(output, route, tun_name)
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
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

    #[cfg(target_os = "windows")]
    {
        let args = route.windows_delete_args(tun_name);
        let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let output = Command::new("netsh")
            .args(&args_ref)
            .output()
            .await
            .map_err(|e| VpnError::TunDevice(format!("Failed to execute netsh command: {}", e)))?;

        handle_route_remove_output(output, route, tun_name);
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
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

    #[cfg(target_os = "windows")]
    {
        let args = route.windows_delete_args(tun_name);
        let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let result = std::process::Command::new("netsh").args(&args_ref).output();

        match result {
            Ok(output) if output.status.success() => {
                log::info!("Removed {} {} via {}", R::LABEL, route, tun_name);
            }
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                log::warn!("Failed to remove {} {}: {}", R::LABEL, route, stderr);
            }
            Err(e) => {
                log::warn!("Failed to execute netsh route delete command: {}", e);
            }
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
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
            log::warn!(
                "Failed to add route {}, rolling back {} route(s)",
                route,
                added.len()
            );
            for added_route in added.iter().rev() {
                if let Err(rollback_err) = remove_route(tun_name, added_route).await {
                    log::warn!(
                        "Rollback failed for route {}: {}",
                        added_route,
                        rollback_err
                    );
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
        log::info!(
            "Cleaning up {} route(s) via {}",
            self.routes.len(),
            self.tun_name
        );
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

/// Configure IPv6 address on TUN device (Windows).
#[cfg(target_os = "windows")]
fn configure_tun_ipv6(tun_name: &str, addr: Ipv6Addr, prefix_len: u8) -> VpnResult<()> {
    let output = std::process::Command::new("netsh")
        .args([
            "interface",
            "ipv6",
            "add",
            "address",
            &format!("interface={}", tun_name),
            &format!("address={}/{}", addr, prefix_len),
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
#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
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

/// Add an IPv6 route with an explicit source address.
///
/// This is important when the client has multiple IPv6 addresses (e.g., a real
/// public IPv6 and a VPN-assigned IPv6). Without specifying the source, the kernel
/// may select the wrong source address for packets routed through this route.
///
/// If the route already exists, this is treated as idempotent success.
pub async fn add_route6_with_src(
    tun_name: &str,
    route: &Ipv6Net,
    src: Ipv6Addr,
) -> VpnResult<()> {
    #[cfg(target_os = "macos")]
    {
        // macOS doesn't support source address in routes the same way
        // Fall back to standard route addition
        log::debug!(
            "macOS: ignoring source address {} for IPv6 route {} via {}",
            src, route, tun_name
        );
        add_route_generic(tun_name, route).await
    }

    #[cfg(target_os = "linux")]
    {
        let output = Command::new("ip")
            .args([
                "-6",
                "route",
                "add",
                &route.to_string(),
                "dev",
                tun_name,
                "src",
                &src.to_string(),
            ])
            .output()
            .await
            .map_err(|e| {
                VpnError::TunDevice(format!("Failed to execute ip route command: {}", e))
            })?;

        if output.status.success() {
            log::info!("Added IPv6 route {} via {} src {}", route, tun_name, src);
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        let stderr_trimmed = stderr.trim();
        if is_already_exists_error(&stderr) {
            log::warn!(
                "IPv6 route {} already exists (treating as success): {}",
                route,
                stderr_trimmed
            );
            Ok(())
        } else {
            Err(VpnError::TunDevice(format!(
                "Failed to add IPv6 route {}: {}",
                route, stderr_trimmed
            )))
        }
    }

    #[cfg(target_os = "windows")]
    {
        // Windows doesn't support source address in routes the same way
        // Fall back to standard route addition
        log::debug!(
            "Windows: ignoring source address {} for IPv6 route {} via {}",
            src, route, tun_name
        );
        add_route_generic(tun_name, route).await
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        let _ = (tun_name, route, src);
        Err(VpnError::TunDevice(
            "Route management not supported on this platform".into(),
        ))
    }
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

/// Add multiple IPv6 routes with an explicit source address.
///
/// This variant specifies the source address for route selection, which is
/// important when the client has multiple IPv6 addresses. Without specifying
/// the source, the kernel may select the wrong source address.
///
/// Returns a `Route6Guard` that automatically removes the routes when dropped.
/// If any route fails to add, previously added routes are rolled back.
pub async fn add_routes6_with_src(
    tun_name: &str,
    routes: &[Ipv6Net],
    src: Ipv6Addr,
) -> VpnResult<Route6Guard> {
    let mut added: Vec<Ipv6Net> = Vec::with_capacity(routes.len());

    for route in routes {
        if let Err(e) = add_route6_with_src(tun_name, route, src).await {
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

// ============================================================================
// Bypass Route Management (for ICE peer addresses)
// ============================================================================

/// Information about a bypass route for an ICE peer.
#[derive(Debug)]
struct BypassRouteInfo {
    /// The peer address to bypass.
    peer_ip: IpAddr,
    /// The device/interface to route through.
    device: String,
    /// The gateway (optional, for some routes it's direct).
    gateway: Option<IpAddr>,
    /// Raw gateway string with scope ID preserved (e.g., "fe80::1%en0").
    /// Used on macOS where link-local addresses need the scope.
    gateway_str: Option<String>,
}

/// Query the current route for a given IP address.
///
/// Returns the device and optional gateway that the OS would use to reach this IP.
#[cfg(target_os = "linux")]
async fn query_route_for_ip(ip: IpAddr) -> VpnResult<BypassRouteInfo> {
    let ip_str = ip.to_string();
    let args: Vec<&str> = if ip.is_ipv4() {
        vec!["route", "get", &ip_str]
    } else {
        vec!["-6", "route", "get", &ip_str]
    };

    let output = Command::new("ip")
        .args(&args)
        .output()
        .await
        .map_err(|e| VpnError::TunDevice(format!("Failed to query route: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(VpnError::TunDevice(format!(
            "Failed to query route for {}: {}",
            ip,
            stderr.trim()
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_linux_route_get(&stdout, ip)
}

/// Parse the output of `ip route get` on Linux.
#[cfg(target_os = "linux")]
fn parse_linux_route_get(output: &str, peer_ip: IpAddr) -> VpnResult<BypassRouteInfo> {
    // Example output:
    // 2600:1f13:adc:a0b1::1 from :: via fe80::1 dev eth0 proto static src 2603:8002:... metric 100
    // or for direct routes:
    // 10.0.0.1 dev eth0 src 10.0.0.2 uid 0

    let mut device: Option<String> = None;
    let mut gateway: Option<IpAddr> = None;
    let mut gateway_str: Option<String> = None;

    let tokens: Vec<&str> = output.split_whitespace().collect();
    for i in 0..tokens.len() {
        if tokens[i] == "dev" && i + 1 < tokens.len() {
            device = Some(tokens[i + 1].to_string());
        }
        if tokens[i] == "via" && i + 1 < tokens.len() {
            gateway_str = Some(tokens[i + 1].to_string());
            gateway = tokens[i + 1].parse().ok();
        }
    }

    let device = device.ok_or_else(|| {
        VpnError::TunDevice(format!(
            "Could not determine device for route to {}",
            peer_ip
        ))
    })?;

    Ok(BypassRouteInfo {
        peer_ip,
        device,
        gateway,
        gateway_str,
    })
}

/// Query the current route for a given IP address (macOS).
#[cfg(target_os = "macos")]
async fn query_route_for_ip(ip: IpAddr) -> VpnResult<BypassRouteInfo> {
    let ip_str = ip.to_string();
    let args: Vec<&str> = if ip.is_ipv4() {
        vec!["get", &ip_str]
    } else {
        vec!["get", "-inet6", &ip_str]
    };

    let output = Command::new("route")
        .args(&args)
        .output()
        .await
        .map_err(|e| VpnError::TunDevice(format!("Failed to query route: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(VpnError::TunDevice(format!(
            "Failed to query route for {}: {}",
            ip,
            stderr.trim()
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_macos_route_get(&stdout, ip)
}

/// Parse the output of `route get` on macOS.
#[cfg(target_os = "macos")]
fn parse_macos_route_get(output: &str, peer_ip: IpAddr) -> VpnResult<BypassRouteInfo> {
    // Example output:
    //    route to: 2600:1f13:adc:a0b1::1
    // destination: default
    //        mask: default
    //     gateway: fe80::1%en0
    //   interface: en0

    let mut device: Option<String> = None;
    let mut gateway: Option<IpAddr> = None;
    let mut gateway_str: Option<String> = None;

    for line in output.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("interface:") {
            device = Some(rest.trim().to_string());
        }
        if let Some(rest) = line.strip_prefix("gateway:") {
            let gw_str = rest.trim();
            // Preserve raw gateway string (may include scope like fe80::1%en0)
            gateway_str = Some(gw_str.to_string());
            // Parse IpAddr by stripping scope (for non-route uses)
            let gw_clean = gw_str.split('%').next().unwrap_or(gw_str);
            gateway = gw_clean.parse().ok();
        }
    }

    let device = device.ok_or_else(|| {
        VpnError::TunDevice(format!(
            "Could not determine interface for route to {}",
            peer_ip
        ))
    })?;

    Ok(BypassRouteInfo {
        peer_ip,
        device,
        gateway,
        gateway_str,
    })
}

/// Query the current route for a given IP address (Windows stub).
#[cfg(target_os = "windows")]
async fn query_route_for_ip(ip: IpAddr) -> VpnResult<BypassRouteInfo> {
    // Windows route querying is more complex; for now return an error
    Err(VpnError::TunDevice(
        "Bypass route detection not yet implemented on Windows".into(),
    ))
}

/// Query the current route for a given IP address (unsupported platforms).
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
async fn query_route_for_ip(ip: IpAddr) -> VpnResult<BypassRouteInfo> {
    Err(VpnError::TunDevice(
        "Bypass route detection not supported on this platform".into(),
    ))
}

/// Add a bypass route for an ICE peer address.
///
/// This ensures that traffic to the ICE peer continues to use the original
/// network path even after VPN routes are installed. This is critical because
/// the ICE peer address may fall within a VPN route prefix, which would cause
/// ICE keepalive traffic to be black-holed through the VPN tunnel.
///
/// Returns a guard that removes the bypass route when dropped.
pub async fn add_bypass_route(peer_addr: SocketAddr) -> VpnResult<BypassRouteGuard> {
    let peer_ip = peer_addr.ip();

    // Query current route to this IP before adding any VPN routes
    let route_info = query_route_for_ip(peer_ip).await?;

    log::info!(
        "Adding bypass route for ICE peer {} via {} (gateway: {:?})",
        peer_ip,
        route_info.device,
        route_info.gateway
    );

    // Add host-specific route
    add_bypass_route_impl(&route_info).await?;

    Ok(BypassRouteGuard {
        peer_ip,
        device: route_info.device,
        gateway: route_info.gateway,
        gateway_str: route_info.gateway_str,
    })
}

/// Implementation of adding a bypass route (Linux).
#[cfg(target_os = "linux")]
async fn add_bypass_route_impl(info: &BypassRouteInfo) -> VpnResult<()> {
    let prefix = if info.peer_ip.is_ipv4() { 32 } else { 128 };

    let mut args: Vec<String> = Vec::new();
    if info.peer_ip.is_ipv6() {
        args.push("-6".to_string());
    }
    args.extend([
        "route".to_string(),
        "add".to_string(),
        format!("{}/{}", info.peer_ip, prefix),
    ]);

    if let Some(gw) = info.gateway {
        args.extend(["via".to_string(), gw.to_string()]);
    }
    args.extend(["dev".to_string(), info.device.clone()]);

    let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let output = Command::new("ip")
        .args(&args_ref)
        .output()
        .await
        .map_err(|e| VpnError::TunDevice(format!("Failed to add bypass route: {}", e)))?;

    if output.status.success() {
        log::info!(
            "Added bypass route {}/{} via {}",
            info.peer_ip,
            prefix,
            info.device
        );
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    if is_already_exists_error(&stderr) {
        log::warn!(
            "Bypass route {}/{} already exists (treating as success)",
            info.peer_ip,
            prefix
        );
        return Ok(());
    }

    Err(VpnError::TunDevice(format!(
        "Failed to add bypass route {}/{}: {}",
        info.peer_ip,
        prefix,
        stderr.trim()
    )))
}

/// Implementation of adding a bypass route (macOS).
#[cfg(target_os = "macos")]
async fn add_bypass_route_impl(info: &BypassRouteInfo) -> VpnResult<()> {
    let mut args: Vec<String> = vec!["add".to_string()];

    if info.peer_ip.is_ipv6() {
        args.push("-inet6".to_string());
    }

    args.push("-host".to_string());
    args.push(info.peer_ip.to_string());

    // Use raw gateway_str to preserve scope ID for link-local addresses (e.g., fe80::1%en0)
    if let Some(ref gw_str) = info.gateway_str {
        args.push(gw_str.clone());
    } else {
        args.extend(["-interface".to_string(), info.device.clone()]);
    }

    let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let output = Command::new("route")
        .args(&args_ref)
        .output()
        .await
        .map_err(|e| VpnError::TunDevice(format!("Failed to add bypass route: {}", e)))?;

    if output.status.success() {
        log::info!("Added bypass route for {} via {}", info.peer_ip, info.device);
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    if is_already_exists_error(&stderr) {
        log::warn!(
            "Bypass route for {} already exists (treating as success)",
            info.peer_ip
        );
        return Ok(());
    }

    Err(VpnError::TunDevice(format!(
        "Failed to add bypass route for {}: {}",
        info.peer_ip,
        stderr.trim()
    )))
}

/// Implementation of adding a bypass route (Windows stub).
#[cfg(target_os = "windows")]
async fn add_bypass_route_impl(_info: &BypassRouteInfo) -> VpnResult<()> {
    Err(VpnError::TunDevice(
        "Bypass route not yet implemented on Windows".into(),
    ))
}

/// Implementation of adding a bypass route (unsupported platforms).
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
async fn add_bypass_route_impl(_info: &BypassRouteInfo) -> VpnResult<()> {
    Err(VpnError::TunDevice(
        "Bypass route not supported on this platform".into(),
    ))
}

/// Guard that removes a bypass route when dropped.
pub struct BypassRouteGuard {
    peer_ip: IpAddr,
    device: String,
    gateway: Option<IpAddr>,
    /// Raw gateway string with scope ID preserved (e.g., "fe80::1%en0").
    gateway_str: Option<String>,
}

impl Drop for BypassRouteGuard {
    fn drop(&mut self) {
        log::info!("Removing bypass route for {}", self.peer_ip);
        remove_bypass_route_sync(
            self.peer_ip,
            &self.device,
            self.gateway,
            self.gateway_str.as_deref(),
        );
    }
}

/// Remove a bypass route (Linux, blocking).
#[cfg(target_os = "linux")]
fn remove_bypass_route_sync(
    peer_ip: IpAddr,
    device: &str,
    gateway: Option<IpAddr>,
    _gateway_str: Option<&str>,
) {
    let host_route = if peer_ip.is_ipv4() {
        format!("{}/32", peer_ip)
    } else {
        format!("{}/128", peer_ip)
    };

    let mut args: Vec<String> = Vec::new();
    if peer_ip.is_ipv6() {
        args.push("-6".to_string());
    }
    args.extend([
        "route".to_string(),
        "del".to_string(),
        host_route.clone(),
    ]);

    if let Some(gw) = gateway {
        args.extend(["via".to_string(), gw.to_string()]);
    }
    args.extend(["dev".to_string(), device.to_string()]);

    let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    match std::process::Command::new("ip").args(&args_ref).output() {
        Ok(output) if output.status.success() => {
            log::info!("Removed bypass route {}", host_route);
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            log::warn!("Failed to remove bypass route {}: {}", host_route, stderr.trim());
        }
        Err(e) => {
            log::warn!("Failed to execute route delete: {}", e);
        }
    }
}

/// Remove a bypass route (macOS, blocking).
#[cfg(target_os = "macos")]
fn remove_bypass_route_sync(
    peer_ip: IpAddr,
    _device: &str,
    _gateway: Option<IpAddr>,
    gateway_str: Option<&str>,
) {
    let mut args: Vec<String> = vec!["delete".to_string()];

    if peer_ip.is_ipv6() {
        args.push("-inet6".to_string());
    }

    args.push("-host".to_string());
    args.push(peer_ip.to_string());

    // Use raw gateway_str to preserve scope ID for link-local addresses (e.g., fe80::1%en0)
    if let Some(gw_str) = gateway_str {
        args.push(gw_str.to_string());
    }

    let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    match std::process::Command::new("route").args(&args_ref).output() {
        Ok(output) if output.status.success() => {
            log::info!("Removed bypass route for {}", peer_ip);
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            log::warn!("Failed to remove bypass route for {}: {}", peer_ip, stderr.trim());
        }
        Err(e) => {
            log::warn!("Failed to execute route delete: {}", e);
        }
    }
}

/// Remove a bypass route (Windows stub, blocking).
#[cfg(target_os = "windows")]
fn remove_bypass_route_sync(
    peer_ip: IpAddr,
    device: &str,
    gateway: Option<IpAddr>,
    _gateway_str: Option<&str>,
) {
    log::debug!(
        "Bypass route removal not implemented on Windows (peer: {}, device: {}, gateway: {:?})",
        peer_ip,
        device,
        gateway
    );
}

/// Remove a bypass route (unsupported platforms, blocking).
#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn remove_bypass_route_sync(
    _peer_ip: IpAddr,
    _device: &str,
    _gateway: Option<IpAddr>,
    _gateway_str: Option<&str>,
) {
    // Not implemented
}
