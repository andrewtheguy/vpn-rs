//! TUN device creation and management.
//!
//! This module handles creating and managing TUN network interfaces
//! for VPN traffic.

use crate::error::{VpnError, VpnResult};
use ipnet::Ipv4Net;
use std::net::Ipv4Addr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tun::{AbstractDevice, AsyncDevice, Configuration, DeviceReader, DeviceWriter};

/// TUN device configuration.
#[derive(Debug, Clone)]
pub struct TunConfig {
    /// Device name (e.g., "tun0"). If None, system assigns a name.
    pub name: Option<String>,
    /// IP address for this end of the tunnel.
    pub address: Ipv4Addr,
    /// Netmask for the VPN network.
    pub netmask: Ipv4Addr,
    /// Destination/gateway IP (peer's VPN address).
    pub destination: Ipv4Addr,
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

/// Add a route through the VPN TUN interface.
///
/// # Platform Support
/// - macOS: Uses `route add -net <cidr> -interface <tun_device>`
/// - Linux: Uses `ip route add <cidr> dev <tun_device>`
pub async fn add_route(tun_name: &str, route: &Ipv4Net) -> VpnResult<()> {
    #[cfg(target_os = "macos")]
    {
        let output = Command::new("route")
            .args([
                "add",
                "-net",
                &route.network().to_string(),
                "-netmask",
                &route.netmask().to_string(),
                "-interface",
                tun_name,
            ])
            .output()
            .await
            .map_err(|e| VpnError::TunDevice(format!("Failed to execute route command: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(VpnError::TunDevice(format!(
                "Failed to add route {}: {}",
                route, stderr
            )));
        }
        log::info!("Added route {} via {}", route, tun_name);
    }

    #[cfg(target_os = "linux")]
    {
        let output = Command::new("ip")
            .args(["route", "add", &route.to_string(), "dev", tun_name])
            .output()
            .await
            .map_err(|e| VpnError::TunDevice(format!("Failed to execute ip route command: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(VpnError::TunDevice(format!(
                "Failed to add route {}: {}",
                route, stderr
            )));
        }
        log::info!("Added route {} via {}", route, tun_name);
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (tun_name, route);
        return Err(VpnError::TunDevice(
            "Route management not supported on this platform".into(),
        ));
    }

    Ok(())
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
pub async fn remove_route(tun_name: &str, route: &Ipv4Net) -> VpnResult<()> {
    #[cfg(target_os = "macos")]
    {
        let output = Command::new("route")
            .args([
                "delete",
                "-net",
                &route.network().to_string(),
                "-netmask",
                &route.netmask().to_string(),
                "-interface",
                tun_name,
            ])
            .output()
            .await
            .map_err(|e| VpnError::TunDevice(format!("Failed to execute route command: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            log::warn!("Failed to remove route {}: {}", route, stderr);
        } else {
            log::info!("Removed route {} via {}", route, tun_name);
        }
    }

    #[cfg(target_os = "linux")]
    {
        let output = Command::new("ip")
            .args(["route", "del", &route.to_string(), "dev", tun_name])
            .output()
            .await
            .map_err(|e| VpnError::TunDevice(format!("Failed to execute ip route command: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            log::warn!("Failed to remove route {}: {}", route, stderr);
        } else {
            log::info!("Removed route {} via {}", route, tun_name);
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (tun_name, route);
    }

    Ok(())
}

/// Remove a route from the system (blocking version for Drop).
fn remove_route_sync(tun_name: &str, route: &Ipv4Net) {
    #[cfg(target_os = "macos")]
    {
        let result = std::process::Command::new("route")
            .args([
                "delete",
                "-net",
                &route.network().to_string(),
                "-netmask",
                &route.netmask().to_string(),
                "-interface",
                tun_name,
            ])
            .output();

        match result {
            Ok(output) if output.status.success() => {
                log::info!("Removed route {} via {}", route, tun_name);
            }
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                log::warn!("Failed to remove route {}: {}", route, stderr);
            }
            Err(e) => {
                log::warn!("Failed to execute route delete command: {}", e);
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        let result = std::process::Command::new("ip")
            .args(["route", "del", &route.to_string(), "dev", tun_name])
            .output();

        match result {
            Ok(output) if output.status.success() => {
                log::info!("Removed route {} via {}", route, tun_name);
            }
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                log::warn!("Failed to remove route {}: {}", route, stderr);
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
