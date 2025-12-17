use anyhow::{Context, Result};
use std::net::IpAddr;
use tokio::net::lookup_host;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum IpVersion {
    V4,
    V6,
    Any,
}

pub async fn resolve_host(host: &str, version: IpVersion) -> Result<IpAddr> {
    // Try to parse as IpAddr first
    if let Ok(addr) = host.parse::<IpAddr>() {
        match (version, addr) {
            (IpVersion::V4, IpAddr::V6(_)) => return Err(anyhow::anyhow!("IPv6 address provided but -4 used")),
            (IpVersion::V6, IpAddr::V4(_)) => return Err(anyhow::anyhow!("IPv4 address provided but -6 used")),
            _ => return Ok(addr),
        }
    }

    // Resolve domain (assume port 0 as we only need IP)
    // Note: if host has :port, lookup_host might handle it?
    // But we are passing just host part here (caller logic handles port stripping).
    // So we append :0.
    let addrs = lookup_host(format!("{}:0", host))
        .await
        .context(format!("Failed to resolve host: {}", host))?;

    let mut resolved_addrs: Vec<IpAddr> = addrs.map(|socket_addr| socket_addr.ip()).collect();

    // Filter based on version
    match version {
        IpVersion::V4 => resolved_addrs.retain(|addr| addr.is_ipv4()),
        IpVersion::V6 => resolved_addrs.retain(|addr| addr.is_ipv6()),
        IpVersion::Any => {
            // Sort: IPv6 first (stable sort to keep order otherwise)
            // sort_by_key: false (0) comes before true (1).
            // is_ipv6(): true for v6.
            // !is_ipv6(): false for v6.
            // So !is_ipv6() puts v6 first.
            resolved_addrs.sort_by_key(|addr| !addr.is_ipv6());
        }
    }

    resolved_addrs
        .first()
        .copied()
        .ok_or_else(|| anyhow::anyhow!("No IP address found for host"))
}
