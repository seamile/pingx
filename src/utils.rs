use anyhow::{Context, Result};
use std::net::IpAddr;
use tokio::net::lookup_host;

pub async fn resolve_host(host: &str) -> Result<IpAddr> {
    // Try to parse as IpAddr first
    if let Ok(addr) = host.parse::<IpAddr>() {
        return Ok(addr);
    }

    // Resolve domain (assume port 0 as we only need IP)
    let addrs = lookup_host(format!("{}:0", host))
        .await
        .context(format!("Failed to resolve host: {}", host))?;

    let mut resolved_addrs: Vec<IpAddr> = addrs.map(|socket_addr| socket_addr.ip()).collect();

    // Sort: IPv4 first (stable sort to keep order otherwise)
    resolved_addrs.sort_by_key(|addr| !addr.is_ipv4());

    resolved_addrs
        .first()
        .copied()
        .ok_or_else(|| anyhow::anyhow!("No IP address found for host"))
}
