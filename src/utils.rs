use anyhow::{Context, Result};
use std::net::IpAddr;
use tokio::net::lookup_host;
#[cfg(target_os = "linux")]
use colored::Colorize;

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

#[cfg(target_os = "linux")]
pub async fn check_and_acquire_privileges() -> Result<()> {
    use std::process::Command;
    use std::os::unix::process::CommandExt;
    use surge_ping::{Client, Config, ICMP};
    use std::io::{self, Write};
    
    // Try to create an ICMPv4 Client to check permissions
    let config = Config::builder().kind(ICMP::V4).build();
    match Client::new(&config) {
        Ok(_) => return Ok(()),
        Err(e) => {
            // If it's not a permission error, return it
            if e.kind() != std::io::ErrorKind::PermissionDenied {
                return Err(e.into());
            }
        }
    };

    println!("{}", format!("{} uses native Raw Sockets for best performance, this requires 'cap_net_raw' capability.", "pingx".bold()).yellow());
    println!("Grant this permission now via sudo? (One-time setup)");
    println!();
    
    let current_exe = std::env::current_exe()?;
    let exe_path = current_exe.to_string_lossy();
    
    println!("{}", format!("  sudo setcap cap_net_raw+ep {}", exe_path).yellow());
    println!();
    print!("Proceed? [Y/n]: ");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let input = input.trim().to_lowercase();

    if input != "y" && input != "" && input != "yes" {
        return Err(anyhow::anyhow!("Operation cancelled by user"));
    }

    let status = Command::new("sudo")
        .arg("setcap")
        .arg("cap_net_raw+ep")
        .arg(&current_exe)
        .status()
        .context("Failed to execute sudo")?;

    if !status.success() {
        return Err(anyhow::anyhow!("Authorization failed"));
    }

    println!("Authorization successful! Restarting...");
    println!("--------------------------------------------------");

    // Get current arguments and restart process
    let args: Vec<String> = std::env::args().skip(1).collect();
    let err = Command::new(current_exe)
        .args(&args)
        .exec();

    // exec only returns on failure
    Err(anyhow::anyhow!("Failed to restart process: {}", err))
}

#[cfg(not(target_os = "linux"))]
pub async fn check_and_acquire_privileges() -> Result<()> {
    Ok(())
}
