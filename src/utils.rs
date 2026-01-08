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

pub async fn resolve_host(host: &str, version: IpVersion) -> Result<Vec<IpAddr>> {
    // Try to parse as IpAddr first
    if let Ok(addr) = host.parse::<IpAddr>() {
        match (version, addr) {
            (IpVersion::V4, IpAddr::V6(_)) => return Err(anyhow::anyhow!("IPv6 address provided but -4 used")),
            (IpVersion::V6, IpAddr::V4(_)) => return Err(anyhow::anyhow!("IPv4 address provided but -6 used")),
            _ => return Ok(vec![addr]),
        }
    }

    // Resolve domain (assume port 0 as we only need IP)
    let addrs = lookup_host(format!("{}:0", host))
        .await
        .context(format!("Failed to resolve host: {}", host))?;

    let mut resolved_addrs: Vec<IpAddr> = addrs.map(|socket_addr| socket_addr.ip()).collect();

    // Filter based on version
    match version {
        IpVersion::V4 => resolved_addrs.retain(|addr| addr.is_ipv4()),
        IpVersion::V6 => resolved_addrs.retain(|addr| addr.is_ipv6()),
        IpVersion::Any => {
            // Sort: IPv6 first
            resolved_addrs.sort_by_key(|addr| !addr.is_ipv6());
        }
    }

    if resolved_addrs.is_empty() {
        return Err(anyhow::anyhow!("No IP address found for host"));
    }

    Ok(resolved_addrs)
}

#[cfg(target_os = "linux")]
pub async fn check_and_acquire_privileges() -> Result<()> {
    use std::process::Command;
    use std::os::unix::process::CommandExt;
    use surge_ping::{Client, Config, ICMP};
    use std::io::{self, Write};
    
    // Helper to detect Chinese locale
    fn is_chinese_locale() -> bool {
        let vars = ["LC_ALL", "LC_MESSAGES", "LANG"];
        for var in vars {
            if let Ok(val) = std::env::var(var) {
                if val.to_lowercase().contains("zh") {
                    return true;
                }
            }
        }
        false
    }

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

    let is_zh = is_chinese_locale();

    if is_zh {
        println!("{}", format!("{} 使用原生 Raw Sockets 以获得最佳性能，这需要 'cap_net_raw' 权限。", "pingx".bold()).yellow());
        println!("是否立即通过 sudo 授予此权限？（一次性设置）");
    } else {
        println!("{}", format!("{} uses native Raw Sockets for best performance, this requires 'cap_net_raw' capability.", "pingx".bold()).yellow());
        println!("Grant this permission now via sudo? (One-time setup)");
    }
    println!();
    
    let current_exe = std::env::current_exe()?;
    let exe_path = current_exe.to_string_lossy();
    
    println!("{}", format!("  sudo setcap cap_net_raw+ep {}", exe_path).yellow());
    println!();
    
    if is_zh {
        print!("继续？ [Y/n]: ");
    } else {
        print!("Proceed? [Y/n]: ");
    }
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let input = input.trim().to_lowercase();

    if input != "y" && input != "" && input != "yes" {
        let msg = if is_zh { "用户取消操作" } else { "Operation cancelled by user" };
        return Err(anyhow::anyhow!("{}", msg));
    }

    let status = Command::new("sudo")
        .arg("setcap")
        .arg("cap_net_raw+ep")
        .arg(&current_exe)
        .status()
        .context("Failed to execute sudo")?;

    if !status.success() {
        let msg = if is_zh { "授权失败" } else { "Authorization failed" };
        return Err(anyhow::anyhow!("{}", msg));
    }

    if is_zh {
        println!("授权成功！正在重启...");
    } else {
        println!("Authorization successful! Restarting...");
    }
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
