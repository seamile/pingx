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
pub async fn check_and_acquire_privileges(cli: &crate::cli::Cli) -> Result<()> {
    // Check if we need raw socket privileges by inspecting all targets
    // If we have explicit ICMP flags, we definitely need raw socket.
    let needs_raw_socket = if cli.ipv4 || cli.ipv6 {
        true
    } else {
        // Iterate over targets to check if any requires ICMP
        let mut has_icmp = false;
        for target in &cli.targets {
            match detect_protocol(cli, target) {
                Ok((protocol, _)) => {
                    if let crate::cli::Protocol::Icmp = protocol {
                        has_icmp = true;
                        break;
                    }
                },
                Err(_) => {
                    // If detection fails, we might default to ICMP or error out later.
                    // Assuming safe default: if we can't parse it as TCP/HTTP, it might be a hostname for ICMP.
                    has_icmp = true;
                    break;
                }
            }
        }
        has_icmp
    };

    if !needs_raw_socket {
        return Ok(());
    }

    use std::process::Command;
    use std::os::unix::process::CommandExt;
    use socket2::{Domain, Protocol, Socket, Type};
    use std::io::{self, Write};

    // Helper to detect Chinese locale
    fn is_chinese_locale() -> bool {
        let vars = ["LC_ALL", "LC_MESSAGES", "LANG"];
        for var in vars {
            if let Ok(val) = std::env::var(var) 
                && val.to_lowercase().contains("zh") {
                    return true;
            }
        }
        false
    }

    // Try to create an ICMP socket to check permissions.
    // We try DGRAM first (unprivileged), then RAW.
    // If DGRAM works, we don't need to prompt.
    // If DGRAM fails and RAW works, we don't need to prompt.
    // If both fail, and RAW failed with PermissionDenied, we prompt.

    let can_create_dgram = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4)).is_ok();
    if can_create_dgram {
        return Ok(());
    }

    match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)) {
        Ok(_) => return Ok(()),
        Err(e) => {
             // If it's not a permission error, return it
            if e.kind() != std::io::ErrorKind::PermissionDenied {
                return Err(e.into());
            }
        }
    }

    let is_zh = is_chinese_locale();

    if is_zh {
        println!("{} 使用原生 Raw Sockets 以获得最佳性能，这需要 'cap_net_raw' 权限。", "pingx".bold());
        println!("是否立即通过 sudo 授予此权限？（一次性设置）");
    } else {
        println!("{} uses native Raw Sockets for best performance, this requires 'cap_net_raw' capability.", "pingx".bold());
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

    if input != "y" && !input.is_empty() && input != "yes" {
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
pub async fn check_and_acquire_privileges(_cli: &crate::cli::Cli) -> Result<()> {
    Ok(())
}

pub fn detect_protocol(cli: &crate::cli::Cli, target: &str) -> Result<(crate::cli::Protocol, String)> {
    // 1. Force Mode
    if cli.ipv4 || cli.ipv6 {
        return Ok((crate::cli::Protocol::Icmp, target.to_string()));
    }
    if cli.tcp {
        if let Some((host, port_str)) = target.rsplit_once(':') {
             let host = if host.starts_with('[') && host.ends_with(']') {
                 &host[1..host.len()-1]
             } else {
                 host
             };

             if let Ok(port) = port_str.parse::<u16>() {
                 return Ok((crate::cli::Protocol::Tcp(port), host.to_string()));
             }
        }
        return Err(anyhow::anyhow!("TCP mode requires target format <host>:<port>"));
    }
    if cli.http {
        let url_str = if target.starts_with("http") { target.to_string() } else { format!("http://{}", target) };
        if let Ok(url) = reqwest::Url::parse(&url_str) 
            && let Some(host) = url.host_str() {
                return Ok((crate::cli::Protocol::Http(url_str), host.to_string()));
        }
        // Fallback if parsing fails?
        return Ok((crate::cli::Protocol::Http(target.to_string()), target.to_string()));
    }

    // 2. Auto Mode
    if target.starts_with("http://") || target.starts_with("https://") {
         if let Ok(url) = reqwest::Url::parse(target) 
            && let Some(host) = url.host_str() {
                return Ok((crate::cli::Protocol::Http(target.to_string()), host.to_string()));
        }
        return Ok((crate::cli::Protocol::Http(target.to_string()), target.to_string()));
    }

    // Check for TCP format (host:port)
    if let Some((host, port_str)) = target.rsplit_once(':') 
         && let Ok(port) = port_str.parse::<u16>() {
             // Check if it's a valid IPv6 address (which contains colons)
             if target.parse::<std::net::Ipv6Addr>().is_ok() {
                 // It's a plain IPv6 address, so ICMP
                 return Ok((crate::cli::Protocol::Icmp, target.to_string()));
             }

             // Also check IPv4 just in case
             if target.parse::<std::net::Ipv4Addr>().is_ok() {
                 return Ok((crate::cli::Protocol::Icmp, target.to_string()));
             }

             let clean_host = if host.starts_with('[') && host.ends_with(']') {
                 &host[1..host.len()-1]
             } else {
                 host
             };

             return Ok((crate::cli::Protocol::Tcp(port), clean_host.to_string()));
    }

    // Default ICMP
    Ok((crate::cli::Protocol::Icmp, target.to_string()))
}

pub fn parse_headers(raw_headers: &[String]) -> Result<reqwest::header::HeaderMap> {
    use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
    let mut headers = HeaderMap::new();

    for raw in raw_headers {
        // First split by newline
        for line in raw.split('\n') {
            if line.trim().is_empty() {
                continue;
            }

            // Split by semicolon for potential multiple headers in one line
            let segments: Vec<&str> = line.split(';').collect();
            let mut current_header_name: Option<HeaderName> = None;
            let mut current_header_value = String::new();

            for segment in segments {
                let trimmed = segment.trim();
                if trimmed.is_empty() {
                    continue;
                }

                if let Some((name_part, val_part)) = trimmed.split_once(':') {
                    // If we already had a header in progress, save it
                    if let Some(name) = current_header_name.take() {
                        let value = HeaderValue::from_str(current_header_value.trim())
                            .map_err(|e| anyhow::anyhow!("Invalid header value for '{}': {}", name, e))?;
                        headers.append(name, value);
                    }

                    // Start new header
                    let name = HeaderName::from_bytes(name_part.trim().as_bytes())
                        .map_err(|e| anyhow::anyhow!("Invalid header name '{}': {}", name_part, e))?;
                    current_header_name = Some(name);
                    current_header_value = val_part.to_string();
                } else {
                    // No colon, append to previous value if exists (heuristic for semicolons in values)
                    if current_header_name.is_some() {
                        if !current_header_value.is_empty() {
                            current_header_value.push_str("; ");
                        }
                        current_header_value.push_str(trimmed);
                    } else {
                        return Err(anyhow::anyhow!("Invalid header format: '{}'. Expected 'Name: Value'", trimmed));
                    }
                }
            }

            // Save final header in line
            if let Some(name) = current_header_name {
                let value = HeaderValue::from_str(current_header_value.trim())
                    .map_err(|e| anyhow::anyhow!("Invalid header value for '{}': {}", name, e))?;
                headers.append(name, value);
            }
        }
    }

    Ok(headers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_headers() {
        let raw = vec![
            "X-Test: 123".to_string(),
            "A: 1; B: 2".to_string(),
            "Cookie: session=abc; user=xyz".to_string(),
            "Multi:\n  Line: value".to_string(),
        ];
        let headers = parse_headers(&raw).unwrap();
        assert_eq!(headers.get("X-Test").unwrap(), "123");
        assert_eq!(headers.get("A").unwrap(), "1");
        assert_eq!(headers.get("B").unwrap(), "2");
        assert_eq!(headers.get("Cookie").unwrap(), "session=abc; user=xyz");
        assert_eq!(headers.get("Line").unwrap(), "value");
    }

    #[test]
    fn test_parse_headers_invalid() {
        let raw = vec!["Invalid".to_string()];
        assert!(parse_headers(&raw).is_err());
    }

    #[tokio::test]
    async fn test_resolve_host_filtering() {
        // IPv4
        let addrs = resolve_host("127.0.0.1", IpVersion::Any).await.unwrap();
        assert_eq!(addrs.len(), 1);
        assert!(addrs[0].is_ipv4());

        let addrs = resolve_host("127.0.0.1", IpVersion::V4).await.unwrap();
        assert_eq!(addrs.len(), 1);
        
        let res = resolve_host("127.0.0.1", IpVersion::V6).await;
        assert!(res.is_err());

        // IPv6
        let addrs = resolve_host("::1", IpVersion::Any).await.unwrap();
        assert_eq!(addrs.len(), 1);
        assert!(addrs[0].is_ipv6());

        let addrs = resolve_host("::1", IpVersion::V6).await.unwrap();
        assert_eq!(addrs.len(), 1);

        let res = resolve_host("::1", IpVersion::V4).await;
        assert!(res.is_err());
    }

    #[test]
    fn test_detect_protocol() {
        let mut cli = crate::cli::Cli {
            targets: vec![],
            count: None,
            interval: std::time::Duration::from_secs(1),
            timeout: std::time::Duration::from_secs(1),
            deadline: None,
            ttl: 64,
            size: 56,
            quiet: false,
            ipv4: false,
            ipv6: false,
            tcp: false,
            http: false,
            headers: vec![],
        };

        // 1. Basic ICMP (Domain)
        let (proto, target) = detect_protocol(&cli, "google.com").unwrap();
        assert_eq!(proto, crate::cli::Protocol::Icmp);
        assert_eq!(target, "google.com");

        // 2. Basic ICMP (IPv4)
        let (proto, target) = detect_protocol(&cli, "8.8.8.8").unwrap();
        assert_eq!(proto, crate::cli::Protocol::Icmp);
        assert_eq!(target, "8.8.8.8");

        // 3. Basic ICMP (IPv6)
        let (proto, target) = detect_protocol(&cli, "2001:4860:4860::8888").unwrap();
        assert_eq!(proto, crate::cli::Protocol::Icmp);
        assert_eq!(target, "2001:4860:4860::8888");

        // 4. Auto TCP (host:port)
        let (proto, target) = detect_protocol(&cli, "google.com:80").unwrap();
        assert_eq!(proto, crate::cli::Protocol::Tcp(80));
        assert_eq!(target, "google.com");

        // 5. Auto HTTP (http://)
        let (proto, target) = detect_protocol(&cli, "http://google.com").unwrap();
        assert!(matches!(proto, crate::cli::Protocol::Http(ref s) if s == "http://google.com"));
        assert_eq!(target, "google.com");

        // 6. Auto HTTPS (https://)
        let (proto, target) = detect_protocol(&cli, "https://google.com").unwrap();
        assert!(matches!(proto, crate::cli::Protocol::Http(ref s) if s == "https://google.com"));
        assert_eq!(target, "google.com");

        // 7. Force TCP
        cli.tcp = true;
        let (proto, target) = detect_protocol(&cli, "google.com:443").unwrap();
        assert_eq!(proto, crate::cli::Protocol::Tcp(443));
        assert_eq!(target, "google.com");
        cli.tcp = false;

        // 8. Force HTTP
        cli.http = true;
        let (proto, target) = detect_protocol(&cli, "google.com").unwrap();
        assert!(matches!(proto, crate::cli::Protocol::Http(ref s) if s == "http://google.com"));
        assert_eq!(target, "google.com");
        cli.http = false;

        // 9. Force IPv4 (ICMP)
        cli.ipv4 = true;
        let (proto, target) = detect_protocol(&cli, "google.com").unwrap();
        assert_eq!(proto, crate::cli::Protocol::Icmp);
        assert_eq!(target, "google.com");
        cli.ipv4 = false;
    }
}
