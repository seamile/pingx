use anyhow::{Context, Result};
#[cfg(target_os = "linux")]
use colored::Colorize;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::OnceLock;
use tokio::net::TcpStream;

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
            (IpVersion::V4, IpAddr::V6(_)) => {
                return Err(anyhow::anyhow!("IPv6 address provided but -4 used"));
            }
            (IpVersion::V6, IpAddr::V4(_)) => {
                return Err(anyhow::anyhow!("IPv4 address provided but -6 used"));
            }
            _ => return Ok(vec![addr]),
        }
    }

    let mut resolved_addrs = if let Some(iface) = get_bind_interface() {
        resolve_host_on_interface(host, iface).await?
    } else {
        tokio::net::lookup_host(format!("{}:0", host))
            .await
            .context(format!("Failed to resolve host: {}", host))?
            .map(|socket_addr| socket_addr.ip())
            .collect()
    };

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

async fn resolve_host_on_interface(host: &str, iface: &str) -> Result<Vec<IpAddr>> {
    use hickory_resolver::TokioResolver;
    use hickory_resolver::config::ResolverConfig;
    use hickory_resolver::net::runtime::TokioRuntimeProvider;
    use hickory_resolver::system_conf;

    let source_ips = get_interface_ips(iface);
    let (mut config, options) =
        system_conf::read_system_conf().context("failed to read system DNS configuration")?;
    if config.name_servers().is_empty() {
        return Err(anyhow::anyhow!(
            "system DNS configuration has no nameservers"
        ));
    }
    bind_dns_servers(&mut config, &source_ips)
        .with_context(|| format!("cannot use system DNS via interface '{}'", iface))?;
    let resolver = TokioResolver::builder_with_config(
        ResolverConfig::from_parts(
            config.domain().cloned(),
            config.search().to_vec(),
            config.name_servers().to_vec(),
        ),
        TokioRuntimeProvider::default(),
    )
    .with_options(options)
    .build()?;
    let lookup = resolver.lookup_ip(host).await.with_context(|| {
        format!(
            "failed to resolve host '{}' via interface '{}':",
            host, iface
        )
    })?;
    Ok(lookup.iter().collect())
}

pub(crate) fn bind_dns_servers(
    config: &mut hickory_resolver::config::ResolverConfig,
    source_ips: &[IpAddr],
) -> Result<()> {
    config.name_servers.retain_mut(|server| {
        let Some(&source_ip) = source_ips.iter().find(|ip| {
            ip.is_ipv4() == server.ip.is_ipv4()
                && !matches!(ip, IpAddr::V6(ip) if ip.is_unicast_link_local())
        }) else {
            return false;
        };
        for connection in &mut server.connections {
            connection.bind_addr = Some(SocketAddr::new(source_ip, 0));
        }
        true
    });
    anyhow::ensure!(
        !config.name_servers.is_empty(),
        "no DNS server has a matching usable interface address"
    );
    Ok(())
}

static BIND_INTERFACE: OnceLock<Option<String>> = OnceLock::new();

pub fn set_bind_interface(iface: Option<String>) {
    let _ = BIND_INTERFACE.set(iface);
}

pub fn get_bind_interface() -> Option<&'static str> {
    BIND_INTERFACE.get().and_then(|v| v.as_deref())
}

#[cfg(unix)]
fn interface_name_to_index(name: &str) -> io::Result<std::num::NonZeroU32> {
    use std::ffi::CString;
    let cname = CString::new(name).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "interface name contains null byte",
        )
    })?;
    let index = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if index == 0 {
        return Err(io::Error::last_os_error());
    }
    std::num::NonZeroU32::new(index)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "interface not found"))
}

#[cfg(unix)]
pub fn bind_socket_to_interface(
    socket: &socket2::Socket,
    iface: &str,
    is_ipv6: bool,
) -> io::Result<()> {
    let idx = interface_name_to_index(iface)?;
    if is_ipv6 {
        socket.bind_device_by_index_v6(Some(idx))
    } else {
        socket.bind_device_by_index_v4(Some(idx))
    }
}

#[cfg(not(unix))]
pub fn bind_socket_to_interface(
    _socket: &socket2::Socket,
    _iface: &str,
    _is_ipv6: bool,
) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "interface binding is not supported on this platform",
    ))
}

pub async fn connect_tcp(addr: SocketAddr) -> io::Result<TcpStream> {
    if let Some(iface) = get_bind_interface() {
        connect_tcp_bound(addr, iface).await
    } else {
        TcpStream::connect(addr).await
    }
}

#[cfg(unix)]
async fn connect_tcp_bound(addr: SocketAddr, iface: &str) -> io::Result<TcpStream> {
    use socket2::{Domain, Protocol, SockAddr, Socket, Type};
    let domain = if addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    bind_socket_to_interface(&socket, iface, addr.is_ipv6())?;
    socket.set_tcp_nodelay(true)?;
    socket.set_nonblocking(true)?;
    let sockaddr: SockAddr = addr.into();
    match socket.connect(&sockaddr) {
        Ok(()) => {}
        Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
        Err(e) => return Err(e),
    }
    let stream: std::net::TcpStream = socket.into();
    let tokio_stream = TcpStream::from_std(stream)?;
    tokio_stream.writable().await?;
    Ok(tokio_stream)
}

#[cfg(not(unix))]
async fn connect_tcp_bound(_addr: SocketAddr, _iface: &str) -> io::Result<TcpStream> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "interface binding is not supported on this platform",
    ))
}

#[cfg(unix)]
pub fn get_interface_ips(iface: &str) -> Vec<IpAddr> {
    let mut ifaddrs: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut ifaddrs) } != 0 {
        return Vec::new();
    }
    let mut current = ifaddrs;
    let mut result = Vec::new();
    while !current.is_null() {
        unsafe {
            let ifa = &*current;
            let name_ptr = ifa.ifa_name;
            if !name_ptr.is_null()
                && let Ok(name) = std::ffi::CStr::from_ptr(name_ptr).to_str()
                && name == iface
            {
                let addr = ifa.ifa_addr;
                if !addr.is_null() {
                    let family = (*addr).sa_family as libc::c_int;
                    if family == libc::AF_INET {
                        let sin = &*(addr as *const libc::sockaddr_in);
                        let ip = std::net::Ipv4Addr::from(sin.sin_addr.s_addr.to_be());
                        if !ip.is_loopback() && !ip.is_unspecified() {
                            result.push(IpAddr::V4(ip));
                        }
                    } else if family == libc::AF_INET6 {
                        let sin6 = &*(addr as *const libc::sockaddr_in6);
                        let ip = std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                        if !ip.is_loopback() && !ip.is_unspecified() {
                            result.push(IpAddr::V6(ip));
                        }
                    }
                }
            }
            current = (*current).ifa_next;
        }
    }
    unsafe {
        libc::freeifaddrs(ifaddrs);
    }
    result
}

#[cfg(not(unix))]
pub fn get_interface_ips(_iface: &str) -> Vec<IpAddr> {
    Vec::new()
}

#[cfg(target_os = "linux")]
pub async fn check_and_acquire_privileges(cli: &crate::cli::Cli) -> Result<()> {
    use crate::cli::TraceProtocol;
    if cli.traceroute {
        let needs_raw_socket = cli.trace_target()?.1 != TraceProtocol::Udp;
        if !needs_raw_socket {
            return Ok(());
        }
    }
    // Check whether any non-trace target needs ICMP and therefore a raw socket.
    let needs_raw_socket = if cli.traceroute {
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
                }
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

    use socket2::{Domain, Protocol, Socket, Type};
    use std::io::{self, Write};
    use std::os::unix::process::CommandExt;
    use std::process::Command;

    // Helper to detect Chinese locale
    fn is_chinese_locale() -> bool {
        let vars = ["LC_ALL", "LC_MESSAGES", "LANG"];
        for var in vars {
            if let Ok(val) = std::env::var(var)
                && val.to_lowercase().contains("zh")
            {
                return true;
            }
        }
        false
    }

    // Linux ICMP/TCP traceroute uses RAW sockets even when unprivileged ping is available.
    if !cli.traceroute && Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4)).is_ok() {
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
        println!(
            "{} 使用原生 Raw Sockets 以获得最佳性能，这需要 'cap_net_raw' 权限。",
            "pingx".bold()
        );
        println!("是否立即通过 sudo 授予此权限？（一次性设置）");
    } else {
        println!(
            "{} uses native Raw Sockets for best performance, this requires 'cap_net_raw' capability.",
            "pingx".bold()
        );
        println!("Grant this permission now via sudo? (One-time setup)");
    }
    println!();

    let current_exe = std::env::current_exe()?;
    let exe_path = current_exe.to_string_lossy();

    println!(
        "{}",
        format!("  sudo setcap cap_net_raw+ep {}", exe_path).yellow()
    );
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
        let msg = if is_zh {
            "用户取消操作"
        } else {
            "Operation cancelled by user"
        };
        return Err(anyhow::anyhow!("{}", msg));
    }

    let status = Command::new("sudo")
        .arg("setcap")
        .arg("cap_net_raw+ep")
        .arg(&current_exe)
        .status()
        .context("Failed to execute sudo")?;

    if !status.success() {
        let msg = if is_zh {
            "授权失败"
        } else {
            "Authorization failed"
        };
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
    let err = Command::new(current_exe).args(&args).exec();

    // exec only returns on failure
    Err(anyhow::anyhow!("Failed to restart process: {}", err))
}

#[cfg(not(target_os = "linux"))]
pub async fn check_and_acquire_privileges(_cli: &crate::cli::Cli) -> Result<()> {
    Ok(())
}

pub fn detect_protocol(
    cli: &crate::cli::Cli,
    target: &str,
) -> Result<(crate::cli::Protocol, String)> {
    // 1. Force Mode
    if (cli.ipv4 || cli.ipv6) && !cli.tcp {
        return Ok((crate::cli::Protocol::Icmp, target.to_string()));
    }
    if cli.tcp {
        if let Some((host, port_str)) = target.rsplit_once(':') {
            let host = if host.starts_with('[') && host.ends_with(']') {
                &host[1..host.len() - 1]
            } else {
                host
            };

            if let Ok(port) = port_str.parse::<u16>() {
                return Ok((crate::cli::Protocol::Tcp(port), host.to_string()));
            }
        }
        return Err(anyhow::anyhow!(
            "TCP mode requires target format <host>:<port>"
        ));
    }
    if cli.http {
        let url_str = if target.starts_with("http") {
            target.to_string()
        } else {
            format!("http://{}", target)
        };
        if let Ok(url) = reqwest::Url::parse(&url_str)
            && let Some(host) = url.host_str()
        {
            return Ok((crate::cli::Protocol::Http(url_str), host.to_string()));
        }
        // Fallback if parsing fails?
        return Ok((
            crate::cli::Protocol::Http(target.to_string()),
            target.to_string(),
        ));
    }

    // 2. Auto Mode
    if target.starts_with("http://") || target.starts_with("https://") {
        if let Ok(url) = reqwest::Url::parse(target)
            && let Some(host) = url.host_str()
        {
            return Ok((
                crate::cli::Protocol::Http(target.to_string()),
                host.to_string(),
            ));
        }
        return Ok((
            crate::cli::Protocol::Http(target.to_string()),
            target.to_string(),
        ));
    }

    // Check for TCP format (host:port)
    if let Some((host, port_str)) = target.rsplit_once(':')
        && let Ok(port) = port_str.parse::<u16>()
    {
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
            &host[1..host.len() - 1]
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
        for line in raw.split('\n') {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            // Split by ';' but respect double quotes
            let mut segments = Vec::new();
            let mut current = String::new();
            let mut in_quotes = false;
            for c in line.chars() {
                match c {
                    '"' => {
                        in_quotes = !in_quotes;
                        current.push(c);
                    }
                    ';' if !in_quotes => {
                        segments.push(current.trim().to_string());
                        current = String::new();
                    }
                    _ => current.push(c),
                }
            }
            if !current.trim().is_empty() {
                segments.push(current.trim().to_string());
            }

            for segment in segments {
                if let Some((name_part, val_part)) = segment.split_once(':') {
                    let name = HeaderName::from_bytes(name_part.trim().as_bytes()).map_err(|e| {
                        anyhow::anyhow!(
                            "Invalid header name '{}' in segment '{}': {}\nCorrect format: 'Name: Value'",
                            name_part.trim(),
                            segment,
                            e
                        )
                    })?;

                    let mut val = val_part.trim().to_string();
                    // Strip quotes if they wrap the entire value
                    if val.starts_with('"') && val.ends_with('"') && val.len() >= 2 {
                        val = val[1..val.len() - 1].to_string();
                    }

                    let value = HeaderValue::from_str(&val).map_err(|e| {
                        anyhow::anyhow!(
                            "Invalid header value '{}' for '{}': {}\nCorrect format: 'Name: Value'",
                            val,
                            name,
                            e
                        )
                    })?;
                    headers.append(name, value);
                } else {
                    return Err(anyhow::anyhow!(
                        "Invalid header format: '{}'.\nCorrect format is 'Name: Value'. Multiple headers can be separated by ';'.\nExample: --header \"Cookie: k=v; Authorization: Bearer token\"",
                        segment
                    ));
                }
            }
        }
    }

    Ok(headers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bind_dns_servers_matches_address_families() {
        use hickory_resolver::config::{NameServerConfig, ResolverConfig};

        let ipv4 = "172.20.10.3".parse::<IpAddr>().unwrap();
        let ipv6 = "2001:db8::3".parse::<IpAddr>().unwrap();
        let link_local = "fe80::1468:5da3:36e1:2b81".parse().unwrap();
        let mut config = ResolverConfig::default();
        config.name_servers = vec![
            NameServerConfig::udp_and_tcp("223.5.5.5".parse().unwrap()),
            NameServerConfig::udp_and_tcp("2001:db8::53".parse().unwrap()),
        ];
        let mut dual_stack = config.clone();
        bind_dns_servers(&mut dual_stack, &[link_local, ipv4, ipv6]).unwrap();
        assert_eq!(dual_stack.name_servers.len(), 2);
        for (server, source) in dual_stack.name_servers.iter().zip([ipv4, ipv6]) {
            for connection in &server.connections {
                assert_eq!(connection.bind_addr, Some(SocketAddr::new(source, 0)));
            }
        }

        bind_dns_servers(&mut config, &[link_local, ipv4]).unwrap();
        assert_eq!(config.name_servers.len(), 1);
        assert!(config.name_servers[0].ip.is_ipv4());
        assert!(bind_dns_servers(&mut config, &[link_local]).is_err());
    }

    #[test]
    fn test_parse_headers() {
        let raw = vec![
            "X-Test: 123".to_string(),
            "A: 1; B: 2".to_string(),
            "Cookie: \"session=abc; user=xyz\"".to_string(),
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
        let res = parse_headers(&raw);
        assert!(res.is_err());
        assert!(
            res.unwrap_err()
                .to_string()
                .contains("Correct format is 'Name: Value'")
        );
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
            geo: false,
            fetch_geo: false,
            json: None,
            interface: None,
            traceroute: false,
            trace_protocol: None,
            max_hops: 64,
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
        for flag in ["-4", "-6"] {
            use clap::Parser;
            let cli =
                crate::cli::Cli::try_parse_from(["pingx", flag, "-T", "example.com:443"]).unwrap();
            assert_eq!(
                detect_protocol(&cli, "example.com:443").unwrap(),
                (crate::cli::Protocol::Tcp(443), "example.com".to_string())
            );
        }
    }
}
