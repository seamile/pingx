use anyhow::{Result, bail, ensure};
use reqwest::Url;
use std::net::{IpAddr, Ipv6Addr};

#[cfg(unix)]
pub(crate) mod tcp_syn;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Protocol {
    Icmp,
    Tcp(u16),
    Udp(u16),
    Http(String),
}

impl Protocol {
    pub fn port(&self) -> Option<u16> {
        match self {
            Self::Tcp(port) | Self::Udp(port) => Some(*port),
            Self::Icmp | Self::Http(_) => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Icmp => "ICMP",
            Self::Tcp(_) => "TCP",
            Self::Udp(_) => "UDP",
            Self::Http(_) => "HTTP",
        }
    }

    pub fn sequence_name(&self) -> &'static str {
        match self {
            Self::Icmp => "icmp_seq",
            Self::Tcp(_) => "tcp_seq",
            Self::Udp(_) => "udp_seq",
            Self::Http(_) => "http_seq",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ProtocolMode {
    #[default]
    Auto,
    Tcp,
    Udp,
    Http,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetSpec {
    pub input: String,
    pub host: String,
    pub protocol: Protocol,
}

impl TargetSpec {
    pub fn parse(input: &str, mode: ProtocolMode, traceroute: bool) -> Result<Self> {
        let (host, protocol) = match mode {
            ProtocolMode::Http => http_target(input)?,
            ProtocolMode::Auto if is_http_target(input) => http_target(input)?,
            mode => {
                let (host, port) = parse_endpoint(input)?;
                let protocol = match mode {
                    ProtocolMode::Auto => port.map_or(Protocol::Icmp, Protocol::Tcp),
                    ProtocolMode::Tcp => Protocol::Tcp(port.unwrap_or(80)),
                    ProtocolMode::Udp => Protocol::Udp(port.unwrap_or(33434)),
                    ProtocolMode::Http => unreachable!(),
                };
                (host, protocol)
            }
        };
        if traceroute {
            ensure!(
                !matches!(protocol, Protocol::Http(_)),
                "HTTP traceroute is not supported; use -T or -U"
            );
        }
        Ok(Self {
            input: input.to_string(),
            host,
            protocol,
        })
    }
}

fn http_target(input: &str) -> Result<(String, Protocol)> {
    let normalized = if is_http_target(input) {
        input.to_string()
    } else {
        format!("http://{input}")
    };
    let url =
        Url::parse(&normalized).map_err(|error| anyhow::anyhow!("invalid HTTP URL: {error}"))?;
    ensure!(
        matches!(url.scheme(), "http" | "https"),
        "HTTP mode requires an http:// or https:// URL"
    );
    let host = url
        .host_str()
        .filter(|host| !host.is_empty())
        .ok_or_else(|| anyhow::anyhow!("HTTP URL requires a host"))?
        .to_string();
    Ok((host, Protocol::Http(normalized)))
}

fn is_http_target(input: &str) -> bool {
    input
        .get(..7)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("http://"))
        || input
            .get(..8)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("https://"))
}

fn parse_endpoint(input: &str) -> Result<(String, Option<u16>)> {
    if input.is_empty() {
        bail!("target must not be empty");
    }
    if input.parse::<IpAddr>().is_ok() {
        return Ok((input.to_string(), None));
    }

    if input.starts_with('[') {
        let (host, rest) = input
            .strip_prefix('[')
            .and_then(|value| value.split_once(']'))
            .ok_or_else(|| anyhow::anyhow!("invalid bracketed target"))?;
        ensure!(!host.is_empty(), "target host must not be empty");
        host.parse::<Ipv6Addr>()
            .map_err(|_| anyhow::anyhow!("invalid bracketed IPv6 address"))?;
        let port = rest
            .strip_prefix(':')
            .ok_or_else(|| anyhow::anyhow!("bracketed targets require :PORT"))?;
        return Ok((host.to_string(), Some(parse_port(port)?)));
    }

    if input.matches(':').count() == 1 {
        let (host, port) = input
            .split_once(':')
            .ok_or_else(|| anyhow::anyhow!("invalid target"))?;
        ensure!(!host.is_empty(), "target host must not be empty");
        return Ok((host.to_string(), Some(parse_port(port)?)));
    }
    ensure!(
        !input.contains(':'),
        "use HOST:PORT or [IPv6]:PORT for an explicit port"
    );
    Ok((input.to_string(), None))
}

fn parse_port(port: &str) -> Result<u16> {
    port.parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| anyhow::anyhow!("port must be between 1 and 65535"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_mode_parses_icmp_tcp_http_and_ipv6() {
        assert_eq!(
            TargetSpec::parse("example.com", ProtocolMode::Auto, false)
                .unwrap()
                .protocol,
            Protocol::Icmp
        );
        assert_eq!(
            TargetSpec::parse("example.com:443", ProtocolMode::Auto, false)
                .unwrap()
                .protocol,
            Protocol::Tcp(443)
        );
        assert_eq!(
            TargetSpec::parse("[::1]:443", ProtocolMode::Auto, false)
                .unwrap()
                .host,
            "::1"
        );
        assert_eq!(
            TargetSpec::parse("::1", ProtocolMode::Auto, false)
                .unwrap()
                .protocol,
            Protocol::Icmp
        );
        assert!(matches!(
            TargetSpec::parse("https://example.com", ProtocolMode::Auto, false)
                .unwrap()
                .protocol,
            Protocol::Http(_)
        ));
    }

    #[test]
    fn explicit_modes_apply_defaults_and_keep_protocol() {
        assert_eq!(
            TargetSpec::parse("example.com", ProtocolMode::Tcp, false)
                .unwrap()
                .protocol,
            Protocol::Tcp(80)
        );
        assert_eq!(
            TargetSpec::parse("example.com", ProtocolMode::Udp, false)
                .unwrap()
                .protocol,
            Protocol::Udp(33434)
        );
        assert_eq!(
            TargetSpec::parse("example.com:5353", ProtocolMode::Udp, false)
                .unwrap()
                .protocol,
            Protocol::Udp(5353)
        );
    }

    #[test]
    fn rejects_invalid_ports_and_malformed_brackets() {
        for target in [
            "example.com:0",
            "example.com:65536",
            "example.com:abc",
            ":443",
            "[::1]",
            "[bad]:443",
            "[::1:443",
            "2001:db8::1:443:99999",
        ] {
            assert!(
                TargetSpec::parse(target, ProtocolMode::Auto, false).is_err(),
                "{target}"
            );
        }
    }

    #[test]
    fn rejects_http_traceroute() {
        assert!(TargetSpec::parse("https://example.com", ProtocolMode::Auto, true).is_err());
    }
}
