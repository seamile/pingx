use clap::Parser;
use std::time::Duration;

#[derive(Parser, Debug, Clone)]
#[command(author, version, about = "A versatile network diagnostic tool to replace system ping/ping6.", long_about = None)]
pub struct Cli {
    /// Targets. In traceroute mode: HOST[:PORT] [PACKET_LEN]; use [IPv6]:PORT for IPv6 ports.
    #[arg(required_unless_present = "fetch_geo")]
    pub targets: Vec<String>,

    /// Stop after sending N packets.
    #[arg(short = 'c', overrides_with = "count", conflicts_with = "traceroute")]
    pub count: Option<u64>,

    /// Wait N seconds between sending each packet.
    #[arg(
        short = 'i',
        default_value = "1.0",
        value_parser = parse_duration,
        overrides_with = "interval",
        conflicts_with = "traceroute"
    )]
    pub interval: Duration,

    /// Time to wait for a response, in seconds.
    #[arg(short = 'W', default_value = "1.0", value_parser = parse_duration, overrides_with = "timeout")]
    pub timeout: Duration,

    /// Stop running after N seconds.
    #[arg(
        short = 'w',
        value_parser = parse_duration,
        overrides_with = "deadline",
        conflicts_with = "traceroute"
    )]
    pub deadline: Option<Duration>,

    /// Set the IP Time to Live.
    #[arg(
        short = 't',
        default_value = "64",
        overrides_with = "ttl",
        conflicts_with = "traceroute"
    )]
    pub ttl: u32,

    /// Size of payload in bytes.
    #[arg(
        short = 's',
        default_value = "56",
        overrides_with = "size",
        conflicts_with = "traceroute",
        help_heading = "Ping options"
    )]
    pub size: usize,

    /// Quiet output. Nothing is displayed except the summary lines at startup time and when finished.
    #[arg(short = 'q', conflicts_with = "traceroute")]
    pub quiet: bool,

    /// Use this network interface for DNS, probes, HTTP, and GeoIP.
    #[arg(short = 'I', long = "interface", value_name = "IFACE")]
    pub interface: Option<String>,

    // Mode Flags (Mutually Exclusive via 'mode' group)
    /// Force IPv4.
    #[arg(
        short = '4',
        group = "family",
        conflicts_with_all = ["http", "geo", "fetch_geo"]
    )]
    pub ipv4: bool,

    /// Force IPv6.
    #[arg(
        short = '6',
        group = "family",
        conflicts_with_all = ["http", "geo", "fetch_geo"]
    )]
    pub ipv6: bool,

    /// Force TCP ping. Without -R, target must be in host:port format; with -R, use TCP SYN traceroute.
    #[arg(long = "tcp", short = 'T', group = "mode")]
    pub tcp: bool,

    /// Force HTTP ping.
    #[arg(short = 'H', long = "http", group = "mode")]
    pub http: bool,

    /// Custom HTTP headers (e.g., "Host: example.com"). Can be specified multiple times.
    #[arg(long = "header", conflicts_with = "traceroute")]
    pub headers: Vec<String>,

    /// GeoIP lookup mode. Displays location information for the targets and exits.
    #[arg(short = 'g', long = "geo", group = "mode")]
    pub geo: bool,

    /// Fetch/Update the GeoIP database.
    #[arg(long = "fetch-geo", group = "mode")]
    pub fetch_geo: bool,

    /// Output results in JSON format. Optional value specifies output file.
    #[arg(long = "json", num_args = 0..=1, value_name = "FILE")]
    pub json: Option<Option<String>>,

    /// Trace the route to a single IPv4, IPv6, or domain target.
    #[arg(
        short = 'R',
        long = "traceroute",
        help_heading = "Traceroute options",
        conflicts_with_all = [
            "count",
            "interval",
            "deadline",
            "ttl",
            "http",
            "headers",
            "geo",
            "fetch_geo",
            "json"
        ]
    )]
    pub traceroute: bool,

    /// Traceroute probe protocol. Defaults to ICMP.
    #[arg(
        long = "trace-protocol",
        value_enum,
        requires = "traceroute",
        conflicts_with = "tcp",
        value_name = "PROTOCOL",
        help_heading = "Traceroute options"
    )]
    pub trace_protocol: Option<TraceProtocol>,

    /// Maximum number of hops. Requires -R.
    #[arg(
        long = "max-hops",
        default_value_t = 64,
        value_parser = clap::value_parser!(u8).range(1..=255),
        requires = "traceroute",
        help_heading = "Traceroute options"
    )]
    pub max_hops: u8,
}

impl Cli {
    pub fn trace_target(&self) -> anyhow::Result<(&str, TraceProtocol, u16)> {
        let input = self
            .targets
            .first()
            .ok_or_else(|| anyhow::anyhow!("traceroute requires a target"))?;
        let (host, port) = if input.parse::<std::net::IpAddr>().is_ok() || !input.contains(':') {
            (input.as_str(), None)
        } else {
            let (host, port) = input
                .rsplit_once(':')
                .ok_or_else(|| anyhow::anyhow!("invalid traceroute target"))?;
            let host = host
                .strip_prefix('[')
                .and_then(|host| host.strip_suffix(']'))
                .unwrap_or(host);
            anyhow::ensure!(
                !host.is_empty() && (!host.contains(':') || input.starts_with('[')),
                "use HOST:PORT or [IPv6]:PORT"
            );
            if input.starts_with('[') {
                host.parse::<std::net::Ipv6Addr>()
                    .map_err(|_| anyhow::anyhow!("invalid bracketed IPv6 address"))?;
            }
            let port = port
                .parse::<u16>()
                .ok()
                .filter(|port| *port != 0)
                .ok_or_else(|| anyhow::anyhow!("traceroute port must be between 1 and 65535"))?;
            (host, Some(port))
        };
        let protocol = if self.tcp {
            TraceProtocol::Tcp
        } else {
            self.trace_protocol.unwrap_or(if port.is_some() {
                TraceProtocol::Tcp
            } else {
                TraceProtocol::Icmp
            })
        };
        anyhow::ensure!(
            protocol != TraceProtocol::Icmp || port.is_none(),
            "ICMP traceroute does not use a port"
        );
        Ok((
            host,
            protocol,
            port.unwrap_or(if protocol == TraceProtocol::Tcp {
                80
            } else {
                33434
            }),
        ))
    }
}

fn parse_duration(arg: &str) -> Result<Duration, String> {
    let seconds = arg
        .parse::<f64>()
        .map_err(|e| format!("invalid duration: {e}"))?;
    if !seconds.is_finite() || seconds <= 0.0 {
        return Err("duration must be a finite, positive number".to_string());
    }
    Ok(Duration::from_secs_f64(seconds))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("pingx").chain(args.iter().copied()))
    }

    #[test]
    fn traceroute_accepts_network_options() {
        let cli = parse(&[
            "-R",
            "-4",
            "-I",
            "en0",
            "-W",
            "0.5",
            "--max-hops",
            "8",
            "example.com",
        ])
        .unwrap();
        assert!(cli.traceroute);
        assert!(cli.ipv4);
        assert_eq!(cli.max_hops, 8);
    }

    #[test]
    fn traceroute_selects_probe_protocol_independently_from_tcp_ping() {
        assert_eq!(
            parse(&["-R", "--trace-protocol", "udp", "example.com"])
                .unwrap()
                .trace_protocol,
            Some(TraceProtocol::Udp)
        );
        assert_eq!(
            parse(&["-R", "-T", "example.com"]).unwrap().trace_protocol,
            None
        );
        assert_eq!(
            parse(&["-T", "example.com:443"]).unwrap().trace_protocol,
            None
        );
        assert!(parse(&["-R", "-T", "--trace-protocol", "udp", "example.com"]).is_err());
        assert!(parse(&["-R", "--trace-port", "443", "example.com"]).is_err());
    }

    #[test]
    fn traceroute_ports_follow_target_syntax() {
        for (args, expected) in [
            (
                vec!["-R", "1.1.1.1"],
                ("1.1.1.1", TraceProtocol::Icmp, 33434),
            ),
            (
                vec!["-R", "example.com:443"],
                ("example.com", TraceProtocol::Tcp, 443),
            ),
            (
                vec!["-R", "-T", "1.1.1.1:443"],
                ("1.1.1.1", TraceProtocol::Tcp, 443),
            ),
            (
                vec!["-R", "--trace-protocol", "udp", "1.1.1.1:33450"],
                ("1.1.1.1", TraceProtocol::Udp, 33450),
            ),
            (
                vec!["-R", "--trace-protocol", "udp", "[::1]:33450"],
                ("::1", TraceProtocol::Udp, 33450),
            ),
            (vec!["-R", "::1"], ("::1", TraceProtocol::Icmp, 33434)),
            (
                vec!["-R", "-T", "example.com"],
                ("example.com", TraceProtocol::Tcp, 80),
            ),
        ] {
            assert_eq!(parse(&args).unwrap().trace_target().unwrap(), expected);
        }
        for input in [
            "host:0",
            "host:65536",
            "host:abc",
            ":443",
            "[invalid]:443",
            "[::1:443",
        ] {
            assert!(
                parse(&["-R", input]).unwrap().trace_target().is_err(),
                "{input}"
            );
        }
        assert!(
            parse(&["-R", "--trace-protocol", "icmp", "host:443"])
                .unwrap()
                .trace_target()
                .is_err()
        );
    }

    #[test]
    fn traceroute_rejects_unrelated_modes_and_flags() {
        for args in [
            vec!["-R", "--json", "example.com"],
            vec!["-R", "-g", "example.com"],
            vec!["-R", "-c", "2", "example.com"],
            vec!["-R", "-t", "2", "example.com"],
        ] {
            assert!(parse(&args).is_err(), "unexpected success for {args:?}");
        }
    }

    #[test]
    fn family_flags_allow_tcp_and_keep_unrelated_conflicts() {
        assert!(parse(&["-4", "-T", "example.com:443"]).is_ok());
        assert!(parse(&["-6", "-T", "[::1]:443"]).is_ok());
        assert!(parse(&["-R", "-4", "-T", "example.com"]).is_ok());
        assert!(parse(&["-6", "-H", "example.com"]).is_err());
    }

    #[test]
    fn size_keeps_its_normal_ping_default() {
        let cli = parse(&["example.com"]).unwrap();
        assert_eq!(cli.size, 56);
        assert_eq!(parse(&["-s", "32", "example.com"]).unwrap().size, 32);
    }

    #[test]
    fn traceroute_keeps_positional_targets_for_legacy_cli() {
        let cli = parse(&["-R", "example.com"]).unwrap();
        assert_eq!(cli.targets, ["example.com"]);
        assert!(parse(&["-R", "-s", "56", "example.com"]).is_err());
    }

    #[test]
    fn rejects_invalid_durations() {
        for value in ["nan", "inf", "0", "-1", "-inf"] {
            assert!(parse(&["-W", value, "127.0.0.1"]).is_err());
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Protocol {
    Icmp,
    Tcp(u16),
    Http(String),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum TraceProtocol {
    Udp,
    #[default]
    Icmp,
    Tcp,
}

impl From<Option<TraceProtocol>> for TraceProtocol {
    fn from(value: Option<TraceProtocol>) -> Self {
        value.unwrap_or(TraceProtocol::Icmp)
    }
}
