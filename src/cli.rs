use clap::Parser;
use std::time::Duration;

pub use crate::probe::{Protocol, ProtocolMode, TargetSpec};

#[derive(Parser, Debug, Clone)]
#[command(
    author,
    version,
    about = "A versatile network diagnostic tool to replace system ping/ping6.",
    long_about = None,
    after_help = "TCP probes send a half-open SYN; SYN-ACK means open and RST means closed. Closed or rejected TCP/UDP ports count as received responses. macOS privileged probes use the root-owned launchd helper after `pingx helper install`. Windows UDP/TCP Ping and traceroute require Administrator access and WinDivert.dll plus WinDivert64.sys beside pingx.exe."
)]
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

    /// Size of ICMP or UDP payload in bytes, up to 65507 for UDP. TCP SYN probes ignore this option.
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

    /// Use this network interface for DNS, probes, HTTP, and GeoIP (Unix only).
    #[arg(short = 'I', long = "interface", value_name = "IFACE")]
    pub interface: Option<String>,

    // Mode Flags (Mutually Exclusive via 'mode' group)
    /// Force IPv4.
    #[arg(
        short = '4',
        group = "family",
        conflicts_with_all = ["geo", "fetch_geo"]
    )]
    pub ipv4: bool,

    /// Force IPv6.
    #[arg(
        short = '6',
        group = "family",
        conflicts_with_all = ["geo", "fetch_geo"]
    )]
    pub ipv6: bool,

    /// Force TCP ping. Omit the target port to use 80; with -R, use TCP traceroute.
    #[arg(long = "tcp", short = 'T', group = "mode")]
    pub tcp: bool,

    /// Force UDP ping. Omit the target port to use 33434; with -R, use UDP traceroute.
    #[arg(long = "udp", short = 'U', group = "mode")]
    pub udp: bool,

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
    pub fn protocol_mode(&self) -> ProtocolMode {
        if self.tcp {
            ProtocolMode::Tcp
        } else if self.udp {
            ProtocolMode::Udp
        } else if self.http {
            ProtocolMode::Http
        } else {
            ProtocolMode::Auto
        }
    }

    pub fn target_spec(&self, target: &str) -> anyhow::Result<TargetSpec> {
        TargetSpec::parse(target, self.protocol_mode(), self.traceroute)
    }

    pub fn trace_target(&self) -> anyhow::Result<TargetSpec> {
        let input = self
            .targets
            .first()
            .ok_or_else(|| anyhow::anyhow!("traceroute requires a target"))?;
        self.target_spec(input)
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
    fn traceroute_ports_follow_target_syntax() {
        for (args, expected) in [
            (vec!["-R", "1.1.1.1"], ("1.1.1.1", Protocol::Icmp)),
            (
                vec!["-R", "example.com:443"],
                ("example.com", Protocol::Tcp(443)),
            ),
            (
                vec!["-R", "-T", "1.1.1.1:443"],
                ("1.1.1.1", Protocol::Tcp(443)),
            ),
            (
                vec!["-R", "-U", "1.1.1.1:33450"],
                ("1.1.1.1", Protocol::Udp(33450)),
            ),
            (
                vec!["-R", "-U", "[::1]:33450"],
                ("::1", Protocol::Udp(33450)),
            ),
            (vec!["-R", "::1"], ("::1", Protocol::Icmp)),
            (
                vec!["-R", "-T", "example.com"],
                ("example.com", Protocol::Tcp(80)),
            ),
            (
                vec!["-R", "-U", "example.com"],
                ("example.com", Protocol::Udp(33434)),
            ),
        ] {
            let target = parse(&args).unwrap().trace_target().unwrap();
            assert_eq!((target.host.as_str(), target.protocol), expected);
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
        assert!(parse(&["-R", "--trace-protocol", "udp", "example.com"]).is_err());
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
        assert!(parse(&["-6", "-H", "example.com"]).is_ok());
        assert!(parse(&["-4", "-U", "example.com"]).is_ok());
        assert!(parse(&["-T", "-U", "example.com"]).is_err());
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
