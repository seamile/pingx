use clap::Parser;
use std::time::Duration;

pub use crate::probe::{Protocol, ProtocolMode, TargetSpec};

pub const DEFAULT_PING_SIZE: usize = 56;
pub const DEFAULT_TRACEROUTE_MAX_HOPS: u8 = 32;

#[derive(Parser, Debug, Clone)]
#[command(
    author,
    version,
    about = "A versatile network diagnostic tool to replace system ping/ping6.",
    long_about = None,
    override_help = include_str!("help.txt")
)]
pub struct Cli {
    /// Targets. In traceroute mode, specify exactly one HOST[:PORT]; use -s for packet size.
    #[arg(required_unless_present = "fetch_geo")]
    pub targets: Vec<String>,

    /// Stop after sending N packets.
    #[arg(short = 'c', overrides_with = "count", help_heading = "Ping Options")]
    pub count: Option<u64>,

    /// Wait N seconds between sending each packet.
    #[arg(
        short = 'i',
        default_value = "1.0",
        value_parser = parse_duration,
        overrides_with = "interval",
        help_heading = "Ping Options"
    )]
    pub interval: Duration,

    /// Time to wait for a response, in seconds.
    #[arg(short = 'W', default_value = "1.0", value_parser = parse_duration, overrides_with = "timeout", help_heading = "Common Options")]
    pub timeout: Duration,

    /// Stop running after N seconds.
    #[arg(
        short = 'w',
        value_parser = parse_duration,
        overrides_with = "deadline",
        help_heading = "Ping Options"
    )]
    pub deadline: Option<Duration>,

    /// Set the IP Time to Live.
    #[arg(
        short = 't',
        default_value = "64",
        overrides_with = "ttl",
        help_heading = "Ping Options"
    )]
    pub ttl: u32,

    /// Set packet size. Ping uses a payload size (default 56); traceroute uses total IP packet size (default 40/60).
    #[arg(short = 's', overrides_with = "size", help_heading = "Ping Options")]
    pub size: Option<usize>,

    /// Quiet output. Nothing is displayed except the summary lines at startup time and when finished.
    #[arg(short = 'q', help_heading = "Ping Options")]
    pub quiet: bool,

    /// Use this network interface for DNS, probes, HTTP, and GeoIP (Unix only).
    #[arg(
        short = 'I',
        long = "interface",
        value_name = "IFACE",
        help_heading = "Common Options"
    )]
    pub interface: Option<String>,

    // Mode Flags (Mutually Exclusive via 'mode' group)
    /// Force IPv4.
    #[arg(
        short = '4',
        group = "family",
        conflicts_with_all = ["geo", "fetch_geo"],
        help_heading = "Common Options"
    )]
    pub ipv4: bool,

    /// Force IPv6.
    #[arg(
        short = '6',
        group = "family",
        conflicts_with_all = ["geo", "fetch_geo"],
        help_heading = "Common Options"
    )]
    pub ipv6: bool,

    /// Force TCP ping. Omit the target port to use 80; with -R, use TCP traceroute.
    #[arg(
        long = "tcp",
        short = 'T',
        group = "mode",
        help_heading = "Ping Options"
    )]
    pub tcp: bool,

    /// Force UDP ping. Omit the target port to use 33434; with -R, use UDP traceroute.
    #[arg(
        long = "udp",
        short = 'U',
        group = "mode",
        help_heading = "Ping Options"
    )]
    pub udp: bool,

    /// Force HTTP ping.
    #[arg(
        short = 'H',
        long = "http",
        group = "mode",
        help_heading = "Ping Options"
    )]
    pub http: bool,

    /// Custom HTTP headers (e.g., "Host: example.com"). Can be specified multiple times.
    #[arg(long = "header", help_heading = "Ping Options")]
    pub headers: Vec<String>,

    /// GeoIP lookup mode. Displays location information for the targets and exits.
    #[arg(
        short = 'g',
        long = "geo",
        group = "mode",
        help_heading = "Geo Options"
    )]
    pub geo: bool,

    /// Fetch/Update the GeoIP database.
    #[arg(long = "fetch-geo", group = "mode", help_heading = "Geo Options")]
    pub fetch_geo: bool,

    /// Output results as JSON to stdout, or to FILE with --json=FILE.
    #[arg(
        long = "json",
        num_args = 0..=1,
        value_name = "FILE",
        require_equals = true,
        help_heading = "Common Options"
    )]
    pub json: Option<Option<String>>,

    /// Trace the route to a single IPv4, IPv6, or domain target.
    #[arg(
        short = 'R',
        long = "traceroute",
        help_heading = "Traceroute Options",
        conflicts_with_all = [
            "http",
            "geo",
            "fetch_geo"
        ]
    )]
    pub traceroute: bool,

    /// Maximum number of hops. Requires -R.
    #[arg(
        long = "max-hops",
        default_value_t = DEFAULT_TRACEROUTE_MAX_HOPS,
        value_parser = clap::value_parser!(u8).range(1..=255),
        requires = "traceroute",
        help_heading = "Traceroute Options"
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
        anyhow::ensure!(
            self.targets.len() == 1,
            "traceroute mode requires exactly one target"
        );
        let input = self
            .targets
            .first()
            .ok_or_else(|| anyhow::anyhow!("traceroute requires a target"))?;
        self.target_spec(input)
    }

    pub fn ping_size(&self) -> usize {
        self.size.unwrap_or(DEFAULT_PING_SIZE)
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
    use clap::CommandFactory;

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
            vec!["-R", "-g", "example.com"],
            vec!["-R", "-H", "example.com"],
        ] {
            assert!(parse(&args).is_err(), "unexpected success for {args:?}");
        }
    }

    #[test]
    fn traceroute_accepts_json_output() {
        let cli = parse(&["-R", "example.com", "--json"]).unwrap();
        assert_eq!(cli.json, Some(None));

        let cli = parse(&["-R", "example.com", "--json=route.json"]).unwrap();
        assert_eq!(cli.json, Some(Some("route.json".to_string())));
    }

    #[test]
    fn json_without_file_does_not_consume_targets() {
        let cli = parse(&["--json", "192.0.2.1", "192.0.2.2"]).unwrap();
        assert_eq!(cli.json, Some(None));
        assert_eq!(cli.targets, ["192.0.2.1", "192.0.2.2"]);

        let cli = parse(&["--json=result.json", "192.0.2.1"]).unwrap();
        assert_eq!(cli.json, Some(Some("result.json".to_string())));
        assert_eq!(cli.targets, ["192.0.2.1"]);
    }

    #[test]
    fn traceroute_ignores_ping_options() {
        let cli = parse(&[
            "-R",
            "-c",
            "2",
            "-i",
            "0.2",
            "-w",
            "3",
            "-t",
            "2",
            "-s",
            "32",
            "-q",
            "--header",
            "Host: example.com",
            "example.com",
        ])
        .unwrap();
        assert_eq!(cli.count, Some(2));
        assert_eq!(cli.size, Some(32));
        assert!(cli.quiet);
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
        assert_eq!(cli.size, None);
        assert_eq!(cli.ping_size(), 56);
        assert_eq!(parse(&["-s", "32", "example.com"]).unwrap().ping_size(), 32);
    }

    #[test]
    fn traceroute_uses_size_and_requires_one_target() {
        let cli = parse(&["-R", "example.com"]).unwrap();
        assert_eq!(cli.targets, ["example.com"]);
        assert_eq!(cli.size, None);
        assert_eq!(cli.max_hops, DEFAULT_TRACEROUTE_MAX_HOPS);
        assert_eq!(
            parse(&["-R", "-s", "56", "example.com"]).unwrap().size,
            Some(56)
        );
        assert!(
            parse(&["-R", "example.com", "56"])
                .unwrap()
                .trace_target()
                .is_err()
        );
    }

    #[test]
    fn help_lists_mode_groups_and_helper_commands() {
        let help = Cli::command()
            .render_help()
            .to_string()
            .replace("\r\n", "\n");
        assert!(help.contains("Ping Options"));
        assert!(help.contains("Traceroute Options"));
        assert!(help.contains("Geo Options"));
        assert!(help.contains("pingx helper install"));
        assert!(!help.contains("Common Options"));
        assert!(!help.contains("Mode options:"));
        let ping = help.split("Ping Options:\n").nth(1).unwrap();
        let (ping, rest) = ping.split_once("Traceroute Options:\n").unwrap();
        let (trace, rest) = rest.split_once("Geo Options:\n").unwrap();
        let (geo, _) = rest.split_once("Helper Commands (macOS):\n").unwrap();
        for (section, flags) in [
            (
                ping,
                vec![
                    "-c", "-i", "-w", "-t", "-q", "-H", "--header", "-T", "-U", "-4", "-6", "-I",
                    "-s", "-W", "--json",
                ],
            ),
            (
                trace,
                vec![
                    "-R",
                    "--max-hops",
                    "-T",
                    "-U",
                    "-4",
                    "-6",
                    "-I",
                    "-s",
                    "-W",
                    "--json",
                ],
            ),
            (geo, vec!["-g", "--fetch-geo", "-I", "--json"]),
        ] {
            let mut remaining = section;
            for flag in flags {
                remaining = remaining.split_once(flag).unwrap().1;
            }
        }
        for flag in ["-h", "--help"] {
            let error = parse(&[flag]).unwrap_err();
            assert_eq!(error.kind(), clap::error::ErrorKind::DisplayHelp);
            assert_eq!(error.to_string(), help);
        }
        assert_eq!(Cli::command().render_long_help().to_string(), help);
    }

    #[test]
    fn rejects_invalid_durations() {
        for value in ["nan", "inf", "0", "-1", "-inf"] {
            assert!(parse(&["-W", value, "127.0.0.1"]).is_err());
        }
    }
}
