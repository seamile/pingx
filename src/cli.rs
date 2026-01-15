use clap::Parser;
use std::time::Duration;

#[derive(Parser, Debug, Clone)]
#[command(author, version, about = "A versatile network diagnostic tool to replace system ping/ping6.", long_about = None)]
pub struct Cli {
    /// List of IP addresses, Domains, or URLs to ping.
    #[arg(required = true)]
    pub targets: Vec<String>,

    /// Stop after sending N packets.
    #[arg(short = 'c', overrides_with = "count")]
    pub count: Option<u64>,

    /// Wait N seconds between sending each packet.
    #[arg(short = 'i', default_value = "1.0", value_parser = parse_duration, overrides_with = "interval")]
    pub interval: Duration,

    /// Time to wait for a response, in seconds.
    #[arg(short = 'W', default_value = "1.0", value_parser = parse_duration, overrides_with = "timeout")]
    pub timeout: Duration,

    /// Stop running after N seconds.
    #[arg(short = 'w', value_parser = parse_duration, overrides_with = "deadline")]
    pub deadline: Option<Duration>,

    /// Set the IP Time to Live.
    #[arg(short = 't', default_value = "64", overrides_with = "ttl")]
    pub ttl: u32,

    /// Size of payload in bytes.
    #[arg(short = 's', default_value = "56", overrides_with = "size")]
    pub size: usize,

    /// Quiet output. Nothing is displayed except the summary lines at startup time and when finished.
    #[arg(short = 'q')]
    pub quiet: bool,

    // Mode Flags (Mutually Exclusive via 'mode' group)

    /// Force IPv4 ICMP ping.
    #[arg(short = '4', group = "mode")]
    pub ipv4: bool,

    /// Force IPv6 ICMP ping.
    #[arg(short = '6', group = "mode")]
    pub ipv6: bool,

    /// Force TCP ping. Target must be in host:port format.
    #[arg(long = "tcp", short = 'T', group = "mode")]
    pub tcp: bool,

    /// Force HTTP ping.
    #[arg(short = 'H', long = "http", group = "mode")]
    pub http: bool,

    /// Custom HTTP headers (e.g., "Host: example.com"). Can be specified multiple times.
    #[arg(long = "header")]
    pub headers: Vec<String>,
}

fn parse_duration(arg: &str) -> Result<Duration, std::num::ParseFloatError> {
    let seconds = arg.parse::<f64>()?;
    Ok(Duration::from_secs_f64(seconds))
}

#[derive(Clone, Debug, PartialEq)]
pub enum Protocol {
    Icmp,
    Tcp(u16),
    Http(String),
}
