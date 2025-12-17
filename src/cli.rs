use clap::Parser;
use std::time::Duration;

#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// List of IP addresses, Domains, or URLs to ping.
    #[arg(required = true)]
    pub targets: Vec<String>,

    /// Stop after sending N packets.
    #[arg(short = 'c', long)]
    pub count: Option<u64>,

    /// Wait N seconds between sending each packet.
    #[arg(short = 'i', long, default_value = "1.0", value_parser = parse_duration)]
    pub interval: Duration,

    /// Time to wait for a response, in seconds.
    #[arg(short = 'W', long, default_value = "1.0", value_parser = parse_duration)]
    pub timeout: Duration,

    /// Stop running after N seconds.
    #[arg(short = 'w', long, value_parser = parse_duration)]
    pub deadline: Option<Duration>,

    /// Set the IP Time to Live.
    #[arg(long, default_value = "64")]
    pub ttl: u32,

    /// Size of payload in bytes.
    #[arg(short = 's', long, default_value = "56")]
    pub size: usize,

    /// Quiet output. Nothing is displayed except the summary lines at startup time and when finished.
    #[arg(short = 'q', long)]
    pub quiet: bool,

    /// Verbose output (debug logs).
    #[arg(short = 'v', long)]
    pub verbose: bool,

    // Mode Flags (Mutually Exclusive via 'mode' group)

    /// Force IPv4 ICMP ping.
    #[arg(short = '4', group = "mode")]
    pub ipv4: bool,

    /// Force IPv6 ICMP ping.
    #[arg(short = '6', group = "mode")]
    pub ipv6: bool,

    /// Force TCP ping. Target must be in host:port format.
    #[arg(long = "tcp", short = 't', group = "mode")]
    pub tcp: bool,

    /// Force HTTP ping.
    #[arg(short = 'H', long = "http", group = "mode")]
    pub http: bool,
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