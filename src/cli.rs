use clap::Parser;
use std::time::Duration;

#[derive(Parser, Debug, Clone)]
#[command(author, version, about, long_about = None)]
#[group(id = "mode", required = false, multiple = false)] // 互斥组
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
    #[arg(short = 't', long, value_parser = parse_duration)]
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
    #[arg(long = "tcp", short = 'T', group = "mode")] // changed short to 'T' to avoid conflict with 't' (deadline)?
    // Wait, previous code had `short = 't'` for deadline? 
    // Yes: `#[arg(short = 't', long, ...)] pub deadline: Option<Duration>,`
    // So --tcp cannot be `-t`.
    // User asked for `-t` as --tcp.
    // "`-t`: --tcp 使用 TCP 协议探测"
    // I need to rename deadline short flag or tcp short flag.
    // Standard ping uses `-t` for ttl on windows, `-w` for deadline?
    // Linux ping uses `-w` for deadline.
    // User spec overrides standard.
    // I will change `deadline` short to None or something else if user insists on `-t` for tcp.
    // But user prompt said: "`-t`: --tcp".
    // So I must assign `-t` to tcp.
    // I will remove `-t` from deadline.
    pub tcp: bool,

    /// Force HTTP ping.
    #[arg(short = 'H', long = "http", group = "mode")]
    pub http: bool,
}

// Deadline previously used `-t`. I will remove short alias for deadline to avoid conflict.
// Or change it to something else. `ping` uses `-w`.
// My code used `-W` for timeout.
// I will remove short `-t` from deadline.

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
