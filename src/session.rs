use crate::cli::Cli;
use crate::pinger::{Pinger};
use crate::utils::{resolve_host, IpVersion};
use anyhow::Result;
use tokio::signal;
use std::collections::HashMap;
use std::time::Duration;

pub use self::models::{PingResult, ProbeStatus};

mod models {
    use std::net::IpAddr;
    use std::time::Instant;
    use std::time::Duration;

    #[derive(Debug, Clone)]
    pub enum ProbeStatus {
        Success,
        Timeout,
        Error(String),
    }

    #[derive(Debug, Clone)]
    pub struct PingResult {
        pub target: String,
        pub target_addr: IpAddr,
        pub seq: u64,
        pub bytes: usize,
        pub ttl: Option<u8>,
        pub rtt: Duration,
        pub status: ProbeStatus,
    }

    #[derive(Debug, Clone)]
    pub struct PingStats {
        pub target: String,
        pub _address: IpAddr,
        pub transmitted: u64,
        pub received: u64,
        pub start_time: Instant,
        pub rtts: Vec<Duration>,
    }

    impl PingStats {
        pub fn new(target: String, address: IpAddr) -> Self {
            Self {
                target,
                _address: address,
                transmitted: 0,
                received: 0,
                start_time: Instant::now(),
                rtts: Vec::new(),
            }
        }

        pub fn update(&mut self, result: &PingResult) {
            self.transmitted += 1;
            if let ProbeStatus::Success = result.status {
                self.received += 1;
                self.rtts.push(result.rtt);
            }
        }
    }
}

pub struct Session {
    cli: Cli,
}

impl Session {
    pub fn new(cli: Cli) -> Self {
        Self { cli }
    }

    fn detect_protocol(&self, target: &str) -> Result<(crate::cli::Protocol, String)> {
        // 1. Force Mode
        if self.cli.ipv4 || self.cli.ipv6 {
            return Ok((crate::cli::Protocol::Icmp, target.to_string()));
        }
        if self.cli.tcp {
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
        if self.cli.http {
            let url_str = if target.starts_with("http") { target.to_string() } else { format!("http://{}", target) };
            if let Ok(url) = reqwest::Url::parse(&url_str) {
                if let Some(host) = url.host_str() {
                    return Ok((crate::cli::Protocol::Http(url_str), host.to_string()));
                }
            }
            // Fallback if parsing fails?
            return Ok((crate::cli::Protocol::Http(target.to_string()), target.to_string()));
        }

        // 2. Auto Mode
        if target.starts_with("http://") || target.starts_with("https://") {
             if let Ok(url) = reqwest::Url::parse(target) {
                if let Some(host) = url.host_str() {
                    return Ok((crate::cli::Protocol::Http(target.to_string()), host.to_string()));
                }
            }
            return Ok((crate::cli::Protocol::Http(target.to_string()), target.to_string()));
        }

        // Check for TCP format (host:port)
        if let Some((host, port_str)) = target.rsplit_once(':') {
             if let Ok(port) = port_str.parse::<u16>() {
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
        }

        // Default ICMP
        Ok((crate::cli::Protocol::Icmp, target.to_string()))
    }

    pub async fn run(&self) -> Result<()> {
        let targets = &self.cli.targets;
        let multi_target = targets.len() > 1;
        let quiet = self.cli.quiet || multi_target;

        let (tx, mut rx) = tokio::sync::mpsc::channel::<models::PingResult>(100);

        let mut all_stats: HashMap<String, models::PingStats> = HashMap::new();
        let mut pingers: Vec<Box<dyn Pinger>> = Vec::new();

        for target_string in targets {
            // Detect protocol and host
            let (protocol, host_to_resolve) = match self.detect_protocol(target_string) {
                Ok(res) => res,
                Err(e) => {
                    eprintln!("pingx: {}: {}", target_string, e);
                    if !multi_target { return Err(e); }
                    continue;
                }
            };

            let ip_version = if self.cli.ipv4 {
                IpVersion::V4
            } else if self.cli.ipv6 {
                IpVersion::V6
            } else {
                IpVersion::Any
            };

            match resolve_host(&host_to_resolve, ip_version).await {
                Ok(target_addr) => {
                     all_stats.insert(target_string.clone(), models::PingStats::new(target_string.clone(), target_addr));
                     
                     if !quiet {
                         println!("PING {} ({}) {}({}) bytes of data.", target_string, target_addr, self.cli.size, self.cli.size + 28);
                     }

                     let mut pinger = crate::pinger::create_pinger(
                         target_string.clone(),
                         protocol, 
                         target_addr, 
                         self.cli.ttl, 
                         self.cli.size, 
                         self.cli.timeout
                     );
                     
                     if let Err(e) = pinger.start(tx.clone()).await {
                         eprintln!("Failed to start pinger for {}: {}", target_string, e);
                         continue;
                     }
                     pingers.push(pinger);
                },
                Err(e) => {
                    eprintln!("pingx: {}: {}", target_string, e);
                    if !multi_target {
                        return Err(e);
                    }
                }
            }
        }

        drop(tx);

        if pingers.is_empty() {
            return Ok(()); 
        }

        let mut interval = tokio::time::interval(self.cli.interval);
        let mut seq = 1;
        let count = self.cli.count;

        let (stop_tx, mut stop_rx) = tokio::sync::mpsc::channel(1);
        tokio::spawn(async move {
            signal::ctrl_c().await.ok();
            stop_tx.send(()).await.ok();
        });

        let mut wait_timeout = Box::pin(tokio::time::sleep(Duration::from_secs(100000000))); // Initial long sleep
        let mut waiting_for_shutdown = false;
        
        let mut deadline_sleep = if let Some(d) = self.cli.deadline {
            Box::pin(tokio::time::sleep(d))
        } else {
            Box::pin(tokio::time::sleep(Duration::from_secs(1000000000))) // Far future
        };
        let has_deadline = self.cli.deadline.is_some();

        loop {
            tokio::select! {
                _ = interval.tick(), if !waiting_for_shutdown => {
                    if let Some(c) = count {
                        if seq > c {
                            waiting_for_shutdown = true;
                            // Reset sleep to wait for stragglers
                            wait_timeout = Box::pin(tokio::time::sleep(self.cli.timeout + Duration::from_millis(100)));
                            continue;
                        }
                    }
                    
                    for pinger in &pingers {
                        if let Err(e) = pinger.ping(seq).await {
                            eprintln!("Failed to ping: {}", e);
                        }
                    }
                    seq += 1;
                }

                _ = &mut deadline_sleep, if has_deadline => {
                    break;
                }

                _ = &mut wait_timeout, if waiting_for_shutdown => {
                    break;
                }

                Some(result) = rx.recv() => {
                    if let Some(stats) = all_stats.get_mut(&result.target) {
                        stats.update(&result);
                    }
                    if !quiet {
                        Self::print_result(&result);
                    }
                }

                _ = stop_rx.recv() => {
                    break;
                }
            }
        }

        for mut p in pingers {
            p.stop().await.ok();
        }

        for target_host in targets {
            if let Some(stats) = all_stats.get(target_host) {
                Self::print_stats(stats);
            }
        }

        Ok(())
    }

    fn print_result(result: &models::PingResult) {
        match &result.status {
            models::ProbeStatus::Success => {
                println!("{} bytes from {}: icmp_seq={} ttl={:?} time={:.3} ms", 
                    result.bytes, result.target_addr, result.seq, result.ttl.unwrap_or(0), result.rtt.as_secs_f64() * 1000.0);
            },
            models::ProbeStatus::Timeout => {
                println!("Request timeout for icmp_seq={}", result.seq);
            },
            models::ProbeStatus::Error(e) => {
                eprintln!("Error for icmp_seq={}: {}", result.seq, e);
            }
        }
    }

    fn print_stats(stats: &models::PingStats) {
        println!("\n--- {} ping statistics ---", stats.target);
        let loss = if stats.transmitted > 0 {
             100.0 * (1.0 - stats.received as f64 / stats.transmitted as f64)
        } else { 0.0 };

        let total_time = stats.start_time.elapsed().as_millis();

        println!("{} packets transmitted, {} received, {:.0}% packet loss, time {}ms", 
            stats.transmitted, stats.received, loss, total_time);
        
        if stats.received > 0 {
            let min = stats.rtts.iter().min().unwrap().as_secs_f64() * 1000.0;
            let max = stats.rtts.iter().max().unwrap().as_secs_f64() * 1000.0;
            let avg = stats.rtts.iter().sum::<Duration>().as_secs_f64() * 1000.0 / stats.rtts.len() as f64;
            
            let avg_duration = Duration::from_secs_f64(avg / 1000.0);
            let sum_sq_diff: f64 = stats.rtts.iter() 
                .map(|rtt| (rtt.as_secs_f64() - avg_duration.as_secs_f64()).abs())
                .sum();
            let mdev = sum_sq_diff / stats.rtts.len() as f64 * 1000.0;

            println!("rtt min/avg/max/mdev = {:.3}/{:.3}/{:.3}/{:.3} ms", min, avg, max, mdev);
        }
    }
}