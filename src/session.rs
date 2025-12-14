use crate::cli::Cli;
use crate::utils::resolve_host;
use anyhow::Result;
use tokio::signal;
use std::collections::HashMap;
use std::time::Duration; // Add this

pub use self::models::{PingResult, ProbeStatus, PingStats};

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
        pub address: IpAddr,
        pub transmitted: u64,
        pub received: u64,
        pub start_time: Instant,
        pub rtts: Vec<Duration>,
    }

    impl PingStats {
        pub fn new(target: String, address: IpAddr) -> Self {
            Self {
                target,
                address,
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

    pub async fn run(&self) -> Result<()> {
        let targets = &self.cli.targets;
        let multi_target = targets.len() > 1;
        let quiet = self.cli.quiet || multi_target;

        let (tx, mut rx) = tokio::sync::mpsc::channel::<(String, models::PingResult)>(100);

        let mut all_stats: HashMap<String, models::PingStats> = HashMap::new();
        
        for target_host in targets {
            let target_host = target_host.clone();
            let tx = tx.clone();
            let cli = self.cli.clone();
            
            match resolve_host(&target_host).await {
                Ok(target_addr) => {
                     all_stats.insert(target_host.clone(), models::PingStats::new(target_host.clone(), target_addr));
                     
                     if !quiet {
                         println!("PING {} ({}) {}({}) bytes of data.", target_host, target_addr, cli.size, cli.size + 28);
                     }

                     tokio::spawn(async move {
                         let protocol = cli.get_protocol(&target_host);
                         let mut pinger = crate::pinger::create_pinger(protocol, target_addr, cli.ttl, cli.size, cli.timeout);
                         
                         if let Err(e) = pinger.start().await {
                             eprintln!("Failed to start pinger for {}: {}", target_host, e);
                             return;
                         }

                         let mut seq = 1;
                         let mut interval = tokio::time::interval(cli.interval);

                         loop {
                             interval.tick().await;
                             if let Some(count) = cli.count {
                                 if seq > count {
                                     break;
                                 }
                             }
                             
                             match pinger.ping(seq).await {
                                 Ok(result) => {
                                     if tx.send((target_host.clone(), result)).await.is_err() {
                                         break; 
                                     }
                                 },
                                 Err(_) => { } 
                             }
                             seq += 1;
                         }
                         let _ = pinger.stop().await;
                     });
                },
                Err(e) => {
                    eprintln!("pingx: {}: {}", target_host, e);
                    if !multi_target {
                        return Err(e);
                    }
                }
            }
        }

        drop(tx);

        let (stop_tx, mut stop_rx) = tokio::sync::mpsc::channel(1);
        tokio::spawn(async move {
            signal::ctrl_c().await.ok();
            stop_tx.send(()).await.ok();
        });

        loop {
            tokio::select! {
                Some((target_name, result)) = rx.recv() => {
                    if let Some(stats) = all_stats.get_mut(&target_name) {
                        stats.update(&result);
                    }
                    if !quiet {
                        Self::print_result(&result);
                    }
                }
                _ = stop_rx.recv() => {
                    break;
                }
                else => {
                    break;
                }
            }
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

        println!("{} packets transmitted, {} received, {:.0}% packet loss, time ?ms", 
            stats.transmitted, stats.received, loss);
        
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