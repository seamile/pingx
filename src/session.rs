use crate::cli::Cli;
use crate::pinger::Pinger;
use crate::utils::{IpVersion, resolve_host};
use anyhow::Result;
use colored::*;
use serde::Serialize;
use std::collections::HashMap;
use std::time::Duration;
use tokio::signal;

pub use self::models::{PingResult, ProbeStatus, ResponseType};

mod models {
    use std::collections::BTreeMap;
    use std::net::IpAddr;
    use std::time::Duration;
    use std::time::Instant;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum ResponseType {
        IcmpEchoReply,
        TcpOpen,
        TcpClosed,
        UdpApplicationReply,
        UdpPortUnreachable,
        HttpResponse(u16),
    }

    impl ResponseType {
        pub fn as_str(self) -> String {
            match self {
                Self::IcmpEchoReply => "icmp_echo_reply".to_string(),
                Self::TcpOpen => "tcp_open".to_string(),
                Self::TcpClosed => "tcp_closed".to_string(),
                Self::UdpApplicationReply => "udp_application_reply".to_string(),
                Self::UdpPortUnreachable => "udp_port_unreachable".to_string(),
                Self::HttpResponse(code) => format!("http_{code}"),
            }
        }
    }

    #[derive(Debug, Clone)]
    pub enum ProbeStatus {
        Success(ResponseType),
        Timeout,
        NetworkError {
            node: Option<IpAddr>,
            reason: String,
        },
        LocalError(String),
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
        pub _target: String,
        pub _address: IpAddr,
        pub transmitted: u64,
        pub received: u64,
        pub start_time: Instant,
        pub rtts: Vec<Duration>,
        pub response_counts: BTreeMap<ResponseType, u64>,
        pub local_failures: u64,
        pub network_errors: u64,
    }

    impl PingStats {
        pub fn new(target: String, address: IpAddr) -> Self {
            Self {
                _target: target,
                _address: address,
                transmitted: 0,
                received: 0,
                start_time: Instant::now(),
                rtts: Vec::new(),
                response_counts: BTreeMap::new(),
                local_failures: 0,
                network_errors: 0,
            }
        }

        pub fn update(&mut self, result: &PingResult) {
            self.transmitted += 1;
            match &result.status {
                ProbeStatus::Success(kind) => {
                    self.received += 1;
                    self.rtts.push(result.rtt);
                    *self.response_counts.entry(*kind).or_default() += 1;
                }
                ProbeStatus::LocalError(_) => self.local_failures += 1,
                ProbeStatus::NetworkError { .. } => self.network_errors += 1,
                ProbeStatus::Timeout => {}
            }
        }
    }
}

use std::sync::Arc;

#[derive(Serialize)]
pub struct JsonResult {
    pub target: String,
    pub protocol: String,
    pub target_port: Option<u16>,
    pub ip: String,
    pub packet_size: usize,
    pub ttl: u32,
    pub sent: u64,
    pub received: u64,
    pub loss: f64,
    pub time: f64,
    pub min: f64,
    pub avg: f64,
    pub max: f64,
    pub mdev: f64,
    pub jitter: f64,
    pub response_counts: std::collections::BTreeMap<String, u64>,
    pub local_failures: u64,
    pub network_errors: u64,
}

pub struct Session {
    cli: Cli,
}

impl Session {
    pub fn new(cli: Cli) -> Self {
        Self { cli }
    }

    pub async fn run(&self) -> Result<()> {
        self.run_impl(true).await
    }

    #[cfg(target_os = "macos")]
    pub async fn run_json_only(&self) -> Result<()> {
        self.run_impl(false).await
    }

    async fn run_impl(&self, show_headers: bool) -> Result<()> {
        let targets = &self.cli.targets;
        let multi_target = targets.len() > 1;
        let quiet = self.cli.quiet;
        let json_stdout = matches!(self.cli.json.as_ref(), Some(None));

        let headers = crate::utils::parse_headers(&self.cli.headers)?;

        let (tx, mut rx) = tokio::sync::mpsc::channel::<models::PingResult>(100);

        let mut all_stats: HashMap<String, models::PingStats> = HashMap::new();
        let mut target_protocols: HashMap<String, crate::cli::Protocol> = HashMap::new();
        let mut pingers: Vec<Box<dyn Pinger>> = Vec::new();

        #[cfg(unix)]
        let mut client_v4: Option<Arc<crate::pinger::icmp::IcmpClient>> = None;
        #[cfg(unix)]
        let mut client_v6: Option<Arc<crate::pinger::icmp::IcmpClient>> = None;
        #[cfg(not(unix))]
        let client_v4: Option<Arc<crate::pinger::icmp::IcmpClient>> = None;
        #[cfg(not(unix))]
        let client_v6: Option<Arc<crate::pinger::icmp::IcmpClient>> = None;

        for target_string in targets {
            // Detect protocol and host
            let (protocol, host_to_resolve) =
                match crate::utils::detect_protocol(&self.cli, target_string) {
                    Ok(res) => res,
                    Err(e) => {
                        eprintln!("pingx: {}: {}", target_string, e);
                        if !multi_target {
                            return Err(e);
                        }
                        continue;
                    }
                };

            target_protocols.insert(target_string.clone(), protocol.clone());

            let ip_version = if self.cli.ipv4 {
                IpVersion::V4
            } else if self.cli.ipv6 {
                IpVersion::V6
            } else {
                IpVersion::Any
            };

            match resolve_host(&host_to_resolve, ip_version).await {
                Ok(addrs) => {
                    let target_addr =
                        match crate::happy_eyeballs::select_best_addr(addrs, &protocol).await {
                            Ok(addr) => addr,
                            Err(e) => {
                                eprintln!("pingx: {}: {}", target_string, e);
                                if !multi_target {
                                    return Err(e);
                                }
                                continue;
                            }
                        };

                    // Initialize ICMP client if needed
                    #[cfg(unix)]
                    if let crate::cli::Protocol::Icmp = protocol {
                        if target_addr.is_ipv4() {
                            if client_v4.is_none() {
                                match crate::pinger::icmp::IcmpClient::new(false, self.cli.ttl) {
                                    Ok(c) => client_v4 = Some(Arc::new(c)),
                                    Err(e) => {
                                        eprintln!("Failed to create IPv4 ICMP client: {}", e);
                                        if !multi_target {
                                            return Err(anyhow::anyhow!(e));
                                        }
                                        continue;
                                    }
                                }
                            }
                        } else if client_v6.is_none() {
                            match crate::pinger::icmp::IcmpClient::new(true, self.cli.ttl) {
                                Ok(c) => client_v6 = Some(Arc::new(c)),
                                Err(e) => {
                                    eprintln!("Failed to create IPv6 ICMP client: {}", e);
                                    if !multi_target {
                                        return Err(anyhow::anyhow!(e));
                                    }
                                    continue;
                                }
                            }
                        }
                    }

                    all_stats.insert(
                        target_string.clone(),
                        models::PingStats::new(target_string.clone(), target_addr),
                    );

                    if show_headers && !json_stdout {
                        Self::print_header(target_string, target_addr, &protocol, self.cli.size);
                    }

                    let config = crate::pinger::PingerConfig {
                        ttl: self.cli.ttl,
                        size: self.cli.size,
                        timeout: self.cli.timeout,
                        headers: headers.clone(),
                    };

                    let mut pinger = crate::pinger::create_pinger(
                        target_string.clone(),
                        protocol,
                        target_addr,
                        config,
                        client_v4.clone(),
                        client_v6.clone(),
                    );

                    if let Err(e) = pinger.start(tx.clone()).await {
                        eprintln!("Failed to start pinger for {}: {}", target_string, e);
                        continue;
                    }
                    pingers.push(pinger);
                }
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

        let mut inflight_packets = 0;

        loop {
            tokio::select! {
                _ = interval.tick(), if !waiting_for_shutdown => {
                    if let Some(c) = count
                        && seq > c {
                            waiting_for_shutdown = true;
                            if inflight_packets == 0 { break; }
                            // Reset sleep to wait for stragglers
                            wait_timeout = Box::pin(tokio::time::sleep(self.cli.timeout + Duration::from_millis(100)));
                            continue;
                    }

                    for pinger in &pingers {
                        if let Err(e) = pinger.ping(seq).await {
                            eprintln!("Failed to ping: {}", e);
                        } else {
                            inflight_packets += 1;
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
                    if inflight_packets > 0 { inflight_packets -= 1; }

                    if let Some(stats) = all_stats.get_mut(&result.target) {
                        stats.update(&result);
                    }
                    if !quiet && !json_stdout {
                        let protocol = target_protocols.get(&result.target).unwrap_or(&crate::cli::Protocol::Icmp);
                        Self::print_result(&result, protocol);
                    }

                    if waiting_for_shutdown && inflight_packets == 0 {
                        break;
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

        // JSON Output Logic
        if let Some(json_arg) = &self.cli.json {
            let mut json_results = Vec::new();

            for target_host in targets {
                if let Some(stats) = all_stats.get(target_host) {
                    let protocol = target_protocols
                        .get(target_host)
                        .unwrap_or(&crate::cli::Protocol::Icmp);
                    let protocol_str = protocol.name().to_string();

                    // Calculate stats
                    let loss = if stats.transmitted > 0 {
                        100.0 * (1.0 - stats.received as f64 / stats.transmitted as f64)
                    } else {
                        0.0
                    };
                    let total_time = stats.start_time.elapsed().as_secs_f64() * 1000.0;

                    let (min, max, avg, mdev, jitter) = if stats.received > 0 {
                        let min = stats.rtts.iter().min().unwrap().as_secs_f64() * 1000.0;
                        let max = stats.rtts.iter().max().unwrap().as_secs_f64() * 1000.0;
                        let avg = stats.rtts.iter().sum::<Duration>().as_secs_f64() * 1000.0
                            / stats.rtts.len() as f64;

                        let avg_duration = Duration::from_secs_f64(avg / 1000.0);
                        let sum_sq_diff: f64 = stats
                            .rtts
                            .iter()
                            .map(|rtt| (rtt.as_secs_f64() - avg_duration.as_secs_f64()).abs())
                            .sum();
                        let mdev = sum_sq_diff / stats.rtts.len() as f64 * 1000.0;

                        let jitter = if stats.rtts.len() > 1 {
                            let sum_diff: f64 = stats
                                .rtts
                                .windows(2)
                                .map(|w| (w[1].as_secs_f64() - w[0].as_secs_f64()).abs())
                                .sum();
                            sum_diff / (stats.rtts.len() - 1) as f64 * 1000.0
                        } else {
                            0.0
                        };
                        (
                            (min * 1000.0).round() / 1000.0,
                            (max * 1000.0).round() / 1000.0,
                            (avg * 1000.0).round() / 1000.0,
                            (mdev * 1000.0).round() / 1000.0,
                            (jitter * 1000.0).round() / 1000.0,
                        )
                    } else {
                        (0.0, 0.0, 0.0, 0.0, 0.0)
                    };

                    json_results.push(JsonResult {
                        target: target_host.clone(),
                        protocol: protocol_str,
                        target_port: protocol.port(),
                        ip: stats._address.to_string(),
                        packet_size: self.cli.size,
                        ttl: self.cli.ttl,
                        sent: stats.transmitted,
                        received: stats.received,
                        loss: (loss * 1000.0).round() / 1000.0,
                        time: (total_time * 1000.0).round() / 1000.0,
                        min,
                        avg,
                        max,
                        mdev,
                        jitter,
                        response_counts: stats
                            .response_counts
                            .iter()
                            .map(|(kind, count)| (kind.as_str(), *count))
                            .collect(),
                        local_failures: stats.local_failures,
                        network_errors: stats.network_errors,
                    });
                }
            }

            let json_output = if json_results.len() == 1 {
                serde_json::to_string_pretty(&json_results[0]).unwrap()
            } else {
                serde_json::to_string_pretty(&json_results).unwrap()
            };

            if let Some(path) = json_arg {
                write_json_file(path, json_output.as_bytes())?;
            } else {
                println!("{}", json_output);
            }

            return Ok(());
        }

        // Collect table data and calculate global column widths
        let mut tables = Vec::new();
        let mut global_key_widths = [0usize; 3];
        let mut global_val_widths = [0usize; 3];

        for target_host in targets {
            if let Some(stats) = all_stats.get(target_host) {
                let table = Self::prepare_table_data(stats);
                for r in 0..3 {
                    for c in 0..3 {
                        global_key_widths[c] =
                            std::cmp::max(global_key_widths[c], table.rows[r][c].key.len());
                        global_val_widths[c] =
                            std::cmp::max(global_val_widths[c], table.rows[r][c].val.len());
                    }
                }
                tables.push((target_host.clone(), table));
            }
        }

        // Print all tables with global widths
        for (target, table) in tables {
            Self::render_table(&target, &table, &global_key_widths, &global_val_widths);
        }

        Ok(())
    }

    fn print_result(result: &models::PingResult, protocol: &crate::cli::Protocol) {
        let seq_prefix = protocol.sequence_name();

        match &result.status {
            models::ProbeStatus::Success(kind) => {
                let ttl_str = if let Some(ttl) = result.ttl {
                    format!(" ttl={}", ttl)
                } else {
                    "".to_string()
                };

                match kind {
                    models::ResponseType::IcmpEchoReply => {
                        println!(
                            "{} bytes from {}: {}={}{} time={:.3} ms",
                            result.bytes,
                            result.target_addr,
                            seq_prefix,
                            result.seq,
                            ttl_str,
                            result.rtt.as_secs_f64() * 1000.0
                        );
                    }
                    models::ResponseType::TcpOpen | models::ResponseType::TcpClosed => {
                        let state = if matches!(kind, models::ResponseType::TcpOpen) {
                            "open"
                        } else {
                            "closed"
                        };
                        println!(
                            "from {}: {}={} state={}{} time={:.3} ms",
                            result.target_addr,
                            seq_prefix,
                            result.seq,
                            state,
                            ttl_str,
                            result.rtt.as_secs_f64() * 1000.0
                        );
                    }
                    models::ResponseType::UdpApplicationReply
                    | models::ResponseType::UdpPortUnreachable => {
                        let state = if matches!(kind, models::ResponseType::UdpApplicationReply) {
                            "application reply"
                        } else {
                            "port unreachable"
                        };
                        println!(
                            "from {}: {}={} {}{} time={:.3} ms",
                            result.target_addr,
                            seq_prefix,
                            result.seq,
                            state,
                            ttl_str,
                            result.rtt.as_secs_f64() * 1000.0
                        );
                    }
                    models::ResponseType::HttpResponse(code) => {
                        println!(
                            "from {}: {}={} status={}{} time={:.3} ms",
                            result.target_addr,
                            seq_prefix,
                            result.seq,
                            code,
                            ttl_str,
                            result.rtt.as_secs_f64() * 1000.0
                        );
                    }
                }
            }
            models::ProbeStatus::Timeout => {
                println!("Request timeout for {}={}", seq_prefix, result.seq);
            }
            models::ProbeStatus::NetworkError { node, reason } => {
                let node = node.map(|node| format!(" from {node}")).unwrap_or_default();
                eprintln!(
                    "Network error{node} for {}={}: {}",
                    seq_prefix, result.seq, reason
                );
            }
            models::ProbeStatus::LocalError(error) => {
                eprintln!("Local error for {}={}: {}", seq_prefix, result.seq, error);
            }
        }
    }

    fn print_header(
        target: &str,
        address: std::net::IpAddr,
        protocol: &crate::cli::Protocol,
        size: usize,
    ) {
        match protocol {
            crate::cli::Protocol::Icmp => println!(
                "PING {target} ({address}) {size}({}) bytes of data.",
                size + 28
            ),
            crate::cli::Protocol::Tcp(port) => {
                println!("TCP PING {target} ({address}) port {port}: 0 bytes of data.")
            }
            crate::cli::Protocol::Udp(port) => {
                println!("UDP PING {target} ({address}) port {port}: {size} bytes of data.")
            }
            crate::cli::Protocol::Http(_) => {
                println!("HTTP PING {target} ({address}) HEAD request.")
            }
        }
    }

    fn prepare_table_data(stats: &models::PingStats) -> TableData {
        let loss = if stats.transmitted > 0 {
            100.0 * (1.0 - stats.received as f64 / stats.transmitted as f64)
        } else {
            0.0
        };

        let total_time = stats.start_time.elapsed().as_millis();

        let (min, max, avg, mdev, jitter) = if stats.received > 0 {
            let min = stats.rtts.iter().min().unwrap().as_secs_f64() * 1000.0;
            let max = stats.rtts.iter().max().unwrap().as_secs_f64() * 1000.0;
            let avg = stats.rtts.iter().sum::<Duration>().as_secs_f64() * 1000.0
                / stats.rtts.len() as f64;

            let avg_duration = Duration::from_secs_f64(avg / 1000.0);
            let sum_sq_diff: f64 = stats
                .rtts
                .iter()
                .map(|rtt| (rtt.as_secs_f64() - avg_duration.as_secs_f64()).abs())
                .sum();
            let mdev = sum_sq_diff / stats.rtts.len() as f64 * 1000.0;

            let jitter = if stats.rtts.len() > 1 {
                let sum_diff: f64 = stats
                    .rtts
                    .windows(2)
                    .map(|w| (w[1].as_secs_f64() - w[0].as_secs_f64()).abs())
                    .sum();
                sum_diff / (stats.rtts.len() - 1) as f64 * 1000.0
            } else {
                0.0
            };

            (
                format!("{:.3} ms", min),
                format!("{:.3} ms", max),
                format!("{:.3} ms", avg),
                format!("{:.3} ms", mdev),
                format!("{:.3} ms", jitter),
            )
        } else {
            (
                String::from("-"),
                String::from("-"),
                String::from("-"),
                String::from("-"),
                String::from("-"),
            )
        };

        TableData {
            rows: [
                [
                    Cell {
                        key: "send:".to_string(),
                        val: format!("{}", stats.transmitted),
                    },
                    Cell {
                        key: "min:".to_string(),
                        val: min,
                    },
                    Cell {
                        key: "time:".to_string(),
                        val: format!("{} ms", total_time),
                    },
                ],
                [
                    Cell {
                        key: "recv:".to_string(),
                        val: format!("{}", stats.received),
                    },
                    Cell {
                        key: "max:".to_string(),
                        val: max,
                    },
                    Cell {
                        key: "jitter:".to_string(),
                        val: jitter,
                    },
                ],
                [
                    Cell {
                        key: "loss:".to_string(),
                        val: format!("{:.0} %", loss),
                    },
                    Cell {
                        key: "avg:".to_string(),
                        val: avg,
                    },
                    Cell {
                        key: "mdev:".to_string(),
                        val: mdev,
                    },
                ],
            ],
        }
    }

    fn render_table(target: &str, table: &TableData, k_widths: &[usize; 3], v_widths: &[usize; 3]) {
        let sep = " | ";

        // Calculate total width for centering title
        // Each column is k_width + 1 (space) + v_width
        let col_widths: Vec<usize> = (0..3).map(|i| k_widths[i] + 1 + v_widths[i]).collect();
        let total_width = col_widths.iter().sum::<usize>() + (sep.len() * 2);

        let title_clean = format!("=== {} ping statistics ===", target);
        let padding = if total_width > title_clean.len() {
            (total_width - title_clean.len()) / 2
        } else {
            0
        };

        println!(
            "\n{:padding$}{}",
            "",
            format!("=== {} ping statistics ===", target.bold()).blue(),
            padding = padding
        );

        for (r_idx, row) in table.rows.iter().enumerate() {
            let is_last_row = r_idx == 2;
            let mut line = String::new();

            for (c_idx, cell) in row.iter().enumerate() {
                let cell_str = format!(
                    "{:>kw$} {:>vw$}",
                    cell.key,
                    cell.val,
                    kw = k_widths[c_idx],
                    vw = v_widths[c_idx]
                );

                if is_last_row {
                    line.push_str(&cell_str.bold().to_string());
                } else {
                    line.push_str(&cell_str);
                }

                if c_idx < 2 {
                    line.push_str(sep);
                }
            }
            println!("{}", line);
        }
    }
}

fn write_json_file(path: &str, data: &[u8]) -> Result<()> {
    use std::io::Write;

    let mut file = std::fs::File::create(path)
        .map_err(|error| anyhow::anyhow!("write JSON to {path}: {error}"))?;
    file.write_all(data)
        .map_err(|error| anyhow::anyhow!("write JSON to {path}: {error}"))?;
    file.sync_all()
        .map_err(|error| anyhow::anyhow!("flush JSON to {path}: {error}"))?;
    Ok(())
}

struct Cell {
    key: String,
    val: String,
}

struct TableData {
    rows: [[Cell; 3]; 3],
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    #[test]
    fn json_file_write_errors_are_returned() {
        let path = std::env::temp_dir().join(format!(
            "pingx-missing-json-directory-{}/result.json",
            std::process::id()
        ));
        assert!(write_json_file(path.to_str().unwrap(), b"{}").is_err());
    }

    #[test]
    fn test_stats_calculation() {
        let mut stats =
            models::PingStats::new("test".to_string(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));

        // Add samples: 10ms, 20ms, 30ms
        stats.update(&models::PingResult {
            target: "test".to_string(),
            target_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            seq: 1,
            bytes: 56,
            ttl: Some(64),
            rtt: Duration::from_millis(10),
            status: models::ProbeStatus::Success(models::ResponseType::IcmpEchoReply),
        });
        stats.update(&models::PingResult {
            target: "test".to_string(),
            target_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            seq: 2,
            bytes: 56,
            ttl: Some(64),
            rtt: Duration::from_millis(20),
            status: models::ProbeStatus::Success(models::ResponseType::IcmpEchoReply),
        });
        stats.update(&models::PingResult {
            target: "test".to_string(),
            target_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            seq: 3,
            bytes: 56,
            ttl: Some(64),
            rtt: Duration::from_millis(30),
            status: models::ProbeStatus::Success(models::ResponseType::IcmpEchoReply),
        });

        let table = Session::prepare_table_data(&stats);

        // Helper to find value by key
        let get_val = |key: &str| -> String {
            for row in &table.rows {
                for cell in row {
                    if cell.key == key {
                        return cell.val.clone();
                    }
                }
            }
            panic!("Key {} not found", key);
        };

        // Min: 10
        assert_eq!(get_val("min:"), "10.000 ms");
        // Max: 30
        assert_eq!(get_val("max:"), "30.000 ms");
        // Avg: 20
        assert_eq!(get_val("avg:"), "20.000 ms");

        // Mdev: (|10-20| + |20-20| + |30-20|) / 3 = (10 + 0 + 10) / 3 = 6.666...
        assert_eq!(get_val("mdev:"), "6.667 ms");

        // Jitter: (|20-10| + |30-20|) / 2 = (10 + 10) / 2 = 10
        assert_eq!(get_val("jitter:"), "10.000 ms");
    }

    #[test]
    fn test_stats_empty() {
        let stats =
            models::PingStats::new("test".to_string(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        let table = Session::prepare_table_data(&stats);
        // Helper to find value by key
        let get_val = |key: &str| -> String {
            for row in &table.rows {
                for cell in row {
                    if cell.key == key {
                        return cell.val.clone();
                    }
                }
            }
            panic!("Key {} not found", key);
        };

        assert_eq!(get_val("min:"), "-");
        assert_eq!(get_val("max:"), "-");
        assert_eq!(get_val("avg:"), "-");
        assert_eq!(get_val("mdev:"), "-");
        assert_eq!(get_val("jitter:"), "-");
    }

    #[test]
    fn response_kinds_and_failures_are_counted_separately() {
        let mut stats = models::PingStats::new("test".to_string(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        let result = |seq, status| models::PingResult {
            target: "test".to_string(),
            target_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            seq,
            bytes: 0,
            ttl: None,
            rtt: if matches!(&status, models::ProbeStatus::Success(_)) {
                Duration::from_millis(seq)
            } else {
                Duration::ZERO
            },
            status,
        };

        stats.update(&result(
            1,
            models::ProbeStatus::Success(models::ResponseType::TcpClosed),
        ));
        stats.update(&result(
            2,
            models::ProbeStatus::Success(models::ResponseType::UdpPortUnreachable),
        ));
        stats.update(&result(3, models::ProbeStatus::Timeout));
        stats.update(&result(
            4,
            models::ProbeStatus::LocalError("send failed".to_string()),
        ));
        stats.update(&result(
            5,
            models::ProbeStatus::NetworkError {
                node: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                reason: "unreachable".to_string(),
            },
        ));

        assert_eq!(stats.transmitted, 5);
        assert_eq!(stats.received, 2);
        assert_eq!(stats.response_counts[&models::ResponseType::TcpClosed], 1);
        assert_eq!(
            stats.response_counts[&models::ResponseType::UdpPortUnreachable],
            1
        );
        assert_eq!(stats.local_failures, 1);
        assert_eq!(stats.network_errors, 1);
    }
}
