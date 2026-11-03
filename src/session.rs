use crate::cli::Cli;
use crate::pinger::Pinger;
use crate::utils::{IpVersion, resolve_host};
use anyhow::Result;
use colored::*;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::signal;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

// One permit per probe; protocol-specific FD weighting needs profiling before it is safe to add.
const MAX_INFLIGHT_PROBES: usize = 64;

pub use self::models::{PingResult, ProbeStatus, ResponseType};

mod models {
    use std::collections::{BTreeMap, BTreeSet};
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
        pub response_counts: BTreeMap<ResponseType, u64>,
        pub local_failures: u64,
        pub network_errors: u64,
        rtt_count: u64,
        rtt_min: Option<Duration>,
        rtt_max: Option<Duration>,
        rtt_mean_secs: f64,
        rtt_m2_secs: f64,
        last_rtt_secs: Option<f64>,
        jitter_sum_secs: f64,
        jitter_count: u64,
        // Registered on send, removed on settle: bounded by outstanding probes, not total sent.
        pending_sequences: BTreeSet<u64>,
    }

    impl PingStats {
        pub fn new(target: String, address: IpAddr) -> Self {
            Self {
                _target: target,
                _address: address,
                transmitted: 0,
                received: 0,
                start_time: Instant::now(),
                response_counts: BTreeMap::new(),
                local_failures: 0,
                network_errors: 0,
                rtt_count: 0,
                rtt_min: None,
                rtt_max: None,
                rtt_mean_secs: 0.0,
                rtt_m2_secs: 0.0,
                last_rtt_secs: None,
                jitter_sum_secs: 0.0,
                jitter_count: 0,
                pending_sequences: BTreeSet::new(),
            }
        }

        pub fn update(&mut self, result: &PingResult) -> bool {
            if !self.pending_sequences.remove(&result.seq) {
                return false;
            }
            match &result.status {
                ProbeStatus::Success(kind) => {
                    self.received += 1;
                    self.add_rtt(result.rtt);
                    *self.response_counts.entry(*kind).or_default() += 1;
                }
                ProbeStatus::LocalError(_) => self.local_failures += 1,
                ProbeStatus::NetworkError { .. } => self.network_errors += 1,
                ProbeStatus::Timeout => {}
            }
            true
        }

        pub fn record_sent(&mut self, seq: u64) {
            self.transmitted += 1;
            self.pending_sequences.insert(seq);
        }

        fn add_rtt(&mut self, rtt: Duration) {
            let secs = rtt.as_secs_f64();
            self.rtt_min = Some(self.rtt_min.map_or(rtt, |m| m.min(rtt)));
            self.rtt_max = Some(self.rtt_max.map_or(rtt, |m| m.max(rtt)));
            // Welford online mean and M2; M2/n equals the old two-pass population variance.
            self.rtt_count += 1;
            let delta = secs - self.rtt_mean_secs;
            self.rtt_mean_secs += delta / self.rtt_count as f64;
            self.rtt_m2_secs += delta * (secs - self.rtt_mean_secs);
            if let Some(prev) = self.last_rtt_secs {
                self.jitter_sum_secs += (secs - prev).abs();
                self.jitter_count += 1;
            }
            self.last_rtt_secs = Some(secs);
        }

        pub fn rtt_metrics(&self) -> Option<(f64, f64, f64, f64, f64)> {
            if self.rtt_count == 0 {
                return None;
            }

            let min = self.rtt_min.unwrap().as_secs_f64() * 1000.0;
            let max = self.rtt_max.unwrap().as_secs_f64() * 1000.0;
            let avg = self.rtt_mean_secs * 1000.0;
            let mdev = (self.rtt_m2_secs / self.rtt_count as f64).sqrt() * 1000.0;
            let jitter = if self.jitter_count > 0 {
                self.jitter_sum_secs / self.jitter_count as f64 * 1000.0
            } else {
                0.0
            };

            Some((min, max, avg, mdev, jitter))
        }
    }
}

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<JsonTimestamp>,
}

#[derive(Serialize)]
#[serde(untagged)]
pub enum JsonTimestamp {
    Unix(f64),
    Iso(String),
}

pub struct Session {
    cli: Cli,
}

struct ScheduledPinger {
    target: String,
    pinger: Arc<dyn Pinger>,
}

struct ProbeScheduler {
    cursor: usize,
    sent_counts: Vec<u64>,
}

impl ProbeScheduler {
    fn new(target_count: usize) -> Self {
        Self {
            cursor: 0,
            sent_counts: vec![0; target_count],
        }
    }

    fn plan(&mut self, count: Option<u64>, permits: usize) -> Vec<usize> {
        let target_count = self.sent_counts.len();
        if target_count == 0 || permits == 0 {
            return Vec::new();
        }

        let mut selected = Vec::with_capacity(permits.min(target_count));
        for offset in 0..target_count {
            let index = (self.cursor + offset) % target_count;
            if count.is_some_and(|limit| self.sent_counts[index] >= limit) {
                continue;
            }
            selected.push(index);
            if selected.len() == permits {
                self.cursor = (index + 1) % target_count;
                break;
            }
        }
        selected
    }

    fn next_sequence(&self, target: usize) -> u64 {
        self.sent_counts[target] + 1
    }

    fn record_sent(&mut self, target: usize) {
        self.sent_counts[target] += 1;
    }

    fn all_reached(&self, count: u64) -> bool {
        self.sent_counts.iter().all(|sent| *sent >= count)
    }
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
        let targets = unique_targets(&self.cli.targets);
        let multi_target = targets.len() > 1;
        let quiet = self.cli.quiet;
        let json_stdout = matches!(self.cli.json.as_ref(), Some(None));

        let headers = crate::utils::parse_headers(&self.cli.headers)?;

        let mut all_stats: HashMap<String, models::PingStats> = HashMap::new();
        let mut target_protocols: HashMap<String, crate::cli::Protocol> = HashMap::new();
        let mut pingers = Vec::new();

        #[cfg(unix)]
        let mut client_v4: Option<Arc<crate::pinger::icmp::IcmpClient>> = None;
        #[cfg(unix)]
        let mut client_v6: Option<Arc<crate::pinger::icmp::IcmpClient>> = None;
        #[cfg(not(unix))]
        let client_v4: Option<Arc<crate::pinger::icmp::IcmpClient>> = None;
        #[cfg(not(unix))]
        let client_v6: Option<Arc<crate::pinger::icmp::IcmpClient>> = None;

        for &target_string in &targets {
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

            target_protocols.insert(target_string.to_string(), protocol.clone());

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
                        target_string.to_string(),
                        models::PingStats::new(target_string.to_string(), target_addr),
                    );

                    if show_headers && !json_stdout {
                        Self::print_header(
                            target_string,
                            target_addr,
                            &protocol,
                            self.cli.ping_size(),
                        );
                    }

                    let config = crate::pinger::PingerConfig {
                        ttl: self.cli.ttl,
                        size: self.cli.ping_size(),
                        timeout: self.cli.timeout,
                        headers: headers.clone(),
                    };

                    let pinger = crate::pinger::create_pinger(
                        target_string.to_string(),
                        protocol,
                        target_addr,
                        config,
                        client_v4.clone(),
                        client_v6.clone(),
                    );
                    pingers.push(ScheduledPinger {
                        target: target_string.to_string(),
                        pinger,
                    });
                }
                Err(e) => {
                    eprintln!("pingx: {}: {}", target_string, e);
                    if !multi_target {
                        return Err(e);
                    }
                }
            }
        }

        if pingers.is_empty() {
            return Ok(());
        }

        let mut interval = tokio::time::interval(self.cli.interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let count = self.cli.count;
        let mut scheduler = ProbeScheduler::new(pingers.len());
        let probe_slots = Arc::new(Semaphore::new(MAX_INFLIGHT_PROBES));
        let mut tasks = JoinSet::new();

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
                    for index in scheduler.plan(count, probe_slots.available_permits()) {
                        let Ok(permit) = probe_slots.clone().try_acquire_owned() else {
                            break;
                        };
                        let seq = scheduler.next_sequence(index);
                        let target = pingers[index].target.clone();
                        let pinger = pingers[index].pinger.clone();
                        if let Some(stats) = all_stats.get_mut(&target) {
                            stats.record_sent(seq);
                        }
                        scheduler.record_sent(index);
                        tasks.spawn(async move {
                            let result = pinger.probe(seq).await;
                            (result, permit)
                        });
                    }

                    if let Some(limit) = count
                        && scheduler.all_reached(limit)
                    {
                        waiting_for_shutdown = true;
                        if tasks.is_empty() {
                            break;
                        }
                        wait_timeout = Box::pin(tokio::time::sleep(
                            self.cli.timeout + Duration::from_millis(100),
                        ));
                    }
                }

                _ = &mut deadline_sleep, if has_deadline => {
                    tasks.abort_all();
                    break;
                }

                _ = &mut wait_timeout, if waiting_for_shutdown => {
                    tasks.abort_all();
                    break;
                }

                Some(joined) = tasks.join_next(), if !tasks.is_empty() => {
                    match joined {
                        Ok((result, permit)) => {
                            if let Some(stats) = all_stats.get_mut(&result.target) {
                                stats.update(&result);
                            }
                            if !quiet && !json_stdout {
                                let protocol = target_protocols
                                    .get(&result.target)
                                    .unwrap_or(&crate::cli::Protocol::Icmp);
                                Self::print_result(&result, protocol, &self.cli)?;
                            }
                            drop(permit);
                        }
                        Err(error) => eprintln!("Probe task failed: {}", error),
                    }
                    if waiting_for_shutdown && tasks.is_empty() {
                        break;
                    }
                }

                _ = stop_rx.recv() => {
                    tasks.abort_all();
                    break;
                }
            }
        }

        // JSON Output Logic
        if let Some(json_arg) = &self.cli.json {
            let mut json_results = Vec::new();

            for &target_host in &targets {
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

                    let (min, max, avg, mdev, jitter) = stats
                        .rtt_metrics()
                        .map(|(min, max, avg, mdev, jitter)| {
                            (
                                (min * 1000.0).round() / 1000.0,
                                (max * 1000.0).round() / 1000.0,
                                (avg * 1000.0).round() / 1000.0,
                                (mdev * 1000.0).round() / 1000.0,
                                (jitter * 1000.0).round() / 1000.0,
                            )
                        })
                        .unwrap_or_default();

                    json_results.push(JsonResult {
                        target: target_host.to_string(),
                        protocol: protocol_str,
                        target_port: protocol.port(),
                        ip: stats._address.to_string(),
                        packet_size: self.cli.ping_size(),
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
                        timestamp: self
                            .cli
                            .timestamp
                            .then(|| json_timestamp(self.cli.timestamp_format.unwrap_or_default()))
                            .transpose()?,
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
        let geo = crate::geoip::GeoIpManager::new().ok();
        let geo_missing = geo.as_ref().is_none_or(|g| !g.has_databases());
        let mut tables = Vec::new();
        let mut global_key_widths = [0usize; 3];
        let mut global_val_widths = [0usize; 3];

        for &target_host in &targets {
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
                let country = geo.as_ref().and_then(|g| g.country_code(stats._address));
                tables.push((target_host.to_string(), country, table));
            }
        }

        // Print all tables with global widths
        for (target, country, table) in tables {
            Self::render_table(
                &target,
                country.as_deref(),
                &table,
                &global_key_widths,
                &global_val_widths,
            );
        }

        if geo_missing {
            println!("\n{}", crate::geoip::missing_database_note());
        }

        Ok(())
    }

    fn print_result(
        result: &models::PingResult,
        protocol: &crate::cli::Protocol,
        cli: &Cli,
    ) -> Result<()> {
        let seq_prefix = protocol.sequence_name();
        let timestamp = cli
            .timestamp
            .then(|| timestamp_prefix(cli.timestamp_format.unwrap_or_default()))
            .transpose()?
            .unwrap_or_default();

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
                            "{}{} bytes from {}: {}={} status=reply{} time={:.3} ms",
                            timestamp,
                            result.bytes,
                            result.target_addr,
                            seq_prefix,
                            result.seq,
                            ttl_str,
                            result.rtt.as_secs_f64() * 1000.0
                        );
                    }
                    models::ResponseType::TcpOpen | models::ResponseType::TcpClosed => {
                        let status = if matches!(kind, models::ResponseType::TcpOpen) {
                            "open"
                        } else {
                            "closed"
                        };
                        println!(
                            "{}from {}: {}={} status={}{} time={:.3} ms",
                            timestamp,
                            result.target_addr,
                            seq_prefix,
                            result.seq,
                            status,
                            ttl_str,
                            result.rtt.as_secs_f64() * 1000.0
                        );
                    }
                    models::ResponseType::UdpApplicationReply
                    | models::ResponseType::UdpPortUnreachable => {
                        let status = if matches!(kind, models::ResponseType::UdpApplicationReply) {
                            "reply"
                        } else {
                            "port_unreachable"
                        };
                        println!(
                            "{}from {}: {}={} status={}{} time={:.3} ms",
                            timestamp,
                            result.target_addr,
                            seq_prefix,
                            result.seq,
                            status,
                            ttl_str,
                            result.rtt.as_secs_f64() * 1000.0
                        );
                    }
                    models::ResponseType::HttpResponse(code) => {
                        println!(
                            "{}from {}: {}={} status={}{} time={:.3} ms",
                            timestamp,
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
                println!(
                    "{}from {}: {}={} status=timeout",
                    timestamp, result.target_addr, seq_prefix, result.seq
                );
            }
            models::ProbeStatus::NetworkError { node, reason } => {
                let node = node.map(|node| format!(" from {node}")).unwrap_or_default();
                eprintln!(
                    "{}Network error{node}: {}={} status=network_error reason={}",
                    timestamp, seq_prefix, result.seq, reason
                );
            }
            models::ProbeStatus::LocalError(error) => {
                eprintln!(
                    "{}Local error: {}={} status=local_error error={}",
                    timestamp, seq_prefix, result.seq, error
                );
            }
        }
        Ok(())
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

        let (min, max, avg, mdev, jitter) = stats
            .rtt_metrics()
            .map(|(min, max, avg, mdev, jitter)| {
                (
                    format!("{min:.3} ms"),
                    format!("{max:.3} ms"),
                    format!("{avg:.3} ms"),
                    format!("{mdev:.3} ms"),
                    format!("{jitter:.3} ms"),
                )
            })
            .unwrap_or_else(|| ("-".into(), "-".into(), "-".into(), "-".into(), "-".into()));

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

    fn styled_label(target: &str, country: Option<&str>) -> String {
        match country {
            Some(code) => format!("[{}] {}", code, target),
            None => target.to_string(),
        }
    }

    fn render_table(
        target: &str,
        country: Option<&str>,
        table: &TableData,
        k_widths: &[usize; 3],
        v_widths: &[usize; 3],
    ) {
        let sep = " | ";
        let label = Self::styled_label(target, country);

        // Calculate total width for centering title
        // Each column is k_width + 1 (space) + v_width
        let col_widths: Vec<usize> = (0..3).map(|i| k_widths[i] + 1 + v_widths[i]).collect();
        let total_width = col_widths.iter().sum::<usize>() + (sep.len() * 2);

        let title_clean = format!("=== {} ping statistics ===", label);
        let padding = if total_width > title_clean.len() {
            (total_width - title_clean.len()) / 2
        } else {
            0
        };

        println!(
            "\n{:padding$}{}",
            "",
            format!("=== {} ping statistics ===", label.as_str().bold()).blue(),
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

pub(crate) fn write_json_file(path: &str, data: &[u8]) -> Result<()> {
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

fn unique_targets(targets: &[String]) -> Vec<&str> {
    let mut seen = HashSet::new();
    targets
        .iter()
        .map(String::as_str)
        .filter(|target| seen.insert(*target))
        .collect()
}

fn timestamp_prefix_at(format: crate::cli::TimestampFormat, now: SystemTime) -> Result<String> {
    use crate::cli::TimestampFormat;
    let now = now
        .duration_since(UNIX_EPOCH)
        .map_err(|error| anyhow::anyhow!("system clock is before Unix epoch: {error}"))?;
    match format {
        TimestampFormat::Unix => Ok(format!("[{}.{:06}] ", now.as_secs(), now.subsec_micros())),
        TimestampFormat::Iso => {
            let utc = time::OffsetDateTime::from_unix_timestamp_nanos(now.as_nanos() as i128)?;
            let value = utc.format(time::macros::format_description!(
                "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:6]Z"
            ))?;
            Ok(format!("{value} "))
        }
    }
}

fn timestamp_prefix(format: crate::cli::TimestampFormat) -> Result<String> {
    timestamp_prefix_at(format, SystemTime::now())
}

fn json_timestamp(format: crate::cli::TimestampFormat) -> Result<JsonTimestamp> {
    json_timestamp_at(format, SystemTime::now())
}

fn json_timestamp_at(
    format: crate::cli::TimestampFormat,
    now: SystemTime,
) -> Result<JsonTimestamp> {
    use crate::cli::TimestampFormat;

    let now = now
        .duration_since(UNIX_EPOCH)
        .map_err(|error| anyhow::anyhow!("system clock is before Unix epoch: {error}"))?;
    match format {
        TimestampFormat::Unix => Ok(JsonTimestamp::Unix(
            format!("{}.{:06}", now.as_secs(), now.subsec_micros()).parse()?,
        )),
        TimestampFormat::Iso => Ok(JsonTimestamp::Iso(
            timestamp_prefix_at(format, UNIX_EPOCH + now)?
                .trim()
                .to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    #[test]
    fn report_title_prefixes_country_code() {
        assert_eq!(Session::styled_label("1.1.1.1", Some("US")), "[US] 1.1.1.1");
        assert_eq!(Session::styled_label("223.5.5.5", None), "223.5.5.5");
    }

    #[test]
    fn json_file_write_errors_are_returned() {
        let path = std::env::temp_dir().join(format!(
            "pingx-missing-json-directory-{}/result.json",
            std::process::id()
        ));
        assert!(write_json_file(path.to_str().unwrap(), b"{}").is_err());
    }

    #[test]
    fn timestamp_prefix_formats_unix_and_utc_iso_microseconds() {
        let now = UNIX_EPOCH + Duration::from_micros(1_793_427_601_123_456);
        assert_eq!(
            timestamp_prefix_at(crate::cli::TimestampFormat::Unix, now).unwrap(),
            "[1793427601.123456] "
        );

        assert_eq!(
            timestamp_prefix_at(crate::cli::TimestampFormat::Iso, now).unwrap(),
            "2026-10-31T06:20:01.123456Z "
        );
    }

    #[test]
    fn timestamps_keep_six_digits_and_truncate_nanoseconds() {
        use crate::cli::TimestampFormat::{Iso, Unix};
        for (nanos, fraction) in [
            (0, "000000"),
            (120_000_000, "120000"),
            (123_456_999, "123456"),
        ] {
            let now = UNIX_EPOCH + Duration::new(1_793_427_601, nanos);
            let iso = format!("2026-10-31T06:20:01.{fraction}Z");
            let unix = format!("1793427601.{fraction}");
            assert_eq!(timestamp_prefix_at(Iso, now).unwrap(), format!("{iso} "));
            assert_eq!(
                timestamp_prefix_at(Unix, now).unwrap(),
                format!("[{unix}] ")
            );
            assert_eq!(
                serde_json::to_value(json_timestamp_at(Iso, now).unwrap()).unwrap(),
                iso
            );
            assert_eq!(
                serde_json::to_value(json_timestamp_at(Unix, now).unwrap()).unwrap(),
                unix.parse::<f64>().unwrap()
            );
        }
        assert!(timestamp_prefix_at(Iso, UNIX_EPOCH - Duration::from_secs(1)).is_err());
        assert!(json_timestamp_at(Unix, UNIX_EPOCH - Duration::from_secs(1)).is_err());
    }

    #[test]
    fn json_timestamp_keeps_numeric_and_string_shapes() {
        assert!(matches!(
            json_timestamp(crate::cli::TimestampFormat::Unix).unwrap(),
            JsonTimestamp::Unix(_)
        ));
        assert!(matches!(
            json_timestamp(crate::cli::TimestampFormat::Iso).unwrap(),
            JsonTimestamp::Iso(_)
        ));
        assert_eq!(
            serde_json::to_value(JsonResult {
                target: "test".into(),
                protocol: "icmp".into(),
                target_port: None,
                ip: "127.0.0.1".into(),
                packet_size: 56,
                ttl: 64,
                sent: 0,
                received: 0,
                loss: 0.0,
                time: 0.0,
                min: 0.0,
                avg: 0.0,
                max: 0.0,
                mdev: 0.0,
                jitter: 0.0,
                response_counts: Default::default(),
                local_failures: 0,
                network_errors: 0,
                timestamp: Some(JsonTimestamp::Unix(1_793_427_601.123_456)),
            })
            .unwrap()["timestamp"],
            1_793_427_601.123_456
        );
    }

    #[test]
    fn json_file_output_is_synced_to_disk() {
        let path =
            std::env::temp_dir().join(format!("pingx-json-sync-{}.json", std::process::id()));
        write_json_file(path.to_str().unwrap(), b"{\"ok\":true}").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"{\"ok\":true}");
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn test_stats_calculation() {
        let mut stats =
            models::PingStats::new("test".to_string(), IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));

        // Add samples: 10ms, 20ms, 30ms
        stats.record_sent(1);
        stats.update(&models::PingResult {
            target: "test".to_string(),
            target_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            seq: 1,
            bytes: 56,
            ttl: Some(64),
            rtt: Duration::from_millis(10),
            status: models::ProbeStatus::Success(models::ResponseType::IcmpEchoReply),
        });
        stats.record_sent(2);
        stats.update(&models::PingResult {
            target: "test".to_string(),
            target_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            seq: 2,
            bytes: 56,
            ttl: Some(64),
            rtt: Duration::from_millis(20),
            status: models::ProbeStatus::Success(models::ResponseType::IcmpEchoReply),
        });
        stats.record_sent(3);
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

        // Mdev: sqrt(((10-20)^2 + (20-20)^2 + (30-20)^2) / 3) = 8.164...
        assert_eq!(get_val("mdev:"), "8.165 ms");

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
    fn repeated_probe_results_are_counted_once() {
        let mut stats = models::PingStats::new("test".to_string(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        let result = models::PingResult {
            target: "test".to_string(),
            target_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            seq: 1,
            bytes: 0,
            ttl: None,
            rtt: Duration::from_millis(10),
            status: models::ProbeStatus::Success(models::ResponseType::TcpOpen),
        };

        stats.record_sent(1);
        assert!(stats.update(&result));
        assert!(!stats.update(&result));

        assert_eq!(stats.transmitted, 1);
        assert_eq!(stats.received, 1);
        assert_eq!(stats.response_counts[&models::ResponseType::TcpOpen], 1);
        let (min, max, _, _, _) = stats.rtt_metrics().unwrap();
        assert!((min - 10.0).abs() < 1e-9);
        assert!((max - 10.0).abs() < 1e-9);
    }

    #[test]
    fn results_without_matching_send_are_not_settled() {
        let mut stats = models::PingStats::new("test".to_string(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        let result = models::PingResult {
            target: "test".to_string(),
            target_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            seq: 9,
            bytes: 0,
            ttl: None,
            rtt: Duration::from_millis(5),
            status: models::ProbeStatus::Success(models::ResponseType::IcmpEchoReply),
        };

        assert!(!stats.update(&result));
        assert_eq!(stats.received, 0);
        assert!(stats.rtt_metrics().is_none());
    }

    #[test]
    fn late_duplicates_after_out_of_order_settle_are_rejected() {
        let mut stats = models::PingStats::new("test".to_string(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        let result = |seq| models::PingResult {
            target: "test".to_string(),
            target_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
            seq,
            bytes: 0,
            ttl: None,
            rtt: Duration::from_millis(seq),
            status: models::ProbeStatus::Success(models::ResponseType::IcmpEchoReply),
        };

        stats.record_sent(1);
        stats.record_sent(2);
        assert!(stats.update(&result(2)));
        assert!(stats.update(&result(1)));
        assert!(!stats.update(&result(1)));
        assert!(!stats.update(&result(2)));
        assert_eq!(stats.received, 2);
    }

    #[test]
    fn sent_probes_without_results_still_count_as_transmitted() {
        let mut stats = models::PingStats::new("test".to_string(), IpAddr::V4(Ipv4Addr::LOCALHOST));

        stats.record_sent(1);

        assert_eq!(stats.transmitted, 1);
        assert_eq!(stats.received, 0);
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

        stats.record_sent(1);
        stats.update(&result(
            1,
            models::ProbeStatus::Success(models::ResponseType::TcpClosed),
        ));
        stats.record_sent(2);
        stats.update(&result(
            2,
            models::ProbeStatus::Success(models::ResponseType::UdpPortUnreachable),
        ));
        stats.record_sent(3);
        stats.update(&result(3, models::ProbeStatus::Timeout));
        stats.record_sent(4);
        stats.update(&result(
            4,
            models::ProbeStatus::LocalError("send failed".to_string()),
        ));
        stats.record_sent(5);
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

    #[test]
    fn duplicate_targets_are_removed_in_input_order() {
        let targets = vec![
            "first.example".to_string(),
            "second.example".to_string(),
            "first.example".to_string(),
        ];

        assert_eq!(
            unique_targets(&targets),
            ["first.example", "second.example"]
        );
    }

    #[test]
    fn scheduler_rotates_targets_and_counts_only_dispatched_probes() {
        let mut scheduler = ProbeScheduler::new(5);

        assert_eq!(scheduler.plan(None, 2), [0, 1]);
        scheduler.record_sent(0);
        scheduler.record_sent(1);
        assert_eq!(scheduler.plan(None, 2), [2, 3]);
        scheduler.record_sent(2);
        scheduler.record_sent(3);
        assert_eq!(scheduler.plan(None, 2), [4, 0]);
        scheduler.record_sent(4);
        scheduler.record_sent(0);

        assert_eq!(scheduler.plan(Some(2), 5), [1, 2, 3, 4]);
        for target in [1, 2, 3, 4] {
            scheduler.record_sent(target);
        }
        assert!(scheduler.all_reached(2));
        assert!(scheduler.plan(Some(2), 5).is_empty());
    }
}
