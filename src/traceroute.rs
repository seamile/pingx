use crate::cli::Cli;
use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TraceOutput {
    Human,
    Json,
    #[cfg(target_os = "macos")]
    HelperData,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct TraceData {
    target_name: String,
    target: std::net::IpAddr,
    max_hops: u8,
    size: usize,
    rows: Vec<TraceDataRow>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct TraceDataRow {
    ttl: u8,
    nodes: Vec<TraceDataNode>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct TraceDataNode {
    ip: std::net::IpAddr,
    rtt_ns: u64,
    error: Option<u8>,
}

pub struct TraceSession {
    cli: Cli,
}

impl TraceSession {
    pub fn new(cli: Cli) -> Self {
        Self { cli }
    }

    pub async fn run(&self) -> Result<()> {
        let output = if self.cli.json.is_some() {
            TraceOutput::Json
        } else {
            TraceOutput::Human
        };
        run_trace(self.cli.clone(), output).await
    }

    #[cfg(target_os = "macos")]
    pub async fn run_helper_data(&self) -> Result<()> {
        let output = if self.cli.json.is_some() {
            TraceOutput::Json
        } else {
            TraceOutput::HelperData
        };
        run_trace(self.cli.clone(), output).await
    }
}

#[cfg(target_os = "macos")]
pub(crate) async fn render_trace_data(data: &str) -> Result<String> {
    platform::render_trace_data(data).await
}

#[cfg(not(any(unix, windows)))]
async fn run_trace(_cli: Cli, _output: TraceOutput) -> Result<()> {
    Err(anyhow::anyhow!(
        "traceroute mode is not supported on this platform"
    ))
}

#[cfg(any(unix, windows))]
mod platform {
    use super::*;
    use crate::cli::Protocol as ProbeProtocol;
    use crate::geoip::GeoIpManager;
    use crate::pinger::icmp_packet::IcmpPacket;
    use crate::utils::{IpVersion, resolve_host};
    #[cfg(windows)]
    use crate::windivert::{Capture, Injector, packet_source};
    use async_trait::async_trait;
    use colored::Colorize;
    use socket2::{Domain, Protocol, Socket, Type};
    #[cfg(target_os = "linux")]
    use socket2::{SockAddr, SockAddrStorage};
    use std::collections::{BTreeMap, HashMap};
    use std::io;
    use std::net::{IpAddr, SocketAddr};
    #[cfg(unix)]
    use std::os::fd::AsRawFd;
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    #[cfg(unix)]
    use tokio::io::unix::AsyncFd;
    #[cfg(target_os = "macos")]
    use tokio::sync::Mutex as AsyncMutex;
    use tokio::sync::mpsc;
    use unicode_width::UnicodeWidthStr;

    const PROBES_PER_HOP: usize = 3;
    const SEND_WINDOW: usize = 8 * PROBES_PER_HOP;
    const LOCATION_MAX_WIDTH: usize = 48;
    const IP_MAX_WIDTH: usize = 48;
    const ICMP_TIME_EXCEEDED_V4: u8 = 11;
    const ICMP_TIME_EXCEEDED_V6: u8 = 3;
    const ICMP_DEST_UNREACH_V4: u8 = 3;
    const ICMP_DEST_UNREACH_V6: u8 = 1;
    const TCP_SYN: u8 = 0x02;
    const TCP_RST: u8 = 0x04;
    const TCP_ACK: u8 = 0x10;
    const IDENTIFIER: u16 = 0x5047;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum TraceProtocol {
        Icmp,
        Udp,
        Tcp,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum ReplyKind {
        Hop,
        Reached,
        Unreachable(u8),
    }

    #[derive(Clone, Copy, Debug)]
    struct Reply {
        sequence: u16,
        token: u16,
        destination: Option<SocketAddr>,
        ip: IpAddr,
        kind: ReplyKind,
        received_at: Instant,
    }

    #[cfg(target_os = "linux")]
    struct ErrorQueueReply {
        from: IpAddr,
        kind: u8,
        code: u8,
        destination: Option<SocketAddr>,
    }

    #[derive(Debug)]
    struct Probe {
        ttl: u8,
        token: u16,
        started: Instant,
        deadline: Instant,
        reply: Option<(IpAddr, Duration, ReplyKind)>,
        cancelled: bool,
        reservation: Option<Socket>,
    }

    #[derive(Debug)]
    struct Row {
        ttl: u8,
        nodes: Vec<Node>,
    }

    #[derive(Debug)]
    struct Node {
        ip: IpAddr,
        rtts: Vec<Duration>,
        error: Option<u8>,
    }

    impl TraceData {
        fn from_rows(
            target_name: String,
            target: IpAddr,
            max_hops: u8,
            size: usize,
            rows: &[Row],
        ) -> Self {
            Self {
                target_name,
                target,
                max_hops,
                size,
                rows: rows
                    .iter()
                    .map(|row| TraceDataRow {
                        ttl: row.ttl,
                        nodes: row
                            .nodes
                            .iter()
                            .map(|node| TraceDataNode {
                                ip: node.ip,
                                rtt_ns: (node.rtts.iter().sum::<Duration>()
                                    / node.rtts.len() as u32)
                                    .as_nanos()
                                    .min(u64::MAX as u128)
                                    as u64,
                                error: node.error,
                            })
                            .collect(),
                    })
                    .collect(),
            }
        }

        #[cfg(target_os = "macos")]
        fn into_rows(self) -> Vec<Row> {
            self.rows
                .into_iter()
                .map(|row| Row {
                    ttl: row.ttl,
                    nodes: row
                        .nodes
                        .into_iter()
                        .map(|node| Node {
                            ip: node.ip,
                            rtts: vec![Duration::from_nanos(node.rtt_ns)],
                            error: node.error,
                        })
                        .collect(),
                })
                .collect()
        }
    }

    struct ProbeRun {
        probes: HashMap<u16, Probe>,
        stop_hop: Option<u8>,
        terminal_error: Option<u8>,
        max_sent: u8,
    }

    struct ProbeRequest {
        target: IpAddr,
        local: IpAddr,
        ident: u16,
        tcp_seed: u32,
        protocol: TraceProtocol,
        base_port: u16,
        payload_size: usize,
        max_hops: u8,
        timeout: Duration,
    }

    #[async_trait]
    trait ProbeSender {
        async fn send_probe(&self, probe: ProbePacket, target: IpAddr, ttl: u8) -> io::Result<()>;
    }

    #[derive(Clone, Debug)]
    enum ProbePacket {
        Icmp(Vec<u8>),
        Udp(Vec<u8>, u16),
        Tcp(Vec<u8>, u16, u32),
    }

    pub(super) async fn run_trace(cli: Cli, output: TraceOutput) -> Result<()> {
        let spec = cli.trace_target()?;
        let (protocol, trace_port) = match spec.protocol {
            ProbeProtocol::Icmp => (TraceProtocol::Icmp, 33434),
            ProbeProtocol::Tcp(port) => (TraceProtocol::Tcp, port),
            ProbeProtocol::Udp(port) => (TraceProtocol::Udp, port),
            ProbeProtocol::Http(_) => {
                unreachable!("HTTP traceroute is rejected by target parsing")
            }
        };
        let version = if cli.ipv4 {
            IpVersion::V4
        } else if cli.ipv6 {
            IpVersion::V6
        } else {
            IpVersion::Any
        };
        let addrs = resolve_host(&spec.host, version).await?;
        let target = select_target(addrs)?;
        let max_hops = cli.max_hops;
        anyhow::ensure!(
            cli.timeout > Duration::ZERO,
            "traceroute timeout must be greater than zero"
        );
        let timeout = cli.timeout;
        let size = packet_size(target, cli.size, protocol)?;
        if protocol == TraceProtocol::Udp {
            validate_udp_port_range(trace_port, max_hops)?;
        }
        let local = crate::probe::tcp_syn::local_address_for(target)?;
        let socket = Arc::new(TraceSocket::new(local, target, protocol, trace_port)?);

        if output == TraceOutput::Human {
            println!(
                "{}",
                styled_trace_header(&spec.host, target, max_hops, size)
            );
        }

        let (reply_tx, mut reply_rx) = mpsc::channel(128);
        let tcp_seed = crate::probe::tcp_syn::next_sequence();
        let receiver = spawn_receiver(socket.clone(), target, tcp_seed, reply_tx);
        let ident = trace_ident();
        let probe_overhead = match protocol {
            TraceProtocol::Icmp => 8,
            TraceProtocol::Udp => 8,
            TraceProtocol::Tcp => 20,
        };
        let payload_size = size
            .checked_sub(if target.is_ipv4() { 20 } else { 40 })
            .and_then(|value| value.checked_sub(probe_overhead))
            .ok_or_else(|| anyhow::anyhow!("traceroute packet size is too small"))?;
        let result = run_until_interrupted(
            run_probes(
                socket.as_ref(),
                ProbeRequest {
                    target,
                    local,
                    ident,
                    tcp_seed,
                    protocol,
                    base_port: trace_port,
                    payload_size,
                    max_hops,
                    timeout,
                },
                &mut reply_rx,
            ),
            tokio::signal::ctrl_c(),
        )
        .await;
        receiver.abort();
        let result = result?;
        let rows = collect_rows(result.probes, result.stop_hop.unwrap_or(result.max_sent));
        match output {
            TraceOutput::Human => render(&rows).await,
            TraceOutput::Json => output_trace_json(
                &cli,
                &TraceData::from_rows(spec.host, target, max_hops, size, &rows),
                result.stop_hop,
                result.terminal_error,
            )?,
            #[cfg(target_os = "macos")]
            TraceOutput::HelperData => println!(
                "{}",
                serde_json::to_string(&TraceData::from_rows(
                    spec.host, target, max_hops, size, &rows,
                ))?
            ),
        }
        match (result.stop_hop, result.terminal_error) {
            (_, Some(code)) => anyhow::bail!("target is unreachable (ICMP error {})", code),
            (Some(_), None) => Ok(()),
            (None, None) => anyhow::bail!("target was not reached within {} hops", max_hops),
        }
    }

    fn output_trace_json(
        cli: &Cli,
        data: &TraceData,
        stop_hop: Option<u8>,
        terminal_error: Option<u8>,
    ) -> Result<()> {
        if stop_hop.is_none() || terminal_error.is_some() {
            return Ok(());
        }
        let output = serde_json::to_string_pretty(data)?;
        if let Some(path) = cli.json.as_ref().and_then(Option::as_deref) {
            crate::session::write_json_file(path, output.as_bytes())?;
        } else {
            println!("{output}");
        }
        Ok(())
    }

    async fn run_probes(
        sender: &dyn ProbeSender,
        request: ProbeRequest,
        reply_rx: &mut mpsc::Receiver<Reply>,
    ) -> Result<ProbeRun> {
        let ProbeRequest {
            target,
            local,
            ident,
            tcp_seed,
            protocol,
            base_port,
            payload_size,
            max_hops,
            timeout,
        } = request;
        let mut probes = HashMap::<u16, Probe>::new();
        let mut sequence = 1u16;
        let mut next_ttl = 1u16;
        let mut stop_hops = BTreeMap::<u8, ReplyKind>::new();
        let mut terminal_error = None::<u8>;

        loop {
            let now = Instant::now();
            let stop_hop = stop_hops.keys().next().copied();
            while can_send(
                next_ttl,
                max_hops,
                stop_hop,
                active_probe_count(&probes, now),
            ) {
                let ttl = u8::try_from(next_ttl).expect("max-hops is limited to u8");
                for _ in 0..PROBES_PER_HOP {
                    let seq = next_sequence(&mut sequence, &probes);
                    let (token, packet, reservation) = match protocol {
                        TraceProtocol::Icmp => {
                            let token = port_for(seq, protocol, base_port);
                            (
                                token,
                                ProbePacket::Icmp(
                                    IcmpPacket::new_request(
                                        target.is_ipv6(),
                                        ident,
                                        token,
                                        vec![0; payload_size],
                                    )
                                    .encode(),
                                ),
                                None,
                            )
                        }
                        TraceProtocol::Udp => {
                            let token = port_for(seq, protocol, base_port);
                            let mut payload = vec![0; payload_size.max(4)];
                            payload[..4].copy_from_slice(&udp_probe_marker(ident, token));
                            (token, ProbePacket::Udp(payload, token), None)
                        }
                        TraceProtocol::Tcp => {
                            let reservation = crate::probe::tcp_syn::reserve_source_port(local)?;
                            let token = reservation
                                .local_addr()?
                                .as_socket()
                                .ok_or_else(|| {
                                    io::Error::other("local TCP source port unavailable")
                                })?
                                .port();
                            let sequence = tcp_probe_sequence(tcp_seed, token);
                            (
                                token,
                                ProbePacket::Tcp(vec![0; payload_size], token, sequence),
                                Some(reservation),
                            )
                        }
                    };
                    probes.insert(
                        seq,
                        Probe {
                            ttl,
                            token,
                            started: Instant::now(),
                            deadline: Instant::now(),
                            reply: None,
                            cancelled: false,
                            reservation,
                        },
                    );
                    sender.send_probe(packet, target, ttl).await?;
                    let sent_at = Instant::now();
                    let deadline = sent_at
                        .checked_add(timeout)
                        .ok_or_else(|| anyhow::anyhow!("traceroute timeout is too large"))?;
                    if let Some(probe) = probes.get_mut(&seq) {
                        probe.started = sent_at;
                        probe.deadline = deadline;
                    }
                }
                next_ttl += 1;
            }

            if stop_hop.is_some() && pending_for_hop(&probes, stop_hop).is_none() {
                break;
            }
            if stop_hop.is_none()
                && next_ttl > u16::from(max_hops)
                && active_probe_count(&probes, Instant::now()) == 0
            {
                break;
            }

            let now = Instant::now();
            for probe in probes.values_mut() {
                if !is_probe_active(probe, now) {
                    probe.reservation.take();
                }
            }
            let wait = probes
                .values()
                .filter(|p| !p.cancelled && p.reply.is_none() && p.deadline > now)
                .map(|p| p.deadline - now)
                .min()
                .unwrap_or(Duration::from_millis(1))
                .min(Duration::from_millis(25));
            tokio::select! {
                reply = reply_rx.recv() => {
                    if let Some(reply) = reply
                        && let Some(probe) = probes.values_mut().find(|probe| {
                            let token_matches = if protocol == TraceProtocol::Icmp {
                                probe.token == reply.sequence
                            } else {
                                probe.token == reply.token
                            };
                            token_matches
                                && (protocol != TraceProtocol::Udp
                                    || reply.destination.is_none_or(|destination| {
                                        probe.token == destination.port()
                                    }))
                                && reply.received_at <= probe.deadline
                                && !probe.cancelled
                                && probe.reply.is_none()
                        })
                    {
                        let reply_ttl = probe.ttl;
                        let rtt = reply_rtt(probe.started, reply);
                        probe.reservation.take();
                        probe.reply = Some((reply.ip, rtt, reply.kind));
                        if reply.kind == ReplyKind::Reached {
                            stop_hops.entry(reply_ttl).or_insert(ReplyKind::Reached);
                            cancel_higher_ttls(&mut probes, reply_ttl);
                        } else if let ReplyKind::Unreachable(code) = reply.kind {
                            terminal_error = Some(code);
                            stop_hops.entry(reply_ttl).or_insert(ReplyKind::Unreachable(code));
                            cancel_higher_ttls(&mut probes, reply_ttl);
                        }
                    }
                }
                _ = tokio::time::sleep(wait) => {}
            }
        }

        let max_sent = probes.values().map(|p| p.ttl).max().unwrap_or(0);
        Ok(ProbeRun {
            probes,
            stop_hop: stop_hops.keys().next().copied(),
            terminal_error,
            max_sent,
        })
    }

    async fn run_until_interrupted<T>(
        operation: impl Future<Output = Result<T>>,
        interrupt: impl Future<Output = io::Result<()>>,
    ) -> Result<T> {
        tokio::select! {
            result = operation => result,
            signal = interrupt => {
                signal?;
                anyhow::bail!("traceroute cancelled by user")
            }
        }
    }

    fn pending_for_hop(probes: &HashMap<u16, Probe>, target_hop: Option<u8>) -> Option<()> {
        let now = Instant::now();
        let hop = target_hop?;
        probes
            .values()
            .any(|p| p.ttl <= hop && is_probe_active(p, now))
            .then_some(())
    }

    fn is_probe_active(probe: &Probe, now: Instant) -> bool {
        !probe.cancelled && probe.reply.is_none() && now < probe.deadline
    }

    fn active_probe_count(probes: &HashMap<u16, Probe>, now: Instant) -> usize {
        probes.values().filter(|p| is_probe_active(p, now)).count()
    }

    fn can_send(next_ttl: u16, max_hops: u8, stop_hop: Option<u8>, active: usize) -> bool {
        stop_hop.is_none()
            && next_ttl <= u16::from(max_hops)
            && active.saturating_add(PROBES_PER_HOP) <= SEND_WINDOW
    }

    fn cancel_higher_ttls(probes: &mut HashMap<u16, Probe>, ttl: u8) {
        for pending in probes.values_mut() {
            if pending.ttl > ttl && pending.reply.is_none() {
                pending.cancelled = true;
            }
        }
    }

    fn next_sequence(next: &mut u16, probes: &HashMap<u16, Probe>) -> u16 {
        loop {
            let value = *next;
            *next = next.wrapping_add(1);
            if !probes.contains_key(&value) {
                return value;
            }
        }
    }

    fn port_for(sequence: u16, protocol: TraceProtocol, base: u16) -> u16 {
        match protocol {
            TraceProtocol::Icmp => sequence,
            TraceProtocol::Udp => base.wrapping_add(sequence - 1),
            TraceProtocol::Tcp => unreachable!("TCP probes reserve an ephemeral source port"),
        }
    }

    fn validate_udp_port_range(base: u16, max_hops: u8) -> Result<()> {
        anyhow::ensure!(
            u32::from(base) + u32::from(max_hops) * PROBES_PER_HOP as u32
                <= u32::from(u16::MAX) + 1,
            "UDP traceroute port range exceeds 65535"
        );
        Ok(())
    }

    fn tcp_probe_sequence(seed: u32, source_port: u16) -> u32 {
        seed ^ u32::from(source_port).wrapping_mul(0x9e37_79b1)
    }

    fn packet_size(
        target: IpAddr,
        requested: Option<usize>,
        protocol: TraceProtocol,
    ) -> Result<usize> {
        if protocol == TraceProtocol::Tcp {
            let size = if target.is_ipv4() { 40 } else { 60 };
            anyhow::ensure!(
                requested.is_none_or(|requested| requested == size),
                "TCP traceroute packet size is fixed at {size} bytes"
            );
            return Ok(size);
        }
        let size = requested.unwrap_or(if target.is_ipv4() { 40 } else { 60 });
        let minimum = match (target.is_ipv4(), protocol) {
            (true, TraceProtocol::Udp) => 32,
            (true, TraceProtocol::Icmp) => 28,
            (false, TraceProtocol::Udp) => 52,
            (false, TraceProtocol::Icmp) => 48,
            (_, TraceProtocol::Tcp) => unreachable!(),
        };
        anyhow::ensure!(
            (minimum..=u16::MAX as usize).contains(&size),
            "traceroute packet size must be between {} and 65535 bytes",
            minimum
        );
        Ok(size)
    }

    fn select_target(addrs: Vec<IpAddr>) -> Result<IpAddr> {
        select_target_with(addrs, route_available)
    }

    fn select_target_with(
        addrs: Vec<IpAddr>,
        route_available: impl Fn(IpAddr) -> io::Result<()>,
    ) -> Result<IpAddr> {
        let mut route_errors = Vec::new();
        for addr in addrs {
            match route_available(addr) {
                Ok(()) => return Ok(addr),
                Err(e) => route_errors.push(format!("{addr}: {e}")),
            }
        }
        anyhow::bail!("no usable route to target ({})", route_errors.join("; "))
    }

    fn route_available(target: IpAddr) -> io::Result<()> {
        let domain = if target.is_ipv6() {
            Domain::IPV6
        } else {
            Domain::IPV4
        };
        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        if let Some(iface) = crate::utils::get_bind_interface() {
            crate::utils::bind_socket_to_interface(&socket, iface, target.is_ipv6())?;
        }
        let addr = socket2::SockAddr::from(SocketAddr::new(target, 33434));
        socket.connect(&addr)
    }

    fn display_target(name: &str, ip: IpAddr) -> String {
        if name.parse::<IpAddr>().is_ok() {
            name.to_string()
        } else {
            format!("{} ({})", name, ip)
        }
    }

    fn styled_trace_header(name: &str, ip: IpAddr, max_hops: u8, size: usize) -> String {
        format!(
            "{} {}   {} {:>3}    {} {} b",
            "Target:".bold(),
            display_target(name, ip),
            "Max Hops:".bold(),
            max_hops,
            "Size:".bold(),
            size
        )
    }

    #[cfg(unix)]
    struct TraceSocket {
        send: AsyncFd<std::net::UdpSocket>,
        recv: AsyncFd<std::net::UdpSocket>,
        #[cfg(not(target_os = "macos"))]
        tcp_recv: Option<AsyncFd<std::net::UdpSocket>>,
        #[cfg(target_os = "macos")]
        tcp_recv: Option<AsyncMutex<crate::probe::tcp_capture::TcpCapture>>,
        v6: bool,
        protocol: TraceProtocol,
        trace_port: u16,
    }

    #[cfg(unix)]
    impl TraceSocket {
        fn new(
            local: IpAddr,
            target: IpAddr,
            protocol: TraceProtocol,
            trace_port: u16,
        ) -> io::Result<Self> {
            let v6 = target.is_ipv6();
            let _ = local;
            let send = match protocol {
                TraceProtocol::Icmp => Self::icmp_socket(v6)?,
                TraceProtocol::Udp => {
                    let socket =
                        Socket::new(domain(v6), Type::DGRAM, Some(socket2::Protocol::UDP))?;
                    bind_device(&socket, v6)?;
                    socket
                }
                TraceProtocol::Tcp => {
                    let socket = Socket::new(domain(v6), Type::RAW, Some(socket2::Protocol::TCP))
                        .map_err(raw_error)?;
                    bind_device(&socket, v6)?;
                    if v6 {
                        #[cfg(not(target_os = "macos"))]
                        socket.set_header_included_v6(true)?;
                    } else {
                        socket.set_header_included_v4(true)?;
                    }
                    socket
                }
            };
            let recv = match protocol {
                TraceProtocol::Udp => {
                    #[cfg(target_os = "linux")]
                    let socket = send.try_clone()?;
                    #[cfg(not(target_os = "linux"))]
                    let socket = Self::icmp_socket(v6)?;
                    #[cfg(target_os = "linux")]
                    {
                        let on: libc::c_int = 1;
                        let (level, option) = if v6 {
                            (libc::IPPROTO_IPV6, libc::IPV6_RECVERR)
                        } else {
                            (libc::IPPROTO_IP, libc::IP_RECVERR)
                        };
                        let rc = unsafe {
                            libc::setsockopt(
                                socket.as_raw_fd(),
                                level,
                                option,
                                &on as *const _ as *const libc::c_void,
                                std::mem::size_of_val(&on) as libc::socklen_t,
                            )
                        };
                        if rc != 0 {
                            return Err(io::Error::last_os_error());
                        }
                    }
                    socket
                }
                TraceProtocol::Icmp => Self::icmp_socket(v6)?,
                TraceProtocol::Tcp => Self::icmp_socket(v6)?,
            };
            #[cfg(not(target_os = "macos"))]
            let tcp_recv = if protocol == TraceProtocol::Tcp {
                let socket = Socket::new(domain(v6), Type::RAW, Some(socket2::Protocol::TCP))
                    .map_err(raw_error)?;
                bind_device(&socket, v6)?;
                if v6 {
                    socket.set_header_included_v6(true)?;
                } else {
                    socket.set_header_included_v4(true)?;
                }
                socket.set_nonblocking(true)?;
                let socket: std::net::UdpSocket = socket.into();
                Some(unsafe { AsyncFd::register(socket) }?)
            } else {
                None
            };
            #[cfg(target_os = "macos")]
            let tcp_recv = if protocol == TraceProtocol::Tcp {
                Some(AsyncMutex::new(crate::probe::tcp_capture::TcpCapture::new(
                    local,
                )?))
            } else {
                None
            };
            send.set_nonblocking(true)?;
            recv.set_nonblocking(true)?;
            set_ttl_value(&send, v6, 1)?;
            let send = std::net::UdpSocket::from(send);
            let recv: std::net::UdpSocket = recv.into();
            Ok(Self {
                send: unsafe { AsyncFd::register(send) }?,
                recv: unsafe { AsyncFd::register(recv) }?,
                tcp_recv,
                v6,
                protocol,
                trace_port,
            })
        }

        fn icmp_socket(v6: bool) -> io::Result<Socket> {
            let protocol = if v6 {
                socket2::Protocol::ICMPV6
            } else {
                socket2::Protocol::ICMPV4
            };
            let socket = Socket::new(domain(v6), socket_type(), Some(protocol)).map_err(|e| {
                if e.kind() == io::ErrorKind::PermissionDenied {
                    io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "traceroute requires RAW socket privileges; run with sudo or grant CAP_NET_RAW",
                    )
                } else {
                    e
                }
            })?;
            bind_device(&socket, v6)?;
            Ok(socket)
        }

        fn set_ttl(&self, ttl: u8) -> io::Result<()> {
            let value = ttl as libc::c_int;
            let (level, option) = if self.v6 {
                (libc::IPPROTO_IPV6, libc::IPV6_UNICAST_HOPS)
            } else {
                (libc::IPPROTO_IP, libc::IP_TTL)
            };
            let fd = self.send.get_ref().as_raw_fd();
            let rc = unsafe {
                libc::setsockopt(
                    fd,
                    level,
                    option,
                    &value as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&value) as libc::socklen_t,
                )
            };
            if rc == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        }

        async fn send_to(&self, probe: ProbePacket, target: IpAddr, ttl: u8) -> io::Result<()> {
            self.set_ttl(ttl)?;
            let (data, port) = match (&self.protocol, probe) {
                (TraceProtocol::Icmp, ProbePacket::Icmp(data)) => (data, 0),
                (TraceProtocol::Udp, ProbePacket::Udp(data, port)) => (data, port),
                (TraceProtocol::Tcp, ProbePacket::Tcp(payload, source_port, sequence)) => (
                    build_tcp_packet(
                        target,
                        self.trace_port,
                        source_port,
                        sequence,
                        &payload,
                        ttl,
                    )?,
                    0,
                ),
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "probe/protocol mismatch",
                    ));
                }
            };
            let data = if self.protocol == TraceProtocol::Tcp {
                crate::probe::tcp_syn::raw_tcp_payload(&data, target)?
            } else {
                &data
            };
            #[cfg(target_os = "linux")]
            let mut udp_retries = 0;
            loop {
                let mut guard = self.send.writable().await?;
                match guard.try_io(|inner| {
                    // ICMP errors belong to earlier UDP probes and remain in MSG_ERRQUEUE.
                    #[cfg(target_os = "linux")]
                    if self.protocol == TraceProtocol::Udp {
                        inner.get_ref().take_error()?;
                    }
                    inner
                        .get_ref()
                        .send_to(data, SocketAddr::new(target, port))
                        .map(|_| ())
                }) {
                    #[cfg(target_os = "linux")]
                    Ok(Err(error))
                        if self.protocol == TraceProtocol::Udp
                            && udp_retries < 3
                            && matches!(
                                error.raw_os_error(),
                                Some(libc::EHOSTUNREACH | libc::ENETUNREACH | libc::ECONNREFUSED)
                            ) =>
                    {
                        udp_retries += 1;
                        tokio::task::yield_now().await;
                    }
                    Ok(result) => return result,
                    Err(_) => continue,
                }
            }
        }

        async fn send_tcp_reset(
            &self,
            target: IpAddr,
            local_port: u16,
            remote_port: u16,
            sequence: u32,
        ) -> io::Result<()> {
            let source = crate::probe::tcp_syn::local_address_for(target)?;
            let packet = build_tcp_reset_packet(source, target, local_port, remote_port, sequence)?;
            let packet = crate::probe::tcp_syn::raw_tcp_payload(&packet, target)?;
            loop {
                let mut guard = self.send.writable().await?;
                match guard.try_io(|inner| {
                    inner
                        .get_ref()
                        .send_to(packet, SocketAddr::new(target, 0))
                        .map(|_| ())
                }) {
                    Ok(result) => return result,
                    Err(_) => continue,
                }
            }
        }

        async fn recv(&self, data: &mut [u8]) -> io::Result<(usize, IpAddr)> {
            loop {
                let mut guard = self.recv.readable().await?;
                match guard.try_io(|inner| {
                    inner
                        .get_ref()
                        .recv_from(data)
                        .map(|(size, address)| (size, address.ip()))
                }) {
                    Ok(result) => return result,
                    Err(_) => continue,
                }
            }
        }

        #[cfg(target_os = "linux")]
        async fn recv_error(
            &self,
            data: &mut [u8],
        ) -> io::Result<(IpAddr, usize, u8, u8, Option<SocketAddr>)> {
            loop {
                let mut guard = self.recv.ready(tokio::io::Interest::ERROR).await?;
                match guard.try_io(|inner| {
                    let fd = inner.get_ref().as_raw_fd();
                    let mut iov = libc::iovec {
                        iov_base: data.as_mut_ptr().cast(),
                        iov_len: data.len(),
                    };
                    let mut control = [0usize; 32];
                    let mut name: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
                    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
                    msg.msg_name = (&mut name as *mut libc::sockaddr_storage).cast();
                    msg.msg_namelen = std::mem::size_of_val(&name) as libc::socklen_t;
                    msg.msg_iov = &mut iov;
                    msg.msg_iovlen = 1;
                    msg.msg_control = control.as_mut_ptr().cast();
                    msg.msg_controllen = std::mem::size_of_val(&control);
                    let size = unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_ERRQUEUE) };
                    if size < 0 {
                        return Err(io::Error::last_os_error());
                    }
                    let destination = socket_addr_from_storage(&name, msg.msg_namelen);
                    let mut code = None;
                    let mut offender = None;
                    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
                    while !cmsg.is_null() {
                        let header = unsafe { &*cmsg };
                        if (header.cmsg_level == libc::IPPROTO_IP
                            && header.cmsg_type == libc::IP_RECVERR)
                            || (header.cmsg_level == libc::IPPROTO_IPV6
                                && header.cmsg_type == libc::IPV6_RECVERR)
                        {
                            let error = unsafe {
                                &*(libc::CMSG_DATA(cmsg) as *const libc::sock_extended_err)
                            };
                            if matches!(
                                error.ee_origin,
                                libc::SO_EE_ORIGIN_ICMP | libc::SO_EE_ORIGIN_ICMP6
                            ) {
                                let valid = (error.ee_origin == libc::SO_EE_ORIGIN_ICMP
                                    && matches!(
                                        error.ee_type,
                                        ICMP_TIME_EXCEEDED_V4 | ICMP_DEST_UNREACH_V4
                                    ))
                                    || (error.ee_origin == libc::SO_EE_ORIGIN_ICMP6
                                        && matches!(
                                            error.ee_type,
                                            ICMP_TIME_EXCEEDED_V6 | ICMP_DEST_UNREACH_V6
                                        ));
                                if valid {
                                    code = Some((error.ee_type, error.ee_code));
                                }
                                let address = unsafe { libc::SO_EE_OFFENDER(error) };
                                if !address.is_null() {
                                    let len = match unsafe { (*address).sa_family } as i32 {
                                        libc::AF_INET => std::mem::size_of::<libc::sockaddr_in>(),
                                        libc::AF_INET6 => std::mem::size_of::<libc::sockaddr_in6>(),
                                        _ => 0,
                                    };
                                    if len > 0 {
                                        let address = unsafe {
                                            sockaddr_from_ptr(address, len as libc::socklen_t)
                                        };
                                        offender = address.as_socket().map(|address| address.ip());
                                    }
                                }
                            }
                        }
                        cmsg = unsafe { libc::CMSG_NXTHDR(&msg, cmsg) };
                    }
                    match (code, offender) {
                        (Some((kind, code)), Some(address)) => {
                            Ok((address, size as usize, kind, code, destination))
                        }
                        _ => Err(io::Error::new(
                            io::ErrorKind::WouldBlock,
                            "ignore non-ICMP error",
                        )),
                    }
                }) {
                    Ok(result) => return result,
                    Err(_) => continue,
                }
            }
        }

        async fn recv_tcp(&self, data: &mut [u8]) -> io::Result<(usize, IpAddr)> {
            let socket = self.tcp_recv.as_ref().ok_or_else(|| {
                io::Error::new(io::ErrorKind::Unsupported, "TCP receiver unavailable")
            })?;
            #[cfg(target_os = "macos")]
            {
                let (source, packet) = socket.lock().await.recv().await?;
                let size = packet.len().min(data.len());
                data[..size].copy_from_slice(&packet[..size]);
                Ok((size, source))
            }
            #[cfg(not(target_os = "macos"))]
            loop {
                let mut guard = socket.readable().await?;
                match guard.try_io(|inner| {
                    inner
                        .get_ref()
                        .recv_from(data)
                        .map(|(size, address)| (size, address.ip()))
                }) {
                    Ok(result) => return result,
                    Err(_) => continue,
                }
            }
        }
    }

    #[cfg(windows)]
    enum WindowsSend {
        Datagram(tokio::net::UdpSocket),
        Injector(Injector),
    }

    #[cfg(windows)]
    struct TraceSocket {
        send: WindowsSend,
        capture: Capture,
        local: IpAddr,
        v6: bool,
        protocol: TraceProtocol,
        trace_port: u16,
    }

    #[cfg(windows)]
    impl TraceSocket {
        fn new(
            local: IpAddr,
            target: IpAddr,
            protocol: TraceProtocol,
            trace_port: u16,
        ) -> io::Result<Self> {
            let v6 = target.is_ipv6();
            let send = match protocol {
                TraceProtocol::Icmp => WindowsSend::Datagram(probe_socket(local, v6, protocol)?),
                TraceProtocol::Udp => WindowsSend::Datagram(probe_socket(local, v6, protocol)?),
                TraceProtocol::Tcp => WindowsSend::Injector(Injector::open()?),
            };
            let capture = Capture::open(&trace_filter(local, target, protocol, trace_port)?)?;
            Ok(Self {
                send,
                capture,
                local,
                v6,
                protocol,
                trace_port,
            })
        }

        fn set_ttl(&self, ttl: u8) -> io::Result<()> {
            let WindowsSend::Datagram(socket) = &self.send else {
                return Ok(());
            };
            let socket = socket2::SockRef::from(socket);
            if self.v6 {
                socket.set_unicast_hops_v6(u32::from(ttl))
            } else {
                socket.set_ttl_v4(u32::from(ttl))
            }
        }

        async fn send_to(&self, probe: ProbePacket, target: IpAddr, ttl: u8) -> io::Result<()> {
            match (&self.protocol, probe) {
                (TraceProtocol::Icmp, ProbePacket::Icmp(data)) => {
                    self.set_ttl(ttl)?;
                    self.datagram()?
                        .send_to(&data, SocketAddr::new(target, 0))
                        .await
                        .map(|_| ())
                }
                (TraceProtocol::Udp, ProbePacket::Udp(data, port)) => {
                    self.set_ttl(ttl)?;
                    let socket = self.datagram()?;
                    let mut retries = 0;
                    loop {
                        match socket.send_to(&data, SocketAddr::new(target, port)).await {
                            Err(error)
                                if retries < 3
                                    && matches!(
                                        error.kind(),
                                        io::ErrorKind::ConnectionReset
                                            | io::ErrorKind::ConnectionRefused
                                            | io::ErrorKind::HostUnreachable
                                            | io::ErrorKind::NetworkUnreachable
                                    ) =>
                            {
                                retries += 1;
                                tokio::task::yield_now().await;
                            }
                            result => return result.map(|_| ()),
                        }
                    }
                }
                (TraceProtocol::Tcp, ProbePacket::Tcp(payload, source_port, sequence)) => {
                    let packet = build_tcp_packet(
                        target,
                        self.trace_port,
                        source_port,
                        sequence,
                        &payload,
                        ttl,
                    )?;
                    let WindowsSend::Injector(injector) = &self.send else {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "TCP injector unavailable",
                        ));
                    };
                    injector.send(&packet, target.is_ipv6()).map(|_| ())
                }
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "probe/protocol mismatch",
                )),
            }
        }

        fn datagram(&self) -> io::Result<&tokio::net::UdpSocket> {
            match &self.send {
                WindowsSend::Datagram(socket) => Ok(socket),
                WindowsSend::Injector(_) => Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "datagram socket unavailable",
                )),
            }
        }

        async fn send_tcp_reset(
            &self,
            target: IpAddr,
            local_port: u16,
            remote_port: u16,
            sequence: u32,
        ) -> io::Result<()> {
            let packet =
                build_tcp_reset_packet(self.local, target, local_port, remote_port, sequence)?;
            let WindowsSend::Injector(injector) = &self.send else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "TCP injector unavailable",
                ));
            };
            injector.send(&packet, target.is_ipv6()).map(|_| ())
        }

        async fn recv(&self, data: &mut [u8]) -> io::Result<(usize, IpAddr)> {
            let packet = self.capture.recv_any().await?;
            let from = packet_source(&packet.data).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "WinDivert returned a short packet",
                )
            })?;
            let size = packet.data.len().min(data.len());
            data[..size].copy_from_slice(&packet.data[..size]);
            Ok((size, from))
        }
    }

    #[cfg(windows)]
    fn probe_socket(
        local: IpAddr,
        v6: bool,
        trace_protocol: TraceProtocol,
    ) -> io::Result<tokio::net::UdpSocket> {
        let (kind, protocol) = match trace_protocol {
            TraceProtocol::Icmp if v6 => (Type::RAW, socket2::Protocol::ICMPV6),
            TraceProtocol::Icmp => (Type::RAW, socket2::Protocol::ICMPV4),
            TraceProtocol::Udp => (Type::DGRAM, socket2::Protocol::UDP),
            TraceProtocol::Tcp => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "TCP probes use WinDivert",
                ));
            }
        };
        let socket = Socket::new(domain(v6), kind, Some(protocol)).map_err(trace_socket_error)?;
        socket.bind(&SocketAddr::new(local, 0).into())?;
        socket.set_nonblocking(true)?;
        let socket: std::net::UdpSocket = socket.into();
        tokio::net::UdpSocket::from_std(socket)
    }

    #[cfg(windows)]
    fn trace_socket_error(error: io::Error) -> io::Error {
        if error.kind() == io::ErrorKind::PermissionDenied {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "traceroute requires Administrator privileges on Windows",
            )
        } else {
            error
        }
    }

    #[cfg(windows)]
    fn trace_filter(
        local: IpAddr,
        target: IpAddr,
        protocol: TraceProtocol,
        trace_port: u16,
    ) -> io::Result<String> {
        if local.is_ipv6() != target.is_ipv6() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "source and target address families differ",
            ));
        }
        let filter = if target.is_ipv6() {
            let tcp = (protocol == TraceProtocol::Tcp).then(|| {
                format!(
                    " or (tcp and ipv6.SrcAddr == {target} and ipv6.DstAddr == {local} and tcp.SrcPort == {trace_port} and tcp.DstPort != 0 and ((tcp.SYN and tcp.ACK) or (tcp.RST and tcp.ACK)))"
                )
            });
            format!(
                "(inbound or loopback) and ipv6 and ipv6.DstAddr == {local} and ((icmpv6 and (icmpv6.Type == 129 or icmpv6.Type == 1 or icmpv6.Type == 3)){})",
                tcp.as_deref().unwrap_or("")
            )
        } else {
            let tcp = (protocol == TraceProtocol::Tcp).then(|| {
                format!(
                    " or (tcp and ip.SrcAddr == {target} and ip.DstAddr == {local} and tcp.SrcPort == {trace_port} and tcp.DstPort != 0 and ((tcp.SYN and tcp.ACK) or (tcp.RST and tcp.ACK)))"
                )
            });
            format!(
                "(inbound or loopback) and ip and ip.DstAddr == {local} and ((icmp and (icmp.Type == 0 or icmp.Type == 3 or icmp.Type == 11)){})",
                tcp.as_deref().unwrap_or("")
            )
        };
        Ok(filter)
    }

    #[cfg(unix)]
    fn socket_type() -> Type {
        Type::RAW
    }

    #[async_trait]
    impl ProbeSender for TraceSocket {
        async fn send_probe(&self, probe: ProbePacket, target: IpAddr, ttl: u8) -> io::Result<()> {
            self.send_to(probe, target, ttl).await
        }
    }

    fn domain(v6: bool) -> Domain {
        if v6 { Domain::IPV6 } else { Domain::IPV4 }
    }

    #[cfg(unix)]
    fn raw_error(error: io::Error) -> io::Error {
        if error.kind() == io::ErrorKind::PermissionDenied {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "TCP traceroute requires RAW socket privileges; run with sudo or grant CAP_NET_RAW",
            )
        } else {
            error
        }
    }

    #[cfg(unix)]
    fn bind_device(socket: &Socket, v6: bool) -> io::Result<()> {
        if let Some(iface) = crate::utils::get_bind_interface() {
            crate::utils::bind_socket_to_interface(socket, iface, v6)?;
        }
        Ok(())
    }

    #[cfg(unix)]
    fn set_ttl_value(socket: &Socket, v6: bool, ttl: u8) -> io::Result<()> {
        if v6 {
            socket.set_unicast_hops_v6(u32::from(ttl))
        } else {
            socket.set_ttl_v4(u32::from(ttl))
        }
    }

    fn build_tcp_packet(
        target: IpAddr,
        port: u16,
        source_port: u16,
        sequence: u32,
        payload: &[u8],
        ttl: u8,
    ) -> io::Result<Vec<u8>> {
        let source = crate::probe::tcp_syn::local_address_for(target)?;
        crate::probe::tcp_syn::build_tcp_packet(
            source,
            target,
            crate::probe::tcp_syn::TcpSegment {
                source_port,
                target_port: port,
                sequence,
                acknowledgement: 0,
                flags: TCP_SYN,
                payload,
            },
            ttl,
        )
    }

    fn build_tcp_reset_packet(
        source: IpAddr,
        target: IpAddr,
        local_port: u16,
        remote_port: u16,
        sequence: u32,
    ) -> io::Result<Vec<u8>> {
        crate::probe::tcp_syn::build_tcp_packet(
            source,
            target,
            crate::probe::tcp_syn::TcpSegment {
                source_port: local_port,
                target_port: remote_port,
                sequence,
                acknowledgement: 0,
                flags: TCP_RST,
                payload: &[],
            },
            64,
        )
    }

    #[cfg(test)]
    fn ip_checksum(header: &[u8]) -> u16 {
        finish_checksum(header.chunks(2).fold(0u32, |sum, word| {
            sum + u16::from_be_bytes([word[0], *word.get(1).unwrap_or(&0)]) as u32
        }))
    }

    #[cfg(test)]
    fn tcp_checksum(source: std::net::Ipv4Addr, tcp: &[u8], target_octets: &[u8]) -> u16 {
        let source_octets = source.octets();
        let mut sum = source_octets
            .chunks(2)
            .chain(target_octets.chunks(2))
            .fold(0u32, |sum, word| {
                sum + u16::from_be_bytes([word[0], word[1]]) as u32
            });
        sum += 6u32 + tcp.len() as u32;
        sum += tcp.chunks(2).fold(0u32, |sum, word| {
            sum + u16::from_be_bytes([word[0], *word.get(1).unwrap_or(&0)]) as u32
        });
        finish_checksum(sum)
    }

    fn udp_probe_marker(ident: u16, port: u16) -> [u8; 4] {
        let marker = (u32::from(ident) << 16) | u32::from(port);
        marker.to_be_bytes()
    }

    #[cfg(target_os = "linux")]
    fn socket_addr_from_storage(
        storage: &libc::sockaddr_storage,
        len: libc::socklen_t,
    ) -> Option<SocketAddr> {
        (len > 0)
            .then(|| unsafe {
                sockaddr_from_ptr((storage as *const libc::sockaddr_storage).cast(), len)
            })
            .and_then(|address| address.as_socket())
    }

    #[cfg(target_os = "linux")]
    unsafe fn sockaddr_from_ptr(address: *const libc::sockaddr, len: libc::socklen_t) -> SockAddr {
        let storage: SockAddrStorage = unsafe { std::ptr::read_unaligned(address.cast()) };
        unsafe { SockAddr::new(storage, len) }
    }

    #[cfg(test)]
    fn finish_checksum(sum: u32) -> u16 {
        let mut sum = (sum & 0xffff) + (sum >> 16);
        sum = (sum & 0xffff) + (sum >> 16);
        !(sum as u16)
    }

    fn spawn_receiver(
        socket: Arc<TraceSocket>,
        target: IpAddr,
        tcp_seed: u32,
        tx: mpsc::Sender<Reply>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut icmp_data = [0u8; 65535];
            #[cfg(not(windows))]
            let mut tcp_data = [0u8; 65535];
            loop {
                #[cfg(target_os = "linux")]
                let received = if socket.protocol == TraceProtocol::Udp {
                    socket.recv_error(&mut icmp_data).await.map(
                        |(from, size, kind, code, destination)| {
                            (
                                size,
                                from,
                                icmp_data[..size].to_vec(),
                                Some((kind, code)),
                                destination,
                            )
                        },
                    )
                } else if socket.tcp_recv.is_some() {
                    tokio::select! {
                        result = socket.recv(&mut icmp_data) => result.map(|(size, from)| (size, from, icmp_data[..size].to_vec(), None::<(u8, u8)>, None::<SocketAddr>)),
                        result = socket.recv_tcp(&mut tcp_data) => result.map(|(size, from)| (size, from, tcp_data[..size].to_vec(), None::<(u8, u8)>, None::<SocketAddr>)),
                    }
                } else {
                    socket.recv(&mut icmp_data).await.map(|(size, from)| {
                        (
                            size,
                            from,
                            icmp_data[..size].to_vec(),
                            None::<(u8, u8)>,
                            None::<SocketAddr>,
                        )
                    })
                };
                #[cfg(all(not(target_os = "linux"), not(windows)))]
                let received = if socket.tcp_recv.is_some() {
                    tokio::select! {
                        result = socket.recv(&mut icmp_data) => result.map(|(size, from)| (size, from, icmp_data[..size].to_vec(), None::<(u8, u8)>, None::<SocketAddr>)),
                        result = socket.recv_tcp(&mut tcp_data) => result.map(|(size, from)| (size, from, tcp_data[..size].to_vec(), None::<(u8, u8)>, None::<SocketAddr>)),
                    }
                } else {
                    socket.recv(&mut icmp_data).await.map(|(size, from)| {
                        (
                            size,
                            from,
                            icmp_data[..size].to_vec(),
                            None::<(u8, u8)>,
                            None::<SocketAddr>,
                        )
                    })
                };
                #[cfg(windows)]
                let received = socket.recv(&mut icmp_data).await.map(|(size, from)| {
                    (
                        size,
                        from,
                        icmp_data[..size].to_vec(),
                        None::<(u8, u8)>,
                        None::<SocketAddr>,
                    )
                });
                match received {
                    Ok((_, from, data, _error, _destination)) => {
                        let received_at = Instant::now();
                        #[cfg(target_os = "linux")]
                        let reply = if let Some((kind, code)) = _error {
                            parse_udp_error(
                                &data,
                                trace_ident(),
                                ErrorQueueReply {
                                    from,
                                    kind,
                                    code,
                                    destination: _destination,
                                },
                                target,
                            )
                        } else {
                            parse_reply(
                                &data,
                                from,
                                target,
                                socket.protocol,
                                socket.trace_port,
                                tcp_seed,
                                received_at,
                            )
                        };
                        #[cfg(not(target_os = "linux"))]
                        let reply = parse_reply(
                            &data,
                            from,
                            target,
                            socket.protocol,
                            socket.trace_port,
                            tcp_seed,
                            received_at,
                        );
                        if socket.protocol == TraceProtocol::Tcp
                            && from == target
                            && let Some((source_port, sequence)) =
                                tcp_reset_fields(&data, target, socket.trace_port, tcp_seed)
                        {
                            let _ = socket
                                .send_tcp_reset(target, source_port, socket.trace_port, sequence)
                                .await;
                        }
                        if let Some(reply) = reply
                            && tx.send(reply).await.is_err()
                        {
                            break;
                        }
                    }
                    Err(e) => {
                        eprintln!("pingx: traceroute receive error: {}", e);
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                }
            }
        })
    }

    fn collect_rows(probes: HashMap<u16, Probe>, max_ttl: u8) -> Vec<Row> {
        let mut rows = Vec::new();
        for ttl in 1..=max_ttl {
            let hop: Vec<_> = probes
                .values()
                .filter(|p| p.ttl == ttl && !p.cancelled)
                .collect();
            let mut grouped = BTreeMap::<IpAddr, (Vec<Duration>, Option<u8>)>::new();
            for probe in &hop {
                if let Some((ip, rtt, kind)) = probe.reply {
                    let node = grouped.entry(ip).or_default();
                    node.0.push(rtt);
                    if let ReplyKind::Unreachable(code) = kind {
                        node.1 = Some(code);
                    }
                }
            }
            let nodes = grouped
                .into_iter()
                .map(|(ip, (mut rtts, error))| {
                    rtts.sort_unstable();
                    Node { ip, rtts, error }
                })
                .collect();
            rows.push(Row { ttl, nodes });
        }
        rows
    }

    fn reply_rtt(started: Instant, reply: Reply) -> Duration {
        reply.received_at.saturating_duration_since(started)
    }

    fn location_for(geo: Option<&GeoIpManager>, ip: IpAddr) -> String {
        if is_internal_ip(ip) {
            return "Internal node".to_string();
        }
        geo.and_then(|geo| geo.lookup(ip))
            .map(|record| {
                [record.city, record.region, record.country]
                    .into_iter()
                    .filter(|part| !part.is_empty() && part != "-")
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .filter(|location| !location.is_empty())
            .unwrap_or_else(|| "-".to_string())
    }

    fn is_internal_ip(ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ip) => {
                let [a, b, ..] = ip.octets();
                ip.is_private()
                    || ip.is_loopback()
                    || ip.is_link_local()
                    || a == 0
                    || (a == 172 && (16..=31).contains(&b))
            }
            IpAddr::V6(ip) => {
                let [first, ..] = ip.segments();
                ip.is_loopback()
                    || ip.is_unspecified()
                    || (first & 0xfe00) == 0xfc00
                    || (first & 0xffc0) == 0xfe80
            }
        }
    }

    fn parse_reply(
        data: &[u8],
        from: IpAddr,
        target: IpAddr,
        protocol: TraceProtocol,
        trace_port: u16,
        tcp_seed: u32,
        received_at: Instant,
    ) -> Option<Reply> {
        match protocol {
            TraceProtocol::Icmp if target.is_ipv6() => {
                parse_reply_v6(data, from, target, received_at)
            }
            TraceProtocol::Icmp => parse_reply_v4(data, from, target, received_at),
            TraceProtocol::Udp => {
                if target.is_ipv4() {
                    parse_icmp_probe_reply_v4(
                        data,
                        from,
                        target,
                        17,
                        trace_port,
                        tcp_seed,
                        received_at,
                    )
                } else {
                    parse_icmp_probe_reply_v6(
                        data,
                        from,
                        target,
                        17,
                        trace_port,
                        tcp_seed,
                        received_at,
                    )
                }
            }
            TraceProtocol::Tcp if target.is_ipv6() => {
                parse_tcp_reply_v6(data, from, target, trace_port, tcp_seed, received_at)
            }
            TraceProtocol::Tcp => {
                parse_tcp_reply_v4(data, from, target, trace_port, tcp_seed, received_at)
            }
        }
    }

    fn parse_reply_v4(
        data: &[u8],
        from: IpAddr,
        target: IpAddr,
        received_at: Instant,
    ) -> Option<Reply> {
        let (icmp, icmp_offset) = strip_ipv4(data)?;
        const IPPROTO_ICMP: u8 = 1;
        if icmp_offset > 0 && data[9] != IPPROTO_ICMP {
            return None;
        }
        let packet = IcmpPacket::decode(icmp).ok()?;
        let kind = match packet.message_type {
            0 if from == target => ReplyKind::Reached,
            ICMP_TIME_EXCEEDED_V4 => ReplyKind::Hop,
            ICMP_DEST_UNREACH_V4 => ReplyKind::Unreachable(packet.code),
            _ => return None,
        };
        let sequence = if kind == ReplyKind::Reached {
            if packet.identifier != trace_ident() {
                return None;
            }
            packet.sequence
        } else {
            embedded_sequence_v4(icmp, target)?
        };
        Some(Reply {
            sequence,
            token: if kind == ReplyKind::Hop {
                embedded_token_v4(icmp)?
            } else {
                packet.identifier
            },
            destination: None,
            ip: from,
            kind,
            received_at,
        })
    }

    fn parse_reply_v6(
        data: &[u8],
        from: IpAddr,
        target: IpAddr,
        received_at: Instant,
    ) -> Option<Reply> {
        let packet = IcmpPacket::decode(strip_ipv6_icmp(data)?).ok()?;
        let kind = match packet.message_type {
            129 if from == target => ReplyKind::Reached,
            ICMP_TIME_EXCEEDED_V6 => ReplyKind::Hop,
            ICMP_DEST_UNREACH_V6 => ReplyKind::Unreachable(packet.code),
            _ => return None,
        };
        let sequence = if kind == ReplyKind::Reached {
            if packet.identifier != trace_ident() {
                return None;
            }
            packet.sequence
        } else {
            embedded_sequence_v6(&packet.payload, target)?
        };
        Some(Reply {
            sequence,
            token: packet.identifier,
            destination: None,
            ip: from,
            kind,
            received_at,
        })
    }

    fn strip_ipv4(data: &[u8]) -> Option<(&[u8], usize)> {
        if data.len() >= 20 && data[0] >> 4 == 4 {
            let ihl = (data[0] & 0x0f) as usize * 4;
            return (ihl >= 20 && data.len() >= ihl).then_some((&data[ihl..], ihl));
        }
        // Some raw/DGRAM ICMP reads omit the outer IPv4 header.
        (data.len() >= 8 && matches!(data[0], 0 | ICMP_TIME_EXCEEDED_V4 | ICMP_DEST_UNREACH_V4))
            .then_some((data, 0))
    }

    fn strip_ipv6_icmp(data: &[u8]) -> Option<&[u8]> {
        if data.len() >= 40 && data[0] >> 4 == 6 {
            data.get(ipv6_transport_offset(data, 58)?..)
        } else {
            Some(data)
        }
    }

    fn embedded_token_v4(icmp: &[u8]) -> Option<u16> {
        if icmp.len() < 8 + 20 {
            return None;
        }
        let embedded = &icmp[8..];
        let (inner, _) = strip_ipv4(embedded)?;
        match embedded[9] {
            1 => inner
                .get(4..6)
                .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]])),
            17 | 6 => inner
                .get(0..2)
                .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]])),
            _ => None,
        }
    }

    fn parse_tcp_reply_v4(
        data: &[u8],
        from: IpAddr,
        target: IpAddr,
        trace_port: u16,
        tcp_seed: u32,
        received_at: Instant,
    ) -> Option<Reply> {
        let tcp = match data {
            [first, ..] if first >> 4 == 4 && data.get(9) == Some(&6) => {
                let target = match target {
                    IpAddr::V4(target) => target.octets(),
                    IpAddr::V6(_) => return None,
                };
                if data.get(12..16) == Some(target.as_slice()) {
                    let offset = usize::from(data[0] & 0x0f) * 4;
                    data.get(offset..)?
                } else {
                    data
                }
            }
            _ => data,
        };
        if tcp.len() >= 20 && from == target {
            let local_port = u16::from_be_bytes([tcp[2], tcp[3]]);
            let acknowledgement = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);
            if u16::from_be_bytes([tcp[0], tcp[1]]) == trace_port
                && tcp[13] & TCP_ACK != 0
                && (tcp[13] & TCP_RST != 0 || tcp[13] & TCP_SYN != 0)
                && acknowledgement == tcp_probe_sequence(tcp_seed, local_port).wrapping_add(1)
            {
                return Some(Reply {
                    sequence: 0,
                    token: local_port,
                    destination: None,
                    ip: from,
                    kind: ReplyKind::Reached,
                    received_at,
                });
            }
        }
        parse_icmp_probe_reply_v4(data, from, target, 6, trace_port, tcp_seed, received_at)
    }

    fn tcp_reset_fields(
        data: &[u8],
        target: IpAddr,
        target_port: u16,
        tcp_seed: u32,
    ) -> Option<(u16, u32)> {
        let tcp = match (target, data.first().map(|byte| byte >> 4)) {
            (IpAddr::V4(target), Some(4))
                if data.get(9) == Some(&6)
                    && data.get(12..16) == Some(target.octets().as_slice()) =>
            {
                let offset = usize::from(data[0] & 0x0f) * 4;
                data.get(offset..)?
            }
            (IpAddr::V6(target), Some(6))
                if data.get(8..24) == Some(target.octets().as_slice()) =>
            {
                data.get(ipv6_transport_offset(data, 6)?..)?
            }
            _ => data,
        };
        if tcp.len() < 20
            || u16::from_be_bytes([tcp[0], tcp[1]]) != target_port
            || tcp[13] & (TCP_SYN | TCP_ACK) != (TCP_SYN | TCP_ACK)
        {
            return None;
        }
        let local_port = u16::from_be_bytes([tcp[2], tcp[3]]);
        let acknowledgement = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);
        (acknowledgement == tcp_probe_sequence(tcp_seed, local_port).wrapping_add(1))
            .then_some((local_port, acknowledgement))
    }

    fn parse_tcp_reply_v6(
        data: &[u8],
        from: IpAddr,
        target: IpAddr,
        trace_port: u16,
        tcp_seed: u32,
        received_at: Instant,
    ) -> Option<Reply> {
        let tcp = match (target, data.first().map(|byte| byte >> 4)) {
            (IpAddr::V6(target), Some(6))
                if data.get(8..24) == Some(target.octets().as_slice()) =>
            {
                data.get(ipv6_transport_offset(data, 6)?..).unwrap_or(data)
            }
            _ => data,
        };
        if tcp.len() >= 20 && from == target {
            let local_port = u16::from_be_bytes([tcp[2], tcp[3]]);
            let acknowledgement = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);
            if u16::from_be_bytes([tcp[0], tcp[1]]) == trace_port
                && tcp[13] & TCP_ACK != 0
                && (tcp[13] & TCP_RST != 0 || tcp[13] & TCP_SYN != 0)
                && acknowledgement == tcp_probe_sequence(tcp_seed, local_port).wrapping_add(1)
            {
                return Some(Reply {
                    sequence: 0,
                    token: local_port,
                    destination: None,
                    ip: from,
                    kind: ReplyKind::Reached,
                    received_at,
                });
            }
        }
        parse_icmp_probe_reply_v6(data, from, target, 6, trace_port, tcp_seed, received_at)
    }

    fn parse_icmp_probe_reply_v4(
        data: &[u8],
        from: IpAddr,
        target: IpAddr,
        protocol: u8,
        trace_port: u16,
        tcp_seed: u32,
        received_at: Instant,
    ) -> Option<Reply> {
        let (icmp, offset) = strip_ipv4(data)?;
        if offset > 0 && data[9] != 1 {
            return None;
        }
        if icmp.len() < 8 + 20 || !matches!(icmp[0], ICMP_TIME_EXCEEDED_V4 | ICMP_DEST_UNREACH_V4) {
            return None;
        }
        let embedded = &icmp[8..];
        let IpAddr::V4(target_ip) = target else {
            return None;
        };
        if embedded[9] != protocol || embedded[16..20] != target_ip.octets() {
            return None;
        }
        let inner_ihl = (embedded[0] & 0x0f) as usize * 4;
        let inner_total = u16::from_be_bytes([embedded[2], embedded[3]]) as usize;
        let inner_minimum = inner_ihl + if protocol == 6 { 20 } else { 8 };
        if embedded[0] >> 4 != 4
            || inner_ihl < 20
            || inner_total < inner_minimum
            || embedded.len() < inner_ihl + 8
        {
            return None;
        }
        let l4 = &embedded[inner_ihl..];
        let token = match protocol {
            17 if u16::from_be_bytes([l4[2], l4[3]]) >= trace_port => {
                u16::from_be_bytes([l4[2], l4[3]])
            }
            6 if u16::from_be_bytes([l4[2], l4[3]]) == trace_port => {
                u16::from_be_bytes([l4[0], l4[1]])
            }
            _ => return None,
        };
        if protocol == 6
            && u32::from_be_bytes([l4[4], l4[5], l4[6], l4[7]])
                != tcp_probe_sequence(tcp_seed, token)
        {
            return None;
        }
        let kind = match icmp[0] {
            ICMP_TIME_EXCEEDED_V4 if icmp[1] == 0 => ReplyKind::Hop,
            ICMP_DEST_UNREACH_V4 if from == target && protocol == 17 && icmp[1] == 3 => {
                ReplyKind::Reached
            }
            ICMP_DEST_UNREACH_V4 => ReplyKind::Unreachable(icmp[1]),
            _ => return None,
        };
        Some(Reply {
            sequence: 0,
            token,
            destination: None,
            ip: from,
            kind,
            received_at,
        })
    }

    fn parse_icmp_probe_reply_v6(
        data: &[u8],
        from: IpAddr,
        target: IpAddr,
        protocol: u8,
        trace_port: u16,
        tcp_seed: u32,
        received_at: Instant,
    ) -> Option<Reply> {
        let packet = IcmpPacket::decode(strip_ipv6_icmp(data)?).ok()?;
        if !matches!(
            packet.message_type,
            ICMP_TIME_EXCEEDED_V6 | ICMP_DEST_UNREACH_V6
        ) {
            return None;
        }
        let embedded = &packet.payload;
        let l4_offset = ipv6_transport_offset(embedded, protocol)?;
        let IpAddr::V6(target_ip) = target else {
            return None;
        };
        if embedded[24..40] != target_ip.octets() {
            return None;
        }
        let l4 = &embedded[l4_offset..];
        if l4.len() < 8 {
            return None;
        }
        let source_port = u16::from_be_bytes([l4[0], l4[1]]);
        let destination_port = u16::from_be_bytes([l4[2], l4[3]]);
        let token = match protocol {
            6 if destination_port == trace_port => source_port,
            17 if destination_port >= trace_port => destination_port,
            _ => return None,
        };
        if protocol == 6
            && u32::from_be_bytes([l4[4], l4[5], l4[6], l4[7]])
                != tcp_probe_sequence(tcp_seed, token)
        {
            return None;
        }
        Some(Reply {
            sequence: 0,
            token,
            destination: None,
            ip: from,
            kind: if packet.message_type == ICMP_TIME_EXCEEDED_V6 && packet.code == 0 {
                ReplyKind::Hop
            } else if packet.message_type == ICMP_TIME_EXCEEDED_V6 {
                return None;
            } else if from == target && packet.code == 4 {
                ReplyKind::Reached
            } else {
                ReplyKind::Unreachable(packet.code)
            },
            received_at,
        })
    }

    #[cfg(target_os = "linux")]
    fn parse_udp_error(
        data: &[u8],
        ident: u16,
        error: ErrorQueueReply,
        target: IpAddr,
    ) -> Option<Reply> {
        let destination = error.destination?;
        let expected = match (destination, target) {
            (SocketAddr::V4(destination), IpAddr::V4(target)) => destination.ip() == &target,
            (SocketAddr::V6(destination), IpAddr::V6(target)) => destination.ip() == &target,
            _ => false,
        };
        if !expected || destination.port() == 0 {
            return None;
        }
        let marker = udp_probe_marker(ident, destination.port());
        let quoted = data.len().min(marker.len());
        // Routers may quote only the UDP header, leaving no payload in the error queue.
        if data[..quoted] != marker[..quoted] {
            return None;
        }
        Some(Reply {
            sequence: 0,
            token: destination.port(),
            destination: Some(destination),
            ip: error.from,
            kind: match (target.is_ipv4(), error.kind, error.code) {
                (true, ICMP_TIME_EXCEEDED_V4, 0) | (false, ICMP_TIME_EXCEEDED_V6, 0) => {
                    ReplyKind::Hop
                }
                (true, ICMP_DEST_UNREACH_V4, 3) | (false, ICMP_DEST_UNREACH_V6, 4)
                    if error.from == target =>
                {
                    ReplyKind::Reached
                }
                (true, ICMP_DEST_UNREACH_V4, code) | (false, ICMP_DEST_UNREACH_V6, code) => {
                    ReplyKind::Unreachable(code)
                }
                _ => return None,
            },
            received_at: Instant::now(),
        })
    }

    fn embedded_sequence_v4(icmp: &[u8], target: IpAddr) -> Option<u16> {
        let IpAddr::V4(target) = target else {
            return None;
        };
        if icmp.len() < 8 + 20 {
            return None;
        }
        let embedded = &icmp[8..];
        let (inner, _) = strip_ipv4(embedded)?;
        if inner.len() < 8
            || inner[0] != 8
            || inner[4..6] != trace_ident().to_be_bytes()
            || embedded[16..20] != target.octets()
        {
            return None;
        }
        Some(u16::from_be_bytes([inner[6], inner[7]]))
    }

    fn embedded_sequence_v6(payload: &[u8], target: IpAddr) -> Option<u16> {
        let IpAddr::V6(target) = target else {
            return None;
        };
        let offset = ipv6_transport_offset(payload, 58)?;
        (offset + 8 <= payload.len()
            && payload[24..40] == target.octets()
            && payload[offset] == 128
            && payload[offset + 4..offset + 6] == trace_ident().to_be_bytes())
        .then(|| u16::from_be_bytes([payload[offset + 6], payload[offset + 7]]))
    }

    fn ipv6_transport_offset(payload: &[u8], protocol: u8) -> Option<usize> {
        if payload.len() < 40 || payload[0] >> 4 != 6 {
            return None;
        }
        let declared = 40 + usize::from(u16::from_be_bytes([payload[4], payload[5]]));
        if declared < 48 {
            return None;
        }
        let mut offset = 40usize;
        let mut next_header = payload[6];
        loop {
            if offset + 8 > payload.len() {
                return None;
            }
            let next = match next_header {
                0 | 43 | 60 => {
                    next_header = payload[offset];
                    (payload[offset + 1] as usize + 1) * 8
                }
                44 => {
                    if u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]) & 0xfff8 != 0
                    {
                        return None;
                    }
                    next_header = payload[offset];
                    8
                }
                51 => {
                    next_header = payload[offset];
                    (payload[offset + 1] as usize + 2) * 4
                }
                _ => break,
            };
            offset = offset.checked_add(next)?;
        }
        (next_header == protocol).then_some(offset)
    }

    async fn render(rows: &[Row]) {
        let geo = match GeoIpManager::new() {
            Ok(manager) => Some(manager),
            Err(e) => {
                eprintln!("pingx: GeoIP unavailable: {}", e);
                None
            }
        };
        if geo.as_ref().is_none_or(|geo| !geo.has_databases()) {
            eprintln!(
                "pingx: GeoIP database is unavailable; locations are shown as '-'. Run `pingx --fetch-geo` to configure it."
            );
        }
        println!("{}", render_rows(rows, geo.as_ref()));
    }

    #[cfg(target_os = "macos")]
    pub(super) async fn render_trace_data(data: &str) -> Result<String> {
        let data: TraceData = serde_json::from_str(data)?;
        let rows = data.clone().into_rows();
        let geo = match GeoIpManager::new() {
            Ok(manager) => Some(manager),
            Err(error) => {
                eprintln!("pingx: GeoIP unavailable: {error}");
                None
            }
        };
        if geo.as_ref().is_none_or(|geo| !geo.has_databases()) {
            eprintln!(
                "pingx: GeoIP database is unavailable; locations are shown as '-'. Run `pingx --fetch-geo` to configure it."
            );
        }
        Ok(format!(
            "{}\n{}",
            styled_trace_header(&data.target_name, data.target, data.max_hops, data.size),
            render_rows(&rows, geo.as_ref())
        ))
    }

    fn render_rows(rows: &[Row], geo: Option<&GeoIpManager>) -> String {
        let mut cells = Vec::with_capacity(rows.len());
        for row in rows {
            if row.nodes.is_empty() {
                cells.push((
                    row.ttl.to_string(),
                    "*".to_string(),
                    "-".to_string(),
                    "*".to_string(),
                ));
                continue;
            }
            for (index, node) in row.nodes.iter().enumerate() {
                let location = location_for(geo, node.ip);
                let avg = node.rtts.iter().sum::<Duration>() / node.rtts.len() as u32;
                let error = node
                    .error
                    .map(|code| format!(" (error {})", code))
                    .unwrap_or_default();
                let rtt = format!("{:.3} ms{}", avg.as_secs_f64() * 1000.0, error);
                cells.push((
                    if index == 0 {
                        row.ttl.to_string()
                    } else {
                        String::new()
                    },
                    node.ip.to_string(),
                    location,
                    rtt,
                ));
            }
        }
        render_table(&cells)
    }

    fn render_table(cells: &[(String, String, String, String)]) -> String {
        let cells: Vec<_> = cells
            .iter()
            .map(|(hop, ip, location, rtt)| {
                (
                    hop.clone(),
                    truncate(ip, IP_MAX_WIDTH),
                    truncate(location, LOCATION_MAX_WIDTH),
                    rtt.clone(),
                )
            })
            .collect();
        let width = |index: usize, fallback: usize| {
            cells
                .iter()
                .map(|cell| match index {
                    0 => UnicodeWidthStr::width(cell.0.as_str()),
                    1 => UnicodeWidthStr::width(cell.1.as_str()),
                    2 => UnicodeWidthStr::width(cell.2.as_str()),
                    _ => UnicodeWidthStr::width(cell.3.as_str()),
                })
                .max()
                .unwrap_or(fallback)
                .max(fallback)
        };
        let widths = [width(0, 3), width(1, 2), width(2, 8), width(3, 3)];
        let header = [
            pad_left("Hop", widths[0]),
            pad_right("IP", widths[1]),
            pad_right("Location", widths[2]),
            pad_left("RTT", widths[3]),
        ];
        let mut lines = vec![
            header
                .each_ref()
                .map(|cell| cell.bold().to_string())
                .join(" | "),
            format!(
                "{}+{}+{}+{}",
                "-".repeat(widths[0] + 1),
                "-".repeat(widths[1] + 2),
                "-".repeat(widths[2] + 2),
                "-".repeat(widths[3] + 2)
            ),
        ];
        for (hop, ip, location, rtt) in &cells {
            lines.push(format!(
                "{} | {} | {} | {}",
                pad_left(hop, widths[0]),
                pad_right(ip, widths[1]),
                pad_right(location, widths[2]),
                pad_left(rtt, widths[3])
            ));
        }
        lines.join("\n")
    }

    fn truncate(value: &str, max_width: usize) -> String {
        if UnicodeWidthStr::width(value) <= max_width {
            return value.to_string();
        }
        let mut result = String::new();
        let target_width = max_width.saturating_sub(1);
        for ch in value.chars() {
            let next_width = UnicodeWidthStr::width(result.as_str()) + char_width(ch);
            if next_width > target_width {
                break;
            }
            result.push(ch);
        }
        result.push('…');
        result
    }

    fn char_width(ch: char) -> usize {
        UnicodeWidthStr::width(ch.to_string().as_str())
    }

    fn pad_right(value: &str, width: usize) -> String {
        format!(
            "{}{}",
            value,
            " ".repeat(width.saturating_sub(UnicodeWidthStr::width(value)))
        )
    }

    fn pad_left(value: &str, width: usize) -> String {
        format!(
            "{}{}",
            " ".repeat(width.saturating_sub(UnicodeWidthStr::width(value))),
            value
        )
    }

    fn trace_ident() -> u16 {
        (std::process::id() as u16) ^ IDENTIFIER
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use clap::Parser;
        use std::net::{Ipv4Addr, Ipv6Addr};
        use std::sync::Mutex;
        use tokio::sync::mpsc;

        const TCP_SEED: u32 = 0x1234_5678;

        #[derive(Default)]
        struct TestSender {
            ttl_log: Mutex<Vec<u8>>,
        }

        impl TestSender {
            fn sent_ttls(&self) -> Vec<u8> {
                self.ttl_log.lock().unwrap().clone()
            }
        }

        #[async_trait]
        impl ProbeSender for TestSender {
            async fn send_probe(
                &self,
                _probe: ProbePacket,
                _target: IpAddr,
                ttl: u8,
            ) -> io::Result<()> {
                self.ttl_log.lock().unwrap().push(ttl);
                Ok(())
            }
        }

        async fn run_fake_trace(
            sender: &TestSender,
            max_hops: u8,
            timeout: Duration,
            replies: Vec<Reply>,
            reply_delay: Duration,
        ) -> Result<ProbeRun> {
            let (tx, mut rx) = mpsc::channel(128);
            tokio::spawn(async move {
                tokio::time::sleep(reply_delay).await;
                for reply in replies {
                    let _ = tx.send(reply).await;
                }
            });
            run_probes(
                sender,
                ProbeRequest {
                    target: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    local: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    ident: trace_ident(),
                    tcp_seed: TCP_SEED,
                    protocol: TraceProtocol::Icmp,
                    base_port: 33434,
                    payload_size: 12,
                    max_hops,
                    timeout,
                },
                &mut rx,
            )
            .await
        }

        fn ipv4_packet(src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
            let mut data = vec![0u8; 20];
            data[0] = 0x45;
            data[2..4].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
            data[8] = 64;
            data[9] = 1;
            data[12..16].copy_from_slice(&src.octets());
            data[16..20].copy_from_slice(&dst.octets());
            data.extend_from_slice(payload);
            data
        }

        fn tcp_control_packet(
            src: Ipv4Addr,
            dst: Ipv4Addr,
            source: u16,
            destination: u16,
            flags: u8,
            sequence: u32,
        ) -> Vec<u8> {
            let mut packet = vec![0u8; 40];
            packet[0] = 0x45;
            packet[2..4].copy_from_slice(&40u16.to_be_bytes());
            packet[8] = 64;
            packet[9] = 6;
            packet[12..16].copy_from_slice(&src.octets());
            packet[16..20].copy_from_slice(&dst.octets());
            packet[20..22].copy_from_slice(&source.to_be_bytes());
            packet[22..24].copy_from_slice(&destination.to_be_bytes());
            if flags & 0x10 != 0 {
                packet[28..32].copy_from_slice(&(sequence.wrapping_add(1)).to_be_bytes());
            }
            packet[32] = 0x50;
            packet[33] = flags;
            packet
        }

        fn ipv6_tcp_control_packet(
            src: Ipv6Addr,
            dst: Ipv6Addr,
            source: u16,
            destination: u16,
            flags: u8,
            sequence: u32,
        ) -> Vec<u8> {
            let mut packet = vec![0u8; 60];
            packet[0] = 0x60;
            packet[4..6].copy_from_slice(&20u16.to_be_bytes());
            packet[6] = 6;
            packet[7] = 64;
            packet[8..24].copy_from_slice(&src.octets());
            packet[24..40].copy_from_slice(&dst.octets());
            packet[40..42].copy_from_slice(&source.to_be_bytes());
            packet[42..44].copy_from_slice(&destination.to_be_bytes());
            if flags & 0x10 != 0 {
                packet[48..52].copy_from_slice(&(sequence.wrapping_add(1)).to_be_bytes());
            }
            packet[52] = 0x50;
            packet[53] = flags;
            packet
        }

        fn ipv4_transport_packet(
            src: Ipv4Addr,
            dst: Ipv4Addr,
            protocol: u8,
            payload: &[u8],
        ) -> Vec<u8> {
            let mut packet = ipv4_packet(src, dst, payload);
            packet[9] = protocol;
            packet
        }

        fn icmp_error(icmp_type: u8, code: u8, embedded: &[u8]) -> Vec<u8> {
            let mut packet = vec![icmp_type, code, 0, 0, 0, 0, 0, 0];
            packet.extend(embedded);
            packet
        }

        fn udp_header(source: u16, destination: u16) -> [u8; 8] {
            let mut udp = [0u8; 8];
            udp[0..2].copy_from_slice(&source.to_be_bytes());
            udp[2..4].copy_from_slice(&destination.to_be_bytes());
            udp[4..6].copy_from_slice(&8u16.to_be_bytes());
            udp
        }

        #[cfg(target_os = "linux")]
        #[tokio::test]
        async fn udp_error_queue_reaches_closed_loopback_port_without_raw_socket() {
            let target = IpAddr::V4(Ipv4Addr::LOCALHOST);
            let reserve = std::net::UdpSocket::bind(SocketAddr::new(target, 0)).unwrap();
            let base_port = reserve.local_addr().unwrap().port().min(65533);
            drop(reserve);
            let socket =
                Arc::new(TraceSocket::new(target, target, TraceProtocol::Udp, base_port).unwrap());
            let (tx, mut rx) = mpsc::channel(8);
            let receiver = spawn_receiver(socket.clone(), target, TCP_SEED, tx);
            let result = run_probes(
                socket.as_ref(),
                ProbeRequest {
                    target,
                    local: target,
                    ident: trace_ident(),
                    tcp_seed: TCP_SEED,
                    protocol: TraceProtocol::Udp,
                    base_port,
                    payload_size: 4,
                    max_hops: 1,
                    timeout: Duration::from_secs(1),
                },
                &mut rx,
            )
            .await;
            receiver.abort();
            assert_eq!(result.unwrap().stop_hop, Some(1));
        }

        #[cfg(target_os = "linux")]
        #[test]
        fn correlates_udp_error_queue_payload_and_destination() {
            let target = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
            let destination = SocketAddr::new(target, 33442);
            let ident = trace_ident();
            let marker = udp_probe_marker(ident, 33442);
            let reply = parse_udp_error(
                &marker,
                ident,
                ErrorQueueReply {
                    from: target,
                    kind: ICMP_TIME_EXCEEDED_V4,
                    code: 0,
                    destination: Some(destination),
                },
                target,
            )
            .unwrap();
            assert_eq!(reply.token, 33442);
            assert_eq!(reply.destination, Some(destination));
            for (data, kind, code, expected) in [
                (&[][..], ICMP_TIME_EXCEEDED_V4, 0, ReplyKind::Hop),
                (&marker[..], ICMP_DEST_UNREACH_V4, 3, ReplyKind::Reached),
                (
                    &marker[..],
                    ICMP_DEST_UNREACH_V4,
                    13,
                    ReplyKind::Unreachable(13),
                ),
            ] {
                assert_eq!(
                    parse_udp_error(
                        data,
                        ident,
                        ErrorQueueReply {
                            from: target,
                            kind,
                            code,
                            destination: Some(destination),
                        },
                        target
                    )
                    .unwrap()
                    .kind,
                    expected
                );
            }

            assert!(
                parse_udp_error(
                    &marker,
                    ident ^ 1,
                    ErrorQueueReply {
                        from: target,
                        kind: ICMP_TIME_EXCEEDED_V4,
                        code: 0,
                        destination: Some(destination),
                    },
                    target,
                )
                .is_none()
            );
            assert!(
                parse_udp_error(
                    &marker,
                    ident,
                    ErrorQueueReply {
                        from: target,
                        kind: ICMP_TIME_EXCEEDED_V4,
                        code: 0,
                        destination: Some(SocketAddr::new(target, 33443)),
                    },
                    target,
                )
                .is_none()
            );
        }

        fn tcp_header(source: u16, destination: u16, flags: u8, sequence: u32) -> [u8; 20] {
            let mut tcp = [0u8; 20];
            tcp[0..2].copy_from_slice(&source.to_be_bytes());
            tcp[2..4].copy_from_slice(&destination.to_be_bytes());
            tcp[4..8].copy_from_slice(&sequence.to_be_bytes());
            tcp[12] = 0x50;
            tcp[13] = flags;
            tcp
        }

        #[test]
        fn parses_udp_reachability_and_rejects_wrong_ports() {
            let hop = Ipv4Addr::new(192, 0, 2, 1);
            let target = Ipv4Addr::new(198, 51, 100, 1);
            let embedded_hop = ipv4_transport_packet(hop, target, 17, &udp_header(49000, 33442));
            let embedded_target =
                ipv4_transport_packet(target, target, 17, &udp_header(49000, 33442));
            let packet = ipv4_packet(
                hop,
                Ipv4Addr::LOCALHOST,
                &icmp_error(ICMP_TIME_EXCEEDED_V4, 0, &embedded_hop),
            );
            let reply = parse_reply(
                &packet,
                IpAddr::V4(hop),
                IpAddr::V4(target),
                TraceProtocol::Udp,
                33442,
                TCP_SEED,
                Instant::now(),
            )
            .unwrap();
            assert_eq!(reply.token, 33442);
            assert_eq!(reply.kind, ReplyKind::Hop);
            assert!(
                parse_reply(
                    &packet,
                    IpAddr::V4(hop),
                    IpAddr::V4(target),
                    TraceProtocol::Udp,
                    33443,
                    TCP_SEED,
                    Instant::now(),
                )
                .is_none()
            );

            let packet = ipv4_packet(
                target,
                Ipv4Addr::LOCALHOST,
                &icmp_error(ICMP_DEST_UNREACH_V4, 3, &embedded_target),
            );
            let reply = parse_reply(
                &packet,
                IpAddr::V4(target),
                IpAddr::V4(target),
                TraceProtocol::Udp,
                33442,
                TCP_SEED,
                Instant::now(),
            )
            .unwrap();
            assert_eq!(reply.kind, ReplyKind::Reached);
        }

        #[test]
        fn parses_tcp_icmp_and_control_replies_using_source_port() {
            let hop = Ipv4Addr::new(192, 0, 2, 1);
            let target = Ipv4Addr::new(198, 51, 100, 1);
            let source_port = 33442;
            let target_port = 443;
            let sequence = tcp_probe_sequence(TCP_SEED, source_port);
            let embedded = ipv4_transport_packet(
                hop,
                target,
                6,
                &tcp_header(source_port, target_port, 0x02, sequence),
            );
            let packet = ipv4_packet(
                hop,
                Ipv4Addr::LOCALHOST,
                &icmp_error(ICMP_TIME_EXCEEDED_V4, 0, &embedded),
            );
            let reply = parse_reply(
                &packet,
                IpAddr::V4(hop),
                IpAddr::V4(target),
                TraceProtocol::Tcp,
                target_port,
                TCP_SEED,
                Instant::now(),
            )
            .unwrap();
            assert_eq!(reply.token, source_port);
            assert_eq!(reply.kind, ReplyKind::Hop);
            let mut quoted = embedded.clone();
            quoted.truncate(28);
            let short = ipv4_packet(
                hop,
                Ipv4Addr::LOCALHOST,
                &icmp_error(ICMP_TIME_EXCEEDED_V4, 0, &quoted),
            );
            assert_eq!(
                parse_reply(
                    &short,
                    IpAddr::V4(hop),
                    IpAddr::V4(target),
                    TraceProtocol::Tcp,
                    target_port,
                    TCP_SEED,
                    Instant::now()
                )
                .unwrap()
                .token,
                source_port
            );

            for flags in [0x14, 0x12] {
                let packet = tcp_control_packet(
                    target,
                    Ipv4Addr::LOCALHOST,
                    target_port,
                    source_port,
                    flags,
                    sequence,
                );
                let reply = parse_reply(
                    &packet,
                    IpAddr::V4(target),
                    IpAddr::V4(target),
                    TraceProtocol::Tcp,
                    target_port,
                    TCP_SEED,
                    Instant::now(),
                )
                .expect("parse TCP control reply");
                assert_eq!(reply.token, source_port);
                assert_eq!(reply.kind, ReplyKind::Reached);
            }

            let syn_ack = tcp_control_packet(
                target,
                Ipv4Addr::LOCALHOST,
                target_port,
                source_port,
                0x12,
                sequence,
            );
            assert_eq!(
                tcp_reset_fields(&syn_ack, IpAddr::V4(target), target_port, TCP_SEED),
                Some((source_port, sequence.wrapping_add(1)))
            );
            let mut wrong_ack = syn_ack.clone();
            wrong_ack[28..32].copy_from_slice(&1u32.to_be_bytes());
            assert!(
                parse_reply(
                    &wrong_ack,
                    IpAddr::V4(target),
                    IpAddr::V4(target),
                    TraceProtocol::Tcp,
                    target_port,
                    TCP_SEED,
                    Instant::now(),
                )
                .is_none()
            );

            let target_v6 = Ipv6Addr::LOCALHOST;
            let reply = parse_reply(
                &ipv6_tcp_control_packet(
                    target_v6,
                    target_v6,
                    target_port,
                    source_port,
                    0x12,
                    sequence,
                ),
                IpAddr::V6(target_v6),
                IpAddr::V6(target_v6),
                TraceProtocol::Tcp,
                target_port,
                TCP_SEED,
                Instant::now(),
            )
            .expect("parse IPv6 TCP control reply");
            assert_eq!(reply.token, source_port);
            assert_eq!(reply.kind, ReplyKind::Reached);
            let bare = parse_reply(
                &packet[20..],
                IpAddr::V4(target),
                IpAddr::V4(target),
                TraceProtocol::Tcp,
                target_port,
                TCP_SEED,
                Instant::now(),
            )
            .expect("parse bare IPv4 TCP reply");
            assert_eq!(bare.token, source_port);
        }

        #[test]
        fn rejects_icmp_errors_for_other_destinations_and_protocols() {
            let hop = Ipv4Addr::new(192, 0, 2, 1);
            let target = Ipv4Addr::new(198, 51, 100, 1);
            let embedded = ipv4_transport_packet(
                hop,
                target,
                6,
                &tcp_header(33442, 443, 0x02, tcp_probe_sequence(TCP_SEED, 33442)),
            );
            let packet = ipv4_packet(
                hop,
                Ipv4Addr::LOCALHOST,
                &icmp_error(ICMP_TIME_EXCEEDED_V4, 0, &embedded),
            );
            assert!(
                parse_reply(
                    &packet,
                    IpAddr::V4(hop),
                    IpAddr::V4(target),
                    TraceProtocol::Udp,
                    443,
                    TCP_SEED,
                    Instant::now(),
                )
                .is_none()
            );
            assert!(
                parse_reply(
                    &packet,
                    IpAddr::V4(hop),
                    IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
                    TraceProtocol::Tcp,
                    443,
                    TCP_SEED,
                    Instant::now(),
                )
                .is_none()
            );
        }

        #[test]
        fn parses_ipv4_time_exceeded() {
            let received_at = Instant::now();
            let inner = IcmpPacket::new_request(false, trace_ident(), 42, vec![0; 12]).encode();
            let mut icmp = vec![ICMP_TIME_EXCEEDED_V4, 0, 0, 0, 0, 0, 0, 0];
            icmp.extend(ipv4_packet(
                Ipv4Addr::new(192, 0, 2, 1),
                Ipv4Addr::new(198, 51, 100, 1),
                &inner,
            ));
            let packet = ipv4_packet(
                Ipv4Addr::new(203, 0, 113, 1),
                Ipv4Addr::new(192, 0, 2, 1),
                &icmp,
            );
            let reply = parse_reply_v4(
                &packet,
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
                received_at,
            )
            .unwrap();
            assert_eq!(reply.sequence, 42);
            assert_eq!(reply.kind, ReplyKind::Hop);
            assert_eq!(reply.received_at, received_at);
        }

        #[test]
        fn parses_ipv4_icmp_with_out_and_with_ip_header() {
            let target = Ipv4Addr::new(198, 51, 100, 1);
            let inner = IcmpPacket::new_request(false, trace_ident(), 44, vec![0; 12]).encode();
            let mut time_exceeded = vec![ICMP_TIME_EXCEEDED_V4, 0, 0, 0, 0, 0, 0, 0];
            time_exceeded.extend(ipv4_packet(Ipv4Addr::new(192, 0, 2, 1), target, &inner));
            let reply = parse_reply_v4(
                &time_exceeded,
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
                IpAddr::V4(target),
                Instant::now(),
            )
            .unwrap();
            assert_eq!(reply.sequence, 44);
            assert_eq!(reply.kind, ReplyKind::Hop);

            let mut echo = vec![0, 0, 0, 0, 0, 0, 0, 0];
            echo[4..6].copy_from_slice(&trace_ident().to_be_bytes());
            echo[6..8].copy_from_slice(&45u16.to_be_bytes());
            let reply = parse_reply_v4(
                &echo,
                IpAddr::V4(target),
                IpAddr::V4(target),
                Instant::now(),
            )
            .unwrap();
            assert_eq!(reply.sequence, 45);
            assert_eq!(reply.kind, ReplyKind::Reached);
        }

        #[test]
        fn parses_ipv6_with_fragment_header() {
            let received_at = Instant::now();
            let inner = IcmpPacket::new_request(true, trace_ident(), 43, vec![0; 12]).encode();
            let mut embedded = vec![0u8; 48];
            embedded[0] = 0x60;
            embedded[4..6].copy_from_slice(&(8u16 + inner.len() as u16).to_be_bytes());
            embedded[6] = 44;
            embedded[7] = 8;
            embedded[24..40].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
            embedded[40] = 58;
            embedded.extend(inner);
            let mut packet = vec![ICMP_TIME_EXCEEDED_V6, 0, 0, 0, 0, 0, 0, 0];
            packet.extend(embedded);
            let reply = parse_reply_v6(
                &packet,
                IpAddr::V6(Ipv6Addr::LOCALHOST),
                IpAddr::V6(Ipv6Addr::LOCALHOST),
                received_at,
            )
            .unwrap();
            assert_eq!(reply.sequence, 43);
            assert_eq!(reply.kind, ReplyKind::Hop);
        }

        #[test]
        fn parses_ipv6_icmp_with_full_ip_header() {
            let target = "2001:db8::2".parse::<Ipv6Addr>().unwrap();
            let local = "2001:db8::1".parse::<Ipv6Addr>().unwrap();
            let router = "2001:db8::ff".parse::<Ipv6Addr>().unwrap();
            let inner = IcmpPacket::new_request(true, trace_ident(), 46, vec![0; 12]).encode();
            let mut embedded = vec![0u8; 40];
            embedded[0] = 0x60;
            embedded[4..6].copy_from_slice(&(inner.len() as u16).to_be_bytes());
            embedded[6] = 58;
            embedded[7] = 64;
            embedded[8..24].copy_from_slice(&local.octets());
            embedded[24..40].copy_from_slice(&target.octets());
            embedded.extend(inner);
            let mut icmp = vec![ICMP_TIME_EXCEEDED_V6, 0, 0, 0, 0, 0, 0, 0];
            icmp.extend(embedded);
            let mut packet = vec![0u8; 40];
            packet[0] = 0x60;
            packet[4..6].copy_from_slice(&(icmp.len() as u16).to_be_bytes());
            packet[6] = 58;
            packet[7] = 64;
            packet[8..24].copy_from_slice(&router.octets());
            packet[24..40].copy_from_slice(&local.octets());
            packet.extend(icmp);
            let reply = parse_reply_v6(
                &packet,
                IpAddr::V6(router),
                IpAddr::V6(target),
                Instant::now(),
            )
            .unwrap();
            assert_eq!(reply.sequence, 46);
            assert_eq!(reply.kind, ReplyKind::Hop);
        }

        #[test]
        fn rtt_uses_the_receive_timestamp_not_processing_time() {
            let started = Instant::now();
            let received_at = started + Duration::from_millis(7);
            let reply = Reply {
                sequence: 1,
                token: trace_ident(),
                destination: None,
                ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                kind: ReplyKind::Reached,
                received_at,
            };
            assert_eq!(reply_rtt(started, reply), Duration::from_millis(7));
        }

        #[test]
        fn rejects_wrong_target_and_short_packet() {
            assert!(
                parse_reply(
                    &[0; 4],
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                    TraceProtocol::Icmp,
                    33434,
                    TCP_SEED,
                    Instant::now(),
                )
                .is_none()
            );
            assert!(embedded_sequence_v4(&[0; 8], IpAddr::V6(Ipv6Addr::LOCALHOST)).is_none());
        }

        #[cfg(windows)]
        #[test]
        fn windows_trace_filter_matches_icmp_and_the_tcp_tuple() {
            let filter = trace_filter(
                "192.0.2.10".parse().unwrap(),
                "198.51.100.20".parse().unwrap(),
                TraceProtocol::Tcp,
                443,
            )
            .unwrap();
            assert!(filter.contains("icmp.Type == 11"));
            assert!(filter.contains("ip.SrcAddr == 198.51.100.20"));
            assert!(filter.contains("tcp.SrcPort == 443"));
            assert!(filter.contains("ip.DstAddr == 192.0.2.10"));
            assert!(filter.contains("tcp.DstPort != 0"));
            assert!(filter.contains("tcp.SYN and tcp.ACK"));
        }

        #[test]
        fn rejects_wrong_identifier() {
            let inner =
                IcmpPacket::new_request(false, trace_ident().wrapping_add(1), 42, vec![0; 12])
                    .encode();
            let mut icmp = vec![ICMP_TIME_EXCEEDED_V4, 0, 0, 0, 0, 0, 0, 0];
            icmp.extend(ipv4_packet(
                Ipv4Addr::new(192, 0, 2, 1),
                Ipv4Addr::new(198, 51, 100, 1),
                &inner,
            ));
            let packet = ipv4_packet(
                Ipv4Addr::new(203, 0, 113, 1),
                Ipv4Addr::new(192, 0, 2, 1),
                &icmp,
            );
            assert!(
                parse_reply_v4(
                    &packet,
                    IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
                    IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
                    Instant::now(),
                )
                .is_none()
            );
        }

        #[test]
        fn packet_size_uses_ip_total_length() {
            for (ip, minimum) in [
                (IpAddr::V4(Ipv4Addr::LOCALHOST), 32),
                (IpAddr::V6(Ipv6Addr::LOCALHOST), 52),
            ] {
                assert_eq!(
                    packet_size(ip, Some(minimum), TraceProtocol::Udp).unwrap(),
                    minimum
                );
                assert!(packet_size(ip, Some(minimum - 1), TraceProtocol::Udp).is_err());
            }
            assert_eq!(
                packet_size(IpAddr::V4(Ipv4Addr::LOCALHOST), None, TraceProtocol::Icmp).unwrap(),
                40
            );
            assert_eq!(
                packet_size(IpAddr::V6(Ipv6Addr::LOCALHOST), None, TraceProtocol::Icmp).unwrap(),
                60
            );
            assert_eq!(
                packet_size(
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                    Some(56),
                    TraceProtocol::Icmp
                )
                .unwrap(),
                56
            );
            assert!(
                packet_size(
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                    Some(20),
                    TraceProtocol::Icmp
                )
                .is_err()
            );
            assert!(
                packet_size(
                    IpAddr::V6(Ipv6Addr::LOCALHOST),
                    Some(40),
                    TraceProtocol::Icmp
                )
                .is_err()
            );
            assert_eq!(
                packet_size(IpAddr::V4(Ipv4Addr::LOCALHOST), None, TraceProtocol::Tcp).unwrap(),
                40
            );
            assert_eq!(
                packet_size(IpAddr::V6(Ipv6Addr::LOCALHOST), None, TraceProtocol::Tcp).unwrap(),
                60
            );
            assert!(
                packet_size(
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                    Some(41),
                    TraceProtocol::Tcp
                )
                .is_err()
            );
        }

        #[test]
        fn keeps_each_node_with_its_own_rtts() {
            let now = Instant::now();
            let mut probes = HashMap::new();
            for (seq, ip, rtt) in [
                (1, Ipv4Addr::new(1, 1, 1, 1), 1),
                (2, Ipv4Addr::new(1, 1, 1, 1), 2),
                (3, Ipv4Addr::new(2, 2, 2, 2), 3),
            ] {
                probes.insert(
                    seq,
                    Probe {
                        ttl: 1,
                        token: seq,
                        started: now,
                        deadline: now + Duration::from_secs(1),
                        reply: Some((IpAddr::V4(ip), Duration::from_millis(rtt), ReplyKind::Hop)),
                        cancelled: false,
                        reservation: None,
                    },
                );
            }
            let rows = collect_rows(probes, 1);
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].nodes.len(), 2);
            assert_eq!(rows[0].nodes[0].rtts.len(), 2);
            assert_eq!(rows[0].nodes[1].rtts.len(), 1);
            assert!(rows.iter().all(|row| !row.nodes.is_empty()));
        }

        #[test]
        fn missing_location_is_a_placeholder() {
            assert_eq!(
                location_for(None, IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
                "-"
            );
        }

        #[test]
        fn internal_addresses_have_a_local_label() {
            for ip in [
                Ipv4Addr::new(10, 1, 2, 3),
                Ipv4Addr::new(172, 16, 0, 1),
                Ipv4Addr::new(172, 31, 255, 254),
                Ipv4Addr::new(192, 168, 1, 1),
                Ipv4Addr::LOCALHOST,
            ] {
                assert_eq!(location_for(None, IpAddr::from(ip)), "Internal node");
            }
            assert_eq!(
                location_for(None, IpAddr::V6(Ipv6Addr::LOCALHOST)),
                "Internal node"
            );
            for ip in [
                Ipv4Addr::new(1, 1, 1, 1),
                Ipv4Addr::new(172, 15, 255, 255),
                Ipv4Addr::new(172, 32, 0, 1),
            ] {
                assert_eq!(location_for(None, IpAddr::from(ip)), "-");
            }
        }

        #[test]
        fn unanswered_hop_uses_a_star_in_the_ip_column() {
            let rows = vec![Row {
                ttl: 1,
                nodes: Vec::new(),
            }];
            let rendered = render_rows(&rows, None);
            let lines: Vec<_> = rendered.lines().collect();
            assert!(lines[2].contains("1"));
            let columns: Vec<_> = lines[2].split('|').map(str::trim).collect();
            assert_eq!(columns[1], "*");
            assert_eq!(columns[3], "*");
        }

        #[test]
        fn trace_json_uses_the_public_hop_shape() {
            let rows = vec![
                Row {
                    ttl: 1,
                    nodes: Vec::new(),
                },
                Row {
                    ttl: 2,
                    nodes: vec![
                        Node {
                            ip: "192.0.2.1".parse().unwrap(),
                            rtts: vec![Duration::from_millis(3), Duration::from_millis(5)],
                            error: None,
                        },
                        Node {
                            ip: "192.0.2.2".parse().unwrap(),
                            rtts: vec![Duration::from_millis(7)],
                            error: Some(3),
                        },
                    ],
                },
            ];
            let value = serde_json::to_value(TraceData::from_rows(
                "example.com".to_string(),
                "198.51.100.1".parse().unwrap(),
                64,
                40,
                &rows,
            ))
            .unwrap();

            assert_eq!(value["target_name"], "example.com");
            assert_eq!(value["target"], "198.51.100.1");
            assert_eq!(value["max_hops"], 64);
            assert_eq!(value["size"], 40);
            assert_eq!(value["rows"][0]["ttl"], 1);
            assert_eq!(value["rows"][0]["nodes"], serde_json::json!([]));
            assert_eq!(value["rows"][1]["nodes"][0]["rtt_ns"], 4_000_000);
            assert!(value["rows"][1]["nodes"][0]["error"].is_null());
            assert_eq!(value["rows"][1]["nodes"][1]["error"], 3);
        }

        #[test]
        fn trace_json_is_written_only_after_the_target_is_reached() {
            let path = std::env::temp_dir().join(format!(
                "pingx-trace-json-success-{}.json",
                std::process::id()
            ));
            std::fs::write(&path, b"existing").unwrap();
            let cli = Cli::try_parse_from([
                "pingx",
                "-R",
                "example.com",
                &format!("--json={}", path.to_str().unwrap()),
            ])
            .unwrap();
            let data = TraceData::from_rows(
                "example.com".to_string(),
                "198.51.100.1".parse().unwrap(),
                32,
                40,
                &[Row {
                    ttl: 1,
                    nodes: vec![Node {
                        ip: "192.0.2.1".parse().unwrap(),
                        rtts: vec![Duration::from_millis(2)],
                        error: None,
                    }],
                }],
            );

            output_trace_json(&cli, &data, None, None).unwrap();
            assert_eq!(std::fs::read(&path).unwrap(), b"existing");
            output_trace_json(&cli, &data, Some(2), Some(3)).unwrap();
            assert_eq!(std::fs::read(&path).unwrap(), b"existing");

            std::fs::remove_file(&path).unwrap();
            output_trace_json(&cli, &data, None, None).unwrap();
            assert!(!path.exists());

            output_trace_json(&cli, &data, Some(2), None).unwrap();
            let output = std::fs::read_to_string(&path).unwrap();
            assert!(output.contains('\n'));
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&output).unwrap()["max_hops"],
                32
            );
            std::fs::remove_file(path).unwrap();
        }

        #[cfg(target_os = "macos")]
        #[test]
        fn helper_trace_data_preserves_hop_nodes_and_rtt() {
            let rows = vec![Row {
                ttl: 2,
                nodes: vec![
                    Node {
                        ip: "192.0.2.1".parse().unwrap(),
                        rtts: vec![Duration::from_millis(3), Duration::from_millis(5)],
                        error: None,
                    },
                    Node {
                        ip: "192.0.2.2".parse().unwrap(),
                        rtts: vec![Duration::from_millis(7)],
                        error: Some(3),
                    },
                ],
            }];
            let encoded = serde_json::to_string(&TraceData::from_rows(
                "example.com".to_string(),
                "198.51.100.1".parse().unwrap(),
                64,
                40,
                &rows,
            ))
            .unwrap();
            let decoded: TraceData = serde_json::from_str(&encoded).unwrap();
            let decoded = decoded.into_rows();
            assert_eq!(decoded[0].ttl, 2);
            assert_eq!(
                decoded[0].nodes[0].ip,
                "192.0.2.1".parse::<IpAddr>().unwrap()
            );
            assert_eq!(decoded[0].nodes[0].rtts, [Duration::from_millis(4)]);
            assert_eq!(decoded[0].nodes[1].error, Some(3));
        }

        #[test]
        fn send_window_stops_after_target_or_max_hops() {
            assert!(can_send(9, 64, None, 0));
            assert!(!can_send(9, 64, Some(8), 0));
            assert!(!can_send(256, 255, None, 0));
            assert!(can_send(255, 255, None, SEND_WINDOW - PROBES_PER_HOP));
            assert!(!can_send(1, 255, None, SEND_WINDOW));
            assert!(!can_send(1, 255, None, SEND_WINDOW - PROBES_PER_HOP + 1));
        }

        #[test]
        fn udp_trace_port_range_rejects_the_first_overflow() {
            assert!(validate_udp_port_range(65533, 1).is_ok());
            assert!(validate_udp_port_range(65534, 1).is_err());
            assert!(validate_udp_port_range(33434, 255).is_ok());
        }

        #[test]
        fn send_window_consumes_the_full_active_budget() {
            let mut ttl = 1;
            while can_send(ttl, 255, None, 0) {
                ttl += 1;
            }
            assert_eq!(ttl, 256);
            assert!(next_sequence_can_wrap_with_distinct_active_probes());
        }

        fn next_sequence_can_wrap_with_distinct_active_probes() -> bool {
            let now = Instant::now();
            let mut probes = HashMap::new();
            let mut sequence = u16::MAX;
            for ttl in 1..=SEND_WINDOW {
                let seq = next_sequence(&mut sequence, &probes);
                probes.insert(
                    seq,
                    Probe {
                        ttl: ttl as u8,
                        token: seq,
                        started: now,
                        deadline: now + Duration::from_secs(1),
                        reply: None,
                        cancelled: false,
                        reservation: None,
                    },
                );
            }
            probes.len() == SEND_WINDOW
        }

        #[test]
        fn expired_probes_are_inactive() {
            let now = Instant::now();
            let probe = Probe {
                ttl: 1,
                token: 1,
                started: now - Duration::from_secs(1),
                deadline: now - Duration::from_millis(1),
                reply: None,
                cancelled: false,
                reservation: None,
            };
            assert!(!is_probe_active(&probe, now));
            assert_eq!(active_probe_count(&HashMap::from([(1, probe)]), now), 0);
        }

        #[test]
        fn reaching_target_cancels_only_higher_ttls() {
            let now = Instant::now();
            let probe = |ttl| Probe {
                ttl,
                token: ttl as u16,
                started: now,
                deadline: now + Duration::from_secs(1),
                reply: None,
                cancelled: false,
                reservation: None,
            };
            let mut probes = HashMap::from([(1, probe(3)), (2, probe(2)), (3, probe(1))]);
            cancel_higher_ttls(&mut probes, 2);
            assert!(probes[&1].cancelled);
            assert!(!probes[&2].cancelled);
            assert!(!probes[&3].cancelled);
        }

        #[tokio::test]
        async fn full_trace_pipelines_and_stops_after_target() {
            let sender = TestSender::default();
            let result = run_fake_trace(
                &sender,
                64,
                Duration::from_millis(30),
                vec![Reply {
                    sequence: 7,
                    token: trace_ident(),
                    destination: None,
                    ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    kind: ReplyKind::Reached,
                    received_at: Instant::now() + Duration::from_millis(1),
                }],
                Duration::from_millis(10),
            )
            .await
            .unwrap();

            assert_eq!(
                sender.sent_ttls(),
                [
                    1, 1, 1, 2, 2, 2, 3, 3, 3, 4, 4, 4, 5, 5, 5, 6, 6, 6, 7, 7, 7, 8, 8, 8
                ]
            );
            assert_eq!(result.stop_hop, Some(3));
            assert_eq!(result.terminal_error, None);
            assert_eq!(result.max_sent, 8);
        }

        #[tokio::test]
        async fn full_trace_reports_terminal_unreachable() {
            let sender = TestSender::default();
            let result = run_fake_trace(
                &sender,
                64,
                Duration::from_millis(30),
                vec![Reply {
                    sequence: 4,
                    token: trace_ident(),
                    destination: None,
                    ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    kind: ReplyKind::Unreachable(3),
                    received_at: Instant::now(),
                }],
                Duration::from_millis(10),
            )
            .await
            .unwrap();

            assert_eq!(result.stop_hop, Some(2));
            assert_eq!(result.terminal_error, Some(3));
            assert_eq!(sender.sent_ttls().len(), SEND_WINDOW);
        }

        #[tokio::test]
        async fn full_trace_respects_max_hops_after_timeouts() {
            let sender = TestSender::default();
            let result = run_fake_trace(
                &sender,
                2,
                Duration::from_millis(10),
                vec![],
                Duration::from_millis(50),
            )
            .await
            .unwrap();

            assert_eq!(sender.sent_ttls(), [1, 1, 1, 2, 2, 2]);
            assert_eq!(result.stop_hop, None);
            assert_eq!(result.max_sent, 2);
            assert!(result.probes.values().all(|probe| probe.reply.is_none()));
        }

        #[tokio::test]
        async fn trace_interruption_reports_that_no_rows_were_rendered() {
            let outcome = run_until_interrupted(
                std::future::pending::<Result<()>>(),
                std::future::ready(Ok(())),
            )
            .await;

            assert_eq!(
                outcome.unwrap_err().to_string(),
                "traceroute cancelled by user"
            );
        }

        #[tokio::test]
        async fn udp_raw_replies_match_tokens_and_reject_late_replies() {
            for late in [false, true] {
                let sender = TestSender::default();
                let (tx, mut rx) = mpsc::channel(8);
                tx.send(Reply {
                    sequence: 0,
                    token: 33434,
                    destination: None,
                    ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                    kind: ReplyKind::Reached,
                    received_at: Instant::now()
                        + Duration::from_millis(if late { 1000 } else { 1 }),
                })
                .await
                .unwrap();
                let result = run_probes(
                    &sender,
                    ProbeRequest {
                        target: IpAddr::V4(Ipv4Addr::LOCALHOST),
                        local: IpAddr::V4(Ipv4Addr::LOCALHOST),
                        ident: trace_ident(),
                        tcp_seed: TCP_SEED,
                        protocol: TraceProtocol::Udp,
                        base_port: 33434,
                        payload_size: 4,
                        max_hops: 1,
                        timeout: Duration::from_millis(20),
                    },
                    &mut rx,
                )
                .await
                .unwrap();
                assert_eq!(result.stop_hop, if late { None } else { Some(1) });
                assert_eq!(
                    result.probes.values().filter(|p| p.reply.is_some()).count(),
                    usize::from(!late)
                );
            }
        }

        #[test]
        fn tcp_packet_has_transport_header_payload_and_probe_ttl() {
            let packet = build_tcp_packet(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                443,
                33442,
                0x1234_5678,
                &[1, 2, 3],
                7,
            )
            .unwrap();
            assert_eq!(packet.len(), 43);
            assert_eq!(packet[8], 7);
            assert_eq!(&packet[20..24], &[0x82, 0xa2, 0x01, 0xbb]);
            assert_eq!(&packet[24..28], &0x1234_5678u32.to_be_bytes());
            assert_eq!(&packet[40..], &[1, 2, 3]);
            assert_eq!(
                tcp_checksum(
                    Ipv4Addr::LOCALHOST,
                    &packet[20..],
                    &Ipv4Addr::LOCALHOST.octets()
                ),
                0
            );
            assert_eq!(ip_checksum(&packet[..20]), 0);
        }

        #[test]
        fn tcp_reset_uses_the_probe_tuple_in_reverse_direction() {
            let packet = build_tcp_reset_packet(
                "192.0.2.1".parse().unwrap(),
                "198.51.100.2".parse().unwrap(),
                40000,
                443,
                0x1234_5678,
            )
            .unwrap();
            assert_eq!(&packet[20..22], &40000u16.to_be_bytes());
            assert_eq!(&packet[22..24], &443u16.to_be_bytes());
            assert_eq!(&packet[24..28], &0x1234_5678u32.to_be_bytes());
            assert_eq!(packet[33], TCP_RST);
        }

        #[test]
        fn active_tcp_probes_reserve_distinct_source_ports() {
            let local = IpAddr::V4(Ipv4Addr::LOCALHOST);
            let first = crate::probe::tcp_syn::reserve_source_port(local).unwrap();
            let second = crate::probe::tcp_syn::reserve_source_port(local).unwrap();
            let port = |socket: &Socket| socket.local_addr().unwrap().as_socket().unwrap().port();
            assert_ne!(port(&first), port(&second));
        }

        #[test]
        fn table_pads_cjk_by_terminal_width() {
            let cells = [(
                "1".to_string(),
                "1.1.1.1".to_string(),
                "东京".to_string(),
                "1.000 ms".to_string(),
            )];
            let table = render_table(&cells);
            let lines: Vec<_> = table.lines().collect();
            assert_eq!(
                UnicodeWidthStr::width(strip_style(lines[0]).as_str()),
                UnicodeWidthStr::width(strip_style(lines[2]).as_str())
            );
        }

        #[test]
        fn header_uses_the_documented_layout() {
            assert_eq!(
                strip_style(&styled_trace_header(
                    "demo.example",
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                    64,
                    40,
                )),
                "Target: demo.example (127.0.0.1)   Max Hops:  64    Size: 40 b"
            );
        }

        #[test]
        fn trace_header_bolds_only_keys() {
            let target = IpAddr::V4(Ipv4Addr::LOCALHOST);
            let styled = format!(
                "{} {}   {} {:>3}    {} {} b",
                "Target:".bold(),
                display_target("demo.example", target),
                "Max Hops:".bold(),
                64,
                "Size:".bold(),
                40
            );
            let plain = format!(
                "Target: {}   Max Hops:  64    Size: 40 b",
                display_target("demo.example", target)
            );
            assert_eq!(styled.replace("\x1b[1m", "").replace("\x1b[0m", ""), plain);
            assert!(!styled.contains(&format!(
                "\x1b[1m{}",
                display_target("demo.example", target)
            )));
            assert!(!styled.contains(&format!("\x1b[1m{}", 64)));
            assert!(!styled.contains(&format!("\x1b[1m{}", 40)));
        }

        #[test]
        fn styled_header_does_not_break_table_alignment() {
            let cells = [(
                "1".to_string(),
                "1.1.1.1".to_string(),
                "Tokyo".to_string(),
                "1.000 ms".to_string(),
            )];
            let table = render_table(&cells);
            let lines: Vec<_> = table.lines().collect();
            assert_eq!(strip_style(lines[0]), "Hop | IP      | Location |      RTT");
        }

        #[test]
        fn long_cells_are_truncated_without_breaking_alignment() {
            let location = "城".repeat(LOCATION_MAX_WIDTH);
            let cells = (
                "1".to_string(),
                "1.1.1.1".to_string(),
                location,
                "1.000 ms".to_string(),
            );
            let table = render_table(&[cells]);
            let lines: Vec<_> = table.lines().collect();
            assert_eq!(
                UnicodeWidthStr::width(strip_style(lines[0]).as_str()),
                UnicodeWidthStr::width(strip_style(lines[2]).as_str())
            );
            assert!(UnicodeWidthStr::width(strip_style(lines[2]).as_str()) < 160);
        }

        fn strip_style(value: &str) -> String {
            value.replace("\x1b[1m", "").replace("\x1b[0m", "")
        }

        #[test]
        fn rows_keep_timeouts_and_multiple_nodes_readable() {
            let rows = vec![
                Row {
                    ttl: 1,
                    nodes: vec![
                        Node {
                            ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                            rtts: vec![Duration::from_millis(2)],
                            error: None,
                        },
                        Node {
                            ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
                            rtts: vec![Duration::from_millis(1), Duration::from_millis(3)],
                            error: None,
                        },
                    ],
                },
                Row {
                    ttl: 2,
                    nodes: vec![Node {
                        ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
                        rtts: vec![Duration::from_millis(5), Duration::from_millis(6)],
                        error: None,
                    }],
                },
                Row {
                    ttl: 3,
                    nodes: vec![Node {
                        ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                        rtts: vec![Duration::from_millis(4)],
                        error: Some(3),
                    }],
                },
            ];

            let table = render_rows(&rows, None);
            let lines: Vec<_> = table.lines().collect();
            assert_eq!(lines.len(), 6);
            assert!(lines[0].contains("Hop") && lines[0].contains("Location"));
            assert!(!lines[0].contains("Host"));
            assert_eq!(lines[1].chars().filter(|&ch| ch == '+').count(), 3);
            assert!(lines[2].contains("1 | 192.0.2.1"));
            assert!(lines[3].starts_with("    | 192.0.2.2"));
            assert!(lines[4].contains("2 | 192.0.2.2") && lines[4].contains("5.500 ms"));
            assert!(!lines[4].contains("*"));
            assert!(lines[5].contains("| Internal node") && lines[5].contains("(error 3)"));
            assert!(lines[5].contains("4.000 ms (error 3)"));
            assert!(
                lines[2..].iter().all(|line| {
                    UnicodeWidthStr::width(*line) == UnicodeWidthStr::width(lines[2])
                })
            );
        }

        #[test]
        fn selects_a_reachable_family_candidate() {
            let target = select_target_with(
                vec![
                    IpAddr::V6("2001:db8::1".parse().unwrap()),
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                ],
                |addr| {
                    if addr.is_ipv6() {
                        Err(io::Error::new(
                            io::ErrorKind::NetworkUnreachable,
                            "unreachable",
                        ))
                    } else {
                        Ok(())
                    }
                },
            )
            .unwrap();
            assert_eq!(target, IpAddr::V4(Ipv4Addr::LOCALHOST));
        }
    }
}

#[cfg(any(unix, windows))]
use platform::run_trace;
