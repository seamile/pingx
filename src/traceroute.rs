use crate::cli::Cli;
use anyhow::Result;

pub struct TraceSession {
    cli: Cli,
}

impl TraceSession {
    pub fn new(cli: Cli) -> Self {
        Self { cli }
    }

    pub async fn run(&self) -> Result<()> {
        run_trace(self.cli.clone()).await
    }
}

#[cfg(not(unix))]
async fn run_trace(_cli: Cli) -> Result<()> {
    Err(anyhow::anyhow!(
        "traceroute mode is not supported on this platform"
    ))
}

#[cfg(unix)]
mod unix {
    use super::*;
    use crate::geoip::GeoIpManager;
    use crate::pinger::icmp_packet::IcmpPacket;
    use crate::utils::{IpVersion, resolve_host};
    use async_trait::async_trait;
    use socket2::{Domain, Protocol, Socket, Type};
    use std::collections::{BTreeMap, HashMap};
    use std::io;
    use std::net::{IpAddr, SocketAddr};
    use std::os::fd::AsRawFd;
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use tokio::io::unix::AsyncFd;
    use tokio::sync::mpsc;
    use tokio::task::JoinSet;
    use unicode_width::UnicodeWidthStr;

    const PROBES_PER_HOP: usize = 3;
    const SEND_WINDOW: usize = 8 * PROBES_PER_HOP;
    const HOST_MAX_WIDTH: usize = 48;
    const LOCATION_MAX_WIDTH: usize = 48;
    const IP_MAX_WIDTH: usize = 48;
    const ICMP_TIME_EXCEEDED_V4: u8 = 11;
    const ICMP_TIME_EXCEEDED_V6: u8 = 3;
    const ICMP_DEST_UNREACH_V4: u8 = 3;
    const ICMP_DEST_UNREACH_V6: u8 = 1;
    const IDENTIFIER: u16 = 0x5047;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum ReplyKind {
        Hop,
        Reached,
        Unreachable(u8),
    }

    #[derive(Clone, Copy, Debug)]
    struct Reply {
        sequence: u16,
        ip: IpAddr,
        kind: ReplyKind,
        received_at: Instant,
    }

    #[derive(Clone, Copy, Debug)]
    struct Probe {
        ttl: u8,
        started: Instant,
        deadline: Instant,
        reply: Option<(IpAddr, Duration, ReplyKind)>,
        cancelled: bool,
    }

    #[derive(Debug)]
    struct Row {
        ttl: u8,
        nodes: Vec<Node>,
        missing: usize,
    }

    #[derive(Debug)]
    struct Node {
        ip: IpAddr,
        rtts: Vec<Duration>,
        error: Option<u8>,
    }

    struct ProbeRun {
        probes: HashMap<u16, Probe>,
        stop_hop: Option<u8>,
        terminal_error: Option<u8>,
        max_sent: u8,
    }

    #[async_trait]
    trait ProbeSender {
        async fn send_probe(&self, data: Vec<u8>, target: IpAddr, ttl: u8) -> io::Result<()>;
    }

    pub(super) async fn run_trace(cli: Cli) -> Result<()> {
        let target_name = cli.targets[0].clone();
        let version = if cli.ipv4 {
            IpVersion::V4
        } else if cli.ipv6 {
            IpVersion::V6
        } else {
            IpVersion::Any
        };
        let addrs = resolve_host(&target_name, version).await?;
        let target = select_target(addrs)?;
        let requested = cli
            .targets
            .get(1)
            .map(|value| value.parse::<usize>())
            .transpose()
            .map_err(|_| anyhow::anyhow!("traceroute packet size must be an integer"))?;
        let size = packet_size(target, requested)?;
        let max_hops = cli.max_hops;
        anyhow::ensure!(
            cli.timeout > Duration::ZERO,
            "traceroute timeout must be greater than zero"
        );
        let timeout = cli.timeout;
        let socket = Arc::new(TraceSocket::new(target.is_ipv6())?);

        println!("{}", trace_header(&target_name, target, max_hops, size));

        let (reply_tx, mut reply_rx) = mpsc::channel(128);
        let receiver = spawn_receiver(socket.clone(), target, reply_tx);
        let ident = trace_ident();
        let payload_size = size - if target.is_ipv4() { 28 } else { 48 };
        let result = run_probes(
            socket.as_ref(),
            target,
            ident,
            payload_size,
            max_hops,
            timeout,
            &mut reply_rx,
        )
        .await;
        receiver.abort();
        let result = result?;
        render(&collect_rows(
            result.probes,
            result.stop_hop.unwrap_or(result.max_sent),
        ))
        .await;
        match (result.stop_hop, result.terminal_error) {
            (_, Some(code)) => anyhow::bail!("target is unreachable (ICMP error {})", code),
            (Some(_), None) => Ok(()),
            (None, None) => anyhow::bail!("target was not reached within {} hops", max_hops),
        }
    }

    async fn run_probes(
        sender: &dyn ProbeSender,
        target: IpAddr,
        ident: u16,
        payload_size: usize,
        max_hops: u8,
        timeout: Duration,
        reply_rx: &mut mpsc::Receiver<Reply>,
    ) -> Result<ProbeRun> {
        let mut probes = HashMap::<u16, Probe>::new();
        let mut sequence = 1u16;
        let mut next_ttl = 1u16;
        let mut stop_hop = None::<u8>;
        let mut terminal_error = None::<u8>;

        loop {
            let now = Instant::now();
            while can_send(
                next_ttl,
                max_hops,
                stop_hop,
                active_probe_count(&probes, now),
            ) {
                let ttl = u8::try_from(next_ttl).expect("max-hops is limited to u8");
                for _ in 0..PROBES_PER_HOP {
                    let seq = next_sequence(&mut sequence, &probes);
                    let packet = IcmpPacket::new_request(
                        target.is_ipv6(),
                        ident,
                        seq,
                        vec![0; payload_size],
                    );
                    probes.insert(
                        seq,
                        Probe {
                            ttl,
                            started: Instant::now(),
                            deadline: Instant::now(),
                            reply: None,
                            cancelled: false,
                        },
                    );
                    sender.send_probe(packet.encode(), target, ttl).await?;
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
                        && let Some(probe) = probes.get_mut(&reply.sequence)
                        && !probe.cancelled
                        && probe.reply.is_none()
                    {
                        let reply_ttl = probe.ttl;
                        let rtt = reply_rtt(probe.started, reply);
                        probe.reply = Some((reply.ip, rtt, reply.kind));
                        if reply.kind == ReplyKind::Reached {
                            stop_hop =
                                Some(stop_hop.map_or(reply_ttl, |hop: u8| hop.min(reply_ttl)));
                            cancel_higher_ttls(&mut probes, reply_ttl);
                        } else if let ReplyKind::Unreachable(code) = reply.kind {
                            terminal_error = Some(code);
                            stop_hop = Some(stop_hop.map_or(reply_ttl, |hop: u8| hop.min(reply_ttl)));
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
            stop_hop,
            terminal_error,
            max_sent,
        })
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

    fn packet_size(target: IpAddr, requested: Option<usize>) -> Result<usize> {
        let size = requested.unwrap_or(if target.is_ipv4() { 40 } else { 60 });
        let minimum = if target.is_ipv4() { 28 } else { 48 };
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

    fn trace_header(name: &str, ip: IpAddr, max_hops: u8, size: usize) -> String {
        format!(
            "Target: {}   Max Hops: {:>3}    Size: {} b",
            display_target(name, ip),
            max_hops,
            size
        )
    }

    struct TraceSocket {
        inner: AsyncFd<std::net::UdpSocket>,
        v6: bool,
    }

    impl TraceSocket {
        fn new(v6: bool) -> io::Result<Self> {
            let (domain, protocol) = if v6 {
                (Domain::IPV6, Protocol::ICMPV6)
            } else {
                (Domain::IPV4, Protocol::ICMPV4)
            };
            let socket = Socket::new(domain, socket_type(), Some(protocol)).map_err(|e| {
                if e.kind() == io::ErrorKind::PermissionDenied {
                    io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "traceroute requires RAW ICMP privileges; run with sudo or grant CAP_NET_RAW",
                    )
                } else {
                    e
                }
            })?;
            if let Some(iface) = crate::utils::get_bind_interface() {
                crate::utils::bind_socket_to_interface(&socket, iface, v6)?;
            }
            socket.set_nonblocking(true)?;
            if v6 {
                socket.set_unicast_hops_v6(1)?;
            } else {
                socket.set_ttl_v4(1)?;
            }
            let socket: std::net::UdpSocket = socket.into();
            let inner = unsafe { AsyncFd::register(socket) }?;
            Ok(Self { inner, v6 })
        }

        fn set_ttl(&self, ttl: u8) -> io::Result<()> {
            let value = ttl as libc::c_int;
            let (level, option) = if self.v6 {
                (libc::IPPROTO_IPV6, libc::IPV6_UNICAST_HOPS)
            } else {
                (libc::IPPROTO_IP, libc::IP_TTL)
            };
            let rc = unsafe {
                libc::setsockopt(
                    self.inner.get_ref().as_raw_fd(),
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

        async fn send_to(&self, data: &[u8], target: IpAddr, ttl: u8) -> io::Result<()> {
            self.set_ttl(ttl)?;
            loop {
                let mut guard = self.inner.writable().await?;
                match guard.try_io(|inner| {
                    inner
                        .get_ref()
                        .send_to(data, SocketAddr::new(target, 0))
                        .map(|_| ())
                }) {
                    Ok(result) => return result,
                    Err(_) => continue,
                }
            }
        }

        async fn recv(&self, data: &mut [u8]) -> io::Result<(usize, IpAddr)> {
            loop {
                let mut guard = self.inner.readable().await?;
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

    #[cfg(target_os = "macos")]
    fn socket_type() -> Type {
        Type::DGRAM
    }

    #[cfg(not(target_os = "macos"))]
    fn socket_type() -> Type {
        Type::RAW
    }

    #[async_trait]
    impl ProbeSender for TraceSocket {
        async fn send_probe(&self, data: Vec<u8>, target: IpAddr, ttl: u8) -> io::Result<()> {
            self.send_to(&data, target, ttl).await
        }
    }

    fn spawn_receiver(
        socket: Arc<TraceSocket>,
        target: IpAddr,
        tx: mpsc::Sender<Reply>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut data = [0u8; 65535];
            loop {
                match socket.recv(&mut data).await {
                    Ok((size, from)) => {
                        let received_at = Instant::now();
                        if let Some(reply) = parse_reply(&data[..size], from, target, received_at)
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
            rows.push(Row {
                ttl,
                nodes,
                missing: hop.iter().filter(|p| p.reply.is_none()).count(),
            });
        }
        rows
    }

    fn reply_rtt(started: Instant, reply: Reply) -> Duration {
        reply.received_at.saturating_duration_since(started)
    }

    fn location_for(geo: Option<&GeoIpManager>, ip: IpAddr) -> String {
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

    fn parse_reply(
        data: &[u8],
        from: IpAddr,
        target: IpAddr,
        received_at: Instant,
    ) -> Option<Reply> {
        if target.is_ipv6() {
            parse_reply_v6(data, from, target, received_at)
        } else {
            parse_reply_v4(data, from, target, received_at)
        }
    }

    fn parse_reply_v4(
        data: &[u8],
        from: IpAddr,
        target: IpAddr,
        received_at: Instant,
    ) -> Option<Reply> {
        let (icmp, _) = strip_ipv4(data)?;
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
        let packet = IcmpPacket::decode(data).ok()?;
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
        // DGRAM ICMP sockets may return the ICMP message without an IPv4 header.
        (data.len() >= 8 && matches!(data[0], 0 | ICMP_TIME_EXCEEDED_V4 | ICMP_DEST_UNREACH_V4))
            .then_some((data, 0))
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
        if payload.len() < 48 || payload[0] >> 4 != 6 || payload[24..40] != target.octets() {
            return None;
        }
        let mut offset = 40usize;
        loop {
            if offset + 8 > payload.len() {
                return None;
            }
            let next = match payload[offset] {
                0 | 43 | 60 => (payload[offset + 1] as usize + 1) * 8,
                44 => 8,
                51 => (payload[offset + 1] as usize + 2) * 4,
                _ => break,
            };
            offset = offset.checked_add(next)?;
        }
        (offset + 8 <= payload.len()
            && payload[offset] == 128
            && payload[offset + 4..offset + 6] == trace_ident().to_be_bytes())
        .then(|| u16::from_be_bytes([payload[offset + 6], payload[offset + 7]]))
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
        let resolver = crate::utils::dns_resolver(Duration::from_millis(300), 1).ok();
        let mut ptr_results = JoinSet::new();
        for row in rows {
            for node in &row.nodes {
                if let Some(resolver) = resolver.clone() {
                    let ip = node.ip;
                    ptr_results.spawn(async move { (ip, reverse_lookup(&resolver, ip).await) });
                }
            }
        }
        let mut hosts = HashMap::new();
        while let Some(result) = ptr_results.join_next().await {
            if let Ok((ip, host)) = result {
                hosts.insert(ip, host.unwrap_or_else(|| "-".to_string()));
            }
        }
        println!("\n{}", render_rows(rows, &hosts, geo.as_ref()));
    }

    fn render_rows(
        rows: &[Row],
        hosts: &HashMap<IpAddr, String>,
        geo: Option<&GeoIpManager>,
    ) -> String {
        let mut cells = Vec::with_capacity(rows.len());
        for row in rows {
            if row.nodes.is_empty() {
                cells.push((
                    row.ttl.to_string(),
                    "-".to_string(),
                    "-".to_string(),
                    "-".to_string(),
                    "*".to_string(),
                ));
                continue;
            }
            for (index, node) in row.nodes.iter().enumerate() {
                let host = hosts
                    .get(&node.ip)
                    .cloned()
                    .unwrap_or_else(|| "-".to_string());
                let location = location_for(geo, node.ip);
                let min = node.rtts[0];
                let max = node.rtts[node.rtts.len() - 1];
                let avg = node.rtts.iter().sum::<Duration>() / node.rtts.len() as u32;
                let suffix = if index + 1 == row.nodes.len() && row.missing > 0 {
                    "*"
                } else {
                    ""
                };
                let error = node
                    .error
                    .map(|code| format!(" (error {})", code))
                    .unwrap_or_default();
                let rtt = format!(
                    "{:.3}/{:.3}/{:.3} ms{}{}",
                    min.as_secs_f64() * 1000.0,
                    avg.as_secs_f64() * 1000.0,
                    max.as_secs_f64() * 1000.0,
                    suffix,
                    error
                );
                cells.push((
                    if index == 0 {
                        row.ttl.to_string()
                    } else {
                        String::new()
                    },
                    host,
                    node.ip.to_string(),
                    location,
                    rtt,
                ));
            }
        }
        render_table(&cells)
    }

    fn render_table(cells: &[(String, String, String, String, String)]) -> String {
        let cells: Vec<_> = cells
            .iter()
            .map(|(hop, host, ip, location, rtt)| {
                (
                    hop.clone(),
                    truncate(host, HOST_MAX_WIDTH),
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
                    3 => UnicodeWidthStr::width(cell.3.as_str()),
                    _ => UnicodeWidthStr::width(cell.4.as_str()),
                })
                .max()
                .unwrap_or(fallback)
                .max(fallback)
        };
        let widths = [
            width(0, 3),
            width(1, 4),
            width(2, 2),
            width(3, 8),
            width(4, 3),
        ];
        let mut lines = vec![
            format!(
                "{} | {} | {} | {} | {}",
                pad_left("Hop", widths[0]),
                pad_right("Host", widths[1]),
                pad_right("IP", widths[2]),
                pad_right("Location", widths[3]),
                pad_left("RTT", widths[4])
            ),
            format!(
                "{}+{}+{}+{}+{}",
                "-".repeat(widths[0] + 2),
                "-".repeat(widths[1] + 2),
                "-".repeat(widths[2] + 2),
                "-".repeat(widths[3] + 2),
                "-".repeat(widths[4] + 2)
            ),
        ];
        for (hop, host, ip, location, rtt) in &cells {
            lines.push(format!(
                "{} | {} | {} | {} | {}",
                pad_left(hop, widths[0]),
                pad_right(host, widths[1]),
                pad_right(ip, widths[2]),
                pad_right(location, widths[3]),
                pad_left(rtt, widths[4])
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

    async fn reverse_lookup(
        resolver: &hickory_resolver::TokioResolver,
        ip: IpAddr,
    ) -> Option<String> {
        let lookup = tokio::time::timeout(Duration::from_millis(500), resolver.reverse_lookup(ip))
            .await
            .ok()?
            .ok()?;
        lookup.answers().iter().find_map(|record| {
            if let hickory_resolver::proto::rr::RData::PTR(name) = &record.data {
                Some(name.to_utf8().trim_end_matches('.').to_string())
            } else {
                None
            }
        })
    }

    fn trace_ident() -> u16 {
        (std::process::id() as u16) ^ IDENTIFIER
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::net::{Ipv4Addr, Ipv6Addr};
        use std::sync::Mutex;
        use tokio::sync::mpsc;

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
            async fn send_probe(&self, _data: Vec<u8>, _target: IpAddr, ttl: u8) -> io::Result<()> {
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
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                trace_ident(),
                12,
                max_hops,
                timeout,
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
        fn parses_ipv4_dgram_replies_without_ip_header() {
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
            embedded[6] = 44;
            embedded[7] = 8;
            embedded[24..40].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
            embedded[40] = 44;
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
        fn rtt_uses_the_receive_timestamp_not_processing_time() {
            let started = Instant::now();
            let received_at = started + Duration::from_millis(7);
            let reply = Reply {
                sequence: 1,
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
                    Instant::now(),
                )
                .is_none()
            );
            assert!(embedded_sequence_v4(&[0; 8], IpAddr::V6(Ipv6Addr::LOCALHOST)).is_none());
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
            assert_eq!(
                packet_size(IpAddr::V4(Ipv4Addr::LOCALHOST), None).unwrap(),
                40
            );
            assert_eq!(
                packet_size(IpAddr::V6(Ipv6Addr::LOCALHOST), None).unwrap(),
                60
            );
            assert_eq!(
                packet_size(IpAddr::V4(Ipv4Addr::LOCALHOST), Some(56)).unwrap(),
                56
            );
            assert!(packet_size(IpAddr::V4(Ipv4Addr::LOCALHOST), Some(20)).is_err());
            assert!(packet_size(IpAddr::V6(Ipv6Addr::LOCALHOST), Some(40)).is_err());
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
                        started: now,
                        deadline: now + Duration::from_secs(1),
                        reply: Some((IpAddr::V4(ip), Duration::from_millis(rtt), ReplyKind::Hop)),
                        cancelled: false,
                    },
                );
            }
            let rows = collect_rows(probes, 1);
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].nodes.len(), 2);
            assert_eq!(rows[0].nodes[0].rtts.len(), 2);
            assert_eq!(rows[0].nodes[1].rtts.len(), 1);
            assert_eq!(rows.iter().map(|row| row.missing).sum::<usize>(), 0);
        }

        #[test]
        fn missing_location_is_a_placeholder() {
            assert_eq!(location_for(None, IpAddr::V4(Ipv4Addr::LOCALHOST)), "-");
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
                        started: now,
                        deadline: now + Duration::from_secs(1),
                        reply: None,
                        cancelled: false,
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
                started: now - Duration::from_secs(1),
                deadline: now - Duration::from_millis(1),
                reply: None,
                cancelled: false,
            };
            assert!(!is_probe_active(&probe, now));
            assert_eq!(active_probe_count(&HashMap::from([(1, probe)]), now), 0);
        }

        #[test]
        fn reaching_target_cancels_only_higher_ttls() {
            let now = Instant::now();
            let probe = |ttl| Probe {
                ttl,
                started: now,
                deadline: now + Duration::from_secs(1),
                reply: None,
                cancelled: false,
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

        #[test]
        fn table_pads_cjk_by_terminal_width() {
            let cells = [(
                "1".to_string(),
                "host".to_string(),
                "1.1.1.1".to_string(),
                "东京".to_string(),
                "1.000 ms".to_string(),
            )];
            let table = render_table(&cells);
            let lines: Vec<_> = table.lines().collect();
            assert_eq!(
                UnicodeWidthStr::width(lines[0]),
                UnicodeWidthStr::width(lines[2])
            );
        }

        #[test]
        fn header_uses_the_documented_layout() {
            assert_eq!(
                trace_header("demo.example", IpAddr::V4(Ipv4Addr::LOCALHOST), 64, 40),
                "Target: demo.example (127.0.0.1)   Max Hops:  64    Size: 40 b"
            );
        }

        #[test]
        fn long_cells_are_truncated_without_breaking_alignment() {
            let host = "h".repeat(HOST_MAX_WIDTH + 20);
            let location = "城".repeat(LOCATION_MAX_WIDTH);
            let cells = (
                "1".to_string(),
                host,
                "1.1.1.1".to_string(),
                location,
                "1.000 ms".to_string(),
            );
            let table = render_table(&[cells]);
            let lines: Vec<_> = table.lines().collect();
            assert_eq!(
                UnicodeWidthStr::width(lines[0]),
                UnicodeWidthStr::width(lines[2])
            );
            assert!(UnicodeWidthStr::width(lines[2]) < 160);
        }

        #[test]
        fn rows_keep_timeouts_and_multiple_nodes_readable() {
            let hosts = HashMap::from([
                (
                    IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                    "edge.example".to_string(),
                ),
                (
                    IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
                    "core.example".to_string(),
                ),
            ]);
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
                    missing: 0,
                },
                Row {
                    ttl: 2,
                    nodes: vec![Node {
                        ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
                        rtts: vec![Duration::from_millis(5), Duration::from_millis(6)],
                        error: None,
                    }],
                    missing: 1,
                },
                Row {
                    ttl: 3,
                    nodes: vec![Node {
                        ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                        rtts: vec![Duration::from_millis(4)],
                        error: Some(3),
                    }],
                    missing: 2,
                },
            ];

            let table = render_rows(&rows, &hosts, None);
            let lines: Vec<_> = table.lines().collect();
            assert_eq!(lines.len(), 6);
            assert!(lines[2].contains("1 | edge.example"));
            assert!(lines[3].trim_start().starts_with("| core.example"));
            assert!(lines[4].contains("2 | core.example"));
            assert!(lines[4].contains("ms*"));
            assert!(lines[5].contains("3 | -") && lines[5].contains("(error 3)"));
            assert!(lines[5].contains("ms* (error 3)"));
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

#[cfg(unix)]
use unix::run_trace;
