use socket2::{Domain, Protocol, Socket, Type};
use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
#[cfg(unix)]
use tokio::io::unix::AsyncFd;
#[cfg(target_os = "macos")]
use tokio::sync::Mutex as AsyncMutex;

const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_ACK: u8 = 0x10;
const ICMP_DEST_UNREACH_V4: u8 = 3;
const ICMP_TIME_EXCEEDED_V4: u8 = 11;
const ICMP_DEST_UNREACH_V6: u8 = 1;
const ICMP_TIME_EXCEEDED_V6: u8 = 3;

static SEQUENCE_COUNTER: AtomicU32 = AtomicU32::new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpSynKind {
    Open,
    Closed,
}

#[derive(Clone, Copy, Debug)]
pub struct TcpSynReply {
    pub kind: TcpSynKind,
    pub rtt: Duration,
}

pub(crate) struct TcpSegment<'a> {
    pub source_port: u16,
    pub target_port: u16,
    pub sequence: u32,
    pub acknowledgement: u32,
    pub flags: u8,
    pub payload: &'a [u8],
}

#[derive(Clone, Debug)]
pub enum TcpSynFailure {
    Timeout,
    Network {
        node: Option<IpAddr>,
        reason: String,
    },
    Local(String),
}

impl fmt::Display for TcpSynFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => f.write_str("request timed out"),
            Self::Network { node, reason } => {
                if let Some(node) = node {
                    write!(f, "network error from {node}: {reason}")
                } else {
                    write!(f, "network error: {reason}")
                }
            }
            Self::Local(error) => write!(f, "local error: {error}"),
        }
    }
}

#[cfg(unix)]
pub async fn probe(
    target: IpAddr,
    port: u16,
    timeout: Duration,
    ttl: u32,
) -> Result<TcpSynReply, TcpSynFailure> {
    let ttl = u8::try_from(ttl)
        .map_err(|_| TcpSynFailure::Local("TTL must be between 0 and 255".to_string()))?;
    let local = local_address_for(target).map_err(to_local_failure)?;
    let reservation = reserve_source_port(local).map_err(to_local_failure)?;
    let source_port = reservation
        .local_addr()
        .map_err(to_local_failure)?
        .as_socket()
        .ok_or_else(|| TcpSynFailure::Local("local source port unavailable".to_string()))?
        .port();
    let sequence = next_sequence();
    let sockets = TcpSynSockets::new(local, target, ttl).map_err(to_local_failure)?;
    let packet = build_tcp_packet(
        local,
        target,
        TcpSegment {
            source_port,
            target_port: port,
            sequence,
            acknowledgement: 0,
            flags: TCP_SYN,
            payload: &[],
        },
        ttl,
    )
    .map_err(to_local_failure)?;
    sockets
        .send(&packet, target)
        .await
        .map_err(to_local_failure)?;
    let started = Instant::now();
    let deadline = tokio::time::sleep(timeout);
    tokio::pin!(deadline);
    let mut tcp_buffer = [0u8; 65_535];
    let mut icmp_buffer = [0u8; 65_535];

    loop {
        tokio::select! {
            received = sockets.recv_tcp(&mut tcp_buffer) => {
                let (size, from) = received.map_err(to_local_failure)?;
                let Some(reply) = parse_tcp_reply(
                    &tcp_buffer[..size],
                    from,
                    local,
                    target,
                    source_port,
                    port,
                    sequence,
                ) else { continue };
                if reply.kind == TcpSynKind::Open {
                    let reset = build_tcp_packet(
                        local,
                        target,
                        TcpSegment {
                            source_port,
                            target_port: port,
                            sequence: reply.acknowledgement,
                            acknowledgement: 0,
                            flags: TCP_RST,
                            payload: &[],
                        },
                        64,
                    ).map_err(to_local_failure)?;
                    let _ = sockets.send(&reset, target).await;
                }
                return Ok(TcpSynReply {
                    kind: reply.kind,
                    rtt: started.elapsed(),
                });
            }
            received = sockets.recv_icmp(&mut icmp_buffer) => {
                let (size, from) = received.map_err(to_local_failure)?;
                if let Some(failure) = parse_icmp_error(
                    &icmp_buffer[..size],
                    from,
                    local,
                    target,
                    source_port,
                    port,
                ) {
                    return Err(failure);
                }
            }
            _ = &mut deadline => return Err(TcpSynFailure::Timeout),
        }
    }
}

pub fn local_address_for(target: IpAddr) -> io::Result<IpAddr> {
    let v6 = target.is_ipv6();
    let socket = Socket::new(domain(v6), Type::DGRAM, Some(Protocol::UDP))?;
    #[cfg(unix)]
    bind_device(&socket, v6)?;
    socket.connect(&SocketAddr::new(target, 9).into())?;
    socket
        .local_addr()?
        .as_socket()
        .map(|address| address.ip())
        .ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "local address unavailable"))
}

#[cfg(windows)]
pub async fn probe_windows(
    target: IpAddr,
    port: u16,
    timeout: Duration,
    ttl: u32,
) -> Result<TcpSynReply, TcpSynFailure> {
    use crate::windivert::{Capture, Injector};

    let ttl = u8::try_from(ttl)
        .map_err(|_| TcpSynFailure::Local("TTL must be between 0 and 255".to_string()))?;
    let local = local_address_for(target).map_err(to_local_failure)?;
    let reservation = reserve_source_port(local).map_err(to_local_failure)?;
    let source_port = reservation
        .local_addr()
        .map_err(to_local_failure)?
        .as_socket()
        .ok_or_else(|| TcpSynFailure::Local("local source port unavailable".to_string()))?
        .port();
    let sequence = next_sequence();
    let packet = build_tcp_packet(
        local,
        target,
        TcpSegment {
            source_port,
            target_port: port,
            sequence,
            acknowledgement: 0,
            flags: TCP_SYN,
            payload: &[],
        },
        ttl,
    )
    .map_err(to_local_failure)?;
    let capture =
        Capture::open(&reply_filter(local, target, source_port, port)).map_err(to_local_failure)?;
    let injector = Injector::open().map_err(to_local_failure)?;
    let started = Instant::now();
    injector
        .send(&packet, target.is_ipv6())
        .map_err(to_local_failure)?;
    let deadline = started
        .checked_add(timeout)
        .ok_or_else(|| TcpSynFailure::Local("timeout is too large".to_string()))?;

    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(TcpSynFailure::Timeout);
        }
        let received = match capture.recv(remaining).await {
            Ok(packet) => packet,
            Err(error) if error.kind() == io::ErrorKind::TimedOut => {
                return Err(TcpSynFailure::Timeout);
            }
            Err(error) => return Err(to_local_failure(error)),
        };
        if let Some(reply) = parse_tcp_reply(
            &received.data,
            target,
            local,
            target,
            source_port,
            port,
            sequence,
        ) {
            if reply.kind == TcpSynKind::Open {
                let reset = build_tcp_packet(
                    local,
                    target,
                    TcpSegment {
                        source_port,
                        target_port: port,
                        sequence: reply.acknowledgement,
                        acknowledgement: 0,
                        flags: TCP_RST,
                        payload: &[],
                    },
                    ttl,
                )
                .map_err(to_local_failure)?;
                injector
                    .send(&reset, target.is_ipv6())
                    .map_err(to_local_failure)?;
            }
            return Ok(TcpSynReply {
                kind: reply.kind,
                rtt: started.elapsed(),
            });
        }
        if let Some(from) = packet_source(&received.data)
            && let Some(failure) =
                parse_icmp_error(&received.data, from, local, target, source_port, port)
        {
            return Err(failure);
        }
    }
}

#[cfg(windows)]
fn reply_filter(local: IpAddr, target: IpAddr, source_port: u16, target_port: u16) -> String {
    if target.is_ipv4() {
        format!(
            "(inbound or loopback) and (((ip and ip.SrcAddr == {target} and ip.DstAddr == {local} and tcp.SrcPort == {target_port} and tcp.DstPort == {source_port} and ((tcp.SYN and tcp.ACK) or (tcp.RST and tcp.ACK))) or (icmp and ip.DstAddr == {local} and (icmp.Type == {ICMP_DEST_UNREACH_V4} or icmp.Type == {ICMP_TIME_EXCEEDED_V4}))))"
        )
    } else {
        format!(
            "(inbound or loopback) and (((ipv6 and ipv6.SrcAddr == {target} and ipv6.DstAddr == {local} and tcp.SrcPort == {target_port} and tcp.DstPort == {source_port} and ((tcp.SYN and tcp.ACK) or (tcp.RST and tcp.ACK))) or (icmpv6 and ipv6.DstAddr == {local} and (icmpv6.Type == {ICMP_DEST_UNREACH_V6} or icmpv6.Type == {ICMP_TIME_EXCEEDED_V6}))))"
        )
    }
}

#[cfg(windows)]
fn packet_source(packet: &[u8]) -> Option<IpAddr> {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) if packet.len() >= 20 => {
            Some(Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]).into())
        }
        Some(6) if packet.len() >= 40 => {
            Some(Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?).into())
        }
        _ => None,
    }
}

pub(crate) fn reserve_source_port(local: IpAddr) -> io::Result<Socket> {
    let socket = Socket::new(domain(local.is_ipv6()), Type::STREAM, Some(Protocol::TCP))?;
    socket.bind(&SocketAddr::new(local, 0).into())?;
    Ok(socket)
}

pub(crate) fn next_sequence() -> u32 {
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    let counter = SEQUENCE_COUNTER.fetch_add(1, Ordering::Relaxed);
    time ^ counter.rotate_left(13) ^ u32::from(std::process::id() as u16).rotate_left(24)
}

#[cfg(unix)]
struct TcpSynSockets {
    send: AsyncFd<std::net::UdpSocket>,
    #[cfg(not(target_os = "macos"))]
    tcp: AsyncFd<std::net::UdpSocket>,
    #[cfg(target_os = "macos")]
    tcp: AsyncMutex<crate::probe::tcp_capture::TcpCapture>,
    icmp: AsyncFd<std::net::UdpSocket>,
}

#[cfg(unix)]
impl TcpSynSockets {
    fn new(local: IpAddr, target: IpAddr, ttl: u8) -> io::Result<Self> {
        let v6 = target.is_ipv6();
        #[cfg(not(target_os = "macos"))]
        let _ = local;
        let send = raw_socket(v6, Protocol::TCP)?;
        bind_device(&send, v6)?;
        if v6 {
            send.set_unicast_hops_v6(u32::from(ttl))?;
            #[cfg(not(target_os = "macos"))]
            send.set_header_included_v6(true)?;
        } else {
            send.set_header_included_v4(true)?;
            send.set_ttl_v4(u32::from(ttl))?;
        }
        #[cfg(not(target_os = "macos"))]
        let tcp = {
            let tcp = raw_socket(v6, Protocol::TCP)?;
            bind_device(&tcp, v6)?;
            if v6 {
                tcp.set_header_included_v6(true)?;
            } else {
                tcp.set_header_included_v4(true)?;
            }
            tcp.set_nonblocking(true)?;
            let tcp: std::net::UdpSocket = tcp.into();
            unsafe { AsyncFd::register(tcp) }?
        };
        #[cfg(target_os = "macos")]
        let tcp = AsyncMutex::new(crate::probe::tcp_capture::TcpCapture::new(local)?);
        let icmp_protocol = if v6 {
            Protocol::ICMPV6
        } else {
            Protocol::ICMPV4
        };
        let icmp = raw_socket(v6, icmp_protocol)?;
        bind_device(&icmp, v6)?;

        send.set_nonblocking(true)?;
        icmp.set_nonblocking(true)?;
        // Tokio can drive nonblocking raw Unix sockets through AsyncFd.
        let send: std::net::UdpSocket = send.into();
        let icmp: std::net::UdpSocket = icmp.into();
        Ok(Self {
            send: unsafe { AsyncFd::register(send) }?,
            tcp,
            icmp: unsafe { AsyncFd::register(icmp) }?,
        })
    }

    async fn send(&self, packet: &[u8], target: IpAddr) -> io::Result<()> {
        loop {
            let mut guard = self.send.writable().await?;
            let packet = raw_tcp_payload(packet, target)?;
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

    async fn recv_tcp(&self, data: &mut [u8]) -> io::Result<(usize, IpAddr)> {
        #[cfg(target_os = "macos")]
        {
            let (source, packet) = self.tcp.lock().await.recv().await?;
            let size = packet.len().min(data.len());
            data[..size].copy_from_slice(&packet[..size]);
            Ok((size, source))
        }
        #[cfg(not(target_os = "macos"))]
        recv_from(&self.tcp, data).await
    }

    async fn recv_icmp(&self, data: &mut [u8]) -> io::Result<(usize, IpAddr)> {
        recv_from(&self.icmp, data).await
    }
}

#[cfg(unix)]
pub(crate) fn raw_tcp_payload(packet: &[u8], target: IpAddr) -> io::Result<&[u8]> {
    #[cfg(target_os = "macos")]
    if target.is_ipv6() {
        return packet.get(40..).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "macOS IPv6 TCP packet is too short",
            )
        });
    }
    let _ = target;
    Ok(packet)
}

#[cfg(unix)]
async fn recv_from(
    socket: &AsyncFd<std::net::UdpSocket>,
    data: &mut [u8],
) -> io::Result<(usize, IpAddr)> {
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

#[cfg(unix)]
fn raw_socket(v6: bool, protocol: Protocol) -> io::Result<Socket> {
    Socket::new(domain(v6), Type::RAW, Some(protocol)).map_err(|error| {
        if error.kind() == io::ErrorKind::PermissionDenied {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "TCP SYN ping requires RAW socket privileges; run with sudo or grant CAP_NET_RAW",
            )
        } else {
            error
        }
    })
}

#[cfg(unix)]
fn bind_device(socket: &Socket, v6: bool) -> io::Result<()> {
    if let Some(interface) = crate::utils::get_bind_interface() {
        crate::utils::bind_socket_to_interface(socket, interface, v6)?;
    }
    Ok(())
}

pub(crate) fn build_tcp_packet(
    source: IpAddr,
    target: IpAddr,
    segment: TcpSegment<'_>,
    ttl: u8,
) -> io::Result<Vec<u8>> {
    match (source, target) {
        (IpAddr::V4(source), IpAddr::V4(target)) => {
            build_tcp_packet_v4(source, target, segment, ttl)
        }
        (IpAddr::V6(source), IpAddr::V6(target)) => {
            build_tcp_packet_v6(source, target, segment, ttl)
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "source and target address families differ",
        )),
    }
}

fn build_tcp_packet_v4(
    source: Ipv4Addr,
    target: Ipv4Addr,
    segment: TcpSegment<'_>,
    ttl: u8,
) -> io::Result<Vec<u8>> {
    let total = 40usize
        .checked_add(segment.payload.len())
        .filter(|size| *size <= u16::MAX as usize)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "TCP packet is too large"))?;
    let mut packet = vec![0u8; total];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    packet[6] = 0x40;
    packet[8] = ttl;
    packet[9] = 6;
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&target.octets());
    fill_tcp_header(&mut packet[20..], &segment);
    let sum = pseudo_header(&source.octets(), &target.octets(), packet[20..].len())
        + words(&packet[20..]);
    let tcp_checksum = finish_checksum(sum);
    packet[36..38].copy_from_slice(&tcp_checksum.to_be_bytes());

    #[cfg(target_os = "macos")]
    {
        packet[2..4].copy_from_slice(&(total as u16).to_ne_bytes());
        packet[6..8].copy_from_slice(&0x4000u16.to_ne_bytes());
    }
    #[cfg(not(target_os = "macos"))]
    {
        let header_checksum = finish_checksum(words(&packet[..20]));
        packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());
    }
    Ok(packet)
}

fn build_tcp_packet_v6(
    source: Ipv6Addr,
    target: Ipv6Addr,
    segment: TcpSegment<'_>,
    ttl: u8,
) -> io::Result<Vec<u8>> {
    let payload_length = 20usize
        .checked_add(segment.payload.len())
        .filter(|size| *size <= u16::MAX as usize)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "TCP packet is too large"))?;
    let mut packet = vec![0u8; 40 + payload_length];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&(payload_length as u16).to_be_bytes());
    packet[6] = 6;
    packet[7] = ttl;
    packet[8..24].copy_from_slice(&source.octets());
    packet[24..40].copy_from_slice(&target.octets());
    fill_tcp_header(&mut packet[40..], &segment);
    let sum =
        pseudo_header(&source.octets(), &target.octets(), payload_length) + words(&packet[40..]);
    let tcp_checksum = finish_checksum(sum);
    packet[56..58].copy_from_slice(&tcp_checksum.to_be_bytes());
    Ok(packet)
}

fn fill_tcp_header(tcp: &mut [u8], segment: &TcpSegment<'_>) {
    tcp[0..2].copy_from_slice(&segment.source_port.to_be_bytes());
    tcp[2..4].copy_from_slice(&segment.target_port.to_be_bytes());
    tcp[4..8].copy_from_slice(&segment.sequence.to_be_bytes());
    tcp[8..12].copy_from_slice(&segment.acknowledgement.to_be_bytes());
    tcp[12] = 0x50;
    tcp[13] = segment.flags;
    tcp[14..16].copy_from_slice(&65_535u16.to_be_bytes());
    tcp[20..].copy_from_slice(segment.payload);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ParsedTcpReply {
    pub(crate) kind: TcpSynKind,
    pub(crate) acknowledgement: u32,
}

pub(crate) fn parse_tcp_reply(
    data: &[u8],
    from: IpAddr,
    local: IpAddr,
    target: IpAddr,
    source_port: u16,
    target_port: u16,
    sequence: u32,
) -> Option<ParsedTcpReply> {
    let (tcp, has_ip_header) = match target {
        IpAddr::V4(_) => {
            if let Some(((source, destination), tcp)) = strip_ipv4(data, 6)
                && IpAddr::V4(source) == target
                && IpAddr::V4(destination) == local
            {
                (tcp, true)
            } else {
                (data, false)
            }
        }
        IpAddr::V6(_) => {
            if let Some(((source, destination), tcp)) = strip_ipv6(data, 6)
                && IpAddr::V6(source) == target
                && IpAddr::V6(destination) == local
            {
                (tcp, true)
            } else {
                (data, false)
            }
        }
    };
    if from != target
        || (!has_ip_header && data.len() < 20)
        || tcp.len() < 20
        || u16::from_be_bytes([tcp[0], tcp[1]]) != target_port
        || u16::from_be_bytes([tcp[2], tcp[3]]) != source_port
    {
        return None;
    }
    let acknowledgement = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);
    if acknowledgement != sequence.wrapping_add(1) {
        return None;
    }
    let flags = tcp[13];
    let kind = if flags & (TCP_SYN | TCP_ACK) == (TCP_SYN | TCP_ACK) {
        TcpSynKind::Open
    } else if flags & (TCP_RST | TCP_ACK) == (TCP_RST | TCP_ACK) {
        TcpSynKind::Closed
    } else {
        return None;
    };
    Some(ParsedTcpReply {
        kind,
        acknowledgement,
    })
}

pub(crate) fn parse_icmp_error(
    data: &[u8],
    from: IpAddr,
    local: IpAddr,
    target: IpAddr,
    source_port: u16,
    target_port: u16,
) -> Option<TcpSynFailure> {
    match target {
        IpAddr::V4(_) => parse_icmp_error_v4(data, from, local, target, source_port, target_port),
        IpAddr::V6(_) => parse_icmp_error_v6(data, from, local, target, source_port, target_port),
    }
}

fn parse_icmp_error_v4(
    data: &[u8],
    from: IpAddr,
    local: IpAddr,
    target: IpAddr,
    source_port: u16,
    target_port: u16,
) -> Option<TcpSynFailure> {
    let icmp = if data.len() >= 20 && data[0] >> 4 == 4 {
        let ((source, destination), icmp) = strip_ipv4(data, 1)?;
        if IpAddr::V4(source) != from || IpAddr::V4(destination) != local {
            return None;
        }
        icmp
    } else if data.len() >= 8 && matches!(data[0], ICMP_DEST_UNREACH_V4 | ICMP_TIME_EXCEEDED_V4) {
        data
    } else {
        return None;
    };
    if icmp.len() < 8 || !matches!(icmp[0], ICMP_DEST_UNREACH_V4 | ICMP_TIME_EXCEEDED_V4) {
        return None;
    }
    let embedded = &icmp[8..];
    let (source, destination) = parse_ipv4_addresses(embedded)?;
    if IpAddr::V4(source) != local
        || IpAddr::V4(destination) != target
        || embedded.get(9).copied() != Some(6)
    {
        return None;
    }
    let tcp = embedded.get(20..)?;
    if tcp.len() < 4
        || u16::from_be_bytes([tcp[0], tcp[1]]) != source_port
        || u16::from_be_bytes([tcp[2], tcp[3]]) != target_port
    {
        return None;
    }
    Some(TcpSynFailure::Network {
        node: Some(from),
        reason: icmp_reason(false, icmp[0], icmp[1]).to_string(),
    })
}

fn parse_icmp_error_v6(
    data: &[u8],
    from: IpAddr,
    local: IpAddr,
    target: IpAddr,
    source_port: u16,
    target_port: u16,
) -> Option<TcpSynFailure> {
    let icmp = if data.len() >= 40 && data[0] >> 4 == 6 {
        let ((source, destination), icmp) = strip_ipv6(data, 58)?;
        if IpAddr::V6(source) != from || IpAddr::V6(destination) != local {
            return None;
        }
        icmp
    } else if data.len() >= 8 && matches!(data[0], ICMP_DEST_UNREACH_V6 | ICMP_TIME_EXCEEDED_V6) {
        data
    } else {
        return None;
    };
    if !matches!(icmp[0], ICMP_DEST_UNREACH_V6 | ICMP_TIME_EXCEEDED_V6) {
        return None;
    }
    let embedded = &icmp[8..];
    if embedded.len() < 40 {
        return None;
    }
    let source = Ipv6Addr::from(<[u8; 16]>::try_from(&embedded[8..24]).ok()?);
    let destination = Ipv6Addr::from(<[u8; 16]>::try_from(&embedded[24..40]).ok()?);
    if IpAddr::V6(source) != local || IpAddr::V6(destination) != target {
        return None;
    }
    let offset = ipv6_transport_offset(embedded, 6)?;
    let tcp = embedded.get(offset..)?;
    if tcp.len() < 4
        || u16::from_be_bytes([tcp[0], tcp[1]]) != source_port
        || u16::from_be_bytes([tcp[2], tcp[3]]) != target_port
    {
        return None;
    }
    Some(TcpSynFailure::Network {
        node: Some(from),
        reason: icmp_reason(true, icmp[0], icmp[1]).to_string(),
    })
}

fn icmp_reason(v6: bool, kind: u8, code: u8) -> &'static str {
    match (v6, kind, code) {
        (false, ICMP_DEST_UNREACH_V4, 0) | (true, ICMP_DEST_UNREACH_V6, 0) => "network unreachable",
        (false, ICMP_DEST_UNREACH_V4, 1) | (true, ICMP_DEST_UNREACH_V6, 1) => "host unreachable",
        (false, ICMP_DEST_UNREACH_V4, 3) | (true, ICMP_DEST_UNREACH_V6, 4) => "port unreachable",
        (false, ICMP_DEST_UNREACH_V4, 13) => "communication prohibited",
        (false, ICMP_TIME_EXCEEDED_V4, _) | (true, ICMP_TIME_EXCEEDED_V6, _) => "time exceeded",
        _ => "ICMP error",
    }
}

fn strip_ipv4(data: &[u8], protocol: u8) -> Option<((Ipv4Addr, Ipv4Addr), &[u8])> {
    if data.len() < 20 || data[0] >> 4 != 4 || data[9] != protocol {
        return None;
    }
    let header_len = usize::from(data[0] & 0x0f) * 4;
    if header_len < 20 || data.len() < header_len {
        return None;
    }
    let source = Ipv4Addr::new(data[12], data[13], data[14], data[15]);
    let target = Ipv4Addr::new(data[16], data[17], data[18], data[19]);
    Some(((source, target), &data[header_len..]))
}

fn parse_ipv4_addresses(data: &[u8]) -> Option<(Ipv4Addr, Ipv4Addr)> {
    if data.len() < 20 || data[0] >> 4 != 4 {
        return None;
    }
    Some((
        Ipv4Addr::new(data[12], data[13], data[14], data[15]),
        Ipv4Addr::new(data[16], data[17], data[18], data[19]),
    ))
}

fn strip_ipv6(data: &[u8], protocol: u8) -> Option<((Ipv6Addr, Ipv6Addr), &[u8])> {
    if data.len() < 40 || data[0] >> 4 != 6 {
        return None;
    }
    let source = Ipv6Addr::from(<[u8; 16]>::try_from(&data[8..24]).ok()?);
    let target = Ipv6Addr::from(<[u8; 16]>::try_from(&data[24..40]).ok()?);
    let offset = ipv6_transport_offset(data, protocol)?;
    Some(((source, target), &data[offset..]))
}

fn ipv6_transport_offset(payload: &[u8], protocol: u8) -> Option<usize> {
    if payload.len() < 40 || payload[0] >> 4 != 6 {
        return None;
    }
    let mut offset = 40usize;
    let mut next_header = payload[6];
    loop {
        if offset + 8 > payload.len() {
            return None;
        }
        let length = match next_header {
            0 | 43 | 60 => {
                next_header = payload[offset];
                (usize::from(payload[offset + 1]) + 1) * 8
            }
            44 => {
                if u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]) & 0xfff8 != 0 {
                    return None;
                }
                next_header = payload[offset];
                8
            }
            51 => {
                next_header = payload[offset];
                (usize::from(payload[offset + 1]) + 2) * 4
            }
            _ => break,
        };
        offset = offset.checked_add(length)?;
    }
    (next_header == protocol && offset <= payload.len()).then_some(offset)
}

fn words(data: &[u8]) -> u32 {
    data.chunks(2).fold(0, |sum, word| {
        sum + u32::from(u16::from_be_bytes([word[0], *word.get(1).unwrap_or(&0)]))
    })
}

fn pseudo_header(source: &[u8], target: &[u8], transport_length: usize) -> u32 {
    words(source) + words(target) + 6 + transport_length as u32
}

fn finish_checksum(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn domain(v6: bool) -> Domain {
    if v6 { Domain::IPV6 } else { Domain::IPV4 }
}

fn to_local_failure(error: impl ToString) -> TcpSynFailure {
    TcpSynFailure::Local(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_syn_packet_has_valid_lengths_and_headers() {
        let packet = build_tcp_packet(
            "192.0.2.1".parse().unwrap(),
            "198.51.100.2".parse().unwrap(),
            TcpSegment {
                source_port: 40000,
                target_port: 443,
                sequence: 0x12345678,
                acknowledgement: 0,
                flags: TCP_SYN,
                payload: &[],
            },
            64,
        )
        .unwrap();
        assert_eq!(packet.len(), 40);
        assert_eq!(packet[9], 6);
        assert_eq!(&packet[20..22], &40000u16.to_be_bytes());
        assert_eq!(&packet[22..24], &443u16.to_be_bytes());
        assert_eq!(packet[33], TCP_SYN);
        assert_eq!(
            finish_checksum(
                pseudo_header(&[192, 0, 2, 1], &[198, 51, 100, 2], packet[20..].len())
                    + words(&packet[20..])
            ),
            0
        );
    }

    #[test]
    fn ipv6_syn_packet_has_a_transport_header() {
        let packet = build_tcp_packet(
            "2001:db8::1".parse().unwrap(),
            "2001:db8::2".parse().unwrap(),
            TcpSegment {
                source_port: 40000,
                target_port: 443,
                sequence: 0x12345678,
                acknowledgement: 0,
                flags: TCP_SYN,
                payload: &[],
            },
            64,
        )
        .unwrap();
        assert_eq!(packet.len(), 60);
        assert_eq!(packet[0], 0x60);
        assert_eq!(&packet[4..6], &20u16.to_be_bytes());
        assert_eq!(packet[6], 6);
        assert_eq!(packet[53], TCP_SYN);
        assert_eq!(
            finish_checksum(
                pseudo_header(
                    &"2001:db8::1".parse::<Ipv6Addr>().unwrap().octets(),
                    &"2001:db8::2".parse::<Ipv6Addr>().unwrap().octets(),
                    packet[40..].len()
                ) + words(&packet[40..])
            ),
            0
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_filter_matches_the_probe_tuple_and_reply_flags() {
        let filter = reply_filter(
            "192.0.2.10".parse().unwrap(),
            "198.51.100.20".parse().unwrap(),
            40000,
            443,
        );
        assert!(filter.contains("tcp.SrcPort == 443"));
        assert!(filter.contains("tcp.DstPort == 40000"));
        assert!(filter.contains("tcp.SYN and tcp.ACK"));
        assert!(filter.contains("icmp.Type == 3"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_ipv6_raw_payload_contains_only_the_transport_header() {
        let packet = build_tcp_packet(
            "2001:db8::1".parse().unwrap(),
            "2001:db8::2".parse().unwrap(),
            TcpSegment {
                source_port: 40000,
                target_port: 443,
                sequence: 1,
                acknowledgement: 0,
                flags: TCP_SYN,
                payload: &[],
            },
            64,
        )
        .unwrap();
        assert_eq!(
            raw_tcp_payload(&packet, "2001:db8::2".parse().unwrap()).unwrap(),
            &packet[40..]
        );
        assert!(raw_tcp_payload(&packet[..39], "2001:db8::2".parse().unwrap()).is_err());
    }

    #[test]
    fn parses_only_matching_syn_ack_and_reset_replies() {
        let local_ip: Ipv4Addr = "192.0.2.1".parse().unwrap();
        let target_ip: Ipv4Addr = "198.51.100.2".parse().unwrap();
        let local = IpAddr::V4(local_ip);
        let target = IpAddr::V4(target_ip);
        let sequence = 10;
        let packet = tcp_reply_v4(local_ip, target_ip, 443, 40000, sequence + 1, 0x12);
        assert_eq!(
            parse_tcp_reply(&packet, target, local, target, 40000, 443, sequence)
                .unwrap()
                .kind,
            TcpSynKind::Open
        );
        assert_eq!(
            parse_tcp_reply(&packet[20..], target, local, target, 40000, 443, sequence)
                .unwrap()
                .kind,
            TcpSynKind::Open
        );
        let reset = tcp_reply_v4(local_ip, target_ip, 443, 40000, sequence + 1, 0x14);
        assert_eq!(
            parse_tcp_reply(&reset, target, local, target, 40000, 443, sequence)
                .unwrap()
                .kind,
            TcpSynKind::Closed
        );
        assert!(parse_tcp_reply(&packet, target, local, target, 40001, 443, sequence).is_none());
        assert!(
            parse_tcp_reply(&packet, target, local, target, 40000, 443, sequence + 1).is_none()
        );
        let wrong_ack = tcp_reply_v4(local_ip, target_ip, 443, 40000, sequence + 2, 0x12);
        assert!(parse_tcp_reply(&wrong_ack, target, local, target, 40000, 443, sequence).is_none());
    }

    #[test]
    fn ipv6_transport_parser_skips_extension_headers() {
        let source = "2001:db8::1".parse::<Ipv6Addr>().unwrap();
        let target = "2001:db8::2".parse::<Ipv6Addr>().unwrap();
        let mut packet = vec![0u8; 40 + 8 + 20];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&28u16.to_be_bytes());
        packet[6] = 0;
        packet[8..24].copy_from_slice(&source.octets());
        packet[24..40].copy_from_slice(&target.octets());
        packet[40] = 6;

        let ((parsed_source, parsed_target), tcp) = strip_ipv6(&packet, 6).unwrap();
        assert_eq!(parsed_source, source);
        assert_eq!(parsed_target, target);
        assert_eq!(tcp.len(), 20);
    }

    #[test]
    fn parses_matching_ipv4_and_ipv6_icmp_errors() {
        let local_v4 = "192.0.2.1".parse::<Ipv4Addr>().unwrap();
        let target_v4 = "198.51.100.2".parse::<Ipv4Addr>().unwrap();
        let probe_v4 = build_tcp_packet(
            IpAddr::V4(local_v4),
            IpAddr::V4(target_v4),
            TcpSegment {
                source_port: 40000,
                target_port: 443,
                sequence: 1,
                acknowledgement: 0,
                flags: TCP_SYN,
                payload: &[],
            },
            64,
        )
        .unwrap();
        let mut icmp_v4 = vec![ICMP_TIME_EXCEEDED_V4, 0, 0, 0, 0, 0, 0, 0];
        icmp_v4.extend_from_slice(&probe_v4);
        let router_v4 = Ipv4Addr::new(203, 0, 113, 1);
        let outer_v4 = ipv4_icmp_packet(router_v4, local_v4, &icmp_v4);
        assert_network_error(
            parse_icmp_error(
                &outer_v4,
                IpAddr::V4(router_v4),
                IpAddr::V4(local_v4),
                IpAddr::V4(target_v4),
                40000,
                443,
            ),
            router_v4.into(),
        );
        assert_network_error(
            parse_icmp_error(
                &icmp_v4,
                IpAddr::V4(router_v4),
                IpAddr::V4(local_v4),
                IpAddr::V4(target_v4),
                40000,
                443,
            ),
            router_v4.into(),
        );

        let local_v6 = "2001:db8::1".parse::<Ipv6Addr>().unwrap();
        let target_v6 = "2001:db8::2".parse::<Ipv6Addr>().unwrap();
        let probe_v6 = build_tcp_packet(
            IpAddr::V6(local_v6),
            IpAddr::V6(target_v6),
            TcpSegment {
                source_port: 40000,
                target_port: 443,
                sequence: 1,
                acknowledgement: 0,
                flags: TCP_SYN,
                payload: &[],
            },
            64,
        )
        .unwrap();
        let mut icmp_v6 = vec![ICMP_TIME_EXCEEDED_V6, 0, 0, 0, 0, 0, 0, 0];
        icmp_v6.extend_from_slice(&probe_v6);
        let router_v6 = "2001:db8::ff".parse::<Ipv6Addr>().unwrap();
        assert_network_error(
            parse_icmp_error(
                &icmp_v6,
                IpAddr::V6(router_v6),
                IpAddr::V6(local_v6),
                IpAddr::V6(target_v6),
                40000,
                443,
            ),
            router_v6.into(),
        );
    }

    fn assert_network_error(failure: Option<TcpSynFailure>, expected: IpAddr) {
        match failure.expect("matching ICMP error") {
            TcpSynFailure::Network {
                node: Some(node),
                reason,
            } => {
                assert_eq!(node, expected);
                assert_eq!(reason, "time exceeded");
            }
            other => panic!("unexpected failure: {other:?}"),
        }
    }

    fn ipv4_icmp_packet(source: Ipv4Addr, target: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 1;
        packet[12..16].copy_from_slice(&source.octets());
        packet[16..20].copy_from_slice(&target.octets());
        packet.extend_from_slice(payload);
        packet
    }

    fn tcp_reply_v4(
        local: Ipv4Addr,
        target: Ipv4Addr,
        source_port: u16,
        target_port: u16,
        acknowledgement: u32,
        flags: u8,
    ) -> Vec<u8> {
        let mut packet = vec![0; 40];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&40u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&target.octets());
        packet[16..20].copy_from_slice(&local.octets());
        packet[20..22].copy_from_slice(&source_port.to_be_bytes());
        packet[22..24].copy_from_slice(&target_port.to_be_bytes());
        packet[24..28].copy_from_slice(&100u32.to_be_bytes());
        packet[28..32].copy_from_slice(&acknowledgement.to_be_bytes());
        packet[32] = 0x50;
        packet[33] = flags;
        packet
    }
}
