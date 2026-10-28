use socket2::{Domain, Protocol, Socket, Type};
use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::io::unix::AsyncFd;

const ICMP_DEST_UNREACH_V4: u8 = 3;
const ICMP_TIME_EXCEEDED_V4: u8 = 11;
const ICMP_DEST_UNREACH_V6: u8 = 1;
const ICMP_TIME_EXCEEDED_V6: u8 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UdpProbeKind {
    ApplicationReply,
    PortUnreachable,
}

#[derive(Clone, Copy, Debug)]
pub struct UdpProbeReply {
    pub kind: UdpProbeKind,
    pub bytes: usize,
    pub rtt: Duration,
}

#[derive(Clone, Debug)]
pub enum UdpProbeFailure {
    Timeout,
    Network {
        node: Option<IpAddr>,
        reason: String,
    },
    Local(String),
}

impl fmt::Display for UdpProbeFailure {
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

pub async fn probe(
    target: IpAddr,
    port: u16,
    payload_size: usize,
    timeout: Duration,
    ttl: u32,
) -> Result<UdpProbeReply, UdpProbeFailure> {
    let ttl = u8::try_from(ttl)
        .map_err(|_| UdpProbeFailure::Local("TTL must be between 0 and 255".to_string()))?;
    let sockets = UdpProbeSockets::new(target, port, ttl).map_err(to_local_failure)?;
    let source_port = sockets.local_addr().map_err(to_local_failure)?.port();
    let payload = vec![0u8; payload_size];
    let started = Instant::now();
    sockets.send(&payload).await.map_err(to_local_failure)?;
    let deadline = tokio::time::sleep(timeout);
    tokio::pin!(deadline);
    let mut application_buffer = vec![0u8; 65_535];
    let mut icmp_buffer = vec![0u8; 65_535];

    tokio::select! {
        received = sockets.recv(
            &mut application_buffer,
            &mut icmp_buffer,
            target,
            source_port,
            port,
        ) => {
            match received.map_err(to_local_failure)? {
                ReceiveEvent::ApplicationReply(bytes) => Ok(UdpProbeReply {
                    kind: UdpProbeKind::ApplicationReply,
                    bytes,
                    rtt: started.elapsed(),
                }),
                ReceiveEvent::PortUnreachable => Ok(UdpProbeReply {
                    kind: UdpProbeKind::PortUnreachable,
                    bytes: 0,
                    rtt: started.elapsed(),
                }),
                ReceiveEvent::Network { node, reason } => {
                    Err(UdpProbeFailure::Network { node, reason })
                }
            }
        }
        _ = &mut deadline => Err(UdpProbeFailure::Timeout),
    }
}

#[derive(Clone, Debug)]
struct IcmpError {
    v6: bool,
    node: Option<IpAddr>,
    kind: u8,
    code: u8,
}

enum ReceiveEvent {
    ApplicationReply(usize),
    PortUnreachable,
    Network {
        node: Option<IpAddr>,
        reason: String,
    },
}

struct UdpProbeSockets {
    udp: AsyncFd<std::net::UdpSocket>,
    #[cfg(not(target_os = "linux"))]
    icmp: AsyncFd<std::net::UdpSocket>,
}

impl UdpProbeSockets {
    fn new(target: IpAddr, port: u16, ttl: u8) -> io::Result<Self> {
        let v6 = target.is_ipv6();
        let udp = Socket::new(domain(v6), Type::DGRAM, Some(Protocol::UDP))?;
        bind_device(&udp, v6)?;
        set_ttl(&udp, v6, ttl)?;
        #[cfg(target_os = "linux")]
        enable_error_queue(&udp, v6)?;
        udp.set_nonblocking(true)?;
        let udp: std::net::UdpSocket = udp.into();
        udp.connect(SocketAddr::new(target, port))?;

        #[cfg(not(target_os = "linux"))]
        let icmp = raw_icmp_socket(v6)?;
        Ok(Self {
            udp: unsafe { AsyncFd::register(udp) }?,
            #[cfg(not(target_os = "linux"))]
            icmp: unsafe { AsyncFd::register(icmp) }?,
        })
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.udp.get_ref().local_addr()
    }

    async fn send(&self, payload: &[u8]) -> io::Result<()> {
        loop {
            let mut guard = self.udp.writable().await?;
            match guard.try_io(|inner| inner.get_ref().send(payload).map(|_| ())) {
                Ok(result) => return result,
                Err(_) => continue,
            }
        }
    }

    #[cfg(target_os = "linux")]
    async fn recv(
        &self,
        application: &mut [u8],
        _icmp: &mut [u8],
        target: IpAddr,
        _source_port: u16,
        _target_port: u16,
    ) -> io::Result<ReceiveEvent> {
        loop {
            let mut guard = self
                .udp
                .ready(tokio::io::Interest::READABLE | tokio::io::Interest::ERROR)
                .await?;
            match guard.try_io(|inner| {
                match recv_error(inner.get_ref()) {
                    Ok(Some(error)) => return Ok(Some(classify_icmp(error, target))),
                    Ok(None) => {}
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) => return Err(error),
                }
                inner
                    .get_ref()
                    .recv(application)
                    .map(|bytes| Some(ReceiveEvent::ApplicationReply(bytes)))
            }) {
                Ok(Ok(Some(event))) => return Ok(event),
                Ok(Ok(None)) | Err(_) => continue,
                Ok(Err(error))
                    if matches!(
                        error.kind(),
                        io::ErrorKind::ConnectionRefused
                            | io::ErrorKind::HostUnreachable
                            | io::ErrorKind::NetworkUnreachable
                    ) =>
                {
                    guard.clear_ready();
                    continue;
                }
                Ok(Err(error)) => return Err(error),
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    async fn recv(
        &self,
        application: &mut [u8],
        icmp_data: &mut [u8],
        target: IpAddr,
        source_port: u16,
        target_port: u16,
    ) -> io::Result<ReceiveEvent> {
        loop {
            tokio::select! {
                ready = self.udp.readable() => {
                    let mut guard = ready?;
                    match guard.try_io(|inner| inner.get_ref().recv(application)) {
                        Ok(Ok(bytes)) => return Ok(ReceiveEvent::ApplicationReply(bytes)),
                        Ok(Err(error))
                            if matches!(
                                error.kind(),
                                io::ErrorKind::ConnectionRefused
                                    | io::ErrorKind::HostUnreachable
                                    | io::ErrorKind::NetworkUnreachable
                            ) => {
                                guard.clear_ready();
                                continue;
                            }
                        Ok(Err(error)) => return Err(error),
                        Err(_) => continue,
                    }
                }
                received = recv_from(&self.icmp, icmp_data) => {
                    let (size, from) = received?;
                    let Some(error) = parse_icmp_error(
                        &icmp_data[..size],
                        from,
                        self.local_addr()?.ip(),
                        target,
                        source_port,
                        target_port,
                    ) else { continue };
                    return Ok(classify_icmp(error, target));
                }
            }
        }
    }
}

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

fn classify_icmp(error: IcmpError, target: IpAddr) -> ReceiveEvent {
    match (error.v6, error.kind, error.code) {
        (false, ICMP_DEST_UNREACH_V4, 3) | (true, ICMP_DEST_UNREACH_V6, 4)
            if error.node == Some(target) =>
        {
            ReceiveEvent::PortUnreachable
        }
        _ => ReceiveEvent::Network {
            node: error.node,
            reason: icmp_reason(error.v6, error.kind, error.code).to_string(),
        },
    }
}

fn parse_icmp_error(
    data: &[u8],
    from: IpAddr,
    local: IpAddr,
    target: IpAddr,
    source_port: u16,
    target_port: u16,
) -> Option<IcmpError> {
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
) -> Option<IcmpError> {
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
        || embedded.get(9).copied() != Some(17)
    {
        return None;
    }
    let header_len = usize::from(embedded[0] & 0x0f) * 4;
    if header_len < 20 {
        return None;
    }
    let udp = embedded.get(header_len..)?;
    if udp.len() < 8
        || u16::from_be_bytes([udp[0], udp[1]]) != source_port
        || u16::from_be_bytes([udp[2], udp[3]]) != target_port
    {
        return None;
    }
    Some(IcmpError {
        v6: false,
        node: Some(from),
        kind: icmp[0],
        code: icmp[1],
    })
}

fn parse_icmp_error_v6(
    data: &[u8],
    from: IpAddr,
    local: IpAddr,
    target: IpAddr,
    source_port: u16,
    target_port: u16,
) -> Option<IcmpError> {
    if data.len() < 8 || !matches!(data[0], ICMP_DEST_UNREACH_V6 | ICMP_TIME_EXCEEDED_V6) {
        return None;
    }
    let embedded = &data[8..];
    if embedded.len() < 40 {
        return None;
    }
    let source = Ipv6Addr::from(<[u8; 16]>::try_from(&embedded[8..24]).ok()?);
    let destination = Ipv6Addr::from(<[u8; 16]>::try_from(&embedded[24..40]).ok()?);
    if IpAddr::V6(source) != local || IpAddr::V6(destination) != target {
        return None;
    }
    let offset = ipv6_transport_offset(embedded, 17)?;
    let udp = embedded.get(offset..)?;
    if udp.len() < 8
        || u16::from_be_bytes([udp[0], udp[1]]) != source_port
        || u16::from_be_bytes([udp[2], udp[3]]) != target_port
    {
        return None;
    }
    Some(IcmpError {
        v6: true,
        node: Some(from),
        kind: data[0],
        code: data[1],
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
    Some((
        (
            Ipv4Addr::new(data[12], data[13], data[14], data[15]),
            Ipv4Addr::new(data[16], data[17], data[18], data[19]),
        ),
        &data[header_len..],
    ))
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

fn set_ttl(socket: &Socket, v6: bool, ttl: u8) -> io::Result<()> {
    if v6 {
        socket.set_unicast_hops_v6(u32::from(ttl))
    } else {
        socket.set_ttl_v4(u32::from(ttl))
    }
}

fn bind_device(socket: &Socket, v6: bool) -> io::Result<()> {
    if let Some(interface) = crate::utils::get_bind_interface() {
        crate::utils::bind_socket_to_interface(socket, interface, v6)?;
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn raw_icmp_socket(v6: bool) -> io::Result<std::net::UdpSocket> {
    let protocol = if v6 {
        Protocol::ICMPV6
    } else {
        Protocol::ICMPV4
    };
    let socket = Socket::new(domain(v6), Type::RAW, Some(protocol)).map_err(|error| {
        if error.kind() == io::ErrorKind::PermissionDenied {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "UDP ICMP error capture requires root privileges on macOS; run with sudo",
            )
        } else {
            error
        }
    })?;
    bind_device(&socket, v6)?;
    socket.set_nonblocking(true)?;
    Ok(socket.into())
}

#[cfg(target_os = "linux")]
fn enable_error_queue(socket: &Socket, v6: bool) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    let on: libc::c_int = 1;
    let (level, option) = if v6 {
        (libc::IPPROTO_IPV6, libc::IPV6_RECVERR)
    } else {
        (libc::IPPROTO_IP, libc::IP_RECVERR)
    };
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            option,
            &on as *const _ as *const libc::c_void,
            std::mem::size_of_val(&on) as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(target_os = "linux")]
fn recv_error(socket: &std::net::UdpSocket) -> io::Result<Option<IcmpError>> {
    use socket2::{SockAddr, SockAddrStorage};
    use std::os::fd::AsRawFd;

    let fd = socket.as_raw_fd();
    let mut data = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: data.as_mut_ptr().cast(),
        iov_len: data.len(),
    };
    let mut control = [0usize; 64];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = std::mem::size_of_val(&control);
    let size = unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_ERRQUEUE) };
    if size < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut result = None;
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    while !cmsg.is_null() {
        let header = unsafe { &*cmsg };
        if (header.cmsg_level == libc::IPPROTO_IP && header.cmsg_type == libc::IP_RECVERR)
            || (header.cmsg_level == libc::IPPROTO_IPV6 && header.cmsg_type == libc::IPV6_RECVERR)
        {
            let error = unsafe { &*(libc::CMSG_DATA(cmsg) as *const libc::sock_extended_err) };
            let v6 = error.ee_origin == libc::SO_EE_ORIGIN_ICMP6;
            if error.ee_origin == libc::SO_EE_ORIGIN_ICMP
                || error.ee_origin == libc::SO_EE_ORIGIN_ICMP6
            {
                let node = unsafe {
                    let address = libc::SO_EE_OFFENDER(error);
                    if address.is_null() {
                        None
                    } else {
                        let len = match unsafe { (*address).sa_family } as i32 {
                            libc::AF_INET => std::mem::size_of::<libc::sockaddr_in>(),
                            libc::AF_INET6 => std::mem::size_of::<libc::sockaddr_in6>(),
                            _ => 0,
                        };
                        if len == 0 {
                            None
                        } else {
                            let storage: SockAddrStorage =
                                unsafe { std::ptr::read_unaligned(address.cast()) };
                            let address = unsafe { SockAddr::new(storage, len as libc::socklen_t) };
                            address.as_socket().map(|address| address.ip())
                        }
                    }
                };
                result = Some(IcmpError {
                    v6,
                    node,
                    kind: error.ee_type,
                    code: error.ee_code,
                });
            }
        }
        cmsg = unsafe { libc::CMSG_NXTHDR(&msg, cmsg) };
    }
    Ok(result)
}

fn domain(v6: bool) -> Domain {
    if v6 { Domain::IPV6 } else { Domain::IPV4 }
}

fn to_local_failure(error: impl ToString) -> UdpProbeFailure {
    UdpProbeFailure::Local(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_and_ipv6_icmp_errors() {
        let local_v4 = "192.0.2.1".parse::<Ipv4Addr>().unwrap();
        let target_v4 = "198.51.100.2".parse::<Ipv4Addr>().unwrap();
        let router_v4 = Ipv4Addr::new(203, 0, 113, 1);
        let embedded_v4 = ipv4_udp_packet(local_v4, target_v4, 40000, 33434);
        let icmp_v4 = icmp_error(ICMP_DEST_UNREACH_V4, 3, &embedded_v4);
        let outer_v4 = ipv4_packet(target_v4, local_v4, 1, &icmp_v4);
        assert!(matches!(
            classify_icmp(
                parse_icmp_error(
                    &outer_v4,
                    IpAddr::V4(target_v4),
                    IpAddr::V4(local_v4),
                    IpAddr::V4(target_v4),
                    40000,
                    33434
                )
                .unwrap(),
                IpAddr::V4(target_v4)
            ),
            ReceiveEvent::PortUnreachable
        ));
        let router_icmp = ipv4_packet(router_v4, local_v4, 1, &icmp_v4);
        let router_error = parse_icmp_error(
            &router_icmp,
            IpAddr::V4(router_v4),
            IpAddr::V4(local_v4),
            IpAddr::V4(target_v4),
            40000,
            33434,
        )
        .unwrap();
        assert!(matches!(
            classify_icmp(router_error, IpAddr::V4(target_v4)),
            ReceiveEvent::Network {
                node: Some(node),
                ..
            } if node == IpAddr::V4(router_v4)
        ));

        let local_v6 = "2001:db8::1".parse::<Ipv6Addr>().unwrap();
        let target_v6 = "2001:db8::2".parse::<Ipv6Addr>().unwrap();
        let router_v6 = "2001:db8::ff".parse::<Ipv6Addr>().unwrap();
        let embedded_v6 = ipv6_udp_packet(local_v6, target_v6, 40000, 33434);
        let icmp_v6 = icmp_error(ICMP_TIME_EXCEEDED_V6, 0, &embedded_v6);
        let error = parse_icmp_error(
            &icmp_v6,
            IpAddr::V6(router_v6),
            IpAddr::V6(local_v6),
            IpAddr::V6(target_v6),
            40000,
            33434,
        )
        .unwrap();
        match classify_icmp(error, IpAddr::V6(target_v6)) {
            ReceiveEvent::Network { node, reason } => {
                assert_eq!(node, Some(router_v6.into()));
                assert_eq!(reason, "time exceeded");
            }
            _ => panic!("expected a network error"),
        }
    }

    #[test]
    fn rejects_icmp_errors_for_other_udp_probes() {
        let local = "192.0.2.1".parse().unwrap();
        let target = "198.51.100.2".parse().unwrap();
        let router = "203.0.113.1".parse().unwrap();
        let embedded = ipv4_udp_packet(local, target, 40000, 33434);
        let icmp = icmp_error(ICMP_DEST_UNREACH_V4, 3, &embedded);
        let packet = ipv4_packet(router, local, 1, &icmp);
        assert!(
            parse_icmp_error(
                &packet,
                router.into(),
                local.into(),
                target.into(),
                40001,
                33434
            )
            .is_none()
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn receives_an_application_reply() {
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = server.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut buffer = [0; 64];
            let (size, peer) = server.recv_from(&mut buffer).await.unwrap();
            server.send_to(&buffer[..size], peer).await.unwrap();
        });

        let reply = probe(
            "127.0.0.1".parse().unwrap(),
            port,
            4,
            Duration::from_secs(1),
            64,
        )
        .await
        .unwrap();
        assert_eq!(reply.kind, UdpProbeKind::ApplicationReply);
        assert_eq!(reply.bytes, 4);
    }

    fn icmp_error(kind: u8, code: u8, embedded: &[u8]) -> Vec<u8> {
        let mut icmp = vec![kind, code, 0, 0, 0, 0, 0, 0];
        icmp.extend_from_slice(embedded);
        icmp
    }

    fn ipv4_packet(source: Ipv4Addr, target: Ipv4Addr, protocol: u8, payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = protocol;
        packet[12..16].copy_from_slice(&source.octets());
        packet[16..20].copy_from_slice(&target.octets());
        packet.extend_from_slice(payload);
        packet
    }

    fn ipv4_udp_packet(
        source: Ipv4Addr,
        target: Ipv4Addr,
        source_port: u16,
        target_port: u16,
    ) -> Vec<u8> {
        let mut udp = vec![0u8; 8];
        udp[0..2].copy_from_slice(&source_port.to_be_bytes());
        udp[2..4].copy_from_slice(&target_port.to_be_bytes());
        udp[4..6].copy_from_slice(&8u16.to_be_bytes());
        ipv4_packet(source, target, 17, &udp)
    }

    fn ipv6_udp_packet(
        source: Ipv6Addr,
        target: Ipv6Addr,
        source_port: u16,
        target_port: u16,
    ) -> Vec<u8> {
        let mut packet = vec![0u8; 48];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&8u16.to_be_bytes());
        packet[6] = 17;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&source.octets());
        packet[24..40].copy_from_slice(&target.octets());
        packet[40..42].copy_from_slice(&source_port.to_be_bytes());
        packet[42..44].copy_from_slice(&target_port.to_be_bytes());
        packet[44..46].copy_from_slice(&8u16.to_be_bytes());
        packet
    }
}
