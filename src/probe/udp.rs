use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::io::unix::AsyncFd;

use super::udp_error::{self, IcmpError, UdpIcmpError};
pub(crate) use super::udp_error::{UdpProbeFailure, UdpProbeKind, UdpProbeReply};

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
                    let Some(error) = udp_error::parse_icmp_error(
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

#[cfg(not(target_os = "linux"))]
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
    match udp_error::classify_icmp(error, target) {
        UdpIcmpError::PortUnreachable => ReceiveEvent::PortUnreachable,
        UdpIcmpError::Network { node, reason } => ReceiveEvent::Network { node, reason },
    }
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
                let node = {
                    let address = unsafe { libc::SO_EE_OFFENDER(error) };
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

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

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
}
