use super::udp_error::{self, UdpIcmpError, UdpProbeFailure, UdpProbeKind, UdpProbeReply};
use crate::windivert::{Capture, packet_source};
use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

pub(crate) async fn probe(
    target: IpAddr,
    port: u16,
    payload_size: usize,
    timeout: Duration,
    ttl: u32,
) -> Result<UdpProbeReply, UdpProbeFailure> {
    udp_error::validate_payload_size(payload_size)?;
    let ttl = u8::try_from(ttl)
        .map_err(|_| UdpProbeFailure::Local("TTL must be between 0 and 255".to_string()))?;
    let v6 = target.is_ipv6();
    let socket =
        Socket::new(domain(v6), Type::DGRAM, Some(Protocol::UDP)).map_err(to_local_failure)?;
    if v6 {
        socket
            .set_unicast_hops_v6(u32::from(ttl))
            .map_err(to_local_failure)?;
    } else {
        socket
            .set_ttl_v4(u32::from(ttl))
            .map_err(to_local_failure)?;
    }
    socket.set_nonblocking(true).map_err(to_local_failure)?;
    socket
        .bind(&SocketAddr::new(unspecified(v6), 0).into())
        .map_err(to_local_failure)?;
    let socket: std::net::UdpSocket = socket.into();
    socket
        .connect(SocketAddr::new(target, port))
        .map_err(to_local_failure)?;
    let local = socket.local_addr().map_err(to_local_failure)?;
    let source_port = local.port();
    let local = local.ip();
    let socket = tokio::net::UdpSocket::from_std(socket).map_err(to_local_failure)?;
    let capture = Capture::open(&icmp_filter(local, target)).map_err(to_local_failure)?;
    let payload = vec![0u8; payload_size];
    let started = Instant::now();
    socket.send(&payload).await.map_err(to_local_failure)?;
    let mut application = vec![0u8; 65_535];

    loop {
        let remaining = timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            break;
        }
        tokio::select! {
            received = socket.recv(&mut application) => {
                match received {
                    Ok(bytes) => {
                        return Ok(UdpProbeReply {
                            kind: UdpProbeKind::ApplicationReply,
                            bytes,
                            rtt: started.elapsed(),
                        });
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::ConnectionRefused | io::ErrorKind::ConnectionReset
                        ) =>
                    {
                        return Ok(UdpProbeReply {
                            kind: UdpProbeKind::PortUnreachable,
                            bytes: 0,
                            rtt: started.elapsed(),
                        });
                    }
                    Err(error) => return Err(to_local_failure(error)),
                }
            }
            received = capture.recv(remaining) => {
                let packet = match received {
                    Ok(packet) => packet,
                    Err(error) if error.kind() == io::ErrorKind::TimedOut => break,
                    Err(error) => return Err(to_local_failure(error)),
                };
                let Some(from) = packet_source(&packet.data) else { continue };
                let Some(error) = udp_error::parse_icmp_error(
                    &packet.data,
                    from,
                    local,
                    target,
                    source_port,
                    port,
                ) else { continue };
                match udp_error::classify_icmp(error, target) {
                    UdpIcmpError::PortUnreachable => {
                        return Ok(UdpProbeReply {
                            kind: UdpProbeKind::PortUnreachable,
                            bytes: 0,
                            rtt: started.elapsed(),
                        });
                    }
                    UdpIcmpError::Network { node, reason } => {
                        return Err(UdpProbeFailure::Network { node, reason });
                    }
                }
            }
        }
    }
    Err(UdpProbeFailure::Timeout)
}

fn icmp_filter(local: IpAddr, target: IpAddr) -> String {
    if target.is_ipv4() {
        format!(
            "(inbound or loopback) and icmp and ip.DstAddr == {local} and (icmp.Type == 3 or icmp.Type == 11)"
        )
    } else {
        format!(
            "(inbound or loopback) and icmpv6 and ipv6.DstAddr == {local} and (icmpv6.Type == 1 or icmpv6.Type == 3)"
        )
    }
}

fn domain(v6: bool) -> Domain {
    if v6 { Domain::IPV6 } else { Domain::IPV4 }
}

fn unspecified(v6: bool) -> IpAddr {
    if v6 {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    } else {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    }
}

fn to_local_failure(error: impl ToString) -> UdpProbeFailure {
    UdpProbeFailure::Local(error.to_string())
}
