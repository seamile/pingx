use crate::pinger::Pinger;
use crate::session::{PingResult, ProbeStatus};
use anyhow::{Context, Result};
use async_trait::async_trait;
use pnet_packet::Packet;
use pnet_packet::icmp::echo_reply::EchoReplyPacket;
use pnet_packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet_packet::icmp::{IcmpCode, IcmpTypes};
use socket2::{Domain, Protocol as SocketProtocol, Socket, Type};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

pub struct IcmpPinger {
    target: IpAddr,
    socket: Option<UdpSocket>,
    id: u16,
    ttl: u32,
    size: usize,
    timeout: Duration,
}

impl IcmpPinger {
    pub fn new(target: IpAddr, ttl: u32, size: usize, timeout: Duration) -> Self {
        // Use process ID as identifier (standard practice), folded to u16
        let id = (std::process::id() % u16::MAX as u32) as u16;
        Self {
            target,
            socket: None,
            id,
            ttl,
            size,
            timeout,
        }
    }

    fn create_socket(&self) -> Result<UdpSocket> {
        let domain = match self.target {
            IpAddr::V4(_) => Domain::IPV4,
            IpAddr::V6(_) => Domain::IPV6,
        };

        // Try unprivileged first (DGRAM + ICMP)
        // Note: variable 'socket' was shadowed in previous code, fixing logic here.
        let socket = match Socket::new(domain, Type::DGRAM, Some(SocketProtocol::ICMPV4)) {
            Ok(s) => s,
            Err(_) => {
                // Try RAW
                match Socket::new(domain, Type::RAW, Some(SocketProtocol::ICMPV4)) {
                    Ok(s) => s,
                    Err(e) => {
                        return Err(anyhow::anyhow!(
                            "Failed to create ICMP socket (tried DGRAM and RAW). Permission denied? Error: {}",
                            e
                        ));
                    }
                }
            }
        };

        socket.set_ttl(self.ttl).context("Failed to set TTL")?;

        socket.set_nonblocking(true)?;

        let std_socket: std::net::UdpSocket = socket.into();
        UdpSocket::from_std(std_socket).context("Failed to create tokio UdpSocket")
    }
}

#[async_trait]
impl Pinger for IcmpPinger {
    async fn start(&mut self) -> Result<()> {
        self.socket = Some(self.create_socket()?);
        Ok(())
    }

    async fn ping(&mut self, seq: u64) -> Result<PingResult> {
        let socket = self
            .socket
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Socket not initialized"))?;

        // Prepare buffer
        let mut buf = vec![0u8; self.size + 8]; // 8 bytes header + payload
        let mut packet = MutableEchoRequestPacket::new(&mut buf)
            .ok_or_else(|| anyhow::anyhow!("Failed to create packet"))?;

        packet.set_icmp_type(IcmpTypes::EchoRequest);
        packet.set_icmp_code(IcmpCode::new(0));
        packet.set_sequence_number(seq as u16);
        packet.set_identifier(self.id);

        let checksum = pnet_packet::util::checksum(packet.packet(), 1);
        packet.set_checksum(checksum);

        let dest = SocketAddr::new(self.target, 0);
        let start = Instant::now();

        socket
            .send_to(packet.packet(), dest)
            .await
            .context("Failed to send packet")?;

        // Receive loop to filter our packet
        let mut recv_buf = vec![0u8; 1024];
        let timeout = self.timeout;

        let result: Result<(usize, Duration)> = tokio::select! {
            res = async {
                loop {
                    let (len, _addr) = socket.recv_from(&mut recv_buf).await?;

                    // Simple parsing using EchoReplyPacket
                    if let Some(reply) = EchoReplyPacket::new(&recv_buf[..len]) {
                         if reply.get_icmp_type() == IcmpTypes::EchoReply && reply.get_identifier() == self.id && reply.get_sequence_number() == seq as u16 {
                             return Ok((len, start.elapsed()));
                         }
                    }
                }
            } => res,
            _ = tokio::time::sleep(timeout) => {
                Ok((0, timeout)) // Timeout marker
            }
        };

        match result {
            Ok((len, rtt)) if len > 0 => {
                Ok(PingResult {
                    target_addr: self.target,
                    seq,
                    bytes: len,
                    ttl: None, // Hard to get TTL from UdpSocket recv_from without cmsg
                    rtt,
                    status: ProbeStatus::Success,
                })
            }
            Ok((_, _)) => Ok(PingResult {
                target_addr: self.target,
                seq,
                bytes: 0,
                ttl: None,
                rtt: Duration::ZERO,
                status: ProbeStatus::Timeout,
            }),
            Err(e) => Ok(PingResult {
                target_addr: self.target,
                seq,
                bytes: 0,
                ttl: None,
                rtt: Duration::ZERO,
                status: ProbeStatus::Error(e.to_string()),
            }),
        }
    }

    async fn stop(&mut self) -> Result<()> {
        self.socket = None;
        Ok(())
    }
}
