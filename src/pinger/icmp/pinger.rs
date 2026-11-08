use crate::pinger::Pinger;
use crate::pinger::icmp::client::IcmpClient;
use crate::pinger::icmp_packet::IcmpPacket;
use crate::session::{PingResult, ProbeStatus, ResponseType};
use async_trait::async_trait;
use socket2::Type;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

pub struct IcmpPinger {
    target_name: String,
    target: IpAddr,
    id: u16,
    size: usize,
    timeout: Duration,
    client: Arc<IcmpClient>,
}

impl IcmpPinger {
    pub fn new(
        target_name: String,
        target: IpAddr,
        _ttl: u32,
        size: usize,
        timeout: Duration,
        client: Arc<IcmpClient>,
    ) -> Self {
        let id = (std::process::id() % u16::MAX as u32) as u16;
        Self {
            target_name,
            target,
            id,
            size,
            timeout,
            client,
        }
    }
}

struct ReplyRegistration {
    client: Arc<IcmpClient>,
    target: IpAddr,
    ident: Option<u16>,
    seq: u16,
    armed: bool,
}

impl ReplyRegistration {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ReplyRegistration {
    fn drop(&mut self) {
        if self.armed {
            self.client.unregister(self.target, self.ident, self.seq);
        }
    }
}

#[async_trait]
impl Pinger for IcmpPinger {
    async fn probe(&self, seq: u64) -> PingResult {
        let wire_seq = self.client.next_sequence();
        let payload = vec![0u8; self.size];

        let ident_hint = self.id;

        let ident_key = if self.client.get_socket().get_type() == Type::DGRAM {
            None
        } else {
            Some(ident_hint)
        };

        let rx = self.client.register(self.target, ident_key, wire_seq);
        let mut registration = ReplyRegistration {
            client: self.client.clone(),
            target: self.target,
            ident: ident_key,
            seq: wire_seq,
            armed: true,
        };

        let packet = IcmpPacket::new_request(self.target.is_ipv6(), ident_hint, wire_seq, payload);
        let encoded = packet.encode();
        let sock_addr = SocketAddr::new(self.target, 0);

        if let Err(e) = self.client.get_socket().send_to(&encoded, &sock_addr).await {
            self.client.unregister(self.target, ident_key, wire_seq);
            registration.disarm();
            return PingResult {
                target: self.target_name.clone(),
                target_addr: self.target,
                seq,
                bytes: 0,
                ttl: None,
                rtt: Duration::ZERO,
                status: ProbeStatus::LocalError(e.to_string()),
            };
        }

        let start = std::time::Instant::now();
        match tokio::time::timeout(self.timeout, rx).await {
            Ok(Ok(reply)) => {
                registration.disarm();
                PingResult {
                    target: self.target_name.clone(),
                    target_addr: self.target,
                    seq,
                    bytes: self.size,
                    ttl: reply.ttl,
                    rtt: reply.timestamp.duration_since(start),
                    status: ProbeStatus::Success(ResponseType::IcmpEchoReply),
                }
            }
            Ok(Err(_)) => {
                registration.disarm();
                PingResult {
                    target: self.target_name.clone(),
                    target_addr: self.target,
                    seq,
                    bytes: 0,
                    ttl: None,
                    rtt: Duration::ZERO,
                    status: ProbeStatus::LocalError("receiver closed".into()),
                }
            }
            Err(_) => PingResult {
                target: self.target_name.clone(),
                target_addr: self.target,
                seq,
                bytes: 0,
                ttl: None,
                rtt: Duration::ZERO,
                status: ProbeStatus::Timeout,
            },
        }
    }
}
