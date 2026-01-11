use crate::pinger::Pinger;
use crate::pinger::icmp_packet::{IcmpPacket};
use crate::session::{PingResult, ProbeStatus};
use anyhow::Result;
use async_trait::async_trait;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex};
use crate::pinger::icmp::client::{IcmpClient};
use socket2::Type;

pub struct IcmpPinger {
    target_name: String,
    target: IpAddr,
    id: u16,
    size: usize,
    timeout: Duration,
    client: Arc<IcmpClient>,
    result_tx: Arc<Mutex<Option<mpsc::Sender<PingResult>>>>,
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
            result_tx: Arc::new(Mutex::new(None)),
        }
    }

    async fn send_result(&self, res: PingResult) {
        let guard = self.result_tx.lock().await;
        if let Some(tx) = guard.as_ref() {
            let _ = tx.send(res).await;
        }
    }
}

#[async_trait]
impl Pinger for IcmpPinger {
    async fn start(&mut self, tx: mpsc::Sender<PingResult>) -> Result<()> {
        let mut guard = self.result_tx.lock().await;
        *guard = Some(tx);
        Ok(())
    }

    async fn ping(&self, seq: u64) -> Result<()> {
        let seq_u16 = seq as u16;
        let payload = vec![0u8; self.size];
        
        let ident_hint = self.id;
        
        let ident_key = if self.client.get_socket().get_type() == Type::DGRAM {
            None
        } else {
            Some(ident_hint)
        };
        
        let rx = self.client.register(self.target, ident_key, seq_u16);

        let packet = IcmpPacket::new_request(self.target.is_ipv6(), ident_hint, seq_u16, payload);
        let encoded = packet.encode();
        let sock_addr = SocketAddr::new(self.target, 0);

        if let Err(e) = self.client.get_socket().send_to(&encoded, &sock_addr).await {
            self.client.unregister(self.target, ident_key, seq_u16);
             self.send_result(PingResult {
                target: self.target_name.clone(),
                target_addr: self.target,
                seq,
                bytes: 0,
                ttl: None,
                rtt: Duration::ZERO,
                status: ProbeStatus::Error(e.to_string()),
            }).await;
            return Ok(());
        }

        let start = std::time::Instant::now();
        let timeout = self.timeout;
        let target_name = self.target_name.clone();
        let target_addr = self.target;
        let size = self.size;
        let result_tx = self.result_tx.clone();
        let client = self.client.clone();

        tokio::spawn(async move {
            match tokio::time::timeout(timeout, rx).await {
                Ok(Ok(reply)) => {
                    let rtt = reply.timestamp.duration_since(start);
                    let guard = result_tx.lock().await;
                    if let Some(tx) = guard.as_ref() {
                        let _ = tx.send(PingResult {
                            target: target_name,
                            target_addr,
                            seq,
                            bytes: size,
                            ttl: reply.ttl,
                            rtt,
                            status: ProbeStatus::Success,
                        }).await;
                    }
                },
                Ok(Err(_)) => {
                    let guard = result_tx.lock().await;
                    if let Some(tx) = guard.as_ref() {
                        let _ = tx.send(PingResult {
                            target: target_name,
                            target_addr,
                            seq,
                            bytes: 0,
                            ttl: None,
                            rtt: Duration::ZERO,
                            status: ProbeStatus::Error("Receiver closed".into()),
                        }).await;
                    }
                },
                Err(_) => {
                    client.unregister(target_addr, ident_key, seq_u16);
                    let guard = result_tx.lock().await;
                    if let Some(tx) = guard.as_ref() {
                        let _ = tx.send(PingResult {
                            target: target_name,
                            target_addr,
                            seq,
                            bytes: 0,
                            ttl: None,
                            rtt: Duration::ZERO,
                            status: ProbeStatus::Timeout,
                        }).await;
                    }
                }
            }
        });

        Ok(())
    }

    async fn stop(&mut self) -> Result<()> {
        Ok(())
    }
}