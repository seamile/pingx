use crate::pinger::Pinger;
use crate::session::{PingResult, ProbeStatus};
use anyhow::Result;
use async_trait::async_trait;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex};
use surge_ping::{Client, Config, PingIdentifier, ICMP};

pub struct IcmpPinger {
    target_name: String,
    target: IpAddr,
    id: u16,
    ttl: u32,
    size: usize,
    timeout: Duration,
    client: Option<Client>,
    result_tx: Arc<Mutex<Option<mpsc::Sender<PingResult>>>>,
}

impl IcmpPinger {
    pub fn new(target_name: String, target: IpAddr, ttl: u32, size: usize, timeout: Duration) -> Self {
        let id = (std::process::id() % u16::MAX as u32) as u16;
        Self {
            target_name,
            target,
            id,
            ttl,
            size,
            timeout,
            client: None,
            result_tx: Arc::new(Mutex::new(None)),
        }
    }
}

#[async_trait]
impl Pinger for IcmpPinger {
    async fn start(&mut self, tx: mpsc::Sender<PingResult>) -> Result<()> {
        {
            let mut guard = self.result_tx.lock().await;
            *guard = Some(tx);
        }

        let kind = if self.target.is_ipv6() { ICMP::V6 } else { ICMP::V4 };

        let client = Client::new(&Config::builder().kind(kind).ttl(self.ttl).build())?;
        self.client = Some(client);
        Ok(())
    }

    async fn ping(&self, seq: u64) -> Result<()> {
        let client = self.client.as_ref().ok_or_else(|| anyhow::anyhow!("Client not initialized"))?.clone();
        let result_tx = {
            let guard = self.result_tx.lock().await;
            if guard.is_none() { return Ok(()); }
            guard.clone().unwrap()
        };

        let target = self.target;
        let id = self.id;
        let size = self.size;
        let target_name = self.target_name.clone();
        let timeout = self.timeout;
        // let ttl = self.ttl; // Unused for now if pinger doesn't support it directly

        tokio::spawn(async move {
            let payload = vec![0u8; size];
            let mut pinger = client.pinger(target, PingIdentifier(id)).await;
            pinger.timeout(timeout);
            // pinger.ttl(ttl as u8); // Attempting to use TTL if method exists?
            // If it doesn't exist, I can't use it easily without rebuilding Client?
            // Client is shared.
            // surge-ping might bind socket with TTL.

            match pinger.ping((seq as u16).into(), &payload).await {
                Ok((packet, rtt)) => {
                    let ttl = match packet {
                        surge_ping::IcmpPacket::V4(p) => p.get_ttl(),
                        surge_ping::IcmpPacket::V6(p) => Some(p.get_max_hop_limit()),
                    };
                    let _ = result_tx.send(PingResult {
                        target: target_name,
                        target_addr: target,
                        seq,
                        bytes: size,
                        ttl: ttl.map(|t| t as u8),
                        rtt,
                        status: ProbeStatus::Success,
                    }).await;
                },
                Err(e) => {
                    let msg = e.to_string();
                    let status = if msg.contains("timeout") {
                        ProbeStatus::Timeout
                    } else {
                        ProbeStatus::Error(msg)
                    };

                    let _ = result_tx.send(PingResult {
                        target: target_name,
                        target_addr: target,
                        seq,
                        bytes: 0,
                        ttl: None,
                        rtt: Duration::ZERO,
                        status,
                    }).await;
                }
            }
        });

        Ok(())
    }

    async fn stop(&mut self) -> Result<()> {
        Ok(())
    }
}
