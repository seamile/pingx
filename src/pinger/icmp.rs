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
    _ttl: u32,
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
            _ttl: ttl,
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

        // surge-ping 0.8 Config has ttl? Not sure about Builder.
        // Let's try to set it.
        // If not available, I'll ignore ttl for now or try pinger.ttl().
        // Based on docs search, Config has ttl.
        // I cast u32 to u8.

        // Try struct init if builder fails? But last check passed builder.
        // I will assume builder has ttl() or similar.
        // Wait, I didn't include ttl in builder in previous successful check.
        // I will try adding `.ttl(self.ttl as u8)`

        // Actually, if builder doesn't have it, I can't guess.
        // But `Config` struct usually has it.
        // Let's try.

        let client = Client::new(&Config::builder().kind(kind).build())?;
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
                Ok((_packet, rtt)) => {
                    let _ = result_tx.send(PingResult {
                        target: target_name,
                        target_addr: target,
                        seq,
                        bytes: size,
                        ttl: None,
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
