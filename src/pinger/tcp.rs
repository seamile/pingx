use crate::pinger::Pinger;
use crate::session::{PingResult, ProbeStatus};
use anyhow::Result;
use async_trait::async_trait;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};

pub struct TcpPinger {
    target_name: String,
    target: IpAddr,
    port: u16,
    timeout: std::time::Duration,
    result_tx: Arc<Mutex<Option<mpsc::Sender<PingResult>>>>,
}

impl TcpPinger {
    pub fn new(target_name: String, target: IpAddr, port: u16, timeout: std::time::Duration) -> Self {
        Self { target_name, target, port, timeout, result_tx: Arc::new(Mutex::new(None)) }
    }
}

#[async_trait]
impl Pinger for TcpPinger {
    async fn start(&mut self, tx: mpsc::Sender<PingResult>) -> Result<()> {
        let mut guard = self.result_tx.lock().await;
        *guard = Some(tx);
        Ok(())
    }

    async fn ping(&self, seq: u64) -> Result<()> {
        let result_tx = {
            let guard = self.result_tx.lock().await;
            if guard.is_none() { return Ok(()); }
            guard.clone().unwrap()
        };

        let addr = SocketAddr::new(self.target, self.port);
        let timeout = self.timeout;
        let target_name = self.target_name.clone();
        let target = self.target;

        tokio::spawn(async move {
            let start = Instant::now();
            let connect_future = TcpStream::connect(addr);
            let result = tokio::time::timeout(timeout, connect_future).await;

            let status = match result {
                Ok(Ok(_stream)) => ProbeStatus::Success,
                Ok(Err(e)) => ProbeStatus::Error(e.to_string()),
                Err(_) => ProbeStatus::Timeout,
            };

            let rtt = if let ProbeStatus::Success = status { start.elapsed() } else { std::time::Duration::ZERO };

            let _ = result_tx.send(PingResult {
                target: target_name,
                target_addr: target,
                seq,
                bytes: 0,
                ttl: None,
                rtt,
                status,
            }).await;
        });

        Ok(())
    }

    async fn stop(&mut self) -> Result<()> {
        Ok(())
    }
}
