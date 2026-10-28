use crate::pinger::Pinger;
use crate::session::{PingResult, ProbeStatus, ResponseType};
use anyhow::Result;
use async_trait::async_trait;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};

pub struct TcpPinger {
    target_name: String,
    target: IpAddr,
    port: u16,
    ttl: u32,
    timeout: std::time::Duration,
    result_tx: Arc<Mutex<Option<mpsc::Sender<PingResult>>>>,
}

impl TcpPinger {
    pub fn new(
        target_name: String,
        target: IpAddr,
        port: u16,
        ttl: u32,
        timeout: std::time::Duration,
    ) -> Self {
        Self {
            target_name,
            target,
            port,
            ttl,
            timeout,
            result_tx: Arc::new(Mutex::new(None)),
        }
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
            if guard.is_none() {
                return Ok(());
            }
            guard.clone().unwrap()
        };

        let timeout = self.timeout;
        let ttl = self.ttl;
        let port = self.port;
        let target_name = self.target_name.clone();
        let target = self.target;

        tokio::spawn(async move {
            let (status, rtt) = probe(target, port, timeout, ttl).await;

            let _ = result_tx
                .send(PingResult {
                    target: target_name,
                    target_addr: target,
                    seq,
                    bytes: 0,
                    ttl: None,
                    rtt,
                    status,
                })
                .await;
        });

        Ok(())
    }

    async fn stop(&mut self) -> Result<()> {
        Ok(())
    }
}

#[cfg(any(unix, windows))]
async fn probe(
    target: IpAddr,
    port: u16,
    timeout: std::time::Duration,
    ttl: u32,
) -> (ProbeStatus, std::time::Duration) {
    use crate::probe::tcp_syn::{self, TcpSynFailure, TcpSynKind};

    #[cfg(unix)]
    let result = tcp_syn::probe(target, port, timeout, ttl).await;
    #[cfg(windows)]
    let result = tcp_syn::probe_windows(target, port, timeout, ttl).await;
    match result {
        Ok(reply) => (
            ProbeStatus::Success(match reply.kind {
                TcpSynKind::Open => ResponseType::TcpOpen,
                TcpSynKind::Closed => ResponseType::TcpClosed,
            }),
            reply.rtt,
        ),
        Err(TcpSynFailure::Timeout) => (ProbeStatus::Timeout, std::time::Duration::ZERO),
        Err(TcpSynFailure::Network { node, reason }) => (
            ProbeStatus::NetworkError { node, reason },
            std::time::Duration::ZERO,
        ),
        Err(TcpSynFailure::Local(error)) => {
            (ProbeStatus::LocalError(error), std::time::Duration::ZERO)
        }
    }
}

#[cfg(not(any(unix, windows)))]
async fn probe(
    _target: IpAddr,
    _port: u16,
    _timeout: std::time::Duration,
    _ttl: u32,
) -> (ProbeStatus, std::time::Duration) {
    (
        ProbeStatus::LocalError("TCP SYN ping is not implemented on this platform".to_string()),
        std::time::Duration::ZERO,
    )
}
