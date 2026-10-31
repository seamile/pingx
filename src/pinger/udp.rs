use crate::pinger::Pinger;
use crate::session::{PingResult, ProbeStatus, ResponseType};
use anyhow::Result;
use async_trait::async_trait;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, mpsc};

pub struct UdpPinger {
    target_name: String,
    target: IpAddr,
    port: u16,
    size: usize,
    ttl: u32,
    timeout: Duration,
    result_tx: Arc<Mutex<Option<mpsc::Sender<PingResult>>>>,
}

impl UdpPinger {
    pub fn new(
        target_name: String,
        target: IpAddr,
        port: u16,
        size: usize,
        ttl: u32,
        timeout: Duration,
    ) -> Self {
        Self {
            target_name,
            target,
            port,
            size,
            ttl,
            timeout,
            result_tx: Arc::new(Mutex::new(None)),
        }
    }
}

#[async_trait]
impl Pinger for UdpPinger {
    async fn start(&mut self, tx: mpsc::Sender<PingResult>) -> Result<()> {
        *self.result_tx.lock().await = Some(tx);
        Ok(())
    }

    async fn ping(&self, seq: u64) -> Result<()> {
        let Some(result_tx) = self.result_tx.lock().await.clone() else {
            return Ok(());
        };
        let target_name = self.target_name.clone();
        let target = self.target;
        let port = self.port;
        let size = self.size;
        let ttl = self.ttl;
        let timeout = self.timeout;

        tokio::spawn(async move {
            let (status, rtt, bytes) = probe(target, port, size, timeout, ttl).await;
            send_result(&result_tx, target_name, target, seq, bytes, rtt, status).await;
        });
        Ok(())
    }

    async fn stop(&mut self) -> Result<()> {
        Ok(())
    }
}

#[cfg(unix)]
async fn probe(
    target: IpAddr,
    port: u16,
    size: usize,
    timeout: Duration,
    ttl: u32,
) -> (ProbeStatus, Duration, usize) {
    use crate::probe::udp::{self, UdpProbeFailure, UdpProbeKind};

    match udp::probe(target, port, size, timeout, ttl).await {
        Ok(reply) => (
            ProbeStatus::Success(match reply.kind {
                UdpProbeKind::ApplicationReply => ResponseType::UdpApplicationReply,
                UdpProbeKind::PortUnreachable => ResponseType::UdpPortUnreachable,
            }),
            reply.rtt,
            reply.bytes,
        ),
        Err(UdpProbeFailure::Timeout) => (ProbeStatus::Timeout, Duration::ZERO, 0),
        Err(UdpProbeFailure::Network { node, reason }) => (
            ProbeStatus::NetworkError { node, reason },
            Duration::ZERO,
            0,
        ),
        Err(UdpProbeFailure::Local(error)) => (ProbeStatus::LocalError(error), Duration::ZERO, 0),
    }
}

#[cfg(windows)]
async fn probe(
    target: IpAddr,
    port: u16,
    size: usize,
    timeout: Duration,
    ttl: u32,
) -> (ProbeStatus, Duration, usize) {
    use crate::probe::udp_error::{UdpProbeFailure, UdpProbeKind};

    match crate::probe::udp_windows::probe(target, port, size, timeout, ttl).await {
        Ok(reply) => (
            ProbeStatus::Success(match reply.kind {
                UdpProbeKind::ApplicationReply => ResponseType::UdpApplicationReply,
                UdpProbeKind::PortUnreachable => ResponseType::UdpPortUnreachable,
            }),
            reply.rtt,
            reply.bytes,
        ),
        Err(UdpProbeFailure::Timeout) => (ProbeStatus::Timeout, Duration::ZERO, 0),
        Err(UdpProbeFailure::Network { node, reason }) => (
            ProbeStatus::NetworkError { node, reason },
            Duration::ZERO,
            0,
        ),
        Err(UdpProbeFailure::Local(error)) => (ProbeStatus::LocalError(error), Duration::ZERO, 0),
    }
}

#[cfg(not(any(unix, windows)))]
async fn probe(
    _target: IpAddr,
    _port: u16,
    _size: usize,
    _timeout: Duration,
    _ttl: u32,
) -> (ProbeStatus, Duration, usize) {
    (
        ProbeStatus::LocalError("UDP ping is not implemented on this platform".to_string()),
        Duration::ZERO,
        0,
    )
}

async fn send_result(
    tx: &mpsc::Sender<PingResult>,
    target: String,
    target_addr: IpAddr,
    seq: u64,
    bytes: usize,
    rtt: Duration,
    status: ProbeStatus,
) {
    let _ = tx
        .send(PingResult {
            target,
            target_addr,
            seq,
            bytes,
            ttl: None,
            rtt,
            status,
        })
        .await;
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

        let (tx, mut rx) = mpsc::channel(1);
        let mut pinger = UdpPinger::new(
            "localhost".to_string(),
            "127.0.0.1".parse().unwrap(),
            port,
            4,
            64,
            Duration::from_secs(1),
        );
        pinger.start(tx).await.unwrap();
        pinger.ping(1).await.unwrap();

        let result = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            result.status,
            ProbeStatus::Success(ResponseType::UdpApplicationReply)
        ));
        assert_eq!(result.bytes, 4);
    }
}
