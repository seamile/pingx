use crate::pinger::Pinger;
use crate::session::{PingResult, ProbeStatus, ResponseType};
use async_trait::async_trait;
use std::net::IpAddr;
use std::time::Duration;

pub struct UdpPinger {
    target_name: String,
    target: IpAddr,
    port: u16,
    size: usize,
    ttl: u32,
    timeout: Duration,
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
        }
    }
}

#[async_trait]
impl Pinger for UdpPinger {
    async fn probe(&self, seq: u64) -> PingResult {
        let (status, rtt, bytes) =
            probe(self.target, self.port, self.size, self.timeout, self.ttl).await;
        PingResult {
            target: self.target_name.clone(),
            target_addr: self.target,
            seq,
            bytes,
            ttl: None,
            rtt,
            status,
        }
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

        let pinger = UdpPinger::new(
            "localhost".to_string(),
            "127.0.0.1".parse().unwrap(),
            port,
            4,
            64,
            Duration::from_secs(1),
        );
        let result = tokio::time::timeout(Duration::from_secs(1), pinger.probe(1))
            .await
            .unwrap();
        assert!(matches!(
            result.status,
            ProbeStatus::Success(ResponseType::UdpApplicationReply)
        ));
        assert_eq!(result.bytes, 4);
    }
}
