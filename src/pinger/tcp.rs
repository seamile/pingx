use crate::pinger::Pinger;
use crate::session::{PingResult, ProbeStatus, ResponseType};
use async_trait::async_trait;
use std::net::IpAddr;

pub struct TcpPinger {
    target_name: String,
    target: IpAddr,
    port: u16,
    ttl: u32,
    timeout: std::time::Duration,
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
        }
    }
}

#[async_trait]
impl Pinger for TcpPinger {
    async fn probe(&self, seq: u64) -> PingResult {
        let (status, rtt) = probe(self.target, self.port, self.timeout, self.ttl).await;
        PingResult {
            target: self.target_name.clone(),
            target_addr: self.target,
            seq,
            bytes: 0,
            ttl: None,
            rtt,
            status,
        }
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
