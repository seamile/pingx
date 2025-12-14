use crate::pinger::Pinger;
use crate::session::{PingResult, ProbeStatus};
use anyhow::Result;
use async_trait::async_trait;
use std::net::{IpAddr, SocketAddr};
use std::time::Instant;
use tokio::net::TcpStream;

pub struct TcpPinger {
    target: IpAddr,
    port: u16,
    timeout: std::time::Duration,
}

impl TcpPinger {
    pub fn new(target: IpAddr, port: u16, timeout: std::time::Duration) -> Self {
        Self {
            target,
            port,
            timeout,
        }
    }
}

#[async_trait]
impl Pinger for TcpPinger {
    async fn start(&mut self) -> Result<()> {
        // TCP ping is stateless between pings, nothing to open here.
        Ok(())
    }

    async fn ping(&mut self, seq: u64) -> Result<PingResult> {
        let addr = SocketAddr::new(self.target, self.port);
        let start = Instant::now();

        let connect_future = TcpStream::connect(addr);

        let result = tokio::time::timeout(self.timeout, connect_future).await;

        match result {
            Ok(Ok(_stream)) => {
                // Connection successful
                let rtt = start.elapsed();
                // We drop the stream immediately, closing connection.
                Ok(PingResult {
                    target_addr: self.target,
                    seq,
                    bytes: 0, // No payload for TCP handshake measurement usually, or could count syn-ack?
                    ttl: None,
                    rtt,
                    status: ProbeStatus::Success,
                })
            }
            Ok(Err(e)) => Ok(PingResult {
                target_addr: self.target,
                seq,
                bytes: 0,
                ttl: None,
                rtt: std::time::Duration::ZERO,
                status: ProbeStatus::Error(e.to_string()),
            }),
            Err(_) => {
                // Timeout
                Ok(PingResult {
                    target_addr: self.target,
                    seq,
                    bytes: 0,
                    ttl: None,
                    rtt: std::time::Duration::ZERO,
                    status: ProbeStatus::Timeout,
                })
            }
        }
    }

    async fn stop(&mut self) -> Result<()> {
        Ok(())
    }
}
