use crate::pinger::Pinger;
use crate::session::{PingResult, ProbeStatus, ResponseType};
use anyhow::Result;
use async_trait::async_trait;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, mpsc};

pub struct UdpPinger {
    target_name: String,
    target: IpAddr,
    port: u16,
    size: usize,
    timeout: Duration,
    result_tx: Arc<Mutex<Option<mpsc::Sender<PingResult>>>>,
}

impl UdpPinger {
    pub fn new(
        target_name: String,
        target: IpAddr,
        port: u16,
        size: usize,
        timeout: Duration,
    ) -> Self {
        Self {
            target_name,
            target,
            port,
            size,
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
        let timeout = self.timeout;

        tokio::spawn(async move {
            let start = Instant::now();
            let socket = match udp_socket(target, port).await {
                Ok(socket) => socket,
                Err(error) => {
                    send_result(
                        &result_tx,
                        target_name,
                        target,
                        seq,
                        0,
                        Duration::ZERO,
                        ProbeStatus::LocalError(error.to_string()),
                    )
                    .await;
                    return;
                }
            };

            if let Err(error) = socket.send(&vec![0; size]).await {
                send_result(
                    &result_tx,
                    target_name,
                    target,
                    seq,
                    0,
                    Duration::ZERO,
                    ProbeStatus::LocalError(error.to_string()),
                )
                .await;
                return;
            }

            let mut buffer = vec![0; 65_535];
            let (status, rtt, bytes) =
                match tokio::time::timeout(timeout, socket.recv(&mut buffer)).await {
                    Ok(Ok(bytes)) => (
                        ProbeStatus::Success(ResponseType::UdpApplicationReply),
                        start.elapsed(),
                        bytes,
                    ),
                    Ok(Err(error)) if error.kind() == io::ErrorKind::ConnectionRefused => (
                        ProbeStatus::Success(ResponseType::UdpPortUnreachable),
                        start.elapsed(),
                        0,
                    ),
                    Ok(Err(error)) => (
                        ProbeStatus::NetworkError {
                            node: None,
                            reason: error.to_string(),
                        },
                        Duration::ZERO,
                        0,
                    ),
                    Err(_) => (ProbeStatus::Timeout, Duration::ZERO, 0),
                };
            send_result(&result_tx, target_name, target, seq, bytes, rtt, status).await;
        });
        Ok(())
    }

    async fn stop(&mut self) -> Result<()> {
        Ok(())
    }
}

async fn udp_socket(target: IpAddr, port: u16) -> io::Result<tokio::net::UdpSocket> {
    #[cfg(unix)]
    let socket = if let Some(interface) = crate::utils::get_bind_interface() {
        use socket2::{Domain, Protocol, Socket, Type};
        let domain = if target.is_ipv6() {
            Domain::IPV6
        } else {
            Domain::IPV4
        };
        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        crate::utils::bind_socket_to_interface(&socket, interface, target.is_ipv6())?;
        socket.set_nonblocking(true)?;
        let socket: std::net::UdpSocket = socket.into();
        tokio::net::UdpSocket::from_std(socket)?
    } else {
        tokio::net::UdpSocket::bind(if target.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        })
        .await?
    };

    #[cfg(not(unix))]
    let socket = tokio::net::UdpSocket::bind(if target.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    })
    .await?;

    socket.connect(SocketAddr::new(target, port)).await?;
    Ok(socket)
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

#[cfg(test)]
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
