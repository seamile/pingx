use crate::pinger::Pinger;
use crate::session::{PingResult, ProbeStatus, ResponseType};
use anyhow::Result;
use async_trait::async_trait;
use reqwest::{Client, Method, Url, header::HeaderMap};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, mpsc};

pub struct HttpPinger {
    target_name: String,
    target_url: Url,
    target_ip: IpAddr,
    client: Client,
    headers: HeaderMap,
    result_tx: Arc<Mutex<Option<mpsc::Sender<PingResult>>>>,
}

impl HttpPinger {
    pub fn new(
        target_name: String,
        target_url: Url,
        target_ip: IpAddr,
        timeout: Duration,
        headers: HeaderMap,
    ) -> Self {
        let mut builder = Client::builder()
            .timeout(timeout)
            .danger_accept_invalid_certs(true);

        #[cfg(unix)]
        if let Some(iface) = crate::utils::get_bind_interface() {
            builder = builder.interface(iface).no_proxy();
        }

        if let Some(host) = target_url.host_str() {
            let port = target_url.port_or_known_default().unwrap_or(80);
            builder = builder.resolve(host, SocketAddr::new(target_ip, port));
        }

        let client = builder.build().expect("failed to build bound HTTP client");

        Self {
            target_name,
            target_url,
            target_ip,
            client,
            headers,
            result_tx: Arc::new(Mutex::new(None)),
        }
    }
}

#[async_trait]
impl Pinger for HttpPinger {
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

        let target_name = self.target_name.clone();
        let target_ip = self.target_ip;
        let url = self.target_url.clone();
        let client = self.client.clone();
        let headers = self.headers.clone();

        tokio::spawn(async move {
            let start = Instant::now();
            let request = client.request(Method::HEAD, url).headers(headers);

            let (status_res, rtt, bytes) = match request.send().await {
                Ok(response) => {
                    let rtt = start.elapsed();
                    let status_code = response.status();
                    let len = response.content_length().unwrap_or(0) as usize;
                    (
                        ProbeStatus::Success(ResponseType::HttpResponse(status_code.as_u16())),
                        rtt,
                        len,
                    )
                }
                Err(e) => {
                    if e.is_timeout() {
                        (ProbeStatus::Timeout, Duration::ZERO, 0)
                    } else {
                        (
                            ProbeStatus::NetworkError {
                                node: Some(target_ip),
                                reason: e.to_string(),
                            },
                            Duration::ZERO,
                            0,
                        )
                    }
                }
            };

            let _ = result_tx
                .send(PingResult {
                    target: target_name,
                    target_addr: target_ip,
                    seq,
                    bytes,
                    ttl: None,
                    rtt,
                    status: status_res,
                })
                .await;
        });

        Ok(())
    }

    async fn stop(&mut self) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn assert_status_counts_as_a_response(status: u16, reason: &'static str) {
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 1024];
            let _ = stream.read(&mut request).await.unwrap();
            let response = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });

        let mut pinger = HttpPinger::new(
            "test".to_string(),
            Url::parse(&format!("http://{addr}/")).unwrap(),
            addr.ip(),
            Duration::from_secs(1),
            HeaderMap::new(),
        );
        let (tx, mut rx) = mpsc::channel(1);
        pinger.start(tx).await.unwrap();
        pinger.ping(1).await.unwrap();

        let result = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(
            result.status,
            ProbeStatus::Success(ResponseType::HttpResponse(code)) if code == status
        ));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn success_client_and_server_http_statuses_count_as_responses() {
        for (status, reason) in [
            (200, "OK"),
            (404, "Not Found"),
            (500, "Internal Server Error"),
        ] {
            assert_status_counts_as_a_response(status, reason).await;
        }
    }
}
