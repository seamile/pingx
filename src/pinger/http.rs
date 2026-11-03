use crate::pinger::Pinger;
use crate::session::{PingResult, ProbeStatus, ResponseType};
use async_trait::async_trait;
use reqwest::{Client, Method, Url, header::HeaderMap};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

pub struct HttpPinger {
    target_name: String,
    target_url: Url,
    target_ip: IpAddr,
    client: Client,
    headers: HeaderMap,
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
        }
    }
}

#[async_trait]
impl Pinger for HttpPinger {
    async fn probe(&self, seq: u64) -> PingResult {
        let start = Instant::now();
        let request = self
            .client
            .request(Method::HEAD, self.target_url.clone())
            .headers(self.headers.clone());

        let (status, rtt, bytes) = match request.send().await {
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
            Err(error) if error.is_timeout() => (ProbeStatus::Timeout, Duration::ZERO, 0),
            Err(error) => (
                ProbeStatus::NetworkError {
                    node: Some(self.target_ip),
                    reason: error.to_string(),
                },
                Duration::ZERO,
                0,
            ),
        };

        PingResult {
            target: self.target_name.clone(),
            target_addr: self.target_ip,
            seq,
            bytes,
            ttl: None,
            rtt,
            status,
        }
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

        let pinger = HttpPinger::new(
            "test".to_string(),
            Url::parse(&format!("http://{addr}/")).unwrap(),
            addr.ip(),
            Duration::from_secs(1),
            HeaderMap::new(),
        );
        let result = tokio::time::timeout(Duration::from_secs(2), pinger.probe(1))
            .await
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
