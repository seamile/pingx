use crate::pinger::Pinger;
use crate::session::{PingResult, ProbeStatus};
use anyhow::Result;
use async_trait::async_trait;
use reqwest::{Client, Method, Url};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Mutex};

pub struct HttpPinger {
    target_name: String,
    target_url: Url,
    target_ip: IpAddr,
    client: Client,
    result_tx: Arc<Mutex<Option<mpsc::Sender<PingResult>>>>,
}

impl HttpPinger {
    pub fn new(target_name: String, target_url: Url, target_ip: IpAddr, timeout: Duration) -> Self {
        let mut builder = Client::builder()
            .timeout(timeout)
            .danger_accept_invalid_certs(true);

        if let Some(host) = target_url.host_str() {
             let port = target_url.port_or_known_default().unwrap_or(80);
             builder = builder.resolve(host, SocketAddr::new(target_ip, port));
        }

        let client = builder.build()
            .unwrap_or_else(|_| Client::new());

        Self {
            target_name,
            target_url,
            target_ip,
            client,
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
            if guard.is_none() { return Ok(()); }
            guard.clone().unwrap()
        };

        let target_name = self.target_name.clone();
        let target_ip = self.target_ip;
        let url = self.target_url.clone();
        let client = self.client.clone();

        tokio::spawn(async move {
            let start = Instant::now();
            let request = client.request(Method::HEAD, url);

            let (status_res, rtt, bytes) = match request.send().await {
                Ok(response) => {
                    let rtt = start.elapsed();
                    let status_code = response.status();
                    let len = response.content_length().unwrap_or(0) as usize;
                    if status_code.is_success() || status_code.is_redirection() {
                        (ProbeStatus::Success, rtt, len)
                    } else {
                        (ProbeStatus::Error(format!("HTTP {}", status_code)), rtt, 0)
                    }
                },
                Err(e) => {
                    if e.is_timeout() {
                        (ProbeStatus::Timeout, Duration::ZERO, 0)
                    } else {
                        (ProbeStatus::Error(e.to_string()), Duration::ZERO, 0)
                    }
                }
            };

            let _ = result_tx.send(PingResult {
                target: target_name,
                target_addr: target_ip,
                seq,
                bytes,
                ttl: None,
                rtt,
                status: status_res,
            }).await;
        });

        Ok(())
    }

    async fn stop(&mut self) -> Result<()> {
        Ok(())
    }
}
