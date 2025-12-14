use crate::pinger::Pinger;
use crate::session::{PingResult, ProbeStatus};
use anyhow::Result;
use async_trait::async_trait;
use reqwest::{Client, Method, Url};
use std::net::IpAddr;
use std::time::{Duration, Instant};

pub struct HttpPinger {
    target_url: Url,
    target_ip: IpAddr, // For reporting
    client: Client,
    timeout: Duration,
}

impl HttpPinger {
    pub fn new(target_url: Url, target_ip: IpAddr, timeout: Duration) -> Self {
        // We use a shared client but we could recreate it.
        // Reusing connection (Keep-Alive) might affect latency measurement (make it lower).
        // Usually "ping" implies new connection check?
        // But http-ping usually checks service availability.
        // Let's create one client.
        let client = Client::builder()
            .timeout(timeout)
            .danger_accept_invalid_certs(true) // Should be configurable? Spec didn't say.
            .build()
            .unwrap_or_else(|_| Client::new());

        Self {
            target_url,
            target_ip,
            client,
            timeout,
        }
    }
}

#[async_trait]
impl Pinger for HttpPinger {
    async fn start(&mut self) -> Result<()> {
        Ok(())
    }

    async fn ping(&mut self, seq: u64) -> Result<PingResult> {
        let start = Instant::now();

        // Use HEAD request
        let request = self.client.request(Method::HEAD, self.target_url.clone());

        match request.send().await {
            Ok(response) => {
                let rtt = start.elapsed();
                let status = response.status();
                let bytes = response.content_length().unwrap_or(0) as usize; // Usually 0 for HEAD but headers size?

                if status.is_success() || status.is_redirection() {
                    Ok(PingResult {
                        target_addr: self.target_ip, // Reqwest resolves it, but we store the one we resolved earlier?
                        // Actually reqwest does its own resolution.
                        // But we return what we resolved for consistency in logs.
                        seq,
                        bytes, // Content length
                        ttl: None,
                        rtt,
                        status: ProbeStatus::Success,
                    })
                } else {
                    Ok(PingResult {
                        target_addr: self.target_ip,
                        seq,
                        bytes: 0,
                        ttl: None,
                        rtt,
                        status: ProbeStatus::Error(format!("HTTP {}", status)),
                    })
                }
            }
            Err(e) => {
                if e.is_timeout() {
                    Ok(PingResult {
                        target_addr: self.target_ip,
                        seq,
                        bytes: 0,
                        ttl: None,
                        rtt: Duration::ZERO,
                        status: ProbeStatus::Timeout,
                    })
                } else {
                    Ok(PingResult {
                        target_addr: self.target_ip,
                        seq,
                        bytes: 0,
                        ttl: None,
                        rtt: Duration::ZERO,
                        status: ProbeStatus::Error(e.to_string()),
                    })
                }
            }
        }
    }

    async fn stop(&mut self) -> Result<()> {
        Ok(())
    }
}
