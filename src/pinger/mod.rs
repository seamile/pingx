pub mod http;
pub mod icmp;
pub mod tcp;

use crate::cli::Protocol;
use crate::session::PingResult;
use anyhow::Result;
use async_trait::async_trait;
use std::net::IpAddr;
use std::time::Duration;

#[async_trait]
pub trait Pinger: Send + Sync {
    async fn start(&mut self) -> Result<()>;
    async fn ping(&mut self, seq: u64) -> Result<PingResult>;
    async fn stop(&mut self) -> Result<()>;
}

pub fn create_pinger(
    protocol: Protocol,
    target: IpAddr,
    ttl: u32,
    size: usize,
    timeout: Duration,
) -> Box<dyn Pinger> {
    match protocol {
        Protocol::Icmp => Box::new(icmp::IcmpPinger::new(target, ttl, size, timeout)),
        Protocol::Tcp(port) => Box::new(tcp::TcpPinger::new(target, port, timeout)),
        Protocol::Http(url) => {
            // Need to parse URL to create HttpPinger.
            // But CLI parsing already did some validation?
            // create_pinger takes Protocol enum which has String.
            use reqwest::Url;
            let url = Url::parse(&url)
                .unwrap_or_else(|_| Url::parse(&format!("http://{}", url)).unwrap());
            Box::new(http::HttpPinger::new(url, target, timeout))
        }
    }
}
