pub mod icmp;
pub mod tcp;
pub mod http;

use async_trait::async_trait;
use anyhow::Result;
use crate::session::PingResult;
use crate::cli::Protocol;
use std::net::IpAddr;
use std::time::Duration;
use tokio::sync::mpsc::Sender;

#[async_trait]
pub trait Pinger: Send + Sync {
    async fn start(&mut self, tx: Sender<PingResult>) -> Result<()>;
    async fn ping(&self, seq: u64) -> Result<()>;
    async fn stop(&mut self) -> Result<()>;
}

pub fn create_pinger(
    target_name: String, // Added
    protocol: Protocol, 
    target: IpAddr, 
    ttl: u32, 
    size: usize, 
    timeout: Duration
) -> Box<dyn Pinger> {
    match protocol {
        Protocol::Icmp => Box::new(icmp::IcmpPinger::new(target_name, target, ttl, size, timeout)),
        Protocol::Tcp(port) => Box::new(tcp::TcpPinger::new(target_name, target, port, timeout)),
        Protocol::Http(url) => {
            use reqwest::Url;
            let url = Url::parse(&url).unwrap_or_else(|_| Url::parse(&format!("http://{}", url)).unwrap());
             Box::new(http::HttpPinger::new(target_name, url, target, timeout))
        },
    }
}
