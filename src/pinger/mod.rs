pub mod icmp;
pub mod icmp_packet;
pub mod tcp;
pub mod http;

use async_trait::async_trait;
use anyhow::Result;
use crate::session::PingResult;
use crate::cli::Protocol;
use std::net::IpAddr;
use std::time::Duration;
use std::sync::Arc;
use tokio::sync::mpsc::Sender;
use crate::pinger::icmp::IcmpClient;

#[async_trait]
pub trait Pinger: Send + Sync {
    async fn start(&mut self, tx: Sender<PingResult>) -> Result<()>;
    async fn ping(&self, seq: u64) -> Result<()>;
    async fn stop(&mut self) -> Result<()>;
}

pub fn create_pinger(
    target_name: String,
    protocol: Protocol,
    target: IpAddr,
    ttl: u32,
    size: usize,
    timeout: Duration,
    client_v4: Option<Arc<IcmpClient>>,
    client_v6: Option<Arc<IcmpClient>>,
) -> Box<dyn Pinger> {
    match protocol {
        Protocol::Icmp => {
            let client = if target.is_ipv6() {
                client_v6.expect("IPv6 client needed but not provided")
            } else {
                client_v4.expect("IPv4 client needed but not provided")
            };
            Box::new(icmp::IcmpPinger::new(target_name, target, ttl, size, timeout, client))
        },
        Protocol::Tcp(port) => Box::new(tcp::TcpPinger::new(target_name, target, port, timeout)),
        Protocol::Http(url) => {
            use reqwest::Url;
            let url = Url::parse(&url).unwrap_or_else(|_| Url::parse(&format!("http://{}", url)).unwrap());
             Box::new(http::HttpPinger::new(target_name, url, target, timeout))
        },
    }
}
