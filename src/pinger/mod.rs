pub mod http;
pub mod icmp;
pub mod icmp_packet;
pub mod tcp;

use crate::cli::Protocol;
use crate::pinger::icmp::IcmpClient;
use crate::session::PingResult;
use anyhow::Result;
use async_trait::async_trait;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::Sender;

#[async_trait]
pub trait Pinger: Send + Sync {
    async fn start(&mut self, tx: Sender<PingResult>) -> Result<()>;
    async fn ping(&self, seq: u64) -> Result<()>;
    async fn stop(&mut self) -> Result<()>;
}

pub struct PingerConfig {
    pub ttl: u32,
    pub size: usize,
    pub timeout: Duration,
    pub headers: reqwest::header::HeaderMap,
}

pub fn create_pinger(
    target_name: String,
    protocol: Protocol,
    target: IpAddr,
    config: PingerConfig,
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
            Box::new(icmp::IcmpPinger::new(
                target_name,
                target,
                config.ttl,
                config.size,
                config.timeout,
                client,
            ))
        }
        Protocol::Tcp(port) => Box::new(tcp::TcpPinger::new(
            target_name,
            target,
            port,
            config.timeout,
        )),
        Protocol::Http(url) => {
            use reqwest::Url;
            let url = Url::parse(&url)
                .unwrap_or_else(|_| Url::parse(&format!("http://{}", url)).unwrap());
            Box::new(http::HttpPinger::new(
                target_name,
                url,
                target,
                config.timeout,
                config.headers,
            ))
        }
    }
}
