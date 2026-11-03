pub mod http;
pub mod icmp;
pub mod icmp_packet;
pub mod tcp;
pub mod udp;

use crate::cli::Protocol;
use crate::pinger::icmp::IcmpClient;
use crate::session::PingResult;
use async_trait::async_trait;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

#[async_trait]
pub trait Pinger: Send + Sync {
    async fn probe(&self, seq: u64) -> PingResult;
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
) -> Arc<dyn Pinger> {
    #[cfg(windows)]
    let _ = (client_v4, client_v6);
    match protocol {
        Protocol::Icmp => {
            #[cfg(unix)]
            {
                let client = if target.is_ipv6() {
                    client_v6.expect("IPv6 client needed but not provided")
                } else {
                    client_v4.expect("IPv4 client needed but not provided")
                };
                Arc::new(icmp::IcmpPinger::new(
                    target_name,
                    target,
                    config.ttl,
                    config.size,
                    config.timeout,
                    client,
                ))
            }
            #[cfg(windows)]
            {
                Arc::new(icmp::windows::IcmpPinger::new(
                    target_name,
                    target,
                    config.ttl,
                    config.size,
                    config.timeout,
                ))
            }
        }
        Protocol::Tcp(port) => Arc::new(tcp::TcpPinger::new(
            target_name,
            target,
            port,
            config.ttl,
            config.timeout,
        )),
        Protocol::Udp(port) => Arc::new(udp::UdpPinger::new(
            target_name,
            target,
            port,
            config.size,
            config.ttl,
            config.timeout,
        )),
        Protocol::Http(url) => {
            use reqwest::Url;
            let url = Url::parse(&url)
                .unwrap_or_else(|_| Url::parse(&format!("http://{}", url)).unwrap());
            Arc::new(http::HttpPinger::new(
                target_name,
                url,
                target,
                config.timeout,
                config.headers,
            ))
        }
    }
}
