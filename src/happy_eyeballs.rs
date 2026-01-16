use crate::cli::Protocol;
use anyhow::{Context, Result};
use futures::stream::{FuturesUnordered, StreamExt};
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio::time::{Instant, Sleep, sleep};

// RFC 8305 parameters
const CONNECTION_ATTEMPT_DELAY: Duration = Duration::from_millis(50);
const MIN_CONNECTION_ATTEMPT_DELAY: Duration = Duration::from_millis(10);
const MAX_CONNECTION_ATTEMPT_DELAY: Duration = Duration::from_secs(2);
const PROBE_TIMEOUT: Duration = Duration::from_secs(1);

pub async fn select_best_addr(addrs: Vec<IpAddr>, protocol: &Protocol) -> Result<IpAddr> {
    if addrs.is_empty() {
        return Err(anyhow::anyhow!("No addresses to probe"));
    }
    if addrs.len() == 1 {
        return Ok(addrs[0]);
    }

    let sorted_addrs = interleave_addrs(addrs);
    let mut addr_iter = sorted_addrs.into_iter();
    let mut futures = FuturesUnordered::new();

    let mut last_start_time = Instant::now();

    // Start the first attempt immediately
    if let Some(addr) = addr_iter.next() {
        futures.push(spawn_probe(addr, protocol.clone()));
        last_start_time = Instant::now();
    }

    let delay =
        CONNECTION_ATTEMPT_DELAY.clamp(MIN_CONNECTION_ATTEMPT_DELAY, MAX_CONNECTION_ATTEMPT_DELAY);
    let mut next_attempt_timer: Pin<Box<Sleep>> = Box::pin(sleep(delay));

    loop {
        tokio::select! {
            // Case 1: Timer expired (Start next probe)
            _ = &mut next_attempt_timer, if addr_iter.len() > 0 => {
                if let Some(addr) = addr_iter.next() {
                    futures.push(spawn_probe(addr, protocol.clone()));
                    last_start_time = Instant::now();
                    next_attempt_timer = Box::pin(sleep(delay));
                }
            }

            // Case 2: A probe returned result
            Some(result) = futures.next(), if !futures.is_empty() => {
                match result {
                    Ok(Ok(addr)) => {
                        return Ok(addr);
                    },
                    Ok(Err(_)) => {
                        // RFC 8305 Section 5: Start next attempt immediately if allowed by MIN_DELAY.
                        if addr_iter.len() > 0 {
                            let elapsed = last_start_time.elapsed();
                            if elapsed >= MIN_CONNECTION_ATTEMPT_DELAY {
                                if let Some(addr) = addr_iter.next() {
                                    futures.push(spawn_probe(addr, protocol.clone()));
                                    last_start_time = Instant::now();
                                    next_attempt_timer = Box::pin(sleep(delay));
                                }
                            } else {
                                let remaining = MIN_CONNECTION_ATTEMPT_DELAY - elapsed;
                                next_attempt_timer = Box::pin(sleep(remaining));
                            }
                        }
                    },
                    Err(_) => {}
                }
            }

            else => {
                break;
            }
        }
    }

    Err(anyhow::anyhow!("All address probes failed"))
}

struct AbortOnDropHandle<T>(JoinHandle<T>);

impl<T> Future for AbortOnDropHandle<T> {
    type Output = Result<T, tokio::task::JoinError>;
    fn poll(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx)
    }
}

impl<T> Drop for AbortOnDropHandle<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn interleave_addrs(addrs: Vec<IpAddr>) -> Vec<IpAddr> {
    let mut v6 = Vec::new();
    let mut v4 = Vec::new();
    for addr in addrs {
        if addr.is_ipv6() {
            v6.push(addr);
        } else {
            v4.push(addr);
        }
    }
    let mut result = Vec::with_capacity(v6.len() + v4.len());
    let mut v6_iter = v6.drain(..);
    let mut v4_iter = v4.drain(..);
    loop {
        let a = v6_iter.next();
        let b = v4_iter.next();
        if a.is_none() && b.is_none() {
            break;
        }
        if let Some(ip) = a {
            result.push(ip);
        }
        if let Some(ip) = b {
            result.push(ip);
        }
    }
    result
}

fn spawn_probe(addr: IpAddr, protocol: Protocol) -> AbortOnDropHandle<Result<IpAddr>> {
    let handle = tokio::spawn(async move { probe_address(addr, &protocol).await.map(|_| addr) });
    AbortOnDropHandle(handle)
}

async fn probe_address(addr: IpAddr, protocol: &Protocol) -> Result<()> {
    match protocol {
        Protocol::Icmp => probe_icmp(addr).await,
        Protocol::Tcp(port) => probe_tcp(addr, *port).await,
        Protocol::Http(url_str) => {
            let port = if let Ok(url) = reqwest::Url::parse(url_str) {
                url.port_or_known_default().unwrap_or(80)
            } else {
                80
            };
            probe_tcp(addr, port).await
        }
    }
}

async fn probe_tcp(addr: IpAddr, port: u16) -> Result<()> {
    let socket_addr = SocketAddr::new(addr, port);
    tokio::time::timeout(PROBE_TIMEOUT, TcpStream::connect(socket_addr))
        .await
        .context("Timeout")?
        .context("Connection failed")?;
    Ok(())
}

async fn probe_icmp(addr: IpAddr) -> Result<()> {
    use crate::pinger::Pinger;
    use std::sync::Arc;

    let (tx, mut rx) = tokio::sync::mpsc::channel(1);

    // Create a temporary client for this probe
    let client = Arc::new(crate::pinger::icmp::IcmpClient::new(addr.is_ipv6(), 64)?);

    let mut pinger = crate::pinger::icmp::IcmpPinger::new(
        "probe".to_string(),
        addr,
        64, // dummy ttl
        64, // size
        PROBE_TIMEOUT,
        client,
    );

    pinger.start(tx).await?;
    pinger.ping(0).await?;

    match rx.recv().await {
        Some(res) => match res.status {
            crate::session::ProbeStatus::Success => Ok(()),
            _ => Err(anyhow::anyhow!("Probe failed: {:?}", res.status)),
        },
        None => Err(anyhow::anyhow!("No result")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_interleave_addrs() {
        let v4_1 = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let v6_1 = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));
        let v6_2 = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 2));
        let input = vec![v4_1, v6_1, v6_2];
        let output = interleave_addrs(input);
        assert_eq!(output, vec![v6_1, v4_1, v6_2]);
    }
}
