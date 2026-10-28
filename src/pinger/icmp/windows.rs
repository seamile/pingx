use crate::pinger::Pinger;
use crate::session::{PingResult, ProbeStatus, ResponseType};
use anyhow::Result;
use async_trait::async_trait;
use std::mem::{size_of, zeroed};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, mpsc};
use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    ICMP_ECHO_REPLY, ICMPV6_ECHO_REPLY_LH, IP_DEST_HOST_UNREACHABLE, IP_DEST_NET_UNREACHABLE,
    IP_DEST_PORT_UNREACHABLE, IP_DEST_PROHIBITED, IP_OPTION_INFORMATION, IP_REQ_TIMED_OUT,
    IP_SUCCESS, IP_TIME_EXCEEDED, IP_TTL_EXPIRED_TRANSIT, Icmp6CreateFile, Icmp6SendEcho2,
    IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho,
};
use windows_sys::Win32::Networking::WinSock::{
    AF_INET6, IN6_ADDR, IN6_ADDR_0, SOCKADDR_IN6, SOCKADDR_IN6_0,
};

pub struct IcmpPinger {
    target_name: String,
    target: IpAddr,
    ttl: u32,
    size: usize,
    timeout: Duration,
    result_tx: Arc<Mutex<Option<mpsc::Sender<PingResult>>>>,
}

impl IcmpPinger {
    pub fn new(
        target_name: String,
        target: IpAddr,
        ttl: u32,
        size: usize,
        timeout: Duration,
    ) -> Self {
        Self {
            target_name,
            target,
            ttl,
            size,
            timeout,
            result_tx: Arc::new(Mutex::new(None)),
        }
    }
}

#[async_trait]
impl Pinger for IcmpPinger {
    async fn start(&mut self, tx: mpsc::Sender<PingResult>) -> Result<()> {
        *self.result_tx.lock().await = Some(tx);
        Ok(())
    }

    async fn ping(&self, seq: u64) -> Result<()> {
        let Some(tx) = self.result_tx.lock().await.clone() else {
            return Ok(());
        };
        let target_name = self.target_name.clone();
        let target = self.target;
        let ttl = self.ttl;
        let size = self.size;
        let timeout = self.timeout;
        tokio::spawn(async move {
            let result = match tokio::task::spawn_blocking(move || {
                probe_blocking(target, ttl, size, timeout)
            })
            .await
            {
                Ok(result) => result,
                Err(error) => (
                    ProbeStatus::LocalError(format!("ICMP task failed: {error}")),
                    Duration::ZERO,
                    0,
                    None,
                ),
            };
            let _ = tx
                .send(PingResult {
                    target: target_name,
                    target_addr: target,
                    seq,
                    bytes: result.2,
                    ttl: result.3,
                    rtt: result.1,
                    status: result.0,
                })
                .await;
        });
        Ok(())
    }

    async fn stop(&mut self) -> Result<()> {
        Ok(())
    }
}

fn probe_blocking(
    target: IpAddr,
    ttl: u32,
    size: usize,
    timeout: Duration,
) -> (ProbeStatus, Duration, usize, Option<u8>) {
    let result = match target {
        IpAddr::V4(target) => probe_v4(target, ttl, size, timeout),
        IpAddr::V6(target) => probe_v6(target, ttl, size, timeout),
    };
    match result {
        Ok(reply) => (
            ProbeStatus::Success(ResponseType::IcmpEchoReply),
            reply.rtt,
            reply.bytes,
            reply.ttl,
        ),
        Err(failure) => (failure.status, Duration::ZERO, 0, None),
    }
}

struct Reply {
    rtt: Duration,
    bytes: usize,
    ttl: Option<u8>,
}

struct Failure {
    status: ProbeStatus,
}

fn probe_v4(target: Ipv4Addr, ttl: u32, size: usize, timeout: Duration) -> Result<Reply, Failure> {
    let request = vec![0u8; size];
    let request_size = request_size(size)?;
    let ttl = ttl_byte(ttl)?;
    let timeout = timeout_millis(timeout)?;
    let reply_size = size_of::<ICMP_ECHO_REPLY>()
        .checked_add(request.len() + 8)
        .and_then(|size| u32::try_from(size).ok())
        .ok_or_else(|| local_failure("ICMP reply buffer is too large"))?;
    let words = usize::try_from(reply_size)
        .unwrap()
        .div_ceil(size_of::<u64>());
    let mut buffer = vec![0u64; words];
    let options = IP_OPTION_INFORMATION {
        Ttl: ttl,
        ..IP_OPTION_INFORMATION::default()
    };
    let handle = IcmpHandle::new(false)?;
    let replies = unsafe {
        IcmpSendEcho(
            handle.0,
            u32::from_be_bytes(target.octets()),
            request.as_ptr().cast(),
            request_size,
            &options,
            buffer.as_mut_ptr().cast(),
            reply_size,
            timeout,
        )
    };
    if replies == 0 {
        return Err(status_failure());
    }
    let reply = unsafe { std::ptr::read_unaligned(buffer.as_ptr().cast::<ICMP_ECHO_REPLY>()) };
    match reply.Status {
        IP_SUCCESS => Ok(Reply {
            rtt: Duration::from_millis(u64::from(reply.RoundTripTime)),
            bytes: usize::from(reply.DataSize),
            ttl: (reply.Options.Ttl != 0).then_some(reply.Options.Ttl),
        }),
        status => Err(ip_status_failure(
            status,
            (reply.Address != 0).then(|| Ipv4Addr::from(reply.Address).into()),
        )),
    }
}

fn probe_v6(target: Ipv6Addr, ttl: u32, size: usize, timeout: Duration) -> Result<Reply, Failure> {
    let request = vec![0u8; size];
    let request_size = request_size(size)?;
    let ttl = ttl_byte(ttl)?;
    let timeout = timeout_millis(timeout)?;
    let reply_size = size_of::<ICMPV6_ECHO_REPLY_LH>()
        .checked_add(request.len() + 8)
        .and_then(|size| u32::try_from(size).ok())
        .ok_or_else(|| local_failure("ICMPv6 reply buffer is too large"))?;
    let words = usize::try_from(reply_size)
        .unwrap()
        .div_ceil(size_of::<u64>());
    let mut buffer = vec![0u64; words];
    let options = IP_OPTION_INFORMATION {
        Ttl: ttl,
        ..IP_OPTION_INFORMATION::default()
    };
    let source: SOCKADDR_IN6 = unsafe { zeroed() };
    let destination = socket_address(target);
    let handle = IcmpHandle::new(true)?;
    let replies = unsafe {
        Icmp6SendEcho2(
            handle.0,
            std::ptr::null_mut(),
            None,
            std::ptr::null(),
            &source,
            &destination,
            request.as_ptr().cast(),
            request_size,
            &options,
            buffer.as_mut_ptr().cast(),
            reply_size,
            timeout,
        )
    };
    if replies == 0 {
        return Err(status_failure());
    }
    let reply = unsafe { std::ptr::read_unaligned(buffer.as_ptr().cast::<ICMPV6_ECHO_REPLY_LH>()) };
    match reply.Status {
        IP_SUCCESS => Ok(Reply {
            rtt: Duration::from_millis(u64::from(reply.RoundTripTime)),
            bytes: size,
            ttl: None,
        }),
        status => {
            let address = reply.Address;
            let octets = ipv6_reply_octets(address.sin6_addr);
            Err(ip_status_failure(
                status,
                (octets != [0; 16]).then(|| Ipv6Addr::from(octets).into()),
            ))
        }
    }
}

struct IcmpHandle(HANDLE);

impl IcmpHandle {
    fn new(v6: bool) -> Result<Self, Failure> {
        let handle = unsafe {
            if v6 {
                Icmp6CreateFile()
            } else {
                IcmpCreateFile()
            }
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(local_failure(format!(
                "IcmpCreateFile failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(Self(handle))
    }
}

impl Drop for IcmpHandle {
    fn drop(&mut self) {
        unsafe {
            IcmpCloseHandle(self.0);
        }
    }
}

fn request_size(size: usize) -> Result<u16, Failure> {
    u16::try_from(size).map_err(|_| local_failure("ICMP payload must not exceed 65535 bytes"))
}

fn ttl_byte(ttl: u32) -> Result<u8, Failure> {
    u8::try_from(ttl).map_err(|_| local_failure("TTL must be between 0 and 255"))
}

fn timeout_millis(timeout: Duration) -> Result<u32, Failure> {
    u32::try_from(timeout.as_millis().max(1)).map_err(|_| local_failure("timeout is too large"))
}

fn status_failure() -> Failure {
    let error = std::io::Error::last_os_error();
    match error.raw_os_error().map(|code| code as u32) {
        Some(IP_REQ_TIMED_OUT) => Failure {
            status: ProbeStatus::Timeout,
        },
        Some(IP_SUCCESS) => local_failure("ICMP request returned no reply"),
        Some(status) => ip_status_failure(status, None),
        None => local_failure(format!("ICMP request failed: {error}")),
    }
}

fn ip_status_failure(status: u32, node: Option<IpAddr>) -> Failure {
    if status == IP_REQ_TIMED_OUT {
        return Failure {
            status: ProbeStatus::Timeout,
        };
    }
    if (11000..=11050).contains(&status) {
        return Failure {
            status: ProbeStatus::NetworkError {
                node,
                reason: status_reason(status).to_string(),
            },
        };
    }
    local_failure(format!("ICMP request failed with status {status}"))
}

fn status_reason(status: u32) -> &'static str {
    match status {
        IP_DEST_NET_UNREACHABLE => "network unreachable",
        IP_DEST_HOST_UNREACHABLE => "host unreachable",
        IP_DEST_PORT_UNREACHABLE => "port unreachable",
        IP_DEST_PROHIBITED => "communication prohibited",
        IP_TTL_EXPIRED_TRANSIT => "TTL expired in transit",
        IP_TIME_EXCEEDED => "time exceeded",
        _ => "ICMP error",
    }
}

fn local_failure(error: impl ToString) -> Failure {
    Failure {
        status: ProbeStatus::LocalError(error.to_string()),
    }
}

fn socket_address(address: Ipv6Addr) -> SOCKADDR_IN6 {
    SOCKADDR_IN6 {
        sin6_family: AF_INET6,
        sin6_port: 0,
        sin6_flowinfo: 0,
        sin6_addr: IN6_ADDR {
            u: IN6_ADDR_0 {
                Byte: address.octets(),
            },
        },
        Anonymous: SOCKADDR_IN6_0 { sin6_scope_id: 0 },
    }
}

fn ipv6_reply_octets(address: [u16; 8]) -> [u8; 16] {
    let mut octets = [0u8; 16];
    for (index, word) in address.into_iter().enumerate() {
        octets[index * 2..index * 2 + 2].copy_from_slice(&word.to_ne_bytes());
    }
    octets
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv6_reply_words_preserve_network_byte_order() {
        let expected = *b"\x20\x01\x0d\xb8\x00\x01\x00\x02\x00\x03\x00\x04\x00\x05\x00\x06";
        let words = std::array::from_fn(|index| {
            u16::from_ne_bytes([expected[index * 2], expected[index * 2 + 1]])
        });
        assert_eq!(ipv6_reply_octets(words), expected);
    }

    #[test]
    fn maps_ip_helper_statuses_to_reasons() {
        assert_eq!(status_reason(IP_DEST_HOST_UNREACHABLE), "host unreachable");
        assert_eq!(
            status_reason(IP_TTL_EXPIRED_TRANSIT),
            "TTL expired in transit"
        );
    }
}
