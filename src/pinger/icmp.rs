use crate::pinger::Pinger;
use crate::pinger::icmp_packet::{IcmpPacket, IcmpType};
use crate::session::{PingResult, ProbeStatus};
use anyhow::{Result, anyhow};
use async_trait::async_trait;
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
#[cfg(unix)]
use tokio::io::unix::AsyncFd;
use std::mem::MaybeUninit;
use tokio::sync::{mpsc, oneshot, Mutex, Notify};

pub struct IcmpPinger {
    target_name: String,
    target: IpAddr,
    id: u16,
    ttl: u32,
    size: usize,
    timeout: Duration,
    state: Arc<SocketState>,
    result_tx: Arc<Mutex<Option<mpsc::Sender<PingResult>>>>,
    stop_notify: Arc<Notify>,
}

type InflightMap = HashMap<u16, oneshot::Sender<(IcmpPacket, Duration, Option<u8>)>>;

struct SocketState {
    socket: Mutex<Option<Arc<AsyncFd<Socket>>>>,
    inflight: Mutex<InflightMap>,
}

impl IcmpPinger {
    pub fn new(target_name: String, target: IpAddr, ttl: u32, size: usize, timeout: Duration) -> Self {
        let id = (std::process::id() % u16::MAX as u32) as u16;
        Self {
            target_name,
            target,
            id,
            ttl,
            size,
            timeout,
            state: Arc::new(SocketState {
                socket: Mutex::new(None),
                inflight: Mutex::new(HashMap::new()),
            }),
            result_tx: Arc::new(Mutex::new(None)),
            stop_notify: Arc::new(Notify::new()),
        }
    }

    #[cfg(unix)]
    async fn receiver_loop(
        socket: Arc<AsyncFd<Socket>>,
        state: Arc<SocketState>,
        my_id: u16,
        is_ipv6: bool,
        stop_notify: Arc<Notify>,
    ) {
        let mut buf = [MaybeUninit::uninit(); 2048];
        loop {
            tokio::select! {
                _ = stop_notify.notified() => {
                    break;
                }
                res = socket.readable() => {
                    match res {
                        Ok(mut guard) => {
                             match socket.get_ref().recv_from(&mut buf) {
                                Ok((n, _addr)) => {
                                    guard.clear_ready();
                                    
                                    let packet_data = unsafe {
                                        std::slice::from_raw_parts(buf.as_ptr() as *const u8, n)
                                    };


                                    let (icmp_bytes, ttl) = if is_ipv6 {
                                        (packet_data, None)
                                    } else {
                                        if packet_data.len() < 20 { continue; }
                                        let version_ihl = packet_data[0];
                                        let ihl = (version_ihl & 0x0f) * 4;
                                        if packet_data.len() < ihl as usize { continue; }
                                        let ttl = packet_data[8];
                                        (&packet_data[ihl as usize..], Some(ttl))
                                    };

                                    if let Ok(packet) = IcmpPacket::decode(icmp_bytes) {
                                        let is_reply = if is_ipv6 {
                                            packet.message_type == IcmpType::EchoReplyV6 as u8
                                        } else {
                                            packet.message_type == IcmpType::EchoReply as u8
                                        };

                                        if is_reply && packet.identifier == my_id {
                                             let mut map = state.inflight.lock().await;
                                             if let Some(tx) = map.remove(&packet.sequence) {
                                                 let _ = tx.send((packet, Duration::ZERO, ttl));
                                             }
                                        }
                                    }
                                }
                                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                    guard.clear_ready();
                                }
                                Err(_) => {
                                    guard.clear_ready();
                                }
                            }
                        }
                        Err(_) => break,
                    }
                }
            }
        }
    }

    async fn send_result(&self, res: PingResult) {
        let guard = self.result_tx.lock().await;
        if let Some(tx) = guard.as_ref() {
            let _ = tx.send(res).await;
        }
    }
}

#[async_trait]
impl Pinger for IcmpPinger {
    async fn start(&mut self, tx: mpsc::Sender<PingResult>) -> Result<()> {
        {
            let mut guard = self.result_tx.lock().await;
            *guard = Some(tx);
        }

        let domain = if self.target.is_ipv6() { Domain::IPV6 } else { Domain::IPV4 };
        let protocol = if self.target.is_ipv6() { Protocol::ICMPV6 } else { Protocol::ICMPV4 };
        
        let socket = Socket::new(domain, Type::RAW, Some(protocol))?;
        socket.set_nonblocking(true)?;
        
        if !self.target.is_ipv6() {
            socket.set_ttl(self.ttl)?;
        } else {
            socket.set_unicast_hops_v6(self.ttl)?;
        }

        // Bind
        let addr = if self.target.is_ipv6() {
            SocketAddr::new("::".parse().unwrap(), 0)
        } else {
            SocketAddr::new("0.0.0.0".parse().unwrap(), 0)
        };
        socket.bind(&addr.into())?;

        #[cfg(unix)]
        let async_fd = AsyncFd::new(socket)?;
        #[cfg(not(unix))]
        return Err(anyhow!("Windows not supported yet")); // Placeholder

        let socket_arc = Arc::new(async_fd);

        // Store socket
        {
            let mut guard = self.state.socket.lock().await;
            *guard = Some(socket_arc.clone());
        }

        // Spawn receiver
        let state = self.state.clone();
        let my_id = self.id;
        let is_ipv6 = self.target.is_ipv6();
        let stop_notify = self.stop_notify.clone();
        
        #[cfg(unix)]
        tokio::spawn(async move {
             Self::receiver_loop(socket_arc, state, my_id, is_ipv6, stop_notify).await;
        });

        Ok(())
    }

    async fn ping(&self, seq: u64) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        let seq_u16 = seq as u16;

        {
            let mut guard = self.state.inflight.lock().await;
            guard.insert(seq_u16, tx);
        }

        let payload = vec![0u8; self.size];
        let packet = IcmpPacket::new_request(self.target.is_ipv6(), self.id, seq_u16, payload);
        let encoded = packet.encode();

        let start_time = Instant::now();

        // Send
        {
            let socket_guard = self.state.socket.lock().await;
            if let Some(socket) = socket_guard.as_ref() {
                let addr = SocketAddr::new(self.target, 0);
                match socket.get_ref().send_to(&encoded, &addr.into()) {
                    Ok(_) => {},
                    Err(e) => {
                         let mut map = self.state.inflight.lock().await;
                         map.remove(&seq_u16);
                         drop(map); 
                         
                         self.send_result(PingResult {
                            target: self.target_name.clone(),
                            target_addr: self.target,
                            seq,
                            bytes: 0,
                            ttl: None,
                            rtt: Duration::ZERO,
                            status: ProbeStatus::Error(e.to_string()),
                        }).await;
                        return Ok(());
                    }
                }
            } else {
                 return Err(anyhow!("Socket not started"));
            }
        } 

        let timeout = self.timeout;
        
        match tokio::time::timeout(timeout, rx).await {
            Ok(Ok((_packet, _, ttl))) => {
                let rtt = start_time.elapsed();
                self.send_result(PingResult {
                    target: self.target_name.clone(),
                    target_addr: self.target,
                    seq,
                    bytes: self.size,
                    ttl,
                    rtt,
                    status: ProbeStatus::Success,
                }).await;
            },
            Ok(Err(_)) => {
                 self.send_result(PingResult {
                    target: self.target_name.clone(),
                    target_addr: self.target,
                    seq,
                    bytes: 0,
                    ttl: None,
                    rtt: Duration::ZERO,
                    status: ProbeStatus::Error("Receiver closed".into()),
                }).await;
            },
            Err(_) => {
                // Timeout
                {
                    let mut map = self.state.inflight.lock().await;
                    map.remove(&seq_u16);
                }
                self.send_result(PingResult {
                    target: self.target_name.clone(),
                    target_addr: self.target,
                    seq,
                    bytes: 0,
                    ttl: None,
                    rtt: Duration::ZERO,
                    status: ProbeStatus::Timeout,
                }).await;
            }
        }

        Ok(())
    }

    async fn stop(&mut self) -> Result<()> {
        self.stop_notify.notify_waiters();
        Ok(())
    }
}

impl Drop for IcmpPinger {
    fn drop(&mut self) {
        self.stop_notify.notify_waiters();
    }
}