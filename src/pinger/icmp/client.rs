use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd};

use parking_lot::Mutex;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::unix::AsyncFd;
use tokio::sync::oneshot;
use tokio::task::{self, JoinHandle};

use crate::pinger::icmp_packet::{IcmpPacket, IcmpType};

#[derive(Clone)]
pub struct AsyncSocket {
    inner: Arc<AsyncFd<std::net::UdpSocket>>,
    sock_type: Type,
}

impl AsyncSocket {
    pub fn new(v6: bool, ttl: u32) -> io::Result<Self> {
        let (sock_type, socket) = Self::create_socket(v6)?;
        
        socket.set_nonblocking(true)?;

        if v6 {
            socket.set_unicast_hops_v6(ttl)?;
            // Enable receiving Hop Limit (TTL) via CMSG
            // IPV6_RECVHOPLIMIT is standard (RFC 3542)
            let on: libc::c_int = 1;
            unsafe {
                let ret = libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::IPPROTO_IPV6,
                    libc::IPV6_RECVHOPLIMIT,
                    &on as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&on) as libc::socklen_t,
                );
                if ret != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
        } else {
            socket.set_ttl(ttl)?;
            // Enable receiving TTL via CMSG
            let on: libc::c_int = 1;
             unsafe {
                // IP_RECVTTL is standard for Linux/macOS
                let ret = libc::setsockopt(
                    socket.as_raw_fd(),
                    libc::IPPROTO_IP,
                    libc::IP_RECVTTL,
                    &on as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&on) as libc::socklen_t,
                );
                if ret != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
        }
        
        let std_sock = unsafe { std::net::UdpSocket::from_raw_fd(socket.into_raw_fd()) };
        let async_fd = AsyncFd::new(std_sock)?;

        Ok(Self {
            inner: Arc::new(async_fd),
            sock_type,
        })
    }

    fn create_socket(v6: bool) -> io::Result<(Type, Socket)> {
        let (domain, proto) = if v6 {
            (Domain::IPV6, Some(Protocol::ICMPV6))
        } else {
            (Domain::IPV4, Some(Protocol::ICMPV4))
        };

        // Try DGRAM first (unprivileged mode on Linux)
        match Socket::new(domain, Type::DGRAM, proto) {
            Ok(sock) => Ok((Type::DGRAM, sock)),
            Err(_) => {
                // Fallback to RAW
                let sock = Socket::new(domain, Type::RAW, proto)?;
                Ok((Type::RAW, sock))
            }
        }
    }

    pub async fn recv_msg(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr, Option<u8>)> {
        loop {
            let mut guard = self.inner.readable().await?;

            match guard.try_io(|inner| {
                let fd = inner.get_ref().as_raw_fd();
                let mut iov = libc::iovec {
                    iov_base: buf.as_mut_ptr() as *mut _,
                    iov_len: buf.len(),
                };
                let mut msg_name: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
                let mut control_buf = [0u8; 1024];
                
                let mut msg = libc::msghdr {
                    msg_name: &mut msg_name as *mut _ as *mut _,
                    msg_namelen: std::mem::size_of_val(&msg_name) as libc::socklen_t,
                    msg_iov: &mut iov,
                    msg_iovlen: 1,
                    msg_control: control_buf.as_mut_ptr() as *mut _,
                    msg_controllen: control_buf.len() as libc::socklen_t,
                    msg_flags: 0,
                };

                let ret = unsafe { libc::recvmsg(fd, &mut msg, 0) };
                if ret < 0 {
                    let err = io::Error::last_os_error();
                    if err.kind() == io::ErrorKind::WouldBlock {
                        return Err(err);
                    }
                    return Err(err);
                }
                
                let n = ret as usize;
                
                // Parse address
                let addr = unsafe {
                    let ptr = &msg_name as *const libc::sockaddr_storage;
                    let (_, sock_addr) = socket2::SockAddr::try_init(|storage, len| {
                        std::ptr::copy_nonoverlapping(ptr, storage as *mut _, 1);
                        *len = msg.msg_namelen;
                        Ok(())
                    })?;
                    sock_addr.as_socket().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid address"))?
                };

                // Parse CMSG for TTL
                let mut ttl = None;
                unsafe {
                    let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
                    while !cmsg.is_null() {
                        let level = (*cmsg).cmsg_level;
                        let type_ = (*cmsg).cmsg_type;
                        
                        if level == libc::IPPROTO_IP && type_ == libc::IP_TTL {
                             let ptr = libc::CMSG_DATA(cmsg) as *const libc::c_int;
                             ttl = Some(*ptr as u8);
                        } else if level == libc::IPPROTO_IPV6 && type_ == libc::IPV6_HOPLIMIT {
                             let ptr = libc::CMSG_DATA(cmsg) as *const libc::c_int;
                             ttl = Some(*ptr as u8);
                        }
                        
                        cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
                    }
                }

                Ok((n, addr, ttl))
            }) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    pub async fn send_to(&self, buf: &[u8], target: &SocketAddr) -> io::Result<usize> {
        loop {
            let mut guard = self.inner.writable().await?;
            match guard.try_io(|inner| inner.get_ref().send_to(buf, target)) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }
    
    pub fn get_type(&self) -> Type {
        self.sock_type
    }
}

#[derive(PartialEq, Eq, Hash, Debug)]
struct ReplyToken(IpAddr, Option<u16>, u16);

pub struct Reply {
    pub timestamp: Instant,
    #[allow(dead_code)]
    pub packet: IcmpPacket,
    pub ttl: Option<u8>,
}

#[derive(Clone, Default)]
struct ReplyMap {
    inner: Arc<Mutex<HashMap<ReplyToken, oneshot::Sender<Reply>>>>,
}

impl ReplyMap {
    pub fn new_waiter(
        &self,
        host: IpAddr,
        ident: Option<u16>,
        seq: u16,
    ) -> oneshot::Receiver<Reply> {
        let (tx, rx) = oneshot::channel();
        self.inner.lock().insert(ReplyToken(host, ident, seq), tx);
        rx
    }

    pub fn remove(
        &self,
        host: IpAddr,
        ident: Option<u16>,
        seq: u16,
    ) {
        self.inner.lock().remove(&ReplyToken(host, ident, seq));
    }
    
    pub fn dispatch(&self, host: IpAddr, ident: Option<u16>, seq: u16, reply: Reply) {
        if let Some(tx) = self.inner.lock().remove(&ReplyToken(host, ident, seq)) {
            let _ = tx.send(reply);
        }
    }
}

#[derive(Clone)]
pub struct IcmpClient {
    socket: AsyncSocket,
    reply_map: ReplyMap,
    recv_task: Arc<JoinHandle<()>>, 
}

impl IcmpClient {
    pub fn new(v6: bool, ttl: u32) -> io::Result<Self> {
        let socket = AsyncSocket::new(v6, ttl)?;
        let reply_map = ReplyMap::default();
        
        let socket_clone = socket.clone();
        let map_clone = reply_map.clone();
        
        let recv_task = task::spawn(async move {
            let mut buf = [0u8; 2048];
            loop {
                match socket_clone.recv_msg(&mut buf).await {
                    Ok((sz, addr, msg_ttl)) => {
                        let timestamp = Instant::now();
                        let data = &buf[..sz];
                        
                        let is_v6 = addr.ip().is_ipv6();
                        let socket_type = socket_clone.get_type();
                        
                        let (icmp_bytes, ttl) = if is_v6 {
                            (data, msg_ttl)
                        } else {
                            // Adaptive IPv4 header skipping
                            // Note: If using RAW socket, kernel might pass IP header. 
                            // If DGRAM, it might not.
                            // If we have msg_ttl (from CMSG), we prefer it.
                            if data.len() >= 20 && (data[0] >> 4) == 4 {
                                let ihl = (data[0] & 0x0f) as usize * 4;
                                if data.len() >= ihl {
                                    // Header TTL is at offset 8
                                    let header_ttl = data[8];
                                    (&data[ihl..], msg_ttl.or(Some(header_ttl)))
                                } else {
                                    (data, msg_ttl)
                                }
                            } else {
                                (data, msg_ttl)
                            }
                        };

                        if let Ok(packet) = IcmpPacket::decode(icmp_bytes) {
                             let is_reply = if is_v6 {
                                packet.message_type == IcmpType::EchoReplyV6 as u8
                            } else {
                                packet.message_type == IcmpType::EchoReply as u8
                            };
                            
                            if is_reply {
                                let ident = if socket_type == Type::DGRAM {
                                    None
                                } else {
                                    Some(packet.identifier)
                                };
                                
                                map_clone.dispatch(
                                    addr.ip(), 
                                    ident, 
                                    packet.sequence, 
                                    Reply { timestamp, packet, ttl }
                                );
                            }
                        }
                    }
                    Err(e) => {
                         eprintln!("ICMP recv error: {}", e);
                    }
                }
            }
        });

        Ok(Self {
            socket,
            reply_map,
            recv_task: Arc::new(recv_task),
        })
    }
    
    pub fn get_socket(&self) -> &AsyncSocket {
        &self.socket
    }
    
    pub fn register(&self, host: IpAddr, ident: Option<u16>, seq: u16) -> oneshot::Receiver<Reply> {
        self.reply_map.new_waiter(host, ident, seq)
    }
    
    pub fn unregister(&self, host: IpAddr, ident: Option<u16>, seq: u16) {
        self.reply_map.remove(host, ident, seq);
    }
}

impl Drop for IcmpClient {
    fn drop(&mut self) {
        if Arc::strong_count(&self.recv_task) <= 1 {
            self.recv_task.abort();
        }
    }
}