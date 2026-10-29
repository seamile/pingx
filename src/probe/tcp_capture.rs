use std::collections::HashMap;
use std::ffi::CString;
use std::io;
use std::mem::{self, MaybeUninit};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::{Mutex, OnceLock};
use tokio::io::unix::AsyncFd;
use tokio::sync::broadcast;

const BPF_BUFFER_SIZE: usize = 1 << 16;
const CAPTURE_CHANNEL_SIZE: usize = 4_096;
const DLT_NULL: u32 = 0;
const DLT_EN10MB: u32 = 1;
const DLT_RAW: u32 = 12;
const DLT_LOOP: u32 = 108;

#[derive(Clone, Debug)]
enum CaptureEvent {
    Packet { source: IpAddr, data: Vec<u8> },
    Error(String),
}

static CAPTURES: OnceLock<Mutex<HashMap<String, broadcast::Sender<CaptureEvent>>>> =
    OnceLock::new();

pub(crate) struct TcpCapture {
    receiver: broadcast::Receiver<CaptureEvent>,
}

impl TcpCapture {
    pub(crate) fn new(local: IpAddr) -> io::Result<Self> {
        let interface = interface_for(local)?;
        let mut capture_map = captures().lock().unwrap_or_else(|error| error.into_inner());
        let sender = if let Some(sender) = capture_map.get(&interface) {
            sender.clone()
        } else {
            let capture = BpfCapture::open(&interface)?;
            let (sender, _) = broadcast::channel(CAPTURE_CHANNEL_SIZE);
            let task_sender = sender.clone();
            let task_interface = interface.clone();
            tokio::spawn(async move {
                loop {
                    match capture.recv().await {
                        Ok(packets) => {
                            for (source, data) in packets {
                                if task_sender
                                    .send(CaptureEvent::Packet { source, data })
                                    .is_err()
                                {
                                    break;
                                }
                            }
                        }
                        Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                        Err(error) => {
                            let _ = task_sender.send(CaptureEvent::Error(error.to_string()));
                            break;
                        }
                    }
                }
                captures()
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .remove(&task_interface);
            });
            capture_map.insert(interface, sender.clone());
            sender
        };
        Ok(Self {
            receiver: sender.subscribe(),
        })
    }

    pub(crate) async fn recv(&mut self) -> io::Result<(IpAddr, Vec<u8>)> {
        loop {
            match self.receiver.recv().await {
                Ok(CaptureEvent::Packet { source, data }) => return Ok((source, data)),
                Ok(CaptureEvent::Error(error)) => {
                    return Err(io::Error::other(format!(
                        "macOS TCP packet capture failed: {error}"
                    )));
                }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "macOS TCP packet capture stopped",
                    ));
                }
            }
        }
    }
}

fn captures() -> &'static Mutex<HashMap<String, broadcast::Sender<CaptureEvent>>> {
    CAPTURES.get_or_init(|| Mutex::new(HashMap::new()))
}

fn interface_for(address: IpAddr) -> io::Result<String> {
    let mut interfaces = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut interfaces) } != 0 {
        return Err(io::Error::last_os_error());
    }

    let mut current = interfaces;
    let mut result = None;
    while !current.is_null() {
        let entry = unsafe { &*current };
        if !entry.ifa_name.is_null() && !entry.ifa_addr.is_null() {
            let interface_address = unsafe { &*entry.ifa_addr };
            let matches = match (address, interface_address.sa_family as i32) {
                (IpAddr::V4(address), libc::AF_INET) => unsafe {
                    let socket = &*(entry.ifa_addr as *const libc::sockaddr_in);
                    address == Ipv4Addr::from(socket.sin_addr.s_addr.to_ne_bytes())
                },
                (IpAddr::V6(address), libc::AF_INET6) => unsafe {
                    let socket = &*(entry.ifa_addr as *const libc::sockaddr_in6);
                    address == Ipv6Addr::from(socket.sin6_addr.s6_addr)
                },
                _ => false,
            };
            if matches {
                result = unsafe { std::ffi::CStr::from_ptr(entry.ifa_name) }
                    .to_str()
                    .ok()
                    .map(str::to_owned);
                if result.is_some() {
                    break;
                }
            }
        }
        current = entry.ifa_next;
    }
    unsafe { libc::freeifaddrs(interfaces) };
    result.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("no interface owns local address {address}"),
        )
    })
}

struct BpfCapture {
    fd: AsyncFd<OwnedFd>,
    data_link_type: u32,
    buffer_size: usize,
}

impl BpfCapture {
    fn open(interface: &str) -> io::Result<Self> {
        let mut last_error = None;
        for index in 0..256 {
            let path = CString::new(format!("/dev/bpf{index}")).expect("BPF path has no NUL");
            let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_NONBLOCK) };
            if fd < 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::EBUSY)
                    || error.raw_os_error() == Some(libc::ENOENT)
                {
                    last_error = Some(error);
                    continue;
                }
                return Err(if error.kind() == io::ErrorKind::PermissionDenied {
                    io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "macOS TCP SYN ping requires root privileges; run with sudo",
                    )
                } else {
                    error
                });
            }
            let fd = unsafe { OwnedFd::from_raw_fd(fd) };
            let buffer_size = match configure(fd.as_raw_fd(), interface) {
                Ok(buffer_size) => buffer_size,
                Err(error) if error.raw_os_error() == Some(libc::EBUSY) => {
                    last_error = Some(error);
                    continue;
                }
                Err(error) => return Err(error),
            };
            let mut data_link_type = 0u32;
            if unsafe {
                libc::ioctl(
                    fd.as_raw_fd(),
                    libc::BIOCGDLT,
                    &mut data_link_type as *mut u32,
                )
            } != 0
            {
                return Err(ioctl_error(
                    "read BPF data-link type",
                    io::Error::last_os_error(),
                ));
            }
            if !matches!(data_link_type, DLT_NULL | DLT_EN10MB | DLT_RAW | DLT_LOOP) {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!("unsupported BPF data-link type {data_link_type} on {interface}"),
                ));
            }
            let filter = tcp_filter(data_link_type)
                .map_err(|error| ioctl_error("build BPF TCP filter", error))?;
            if unsafe { libc::ioctl(fd.as_raw_fd(), libc::BIOCSETF, &filter) } != 0 {
                return Err(ioctl_error(
                    "install BPF TCP filter",
                    io::Error::last_os_error(),
                ));
            }
            return Ok(Self {
                fd: unsafe { AsyncFd::register(fd) }
                    .map_err(|error| ioctl_error("register BPF device", error.into()))?,
                data_link_type,
                buffer_size,
            });
        }
        Err(last_error.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "no macOS BPF device available",
            )
        }))
    }

    async fn recv(&self) -> io::Result<Vec<(IpAddr, Vec<u8>)>> {
        loop {
            let mut guard = self.fd.readable().await?;
            match guard.try_io(|inner| {
                read_packets(inner.get_ref(), self.data_link_type, self.buffer_size)
            }) {
                Ok(result) => return result,
                Err(_) => continue,
            }
        }
    }
}

fn configure(fd: RawFd, interface: &str) -> io::Result<usize> {
    let mut buffer_size = BPF_BUFFER_SIZE as u32;
    if unsafe { libc::ioctl(fd, libc::BIOCSBLEN, &mut buffer_size) } != 0 {
        return Err(ioctl_error(
            "set BPF buffer size",
            io::Error::last_os_error(),
        ));
    }

    let mut request = IfReq::zeroed();
    let name = interface.as_bytes();
    if name.len() >= request.name.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("interface name is too long: {interface}"),
        ));
    }
    for (target, source) in request.name.iter_mut().zip(name) {
        *target = *source as libc::c_char;
    }
    if unsafe { libc::ioctl(fd, libc::BIOCSETIF, &request) } != 0 {
        return Err(ioctl_error("set BPF interface", io::Error::last_os_error()));
    }

    let immediate: libc::c_uint = 1;
    if unsafe { libc::ioctl(fd, libc::BIOCIMMEDIATE, &immediate) } != 0 {
        return Err(ioctl_error(
            "enable immediate BPF mode",
            io::Error::last_os_error(),
        ));
    }
    let see_sent: libc::c_uint = 1;
    if unsafe { libc::ioctl(fd, libc::BIOCSSEESENT, &see_sent) } != 0 {
        return Err(ioctl_error(
            "enable sent BPF packets",
            io::Error::last_os_error(),
        ));
    }
    let timeout = libc::timeval {
        tv_sec: 0,
        tv_usec: 10_000,
    };
    if unsafe { libc::ioctl(fd, libc::BIOCSRTIMEOUT, &timeout) } != 0 {
        return Err(ioctl_error(
            "set BPF read timeout",
            io::Error::last_os_error(),
        ));
    }
    let mut buffer_size = 0u32;
    if unsafe { libc::ioctl(fd, libc::BIOCGBLEN, &mut buffer_size) } != 0 {
        return Err(ioctl_error(
            "read BPF buffer size",
            io::Error::last_os_error(),
        ));
    }
    Ok(buffer_size as usize)
}

fn ioctl_error(stage: &str, error: io::Error) -> io::Error {
    io::Error::new(error.kind(), format!("{stage}: {error}"))
}

fn tcp_filter(data_link_type: u32) -> io::Result<BpfProgram> {
    let ip_offset = match data_link_type {
        DLT_NULL | DLT_LOOP => 4,
        DLT_EN10MB => 14,
        DLT_RAW => 0,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "unsupported BPF data-link type",
            ));
        }
    };
    Ok(BpfProgram::new(vec![
        BpfInsn::new(0x30, 0, 0, ip_offset as u32),
        BpfInsn::new(0x54, 0, 0, 0xf0),
        BpfInsn::new(0x15, 0, 1, 0x40),
        BpfInsn::new(0x06, 0, 0, u32::MAX),
        BpfInsn::new(0x15, 0, 1, 0x60),
        BpfInsn::new(0x06, 0, 0, u32::MAX),
        BpfInsn::new(0x06, 0, 0, 0),
    ]))
}

fn read_packets(
    fd: &OwnedFd,
    data_link_type: u32,
    buffer_size: usize,
) -> io::Result<Vec<(IpAddr, Vec<u8>)>> {
    let mut buffer = vec![0u8; buffer_size];
    let size = unsafe { libc::read(fd.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len()) };
    if size < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(parse_packets(&buffer[..size as usize], data_link_type))
}

fn parse_packets(buffer: &[u8], data_link_type: u32) -> Vec<(IpAddr, Vec<u8>)> {
    let mut packets = Vec::new();
    let header_size = mem::size_of::<libc::bpf_hdr>();
    let mut offset = 0usize;
    while offset
        .checked_add(header_size)
        .is_some_and(|end| end <= buffer.len())
    {
        let header =
            unsafe { std::ptr::read_unaligned(buffer[offset..].as_ptr().cast::<libc::bpf_hdr>()) };
        let packet_start = offset + usize::from(header.bh_hdrlen);
        let packet_end = packet_start + header.bh_caplen as usize;
        let Some(frame) = buffer.get(packet_start..packet_end) else {
            break;
        };
        if let Some((source, packet)) = parse_frame(frame, data_link_type) {
            packets.push((source, packet.to_vec()));
        }
        offset = offset
            .saturating_add(usize::from(header.bh_hdrlen))
            .saturating_add(header.bh_caplen as usize);
        offset = (offset + 3) & !3;
    }
    packets
}

fn parse_frame(frame: &[u8], data_link_type: u32) -> Option<(IpAddr, &[u8])> {
    let packet = match data_link_type {
        DLT_NULL | DLT_LOOP => frame.get(4..)?,
        DLT_EN10MB => {
            let ether_type = u16::from_be_bytes([*frame.get(12)?, *frame.get(13)?]);
            if !matches!(ether_type, 0x0800 | 0x86dd) {
                return None;
            }
            frame.get(14..)?
        }
        DLT_RAW => frame,
        _ => return None,
    };
    let source = match packet.first()? >> 4 {
        4 if packet.len() >= 20 => IpAddr::V4(Ipv4Addr::new(
            packet[12], packet[13], packet[14], packet[15],
        )),
        6 if packet.len() >= 40 => {
            IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?))
        }
        _ => return None,
    };
    Some((source, packet))
}

type RawFd = libc::c_int;

#[repr(C)]
struct IfReq {
    name: [libc::c_char; 16],
    value: [u8; 16],
}

impl IfReq {
    fn zeroed() -> Self {
        unsafe { MaybeUninit::<Self>::zeroed().assume_init() }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct BpfInsn {
    code: libc::c_ushort,
    jt: libc::c_uchar,
    jf: libc::c_uchar,
    k: u32,
}

impl BpfInsn {
    const fn new(code: libc::c_ushort, jt: libc::c_uchar, jf: libc::c_uchar, k: u32) -> Self {
        Self { code, jt, jf, k }
    }
}

#[repr(C)]
struct BpfProgram {
    length: libc::c_uint,
    instructions: *mut BpfInsn,
    storage: Vec<BpfInsn>,
}

impl BpfProgram {
    fn new(instructions: Vec<BpfInsn>) -> Self {
        let mut program = Self {
            length: instructions.len() as libc::c_uint,
            instructions: std::ptr::null_mut(),
            storage: instructions,
        };
        program.instructions = program.storage.as_mut_ptr();
        program
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bpf_packets_after_link_headers() {
        let mut frame = vec![0u8; 4 + 20 + 20];
        frame[4] = 0x45;
        frame[16..20].copy_from_slice(&[192, 0, 2, 1]);
        let header_size = mem::size_of::<libc::bpf_hdr>();
        let mut capture = vec![0u8; header_size + frame.len() + 3];
        let header = libc::bpf_hdr {
            bh_tstamp: libc::timeval32 {
                tv_sec: 0,
                tv_usec: 0,
            },
            bh_caplen: frame.len() as u32,
            bh_datalen: frame.len() as u32,
            bh_hdrlen: header_size as libc::c_ushort,
        };
        unsafe {
            std::ptr::write_unaligned(capture.as_mut_ptr().cast::<libc::bpf_hdr>(), header);
        }
        capture[header_size..header_size + frame.len()].copy_from_slice(&frame);

        let packets = parse_packets(&capture, DLT_NULL);
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].0, "192.0.2.1".parse::<IpAddr>().unwrap());
        assert_eq!(packets[0].1.len(), 40);
    }

    #[test]
    fn filters_ipv4_and_ipv6_frames() {
        assert_eq!(tcp_filter(DLT_NULL).unwrap().length, 7);

        let mut ipv4 = vec![0u8; 4 + 20];
        ipv4[4] = 0x45;
        ipv4[4 + 9] = 6;
        assert!(parse_frame(&ipv4, DLT_NULL).is_some());

        let mut ipv6 = vec![0u8; 4 + 48];
        ipv6[4] = 0x60;
        ipv6[4 + 6] = 60;
        ipv6[4 + 40] = 6;
        ipv6[4 + 8..4 + 24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        assert!(parse_frame(&ipv6, DLT_NULL).is_some());
    }

    #[test]
    fn bpf_requests_sent_packets() {
        assert_eq!(libc::BIOCSSEESENT, 0x80044277);
    }
}
