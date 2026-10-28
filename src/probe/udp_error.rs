use std::fmt;
use std::net::IpAddr;
#[cfg(any(not(target_os = "linux"), test))]
use std::net::{Ipv4Addr, Ipv6Addr};

const ICMP_DEST_UNREACH_V4: u8 = 3;
const ICMP_TIME_EXCEEDED_V4: u8 = 11;
const ICMP_DEST_UNREACH_V6: u8 = 1;
const ICMP_TIME_EXCEEDED_V6: u8 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UdpProbeKind {
    ApplicationReply,
    PortUnreachable,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct UdpProbeReply {
    pub(crate) kind: UdpProbeKind,
    pub(crate) bytes: usize,
    pub(crate) rtt: std::time::Duration,
}

#[derive(Clone, Debug)]
pub(crate) enum UdpProbeFailure {
    Timeout,
    Network {
        node: Option<IpAddr>,
        reason: String,
    },
    Local(String),
}

impl fmt::Display for UdpProbeFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => f.write_str("request timed out"),
            Self::Network { node, reason } => {
                if let Some(node) = node {
                    write!(f, "network error from {node}: {reason}")
                } else {
                    write!(f, "network error: {reason}")
                }
            }
            Self::Local(error) => write!(f, "local error: {error}"),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct IcmpError {
    pub(crate) node: Option<IpAddr>,
    pub(crate) v6: bool,
    pub(crate) kind: u8,
    pub(crate) code: u8,
}

pub(crate) enum UdpIcmpError {
    PortUnreachable,
    Network {
        node: Option<IpAddr>,
        reason: String,
    },
}

pub(crate) fn classify_icmp(error: IcmpError, target: IpAddr) -> UdpIcmpError {
    match (error.v6, error.kind, error.code) {
        (false, ICMP_DEST_UNREACH_V4, 3) | (true, ICMP_DEST_UNREACH_V6, 4)
            if error.node == Some(target) =>
        {
            UdpIcmpError::PortUnreachable
        }
        _ => UdpIcmpError::Network {
            node: error.node,
            reason: icmp_reason(error.v6, error.kind, error.code).to_string(),
        },
    }
}

#[cfg(any(not(target_os = "linux"), test))]
pub(crate) fn parse_icmp_error(
    data: &[u8],
    from: IpAddr,
    local: IpAddr,
    target: IpAddr,
    source_port: u16,
    target_port: u16,
) -> Option<IcmpError> {
    match target {
        IpAddr::V4(_) => parse_icmp_error_v4(data, from, local, target, source_port, target_port),
        IpAddr::V6(_) => parse_icmp_error_v6(data, from, local, target, source_port, target_port),
    }
}

#[cfg(any(not(target_os = "linux"), test))]
fn parse_icmp_error_v4(
    data: &[u8],
    from: IpAddr,
    local: IpAddr,
    target: IpAddr,
    source_port: u16,
    target_port: u16,
) -> Option<IcmpError> {
    let icmp = if data.len() >= 20 && data[0] >> 4 == 4 {
        let ((source, destination), icmp) = strip_ipv4(data, 1)?;
        if IpAddr::V4(source) != from || IpAddr::V4(destination) != local {
            return None;
        }
        icmp
    } else if data.len() >= 8 && matches!(data[0], ICMP_DEST_UNREACH_V4 | ICMP_TIME_EXCEEDED_V4) {
        data
    } else {
        return None;
    };
    if icmp.len() < 8 || !matches!(icmp[0], ICMP_DEST_UNREACH_V4 | ICMP_TIME_EXCEEDED_V4) {
        return None;
    }
    let embedded = &icmp[8..];
    let (source, destination) = parse_ipv4_addresses(embedded)?;
    if IpAddr::V4(source) != local
        || IpAddr::V4(destination) != target
        || embedded.get(9).copied() != Some(17)
    {
        return None;
    }
    let header_len = usize::from(embedded[0] & 0x0f) * 4;
    if header_len < 20 {
        return None;
    }
    let udp = embedded.get(header_len..)?;
    if udp.len() < 8
        || u16::from_be_bytes([udp[0], udp[1]]) != source_port
        || u16::from_be_bytes([udp[2], udp[3]]) != target_port
    {
        return None;
    }
    Some(IcmpError {
        node: Some(from),
        v6: false,
        kind: icmp[0],
        code: icmp[1],
    })
}

#[cfg(any(not(target_os = "linux"), test))]
fn parse_icmp_error_v6(
    data: &[u8],
    from: IpAddr,
    local: IpAddr,
    target: IpAddr,
    source_port: u16,
    target_port: u16,
) -> Option<IcmpError> {
    let icmp = if data.len() >= 40 && data[0] >> 4 == 6 {
        let ((source, destination), icmp) = strip_ipv6(data, 58)?;
        if IpAddr::V6(source) != from || IpAddr::V6(destination) != local {
            return None;
        }
        icmp
    } else if data.len() >= 8 && matches!(data[0], ICMP_DEST_UNREACH_V6 | ICMP_TIME_EXCEEDED_V6) {
        data
    } else {
        return None;
    };
    if icmp.len() < 8 || !matches!(icmp[0], ICMP_DEST_UNREACH_V6 | ICMP_TIME_EXCEEDED_V6) {
        return None;
    }
    let embedded = &icmp[8..];
    if embedded.len() < 40 {
        return None;
    }
    let source = Ipv6Addr::from(<[u8; 16]>::try_from(&embedded[8..24]).ok()?);
    let destination = Ipv6Addr::from(<[u8; 16]>::try_from(&embedded[24..40]).ok()?);
    if IpAddr::V6(source) != local || IpAddr::V6(destination) != target {
        return None;
    }
    let offset = ipv6_transport_offset(embedded, 17)?;
    let udp = embedded.get(offset..)?;
    if udp.len() < 8
        || u16::from_be_bytes([udp[0], udp[1]]) != source_port
        || u16::from_be_bytes([udp[2], udp[3]]) != target_port
    {
        return None;
    }
    Some(IcmpError {
        node: Some(from),
        v6: true,
        kind: icmp[0],
        code: icmp[1],
    })
}

fn icmp_reason(v6: bool, kind: u8, code: u8) -> &'static str {
    match (v6, kind, code) {
        (false, ICMP_DEST_UNREACH_V4, 0) | (true, ICMP_DEST_UNREACH_V6, 0) => "network unreachable",
        (false, ICMP_DEST_UNREACH_V4, 1) | (true, ICMP_DEST_UNREACH_V6, 1) => "host unreachable",
        (false, ICMP_DEST_UNREACH_V4, 3) | (true, ICMP_DEST_UNREACH_V6, 4) => "port unreachable",
        (false, ICMP_DEST_UNREACH_V4, 13) => "communication prohibited",
        (false, ICMP_TIME_EXCEEDED_V4, _) | (true, ICMP_TIME_EXCEEDED_V6, _) => "time exceeded",
        _ => "ICMP error",
    }
}

#[cfg(any(not(target_os = "linux"), test))]
fn strip_ipv4(data: &[u8], protocol: u8) -> Option<((Ipv4Addr, Ipv4Addr), &[u8])> {
    if data.len() < 20 || data[0] >> 4 != 4 || data[9] != protocol {
        return None;
    }
    let header_len = usize::from(data[0] & 0x0f) * 4;
    if header_len < 20 || data.len() < header_len {
        return None;
    }
    Some((
        (
            Ipv4Addr::new(data[12], data[13], data[14], data[15]),
            Ipv4Addr::new(data[16], data[17], data[18], data[19]),
        ),
        &data[header_len..],
    ))
}

#[cfg(any(not(target_os = "linux"), test))]
fn parse_ipv4_addresses(data: &[u8]) -> Option<(Ipv4Addr, Ipv4Addr)> {
    if data.len() < 20 || data[0] >> 4 != 4 {
        return None;
    }
    Some((
        Ipv4Addr::new(data[12], data[13], data[14], data[15]),
        Ipv4Addr::new(data[16], data[17], data[18], data[19]),
    ))
}

#[cfg(any(not(target_os = "linux"), test))]
fn strip_ipv6(data: &[u8], protocol: u8) -> Option<((Ipv6Addr, Ipv6Addr), &[u8])> {
    if data.len() < 40 || data[0] >> 4 != 6 {
        return None;
    }
    let source = Ipv6Addr::from(<[u8; 16]>::try_from(&data[8..24]).ok()?);
    let destination = Ipv6Addr::from(<[u8; 16]>::try_from(&data[24..40]).ok()?);
    let offset = ipv6_transport_offset(data, protocol)?;
    Some(((source, destination), &data[offset..]))
}

#[cfg(any(not(target_os = "linux"), test))]
fn ipv6_transport_offset(payload: &[u8], protocol: u8) -> Option<usize> {
    if payload.len() < 40 || payload[0] >> 4 != 6 {
        return None;
    }
    let mut offset = 40usize;
    let mut next_header = payload[6];
    loop {
        if offset + 8 > payload.len() {
            return None;
        }
        let length = match next_header {
            0 | 43 | 60 => {
                next_header = payload[offset];
                (usize::from(payload[offset + 1]) + 1) * 8
            }
            44 => {
                if u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]) & 0xfff8 != 0 {
                    return None;
                }
                next_header = payload[offset];
                8
            }
            51 => {
                next_header = payload[offset];
                (usize::from(payload[offset + 1]) + 2) * 4
            }
            _ => break,
        };
        offset = offset.checked_add(length)?;
    }
    (next_header == protocol && offset <= payload.len()).then_some(offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_and_full_ipv6_icmp_errors() {
        let local_v4 = "192.0.2.1".parse::<Ipv4Addr>().unwrap();
        let target_v4 = "198.51.100.2".parse::<Ipv4Addr>().unwrap();
        let embedded_v4 = ipv4_udp_packet(local_v4, target_v4, 40000, 33434);
        let icmp_v4 = icmp_error(ICMP_DEST_UNREACH_V4, 3, &embedded_v4);
        let outer_v4 = ipv4_packet(target_v4, local_v4, 1, &icmp_v4);
        let error = parse_icmp_error(
            &outer_v4,
            target_v4.into(),
            local_v4.into(),
            target_v4.into(),
            40000,
            33434,
        )
        .unwrap();
        assert!(matches!(
            classify_icmp(error, target_v4.into()),
            UdpIcmpError::PortUnreachable
        ));

        let local_v6 = "2001:db8::1".parse::<Ipv6Addr>().unwrap();
        let target_v6 = "2001:db8::2".parse::<Ipv6Addr>().unwrap();
        let router_v6 = "2001:db8::ff".parse::<Ipv6Addr>().unwrap();
        let embedded_v6 = ipv6_udp_packet(local_v6, target_v6, 40000, 33434);
        let icmp_v6 = icmp_error(ICMP_TIME_EXCEEDED_V6, 0, &embedded_v6);
        let outer_v6 = ipv6_packet(router_v6, local_v6, 58, &icmp_v6);
        let error = parse_icmp_error(
            &outer_v6,
            router_v6.into(),
            local_v6.into(),
            target_v6.into(),
            40000,
            33434,
        )
        .unwrap();
        assert!(matches!(
            classify_icmp(error, target_v6.into()),
            UdpIcmpError::Network { node: Some(node), .. }
                if node == IpAddr::V6(router_v6)
        ));
    }

    fn icmp_error(kind: u8, code: u8, embedded: &[u8]) -> Vec<u8> {
        let mut icmp = vec![kind, code, 0, 0, 0, 0, 0, 0];
        icmp.extend_from_slice(embedded);
        icmp
    }

    fn ipv4_packet(source: Ipv4Addr, target: Ipv4Addr, protocol: u8, payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = protocol;
        packet[12..16].copy_from_slice(&source.octets());
        packet[16..20].copy_from_slice(&target.octets());
        packet.extend_from_slice(payload);
        packet
    }

    fn ipv6_packet(source: Ipv6Addr, target: Ipv6Addr, protocol: u8, payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        packet[6] = protocol;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&source.octets());
        packet[24..40].copy_from_slice(&target.octets());
        packet.extend_from_slice(payload);
        packet
    }

    fn ipv4_udp_packet(
        source: Ipv4Addr,
        target: Ipv4Addr,
        source_port: u16,
        target_port: u16,
    ) -> Vec<u8> {
        let mut udp = vec![0u8; 8];
        udp[0..2].copy_from_slice(&source_port.to_be_bytes());
        udp[2..4].copy_from_slice(&target_port.to_be_bytes());
        udp[4..6].copy_from_slice(&8u16.to_be_bytes());
        ipv4_packet(source, target, 17, &udp)
    }

    fn ipv6_udp_packet(
        source: Ipv6Addr,
        target: Ipv6Addr,
        source_port: u16,
        target_port: u16,
    ) -> Vec<u8> {
        let mut udp = vec![0u8; 8];
        udp[0..2].copy_from_slice(&source_port.to_be_bytes());
        udp[2..4].copy_from_slice(&target_port.to_be_bytes());
        udp[4..6].copy_from_slice(&8u16.to_be_bytes());
        ipv6_packet(source, target, 17, &udp)
    }
}
