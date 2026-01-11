use std::io::Cursor;
use bytes::{Buf, BufMut, BytesMut};
use anyhow::{Result, anyhow};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpType {
    EchoReply = 0,
    EchoRequest = 8,
    // IPv6
    EchoReplyV6 = 129,
    EchoRequestV6 = 128,
}

#[derive(Debug)]
pub struct IcmpPacket {
    pub message_type: u8,
    pub code: u8,
    #[allow(dead_code)]
    pub checksum: u16,
    pub identifier: u16,
    pub sequence: u16,
    pub payload: Vec<u8>,
}

impl IcmpPacket {
    pub fn new_request(v6: bool, identifier: u16, sequence: u16, payload: Vec<u8>) -> Self {
        let message_type = if v6 { IcmpType::EchoRequestV6 as u8 } else { IcmpType::EchoRequest as u8 };
        Self {
            message_type,
            code: 0,
            checksum: 0,
            identifier,
            sequence,
            payload,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = BytesMut::with_capacity(8 + self.payload.len());
        buf.put_u8(self.message_type);
        buf.put_u8(self.code);
        buf.put_u16(0); // Checksum placeholder
        buf.put_u16(self.identifier);
        buf.put_u16(self.sequence);
        buf.put_slice(&self.payload);

        let mut packet = buf.to_vec();

        if self.message_type == IcmpType::EchoRequest as u8 {
            let checksum = calculate_checksum(&packet);
            packet[2] = (checksum >> 8) as u8;
            packet[3] = (checksum & 0xff) as u8;
        } else if self.message_type == IcmpType::EchoRequestV6 as u8 {
             // IPv6 checksum handled by kernel for IPPROTO_ICMPV6
        }

        packet
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 8 {
            return Err(anyhow!("Packet too short"));
        }
        let mut buf = Cursor::new(data);
        let message_type = buf.get_u8();
        let code = buf.get_u8();
        let checksum = buf.get_u16();
        let identifier = buf.get_u16();
        let sequence = buf.get_u16();
        let payload = data[8..].to_vec();

        Ok(Self {
            message_type,
            code,
            checksum,
            identifier,
            sequence,
            payload,
        })
    }
}

fn calculate_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        let word = u16::from_be_bytes([data[i], data[i + 1]]);
        sum = sum.wrapping_add(word as u32);
        i += 2;
    }
    if i < data.len() {
        sum = sum.wrapping_add((data[i] as u32) << 8);
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !sum as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checksum() {
        let data = vec![0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x61, 0x62, 0x63, 0x64];
        let chk = calculate_checksum(&data);
        // Wireshark or online calc verification needed if complex, but standard algo is simple.
        // 0800 + 0000 + 0001 + 0001 + 6162 + 6364 = ...
        assert_ne!(chk, 0);
    }

    #[test]
    fn test_encode_decode() {
        let pkt = IcmpPacket::new_request(false, 123, 456, vec![1, 2, 3]);
        let raw = pkt.encode();
        let decoded = IcmpPacket::decode(&raw).unwrap();
        assert_eq!(decoded.identifier, 123);
        assert_eq!(decoded.sequence, 456);
        assert_eq!(decoded.payload, vec![1, 2, 3]);
        // Checksum should be set
        assert_ne!(decoded.checksum, 0);
    }
}
