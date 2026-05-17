// Wire format for stream multiplexing across a norn-rs PacketConn.
//
// Layout:
//   +------+------+--------------+----------------------+
//   | ver  | kind | stream_id    | payload (variable)   |
//   | 1B   | 1B   | 4B big-endian|                      |
//   +------+------+--------------+----------------------+
//
// The PacketConn already supplies the source pub key on read, so frames
// carry no source field. Destination routing happens at the PacketConn
// layer; the frame is opaque to it.

use anyhow::{bail, Result};
use std::net::SocketAddr;

use crate::StreamId;

pub const PROTO_VERSION: u8 = 1;
pub const HEADER_SIZE: usize = 6;
/// Worst-case bytes added by the framing layer on top of payload data.
/// Used to compute the effective MTU for stream chunking.
pub const MAX_FRAME_OVERHEAD: usize = HEADER_SIZE;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameKind {
    Open    = 0x01,
    Data    = 0x02,
    /// Graceful half-close — peer signals it will write no more bytes.
    Close   = 0x03,
    /// Abortive close with an error code byte.
    Reset   = 0x04,
    /// Response to Open: 0x00 success, anything else = SOCKS5 reply code.
    OpenAck = 0x05,
}

impl FrameKind {
    fn from_byte(b: u8) -> Option<Self> {
        Some(match b {
            0x01 => Self::Open,
            0x02 => Self::Data,
            0x03 => Self::Close,
            0x04 => Self::Reset,
            0x05 => Self::OpenAck,
            _ => return None,
        })
    }
}

/// The CONNECT target carried in an Open frame. Mirrors the SOCKS5 ATYP
/// field so we can pass through hostnames without forcing DNS on the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenTarget {
    V4(std::net::Ipv4Addr, u16),
    V6(std::net::Ipv6Addr, u16),
    /// `len` ≤ 255 by SOCKS5 spec.
    Domain(String, u16),
}

impl OpenTarget {
    pub fn from_socket_addr(sa: SocketAddr) -> Self {
        match sa {
            SocketAddr::V4(v4) => Self::V4(*v4.ip(), v4.port()),
            SocketAddr::V6(v6) => Self::V6(*v6.ip(), v6.port()),
        }
    }

    /// For logging / metrics — domain targets render as "host:port".
    pub fn display(&self) -> String {
        match self {
            Self::V4(ip, port) => format!("{ip}:{port}"),
            Self::V6(ip, port) => format!("[{ip}]:{port}"),
            Self::Domain(d, port) => format!("{d}:{port}"),
        }
    }

    fn encode_into(&self, out: &mut Vec<u8>) -> Result<()> {
        match self {
            Self::V4(ip, port) => {
                out.push(0x01);
                out.extend_from_slice(&ip.octets());
                out.extend_from_slice(&port.to_be_bytes());
            }
            Self::Domain(host, port) => {
                if host.len() > 255 {
                    bail!("domain target longer than 255 bytes ({})", host.len());
                }
                out.push(0x03);
                out.push(host.len() as u8);
                out.extend_from_slice(host.as_bytes());
                out.extend_from_slice(&port.to_be_bytes());
            }
            Self::V6(ip, port) => {
                out.push(0x04);
                out.extend_from_slice(&ip.octets());
                out.extend_from_slice(&port.to_be_bytes());
            }
        }
        Ok(())
    }

    fn decode(buf: &[u8]) -> Result<Self> {
        let mut it = buf.iter().copied();
        let atyp = it.next().ok_or_else(|| anyhow::anyhow!("open target: missing ATYP"))?;
        match atyp {
            0x01 => {
                if buf.len() < 1 + 4 + 2 {
                    bail!("open target v4: truncated");
                }
                let mut octets = [0u8; 4];
                octets.copy_from_slice(&buf[1..5]);
                let port = u16::from_be_bytes([buf[5], buf[6]]);
                Ok(Self::V4(octets.into(), port))
            }
            0x03 => {
                if buf.len() < 2 {
                    bail!("open target domain: truncated header");
                }
                let dlen = buf[1] as usize;
                if buf.len() < 2 + dlen + 2 {
                    bail!("open target domain: truncated body");
                }
                let host = std::str::from_utf8(&buf[2..2 + dlen])
                    .map_err(|_| anyhow::anyhow!("open target domain: non-utf8"))?
                    .to_string();
                let port = u16::from_be_bytes([buf[2 + dlen], buf[2 + dlen + 1]]);
                Ok(Self::Domain(host, port))
            }
            0x04 => {
                if buf.len() < 1 + 16 + 2 {
                    bail!("open target v6: truncated");
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&buf[1..17]);
                let port = u16::from_be_bytes([buf[17], buf[18]]);
                Ok(Self::V6(octets.into(), port))
            }
            other => bail!("open target: unknown ATYP 0x{:02x}", other),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Open { sid: StreamId, target: OpenTarget },
    Data { sid: StreamId, data: Vec<u8> },
    Close { sid: StreamId },
    Reset { sid: StreamId, code: u8 },
    OpenAck { sid: StreamId, code: u8 },
}

impl Frame {
    pub fn sid(&self) -> StreamId {
        match self {
            Self::Open { sid, .. }
            | Self::Data { sid, .. }
            | Self::Close { sid }
            | Self::Reset { sid, .. }
            | Self::OpenAck { sid, .. } => *sid,
        }
    }

    pub fn kind(&self) -> FrameKind {
        match self {
            Self::Open { .. } => FrameKind::Open,
            Self::Data { .. } => FrameKind::Data,
            Self::Close { .. } => FrameKind::Close,
            Self::Reset { .. } => FrameKind::Reset,
            Self::OpenAck { .. } => FrameKind::OpenAck,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(HEADER_SIZE + 64);
        out.push(PROTO_VERSION);
        out.push(self.kind() as u8);
        out.extend_from_slice(&self.sid().to_be_bytes());
        match self {
            Self::Open { target, .. } => target.encode_into(&mut out)?,
            Self::Data { data, .. } => out.extend_from_slice(data),
            Self::Close { .. } => {}
            Self::Reset { code, .. } => out.push(*code),
            Self::OpenAck { code, .. } => out.push(*code),
        }
        Ok(out)
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        if buf.len() < HEADER_SIZE {
            bail!("frame: header truncated ({} bytes)", buf.len());
        }
        let ver = buf[0];
        if ver != PROTO_VERSION {
            bail!("frame: unsupported version 0x{:02x}", ver);
        }
        let kind = FrameKind::from_byte(buf[1])
            .ok_or_else(|| anyhow::anyhow!("frame: unknown kind 0x{:02x}", buf[1]))?;
        let sid = u32::from_be_bytes([buf[2], buf[3], buf[4], buf[5]]);
        let body = &buf[HEADER_SIZE..];
        Ok(match kind {
            FrameKind::Open => Self::Open { sid, target: OpenTarget::decode(body)? },
            FrameKind::Data => Self::Data { sid, data: body.to_vec() },
            FrameKind::Close => Self::Close { sid },
            FrameKind::Reset => {
                if body.is_empty() { bail!("reset: missing code byte"); }
                Self::Reset { sid, code: body[0] }
            }
            FrameKind::OpenAck => {
                if body.is_empty() { bail!("open_ack: missing code byte"); }
                Self::OpenAck { sid, code: body[0] }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn open_v4_roundtrip() {
        let f = Frame::Open {
            sid: 0xdead_beef,
            target: OpenTarget::V4(Ipv4Addr::new(1, 2, 3, 4), 443),
        };
        let bytes = f.encode().unwrap();
        let back = Frame::decode(&bytes).unwrap();
        assert_eq!(f, back);
    }

    #[test]
    fn open_domain_roundtrip() {
        let f = Frame::Open {
            sid: 7,
            target: OpenTarget::Domain("example.com".into(), 80),
        };
        let back = Frame::decode(&f.encode().unwrap()).unwrap();
        assert_eq!(f, back);
    }

    #[test]
    fn open_v6_roundtrip() {
        let f = Frame::Open {
            sid: 1,
            target: OpenTarget::V6(Ipv6Addr::LOCALHOST, 22),
        };
        let back = Frame::decode(&f.encode().unwrap()).unwrap();
        assert_eq!(f, back);
    }

    #[test]
    fn data_close_reset_ack_roundtrip() {
        for f in [
            Frame::Data { sid: 1, data: b"hello".to_vec() },
            Frame::Close { sid: 2 },
            Frame::Reset { sid: 3, code: 0x42 },
            Frame::OpenAck { sid: 4, code: 0x00 },
        ] {
            assert_eq!(Frame::decode(&f.encode().unwrap()).unwrap(), f);
        }
    }

    #[test]
    fn decode_rejects_short_header() {
        assert!(Frame::decode(&[1, 2, 3]).is_err());
    }

    #[test]
    fn decode_rejects_bad_version() {
        let mut bytes = Frame::Close { sid: 0 }.encode().unwrap();
        bytes[0] = 0xff;
        assert!(Frame::decode(&bytes).is_err());
    }

    #[test]
    fn decode_rejects_oversized_domain() {
        // Manually craft an Open with a domain length exceeding bytes available.
        let mut bytes = vec![PROTO_VERSION, FrameKind::Open as u8, 0, 0, 0, 5];
        bytes.push(0x03); // ATYP=DOMAIN
        bytes.push(200);   // len=200 but no body follows
        bytes.extend_from_slice(&[0u8; 2]); // port
        assert!(Frame::decode(&bytes).is_err());
    }
}
