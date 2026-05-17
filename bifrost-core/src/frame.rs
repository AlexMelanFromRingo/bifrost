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

// v1 (initial) carried only seq-less Data frames and assumed the
// underlying PacketConn was lossless (direct-peer SOCKS5 only).
// v2 adds per-frame `seq: u32` to Data and a new Ack frame so the
// stream layer retransmits its own lost frames, lifting the
// "exit must be a direct neighbour" restriction. v2 is wire-
// incompatible with v1; decode_rejects_bad_version covers that.
pub const PROTO_VERSION: u8 = 2;
pub const HEADER_SIZE: usize = 6;
/// Worst-case bytes added by the framing layer on top of payload data,
/// counting the v2 sequence number that follows the header for Data
/// frames. Used to compute the effective MTU for stream chunking.
pub const MAX_FRAME_OVERHEAD: usize = HEADER_SIZE + 4;

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
    /// Cumulative ACK + advertised receive window (v2 reliability).
    Ack     = 0x06,
}

impl FrameKind {
    fn from_byte(b: u8) -> Option<Self> {
        Some(match b {
            0x01 => Self::Open,
            0x02 => Self::Data,
            0x03 => Self::Close,
            0x04 => Self::Reset,
            0x05 => Self::OpenAck,
            0x06 => Self::Ack,
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
    /// Data carries a u32 sequence number assigned by the sender; the
    /// receiver ACKs cumulatively via the Ack frame. Seq counts bytes
    /// (not frames) so the receiver can advance even if the sender
    /// regrouped DATA into different chunk sizes on retransmit.
    Data { sid: StreamId, seq: u32, data: Vec<u8> },
    /// FIN with the byte position at which the sender stops. The
    /// receiver delivers EOF only after expected_seq has caught up to
    /// this value, so out-of-order Close can't truncate the stream.
    Close { sid: StreamId, seq: u32 },
    Reset { sid: StreamId, code: u8 },
    OpenAck { sid: StreamId, code: u8 },
    /// Cumulative ACK: `ack` is the next byte the receiver expects;
    /// `win` is the bytes of receive buffer the receiver can still
    /// absorb without dropping. The sender uses `win` for flow control.
    Ack { sid: StreamId, ack: u32, win: u32 },
}

impl Frame {
    pub fn sid(&self) -> StreamId {
        match self {
            Self::Open { sid, .. }
            | Self::Data { sid, .. }
            | Self::Close { sid, .. }
            | Self::Reset { sid, .. }
            | Self::OpenAck { sid, .. }
            | Self::Ack { sid, .. } => *sid,
        }
    }

    pub fn kind(&self) -> FrameKind {
        match self {
            Self::Open { .. } => FrameKind::Open,
            Self::Data { .. } => FrameKind::Data,
            Self::Close { .. } => FrameKind::Close,
            Self::Reset { .. } => FrameKind::Reset,
            Self::OpenAck { .. } => FrameKind::OpenAck,
            Self::Ack { .. } => FrameKind::Ack,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(HEADER_SIZE + 64);
        out.push(PROTO_VERSION);
        out.push(self.kind() as u8);
        out.extend_from_slice(&self.sid().to_be_bytes());
        match self {
            Self::Open { target, .. } => target.encode_into(&mut out)?,
            Self::Data { seq, data, .. } => {
                out.extend_from_slice(&seq.to_be_bytes());
                out.extend_from_slice(data);
            }
            Self::Close { seq, .. } => out.extend_from_slice(&seq.to_be_bytes()),
            Self::Reset { code, .. } => out.push(*code),
            Self::OpenAck { code, .. } => out.push(*code),
            Self::Ack { ack, win, .. } => {
                out.extend_from_slice(&ack.to_be_bytes());
                out.extend_from_slice(&win.to_be_bytes());
            }
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
            FrameKind::Data => {
                if body.len() < 4 {
                    bail!("data: seq field truncated");
                }
                let seq = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
                Self::Data { sid, seq, data: body[4..].to_vec() }
            }
            FrameKind::Close => {
                if body.len() < 4 {
                    bail!("close: seq field truncated");
                }
                let seq = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
                Self::Close { sid, seq }
            }
            FrameKind::Reset => {
                if body.is_empty() { bail!("reset: missing code byte"); }
                Self::Reset { sid, code: body[0] }
            }
            FrameKind::OpenAck => {
                if body.is_empty() { bail!("open_ack: missing code byte"); }
                Self::OpenAck { sid, code: body[0] }
            }
            FrameKind::Ack => {
                if body.len() < 8 {
                    bail!("ack: body truncated ({} bytes)", body.len());
                }
                let ack = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
                let win = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
                Self::Ack { sid, ack, win }
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
            Frame::Data { sid: 1, seq: 0, data: b"hello".to_vec() },
            Frame::Data { sid: 1, seq: u32::MAX - 1, data: vec![] },
            Frame::Close { sid: 2, seq: 0 },
            Frame::Close { sid: 2, seq: u32::MAX },
            Frame::Reset { sid: 3, code: 0x42 },
            Frame::OpenAck { sid: 4, code: 0x00 },
            Frame::Ack { sid: 5, ack: 12345, win: 64 * 1024 },
            Frame::Ack { sid: 6, ack: 0, win: 0 },
        ] {
            assert_eq!(Frame::decode(&f.encode().unwrap()).unwrap(), f);
        }
    }

    #[test]
    fn data_decode_rejects_short_body() {
        // Header is fine, but the seq field needs 4 bytes — body is 2.
        let mut bytes = vec![PROTO_VERSION, FrameKind::Data as u8, 0, 0, 0, 1];
        bytes.extend_from_slice(&[0u8, 1]);
        assert!(Frame::decode(&bytes).is_err());
    }

    #[test]
    fn ack_decode_rejects_short_body() {
        let mut bytes = vec![PROTO_VERSION, FrameKind::Ack as u8, 0, 0, 0, 1];
        bytes.extend_from_slice(&[0u8; 4]); // only ack, missing win
        assert!(Frame::decode(&bytes).is_err());
    }

    #[test]
    fn decode_rejects_short_header() {
        assert!(Frame::decode(&[1, 2, 3]).is_err());
    }

    #[test]
    fn decode_rejects_bad_version() {
        let mut bytes = Frame::Close { sid: 0, seq: 0 }.encode().unwrap();
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
