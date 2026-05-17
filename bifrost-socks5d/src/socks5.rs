// SOCKS5 v5 (RFC 1928) protocol handling — just enough for CONNECT.
//
// What we support:
//   * VER negotiation (0x05) with method 0x00 (no auth).
//   * CMD = 0x01 (CONNECT). UDP ASSOCIATE / BIND are rejected with
//     command-not-supported (0x07).
//   * ATYP = IPv4 (0x01), DOMAIN (0x03), IPv6 (0x04).
//
// Anything that doesn't fit, we close with the matching REP code so the
// SOCKS5 client gets a real error instead of a black hole.

use anyhow::{bail, Result};
use bifrost_core::frame::OpenTarget;
use std::net::{Ipv4Addr, Ipv6Addr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub const VER_V5: u8 = 0x05;
pub const METHOD_NO_AUTH: u8 = 0x00;
pub const METHOD_NONE_ACCEPTABLE: u8 = 0xff;
pub const CMD_CONNECT: u8 = 0x01;

// SOCKS5 reply codes mirror what we tunnel through OpenAck/Reset frames.
pub const REP_SUCCESS:           u8 = 0x00;
pub const REP_GENERAL_FAILURE:   u8 = 0x01;
pub const REP_CMD_NOT_SUPPORTED: u8 = 0x07;
pub const REP_ATYP_NOT_SUPPORTED:u8 = 0x08;

pub const ATYP_V4:     u8 = 0x01;
pub const ATYP_DOMAIN: u8 = 0x03;
pub const ATYP_V6:     u8 = 0x04;

/// Step 1: method negotiation. Returns Ok if we agreed on no-auth.
/// On any unsupported scenario we already wrote the rejection back.
pub async fn negotiate_methods(s: &mut TcpStream) -> Result<()> {
    let mut hdr = [0u8; 2];
    s.read_exact(&mut hdr).await?;
    if hdr[0] != VER_V5 {
        bail!("unsupported SOCKS version 0x{:02x}", hdr[0]);
    }
    let nmethods = hdr[1] as usize;
    let mut methods = vec![0u8; nmethods];
    s.read_exact(&mut methods).await?;
    if methods.contains(&METHOD_NO_AUTH) {
        s.write_all(&[VER_V5, METHOD_NO_AUTH]).await?;
        Ok(())
    } else {
        s.write_all(&[VER_V5, METHOD_NONE_ACCEPTABLE]).await?;
        bail!("client offered no acceptable auth methods")
    }
}

/// Step 2: parse the CONNECT request and return the target. Sends a
/// failure reply to the client if the request is malformed; the caller
/// just propagates the resulting Err.
pub async fn read_request(s: &mut TcpStream) -> Result<OpenTarget> {
    let mut hdr = [0u8; 4];
    s.read_exact(&mut hdr).await?;
    if hdr[0] != VER_V5 {
        bail!("request: bad version 0x{:02x}", hdr[0]);
    }
    if hdr[1] != CMD_CONNECT {
        let _ = write_reply(s, REP_CMD_NOT_SUPPORTED).await;
        bail!("only CONNECT is supported (got cmd 0x{:02x})", hdr[1]);
    }
    // hdr[2] is reserved
    let atyp = hdr[3];
    let target = match atyp {
        ATYP_V4 => {
            let mut buf = [0u8; 6];
            s.read_exact(&mut buf).await?;
            let ip = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
            let port = u16::from_be_bytes([buf[4], buf[5]]);
            OpenTarget::V4(ip, port)
        }
        ATYP_DOMAIN => {
            let mut len_buf = [0u8; 1];
            s.read_exact(&mut len_buf).await?;
            let mut dom = vec![0u8; len_buf[0] as usize];
            s.read_exact(&mut dom).await?;
            let mut port_buf = [0u8; 2];
            s.read_exact(&mut port_buf).await?;
            let host = std::str::from_utf8(&dom)
                .map_err(|_| anyhow::anyhow!("non-utf8 domain"))?
                .to_string();
            OpenTarget::Domain(host, u16::from_be_bytes(port_buf))
        }
        ATYP_V6 => {
            let mut buf = [0u8; 18];
            s.read_exact(&mut buf).await?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[..16]);
            let ip = Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([buf[16], buf[17]]);
            OpenTarget::V6(ip, port)
        }
        other => {
            let _ = write_reply(s, REP_ATYP_NOT_SUPPORTED).await;
            bail!("unsupported ATYP 0x{:02x}", other);
        }
    };
    Ok(target)
}

/// Step 3: send the REP reply with a 0.0.0.0:0 BND.ADDR. RFC 1928
/// allows zero here; clients usually only care about REP.
pub async fn write_reply(s: &mut TcpStream, rep: u8) -> Result<()> {
    // VER | REP | RSV | ATYP=IPv4 | BND.ADDR=0.0.0.0 | BND.PORT=0
    let buf = [VER_V5, rep, 0x00, ATYP_V4, 0, 0, 0, 0, 0, 0];
    s.write_all(&buf).await?;
    s.flush().await?;
    Ok(())
}

