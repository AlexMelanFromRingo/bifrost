//! virtio-net-header framing + software GSO segmentation.
//!
//! The bifrost mesh data plane carries `[10-byte virtio_net_hdr | IP]`
//! slots end-to-end: the exit's kernel TUN is `IFF_VNET_HDR`, so a
//! return packet may arrive as a **GSO super-segment** — one slot
//! whose payload is several MTU's worth of TCP/UDP data plus a single
//! header, to be cut into MTU-sized packets by the receiver's NIC/TUN.
//!
//! A desktop client's TUN is also `IFF_VNET_HDR` and lets the kernel
//! do that cut. An Android `VpnService` TUN is **plain** — it only
//! accepts one ready-made IP packet per `write()`. So this module is
//! the plain client's stand-in for the kernel's segmentation offload:
//! [`VhdrTun`] wraps a plain TUN and, on the write path, splits any
//! GSO super-segment into individual packets in software (fixing the
//! IP / TCP / UDP length, id, sequence and checksum fields of each),
//! exactly as wireguard-go's `tun/offload_linux.go` does. On the read
//! path it prepends an all-zero `virtio_net_hdr` so the host's plain
//! packets enter the mesh in the wire format the exit expects.
//!
//! This keeps the fix entirely client-side: the exit, and desktop
//! clients, are untouched.

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bifrost_vpnd::tun_offload::{gso_type, VIRTIO_NET_HDR_LEN};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const VHDR: usize = VIRTIO_NET_HDR_LEN;
/// `virtio_net_hdr.flags` bit: L4 checksum not yet computed.
const VIRTIO_NET_HDR_F_NEEDS_CSUM: u8 = 1;

const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;

/// A plain host TUN presented to the mesh data plane as a
/// virtio-framed, GSO-capable TUN.
pub struct VhdrTun<S> {
    inner: S,
    /// Segmented packets produced from one write slot, not yet handed
    /// to `inner` (drained on the next poll_write / poll_flush).
    pending: VecDeque<Vec<u8>>,
}

impl<S> VhdrTun<S> {
    pub fn new(inner: S) -> Self {
        Self { inner, pending: VecDeque::new() }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for VhdrTun<S> {
    /// Read one plain IP packet from the host TUN and present it to
    /// the mesh as `[10-byte zero virtio_net_hdr | ip]`.
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        dst: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        let before = dst.filled().len();
        if dst.remaining() <= VHDR {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "VhdrTun: read buffer too small for vhdr framing",
            )));
        }
        // Reserve the vhdr slot, read the bare IP packet after it.
        dst.put_slice(&[0u8; VHDR]);
        match Pin::new(&mut me.inner).poll_read(cx, dst) {
            Poll::Ready(Ok(())) => {
                if dst.filled().len() == before + VHDR {
                    // inner produced nothing (EOF) — undo the vhdr stub.
                    dst.set_filled(before);
                }
                Poll::Ready(Ok(()))
            }
            other => {
                // No data — roll the reserved vhdr back.
                dst.set_filled(before);
                other
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for VhdrTun<S> {
    /// Accept one `[vhdr | payload]` mesh slot: segment it (if it is a
    /// GSO super-segment) and write the resulting plain IP packet(s)
    /// to the host TUN. Returns `Ready(Ok(slot.len()))` only once
    /// every packet of the slot has reached `inner`.
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        slot: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        // Leftover from a previous (backpressured) call to this same
        // slot — drain it, don't re-segment.
        if !me.pending.is_empty() {
            return match me.drain(cx) {
                Poll::Ready(Ok(())) => Poll::Ready(Ok(slot.len())),
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            };
        }
        // Fresh slot — segment it into `pending`, then drain.
        for pkt in desegment(slot) {
            me.pending.push_back(pkt);
        }
        match me.drain(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(slot.len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        match me.drain(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut me.inner).poll_flush(cx),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        match me.drain(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut me.inner).poll_shutdown(cx),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S: AsyncWrite + Unpin> VhdrTun<S> {
    /// Write queued packets to `inner` until the queue is empty or the
    /// TUN applies backpressure.
    fn drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while let Some(front) = self.pending.front() {
            match Pin::new(&mut self.inner).poll_write(cx, front) {
                Poll::Ready(Ok(_)) => {
                    // A TUN write is packet-atomic — the packet is gone.
                    self.pending.pop_front();
                }
                Poll::Ready(Err(e)) => {
                    self.pending.pop_front(); // drop the un-writable packet
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }
}

/// Split one `[vhdr | payload]` mesh slot into ready-to-write plain IP
/// packets. A non-GSO slot yields one packet; a GSO super-segment
/// yields one packet per `gso_size` chunk, each with corrected
/// length / id / sequence / checksum fields.
fn desegment(slot: &[u8]) -> Vec<Vec<u8>> {
    if slot.len() <= VHDR {
        return Vec::new();
    }
    let flags = slot[0];
    let gtype = slot[1] & !gso_type::ECN_FLAG;
    let hdr_len = u16::from_le_bytes([slot[2], slot[3]]) as usize;
    let gso_size = u16::from_le_bytes([slot[4], slot[5]]) as usize;
    let payload = &slot[VHDR..];

    // Not a GSO super-segment — one whole packet.
    if gtype == gso_type::NONE
        || gso_size == 0
        || hdr_len == 0
        || hdr_len >= payload.len()
    {
        let mut pkt = payload.to_vec();
        if flags & VIRTIO_NET_HDR_F_NEEDS_CSUM != 0 {
            fix_checksums(&mut pkt);
        }
        return vec![pkt];
    }

    let headers = &payload[..hdr_len];
    let data = &payload[hdr_len..];
    let ver = headers[0] >> 4;
    let ihl: usize = if ver == 4 {
        ((headers[0] & 0x0F) as usize) * 4
    } else {
        40
    };
    if ihl < 20 || ihl > hdr_len {
        let mut pkt = payload.to_vec();
        fix_checksums(&mut pkt);
        return vec![pkt];
    }

    let n = data.len().div_ceil(gso_size);
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let off = i * gso_size;
        let len = gso_size.min(data.len() - off);
        let last = i == n - 1;

        let mut pkt = Vec::with_capacity(hdr_len + len);
        pkt.extend_from_slice(headers);
        pkt.extend_from_slice(&data[off..off + len]);

        // ── L3 length / id ─────────────────────────────────────────
        if ver == 4 {
            let total = (hdr_len + len) as u16;
            pkt[2..4].copy_from_slice(&total.to_be_bytes());
            let id = u16::from_be_bytes([pkt[4], pkt[5]]).wrapping_add(i as u16);
            pkt[4..6].copy_from_slice(&id.to_be_bytes());
        } else {
            let plen = (hdr_len - 40 + len) as u16;
            pkt[4..6].copy_from_slice(&plen.to_be_bytes());
        }

        // ── L4 per-segment fixups ──────────────────────────────────
        match gtype {
            gso_type::TCPV4 | gso_type::TCPV6 => {
                // sequence number advances by the data offset
                let seq = u32::from_be_bytes([
                    pkt[ihl + 4], pkt[ihl + 5], pkt[ihl + 6], pkt[ihl + 7],
                ])
                .wrapping_add(off as u32);
                pkt[ihl + 4..ihl + 8].copy_from_slice(&seq.to_be_bytes());
                if !last {
                    // FIN + PSH belong only on the final segment.
                    pkt[ihl + 13] &= !0x09;
                }
            }
            gso_type::UDP | gso_type::UDP_L4 => {
                // each segment is its own UDP datagram
                let ulen = (8 + len) as u16;
                pkt[ihl + 4..ihl + 6].copy_from_slice(&ulen.to_be_bytes());
            }
            _ => {}
        }

        fix_checksums(&mut pkt);
        out.push(pkt);
    }
    out
}

/// Recompute the IPv4 header checksum and the TCP/UDP checksum of one
/// well-formed plain IP packet, in place. Leaves non-IP / non-TCP-UDP
/// packets' L4 checksum untouched.
fn fix_checksums(pkt: &mut [u8]) {
    if pkt.is_empty() {
        return;
    }
    let ver = pkt[0] >> 4;
    let (ihl, proto): (usize, u8) = match ver {
        4 => {
            let ihl = ((pkt[0] & 0x0F) as usize) * 4;
            if pkt.len() < ihl || ihl < 20 {
                return;
            }
            // IPv4 header checksum
            pkt[10] = 0;
            pkt[11] = 0;
            let c = fold(sum16(&pkt[..ihl], 0));
            pkt[10..12].copy_from_slice(&c.to_be_bytes());
            (ihl, pkt[9])
        }
        6 => {
            if pkt.len() < 40 {
                return;
            }
            (40, pkt[6])
        }
        _ => return,
    };
    if pkt.len() <= ihl {
        return;
    }
    let l4_len = pkt.len() - ihl;

    // Pseudo-header sum (src ‖ dst ‖ proto ‖ L4 length).
    let mut acc: u32 = 0;
    if ver == 4 {
        acc = sum16(&pkt[12..20], acc); // src + dst
    } else {
        acc = sum16(&pkt[8..40], acc); // src + dst
    }
    acc += proto as u32;
    acc += l4_len as u32;

    let csum_field = match proto {
        PROTO_TCP if l4_len >= 20 => ihl + 16,
        PROTO_UDP if l4_len >= 8 => ihl + 6,
        _ => return, // not TCP/UDP — leave L4 alone
    };
    pkt[csum_field] = 0;
    pkt[csum_field + 1] = 0;
    acc = sum16(&pkt[ihl..], acc);
    let mut c = fold(acc);
    // A UDP checksum of 0x0000 must travel as 0xFFFF (0 = "none").
    if proto == PROTO_UDP && c == 0 {
        c = 0xFFFF;
    }
    pkt[csum_field..csum_field + 2].copy_from_slice(&c.to_be_bytes());
}

/// Accumulate `data` into a one's-complement sum of 16-bit big-endian
/// words (a trailing odd byte is the high byte of a final word).
fn sum16(data: &[u8], mut acc: u32) -> u32 {
    let mut i = 0;
    while i + 1 < data.len() {
        acc += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        acc += (data[i] as u32) << 8;
    }
    acc
}

/// Fold carries and one's-complement — the final internet checksum.
fn fold(mut acc: u32) -> u16 {
    while acc >> 16 != 0 {
        acc = (acc & 0xFFFF) + (acc >> 16);
    }
    !(acc as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `[src 10.0.0.1 | dst 10.0.0.2]` IPv4 header, 20 bytes, proto.
    fn ipv4_hdr(proto: u8, total: usize) -> Vec<u8> {
        let mut h = vec![
            0x45, 0x00, 0, 0, // ver/ihl, dscp, total_len
            0x12, 0x34, 0x40, 0x00, // id, flags/frag
            0x40, proto, 0, 0, // ttl, proto, hdr csum
            10, 0, 0, 1, // src
            10, 0, 0, 2, // dst
        ];
        h[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        h
    }

    /// True when `pkt`'s L4 checksum verifies (sum incl. the checksum
    /// field folds to 0).
    fn l4_checksum_ok(pkt: &[u8]) -> bool {
        let ihl = ((pkt[0] & 0x0F) as usize) * 4;
        let proto = pkt[9];
        let l4_len = pkt.len() - ihl;
        let mut acc = sum16(&pkt[12..20], 0);
        acc += proto as u32 + l4_len as u32;
        acc = sum16(&pkt[ihl..], acc);
        fold(acc) == 0
    }

    fn ipv4_hdr_csum_ok(pkt: &[u8]) -> bool {
        let ihl = ((pkt[0] & 0x0F) as usize) * 4;
        fold(sum16(&pkt[..ihl], 0)) == 0
    }

    #[test]
    fn fix_checksums_produces_a_valid_tcp_packet() {
        // 20-byte IP + 20-byte TCP + 4 payload bytes.
        let mut pkt = ipv4_hdr(PROTO_TCP, 44);
        pkt.extend_from_slice(&[
            0x00, 0x50, 0x01, 0xBB, // sport, dport
            0, 0, 0, 1, // seq
            0, 0, 0, 0, // ack
            0x50, 0x18, 0xFF, 0xFF, // off/flags, window
            0, 0, 0, 0, // csum, urg
        ]);
        pkt.extend_from_slice(b"data");
        fix_checksums(&mut pkt);
        assert!(ipv4_hdr_csum_ok(&pkt), "IPv4 header checksum must verify");
        assert!(l4_checksum_ok(&pkt), "TCP checksum must verify");
    }

    #[test]
    fn desegment_passes_through_a_non_gso_slot() {
        let mut slot = vec![0u8; VHDR]; // all-zero vhdr = NONE
        let mut ip = ipv4_hdr(PROTO_UDP, 28);
        ip.extend_from_slice(&[0, 53, 0, 53, 0, 8, 0, 0]); // 8-byte UDP hdr
        slot.extend_from_slice(&ip);
        let out = desegment(&slot);
        assert_eq!(out.len(), 1, "non-GSO slot → one packet");
        assert_eq!(out[0], ip, "non-GSO packet passes through unchanged");
    }

    #[test]
    fn desegment_splits_a_tcp_super_segment() {
        // One slot: vhdr(gso TCPV4, hdr_len 40, gso_size 100) +
        // [20B IP | 20B TCP | 250B data]  →  3 segments (100/100/50).
        let hdr_len = 40usize;
        let gso_size = 100usize;
        let data_len = 250usize;
        let mut slot = vec![0u8; VHDR];
        slot[1] = gso_type::TCPV4;
        slot[2..4].copy_from_slice(&(hdr_len as u16).to_le_bytes());
        slot[4..6].copy_from_slice(&(gso_size as u16).to_le_bytes());

        let mut ip = ipv4_hdr(PROTO_TCP, hdr_len + data_len);
        // minimal TCP header, data-offset 5 (20 bytes), seq = 1000
        ip.extend_from_slice(&[
            0x00, 0x50, 0x01, 0xBB,
            0, 0, 0x03, 0xE8, // seq = 1000
            0, 0, 0, 0,
            0x50, 0x18, 0xFF, 0xFF,
            0, 0, 0, 0,
        ]);
        ip.extend_from_slice(&vec![0xAB_u8; data_len]);
        slot.extend_from_slice(&ip);

        let segs = desegment(&slot);
        assert_eq!(segs.len(), 3, "250 bytes / 100 → 3 segments");
        let sizes: Vec<usize> = segs.iter().map(|s| s.len()).collect();
        assert_eq!(sizes, vec![hdr_len + 100, hdr_len + 100, hdr_len + 50]);

        for (i, seg) in segs.iter().enumerate() {
            assert!(ipv4_hdr_csum_ok(seg), "seg {i}: IPv4 header checksum");
            assert!(l4_checksum_ok(seg), "seg {i}: TCP checksum");
            // total_length field matches the real length
            let total = u16::from_be_bytes([seg[2], seg[3]]) as usize;
            assert_eq!(total, seg.len(), "seg {i}: IPv4 total_length");
        }
        // sequence numbers advance by the data offset
        let seq = |s: &[u8]| u32::from_be_bytes([s[24], s[25], s[26], s[27]]);
        assert_eq!(seq(&segs[0]), 1000);
        assert_eq!(seq(&segs[1]), 1100);
        assert_eq!(seq(&segs[2]), 1200);
        // PSH/FIN only on the last segment
        assert_eq!(segs[0][33] & 0x09, 0, "seg 0: no PSH/FIN");
        assert_eq!(segs[1][33] & 0x09, 0, "seg 1: no PSH/FIN");
        assert_eq!(segs[2][33] & 0x08, 0x08, "last seg keeps PSH");
    }

    #[test]
    fn desegment_splits_a_udp_super_segment() {
        // vhdr(gso UDP, hdr_len 28, gso_size 200) + [20B IP|8B UDP|500B]
        let hdr_len = 28usize;
        let gso_size = 200usize;
        let data_len = 500usize;
        let mut slot = vec![0u8; VHDR];
        slot[1] = gso_type::UDP;
        slot[2..4].copy_from_slice(&(hdr_len as u16).to_le_bytes());
        slot[4..6].copy_from_slice(&(gso_size as u16).to_le_bytes());

        let mut ip = ipv4_hdr(PROTO_UDP, hdr_len + data_len);
        ip.extend_from_slice(&[0x30, 0x39, 0x00, 0x35, 0, 0, 0, 0]); // UDP hdr
        ip.extend_from_slice(&vec![0xCD_u8; data_len]);
        slot.extend_from_slice(&ip);

        let segs = desegment(&slot);
        assert_eq!(segs.len(), 3, "500 / 200 → 3 datagrams");
        for (i, seg) in segs.iter().enumerate() {
            assert!(ipv4_hdr_csum_ok(seg), "seg {i}: IPv4 header checksum");
            assert!(l4_checksum_ok(seg), "seg {i}: UDP checksum");
            let ulen = u16::from_be_bytes([seg[24], seg[25]]) as usize;
            assert_eq!(ulen, seg.len() - 20, "seg {i}: UDP length");
        }
    }
}
