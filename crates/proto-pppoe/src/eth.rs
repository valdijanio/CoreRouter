//! Ethernet II framing with up to two 802.1Q/802.1ad tags (QinQ), the way
//! PPPoE arrives on an access port or a VLAN-per-subscriber trunk
//! (`pppoe-over-vlan-range` in RouterOS v7).

use crate::wire::{Mac, Reader, WireError, put_u16};

/// RFC 2516 §4: Discovery stage EtherType.
pub const ETHERTYPE_DISCOVERY: u16 = 0x8863;
/// RFC 2516 §4: Session stage EtherType.
pub const ETHERTYPE_SESSION: u16 = 0x8864;
/// 802.1Q customer tag.
pub const TPID_8021Q: u16 = 0x8100;
/// 802.1ad service tag (QinQ outer).
pub const TPID_8021AD: u16 = 0x88a8;
/// Pre-standard QinQ outer tag still seen on older access gear.
pub const TPID_QINQ_LEGACY: u16 = 0x9100;

/// The VLAN stack of a frame: `outer` is the first tag on the wire.
/// `0` means "no tag" (VID 0 is priority-only and carries no VLAN).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, PartialOrd, Ord)]
pub struct Vlans {
    pub outer: u16,
    pub inner: u16,
    /// TPID of the outer tag when `inner` is set (0x88a8 or 0x8100).
    pub outer_tpid: u16,
}

impl Vlans {
    pub const NONE: Vlans = Vlans {
        outer: 0,
        inner: 0,
        outer_tpid: 0,
    };

    pub fn single(vid: u16) -> Vlans {
        Vlans {
            outer: vid & 0x0fff,
            inner: 0,
            outer_tpid: TPID_8021Q,
        }
    }

    pub fn qinq(outer: u16, inner: u16) -> Vlans {
        Vlans {
            outer: outer & 0x0fff,
            inner: inner & 0x0fff,
            outer_tpid: TPID_8021AD,
        }
    }

    pub fn is_tagged(&self) -> bool {
        self.outer != 0 || self.inner != 0
    }

    /// Bytes the tags add to the header.
    pub fn header_len(&self) -> usize {
        match (self.outer, self.inner) {
            (0, 0) => 0,
            (_, 0) => 4,
            _ => 8,
        }
    }
}

/// A parsed Ethernet header; `payload` borrows the frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EthFrame<'a> {
    pub dst: Mac,
    pub src: Mac,
    pub vlans: Vlans,
    pub ethertype: u16,
    pub payload: &'a [u8],
}

/// Parses dst, src, up to two VLAN tags and the EtherType.
pub fn parse(frame: &[u8]) -> Result<EthFrame<'_>, WireError> {
    let mut r = Reader::new(frame);
    let dst = Mac(r.array()?);
    let src = Mac(r.array()?);
    let mut et = r.u16()?;
    let mut vlans = Vlans::NONE;
    let mut tags = 0u8;
    while matches!(et, TPID_8021Q | TPID_8021AD | TPID_QINQ_LEGACY) {
        let tci = r.u16()? & 0x0fff;
        match tags {
            0 => {
                vlans.outer = tci;
                vlans.outer_tpid = et;
            }
            1 => vlans.inner = tci,
            _ => return Err(WireError::TooManyTags),
        }
        tags += 1;
        et = r.u16()?;
    }
    if tags == 1 {
        vlans.outer_tpid = TPID_8021Q;
    }
    Ok(EthFrame {
        dst,
        src,
        vlans,
        ethertype: et,
        payload: r.rest(),
    })
}

/// Appends an Ethernet header (with the VLAN stack) to `out`.
pub fn put_header(out: &mut Vec<u8>, dst: Mac, src: Mac, vlans: Vlans, ethertype: u16) {
    out.extend_from_slice(&dst.0);
    out.extend_from_slice(&src.0);
    match (vlans.outer, vlans.inner) {
        (0, 0) => {}
        (o, 0) => {
            put_u16(out, TPID_8021Q);
            put_u16(out, o);
        }
        (o, i) => {
            let tpid = if vlans.outer_tpid == 0 {
                TPID_8021AD
            } else {
                vlans.outer_tpid
            };
            put_u16(out, tpid);
            put_u16(out, o);
            put_u16(out, TPID_8021Q);
            put_u16(out, i);
        }
    }
    put_u16(out, ethertype);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn untagged_single_and_qinq_round_trip() {
        for v in [Vlans::NONE, Vlans::single(100), Vlans::qinq(200, 3001)] {
            let mut b = Vec::new();
            put_header(&mut b, Mac::BROADCAST, Mac([2, 0, 0, 0, 0, 1]), v, 0x8863);
            b.extend_from_slice(&[0x11, 0x09]);
            let f = parse(&b).unwrap();
            assert_eq!(f.vlans, v);
            assert_eq!(f.ethertype, ETHERTYPE_DISCOVERY);
            assert_eq!(f.payload, &[0x11, 0x09]);
            assert_eq!(b.len(), 14 + v.header_len() + 2);
        }
    }

    #[test]
    fn three_tags_are_refused() {
        let mut b = vec![0u8; 12];
        for _ in 0..3 {
            b.extend_from_slice(&[0x81, 0, 0, 1]);
        }
        b.extend_from_slice(&[0x88, 0x63]);
        assert_eq!(parse(&b), Err(WireError::TooManyTags));
    }

    #[test]
    fn short_frames_are_refused() {
        for n in 0..14 {
            assert!(parse(&[0u8; 14][..n]).is_err());
        }
    }
}
