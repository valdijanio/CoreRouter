//! L2 — MNDP (MikroTik Neighbor Discovery Protocol): **decoding only**.
//!
//! CoreRouter never sends MNDP: it does not announce itself as a MikroTik.
//! It only reads the announcements RouterOS devices broadcast, so a mixed
//! network shows its MikroTiks in the neighbor table. There is deliberately
//! no encoder in this crate (tests build packets by hand).
//!
//! MNDP is proprietary and has no published specification. This decoder was
//! written from public descriptions only, no code was copied:
//!
//! - Wireshark's MNDP dissector, `epan/dissectors/packet-mndp.c`
//!   (<https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-mndp.c>,
//!   read 2026-10-21): UDP port 5678 as source and destination, a 4-byte
//!   header (2 bytes not understood + big-endian sequence number), then TLVs
//!   with big-endian 16-bit type and 16-bit length (value only), in
//!   increasing type order, first TLV the MAC address; the TLV numbers below.
//!   The dissector flags Uptime as the one TLV with a different encoding;
//!   RouterOS sends it as a 32-bit little-endian count of seconds.
//! - MikroTik's "Neighbor discovery" manual
//!   (<https://help.mikrotik.com/docs/spaces/ROS/pages/24805517/Neighbor+discovery>,
//!   read 2026-10-21): what each neighbor field means (identity, version,
//!   platform, board, software-id, uptime, unpack, addresses, interface)
//!   and the 30 s default announcement interval.
//!
//! Input is hostile: the packet is capped at [`MAX_PACKET_LEN`], every
//! length is checked before reading, text is decoded lossily and cut at
//! [`MAX_TEXT_LEN`], a fixed-size field with the wrong size is dropped (not
//! an error), and unknown TLVs are skipped (kept raw, at most
//! [`MAX_UNKNOWN_TLVS`]).

use std::net::{Ipv4Addr, Ipv6Addr};

/// UDP port MNDP is broadcast to (and from).
pub const PORT: u16 = 5678;
/// Largest datagram we decode; real announcements are ~100–200 bytes.
pub const MAX_PACKET_LEN: usize = 2048;
/// Longest text field kept, in bytes (longer ones are cut on a char boundary).
pub const MAX_TEXT_LEN: usize = 255;
/// Unknown TLVs kept per packet (the rest are skipped silently).
pub const MAX_UNKNOWN_TLVS: usize = 16;

const HEADER_LEN: usize = 4;

const T_MAC: u16 = 1;
const T_IDENTITY: u16 = 5;
const T_VERSION: u16 = 7;
const T_PLATFORM: u16 = 8;
const T_UPTIME: u16 = 10;
const T_SOFTWARE_ID: u16 = 11;
const T_BOARD: u16 = 12;
const T_UNPACK: u16 = 14;
const T_IPV6: u16 = 15;
const T_INTERFACE: u16 = 16;
const T_IPV4: u16 = 17;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    /// A header with no TLVs: a request for announcements, not one.
    #[error("MNDP request (no TLVs), not an announcement")]
    Request,
    #[error("packet of {0} bytes is shorter than the 4-byte MNDP header")]
    TooShort(usize),
    #[error("packet of {0} bytes exceeds the {MAX_PACKET_LEN}-byte limit")]
    TooLong(usize),
    #[error("TLV header at offset {0} is truncated")]
    TruncatedHeader(usize),
    #[error("TLV type {tlv_type} at offset {offset} claims {len} bytes, only {left} left")]
    TruncatedValue {
        tlv_type: u16,
        offset: usize,
        len: usize,
        left: usize,
    },
    #[error("no 6-byte MAC address TLV")]
    MissingMac,
}

/// A TLV this decoder does not know, kept raw for diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownTlv {
    pub tlv_type: u16,
    pub value: Vec<u8>,
}

/// One decoded MNDP announcement. Every field but the MAC is optional:
/// non-RouterOS senders (and old versions) omit many of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Announcement {
    /// The first two header bytes, not understood (kept for diagnostics).
    pub header: [u8; 2],
    pub seq: u16,
    /// MAC of the sending interface.
    pub mac: [u8; 6],
    pub identity: Option<String>,
    pub version: Option<String>,
    pub platform: Option<String>,
    pub uptime_secs: Option<u32>,
    pub software_id: Option<String>,
    pub board: Option<String>,
    /// Packet compression mode ("unpack"), raw; 1 = none.
    pub unpack: Option<u8>,
    pub ipv6: Option<Ipv6Addr>,
    /// Name of the sender's interface the announcement left from.
    pub interface_name: Option<String>,
    pub ipv4: Option<Ipv4Addr>,
    pub unknown: Vec<UnknownTlv>,
}

fn text(v: &[u8]) -> String {
    let mut s = String::from_utf8_lossy(v).into_owned();
    if s.len() > MAX_TEXT_LEN {
        let mut end = MAX_TEXT_LEN;
        while !s.is_char_boundary(end) {
            end = end.saturating_sub(1);
        }
        s.truncate(end);
    }
    s
}

fn be16(b: &[u8]) -> Option<u16> {
    Some(u16::from_be_bytes(b.try_into().ok()?))
}

/// Decode one MNDP datagram (the UDP payload).
pub fn decode(buf: &[u8]) -> Result<Announcement, DecodeError> {
    if buf.len() > MAX_PACKET_LEN {
        return Err(DecodeError::TooLong(buf.len()));
    }
    let (head, mut rest) = buf
        .split_at_checked(HEADER_LEN)
        .ok_or(DecodeError::TooShort(buf.len()))?;
    if rest.is_empty() {
        return Err(DecodeError::Request);
    }
    let (h, s) = head
        .split_at_checked(2)
        .ok_or(DecodeError::TooShort(buf.len()))?;
    let header: [u8; 2] = h.try_into().map_err(|_| DecodeError::TooShort(buf.len()))?;
    let seq = be16(s).ok_or(DecodeError::TooShort(buf.len()))?;

    let mut a = Announcement {
        header,
        seq,
        mac: [0; 6],
        identity: None,
        version: None,
        platform: None,
        uptime_secs: None,
        software_id: None,
        board: None,
        unpack: None,
        ipv6: None,
        interface_name: None,
        ipv4: None,
        unknown: Vec::new(),
    };
    let mut mac = None;
    while !rest.is_empty() {
        let offset = buf.len().saturating_sub(rest.len());
        let (th, after) = rest
            .split_at_checked(4)
            .ok_or(DecodeError::TruncatedHeader(offset))?;
        let (t, l) = th
            .split_at_checked(2)
            .ok_or(DecodeError::TruncatedHeader(offset))?;
        let tlv_type = be16(t).ok_or(DecodeError::TruncatedHeader(offset))?;
        let len = usize::from(be16(l).ok_or(DecodeError::TruncatedHeader(offset))?);
        let (value, next) = after
            .split_at_checked(len)
            .ok_or(DecodeError::TruncatedValue {
                tlv_type,
                offset,
                len,
                left: after.len(),
            })?;
        rest = next;
        // A repeated TLV keeps the first value; a wrong-size fixed field is
        // dropped.
        let keep_text = |slot: &mut Option<String>| {
            slot.get_or_insert_with(|| text(value));
        };
        match tlv_type {
            T_MAC => {
                if mac.is_none() {
                    mac = <[u8; 6]>::try_from(value).ok();
                }
            }
            T_IDENTITY => keep_text(&mut a.identity),
            T_VERSION => keep_text(&mut a.version),
            T_PLATFORM => keep_text(&mut a.platform),
            T_SOFTWARE_ID => keep_text(&mut a.software_id),
            T_BOARD => keep_text(&mut a.board),
            T_INTERFACE => keep_text(&mut a.interface_name),
            T_UPTIME => {
                if a.uptime_secs.is_none() {
                    a.uptime_secs = <[u8; 4]>::try_from(value).ok().map(u32::from_le_bytes);
                }
            }
            T_UNPACK => {
                if a.unpack.is_none() && value.len() == 1 {
                    a.unpack = value.first().copied();
                }
            }
            T_IPV6 => {
                if a.ipv6.is_none() {
                    a.ipv6 = <[u8; 16]>::try_from(value).ok().map(Ipv6Addr::from);
                }
            }
            T_IPV4 => {
                if a.ipv4.is_none() {
                    a.ipv4 = <[u8; 4]>::try_from(value).ok().map(Ipv4Addr::from);
                }
            }
            _ => {
                if a.unknown.len() < MAX_UNKNOWN_TLVS {
                    a.unknown.push(UnknownTlv {
                        tlv_type,
                        value: value.to_vec(),
                    });
                }
            }
        }
    }
    a.mac = mac.ok_or(DecodeError::MissingMac)?;
    Ok(a)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn tlv(t: u16, v: &[u8]) -> Vec<u8> {
        let l = u16::try_from(v.len()).unwrap();
        [&t.to_be_bytes()[..], &l.to_be_bytes(), v].concat()
    }

    /// An announcement shaped like RouterOS's, built by hand.
    fn routeros() -> Vec<u8> {
        [
            vec![0, 0, 0x12, 0x34],
            tlv(1, &[0x4C, 0x5E, 0x0C, 1, 2, 3]),
            tlv(5, b"MikroTik-HQ"),
            tlv(7, b"7.16.1 (stable)"),
            tlv(8, b"MikroTik"),
            tlv(10, &3600u32.to_le_bytes()),
            tlv(11, b"ABCD-1234"),
            tlv(12, b"RB4011iGS+"),
            tlv(14, &[1]),
            tlv(
                15,
                &"fe80::4e5e:cff:fe01:203"
                    .parse::<Ipv6Addr>()
                    .unwrap()
                    .octets(),
            ),
            tlv(16, b"ether2"),
            tlv(17, &[192, 168, 88, 1]),
        ]
        .concat()
    }

    #[test]
    fn decodes_a_routeros_announcement() {
        let a = decode(&routeros()).unwrap();
        assert_eq!(a.seq, 0x1234);
        assert_eq!(a.mac, [0x4C, 0x5E, 0x0C, 1, 2, 3]);
        assert_eq!(a.identity.as_deref(), Some("MikroTik-HQ"));
        assert_eq!(a.version.as_deref(), Some("7.16.1 (stable)"));
        assert_eq!(a.platform.as_deref(), Some("MikroTik"));
        assert_eq!(a.uptime_secs, Some(3600));
        assert_eq!(a.software_id.as_deref(), Some("ABCD-1234"));
        assert_eq!(a.board.as_deref(), Some("RB4011iGS+"));
        assert_eq!(a.unpack, Some(1));
        assert_eq!(a.ipv6, Some("fe80::4e5e:cff:fe01:203".parse().unwrap()));
        assert_eq!(a.interface_name.as_deref(), Some("ether2"));
        assert_eq!(a.ipv4, Some(Ipv4Addr::new(192, 168, 88, 1)));
        assert!(a.unknown.is_empty());
    }

    #[test]
    fn minimal_and_unknown_tlvs() {
        let pkt = [
            vec![0, 0, 0, 1],
            tlv(99, b"?"),
            tlv(1, &[2, 0, 0, 0, 0, 9]),
            tlv(10, &[1, 2]),    // wrong-size uptime: dropped
            tlv(17, &[1, 2, 3]), // wrong-size IPv4: dropped
            tlv(5, b""),
        ]
        .concat();
        let a = decode(&pkt).unwrap();
        assert_eq!(a.mac, [2, 0, 0, 0, 0, 9]);
        assert_eq!(a.uptime_secs, None);
        assert_eq!(a.ipv4, None);
        assert_eq!(a.identity.as_deref(), Some(""));
        assert_eq!(
            a.unknown,
            [UnknownTlv {
                tlv_type: 99,
                value: b"?".to_vec()
            }]
        );
    }

    #[test]
    fn rejects_bad_packets() {
        assert_eq!(decode(&[0, 0]), Err(DecodeError::TooShort(2)));
        assert_eq!(decode(&[0, 0, 0, 0]), Err(DecodeError::Request));
        assert_eq!(
            decode(&[vec![0; 4], tlv(5, b"x")].concat()),
            Err(DecodeError::MissingMac)
        );
        assert_eq!(
            decode(&[0, 0, 0, 0, 0, 1, 0]),
            Err(DecodeError::TruncatedHeader(4))
        );
        assert!(matches!(
            decode(&[0, 0, 0, 0, 0, 1, 0, 6, 1, 2]),
            Err(DecodeError::TruncatedValue { tlv_type: 1, .. })
        ));
        assert_eq!(
            decode(&vec![0; MAX_PACKET_LEN + 1]),
            Err(DecodeError::TooLong(MAX_PACKET_LEN + 1))
        );
    }

    #[test]
    fn text_and_unknown_tlvs_are_bounded() {
        let mut pkt = [vec![0; 4], tlv(1, &[0; 6]), tlv(5, &[b'a'; 600])].concat();
        for _ in 0..40 {
            pkt.extend(tlv(200, &[]));
        }
        let a = decode(&pkt).unwrap();
        assert_eq!(a.identity.unwrap().len(), MAX_TEXT_LEN);
        assert_eq!(a.unknown.len(), MAX_UNKNOWN_TLVS);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1024))]

        #[test]
        fn decode_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..3000)) {
            let _ = decode(&bytes);
        }

        #[test]
        fn decode_never_panics_on_tlv_soup(
            seq in any::<u16>(),
            tlvs in prop::collection::vec(
                (0u16..20, prop::collection::vec(any::<u8>(), 0..40)), 0..20),
            cut in any::<usize>(),
        ) {
            let mut pkt = [&[0, 0][..], &seq.to_be_bytes()].concat();
            for (t, v) in &tlvs {
                pkt.extend(tlv(*t, v));
            }
            let full = decode(&pkt);
            if let Ok(a) = &full {
                prop_assert_eq!(a.seq, seq);
                prop_assert!(a.unknown.len() <= MAX_UNKNOWN_TLVS);
                for s in [&a.identity, &a.version, &a.platform, &a.board].into_iter().flatten() {
                    prop_assert!(s.len() <= MAX_TEXT_LEN);
                }
            }
            // Any truncation of a packet is handled too.
            let _ = decode(pkt.get(..cut % (pkt.len() + 1)).unwrap_or(&[]));
        }
    }
}
