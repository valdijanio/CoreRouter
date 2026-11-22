//! ICMP extensions (RFC 4884) and the MPLS label stack object (RFC 4950):
//! the labels a router reports in its "time exceeded" when the probe
//! expired inside an MPLS tunnel, what `mtr -e` shows.
//!
//! Pure code over bytes, for `hal-linux` (raw ICMP sockets; a ping socket
//! only hands back the quoted probe, not the error, so it sees no labels)
//! and tests. Every input is hostile: lengths are checked before use, and
//! a structure that fails a check is "no extensions", never an error.
//!
//! Layout after the 8-byte ICMP header (RFC 4884 §4, §7, §8):
//!
//! ```text
//! original datagram, zero-padded, >= 128 octets   (length in the header)
//! +-------+-----------------------+---------------+
//! | ver=2 | reserved (0)          | checksum      |  extension header
//! +-------+-------+-------+-------+---------------+
//! | object length | class | ctype | payload ...   |  one or more objects
//! ```

use crate::probe::MplsLabel;

/// RFC 4884 §7: the extension structure's version.
pub const VERSION: u8 = 2;
/// RFC 4884 §4: with extensions, the original datagram field "MUST contain
/// at least 128 octets"; §5.5 looks there when the length is missing.
pub const MIN_ORIGINAL: usize = 128;
/// RFC 4950 §5: MPLS Label Stack Class, Incoming MPLS Label Stack C-Type.
pub const CLASS_MPLS: u8 = 1;
pub const CTYPE_INCOMING_STACK: u8 = 1;
/// Labels kept from one object (mtr keeps 8; real stacks have 1–4).
pub const MAX_LABELS: usize = 16;
/// Objects walked in one structure.
const MAX_OBJECTS: usize = 16;

const ICMP_UNREACH: u8 = 3;
const ICMP_TIME_EXCEEDED: u8 = 11;
const ICMP_PARAM_PROBLEM: u8 = 12;
const ICMP6_UNREACH: u8 = 1;
const ICMP6_TIME_EXCEEDED: u8 = 3;

/// RFC 1071 Internet checksum.
pub fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let (pairs, rest) = data.as_chunks::<2>();
    for pair in pairs {
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes(*pair)));
    }
    if let [last] = rest {
        sum = sum.wrapping_add(u32::from(*last) << 8);
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// A plausible extension header at the start of `ext`: version 2, reserved
/// bits zero, and a checksum over the whole structure that is right or
/// absent (RFC 4884 §7: "an all-zero value means that no checksum was
/// transmitted").
fn valid(ext: &[u8]) -> bool {
    let [b0, b1, c0, c1, ..] = ext else {
        return false;
    };
    ext.len() >= 8
        && b0 >> 4 == VERSION
        && (b0 & 0x0f) == 0
        && *b1 == 0
        && ((*c0, *c1) == (0, 0) || checksum(ext) == 0)
}

/// The extension structure of the ICMP message `icmp` (header included),
/// if it carries one. `v6`: ICMPv6, else ICMPv4.
pub fn extension(icmp: &[u8], v6: bool) -> Option<&[u8]> {
    let ty = *icmp.first()?;
    // RFC 4884 §4.6: only these messages are extensible.
    let extensible = if v6 {
        matches!(ty, ICMP6_UNREACH | ICMP6_TIME_EXCEEDED)
    } else {
        matches!(ty, ICMP_UNREACH | ICMP_TIME_EXCEEDED | ICMP_PARAM_PROBLEM)
    };
    if !extensible {
        return None;
    }
    // RFC 4884 §4.1–4.5: ICMPv4 length in 32-bit words at octet 5,
    // ICMPv6 in 64-bit words at octet 4.
    let length = if v6 {
        usize::from(*icmp.get(4)?) * 8
    } else {
        usize::from(*icmp.get(5)?) * 4
    };
    let at = if length == 0 {
        // RFC 4884 §5.5: a sender that predates RFC 4884 leaves the length
        // at zero and puts the structure at octet 128 of the original
        // datagram; it counts only if version and checksum check out.
        8 + MIN_ORIGINAL
    } else if length < MIN_ORIGINAL {
        // RFC 4884 §4: shorter than 128 octets means no extensions.
        return None;
    } else {
        8 + length
    };
    let ext = icmp.get(at..)?;
    valid(ext).then_some(ext)
}

/// One object: `(class_num, c_type, payload)`.
pub type Object<'a> = (u8, u8, &'a [u8]);

/// The objects of an extension structure (RFC 4884 §8). A bad length ends
/// the walk; what came before it stays.
pub fn objects(ext: &[u8]) -> Vec<Object<'_>> {
    let mut out = Vec::new();
    let mut at = 4;
    while out.len() < MAX_OBJECTS {
        let Some(&[l0, l1, class, ctype]) = ext.get(at..at + 4) else {
            break;
        };
        let len = usize::from(u16::from_be_bytes([l0, l1]));
        // RFC 4884 §8: the length counts the 4-byte header, payload in
        // 32-bit words.
        if len < 4 || len % 4 != 0 {
            break;
        }
        let Some(payload) = ext.get(at + 4..at + len) else {
            break;
        };
        out.push((class, ctype, payload));
        at += len;
    }
    out
}

/// RFC 4950 §5: each entry is label (20 bits), TC (3, "EXP" before RFC
/// 5462), bottom of stack (1) and TTL (8), the top of the stack first.
pub fn parse_stack(payload: &[u8]) -> Vec<MplsLabel> {
    payload
        .as_chunks::<4>()
        .0
        .iter()
        .take(MAX_LABELS)
        .map(|e| {
            let w = u32::from_be_bytes(*e);
            MplsLabel {
                label: w >> 12,
                tc: ((w >> 9) & 0x7) as u8,
                bottom: (w >> 8) & 1 == 1,
                ttl: (w & 0xff) as u8,
            }
        })
        .collect()
}

/// The incoming label stack an ICMP error reports, empty without one.
pub fn mpls_labels(icmp: &[u8], v6: bool) -> Vec<MplsLabel> {
    let Some(ext) = extension(icmp, v6) else {
        return Vec::new();
    };
    objects(ext)
        .into_iter()
        .find(|(class, ctype, _)| *class == CLASS_MPLS && *ctype == CTYPE_INCOMING_STACK)
        .map(|(_, _, payload)| parse_stack(payload))
        .unwrap_or_default()
}

/// The MPLS label stack object for `labels` (for tests and simulations).
pub fn mpls_object(labels: &[MplsLabel]) -> Vec<u8> {
    let len = 4 + 4 * labels.len().min(MAX_LABELS);
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(&u16::try_from(len).unwrap_or(4).to_be_bytes());
    out.extend_from_slice(&[CLASS_MPLS, CTYPE_INCOMING_STACK]);
    for l in labels.iter().take(MAX_LABELS) {
        let w = (l.label & 0x000f_ffff) << 12
            | u32::from(l.tc & 0x7) << 9
            | u32::from(l.bottom) << 8
            | u32::from(l.ttl);
        out.extend_from_slice(&w.to_be_bytes());
    }
    out
}

/// An extension structure holding `objects` (already encoded), with its
/// checksum.
pub fn encode_extension(objects: &[Vec<u8>]) -> Vec<u8> {
    let mut out = vec![VERSION << 4, 0, 0, 0];
    for o in objects {
        out.extend_from_slice(o);
    }
    let c = checksum(&out).to_be_bytes();
    if let Some(slot) = out.get_mut(2..4) {
        slot.copy_from_slice(&c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn label(label: u32, ttl: u8, bottom: bool) -> MplsLabel {
        MplsLabel {
            label,
            tc: 0,
            bottom,
            ttl,
        }
    }

    /// An ICMP error of `ty` quoting `original` bytes, with RFC 4884
    /// length `length` (in the family's words) and `ext` after it.
    fn icmp(ty: u8, v6: bool, original: usize, length: u8, ext: &[u8]) -> Vec<u8> {
        let mut m = vec![ty, 0, 0, 0, 0, 0, 0, 0];
        m[if v6 { 4 } else { 5 }] = length;
        m.extend((0..original).map(|i| (i % 251) as u8));
        m.extend_from_slice(ext);
        m
    }

    #[test]
    fn rfc4950_figure_1_label_stack() {
        // RFC 4950 §3, Figure 1: "MPLS Label=100048 Exp=0 TTL=1 S=1".
        let stack = [label(100_048, 1, true)];
        let ext = encode_extension(&[mpls_object(&stack)]);
        // RFC 4884 §4.1: ICMPv4 time exceeded, 128 octets = 32 words.
        let m = icmp(ICMP_TIME_EXCEEDED, false, 128, 32, &ext);
        assert_eq!(mpls_labels(&m, false), stack.to_vec());
        assert_eq!(
            mpls_labels(&m, false)[0].to_string(),
            "L=100048 TC=0 S=1 TTL=1"
        );
    }

    #[test]
    fn rfc4884_lengths_by_family_and_padding() {
        let stack = [label(24_017, 1, false), label(16, 255, true)];
        let ext = encode_extension(&[mpls_object(&stack)]);
        // ICMPv6: 64-bit words at octet 4 (RFC 4884 §4.4), 136 = 17 words.
        let m = icmp(ICMP6_TIME_EXCEEDED, true, 136, 17, &ext);
        assert_eq!(mpls_labels(&m, true), stack.to_vec());
        // ICMPv4 with a longer original datagram (§4: padded to words).
        let m = icmp(ICMP_UNREACH, false, 160, 40, &ext);
        assert_eq!(mpls_labels(&m, false).len(), 2);
        // §4: length below 128 octets means no extensions.
        let m = icmp(ICMP_TIME_EXCEEDED, false, 64, 16, &ext);
        assert!(mpls_labels(&m, false).is_empty());
        // §4.6: echo replies and packet too big carry none.
        let m = icmp(0, false, 128, 32, &ext);
        assert!(mpls_labels(&m, false).is_empty());
        let m = icmp(2, true, 128, 16, &ext);
        assert!(mpls_labels(&m, true).is_empty());
    }

    #[test]
    fn rfc4884_5_5_non_compliant_senders() {
        let stack = [label(299_792, 1, true)];
        let ext = encode_extension(&[mpls_object(&stack)]);
        // Length zero, structure at octet 128: accepted when it checks out.
        let m = icmp(ICMP_TIME_EXCEEDED, false, 128, 0, &ext);
        assert_eq!(mpls_labels(&m, false), stack.to_vec());
        // A wrong checksum: not an extension.
        let mut bad = ext.clone();
        bad[3] ^= 0x55;
        let m = icmp(ICMP_TIME_EXCEEDED, false, 128, 0, &bad);
        assert!(mpls_labels(&m, false).is_empty());
        // A plain quote of 200 bytes (no extensions): nothing found.
        let m = icmp(ICMP_TIME_EXCEEDED, false, 200, 0, &[]);
        assert!(mpls_labels(&m, false).is_empty());
    }

    #[test]
    fn zero_checksum_and_unknown_objects() {
        let mut ext = encode_extension(&[
            vec![0, 8, 2, 1, 0, 0, 0, 1],
            mpls_object(&[label(3, 1, true)]),
        ]);
        // RFC 4884 §7: all-zero checksum = none transmitted.
        ext[2] = 0;
        ext[3] = 0;
        let m = icmp(ICMP_TIME_EXCEEDED, false, 128, 32, &ext);
        assert_eq!(
            mpls_labels(&m, false),
            vec![label(3, 1, true)],
            "class 2 skipped"
        );
        // RFC 4884 §8: a bad object length ends the walk.
        let mut broken = encode_extension(&[vec![0, 6, 1, 1, 0, 0]]);
        broken.truncate(10);
        assert!(objects(&broken).is_empty());
    }

    proptest::proptest! {
        /// Hostile messages never panic and give at most MAX_LABELS.
        #[test]
        fn any_bytes_are_safe(bytes in proptest::collection::vec(proptest::num::u8::ANY, 0..400), v6 in proptest::bool::ANY) {
            let labels = mpls_labels(&bytes, v6);
            proptest::prop_assert!(labels.len() <= MAX_LABELS);
        }

        /// Encode then decode gives the stack back.
        #[test]
        fn round_trip(raw in proptest::collection::vec((0u32..1 << 20, 0u8..8, proptest::bool::ANY, proptest::num::u8::ANY), 1..8)) {
            let stack: Vec<MplsLabel> = raw.iter().map(|(l, tc, s, ttl)| MplsLabel { label: *l, tc: *tc, bottom: *s, ttl: *ttl }).collect();
            let ext = encode_extension(&[mpls_object(&stack)]);
            let m = icmp(ICMP_TIME_EXCEEDED, false, 128, 32, &ext);
            proptest::prop_assert_eq!(mpls_labels(&m, false), stack);
        }
    }
}
