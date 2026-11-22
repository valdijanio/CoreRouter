//! OSPF packets as they arrive on a link (hostile input): the header, the
//! Hello and the Database Description, OSPFv2 (RFC 2328 §A.3) and OSPFv3
//! (RFC 5340 §A.3). Only what the Diagnose compares is kept — the values
//! a neighbor must agree on before an adjacency forms (RFC 2328 §10.5,
//! §10.6) — and nothing here allocates more than the packet's own
//! neighbor list (bounded by its length).
//!
//! The FRR daemons speak the protocol; this reads copies of the packets a
//! capture hands the Diagnose, so a neighbor stuck before Full can be
//! explained ("its hello says dead interval 120 s, ours 40 s").

use std::net::Ipv4Addr;

/// Packet types (RFC 2328 §A.3.1, the same in RFC 5340 §A.3.1).
pub const HELLO: u8 = 1;
pub const DD: u8 = 2;

/// RFC 2328 §A.2 options: the E bit (externals flood here: not a stub
/// area) and the N/P bit (NSSA, RFC 3101 §2.3); RFC 5340 §A.2 keeps them
/// in the same places of its 24-bit field. RFC 7166 §2.1: the AT bit.
pub const OPT_E: u32 = 0x02;
pub const OPT_N: u32 = 0x08;
pub const OPT_V3_AT: u32 = 0x0400;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("{0} bytes: shorter than an OSPF header")]
    Short(usize),
    #[error("OSPF version {0}: not 2 or 3")]
    Version(u8),
    #[error("packet length {0} does not fit the {1} bytes received")]
    Length(usize, usize),
    #[error("type {0} packet too short for its fixed fields")]
    Body(u8),
}

/// RFC 2328 §D: the AuType of an OSPFv2 header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Auth {
    None,
    Simple,
    /// Keyed digest (MD5 or HMAC-SHA): the key id and the digest length
    /// say which (16: MD5; 20/32/48/64: SHA-1/256/384/512, RFC 5709 §3).
    Crypto {
        key_id: u8,
        len: u8,
        seq: u32,
    },
    /// OSPFv3 Authentication Trailer present (the AT bit, RFC 7166 §2).
    Trailer,
    Other(u16),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    /// v2 only: the interface's mask (must match on broadcast/NBMA,
    /// RFC 2328 §10.5).
    pub mask: Option<Ipv4Addr>,
    /// v3 only: the sender's interface id.
    pub interface_id: Option<u32>,
    pub hello_interval: u16,
    pub dead_interval: u32,
    pub options: u32,
    pub priority: u8,
    pub dr: Ipv4Addr,
    pub bdr: Ipv4Addr,
    /// Router ids it has heard from on this link.
    pub neighbors: Vec<Ipv4Addr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dd {
    /// RFC 2328 §10.6: a DD with a larger MTU than ours is dropped.
    pub mtu: u16,
    pub options: u32,
    pub flags: u8,
    pub seq: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    Hello(Hello),
    Dd(Dd),
    /// LS Request, Update, Ack: not compared.
    Other(u8),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub version: u8,
    pub router_id: Ipv4Addr,
    pub area: u32,
    /// v3: the link's instance id (RFC 5340 §2.4).
    pub instance_id: Option<u8>,
    pub auth: Auth,
    pub body: Body,
}

fn u16_at(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(i)?, *b.get(i + 1)?]))
}

fn u32_at(b: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_be_bytes([
        *b.get(i)?,
        *b.get(i + 1)?,
        *b.get(i + 2)?,
        *b.get(i + 3)?,
    ]))
}

fn ip_at(b: &[u8], i: usize) -> Option<Ipv4Addr> {
    u32_at(b, i).map(Ipv4Addr::from)
}

/// Parse one OSPF packet (the IP payload, protocol 89).
pub fn parse(b: &[u8]) -> Result<Packet, Error> {
    let version = *b.first().ok_or(Error::Short(0))?;
    let hdr = match version {
        2 => 24,
        3 => 16,
        v => return Err(Error::Version(v)),
    };
    if b.len() < hdr {
        return Err(Error::Short(b.len()));
    }
    let kind = b.get(1).copied().unwrap_or(0);
    let len = usize::from(u16_at(b, 2).unwrap_or(0));
    // The packet length counts the header; a trailer (v2 digest, v3 AT)
    // follows it, so the received bytes may be more, never fewer.
    if len < hdr || len > b.len() {
        return Err(Error::Length(len, b.len()));
    }
    let router_id = ip_at(b, 4).ok_or(Error::Short(b.len()))?;
    let area = u32_at(b, 8).ok_or(Error::Short(b.len()))?;
    let body_bytes = b.get(hdr..len).unwrap_or(&[]);
    let (instance_id, mut auth) = if version == 2 {
        let autype = u16_at(b, 14).unwrap_or(0);
        let auth = match autype {
            0 => Auth::None,
            1 => Auth::Simple,
            // RFC 2328 §D.3: 0, 0, key id, auth data length, sequence.
            2 => Auth::Crypto {
                key_id: b.get(18).copied().unwrap_or(0),
                len: b.get(19).copied().unwrap_or(0),
                seq: u32_at(b, 20).unwrap_or(0),
            },
            o => Auth::Other(o),
        };
        (None, auth)
    } else {
        (b.get(14).copied(), Auth::None)
    };
    let body = match kind {
        HELLO => Body::Hello(hello(version, body_bytes).ok_or(Error::Body(kind))?),
        DD => Body::Dd(dd(version, body_bytes).ok_or(Error::Body(kind))?),
        k => Body::Other(k),
    };
    if version == 3 {
        let opts = match &body {
            Body::Hello(h) => h.options,
            Body::Dd(d) => d.options,
            Body::Other(_) => 0,
        };
        if opts & OPT_V3_AT != 0 {
            auth = Auth::Trailer;
        }
    }
    Ok(Packet {
        version,
        router_id,
        area,
        instance_id,
        auth,
        body,
    })
}

fn neighbors(b: &[u8], from: usize) -> Vec<Ipv4Addr> {
    b.get(from..)
        .unwrap_or(&[])
        .as_chunks::<4>()
        .0
        .iter()
        .map(|c| Ipv4Addr::from(*c))
        .collect()
}

fn hello(version: u8, b: &[u8]) -> Option<Hello> {
    if version == 2 {
        // RFC 2328 §A.3.2: mask, hello interval, options, priority, dead
        // interval, DR, BDR, neighbors.
        Some(Hello {
            mask: Some(ip_at(b, 0)?),
            interface_id: None,
            hello_interval: u16_at(b, 4)?,
            options: u32::from(*b.get(6)?),
            priority: *b.get(7)?,
            dead_interval: u32_at(b, 8)?,
            dr: ip_at(b, 12)?,
            bdr: ip_at(b, 16)?,
            neighbors: neighbors(b, 20),
        })
    } else {
        // RFC 5340 §A.3.2: interface id, priority + 24-bit options, hello
        // interval, dead interval (16 bits), DR, BDR, neighbors.
        let word = u32_at(b, 4)?;
        Some(Hello {
            mask: None,
            interface_id: Some(u32_at(b, 0)?),
            priority: u8::try_from(word >> 24).ok()?,
            options: word & 0x00FF_FFFF,
            hello_interval: u16_at(b, 8)?,
            dead_interval: u32::from(u16_at(b, 10)?),
            dr: ip_at(b, 12)?,
            bdr: ip_at(b, 16)?,
            neighbors: neighbors(b, 20),
        })
    }
}

fn dd(version: u8, b: &[u8]) -> Option<Dd> {
    if version == 2 {
        // RFC 2328 §A.3.3: interface MTU, options, flags, sequence.
        Some(Dd {
            mtu: u16_at(b, 0)?,
            options: u32::from(*b.get(2)?),
            flags: *b.get(3)?,
            seq: u32_at(b, 4)?,
        })
    } else {
        // RFC 5340 §A.3.3: reserved, options (24), MTU, reserved, flags, seq.
        Some(Dd {
            options: u32_at(b, 0)? & 0x00FF_FFFF,
            mtu: u16_at(b, 4)?,
            flags: *b.get(7)?,
            seq: u32_at(b, 8)?,
        })
    }
}

/// The HMAC/MD5 the digest length implies (RFC 5709 §3, RFC 2328 §D.3).
pub fn digest_name(len: u8) -> &'static str {
    match len {
        16 => "md5",
        20 => "sha1",
        32 => "sha256",
        48 => "sha384",
        64 => "sha512",
        _ => "unknown",
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// An OSPFv2 Hello as RFC 2328 §A.3.2 lays it out: router 10.0.0.2,
    /// area 0, /24, hello 10, E bit, priority 1, dead 40, one neighbor.
    pub(crate) fn hello_v2(dead: u32, opts: u8) -> Vec<u8> {
        let mut b = vec![
            2, HELLO, 0, 48, 10, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        b.extend([255, 255, 255, 0, 0, 10, opts, 1]);
        b.extend(dead.to_be_bytes());
        b.extend([10, 0, 0, 2, 0, 0, 0, 0, 10, 0, 0, 1]);
        b
    }

    #[test]
    fn a_v2_hello_parses() {
        let p = parse(&hello_v2(40, OPT_E as u8)).unwrap();
        assert_eq!(p.router_id, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(p.auth, Auth::None);
        let Body::Hello(h) = p.body else { panic!() };
        assert_eq!(h.mask, Some(Ipv4Addr::new(255, 255, 255, 0)));
        assert_eq!((h.hello_interval, h.dead_interval, h.priority), (10, 40, 1));
        assert_eq!(h.options & OPT_E, OPT_E);
        assert_eq!(h.neighbors, vec![Ipv4Addr::new(10, 0, 0, 1)]);
    }

    #[test]
    fn a_v2_dd_with_a_digest() {
        let mut b = vec![
            2, DD, 0, 32, 10, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 7, 32, 0, 0, 0, 9,
        ];
        b.extend([0x05, 0xDC, 0x02, 0x07, 0, 0, 0x30, 0x39]);
        b.extend([0u8; 32]); // the HMAC-SHA-256 after the packet
        let p = parse(&b).unwrap();
        assert_eq!(
            p.auth,
            Auth::Crypto {
                key_id: 7,
                len: 32,
                seq: 9
            }
        );
        assert_eq!(digest_name(32), "sha256");
        assert_eq!(p.area, 1);
        let Body::Dd(d) = p.body else { panic!() };
        assert_eq!((d.mtu, d.flags, d.seq), (1500, 7, 12345));
    }

    #[test]
    fn a_v3_hello_with_the_trailer_bit() {
        let mut b = vec![3, HELLO, 0, 40, 10, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0];
        b.extend([
            0, 0, 0, 5, 1, 0, 0x04, 0x13, 0, 10, 0, 40, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 1,
        ]);
        let p = parse(&b).unwrap();
        assert_eq!(p.instance_id, Some(0));
        assert_eq!(p.auth, Auth::Trailer);
        let Body::Hello(h) = p.body else { panic!() };
        assert_eq!(
            (
                h.interface_id,
                h.priority,
                h.hello_interval,
                h.dead_interval
            ),
            (Some(5), 1, 10, 40)
        );
        assert_eq!(h.options & OPT_E, OPT_E);
    }

    #[test]
    fn hostile_bytes_are_errors() {
        assert_eq!(parse(&[]), Err(Error::Short(0)));
        assert_eq!(parse(&[4; 30]), Err(Error::Version(4)));
        let mut b = hello_v2(40, 2);
        b[3] = 200;
        assert!(matches!(parse(&b), Err(Error::Length(200, _))));
        b.truncate(30);
        b[3] = 30;
        assert_eq!(parse(&b), Err(Error::Body(HELLO)));
    }

    mod prop {
        use proptest::prelude::*;

        use super::super::*;
        use super::hello_v2;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(2000))]

            /// Hostile bytes: an error or a packet, never a panic, and a
            /// Hello never lists more neighbors than its length holds.
            #[test]
            fn any_bytes(b in proptest::collection::vec(any::<u8>(), 0..200)) {
                if let Ok(p) = parse(&b) && let Body::Hello(h) = p.body {
                    prop_assert!(h.neighbors.len() * 4 <= b.len());
                }
            }

            /// A real Hello with one byte changed: still no panic.
            #[test]
            fn mutated_hello(i in 0usize..48, v in any::<u8>(), dead in any::<u32>()) {
                let mut b = hello_v2(dead, 2);
                if let Some(x) = b.get_mut(i) {
                    *x = v;
                }
                let _ = parse(&b);
            }

            /// The fields a Hello is built with come back.
            #[test]
            fn round_trip(dead in any::<u32>(), opts in any::<u8>()) {
                let p = parse(&hello_v2(dead, opts)).unwrap();
                let Body::Hello(h) = p.body else { panic!("not a hello") };
                prop_assert_eq!(h.dead_interval, dead);
                prop_assert_eq!(h.options, u32::from(opts));
            }
        }
    }
}
