//! G4.3g: real captures as goldens. `tests/fixtures/*.pcap` (and
//! `.pcapng`) come from the BNG lab (`cargo xtask bng-lab`): our BNG
//! talking to BNG Blaster's client and to Linux `pppd` with the kernel
//! PPPoE plugin. Every frame, from either side, must parse with these
//! codecs, re-encode to the same bytes (the fuzz oracles' round trips) and
//! not upset the sans-IO server; each capture must hold a whole
//! conversation (discovery, LCP, authentication, IPCP).
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use std::collections::BTreeSet;
use std::path::PathBuf;

use corerouter_proto_pppoe::{discovery, eth, fuzz, ppp};

fn fixtures() -> Vec<PathBuf> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "pcap" || x == "pcapng"))
        .collect();
    v.sort();
    v
}

/// The Ethernet frames of a classic pcap or a pcapng file (little-endian,
/// as tcpdump and BNG Blaster write them on x86).
fn frames(data: &[u8]) -> Vec<Vec<u8>> {
    let u32_at = |o: usize| u32::from_le_bytes(data[o..o + 4].try_into().unwrap()) as usize;
    let mut out = Vec::new();
    match u32_at(0) {
        // pcap: 24-byte header, then 16-byte record headers.
        0xa1b2_c3d4 | 0xa1b2_3c4d => {
            assert_eq!(u32_at(20), 1, "link type Ethernet");
            let mut o = 24;
            while o + 16 <= data.len() {
                let caplen = u32_at(o + 8);
                out.push(data[o + 16..o + 16 + caplen].to_vec());
                o += 16 + caplen;
            }
        }
        // pcapng: blocks of (type, total length, body, total length);
        // Enhanced Packet Blocks (6) hold the frames.
        0x0a0d_0d0a => {
            let mut o = 0;
            while o + 12 <= data.len() {
                let (kind, len) = (u32_at(o), u32_at(o + 4));
                if kind == 6 {
                    let caplen = u32_at(o + 20);
                    out.push(data[o + 28..o + 28 + caplen].to_vec());
                }
                assert!(len >= 12, "pcapng block length");
                o += len;
            }
        }
        m => panic!("not a pcap file (magic {m:#x})"),
    }
    out
}

/// What a frame is, for the conversation check.
fn kind(f: &[u8]) -> Option<String> {
    let e = eth::parse(f).unwrap_or_else(|e| panic!("Ethernet: {e}"));
    match e.ethertype {
        0x8863 => {
            let d = discovery::parse(f).unwrap_or_else(|e| panic!("discovery: {e}"));
            Some(format!("{:?}", d.code))
        }
        0x8864 => {
            let s = ppp::parse_session(f).unwrap_or_else(|e| panic!("session: {e}"));
            let name = match s.protocol {
                0xc021 => "LCP",
                0xc023 => "PAP",
                0xc223 => "CHAP",
                0x8021 => "IPCP",
                0x8057 => "IPV6CP",
                0x0021 => return Some("IPv4".into()),
                0x0057 => return Some("IPv6".into()),
                _ => return Some(format!("proto {:#06x}", s.protocol)),
            };
            let c = ppp::parse_control(s.info).unwrap_or_else(|e| panic!("{name}: {e}"));
            if matches!(name, "LCP" | "IPCP" | "IPV6CP") && (1..=4).contains(&c.code) {
                for o in ppp::options(c.data) {
                    o.unwrap_or_else(|e| panic!("{name} option: {e}"));
                }
            }
            Some(format!("{name} {}", c.code))
        }
        _ => None,
    }
}

#[test]
fn real_captures_parse_and_round_trip() {
    for path in fixtures() {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let all = frames(&std::fs::read(&path).unwrap());
        let mut seen = BTreeSet::new();
        for (i, f) in all.iter().enumerate() {
            let Some(k) = kind(f) else { continue };
            fuzz::discovery(f).unwrap_or_else(|e| panic!("{name} #{i} ({k}): {e}"));
            fuzz::session(f).unwrap_or_else(|e| panic!("{name} #{i} ({k}): {e}"));
            fuzz::server(f).unwrap_or_else(|e| panic!("{name} #{i} ({k}): {e}"));
            seen.insert(k);
        }
        // RFC 2516 §5: PADI, PADO, PADR, PADS; RFC 1661 §5.2
        // Configure-Ack (code 2) for LCP and IPCP; an authentication
        // success (PAP Authenticate-Ack 2, CHAP Success 3). Data frames
        // only where the capture has them (BNG Blaster's `-P` keeps the
        // control plane).
        for want in ["Padi", "Pado", "Padr", "Pads", "LCP 2", "IPCP 2"] {
            assert!(seen.contains(want), "{name}: no {want} in {seen:?}");
        }
        assert!(
            seen.contains("CHAP 3") || seen.contains("PAP 2"),
            "{name}: no authentication success in {seen:?}"
        );
        println!("{name}: {} frames, {seen:?}", all.len());
    }
}
