//! G4.4j: interoperability with a decoder we did not write. The IPFIX
//! messages of the CGNAT's NAT log (RFC 8158 port blocks, limits, NAT44
//! sessions, also with the legacy natEvent 1/2) go into a pcap, over UDP
//! and over SCTP (RFC 7011 §10.2: one IPFIX message per SCTP DATA chunk),
//! and Wireshark's `tshark` decodes them; every element that matters is
//! compared. No capture, no root: the pcap is written here.
//!
//! Skipped (with a line saying so) when `tshark` is not installed;
//! `COREROUTER_REQUIRE_TSHARK=1` makes that a failure.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::net::Ipv4Addr;
use std::process::Command;

use corerouter_proto_flow::export::{Config, DEFAULT_MESSAGE, Exporter};
use corerouter_proto_flow::record::{quota, threshold};
use corerouter_proto_flow::{NatEvent, NatEventType, NatLimit, PortBlock, Record, Version};

/// CRC-32C (Castagnoli), the SCTP checksum (RFC 9260 §6.8, Appendix A).
fn crc32c(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for b in data {
        crc ^= u32::from(*b);
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0x82f6_3b78 } else { crc >> 1 };
        }
    }
    !crc
}

fn ipv4(proto: u8, payload: &[u8]) -> Vec<u8> {
    let len = u16::try_from(20 + payload.len()).unwrap();
    let mut h = vec![0x45, 0];
    h.extend(len.to_be_bytes());
    h.extend([0, 0, 0x40, 0, 64, proto, 0, 0]);
    h.extend([192, 0, 2, 1, 192, 0, 2, 10]);
    let mut sum: u32 = h.chunks(2).map(|c| u32::from(u16::from_be_bytes([c[0], c[1]]))).sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    h[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    h.extend_from_slice(payload);
    h
}

fn udp(msg: &[u8]) -> Vec<u8> {
    let mut u = Vec::new();
    u.extend(40_000u16.to_be_bytes());
    u.extend(4739u16.to_be_bytes());
    u.extend(u16::try_from(8 + msg.len()).unwrap().to_be_bytes());
    u.extend([0, 0]); // no checksum (IPv4)
    u.extend_from_slice(msg);
    ipv4(17, &u)
}

/// One SCTP packet with one DATA chunk (RFC 9260 §3.3.1), stream 0.
fn sctp(msg: &[u8], tsn: u32) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend(40_000u16.to_be_bytes());
    p.extend(4739u16.to_be_bytes());
    p.extend(0x1234_5678u32.to_be_bytes()); // verification tag
    p.extend([0, 0, 0, 0]); // checksum, below
    let len = u16::try_from(16 + msg.len()).unwrap();
    p.extend([0, 0x03]); // DATA, B and E: the whole message
    p.extend(len.to_be_bytes());
    p.extend(tsn.to_be_bytes());
    p.extend([0, 0, 0, 0]); // stream 0, sequence 0
    p.extend([0, 0, 0, 0]); // payload protocol id
    p.extend_from_slice(msg);
    while p.len() % 4 != 0 {
        p.push(0);
    }
    let c = crc32c(&p);
    p[8..12].copy_from_slice(&c.to_le_bytes());
    ipv4(132, &p)
}

/// A pcap of raw IPv4 packets (LINKTYPE_RAW 101).
fn pcap(packets: &[Vec<u8>]) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend(0xa1b2_c3d4u32.to_le_bytes());
    f.extend(2u16.to_le_bytes());
    f.extend(4u16.to_le_bytes());
    f.extend([0u8; 8]);
    f.extend(65_535u32.to_le_bytes());
    f.extend(101u32.to_le_bytes());
    for (i, p) in packets.iter().enumerate() {
        f.extend((1_700_000_000u32 + i as u32).to_le_bytes());
        f.extend(0u32.to_le_bytes());
        let n = u32::try_from(p.len()).unwrap();
        f.extend(n.to_le_bytes());
        f.extend(n.to_le_bytes());
        f.extend_from_slice(p);
    }
    f
}

fn records() -> Vec<Record> {
    vec![
        Record::PortBlock(PortBlock {
            time_ms: 1_700_000_000_500,
            event: NatEventType::PortBlockAllocation,
            src: Ipv4Addr::new(100, 64, 0, 9),
            post_src: Ipv4Addr::new(203, 0, 113, 1),
            port_start: 2048,
            port_end: 3071,
            step: 1,
            ports: 1024,
            user: "ana.lima@isp".into(),
            vlan: 210,
            pool: 3,
        }),
        Record::NatLimit(NatLimit {
            time_ms: 1_700_000_000_600,
            event: NatEventType::QuotaExceeded,
            kind: quota::MAX_ENTRIES_PER_USER,
            src: Ipv4Addr::new(100, 64, 0, 9),
            pool: 3,
            limit: 4096,
        }),
        Record::NatLimit(NatLimit {
            time_ms: 1_700_000_000_700,
            event: NatEventType::ThresholdReached,
            kind: threshold::ADDRESS_PORT_PER_USER_HIGH,
            src: Ipv4Addr::new(100, 64, 0, 9),
            pool: 3,
            limit: 90,
        }),
        Record::NatLimit(NatLimit {
            time_ms: 1_700_000_000_800,
            event: NatEventType::AddressesExhausted,
            kind: 0,
            src: Ipv4Addr::UNSPECIFIED,
            pool: 3,
            limit: 0,
        }),
        Record::Nat(NatEvent {
            time_ms: 1_700_000_000_900,
            start_ms: 1_700_000_000_100,
            event: NatEventType::Nat44SessionCreate,
            protocol: 6,
            src: Ipv4Addr::new(100, 64, 0, 9),
            dst: Ipv4Addr::UNSPECIFIED,
            src_port: 51_000,
            dst_port: 0,
            post_src: Ipv4Addr::new(203, 0, 113, 1),
            post_dst: Ipv4Addr::UNSPECIFIED,
            post_src_port: 2100,
            post_dst_port: 0,
        }),
    ]
}

fn messages(legacy: bool, stream: bool) -> Vec<Vec<u8>> {
    let mut e = Exporter::new(Config {
        version: Version::Ipfix,
        domain: 7,
        max_size: DEFAULT_MESSAGE,
        refresh_ms: 600_000,
        refresh_packets: 20,
        stream,
        boot_ms: 0,
        nat_destination: false,
        legacy_nat: legacy,
    });
    let mut out = Vec::new();
    e.encode(1_700_000_001_000, &records(), &mut out);
    out
}

const FIELDS: &[&str] = &[
    "frame.protocols",
    "cflow.nat_event",
    "cflow.port_range_start",
    "cflow.port_range_end",
    "cflow.port_range_num_ports",
    "cflow.nat_pool_id",
    "cflow.vlanid",
    "cflow.user_name",
    "cflow.nat_quota_exceeded_event",
    "cflow.max_entries_per_user",
    "cflow.nat_threshold_event",
    "cflow.addressport_mapping_per_user_highthreshold",
    "cflow.post_natsource_ipv4_address",
];

/// tshark's answer: per frame, each field's values.
fn decode(file: &std::path::Path) -> Vec<Vec<String>> {
    let mut cmd = Command::new("tshark");
    cmd.arg("-r").arg(file).args(["-T", "fields", "-E", "separator=|", "-E", "occurrence=a", "-E", "aggregator=,"]);
    for f in FIELDS {
        cmd.args(["-e", f]);
    }
    let out = cmd.output().unwrap();
    assert!(out.status.success(), "tshark: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| l.split('|').map(str::to_owned).collect())
        .collect()
}

#[test]
fn tshark_decodes_the_nat_log_over_udp_and_sctp() {
    if Command::new("tshark").arg("-v").output().is_err() {
        let required = std::env::var("COREROUTER_REQUIRE_TSHARK").is_ok_and(|v| v == "1");
        assert!(!required, "tshark is required (COREROUTER_REQUIRE_TSHARK=1)");
        eprintln!("skipped: tshark is not installed");
        return;
    }
    let dir = std::env::temp_dir().join(format!("g44j-tshark-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut packets = Vec::new();
    for m in messages(false, false) {
        packets.push(udp(&m));
    }
    for (i, m) in messages(false, true).iter().enumerate() {
        packets.push(sctp(m, 1 + i as u32));
    }
    for m in messages(true, false) {
        packets.push(udp(&m));
    }
    let file = dir.join("nat-log.pcap");
    std::fs::write(&file, pcap(&packets)).unwrap();
    let frames = decode(&file);
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(frames.len(), 3, "{frames:?}");
    let col = |f: &[String], name: &str| -> String {
        let i = FIELDS.iter().position(|x| *x == name).unwrap();
        f.get(i).cloned().unwrap_or_default()
    };
    for (i, transport) in [(0usize, "udp"), (1, "sctp")] {
        let f = &frames[i];
        assert!(col(f, "frame.protocols").contains(transport) && col(f, "frame.protocols").contains("cflow"), "{f:?}");
        // RFC 8158 Table 2: 16 block, 13 quota, 18 threshold, 3 pool, 4 session.
        assert_eq!(col(f, "cflow.nat_event"), "16,13,18,3,4", "{transport}: {f:?}");
        assert_eq!(col(f, "cflow.port_range_start"), "2048");
        assert_eq!(col(f, "cflow.port_range_end"), "3071");
        assert_eq!(col(f, "cflow.port_range_num_ports"), "1024");
        assert_eq!(col(f, "cflow.nat_pool_id"), "3,3,3,3", "{f:?}");
        assert_eq!(col(f, "cflow.vlanid"), "210");
        assert_eq!(col(f, "cflow.user_name"), "ana.lima@isp", "RFC 7011 §7 variable length");
        assert_eq!(col(f, "cflow.nat_quota_exceeded_event"), "3");
        assert_eq!(col(f, "cflow.max_entries_per_user"), "4096");
        assert_eq!(col(f, "cflow.nat_threshold_event"), "4");
        assert_eq!(col(f, "cflow.addressport_mapping_per_user_highthreshold"), "90");
        assert_eq!(col(f, "cflow.post_natsource_ipv4_address"), "203.0.113.1,203.0.113.1");
    }
    // Legacy: the session is natEvent 1, the rest unchanged.
    assert_eq!(col(&frames[2], "cflow.nat_event"), "16,13,18,3,1", "{:?}", frames[2]);
}
