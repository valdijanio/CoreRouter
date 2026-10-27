use std::net::{IpAddr, Ipv4Addr};

use corerouter_hal::conntrack::{Conn, Event, EventKind, Tuple, status};
use proptest::prelude::*;

use crate::decode::{Decoder, to_record};
use crate::export::{Config, DEFAULT_MESSAGE, Exporter};
use crate::ie::id;
use crate::meter::{AnyInterface, Meter, MeterConfig, Router};
use crate::record::*;
use crate::template::{self, Version};

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn v4(s: &str) -> Ipv4Addr {
    s.parse().unwrap()
}

fn be16(v: u16) -> [u8; 2] {
    v.to_be_bytes()
}

fn be32(v: u32) -> [u8; 4] {
    v.to_be_bytes()
}

/// RFC 7011 Appendix A.2 (template set) and A.3 (data set): a template of
/// five fields and three records, in one message.
fn rfc7011_example() -> Vec<u8> {
    let mut body = Vec::new();
    // A.2: Template Set, Set ID 2, template 256, 5 fields.
    let fields: [(u16, u16); 5] = [(8, 4), (12, 4), (15, 4), (2, 4), (1, 4)];
    body.extend(be16(2));
    body.extend(be16(4 + 4 + 5 * 4));
    body.extend(be16(256));
    body.extend(be16(5));
    for (i, l) in fields {
        body.extend(be16(i));
        body.extend(be16(l));
    }
    // A.3: Data Set 256, three records.
    let rows = [
        (
            "192.0.2.12",
            "192.0.2.254",
            "192.0.2.1",
            5009u32,
            5_344_385u32,
        ),
        ("192.0.2.27", "192.0.2.23", "192.0.2.2", 748, 388_934),
        ("192.0.2.56", "192.0.2.65", "192.0.2.3", 5, 6534),
    ];
    body.extend(be16(256));
    body.extend(be16(4 + 3 * 20));
    for (s, d, n, p, o) in rows {
        body.extend(v4(s).octets());
        body.extend(v4(d).octets());
        body.extend(v4(n).octets());
        body.extend(be32(p));
        body.extend(be32(o));
    }
    let mut msg = Vec::new();
    msg.extend(be16(10));
    msg.extend(be16(u16::try_from(16 + body.len()).unwrap()));
    msg.extend(be32(1_700_000_000));
    msg.extend(be32(0));
    msg.extend(be32(12345));
    msg.extend(body);
    msg
}

#[test]
fn decodes_the_rfc_7011_example() {
    let mut d = Decoder::new();
    let m = d.decode(&rfc7011_example()).unwrap();
    assert_eq!(m.version, 10);
    assert_eq!(m.domain, 12345);
    assert_eq!(m.templates, 1);
    assert_eq!(m.records.len(), 3);
    let r = &m.records[0];
    assert_eq!(r.ip(id::SOURCE_IPV4_ADDRESS), Some(ip("192.0.2.12")));
    assert_eq!(r.ip(15), Some(ip("192.0.2.1")));
    assert_eq!(r.uint(id::PACKET_DELTA_COUNT), Some(5009));
    assert_eq!(r.uint(id::OCTET_DELTA_COUNT), Some(5_344_385));
    assert_eq!(m.records[2].uint(id::OCTET_DELTA_COUNT), Some(6534));
}

/// RFC 3954 §5–§6: a template FlowSet and a data FlowSet in a v9 packet,
/// count covering both records and the packet padded to 32 bits.
#[test]
fn decodes_a_v9_packet() {
    let mut p = Vec::new();
    p.extend(be16(9));
    p.extend(be16(2)); // one template + one data record
    p.extend(be32(60_000)); // sysUpTime
    p.extend(be32(1_700_000_000));
    p.extend(be32(7));
    p.extend(be32(42));
    // Template FlowSet (id 0): template 300 with IN_BYTES, PROTOCOL, IPV4_SRC.
    p.extend(be16(0));
    p.extend(be16(4 + 4 + 3 * 4));
    p.extend(be16(300));
    p.extend(be16(3));
    for (t, l) in [(1u16, 4u16), (4, 1), (8, 4)] {
        p.extend(be16(t));
        p.extend(be16(l));
    }
    // Data FlowSet: 9 bytes of record + 3 of padding.
    p.extend(be16(300));
    p.extend(be16(4 + 9 + 3));
    p.extend(be32(1500));
    p.push(17);
    p.extend(v4("198.51.100.7").octets());
    p.extend([0, 0, 0]);
    let mut d = Decoder::new();
    let m = d.decode(&p).unwrap();
    assert_eq!((m.version, m.count, m.sequence, m.domain), (9, 2, 7, 42));
    assert_eq!(m.records.len(), 1, "the padding is not a record");
    assert_eq!(m.records[0].uint(id::OCTET_DELTA_COUNT), Some(1500));
    assert_eq!(m.records[0].uint(id::PROTOCOL_IDENTIFIER), Some(17));
}

#[test]
fn a_data_set_before_its_template_is_counted_not_guessed() {
    let mut msg = rfc7011_example();
    // Drop the template set (bytes 16..16+28) and fix the length.
    msg.drain(16..44);
    let len = u16::try_from(msg.len()).unwrap();
    msg[2..4].copy_from_slice(&len.to_be_bytes());
    let m = Decoder::new().decode(&msg).unwrap();
    assert!(m.records.is_empty());
    assert_eq!(m.unknown_sets, 1);
}

#[test]
fn withdrawal_forgets_a_template() {
    let mut d = Decoder::new();
    d.decode(&rfc7011_example()).unwrap();
    assert_eq!(d.templates(), 1);
    let mut w = Vec::new();
    w.extend(be16(10));
    w.extend(be16(16 + 8));
    w.extend(be32(0));
    w.extend(be32(3));
    w.extend(be32(12345));
    w.extend(be16(2));
    w.extend(be16(8));
    w.extend(be16(256));
    w.extend(be16(0));
    d.decode(&w).unwrap();
    assert_eq!(d.templates(), 0);
}

fn flow(i: u32) -> Flow {
    Flow {
        start_ms: 1_700_000_000_000 + u64::from(i),
        end_ms: 1_700_000_060_000 + u64::from(i),
        protocol: 6,
        src: IpAddr::V4(Ipv4Addr::from(0x6440_0000 + i)),
        dst: ip("192.0.2.2"),
        src_port: 40_000,
        dst_port: 443,
        post_src: ip("203.0.113.1"),
        post_dst: ip("192.0.2.2"),
        post_src_port: 2100,
        post_dst_port: 443,
        octets: 123_456_789_012,
        packets: 1000 + u64::from(i),
        ingress: 2,
        egress: 1,
        end_reason: EndReason::End,
        direction: Direction::Initiator,
    }
}

fn exporter(v: Version) -> Exporter {
    Exporter::new(Config {
        version: v,
        domain: 7,
        max_size: DEFAULT_MESSAGE,
        refresh_ms: 600_000,
        refresh_packets: 20,
        stream: false,
        boot_ms: 1_699_999_000_000,
        nat_destination: true,
        legacy_nat: false,
    })
}

/// Templates and options templates of one full set.
const TEMPLATES: usize = 10;

fn sample_records() -> Vec<Record> {
    let mut v6 = flow(1);
    v6.src = ip("2001:db8::1");
    v6.dst = ip("2001:db8:1::2");
    v6.post_src = v6.src;
    v6.post_dst = v6.dst;
    v6.direction = Direction::Reverse;
    vec![
        Record::Flow(flow(0)),
        Record::Flow(v6),
        Record::Nat(NatEvent {
            time_ms: 1_700_000_000_123,
            start_ms: 1_700_000_000_100,
            event: NatEventType::Nat44SessionCreate,
            protocol: 17,
            src: v4("100.64.0.9"),
            dst: v4("8.8.8.8"),
            src_port: 5353,
            dst_port: 53,
            post_src: v4("203.0.113.1"),
            post_dst: v4("8.8.8.8"),
            post_src_port: 2048,
            post_dst_port: 53,
        }),
        Record::PortBlock(PortBlock {
            time_ms: 1_700_000_000_500,
            event: NatEventType::PortBlockAllocation,
            src: v4("100.64.0.9"),
            post_src: v4("203.0.113.1"),
            port_start: 2048,
            port_end: 3071,
            step: 1,
            ports: 1024,
            user: "joão.silva@isp".into(),
            vlan: 210,
            pool: 3,
        }),
        Record::NatLimit(NatLimit {
            time_ms: 1_700_000_000_600,
            event: NatEventType::QuotaExceeded,
            kind: quota::MAX_ENTRIES_PER_USER,
            src: v4("100.64.0.9"),
            pool: 3,
            limit: 2048,
        }),
        Record::NatLimit(NatLimit {
            time_ms: 1_700_000_000_700,
            event: NatEventType::ThresholdReached,
            kind: threshold::ADDRESS_PORT_PER_USER_HIGH,
            src: v4("100.64.0.9"),
            pool: 3,
            limit: 80,
        }),
        Record::NatLimit(NatLimit {
            time_ms: 1_700_000_000_800,
            event: NatEventType::AddressesExhausted,
            kind: 0,
            src: Ipv4Addr::UNSPECIFIED,
            pool: 3,
            limit: 0,
        }),
    ]
}

fn decode_all(d: &mut Decoder, msgs: &[Vec<u8>]) -> Vec<Record> {
    let mut out = Vec::new();
    for m in msgs {
        let m = d.decode(m).unwrap();
        out.extend(m.records.iter().filter_map(|r| to_record(r, &m)));
    }
    out
}

#[test]
fn every_record_round_trips_in_both_versions() {
    for v in [Version::Ipfix, Version::V9] {
        let mut e = exporter(v);
        let mut msgs = Vec::new();
        let recs = sample_records();
        e.encode(1_700_000_100_000, &recs, &mut msgs);
        assert_eq!(msgs.len(), 1);
        let back = decode_all(&mut Decoder::new(), &msgs);
        assert_eq!(back, recs, "{v:?}");
    }
}

#[test]
fn ipfix_sequence_counts_data_records_and_v9_counts_packets() {
    let recs: Vec<Record> = (0..100).map(|i| Record::Flow(flow(i))).collect();
    let mut ipfix = exporter(Version::Ipfix);
    let mut v9 = exporter(Version::V9);
    let (mut a, mut b) = (Vec::new(), Vec::new());
    ipfix.encode(1_700_000_100_000, &recs, &mut a);
    v9.encode(1_700_000_100_000, &recs, &mut b);
    assert!(a.len() > 1, "100 records do not fit one message");
    let mut d = Decoder::new();
    let mut expect = 0u32;
    for m in &a {
        assert!(m.len() <= DEFAULT_MESSAGE);
        let m = d.decode(m).unwrap();
        assert_eq!(
            m.sequence, expect,
            "RFC 7011 §3.1: data records before this one"
        );
        expect += u32::try_from(m.records.len()).unwrap();
    }
    // The sampling options record is a data record too.
    assert_eq!(expect, 101);
    let mut d = Decoder::new();
    for (i, m) in b.iter().enumerate() {
        assert_eq!(m.len() % 4, 0, "RFC 3954 §5.3: padded");
        let m = d.decode(m).unwrap();
        assert_eq!(
            m.sequence,
            u32::try_from(i).unwrap(),
            "RFC 3954 §5.1: packets"
        );
        let templates = if i == 0 { TEMPLATES } else { 0 };
        assert_eq!(usize::from(m.count), m.records.len() + templates);
    }
}

#[test]
fn templates_come_back_by_time_and_by_count() {
    let mut e = exporter(Version::Ipfix);
    let t0 = 1_700_000_000_000;
    let one = [Record::Flow(flow(0))];
    let mut d = Decoder::new();
    let mut sent = |e: &mut Exporter, t: u64| {
        let mut out = Vec::new();
        e.encode(t, &one, &mut out);
        d.decode(&out[0]).unwrap().templates
    };
    assert_eq!(sent(&mut e, t0), TEMPLATES, "first message: every template");
    for i in 1..20 {
        assert_eq!(sent(&mut e, t0 + i), 0, "message {i}");
    }
    assert_eq!(
        sent(&mut e, t0 + 20),
        TEMPLATES,
        "after 20 messages (v9-template-refresh)"
    );
    assert_eq!(sent(&mut e, t0 + 30), 0);
    assert_eq!(sent(&mut e, t0 + 600_030), TEMPLATES, "after the timeout");
    // Nothing to send, but they are due: a message with only templates.
    let mut out = Vec::new();
    e.encode(t0 + 1_300_000, &[], &mut out);
    assert_eq!(out.len(), 1);
    e.encode(t0 + 1_300_001, &[], &mut out);
    assert_eq!(out.len(), 1, "nothing due, nothing sent");
}

#[test]
fn a_stream_sends_templates_once_and_again_on_reconnect() {
    let mut cfg = exporter(Version::Ipfix).config().clone();
    cfg.stream = true;
    let mut e = Exporter::new(cfg);
    let mut out = Vec::new();
    for i in 0..30 {
        e.encode(
            1_700_000_000_000 + i * 100_000,
            &[Record::Flow(flow(0))],
            &mut out,
        );
    }
    assert_eq!(e.counters().template_sends, 1);
    e.reset_stream();
    e.encode(1_800_000_000_000, &[Record::Flow(flow(0))], &mut out);
    assert_eq!(e.counters().template_sends, 2);
}

#[test]
fn options_carry_sampling_and_interface_names() {
    let mut e = exporter(Version::V9);
    e.set_meta(Meta {
        sampling_interval: 64,
        interfaces: (1..=100).map(|i| (i, format!("ether{i}"))).collect(),
    });
    let mut out = Vec::new();
    e.encode(1_700_000_000_000, &[], &mut out);
    let mut d = Decoder::new();
    let mut names = Vec::new();
    let mut interval = None;
    for m in &out {
        let m = d.decode(m).unwrap();
        for r in &m.records {
            if r.template == template::OPT_SAMPLING {
                interval = r.uint(id::SAMPLING_INTERVAL);
                assert_eq!(r.uint(1), Some(7), "v9 scope System = source id");
            }
            if r.template == template::OPT_INTERFACE {
                names.push((r.uint(2).unwrap(), r.string(id::INTERFACE_NAME).unwrap()));
            }
        }
    }
    assert_eq!(interval, Some(64));
    assert_eq!(names.len(), 100);
    assert_eq!(names[41], (42, "ether42".into()));
}

fn conn(id: u32, nat: bool) -> Conn {
    Conn {
        id,
        protocol: 6,
        orig: Tuple {
            src: ip("100.64.0.9"),
            dst: ip("192.0.2.2"),
            src_port: 40_000,
            dst_port: 443,
        },
        reply: Tuple {
            src: ip("192.0.2.2"),
            dst: if nat {
                ip("203.0.113.1")
            } else {
                ip("100.64.0.9")
            },
            src_port: 443,
            dst_port: if nat { 2100 } else { 40_000 },
        },
        status: status::CONFIRMED | if nat { status::SRC_NAT } else { 0 },
        timeout: 100,
        tcp_state: Some(3),
        mark: 0,
        orig_packets: 0,
        orig_bytes: 0,
        reply_packets: 0,
        reply_bytes: 0,
    }
}

fn ev(kind: EventKind, c: Conn) -> Event {
    Event {
        kind,
        conn: c,
        start_ns: None,
        stop_ns: None,
    }
}

fn counted(mut c: Conn, op: u64, ob: u64, rp: u64, rb: u64) -> Conn {
    c.orig_packets = op;
    c.orig_bytes = ob;
    c.reply_packets = rp;
    c.reply_bytes = rb;
    c
}

#[test]
fn a_nat_connection_gives_session_events_and_two_flows_with_both_tuples() {
    let mut m = Meter::new(MeterConfig::default());
    let mut out = Vec::new();
    let c = conn(1, true);
    m.event(
        &ev(EventKind::New, c.clone()),
        1000,
        &AnyInterface,
        &mut out,
    );
    let mut end = counted(c, 10, 1000, 8, 9000);
    end.tcp_state = Some(7);
    m.event(&ev(EventKind::Destroy, end), 5000, &AnyInterface, &mut out);
    assert_eq!(out.len(), 4);
    let Record::Nat(create) = &out[0] else {
        panic!("{out:?}")
    };
    assert_eq!(create.event, NatEventType::Nat44SessionCreate);
    assert_eq!(create.post_src, v4("203.0.113.1"));
    assert_eq!(create.post_src_port, 2100);
    assert_eq!((create.time_ms, create.start_ms), (1000, 1000));
    let Record::Nat(delete) = &out[1] else {
        panic!()
    };
    assert_eq!(delete.event, NatEventType::Nat44SessionDelete);
    let Record::Flow(orig) = &out[2] else {
        panic!()
    };
    assert_eq!(
        (orig.src, orig.post_src, orig.post_src_port),
        (ip("100.64.0.9"), ip("203.0.113.1"), 2100)
    );
    assert_eq!(
        (orig.octets, orig.packets, orig.start_ms, orig.end_ms),
        (1000, 10, 1000, 5000)
    );
    assert_eq!(orig.end_reason, EndReason::End, "TCP time-wait: closed");
    let Record::Flow(reply) = &out[3] else {
        panic!()
    };
    assert_eq!(
        (reply.src, reply.dst, reply.post_dst, reply.post_dst_port),
        (ip("192.0.2.2"), ip("203.0.113.1"), ip("100.64.0.9"), 40_000)
    );
    assert_eq!(reply.subscriber(), ip("100.64.0.9"));
    assert_eq!(reply.octets, 9000);
}

#[test]
fn no_nat_no_nat_events() {
    let mut m = Meter::new(MeterConfig::default());
    let mut out = Vec::new();
    m.event(
        &ev(EventKind::New, conn(1, false)),
        1000,
        &AnyInterface,
        &mut out,
    );
    assert!(out.is_empty());
}

#[test]
fn kernel_timestamps_win_over_the_clock() {
    let mut m = Meter::new(MeterConfig::default());
    let mut out = Vec::new();
    let mut e = ev(EventKind::Destroy, counted(conn(1, true), 1, 60, 0, 0));
    e.start_ns = Some(1_000_000_000);
    e.stop_ns = Some(9_000_000_000);
    m.event(&e, 99_999, &AnyInterface, &mut out);
    let Record::Nat(n) = &out[0] else {
        panic!("{out:?}")
    };
    assert_eq!(
        (n.start_ms, n.time_ms),
        (1000, 9000),
        "the delete alone is the whole session"
    );
    let Record::Flow(f) = &out[1] else {
        panic!("{out:?}")
    };
    assert_eq!(
        (f.start_ms, f.end_ms),
        (1000, 9000),
        "unknown connection: whole life from the stamps"
    );
}

#[test]
fn active_and_inactive_timeouts_split_a_long_connection() {
    let cfg = MeterConfig {
        active_ms: 60_000,
        inactive_ms: 15_000,
        nat_events: false,
        ..MeterConfig::default()
    };
    let mut m = Meter::new(cfg);
    let mut out = Vec::new();
    let c = conn(1, true);
    m.event(&ev(EventKind::New, c.clone()), 0, &AnyInterface, &mut out);
    // Busy: the counters move on every read.
    for t in 1..=6u64 {
        let now = counted(c.clone(), t * 10, t * 1000, 0, 0);
        m.scan(&[now], true, t * 10_000, &AnyInterface, &mut out);
    }
    assert_eq!(out.len(), 1, "one active report at 60 s: {out:?}");
    let Record::Flow(f) = &out[0] else { panic!() };
    assert_eq!(
        (f.start_ms, f.end_ms, f.packets, f.end_reason),
        (0, 60_000, 60, EndReason::Active)
    );
    // Then it moves once and goes quiet.
    let last = counted(c.clone(), 70, 7000, 0, 0);
    m.scan(
        std::slice::from_ref(&last),
        true,
        70_000,
        &AnyInterface,
        &mut out,
    );
    m.scan(
        std::slice::from_ref(&last),
        true,
        80_000,
        &AnyInterface,
        &mut out,
    );
    assert_eq!(out.len(), 1);
    m.scan(
        std::slice::from_ref(&last),
        true,
        85_000,
        &AnyInterface,
        &mut out,
    );
    assert_eq!(out.len(), 2, "idle 15 s");
    let Record::Flow(f) = &out[1] else { panic!() };
    assert_eq!((f.packets, f.end_reason), (10, EndReason::Idle));
    // Quiet: nothing more; its end reports nothing new either.
    m.scan(
        std::slice::from_ref(&last),
        true,
        200_000,
        &AnyInterface,
        &mut out,
    );
    m.event(
        &ev(EventKind::Destroy, last),
        300_000,
        &AnyInterface,
        &mut out,
    );
    assert_eq!(out.len(), 2, "{out:?}");
}

#[test]
fn a_connection_that_vanishes_is_reported_once() {
    let mut m = Meter::new(MeterConfig::default());
    let mut out = Vec::new();
    let c = counted(conn(1, true), 3, 300, 0, 0);
    m.scan(&[c], true, 1000, &AnyInterface, &mut out);
    assert_eq!(m.len(), 1);
    m.scan(&[], false, 2000, &AnyInterface, &mut out);
    assert_eq!(m.len(), 1, "an incomplete read proves nothing");
    m.scan(&[], true, 3000, &AnyInterface, &mut out);
    assert_eq!(m.len(), 0);
    assert_eq!(m.stats().vanished, 1);
    let Record::Flow(f) = &out[0] else {
        panic!("{out:?}")
    };
    assert_eq!(
        (f.packets, f.end_reason, f.post_src),
        (3, EndReason::LackOfResources, ip("203.0.113.1"))
    );
}

#[test]
fn a_full_cache_loses_no_bytes() {
    let mut m = Meter::new(MeterConfig {
        max_entries: 1,
        ..MeterConfig::default()
    });
    let mut out = Vec::new();
    m.event(
        &ev(EventKind::New, conn(1, false)),
        0,
        &AnyInterface,
        &mut out,
    );
    m.event(
        &ev(EventKind::New, conn(2, false)),
        0,
        &AnyInterface,
        &mut out,
    );
    assert_eq!((m.len(), m.stats().cache_full), (1, 1));
    m.event(
        &ev(EventKind::Destroy, counted(conn(2, false), 5, 500, 5, 500)),
        9,
        &AnyInterface,
        &mut out,
    );
    assert_eq!(out.len(), 2, "both directions of the unfollowed one");
}

#[test]
fn sampling_keeps_nat_events_and_drops_flows_consistently() {
    let mut m = Meter::new(MeterConfig {
        sampling: 8,
        ..MeterConfig::default()
    });
    let mut out = Vec::new();
    let mut flows = 0;
    for i in 0..800u32 {
        let mut c = conn(i, true);
        c.orig.src_port = u16::try_from(10_000 + i).unwrap();
        m.event(&ev(EventKind::New, c.clone()), 0, &AnyInterface, &mut out);
        m.event(
            &ev(EventKind::Destroy, counted(c, 1, 100, 0, 0)),
            1,
            &AnyInterface,
            &mut out,
        );
    }
    let nat = out.iter().filter(|r| matches!(r, Record::Nat(_))).count();
    flows += out.iter().filter(|r| matches!(r, Record::Flow(_))).count();
    assert_eq!(nat, 1600, "every create and delete");
    assert!((50..=150).contains(&flows), "about 1 in 8: {flows}");
    assert_eq!(m.len(), 0, "sampled-out connections are never followed");
}

struct OnlyLan;
impl Router for OnlyLan {
    fn ifindex(&self, a: IpAddr) -> u32 {
        if a.to_string().starts_with("100.64.") {
            2
        } else {
            1
        }
    }
    fn wanted(&self, ingress: u32, egress: u32) -> bool {
        ingress == 2 || egress == 2
    }
}

#[test]
fn interfaces_come_from_the_router_and_filter_flows() {
    let mut m = Meter::new(MeterConfig::default());
    let mut out = Vec::new();
    m.event(
        &ev(EventKind::Destroy, counted(conn(1, true), 1, 1, 1, 1)),
        1,
        &OnlyLan,
        &mut out,
    );
    let Record::Flow(f) = &out[1] else { panic!() };
    assert_eq!((f.ingress, f.egress), (2, 1));
    let Record::Flow(r) = &out[2] else { panic!() };
    assert_eq!((r.ingress, r.egress), (1, 2));
    let mut wan = conn(2, false);
    wan.orig.src = ip("198.51.100.1");
    wan.reply.dst = wan.orig.src;
    out.clear();
    m.event(
        &ev(EventKind::Destroy, counted(wan, 1, 1, 1, 1)),
        1,
        &OnlyLan,
        &mut out,
    );
    assert!(out.is_empty(), "neither side on a wanted interface");
}

#[test]
fn flush_reports_what_is_pending() {
    let mut m = Meter::new(MeterConfig::default());
    let mut out = Vec::new();
    m.scan(
        &[counted(conn(1, true), 4, 400, 0, 0)],
        true,
        0,
        &AnyInterface,
        &mut out,
    );
    m.flush(10, &mut out);
    assert_eq!(out.len(), 1);
    let Record::Flow(f) = &out[0] else { panic!() };
    assert_eq!((f.packets, f.end_reason), (4, EndReason::Forced));
    assert!(m.is_empty());
}

fn arb_ip() -> impl Strategy<Value = IpAddr> {
    prop_oneof![
        any::<u32>().prop_map(|v| IpAddr::V4(Ipv4Addr::from(v))),
        any::<u128>().prop_map(|v| IpAddr::V6(std::net::Ipv6Addr::from(v))),
    ]
}

prop_compose! {
    fn arb_flow()(v6 in any::<bool>(), a in arb_ip(), b in arb_ip(), c in arb_ip(), d in arb_ip(),
        ports in any::<[u16; 4]>(), start in 1_600_000_000_000u64..1_800_000_000_000, len in 0u64..10_000_000,
        octets in any::<u64>(), packets in any::<u64>(), ifs in any::<(u32, u32)>(), proto in any::<u8>(),
        reason in 1u8..=5, rev in any::<bool>()) -> Flow {
        let fam = |x: IpAddr| match (v6, x) {
            (false, IpAddr::V6(x)) => IpAddr::V4(Ipv4Addr::from(u32::try_from(u128::from(x) & 0xffff_ffff).unwrap())),
            (true, IpAddr::V4(x)) => IpAddr::V6(x.to_ipv6_mapped()),
            (_, x) => x,
        };
        Flow {
            start_ms: start, end_ms: start + len, protocol: proto,
            src: fam(a), dst: fam(b), post_src: fam(c), post_dst: fam(d),
            src_port: ports[0], dst_port: ports[1], post_src_port: ports[2], post_dst_port: ports[3],
            octets, packets, ingress: ifs.0, egress: ifs.1,
            end_reason: EndReason::from_code(reason).unwrap(),
            direction: if rev { Direction::Reverse } else { Direction::Initiator },
        }
    }
}

proptest! {
    /// Any flows survive encode → decode exactly (IPFIX), and every message
    /// stays within the size limit.
    #[test]
    fn flows_round_trip(flows in proptest::collection::vec(arb_flow(), 0..60), size in 512usize..2000) {
        let mut e = Exporter::new(Config { max_size: size, ..exporter(Version::Ipfix).config().clone() });
        let recs: Vec<Record> = flows.into_iter().map(Record::Flow).collect();
        let mut msgs = Vec::new();
        e.encode(1_900_000_000_000, &recs, &mut msgs);
        for m in &msgs {
            prop_assert!(m.len() <= size);
        }
        prop_assert_eq!(decode_all(&mut Decoder::new(), &msgs), recs);
    }

    /// Hostile bytes never panic the decoder, alone or after real templates.
    #[test]
    fn hostile_messages_never_panic(junk in proptest::collection::vec(any::<u8>(), 0..1600), cut in 0usize..1400, flip in 0usize..1400, v9 in any::<bool>()) {
        let mut d = Decoder::new();
        let _ = d.decode(&junk);
        let mut e = exporter(if v9 { Version::V9 } else { Version::Ipfix });
        let mut msgs = Vec::new();
        e.encode(1_700_000_000_000, &sample_records(), &mut msgs);
        let mut m = msgs[0].clone();
        let cut = cut.min(m.len());
        if let Some(b) = m.get_mut(flip) { *b ^= 0xa5; }
        if let Ok(msg) = d.decode(&m[..cut]) {
            for r in &msg.records { let _ = to_record(r, &msg); }
        }
        let mut with_junk = msgs[0].clone();
        with_junk.extend_from_slice(&junk);
        let _ = d.decode(&with_junk);
    }
}

/// The element ids of template `tid` as exported.
fn template_ids(tid: u16) -> Vec<u16> {
    template::all(Version::Ipfix)
        .into_iter()
        .find(|t| t.id == tid)
        .map(|t| t.fields.iter().map(|f| f.id).collect())
        .unwrap()
}

/// RFC 8158 §4.6: "A NAT device that implements a given NAT event MUST
/// support the mandatory IEs in the templates." Each table's mandatory
/// rows (timeStamp is `observationTimeMilliseconds`, §4.2 Table 1).
#[test]
fn rfc_8158_templates_carry_the_mandatory_elements() {
    let tables: [(&str, u16, &[u16]); 5] = [
        // Table 5, without the optional destination (RFC 6888 / Marco Civil).
        (
            "Table 5",
            template::NAT44_SRC,
            &[
                id::OBSERVATION_TIME_MILLISECONDS,
                id::NAT_EVENT,
                id::SOURCE_IPV4_ADDRESS,
                id::POST_NAT_SOURCE_IPV4_ADDRESS,
                id::PROTOCOL_IDENTIFIER,
                id::SOURCE_TRANSPORT_PORT,
                id::POST_NAPT_SOURCE_TRANSPORT_PORT,
            ],
        ),
        (
            "Table 9",
            template::NAT_ADDRESSES_EXHAUSTED,
            &[
                id::OBSERVATION_TIME_MILLISECONDS,
                id::NAT_EVENT,
                id::NAT_POOL_ID,
            ],
        ),
        (
            "Table 13",
            template::NAT_QUOTA_PER_USER,
            &[
                id::OBSERVATION_TIME_MILLISECONDS,
                id::NAT_EVENT,
                id::NAT_QUOTA_EXCEEDED_EVENT,
                id::MAX_ENTRIES_PER_USER,
                id::SOURCE_IPV4_ADDRESS,
            ],
        ),
        (
            "Table 18",
            template::NAT_THRESHOLD_PER_USER,
            &[
                id::OBSERVATION_TIME_MILLISECONDS,
                id::NAT_EVENT,
                id::NAT_THRESHOLD_EVENT,
                id::ADDRESS_PORT_MAPPING_PER_USER_HIGH_THRESHOLD,
                id::SOURCE_IPV4_ADDRESS,
            ],
        ),
        (
            "Table 21",
            template::PORT_BLOCK,
            &[
                id::OBSERVATION_TIME_MILLISECONDS,
                id::NAT_EVENT,
                id::SOURCE_IPV4_ADDRESS,
                id::POST_NAT_SOURCE_IPV4_ADDRESS,
                id::PORT_RANGE_START,
            ],
        ),
    ];
    for (table, tid, mandatory) in tables {
        let have = template_ids(tid);
        for ie in mandatory {
            assert!(
                have.contains(ie),
                "{table}: element {ie} missing from template {tid}"
            );
        }
    }
}

/// RFC 8158 §4.3 Table 2 and §4.4/§4.5 (Tables 3 and 4): the values on
/// the wire.
#[test]
fn rfc_8158_event_values() {
    let codes: Vec<u8> = [
        NatEventType::AddressesExhausted,
        NatEventType::Nat44SessionCreate,
        NatEventType::Nat44SessionDelete,
        NatEventType::QuotaExceeded,
        NatEventType::PortBlockAllocation,
        NatEventType::PortBlockDeallocation,
        NatEventType::ThresholdReached,
    ]
    .iter()
    .map(|e| e.code())
    .collect();
    assert_eq!(codes, [3, 4, 5, 13, 16, 17, 18]);
    assert_eq!(quota::MAX_ENTRIES_PER_USER, 3);
    assert_eq!(threshold::ADDRESS_PORT_PER_USER_HIGH, 4);
    // The Historic 1/2 are read back as the NAT44 session events.
    assert_eq!(
        NatEventType::from_code(1),
        Some(NatEventType::Nat44SessionCreate)
    );
    assert_eq!(
        NatEventType::from_code(2),
        Some(NatEventType::Nat44SessionDelete)
    );
    assert_eq!(NatEventType::from_code(0), None, "0 is Reserved");
}

/// RFC 8158 §4.6.10's port block record, byte by byte: 100.64.0.9 gets
/// 203.0.113.1 ports 2048–3071 of pool 3, on VLAN 210, login "ana".
#[test]
fn a_port_block_record_on_the_wire() {
    let mut e = exporter(Version::Ipfix);
    let mut out = Vec::new();
    e.encode(1_700_000_100_000, &[], &mut out);
    let block = PortBlock {
        time_ms: 0x0000_018b_cfe5_6800,
        event: NatEventType::PortBlockAllocation,
        src: v4("100.64.0.9"),
        post_src: v4("203.0.113.1"),
        port_start: 2048,
        port_end: 3071,
        step: 1,
        ports: 1024,
        user: "ana".into(),
        vlan: 210,
        pool: 3,
    };
    out.clear();
    e.encode(1_700_000_100_000, &[Record::PortBlock(block)], &mut out);
    let msg = &out[0];
    // Header (16) + set header (4) + one record.
    let rec = &msg[20..];
    let mut want = Vec::new();
    want.extend(0x0000_018b_cfe5_6800u64.to_be_bytes());
    want.push(16);
    want.extend([100, 64, 0, 9, 203, 0, 113, 1]);
    want.extend(be16(2048));
    want.extend(be16(3071));
    want.extend(be16(1));
    want.extend(be16(1024));
    want.extend(be32(3));
    want.extend(be16(210));
    // RFC 7011 §7: variable length, one byte of length first.
    want.extend([3, b'a', b'n', b'a']);
    assert_eq!(rec, want.as_slice());
    assert_eq!(&msg[16..18], &be16(template::PORT_BLOCK));
    assert_eq!(
        usize::from(u16::from_be_bytes([msg[18], msg[19]])),
        4 + want.len()
    );
}

#[test]
fn legacy_nat_events_go_out_as_1_and_2() {
    let mut cfg = exporter(Version::Ipfix).config().clone();
    cfg.legacy_nat = true;
    let mut e = Exporter::new(cfg);
    let recs: Vec<Record> = sample_records()
        .into_iter()
        .filter(Record::is_nat)
        .collect();
    let mut out = Vec::new();
    e.encode(1_700_000_100_000, &recs, &mut out);
    let mut d = Decoder::new();
    let mut codes = Vec::new();
    for m in &out {
        let m = d.decode(m).unwrap();
        codes.extend(m.records.iter().filter_map(|r| r.uint(id::NAT_EVENT)));
    }
    assert_eq!(codes, [1, 16, 13, 18, 3], "only the session events change");
    // And they still read back as what they are.
    assert_eq!(decode_all(&mut Decoder::new(), &out), recs);
}

#[test]
fn a_long_user_name_is_cut_at_a_character_boundary() {
    let long = "ç".repeat(200);
    for (v, max) in [
        (Version::Ipfix, template::MAX_USER),
        (Version::V9, usize::from(template::V9_USER_LEN)),
    ] {
        let mut e = exporter(v);
        let rec = Record::PortBlock(PortBlock {
            time_ms: 1,
            event: NatEventType::PortBlockDeallocation,
            src: v4("100.64.0.1"),
            post_src: v4("203.0.113.1"),
            port_start: 1024,
            port_end: 2047,
            step: 1,
            ports: 1024,
            user: long.clone(),
            vlan: 0,
            pool: 1,
        });
        let mut out = Vec::new();
        e.encode(1_700_000_100_000, &[rec], &mut out);
        let back = decode_all(&mut Decoder::new(), &out);
        let Record::PortBlock(b) = &back[0] else {
            panic!()
        };
        assert_eq!(b.user, "ç".repeat(max / 2), "{v:?}: whole characters only");
    }
}

#[test]
fn every_template_fits_the_smallest_message() {
    for v in [Version::Ipfix, Version::V9] {
        let mut cfg = exporter(v).config().clone();
        cfg.max_size = crate::MIN_MESSAGE;
        let mut e = Exporter::new(cfg);
        let mut out = Vec::new();
        e.encode(1_700_000_100_000, &sample_records(), &mut out);
        assert!(out.iter().all(|m| m.len() <= crate::MIN_MESSAGE), "{v:?}");
        let mut d = Decoder::new();
        let first = d.decode(&out[0]).unwrap();
        assert_eq!(
            first.templates, TEMPLATES,
            "{v:?}: all templates in the first message"
        );
    }
}

/// A stream reconnects: the templates go first with the sequence number of
/// the message they precede, so the collector sees no gap (RFC 7011 §3.1,
/// errata 4396: data records before this message).
#[test]
fn templates_only_takes_the_sequence_of_the_next_message() {
    let mut cfg = exporter(Version::Ipfix).config().clone();
    cfg.stream = true;
    let mut e = Exporter::new(cfg);
    let mut out = Vec::new();
    e.encode(
        1_700_000_000_000,
        &[Record::Flow(flow(0)), Record::Flow(flow(1))],
        &mut out,
    );
    e.encode(1_700_000_001_000, &[Record::Flow(flow(2))], &mut out);
    let before = e.counters();
    let mut t = e.templates_only(1_700_000_002_000);
    assert_eq!(e.counters(), before, "the exporter is unchanged");
    let next = crate::export::sequence(&out[1]).unwrap();
    crate::export::set_sequence(&mut t, next);
    let mut d = Decoder::new();
    let m = d.decode(&t).unwrap();
    assert_eq!(
        (m.templates, m.records.len(), m.sequence),
        (TEMPLATES, 0, next)
    );
    let m = d.decode(&out[1]).unwrap();
    assert_eq!(
        m.sequence, 3,
        "two flows and the sampling options record before"
    );
    assert_eq!(decode_all(&mut d, &out[1..]), vec![Record::Flow(flow(2))]);
}
