use std::collections::BTreeMap;
use std::str::FromStr;

use super::*;
use crate::lsp::wire::DsAddress;

struct View {
    labels: BTreeMap<u32, MplsRoute>,
    fecs: BTreeMap<IpNet, Vec<MplsNexthop>>,
    local: Vec<IpNet>,
}

fn ifn(s: &str) -> IfName {
    IfName::from_str(s).unwrap()
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

impl LsrView for View {
    fn label_entry(&self, label: u32) -> Option<MplsRoute> {
        self.labels.get(&label).cloned()
    }
    fn fec_route(&self, p: IpNet) -> Option<Vec<MplsNexthop>> {
        self.fecs.get(&p).cloned()
    }
    fn is_local(&self, p: IpNet) -> bool {
        self.local.contains(&p)
    }
    fn interface_addrs(&self, i: &IfName) -> Vec<IpAddr> {
        if i.as_str() == "ether1" {
            vec![ip("10.0.12.2")]
        } else {
            vec![]
        }
    }
    fn mtu(&self, _: &IfName) -> Option<u16> {
        Some(1500)
    }
}

const FEC: &str = "10.255.0.3/32";

fn fec() -> IpNet {
    FEC.parse().unwrap()
}

/// R2 of R1 — R2 — R3: label 100 in, 200 out to R3 (10.0.23.3).
fn transit() -> View {
    let nh = MplsNexthop {
        via: Some(ip("10.0.23.3")),
        interface: Some(ifn("ether2")),
        out_labels: vec![200],
    };
    View {
        labels: BTreeMap::from([(
            100,
            MplsRoute {
                label: 100,
                origin: Origin::Ldp,
                nexthops: vec![nh.clone()],
            },
        )]),
        fecs: BTreeMap::from([(fec(), vec![nh])]),
        local: vec![],
    }
}

fn egress() -> View {
    View {
        labels: BTreeMap::new(),
        fecs: BTreeMap::new(),
        local: vec![fec()],
    }
}

fn heard(stack: &[(u32, u8)], e: &Echo) -> Heard {
    Heard {
        interface: ifn("ether1"),
        stack: stack
            .iter()
            .enumerate()
            .map(|(i, (label, ttl))| MplsLabel {
                label: *label,
                tc: 0,
                bottom: i + 1 == stack.len(),
                ttl: *ttl,
            })
            .collect(),
        src: ip("10.0.12.1"),
        dst: ip("127.0.0.1"),
        src_port: 50_000,
        dst_port: wire::PORT,
        payload: wire::encode(e),
    }
}

fn request() -> Echo {
    let mut e = Echo::request(0x1234, 9, vec![Fec::Ldp(fec())]);
    e.sent = (100, 200);
    e
}

/// The DDMAP R1 sends: R2 at 10.0.12.2 receives label 100.
fn ddmap_to_r2(label: u32) -> Ddmap {
    ddmap_of(
        &MplsNexthop {
            via: Some(ip("10.0.12.2")),
            interface: None,
            out_labels: vec![label],
        },
        Origin::Ldp,
        Some(1500),
        false,
    )
}

fn answer(h: &Heard, v: &View) -> Echo {
    match respond(h, v, (5, 6)) {
        Verdict::Reply { to, payload, .. } => {
            assert_eq!(to, SocketAddr::new(ip("10.0.12.1"), 50_000));
            wire::parse(&payload).unwrap()
        }
        Verdict::Drop(why) => panic!("dropped: {why}"),
    }
}

#[test]
fn the_egress_answers_code_3_and_copies_the_ids() {
    let r = answer(&heard(&[], &request()), &egress());
    assert_eq!(r.msg_type, wire::MSG_REPLY);
    assert_eq!((r.return_code, r.return_subcode), (code::EGRESS, 1));
    assert_eq!((r.handle, r.seq, r.sent, r.received), (0x1234, 9, (100, 200), (5, 6)));
    // §3.4: the egress sends no DDMAP.
    assert!(r.ddmaps.is_empty());
    // Explicit null arrives at the egress when it asked for it (§4.4 step 4).
    let r = answer(&heard(&[(0, 254)], &request()), &egress());
    assert_eq!(r.return_code, code::EGRESS);
}

#[test]
fn an_lsp_ending_at_a_router_that_is_not_the_egress_says_no_mapping() {
    let r = answer(&heard(&[], &request()), &transit());
    assert_eq!((r.return_code, r.return_subcode), (code::NO_MAPPING, 1));
}

#[test]
fn a_transit_lsr_reports_the_switch_and_its_downstream() {
    let mut e = request();
    e.ddmaps.push(ddmap_to_r2(100));
    let r = answer(&heard(&[(100, 1)], &e), &transit());
    assert_eq!((r.return_code, r.return_subcode), (code::LABEL_SWITCHED, 1));
    assert_eq!(r.ddmaps.len(), 1);
    let d = &r.ddmaps[0];
    assert_eq!(d.address, DsAddress::numbered(ip("10.0.23.3")));
    assert_eq!(d.mtu, 1500);
    assert_eq!(d.labels.len(), 1);
    assert_eq!((d.labels[0].label, d.labels[0].protocol, d.labels[0].bottom), (200, wire::PROTO_LDP, true));
    // Without a DDMAP in the request (a ping that expired): no DDMAP back.
    let r = answer(&heard(&[(100, 1)], &request()), &transit());
    assert_eq!(r.return_code, code::LABEL_SWITCHED);
    assert!(r.ddmaps.is_empty());
}

#[test]
fn a_label_without_entry_is_code_11_at_its_depth() {
    let r = answer(&heard(&[(999, 1)], &request()), &transit());
    assert_eq!((r.return_code, r.return_subcode), (code::NO_LABEL_ENTRY, 1));
    // Two labels: the top is depth 2.
    let r = answer(&heard(&[(999, 1), (16, 1)], &request()), &transit());
    assert_eq!((r.return_code, r.return_subcode), (code::NO_LABEL_ENTRY, 2));
}

#[test]
fn interface_and_label_mismatches_are_code_5_with_what_came_in() {
    // R1 expects R2 to receive 101; it got 100.
    let mut e = request();
    e.ddmaps.push(ddmap_to_r2(101));
    let r = answer(&heard(&[(100, 1)], &e), &transit());
    assert_eq!(r.return_code, code::DS_MISMATCH);
    let i = r.if_label_stack.unwrap();
    assert_eq!(i.address, DsAddress::numbered(ip("10.0.12.2")));
    assert_eq!(i.stack[0].label, 100);
    // Or the request came in on another interface than R1 thinks.
    let mut e = request();
    let mut d = ddmap_to_r2(100);
    d.address = DsAddress::numbered(ip("10.9.9.9"));
    e.ddmaps.push(d);
    assert_eq!(answer(&heard(&[(100, 1)], &e), &transit()).return_code, code::DS_MISMATCH);
    // 127.0.0.1: the upstream does not know the interface (code 6).
    let mut e = request();
    let mut d = ddmap_to_r2(100);
    d.address = DsAddress::unknown(false);
    d.flags = wire::DS_FLAG_IF_LABEL_STACK;
    e.ddmaps.push(d);
    let r = answer(&heard(&[(100, 1)], &e), &transit());
    assert_eq!(r.return_code, code::UPSTREAM_IF_UNKNOWN);
    assert!(r.if_label_stack.is_some());
    // 224.0.0.2: nothing is checked.
    let mut e = request();
    let mut d = ddmap_to_r2(555);
    d.address = DsAddress::all_routers(false);
    e.ddmaps.push(d);
    assert_eq!(answer(&heard(&[(100, 1)], &e), &transit()).return_code, code::LABEL_SWITCHED);
}

#[test]
fn a_label_of_another_fec_is_code_10() {
    let mut v = transit();
    // The FEC's route now leaves by another next hop than label 100 does.
    v.fecs.insert(
        fec(),
        vec![MplsNexthop {
            via: Some(ip("10.0.24.4")),
            interface: None,
            out_labels: vec![300],
        }],
    );
    let mut e = request();
    e.ddmaps.push(ddmap_to_r2(100));
    let r = answer(&heard(&[(100, 1)], &e), &v);
    assert_eq!((r.return_code, r.return_subcode), (code::WRONG_LABEL, 1));
    // No route at all for the FEC: no mapping.
    v.fecs.clear();
    assert_eq!(answer(&heard(&[(100, 1)], &e), &v).return_code, code::NO_MAPPING);
}

#[test]
fn malformed_and_unknown_tlvs() {
    let mut h = heard(&[], &request());
    h.payload.truncate(wire::HEADER_LEN + 6);
    let r = answer(&h, &egress());
    assert_eq!((r.return_code, r.handle, r.seq, r.sent), (code::MALFORMED, 0x1234, 9, (100, 200)));
    // No FEC stack at all.
    let mut e = request();
    e.fec_stack = None;
    assert_eq!(answer(&heard(&[], &e), &egress()).return_code, code::MALFORMED);
    // A mandatory TLV this LSR does not know: code 2, sent back.
    let mut h = heard(&[], &request());
    h.payload.extend_from_slice(&[0, 0x63, 0, 1, 7, 0, 0, 0]);
    let r = answer(&h, &egress());
    assert_eq!(r.return_code, code::TLV_NOT_UNDERSTOOD);
    assert_eq!(r.errored.as_deref(), Some(&[0, 0x63, 0, 1, 7, 0, 0, 0][..]));
}

#[test]
fn what_is_not_answered() {
    let drop = |h: &Heard| matches!(respond(h, &egress(), (0, 0)), Verdict::Drop(_));
    let mut e = request();
    e.reply_mode = wire::REPLY_NONE;
    assert!(drop(&heard(&[], &e)));
    // T flag: only where the TTL expired.
    let mut e = request();
    e.flags = wire::FLAG_TTL_EXPIRED_ONLY;
    assert!(drop(&heard(&[(100, 5)], &e)));
    // Not to 127/8, not port 3503, from a loopback or multicast source.
    let mut h = heard(&[], &request());
    h.dst = ip("10.255.0.3");
    assert!(drop(&h));
    let mut h = heard(&[], &request());
    h.dst_port = 3504;
    assert!(drop(&h));
    for src in ["127.0.0.1", "224.0.0.5", "0.0.0.0", "255.255.255.255"] {
        let mut h = heard(&[], &request());
        h.src = ip(src);
        assert!(drop(&h), "{src}");
    }
    // A reply is not answered (no loops between two responders).
    let mut e = request();
    e.msg_type = wire::MSG_REPLY;
    assert!(drop(&heard(&[], &e)));
    // Reply mode 3 is answered like 2 (RFC 9570 §2.2).
    let mut e = request();
    e.reply_mode = wire::REPLY_UDP_ROUTER_ALERT;
    assert!(!drop(&heard(&[], &e)));
    // IPv6: ::1 and ::ffff:127.0.0.0/104.
    let mut h = heard(&[], &request());
    h.src = ip("2001:db8::1");
    h.dst = ip("::ffff:127.0.0.1");
    assert!(!drop(&h));
}

#[test]
fn the_pad_is_copied_only_when_asked() {
    let mut e = request();
    e.pad = Some(vec![2; 100]);
    assert_eq!(answer(&heard(&[], &e), &egress()).pad, Some(vec![2; 100]));
    e.pad = Some(vec![1; 100]);
    assert_eq!(answer(&heard(&[], &e), &egress()).pad, None);
    // A reply never grows past MAX_REPLY.
    e.pad = Some(vec![2; 4000]);
    let Verdict::Reply { payload, .. } = respond(&heard(&[], &e), &egress(), (0, 0)) else {
        panic!()
    };
    assert!(payload.len() <= MAX_REPLY);
}

proptest::proptest! {
    #[test]
    fn hostile_requests_never_panic(
        b in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..300),
        labels in proptest::collection::vec((0u32..0x10_0000, proptest::prelude::any::<u8>()), 0..4),
    ) {
        let mut h = heard(&labels, &request());
        h.payload = b;
        let _ = respond(&h, &transit(), (0, 0));
        let _ = respond(&h, &egress(), (0, 0));
    }
}
