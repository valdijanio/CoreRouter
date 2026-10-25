//! Server behaviour, rule by rule, through the in-memory lab and raw frames.

use super::*;
use crate::client::ClientPhase;
use crate::lab::{Lab, LabConfig};
use crate::lcp::AuthProto;

fn lab(n: usize, f: impl FnOnce(&mut LabConfig)) -> Lab {
    let mut cfg = LabConfig {
        clients: n,
        ..LabConfig::default()
    };
    f(&mut cfg);
    let mut l = Lab::new(cfg);
    l.start_all();
    l
}

#[test]
fn every_auth_protocol_reaches_up() {
    for p in [
        AuthProto::Pap,
        AuthProto::ChapMd5,
        AuthProto::MsChapV1,
        AuthProto::MsChapV2,
    ] {
        let mut l = lab(3, |c| c.auth_cycle = vec![p]);
        l.run_until(10_000);
        assert_eq!(
            l.clients_up(),
            3,
            "{p:?}: {:?}",
            l.clients.iter().map(|c| c.phase()).collect::<Vec<_>>()
        );
        assert_eq!(l.stats.ups, 3);
        l.check().unwrap();
        for c in &l.clients {
            assert!(c.ipv4().is_some());
        }
    }
}

#[test]
fn ipv6cp_comes_up_with_ipcp() {
    let mut l = lab(2, |c| c.ipv6 = true);
    l.run_until(10_000);
    assert_eq!(l.clients_up(), 2);
    let sid = *l.up.keys().next().unwrap();
    let d = l.servers[0].session(sid.1).unwrap();
    assert!(d.ipv6_iid.is_some() && d.ipv4.is_some(), "{d:?}");
    // Both ends agree on the identifiers.
    let c = l.clients.iter().find(|c| c.session_id() == sid.1).unwrap();
    assert_eq!(
        c.ipv6_iids(),
        Some((d.ipv6_iid.unwrap(), d.local_iid.unwrap()))
    );
}

#[test]
fn rfc8064_ipv6cp_identifiers_are_stable_across_reconnects() {
    // Two runs with other random seeds: the same lines get the same
    // identifiers on both ends (the client asks with zero and takes the
    // BNG's suggestion, RFC 5072 §4.1).
    let run = |seed: u64| {
        let mut l = lab(3, |c| {
            c.ipv6 = true;
            c.ipv6_zero_iid = true;
            c.seed = seed;
            c.server.ipv6_iid_key = Some([5; 32]);
        });
        l.run_until(10_000);
        assert_eq!(l.clients_up(), 3);
        let mut ids: Vec<_> =
            l.up.keys()
                .map(|k| {
                    let d = l.servers[k.0].session(k.1).unwrap();
                    (d.client_mac, d.ipv6_iid.unwrap(), d.local_iid.unwrap())
                })
                .collect();
        ids.sort();
        ids
    };
    let a = run(1);
    assert_eq!(a, run(99));
    for (_, peer, local) in &a {
        assert_ne!(peer, local);
        assert!(!crate::nd::is_reserved_iid(*peer));
    }
}

#[test]
fn use_ipv6_no_rejects_ipv6cp_and_keeps_ipv4() {
    let mut l = lab(2, |c| {
        c.ipv6 = true;
        c.ipv6_mode = crate::server::Ipv6Mode::Off;
        c.reconnect = false;
    });
    l.run_until(15_000);
    assert_eq!(l.clients_up(), 2);
    for k in l.up.keys() {
        let d = l.servers[k.0].session(k.1).unwrap();
        assert!(d.ipv4.is_some() && d.ipv6_iid.is_none(), "{d:?}");
    }
}

#[test]
fn use_ipv6_require_ends_a_session_without_ipv6cp() {
    // The CPE does not speak IPv6CP (this client stays silent): our
    // Configure-Requests run out (RFC 1661 §4.6 Max-Configure) and the
    // session goes down although IPCP opened.
    let mut l = lab(2, |c| {
        c.server.ipv6 = true;
        c.ipv6_mode = crate::server::Ipv6Mode::Require;
        c.reconnect = false;
    });
    l.run_until(5_000);
    assert_eq!(l.clients_up(), 2, "up on IPv4 while IPv6CP retries");
    l.run_until(90_000);
    assert_eq!(l.up.len(), 0);
    assert!(
        l.stats
            .server_reasons
            .get("NcpFailed")
            .copied()
            .unwrap_or(0)
            >= 2,
        "{:?}",
        l.stats.server_reasons
    );
}

#[test]
fn wrong_password_is_refused_and_cleaned_up() {
    let mut l = lab(4, |c| {
        c.bad_password_every = 2;
        c.reconnect = false;
    });
    l.run_until(30_000);
    assert_eq!(l.clients_up(), 2);
    assert_eq!(l.stats.auth_rejects, 2);
    assert_eq!(l.server_sessions(), 2, "failed sessions freed");
    assert!(
        l.clients
            .iter()
            .filter(|c| matches!(c.phase(), ClientPhase::Closed(_)))
            .count()
            == 2
    );
    l.check().unwrap();
}

// ---------------------------------------------------------------- raw frames

const AC: Mac = Mac([0x02, 0xac, 0, 0, 0, 9]);
const HOST: Mac = Mac([0x02, 0x11, 0, 0, 0, 1]);
const HOST2: Mac = Mac([0x02, 0x11, 0, 0, 0, 2]);

fn server(f: impl FnOnce(&mut ServerConfig)) -> (Server, ServerOutput) {
    let mut c = ServerConfig {
        ac_mac: AC,
        ..ServerConfig::default()
    };
    f(&mut c);
    (Server::new(c, [5; 32], 0), ServerOutput::new())
}

fn padi(src: Mac, f: impl FnOnce(&mut DiscoveryWriter<'_>)) -> Vec<u8> {
    let mut b = Vec::new();
    let mut w = DiscoveryWriter::begin(&mut b, Mac::BROADCAST, src, Vlans::NONE, Code::Padi, 0);
    f(&mut w);
    w.finish().unwrap();
    b
}

fn padi_std(src: Mac) -> Vec<u8> {
    padi(src, |w| {
        w.tag(tag::SERVICE_NAME, b"");
        w.tag(tag::HOST_UNIQ, b"hu");
    })
}

/// Parses every frame of `out` as Discovery.
fn replies(out: &ServerOutput) -> Vec<Discovery<'_>> {
    out.frames()
        .filter_map(|(_, f)| discovery::parse(f).ok())
        .collect()
}

fn padr_from(pado: &Discovery<'_>, src: Mac, f: impl FnOnce(&mut DiscoveryWriter<'_>)) -> Vec<u8> {
    let mut b = Vec::new();
    let mut w = DiscoveryWriter::begin(&mut b, AC, src, Vlans::NONE, Code::Padr, 0);
    w.tag(tag::SERVICE_NAME, pado.tags.service_name.unwrap_or(b""));
    if let Some(h) = pado.tags.host_uniq {
        w.tag(tag::HOST_UNIQ, h);
    }
    if let Some(c) = pado.tags.ac_cookie {
        w.tag(tag::AC_COOKIE, c);
    }
    f(&mut w);
    w.finish().unwrap();
    b
}

/// PADI → PADO → PADR; returns the PADR frame and the PADS SID.
fn discover(s: &mut Server, out: &mut ServerOutput, now: Millis, src: Mac) -> (Vec<u8>, u16) {
    out.clear();
    s.handle_frame(now, 1, &padi_std(src), out);
    let padr = {
        let r = replies(out);
        let pado = r.first().expect("PADO");
        padr_from(pado, src, |_| {})
    };
    out.clear();
    s.handle_frame(now, 1, &padr, out);
    let sid = replies(out)
        .iter()
        .find(|d| d.code == Code::Pads)
        .map(|d| d.session_id)
        .expect("PADS");
    (padr, sid)
}

#[test]
fn rfc2516_5_2_pado_carries_ac_name_same_service_and_echoes() {
    let (mut s, mut out) = server(|_| {});
    let f = padi(HOST, |w| {
        w.tag(tag::SERVICE_NAME, b"internet");
        w.tag(tag::HOST_UNIQ, &[9, 9]);
        w.tag(tag::RELAY_SESSION_ID, b"relay-7");
    });
    s.handle_frame(0, 1, &f, &mut out);
    let r = replies(&out);
    assert_eq!(r.len(), 1);
    let p = r[0];
    assert_eq!(p.code, Code::Pado);
    assert_eq!((p.dst, p.src, p.session_id), (HOST, AC, 0));
    assert_eq!(p.tags.ac_name, Some(&b"CoreRouter"[..]));
    assert_eq!(p.tags.service_name, Some(&b"internet"[..]));
    assert_eq!(p.tags.host_uniq, Some(&[9u8, 9][..]));
    assert_eq!(p.tags.relay_session_id, Some(&b"relay-7"[..]));
    assert_eq!(
        p.tags.ac_cookie.map(<[u8]>::len),
        Some(crate::guard::COOKIE_LEN)
    );
    assert_eq!(p.tags.ppp_max_payload, None, "RFC 4638 off by default");
}

#[test]
fn rfc2516_5_2_unserved_service_or_bad_padi_gets_no_answer() {
    let (mut s, mut out) = server(|c| c.service_names = vec![b"internet".to_vec()]);
    for f in [
        padi(HOST, |w| {
            w.tag(tag::SERVICE_NAME, b"iptv");
        }),
        // §5.1: exactly one Service-Name.
        padi(HOST, |_| {}),
        padi(HOST, |w| {
            w.tag(tag::SERVICE_NAME, b"");
            w.tag(tag::SERVICE_NAME, b"internet");
        }),
    ] {
        s.handle_frame(0, 1, &f, &mut out);
    }
    assert!(out.frames.is_empty());
    assert_eq!(s.stats().padi_refused, 3);
    // An empty Service-Name ("any service") and the offered one are served.
    s.handle_frame(0, 1, &padi_std(HOST), &mut out);
    let f = padi(HOST2, |w| {
        w.tag(tag::SERVICE_NAME, b"internet");
    });
    s.handle_frame(0, 1, &f, &mut out);
    assert_eq!(replies(&out).len(), 2);
}

#[test]
fn group_source_mac_is_ignored() {
    let (mut s, mut out) = server(|_| {});
    s.handle_frame(0, 1, &padi_std(Mac([0x03, 0, 0, 0, 0, 1])), &mut out);
    assert!(out.frames.is_empty());
}

#[test]
fn rfc4638_ppp_max_payload_echoed_only_when_supported() {
    let (mut s, mut out) = server(|c| c.max_payload = Some(1500));
    for (v, echoed) in [(1500, true), (1508, false), (1492, false)] {
        out.clear();
        let f = padi(HOST, |w| {
            w.tag(tag::SERVICE_NAME, b"");
            w.tag_u16(tag::PPP_MAX_PAYLOAD, v);
        });
        s.handle_frame(0, 1, &f, &mut out);
        let r = replies(&out);
        assert_eq!(r[0].tags.ppp_max_payload.is_some(), echoed, "{v}");
    }
}

fn pado_for(s: &mut Server, out: &mut ServerOutput, now: Millis, src: Mac) -> Vec<u8> {
    out.clear();
    s.handle_frame(now, 1, &padi_std(src), out);
    let r = replies(out);
    padr_from(r.first().expect("PADO"), src, |_| {})
}

fn pads(out: &ServerOutput) -> Option<Discovery<'_>> {
    replies(out).into_iter().find(|d| d.code == Code::Pads)
}

#[test]
fn rfc2516_9_padr_without_valid_cookie_creates_nothing() {
    let (mut s, mut out) = server(|_| {});
    let good = pado_for(&mut s, &mut out, 0, HOST);
    // Forged: one bit of the tag flipped.
    let mut forged = good.clone();
    let n = forged.len();
    forged[n - 1] ^= 1;
    // Replayed by another MAC.
    let mut stolen = good.clone();
    stolen[6..12].copy_from_slice(&HOST2.0);
    // Without the cookie at all.
    let bare = {
        let mut b = Vec::new();
        let mut w = DiscoveryWriter::begin(&mut b, AC, HOST, Vlans::NONE, Code::Padr, 0);
        w.tag(tag::SERVICE_NAME, b"");
        w.finish().unwrap();
        b
    };
    for f in [&forged, &stolen, &bare] {
        out.clear();
        s.handle_frame(10, 1, f, &mut out);
        assert!(out.frames.is_empty());
    }
    assert_eq!(s.stats().padr_bad_cookie, 3);
    assert_eq!(s.active(), 0);
    // Expired: past cookie_timeout_ms (5 s).
    out.clear();
    s.handle_frame(7000, 1, &good, &mut out);
    assert_eq!(s.active(), 0);
    // In time: a session.
    let fresh = pado_for(&mut s, &mut out, 8000, HOST);
    out.clear();
    s.handle_frame(8000, 1, &fresh, &mut out);
    assert_eq!(s.active(), 1);
    s.check_invariants().unwrap();
}

#[test]
fn cookie_survives_a_secret_rotation() {
    let (mut s, mut out) = server(|_| {});
    let padr = pado_for(&mut s, &mut out, 0, HOST);
    s.rotate_cookie_secret([42; 32]);
    out.clear();
    s.handle_frame(100, 1, &padr, &mut out);
    assert!(pads(&out).is_some_and(|p| p.session_id != 0));
}

#[test]
fn rfc2516_5_4_duplicate_padr_gets_the_same_session() {
    let (mut s, mut out) = server(|_| {});
    let (padr, sid) = discover(&mut s, &mut out, 0, HOST);
    out.clear();
    s.handle_frame(500, 1, &padr, &mut out);
    assert_eq!(pads(&out).map(|p| p.session_id), Some(sid));
    assert_eq!(s.active(), 1);
    assert_eq!(s.stats().padr_duplicate, 1);
}

#[test]
fn rfc2516_5_4_bad_service_in_padr_is_service_name_error_with_sid_zero() {
    let (mut s, mut out) = server(|c| c.service_names = vec![b"internet".to_vec()]);
    out.clear();
    let f = padi(HOST, |w| {
        w.tag(tag::SERVICE_NAME, b"internet");
    });
    s.handle_frame(0, 1, &f, &mut out);
    let padr = {
        let r = replies(&out);
        padr_from(&r[0], HOST, |w| {
            w.tag(tag::SERVICE_NAME, b"second");
        })
    };
    out.clear();
    s.handle_frame(0, 1, &padr, &mut out);
    let p = pads(&out).unwrap();
    assert_eq!(p.session_id, 0);
    assert!(p.tags.service_name_error.is_some());
    assert_eq!(s.active(), 0);
}

#[test]
fn max_sessions_answers_ac_system_error_and_stops_offering() {
    let (mut s, mut out) = server(|c| c.max_sessions = 2);
    discover(&mut s, &mut out, 0, Mac([2, 0, 0, 0, 0, 1]));
    let padr3 = pado_for(&mut s, &mut out, 0, Mac([2, 0, 0, 0, 0, 3]));
    discover(&mut s, &mut out, 0, Mac([2, 0, 0, 0, 0, 2]));
    // Full: no PADO (RFC 2516 §5.2 "able to serve")…
    out.clear();
    s.handle_frame(0, 1, &padi_std(Mac([2, 0, 0, 0, 0, 4])), &mut out);
    assert!(out.frames.is_empty());
    // …and a PADR from an earlier offer gets AC-System-Error, SID 0.
    s.handle_frame(0, 1, &padr3, &mut out);
    let p = pads(&out).unwrap();
    assert_eq!(p.session_id, 0);
    assert!(p.tags.ac_system_error.is_some());
    s.check_invariants().unwrap();
}

#[test]
fn one_session_per_host_replaces_the_old_session() {
    let (mut s, mut out) = server(|_| {});
    let (_, sid1) = discover(&mut s, &mut out, 0, HOST);
    // The host restarts with another Host-Uniq.
    out.clear();
    let f = padi(HOST, |w| {
        w.tag(tag::SERVICE_NAME, b"");
        w.tag(tag::HOST_UNIQ, b"new");
    });
    s.handle_frame(10, 1, &f, &mut out);
    let padr = {
        let r = replies(&out);
        padr_from(&r[0], HOST, |_| {})
    };
    out.clear();
    s.handle_frame(10, 1, &padr, &mut out);
    let r = replies(&out);
    assert!(
        r.iter()
            .any(|d| d.code == Code::Padt && d.session_id == sid1),
        "old one PADT'd"
    );
    let sid2 = pads(&out).unwrap().session_id;
    assert_ne!(sid1, sid2);
    assert_eq!(s.active(), 1);
    assert!(out.events.iter().any(|e| matches!(
        e,
        Event::Down {
            reason: DownReason::Replaced,
            ..
        }
    )));
    s.check_invariants().unwrap();
}

#[test]
fn several_sessions_per_host_when_allowed() {
    let (mut s, mut out) = server(|c| c.one_session_per_host = false);
    discover(&mut s, &mut out, 0, HOST);
    let f = padi(HOST, |w| {
        w.tag(tag::SERVICE_NAME, b"");
        w.tag(tag::HOST_UNIQ, b"second");
    });
    out.clear();
    s.handle_frame(0, 1, &f, &mut out);
    let padr = padr_from(&replies(&out)[0], HOST, |_| {});
    out.clear();
    s.handle_frame(0, 1, &padr, &mut out);
    assert_eq!(s.active(), 2);
    s.check_invariants().unwrap();
}

#[test]
fn rfc2516_4_sids_are_unique_nonzero_and_never_ffff() {
    let (mut s, mut out) = server(|c| c.max_sessions = 300);
    let mut seen = std::collections::HashSet::new();
    for i in 0..300u32 {
        let b = i.to_be_bytes();
        let (_, sid) = discover(&mut s, &mut out, 0, Mac([2, 1, b[0], b[1], b[2], b[3]]));
        assert!(sid != 0 && sid != 0xffff);
        assert!(seen.insert(sid));
    }
    s.check_invariants().unwrap();
}

#[test]
fn rfc2516_5_5_padt_from_the_host_frees_at_once_and_silently() {
    let (mut s, mut out) = server(|_| {});
    let (_, sid) = discover(&mut s, &mut out, 0, HOST);
    let padt = |src: Mac| {
        let mut b = Vec::new();
        DiscoveryWriter::begin(&mut b, AC, src, Vlans::NONE, Code::Padt, sid)
            .finish()
            .unwrap();
        b
    };
    // A PADT from another MAC for that SID does nothing.
    out.clear();
    s.handle_frame(0, 1, &padt(HOST2), &mut out);
    assert_eq!(s.active(), 1);
    s.handle_frame(0, 1, &padt(HOST), &mut out);
    assert_eq!(s.active(), 0);
    assert!(out.frames.is_empty(), "nothing sent after a PADT");
    assert!(matches!(
        out.events.last(),
        Some(Event::Down {
            reason: DownReason::PeerPadt,
            ..
        })
    ));
    // And no timer resurrects it.
    out.clear();
    for t in 1..100 {
        s.handle_timers(t * 1000, &mut out);
    }
    assert!(out.frames.is_empty());
    s.check_invariants().unwrap();
}

#[test]
fn silent_host_after_pads_is_cleaned_up_by_max_configure() {
    let (mut s, mut out) = server(|_| {});
    discover(&mut s, &mut out, 0, HOST);
    let mut padt = false;
    for t in 1..=40 {
        out.clear();
        s.handle_timers(t * 1000, &mut out);
        padt |= replies(&out).iter().any(|d| d.code == Code::Padt);
    }
    assert!(padt);
    assert_eq!(s.active(), 0);
    assert!(s.next_deadline().is_none_or(|d| d > 40_000));
}

#[test]
fn per_mac_padi_limit() {
    let (mut s, mut out) = server(|c| {
        c.mac_padi_limit = 1;
        c.mac_padi_burst = 2;
    });
    for _ in 0..10 {
        s.handle_frame(0, 1, &padi_std(HOST), &mut out);
    }
    s.handle_frame(0, 1, &padi_std(HOST2), &mut out);
    assert_eq!(replies(&out).len(), 3, "2 for HOST, 1 for HOST2");
    assert_eq!(s.stats().padi_limited, 8);
}

#[test]
fn pado_delay_tiers() {
    let (mut s, mut out) = server(|c| c.pado_delay = vec![(0, 0), (1, 300)]);
    discover(&mut s, &mut out, 0, HOST);
    out.clear();
    s.handle_frame(1000, 1, &padi_std(HOST2), &mut out);
    assert!(out.frames.is_empty(), "delayed with one session up");
    assert_eq!(s.next_deadline().map(|d| d <= 1300), Some(true));
    s.handle_timers(1299, &mut out);
    assert!(replies(&out).is_empty());
    s.handle_timers(1300, &mut out);
    assert_eq!(
        replies(&out)
            .iter()
            .filter(|d| d.code == Code::Pado)
            .count(),
        1
    );
}

#[test]
fn vlan_range_filter() {
    let (mut s, mut out) = server(|c| c.vlans = VlanFilter::Ranges(vec![100..=149, 150..=199]));
    let tagged = |vid| {
        let mut b = Vec::new();
        let mut w = DiscoveryWriter::begin(
            &mut b,
            Mac::BROADCAST,
            HOST,
            Vlans::single(vid),
            Code::Padi,
            0,
        );
        w.tag(tag::SERVICE_NAME, b"");
        w.finish().unwrap();
        b
    };
    s.handle_frame(0, 1, &tagged(99), &mut out);
    s.handle_frame(0, 1, &padi_std(HOST), &mut out);
    assert!(out.frames.is_empty());
    s.handle_frame(0, 1, &tagged(150), &mut out);
    let r = replies(&out);
    assert_eq!(r[0].vlans, Vlans::single(150), "answered on the same VLAN");
}

// ------------------------------------------------- one client, hand-pumped

use crate::client::{Client, ClientConfig, ClientOutput};
use crate::layers::AuthSet;

/// Moves frames between one server and one client; `drop` decides, per
/// frame (server → client = true), whether the wire loses it.
struct Pair {
    s: Server,
    c: Client,
    so: ServerOutput,
    co: ClientOutput,
    now: Millis,
    log: Vec<(bool, u16, u8)>,
}

fn ppp_of(f: &[u8]) -> Option<(u16, u8)> {
    let s = ppp::parse_session(f).ok()?;
    let c = ppp::parse_control(s.info).ok()?;
    Some((s.protocol, c.code))
}

impl Pair {
    fn new(auth: AuthProto) -> Pair {
        let (s, so) = server(|_| {});
        let c = Client::new(
            ClientConfig {
                mac: HOST,
                username: b"u".to_vec(),
                password: "p".into(),
                auth: AuthSet::new(&[auth]),
                ..ClientConfig::default()
            },
            [3; 32],
        );
        Pair {
            s,
            c,
            so,
            co: ClientOutput::new(),
            now: 0,
            log: Vec::new(),
        }
    }

    fn answer(&mut self) {
        let evs = std::mem::take(&mut self.so.events);
        for e in evs {
            match e {
                Event::Authenticate { session, request } => {
                    let ok = request.verify_local("p");
                    let v = match ok {
                        Some(sha) => AuthVerdict::Accept(Authorization {
                            mschap2_success: sha,
                            ..Authorization::default()
                        }),
                        None => AuthVerdict::Reject {
                            message: b"no".as_slice().into(),
                        },
                    };
                    self.s.auth_reply(self.now, session, v, &mut self.so);
                }
                Event::NeedAddress { session } => {
                    let a = Ipv4Assignment {
                        address: Ipv4Addr::new(100, 64, 0, 7),
                        dns: [None, None],
                        nbns: [None, None],
                    };
                    self.s
                        .address_reply(self.now, session, Some(a), &mut self.so);
                }
                other => self.so.events.push(other),
            }
        }
    }

    /// Runs `ms` of simulated time in 100 ms steps.
    fn run(&mut self, ms: u64, mut drop: impl FnMut(bool, &[u8]) -> bool) {
        let end = self.now + ms;
        while self.now < end {
            for _ in 0..50 {
                self.answer();
                let sf: Vec<Vec<u8>> = self.so.frames().map(|(_, f)| f.to_vec()).collect();
                let cf: Vec<Vec<u8>> = self.co.frames().map(|(_, f)| f.to_vec()).collect();
                self.so.buf.clear();
                self.so.frames.clear();
                self.co.clear();
                if sf.is_empty() && cf.is_empty() {
                    break;
                }
                for f in sf {
                    if let Some((p, c)) = ppp_of(&f) {
                        self.log.push((true, p, c));
                    }
                    if !drop(true, &f) {
                        self.c.handle_frame(self.now, &f, &mut self.co);
                    }
                }
                for f in cf {
                    if let Some((p, c)) = ppp_of(&f) {
                        self.log.push((false, p, c));
                    }
                    if !drop(false, &f) {
                        self.s.handle_frame(self.now, 1, &f, &mut self.so);
                    }
                }
            }
            self.now += 100;
            self.s.handle_timers(self.now, &mut self.so);
            self.c.handle_timers(self.now, &mut self.co);
        }
    }
}

fn drop_first(proto: u16, code: u8) -> impl FnMut(bool, &[u8]) -> bool {
    let mut done = false;
    move |to_client, f| {
        if !done && to_client && ppp_of(f) == Some((proto, code)) {
            done = true;
            return true;
        }
        false
    }
}

#[test]
fn rfc1994_4_1_lost_success_is_recovered_by_a_repeated_response() {
    for a in [AuthProto::ChapMd5, AuthProto::MsChapV1, AuthProto::MsChapV2] {
        let mut p = Pair::new(a);
        p.c.start(0, &mut p.co);
        p.run(
            15_000,
            drop_first(ppp::proto::CHAP, crate::auth::code::CHAP_SUCCESS),
        );
        assert_eq!(p.c.phase(), ClientPhase::Up, "{a:?}: {:?}", p.log);
        assert!(p.so.events.iter().any(|e| matches!(e, Event::Up { .. })));
    }
}

#[test]
fn rfc1334_lost_pap_ack_is_recovered() {
    let mut p = Pair::new(AuthProto::Pap);
    p.c.start(0, &mut p.co);
    p.run(
        15_000,
        drop_first(ppp::proto::PAP, crate::auth::code::PAP_ACK),
    );
    assert_eq!(p.c.phase(), ClientPhase::Up);
}
