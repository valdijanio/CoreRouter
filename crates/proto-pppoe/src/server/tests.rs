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
    let (mut s, mut out) = server(|c| c.services = ServiceTable::only(&["internet"]));
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
    let (mut s, mut out) = server(|c| c.services = ServiceTable::only(&["internet"]));
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

/// RouterOS `keepalive-timeout` (echoes every T/2, two misses): a
/// subscriber that goes silent is gone T after the last packet heard,
/// wherever the silence falls between the echo ticks. Counting misses at
/// the ticks let it live up to 1.5 T (42 s for 30 s against a RouterOS
/// 7.25 CPE, `scripts/routeros-interop-pppoe.sh keepalive`, G3.9g).
#[test]
fn keepalive_drops_a_silent_subscriber_after_the_timeout_not_later() {
    const T: u64 = 30_000;
    for cut_offset in (0..15_000).step_by(1_000) {
        let mut l = lab(1, |c| {
            c.server.keepalive_interval_ms = T / 2;
            c.server.keepalive_misses = 2;
        });
        l.run_until(10_000);
        assert_eq!(l.server_sessions(), 1);
        l.run_until(60_000 + cut_offset);
        // The line goes dead both ways, silently.
        l.cfg.loss_ppm = 1_000_000;
        let cut = l.now;
        let mut gone = None;
        while l.now < cut + 2 * T {
            l.run_until(l.now + 100);
            if l.server_sessions() == 0 {
                gone = Some(l.now - cut);
                break;
            }
        }
        let gone = gone.expect("the silent subscriber is dropped");
        assert!(
            gone <= T + 200,
            "cut at +{cut_offset} ms: dropped {gone} ms after the cut (timeout {T})"
        );
        assert!(
            gone >= T / 2,
            "cut at +{cut_offset} ms: dropped too early, {gone} ms"
        );
        assert_eq!(l.servers[0].stats().keepalive_timeouts, 1);
    }
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

/// G3.9g, against the RouterOS CHR: our LCP Configure-Request went out with
/// the PADS, before the client listened, and every session waited the 3 s
/// restart timer for the retransmission. The client's first request now
/// brings ours again at once.
#[test]
fn a_configure_request_lost_before_the_client_listens_is_resent_at_once() {
    let mut p = Pair::new(AuthProto::Pap);
    p.c.start(0, &mut p.co);
    let mut drop = drop_first(ppp::proto::LCP, crate::lcp::code::CONFIGURE_REQUEST);
    while p.c.phase() != ClientPhase::Up && p.now < 10_000 {
        p.run(100, &mut drop);
    }
    assert_eq!(p.c.phase(), ClientPhase::Up, "{:?}", p.log);
    assert!(p.now < 1_000, "up after {} ms: {:?}", p.now, p.log);
}

/// G3.9g: the RouterOS client sometimes drops the first Challenge, sent
/// right after its Configure-Ack; the first retry comes in 300 ms, not 3 s.
#[test]
fn a_lost_first_challenge_is_repeated_early() {
    for a in [AuthProto::ChapMd5, AuthProto::MsChapV1, AuthProto::MsChapV2] {
        let mut p = Pair::new(a);
        p.c.start(0, &mut p.co);
        let mut drop = drop_first(ppp::proto::CHAP, crate::auth::code::CHAP_CHALLENGE);
        while p.c.phase() != ClientPhase::Up && p.now < 10_000 {
            p.run(100, &mut drop);
        }
        assert_eq!(p.c.phase(), ClientPhase::Up, "{a:?}: {:?}", p.log);
        assert!(p.now < 1_000, "{a:?}: up after {} ms", p.now);
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

#[test]
fn reconfigure_keeps_the_mac_and_the_sid_space() {
    let cfg = ServerConfig {
        max_sessions: 100,
        ..ServerConfig::default()
    };
    let mac = cfg.ac_mac;
    let mut s = Server::new(cfg, [1; 32], 0);
    let mut next = s.config().clone();
    next.ac_mac = Mac([9; 6]);
    next.max_sessions = 5;
    next.padi_limit = 10;
    next.max_mru = 1400;
    s.reconfigure(next);
    assert_eq!(s.config().ac_mac, mac);
    assert_eq!(s.config().max_sessions, 100);
    assert_eq!((s.config().padi_limit, s.config().max_mru), (10, 1400));
    s.check_invariants().unwrap();
}

/// G4.3g: the service's workers split one port's SESSION_ID space by lane,
/// with no SID in two lanes and none left out.
#[test]
fn sid_lanes_split_the_space_without_overlap() {
    let lanes = 3u16;
    let mut seen = vec![0u8; usize::from(MAX_SID) + 1];
    for lane in 0..lanes {
        let cfg = ServerConfig {
            sid_lane: (lane, lanes),
            ..ServerConfig::default()
        };
        for sid in cfg.sids() {
            seen[usize::from(sid)] += 1;
        }
        let s = Server::new(cfg, [lane as u8; 32], 0);
        s.check_invariants().unwrap();
    }
    assert_eq!(seen[0], 0, "SID 0 is never a session (RFC 2516 §4)");
    assert!(
        seen[1..].iter().all(|n| *n == 1),
        "each SID in exactly one lane"
    );
}

// --- G4.3k: the Service-Name table ---

fn rule(action: ServiceAction) -> ServiceRule {
    ServiceRule {
        action,
        ..ServiceRule::default()
    }
}

fn table() -> ServiceTable {
    ServiceTable::new(
        [
            (b"internet".to_vec(), rule(ServiceAction::Terminate)),
            (
                b"backup".to_vec(),
                ServiceRule {
                    action: ServiceAction::Delay,
                    delay_ms: 400,
                    ..ServiceRule::default()
                },
            ),
            (b"blocked".to_vec(), rule(ServiceAction::Drop)),
        ],
        rule(ServiceAction::Terminate),
        rule(ServiceAction::Drop),
    )
}

fn padi_named(src: Mac, name: &[u8]) -> Vec<u8> {
    padi(src, |w| {
        w.tag(tag::SERVICE_NAME, name);
        w.tag(tag::HOST_UNIQ, b"hu");
    })
}

fn pado_count(out: &ServerOutput) -> usize {
    replies(out).iter().filter(|d| d.code == Code::Pado).count()
}

#[test]
fn rfc2516_5_2_each_terminating_row_gets_a_pado_with_the_same_name() {
    let (mut s, mut out) = server(|c| c.services = table());
    for name in [&b"internet"[..], b""] {
        out.clear();
        s.handle_frame(0, 1, &padi_named(HOST, name), &mut out);
        let r = replies(&out);
        assert_eq!(r.len(), 1, "{name:?}");
        // §5.2: "a Service-Name TAG identical to the one in the PADI".
        assert_eq!(r[0].tags.service_name, Some(name));
    }
}

#[test]
fn rfc2516_5_2_drop_rows_and_unlisted_names_get_no_pado() {
    let (mut s, mut out) = server(|c| c.services = table());
    for name in [&b"blocked"[..], b"voip", b"INTERNET"] {
        s.handle_frame(0, 1, &padi_named(HOST, name), &mut out);
    }
    // §5.2: "If the Access Concentrator can not serve the PADI it MUST
    // NOT respond with a PADO."
    assert!(out.frames.is_empty());
    assert_eq!(s.stats().service_refused, 3);
    assert_eq!(s.stats().padi_refused, 3);
}

#[test]
fn rfc2516_5_4_padr_for_a_drop_row_is_service_name_error_with_sid_zero() {
    let (mut s, mut out) = server(|c| c.services = table());
    s.handle_frame(0, 1, &padi_named(HOST, b"internet"), &mut out);
    // A valid AC-Cookie (it binds the host, not the name) with a name the
    // table drops.
    let padr = padr_from(&replies(&out)[0], HOST, |_| {});
    let padr = {
        let mut b = Vec::new();
        let d = discovery::parse(&padr).unwrap();
        let mut w = DiscoveryWriter::begin(&mut b, AC, HOST, Vlans::NONE, Code::Padr, 0);
        w.tag(tag::SERVICE_NAME, b"blocked");
        w.tag(tag::AC_COOKIE, d.tags.ac_cookie.unwrap());
        w.finish().unwrap();
        b
    };
    out.clear();
    s.handle_frame(0, 1, &padr, &mut out);
    let p = pads(&out).unwrap();
    // §5.4: Service-Name-Error, SESSION_ID 0x0000.
    assert_eq!(p.session_id, 0);
    let err = p.tags.service_name_error.unwrap();
    // Erratum 5634: the UTF-8 text MUST NOT be NULL-terminated.
    assert!(!err.is_empty() && !err.ends_with(&[0]));
    assert_eq!(p.tags.service_name, Some(&b"blocked"[..]));
    assert_eq!(s.active(), 0);
    s.check_invariants().unwrap();
}

#[test]
fn delay_row_answers_after_its_delay_plus_the_load_delay() {
    let (mut s, mut out) = server(|c| {
        c.services = table();
        c.pado_delay = vec![(0, 100)];
    });
    s.handle_frame(1000, 1, &padi_named(HOST, b"backup"), &mut out);
    assert!(out.frames.is_empty());
    s.handle_timers(1499, &mut out);
    assert_eq!(pado_count(&out), 0);
    s.handle_timers(1500, &mut out);
    assert_eq!(pado_count(&out), 1, "400 ms of the row + 100 ms of load");
    out.clear();
    // A terminating row waits only the load delay.
    s.handle_frame(2000, 1, &padi_named(HOST2, b"internet"), &mut out);
    s.handle_timers(2100, &mut out);
    assert_eq!(pado_count(&out), 1);
}

#[test]
fn a_rows_max_sessions_and_padi_limit() {
    let limited = ServiceTable::new(
        [(
            b"iptv".to_vec(),
            ServiceRule {
                max_sessions: 1,
                ..ServiceRule::default()
            },
        )],
        ServiceRule {
            padi_limit: 1,
            ..ServiceRule::default()
        },
        ServiceRule::default(),
    );
    let (mut s, mut out) = server(|c| c.services = limited);
    let go = |s: &mut Server, out: &mut ServerOutput, now, mac, name: &[u8]| {
        out.clear();
        s.handle_frame(now, 1, &padi_named(mac, name), out);
        let r = replies(out);
        let pado = r.first()?;
        let padr = padr_from(pado, mac, |_| {});
        out.clear();
        s.handle_frame(now, 1, &padr, out);
        pads(out).map(|p| p.session_id)
    };
    assert!(go(&mut s, &mut out, 0, HOST, b"iptv").is_some_and(|sid| sid != 0));
    // The row is full: another host gets no PADO, the server still serves
    // other rows.
    assert_eq!(go(&mut s, &mut out, 0, HOST2, b"iptv"), None);
    assert!(go(&mut s, &mut out, 0, HOST2, b"other").is_some());
    // The host of the row's session comes back (CPE reboot): it takes the
    // old session's place (one-session-per-host).
    assert!(go(&mut s, &mut out, 10, HOST, b"iptv").is_some_and(|sid| sid != 0));
    assert_eq!(s.active(), 2);
    // The empty row's 1 PADI/s.
    let m = |i| Mac([2, 0x33, 0, 0, 0, i]);
    out.clear();
    s.handle_frame(20, 1, &padi_named(m(1), b""), &mut out);
    s.handle_frame(21, 1, &padi_named(m(2), b""), &mut out);
    assert_eq!(pado_count(&out), 1);
    s.handle_frame(1100, 1, &padi_named(m(3), b""), &mut out);
    assert_eq!(pado_count(&out), 2);
    s.check_invariants().unwrap();
    let rows = s.service_sessions();
    assert_eq!(rows[0], (b"iptv".to_vec(), 1));
    assert_eq!(rows.last(), Some(&(b"*".to_vec(), 1)));
}

#[test]
fn the_profile_name_reaches_the_authentication() {
    let mut l = lab(4, |c| {
        c.server.services = table();
        c.service_names = vec![b"internet".to_vec(), Vec::new()];
    });
    l.run_until(10_000);
    assert_eq!(l.clients_up(), 4);
    l.check().unwrap();
    let names = l.auth_services.clone();
    assert_eq!(
        names.iter().filter(|n| n.as_slice() == b"internet").count(),
        2,
        "{names:?}"
    );
    assert_eq!(names.iter().filter(|n| n.is_empty()).count(), 2);
}

#[test]
fn reconfiguring_the_table_recounts_the_rows() {
    let (mut s, mut out) = server(|c| c.services = ServiceTable::default());
    discover(&mut s, &mut out, 0, HOST);
    discover(&mut s, &mut out, 0, HOST2);
    let mut c = s.config().clone();
    c.services = table();
    s.reconfigure(c);
    s.check_invariants().unwrap();
    assert_eq!(
        s.service_sessions()
            .iter()
            .find(|r| r.0.is_empty())
            .map(|r| r.1),
        Some(2)
    );
    // Back to "everything": still consistent.
    let mut c = s.config().clone();
    c.services = ServiceTable::only(&["x"]);
    s.reconfigure(c);
    s.check_invariants().unwrap();
}

proptest::proptest! {
    /// Any table, any name: a PADO comes iff the name's row does not drop,
    /// it echoes the name byte for byte, and a PADR then creates a session
    /// or gets Service-Name-Error with SESSION_ID 0 — nothing else.
    #[test]
    fn prop_rfc2516_service_table(
        rows in proptest::collection::vec(
            (proptest::collection::vec(proptest::prelude::any::<u8>(), 0..6), 0u8..3, 0u32..3),
            0..12,
        ),
        empty in 0u8..3,
        any in 0u8..3,
        asked in proptest::collection::vec(proptest::collection::vec(proptest::prelude::any::<u8>(), 0..6), 1..20),
    ) {
        let act = |a: u8| match a {
            0 => ServiceAction::Terminate,
            1 => ServiceAction::Delay,
            _ => ServiceAction::Drop,
        };
        let t = ServiceTable::new(
            rows.iter().map(|(n, a, m)| (n.clone(), ServiceRule { action: act(*a), delay_ms: 10, max_sessions: *m, padi_limit: 0 })),
            rule(act(empty)),
            rule(act(any)),
        );
        let (mut s, mut out) = server(|c| { c.services = t.clone(); c.one_session_per_host = false; });
        for (i, name) in asked.iter().enumerate() {
            let mac = Mac([2, 0x44, 0, 0, 0, i as u8]);
            let now = i as u64 * 1000;
            out.clear();
            s.handle_frame(now, 1, &padi_named(mac, name), &mut out);
            s.handle_timers(now + 50, &mut out);
            let (slot, r) = t.lookup(name);
            let offered = replies(&out).into_iter().find(|d| d.code == Code::Pado).map(|d| (d.tags.service_name.map(<[u8]>::to_vec), padr_from(&d, mac, |_| {})));
            let full_before = s.service_sessions();
            if r.action == ServiceAction::Drop {
                proptest::prop_assert!(offered.is_none());
                continue;
            }
            let Some((echo, padr)) = offered else {
                // Only a full row may stay silent.
                proptest::prop_assert!(r.max_sessions > 0, "slot {slot} silent");
                continue;
            };
            proptest::prop_assert_eq!(echo.as_deref(), Some(name.as_slice()));
            out.clear();
            s.handle_frame(now + 60, 1, &padr, &mut out);
            let p = pads(&out);
            proptest::prop_assert!(p.is_some());
            let p = p.unwrap();
            proptest::prop_assert!(p.session_id != 0 || p.tags.ac_system_error.is_some(), "{full_before:?}");
            s.check_invariants().map_err(proptest::test_runner::TestCaseError::fail)?;
        }
    }
}

// --- G4.3l: stacked VLANs and sessions per VLAN ---

fn padi_on(src: Mac, vlans: Vlans) -> Vec<u8> {
    let mut b = Vec::new();
    let mut w = DiscoveryWriter::begin(&mut b, Mac::BROADCAST, src, vlans, Code::Padi, 0);
    w.tag(tag::SERVICE_NAME, b"");
    w.finish().unwrap();
    b
}

fn stacked(c: &mut ServerConfig) {
    c.vlans = VlanFilter::Stacked {
        outer: vec![100..=104, 105..=109],
        inner: vec![1..=1000, 1001..=2000],
        tpid: eth::TPID_8021AD,
        untagged: false,
    };
}

#[test]
fn stacked_filter_takes_both_tags_and_the_tpid() {
    let (mut s, mut out) = server(stacked);
    let q = |o, i| Vlans::qinq(o, i);
    let q8100 = Vlans {
        outer_tpid: eth::TPID_8021Q,
        ..Vlans::qinq(100, 7)
    };
    for v in [
        Vlans::NONE,
        Vlans::single(100),
        q(110, 7),
        q(100, 2001),
        q8100,
    ] {
        s.handle_frame(0, 1, &padi_on(HOST, v), &mut out);
    }
    assert!(
        out.frames.is_empty(),
        "untagged, one tag, outer or inner out of range, wrong TPID"
    );
    s.handle_frame(0, 1, &padi_on(HOST, q(105, 2000)), &mut out);
    let r = replies(&out);
    assert_eq!(r.len(), 1);
    // The PADO goes back inside the same two tags (802.1ad outside).
    assert_eq!(r[0].vlans, q(105, 2000));
    let f = &out.frames().next().unwrap().1;
    assert_eq!(&f[12..14], &[0x88, 0xa8]);
    assert_eq!(&f[16..18], &[0x81, 0x00]);
    // A single-tag server does not take a QinQ frame.
    let (mut s, mut out) = server(|c| c.vlans = VlanFilter::Ranges(vec![100..=104, 105..=109]));
    s.handle_frame(0, 1, &padi_on(HOST, q(105, 5)), &mut out);
    assert!(out.frames.is_empty());
}

/// TR-101 1:1: one session per VLAN. A second CPE on the line gets no
/// PADO (§5.2) and, with an older offer, AC-System-Error (§5.4); the line's
/// own CPE coming back takes its old session's place; another line is
/// unaffected.
#[test]
fn one_session_per_vlan_in_the_1_to_1_model() {
    let (mut s, mut out) = server(|c| {
        stacked(c);
        c.max_per_vlan = 1;
    });
    let line = Vlans::qinq(100, 7);
    let go = |s: &mut Server, out: &mut ServerOutput, now, mac, v: Vlans| -> (bool, Option<u16>) {
        out.clear();
        s.handle_frame(now, 1, &padi_on(mac, v), out);
        let r = replies(out);
        let Some(pado) = r.first() else {
            return (false, None);
        };
        let mut b = Vec::new();
        let mut w = DiscoveryWriter::begin(&mut b, AC, mac, v, Code::Padr, 0);
        w.tag(tag::SERVICE_NAME, b"");
        w.tag(tag::AC_COOKIE, pado.tags.ac_cookie.unwrap());
        w.finish().unwrap();
        out.clear();
        s.handle_frame(now, 1, &b, out);
        (true, pads(out).map(|p| p.session_id))
    };
    let (_, sid) = go(&mut s, &mut out, 0, HOST, line);
    assert!(sid.is_some_and(|x| x != 0));
    // A second CPE on the same line: no PADO.
    assert_eq!(go(&mut s, &mut out, 0, HOST2, line), (false, None));
    assert_eq!(s.stats().vlan_refused, 1);
    // The line's own CPE after a reboot (a new AC-Cookie): its session,
    // not a refusal.
    let (_, again) = go(&mut s, &mut out, 6000, HOST, line);
    assert!(again.is_some_and(|x| x != 0), "{:?}", s.stats());
    assert_eq!(s.active(), 1);
    // Another line.
    assert!(
        go(&mut s, &mut out, 10, HOST2, Vlans::qinq(100, 8))
            .1
            .is_some_and(|x| x != 0)
    );
    assert_eq!(s.active(), 2);
    s.check_invariants().unwrap();
    // Turning the limit off and on keeps the count right.
    let mut c = s.config().clone();
    c.max_per_vlan = 0;
    s.reconfigure(c.clone());
    c.max_per_vlan = 1;
    s.reconfigure(c);
    s.check_invariants().unwrap();
}

// ------------------------------------------- the router's own client (G3.9ga)

fn client_with(f: impl FnOnce(&mut ClientConfig)) -> Client {
    let mut c = ClientConfig {
        mac: HOST,
        username: b"u".to_vec(),
        password: "p".into(),
        discovery_attempts: 2,
        ..ClientConfig::default()
    };
    f(&mut c);
    Client::new(c, [3; 32])
}

/// RouterOS `ac-name`: only the named concentrator's offer is taken.
#[test]
fn ac_name_takes_only_that_concentrators_offer() {
    let mut p = Pair::new(AuthProto::Pap);
    p.s.reconfigure(ServerConfig {
        ac_name: b"isp-bng".to_vec(),
        ..p.s.config().clone()
    });
    p.c = client_with(|c| {
        c.ac_name = b"other-bng".to_vec();
        c.auth = AuthSet::new(&[AuthProto::Pap]);
    });
    p.c.start(0, &mut p.co);
    p.run(10_000, |_, _| false);
    assert_eq!(
        p.c.phase(),
        ClientPhase::Closed(crate::client::ClientDown::NoOffer)
    );
    p.c = client_with(|c| {
        c.ac_name = b"isp-bng".to_vec();
        c.auth = AuthSet::new(&[AuthProto::Pap]);
    });
    p.c.start(p.now, &mut p.co);
    p.run(2_000, |_, _| false);
    assert_eq!(p.c.phase(), ClientPhase::Up, "{:?}", p.log);
    assert_eq!(p.c.ac_name(), Some(&b"isp-bng"[..]));
    assert_eq!(p.c.ac_mac(), AC);
}

/// The BNG's refusal text is kept for the operator (RFC 1334 §2.2.2,
/// RFC 2759 §6: only the `M=` part of an MS-CHAP failure).
#[test]
fn the_bngs_refusal_message_is_kept() {
    for a in [AuthProto::Pap, AuthProto::ChapMd5, AuthProto::MsChapV2] {
        let mut p = Pair::new(a);
        p.c = client_with(|c| {
            c.password = "wrong".into();
            c.auth = AuthSet::new(&[a]);
        });
        p.c.start(0, &mut p.co);
        p.run(5_000, |_, _| false);
        assert_eq!(
            p.c.phase(),
            ClientPhase::Closed(crate::client::ClientDown::AuthFailed),
            "{a:?}"
        );
        let m = p.c.auth_message().unwrap_or_default().to_owned();
        assert!(m.contains("no") && !m.contains("E=691"), "{a:?}: {m}");
    }
}

/// `max-mtu` below the BNG's MRU caps what the client sends.
#[test]
fn max_mtu_caps_the_links_mtu() {
    let mut p = Pair::new(AuthProto::Pap);
    p.c = client_with(|c| {
        c.mtu = 1400;
        c.mru = 1460;
        c.auth = AuthSet::new(&[AuthProto::Pap]);
    });
    p.c.start(0, &mut p.co);
    p.run(2_000, |_, _| false);
    assert_eq!(p.c.phase(), ClientPhase::Up);
    let (mtu, mru) = p.c.mtu_mru();
    assert!(mtu <= 1400, "mtu {mtu}");
    assert_eq!(mru, 1460);
}

/// RFC 2516 §5.5: the PADT a restarted CPE sends for its old session.
#[test]
fn rfc2516_5_5_padt_of_a_stale_session() {
    let mut out = ClientOutput::new();
    crate::client::padt(HOST, AC, Vlans::NONE, 0x1234, 1, &mut out);
    let frames: Vec<Vec<u8>> = out.frames().map(|(_, f)| f.to_vec()).collect();
    assert_eq!(frames.len(), 1);
    let d = discovery::parse(&frames[0]).unwrap();
    assert_eq!(d.code, Code::Padt);
    assert_eq!(d.session_id, 0x1234);
    assert_eq!((d.src, d.dst), (HOST, AC));
    // Nothing for session 0 or a broadcast AC.
    let mut out = ClientOutput::new();
    crate::client::padt(HOST, AC, Vlans::NONE, 0, 1, &mut out);
    crate::client::padt(HOST, Mac::BROADCAST, Vlans::NONE, 7, 1, &mut out);
    assert!(out.frames.is_empty());
}
