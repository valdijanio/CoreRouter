//! Fuzz oracles (G0.5 pattern, `docs/fuzzing.md`): each takes hostile bytes,
//! runs the real code path and returns `Err` saying what broke. The
//! proptests (`tests/fuzz.rs`, in `cargo xtask ci`) and the libFuzzer
//! targets (`crates/proto-pppoe/fuzz`) run the same functions.
#![doc(hidden)]

use crate::auth::{ChapValue, MsChapResponse, PapRequest};
use crate::client::{Client, ClientConfig, ClientOutput};
use crate::discovery::{self, DiscoveryWriter, Tags};
use crate::lcp::LcpOpt;
use crate::ncp::{IpcpOpt, Ipv6cpOpt};
use crate::ppp::{self, Opt};
use crate::server::{
    AuthVerdict, Authorization, Event, Ipv4Assignment, Server, ServerConfig, ServerOutput,
};

/// Discovery decode; a frame that decodes re-encodes to the same tags.
pub fn discovery(data: &[u8]) -> Result<(), String> {
    let Ok(d) = discovery::parse(data) else {
        return Ok(());
    };
    let mut b = Vec::new();
    let mut w = DiscoveryWriter::begin(&mut b, d.dst, d.src, d.vlans, d.code, d.session_id);
    let t = d.tags;
    for (kind, v) in [
        (discovery::tag::SERVICE_NAME, t.service_name),
        (discovery::tag::AC_NAME, t.ac_name),
        (discovery::tag::HOST_UNIQ, t.host_uniq),
        (discovery::tag::AC_COOKIE, t.ac_cookie),
        (discovery::tag::RELAY_SESSION_ID, t.relay_session_id),
        (discovery::tag::SERVICE_NAME_ERROR, t.service_name_error),
        (discovery::tag::AC_SYSTEM_ERROR, t.ac_system_error),
        (discovery::tag::GENERIC_ERROR, t.generic_error),
        (discovery::tag::VENDOR_SPECIFIC, t.vendor),
    ] {
        if let Some(v) = v {
            w.tag(kind, v);
        }
    }
    if let Some(p) = t.ppp_max_payload {
        w.tag_u16(discovery::tag::PPP_MAX_PAYLOAD, p);
    }
    if w.finish().is_err() {
        // The input carried repeats or unknown tags that made it longer
        // than one frame: nothing to compare.
        return Ok(());
    }
    let back = discovery::parse(&b).map_err(|e| format!("re-encoded frame refused: {e}"))?;
    let want = Tags {
        service_names: t.service_name.map_or(0, |_| 1),
        unknown: 0,
        ..t
    };
    let got = Tags {
        unknown: 0,
        ..back.tags
    };
    if got != want || (back.code, back.session_id, back.vlans) != (d.code, d.session_id, d.vlans) {
        return Err(format!("round trip changed the packet: {want:?} → {got:?}"));
    }
    Ok(())
}

fn round<'a, T: PartialEq + std::fmt::Debug>(
    o: Opt<'a>,
    parse: impl Fn(Opt<'a>) -> Result<T, crate::wire::WireError>,
    put: impl Fn(&T, &mut Vec<u8>) -> Result<(), crate::wire::WireError>,
) -> Result<(), String> {
    let Ok(v) = parse(o) else { return Ok(()) };
    let mut b = Vec::new();
    put(&v, &mut b).map_err(|e| format!("{v:?} does not re-encode: {e}"))?;
    let back = ppp::options(&b)
        .next()
        .ok_or("no option")?
        .map_err(|e| e.to_string())?;
    if back != o {
        return Err(format!("option changed: {o:?} → {back:?}"));
    }
    Ok(())
}

/// Session frame → control packet → every option as LCP, IPCP and IPv6CP:
/// a typed option re-encodes to the same bytes. Also the PAP/CHAP bodies.
pub fn session(data: &[u8]) -> Result<(), String> {
    let Ok(f) = ppp::parse_session(data) else {
        return Ok(());
    };
    let Ok(c) = ppp::parse_control(f.info) else {
        return Ok(());
    };
    for o in ppp::options(c.data).flatten() {
        round(o, LcpOpt::parse, |v, b| v.put(b))?;
        round(o, IpcpOpt::parse, |v, b| v.put(b))?;
        round(o, Ipv6cpOpt::parse, |v, b| v.put(b))?;
    }
    auth(c.data)
}

/// PAP and CHAP bodies.
pub fn auth(data: &[u8]) -> Result<(), String> {
    if let Ok(p) = PapRequest::parse(data) {
        let mut b = Vec::new();
        p.put(&mut b).map_err(|e| e.to_string())?;
        if b.as_slice() != data.get(..b.len()).unwrap_or(&[]) {
            return Err("PAP request round trip".into());
        }
    }
    if let Ok(v) = ChapValue::parse(data) {
        let mut b = Vec::new();
        v.put(&mut b).map_err(|e| e.to_string())?;
        if b != data {
            return Err("CHAP value round trip".into());
        }
        if let Ok(r) = MsChapResponse::parse(v.value)
            && r.to_bytes().as_slice() != v.value
        {
            return Err("MS-CHAP response round trip".into());
        }
    }
    Ok(())
}

/// Splits `data` into frames: each a length octet then that many bytes.
fn frames(data: &[u8]) -> impl Iterator<Item = &[u8]> {
    let mut rest = data;
    std::iter::from_fn(move || {
        let (&n, tail) = rest.split_first()?;
        let n = usize::from(n).min(tail.len());
        let (f, r) = tail.split_at(n);
        rest = r;
        Some(f)
    })
}

/// Hostile frames at a server, with time passing; the server must not
/// panic and its indexes must stay consistent. The server is the one a
/// default [`crate::lab::Lab`] runs (same MAC, same cookie key), so frames
/// captured there reach the session stage. The first byte switches the
/// cookie check and IPv6CP.
pub fn server(data: &[u8]) -> Result<(), String> {
    server_stats(data).map(|_| ())
}

pub fn server_stats(data: &[u8]) -> Result<crate::server::Stats, String> {
    let head = data.first().copied().unwrap_or(0);
    let mut s = Server::new(
        ServerConfig {
            ac_mac: crate::lab::ac_mac(0),
            require_cookie: head & 1 == 1,
            ipv6: head & 2 == 2,
            ..ServerConfig::default()
        },
        crate::lab::server_seed(1, 0),
        0,
    );
    let mut out = ServerOutput::new();
    let mut now = 0;
    for f in frames(data.get(1..).unwrap_or(&[])) {
        s.handle_frame(now, 1, f, &mut out);
        // Answer the questions the way the lab does, so the session goes on.
        let evs = std::mem::take(&mut out.events);
        for e in evs {
            match e {
                Event::Authenticate { session, request } => {
                    let v = match request.verify_local("pass0") {
                        Some(sha) => AuthVerdict::Accept(Authorization {
                            mschap2_success: sha,
                            ..Authorization::default()
                        }),
                        None => AuthVerdict::Accept(Authorization::default()),
                    };
                    s.auth_reply(now, session, v, &mut out);
                }
                Event::NeedAddress { session } => {
                    let a = Ipv4Assignment {
                        address: std::net::Ipv4Addr::new(100, 64, 0, 1),
                        dns: [None, None],
                        nbns: [None, None],
                    };
                    s.address_reply(now, session, Some(a), &mut out);
                }
                _ => {}
            }
        }
        now += 50;
        s.handle_timers(now, &mut out);
        out.clear();
        s.check_invariants()?;
    }
    s.handle_timers(now + 600_000, &mut out);
    s.check_invariants()?;
    Ok(s.stats().clone())
}

/// A real client and server talk; `data` drives edits of the frames in
/// flight both ways (which frame, which byte, what value), so every phase
/// of a session meets hostile input. Afterwards: no panic, consistent
/// indexes, and once the edits stop and the network heals everything ends
/// cleanly on PADT.
pub fn conversation(data: &[u8]) -> Result<(), String> {
    use crate::lab::{Lab, LabConfig};
    use crate::lcp::AuthProto;
    let head = data.first().copied().unwrap_or(0);
    let protos = [
        AuthProto::Pap,
        AuthProto::ChapMd5,
        AuthProto::MsChapV1,
        AuthProto::MsChapV2,
    ];
    let mut l = Lab::new(LabConfig {
        clients: 2,
        start_spread_ms: 1,
        ipv6: head & 4 == 4,
        auth_cycle: vec![
            protos
                .get(usize::from(head & 3))
                .copied()
                .unwrap_or(AuthProto::Pap),
        ],
        reconnect: false,
        ..LabConfig::default()
    });
    let edits: Vec<[u8; 4]> = data.get(1..).unwrap_or(&[]).as_chunks::<4>().0.to_vec();
    let mut n = 0usize;
    l.mutate = Some(Box::new(move |_to_server, f: &mut Vec<u8>| {
        n += 1;
        // Edit k applies to frame number e[0] (mod 64): byte e[1], value
        // e[2], kind e[3] (xor, set, cut, grow).
        for &[frame, byte, val, kind] in &edits {
            if usize::from(frame % 64) != n % 64 || f.is_empty() {
                continue;
            }
            let p = usize::from(byte) % f.len();
            match (kind % 4, f.get_mut(p)) {
                (0, Some(b)) => *b ^= val | 1,
                (1, Some(b)) => *b = val,
                (2, _) => f.truncate(p),
                _ => f.extend(std::iter::repeat_n(val, usize::from(val % 32))),
            }
        }
    }));
    l.start_all();
    l.run_until(20_000);
    l.check()?;
    // Edits off, network fine: everything that is up must close cleanly.
    l.mutate = None;
    l.run_until(40_000);
    l.check()?;
    for i in 0..2 {
        l.abort(i);
    }
    l.run_until(100_000);
    if l.server_sessions() != 0 || l.leases() != 0 {
        return Err(format!(
            "left behind: {} sessions, {} leases",
            l.server_sessions(),
            l.leases()
        ));
    }
    l.check()
}

/// Hostile frames at a client in each phase.
pub fn client(data: &[u8]) -> Result<(), String> {
    let mut c = Client::new(
        ClientConfig {
            ipv6: true,
            ..ClientConfig::default()
        },
        [2; 32],
    );
    let mut out = ClientOutput::new();
    c.start(0, &mut out);
    let mut now = 0;
    for f in frames(data) {
        c.handle_frame(now, f, &mut out);
        now += 700;
        c.handle_timers(now, &mut out);
        out.clear();
    }
    Ok(())
}

/// IPv6 from a subscriber (G4.3e): `nd::classify` and `nd::parse_ra` never
/// panic; an RA that parses re-encodes to the same prefixes, MTU, flags and
/// DNS servers.
pub fn nd(data: &[u8]) -> Result<(), String> {
    use crate::nd;
    let _ = nd::classify(data);
    let Ok(ra) = nd::parse_ra(data) else {
        return Ok(());
    };
    let cfg = nd::RaConfig {
        hop_limit: ra.hop_limit,
        managed: ra.managed,
        other: ra.other,
        router_lifetime: ra.router_lifetime,
        mtu: ra.mtu,
        prefixes: ra.prefixes.clone(),
        rdnss: ra.rdnss.clone(),
        dns_lifetime: ra.dns_lifetime.unwrap_or(0),
        ..nd::RaConfig::default()
    };
    ra_round_trip(&cfg, ra.src)
}

/// An RA built from `cfg` reads back as `cfg` (prefixes truncated to their
/// length, preferred ≤ valid, at most `MAX_DNS` of each) and fits 1280.
pub fn ra_round_trip(cfg: &crate::nd::RaConfig, src: std::net::Ipv6Addr) -> Result<(), String> {
    use crate::nd;
    let mut p = Vec::new();
    nd::router_advert(&mut p, src, nd::ALL_NODES, cfg);
    if p.len() > nd::MAX_BUILT {
        return Err(format!("RA of {} bytes", p.len()));
    }
    let back = nd::parse_ra(&p).map_err(|e| format!("own RA refused: {e}"))?;
    let want: Vec<nd::PrefixInfo> = cfg
        .prefixes
        .iter()
        .take(nd::MAX_DNS)
        .map(|x| {
            let len = x.len.min(128);
            let mask = u128::MAX.checked_shl(128 - u32::from(len)).unwrap_or(0);
            nd::PrefixInfo {
                prefix: std::net::Ipv6Addr::from_bits(x.prefix.to_bits() & mask),
                len,
                preferred: x.preferred.min(x.valid),
                ..*x
            }
        })
        .collect();
    let dns: Vec<_> = cfg.rdnss.iter().take(nd::MAX_DNS).copied().collect();
    if back.prefixes != want
        || back.rdnss != dns
        || back.mtu != cfg.mtu
        || (
            back.managed,
            back.other,
            back.router_lifetime,
            back.hop_limit,
        ) != (cfg.managed, cfg.other, cfg.router_lifetime, cfg.hop_limit)
    {
        return Err(format!("RA changed: {cfg:?} → {back:?}"));
    }
    Ok(())
}
