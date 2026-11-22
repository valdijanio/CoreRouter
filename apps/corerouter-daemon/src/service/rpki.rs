//! RPKI (G3.2c): CoreRouter's own RPKI-to-Router client (RFC 8210, falls
//! back to RFC 6810) for every validator of `routing.rpki`, one named
//! thread each. FRR's `bgpd_rpki` keeps its own session to the same
//! validators and is what drops invalid routes; this client gives the
//! router the same VRPs for `routing.rpki.check`, the badges of the BGP
//! route lists and `routing.rpki.session.list`, in the virtual lab too.
//!
//! The protocol is `corerouter_proto_bgp::rtr` (sans-IO); here is the
//! TCP. The VRP table is built on this service's thread from the union of
//! the validators in sync and only the `Arc` is swapped under the session
//! lock. Data older than the expire interval (RFC 8210 §6) is dropped.

use std::collections::BTreeMap;
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use corerouter_engine::lock;
use corerouter_model::rpki::{RpkiCache, RpkiSession, RpkiStatus};
use corerouter_proto_bgp::rpki::{Vrp, VrpTable};
use corerouter_proto_bgp::rtr::{Client, Event, State};

/// How often the config and the workers are looked at.
const TICK: Duration = Duration::from_secs(1);
/// How long a connect may take, and the read slice (to see stop flags).
const CONNECT: Duration = Duration::from_secs(5);
const SLICE: Duration = Duration::from_millis(500);
/// Retry after a failed connect before the cache said its own (RFC 8210 §6
/// default 600 s is long for a first try; rtrlib uses 30 s).
const FIRST_RETRY: Duration = Duration::from_secs(30);
/// How often FRR's own RTR state is read.
const FRR_EVERY: Duration = Duration::from_secs(10);

pub(crate) const SERVICE: super::Service = super::Service {
    name: "rpki",
    flags: &[],
    topic: "route",
    enable: "routing.rpki.add",
    depends: &[],
    start,
};

fn unix_now() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

/// What a worker shares with the service loop.
#[derive(Default)]
struct Link {
    session: RpkiSession,
    /// The VRPs in force (a copy at each End of Data), and a counter of
    /// copies.
    vrps: Option<Arc<Vec<Vrp>>>,
    generation: u64,
}

struct Worker {
    cfg: RpkiCache,
    stop: Arc<AtomicBool>,
    state: Arc<Mutex<Link>>,
}

fn start(ctx: &super::Ctx) -> Result<super::Run, String> {
    let session = ctx.session.clone();
    let frr_dir = ctx.flag("--frr").filter(|d| !d.is_empty()).map(str::to_owned);
    Ok(Box::new(move |health: &super::Health| {
        let mut workers: BTreeMap<String, Worker> = BTreeMap::new();
        let mut seen: BTreeMap<String, u64> = BTreeMap::new();
        let mut frr_line: Option<String> = None;
        let mut frr_at: Option<Instant> = None;
        let frr = frr_dir.as_deref().map(corerouter_hal_frr::Frr::new);
        while health.sleep(TICK) {
                health.beat();
                let wanted: Vec<RpkiCache> = lock(&session)
                    .store()
                    .running()
                    .routing
                    .rpki
                    .values()
                    .filter(|c| !c.disabled)
                    .cloned()
                    .collect();
                // Start, restart (config changed) and stop workers.
                workers.retain(|name, w| {
                    let keep = wanted.iter().any(|c| c.name == *name && *c == w.cfg);
                    if !keep {
                        w.stop.store(true, Ordering::Release);
                    }
                    keep
                });
                for c in &wanted {
                    if workers.contains_key(&c.name) {
                        continue;
                    }
                    let stop = Arc::new(AtomicBool::new(false));
                    let state = Arc::new(Mutex::new(Link::default()));
                    let (cfg, st, sp, h) = (c.clone(), Arc::clone(&state), Arc::clone(&stop), health.clone());
                    match health.spawn(&format!("rtr-{}", c.name.chars().take(10).collect::<String>()), move || {
                        work(&cfg, &st, &sp, &h);
                    }) {
                        Ok(_) => {
                            workers.insert(
                                c.name.clone(),
                                Worker {
                                    cfg: c.clone(),
                                    stop,
                                    state,
                                },
                            );
                        }
                        Err(e) => health.error(format!("cannot start the RTR thread for {}: {e}", c.name)),
                    }
                }
                if wanted.is_empty() {
                    health.disabled(Some("no RPKI validator (routing.rpki.add)"));
                } else {
                    health.disabled(None);
                }
                // The sessions, and a new table when some VRPs changed.
                let mut sessions = Vec::new();
                let mut changed = seen.len() != workers.len();
                let mut sets: Vec<Arc<Vec<Vrp>>> = Vec::new();
                for (name, w) in &workers {
                    let st = w.state.lock().unwrap_or_else(PoisonError::into_inner);
                    sessions.push(st.session.clone());
                    if seen.get(name) != Some(&st.generation) {
                        changed = true;
                    }
                    if let Some(v) = &st.vrps {
                        sets.push(Arc::clone(v));
                    }
                }
                if changed {
                    seen = workers
                        .iter()
                        .map(|(n, w)| (n.clone(), w.state.lock().unwrap_or_else(PoisonError::into_inner).generation))
                        .collect();
                    // Built here, outside the lock: ~0.1 s for a real
                    // table (benches/rpki.rs).
                    let table = (!sets.is_empty()).then(|| Arc::new(VrpTable::build(sets.iter().flat_map(|s| s.iter()))));
                    if let Some(t) = &table {
                        health.event(format!("{} IPv4 and {} IPv6 VRPs in force", t.len_v4(), t.len_v6()));
                    }
                    lock(&session).set_rpki_table(table);
                }
                if let Some(f) = &frr
                    && !wanted.is_empty()
                    && frr_at.is_none_or(|t| t.elapsed() >= FRR_EVERY)
                {
                    frr_line = f.rpki_state();
                    frr_at = Some(Instant::now());
                }
                let status = RpkiStatus {
                    updated: unix_now(),
                    sessions,
                    frr: if wanted.is_empty() { None } else { frr_line.clone() },
                };
                lock(&session).set_rpki_status(status);
        }
        for w in workers.values() {
            w.stop.store(true, Ordering::Release);
        }
        Ok(())
    }))
}

fn publish(state: &Mutex<Link>, f: impl FnOnce(&mut Link)) {
    let mut s = state.lock().unwrap_or_else(PoisonError::into_inner);
    f(&mut s);
}

/// One validator: connect, query, keep in sync, retry; until `stop`.
fn work(cfg: &RpkiCache, state: &Mutex<Link>, stop: &AtomicBool, health: &super::Health) {
    let addr = SocketAddr::new(cfg.address, cfg.port);
    let mut client = Client::new();
    let mut last_sync: Option<Instant> = None;
    let stopped = || stop.load(Ordering::Acquire) || health.stopping();
    let base = RpkiSession {
        name: cfg.name.clone(),
        group: cfg.group.clone(),
        address: cfg.address.to_string(),
        port: cfg.port,
        state: State::Idle.name().into(),
        ..RpkiSession::default()
    };
    publish(state, |s| s.session = base.clone());
    let mut retry = FIRST_RETRY;
    while !stopped() {
        let timers = client.timers();
        let refresh = Duration::from_secs(u64::from(cfg.refresh_interval.unwrap_or(timers.refresh)));
        let expire = Duration::from_secs(u64::from(cfg.expire_interval.unwrap_or(timers.expire)));
        let error = session(cfg, addr, &mut client, state, stop, health, refresh, expire, &mut last_sync).err();
        client.disconnected();
        // RFC 8210 §6: data older than the expire interval is not used.
        if last_sync.is_some_and(|t| t.elapsed() >= expire) {
            client.expire();
            last_sync = None;
            log::warn!("RPKI {}: data expired", cfg.name);
        }
        let held = (!client.vrps().is_empty()).then(|| Arc::new(client.vrps().iter().copied().collect::<Vec<_>>()));
        publish(state, |s| {
            s.session.state = if error.is_some() { "error" } else { State::Idle.name() }.into();
            s.session.error = error.clone();
            if held.is_none() && s.vrps.is_some() {
                s.vrps = None;
                s.generation += 1;
            }
        });
        if let Some(e) = &error {
            log::info!("RPKI {} ({addr}): {e}", cfg.name);
        }
        retry = match &error {
            // Version negotiated down: reconnect at once (RFC 8210 §7).
            Some(e) if e.contains("reconnecting") => Duration::ZERO,
            _ if last_sync.is_some() => Duration::from_secs(u64::from(cfg.retry_interval.unwrap_or(client.timers().retry))),
            _ => cfg.retry_interval.map_or(retry, |r| Duration::from_secs(u64::from(r))),
        };
        let until = Instant::now() + retry;
        while Instant::now() < until && !stopped() {
            std::thread::sleep(SLICE.min(until.saturating_duration_since(Instant::now())));
            if last_sync.is_some_and(|t| t.elapsed() >= expire) {
                break;
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn session(
    cfg: &RpkiCache,
    addr: SocketAddr,
    client: &mut Client,
    state: &Mutex<Link>,
    stop: &AtomicBool,
    health: &super::Health,
    refresh: Duration,
    expire: Duration,
    last_sync: &mut Option<Instant>,
) -> Result<(), String> {
    publish(state, |s| s.session.state = State::Connecting.name().into());
    let mut tcp = TcpStream::connect_timeout(&addr, CONNECT).map_err(|e| format!("cannot connect: {e}"))?;
    tcp.set_read_timeout(Some(SLICE)).map_err(|e| e.to_string())?;
    tcp.set_write_timeout(Some(CONNECT)).map_err(|e| e.to_string())?;
    let _ = tcp.set_nodelay(true);
    tcp.write_all(&client.query()).map_err(|e| format!("write: {e}"))?;
    let mut asked = Instant::now();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        if stop.load(Ordering::Acquire) || health.stopping() {
            return Ok(());
        }
        // §6: poll again after the refresh interval, and give up on data
        // past the expire interval.
        if client.state() == State::Sync && asked.elapsed() >= refresh {
            tcp.write_all(&client.query()).map_err(|e| format!("write: {e}"))?;
            asked = Instant::now();
        }
        if last_sync.is_some_and(|t| t.elapsed() >= expire) {
            return Err("no update within the expire interval".into());
        }
        let n = match tcp.read(&mut buf) {
            Ok(0) => return Err("the validator closed the connection".into()),
            Ok(n) => n,
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => continue,
            Err(e) => return Err(format!("read: {e}")),
        };
        let chunk = buf.get(..n).unwrap_or_default();
        let events = client.feed(chunk);
        let st = client.state();
        publish(state, |s| s.session.state = st.name().into());
        for ev in events {
            match ev {
                Event::Send(bytes) => {
                    tcp.write_all(&bytes).map_err(|e| format!("write: {e}"))?;
                    asked = Instant::now();
                }
                Event::Synced { serial, announced, withdrawn } => {
                    *last_sync = Some(Instant::now());
                    let vrps: Vec<Vrp> = client.vrps().iter().copied().collect();
                    let (v4, v6) = vrps.iter().fold((0u64, 0u64), |(a, b), v| if v.is_v6() { (a, b + 1) } else { (a + 1, b) });
                    let t = client.timers();
                    let now = unix_now();
                    let exp = u64::from(cfg.expire_interval.unwrap_or(t.expire));
                    publish(state, |s| {
                        s.session.state = State::Sync.name().into();
                        s.session.version = Some(client.version());
                        s.session.session_id = client.session();
                        s.session.serial = Some(serial);
                        s.session.ipv4 = v4;
                        s.session.ipv6 = v6;
                        s.session.router_keys = client.router_keys();
                        s.session.last_update = now;
                        s.session.expires = now.map(|n| n.saturating_add(exp));
                        s.session.refresh = cfg.refresh_interval.unwrap_or(t.refresh);
                        s.session.retry = cfg.retry_interval.unwrap_or(t.retry);
                        s.session.expire = cfg.expire_interval.unwrap_or(t.expire);
                        s.session.error = None;
                        if announced + withdrawn > 0 || s.vrps.is_none() {
                            s.vrps = Some(Arc::new(vrps));
                            s.generation += 1;
                        }
                    });
                    log::debug!("RPKI {}: serial {serial}, +{announced} −{withdrawn}", cfg.name);
                }
                Event::Notified => {
                    tcp.write_all(&client.query()).map_err(|e| format!("write: {e}"))?;
                    asked = Instant::now();
                }
                Event::NoData => return Err("the validator has no data yet".into()),
                Event::Close(why) => return Err(why),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;

    use corerouter_proto_bgp::rtr::{Server, pdu_len};

    use super::*;

    fn vrp(s: &str, max: u8, asn: u32) -> Vrp {
        let (a, l) = s.split_once('/').unwrap();
        Vrp::new(a.parse().unwrap(), l.parse().unwrap(), max, asn).unwrap()
    }

    /// A validator on loopback serving `vrps`, one connection.
    fn validator(vrps: Vec<Vrp>) -> SocketAddr {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let at = l.local_addr().unwrap();
        std::thread::spawn(move || {
            let server = Server::new(9, vrps);
            let (mut s, _) = l.accept().unwrap();
            let mut pending = Vec::new();
            let mut b = [0u8; 1024];
            loop {
                let n = match s.read(&mut b) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => n,
                };
                pending.extend_from_slice(&b[..n]);
                while let Ok(Some(len)) = pdu_len(&pending) {
                    if pending.len() < len {
                        break;
                    }
                    let q: Vec<u8> = pending.drain(..len).collect();
                    let a = server.answer(&q).unwrap_or_else(|e| e);
                    s.write_all(&a).unwrap();
                }
            }
        });
        at
    }

    #[test]
    fn a_worker_syncs_with_a_validator_over_tcp() {
        let at = validator(vec![vrp("192.0.2.0/24", 24, 64500), vrp("2001:db8::/32", 48, 64501)]);
        let cfg = RpkiCache {
            name: "t".into(),
            group: "default".into(),
            address: at.ip(),
            port: at.port(),
            refresh_interval: None,
            retry_interval: None,
            expire_interval: None,
            preference: None,
            disabled: false,
            comment: String::new(),
        };
        let state = Arc::new(Mutex::new(Link::default()));
        let stop = Arc::new(AtomicBool::new(false));
        let health = super::super::Health::new(corerouter_control::Shutdown::default());
        let (c, st, sp, h) = (cfg.clone(), Arc::clone(&state), Arc::clone(&stop), health.clone());
        let t = std::thread::spawn(move || work(&c, &st, &sp, &h));
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let s = state.lock().unwrap();
            if s.session.state == "sync" {
                assert_eq!((s.session.ipv4, s.session.ipv6, s.session.version, s.session.serial), (1, 1, Some(1), Some(1)));
                assert_eq!(s.vrps.as_ref().map(|v| v.len()), Some(2));
                break;
            }
            drop(s);
            assert!(Instant::now() < deadline, "no sync");
            std::thread::sleep(Duration::from_millis(20));
        }
        stop.store(true, Ordering::Release);
        t.join().unwrap();
    }
}
