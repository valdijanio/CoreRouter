//! Authoritative zones at run time (G4.1c, `/ip dns zone`): what the
//! forwarder's `zones` stage cannot do from the config alone.
//!
//! - **NOTIFY out** (RFC 1996): when a primary's serial moves, each
//!   address in its `notify` is told over UDP. §3.6: retransmitted until a
//!   reply (5 at most), with a growing interval (2, 4, 8, 16, 32 s: the
//!   RFC suggests 60 s and allows backoff); NOTIMP or another error ends
//!   it (§3.12).
//! - **Secondaries** (RFC 1034 §4.3.5, RFC 1995, RFC 5936): the SOA of
//!   each primary is checked every REFRESH (RETRY after a failure, and at
//!   once on a NOTIFY or `ip.dns.zone.refresh`); a larger serial brings an
//!   IXFR (AXFR when we have no copy, or the IXFR fails) over TCP. A copy
//!   not refreshed for EXPIRE stops answering (SERVFAIL); a failed
//!   transfer keeps the old copy (RFC 5936 §6). Timers come from the
//!   loaded SOA, clamped like BIND (refresh 300 s..4 weeks, retry 60 s..2
//!   weeks).
//! - **DNSSEC** (G4.1c-2): every second the engine's key life cycle runs
//!   (`Session::dnssec_tick`, with ring generating the keys here); a
//!   signed zone is re-signed in a thread of its own when its data or keys
//!   change and when half of the signature validity is gone, with a
//!   serial larger than the last signed one (the secondaries must fetch
//!   the new signatures), and the signed version is what the zone serves,
//!   transfers and NOTIFYs. A transferred signed zone gets its signatures
//!   indexed, so a secondary answers DO queries with them too.
//! - The engine sees all this through [`ZoneBackend`] (status, a
//!   secondary's zone file, refresh now).
//!
//! The transfers serve themselves from the DNS server's sockets
//! (`dns_server.rs` hands AXFR/IXFR/NOTIFY to `zone::xfr::intercept`).

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use corerouter_control::Shutdown;
use corerouter_engine::dns_zone::ZoneBackend;
use corerouter_engine::dnssec::NewKey;
use corerouter_model::dnssec::{DnssecAlgorithm, DnssecKey, KeyRole, KeyState};
use corerouter_engine::{Shared, lock};
use corerouter_model::dns_zone::{ZoneStatus, ZoneType, serial_gt};
use corerouter_proto_dns::zone::xfr::{self, Ack, Transfer};
use corerouter_proto_dns::zone::{self, Changed, ZoneConf, ZoneData};

use super::dns_server::Server;

/// RFC 1035 §4.2.1.
const DNS_PORT: u16 = 53;
const TICK: Duration = Duration::from_secs(1);
/// How long a primary has to answer the SOA check.
const SOA_WAIT: Duration = Duration::from_secs(3);
const CONNECT_WAIT: Duration = Duration::from_secs(5);
/// Silence on a transfer connection before giving up.
const XFR_IDLE: Duration = Duration::from_secs(15);
/// RFC 1996 §3.6: at most 5 retransmissions.
const NOTIFY_TRIES: u32 = 6;
const NOTIFY_FIRST_WAIT: Duration = Duration::from_secs(2);
/// BIND's clamps on the SOA timers of a secondary.
const MIN_REFRESH_SECS: u32 = 300;
const MAX_REFRESH_SECS: u32 = 2_419_200;
const MIN_RETRY_SECS: u32 = 60;
const MAX_RETRY_SECS: u32 = 1_209_600;

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// One secondary's schedule.
#[derive(Debug, Clone)]
struct Sec {
    next: Instant,
    /// The last successful check of a primary.
    ok_at: Option<Instant>,
    ok_unix: Option<u64>,
    error: String,
    busy: bool,
}

impl Sec {
    fn new(now: Instant) -> Self {
        Self {
            next: now,
            ok_at: None,
            ok_unix: None,
            error: String::new(),
            busy: false,
        }
    }
}

/// What a signed version was made from: a new one is due when this
/// changes.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SignInput {
    serial: u32,
    keys: Vec<(u32, KeyState)>,
    validity: u32,
}

/// One zone's signing.
#[derive(Debug, Default)]
struct SignJob {
    busy: bool,
    done: Option<SignInput>,
    /// After a failure, wait before trying again.
    retry_at: Option<Instant>,
    error: String,
}

/// The zone service: shared by its thread, its workers and the engine.
pub(crate) struct Zones {
    session: Shared,
    srv: Arc<Server>,
    /// Port of the primaries and NOTIFY targets (53; tests use their own).
    port: u16,
    secs: Mutex<HashMap<String, Sec>>,
    /// The last NOTIFY failure per primary zone.
    notify_errors: Mutex<HashMap<String, String>>,
    /// Zones with a NOTIFY sender running, and the change to send next.
    notifying: Mutex<HashMap<String, Option<Changed>>>,
    signing: Mutex<HashMap<String, SignJob>>,
    shutdown: Shutdown,
}

/// SOA refresh/retry/expire of a loaded copy, clamped, or the zone's own
/// config before the first transfer.
fn timers(data: Option<&ZoneData>, conf: &ZoneConf) -> (u32, u32, u32) {
    let (r, y, e) = data.map_or(
        (conf.refresh_secs, conf.retry_secs, conf.expire_secs),
        ZoneData::timers,
    );
    (
        r.clamp(MIN_REFRESH_SECS, MAX_REFRESH_SECS),
        y.clamp(MIN_RETRY_SECS, MAX_RETRY_SECS),
        e,
    )
}

fn bind_for(ip: IpAddr) -> std::io::Result<UdpSocket> {
    let any: IpAddr = if ip.is_ipv4() {
        Ipv4Addr::UNSPECIFIED.into()
    } else {
        Ipv6Addr::UNSPECIFIED.into()
    };
    UdpSocket::bind(SocketAddr::new(any, 0))
}

/// One framed TCP message (RFC 1035 §4.2.2).
fn read_framed(s: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut head = [0u8; 2];
    s.read_exact(&mut head)?;
    let mut msg = vec![0u8; usize::from(u16::from_be_bytes(head))];
    s.read_exact(&mut msg)?;
    Ok(msg)
}

fn write_framed(s: &mut TcpStream, msg: &[u8]) -> std::io::Result<()> {
    let len = u16::try_from(msg.len())
        .map_err(|_| std::io::Error::other("a message over 64 KiB"))?;
    let mut framed = len.to_be_bytes().to_vec();
    framed.extend_from_slice(msg);
    s.write_all(&framed)
}

impl Zones {
    pub(crate) fn new(session: Shared, srv: Arc<Server>, port: u16, shutdown: Shutdown) -> Arc<Self> {
        Arc::new(Self {
            session,
            srv,
            port,
            secs: Mutex::new(HashMap::new()),
            notify_errors: Mutex::new(HashMap::new()),
            notifying: Mutex::new(HashMap::new()),
            signing: Mutex::new(HashMap::new()),
            shutdown,
        })
    }

    fn fwd(&self) -> &corerouter_proto_dns::server::Forwarder {
        self.srv.forwarder()
    }

    /// One second's work: NOTIFY for changed primaries, secondaries due.
    pub(crate) fn tick(self: &Arc<Self>) {
        self.dynamic();
        for c in zone::reload(self.fwd()) {
            if c.notify.is_empty() {
                continue;
            }
            // One sender per zone: a change while it runs waits for it (a
            // script of 1000 commands is one NOTIFY round, not 1000).
            {
                let mut busy = self.notifying.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(pending) = busy.get_mut(&c.zone) {
                    *pending = Some(c);
                    continue;
                }
                busy.insert(c.zone.clone(), None);
            }
            let me = self.clone();
            let zone = c.zone.clone();
            let spawned = thread::Builder::new()
                .name("dns-notify".into())
                .spawn(move || me.notify_loop(c));
            if let Err(e) = spawned {
                log::warn!("DNS: no thread for NOTIFY: {e}");
                self.notifying
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&zone);
            }
        }
        let cfg = self.fwd().config();
        let zones = zone::zones(self.fwd(), &cfg);
        self.dnssec(&zones);
        let secondaries: HashMap<&String, &ZoneConf> = zones
            .conf
            .iter()
            .filter(|(_, c)| c.ztype == ZoneType::Secondary)
            .collect();
        let now = Instant::now();
        let notified = zone::take_notified(self.fwd());
        let mut due = Vec::new();
        {
            let mut secs = self.secs.lock().unwrap_or_else(|e| e.into_inner());
            secs.retain(|name, _| {
                let keep = secondaries.contains_key(name);
                if !keep {
                    zone::drop_secondary(self.fwd(), name);
                }
                keep
            });
            for (name, conf) in &secondaries {
                let sec = secs
                    .entry((*name).clone())
                    .or_insert_with(|| Sec::new(now));
                if notified.contains(*name) {
                    sec.next = now;
                }
                let data = zone::secondary(self.fwd(), name);
                let (_, _, expire) = timers(data.as_deref(), conf);
                // RFC 1034 §4.3.5: past EXPIRE without a refresh, the copy
                // is no longer authoritative.
                if data.is_some()
                    && sec
                        .ok_at
                        .is_some_and(|t| now.duration_since(t) > Duration::from_secs(u64::from(expire)))
                {
                    zone::drop_secondary(self.fwd(), name);
                    sec.error = "expired: no primary answered for expire_secs".into();
                    log::warn!("DNS: zone {name} expired");
                }
                if !sec.busy && now >= sec.next {
                    sec.busy = true;
                    due.push((*conf).clone());
                }
            }
        }
        for conf in due {
            let me = self.clone();
            let name = conf.name.clone();
            let spawned = thread::Builder::new()
                .name("dns-xfr".into())
                .spawn(move || me.refresh(&conf));
            if let Err(e) = spawned {
                log::warn!("DNS: no thread for a zone transfer: {e}");
                if let Some(s) = self
                    .secs
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .get_mut(&name)
                {
                    s.busy = false;
                }
            }
        }
    }

    /// Dynamic records (G4.1c-3): expired ones go, and the forwarder gets
    /// the engine's copy when it moved.
    fn dynamic(&self) {
        let now = unix_now();
        let copy = {
            let mut s = lock(&self.session);
            match s.dns_dynamic_tick(now) {
                Ok(0) => {}
                Ok(n) => log::info!("DNS: {n} dynamic records expired"),
                Err(e) => log::error!("DNS: dynamic records: {e}"),
            }
            (s.dns_dynamic_version() != zone::dynamic_version(self.fwd())).then(|| s.dns_dynamic())
        };
        if let Some((version, state)) = copy {
            zone::set_dynamic(self.fwd(), version, Arc::new(state));
        }
    }

    /// RFC 2136 UPDATE (G4.1c-3): checked by `zone::update`, applied in
    /// the engine (saved before the answer, §3.5), then answered.
    fn update(&self, packet: &[u8], client: IpAddr) -> Option<Vec<u8>> {
        let now = unix_now();
        let u = match zone::update::read(self.fwd(), packet, client, now) {
            Ok(u) => u,
            Err(reply) => return Some(reply),
        };
        let source = match &u.key {
            Some(k) => format!("update {} key {k}", u.client),
            None => format!("update {}", u.client),
        };
        let applied = lock(&self.session).dns_dynamic_apply(&u.zone, &u.ops, &source, None, now);
        let ok = match applied {
            Ok(n) => {
                if n > 0 {
                    log::info!("DNS: zone {}: {n} records changed by {source}", u.zone);
                }
                self.dynamic();
                true
            }
            Err(e) => {
                // §3.4.2.7: nothing applied, SERVFAIL.
                log::warn!("DNS: zone {}: update by {source} failed: {e}", u.zone);
                false
            }
        };
        Some(zone::update::finish(&u, ok, now))
    }

    /// The key life cycle, then a signing thread for each signed zone due.
    fn dnssec(self: &Arc<Self>, zones: &zone::Zones) {
        let now = unix_now();
        let state = {
            let mut s = lock(&self.session);
            let mut generate = |zone: &str, alg: DnssecAlgorithm, role: KeyRole| {
                zone::dnssec::generate(zone, alg, role).map(|g| NewKey {
                    private_key: g.private_key,
                    dnskey: g.dnskey,
                    ds: g.ds,
                    key_tag: g.key_tag,
                })
            };
            if let Err(e) = s.dnssec_tick(now, &mut generate) {
                log::error!("DNSSEC keys: {e}");
            }
            s.dnssec_state()
        };
        let mut jobs = self.signing.lock().unwrap_or_else(|e| e.into_inner());
        for (name, conf) in &zones.conf {
            if conf.ztype != ZoneType::Primary {
                continue;
            }
            if !conf.dnssec {
                zone::drop_signed(self.fwd(), name);
                jobs.remove(name);
                continue;
            }
            let Some(unsigned) = zones.primaries.get(name).cloned() else {
                continue;
            };
            let keys: Vec<DnssecKey> = state.keys_of(name).cloned().collect();
            if !keys.iter().any(|k| k.state == KeyState::Active) {
                continue;
            }
            let input = SignInput {
                serial: unsigned.serial,
                keys: keys.iter().map(|k| (k.id, k.state)).collect(),
                validity: conf.signature_validity_secs,
            };
            // Half of the validity gone: new signatures (Knot and BIND
            // refresh well before expiry, RFC 6781 §4.4.2).
            let expiring = zone::signed(self.fwd(), name)
                .and_then(|z| z.dnssec.as_ref().map(|d| u64::from(d.expires)))
                .is_none_or(|exp| exp < now + u64::from(conf.signature_validity_secs) / 2);
            let job = jobs.entry(name.clone()).or_default();
            if job.busy
                || job.retry_at.is_some_and(|t| Instant::now() < t)
                || (job.done.as_ref() == Some(&input) && !expiring)
            {
                continue;
            }
            job.busy = true;
            let last = state.signed_serial.get(name).copied();
            // Larger than the last signed serial, and than the config's.
            let serial = match last {
                Some(l) if !serial_gt(unsigned.serial, l) => l.wrapping_add(1),
                _ => unsigned.serial,
            };
            let me = self.clone();
            let name = name.clone();
            let thread_name = name.clone();
            let spawned = thread::Builder::new().name("dns-sign".into()).spawn(move || {
                me.sign(&name, &unsigned, &keys, serial, input);
            });
            if let Err(e) = spawned {
                log::warn!("DNSSEC: no thread to sign {thread_name}: {e}");
                job.busy = false;
            }
        }
    }

    fn sign(&self, name: &str, unsigned: &ZoneData, keys: &[DnssecKey], serial: u32, input: SignInput) {
        let now = u32::try_from(unix_now()).unwrap_or(u32::MAX);
        let started = Instant::now();
        let result = zone::dnssec::sign(unsigned, keys, serial, now, input.validity);
        let mut jobs = self.signing.lock().unwrap_or_else(|e| e.into_inner());
        let job = jobs.entry(name.to_owned()).or_default();
        job.busy = false;
        match result {
            Ok(signed) => {
                log::info!(
                    "DNSSEC: zone {name} signed, serial {serial}, {} records, {} ms",
                    signed.len(),
                    started.elapsed().as_millis()
                );
                zone::set_signed(self.fwd(), name, signed);
                job.done = Some(input);
                job.retry_at = None;
                job.error.clear();
                drop(jobs);
                if let Err(e) = lock(&self.session).dnssec_signed(name, serial) {
                    log::error!("DNSSEC: zone {name}: {e}");
                }
            }
            Err(e) => {
                log::error!("DNSSEC: zone {name} not signed: {e}");
                job.error = format!("not signed: {e}");
                job.retry_at = Some(Instant::now() + Duration::from_secs(60));
            }
        }
    }

    /// NOTIFY for `c`, then for the latest change that came meanwhile.
    fn notify_loop(&self, mut c: Changed) {
        loop {
            self.notify(&c);
            let mut busy = self.notifying.lock().unwrap_or_else(|e| e.into_inner());
            match busy.get_mut(&c.zone).and_then(Option::take) {
                Some(next) => c = next,
                None => {
                    busy.remove(&c.zone);
                    return;
                }
            }
        }
    }

    /// RFC 1996 §3.6: to every target, until each answers or gives up.
    fn notify(&self, c: &Changed) {
        let mut errors = Vec::new();
        for ip in &c.notify {
            if let Err(e) = self.notify_one(c, *ip) {
                log::warn!("DNS: NOTIFY {} to {ip}: {e}", c.zone);
                errors.push(format!("NOTIFY to {ip}: {e}"));
            }
        }
        let mut map = self.notify_errors.lock().unwrap_or_else(|e| e.into_inner());
        if errors.is_empty() {
            map.remove(&c.zone);
        } else {
            map.insert(c.zone.clone(), errors.join("; "));
        }
    }

    fn notify_one(&self, c: &Changed, ip: IpAddr) -> Result<(), String> {
        let (id, msg) = xfr::notify_message(c)?;
        let sock = bind_for(ip).map_err(|e| e.to_string())?;
        let to = SocketAddr::new(ip, self.port);
        let mut wait = NOTIFY_FIRST_WAIT;
        let mut buf = [0u8; 4096];
        for _ in 0..NOTIFY_TRIES {
            if self.shutdown.is_closed() {
                return Ok(());
            }
            sock.send_to(&msg, to).map_err(|e| e.to_string())?;
            let deadline = Instant::now() + wait;
            while let Some(left) = deadline.checked_duration_since(Instant::now()) {
                if left.is_zero() {
                    break;
                }
                sock.set_read_timeout(Some(left)).map_err(|e| e.to_string())?;
                match sock.recv_from(&mut buf) {
                    Ok((n, from)) if from.ip().to_canonical() == ip.to_canonical() => {
                        match xfr::notify_ack(buf.get(..n).unwrap_or_default(), id) {
                            Ack::Yes => return Ok(()),
                            Ack::No(why) => return Err(why),
                            Ack::Other => {}
                        }
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
            wait = wait.saturating_mul(2);
        }
        Err("no answer".into())
    }

    /// Checks the primaries in order; the first that answers decides.
    fn refresh(&self, conf: &ZoneConf) {
        let have = zone::secondary(self.fwd(), &conf.name);
        let mut errors = Vec::new();
        let mut done = false;
        for ip in &conf.primaries {
            match self.refresh_from(conf, *ip, have.as_deref()) {
                Ok(()) => {
                    done = true;
                    break;
                }
                Err(e) => errors.push(format!("{ip}: {e}")),
            }
        }
        let data = zone::secondary(self.fwd(), &conf.name);
        let (refresh, retry, _) = timers(data.as_deref(), conf);
        let now = Instant::now();
        let mut secs = self.secs.lock().unwrap_or_else(|e| e.into_inner());
        let Some(s) = secs.get_mut(&conf.name) else {
            return;
        };
        s.busy = false;
        if done {
            s.ok_at = Some(now);
            s.ok_unix = Some(unix_now());
            s.error.clear();
            s.next = now + Duration::from_secs(u64::from(refresh));
        } else {
            s.error = errors.join("; ");
            s.error.truncate(400);
            s.next = now + Duration::from_secs(u64::from(retry));
            log::warn!("DNS: zone {} not refreshed: {}", conf.name, s.error);
        }
    }

    fn refresh_from(&self, conf: &ZoneConf, ip: IpAddr, have: Option<&ZoneData>) -> Result<(), String> {
        let theirs = self.soa_serial(&conf.name, ip)?;
        if have.is_some_and(|h| !serial_gt(theirs, h.serial)) {
            return Ok(());
        }
        let got = match self.transfer(&conf.name, ip, have) {
            // RFC 1995 §4: a server without IXFR may refuse it: AXFR.
            Err(e) if have.is_some() => {
                log::info!("DNS: IXFR of {} from {ip} failed ({e}); trying AXFR", conf.name);
                self.transfer(&conf.name, ip, None)?
            }
            other => other?,
        };
        if let Some(data) = got {
            // A signed zone: its RRSIG/NSEC3 go to the lookup tables.
            let data = zone::dnssec::index(data)?;
            log::info!(
                "DNS: zone {} transferred from {ip}: serial {}, {} records",
                conf.name,
                data.serial,
                data.len()
            );
            zone::set_secondary(self.fwd(), &conf.name, data);
        }
        Ok(())
    }

    /// The primary's serial: UDP, TCP when truncated.
    fn soa_serial(&self, zone: &str, ip: IpAddr) -> Result<u32, String> {
        let (id, q) = xfr::soa_query(zone)?;
        let to = SocketAddr::new(ip, self.port);
        let sock = bind_for(ip).map_err(|e| e.to_string())?;
        sock.set_read_timeout(Some(SOA_WAIT))
            .map_err(|e| e.to_string())?;
        sock.send_to(&q, to).map_err(|e| e.to_string())?;
        let mut buf = vec![0u8; 4096];
        let deadline = Instant::now() + SOA_WAIT;
        loop {
            if Instant::now() >= deadline {
                return Err("no answer to the SOA query".into());
            }
            let Ok((n, from)) = sock.recv_from(&mut buf) else {
                return Err("no answer to the SOA query".into());
            };
            if from.ip().to_canonical() != ip.to_canonical() {
                continue;
            }
            match xfr::soa_serial(buf.get(..n).unwrap_or_default(), id, zone) {
                Ok(Some(s)) => return Ok(s),
                Ok(None) => break,
                Err(e) if e.contains("not ours") => {}
                Err(e) => return Err(e),
            }
        }
        // Truncated: again over TCP.
        let mut s = TcpStream::connect_timeout(&to, CONNECT_WAIT).map_err(|e| e.to_string())?;
        s.set_read_timeout(Some(SOA_WAIT)).map_err(|e| e.to_string())?;
        write_framed(&mut s, &q).map_err(|e| e.to_string())?;
        let reply = read_framed(&mut s).map_err(|e| e.to_string())?;
        xfr::soa_serial(&reply, id, zone)?.ok_or_else(|| "truncated over TCP".into())
    }

    /// IXFR from `have`'s serial (AXFR without a copy), over TCP.
    fn transfer(&self, zone: &str, ip: IpAddr, have: Option<&ZoneData>) -> Result<Option<ZoneData>, String> {
        let (id, q) = xfr::xfr_query(zone, have)?;
        let to = SocketAddr::new(ip, self.port);
        let mut s = TcpStream::connect_timeout(&to, CONNECT_WAIT).map_err(|e| e.to_string())?;
        s.set_read_timeout(Some(XFR_IDLE)).map_err(|e| e.to_string())?;
        s.set_write_timeout(Some(XFR_IDLE)).map_err(|e| e.to_string())?;
        write_framed(&mut s, &q).map_err(|e| e.to_string())?;
        let mut t = Transfer::new(id, zone, have.is_some());
        loop {
            if self.shutdown.is_closed() {
                return Err("closing".into());
            }
            let msg = read_framed(&mut s).map_err(|e| format!("transfer cut: {e}"))?;
            if t.push(&msg)? {
                break;
            }
        }
        t.finish(have)
    }

    /// What `ip.dns.zone.print` shows.
    fn status(&self) -> Vec<ZoneStatus> {
        let cfg = self.fwd().config();
        let zones = zone::zones(self.fwd(), &cfg);
        let secs = self.secs.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let notify = self
            .notify_errors
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let signing: HashMap<String, String> = self
            .signing
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .map(|(k, j)| (k.clone(), j.error.clone()))
            .collect();
        let now = Instant::now();
        let unix = unix_now();
        let mut out: Vec<ZoneStatus> = zones
            .conf
            .values()
            .map(|c| {
                let data = match c.ztype {
                    ZoneType::Primary if c.dnssec => zone::signed(self.fwd(), &c.name)
                        .or_else(|| zones.primaries.get(&c.name).cloned()),
                    ZoneType::Primary => zones.primaries.get(&c.name).cloned(),
                    ZoneType::Secondary => zone::secondary(self.fwd(), &c.name),
                };
                let sec = secs.get(&c.name);
                let sign_error = signing.get(&c.name).cloned().unwrap_or_default();
                let error = match c.ztype {
                    ZoneType::Primary => [notify.get(&c.name).cloned().unwrap_or_default(), sign_error]
                        .into_iter()
                        .filter(|e| !e.is_empty())
                        .collect::<Vec<_>>()
                        .join("; "),
                    ZoneType::Secondary => sec.map(|s| s.error.clone()).unwrap_or_default(),
                };
                let signed = data.as_ref().and_then(|d| d.dnssec.as_ref().map(|s| s.expires));
                ZoneStatus {
                    zone: c.name.clone(),
                    loaded_serial: data.as_ref().map(|d| d.serial),
                    records: data.as_ref().map(|d| d.len()),
                    refreshed_unix: sec.and_then(|s| s.ok_unix),
                    next_refresh_unix: sec.map(|s| {
                        unix + s.next.saturating_duration_since(now).as_secs()
                    }),
                    error,
                    signed_serial: signed.and(data.as_ref().map(|d| d.serial)).filter(|_| c.dnssec),
                    signatures_expire_unix: signed.map(u64::from),
                    signed: signed.is_some() && c.ztype == ZoneType::Secondary,
                }
            })
            .collect();
        out.sort_by(|a, b| a.zone.cmp(&b.zone));
        out
    }

    fn wake(&self, name: &str) -> Result<(), String> {
        let cfg = self.fwd().config();
        let zones = zone::zones(self.fwd(), &cfg);
        if !zones
            .conf
            .get(name)
            .is_some_and(|c| c.ztype == ZoneType::Secondary)
        {
            return Err(format!("{name} is not a running secondary zone (committed and enabled)"));
        }
        zone::mark_notified(self.fwd(), name);
        Ok(())
    }

    /// The service thread: a tick a second until the daemon closes.
    /// The service loop: a tick a second until stopped.
    pub(crate) fn run(self: &Arc<Self>, health: &super::Health) {
        while health.sleep(TICK) {
            health.beat();
            let none = self.fwd().config().config.ip.dns_zones.zones.is_empty();
            health.disabled(none.then_some("no zone (ip.dns.zone.add)"));
            self.tick();
        }
    }
}

struct Backend(Arc<Zones>);

impl ZoneBackend for Backend {
    fn status(&self) -> Vec<ZoneStatus> {
        self.0.status()
    }

    fn file(&self, zone: &str) -> Option<String> {
        zone::secondary(self.0.fwd(), zone).map(|d| d.to_file())
    }

    fn refresh(&self, zone: &str) -> Result<(), String> {
        self.0.wake(zone)
    }
}

/// Starts the service on `srv` and registers it with the engine.
/// The service and its backend, registered with the engine.
fn prepare(session: &Shared, srv: Arc<Server>, port: u16, shutdown: Shutdown) -> Arc<Zones> {
    let z = Zones::new(session.clone(), srv, port, shutdown);
    let weak = Arc::downgrade(&z);
    zone::set_updater(
        z.fwd(),
        Arc::new(move |packet: &[u8], client: IpAddr| weak.upgrade()?.update(packet, client)),
    );
    z.dynamic();
    lock(session).set_zone_backend(Arc::new(Backend(z.clone())));
    z
}

/// Starts the service outside the supervisor (tests).
#[cfg(test)]
pub(crate) fn spawn(session: &Shared, srv: Arc<Server>, port: u16, shutdown: Shutdown) -> std::io::Result<Arc<Zones>> {
    let z = prepare(session, srv, port, shutdown.clone());
    let me = z.clone();
    let health = super::Health::new(shutdown);
    thread::Builder::new()
        .name("dns-zones".into())
        .spawn(move || me.run(&health))?;
    Ok(z)
}

pub(crate) const SERVICE: super::Service = super::Service {
    name: "dns-zones",
    flags: &[],
    topic: "dns",
    enable: "ip.dns.zone.add name=…",
    depends: &["dns-server"],
    start,
};

/// One zone service for the daemon's life (a restart keeps the
/// secondaries' copies and the journal, which live in the forwarder).
fn start(ctx: &super::Ctx) -> Result<super::Run, String> {
    let session = ctx.session.clone();
    let shutdown = ctx.shutdown.clone();
    let zones: Arc<OnceLock<Arc<Zones>>> = Arc::new(OnceLock::new());
    Ok(Box::new(move |health: &super::Health| {
        let z = match zones.get() {
            Some(z) => z.clone(),
            None => {
                let srv = super::dns_server::server().ok_or("the DNS server is not running")?;
                zones
                    .get_or_init(|| prepare(&session, srv, DNS_PORT, shutdown.clone()))
                    .clone()
            }
        };
        z.run(health);
        Ok(())
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_engine::{Session, shared};
    use hickory_proto::op::{Message, Query};
    use hickory_proto::rr::{Name, RecordType};
    use serde_json::{Value, json};

    use super::super::dns::RouterDns;

    fn free_port() -> u16 {
        let u = UdpSocket::bind("127.0.0.1:0").unwrap();
        let p = u.local_addr().unwrap().port();
        let t = std::net::TcpListener::bind(("127.0.0.1", p));
        drop(u);
        if t.is_err() { free_port() } else { p }
    }

    fn ask(port: u16, name: &str) -> Option<Message> {
        let mut m = Message::query();
        m.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        s.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
        s.send_to(&m.to_vec().unwrap(), ("127.0.0.1", port)).unwrap();
        let mut buf = [0u8; 4096];
        let (n, _) = s.recv_from(&mut buf).ok()?;
        Message::from_vec(&buf[..n]).ok()
    }

    fn wait(what: &str, mut ok: impl FnMut() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(20);
        while !ok() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            thread::sleep(Duration::from_millis(100));
        }
    }

    fn run(s: &Shared, id: &str, p: Value) -> Value {
        lock(s).execute(id, &p).unwrap()
    }

    fn answer(port: u16, name: &str) -> Option<String> {
        let m = ask(port, name)?;
        if !m.metadata.authoritative {
            return None;
        }
        m.answers.first().map(|r| r.data.to_string())
    }

    /// A primary and a secondary daemon on loopback: the secondary loads
    /// the zone by AXFR, a change reaches it by NOTIFY + IXFR, and the
    /// engine sees the state.
    #[test]
    fn a_secondary_follows_its_primary() {
        let (pp, sp) = (free_port(), free_port());
        let shutdown = Shutdown::default();

        let primary = shared(Session::virtual_lab());
        run(&primary, "ip.dns.set", json!({"allow_remote_requests": true}));
        run(
            &primary,
            "ip.dns.zone.add",
            json!({"name": "example.com", "allow_transfer": "127.0.0.0/8", "notify": "127.0.0.1"}),
        );
        let www = run(
            &primary,
            "ip.dns.zone.record.add",
            json!({"zone": "example.com", "name": "www", "address": "192.0.2.80"}),
        );
        let p_srv = super::super::dns_server::spawn(
            primary.clone(),
            Arc::new(RouterDns::new()),
            pp,
            shutdown.clone(),
        )
        .unwrap();
        spawn(&primary, p_srv, sp, shutdown.clone()).unwrap();

        let secondary = shared(Session::virtual_lab());
        run(&secondary, "ip.dns.set", json!({"allow_remote_requests": true}));
        run(
            &secondary,
            "ip.dns.zone.add",
            json!({"name": "example.com", "type": "secondary", "primaries": "127.0.0.1"}),
        );
        let s_srv = super::super::dns_server::spawn(
            secondary.clone(),
            Arc::new(RouterDns::new()),
            sp,
            shutdown.clone(),
        )
        .unwrap();
        spawn(&secondary, s_srv, pp, shutdown.clone()).unwrap();

        wait("the primary to answer", || answer(pp, "www.example.com.").is_some());
        wait("the first transfer", || {
            answer(sp, "www.example.com.").as_deref() == Some("192.0.2.80")
        });
        let rows = run(&secondary, "ip.dns.zone.print", json!({}));
        assert_eq!(rows[0]["status"], "loaded", "{rows}");
        assert_eq!(rows[0]["records"], 2, "{rows}");
        let file = run(&secondary, "ip.dns.zone.file.get", json!({"zone": "example.com"}));
        assert!(file["text"].as_str().unwrap().contains("www 3600 IN A 192.0.2.80"));

        // A change on the primary: NOTIFY, then IXFR.
        run(
            &primary,
            "ip.dns.zone.record.set",
            json!({"id": www["id"], "address": "192.0.2.81"}),
        );
        wait("NOTIFY + IXFR", || {
            answer(sp, "www.example.com.").as_deref() == Some("192.0.2.81")
        });
        let p_rows = run(&primary, "ip.dns.zone.print", json!({}));
        let s_rows = run(&secondary, "ip.dns.zone.print", json!({}));
        assert_eq!(p_rows[0]["status"], "running");
        assert_eq!(s_rows[0]["loaded_serial"], p_rows[0]["serial"]);
        assert!(s_rows[0].get("error").is_none(), "{s_rows}");
        // ip.dns.zone.refresh asks again (nothing new: still loaded).
        run(&secondary, "ip.dns.zone.refresh", json!({"zone": "example.com"}));
        // Leaving the config: the copy stops answering.
        run(&secondary, "ip.dns.zone.remove", json!({"id": "example.com"}));
        wait("the copy to go", || answer(sp, "www.example.com.").is_none());
        shutdown.close();
    }

    fn ask_do(port: u16, name: &str, t: RecordType) -> Option<Message> {
        let mut m = Message::query();
        m.add_query(Query::query(Name::from_ascii(name).unwrap(), t));
        let mut e = hickory_proto::op::Edns::new();
        e.set_dnssec_ok(true);
        e.set_max_payload(4096);
        m.set_edns(e);
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        s.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
        s.send_to(&m.to_vec().unwrap(), ("127.0.0.1", port)).unwrap();
        let mut buf = [0u8; 4096];
        let (n, _) = s.recv_from(&mut buf).ok()?;
        Message::from_vec(&buf[..n]).ok()
    }

    fn rrsigs(m: &Message) -> usize {
        m.answers
            .iter()
            .filter(|r| r.record_type() == RecordType::RRSIG)
            .count()
    }

    /// G4.1c-2: `dnssec=yes` makes keys (in the engine's state, not the
    /// config), signs, serves RRSIGs to DO queries only, re-signs on a
    /// change with a new serial, and a secondary serves the signatures it
    /// transferred.
    #[test]
    fn a_signed_zone_and_its_secondary() {
        let (pp, sp) = (free_port(), free_port());
        let shutdown = Shutdown::default();
        let primary = shared(Session::virtual_lab());
        run(&primary, "ip.dns.set", json!({"allow_remote_requests": true}));
        run(
            &primary,
            "ip.dns.zone.add",
            json!({"name": "example.com", "allow_transfer": "127.0.0.0/8", "notify": "127.0.0.1", "dnssec": true}),
        );
        let www = run(
            &primary,
            "ip.dns.zone.record.add",
            json!({"zone": "example.com", "name": "www", "address": "192.0.2.80"}),
        );
        let p_srv = super::super::dns_server::spawn(
            primary.clone(),
            Arc::new(RouterDns::new()),
            pp,
            shutdown.clone(),
        )
        .unwrap();
        spawn(&primary, p_srv, sp, shutdown.clone()).unwrap();
        wait("the signed zone", || {
            ask_do(pp, "www.example.com.", RecordType::A).is_some_and(|m| rrsigs(&m) == 1)
        });
        let keys = run(&primary, "ip.dns.zone.dnssec.print", json!({"zone": "example.com"}));
        assert_eq!(keys.as_array().unwrap().len(), 2, "{keys}");
        assert!(!keys.to_string().contains("private"), "{keys}");
        let zone = run(&primary, "ip.dns.zone.print", json!({}));
        assert!(zone[0]["ds"][0].as_str().unwrap().contains(" 13 2 "), "{zone}");
        let signed = zone[0]["signed_serial"].as_u64().unwrap();
        // Without DO: no RRSIG (RFC 4035 §3.1).
        let m = ask(pp, "www.example.com.").unwrap();
        assert!(m.answers.iter().all(|r| r.record_type() == RecordType::A));
        // A change: re-signed with a larger serial.
        run(
            &primary,
            "ip.dns.zone.record.set",
            json!({"id": www["id"], "address": "192.0.2.81"}),
        );
        wait("the re-signing", || {
            ask_do(pp, "www.example.com.", RecordType::A).is_some_and(|m| {
                rrsigs(&m) == 1 && m.answers.iter().any(|r| r.data.to_string() == "192.0.2.81")
            })
        });
        let again = run(&primary, "ip.dns.zone.print", json!({}))[0]["signed_serial"]
            .as_u64()
            .unwrap();
        assert!(again > signed);

        let secondary = shared(Session::virtual_lab());
        run(&secondary, "ip.dns.set", json!({"allow_remote_requests": true}));
        run(
            &secondary,
            "ip.dns.zone.add",
            json!({"name": "example.com", "type": "secondary", "primaries": "127.0.0.1"}),
        );
        let s_srv = super::super::dns_server::spawn(
            secondary.clone(),
            Arc::new(RouterDns::new()),
            sp,
            shutdown.clone(),
        )
        .unwrap();
        spawn(&secondary, s_srv, pp, shutdown.clone()).unwrap();
        wait("the secondary with signatures", || {
            ask_do(sp, "www.example.com.", RecordType::A).is_some_and(|m| rrsigs(&m) == 1)
        });
        // The same NXDOMAIN proof as the primary's (with two names, one
        // NSEC3 may prove it all).
        let nsec3 = |m: &Message| {
            m.authorities
                .iter()
                .filter(|r| r.record_type() == RecordType::NSEC3)
                .count()
        };
        let pm = ask_do(pp, "nope.example.com.", RecordType::A).unwrap();
        let m = ask_do(sp, "nope.example.com.", RecordType::A).unwrap();
        assert!(nsec3(&m) >= 1);
        assert_eq!(nsec3(&m), nsec3(&pm), "the secondary proves NXDOMAIN too");
        let rows = run(&secondary, "ip.dns.zone.print", json!({}));
        assert_eq!(rows[0]["signed"], true, "{rows}");
        shutdown.close();
    }

    /// G4.1c-3: a TSIG-signed RFC 2136 UPDATE adds a record the zone
    /// answers at once; a bad key changes nothing; a lease (the API the
    /// DHCP server of G4.2 calls) gets its A and PTR, gone at its end.
    #[test]
    fn dynamic_updates_and_leases() {
        use hickory_proto::op::OpCode;
        use hickory_proto::rr::rdata::A;
        use hickory_proto::rr::rdata::tsig::TsigAlgorithm;
        use hickory_proto::rr::{RData, Record, TSigner};
        let port = free_port();
        let shutdown = Shutdown::default();
        let session = shared(Session::virtual_lab());
        run(&session, "ip.dns.set", json!({"allow_remote_requests": true}));
        let key = run(&session, "ip.dns.tsig-key.add", json!({"name": "ddns"}));
        let secret = corerouter_model::dns_tsig::base64_decode(key["secret"].as_str().unwrap()).unwrap();
        run(&session, "ip.dns.zone.add", json!({"name": "lan.example", "update_keys": "ddns"}));
        run(&session, "ip.dns.zone.add", json!({"name": "88.168.192.in-addr.arpa"}));
        let srv = super::super::dns_server::spawn(
            session.clone(),
            Arc::new(RouterDns::new()),
            port,
            shutdown.clone(),
        )
        .unwrap();
        spawn(&session, srv, port, shutdown.clone()).unwrap();
        wait("the zone", || ask(port, "lan.example.").is_some_and(|m| m.metadata.authoritative));

        let send = |secret: &[u8]| -> Message {
            let mut m = Message::query();
            m.metadata.op_code = OpCode::Update;
            m.add_query(Query::query(Name::from_ascii("lan.example.").unwrap(), RecordType::SOA));
            m.add_authority(Record::from_rdata(
                Name::from_ascii("pc.lan.example.").unwrap(),
                300,
                RData::A(A::new(192, 168, 88, 50)),
            ));
            let signer = TSigner::new(
                secret.to_vec(),
                TsigAlgorithm::HmacSha256,
                Name::from_ascii("ddns.").unwrap(),
                300,
            )
            .unwrap();
            let (tsig, _) = signer.sign_message(&m, unix_now()).unwrap();
            m.set_signature(tsig);
            let s = UdpSocket::bind("127.0.0.1:0").unwrap();
            s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            s.send_to(&m.to_vec().unwrap(), ("127.0.0.1", port)).unwrap();
            let mut buf = [0u8; 4096];
            let (n, _) = s.recv_from(&mut buf).unwrap();
            Message::from_vec(&buf[..n]).unwrap()
        };
        let r = send(&[1; 32]);
        assert_eq!(r.metadata.response_code, hickory_proto::op::ResponseCode::NotAuth);
        assert!(answer(port, "pc.lan.example.").is_none(), "a bad key changes nothing");
        let r = send(&secret);
        assert_eq!(r.metadata.response_code, hickory_proto::op::ResponseCode::NoError);
        assert!(r.signature().is_some(), "RFC 8945 §5.3: signed answer");
        assert_eq!(answer(port, "pc.lan.example.").as_deref(), Some("192.168.88.50"));
        let rows = run(&session, "ip.dns.zone.record.print", json!({"zone": "lan.example"}));
        assert_eq!(rows[0]["flags"], "D", "{rows}");
        assert!(rows[0]["source"].as_str().unwrap().contains("key ddns"));

        // A lease, as the DHCP server will hand it over.
        let now = unix_now();
        lock(&session)
            .dns_dynamic_lease(
                &corerouter_engine::dns_dynamic::LeaseName {
                    zone: "lan.example".into(),
                    host: "laptop".into(),
                    address: "192.168.88.77".parse().unwrap(),
                    ttl_secs: 600,
                    expires_unix: Some(now + 2),
                    source: "dhcp lan".into(),
                },
                now,
            )
            .unwrap();
        wait("the lease's A", || answer(port, "laptop.lan.example.").as_deref() == Some("192.168.88.77"));
        let mut q = Message::query();
        q.add_query(Query::query(Name::from_ascii("77.88.168.192.in-addr.arpa.").unwrap(), RecordType::PTR));
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        s.send_to(&q.to_vec().unwrap(), ("127.0.0.1", port)).unwrap();
        let mut buf = [0u8; 4096];
        let (n, _) = s.recv_from(&mut buf).unwrap();
        let ptr = Message::from_vec(&buf[..n]).unwrap();
        assert_eq!(ptr.answers[0].data.to_string(), "laptop.lan.example.");
        wait("the lease's end", || answer(port, "laptop.lan.example.").is_none());
        shutdown.close();
    }
}
