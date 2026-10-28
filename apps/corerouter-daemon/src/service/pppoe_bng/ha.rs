//! G4.3h hot standby inside one BNG worker: what the active publishes of
//! each session (a `proto_ha` [`SessionRecord`], when it comes up or
//! changes, and its counters every [`COUNTERS_MS`]) and how the node that
//! takes over adopts them (`proto-pppoe`'s `Server::import` in Opened
//! state, then what `up` does — address held, data plane, routes, the
//! active table — except what would tell the subscriber or the RADIUS
//! server that anything happened: no PADT, no new Acct-Session-Id, no
//! Start; an Interim-Update with the counters carried over instead).

use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};

use corerouter_proto_ha::msg::{Counters as HaCounters, Key};
use corerouter_proto_ha::record::{Kind, Prefix6, SessionRecord};
use corerouter_proto_pppoe::descriptor::vlan_field;
use corerouter_proto_pppoe::eth::Vlans;
use corerouter_proto_pppoe::server::ha::SessionState;

use super::*;

/// Counters go to the standby this often (**estimado**: 10 s of traffic is
/// what an accounting record may lose at a takeover).
pub(crate) const COUNTERS_MS: Millis = 10_000;

/// A change for the pair's sync stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HaChange {
    Up(Key, Arc<[u8]>),
    Gone(Key),
    Counters(Key, HaCounters),
}

/// Takeovers handed to the workers: the number grows with each, and the
/// records of a stateful one wait in [`TAKEOVER`] (every worker takes the
/// sessions of its own lane).
pub(crate) static TAKEOVER_GEN: AtomicU64 = AtomicU64::new(0);
pub(crate) static TAKEOVER: Mutex<Option<Arc<Vec<SessionRecord>>>> = Mutex::new(None);
/// Workers of the running `pppoe` service: the pair must run as many (a
/// CPE's frames reach the worker its MAC hashes to, and its SESSION_ID is
/// that worker's), so it is a config section compared for drift.
pub(crate) static LANES: AtomicU16 = AtomicU16::new(0);

/// G4.3hh: sessions a worker adopts per hold of the shared locks (the
/// active table, the pools, the slow path's address table). One hold per
/// session had the 8 workers of a 100 000-session takeover queue on the
/// active table's lock: 300 of the 430 ms each worker spent (**medido**,
/// `pppoe_ha_tests::adopt_profile`). A hold of this many is ≈ 1 ms, so a
/// reader (`ppp.active`, the RADIUS thread) waits at most that.
const ADOPT_CHUNK: usize = 1024;

/// What a chunk of adopted sessions writes to the shared state, applied
/// in one hold of each lock ([`Bng::adopt_commit`]).
#[derive(Default)]
struct AdoptBatch {
    rows: Vec<AdoptRow>,
    hold4: Vec<Ipv4Addr>,
    hold6: Vec<ipnet::Ipv6Net>,
    /// The slow path's address → worker table.
    lanes: Vec<Ipv4Addr>,
    /// Interims, posted once the rows are in the table (their counters
    /// are read from it).
    acct: Vec<(String, AcctRequest, Arc<dyn AcctSource>)>,
    /// `Ppp::effective` without a secret, by (profile, fallback): a
    /// handful, a walk finds it without allocating a key.
    effective: Vec<(Box<str>, Box<str>, corerouter_model::ppp::Effective)>,
}

struct AdoptRow {
    id: String,
    active: ActiveSession,
    acct_id: String,
    ip: Option<Ipv4Addr>,
    history: HistoryEntry,
}

/// What a takeover did in one worker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Adopted {
    pub sessions: usize,
    /// Records of a server this node does not have, or a SESSION_ID its
    /// lane cannot hold (the pair runs a different number of workers).
    pub skipped: usize,
}

#[derive(Default)]
pub(crate) struct HaState {
    /// Sessions whose record changed since the last publish.
    pub(crate) dirty: HashSet<(usize, u16)>,
    out: Vec<HaChange>,
    counters_at: Millis,
    /// The last takeover this worker adopted.
    pub(crate) gen_done: u64,
    /// The key each published session went out with: its end and its
    /// counters reuse it (no export, no copy, at 100 000 sessions every
    /// 10 s; and at its end the `proto-pppoe` session is already gone).
    keys: HashMap<(usize, u16), Key>,
    /// Ending sessions because the peer took them (no Acct-Stop).
    pub(crate) handed_over: bool,
    /// G4.3hh: the next flush carries a takeover's routes (its timeline
    /// marks when they are in the kernel).
    routes_mark: bool,
    /// G4.3hh: adopted sessions whose bookkeeping waits for
    /// [`Bng::ha_adopt_rest`], and the order to take them.
    later: HashMap<(usize, u16), Later>,
    later_order: Vec<(usize, u16)>,
    /// G4.3hh: the takeover being adopted: its records, the ones of this
    /// worker still waiting by (CPE MAC, SESSION_ID), the order the chunks
    /// take them, and the totals so far.
    records: Option<Arc<Vec<SessionRecord>>>,
    waiting: HashMap<([u8; 6], u16), usize>,
    order: Vec<usize>,
    total: Adopted,
}

/// What the second phase of an adoption needs of the session's record.
pub(crate) struct Later {
    acct_id: Box<str>,
    counters: HaCounters,
    age_ms: u64,
    /// The `proto-pppoe` session may be gone when the row is made (a
    /// session that ends first): what the row needs of it.
    auth: Option<AuthProto>,
}

impl HaState {
    /// The counters of published session `k`, read in `tick`'s pass over
    /// the active table (no lock or lookup of its own).
    pub(super) fn counters(&mut self, k: (usize, u16), a: &ActiveSession) {
        if let Some(key) = self.keys.get(&k) {
            self.out.push(HaChange::Counters(*key, counters_of(a)));
        }
    }
}

fn auth_codes(a: Option<AuthProto>) -> (u16, u8) {
    match a {
        Some(AuthProto::Pap) => (0xc023, 0),
        Some(AuthProto::ChapMd5) => (0xc223, 5),
        Some(AuthProto::MsChapV1) => (0xc223, 0x80),
        Some(AuthProto::MsChapV2) => (0xc223, 0x81),
        None => (0, 0),
    }
}

fn auth_of(proto: u16, algo: u8) -> Option<AuthProto> {
    match (proto, algo) {
        (0xc023, _) => Some(AuthProto::Pap),
        (0xc223, 5) => Some(AuthProto::ChapMd5),
        (0xc223, 0x80) => Some(AuthProto::MsChapV1),
        (0xc223, 0x81) => Some(AuthProto::MsChapV2),
        _ => None,
    }
}

fn origin_of(t: &str) -> RouteOrigin {
    [
        RouteOrigin::FramedRoute,
        RouteOrigin::FramedIpv6Route,
        RouteOrigin::FramedIpv6Prefix,
    ]
    .into_iter()
    .find(|o| o.as_str() == t)
    .unwrap_or(RouteOrigin::Secret)
}

fn counters_of(a: &ActiveSession) -> HaCounters {
    HaCounters {
        rx_bytes: a.rx_bytes,
        tx_bytes: a.tx_bytes,
        rx_packets: a.rx_packets,
        tx_packets: a.tx_packets,
    }
}

/// The worker a CPE's frames reach (`Bng::lane_of` on its MAC).
/// The (source MAC, SESSION_ID) of a PPPoE frame of a session (session
/// stage, or a PADT), without parsing the rest.
fn session_key(frame: &[u8]) -> Option<([u8; 6], u16)> {
    use corerouter_proto_pppoe::eth::{ETHERTYPE_DISCOVERY, ETHERTYPE_SESSION, parse};
    let e = parse(frame).ok()?;
    if e.ethertype != ETHERTYPE_SESSION && e.ethertype != ETHERTYPE_DISCOVERY {
        return None;
    }
    let h = corerouter_proto_pppoe::discovery::parse_header(e.payload).ok()?;
    (h.session_id != 0).then_some((e.src.0, h.session_id))
}

pub(crate) fn mac_lane(mac: [u8; 6], lanes: u16) -> u16 {
    let [_, _, a, b, c, d] = mac;
    let k = u32::from_be_bytes([a, b, c, d]);
    ((k.wrapping_mul(0x9E37_79B1) >> 16) % u32::from(lanes.max(1))) as u16
}

impl Bng {
    /// The pair runs hot standby: sessions are published.
    fn ha_hot(&self) -> bool {
        let r = &self.cfg.ppp.redundancy;
        r.enabled && r.mode == corerouter_model::ppp_redundancy::HaMode::HotStandby
    }

    /// The session's record changed (up, rate, IPv6, routes).
    pub(super) fn ha_dirty(&mut self, key: (usize, u16)) {
        if self.ha_hot() {
            self.ha.dirty.insert(key);
        }
    }

    /// The session ended here.
    pub(super) fn ha_gone(&mut self, sub: &Sub) {
        let k = (sub.slot, sub.sref.sid);
        self.ha.dirty.remove(&k);
        if let Some(key) = self.ha.keys.remove(&k)
            && self.ha_hot()
        {
            self.ha.out.push(HaChange::Gone(key));
        }
    }

    /// The record of an established session, or `None`.
    fn ha_record(
        &self,
        now: Millis,
        key: (usize, u16),
        counters: HaCounters,
    ) -> Option<SessionRecord> {
        let sub = self.subs.get(&key)?;
        let up = sub.up_at?;
        let slot = self.slots.get(key.0)?;
        let st = slot.server.export(now, key.1)?;
        let (auth_proto, auth_algo) = auth_codes(st.auth);
        let v6 = sub.v6.as_deref();
        let pool_of = |s: &v6::Source| match s {
            v6::Source::Pool(n) => Some(n.as_str().into()),
            v6::Source::Radius => None,
        };
        Some(SessionRecord {
            kind: Kind::Pppoe,
            ifindex: st.ifindex,
            vlan: vlan_field(st.vlans.outer),
            inner_vlan: vlan_field(st.vlans.inner),
            outer_tpid: if st.vlans.inner != 0 {
                st.vlans.outer_tpid
            } else {
                0
            },
            sid: st.sid,
            client_mac: st.client_mac.0,
            server_mac: slot.port.mac,
            our_magic: st.our_magic,
            peer_magic: st.peer_magic,
            mru: st.peer_mru,
            our_mru: st.our_mru,
            auth_proto,
            auth_algo,
            username: st.username.clone(),
            service_name: st.service.clone(),
            ipv4: st.ipv4,
            local_ipv4: st.local_ipv4,
            dns: st.dns,
            nbns: st.nbns,
            ipv6_iid: st.ipv6.map(|(_, peer)| peer),
            local_iid: st.ipv6.map(|(local, _)| local),
            ipv6_prefix: v6.and_then(|x| x.link.as_ref()).map(|(n, _)| Prefix6 {
                addr: n.network(),
                len: n.prefix_len(),
            }),
            delegated: v6.and_then(|x| x.delegated.as_ref()).map(|(n, _)| Prefix6 {
                addr: n.network(),
                len: n.prefix_len(),
            }),
            pool6: v6
                .and_then(|x| x.link.as_ref())
                .and_then(|(_, s)| pool_of(s)),
            pd_pool: v6
                .and_then(|x| x.delegated.as_ref())
                .and_then(|(_, s)| pool_of(s)),
            dns6: v6
                .map(|x| x.dns.iter().take(4).copied().collect())
                .unwrap_or_default(),
            rate_limit: sub.rate.as_deref().map(Into::into),
            session_timeout: sub.session_timeout,
            idle_timeout: sub.effective.idle_timeout,
            circuit_id: sub.circuit_id.as_deref().map(|c| c.as_bytes().into()),
            remote_id: sub.remote_id.as_deref().map(|c| c.as_bytes().into()),
            acct_session_id: sub.acct_id.as_str().into(),
            class: sub.class.iter().map(|c| c.as_slice().into()).collect(),
            radius: sub.radius,
            acct_interim: sub.interim,
            profile: sub.effective.profile.as_str().into(),
            server: slot.cfg.name.as_str().into(),
            pool: sub.pool.as_deref().map(Into::into),
            address_list: sub.effective.address_list.as_deref().map(Into::into),
            routes: sub
                .routes
                .iter()
                .take(corerouter_proto_ha::record::MAX_ROUTES)
                .map(|(r, o)| format!("{r}|{}", o.as_str()).into())
                .collect(),
            limit_in: sub.limit_in,
            limit_out: sub.limit_out,
            fallback_profile: sub.fallback_profile.as_str().into(),
            started_at: self.cfg.unix_base + up / 1000,
            counters,
            lease: None,
            extra: Vec::new(),
        })
    }

    /// What to send to the standby now: records of the sessions that
    /// changed, ends, and the counters `tick` gathered.
    pub(crate) fn ha_take(&mut self, now: Millis) -> Vec<HaChange> {
        if !self.ha_hot() {
            self.ha.dirty.clear();
            self.ha.out.clear();
            return Vec::new();
        }
        let dirty: Vec<(usize, u16)> = self.ha.dirty.drain().collect();
        if !dirty.is_empty() {
            // One lock of the shared table for the whole batch.
            let counters: Vec<HaCounters> = {
                let sh = guard(&self.shared);
                dirty
                    .iter()
                    .map(|k| {
                        sh.active
                            .get(&session_id(k.0, &self.slots, k.1))
                            .map(counters_of)
                            .unwrap_or_default()
                    })
                    .collect()
            };
            for (k, c) in dirty.into_iter().zip(counters) {
                if let Some(r) = self.ha_record(now, k, c)
                    && let Ok(b) = r.to_bytes()
                {
                    let key = r.key();
                    self.ha.keys.insert(k, key);
                    self.ha.out.push(HaChange::Up(key, Arc::from(b)));
                }
            }
        }
        std::mem::take(&mut self.ha.out)
    }

    /// Changes the pair's publisher could not take now (its lock busy):
    /// back in front of the next round's, in order.
    pub(crate) fn ha_requeue(&mut self, mut changes: Vec<HaChange>) {
        changes.append(&mut self.ha.out);
        self.ha.out = changes;
    }

    /// Whether this tick sends the counters (every [`COUNTERS_MS`]).
    pub(super) fn ha_counters_due(&mut self, now: Millis) -> bool {
        if !self.ha_hot() || now.saturating_sub(self.ha.counters_at) < COUNTERS_MS {
            return false;
        }
        self.ha.counters_at = now;
        true
    }

    /// G4.3hh: whether this round's routes are a takeover's (once).
    pub(crate) fn ha_take_routes_mark(&mut self) -> bool {
        std::mem::take(&mut self.ha.routes_mark)
    }

    /// A takeover waits for this worker (adopt it before answering).
    pub(crate) fn ha_pending(&self) -> bool {
        TAKEOVER_GEN.load(Ordering::Acquire) > self.ha.gen_done
    }

    /// Starts adopting the sessions of the latest takeover that land on
    /// this worker (by the CPE's MAC, like its frames), and adopts the
    /// first [`ADOPT_CHUNK`] of them. From here the worker answers: a frame
    /// of a session still waiting adopts it on the spot
    /// ([`Self::ha_adopt_for`]), so it never gets a PADT, and
    /// [`Self::ha_adopt_step`] takes the next chunk each round (G4.3hh).
    /// `Some` with the totals once this worker's share is all adopted.
    pub(crate) fn ha_adopt_pending(&mut self, now: Millis) -> Option<Adopted> {
        let gen_ = TAKEOVER_GEN.load(Ordering::Acquire);
        if gen_ <= self.ha.gen_done {
            return None;
        }
        let records = guard(&TAKEOVER).clone();
        self.ha.gen_done = gen_;
        self.ha.waiting.clear();
        self.ha.order.clear();
        self.ha.total = Adopted::default();
        self.ha.records = None;
        let Some(records) = records else {
            return Some(Adopted::default());
        };
        for (k, r) in records.iter().enumerate() {
            if r.kind == Kind::Pppoe && mac_lane(r.client_mac, self.lanes) == self.lane {
                self.ha.waiting.insert((r.client_mac, r.sid), k);
                self.ha.order.push(k);
            }
        }
        // Room for the whole share at once: growing these tables step by
        // step maps and unmaps memory under every worker's feet.
        let n = self.ha.order.len();
        self.subs.reserve(n);
        self.index.reserve(n);
        self.effects.reserve(2 * n);
        self.ha.later.reserve(n);
        self.ha.later_order.reserve(n);
        self.ha.records = Some(records);
        self.ha_adopt_step(now)
    }

    /// Sessions of a takeover this worker has not adopted yet.
    pub(crate) fn ha_adopting(&self) -> bool {
        !self.ha.waiting.is_empty()
    }

    /// The next [`ADOPT_CHUNK`] sessions of the takeover; `Some` with the
    /// totals when it was the last.
    pub(crate) fn ha_adopt_step(&mut self, now: Millis) -> Option<Adopted> {
        let records = self.ha.records.clone()?;
        let mut chunk: Vec<&SessionRecord> = Vec::with_capacity(ADOPT_CHUNK);
        while chunk.len() < ADOPT_CHUNK {
            let Some(k) = self.ha.order.pop() else {
                break;
            };
            let Some(r) = records.get(k) else {
                continue;
            };
            // Adopted already, on demand.
            if self.ha.waiting.remove(&(r.client_mac, r.sid)).is_some() {
                chunk.push(r);
            }
        }
        self.adopt_counted(now, &chunk);
        if !self.ha.order.is_empty() {
            return None;
        }
        self.ha.waiting.clear();
        self.ha.records = None;
        let done = std::mem::take(&mut self.ha.total);
        if done.sessions + done.skipped > 0 {
            self.log(
                done.skipped > 0,
                format!(
                    "PPPoE: o par caiu; {} sessões assumidas sem o assinante perceber{}",
                    done.sessions,
                    if done.skipped > 0 {
                        format!(
                            ", {} não couberam (servidor ou número de workers diferente no par)",
                            done.skipped
                        )
                    } else {
                        String::new()
                    }
                ),
            );
        }
        Some(done)
    }

    /// A frame of a session of the takeover still waiting: adopted now,
    /// before the frame reaches `proto-pppoe` (which would answer an
    /// unknown session with a PADT).
    pub(super) fn ha_adopt_for(&mut self, now: Millis, frame: &[u8]) {
        let Some(key) = session_key(frame) else {
            return;
        };
        let Some(k) = self.ha.waiting.remove(&key) else {
            return;
        };
        let Some(records) = self.ha.records.clone() else {
            return;
        };
        if let Some(r) = records.get(k) {
            self.adopt_counted(now, &[r]);
        }
    }

    fn adopt_counted(&mut self, now: Millis, records: &[&SessionRecord]) {
        if records.is_empty() {
            return;
        }
        let d = self.adopt(now, records);
        self.ha.routes_mark |= d.sessions > 0;
        self.ha.total.sessions += d.sessions;
        self.ha.total.skipped += d.skipped;
    }

    /// Takes `records` over: Opened in `proto-pppoe`, then the BNG's side
    /// of an Up without its announcements.
    pub(crate) fn adopt(&mut self, now: Millis, records: &[&SessionRecord]) -> Adopted {
        let mut done = Adopted::default();
        let unix_now = self.cfg.unix_base + now / 1000;
        let mut adopt: Vec<(usize, SessionRef, &SessionRecord)> = Vec::new();
        for (i, slot) in self.slots.iter_mut().enumerate() {
            let here: Vec<&SessionRecord> = records
                .iter()
                .filter(|r| *r.server == *slot.cfg.name)
                .copied()
                .collect();
            if here.is_empty() {
                continue;
            }
            let states: Vec<SessionState> = here
                .iter()
                .map(|r| SessionState {
                    sid: r.sid,
                    ifindex: slot.port.ifindex,
                    vlans: Vlans {
                        outer: r.vlan & 0x0fff,
                        inner: r.inner_vlan & 0x0fff,
                        outer_tpid: r.outer_tpid,
                    },
                    client_mac: Mac(r.client_mac),
                    our_magic: r.our_magic,
                    peer_magic: r.peer_magic,
                    our_mru: r.our_mru,
                    peer_mru: r.mru,
                    auth: auth_of(r.auth_proto, r.auth_algo),
                    username: r.username.clone(),
                    service: r.service_name.clone(),
                    ipv4: r.ipv4,
                    local_ipv4: r.local_ipv4,
                    dns: r.dns,
                    nbns: r.nbns,
                    ipv6: r.local_iid.zip(r.ipv6_iid),
                    v6_mode: Ipv6Mode::On,
                    rate_limit: r
                        .rate_limit
                        .as_deref()
                        .and_then(|t| t.parse::<RateLimit>().ok()),
                    session_timeout: r.session_timeout,
                    timeout_left_ms: r.session_timeout.map(|t| {
                        (r.started_at + u64::from(t))
                            .saturating_sub(unix_now)
                            .max(1)
                            * 1000
                    }),
                    circuit_id: r.circuit_id.clone(),
                    remote_id: r.remote_id.clone(),
                })
                .collect();
            let results = slot.server.import(now, &states, &mut self.out);
            for (r, res) in here.iter().zip(results) {
                match res {
                    Ok(sref) => {
                        adopt.push((i, sref, *r));
                        done.sessions += 1;
                    }
                    Err(_) => done.skipped += 1,
                }
            }
        }
        done.skipped += records.len().saturating_sub(done.sessions + done.skipped);
        let mut batch = AdoptBatch::default();
        for chunk in adopt.chunks(ADOPT_CHUNK) {
            for &(i, sref, r) in chunk {
                self.adopt_one(now, i, sref, r, &mut batch);
            }
            self.adopt_commit(&mut batch);
        }
        done
    }

    /// One hold of each shared lock for a chunk of adopted sessions, then
    /// their Interims.
    fn adopt_commit(&mut self, b: &mut AdoptBatch) {
        if !b.hold4.is_empty() {
            let mut p = guard(&self.pools);
            for ip in b.hold4.drain(..) {
                p.hold(ip);
            }
        }
        if !b.hold6.is_empty() {
            let mut p = guard(&self.pools6);
            for n in b.hold6.drain(..) {
                p.hold(n);
            }
        }
        if !b.lanes.is_empty()
            && let Ok(mut t) = self.routes.write()
        {
            for ip in b.lanes.drain(..) {
                t.insert(ip, self.lane);
            }
        }
        b.lanes.clear();
        if !b.rows.is_empty() {
            let mut sh = guard(&self.shared);
            for row in b.rows.drain(..) {
                sh.by_acct.insert(row.acct_id, row.id.clone());
                if let Some(ip) = row.ip {
                    sh.by_ip.insert(ip, row.id.clone());
                }
                sh.active.insert(row.id, row.active);
                sh.record(row.history);
            }
        }
        let Some(aaa) = self.cfg.aaa.clone() else {
            b.acct.clear();
            return;
        };
        for (user, req, src) in std::mem::take(&mut b.acct) {
            if let Err(e) = aaa.account(req, Some(src)) {
                self.log(
                    true,
                    format!("PPP: Accounting-Interim de {user} (tomada) não enviado: {e}"),
                );
            }
        }
    }

    fn adopt_one(
        &mut self,
        now: Millis,
        i: usize,
        sref: SessionRef,
        r: &SessionRecord,
        batch: &mut AdoptBatch,
    ) {
        let Some(slot) = self.slots.get(i) else {
            return;
        };
        let Some(d) = slot.server.session(sref.sid) else {
            return;
        };
        let port = slot.port;
        let interface = slot.cfg.interface.to_string();
        let user = String::from_utf8_lossy(&r.username).into_owned();
        // The profiles' part once per pair of names (it clones three
        // profiles), the secret's addresses on top of each.
        let found = batch
            .effective
            .iter()
            .find(|(p, f, _)| *p == r.profile && *f == r.fallback_profile)
            .map(|(_, _, e)| e.clone());
        let base = match found {
            Some(e) => e,
            None => {
                let e = self
                    .cfg
                    .ppp
                    .effective(None, &r.profile, &r.fallback_profile);
                batch
                    .effective
                    .push((r.profile.clone(), r.fallback_profile.clone(), e.clone()));
                e
            }
        };
        let effective = base.with_secret(if r.radius {
            None
        } else {
            self.cfg.ppp.secret(&user)
        });
        let unix_now = self.cfg.unix_base + now / 1000;
        let age_ms = unix_now.saturating_sub(r.started_at) * 1000;
        if let (Some(ip), Some(_)) = (r.ipv4, &r.pool) {
            batch.hold4.push(ip);
        }
        let xdp = if self.xdp { self.slot_index() } else { None };
        let mut hold6 =
            |p: Option<Prefix6>, pool: &Option<Box<str>>| -> Option<(ipnet::Ipv6Net, v6::Source)> {
                let p = p?;
                let n = ipnet::Ipv6Net::new(p.addr, p.len).ok()?;
                batch.hold6.push(n);
                Some((
                    n,
                    pool.as_deref()
                        .map_or(v6::Source::Radius, |name| v6::Source::Pool(name.to_owned())),
                ))
            };
        let link = hold6(r.ipv6_prefix, &r.pool6);
        let delegated = hold6(r.delegated, &r.pd_pool);
        let v6 = match (r.local_iid, r.ipv6_iid) {
            (Some(local), Some(peer)) => Some(Box::new(V6::new(
                now,
                local,
                peer,
                link,
                delegated,
                r.dns6.clone(),
                effective.dhcpv6_lease_time,
                d.mtu,
                port.mac,
            ))),
            _ => None,
        };
        let want: Vec<(FramedRoute, RouteOrigin)> = r
            .routes
            .iter()
            .filter_map(|t| {
                let (route, origin) = t.split_once('|').unwrap_or((t, "secret"));
                Some((route.parse::<FramedRoute>().ok()?, origin_of(origin)))
            })
            .collect();
        let vlans = Vlans {
            outer: r.vlan & 0x0fff,
            inner: r.inner_vlan & 0x0fff,
            outer_tpid: r.outer_tpid,
        };
        let circuit_id = r
            .circuit_id
            .as_deref()
            .map(|c| String::from_utf8_lossy(c).into_owned());
        // The same NAS-Port-Id as the node that opened it (`up` in pppoe_bng.rs).
        let nas_port_id = match &circuit_id {
            Some(c) if self.cfg.ppp.aaa.use_circuit_id_in_nas_port_id => c.clone(),
            _ => nas_port(&interface, vlans),
        };
        let sub = Sub {
            slot: i,
            sref,
            user: user.clone(),
            mac: d.client_mac,
            stage: Stage::Up,
            effective,
            radius: r.radius,
            ip: r.ipv4,
            pool: r.pool.as_deref().map(str::to_owned),
            rate: r.rate_limit.as_deref().map(str::to_owned),
            acct_id: r.acct_session_id.to_string(),
            interim: r.acct_interim,
            class: r.class.iter().map(|c| c.to_vec()).collect(),
            xdp,
            up_at: Some(now.saturating_sub(age_ms)),
            limit_in: r.limit_in,
            limit_out: r.limit_out,
            session_timeout: r.session_timeout,
            reply_message: None,
            cause: None,
            last_bytes: (r.counters.rx_bytes, r.counters.tx_bytes),
            prev: (r.counters.rx_bytes, r.counters.tx_bytes, now),
            list_at: now,
            idle_since: now,
            vlans,
            nas_port_id,
            auth_cancel: None,
            circuit_id,
            remote_id: r
                .remote_id
                .as_deref()
                .map(|c| String::from_utf8_lossy(c).into_owned()),
            service_name: String::from_utf8_lossy(&r.service_name).into_owned(),
            fallback_profile: r.fallback_profile.to_string(),
            mtu: d.mtu,
            radius6: RadiusV6::default(),
            v6,
            want_routes: Vec::new(),
            want_refused: Vec::new(),
            routes: Vec::new(),
            base: [
                r.counters.rx_bytes,
                r.counters.tx_bytes,
                r.counters.rx_packets,
                r.counters.tx_packets,
            ],
        };
        let id = session_id(i, &self.slots, sref.sid);
        self.index.add((i, sref.sid), &sub);
        self.subs.insert((i, sref.sid), sub);
        let ip = r.ipv4;
        if xdp.is_none()
            && let Some(ip) = ip
        {
            batch.lanes.push(ip);
        }
        let Some(sub) = self.subs.get_mut(&(i, sref.sid)) else {
            return;
        };
        match xdp {
            Some(idx) => self.effects.push(Effect::Xdp(PppoeOp::Upsert(
                idx,
                xdp_session(
                    &d,
                    sub.rate.as_deref(),
                    sub.v6.as_deref(),
                    corerouter_engine::queue::shape_of(&self.cfg.queues, &sub.effective),
                ),
            ))),
            None => {
                if let Some(ip) = ip {
                    self.effects.push(Effect::Route { ip, add: true });
                }
            }
        }
        let holder = Holder {
            session: id.clone(),
            user: user.clone(),
            origin: RouteOrigin::Secret,
            lane: self.lane,
            service: "pppoe",
        };
        let adm = framed::admit(
            &self.cfg.framed,
            &self.cfg.forbidden,
            &want,
            &holder,
            ip,
            v6_refusal(xdp.is_some()),
        );
        sub.routes = adm.routes.clone();
        for (rt, _) in &adm.routes {
            self.effects.push(route_effect(xdp, rt, true));
        }
        // The rest (active table, history, Interim, address list, the
        // publish) waits for `ha_adopt_rest`: the worker answers first.
        self.ha.later.insert(
            (i, sref.sid),
            Later {
                acct_id: r.acct_session_id.clone(),
                counters: r.counters,
                age_ms,
                auth: d.auth,
            },
        );
        self.ha.later_order.push((i, sref.sid));
    }

    /// G4.3hh: whether adopted sessions still wait for their bookkeeping.
    pub(crate) fn ha_later(&self) -> bool {
        !self.ha.later.is_empty()
    }

    /// G4.3hh, second phase of a takeover: the bookkeeping of up to
    /// [`ADOPT_CHUNK`] adopted sessions (the active table and the history
    /// in one hold of the shared lock, then their Interims). The worker
    /// calls it once per round, between its frames.
    pub(crate) fn ha_adopt_rest(&mut self, now: Millis) {
        let mut batch = AdoptBatch::default();
        let mut taken = 0;
        while taken < ADOPT_CHUNK {
            let Some(key) = self.ha.later_order.pop() else {
                break;
            };
            let Some(l) = self.ha.later.remove(&key) else {
                continue;
            };
            taken += 1;
            self.later_row(now, key, &l, &mut batch, true);
        }
        if self.ha.later.is_empty() {
            self.ha.later_order = Vec::new();
        }
        self.adopt_commit(&mut batch);
    }

    /// A session that ends before its bookkeeping: its row first, so the
    /// end finds it (the Stop's counters, the history), without an Interim.
    pub(super) fn ha_adopt_now(&mut self, now: Millis, sub: &Sub) {
        let key = (sub.slot, sub.sref.sid);
        let Some(l) = self.ha.later.remove(&key) else {
            return;
        };
        let mut batch = AdoptBatch::default();
        if l.acct_id.as_ref() == sub.acct_id.as_str() {
            self.row_of(now, key, sub, &l, &mut batch, false);
        }
        self.adopt_commit(&mut batch);
    }

    fn later_row(
        &mut self,
        now: Millis,
        key: (usize, u16),
        l: &Later,
        batch: &mut AdoptBatch,
        acct: bool,
    ) {
        // Gone in the meantime (or its SESSION_ID already another's).
        let Some(sub) = self.subs.get(&key) else {
            return;
        };
        if l.acct_id.as_ref() != sub.acct_id.as_str() {
            return;
        }
        // `row_of` reads `self`; the sub is taken out for the call.
        let Some(sub) = self.subs.remove(&key) else {
            return;
        };
        self.row_of(now, key, &sub, l, batch, acct);
        self.subs.insert(key, sub);
        // The standby publishes from here on (the new active's stream).
        self.ha_dirty(key);
    }

    fn row_of(
        &mut self,
        now: Millis,
        key: (usize, u16),
        sub: &Sub,
        l: &Later,
        batch: &mut AdoptBatch,
        acct: bool,
    ) {
        let (i, sid) = key;
        let Some(slot) = self.slots.get(i) else {
            return;
        };
        let server = slot.cfg.name.clone();
        let interface = slot.cfg.interface.to_string();
        let id = session_id(i, &self.slots, sid);
        let user = sub.user.clone();
        let ip = sub.ip;
        let unix_now = self.cfg.unix_base + now / 1000;
        let age_ms = l.age_ms;
        let r = l;
        let routes = framed::rows(&sub.routes);
        let mac = mac_text(sub.mac);
        let mut a = ActiveSession {
            id: id.clone(),
            name: user.clone(),
            service: "pppoe".into(),
            service_name: Some(sub.service_name.clone()),
            caller_id: mac.clone(),
            address: ip,
            session_id: sid,
            server: server.clone(),
            interface: interface.clone(),
            vlan: (sub.vlans.outer != 0).then_some(sub.vlans.outer),
            inner_vlan: (sub.vlans.inner != 0).then_some(sub.vlans.inner),
            circuit_id: sub.circuit_id.clone(),
            remote_id: sub.remote_id.clone(),
            rate_limit: sub.rate.clone(),
            profile: sub.effective.profile.clone(),
            encoding: match l.auth {
                Some(AuthProto::Pap) => "pap",
                Some(AuthProto::ChapMd5) => "chap",
                Some(AuthProto::MsChapV1) => "mschap1",
                Some(AuthProto::MsChapV2) => "mschap2",
                None => "none",
            }
            .into(),
            radius: sub.radius,
            mtu: sub.mtu,
            limit_bytes_in: (sub.limit_in > 0).then_some(sub.limit_in),
            limit_bytes_out: (sub.limit_out > 0).then_some(sub.limit_out),
            routes,
            rx_bytes: r.counters.rx_bytes,
            tx_bytes: r.counters.tx_bytes,
            rx_packets: r.counters.rx_packets,
            tx_packets: r.counters.tx_packets,
            uptime_secs: age_ms / 1000,
            ..ActiveSession::default()
        };
        if let Some(f) = sub.v6.as_deref().map(active_v6) {
            f.apply(&mut a);
        }
        let v6_attrs = sub
            .v6
            .as_deref()
            .map(V6::acct_attributes)
            .unwrap_or_default();
        let list = sub.effective.address_list.clone();
        let interim = sub.interim;
        let acct_id = sub.acct_id.clone();
        let radius_acct = sub.radius || self.cfg.ppp.aaa.use_radius;
        let row = AdoptRow {
            id: id.clone(),
            active: ActiveSession::default(),
            acct_id: acct_id.clone(),
            ip,
            history: HistoryEntry {
                at: unix_now,
                name: user.clone(),
                caller_id: mac.clone(),
                server: server.clone(),
                event: "up".into(),
                stage: Some(Stage::Up),
                reason: "takeover".into(),
                hint: "Assumida do outro BNG do par, sem novo login (redundância).".into(),
                address: ip,
                ..HistoryEntry::default()
            },
        };
        // RFC 2866: the same Acct-Session-Id goes on, and an Interim says
        // where it is now (its Start went from the other node; a second
        // one would be a duplicate). The RADIUS service schedules the next
        // interims from it.
        if acct && radius_acct && self.cfg.ppp.aaa.accounting && self.cfg.aaa.is_some() {
            let src: Arc<dyn AcctSource> = Arc::new(Counters {
                shared: self.shared.clone(),
                id: id.clone(),
            });
            let req = AcctRequest {
                service: AaaService::Ppp,
                status: AcctStatus::InterimUpdate,
                session_id: acct_id,
                user: user.clone(),
                counters: Some(acct_counters(&a)),
                terminate_cause: None,
                interim_secs: interim,
                attributes: {
                    let mut at = acct_attributes(ip, &mac, sub);
                    at.extend(v6_attrs);
                    at.extend(route_attributes(&sub.routes));
                    at
                },
                class: sub.class.clone(),
            };
            batch.acct.push((user.clone(), req, src));
        }
        batch.rows.push(AdoptRow { active: a, ..row });
        if let (Some(l), Some(ip)) = (list, ip) {
            self.effects.push(Effect::AddressList {
                list: l,
                ip,
                add: true,
                comment: format!("ppp {user}"),
            });
        }
    }
}
