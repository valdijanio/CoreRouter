//! G4.3hd: IPoE subscribers in the redundant pair's hot standby, as the
//! PPPoE ones (`pppoe_bng/ha.rs`). The active publishes each session with
//! its DHCP binding (a `proto_ha` [`SessionRecord`] of [`Kind::Ipoe`], when
//! it comes up and at each renewal, and its counters every
//! [`COUNTERS_MS`]); the node that takes over adopts them: the session
//! here (the same Acct-Session-Id and Class, an Interim-Update with the
//! counters carried over, no Start) and the binding in the DHCP server
//! ([`IpoeBackend::takeover`]), so the client's next renewal is answered
//! as if nothing happened. An ARP ping to every adopted subscriber, from
//! the gateway's address, points its ARP entry at this node (RFC 826: a
//! known sender's entry is updated).
//!
//! [`IpoeBackend::takeover`]: corerouter_engine::ipoe::IpoeBackend::takeover

use std::collections::HashSet;

use corerouter_proto_dhcp::server::leases::State as LeaseState;
use corerouter_proto_ha::msg::{Counters as HaCounters, Key as HaKey};
use corerouter_proto_ha::record::{Kind, Lease4, SessionRecord};

use super::*;

/// Sessions adopted per hold of the core's lock.
const ADOPT_BATCH: usize = 1024;

/// Counters go to the standby this often (as PPPoE's, **estimado**).
pub(crate) const COUNTERS_MS: u64 = 10_000;

/// A change for the pair's sync stream (the service hands it to
/// `ppp_ha::publish`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum IpoeHaChange {
    Up(HaKey, Arc<[u8]>),
    Gone(HaKey),
    Counters(HaKey, HaCounters),
}

#[derive(Default)]
pub(crate) struct IpoeHa {
    /// Redundancy on; hot standby (sessions published).
    pub enabled: bool,
    pub hot: bool,
    /// This node answers DHCP on the session servers (the service sets
    /// it: active, and the takeover adopted).
    pub answering: bool,
    /// The `ppp-ha` loop runs a pair (G4.3hk; the service sets it): with
    /// `enabled` still off, the config here is behind, so keep quiet.
    pub paired: bool,
    /// The takeover this core adopted last.
    pub gen_done: u64,
    /// Bindings for the DHCP server's next round (taken once).
    pub leases: Option<(Vec<String>, Vec<Lease>)>,
    dirty: HashSet<Key>,
    out: Vec<IpoeHaChange>,
    /// The key each published session went out with.
    keys: HashMap<Key, HaKey>,
    counters_at: u64,
}

impl IpoeHa {
    /// Before the first config: as a pair's member, not answering.
    pub(crate) fn silent() -> Self {
        Self {
            enabled: true,
            ..Self::default()
        }
    }
}

/// What one takeover did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct Adopted {
    pub sessions: usize,
    /// Records of a server this node does not run.
    pub skipped: usize,
}

fn counters_of(a: &ActiveSession) -> HaCounters {
    HaCounters {
        rx_bytes: a.rx_bytes,
        tx_bytes: a.tx_bytes,
        rx_packets: a.rx_packets,
        tx_packets: a.tx_packets,
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

fn opt(b: &Option<Vec<u8>>) -> Option<Box<[u8]>> {
    b.as_deref().map(|v| {
        v.get(..v.len().min(corerouter_proto_ha::record::MAX_OPTION))
            .unwrap_or(v)
            .into()
    })
}

/// The binding of a record, for the DHCP server.
fn lease_of(r: &SessionRecord) -> Option<Lease> {
    let l = r.lease.as_ref()?;
    Some(Lease {
        address: r.ipv4?,
        server: r.server.to_string(),
        state: LeaseState::Bound,
        mac: r.client_mac,
        client_id: l.client_id.as_deref().map(<[u8]>::to_vec),
        host_name: String::from_utf8_lossy(&l.host_name).into_owned(),
        vendor_class: String::new(),
        expires: l.expires,
        lease_time: l.lease_time,
        last_seen: l.last_seen,
        reason: String::new(),
        relay_info: l.relay_info.as_deref().map(<[u8]>::to_vec),
        hw: l.hw.as_deref().map(<[u8]>::to_vec),
    })
}

impl State {
    /// Session `key`'s record changed (up, renewal, rate, routes).
    pub(super) fn ha_dirty(&mut self, key: &Key) {
        if self.ha.hot {
            self.ha.dirty.insert(key.clone());
        }
    }

    /// Session `key` ended here.
    pub(super) fn ha_gone(&mut self, key: &Key) {
        self.ha.dirty.remove(key);
        if let Some(k) = self.ha.keys.remove(key)
            && self.ha.hot
        {
            self.ha.out.push(IpoeHaChange::Gone(k));
        }
    }

    /// Every [`COUNTERS_MS`], the counters of the published sessions.
    pub(super) fn ha_counters(&mut self, now: u64) {
        if !self.ha.hot || now.saturating_sub(self.ha.counters_at) < COUNTERS_MS {
            return;
        }
        self.ha.counters_at = now;
        let mut out = Vec::with_capacity(self.ha.keys.len());
        for (k, hk) in &self.ha.keys {
            if let Some(a) = self.subs.get(k).and_then(|s| self.active.get(&s.id)) {
                out.push(IpoeHaChange::Counters(*hk, counters_of(a)));
            }
        }
        self.ha.out.append(&mut out);
    }

    fn record_of(&self, s: &Sub) -> Option<SessionRecord> {
        let a = self.active.get(&s.id)?;
        let l = s.lease.as_ref()?;
        Some(SessionRecord {
            kind: Kind::Ipoe,
            client_mac: s.mac,
            username: s.user.as_bytes().into(),
            ipv4: Some(s.ip),
            rate_limit: s.rate.as_deref().map(Into::into),
            circuit_id: a.circuit_id.as_deref().map(|c| c.as_bytes().into()),
            remote_id: a.remote_id.as_deref().map(|c| c.as_bytes().into()),
            acct_session_id: s.acct_id.as_str().into(),
            class: s.class.iter().map(|c| c.as_slice().into()).collect(),
            radius: a.radius,
            acct_interim: s.interim,
            profile: a.profile.as_str().into(),
            server: s.server.as_str().into(),
            routes: s
                .routes
                .iter()
                .take(corerouter_proto_ha::record::MAX_ROUTES)
                .map(|(r, o)| format!("{r}|{}", o.as_str()).into())
                .collect(),
            started_at: s.up_at,
            counters: counters_of(a),
            lease: Some(Lease4 {
                expires: l.expires,
                lease_time: l.lease_time,
                last_seen: l.last_seen,
                client_id: opt(&l.client_id),
                relay_info: opt(&l.relay_info),
                hw: opt(&l.hw),
                host_name: l
                    .host_name
                    .as_bytes()
                    .get(
                        ..l.host_name
                            .len()
                            .min(corerouter_proto_ha::record::MAX_OPTION),
                    )
                    .unwrap_or_default()
                    .into(),
            }),
            ..SessionRecord::default()
        })
    }
}

impl Core {
    /// What to send to the standby now (the service, every tick).
    pub(crate) fn ha_take(&self) -> Vec<IpoeHaChange> {
        let mut st = guard(&self.st);
        if !st.ha.hot {
            st.ha.dirty.clear();
            st.ha.out.clear();
            return Vec::new();
        }
        let dirty: Vec<Key> = st.ha.dirty.drain().collect();
        for k in dirty {
            let Some(r) = st.subs.get(&k).and_then(|s| st.record_of(s)) else {
                continue;
            };
            if let Ok(b) = r.to_bytes() {
                let hk = r.key();
                st.ha.keys.insert(k, hk);
                st.ha.out.push(IpoeHaChange::Up(hk, Arc::from(b)));
            }
        }
        std::mem::take(&mut st.ha.out)
    }

    /// Changes the pair's publisher could not take now: back in front.
    pub(crate) fn ha_requeue(&self, mut changes: Vec<IpoeHaChange>) {
        let mut st = guard(&self.st);
        changes.append(&mut st.ha.out);
        st.ha.out = changes;
    }

    pub(crate) fn ha_gen(&self) -> u64 {
        guard(&self.st).ha.gen_done
    }

    pub(crate) fn ha_enabled(&self) -> bool {
        guard(&self.st).ha.enabled
    }

    /// The DHCP server may answer on the session servers.
    pub(crate) fn set_answering(&self, on: bool) {
        guard(&self.st).ha.answering = on;
    }

    pub(crate) fn set_paired(&self, on: bool) {
        guard(&self.st).ha.paired = on;
    }

    /// The pair's role went to the peer: every session ends here without
    /// a word to the subscriber or an Acct-Stop (the peer goes on with it,
    /// hot standby) — or with the Stop (stateless: it redials there).
    pub(crate) fn abandon(&self) {
        let mut st = guard(&self.st);
        let hot = st.ha.hot;
        let keys: Vec<Key> = st.subs.keys().cloned().collect();
        let mut stops = Vec::new();
        for k in keys {
            let out = self.end_locked(
                &mut st,
                &k,
                (
                    "handover",
                    "o outro BNG do par assumiu a sessão (redundância)",
                    cause::ADMIN_RESET,
                ),
            );
            if !hot {
                stops.extend(out);
            }
        }
        st.ha.out.clear();
        st.ha.keys.clear();
        st.ha.dirty.clear();
        st.logs.push((
            false,
            "IPoE: o par assumiu; as sessões deste nó foram encerradas sem aviso ao CPE".into(),
        ));
        let aaa = st.aaa.clone();
        drop(st);
        if let Some(a) = aaa {
            for o in stops {
                let _ = a.account(o.req, o.source);
            }
        }
    }

    /// Takeover `gen`: adopts the IPoE sessions of `records` (the PPPoE
    /// ones are the `pppoe` workers'), then hands their bindings to the
    /// DHCP server. Once per takeover.
    pub(crate) fn adopt(self: &Arc<Self>, gen_: u64, records: &[SessionRecord]) -> Adopted {
        let now = self.ms();
        let unix = unix_now();
        let mut done = Adopted::default();
        if gen_ <= guard(&self.st).ha.gen_done {
            return done;
        }
        let mut interims = Vec::new();
        let mut leases = Vec::new();
        let mine: Vec<&SessionRecord> = records.iter().filter(|r| r.kind == Kind::Ipoe).collect();
        {
            // The tables grow once, not by doubling in the middle.
            let mut st = guard(&self.st);
            let n = mine.len();
            st.subs.reserve(n);
            st.by_acct.reserve(n);
            st.by_id.reserve(n);
            st.by_ip.reserve(n);
            st.ha.dirty.reserve(n);
        }
        // The lock in batches: the DHCP server's calls and the CoAs wait
        // for one batch, not the whole takeover (774 ms for 100 000 in one
        // hold, release, **medido**). DHCP stays silent until the end
        // (`gen_done` last).
        for batch in mine.chunks(ADOPT_BATCH) {
            let mut st = guard(&self.st);
            for r in batch {
                let (Some(srv), Some(lease)) = (st.servers.get(&*r.server).cloned(), lease_of(r))
                else {
                    done.skipped += 1;
                    continue;
                };
                let key: Key = (lease.server.clone(), lease.client_key());
                if st.subs.contains_key(&key) {
                    // An older copy of it here: the pair's is newer.
                    let _ = self.end_locked(&mut st, &key, ("handover", "", cause::ADMIN_RESET));
                }
                interims.extend(self.adopt_one(&mut st, now, unix, &srv, r, key, lease.clone()));
                leases.push(lease);
                done.sessions += 1;
            }
        }
        let mut st = guard(&self.st);
        let servers: Vec<String> = st.servers.keys().cloned().collect();
        st.ha.leases = Some((servers, leases));
        st.ha.gen_done = gen_;
        if done.sessions + done.skipped > 0 {
            st.logs.push((
                done.skipped > 0,
                format!(
                    "IPoE: o par caiu; {} sessões assumidas sem o assinante perceber{}",
                    done.sessions,
                    if done.skipped > 0 {
                        format!(", {} de um servidor DHCP que este nó não tem", done.skipped)
                    } else {
                        String::new()
                    }
                ),
            ));
        }
        let aaa = st.aaa.clone();
        drop(st);
        if let Some(a) = aaa {
            for o in interims {
                if let Err(e) = a.account(o.req, o.source) {
                    log::warn!("ipoe: Accounting-Interim (tomada) não enviado: {e}");
                }
            }
        }
        done
    }

    #[allow(clippy::too_many_arguments)]
    fn adopt_one(
        self: &Arc<Self>,
        st: &mut State,
        now: u64,
        unix: u64,
        srv: &DhcpServer,
        r: &SessionRecord,
        key: Key,
        lease: Lease,
    ) -> Option<AcctOut> {
        let ip = lease.address;
        let user = String::from_utf8_lossy(&r.username).into_owned();
        let circuit = r
            .circuit_id
            .as_deref()
            .map(|c| String::from_utf8_lossy(c).into_owned());
        let remote = r
            .remote_id
            .as_deref()
            .map(|c| String::from_utf8_lossy(c).into_owned());
        st.seq = st.seq.wrapping_add(1);
        let id = format!("*i{:x}", st.seq);
        let slot = if st.xdp { st.slot() } else { None };
        let want: Vec<(FramedRoute, RouteOrigin)> = r
            .routes
            .iter()
            .filter_map(|t| {
                let (route, origin) = t.split_once('|').unwrap_or((t, "secret"));
                Some((route.parse::<FramedRoute>().ok()?, origin_of(origin)))
            })
            .collect();
        let holder = Holder {
            session: id.clone(),
            user: user.clone(),
            origin: RouteOrigin::Secret,
            lane: 0,
            service: "ipoe",
        };
        let adm = framed::admit(
            &st.framed,
            &st.forbidden,
            &want,
            &holder,
            Some(ip),
            Some(NO_V6),
        );
        let rate = r.rate_limit.as_deref().map(str::to_owned);
        let profile: String = if r.profile.is_empty() {
            DEFAULT_PROFILE.into()
        } else {
            r.profile.to_string()
        };
        let mac = mac_text(r.client_mac);
        let a = ActiveSession {
            id: id.clone(),
            name: user.clone(),
            service: "ipoe".into(),
            caller_id: mac.clone(),
            address: Some(ip),
            server: srv.name.clone(),
            interface: srv.interface.to_string(),
            circuit_id: circuit.clone(),
            remote_id: remote.clone(),
            rate_limit: rate.clone(),
            profile: profile.clone(),
            encoding: "dhcp".into(),
            radius: r.radius,
            mtu: 1500,
            routes: adm.rows(),
            refused_routes: adm.refused.clone(),
            rx_bytes: r.counters.rx_bytes,
            tx_bytes: r.counters.tx_bytes,
            rx_packets: r.counters.rx_packets,
            tx_packets: r.counters.tx_packets,
            uptime_secs: unix.saturating_sub(r.started_at),
            ..ActiveSession::default()
        };
        let shape = st
            .profile_shapes
            .get(&profile)
            .copied()
            .unwrap_or_else(|| st.profile_shapes.get(DEFAULT_PROFILE).copied().flatten());
        let sub = Sub {
            id: id.clone(),
            key: key.clone(),
            user: user.clone(),
            ip,
            mac: r.client_mac,
            server: srv.name.clone(),
            interface: srv.interface.clone(),
            slot,
            rate: rate.clone(),
            acct: srv.use_radius != UseRadius::No,
            acct_id: r.acct_session_id.to_string(),
            interim: r.acct_interim,
            class: r.class.iter().map(|c| c.to_vec()).collect(),
            up_at: r.started_at,
            keepalive: srv.ipoe_keepalive,
            alive_ms: now,
            unanswered: 0,
            pinged_ms: now,
            rx_seen: r.counters.rx_bytes,
            routes: adm.routes.clone(),
            shape,
            lease: Some(lease),
        };
        if let Some(slot) = slot {
            let (up, down) = rates(rate.as_deref());
            st.ops.push(XdpOp::Upsert {
                slot,
                interface: srv.interface.clone(),
                client_mac: r.client_mac,
                ip,
                up,
                down,
                shape,
            });
        }
        for (rt, _) in &adm.routes {
            if let Some(slot) = slot {
                st.ops.push(XdpOp::Route {
                    dst: rt.dst,
                    slot,
                    add: true,
                });
            }
            if let IpNet::V4(dst) = rt.dst {
                st.kroutes.push(KernelRoute {
                    dst,
                    via: ip,
                    add: true,
                });
            }
        }
        // The subscriber's ARP entry for its gateway now points here.
        st.pings.push((srv.interface.clone(), ip));
        st.record(
            &[&user, &mac],
            HistoryEntry {
                at: unix,
                name: user.clone(),
                caller_id: mac.clone(),
                server: srv.name.clone(),
                event: "up".into(),
                stage: Some(Stage::Up),
                reason: "takeover".into(),
                hint: "Assumida do outro BNG do par, sem novo DHCP (redundância).".into(),
                address: Some(ip),
                ..HistoryEntry::default()
            },
        );
        let counters = AcctCounters {
            input_octets: a.rx_bytes,
            output_octets: a.tx_bytes,
            input_packets: a.rx_packets,
            output_packets: a.tx_packets,
            session_time: u32::try_from(a.uptime_secs).unwrap_or(u32::MAX),
        };
        st.active.insert(id.clone(), a);
        st.by_acct.insert(sub.acct_id.clone(), id.clone());
        st.by_id.insert(id.clone(), key.clone());
        st.by_ip.insert(ip, key.clone());
        let acct = sub.acct;
        let interim = sub
            .interim
            .or((st.interim_default > 0).then_some(st.interim_default));
        let req = AcctRequest {
            service: AaaService::Dhcp,
            status: AcctStatus::InterimUpdate,
            session_id: sub.acct_id.clone(),
            user,
            counters: Some(counters),
            terminate_cause: None,
            interim_secs: interim,
            attributes: {
                let mut v = acct_attributes(
                    ip,
                    &mac,
                    &srv.interface,
                    circuit.as_deref(),
                    remote.as_deref(),
                );
                v.extend(route_attributes(&adm.routes));
                v
            },
            class: sub.class.clone(),
        };
        st.subs.insert(key.clone(), sub);
        // The new active's stream publishes it from here on.
        st.ha_dirty(&key);
        // RFC 2866: the same Acct-Session-Id goes on; the Interim says
        // where (its Start went from the other node).
        (acct && st.aaa.is_some()).then(|| AcctOut {
            req,
            source: Some(Arc::new(Counters {
                core: self.clone(),
                id,
            })),
        })
    }
}
