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
    /// Ending sessions because the peer took them (no Acct-Stop).
    pub(crate) handed_over: bool,
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

/// The worker a CPE's frames reach (`Bng::lane_of` on its MAC).
fn mac_lane(mac: [u8; 6], lanes: u16) -> u16 {
    let [_, _, a, b, c, d] = mac;
    let k = u32::from_be_bytes([a, b, c, d]);
    ((k.wrapping_mul(0x9E37_79B1) >> 16) % u32::from(lanes.max(1))) as u16
}

/// The replication key of a session (`SessionRecord::key`).
fn key_of(server: &str, vlans: Vlans, sid: u16, mac: Mac) -> Key {
    SessionRecord {
        kind: Kind::Pppoe,
        vlan: vlan_field(vlans.outer),
        inner_vlan: vlan_field(vlans.inner),
        sid,
        client_mac: mac.0,
        server: server.into(),
        ..SessionRecord::default()
    }
    .key()
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
        if !self.ha_hot() || sub.up_at.is_none() {
            return;
        }
        self.ha.dirty.remove(&(sub.slot, sub.sref.sid));
        let Some((name, st)) = self
            .slots
            .get(sub.slot)
            .map(|s| (s.cfg.name.clone(), s.server.export(0, sub.sref.sid)))
        else {
            return;
        };
        let vlans = st.map_or(
            Vlans {
                outer: sub.descriptor_vlan.unwrap_or(0),
                ..Vlans::NONE
            },
            |s| s.vlans,
        );
        self.ha
            .out
            .push(HaChange::Gone(key_of(&name, vlans, sub.sref.sid, sub.mac)));
    }

    /// The record of an established session, or `None`.
    fn ha_record(&self, now: Millis, key: (usize, u16)) -> Option<SessionRecord> {
        let sub = self.subs.get(&key)?;
        let up = sub.up_at?;
        let slot = self.slots.get(key.0)?;
        let st = slot.server.export(now, key.1)?;
        let (auth_proto, auth_algo) = auth_codes(st.auth);
        let id = session_id(key.0, &self.slots, key.1);
        let counters = guard(&self.shared)
            .active
            .get(&id)
            .map(|a| HaCounters {
                rx_bytes: a.rx_bytes,
                tx_bytes: a.tx_bytes,
                rx_packets: a.rx_packets,
                tx_packets: a.tx_packets,
            })
            .unwrap_or_default();
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
            class: Vec::new(),
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
            extra: Vec::new(),
        })
    }

    /// What to send to the standby now: records of the sessions that
    /// changed, ends, and every [`COUNTERS_MS`] the counters.
    pub(crate) fn ha_take(&mut self, now: Millis) -> Vec<HaChange> {
        if !self.ha_hot() {
            self.ha.dirty.clear();
            self.ha.out.clear();
            return Vec::new();
        }
        let dirty: Vec<(usize, u16)> = self.ha.dirty.drain().collect();
        for k in dirty {
            if let Some(r) = self.ha_record(now, k)
                && let Ok(b) = r.to_bytes()
            {
                self.ha.out.push(HaChange::Up(r.key(), Arc::from(b)));
            }
        }
        if now.saturating_sub(self.ha.counters_at) >= COUNTERS_MS {
            self.ha.counters_at = now;
            let sh = guard(&self.shared);
            for ((slot, sid), sub) in &self.subs {
                if sub.up_at.is_none() {
                    continue;
                }
                let Some(s) = self.slots.get(*slot) else {
                    continue;
                };
                let Some(a) = sh.active.get(&session_id(*slot, &self.slots, *sid)) else {
                    continue;
                };
                let vlans = s
                    .server
                    .export(now, *sid)
                    .map_or(Vlans::NONE, |st| st.vlans);
                self.ha.out.push(HaChange::Counters(
                    key_of(&s.cfg.name, vlans, *sid, sub.mac),
                    HaCounters {
                        rx_bytes: a.rx_bytes,
                        tx_bytes: a.tx_bytes,
                        rx_packets: a.rx_packets,
                        tx_packets: a.tx_packets,
                    },
                ));
            }
        }
        std::mem::take(&mut self.ha.out)
    }

    /// A takeover waits for this worker (adopt it before answering).
    pub(crate) fn ha_pending(&self) -> bool {
        TAKEOVER_GEN.load(Ordering::Acquire) > self.ha.gen_done
    }

    /// Adopts the sessions of the latest takeover that land on this
    /// worker (by the CPE's MAC, like its frames).
    pub(crate) fn ha_adopt_pending(&mut self, now: Millis) -> Adopted {
        let gen_ = TAKEOVER_GEN.load(Ordering::Acquire);
        if gen_ <= self.ha.gen_done {
            return Adopted::default();
        }
        let records = guard(&TAKEOVER).clone();
        self.ha.gen_done = gen_;
        let Some(records) = records else {
            return Adopted::default();
        };
        let mine: Vec<&SessionRecord> = records
            .iter()
            .filter(|r| mac_lane(r.client_mac, self.lanes) == self.lane)
            .collect();
        let done = self.adopt(now, &mine);
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
        done
    }

    /// Takes `records` over: Opened in `proto-pppoe`, then the BNG's side
    /// of an Up without its announcements.
    pub(crate) fn adopt(&mut self, now: Millis, records: &[&SessionRecord]) -> Adopted {
        let mut done = Adopted::default();
        let unix_now = self.cfg.unix_base + now / 1000;
        let mut adopt: Vec<(usize, SessionRef, SessionRecord)> = Vec::new();
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
                        adopt.push((i, sref, (*r).clone()));
                        done.sessions += 1;
                    }
                    Err(_) => done.skipped += 1,
                }
            }
        }
        done.skipped += records.len().saturating_sub(done.sessions + done.skipped);
        for (i, sref, r) in adopt {
            self.adopt_one(now, i, sref, &r);
        }
        done
    }

    fn adopt_one(&mut self, now: Millis, i: usize, sref: SessionRef, r: &SessionRecord) {
        let Some(slot) = self.slots.get(i) else {
            return;
        };
        let Some(d) = slot.server.session(sref.sid) else {
            return;
        };
        let port = slot.port;
        let server = slot.cfg.name.clone();
        let interface = slot.cfg.interface.to_string();
        let user = String::from_utf8_lossy(&r.username).into_owned();
        let secret = self.cfg.ppp.secret(&user).cloned();
        let effective = self.cfg.ppp.effective(
            if r.radius { None } else { secret.as_ref() },
            &r.profile,
            &r.fallback_profile,
        );
        let unix_now = self.cfg.unix_base + now / 1000;
        let age_ms = unix_now.saturating_sub(r.started_at) * 1000;
        if let (Some(ip), Some(_)) = (r.ipv4, &r.pool) {
            guard(&self.pools).hold(ip);
        }
        let xdp = if self.xdp { self.slot_index() } else { None };
        let hold6 =
            |p: Option<Prefix6>, pool: &Option<Box<str>>| -> Option<(ipnet::Ipv6Net, v6::Source)> {
                let p = p?;
                let n = ipnet::Ipv6Net::new(p.addr, p.len).ok()?;
                guard(&self.pools6).hold(n);
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
            descriptor_vlan: (d.vlan != 0).then_some(d.vlan & 0x0fff),
            auth_cancel: None,
            circuit_id: r
                .circuit_id
                .as_deref()
                .map(|c| String::from_utf8_lossy(c).into_owned()),
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
            && let Ok(mut t) = self.routes.write()
        {
            t.insert(ip, self.lane);
        }
        let Some(sub) = self.subs.get_mut(&(i, sref.sid)) else {
            return;
        };
        match xdp {
            Some(idx) => self.effects.push(Effect::Xdp(PppoeOp::Upsert(
                idx,
                xdp_session(&d, sub.rate.as_deref(), sub.v6.as_deref()),
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
            xdp.is_some(),
        );
        sub.routes = adm.routes.clone();
        for (rt, _) in &adm.routes {
            self.effects.push(route_effect(xdp, rt, true));
        }
        let mac = mac_text(sub.mac);
        let mut a = ActiveSession {
            id: id.clone(),
            name: user.clone(),
            service: "pppoe".into(),
            service_name: Some(sub.service_name.clone()),
            caller_id: mac.clone(),
            address: ip,
            session_id: sref.sid,
            server: server.clone(),
            interface: interface.clone(),
            vlan: sub.descriptor_vlan,
            circuit_id: sub.circuit_id.clone(),
            remote_id: sub.remote_id.clone(),
            rate_limit: sub.rate.clone(),
            profile: sub.effective.profile.clone(),
            encoding: match d.auth {
                Some(AuthProto::Pap) => "pap",
                Some(AuthProto::ChapMd5) => "chap",
                Some(AuthProto::MsChapV1) => "mschap1",
                Some(AuthProto::MsChapV2) => "mschap2",
                None => "none",
            }
            .into(),
            radius: sub.radius,
            mtu: d.mtu,
            limit_bytes_in: (sub.limit_in > 0).then_some(sub.limit_in),
            limit_bytes_out: (sub.limit_out > 0).then_some(sub.limit_out),
            routes: adm.rows(),
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
        {
            let mut sh = guard(&self.shared);
            sh.active.insert(id.clone(), a.clone());
            sh.by_acct.insert(acct_id.clone(), id.clone());
            if let Some(ip) = ip {
                sh.by_ip.insert(ip, id.clone());
            }
            sh.record(HistoryEntry {
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
            });
        }
        // RFC 2866: the same Acct-Session-Id goes on, and an Interim says
        // where it is now (its Start went from the other node; a second
        // one would be a duplicate). The RADIUS service schedules the next
        // interims from it.
        if radius_acct
            && self.cfg.ppp.aaa.accounting
            && let Some(aaa) = &self.cfg.aaa
        {
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
                    let mut at = acct_attributes(ip, &mac, &interface);
                    at.extend(v6_attrs);
                    at.extend(route_attributes(&adm.routes));
                    at
                },
            };
            if let Err(e) = aaa.account(req, Some(src)) {
                self.log(
                    true,
                    format!("PPP: Accounting-Interim de {user} (tomada) não enviado: {e}"),
                );
            }
        }
        if let (Some(l), Some(ip)) = (list, ip) {
            self.effects.push(Effect::AddressList {
                list: l,
                ip,
                add: true,
                comment: format!("ppp {user}"),
            });
        }
        // The standby publishes from here on (the new active's stream).
        self.ha_dirty((i, sref.sid));
    }
}
