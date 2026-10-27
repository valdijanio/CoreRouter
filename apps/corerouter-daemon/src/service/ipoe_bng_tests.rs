//! Tests of the IPoE core (`ipoe_bng.rs`) against the engine's own DHCP
//! server and the lab's DHCP clients (`proto_dhcp::lab_hosts`, four behind
//! each port), on the session clock, with a RADIUS that answers in memory:
//! sessions from leases, RADIUS attributes, accounting, `ppp.active.remove`,
//! CoA/Disconnect, the keepalive and the XDP map changes.
#![cfg(test)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::sync::{Arc, Mutex};

use corerouter_engine::radius::{AaaBackend, AcctSource, AuthDone, SessionOwner};
use corerouter_engine::Session;
use corerouter_model::radius::{
    AcctRequest, AcctStatus, Attribute, AuthOutcome, AuthReply, AuthRequest, CoaKind, CoaOutcome,
    CoaRequest, CoaSelector, RadiusStatus,
};
use serde_json::{Value, json};

use super::ipoe_bng::{Backend, Core, Owner, Sessions, XdpOp};

/// RADIUS in memory: the lab's first two hosts are known (a rate, a fixed
/// address for the second), the others rejected; every request is kept.
#[derive(Default)]
struct FakeAaa {
    asks: Mutex<Vec<AuthRequest>>,
    accts: Mutex<Vec<AcctRequest>>,
}

impl AaaBackend for FakeAaa {
    fn authenticate(&self, req: AuthRequest, done: AuthDone) {
        let known = ["02:1A:B0:02:00:01", "02:1A:B0:02:00:02"];
        let ok = known.contains(&req.user.as_str());
        let mut reply = AuthReply::failed(if ok { AuthOutcome::Accept } else { AuthOutcome::Reject }, "");
        reply.message = (!ok).then(|| "Inadimplente".into());
        if ok {
            reply.attributes = vec![
                Attribute::new("Mikrotik-Rate-Limit", "10M/50M"),
                Attribute::new("Acct-Interim-Interval", "300"),
                Attribute::new("Class", "plano-50"),
            ];
            if req.user.ends_with("02") {
                reply.attributes.push(Attribute::new("Framed-IP-Address", "192.168.88.200"));
                reply.attributes.push(Attribute::new("Session-Timeout", "900"));
            }
        }
        self.asks.lock().unwrap().push(req);
        done(reply);
    }

    fn account(&self, req: AcctRequest, _: Option<Arc<dyn AcctSource>>) -> Result<(), String> {
        self.accts.lock().unwrap().push(req);
        Ok(())
    }

    fn register_owner(&self, _: Arc<dyn SessionOwner>) {}

    fn status(&self) -> RadiusStatus {
        RadiusStatus::default()
    }
}

fn ok(s: &mut Session, id: &str, p: Value) -> Value {
    s.execute(id, &p).unwrap_or_else(|e| panic!("{id} {p}: {e}"))
}

struct Lab {
    s: Session,
    core: Arc<Core>,
    aaa: Arc<FakeAaa>,
    ms: u64,
    clock: Arc<std::sync::atomic::AtomicU64>,
}

impl Lab {
    fn new(server: Value) -> Self {
        let mut s = Session::virtual_lab();
        s.tick(1_700_000_000);
        let mut srv = json!({"interface": "ether2", "address_pool": "lan", "lease_time": "10m"});
        for (k, v) in server.as_object().unwrap() {
            srv[k] = v.clone();
        }
        for (id, p) in [
            ("ip.address.add", json!({"address": "192.168.88.1/24", "interface": "ether2"})),
            ("ip.pool.add", json!({"name": "lan", "ranges": "192.168.88.10-192.168.88.50"})),
            ("ip.dhcp-server.add", srv),
            ("ip.dhcp-server.network.add", json!({"address": "192.168.88.0/24", "gateway": "192.168.88.1"})),
        ] {
            ok(&mut s, id, p);
        }
        let clock = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let c2 = clock.clone();
        let core = Core::with_clock(Box::new(move || c2.load(std::sync::atomic::Ordering::Relaxed)));
        s.set_ipoe_backend(Arc::new(Backend(core.clone())));
        s.set_ipoe_sessions(Arc::new(Sessions(core.clone())));
        let aaa = Arc::new(FakeAaa::default());
        let mut lab = Lab { s, core, aaa, ms: 0, clock };
        lab.configure();
        lab
    }

    fn configure(&mut self) {
        let a: Arc<dyn AaaBackend> = self.aaa.clone();
        self.core.configure(self.s.store().running(), Some(a));
    }

    fn run(&mut self, secs: u64) {
        for _ in 0..secs * 4 {
            self.ms += 250;
            self.clock.store(self.ms, std::sync::atomic::Ordering::Relaxed);
            self.s.tick(1_700_000_000 + self.ms / 1000);
            self.s.dhcp_service(self.ms);
        }
    }

    fn active(&mut self) -> Vec<Value> {
        ok(&mut self.s, "ppp.active.list", json!({}))["rows"].as_array().unwrap().clone()
    }
}

#[test]
fn radius_makes_sessions_with_rates_and_accounting() {
    let mut lab = Lab::new(json!({"use_radius": "yes"}));
    lab.core.set_xdp(true);
    lab.run(20);
    let rows = lab.active();
    assert_eq!(rows.len(), 2, "the two RADIUS users: {rows:?}");
    for r in &rows {
        assert_eq!(r["service"], "ipoe");
        assert_eq!(r["radius"], true);
        assert_eq!(r["rate_limit"], "10M/50M");
    }
    // Framed-IP-Address and Session-Timeout (the lease time).
    let fixed = rows.iter().find(|r| r["caller_id"] == "02:1A:B0:02:00:02").unwrap();
    assert_eq!(fixed["address"], "192.168.88.200");
    // What went to RADIUS: the MAC, service dhcp, Ethernet, an empty password.
    let asks = lab.aaa.asks.lock().unwrap().clone();
    assert!(asks.len() >= 4, "every lab host was asked: {}", asks.len());
    let a = &asks[0];
    assert_eq!(a.service, corerouter_model::radius::AaaService::Dhcp);
    assert_eq!(a.calling_station_id.as_deref(), Some(a.user.as_str()));
    assert!(a.attributes.iter().any(|x| x.name == "NAS-Port-Type" && x.value == "15"));
    // Accounting: a Start per session, Class back, the interim of the Accept.
    let accts = lab.aaa.accts.lock().unwrap().clone();
    let starts: Vec<_> = accts.iter().filter(|r| r.status == AcctStatus::Start).collect();
    assert_eq!(starts.len(), 2);
    assert_eq!(starts[0].interim_secs, Some(300));
    assert_eq!(starts[0].class, vec![b"plano-50".to_vec()]);
    // The XDP map: an IPoE entry per session, from the top slots.
    let ops = lab.core.take_ops();
    assert_eq!(ops.iter().filter(|o| matches!(o, XdpOp::Upsert { .. })).count(), 2, "{ops:?}");
    assert!(ops.iter().all(|o| matches!(o, XdpOp::Upsert { slot, .. } if *slot > 1 << 16)));
    // The rejected hosts: "Why?" says RADIUS refused them.
    let why = ok(&mut lab.s, "ppp.why", json!({"name": "02:1A:B0:02:00:03"}));
    assert_eq!(why["last"]["reason"], "rejected", "{why}");
    assert!(why["last"]["reply_message"].as_str().unwrap_or("").contains("Inadimplente"), "{why}");
}

#[test]
fn removing_a_session_ends_its_lease_and_accounts_it() {
    let mut lab = Lab::new(json!({"use_radius": "yes"}));
    lab.run(20);
    let rows = lab.active();
    let id = rows[0]["id"].as_str().unwrap().to_owned();
    ok(&mut lab.s, "ppp.active.remove", json!({"id": id}));
    lab.run(2);
    let stops: Vec<_> = lab.aaa.accts.lock().unwrap().iter().filter(|r| r.status == AcctStatus::Stop).cloned().collect();
    assert_eq!(stops.len(), 1);
    assert_eq!(stops[0].terminate_cause, Some(6), "Admin-Reset");
    let h = ok(&mut lab.s, "ppp.history", json!({"event": "down"}));
    assert!(h.to_string().contains("admin-reset"), "{h}");
    // The client comes back (its renewal is NAKed, it starts over).
    lab.run(400);
    assert_eq!(lab.active().len(), 2, "back after the disconnect");
}

#[test]
fn coa_changes_the_rate_and_disconnect_ends_it() {
    let mut lab = Lab::new(json!({"use_radius": "yes"}));
    lab.core.set_xdp(true);
    lab.run(20);
    let _ = lab.core.take_ops();
    let owner = Owner(lab.core.clone());
    let req = |kind, changes: Vec<Attribute>| CoaRequest {
        kind,
        from: "127.0.0.1:3799".parse().unwrap(),
        selector: CoaSelector { user_name: Some("02:1A:B0:02:00:01".into()), ..CoaSelector::default() },
        changes,
        authorize_only: false,
        packet: Vec::new(),
    };
    assert_eq!(owner.handle(&req(CoaKind::Coa, vec![Attribute::new("Mikrotik-Rate-Limit", "2M/4M")])), CoaOutcome::Ack);
    assert!(matches!(lab.core.take_ops().as_slice(), [XdpOp::Upsert { up, .. }] if up.rate_bps == 2_000_000));
    assert_eq!(owner.handle(&req(CoaKind::Coa, vec![Attribute::new("Mikrotik-Rate-Limit", "lento")])), CoaOutcome::Nak(407));
    let mut nobody = req(CoaKind::Disconnect, Vec::new());
    nobody.selector.user_name = Some("ninguem".into());
    assert_eq!(owner.handle(&nobody), CoaOutcome::NotMine);
    assert_eq!(owner.handle(&req(CoaKind::Disconnect, Vec::new())), CoaOutcome::Ack);
    lab.run(2);
    assert_eq!(lab.active().len(), 1);
    assert!(lab.core.take_ops().iter().any(|o| matches!(o, XdpOp::Remove(_))));
}

#[test]
fn local_secrets_and_lease_rates_without_radius() {
    let mut lab = Lab::new(json!({"ipoe": true, "ipoe_unknown": "reject"}));
    ok(&mut lab.s, "ppp.profile.add", json!({"name": "p20", "rate_limit": "20M/20M"}));
    ok(&mut lab.s, "ppp.secret.add", json!({"name": "02:1A:B0:02:00:01", "service": "ipoe", "profile": "p20"}));
    ok(&mut lab.s, "ppp.secret.add", json!({"name": "02:1A:B0:02:00:03", "service": "ipoe"}));
    ok(&mut lab.s, "ip.dhcp-server.lease.add", json!({"address": "192.168.88.33", "mac_address": "02:1A:B0:02:00:03", "rate_limit": "3M/3M"}));
    lab.configure();
    lab.run(20);
    let rows = lab.active();
    assert_eq!(rows.len(), 2, "{rows:?}");
    let by = |m: &str| rows.iter().find(|r| r["caller_id"] == m).unwrap().clone();
    assert_eq!(by("02:1A:B0:02:00:01")["rate_limit"], "20M/20M");
    assert_eq!(by("02:1A:B0:02:00:01")["profile"], "p20");
    assert_eq!(by("02:1A:B0:02:00:03")["rate_limit"], "3M/3M");
    assert_eq!(by("02:1A:B0:02:00:03")["radius"], false);
    // No RADIUS: nobody asked, no accounting.
    assert!(lab.aaa.asks.lock().unwrap().is_empty());
    assert!(lab.aaa.accts.lock().unwrap().is_empty());
    let why = ok(&mut lab.s, "ppp.why", json!({"mac": "02:1A:B0:02:00:02"}));
    assert_eq!(why["last"]["reason"], "not-authorized", "{why}");
}

#[test]
fn the_keepalive_pings_and_ends_a_silent_subscriber() {
    let mut lab = Lab::new(json!({"ipoe": true, "ipoe_keepalive": "30s"}));
    lab.run(15);
    let n = lab.active().len();
    assert!(n >= 3, "{n}");
    // The lab's hosts answer ARP for their own address (RFC 5227): pinged
    // after 30 s of silence, they answer and stay.
    for _ in 0..60 {
        lab.core.keepalive();
        lab.run(1);
    }
    assert_eq!(lab.active().len(), n, "answering hosts stay");
    // Pings that get no answer (the replies never reach the core here: the
    // DHCP server's round, which carries them, does not run): three, 10 s
    // apart, then the session ends with "keepalive".
    for _ in 0..50 {
        lab.ms += 1000;
        lab.clock.store(lab.ms, std::sync::atomic::Ordering::Relaxed);
        lab.core.keepalive();
    }
    lab.run(1);
    let h = ok(&mut lab.s, "ppp.history", json!({"event": "down"}));
    assert!(h.to_string().contains("keepalive"), "{h}");
    assert!(lab.active().len() < n);
}

/// The XDP slots of the two services never meet: PPPoE the lower half of
/// the session map, IPoE the upper one.
#[test]
fn ipoe_and_pppoe_slots_are_disjoint() {
    use super::ipoe_bng::{SLOT_TOP, SLOTS};
    use super::pppoe_bng::XDP_SLOTS;
    let ipoe_lowest = SLOT_TOP + 1 - SLOTS;
    assert!(XDP_SLOTS <= ipoe_lowest, "PPPoE below {XDP_SLOTS}, IPoE from {ipoe_lowest}");
    assert_eq!(SLOT_TOP, (1 << 17) - 1, "the top of SESSIONS_MAX");
}

/// `ppp.active.list` pages the IPoE half in place: sorted by name, the
/// total of all, only `limit` copied.
#[test]
fn the_ipoe_half_pages_in_place() {
    use corerouter_engine::ppp::PppBackend;
    let mut lab = Lab::new(json!({"ipoe": true}));
    lab.run(20);
    let s = Sessions(lab.core.clone());
    let all = s.active().len();
    assert!(all >= 3, "{all}");
    let (total, page) = s.active_page(&|_| true, 2);
    assert_eq!((total, page.len()), (all, 2));
    assert!(page[0].name <= page[1].name);
    let mut names: Vec<_> = s.active().into_iter().map(|a| a.name).collect();
    names.sort();
    assert_eq!(page[0].name, names[0]);
    assert_eq!(s.sessions_by_server().get("dhcp1"), Some(&all));
}

/// G4.3cd: a business IPoE subscriber's routed block (`routes` of its
/// secret): the LPM entry after the session's, a kernel route via the
/// subscriber (the kernel forwards IPoE downstream), IPv6 refused (IPoE is
/// IPv4), and all of it gone, before the session, when it ends.
#[test]
fn routed_blocks_follow_the_ipoe_session() {
    let mut lab = Lab::new(json!({"ipoe": true, "ipoe_unknown": "reject"}));
    ok(&mut lab.s, "ppp.secret.add", json!({"name": "02:1A:B0:02:00:01", "service": "ipoe", "routes": "203.0.113.8/29,2001:db8:100::/48"}));
    lab.configure();
    lab.core.set_xdp(true);
    lab.run(20);
    let rows = lab.active();
    let r = rows.iter().find(|r| r["caller_id"] == "02:1A:B0:02:00:01").unwrap().clone();
    assert_eq!(r["routes"][0]["route"], "203.0.113.8/29", "{r}");
    assert_eq!(r["routes"][0]["origin"], "secret");
    assert!(r["refused_routes"][0].as_str().unwrap().contains("G4.3s"), "{r}");
    let ip: std::net::Ipv4Addr = r["address"].as_str().unwrap().parse().unwrap();
    let ops = lab.core.take_ops();
    let up = ops.iter().position(|o| matches!(o, XdpOp::Upsert { ip: a, .. } if *a == ip)).unwrap();
    let route = ops.iter().position(|o| matches!(o, XdpOp::Route { add: true, .. })).unwrap();
    assert!(up < route, "{ops:?}");
    let k = lab.core.take_kernel_routes();
    assert_eq!(k.len(), 1);
    assert_eq!((k[0].dst.to_string(), k[0].via, k[0].add), ("203.0.113.8/29".to_owned(), ip, true));
    assert!(lab.core.take_logs().iter().any(|(e, t)| *e && t.contains("rota recusada")));
    ok(&mut lab.s, "ppp.active.remove", json!({"id": r["id"]}));
    lab.run(2);
    let ops = lab.core.take_ops();
    let gone = ops.iter().position(|o| matches!(o, XdpOp::Route { add: false, .. })).unwrap();
    let removed = ops.iter().position(|o| matches!(o, XdpOp::Remove(_))).unwrap();
    assert!(gone < removed, "{ops:?}");
    let k = lab.core.take_kernel_routes();
    assert!(k.iter().any(|x| !x.add && x.dst.to_string() == "203.0.113.8/29"), "{k:?}");
}

/// G4.3cd: a CoA with `Framed-Route` changes an IPoE subscriber's blocks
/// without ending the lease; an invalid one is refused whole (NAK 407).
#[test]
fn coa_changes_ipoe_routes() {
    let mut lab = Lab::new(json!({"use_radius": "yes"}));
    lab.run(20);
    let _ = lab.core.take_kernel_routes();
    let owner = Owner(lab.core.clone());
    let coa = |routes: &[&str]| CoaRequest {
        kind: CoaKind::Coa,
        from: "127.0.0.1:3799".parse().unwrap(),
        selector: CoaSelector { user_name: Some("02:1A:B0:02:00:01".into()), ..CoaSelector::default() },
        changes: routes.iter().map(|r| Attribute::new("Framed-Route", *r)).collect(),
        authorize_only: false,
        packet: Vec::new(),
    };
    assert_eq!(owner.handle(&coa(&["127.0.0.0/8"])), CoaOutcome::Nak(407));
    assert_eq!(owner.handle(&coa(&["192.168.88.0/29"])), CoaOutcome::Nak(407), "holds the router's 192.168.88.1");
    assert!(lab.core.take_kernel_routes().is_empty());
    assert_eq!(owner.handle(&coa(&["203.0.113.8/29"])), CoaOutcome::Ack);
    assert_eq!(owner.handle(&coa(&["203.0.113.64/29"])), CoaOutcome::Ack);
    let k: Vec<String> = lab.core.take_kernel_routes().iter().map(|k| format!("{}{}", if k.add { "+" } else { "-" }, k.dst)).collect();
    assert_eq!(k, ["+203.0.113.8/29", "+203.0.113.64/29", "-203.0.113.8/29"]);
    let row = lab.active().into_iter().find(|r| r["caller_id"] == "02:1A:B0:02:00:01").unwrap();
    assert_eq!(row["routes"][0]["route"], "203.0.113.64/29");
    lab.run(2);
    assert_eq!(lab.active().len(), 2, "no lease ended");
}

// ---- G4.3hd: the redundant pair ---------------------------------------------

impl Lab {
    /// A pair member in hot standby, its DHCP answering or not.
    fn paired(answering: bool) -> Self {
        let mut lab = Lab::new(json!({"use_radius": "yes"}));
        ok(
            &mut lab.s,
            "ppp.redundancy.set",
            json!({"enabled": true, "mode": "hot-standby", "peer": "10.9.0.2:8730", "secret": "segredo-do-par-123", "interfaces": ["ether2"], "witness": ["192.168.88.254"]}),
        );
        lab.configure();
        lab.core.set_answering(answering);
        lab
    }

    fn bound(&mut self) -> usize {
        ok(&mut self.s, "ip.dhcp-server.lease.print", json!({"status": "bound"}))
            .as_array()
            .map_or(0, Vec::len)
    }
}

fn ipoe_records(changes: &[super::ipoe_bng::ha::IpoeHaChange]) -> Vec<corerouter_proto_ha::record::SessionRecord> {
    changes
        .iter()
        .filter_map(|c| match c {
            super::ipoe_bng::ha::IpoeHaChange::Up(_, v) => corerouter_proto_ha::record::SessionRecord::decode(v).ok(),
            _ => None,
        })
        .collect()
}

#[test]
fn the_standby_is_silent_and_adopts_the_ipoe_sessions_with_their_leases() {
    // A, the active: two RADIUS subscribers, published with their leases.
    let mut a = Lab::paired(true);
    a.run(20);
    assert_eq!(a.active().len(), 2);
    let published = ipoe_records(&a.core.ha_take());
    assert_eq!(published.len(), 2, "one record per session");
    for r in &published {
        assert_eq!(r.kind, corerouter_proto_ha::record::Kind::Ipoe);
        let l = r.lease.as_ref().expect("the DHCP binding");
        assert!(l.expires > 1_700_000_000 && l.lease_time > 0, "{l:?}");
        assert_eq!(r.class, vec![b"plano-50".to_vec().into_boxed_slice()]);
    }
    let starts = a.aaa.accts.lock().unwrap().iter().filter(|r| r.status == AcctStatus::Start).count();
    assert_eq!(starts, 2);

    // C, the standby: the same lab hosts ask, nobody is answered.
    let mut c = Lab::paired(false);
    c.run(20);
    assert_eq!((c.active().len(), c.bound()), (0, 0), "the standby's DHCP stays silent");
    assert!(c.aaa.asks.lock().unwrap().is_empty(), "nor asks RADIUS");

    // A dies: C adopts the sessions and their bindings, then answers.
    let done = c.core.adopt(1, &published);
    assert_eq!((done.sessions, done.skipped), (2, 0));
    assert_eq!(c.core.adopt(1, &published).sessions, 0, "a takeover is adopted once");
    c.core.set_answering(true);
    c.core.set_xdp(true);
    let pings = super::ipoe_bng::Backend(c.core.clone());
    assert_eq!(corerouter_engine::ipoe::IpoeBackend::pings(&pings).len(), 2, "an ARP ping to each adopted subscriber");
    c.run(1);
    assert_eq!(c.bound(), 2, "the bindings are the DHCP server's");
    let rows = c.active();
    assert_eq!(rows.len(), 2);
    let mut x: Vec<_> = published.iter().map(|r| (r.ipv4, r.acct_session_id.to_string())).collect();
    x.sort();
    // The clients go on (renew, or start over and get the same address):
    // no new session, no Start; one Interim each with the same id.
    c.run(700);
    assert_eq!(c.active().len(), 2, "the same two sessions");
    let accts = c.aaa.accts.lock().unwrap().clone();
    assert_eq!(accts.iter().filter(|r| r.status == AcctStatus::Start).count(), 0, "{accts:?}");
    assert_eq!(accts.iter().filter(|r| r.status == AcctStatus::Stop).count(), 0, "{accts:?}");
    let mut y: Vec<_> = accts
        .iter()
        .filter(|r| r.status == AcctStatus::InterimUpdate)
        .map(|r| (r.attributes.iter().find(|a| a.name == "Framed-IP-Address").and_then(|a| a.value.parse().ok()), r.session_id.clone()))
        .collect();
    y.sort();
    assert_eq!(x, y, "an Interim per adopted session, the same Acct-Session-Id");
    assert!(accts.iter().all(|r| r.class == [b"plano-50".to_vec()]), "the Class goes on");
    let h = ok(&mut c.s, "ppp.history", json!({}));
    assert!(h.to_string().contains("takeover"), "{h}");
    // C publishes them as its own.
    assert_eq!(ipoe_records(&c.core.ha_take()).len(), 2);

    // A, now the standby: its sessions end without a Stop.
    a.core.abandon();
    a.core.set_answering(false);
    assert_eq!(a.active().len(), 0);
    assert_eq!(a.aaa.accts.lock().unwrap().iter().filter(|r| r.status == AcctStatus::Stop).count(), 0);
}
