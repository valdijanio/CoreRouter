//! G0.22 — the incremental commit validates only the units that read a
//! changed section. These tests make a missed dependency fail here instead
//! of letting a bad config be committed:
//!
//! - each unit answers the same on a config restricted to the sections it
//!   declares (`sections::restrict`) as on the whole config, over a corpus
//!   of configs (a rich one built by commands, and that one with random
//!   items removed, so references dangle and validators speak);
//! - random changes to a valid config, validated incrementally (only the
//!   units whose sections changed) and in full, give the same issues.

// Shared helpers are not `#[test]` fns, so clippy's in-tests allowances skip them.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use corerouter_engine::Session;
use corerouter_engine::validate::{UNITS, validate_all, validate_changed, validate_commit};
use corerouter_model::Config;
use corerouter_model::sections::{Sections, changed, restrict};
use proptest::prelude::*;
use serde_json::{Value, json};

/// A config that uses a bit of everything, built through the commands.
fn rich() -> Config {
    let mut s = Session::virtual_lab();
    let steps: Vec<(&str, Value)> = vec![
        (
            "interface.vlan.add",
            json!({"name": "vlan10", "parent": "ether2", "vlan_id": 10}),
        ),
        ("interface.bridge.add", json!({"name": "br-lan"})),
        (
            "interface.bridge.port.add",
            json!({"bridge": "br-lan", "interface": "ether3"}),
        ),
        (
            "interface.bridge.port.add",
            json!({"bridge": "br-lan", "interface": "ether4"}),
        ),
        (
            "ip.vrf.add",
            json!({"name": "cust", "interfaces": "ether5"}),
        ),
        (
            "interface.bonding.add",
            json!({"name": "bond1", "slaves": "ether6,ether7", "mode": "802.3ad"}),
        ),
        (
            "interface.list.member.add",
            json!({"list": "LAN", "interface": "br-lan"}),
        ),
        (
            "interface.list.member.add",
            json!({"list": "WAN", "interface": "ether1"}),
        ),
        (
            "ip.address.add",
            json!({"address": "198.51.100.2/30", "interface": "ether1"}),
        ),
        (
            "ip.address.add",
            json!({"address": "192.168.88.1/24", "interface": "br-lan"}),
        ),
        (
            "ip.address.add",
            json!({"address": "10.10.0.1/24", "interface": "vlan10"}),
        ),
        (
            "ip.address.add",
            json!({"address": "10.20.0.1/24", "interface": "ether5"}),
        ),
        (
            "ip.address.add",
            json!({"address": "10.30.0.1/24", "interface": "bond1"}),
        ),
        (
            "ip.address.add",
            json!({"address": "2001:db8:1::1/64", "interface": "br-lan"}),
        ),
        (
            "ip.route.add",
            json!({"dst_address": "0.0.0.0/0", "gateway": "198.51.100.1"}),
        ),
        (
            "ip.route.add",
            json!({"dst_address": "172.16.0.0/16", "gateway": "10.10.0.2"}),
        ),
        (
            "ip.route.add",
            json!({"dst_address": "172.17.0.0/16", "gateway": "10.20.0.2", "routing_table": "cust"}),
        ),
        (
            "ip.route.add",
            json!({"dst_address": "172.18.0.0/16", "gateway": "vlan10"}),
        ),
        (
            "ip.firewall.address-list.add",
            json!({"list": "blocked", "address": "203.0.113.0/24"}),
        ),
        (
            "ip.firewall.address-list.add",
            json!({"list": "mgmt", "address": "192.168.88.10"}),
        ),
        (
            "ip.firewall.filter.add",
            json!({"chain": "input", "action": "accept", "connection_state": "established,related"}),
        ),
        (
            "ip.firewall.filter.add",
            json!({"chain": "input", "action": "accept", "src_address_list": "mgmt", "in_interface_list": "LAN"}),
        ),
        (
            "ip.firewall.filter.add",
            json!({"chain": "forward", "action": "jump", "jump_target": "cust"}),
        ),
        (
            "ip.firewall.filter.add",
            json!({"chain": "cust", "action": "drop", "src_address_list": "blocked"}),
        ),
        (
            "ip.firewall.filter.add",
            json!({"chain": "forward", "action": "drop", "in_interface": "ether1", "out_interface": "vlan10"}),
        ),
        (
            "ip.firewall.nat.add",
            json!({"chain": "srcnat", "action": "masquerade", "out_interface_list": "WAN"}),
        ),
        (
            "ip.firewall.nat.add",
            json!({"chain": "dstnat", "action": "dst-nat", "protocol": "tcp", "dst_port": "8080", "to_addresses": "192.168.88.10", "in_interface": "ether1"}),
        ),
        (
            "ip.firewall.mangle.add",
            json!({"chain": "prerouting", "action": "mark-connection", "new_connection_mark": "lan", "in_interface": "br-lan"}),
        ),
        (
            "ip.pool.add",
            json!({"name": "lan", "ranges": "192.168.88.100-192.168.88.200"}),
        ),
        (
            "ip.pool.add",
            json!({"name": "pppoe", "ranges": "100.64.0.0/22"}),
        ),
        (
            "ip.dhcp-server.add",
            json!({"name": "dhcp1", "interface": "br-lan", "address_pool": "lan"}),
        ),
        (
            "ip.dhcp-server.network.add",
            json!({"address": "192.168.88.0/24", "gateway": "192.168.88.1"}),
        ),
        (
            "ip.dhcp-server.lease.add",
            json!({"address": "192.168.88.50", "mac_address": "02:00:00:00:00:50", "server": "dhcp1"}),
        ),
        (
            "ip.dhcp-server.option.add",
            json!({"name": "tftp", "code": 66, "value": "'10.0.0.1'"}),
        ),
        (
            "ip.dhcp-server.option-set.add",
            json!({"name": "phones", "options": "tftp"}),
        ),
        (
            "ip.dns.set",
            json!({"servers": ["1.1.1.1"], "allow_remote_requests": true}),
        ),
        (
            "ip.dns.static.add",
            json!({"name": "router.lan", "address": "192.168.88.1"}),
        ),
        (
            "ip.dns.forwarders.add",
            json!({"name": "corp", "dns_servers": ["10.0.0.53"]}),
        ),
        (
            "ip.dns.static.add",
            json!({"name": "corp.example", "type": "FWD", "forward_to": "corp"}),
        ),
        ("ip.dns.zone.add", json!({"name": "example.com"})),
        (
            "ip.dns.zone.record.add",
            json!({"zone": "example.com", "name": "www", "address": "192.168.88.10"}),
        ),
        (
            "ip.firewall.cgnat.pool.add",
            json!({"name": "cg", "inside": "100.64.0.0/22", "outside": "198.51.100.64/28", "out_interface": "ether1"}),
        ),
        (
            "ip.firewall.cgnat.exception.add",
            json!({"subscriber": "100.64.9.9", "public": "198.51.100.99"}),
        ),
        ("ip.firewall.fastpath.set", json!({"enabled": true})),
        (
            "ipv6.pool.add",
            json!({"name": "pd", "prefix": "2001:db8:100::/40", "prefix_length": 56}),
        ),
        (
            "ipv6.dhcp-server.add",
            json!({"name": "v6", "interface": "br-lan", "prefix_pool": "pd"}),
        ),
        (
            "ipv6.settings.set",
            json!({"accept_router_advertisements": "no"}),
        ),
        (
            "routing.bgp.instance.set",
            json!({"asn": 65000, "router_id": "198.51.100.2"}),
        ),
        (
            "ip.neighbor.discovery.set",
            json!({"enabled": true, "interfaces": ["ether1", "br-lan"]}),
        ),
        (
            "system.ntp.client.set",
            json!({"enabled": true, "servers": ["pool.ntp.org"]}),
        ),
        (
            "radius.add",
            json!({"address": "10.0.0.9", "service": "ppp,dhcp", "secret": "s"}),
        ),
        (
            "ppp.profile.add",
            json!({"name": "plan", "local_address": "100.64.255.1", "remote_address": "pppoe", "rate_limit": "10M/50M"}),
        ),
        (
            "ppp.secret.add",
            json!({"name": "ana", "password": "x", "profile": "plan"}),
        ),
        (
            "ppp.secret.add",
            json!({"name": "biz", "password": "x", "profile": "plan", "remote_address": "100.64.3.3", "routes": "203.0.113.64/29"}),
        ),
        (
            "interface.pppoe-server.server.add",
            json!({"interface": "vlan10", "service_name": "isp", "default_profile": "plan"}),
        ),
        (
            "queue.simple.add",
            json!({"name": "q1", "target": "192.168.88.50", "max_limit": "10M/10M"}),
        ),
    ];
    let mut ok = 0;
    for (id, p) in &steps {
        match s.execute(id, p) {
            Ok(_) => ok += 1,
            Err(e) => eprintln!("rich config: {id} {p}: {e}"),
        }
    }
    // The corpus must stay rich as commands change.
    assert!(
        ok * 10 >= steps.len() * 8,
        "only {ok} of {} steps applied",
        steps.len()
    );
    s.store().running().clone()
}

/// `cfg` with every `k`-th item of the big lists gone, so references to
/// them dangle (and the validators that follow them speak).
fn thinned(cfg: &Config, k: usize) -> Config {
    let mut c = cfg.clone();
    let mut n = 0usize;
    let mut drop = |_: &dyn std::any::Any| {
        n += 1;
        n.is_multiple_of(k)
    };
    c.ip.addresses.retain(|x| !drop(x));
    c.ip.routes.retain(|x| !drop(x));
    c.ip.firewall.filter.retain(|x| !drop(x));
    c.ip.firewall.address_lists.retain(|x| !drop(x));
    c.ip.pools.pools.retain(|x| !drop(x));
    c.ppp.profiles.retain(|x| !drop(x));
    let names: Vec<_> = c.interfaces.keys().cloned().collect();
    for (i, name) in names.iter().enumerate() {
        if i % k == k - 1 && name.as_str() != "ether1" {
            c.interfaces.remove(name);
        }
    }
    c
}

/// The rich config, thinned, and broken every way [`Change`] knows (each
/// change at several items), so every section has something to complain
/// about in some config.
fn corpus() -> Vec<Config> {
    let base = rich();
    let mut out = vec![base.clone(), corerouter_firewall::sample::sample()];
    for k in 2..6 {
        out.push(thinned(&base, k));
    }
    for i in 0..16 {
        for ch in every_change(i) {
            let mut c = base.clone();
            apply(&mut c, &ch);
            out.push(c);
        }
    }
    out
}

fn every_change(i: usize) -> Vec<Change> {
    vec![
        Change::DropInterface(i),
        Change::InterfaceMtu(i, 20),
        Change::DisableInterface(i),
        Change::DropAddress(i),
        Change::AddressOn(i),
        Change::DropRoute(i),
        Change::DropRule(i),
        Change::DropListEntry(i),
        Change::DropPool(i),
        Change::DropProfile(i),
        Change::DropList(i),
        Change::NtpPoll(u8::try_from(i).unwrap_or(0) + 20),
    ]
}

#[test]
fn each_unit_reads_only_what_it_declares() {
    let mut missing = Vec::new();
    for cfg in corpus() {
        for u in UNITS {
            let full = (u.run)(&cfg);
            // Each section alone: blanking one it does not declare must not
            // change its answer.
            for s in Sections::ALL.each() {
                if u.reads.contains(s) {
                    continue;
                }
                let without = restrict(&cfg, Sections::ALL.union(Sections::NONE).without(s));
                if (u.run)(&without) != full {
                    missing.push(format!("{} reads {s:?}", u.name));
                }
            }
            if (u.run)(&restrict(&cfg, u.reads)) != full {
                missing.push(format!(
                    "{} restricted to {:?} answers otherwise",
                    u.name, u.reads
                ));
            }
        }
    }
    missing.sort();
    missing.dedup();
    assert!(missing.is_empty(), "undeclared reads: {missing:#?}");
}

#[test]
fn the_rich_config_is_valid_and_restricting_nothing_changes_nothing() {
    let cfg = rich();
    assert_eq!(validate_all(&cfg), Vec::new());
    assert_eq!(
        changed(&cfg, &restrict(&cfg, Sections::ALL)),
        Sections::NONE
    );
}

/// A random change to one part of the config.
#[derive(Debug, Clone)]
enum Change {
    DropInterface(usize),
    InterfaceComment(usize),
    InterfaceMtu(usize, u16),
    DisableInterface(usize),
    DropAddress(usize),
    AddressOn(usize),
    DropRoute(usize),
    /// G0.31e: a copy of a route (a duplicate), or one with another
    /// gateway, destination with host bits or distance 0.
    CopyRoute(usize, u8),
    DropRule(usize),
    DropListEntry(usize),
    DropPool(usize),
    DropProfile(usize),
    DropList(usize),
    ClearDhcp,
    ClearDnsStatic,
    ClearZones,
    ClearCgnat,
    NtpPoll(u8),
    ClearRouting,
    ClearIpv6,
    ClearPppoe,
    ClearRadius,
    ClearQueue,
    ClearSecrets,
}

fn change() -> impl Strategy<Value = Change> {
    prop_oneof![
        any::<usize>().prop_map(Change::DropInterface),
        any::<usize>().prop_map(Change::InterfaceComment),
        (any::<usize>(), 0u16..10_000).prop_map(|(i, m)| Change::InterfaceMtu(i, m)),
        any::<usize>().prop_map(Change::DisableInterface),
        any::<usize>().prop_map(Change::DropAddress),
        any::<usize>().prop_map(Change::AddressOn),
        any::<usize>().prop_map(Change::DropRoute),
        (any::<usize>(), 0u8..5).prop_map(|(i, how)| Change::CopyRoute(i, how)),
        any::<usize>().prop_map(Change::DropRule),
        any::<usize>().prop_map(Change::DropListEntry),
        any::<usize>().prop_map(Change::DropPool),
        any::<usize>().prop_map(Change::DropProfile),
        any::<usize>().prop_map(Change::DropList),
        Just(Change::ClearDhcp),
        Just(Change::ClearDnsStatic),
        Just(Change::ClearZones),
        Just(Change::ClearCgnat),
        (0u8..30).prop_map(Change::NtpPoll),
        Just(Change::ClearRouting),
        Just(Change::ClearIpv6),
        Just(Change::ClearPppoe),
        Just(Change::ClearRadius),
        Just(Change::ClearQueue),
        Just(Change::ClearSecrets),
    ]
}

fn apply(c: &mut Config, ch: &Change) {
    let pick = |n: usize, i: usize| (n > 0).then(|| i % n);
    match *ch {
        Change::DropInterface(i) => {
            if let Some(k) =
                pick(c.interfaces.len(), i).and_then(|k| c.interfaces.keys().nth(k).cloned())
            {
                c.interfaces.remove(&k);
            }
        }
        Change::InterfaceComment(i) => {
            if let Some(k) =
                pick(c.interfaces.len(), i).and_then(|k| c.interfaces.keys().nth(k).cloned())
                && let Some(x) = c.interfaces.get_mut(&k)
            {
                x.comment = format!("c{i}");
            }
        }
        Change::InterfaceMtu(i, m) => {
            if let Some(k) =
                pick(c.interfaces.len(), i).and_then(|k| c.interfaces.keys().nth(k).cloned())
                && let Some(x) = c.interfaces.get_mut(&k)
            {
                x.mtu = m;
            }
        }
        Change::DisableInterface(i) => {
            if let Some(k) =
                pick(c.interfaces.len(), i).and_then(|k| c.interfaces.keys().nth(k).cloned())
                && let Some(x) = c.interfaces.get_mut(&k)
            {
                x.disabled = !x.disabled;
            }
        }
        Change::DropAddress(i) => {
            if let Some(k) = pick(c.ip.addresses.len(), i) {
                c.ip.addresses.remove(k);
            }
        }
        Change::AddressOn(i) => {
            if let Some(k) =
                pick(c.interfaces.len(), i).and_then(|k| c.interfaces.keys().nth(k).cloned())
            {
                let id = c.ip.next_address_id();
                let octet = u8::try_from(i % 200).unwrap_or(0);
                c.ip.addresses.push(corerouter_model::AddressEntry {
                    id,
                    address: format!("10.99.{octet}.1/24").parse().unwrap(),
                    interface: k,
                    disabled: false,
                    comment: String::new(),
                    from_pool: None,
                });
            }
        }
        Change::DropRoute(i) => {
            if let Some(k) = pick(c.ip.routes.len(), i) {
                c.ip.routes.remove(k);
            }
        }
        Change::CopyRoute(i, how) => {
            if let Some(mut r) = pick(c.ip.routes.len(), i)
                .and_then(|k| c.ip.routes.get(k))
                .cloned()
            {
                r.id = c.ip.next_route_id();
                match how {
                    0 => {}
                    1 => r.gateway = "10.10.0.9".parse().unwrap(),
                    2 => r.gateway = "203.0.113.1".parse().unwrap(),
                    3 => r.dst_address = "172.16.0.1/16".parse().unwrap(),
                    _ => r.distance = 0,
                }
                c.ip.routes.push(r);
            }
        }
        Change::DropRule(i) => {
            if let Some(k) = pick(c.ip.firewall.filter.len(), i) {
                c.ip.firewall.filter.remove(k);
            }
        }
        Change::DropListEntry(i) => {
            if let Some(k) = pick(c.ip.firewall.address_lists.len(), i) {
                c.ip.firewall.address_lists.remove(k);
            }
        }
        Change::DropPool(i) => {
            if let Some(k) = pick(c.ip.pools.pools.len(), i) {
                c.ip.pools.pools.remove(k);
            }
        }
        Change::DropProfile(i) => {
            if let Some(k) = pick(c.ppp.profiles.len(), i) {
                c.ppp.profiles.remove(k);
            }
        }
        Change::DropList(i) => {
            if let Some(k) = pick(c.interface_lists.lists.len(), i) {
                c.interface_lists.lists.remove(k);
            }
        }
        Change::ClearDhcp => c.ip.dhcp_server = Default::default(),
        Change::ClearDnsStatic => c.ip.dns_static = Default::default(),
        Change::ClearZones => c.ip.dns_zones = Default::default(),
        Change::ClearCgnat => c.ip.cgnat = Default::default(),
        Change::NtpPoll(p) => c.system.ntp_client.min_poll = p,
        Change::ClearRouting => c.routing = Default::default(),
        Change::ClearIpv6 => c.ipv6 = Default::default(),
        Change::ClearPppoe => c.ppp.pppoe_servers.clear(),
        Change::ClearRadius => c.radius = Default::default(),
        Change::ClearQueue => c.queue = Default::default(),
        Change::ClearSecrets => c.ppp.secrets = Default::default(),
    }
}

fn sorted(mut v: Vec<corerouter_model::Issue>) -> Vec<String> {
    let mut out: Vec<String> = v.drain(..).map(|i| i.to_string()).collect();
    out.sort();
    out
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]
    /// Incremental validation of random changes to a valid config gives
    /// the issues of a full validation.
    #[test]
    fn incremental_equals_full(changes in proptest::collection::vec(change(), 1..5)) {
        thread_local! {
            static BASE: Config = rich();
        }
        let base = BASE.with(Clone::clone);
        let mut c = base.clone();
        for ch in &changes {
            apply(&mut c, ch);
        }
        let diff = changed(&base, &c);
        prop_assert_eq!(sorted(validate_changed(&c, diff)), sorted(validate_all(&c)), "changed {:?}", diff);
        // G0.31e: the commit's own validation, routes from the index: the
        // same issues in the same order.
        prop_assert_eq!(validate_commit(&base, &c, diff), validate_all(&c), "changed {:?}", diff);
    }
}
