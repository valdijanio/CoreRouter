//! fix-journal-routing-delta: every part of the config survives a restart
//! through the journal. OSPF, MPLS, BFD and RPKI were written as `{}` by
//! the typed revision delta (`config_delta::diff_routing` only knew BGP and
//! the filter) and came back empty after a restart.
//!
//! One command fills each field of each section; then the typed delta of
//! every commit must rebuild that commit (without the whole-tree fallback
//! of `persist::revision_delta`, which would hide a section the typed diff
//! misses), and a reboot from the journal must give the same config. A
//! field no command here fills fails the test by name: a new section gets
//! a command below (or a reason in `NOT_FILLED`).

// Shared helpers are not `#[test]` fns, so clippy's in-tests allowances skip them.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use corerouter_engine::sealing::{self, SealKey};
use corerouter_engine::{MemoryStorage, Session};
use corerouter_hal::VirtualHal;
use corerouter_model::config::{Config, Ip, Routing, System};
use corerouter_model::config_delta;
use corerouter_model::dhcp_server::DhcpServers;
use corerouter_model::dns_static::DnsStatic;
use corerouter_model::firewall::Firewall;
use corerouter_model::ipv6::Ipv6;
use corerouter_model::ppp::Ppp;
use corerouter_model::queue::Queues;
use serde::de::{self, Deserialize, Visitor};
use serde_json::{Value, json};

fn boot(storage: &MemoryStorage) -> Session {
    Session::with_storage(Box::new(VirtualHal::default()), Box::new(storage.clone()))
}

/// `config` with the PPP passwords opened: each session seals with its own
/// key and a random nonce (`config_journal.rs`).
fn opened(key: &SealKey, config: &Config) -> Config {
    let mut c = config.clone();
    for i in 0..c.ppp.secrets.len() {
        c.ppp.secrets.update(i, |x| {
            x.password = key.open(&x.password).unwrap_or_default().into();
        });
    }
    c
}

/// The commands that fill the config, one or more per field.
fn commands() -> Vec<(&'static str, Value)> {
    vec![
        // system
        ("system.identity.set", json!({"name": "sweep"})),
        (
            "system.ntp.client.set",
            json!({"enabled": true, "servers": ["192.0.2.123"]}),
        ),
        (
            "system.logging.action.add",
            json!({"name": "remote", "remote": "192.0.2.14"}),
        ),
        (
            "system.logging.add",
            json!({"topics": ["route"], "action": "remote"}),
        ),
        (
            "system.tuning.set",
            json!({"name": "net.core.netdev_budget", "value": 600}),
        ),
        ("ip.service.metrics.set", json!({"port": 9101})),
        ("system.analytics.set", json!({"database": "cr"})),
        ("tool.bandwidth-server.set", json!({"port": 2001})),
        ("system.graph.set", json!({"store_every": 600})),
        ("ip.service.www.set", json!({"port": 8081})),
        // interfaces and lists
        (
            "interface.vlan.add",
            json!({"name": "vlan10", "parent": "ether2", "vlan_id": 10}),
        ),
        ("interface.list.add", json!({"name": "LANS"})),
        (
            "interface.list.member.add",
            json!({"list": "LANS", "interface": "ether2"}),
        ),
        // ip
        (
            "ip.address.add",
            json!({"address": "192.0.2.1/24", "interface": "ether1"}),
        ),
        (
            "ip.address.add",
            json!({"address": "10.0.0.1/24", "interface": "ether2"}),
        ),
        (
            "ip.route.add",
            json!({"dst_address": "198.51.100.0/24", "gateway": "192.0.2.254"}),
        ),
        ("ip.neighbor.discovery.set", json!({"interval_secs": 60})),
        (
            "ip.firewall.filter.add",
            json!({"chain": "forward", "action": "accept", "comment": "sweep"}),
        ),
        (
            "ip.firewall.nat.add",
            json!({"chain": "srcnat", "action": "masquerade", "out_interface": "ether1"}),
        ),
        (
            "ip.firewall.mangle.add",
            json!({"chain": "prerouting", "action": "accept"}),
        ),
        (
            "ip.firewall.raw.add",
            json!({"chain": "prerouting", "action": "accept"}),
        ),
        (
            "ip.firewall.address-list.add",
            json!({"list": "l", "address": "10.9.0.1"}),
        ),
        (
            "ip.firewall.zone.set",
            json!({"from": "LANS", "to": "router", "action": "allow"}),
        ),
        ("ip.firewall.xdp.set", json!({"rate_limit": 1000})),
        (
            "ip.dns.adlist.add",
            json!({"url": "https://example.com/hosts"}),
        ),
        (
            "ip.dns.forwarders.add",
            json!({"name": "fw", "dns_servers": ["192.0.2.53"]}),
        ),
        ("ip.dhcp-client.add", json!({"interface": "vlan10"})),
        ("ip.dns.set", json!({"servers": ["192.0.2.53"]})),
        (
            "ip.dns.static.add",
            json!({"name": "r.lan", "address": "10.0.0.1"}),
        ),
        ("ip.dns.zone.add", json!({"name": "example.com"})),
        ("ip.dns.tsig-key.add", json!({"name": "k"})),
        (
            "ip.pool.add",
            json!({"name": "p", "ranges": "10.0.0.100-10.0.0.200"}),
        ),
        (
            "ip.dhcp-server.add",
            json!({"interface": "ether2", "address_pool": "p"}),
        ),
        (
            "ip.dhcp-server.network.add",
            json!({"address": "10.0.0.0/24", "gateway": "10.0.0.1"}),
        ),
        (
            "ip.dhcp-server.option.add",
            json!({"name": "o", "code": 66, "value": "'tftp'"}),
        ),
        (
            "ip.dhcp-server.option-set.add",
            json!({"name": "os", "options": "o"}),
        ),
        (
            "ip.dhcp-server.matcher.add",
            json!({"name": "m", "code": 60, "value": "'MSFT 5.0'", "option_set": "os"}),
        ),
        ("ip.dhcp-server.alert.add", json!({"interface": "ether2"})),
        (
            "ip.dhcp-server.config.set",
            json!({"history_retention": "30d"}),
        ),
        (
            "ip.dhcp-relay.add",
            json!({"interface": "vlan10", "dhcp_server": ["192.0.2.67"]}),
        ),
        (
            "ip.firewall.cgnat.pool.add",
            json!({"name": "c", "inside": "100.64.0.0/24", "outside": "203.0.113.0/29"}),
        ),
        ("ip.firewall.fastpath.set", json!({"enabled": true})),
        ("ip.traffic-flow.set", json!({"cache_entries": 2048})),
        ("ip.subscriber-notice.settings.set", json!({"port": 8881})),
        (
            "ip.arp.add",
            json!({"address": "10.0.0.9", "mac_address": "02:00:00:00:00:09", "interface": "ether2"}),
        ),
        // ipv6
        (
            "ipv6.settings.set",
            json!({"accept_router_advertisements": "no"}),
        ),
        (
            "ipv6.dhcp-client.add",
            json!({"interface": "ether1", "request": "address"}),
        ),
        ("ipv6.dhcp-server.add", json!({"interface": "ether2"})),
        ("ipv6.nd.add", json!({"interface": "ether2"})),
        // routing
        (
            "routing.bgp.instance.set",
            json!({"asn": 65000, "router_id": "10.255.0.1"}),
        ),
        (
            "routing.bgp.template.add",
            json!({"name": "t", "remote_as": 65001}),
        ),
        (
            "routing.bgp.connection.add",
            json!({"name": "n", "remote_address": "192.0.2.2", "remote_as": 65001}),
        ),
        (
            "routing.filter.rule.add",
            json!({"chain": "in", "rule": "if (dst in 10.0.0.0/8) { reject }"}),
        ),
        (
            "routing.rpki.add",
            json!({"name": "r", "address": "192.0.2.3"}),
        ),
        ("routing.bfd.profile.add", json!({"name": "bp"})),
        ("routing.bfd.peer.add", json!({"address": "192.0.2.4"})),
        (
            "routing.ospf.instance.add",
            json!({"name": "v2", "router_id": "10.255.0.1"}),
        ),
        (
            "routing.ospf.area.add",
            json!({"name": "bb", "instance": "v2", "area_id": "0.0.0.0"}),
        ),
        (
            "routing.ospf.interface-template.add",
            json!({"area": "bb", "interfaces": "ether1"}),
        ),
        ("routing.ospf.keychain.add", json!({"name": "kc"})),
        ("mpls.interface.add", json!({"interface": "ether1"})),
        ("mpls.ldp.add", json!({"lsr_id": "10.255.0.1"})),
        ("mpls.ldp.interface.add", json!({"interface": "ether1"})),
        (
            "mpls.settings.set",
            json!({"dynamic_label_range": "16-99999"}),
        ),
        (
            "mpls.static.add",
            json!({"label": 100000, "nexthop": "192.0.2.254", "out_labels": "200"}),
        ),
        // radius, ppp, queues
        (
            "radius.add",
            json!({"address": "192.0.2.5", "service": "ppp", "secret": "s"}),
        ),
        ("ppp.aaa.set", json!({"interim_update": 300})),
        ("ppp.profile.add", json!({"name": "pp"})),
        ("ppp.secret.add", json!({"name": "u", "password": "x"})),
        (
            "interface.pppoe-server.server.add",
            json!({"interface": "ether3"}),
        ),
        ("interface.pppoe-server.settings.set", json!({"workers": 2})),
        ("ppp.redundancy.set", json!({"group": 2})),
        ("queue.type.add", json!({"name": "q", "kind": "pfifo"})),
        (
            "queue.simple.add",
            json!({"target": "10.0.0.50", "max_limit": "10M/10M"}),
        ),
    ]
}

/// Fields no command above fills, each with the reason. Keep it short: a
/// field here is one the test cannot prove survives a restart.
const NOT_FILLED: &[(&str, &str)] = &[];

/// The field names of a struct, from its `Deserialize` (a deserializer
/// that only records what `deserialize_struct` is asked for).
fn fields<'de, T: Deserialize<'de>>() -> Vec<&'static str> {
    struct Names<'a>(&'a mut Vec<&'static str>);
    impl<'de> de::Deserializer<'de> for Names<'_> {
        type Error = de::value::Error;
        fn deserialize_any<V: Visitor<'de>>(self, _: V) -> Result<V::Value, Self::Error> {
            Err(de::Error::custom("not a struct"))
        }
        fn deserialize_struct<V: Visitor<'de>>(
            self,
            _: &'static str,
            fields: &'static [&'static str],
            _: V,
        ) -> Result<V::Value, Self::Error> {
            self.0.extend_from_slice(fields);
            Err(de::Error::custom("names only"))
        }
        serde::forward_to_deserialize_any! {
            bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
            bytes byte_buf option unit unit_struct newtype_struct seq tuple
            tuple_struct map enum identifier ignored_any
        }
    }
    let mut out = Vec::new();
    let _ = T::deserialize(Names(&mut out));
    assert!(
        !out.is_empty(),
        "{} is not a plain struct",
        std::any::type_name::<T>()
    );
    out
}

/// Each section the typed delta handles, by its path in the config JSON.
fn sections() -> Vec<(&'static str, Vec<&'static str>)> {
    vec![
        ("", fields::<Config>()),
        ("system", fields::<System>()),
        ("ipv6", fields::<Ipv6>()),
        ("ip", fields::<Ip>()),
        ("ip.firewall", fields::<Firewall>()),
        ("ip.dhcp_server", fields::<DhcpServers>()),
        ("ip.dns_static", fields::<DnsStatic>()),
        ("routing", fields::<Routing>()),
        ("ppp", fields::<Ppp>()),
        ("queue", fields::<Queues>()),
    ]
}

fn at<'a>(v: &'a Value, path: &str) -> &'a Value {
    path.split('.')
        .filter(|p| !p.is_empty())
        .fold(v, |v, p| v.get(p).unwrap_or(&Value::Null))
}

#[test]
fn every_section_survives_a_restart_through_the_journal() {
    let storage = MemoryStorage::default();
    let mut s = boot(&storage);
    for (id, params) in commands() {
        if let Err(e) = s.execute(id, &params) {
            panic!("{id} {params}: {e}");
        }
    }
    // Every field filled (a new one needs a command above).
    let now = serde_json::to_value(s.store().running()).unwrap();
    let empty = serde_json::to_value(Config::default()).unwrap();
    let mut missing = Vec::new();
    for (path, names) in sections() {
        for f in names {
            let key = if path.is_empty() {
                f.to_owned()
            } else {
                format!("{path}.{f}")
            };
            let (a, b) = (at(&now, path).get(f), at(&empty, path).get(f));
            if a == b && !NOT_FILLED.iter().any(|(k, _)| *k == key) {
                missing.push(key);
            }
        }
    }
    assert!(
        missing.is_empty(),
        "fields no command fills: {missing:?} (add a command to commands())"
    );
    // The typed delta of each commit rebuilds it, alone.
    let history = s.store().history();
    assert!(history.len() > commands().len() / 2, "{}", history.len());
    for w in history.windows(2) {
        let (old, new) = (&w[0].config, &w[1].config);
        let d = config_delta::diff(old, new).unwrap();
        let got = config_delta::apply(old, &d).unwrap();
        assert!(
            got == *new,
            "revision {} ({}): typed delta {d} misses a change",
            w[1].number,
            w[1].comment
        );
    }
    // And a reboot from the journal gives the same config.
    let mut t = boot(&storage);
    assert!(
        t.storage_status().boot_errors.is_empty(),
        "{:?}",
        t.storage_status().boot_errors
    );
    let (ks, kt) = (sealing::key(&mut s).unwrap(), sealing::key(&mut t).unwrap());
    let (a, b) = (
        opened(&ks, s.store().running()),
        opened(&kt, t.store().running()),
    );
    if a != b {
        let (a, b) = (
            serde_json::to_value(&a).unwrap(),
            serde_json::to_value(&b).unwrap(),
        );
        panic!(
            "after the reboot: {}",
            corerouter_model::json_delta::diff(&a, &b)
        );
    }
}
