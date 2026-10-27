//! A config that uses every matcher and action once: the fixture of the
//! golden render test, the netns test of `hal-linux` and the engine tests.
//! Built from string literals known to parse; if one ever does not,
//! [`sample`] is empty instead of panicking (the golden test would show it).

use corerouter_model::cow_list::CowList;
use corerouter_model::firewall::{Action, AddressListEntry, FirewallRule, Matchers};
use corerouter_model::interface_list::InterfaceListMember;
use corerouter_model::{Config, ItemId};

pub fn rule(id: u32, chain: &str, m: Matchers, action: Action) -> Option<FirewallRule> {
    Some(FirewallRule {
        id: ItemId(id),
        chain: chain.parse().ok()?,
        family: Default::default(),
        matchers: m,
        action,
        disabled: false,
        comment: String::new(),
        section: false,
        zone: false,
    })
}

/// Matchers from (key, RouterOS value) pairs.
pub fn m(pairs: &[(&str, &str)]) -> Option<Matchers> {
    let obj: serde_json::Map<String, serde_json::Value> = pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), serde_json::Value::String((*v).to_owned())))
        .collect();
    serde_json::from_value(serde_json::Value::Object(obj)).ok()
}

/// An action from its JSON form (`{"type": "jump", …}`).
pub fn act(json: &str) -> Option<Action> {
    serde_json::from_str(json).ok()
}

/// A config that uses every matcher and action at least once.
pub fn sample() -> Config {
    build().unwrap_or_default()
}

fn build() -> Option<Config> {
    let mut cfg = Config::default();
    let lists = &mut cfg.interface_lists;
    for (id, list, iface) in [
        (1, "LAN", "ether2"),
        (2, "LAN", "bridge1"),
        (3, "WAN", "ether1"),
    ] {
        lists.members.push(InterfaceListMember {
            id: ItemId(id),
            list: list.parse().ok()?,
            interface: iface.parse().ok()?,
            disabled: false,
            comment: String::new(),
        });
    }
    let fw = &mut cfg.ip.firewall;
    for (id, list, addr) in [
        (1, "blocked", "203.0.113.0/24"),
        (2, "blocked", "2001:db8:bad::/48"),
        (3, "blocked", "198.51.100.1-198.51.100.9"),
        (4, "mgmt", "10.0.0.5"),
    ] {
        fw.address_lists.push(AddressListEntry {
            id: ItemId(id),
            list: list.parse().ok()?,
            address: addr.parse().ok()?,
            disabled: false,
            comment: String::new(),
        });
    }
    let mut section = rule(1, "input", Matchers::default(), Action::Accept)?;
    section.section = true;
    section.comment = "Router protection".into();
    let mut disabled = rule(9, "input", Matchers::default(), Action::Drop)?;
    disabled.disabled = true;
    fw.filter = CowList::from(vec![
        section,
        rule(
            2,
            "input",
            m(&[("connection_state", "established,related,untracked")])?,
            Action::Accept,
        )?,
        rule(
            3,
            "input",
            m(&[("connection_state", "invalid")])?,
            Action::Drop,
        )?,
        rule(
            4,
            "input",
            m(&[("protocol", "icmp"), ("icmp_options", "8:0")])?,
            Action::Accept,
        )?,
        rule(
            5,
            "input",
            m(&[("in_interface_list", "LAN")])?,
            Action::Accept,
        )?,
        rule(
            6,
            "input",
            m(&[("src_address_list", "blocked")])?,
            act(r#"{"type": "log", "log_prefix": "blocked: "}"#)?,
        )?,
        rule(
            7,
            "input",
            m(&[
                ("protocol", "tcp"),
                ("dst_port", "22,8291"),
                ("src_address_list", "!mgmt"),
            ])?,
            act(r#"{"type": "jump", "jump_target": "ssh-guard"}"#)?,
        )?,
        rule(
            8,
            "ssh-guard",
            m(&[("protocol", "tcp")])?,
            act(r#"{"type": "reject", "reject_with": "tcp-reset"}"#)?,
        )?,
        rule(
            21,
            "input",
            m(&[
                ("protocol", "tcp"),
                ("dst_port", "22"),
                ("connection_state", "new"),
            ])?,
            act(
                r#"{"type": "add-src-to-address-list", "address_list": "blocked", "address_list_timeout": "1m"}"#,
            )?,
        )?,
        rule(
            22,
            "input",
            m(&[
                ("protocol", "icmp"),
                ("icmp_options", "8:0"),
                ("limit", "5/1s,10"),
            ])?,
            Action::Accept,
        )?,
        disabled,
        rule(
            10,
            "input",
            m(&[("in_interface_list", "!LAN")])?,
            Action::Drop,
        )?,
        rule(
            11,
            "forward",
            m(&[
                ("connection_nat_state", "!dstnat"),
                ("in_interface_list", "WAN"),
                ("connection_state", "new"),
            ])?,
            act(r#"{"type": "reject", "reject_with": "icmp-admin-prohibited"}"#)?,
        )?,
        rule(
            12,
            "forward",
            m(&[
                ("src_address", "!10.0.0.0/8"),
                ("dst_address", "192.0.2.0/24"),
                ("protocol", "udp"),
                ("src_port", "1024-65535"),
            ])?,
            Action::Passthrough,
        )?,
        rule(13, "output", m(&[("protocol", "icmpv6")])?, Action::Accept)?,
    ]);
    fw.nat = CowList::from(vec![
        rule(
            14,
            "srcnat",
            m(&[("out_interface_list", "WAN")])?,
            act(r#"{"type": "masquerade"}"#)?,
        )?,
        rule(
            15,
            "srcnat",
            m(&[
                ("out_interface", "ether1"),
                ("src_address", "10.9.0.0/16"),
                ("protocol", "udp"),
            ])?,
            act(
                r#"{"type": "src-nat", "to_addresses": "198.51.100.10-198.51.100.12", "to_ports": "10000-20000"}"#,
            )?,
        )?,
        rule(
            16,
            "dstnat",
            m(&[
                ("in_interface", "ether1"),
                ("protocol", "tcp"),
                ("dst_port", "8080"),
            ])?,
            act(r#"{"type": "dst-nat", "to_addresses": "10.0.0.20", "to_ports": "80"}"#)?,
        )?,
        rule(
            17,
            "dstnat",
            m(&[("protocol", "tcp"), ("dst_port", "443")])?,
            act(r#"{"type": "dst-nat", "to_addresses": "2001:db8::20", "to_ports": "8443"}"#)?,
        )?,
    ]);
    fw.mangle = CowList::from(vec![
        rule(
            18,
            "prerouting",
            m(&[("in_interface", "ether1"), ("connection_state", "new")])?,
            act(r#"{"type": "mark-connection", "new_connection_mark": "from-wan"}"#)?,
        )?,
        rule(
            19,
            "prerouting",
            m(&[("connection_mark", "from-wan")])?,
            act(r#"{"type": "mark-routing", "new_routing_mark": "isp2", "passthrough": false}"#)?,
        )?,
        rule(
            20,
            "forward",
            m(&[("packet_mark", "!bulk"), ("routing_mark", "isp2")])?,
            act(r#"{"type": "mark-packet", "new_packet_mark": "bulk"}"#)?,
        )?,
    ]);
    fw.raw = CowList::from(vec![
        rule(
            22,
            "prerouting",
            m(&[("in_interface_list", "WAN"), ("src_address_list", "blocked")])?,
            Action::Drop,
        )?,
        rule(
            23,
            "prerouting",
            m(&[("protocol", "udp"), ("dst_port", "53")])?,
            act(r#"{"type": "notrack"}"#)?,
        )?,
        rule(
            24,
            "output",
            m(&[("protocol", "udp"), ("src_port", "53")])?,
            act(r#"{"type": "notrack"}"#)?,
        )?,
    ]);
    fw.next_rule_id = 25;
    fw.next_address_list_id = 4;
    Some(cfg)
}
