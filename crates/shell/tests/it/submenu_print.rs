//! G3.9hl — `print` and `export` of the `/interface` sub-menus, as an
//! operator types them in RouterOS 7: `/interface vlan print`, `print
//! detail`, `where`, `as-json`, numbers of the last print for `set` and
//! `remove`, and the sub-menu's own `export`. The columns are the ones the
//! RouterOS 7.25 CHR prints first (`scripts/routeros-interop-l2.sh prints`),
//! minus what CoreRouter has no field for (ARP, L2MTU).
// Shared helpers are not `#[test]` fns, so clippy's in-tests allowances skip them.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use serde_json::Value;

use super::terminal::Term;

/// The column titles of a `print` table (the line after the legend).
fn header(out: &str) -> Vec<String> {
    out.lines()
        .find(|l| l.trim_start().starts_with('#'))
        .unwrap_or_else(|| panic!("no header in:\n{out}"))
        .split_whitespace()
        .skip(1)
        .map(str::to_owned)
        .collect()
}

/// The `NAME` of each numbered row, in order.
fn names(out: &str) -> Vec<String> {
    let cols = header(out);
    let at = cols.iter().position(|c| c == "NAME").unwrap_or(0);
    out.lines()
        .filter(|l| l.trim_start().starts_with(|c: char| c.is_ascii_digit()))
        .filter_map(|l| {
            let mut w = l.split_whitespace().skip(1);
            // The flags column is there when the row has a flag.
            let first = w.next()?;
            let mut rest: Vec<&str> = std::iter::once(first).chain(w).collect();
            if first.chars().all(|c| c.is_ascii_uppercase()) && first.len() <= 3 {
                rest.remove(0);
            }
            rest.get(at).map(|s| (*s).to_owned())
        })
        .collect()
}

fn lab() -> Term {
    let mut t = Term::new();
    for line in [
        "/interface vlan add name=v30 vlan-id=30 interface=ether1 comment=prints",
        "/interface vlan add name=v31 vlan-id=31 interface=ether1 disabled=yes",
        "/interface bridge add name=br1",
        "/interface bridge port add bridge=br1 interface=v30",
        "/interface bonding add name=bond1 slaves=ether2,ether3 mode=802.3ad",
        "/interface loopback add name=lo1",
        "/interface ethernet set ether4 auto-negotiation=no speed=100Mbps duplex=full",
    ] {
        t.ok(line);
    }
    t
}

fn export_of(t: &mut Term, menu: &str) -> String {
    t.ok(&format!("{menu} export file=x"));
    t.router.files.get("x").cloned().unwrap_or_default()
}

#[test]
fn vlan_print_lists_the_vlans_with_routeros_columns() {
    let mut t = lab();
    let out = t.ok("/interface vlan print");
    assert!(out.starts_with("Flags: X - disabled, R - running"), "{out}");
    assert_eq!(
        header(&out).get(..4),
        Some(&["NAME", "MTU", "VLAN-ID", "INTERFACE"].map(String::from)[..]),
        "{out}"
    );
    assert_eq!(names(&out), ["v30", "v31"], "{out}");
    assert!(out.contains(";;; prints"), "{out}");
    assert!(out.contains(" 1 X v31"), "{out}");
    // From inside the menu, abbreviated, as RouterOS takes it.
    t.ok("/interface vlan");
    assert_eq!(t.ok("pr"), out);
    t.ok("/");

    let detail = t.ok("/interface vlan print detail");
    assert!(
        detail.contains("name=v30 mtu=1500 vlan-id=30 interface=ether1"),
        "{detail}"
    );
    let one = t.ok("/interface vlan print where vlan-id=31");
    assert_eq!(names(&one), ["v31"], "{one}");
    assert_eq!(t.ok("/interface vlan print count-only").trim(), "2");
    let json: Value = serde_json::from_str(&t.ok("/interface vlan print as-json")).unwrap();
    assert_eq!(json[0]["interface"], "ether1");
    assert_eq!(json[1]["vlan_id"], 31);
}

#[test]
fn numbers_of_a_submenu_print_pick_its_items() {
    let mut t = lab();
    t.ok("/interface vlan print");
    t.ok("/interface vlan set 1 mtu=1400 comment=second");
    let out = t.ok("/interface vlan print detail where name=v31");
    assert!(out.contains("mtu=1400"), "{out}");
    t.ok("/interface vlan print");
    // `remove 0` is v30, not ether1 (the first row of `/interface print`).
    t.ok("/interface bridge port print");
    t.ok("/interface bridge port remove 0");
    t.ok("/interface vlan remove 0");
    assert_eq!(names(&t.ok("/interface vlan print")), ["v31"]);
    assert!(t.ok("/interface print").contains("ether1"));
    // Numbers belong to the print of their own menu.
    t.ok("/interface loopback print");
    let e = t.fails("/interface bridge remove 0");
    assert!(e.contains("run print first"), "{e}");
    t.ok("/interface bridge print");
    t.ok("/interface bridge remove 0");
    assert!(!t.ok("/interface print").contains("br1"));
}

#[test]
fn bridge_bonding_loopback_and_ethernet_print() {
    let mut t = lab();
    let br = t.ok("/interface bridge print");
    assert_eq!(
        header(&br).get(..2),
        Some(&["NAME", "MTU"].map(String::from)[..]),
        "{br}"
    );
    assert_eq!(names(&br), ["br1"]);
    let port = t.ok("/interface bridge port print");
    assert_eq!(header(&port), ["INTERFACE", "BRIDGE"], "{port}");
    let bond = t.ok("/interface bonding print");
    assert_eq!(
        header(&bond).get(..3),
        Some(&["NAME", "MODE", "SLAVES"].map(String::from)[..]),
        "{bond}"
    );
    assert_eq!(names(&bond), ["bond1"]);
    let lo = t.ok("/interface loopback print");
    assert_eq!(names(&lo), ["lo1"], "{lo}");
    let eth = t.ok("/interface ethernet print");
    assert_eq!(
        header(&eth).get(..3),
        Some(&["NAME", "MTU", "MAC-ADDRESS"].map(String::from)[..]),
        "{eth}"
    );
    assert!(names(&eth).iter().all(|n| n.starts_with("ether")), "{eth}");
    assert!(eth.contains("100Mbps"), "{eth}");
    // `set` by number on the ethernet print.
    let at = names(&eth).iter().position(|n| n == "ether5").unwrap();
    t.ok(&format!("/interface ethernet set {at} rx-flow-control=on"));
    assert!(
        t.ok("/interface ethernet print detail where name=ether5")
            .contains("rx-flow-control=on")
    );
    let ppp = t.ok("/interface pppoe-client print");
    assert!(ppp.is_empty() || !ppp.contains("bad command"), "{ppp}");
}

#[test]
fn each_submenu_exports_its_own_items() {
    let mut t = lab();
    let vlan = export_of(&mut t, "/interface vlan");
    assert!(
        vlan.contains("/interface vlan\nadd name=v30 interface=ether1 vlan-id=30"),
        "{vlan}"
    );
    assert!(!vlan.contains("/interface bridge"), "{vlan}");
    let bridge = export_of(&mut t, "/interface bridge");
    assert!(
        bridge.contains("/interface bridge\nadd name=br1"),
        "{bridge}"
    );
    assert!(
        bridge.contains("/interface bridge port\nadd bridge=br1 interface=v30"),
        "{bridge}"
    );
    // Only the port somebody configured, as `set` takes it.
    let eth = export_of(&mut t, "/interface ethernet");
    assert!(
        eth.contains(
            "/interface ethernet\nset name=ether4 auto-negotiation=no speed=100Mbps duplex=full\n"
        ),
        "{eth}"
    );
    assert!(!eth.contains("ether1"), "{eth}");
    // No line twice: a VLAN is written by /interface vlan only.
    let all = t.export();
    assert_eq!(all.matches("name=v30 ").count(), 1, "{all}");
    assert_eq!(all.matches("set name=ether4 auto").count(), 1, "{all}");
}

#[test]
fn the_whole_interface_export_imports_back_the_same() {
    let mut a = lab();
    let script = export_of(&mut a, "/interface");
    let mut b = Term::new();
    b.router.files.insert("i.rsc".into(), script.clone());
    b.ok("/import file=i.rsc");
    assert_eq!(export_of(&mut b, "/interface"), script);
    for menu in [
        "vlan",
        "bridge",
        "bridge port",
        "bonding",
        "loopback",
        "ethernet",
    ] {
        let line = format!("/interface {menu} print");
        assert_eq!(b.ok(&line), a.ok(&line), "{line}");
    }
}
