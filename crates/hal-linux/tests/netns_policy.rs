//! G1.27e against a real kernel, in a throwaway network namespace (no root,
//! nothing reaches the host; `cargo xtask netns` runs it):
//!
//! - routes in a named `/routing table` land in its kernel table, through
//!   main's networks;
//! - frames written with `AF_PACKET` into a veth are forwarded out of the
//!   dummy port the rule's table says (`tx_packets` proves it), for each
//!   match and action, and drop and unreachable differ on the wire;
//! - a restart does not duplicate rules, another program's rule stays, and
//!   a rule removed by hand is drift that `reconcile` puts back.
//!
//! Helpers outside `#[test]` fns may unwrap/panic too.
#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::os::fd::AsRawFd;
use std::process::Command;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use corerouter_hal::Hal;
use corerouter_hal::drift;
use corerouter_hal::policy::{self, KernelRuleAction, RuleOwner, RulePacket, RuleVerdict};
use corerouter_hal::route_get::{PolicyQuery, RouteKind, RouteQuery};
use corerouter_hal_linux::{LinuxHal, Policy};
use corerouter_model::firewall::FirewallRule;
use corerouter_model::policy_rule::{RoutingRule, RuleAction};
use corerouter_model::routing_table::NamedTable;
use corerouter_model::{
    AddressEntry, Config, IfName, Interface, InterfaceKind, ItemId, RouteEntry, RoutingTable,
};
use nix::ifaddrs::getifaddrs;
use nix::sys::socket::{LinkAddr, MsgFlags, bind, send};
use socket2::{Domain, Protocol, Socket, Type};

/// The rule list is one per namespace and each `apply` makes it what its
/// config says: these tests take turns.
static LIST: Mutex<()> = Mutex::new(());

const ENV: &str = "COREROUTER_NETNS_TESTS";

/// True when the tests may touch the kernel; panics outside a fresh
/// namespace (only `lo`), so a stray variable on the host touches nothing.
fn in_netns() -> bool {
    if std::env::var_os(ENV).is_none_or(|v| v != "1") {
        eprintln!("skipped: set {ENV}=1 and run inside `unshare --user --map-root-user --net`");
        return false;
    }
    static FRESH: OnceLock<Result<(), String>> = OnceLock::new();
    let fresh = FRESH.get_or_init(|| {
        let out = Command::new("ip")
            .args(["-o", "link", "show"])
            .output()
            .map_err(|e| format!("cannot run `ip`: {e}"))?;
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        let names: Vec<&str> = text
            .lines()
            .filter_map(|l| l.split(':').nth(1))
            .map(str::trim)
            .collect();
        if names == ["lo"] {
            Ok(())
        } else {
            Err(format!(
                "{ENV}=1 but this namespace has {names:?}; refusing to touch it"
            ))
        }
    });
    if let Err(e) = fresh {
        panic!("{e}");
    }
    true
}

fn ip(args: &[&str]) -> String {
    let out = Command::new("ip").args(args).output().unwrap();
    assert!(
        out.status.success(),
        "ip {}: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn n(s: &str) -> IfName {
    s.parse().unwrap()
}

/// A dummy port `port` with `address`.
fn port(c: &mut Config, port: &str, address: &str) {
    ip(&["link", "add", port, "type", "dummy"]);
    c.interfaces
        .insert(n(port), Interface::new(n(port), InterfaceKind::Ethernet));
    let id = c.ip.next_address_id();
    c.ip.addresses.push(AddressEntry {
        id,
        address: address.parse().unwrap(),
        interface: n(port),
        disabled: false,
        comment: String::new(),
        from_pool: None,
    });
}

fn table(c: &mut Config, name: &str, id: u32) {
    c.routing.tables.insert(
        n(name),
        NamedTable {
            name: n(name),
            table: id,
            comment: String::new(),
        },
    );
}

fn route(c: &mut Config, dst: &str, gw: &str, table: &str) {
    let id = c.ip.next_route_id();
    c.ip.routes.push(RouteEntry {
        id,
        dst_address: dst.parse().unwrap(),
        gateway: gw.parse().unwrap(),
        distance: 1,
        routing_table: table.parse::<RoutingTable>().unwrap(),
        disabled: false,
        comment: String::new(),
        check_gateway: Default::default(),
        bfd_profile: String::new(),
    });
}

#[test]
fn a_route_lands_in_the_kernel_table_of_its_named_table() {
    if !in_netns() {
        return;
    }
    let _list = LIST.lock().unwrap_or_else(|e| e.into_inner());
    let mut hal = LinuxHal::new();
    let mut base = Config::default();
    port(&mut base, "tbl0", "10.71.0.2/24");
    hal.apply(&Config::default(), &base).unwrap();

    let mut to = base.clone();
    table(&mut to, "isp2", 1000);
    route(&mut to, "0.0.0.0/0", "10.71.0.1", "isp2");
    route(&mut to, "203.0.113.0/24", "blackhole", "isp2");
    hal.apply(&base, &to).unwrap();

    let t = ip(&["route", "show", "table", "1000"]);
    assert!(t.contains("default via 10.71.0.1 dev tbl0"), "{t}");
    assert!(t.contains("blackhole 203.0.113.0/24"), "{t}");
    let main = ip(&["route", "show", "default"]);
    assert_eq!(main, "", "main stays without a default route");
    let have = hal.snapshot(&to).unwrap();
    assert_eq!(
        drift::diff(&drift::expected(&to), &have),
        vec![],
        "{have:?}"
    );

    hal.apply(&to, &base).unwrap();
    assert_eq!(ip(&["route", "show", "table", "1000"]), "");
}

fn rule(action: RuleAction, table: &str, src: Option<&str>) -> RoutingRule {
    RoutingRule {
        id: ItemId(1),
        src_address: src.map(|s| s.parse().unwrap()),
        dst_address: None,
        interface: None,
        routing_mark: None,
        action,
        table: table.parse().unwrap(),
        min_prefix: None,
        disabled: false,
        comment: String::new(),
    }
}

fn mangle_mark(id: u32, src: &str, mark: &str) -> FirewallRule {
    serde_json::from_value(serde_json::json!({
        "id": format!("*{id:X}"),
        "chain": "prerouting",
        "matchers": {"src_address": src},
        "action": {"type": "mark-routing", "new_routing_mark": mark},
    }))
    .unwrap()
}

fn link(name: &str) -> (LinkAddr, [u8; 6]) {
    getifaddrs()
        .unwrap()
        .filter(|a| a.interface_name == name)
        .find_map(|a| {
            let l = *a.address?.as_link_addr()?;
            Some((l, l.addr()?))
        })
        .unwrap()
}

fn checksum(words: &[u8]) -> u16 {
    let mut sum: u32 = words
        .chunks(2)
        .map(|c| u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)])))
        .sum();
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// A 64-byte Ethernet/IPv4/UDP frame.
fn frame(dst_mac: [u8; 6], src_mac: [u8; 6], src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
    let mut f = Vec::with_capacity(64);
    f.extend_from_slice(&dst_mac);
    f.extend_from_slice(&src_mac);
    f.extend_from_slice(&[0x08, 0x00]);
    let mut iph = vec![0x45, 0, 0, 50, 0, 0, 0x40, 0, 64, 17, 0, 0];
    iph.extend_from_slice(&src);
    iph.extend_from_slice(&dst);
    let c = checksum(&iph);
    iph[10..12].copy_from_slice(&c.to_be_bytes());
    f.extend_from_slice(&iph);
    f.extend_from_slice(&40000u16.to_be_bytes());
    f.extend_from_slice(&9000u16.to_be_bytes());
    f.extend_from_slice(&30u16.to_be_bytes());
    f.extend_from_slice(&[0, 0]); // UDP checksum 0: none (IPv4)
    f.resize(64, 0);
    f
}

fn tx(hal: &mut LinuxHal, name: &str) -> u64 {
    hal.poll()
        .into_iter()
        .find(|l| l.name.as_str() == name)
        .map_or(0, |l| l.tx_packets)
}

/// How many frames (of `FRAMES`) leave each port.
const FRAMES: u64 = 5;

struct Wire {
    sock: Socket,
    fa_mac: [u8; 6],
    fb_mac: [u8; 6],
}

impl Wire {
    fn new() -> Self {
        let (fa, fa_mac) = link("pfa");
        let (_, fb_mac) = link("pfb");
        let sock = Socket::new(Domain::PACKET, Type::RAW, Some(Protocol::from(0))).unwrap();
        bind(sock.as_raw_fd(), &fa).unwrap();
        Self {
            sock,
            fa_mac,
            fb_mac,
        }
    }

    /// (out of `po1`, out of `po2`, out of `pfb`: an ICMP back) for frames
    /// from `src` to `dst`.
    fn send(&self, hal: &mut LinuxHal, src: [u8; 4], dst: [u8; 4]) -> (u64, u64, u64) {
        let before = (tx(hal, "po1"), tx(hal, "po2"), tx(hal, "pfb"));
        let f = frame(self.fb_mac, self.fa_mac, src, dst);
        for _ in 0..FRAMES {
            send(self.sock.as_raw_fd(), &f, MsgFlags::empty()).unwrap();
        }
        std::thread::sleep(Duration::from_millis(30));
        (
            tx(hal, "po1") - before.0,
            tx(hal, "po2") - before.1,
            tx(hal, "pfb") - before.2,
        )
    }
}

/// `pfb` takes the frames (its peer `pfa` is the wire); `po1` is main's way
/// out, `po2` table `isp2`'s; `empty` has no route. The sources 10.88/13
/// route back through `pfb`, so an ICMP error shows there.
fn wired() -> (Config, LinuxHal) {
    ip(&["link", "add", "pfa", "type", "veth", "peer", "name", "pfb"]);
    // No DAD or router solicitations in the counter of `pfb`.
    for d in ["pfa", "pfb"] {
        std::fs::write(format!("/proc/sys/net/ipv6/conf/{d}/disable_ipv6"), "1").unwrap();
    }
    ip(&["link", "set", "pfa", "up"]);
    let mut c = Config::default();
    c.interfaces
        .insert(n("pfb"), Interface::new(n("pfb"), InterfaceKind::Ethernet));
    let id = c.ip.next_address_id();
    c.ip.addresses.push(AddressEntry {
        id,
        address: "10.72.0.2/24".parse().unwrap(),
        interface: n("pfb"),
        disabled: false,
        comment: String::new(),
        from_pool: None,
    });
    port(&mut c, "po1", "10.72.1.2/24");
    port(&mut c, "po2", "10.72.2.2/24");
    table(&mut c, "isp2", 1000);
    table(&mut c, "empty", 1001);
    route(&mut c, "0.0.0.0/0", "10.72.1.1", "main");
    route(&mut c, "10.88.0.0/13", "pfb", "main");
    route(&mut c, "0.0.0.0/0", "10.72.2.1", "isp2");
    for (k, v) in [
        ("net.ipv4.ip_forward", 1),
        ("net.ipv4.conf.all.rp_filter", 0),
        ("net.ipv4.conf.default.rp_filter", 0),
    ] {
        c.system.tuning.sysctl.insert(k.to_owned(), v);
    }
    let hal = LinuxHal::with_policy(Policy {
        manage: vec!["pfb".into()],
        unmanaged: Vec::new(),
    });
    (c, hal)
}

#[test]
fn real_traffic_leaves_by_the_table_each_rule_chooses() {
    if !in_netns() {
        return;
    }
    let _list = LIST.lock().unwrap_or_else(|e| e.into_inner());
    let (base, mut hal) = wired();
    hal.apply(&Config::default(), &base).unwrap();
    // A permanent neighbor, so the ICMP errors go out at once.
    let (_, fa_mac) = link("pfa");
    let mac = fa_mac
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":");
    for host in ["10.95.0.1", "10.94.0.1"] {
        ip(&[
            "neigh",
            "add",
            host,
            "lladdr",
            &mac,
            "dev",
            "pfb",
            "nud",
            "permanent",
        ]);
    }

    let mut to = base.clone();
    let mut by_iif = rule(RuleAction::Lookup, "isp2", None);
    by_iif.dst_address = Some("198.51.100.0/24".parse().unwrap());
    by_iif.interface = Some(n("pfb"));
    let mut by_mark = rule(RuleAction::Lookup, "isp2", None);
    by_mark.routing_mark = Some("other".parse().unwrap());
    let mut hidden = rule(RuleAction::Lookup, "isp2", Some("10.90.0.0/24"));
    hidden.min_prefix = Some(0);
    to.routing.rules = vec![
        rule(RuleAction::Lookup, "isp2", Some("10.91.0.0/24")),
        rule(RuleAction::LookupOnlyInTable, "empty", Some("10.92.0.0/24")),
        rule(RuleAction::Lookup, "empty", Some("10.93.0.0/24")),
        rule(RuleAction::Drop, "main", Some("10.94.0.0/24")),
        rule(RuleAction::Unreachable, "main", Some("10.95.0.0/24")),
        by_iif,
        by_mark,
        hidden,
    ];
    for (i, (src, mark)) in [("10.96.0.0/24", "isp2"), ("10.97.0.0/24", "other")]
        .iter()
        .enumerate()
    {
        to.ip
            .firewall
            .mangle
            .push(mangle_mark(u32::try_from(i).unwrap() + 1, src, mark));
    }
    hal.apply(&base, &to).unwrap();
    let list = ip(&["rule"]);
    assert!(
        list.contains("100:\tfrom all fwmark"),
        "the mark of a table: {list}"
    );

    let wire = Wire::new();
    let far = [8, 8, 8, 8];
    let mut check = |what: &str, src: [u8; 4], dst: [u8; 4], want: (u64, u64, u64)| {
        let got = wire.send(&mut hal, src, dst);
        assert_eq!(got, want, "{what}: (main, isp2, back)\n{}", ip(&["rule"]));
    };
    check("no rule: main", [10, 89, 0, 1], far, (FRAMES, 0, 0));
    check("src, lookup", [10, 91, 0, 1], far, (0, FRAMES, 0));
    // Unreachable: nothing forwarded, the ICMP back starts with an ARP request.
    let got = wire.send(&mut hal, [10, 92, 0, 1], far);
    assert_eq!(
        (got.0, got.1),
        (0, 0),
        "lookup-only-in-table, empty: {got:?}"
    );
    assert!(got.2 > 0, "lookup-only-in-table answers: {got:?}");
    let mut check = |what: &str, src: [u8; 4], dst: [u8; 4], want: (u64, u64, u64)| {
        let got = wire.send(&mut hal, src, dst);
        assert_eq!(got, want, "{what}: (main, isp2, back)\n{}", ip(&["rule"]));
    };
    check(
        "lookup, empty: falls through",
        [10, 93, 0, 1],
        far,
        (FRAMES, 0, 0),
    );
    check("drop: silent", [10, 94, 0, 1], far, (0, 0, 0));
    let got = wire.send(&mut hal, [10, 95, 0, 1], far);
    assert_eq!((got.0, got.1), (0, 0), "unreachable forwards nothing");
    assert!(got.2 > 0, "unreachable answers with ICMP: {got:?}");
    let mut check = |what: &str, src: [u8; 4], dst: [u8; 4], want: (u64, u64, u64)| {
        let got = wire.send(&mut hal, src, dst);
        assert_eq!(got, want, "{what}: (main, isp2, back)\n{}", ip(&["rule"]));
    };
    check(
        "iif + dst",
        [10, 89, 0, 2],
        [198, 51, 100, 7],
        (0, FRAMES, 0),
    );
    check(
        "mark of the mangle names a table",
        [10, 96, 0, 1],
        far,
        (0, FRAMES, 0),
    );
    check("rule on a mark", [10, 97, 0, 1], far, (0, FRAMES, 0));
    check(
        "min-prefix hides the default route",
        [10, 90, 0, 1],
        far,
        (FRAMES, 0, 0),
    );

    // The kernel's answer and the shared walk agree on every one.
    let want: Vec<_> = policy::expected_rules(&to).into_iter().collect();
    let iif = n("pfb");
    let mark = |name: &str| {
        corerouter_firewall::nft::mark_value(
            corerouter_firewall::nft::MarkKind::Routing,
            &name.parse().unwrap(),
        )
    };
    for (src, dst, m) in [
        ("10.89.0.1", "8.8.8.8", 0),
        ("10.91.0.1", "8.8.8.8", 0),
        ("10.92.0.1", "8.8.8.8", 0),
        ("10.93.0.1", "8.8.8.8", 0),
        ("10.94.0.1", "8.8.8.8", 0),
        ("10.95.0.1", "8.8.8.8", 0),
        ("10.89.0.2", "198.51.100.7", 0),
        ("10.96.0.1", "8.8.8.8", mark("isp2")),
        ("10.97.0.1", "8.8.8.8", mark("other")),
        ("10.90.0.1", "8.8.8.8", 0),
    ] {
        let q = RouteQuery {
            dst: dst.parse().unwrap(),
            table: 0,
            src: Some(src.parse().unwrap()),
            policy: Some(PolicyQuery {
                iif: Some(iif.clone()),
                mark: m,
                vrf: None,
            }),
        };
        let k = hal.route_get(&to, &q).unwrap();
        let packet = RulePacket {
            src: q.src,
            dst: q.dst,
            iif: Some(&iif),
            mark: m,
            vrf: None,
        };
        let w = policy::walk(&want, &packet, |t, s| {
            // Each of the tables here holds only a default route or nothing;
            // main's connected networks do not reach these destinations.
            (t == 254 || t == 1000) && s.is_none()
        });
        match w.verdict {
            RuleVerdict::Table(t) => {
                assert_eq!((k.kind, k.table), (RouteKind::Unicast, t), "{src}: {k:?}");
            }
            RuleVerdict::Blackhole => assert_eq!(k.kind, RouteKind::Blackhole, "{src}: {k:?}"),
            RuleVerdict::Unreachable => assert_eq!(k.kind, RouteKind::Unreachable, "{src}: {k:?}"),
        }
    }

    // A disabled rule leaves the kernel; the others keep their priority.
    let prefs =
        |cfg: &Config| -> Vec<u32> { policy::expected_rules(cfg).iter().map(|r| r.pref).collect() };
    let mut off = to.clone();
    off.routing.rules[0].disabled = true;
    hal.apply(&to, &off).unwrap();
    assert!(!prefs(&off).contains(&2000));
    assert!(prefs(&off).contains(&2002));
    let wire2 = Wire::new();
    assert_eq!(wire2.send(&mut hal, [10, 91, 0, 1], far), (FRAMES, 0, 0));
    hal.apply(&off, &base).unwrap();
    let left = ip(&["rule"]);
    assert!(
        !left.contains("proto 200"),
        "only the kernel's stay: {left}"
    );
    ip(&["link", "del", "pfa"]);
    hal.apply(&base, &Config::default()).unwrap();
}

#[test]
fn only_our_rules_are_ours() {
    if !in_netns() {
        return;
    }
    let _list = LIST.lock().unwrap_or_else(|e| e.into_inner());
    let mut base = Config::default();
    port(&mut base, "own0", "10.73.0.2/24");
    table(&mut base, "isp2", 1000);
    let mut to = base.clone();
    to.routing.rules = vec![
        rule(RuleAction::LookupOnlyInTable, "isp2", Some("10.91.0.0/24")),
        rule(RuleAction::Drop, "main", Some("2001:db8:91::/48")),
    ];
    let mut hal = LinuxHal::new();
    hal.apply(&Config::default(), &base).unwrap();
    // Someone else's rules, one right in our range.
    ip(&[
        "rule",
        "add",
        "pref",
        "2000",
        "from",
        "192.0.2.0/24",
        "lookup",
        "77",
    ]);
    ip(&["rule", "add", "pref", "1500", "fwmark", "0x7", "prohibit"]);
    hal.apply(&base, &to).unwrap();
    let rows = hal.rule_dump().unwrap();
    let owner = |pref: u32| {
        rows.iter()
            .filter(|r| r.rule.pref == pref)
            .map(|r| r.owner)
            .collect::<Vec<_>>()
    };
    assert_eq!(owner(0), [RuleOwner::Kernel, RuleOwner::Kernel]);
    assert_eq!(owner(1500), [RuleOwner::Foreign]);
    assert!(owner(2000).contains(&RuleOwner::Foreign));
    assert!(owner(2000).contains(&RuleOwner::Corerouter));
    assert_eq!(
        owner(2001),
        [RuleOwner::Corerouter],
        "lookup-only: the unreachable after it"
    );
    let prohibit = rows.iter().find(|r| r.rule.pref == 1500).unwrap();
    assert_eq!(prohibit.rule.action, KernelRuleAction::Other(8));

    // They are not drift.
    let have = hal.snapshot(&to).unwrap();
    assert_eq!(
        drift::diff(&drift::expected(&to), &have),
        vec![],
        "{have:?}"
    );

    // A new process over the same kernel: no twins, and theirs stay.
    let before = ip(&["rule"]);
    let mut again = LinuxHal::new();
    again.apply(&Config::default(), &to).unwrap();
    assert_eq!(ip(&["rule"]), before);
    // It starts with no rules: ours go, theirs stay.
    let mut fresh = LinuxHal::new();
    fresh.apply(&to, &base).unwrap();
    let after = ip(&["rule"]);
    assert!(after.contains("from 192.0.2.0/24 lookup 77"), "{after}");
    assert!(after.contains("prohibit"), "{after}");
    assert!(!after.contains("10.91.0.0/24"), "{after}");

    // Removed by hand: drift, and `reconcile` puts it back.
    let mut hal = LinuxHal::new();
    hal.apply(&base, &to).unwrap();
    ip(&["rule", "del", "pref", "2001"]);
    let d = drift::diff(&drift::expected(&to), &hal.snapshot(&to).unwrap());
    assert_eq!(d.len(), 1, "{d:?}");
    assert_eq!(d[0].kind, drift::DriftKind::RuleMissing);
    ip(&[
        "rule",
        "add",
        "pref",
        "2500",
        "unreachable",
        "protocol",
        "200",
    ]);
    let d = drift::diff(&drift::expected(&to), &hal.snapshot(&to).unwrap());
    assert_eq!(d.len(), 2, "one of our protocol the config lacks: {d:?}");
    hal.reconcile(&to).unwrap();
    let d = drift::diff(&drift::expected(&to), &hal.snapshot(&to).unwrap());
    assert_eq!(d, vec![]);
    assert!(
        ip(&["rule"]).contains("from 192.0.2.0/24 lookup 77"),
        "theirs stay"
    );

    hal.apply(&to, &base).unwrap();
    ip(&["rule", "del", "pref", "2000"]);
    ip(&["rule", "del", "pref", "1500"]);
    hal.apply(&base, &Config::default()).unwrap();
}

#[test]
fn a_vrf_miss_does_not_leak_to_main_or_a_rule() {
    if !in_netns() {
        return;
    }
    let _list = LIST.lock().unwrap_or_else(|e| e.into_inner());
    let mut base = Config::default();
    port(&mut base, "vp1", "10.74.0.2/24");
    port(&mut base, "vp2", "10.74.1.2/24");
    base.interfaces.insert(
        n("vblue"),
        Interface::new(n("vblue"), InterfaceKind::Vrf { table: 1002 }),
    );
    base.interfaces.get_mut(&n("vp2")).unwrap().vrf = Some(n("vblue"));
    route(&mut base, "0.0.0.0/0", "10.74.0.1", "main");
    let mut hal = LinuxHal::new();
    hal.apply(&Config::default(), &base).unwrap();
    let list = ip(&["rule"]);
    assert!(list.contains("1001:"), "{list}");

    let ask = |hal: &mut LinuxHal, src: &str| {
        let q = RouteQuery {
            dst: "8.8.8.8".parse().unwrap(),
            table: 0,
            src: Some(src.parse().unwrap()),
            policy: Some(PolicyQuery {
                iif: None,
                mark: 0,
                vrf: None,
            }),
        };
        hal.route_get(&base, &q).unwrap()
    };
    // The `oif`-less output of a socket bound to a VRF is not what `ip route
    // get from` does: this asks the plain path, and `iif` below the VRF one.
    assert_eq!(ask(&mut hal, "10.74.0.2").kind, RouteKind::Unicast);
    let forwarded = RouteQuery {
        dst: "8.8.8.8".parse().unwrap(),
        table: 0,
        src: Some("10.74.1.9".parse().unwrap()),
        policy: Some(PolicyQuery {
            iif: Some(n("vp2")),
            mark: 0,
            vrf: None,
        }),
    };
    ip(&["link", "set", "vp2", "up"]);
    let k = hal.route_get(&base, &forwarded).unwrap();
    assert_eq!(
        k.kind,
        RouteKind::Unreachable,
        "no leak to main's default: {k:?}"
    );

    hal.apply(&base, &Config::default()).unwrap();
    // As the kernel's own `l3mdev`, it stays: it matches nothing now.
    let list = ip(&["rule"]);
    assert!(list.contains("1000:") && list.contains("1001:"), "{list}");
}
