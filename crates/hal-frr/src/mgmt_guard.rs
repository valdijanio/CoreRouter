//! G3.4z: the management guard in FRR. For each family with an active
//! network, zebra gets a route-map that denies the prefixes inside a
//! guarded network and longer than it, applied to every protocol:
//!
//! ```text
//! ip prefix-list CR-MG-4 seq 5 permit 192.168.0.0/24 ge 25
//! route-map CR-MG-4 deny 10
//!  match ip address prefix-list CR-MG-4
//! exit
//! route-map CR-MG-4 permit 65535
//! exit
//! ip protocol any route-map CR-MG-4
//! ```
//!
//! Read in FRR 10.7.1: a deny takes the next hop's `NEXTHOP_FLAG_ACTIVE`
//! away (`zebra/zebra_nhg.c:2800`, `nexthop_active_check`), so the route
//! stays in the protocol's RIB and in zebra's as inactive, and never
//! reaches the kernel; the kernel's own routes (connected, the static
//! routes CoreRouter writes by netlink) are never checked
//! (`RIB_SYSTEM_ROUTE`). `ip protocol` is a YANG command of mgmtd in FRR 10
//! (`zebra/zebra_cli.c:2345`), so all of it is typed there, in one
//! transaction (`push`): zebra never sees the `ip protocol` line without
//! its route-map, which would deny every route (`zebra_route_map_check`:
//! a named map that does not exist is a deny). A per-protocol map would
//! win over `any` (same function); CoreRouter types none.

use std::fmt::Write as _;

use corerouter_model::mgmt_guard::RibRoute;
use corerouter_model::{Config, RoutingTable};
use ipnet::IpNet;
use serde_json::Value;

/// The route-map and prefix-list names of the main table, per family.
pub const V4: &str = "CR-MG-4";
pub const V6: &str = "CR-MG-6";

/// Most routes read from one guarded network's RIB.
pub const MAX_RIB_ROUTES: usize = 10_000;

/// The route-map (and prefix-list) name of a family in `table`: `CR-MG-4`
/// in main (as G3.4z typed it: a router that has it keeps it), `CR-MG-4-<vrf>`
/// in a VRF (a VRF name follows interface-name rules, 15 characters of
/// `A-Z a-z 0-9 - _ .`, all valid in an FRR map name).
pub fn map_name(v6: bool, table: &RoutingTable) -> String {
    let base = if v6 { V6 } else { V4 };
    match table {
        RoutingTable::Main => base.to_owned(),
        RoutingTable::Vrf(v) => format!("{base}-{v}"),
    }
}

/// The FRR text of `cfg`'s guard (empty when nothing is active).
///
/// G3.4za: a VRF's networks get their own prefix-list and route-map, and
/// the `ip protocol` line inside zebra's `vrf <name>` context
/// (`zebra/zebra_cli.c:3380` in FRR 10.7.1 installs `ip protocol` in
/// `VRF_NODE`; it writes `filter-protocol` of that VRF, read by
/// `zebra_route_map_check` with the route's own `vrf_id`). Only routes of
/// that VRF are checked against it.
pub fn render(cfg: &Config) -> String {
    let guard = &cfg.routing.management_guard;
    let mut out = String::new();
    let mut vrf_lines: Vec<(String, String)> = Vec::new();
    for table in guard.tables() {
        for (v6, ip) in [(false, "ip"), (true, "ipv6")] {
            let nets: Vec<&IpNet> = guard
                .active_in(table)
                .filter(|n| n.addr().is_ipv6() == v6 && n.prefix_len() < n.max_prefix_len())
                .collect();
            if nets.is_empty() {
                continue;
            }
            let name = map_name(v6, table);
            for (i, n) in nets.iter().enumerate() {
                let _ = writeln!(
                    out,
                    "{ip} prefix-list {name} seq {} permit {n} ge {}",
                    (i + 1) * 5,
                    n.prefix_len() + 1
                );
            }
            let _ = write!(
                out,
                "route-map {name} deny 10\n match {ip} address prefix-list {name}\nexit\n\
                 route-map {name} permit 65535\nexit\n"
            );
            let line = format!("{ip} protocol any route-map {name}");
            match table {
                RoutingTable::Main => {
                    let _ = writeln!(out, "{line}");
                }
                RoutingTable::Vrf(v) => vrf_lines.push((v.to_string(), line)),
            }
        }
    }
    let mut last: Option<&str> = None;
    for (vrf, line) in &vrf_lines {
        if last != Some(vrf.as_str()) {
            if last.is_some() {
                out.push_str("exit\n");
            }
            let _ = writeln!(out, "vrf {vrf}");
            last = Some(vrf.as_str());
        }
        let _ = writeln!(out, " {line}");
    }
    if last.is_some() {
        out.push_str("exit\n");
    }
    out
}

/// The zebra command that lists `net` and what is inside it, in `table`.
pub fn rib_command(table: &RoutingTable, net: &IpNet) -> String {
    let ip = if net.addr().is_ipv4() { "ip" } else { "ipv6" };
    match table {
        RoutingTable::Main => format!("show {ip} route {net} longer-prefixes json"),
        RoutingTable::Vrf(v) => format!("show {ip} route vrf {v} {net} longer-prefixes json"),
    }
}

/// zebra's `show ip route … json`: `{prefix: [route, …]}`, each route with
/// `protocol`, `installed` and `nexthops: [{active, ip, interfaceName}]`.
pub fn parse_rib(json: &[u8]) -> Result<Vec<RibRoute>, String> {
    if json.iter().all(u8::is_ascii_whitespace) {
        return Ok(Vec::new());
    }
    let v: Value = serde_json::from_slice(json).map_err(|e| format!("zebra: not JSON ({e})"))?;
    let Some(map) = v.as_object() else {
        return Err("zebra: not a route table".into());
    };
    let mut out = Vec::new();
    for (key, routes) in map {
        let Ok(prefix) = key.parse::<IpNet>() else {
            continue;
        };
        for r in routes.as_array().into_iter().flatten() {
            if out.len() >= MAX_RIB_ROUTES {
                return Err(format!(
                    "more than {MAX_RIB_ROUTES} routes inside the network"
                ));
            }
            let protocol = r
                .get("protocol")
                .and_then(Value::as_str)
                .unwrap_or("?")
                .chars()
                .take(32)
                .collect();
            let hops = r.get("nexthops").and_then(Value::as_array);
            let active = hops.is_some_and(|h| {
                h.iter()
                    .any(|n| n.get("active").and_then(Value::as_bool) == Some(true))
            });
            let via = hops
                .and_then(|h| h.first())
                .map(|n| {
                    let ip = n.get("ip").and_then(Value::as_str).unwrap_or("");
                    let dev = n.get("interfaceName").and_then(Value::as_str).unwrap_or("");
                    format!("{ip} {dev}").trim().chars().take(80).collect()
                })
                .unwrap_or_default();
            out.push(RibRoute {
                prefix,
                protocol,
                installed: r.get("installed").and_then(Value::as_bool) == Some(true),
                inactive: !active,
                via,
            });
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_model::ItemId;
    use corerouter_model::mgmt_guard::GuardNetwork;

    fn guard(nets: &[(&str, bool)]) -> Config {
        guard_in(
            &nets
                .iter()
                .map(|(n, d)| (*n, *d, "main"))
                .collect::<Vec<_>>(),
        )
    }

    fn guard_in(nets: &[(&str, bool, &str)]) -> Config {
        let mut c = Config::default();
        for (i, (n, disabled, vrf)) in nets.iter().enumerate() {
            c.routing.management_guard.networks.push(GuardNetwork {
                id: ItemId(i as u32 + 1),
                network: n.parse().unwrap(),
                vrf: vrf.parse().unwrap(),
                disabled: *disabled,
                comment: String::new(),
            });
        }
        c
    }

    #[test]
    fn a_vrf_network_gets_its_own_map_inside_the_vrf_context() {
        let text = render(&guard_in(&[
            ("192.168.0.0/24", false, "main"),
            ("10.99.0.0/24", false, "mgmt"),
            ("2001:db8:9::/64", false, "mgmt"),
            ("10.98.0.0/24", false, "oob"),
            ("10.97.0.0/24", true, "oob"),
        ]));
        assert_eq!(
            text,
            "ip prefix-list CR-MG-4 seq 5 permit 192.168.0.0/24 ge 25\n\
             route-map CR-MG-4 deny 10\n match ip address prefix-list CR-MG-4\nexit\n\
             route-map CR-MG-4 permit 65535\nexit\n\
             ip protocol any route-map CR-MG-4\n\
             ip prefix-list CR-MG-4-mgmt seq 5 permit 10.99.0.0/24 ge 25\n\
             route-map CR-MG-4-mgmt deny 10\n match ip address prefix-list CR-MG-4-mgmt\nexit\n\
             route-map CR-MG-4-mgmt permit 65535\nexit\n\
             ipv6 prefix-list CR-MG-6-mgmt seq 5 permit 2001:db8:9::/64 ge 65\n\
             route-map CR-MG-6-mgmt deny 10\n match ipv6 address prefix-list CR-MG-6-mgmt\nexit\n\
             route-map CR-MG-6-mgmt permit 65535\nexit\n\
             ip prefix-list CR-MG-4-oob seq 5 permit 10.98.0.0/24 ge 25\n\
             route-map CR-MG-4-oob deny 10\n match ip address prefix-list CR-MG-4-oob\nexit\n\
             route-map CR-MG-4-oob permit 65535\nexit\n\
             vrf mgmt\n ip protocol any route-map CR-MG-4-mgmt\n ipv6 protocol any route-map CR-MG-6-mgmt\nexit\n\
             vrf oob\n ip protocol any route-map CR-MG-4-oob\nexit\n"
        );
        // All of it to mgmtd; the VRF contexts hold only the guard's lines.
        let conf = crate::conf::Conf::parse(&text).unwrap();
        let by = crate::render::by_daemon(crate::render::OWNED, &conf);
        assert_eq!(by.len(), 1, "{by:?}");
        assert_eq!(by[0].0, crate::render::Daemon::Mgmtd);
        let vrfs: Vec<_> = by[0]
            .1
            .nodes
            .iter()
            .filter(|n| n.line.starts_with("vrf "))
            .collect();
        assert_eq!(vrfs.len(), 2);
        assert_eq!(vrfs[0].children.len(), 2);
        assert_eq!(
            rib_command(&"mgmt".parse().unwrap(), &"10.99.0.0/24".parse().unwrap()),
            "show ip route vrf mgmt 10.99.0.0/24 longer-prefixes json"
        );
        assert_eq!(
            rib_command(&RoutingTable::Main, &"2001:db8::/64".parse().unwrap()),
            "show ipv6 route 2001:db8::/64 longer-prefixes json"
        );
    }

    #[test]
    fn the_vrf_context_as_frr_prints_it_keeps_only_the_guard_lines() {
        // mgmtd's running config of a VRF the operator also gave a VNI.
        let running = crate::conf::Conf::parse(
            "vrf mgmt\n vni 100\n ip protocol any route-map CR-MG-4-mgmt\n ip protocol ospf route-map OPERATOR\nexit-vrf\n\
             vrf blue\n vni 200\nexit-vrf\n",
        )
        .unwrap();
        let mine: Vec<_> = running
            .owned(|l| {
                crate::render::daemons_of(crate::render::OWNED, l)
                    .contains(&crate::render::Daemon::Mgmtd)
            })
            .nodes
            .iter()
            .filter_map(|n| crate::render::part_of(crate::render::Daemon::Mgmtd, n))
            .collect();
        assert_eq!(
            mine.len(),
            1,
            "a VRF without guard lines is not ours: {mine:?}"
        );
        assert_eq!(mine[0].children.len(), 1, "{mine:?}");
        // Taking the guard away deletes the line and leaves the VRF.
        let old = crate::conf::Conf { nodes: mine };
        let new = crate::conf::Conf::parse(&render(&guard(&[]))).unwrap();
        let script = crate::conf::diff(&old, &new);
        assert_eq!(
            script,
            [
                "vrf mgmt",
                " no ip protocol any route-map CR-MG-4-mgmt",
                "exit"
            ],
            "{script:?}"
        );
    }

    #[test]
    fn each_family_gets_its_route_map_for_every_protocol() {
        let text = render(&guard(&[
            ("192.168.0.0/24", false),
            ("100.64.0.0/24", true),
            ("10.9.0.0/16", false),
            ("2001:db8:1::/64", false),
        ]));
        assert_eq!(
            text,
            "ip prefix-list CR-MG-4 seq 5 permit 192.168.0.0/24 ge 25\n\
             ip prefix-list CR-MG-4 seq 10 permit 10.9.0.0/16 ge 17\n\
             route-map CR-MG-4 deny 10\n match ip address prefix-list CR-MG-4\nexit\n\
             route-map CR-MG-4 permit 65535\nexit\n\
             ip protocol any route-map CR-MG-4\n\
             ipv6 prefix-list CR-MG-6 seq 5 permit 2001:db8:1::/64 ge 65\n\
             route-map CR-MG-6 deny 10\n match ipv6 address prefix-list CR-MG-6\nexit\n\
             route-map CR-MG-6 permit 65535\nexit\n\
             ipv6 protocol any route-map CR-MG-6\n"
        );
        assert_eq!(
            render(&guard(&[("192.168.0.0/24", true)])),
            "",
            "only disabled: nothing typed"
        );
        assert_eq!(render(&Config::default()), "");
    }

    #[test]
    fn it_all_goes_to_mgmtd_and_parses_as_frr_prints_it() {
        let conf = crate::conf::Conf::parse(&render(&guard(&[("192.168.0.0/24", false)]))).unwrap();
        let by = crate::render::by_daemon(crate::render::OWNED, &conf);
        assert_eq!(by.len(), 1, "{by:?}");
        assert_eq!(by[0].0, crate::render::Daemon::Mgmtd);
        assert_eq!(
            by[0].1.nodes.len(),
            4,
            "prefix-list, two route-map entries, ip protocol"
        );
        for n in &by[0].1.nodes {
            assert!(crate::render::owned(&n.line), "{}", n.line);
        }
        // The BGP filters keep their own daemon.
        assert_eq!(
            crate::render::daemons_of(crate::render::OWNED, "route-map CR-BOGONS permit 10"),
            [crate::render::Daemon::Bgpd]
        );
    }

    #[test]
    fn zebra_routes_inside_a_network_are_read() {
        let json = br#"{
          "192.168.0.0/24": [
            {"prefix":"192.168.0.0/24","protocol":"connected","selected":true,"installed":true,
             "nexthops":[{"fib":true,"directlyConnected":true,"interfaceName":"ether1","active":true}]},
            {"prefix":"192.168.0.0/24","protocol":"ospf","distance":110,
             "nexthops":[{"ip":"10.0.1.2","interfaceName":"ether2","active":true}]}],
          "192.168.0.2/32": [
            {"prefix":"192.168.0.2/32","protocol":"ospf","distance":110,"metric":20,
             "nexthops":[{"ip":"10.0.1.2","afi":"ipv4","interfaceName":"ether2"}]}]
        }"#;
        let r = parse_rib(json).unwrap();
        assert_eq!(r.len(), 3);
        let host = r.iter().find(|r| r.prefix.prefix_len() == 32).unwrap();
        assert_eq!(
            (
                host.protocol.as_str(),
                host.installed,
                host.inactive,
                host.via.as_str()
            ),
            ("ospf", false, true, "10.0.1.2 ether2")
        );
        assert!(r.iter().any(|r| r.protocol == "connected" && r.installed));
        assert_eq!(
            parse_rib(b"").unwrap(),
            Vec::new(),
            "nothing inside: zebra prints nothing"
        );
        assert!(parse_rib(b"% Unknown command").is_err());
        assert!(parse_rib(b"[1,2]").is_err());
    }
}
