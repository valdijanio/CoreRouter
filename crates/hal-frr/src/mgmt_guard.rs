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

use corerouter_model::Config;
use corerouter_model::mgmt_guard::RibRoute;
use ipnet::IpNet;
use serde_json::Value;

/// The route-map and prefix-list names, per family.
pub const V4: &str = "CR-MG-4";
pub const V6: &str = "CR-MG-6";

/// Most routes read from one guarded network's RIB.
pub const MAX_RIB_ROUTES: usize = 10_000;

/// The FRR text of `cfg`'s guard (empty when nothing is active).
pub fn render(cfg: &Config) -> String {
    let mut out = String::new();
    for (v6, name, ip) in [(false, V4, "ip"), (true, V6, "ipv6")] {
        let nets: Vec<&IpNet> = cfg
            .routing
            .management_guard
            .active()
            .filter(|n| n.addr().is_ipv6() == v6 && n.prefix_len() < n.max_prefix_len())
            .collect();
        if nets.is_empty() {
            continue;
        }
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
             route-map {name} permit 65535\nexit\n\
             {ip} protocol any route-map {name}\n"
        );
    }
    out
}

/// The zebra command that lists `net` and what is inside it.
pub fn rib_command(net: &IpNet) -> String {
    let ip = if net.addr().is_ipv4() { "ip" } else { "ipv6" };
    format!("show {ip} route {net} longer-prefixes json")
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
        let mut c = Config::default();
        for (i, (n, disabled)) in nets.iter().enumerate() {
            c.routing.management_guard.networks.push(GuardNetwork {
                id: ItemId(i as u32 + 1),
                network: n.parse().unwrap(),
                disabled: *disabled,
                comment: String::new(),
            });
        }
        c
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
