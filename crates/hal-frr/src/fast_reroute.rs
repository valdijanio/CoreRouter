//! TI-LFA backups as zebra installed them (G3.4d): `show ip route ospf
//! json` (FRR 10.7.1 `zebra/zebra_vty.c`, `lib/nexthop.c`): per prefix,
//! the `nexthops` with their `labels` and `backupIndex`, and the
//! `backupNexthops` they point to. `ospfd` itself prints no backup: it hands
//! them to zebra (`ospf_zebra.c`, `backup_nexthops`).
//!
//! Read straight from the socket into typed rows (unknown fields skipped by
//! serde, no JSON tree), so 10 000 routes never sit in memory as `Value`s
//! (numbers in `docs/ospf.md`).

use std::collections::BTreeMap;
use std::io::Read;

use corerouter_model::ospf_state::{FrrHop, RouteFrr};
use serde::Deserialize;

/// Most routes kept (past it the rest are dropped).
pub const MAX_ROUTES: usize = 200_000;
const MAX_HOPS: usize = 16;
const MAX_LABELS: usize = 16;

#[derive(Deserialize)]
struct Hop {
    #[serde(default)]
    ip: Option<String>,
    #[serde(default, rename = "interfaceName")]
    interface: Option<String>,
    #[serde(default)]
    labels: Vec<u32>,
    #[serde(default, rename = "backupIndex")]
    backup_index: Vec<usize>,
}

#[derive(Deserialize)]
struct Route {
    #[serde(default)]
    protocol: String,
    #[serde(default)]
    selected: bool,
    #[serde(default)]
    nexthops: Vec<Hop>,
    #[serde(default, rename = "backupNexthops")]
    backups: Vec<Hop>,
}

fn hop(h: &Hop) -> FrrHop {
    FrrHop {
        via: h.ip.as_ref().map(|s| s.chars().take(64).collect()),
        interface: h
            .interface
            .as_deref()
            .unwrap_or("")
            .chars()
            .take(32)
            .collect(),
        labels: h.labels.iter().take(MAX_LABELS).copied().collect(),
    }
}

/// prefix → what zebra has for the selected OSPF route.
pub fn read(input: impl Read) -> Result<BTreeMap<String, RouteFrr>, String> {
    let all: BTreeMap<String, Vec<Route>> =
        serde_json::from_reader(std::io::BufReader::with_capacity(64 * 1024, input))
            .map_err(|e| format!("zebra answered bad JSON: {e}"))?;
    let mut out = BTreeMap::new();
    for (prefix, routes) in all {
        if out.len() >= MAX_ROUTES {
            break;
        }
        let Some(r) = routes
            .iter()
            .find(|r| r.protocol == "ospf" && r.selected)
            .or_else(|| routes.iter().find(|r| r.protocol == "ospf"))
        else {
            continue;
        };
        let primary: Vec<FrrHop> = r.nexthops.iter().take(MAX_HOPS).map(hop).collect();
        let mut backup: Vec<FrrHop> = Vec::new();
        for h in r.nexthops.iter().take(MAX_HOPS) {
            for i in &h.backup_index {
                if let Some(b) = r.backups.get(*i) {
                    let b = hop(b);
                    if !backup.contains(&b) {
                        backup.push(b);
                    }
                }
            }
        }
        // A backup list without indexes still counts.
        if backup.is_empty() {
            backup = r.backups.iter().take(MAX_HOPS).map(hop).collect();
        }
        out.insert(
            prefix.chars().take(64).collect(),
            RouteFrr { primary, backup },
        );
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// zebra's JSON for R4 of the lab square (FRR 10.7.1, lab VM).
    pub(crate) const SAMPLE: &str = r#"{
      "10.255.0.2/32": [{"prefix": "10.255.0.2/32", "protocol": "ospf", "selected": true, "installed": true,
        "nexthops": [{"flags": 3, "fib": true, "ip": "10.0.14.1", "afi": "ipv4", "interfaceIndex": 5,
          "interfaceName": "crsr-g", "active": true, "backupIndex": [0], "labels": [16002], "weight": 1}],
        "backupNexthops": [{"flags": 1, "ip": "10.0.34.2", "afi": "ipv4", "interfaceName": "crsr-f",
          "labels": [15001, 16002], "weight": 1}]}],
      "10.0.23.0/30": [{"prefix": "10.0.23.0/30", "protocol": "ospf", "selected": true,
        "nexthops": [{"ip": "10.0.34.2", "interfaceName": "crsr-f"}]}],
      "10.9.9.0/24": [{"protocol": "static", "nexthops": []}]
    }"#;

    #[test]
    fn reads_primaries_and_backups() {
        let m = read(SAMPLE.as_bytes()).unwrap();
        assert_eq!(m.len(), 2, "{m:?}");
        let r = &m["10.255.0.2/32"];
        assert_eq!(r.primary[0].labels, vec![16002]);
        assert_eq!(r.backup[0].via.as_deref(), Some("10.0.34.2"));
        assert_eq!(r.backup[0].interface, "crsr-f");
        assert_eq!(r.backup[0].labels, vec![15001, 16002]);
        assert!(m["10.0.23.0/30"].backup.is_empty());
        assert!(read("nope".as_bytes()).is_err());
    }
}
