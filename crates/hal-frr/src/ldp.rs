//! LDP state read from `ldpd` (G3.5): `show mpls ldp neighbor json`,
//! `binding json`, `interface json`, and `ospfd`'s `show ip ospf mpls
//! ldp-sync json` (RFC 5443), turned into the model's [`LdpState`].
//!
//! The JSON is the daemon's, read leniently: an unknown or oddly typed
//! field is skipped, never an error; only output that is not JSON is.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use corerouter_model::mpls::{IMPLICIT_NULL, IPV4_EXPLICIT_NULL, IPV6_EXPLICIT_NULL};
use corerouter_model::mpls_state::{
    IgpSyncState, LdpBinding, LdpInterfaceState, LdpNeighborState, RemoteLabel,
};
use serde_json::{Map, Value};

/// Bindings kept from one read at most (hostile or huge input).
pub const MAX_BINDINGS: usize = 200_000;

fn parse(json: &str, what: &str) -> Result<Value, String> {
    serde_json::from_str(json).map_err(|e| format!("ldpd answered bad JSON for {what}: {e}"))
}

fn text(m: &Map<String, Value>, k: &str) -> Option<String> {
    m.get(k)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(|s| s.chars().take(64).collect())
}

/// A label as FRR prints it: a number, `imp-null`, `exp-null`, `-`.
pub fn label(v: &Value) -> Option<u32> {
    if let Some(n) = v.as_u64() {
        return u32::try_from(n).ok();
    }
    let s = v.as_str()?;
    match s {
        "imp-null" | "implicit-null" => Some(IMPLICIT_NULL),
        "exp-null" | "explicit-null" => Some(IPV4_EXPLICIT_NULL),
        "exp-null6" => Some(IPV6_EXPLICIT_NULL),
        s => s.parse().ok(),
    }
}

fn truthy(v: Option<&Value>) -> bool {
    match v {
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_u64().is_some_and(|n| n != 0),
        Some(Value::String(s)) => matches!(s.as_str(), "yes" | "true" | "1"),
        _ => false,
    }
}

/// `{"neighbors": [...]}`.
pub fn neighbors(json: &str) -> Result<Vec<LdpNeighborState>, String> {
    let v = parse(json, "neighbors")?;
    let list = v
        .get("neighbors")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut out: Vec<LdpNeighborState> = list
        .iter()
        .filter_map(Value::as_object)
        .filter_map(|n| {
            Some(LdpNeighborState {
                lsr_id: text(n, "neighborId")?.parse().ok()?,
                afi: text(n, "addressFamily").unwrap_or_default(),
                state: text(n, "state").unwrap_or_default(),
                transport: text(n, "transportAddress").and_then(|t| t.parse().ok()),
                uptime: text(n, "upTime"),
            })
        })
        .collect();
    out.sort_by_key(|n| n.lsr_id);
    Ok(out)
}

/// `{"bindings": [{prefix, neighborId, localLabel, remoteLabel, inUse}]}`:
/// one line per (FEC, neighbor), grouped by FEC.
pub fn bindings(json: &str) -> Result<Vec<LdpBinding>, String> {
    let v = parse(json, "bindings")?;
    let list = v
        .get("bindings")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut by: BTreeMap<ipnet::IpNet, LdpBinding> = BTreeMap::new();
    for b in list.iter().filter_map(Value::as_object) {
        let Some(prefix) = text(b, "prefix").and_then(|p| p.parse::<ipnet::IpNet>().ok()) else {
            continue;
        };
        if by.len() >= MAX_BINDINGS && !by.contains_key(&prefix) {
            continue;
        }
        let e = by.entry(prefix).or_insert_with(|| LdpBinding {
            prefix,
            local_label: None,
            remote: Vec::new(),
        });
        if e.local_label.is_none() {
            e.local_label = b.get("localLabel").and_then(label);
        }
        let neighbor = text(b, "neighborId").and_then(|n| n.parse::<Ipv4Addr>().ok());
        let remote = b.get("remoteLabel").and_then(label);
        if let (Some(neighbor), Some(label)) = (neighbor, remote)
            && e.remote.len() < 64
        {
            e.remote.push(RemoteLabel {
                neighbor,
                label,
                in_use: truthy(b.get("inUse")),
            });
        }
    }
    Ok(by.into_values().collect())
}

/// `{"<ifname>": {name, addressFamily, state, adjacencyCount}}`, or the
/// same objects in a list.
pub fn interfaces(json: &str) -> Result<Vec<LdpInterfaceState>, String> {
    let v = parse(json, "interfaces")?;
    let items: Vec<(&str, &Map<String, Value>)> = match &v {
        Value::Object(m) => m
            .iter()
            .filter_map(|(k, v)| Some((k.as_str(), v.as_object()?)))
            .collect(),
        Value::Array(a) => a
            .iter()
            .filter_map(|v| Some(("", v.as_object()?)))
            .collect(),
        _ => Vec::new(),
    };
    let mut out: Vec<LdpInterfaceState> = items
        .into_iter()
        .filter_map(|(k, i)| {
            let name = text(i, "name").unwrap_or_else(|| k.to_owned());
            // Keys like "ether1: ipv4" (one per family) carry the name inside.
            let name = name.split(':').next().unwrap_or_default().trim().to_owned();
            (!name.is_empty()).then(|| LdpInterfaceState {
                name,
                afi: text(i, "addressFamily").unwrap_or_default(),
                state: text(i, "state").unwrap_or_default(),
                adjacencies: i
                    .get("adjacencyCount")
                    .and_then(Value::as_u64)
                    .and_then(|n| u32::try_from(n).ok())
                    .unwrap_or(0),
            })
        })
        .collect();
    out.sort_by(|a, b| (&a.name, &a.afi).cmp(&(&b.name, &b.afi)));
    Ok(out)
}

/// ospfd's `show ip ospf mpls ldp-sync json`: per interface, whether the
/// sync is achieved (RFC 5443 §2) and the holddown left.
pub fn ospf_sync(json: &str) -> Result<Vec<IgpSyncState>, String> {
    let v = parse(json, "ldp-sync")?;
    let Value::Object(top) = v else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for (name, i) in &top {
        let Value::Object(i) = i else { continue };
        let state = ["ldpIgpSyncState", "syncState", "state"]
            .iter()
            .find_map(|k| text(i, k))
            .unwrap_or_default()
            .to_ascii_lowercase();
        // "Sync not required: non-p2p link" (a loopback, a broadcast
        // link): RFC 5443 does not apply there, so no row (it would read
        // as waiting forever). Seen on FRR 10.7.1 in the lab VM.
        if state.is_empty() || state.contains("not required") {
            continue;
        }
        out.push(IgpSyncState {
            interface: name.chars().take(32).collect(),
            igp: "ospf".into(),
            achieved: state.contains("achieved") && !state.contains("not"),
            holddown_left: ["holdDownTimeRemainingInSec", "holdDownTimeRemaining"]
                .iter()
                .find_map(|k| i.get(*k).and_then(Value::as_u64))
                .and_then(|n| u32::try_from(n).ok()),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn reads_ldpd_json() {
        let n = neighbors(r#"{"neighbors":[{"addressFamily":"ipv4","neighborId":"10.255.0.2","state":"OPERATIONAL","transportAddress":"10.255.0.2","upTime":"00:01:02"},{"neighborId":"junk"}]}"#).unwrap();
        assert_eq!(n.len(), 1);
        assert!(n[0].operational());
        let b = bindings(r#"{"bindings":[
            {"addressFamily":"ipv4","prefix":"10.255.0.2/32","neighborId":"10.255.0.2","localLabel":"16","remoteLabel":"imp-null","inUse":1},
            {"addressFamily":"ipv4","prefix":"10.255.0.1/32","neighborId":"10.255.0.2","localLabel":"imp-null","remoteLabel":"17","inUse":0},
            {"addressFamily":"ipv4","prefix":"10.9.0.0/24","neighborId":"-","localLabel":"18","remoteLabel":"-","inUse":0}
        ]}"#).unwrap();
        assert_eq!(b.len(), 3);
        let own = b
            .iter()
            .find(|x| x.prefix.to_string() == "10.255.0.1/32")
            .unwrap();
        assert_eq!(own.local_label, Some(IMPLICIT_NULL));
        let php = b
            .iter()
            .find(|x| x.prefix.to_string() == "10.255.0.2/32")
            .unwrap();
        assert_eq!(php.in_use().map(|r| r.label), Some(IMPLICIT_NULL));
        assert!(
            b.iter()
                .find(|x| x.prefix.to_string() == "10.9.0.0/24")
                .unwrap()
                .remote
                .is_empty()
        );
        let i = interfaces(r#"{"ether1: ipv4":{"name":"ether1","addressFamily":"ipv4","state":"ACTIVE","adjacencyCount":1}}"#).unwrap();
        assert_eq!(i[0].name, "ether1");
        assert_eq!(i[0].adjacencies, 1);
        let s = ospf_sync(r#"{"ether1":{"ldpIgpSyncEnabled":true,"ldpIgpSyncState":"Sync achieved"},"ether2":{"ldpIgpSyncState":"Sync not achieved"}}"#).unwrap();
        assert!(s[0].achieved && !s[1].achieved);
        // FRR 10.7.1's own output (lab VM, scripts/frr-ldp-live.sh).
        let s = ospf_sync(r#"{
  "crldp-a":{"ldpIgpSyncEnabled":true,"holdDownTimeInSec":0,"ldpIgpSyncState":"Sync not achieved"},
  "crldp-lo":{"ldpIgpSyncEnabled":true,"holdDownTimeInSec":0,"ldpIgpSyncState":"Sync not required: non-p2p link"}
}"#).unwrap();
        assert_eq!(s.len(), 1);
        assert_eq!((s[0].interface.as_str(), s[0].achieved), ("crldp-a", false));
    }

    #[test]
    fn hostile_json_is_an_error_or_ignored() {
        assert!(neighbors("not json").is_err());
        assert!(bindings("[]").unwrap().is_empty());
        assert!(interfaces("3").unwrap().is_empty());
        assert!(ospf_sync(r#"{"x":5}"#).unwrap().is_empty());
        assert_eq!(label(&Value::from(u64::MAX)), None);
    }
}
