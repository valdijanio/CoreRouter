//! Sessions read from `bgpd` (`show bgp vrf all neighbors json`, `show bgp
//! view NAME neighbors json`), turned into the model's [`BgpSession`].
//!
//! The JSON is the daemon's, so it is read leniently: a missing or oddly
//! typed field becomes `None`, never an error, and an object is a neighbor
//! only when it has `bgpState`.

use corerouter_model::routing_state::BgpSession;
use serde_json::{Map, Value};

/// Sessions in `json`. `vrf_instance` maps the VRF (or view) name FRR
/// reports to the CoreRouter instance; `vrf` is the name when the output is
/// one instance's flat map of neighbors (`show bgp view X neighbors json`).
pub fn bgp_sessions(
    json: &str,
    vrf: Option<&str>,
    vrf_instance: &dyn Fn(&str) -> String,
) -> Result<Vec<BgpSession>, String> {
    let v: Value = serde_json::from_str(json).map_err(|e| format!("bgpd answered bad JSON: {e}"))?;
    let Value::Object(top) = v else {
        return Err("bgpd answered JSON that is not an object".into());
    };
    let mut out = Vec::new();
    match vrf {
        Some(name) => neighbors(&top, name, vrf_instance, &mut out),
        None => {
            for (key, val) in &top {
                if let Value::Object(inner) = val {
                    let name = inner.get("vrfName").and_then(Value::as_str).unwrap_or(key);
                    neighbors(inner, name, vrf_instance, &mut out);
                }
            }
        }
    }
    out.sort_by(|a, b| (&a.instance, &a.remote_address).cmp(&(&b.instance, &b.remote_address)));
    Ok(out)
}

fn neighbors(
    map: &Map<String, Value>,
    vrf: &str,
    vrf_instance: &dyn Fn(&str) -> String,
    out: &mut Vec<BgpSession>,
) {
    for (addr, n) in map {
        let Value::Object(n) = n else { continue };
        let Some(state) = n.get("bgpState").and_then(Value::as_str) else {
            continue;
        };
        out.push(session(addr, n, state, vrf, vrf_instance(vrf)));
    }
}

fn u64_of(n: &Map<String, Value>, key: &str) -> Option<u64> {
    n.get(key).and_then(Value::as_u64)
}

fn str_of(n: &Map<String, Value>, key: &str) -> Option<String> {
    n.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

fn session(
    addr: &str,
    n: &Map<String, Value>,
    state: &str,
    vrf: &str,
    instance: String,
) -> BgpSession {
    let established = state == "Established";
    let (mut rcvd, mut sent, mut any) = (0u64, 0u64, false);
    if let Some(Value::Object(afs)) = n.get("addressFamilyInfo") {
        for af in afs.values() {
            if let Value::Object(af) = af {
                if let Some(r) = u64_of(af, "acceptedPrefixCounter") {
                    rcvd = rcvd.saturating_add(r);
                    any = true;
                }
                if let Some(s) = u64_of(af, "sentPrefixCounter") {
                    sent = sent.saturating_add(s);
                    any = true;
                }
            }
        }
    }
    let stats = n.get("messageStats").and_then(Value::as_object);
    let stat = |k: &str| stats.and_then(|s| u64_of(s, k));
    let remote_id = str_of(n, "remoteRouterId").filter(|id| id != "0.0.0.0");
    BgpSession {
        instance,
        vrf: vrf.to_owned(),
        remote_address: addr.to_owned(),
        remote_as: u64_of(n, "remoteAs")
            .and_then(|a| u32::try_from(a).ok())
            .unwrap_or(0),
        local_as: u64_of(n, "localAs")
            .and_then(|a| u32::try_from(a).ok())
            .unwrap_or(0),
        remote_id,
        state: state.to_ascii_lowercase(),
        established,
        uptime_secs: if established {
            u64_of(n, "bgpTimerUpMsec").map(|ms| ms / 1000)
        } else {
            None
        },
        prefix_count: any.then_some(rcvd),
        prefix_sent: any.then_some(sent),
        messages_received: stat("totalRecv"),
        messages_sent: stat("totalSent"),
        reason: if established {
            None
        } else {
            str_of(n, "lastResetDueTo").or_else(|| str_of(n, "adminShutDown").map(|_| "Admin. shutdown".into()))
        },
        description: str_of(n, "nbrDesc"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VRF_ALL: &str = r#"{
      "default": {
        "vrfId": 0, "vrfName": "default",
        "192.0.2.2": {
          "remoteAs": 65001, "localAs": 65000, "nbrExternalLink": true,
          "nbrDesc": "upstream", "remoteRouterId": "192.0.2.2",
          "bgpState": "Established", "bgpTimerUpMsec": 93000,
          "messageStats": {"totalSent": 7, "totalRecv": 9},
          "addressFamilyInfo": {
            "ipv4Unicast": {"acceptedPrefixCounter": 10, "sentPrefixCounter": 2},
            "ipv6Unicast": {"acceptedPrefixCounter": 5, "sentPrefixCounter": 1}
          }
        },
        "192.0.2.6": {
          "remoteAs": 65002, "localAs": 65000, "remoteRouterId": "0.0.0.0",
          "bgpState": "Active", "lastResetDueTo": "Waiting for peer OPEN",
          "messageStats": {"totalSent": 0, "totalRecv": 0}
        }
      }
    }"#;

    #[test]
    fn reads_neighbors_of_every_vrf() {
        let s = bgp_sessions(VRF_ALL, None, &|v| v.to_owned()).unwrap();
        assert_eq!(s.len(), 2);
        let up = &s[0];
        assert_eq!(up.remote_address, "192.0.2.2");
        assert!(up.established);
        assert_eq!(up.uptime_secs, Some(93));
        assert_eq!(up.prefix_count, Some(15));
        assert_eq!(up.prefix_sent, Some(3));
        assert_eq!(up.messages_received, Some(9));
        assert_eq!(up.description.as_deref(), Some("upstream"));
        let down = &s[1];
        assert_eq!(down.state, "active");
        assert_eq!(down.remote_id, None);
        assert_eq!(down.reason.as_deref(), Some("Waiting for peer OPEN"));
        assert_eq!(down.prefix_count, None);
    }

    #[test]
    fn reads_one_view() {
        let json = r#"{"10.9.9.9": {"remoteAs": 1, "localAs": 2, "bgpState": "Idle"}}"#;
        let s = bgp_sessions(json, Some("lab"), &|v| format!("i-{v}")).unwrap();
        assert_eq!(s[0].instance, "i-lab");
        assert_eq!(s[0].vrf, "lab");
    }

    #[test]
    fn hostile_json_is_an_error_or_ignored() {
        assert!(bgp_sessions("not json", None, &|v| v.into()).is_err());
        assert!(bgp_sessions("[1]", None, &|v| v.into()).is_err());
        let odd = r#"{"default": {"x": {"bgpState": 5}, "y": 3, "z": {"bgpState": "Idle", "remoteAs": -1}}}"#;
        let s = bgp_sessions(odd, None, &|v| v.into()).unwrap();
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].remote_as, 0);
    }
}
