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
    let v: Value =
        serde_json::from_str(json).map_err(|e| format!("bgpd answered bad JSON: {e}"))?;
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
    let (mut afi, mut policy_in, mut policy_out) = (Vec::new(), None, None);
    if let Some(Value::Object(afs)) = n.get("addressFamilyInfo") {
        for (name, af) in afs {
            if let Value::Object(af) = af {
                if let Some(r) = u64_of(af, "acceptedPrefixCounter") {
                    rcvd = rcvd.saturating_add(r);
                    any = true;
                }
                if let Some(s) = u64_of(af, "sentPrefixCounter") {
                    sent = sent.saturating_add(s);
                    any = true;
                }
                afi.push(family(name));
                policy_in = policy_in.or_else(|| str_of(af, "routeMapForIncomingAdvertisements"));
                policy_out = policy_out.or_else(|| str_of(af, "routeMapForOutgoingAdvertisements"));
            }
        }
    }
    let stats = n.get("messageStats").and_then(Value::as_object);
    let stat = |k: &str| stats.and_then(|s| u64_of(s, k));
    let remote_id = str_of(n, "remoteRouterId").filter(|id| id != "0.0.0.0");
    let secs = |k: &str| u64_of(n, k).map(|ms| ms / 1000);
    let description = str_of(n, "nbrDesc");
    let gr = n.get("gracefulRestartInfo").and_then(Value::as_object);
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
            secs("bgpTimerUpMsec")
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
            str_of(n, "lastResetDueTo")
                .or_else(|| str_of(n, "adminShutDown").map(|_| "Admin. shutdown".into()))
        },
        connection: description.clone(),
        description,
        hold_time: secs("bgpTimerHoldTimeMsecs"),
        keepalive_time: secs("bgpTimerKeepAliveIntervalMsecs"),
        // FRR keeps a reset reason before the first reset too ("No path
        // to specified Neighbor"): shown only once the session went down.
        last_error: str_of(n, "lastNotificationReason")
            .or_else(|| str_of(n, "lastErrorCodeSubcode").map(|c| format!("code {c}")))
            .or_else(|| {
                (!established || u64_of(n, "connectionsDropped").unwrap_or(0) > 0)
                    .then(|| str_of(n, "lastResetDueTo"))
                    .flatten()
            }),
        flaps: u64_of(n, "connectionsDropped"),
        bfd: n
            .get("peerBfdInfo")
            .and_then(Value::as_object)
            .and_then(|b| str_of(b, "status"))
            .map(|s| s.to_ascii_lowercase()),
        afi,
        policy_in,
        policy_out,
        gr_local: gr.and_then(|g| gr_mode(g, "localGrMode")),
        gr_remote: gr.and_then(|g| gr_mode(g, "remoteGrMode")),
        end_of_rib_received: gr
            .and_then(|g| g.get("endOfRibRecv"))
            .and_then(Value::as_object)
            .map(|m| {
                m.iter()
                    .filter(|(_, v)| v.as_bool() == Some(true))
                    .map(|(k, _)| family(k))
                    .collect()
            })
            .unwrap_or_default(),
        // G3.9fj: FRR reports `nBit` only for an established session with
        // the capability on both sides (`bgp_vty.c`,
        // `bgp_show_neighnor_graceful_restart_flags`).
        n_bit: gr
            .and_then(|g| g.get("nBit"))
            .and_then(Value::as_bool)
            .unwrap_or(false),
        // G3.9fj, RFC 9494: per family under `gracefulRestartInfo`
        // (`peer->llgr[afi][safi].stale_time`, what the neighbor sent);
        // FRR sends the capability with 0 whenever it announces GR.
        llgr_stale_time: gr
            .map(|g| {
                g.values()
                    .filter_map(|f| f.get("timers")?.get("llgrStaleTime")?.as_u64())
                    .max()
                    .unwrap_or(0)
            })
            .and_then(|t| u32::try_from(t).ok())
            .filter(|t| *t > 0),
        // Only while down: FRR clears `notify.hard_reset` when a
        // graceful-restart session comes back (`bgp_fsm.c`,
        // `bgp_peer_process_gr_cap_clear_stale`) and keeps the error code,
        // so an established session always says false (**medido**).
        last_hard_reset: n
            .get("lastNotificationHardReset")
            .and_then(Value::as_bool)
            .filter(|_| !established && n.get("lastErrorCodeSubcode").is_some()),
    }
}

/// G3.9ff: FRR's `Restart`, `Helper*` (the `*`: inherited from the
/// instance), `Disable`, lowercase; `NotApplicable` and the rest: none.
fn gr_mode(g: &Map<String, Value>, key: &str) -> Option<String> {
    let m = g
        .get(key)?
        .as_str()?
        .trim_end_matches('*')
        .to_ascii_lowercase();
    matches!(m.as_str(), "restart" | "helper" | "disable").then_some(m)
}

/// `ipv4Unicast` → `ipv4`.
fn family(key: &str) -> String {
    key.strip_suffix("Unicast").unwrap_or(key).to_owned()
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
          },
          "gracefulRestartInfo": {"endOfRibSend": {"ipv4Unicast": true}, "endOfRibRecv": {"ipv4Unicast": true},
            "localGrMode": "Restart", "remoteGrMode": "Helper", "rBit": false, "nBit": true,
            "ipv4Unicast": {"timers": {"llgrStaleTime": 3600, "stalePathTimer": 360}},
            "ipv6Unicast": {"timers": {"llgrStaleTime": 0}}}
        },
        "192.0.2.6": {
          "remoteAs": 65002, "localAs": 65000, "remoteRouterId": "0.0.0.0",
          "bgpState": "Active", "lastResetDueTo": "Waiting for peer OPEN",
          "lastErrorCodeSubcode": "0609", "lastNotificationReason": "Cease/Hard Reset", "lastNotificationHardReset": true,
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
        // G3.9ff: the graceful-restart roles and the End-of-RIBs received.
        assert_eq!(
            (up.gr_local.as_deref(), up.gr_remote.as_deref()),
            (Some("restart"), Some("helper"))
        );
        assert_eq!(up.end_of_rib_received, ["ipv4"]);
        assert!(up.n_bit, "RFC 8538 §2");
        assert_eq!(up.llgr_stale_time, Some(3600), "RFC 9494 §3.1");
        let down = &s[1];
        assert_eq!(
            (down.gr_local.as_deref(), down.end_of_rib_received.len()),
            (None, 0)
        );
        assert!(!down.n_bit);
        assert_eq!(down.llgr_stale_time, None);
        assert_eq!(down.last_hard_reset, Some(true), "RFC 8538 §3");
        assert_eq!(up.last_hard_reset, None, "established: FRR has cleared it");
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
