//! Why a neighbor does not reach Full: the checks of RFC 2328 §10.5 (a
//! Hello is dropped when the area, the mask on a multi-access link, the
//! hello or dead interval, or the E/N option bits differ from ours),
//! §10.6 (a Database Description with a larger MTU is dropped: the pair
//! sticks in ExStart/Exchange), §D (authentication) and §C.1 (two routers
//! with one router id), with the section that says so.
//!
//! The inputs are what this router runs on the interface ([`Local`], from
//! the config and the daemon's interface state), the neighbor states the
//! daemon reports, and — when a capture ran — the Hellos and DDs the far
//! end sent ([`crate::packet`]). Each finding names the side to change.

use std::net::Ipv4Addr;

use crate::packet::{Auth, Body, OPT_E, OPT_N, Packet, digest_name};

/// What this router runs on the interface.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Local {
    pub version: u8,
    pub interface: String,
    pub router_id: Option<Ipv4Addr>,
    pub area: u32,
    /// Stub (no E bit) or NSSA (N bit, no E bit), RFC 3101 §2.3.
    pub stub: bool,
    pub nssa: bool,
    /// v2: the interface's mask (compared on broadcast/NBMA only).
    pub mask: Option<Ipv4Addr>,
    /// `broadcast`, `ptp`, `nbma`, `ptmp`.
    pub network_type: String,
    pub hello: u32,
    pub dead: u32,
    pub mtu: Option<u32>,
    pub mtu_ignore: bool,
    /// `none`, `simple`, `md5`, `sha256`, …
    pub auth: String,
    pub key_id: Option<u16>,
    pub passive: bool,
    /// The daemon's view of the interface (`DR`, `Point-To-Point`, `Down`).
    pub state: Option<String>,
}

/// A neighbor as the daemon reports it on this interface.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Seen {
    pub router_id: String,
    pub state: String,
    pub state_secs: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// `error` (keeps the adjacency down), `warning`, `ok`, `info`.
    pub level: &'static str,
    /// A stable id (`mtu`, `dead-interval`, …) for the UI and the
    /// translations.
    pub check: &'static str,
    pub message: String,
    /// The RFC section that says so.
    pub rfc: &'static str,
}

fn find(level: &'static str, check: &'static str, message: String, rfc: &'static str) -> Finding {
    Finding {
        level,
        check,
        message,
        rfc,
    }
}

fn bits(o: u32) -> (bool, bool) {
    (o & OPT_E != 0, o & OPT_N != 0)
}

/// Every finding for one interface.
pub fn diagnose(local: &Local, seen: &[Seen], heard: &[Packet]) -> Vec<Finding> {
    let mut out = Vec::new();
    let iface = &local.interface;
    if local.passive {
        out.push(find(
            "info",
            "passive",
            format!("{iface} is passive: no Hello is sent, so no neighbor forms here (by design)"),
            "RFC 2328 §C.3",
        ));
        return out;
    }
    if local.state.as_deref() == Some("Down") {
        out.push(find(
            "error",
            "down",
            format!("{iface} is down in the daemon (no link or no address)"),
            "RFC 2328 §9.1",
        ));
    }
    for n in seen {
        let st = n.state.split('/').next().unwrap_or("");
        let mins = n.state_secs.map_or(String::new(), |s| match s {
            // Seen in the lab VM: "stuck in Exchange for 0 min".
            0..60 => format!(" for {s} s"),
            _ => format!(" for {} min", s / 60),
        });
        match st {
            "Full" => out.push(find("ok", "full", format!("{} is Full{mins}", n.router_id), "RFC 2328 §10.1")),
            "2-Way" | "TwoWay" if local.network_type == "broadcast" || local.network_type == "nbma" => out.push(find(
                "ok",
                "two-way",
                format!("{} stays 2-Way: on a multi-access link only the DR and the BDR become Full with everyone (normal)", n.router_id),
                "RFC 2328 §10.4",
            )),
            "ExStart" | "Exchange" => out.push(find(
                "error",
                "stuck-exstart",
                format!(
                    "{} is stuck in {st}{mins}: the database exchange does not finish — usually an MTU mismatch (the side with the smaller MTU drops the other's DD packets)",
                    n.router_id
                ),
                "RFC 2328 §10.6",
            )),
            "Init" => out.push(find(
                "error",
                "one-way",
                format!(
                    "{} is in Init: its Hellos arrive but do not list us — it drops ours (authentication, area, timers or mask differ on its side) or multicast is filtered towards it",
                    n.router_id
                ),
                "RFC 2328 §10.5",
            )),
            "Loading" => out.push(find("info", "loading", format!("{} is Loading (requesting LSAs)", n.router_id), "RFC 2328 §10.9")),
            _ => {}
        }
    }
    if seen.is_empty() && heard.is_empty() {
        out.push(find(
            "warning",
            "silent",
            format!(
                "no neighbor on {iface}: nothing heard. Check that the far end runs OSPF on this link, that multicast 224.0.0.5 (ff02::5) is not filtered, and the checks below once a capture hears it"
            ),
            "RFC 2328 §10.5",
        ));
    }
    for p in heard {
        compare(local, p, &mut out);
    }
    out.dedup();
    out
}

fn compare(local: &Local, p: &Packet, out: &mut Vec<Finding>) {
    let who = p.router_id;
    if local.router_id == Some(who) {
        out.push(find(
            "error",
            "duplicate-router-id",
            format!(
                "a router on {} uses our router id {who}: router ids must be unique in the AS",
                local.interface
            ),
            "RFC 2328 §C.1",
        ));
    }
    if p.area != local.area {
        out.push(find(
            "error",
            "area",
            format!(
                "{who} is in area {} and we are in {}: Hellos of another area are dropped",
                Ipv4Addr::from(p.area),
                Ipv4Addr::from(local.area)
            ),
            "RFC 2328 §10.5",
        ));
    }
    auth(local, p, out);
    match &p.body {
        Body::Hello(h) => {
            if u32::from(h.hello_interval) != local.hello {
                out.push(find(
                    "error",
                    "hello-interval",
                    format!(
                        "{who} sends Hellos every {} s, we every {} s: they must match",
                        h.hello_interval, local.hello
                    ),
                    "RFC 2328 §10.5",
                ));
            }
            if h.dead_interval != local.dead {
                out.push(find(
                    "error",
                    "dead-interval",
                    format!(
                        "{who} has dead interval {} s, we {} s: they must match",
                        h.dead_interval, local.dead
                    ),
                    "RFC 2328 §10.5",
                ));
            }
            let multi = local.network_type == "broadcast" || local.network_type == "nbma";
            if multi
                && let (Some(m), Some(ours)) = (h.mask, local.mask)
                && m != ours
            {
                out.push(find(
                    "error",
                    "mask",
                    format!(
                        "{who} has mask {m}, we {ours}: on a multi-access link they must match"
                    ),
                    "RFC 2328 §10.5",
                ));
            }
            let (e, n) = bits(h.options);
            let want_e = !local.stub && !local.nssa;
            if e != want_e || (local.version == 2 && n != local.nssa) {
                let theirs = if n {
                    "NSSA"
                } else if e {
                    "a normal area"
                } else {
                    "stub"
                };
                let ours = if local.nssa {
                    "NSSA"
                } else if local.stub {
                    "stub"
                } else {
                    "a normal area"
                };
                out.push(find(
                    "error",
                    "area-type",
                    format!("{who} treats the area as {theirs}, we as {ours}: the E/N bits of the Hello must agree"),
                    "RFC 2328 §10.5, RFC 3101 §2.3",
                ));
            }
            // A ptp end sends no DR; a broadcast end elects one: the two
            // never agree on adjacency rules.
            let ptp = matches!(local.network_type.as_str(), "ptp" | "ptmp");
            if ptp && (h.dr != Ipv4Addr::UNSPECIFIED || h.bdr != Ipv4Addr::UNSPECIFIED) {
                out.push(find(
                    "warning",
                    "network-type",
                    format!("{who} elects a DR ({}) and we run {}: set the same network type on both ends", h.dr, local.network_type),
                    "RFC 2328 §9.4",
                ));
            }
            if let Some(id) = local.router_id
                && !h.neighbors.contains(&id)
                && !h.neighbors.is_empty()
            {
                out.push(find(
                    "warning",
                    "not-listed",
                    format!("{who}'s Hello does not list us: it does not accept our Hellos"),
                    "RFC 2328 §10.5",
                ));
            }
        }
        Body::Dd(d) => {
            if let Some(mtu) = local.mtu
                && u32::from(d.mtu) != mtu
                && d.mtu != 0
                && !local.mtu_ignore
            {
                out.push(find(
                    "error",
                    "mtu",
                    format!(
                        "{who} has interface MTU {}, we {mtu}: the side with the smaller MTU drops the other's DD packets and the pair sticks in ExStart (fix the MTU, or mtu-ignore on both)",
                        d.mtu
                    ),
                    "RFC 2328 §10.6",
                ));
            }
        }
        Body::Other(_) => {}
    }
}

fn auth(local: &Local, p: &Packet, out: &mut Vec<Finding>) {
    let theirs = match p.auth {
        Auth::None => "none".to_owned(),
        Auth::Simple => "simple".to_owned(),
        Auth::Crypto { len, .. } => digest_name(len).to_owned(),
        Auth::Trailer => "trailer".to_owned(),
        Auth::Other(n) => format!("type {n}"),
    };
    let ours = local.auth.as_str();
    let agree = match p.auth {
        Auth::None => ours == "none",
        Auth::Simple => ours == "simple",
        Auth::Crypto { .. } => theirs == ours,
        Auth::Trailer => ours != "none",
        Auth::Other(_) => false,
    };
    if !agree {
        out.push(find(
            "error",
            "auth",
            format!("{} authenticates with {theirs}, we with {ours}: both ends must use the same type and key", p.router_id),
            if local.version == 3 { "RFC 7166 §4" } else { "RFC 2328 §D.2" },
        ));
    } else if let (Auth::Crypto { key_id, .. }, Some(k)) = (p.auth, local.key_id)
        && u16::from(key_id) != k
    {
        out.push(find(
            "error",
            "key-id",
            format!("{} signs with key id {key_id}, we with {k}: the key ids (RouterOS auth-id) must match", p.router_id),
            "RFC 2328 §D.3",
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::parse;

    fn local() -> Local {
        Local {
            version: 2,
            interface: "ether1".into(),
            router_id: Some(Ipv4Addr::new(10, 0, 0, 1)),
            area: 0,
            mask: Some(Ipv4Addr::new(255, 255, 255, 0)),
            network_type: "broadcast".into(),
            hello: 10,
            dead: 40,
            mtu: Some(1500),
            auth: "none".into(),
            ..Local::default()
        }
    }

    #[test]
    fn dead_interval_and_area_type_mismatch() {
        let p = parse(&crate::packet::tests::hello_v2(120, 0)).unwrap();
        let f = diagnose(&local(), &[], &[p]);
        let checks: Vec<_> = f.iter().map(|f| f.check).collect();
        assert!(checks.contains(&"dead-interval"), "{f:?}");
        assert!(checks.contains(&"area-type"), "{f:?}");
        assert!(f.iter().all(|f| !f.rfc.is_empty()));
    }

    #[test]
    fn exstart_points_at_the_mtu() {
        let seen = [Seen {
            router_id: "10.0.0.2".into(),
            state: "ExStart/DR".into(),
            state_secs: Some(300),
        }];
        let f = diagnose(&local(), &seen, &[]);
        assert_eq!(f[0].check, "stuck-exstart");
        assert_eq!(f[0].rfc, "RFC 2328 §10.6");
        assert!(f[0].message.contains("for 5 min"));
        // Under a minute: seconds, not "0 min".
        let seen = [Seen {
            state_secs: Some(12),
            ..seen[0].clone()
        }];
        let f = diagnose(&local(), &seen, &[]);
        assert!(f[0].message.contains("for 12 s"), "{}", f[0].message);
    }

    #[test]
    fn a_matching_hello_is_quiet() {
        let p = parse(&crate::packet::tests::hello_v2(40, OPT_E as u8)).unwrap();
        let f = diagnose(&local(), &[], &[p]);
        assert!(f.iter().all(|f| f.level != "error"), "{f:?}");
    }
}
