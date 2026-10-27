//! What a commit does to the adjacencies: the interfaces of the running
//! config against those of the candidate, and which changes bring the
//! adjacencies on an interface down. A neighbor drops when the two ends
//! stop agreeing on what the hello carries (RFC 2328 §10.5: area, mask on
//! broadcast links, hello and dead intervals, the E/N option bits of the
//! area type) or on authentication (§D), when the interface leaves OSPF
//! or turns passive, and when the router id changes (every adjacency of
//! the instance restarts).
//!
//! Pure and by value: the engine shows it before the commit (with the
//! neighbors up on each interface, from the routing status) and suggests
//! Safe Mode when an adjacency drops.

use std::collections::BTreeMap;

use corerouter_model::Config;
use corerouter_model::ospf::{OspfArea, OspfInstance, OspfTemplate};

use crate::bind::{Binding, bindings};

/// One change on one interface of one instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub instance: String,
    /// Empty for a change of the whole instance (router id, disabled).
    pub interface: String,
    /// `enters`, `leaves`, `area`, `auth`, `type`, `timers`, `passive`,
    /// `area-type`, `router-id`, `cost`, `other`.
    pub what: &'static str,
    pub message: String,
    /// The adjacencies there go down (until the far end changes too).
    pub drops: bool,
}

/// What an interface runs, compared field by field.
#[derive(Debug, Clone, PartialEq)]
struct Side<'a> {
    inst: &'a OspfInstance,
    area: &'a OspfArea,
    t: &'a OspfTemplate,
}

fn by_key(cfg: &Config) -> BTreeMap<(String, String), Side<'_>> {
    bindings(cfg)
        .into_iter()
        .map(
            |Binding {
                 interface,
                 instance,
                 area,
                 template,
                 ..
             }| {
                (
                    (instance.name.clone(), interface.to_string()),
                    Side {
                        inst: instance,
                        area,
                        t: template,
                    },
                )
            },
        )
        .collect()
}

fn auth_of(t: &OspfTemplate) -> (Option<&'static str>, Option<&str>, Option<u16>, &str) {
    (
        t.auth.map(|a| a.name()),
        t.keychain.as_deref(),
        t.auth_id,
        // The sealed box changes when the key does (a new nonce even for the
        // same key, so a re-typed key counts as a change: the safe side).
        t.auth_key.stored(),
    )
}

/// Every change from `before` to `after`, instances first.
pub fn changes(before: &Config, after: &Config) -> Vec<Change> {
    let mut out = Vec::new();
    let (b_inst, a_inst) = (
        &before.routing.ospf.instances,
        &after.routing.ospf.instances,
    );
    for (name, a) in a_inst {
        let Some(b) = b_inst.get(name) else { continue };
        if b.router_id != a.router_id && !a.disabled {
            out.push(Change {
                instance: name.clone(),
                interface: String::new(),
                what: "router-id",
                message: format!(
                    "the router id of {name} changes ({} → {}): every adjacency of the instance restarts",
                    b.router_id.map_or("auto".into(), |r| r.to_string()),
                    a.router_id.map_or("auto".into(), |r| r.to_string()),
                ),
                drops: true,
            });
        }
        if !b.disabled && a.disabled {
            out.push(Change {
                instance: name.clone(),
                interface: String::new(),
                what: "disabled",
                message: format!("instance {name} is disabled: all its adjacencies go down"),
                drops: true,
            });
        }
    }
    for (name, b) in b_inst {
        if !a_inst.contains_key(name) && !b.disabled {
            out.push(Change {
                instance: name.clone(),
                interface: String::new(),
                what: "removed",
                message: format!("instance {name} is removed: all its adjacencies go down"),
                drops: true,
            });
        }
    }
    let old = by_key(before);
    let new = by_key(after);
    for ((inst, iface), o) in &old {
        let key = (inst.clone(), iface.clone());
        let mut push = |what: &'static str, message: String, drops: bool| {
            out.push(Change {
                instance: inst.clone(),
                interface: iface.clone(),
                what,
                message,
                drops,
            });
        };
        let Some(n) = new.get(&key) else {
            // Gone with the whole instance: said once above.
            if a_inst.get(inst).is_some_and(|i| !i.disabled) {
                push(
                    "leaves",
                    format!("{iface} leaves OSPF ({inst}, area {})", o.area.area_id),
                    !o.t.passive,
                );
            }
            continue;
        };
        if o.area.area_id != n.area.area_id {
            push(
                "area",
                format!(
                    "{iface} moves from area {} to {} (RFC 2328 §10.5: the hello's area must match)",
                    o.area.area_id, n.area.area_id
                ),
                !n.t.passive,
            );
        } else if o.area.kind != n.area.kind || o.area.no_summaries != n.area.no_summaries {
            push(
                "area-type",
                format!(
                    "area {} becomes {} (the hello's E/N bits change, RFC 2328 §10.5, RFC 3101 §2.3): every router of the area must change with it",
                    n.area.area_id,
                    n.area.kind.name()
                ),
                !n.t.passive,
            );
        }
        if auth_of(o.t) != auth_of(n.t) {
            let what = match (o.t.auth, n.t.auth) {
                (None, Some(a)) => format!("authentication turns on ({})", a.name()),
                (Some(_), None) => "authentication turns off".to_owned(),
                _ => "the authentication or its key changes".to_owned(),
            };
            push(
                "auth",
                format!(
                    "{iface}: {what}; the neighbors drop until they use the same (a key chain rotates without a drop)"
                ),
                !n.t.passive,
            );
        }
        if o.t.kind != n.t.kind {
            push(
                "type",
                format!(
                    "{iface}: network type {} → {} (both ends must agree; DR election restarts)",
                    o.t.kind.name(),
                    n.t.kind.name()
                ),
                !n.t.passive,
            );
        }
        if (o.t.hello_interval, o.t.dead_interval) != (n.t.hello_interval, n.t.dead_interval) {
            push(
                "timers",
                format!(
                    "{iface}: hello/dead intervals change (RFC 2328 §10.5: they must match the neighbors')"
                ),
                !n.t.passive,
            );
        }
        if !o.t.passive && n.t.passive {
            push(
                "passive",
                format!("{iface} turns passive: no more hellos, its adjacencies drop"),
                true,
            );
        }
        if o.t.cost != n.t.cost {
            push(
                "cost",
                format!(
                    "{iface}: cost {} → {} (paths may move; no adjacency drops)",
                    o.t.cost.map_or("auto".into(), |c| c.to_string()),
                    n.t.cost.map_or("auto".into(), |c| c.to_string())
                ),
                false,
            );
        }
    }
    for ((inst, iface), n) in &new {
        if !old.contains_key(&(inst.clone(), iface.clone())) {
            out.push(Change {
                instance: inst.clone(),
                interface: iface.clone(),
                what: "enters",
                message: format!(
                    "{iface} enters OSPF ({inst}, area {}{})",
                    n.area.area_id,
                    if n.t.passive { ", passive" } else { "" }
                ),
                drops: false,
            });
        }
    }
    out
}

/// The interfaces whose adjacencies drop, sorted and once each.
pub fn dropping(changes: &[Change]) -> Vec<String> {
    let mut v: Vec<String> = changes
        .iter()
        .filter(|c| c.drops)
        .map(|c| {
            if c.interface.is_empty() {
                format!("all of {}", c.instance)
            } else {
                c.interface.clone()
            }
        })
        .collect();
    v.sort();
    v.dedup();
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::sample;
    use corerouter_model::ospf::{AuthType, NetworkType};

    #[test]
    fn auth_area_and_type_changes_drop_cost_does_not() {
        let before = sample();
        let mut after = before.clone();
        after.routing.ospf.templates[0].auth = Some(AuthType::Sha512);
        after.routing.ospf.templates[0].kind = NetworkType::Ptp;
        after.routing.ospf.templates[0].cost = Some(50);
        let c = changes(&before, &after);
        let whats: Vec<_> = c
            .iter()
            .map(|c| (c.interface.as_str(), c.what, c.drops))
            .collect();
        assert!(whats.contains(&("ether1", "auth", true)), "{whats:?}");
        assert!(whats.contains(&("ether1", "type", true)), "{whats:?}");
        assert!(whats.contains(&("ether1", "cost", false)), "{whats:?}");
        assert_eq!(dropping(&c), vec!["ether1".to_owned()]);
    }

    #[test]
    fn leaving_and_router_id() {
        let before = sample();
        let mut after = before.clone();
        after.routing.ospf.templates.remove(0);
        if let Some(i) = after.routing.ospf.instances.get_mut("v2") {
            i.router_id = Some([10, 255, 0, 2].into());
        }
        let c = changes(&before, &after);
        // ether1 now matches the second template (passive): not a leave.
        assert!(c.iter().any(|c| c.what == "router-id" && c.drops));
        assert!(
            c.iter()
                .any(|c| c.interface == "ether1" && c.what == "passive"),
            "{c:?}"
        );
        assert!(changes(&before, &before).is_empty());
    }
}
