//! `ip.route.detail` (G1.27b): everything the panel under the Routes table
//! says about one route — where it came from (the command and revision
//! that created it, the DHCP client, the Router Advertisement, the
//! address), why it was chosen or not (its distance against the others to
//! the same prefix), its check-gateway, its state changes of the last 24 h
//! and whether the kernel holds what the config puts there.

use std::collections::BTreeSet;

use corerouter_hal::drift::{self, KernelRoute};
use corerouter_model::store::Revision;
use corerouter_model::{Config, ItemId, RouteEntry};
use serde_json::{Value, json};

use crate::Session;
use corerouter_model::route::Why;

use crate::route_table::{Line, Origin, RouteWatch, State};

/// The first revision where `has` holds, and the last one where what it
/// finds changed: (created, changed).
fn revisions<T: PartialEq>(
    history: &[Revision],
    find: impl Fn(&Config) -> Option<T>,
) -> (Option<&Revision>, Option<&Revision>) {
    let mut created = None;
    let mut changed = None;
    let mut before: Option<T> = None;
    for rev in history {
        let now = find(&rev.config);
        match (&before, &now) {
            (None, Some(_)) => {
                created = Some(rev);
                changed = Some(rev);
            }
            (Some(a), Some(b)) if a != b => changed = Some(rev),
            _ => {}
        }
        before = now;
    }
    (created, changed)
}

fn rev_json(r: Option<&Revision>, now: Option<u64>) -> Value {
    r.map_or(Value::Null, |r| {
        json!({
            "revision": r.number,
            "command": r.comment,
            "timestamp": r.timestamp,
            "ago_secs": r.timestamp.zip(now).map(|(t, n)| n.saturating_sub(t)),
        })
    })
}

/// Why a route is the one in use (`chosen_id`, translated by the GUI like
/// the reasons); an unused route says its reason (`route_table::REASONS`).
pub const CHOICES: &[(&str, &str)] = &[
    ("ecmp", "shares the traffic with {others} other path(s) at distance {distance}"),
    ("lowest", "lowest distance ({distance}) among the usable routes; the next one ({next}) takes over if it goes"),
    ("only", "the only route to this prefix"),
    ("only-usable", "the only usable route ({others} other(s) inactive)"),
];

/// Why `me` is (or is not) the route in use: (id, args, English).
pub fn choice(me: &Line, group: &[&Line]) -> Why {
    let others = group.iter().filter(|l| l.key != me.key).count();
    match me.state {
        State::Active if me.ecmp > 1 => Why::new(
            "ecmp",
            format!(
                "shares the traffic with {} other path(s) at distance {}",
                me.ecmp - 1,
                me.distance
            ),
        )
        .arg("others", me.ecmp - 1)
        .arg("distance", me.distance),
        State::Active if others == 0 => Why::new("only", "the only route to this prefix".into()),
        State::Active => {
            let next = group
                .iter()
                .filter(|l| l.key != me.key && l.state == State::Standby)
                .map(|l| l.distance)
                .min();
            match next {
                Some(d) => Why::new(
                    "lowest",
                    format!(
                        "lowest distance ({}) among the usable routes; the next one ({d}) takes over if it goes",
                        me.distance
                    ),
                )
                .arg("distance", me.distance)
                .arg("next", d),
                None => Why::new(
                    "only-usable",
                    format!("the only usable route ({others} other(s) inactive)"),
                )
                .arg("others", others),
            }
        }
        _ => me
            .why
            .clone()
            .unwrap_or_else(|| Why::new("disabled", "not usable".into())),
    }
}

/// `{reason, reason_id, reason_args}` of a `Why`.
fn why_json(w: Option<&Why>) -> (Value, Value, Value) {
    match w {
        Some(w) => (
            json!(w.text),
            json!(w.id),
            Value::Object(
                w.args
                    .iter()
                    .map(|(k, v)| ((*k).to_owned(), json!(v)))
                    .collect(),
            ),
        ),
        None => (Value::Null, Value::Null, Value::Null),
    }
}

/// What the kernel holds of `entry` against what `cfg` puts there.
fn kernel_view(cfg: &Config, entry: &RouteEntry, held: &BTreeSet<KernelRoute>) -> Value {
    let expected = drift::kernel_routes_of(cfg, std::iter::once(entry));
    let ours = drift::kernel_routes(cfg);
    let table = corerouter_model::route::table_id(cfg, &entry.routing_table);
    let dst = entry.dst_address.trunc();
    let here: Vec<&KernelRoute> = held
        .iter()
        .filter(|k| Some(k.table) == table && k.dst == dst)
        .collect();
    let missing: Vec<String> = expected
        .iter()
        .filter(|k| !held.contains(k))
        .map(ToString::to_string)
        .collect();
    // Present but put there by no route of the config: by hand, stale.
    let extra: Vec<String> = here
        .iter()
        .filter(|k| !ours.contains(k))
        .map(|k| k.to_string())
        .collect();
    json!({
        "available": true,
        "same": missing.is_empty() && extra.is_empty(),
        "expected": expected.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "present": here.iter().map(|k| k.to_string()).collect::<Vec<_>>(),
        "missing": missing,
        "extra": extra,
        "note": null,
    })
}

fn kernel_note(note: &str) -> Value {
    json!({"available": true, "same": null, "note": note, "missing": [], "extra": []})
}

impl Session {
    /// `ip.route.detail` of route `key`; `None` when there is no such route.
    pub(crate) fn route_detail(&mut self, key: &str) -> Option<Value> {
        let (lines, now) = self.watched_route_lines();
        let me = lines.iter().find(|l| l.key == key)?.clone();
        let group: Vec<&Line> = lines
            .iter()
            .filter(|l| l.table == me.table && l.dst == me.dst)
            .collect();
        let competitors: Vec<Value> = group
            .iter()
            .map(|l| {
                let (reason, reason_id, reason_args) = why_json(l.why.as_ref());
                json!({
                    "key": l.key,
                    "id": l.id,
                    "gateway": l.gateway,
                    "distance": l.distance,
                    "origin": l.origin.as_str(),
                    "state": l.state.as_str(),
                    "reason": reason,
                    "reason_id": reason_id,
                    "reason_args": reason_args,
                    "this": l.key == me.key,
                })
            })
            .collect();
        let chosen = choice(&me, &group);
        // An unused route's choice is its reason: `route.<id>` in the GUI.
        let chosen_kind = if me.state == State::Active { "choice" } else { "route" };
        let source = self.route_source(&me, now);
        // G1.27f: the transitions of the gateway's check (shared by every
        // route through it).
        let check_history = match (me.origin, me.gateway_address) {
            (Origin::Static, Some(gw)) if me.check.is_some() => self.route_check_history(Some(gw)),
            _ => Vec::new(),
        };
        let check = me.check.as_ref().map(|c| {
            json!({
                "method": c.method,
                "interval_secs": c.interval_secs,
                "misses": c.misses,
                "state": if c.down { "down" } else { "up" },
                "status": c.status,
                "hold_down_secs": c.hold_secs,
                "bfd_profile": c.profile,
                "history": check_history,
                "down_secs": c.down_since_ms.zip(self.dhcp.now_ms)
                    .map(|(at, n)| n.saturating_sub(at) / 1000),
            })
        });
        let history: Vec<Value> = match (now, self.ext::<RouteWatch>()) {
            (Some(n), Some(w)) => w
                .changes_of(&me.key, n)
                .into_iter()
                .map(|c| {
                    let (reason, reason_id, reason_args) = why_json(c.reason.as_ref());
                    json!({
                        "at": c.at,
                        "ago_secs": n.saturating_sub(c.at),
                        "from": c.from.as_str(),
                        "to": c.to.as_str(),
                        "reason": reason,
                        "reason_id": reason_id,
                        "reason_args": reason_args,
                    })
                })
                .collect(),
            _ => Vec::new(),
        };
        let watching = self.ext::<RouteWatch>().and_then(|w| w.since);
        let kernel = self.route_kernel(&me);
        let changed = self.ext::<RouteWatch>().map(RouteWatch::changed);
        let mut route = crate::cmd::route::row(&me, changed.as_ref(), now);
        crate::cmd::route::layer2(&mut route, &me, &self.neigh_fresh().lock());
        Some(json!({
            "key": me.key,
            "route": route,
            "source": source,
            "chosen": chosen.text,
            "chosen_id": format!("{chosen_kind}.{}", chosen.id),
            "chosen_args": why_json(Some(&chosen)).2,
            "competitors": competitors,
            "check_gateway": check,
            "history": history,
            "watching_since_secs": watching.zip(now).map(|(s, n)| n.saturating_sub(s)),
            "kernel": kernel,
        }))
    }

    fn route_source(&self, me: &Line, now: Option<u64>) -> Value {
        let history = self.store().history();
        match (me.origin, me.id) {
            (Origin::Static, Some(id)) => {
                let (created, changed) = revisions(history, |c| find_route(c, id));
                json!({
                    "kind": "static",
                    "text": "static route",
                    "created": rev_json(created, now),
                    "changed": rev_json(changed, now),
                })
            }
            (Origin::Dhcp, Some(id)) => {
                let owner = self.dhcp.runners.values().find(|r| r.routes.iter().any(|rt| rt.id == id));
                let iface = owner.map(|r| r.cfg.interface.to_string());
                let server = owner.and_then(|r| r.lease()).map(|l| l.server.to_string());
                json!({
                    "kind": "dhcp",
                    "text": match (&iface, &server) {
                        (Some(i), Some(s)) => format!("DHCP client on {i} (lease from {s})"),
                        (Some(i), None) => format!("DHCP client on {i}"),
                        _ => "DHCP client".into(),
                    },
                    "interface": iface,
                    "server": server,
                    "client": owner.map(|r| r.cfg.id),
                })
            }
            (Origin::Ppp, _) => json!({
                "kind": "ppp",
                "text": format!(
                    "PPPoE client {}",
                    me.gateway_interface.as_ref().map(ToString::to_string).unwrap_or_default()
                ),
                "interface": me.gateway_interface,
            }),
            (Origin::Ra, _) => json!({
                "kind": "ra",
                "text": format!(
                    "router advertisement on {}",
                    me.gateway_interface.as_ref().map(ToString::to_string).unwrap_or_default()
                ),
                "interface": me.gateway_interface,
                "note": me.comment,
            }),
            _ => {
                // Connected: the address that makes it.
                let iface = me.gateway_interface.clone();
                let address = self.store().candidate().ip.addresses.iter().find(|a| {
                    Some(&a.interface) == iface.as_ref() && a.address.trunc() == me.dst
                }).map(|a| (a.id, a.address));
                let (created, _) = match address {
                    Some((id, _)) => revisions(history, |c| {
                        c.ip.addresses.iter().find(|a| a.id == id).cloned()
                    }),
                    None => (None, None),
                };
                json!({
                    "kind": "connected",
                    "text": match (address, &iface) {
                        (Some((_, a)), Some(i)) => format!("address {a} on {i}"),
                        _ => "connected network".into(),
                    },
                    "address": address.map(|(id, a)| json!({"id": id, "address": a.to_string()})),
                    "created": rev_json(created, now),
                })
            }
        }
    }

    /// The kernel's side: what the running config puts there for this route.
    fn route_kernel(&mut self, me: &Line) -> Value {
        let entry = match (me.origin, me.id) {
            (Origin::Static | Origin::Dhcp, Some(id)) => id,
            (Origin::Connected, _) => {
                return kernel_note("the kernel makes connected routes from the addresses");
            }
            _ => return kernel_note("learned by the kernel itself"),
        };
        let running = self.store().running().clone();
        let cfg = self.effective(&running).into_owned();
        let Some(entry) = cfg.ip.routes.iter().find(|r| r.id == entry).cloned() else {
            if running.ip.routes.iter().any(|r| r.id == entry && self.static_withholds(r)) {
                return kernel_note("out of the kernel while its gateway fails check-gateway");
            }
            return kernel_note("not applied yet (pending in the transaction)");
        };
        match self.hal_mut().snapshot(&cfg) {
            Ok(snap) => kernel_view(&cfg, &entry, &snap.routes),
            Err(e) => json!({"available": false, "same": null, "note": e.to_string(), "missing": [], "extra": []}),
        }
    }
}

fn find_route(c: &Config, id: ItemId) -> Option<RouteEntry> {
    c.ip.routes.iter().find(|r| r.id == id).cloned()
}
