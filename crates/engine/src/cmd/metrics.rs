//! `system.metrics` (G4.4): every counter a monitoring system scrapes, in
//! one query, so the daemon's Prometheus `/metrics` (and an MCP agent) pay
//! one lock and one platform poll per scrape instead of one per interface.
//!
//! Interfaces are the config's plus the platform's links outside it
//! (unmanaged ones included: their traffic is still the router's). Error
//! and drop counters come from the platform's `interface` counter group
//! (`interface.stats`); a platform that has none reports `null`, never a
//! made-up zero.

use corerouter_hal::LinkState;
use corerouter_model::IfName;
use serde_json::{Value, json};

use super::{CommandSpec, always};
use crate::{Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[cmd!(query "system.metrics", "Metrics", [], None,
    "{} → {revision, mode (immediate | transactional), safe_mode, engine: {changes_ok, changes_failed, queries_ok, queries_failed, unknown, commits_ok, commits_failed}, interfaces: [{name, type, managed, disabled, running, rx_bytes, tx_bytes, rx_packets, tx_packets, rx_errors, tx_errors, rx_dropped, tx_dropped, link_downs}]}",
    always, metrics)];

/// Error and drop counters of the platform's `interface` group, by the
/// names `interface.stats` shows.
const ERROR_COUNTERS: [&str; 4] = ["rx_errors", "tx_errors", "rx_dropped", "tx_dropped"];

fn metrics(s: &mut Session, _: &Value) -> Result<Value> {
    let live = s.hal_mut().poll();
    s.watch_links(&live);
    let mut names: Vec<(IfName, Option<&LinkState>)> = s
        .store()
        .candidate()
        .interfaces
        .keys()
        .map(|n| (n.clone(), live.iter().find(|l| &l.name == n)))
        .collect();
    names.extend(
        live.iter()
            .filter(|l| !s.store().candidate().interfaces.contains_key(&l.name))
            .map(|l| (l.name.clone(), Some(l))),
    );
    let mut rows = Vec::with_capacity(names.len());
    for (name, st) in names {
        let [rx_errors, tx_errors, rx_dropped, tx_dropped] = match st {
            Some(_) => interface_errors(s, &name),
            None => [None; 4],
        };
        let cfg = s.store().candidate().interfaces.get(&name);
        let kind = cfg.map_or_else(
            || st.map_or("", |l| l.kind.as_str()).to_owned(),
            |i| i.kind.label().to_owned(),
        );
        rows.push(json!({
            "name": name,
            "type": kind,
            "managed": cfg.is_some() && st.is_none_or(|l| l.unmanaged.is_none()),
            "disabled": cfg.is_some_and(|i| i.disabled),
            "running": st.is_some_and(|l| l.running),
            "rx_bytes": st.map(|l| l.rx_bytes),
            "tx_bytes": st.map(|l| l.tx_bytes),
            "rx_packets": st.map(|l| l.rx_packets),
            "tx_packets": st.map(|l| l.tx_packets),
            "rx_errors": rx_errors,
            "tx_errors": tx_errors,
            "rx_dropped": rx_dropped,
            "tx_dropped": tx_dropped,
            "link_downs": s.links.get(&name).map(|t| t.downs),
        }));
    }
    Ok(json!({
        "revision": s.store().current_revision(),
        "mode": s.mode(),
        "safe_mode": s.in_safe_mode(),
        "engine": s.counters,
        "interfaces": rows,
    }))
}

/// `[rx_errors, tx_errors, rx_dropped, tx_dropped]`, `None` where the
/// platform does not count it.
fn interface_errors(s: &mut Session, name: &IfName) -> [Option<u64>; 4] {
    let Ok(c) = s.hal_mut().counters(name) else {
        return [None; 4];
    };
    let group = c.groups.iter().find(|g| g.name == "interface");
    ERROR_COUNTERS.map(|key| {
        group.and_then(|g| g.counters.iter().find(|x| x.name == key).map(|x| x.value))
    })
}
