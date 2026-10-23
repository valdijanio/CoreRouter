//! `system.metrics` (G4.4): every counter a monitoring system scrapes, in
//! one query, so the daemon's Prometheus `/metrics` (and an MCP agent) pay
//! one lock and one platform poll per scrape instead of one per interface.
//!
//! Interfaces are the config's plus the platform's links outside it
//! (unmanaged ones included: their traffic is still the router's). Error
//! and drop counters are those of the platform's `interface` counter group
//! (`interface.stats`); a platform that has none reports `null`, never a
//! made-up zero. They ride on the poll itself (`LinkState::errors`, Linux
//! `IFLA_STATS64`): asking `counters` per link meant a netlink and an
//! ethtool round trip per interface under the session lock, per scrape.

use std::collections::BTreeMap;

use corerouter_hal::LinkState;
use corerouter_model::IfName;
use corerouter_model::service::ServiceTable;
use serde_json::{Value, json};

use super::{CommandSpec, always};
use crate::{Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[cmd!(query "system.metrics", "Metrics", [], None,
    "{} → {revision, mode (immediate | transactional), safe_mode, engine: {changes_ok, changes_failed, queries_ok, queries_failed, unknown, commits_ok, commits_failed}, interfaces: [{name, type, managed, disabled, running, rx_bytes, tx_bytes, rx_packets, tx_packets, rx_errors, tx_errors, rx_dropped, tx_dropped, link_downs}], services: [{name, state, up, restarts}], dhcp_server (null until a DHCP server ran; else as ip.dhcp-server.statistics.print)}",
    always, metrics)];

fn metrics(s: &mut Session, _: &Value) -> Result<Value> {
    let live = s.hal_mut().poll();
    s.watch_links(&live);
    let by_name: BTreeMap<&IfName, &LinkState> = live.iter().map(|l| (&l.name, l)).collect();
    let mut names: Vec<(IfName, Option<&LinkState>)> = s
        .store()
        .candidate()
        .interfaces
        .keys()
        .map(|n| (n.clone(), by_name.get(n).copied()))
        .collect();
    names.extend(
        live.iter()
            .filter(|l| !s.store().candidate().interfaces.contains_key(&l.name))
            .map(|l| (l.name.clone(), Some(l))),
    );
    let mut rows = Vec::with_capacity(names.len());
    for (name, st) in names {
        let errors = st.and_then(|l| l.errors);
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
            "rx_errors": errors.map(|e| e.rx_errors),
            "tx_errors": errors.map(|e| e.tx_errors),
            "rx_dropped": errors.map(|e| e.rx_dropped),
            "tx_dropped": errors.map(|e| e.tx_dropped),
            "link_downs": s.links.get(&name).map(|t| t.downs),
        }));
    }
    Ok(json!({
        "revision": s.store().current_revision(),
        "mode": s.mode(),
        "safe_mode": s.in_safe_mode(),
        "engine": s.counters,
        "interfaces": rows,
        "services": services(s),
        "dhcp_server": super::dhcp_server_stats::snapshot(s),
    }))
}

/// The supervised services (G0.10); none without a daemon.
fn services(s: &Session) -> Vec<Value> {
    s.ext::<ServiceTable>()
        .filter(|t| t.supervised)
        .map(|t| {
            t.rows
                .iter()
                .map(|r| {
                    json!({
                        "name": r.name,
                        "state": r.state.as_str(),
                        "up": r.state.is_up(),
                        "restarts": r.restarts,
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}
