//! Drift (G1.3): does the data plane still hold what the running config
//! put there? `config.drift.list` compares; `config.drift.reconcile` puts
//! the config back where it drifted, without touching the config.
//!
//! The comparison is against the running config plus what the DHCP clients
//! installed (the same config `apply` got), never against an uncommitted
//! candidate. What is compared is in `corerouter_hal::drift`.

use std::net::IpAddr;

use corerouter_hal::drift::{self, Drift, DriftKind};
use corerouter_model::Config;
use serde_json::{Value, json};

use super::args::opt_bool;
use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(query "config.drift.list", "Drift", [], None,
        "{} → {backend, in_sync: bool, drift: [{kind (link-missing | admin-state | mtu | master | address-missing | address-extra | route-missing | route-extra), interface, item, expected, actual, fixable: bool}]}",
        always, list),
    cmd!(
        "config.drift.reconcile",
        "Reconcile",
        [],
        None,
        "{force?: bool (also remove an address this session's connection uses)} → {fixed: u32, remaining: [{kind, interface, item, expected, actual, fixable}]}",
        always,
        reconcile
    ),
];

/// Rounds of `reconcile`: fixing one thing can undo another in the kernel
/// (enslaving a link to a VRF drops its IPv6 addresses), so it repeats
/// while that makes progress.
const ROUNDS: usize = 3;

/// The config the data plane should hold.
fn applied(s: &Session) -> Config {
    s.effective(s.store().running()).into_owned()
}

fn hal_err(e: corerouter_hal::HalError) -> EngineError {
    EngineError::Hal(e.to_string())
}

fn current(s: &mut Session, cfg: &Config) -> Result<Vec<Drift>> {
    let have = s.hal_mut().snapshot(cfg).map_err(hal_err)?;
    Ok(drift::diff(&drift::expected(cfg), &have))
}

/// A gone port cannot be created again; everything else can be put back.
fn fixable(cfg: &Config, d: &Drift) -> bool {
    d.kind != DriftKind::LinkMissing || drift::recreatable(cfg, &d.interface)
}

fn rows(cfg: &Config, list: &[Drift]) -> Vec<Value> {
    list.iter()
        .map(|d| {
            json!({
                "kind": d.kind,
                "interface": d.interface,
                "item": d.item,
                "expected": d.expected,
                "actual": d.actual,
                "fixable": fixable(cfg, d),
            })
        })
        .collect()
}

fn list(s: &mut Session, _: &Value) -> Result<Value> {
    let cfg = applied(s);
    // The data plane is read under the lock (the HAL is the session's);
    // what it should hold and the comparison come after it (G0.31b).
    let have = s.hal_mut().snapshot(&cfg).map_err(hal_err)?;
    let backend = s.backend();
    s.defer(move || {
        let found = drift::diff(&drift::expected(&cfg), &have);
        Ok(json!({
            "backend": backend,
            "in_sync": found.is_empty(),
            "drift": rows(&cfg, &found),
        }))
    })
}

/// `::ffff:10.0.0.1` (a dual-stack socket) is 10.0.0.1.
fn plain(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

/// Refuse to remove an address outside the config that the caller's own
/// management connection arrives on: the operator may have added it by
/// hand to reach the router (the same idea as the firewall lockout check).
fn check_connection(s: &Session, found: &[Drift]) -> Result<()> {
    let Some(link) = s.caller().link else {
        return Ok(());
    };
    if s.in_safe_mode() {
        return Ok(());
    }
    let local = plain(link.local.ip());
    let hit = found.iter().find(|d| {
        d.kind == DriftKind::AddressExtra
            && d.item
                .parse::<ipnet::IpNet>()
                .is_ok_and(|a| a.addr() == local)
    });
    match hit {
        Some(d) => Err(EngineError::bad(
            "force",
            format!(
                "this session's connection arrives on {} of '{}', which is not in the config: \
                 reconciling would remove it and cut you off; add it (ip.address.add) or pass force: true",
                d.item, d.interface
            ),
        )),
        None => Ok(()),
    }
}

fn reconcile(s: &mut Session, p: &Value) -> Result<Value> {
    let force = opt_bool(p, "force")?.unwrap_or(false);
    let cfg = applied(s);
    let first = current(s, &cfg)?;
    if !force {
        check_connection(s, &first)?;
    }
    let mut left = first.clone();
    for _ in 0..ROUNDS {
        if !left.iter().any(|d| fixable(&cfg, d)) {
            break;
        }
        s.hal_mut().reconcile(&cfg).map_err(hal_err)?;
        let now = current(s, &cfg)?;
        let progress = now.len() < left.len();
        left = now;
        if !progress {
            break;
        }
    }
    let fixed = first.iter().filter(|d| !left.contains(d)).count();
    Ok(json!({
        "fixed": u32::try_from(fixed).unwrap_or(u32::MAX),
        "remaining": rows(&cfg, &left),
    }))
}
