//! State badges of the side menu (G0.23c): "Services 1 failed" in red,
//! DHCP leases in conflict and drift between the config and the router in
//! amber. A panel with no window: it asks queries that already exist
//! (`system.service.print`, `ip.dhcp-server.statistics.print`,
//! `config.drift.list`) every few seconds and the menu reads the counts.
//! Nothing is decided here: a service is failed when the engine says so.

use std::cell::Cell;
use std::collections::BTreeMap;

use serde_json::Value;

use crate::backend::RequestId;
use crate::i18n::{Lang, tr};
use crate::panel::{Panel, PanelState, Query};
use crate::CoreRouterUi;

pub(crate) const PANEL: Panel = Panel {
    name: "menu-badges",
    windows: &[],
    new: || Box::new(Badges::default()),
};

/// Seconds between two rounds of the badges' queries (drift reads the
/// kernel; nobody needs it every second).
const EVERY_SECS: f64 = 5.0;
/// Names listed in a tooltip.
const MAX_LISTED: usize = 8;

/// What the badges' queries said last.
#[derive(Debug, Default)]
pub(crate) struct Badges {
    /// Services the supervisor reports `failed`.
    pub failed: Vec<String>,
    /// DHCP leases in conflict now.
    pub conflicts: u64,
    /// Differences between the config and the router (`kind item`).
    pub drift: Vec<String>,
    /// UI time of the last round.
    asked: Cell<Option<f64>>,
}

/// How bad a badge is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Level {
    /// Worth a look (amber).
    Notice,
    /// Broken, needs the operator (red).
    Alert,
}

/// A badge on a menu item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Badge {
    pub level: Level,
    pub text: String,
    pub tip: String,
}

fn text(v: &Value, k: &str) -> String {
    v.get(k)
        .map(|x| x.as_str().map_or_else(|| x.to_string(), str::to_owned))
        .unwrap_or_default()
}

/// At most `MAX_LISTED` lines, and how many more.
fn listed(items: &[String]) -> String {
    let mut out: Vec<String> = items.iter().take(MAX_LISTED).cloned().collect();
    if items.len() > MAX_LISTED {
        out.push(format!("+{}", items.len() - MAX_LISTED));
    }
    out.join("\n")
}

impl Badges {
    /// The badges by window key (`menu::key`), in the labels' language.
    pub(crate) fn by_window(&self, l: Lang) -> BTreeMap<&'static str, Badge> {
        let mut out = BTreeMap::new();
        if !self.failed.is_empty() {
            out.insert(
                crate::services::WIN,
                Badge {
                    level: Level::Alert,
                    text: format!("{} {}", self.failed.len(), tr(l, "failed")),
                    tip: format!("{}\n{}", tr(l, "Services that failed:"), listed(&self.failed)),
                },
            );
        }
        if self.conflicts > 0 {
            out.insert(
                crate::dhcp_server::WIN,
                Badge {
                    level: Level::Notice,
                    text: format!("{} {}", self.conflicts, tr(l, "conflict")),
                    tip: tr(l, "Leases in conflict: another host answers for the address (Leases tab).")
                        .to_owned(),
                },
            );
        }
        if !self.drift.is_empty() {
            out.insert(
                "history",
                Badge {
                    level: Level::Notice,
                    text: format!("{} {}", tr(l, "drift"), self.drift.len()),
                    tip: format!(
                        "{}\n{}\n{}",
                        tr(l, "The router differs from the config:"),
                        listed(&self.drift),
                        tr(l, "Terminal: /config drift reconcile")
                    ),
                },
            );
        }
        out
    }
}

impl PanelState for Badges {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        let now = app.nic_clock;
        if self.asked.get().is_some_and(|t| now - t < EVERY_SECS && now >= t) {
            return Vec::new();
        }
        self.asked.set(Some(now));
        [
            ("services", "system.service.print"),
            ("dhcp", "ip.dhcp-server.statistics.print"),
            ("drift", "config.drift.list"),
        ]
        .into_iter()
        .filter(|(_, c)| app.has_command(c))
        .map(|(key, command)| Query {
            key,
            command,
            params: Value::Null,
        })
        .collect()
    }

    fn arrived(&mut self, _app: &mut CoreRouterUi, key: &'static str, _: RequestId, value: Value) {
        match key {
            "services" => {
                self.failed = value
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter(|s| s.get("state").and_then(Value::as_str) == Some("failed"))
                    .map(|s| text(s, "name"))
                    .collect();
            }
            "dhcp" => {
                self.conflicts = value
                    .pointer("/leases/conflict")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
            }
            "drift" => {
                self.drift = value
                    .get("drift")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .map(|d| {
                        let what = [text(d, "interface"), text(d, "item")]
                            .into_iter()
                            .filter(|s| !s.is_empty())
                            .collect::<Vec<_>>()
                            .join(" ");
                        format!("{} {what}", text(d, "kind")).trim().to_owned()
                    })
                    .collect();
            }
            _ => {}
        }
    }

    fn window(&mut self, _app: &mut CoreRouterUi, _win: &'static str, _ui: &mut egui::Ui) {}
}

impl CoreRouterUi {
    /// The menu's badges now, by window key.
    pub(crate) fn menu_badges(&mut self) -> BTreeMap<&'static str, Badge> {
        let l = self.lang.labels;
        self.panel_mut::<Badges>()
            .map(|b| b.by_window(l))
            .unwrap_or_default()
    }
}
