//! Panels: self-contained windows. A module of `src/` that defines
//! `pub(crate) const PANEL: Panel` is found by `build.rs` and wired in: its
//! windows join the side menu (alphabetical inside their group, like
//! WinBox), its queries go out with every refresh, their replies and its
//! command replies come back to it, and its dialogs are drawn each frame.
//! A new window is a new file — no edit to `lib.rs` or `windows.rs`, which
//! every feature used to touch (the merge-conflict hot spots).
//!
//! The panel keeps its own state (rows, dialogs, table selection) and acts
//! through the app it is handed (`run`, `can`, `floats`, the log), like the
//! older windows do through `self`.

use std::any::Any;

use serde_json::Value;

use crate::backend::RequestId;
use crate::table::TableState;
use crate::{CoreRouterUi, Then};

/// One window of a panel.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct WinDef {
    /// Stable id (`Win::Panel(id)`), unique across panels.
    pub id: &'static str,
    /// Side menu group (`IP`, `IPv6`, …): one of `windows::MENU`'s.
    pub group: &'static str,
    pub title: &'static str,
    pub size: [f32; 2],
    /// Esc clears the find text, then the selection, then closes.
    pub escape: bool,
}

/// What `build.rs` collects: the panel's windows and how to make its state.
pub(crate) struct Panel {
    /// Unique name, used to route replies back.
    pub name: &'static str,
    pub windows: &'static [WinDef],
    pub new: fn() -> Box<dyn PanelState>,
}

/// A query a panel wants in this refresh; `key` comes back to `arrived`.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Query {
    pub key: &'static str,
    pub command: &'static str,
    pub params: Value,
}

/// A command reply a panel asked for: `then` is its own value, handed back.
pub(crate) type PanelThen = Box<dyn Any + Send>;

pub(crate) trait PanelState: Any {
    /// The queries to send now (usually only while a window is open).
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query>;

    /// A reply to query `key` (request `id`).
    fn arrived(&mut self, app: &mut CoreRouterUi, key: &'static str, id: RequestId, value: Value);

    /// Draw window `win` (one of the panel's `WinDef::id`).
    fn window(&mut self, app: &mut CoreRouterUi, win: &'static str, ui: &mut egui::Ui);

    /// Draw the panel's floating dialogs.
    fn dialogs(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, area: egui::Rect) {
        let _ = (app, ctx, area);
    }

    /// The reply of a command sent with `Then::Panel`.
    fn reply(&mut self, app: &mut CoreRouterUi, then: PanelThen, result: &Result<Value, String>) {
        let _ = (app, then, result);
    }

    /// Esc on window `win`; whether it stays open.
    fn escape(&mut self, win: &'static str) -> bool {
        let _ = win;
        false
    }

    /// The panel's tables by salt (stored preferences name them so).
    fn tables(&self) -> Vec<(&'static str, &TableState)> {
        Vec::new()
    }

    fn tables_mut(&mut self) -> Vec<(&'static str, &mut TableState)> {
        Vec::new()
    }
}

/// Every panel (`build.rs`: the modules defining `PANEL`).
pub(crate) fn all() -> &'static [&'static Panel] {
    crate::PANELS
}

/// The window `id`, and the panel it belongs to.
pub(crate) fn find(id: &str) -> Option<(&'static Panel, &'static WinDef)> {
    all()
        .iter()
        .find_map(|p| p.windows.iter().find(|w| w.id == id).map(|w| (*p, w)))
}

/// `Then` for a command whose reply panel `panel` handles.
pub(crate) fn then(panel: &'static str, value: impl Any + Send) -> Then {
    Then::Panel {
        panel,
        then: Box::new(value),
    }
}

impl CoreRouterUi {
    /// Run `f` on panel `name` with the app at hand (the panel is taken out
    /// meanwhile, so it can act through the app). `None`: no such panel.
    pub(crate) fn with_panel<R>(
        &mut self,
        name: &str,
        f: impl FnOnce(&mut dyn PanelState, &mut Self) -> R,
    ) -> Option<R> {
        let i = all().iter().position(|p| p.name == name)?;
        let mut state = self.panels.get_mut(i)?.take()?;
        let out = f(state.as_mut(), self);
        if let Some(slot) = self.panels.get_mut(i) {
            *slot = Some(state);
        }
        Some(out)
    }

    /// Every panel's queries for this refresh, as (panel, query).
    pub(crate) fn panel_queries(&self) -> Vec<(&'static str, Query)> {
        all()
            .iter()
            .zip(&self.panels)
            .filter_map(|(p, s)| s.as_ref().map(|s| (p.name, s)))
            .flat_map(|(name, s)| s.queries(self).into_iter().map(move |q| (name, q)))
            .collect()
    }

    /// Whether the router has command `id` and allows it now (a query for
    /// it would not be refused). An older daemon may lack a panel's queries.
    pub(crate) fn has_command(&self, id: &str) -> bool {
        self.cache
            .commands
            .iter()
            .any(|c| c.get("id").and_then(Value::as_str) == Some(id))
            && self.can.check(id).is_ok()
    }

    /// The state of panel type `T` (tests look inside).
    #[cfg(test)]
    pub(crate) fn panel_mut<T: PanelState>(&mut self) -> Option<&mut T> {
        self.panels
            .iter_mut()
            .flatten()
            .find_map(|p| (p.as_mut() as &mut dyn Any).downcast_mut::<T>())
    }

    /// Run `f` on the panel of type `T` (tests drive a panel directly).
    #[cfg(test)]
    pub(crate) fn with_panel_as<T: PanelState, R>(
        &mut self,
        f: impl FnOnce(&mut T, &mut Self) -> R,
    ) -> Option<R> {
        let name = all().iter().zip(&self.panels).find_map(|(p, s)| {
            let s: &dyn Any = s.as_deref()?;
            s.is::<T>().then_some(p.name)
        })?;
        self.with_panel(name, |s, app| {
            (s as &mut dyn Any).downcast_mut::<T>().map(|t| f(t, app))
        })?
    }

    /// Draw every panel's dialogs.
    pub(crate) fn panel_dialogs(&mut self, ctx: &egui::Context, area: egui::Rect) {
        for p in all() {
            self.with_panel(p.name, |s, app| s.dialogs(app, ctx, area));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn panel_names_and_window_ids_are_unique() {
        let mut names = Vec::new();
        let mut ids = Vec::new();
        for p in all() {
            assert!(!names.contains(&p.name), "panel {} twice", p.name);
            names.push(p.name);
            for w in p.windows {
                assert!(!ids.contains(&w.id), "window {} twice", w.id);
                ids.push(w.id);
                assert!(
                    crate::windows::MENU.iter().any(|(g, _)| *g == w.group),
                    "window {} names group {}, which windows::MENU lacks",
                    w.id,
                    w.group
                );
            }
        }
    }
}
