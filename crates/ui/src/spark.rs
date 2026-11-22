//! The mini graph next to each row of the Interfaces window (G4.5): the
//! last five minutes of receive and transmit, from the router's traffic
//! history (`system.graph.query` of every kept interface, every few
//! seconds while the window is open). Interfaces the history does not keep
//! have an empty cell.
//!
//! A table cell is text, so the graph travels in it: [`SEP`], then one
//! level (`0`–`f`, `-` unknown) per point of receive, `/`, the same of
//! transmit, `/` and the tooltip. `table.rs` paints such a cell
//! ([`paint`]) instead of its text.

use std::cell::Cell;
use std::collections::BTreeMap;

use egui::{Color32, Painter, Rect, Stroke, pos2};
use serde_json::{Value, json};

use crate::backend::RequestId;
use crate::panel::{Panel, PanelState, Query};
use crate::{CoreRouterUi, Win};

pub(crate) const NAME: &str = "spark";
/// Starts a sparkline cell.
pub(crate) const SEP: char = '\u{1e}';
/// Width of the cell's drawing.
pub(crate) const WIDTH: f32 = 96.0;
/// Seconds shown and between points.
const RANGE: u64 = 300;
const STEP: u64 = 10;
/// UI refreshes (one a second) between two asks.
const EVERY: u32 = 5;
const RX: Color32 = Color32::from_rgb(40, 120, 220);
const TX: Color32 = Color32::from_rgb(220, 60, 60);

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[],
    new: || Box::<Spark>::default(),
};

#[derive(Default)]
pub(crate) struct Spark {
    /// Cell text by interface name.
    pub(crate) cells: BTreeMap<String, String>,
    tick: Cell<u32>,
}

impl PanelState for Spark {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        if !app.open.contains(&Win::Interfaces) || !app.has_command(crate::graphs::QUERY) {
            return Vec::new();
        }
        let n = self.tick.get();
        self.tick.set(n.wrapping_add(1));
        if !n.is_multiple_of(EVERY) {
            return Vec::new();
        }
        vec![Query {
            key: "spark",
            command: crate::graphs::QUERY,
            params: json!({
                "series": ["interface:*"],
                "range": RANGE,
                "step": STEP,
                "fields": ["rx_bps", "tx_bps"],
                "stats": false,
                "max": false,
            }),
        }]
    }

    fn arrived(&mut self, _: &mut CoreRouterUi, _: &'static str, _: RequestId, value: Value) {
        let empty = Vec::new();
        let series = value.get("series").and_then(Value::as_array).unwrap_or(&empty);
        self.cells = series
            .iter()
            .filter_map(|s| {
                let name = s.get("series").and_then(Value::as_str)?.strip_prefix("interface:")?;
                let col = |f: &str| -> Vec<Option<f64>> {
                    s.get("data")
                        .and_then(|d| d.get(f))
                        .and_then(Value::as_array)
                        .map(|a| a.iter().map(Value::as_f64).collect())
                        .unwrap_or_default()
                };
                Some((name.to_owned(), cell(&col("rx_bps"), &col("tx_bps"))))
            })
            .collect();
    }

    fn window(&mut self, _: &mut CoreRouterUi, _: &'static str, _: &mut egui::Ui) {}
}

/// The cell of two series (bits per second; `None` unknown).
pub(crate) fn cell(rx: &[Option<f64>], tx: &[Option<f64>]) -> String {
    let top = rx.iter().chain(tx).flatten().fold(0.0f64, |a, b| a.max(*b));
    let levels = |v: &[Option<f64>]| -> String {
        v.iter()
            .map(|x| match x {
                Some(x) if top > 0.0 => {
                    let l = ((x / top) * 15.0).round().clamp(0.0, 15.0) as u32;
                    char::from_digit(l, 16).unwrap_or('0')
                }
                Some(_) => '0',
                None => '-',
            })
            .collect()
    };
    let last = |v: &[Option<f64>]| v.iter().rev().flatten().next().copied();
    let tip = format!(
        "Up to 5 min: Rx {} / Tx {} (max {})",
        last(rx).map_or("–".into(), |v| crate::graphs::rate(v, "bps")),
        last(tx).map_or("–".into(), |v| crate::graphs::rate(v, "bps")),
        crate::graphs::rate(top, "bps"),
    );
    format!("{SEP}{}/{}/{tip}", levels(rx), levels(tx))
}

/// The tooltip of a sparkline cell, if `cell` is one.
pub(crate) fn tip(cell: &str) -> Option<&str> {
    cell.strip_prefix(SEP)?.splitn(3, '/').nth(2)
}

/// Draw sparkline cell `cell` in `rect`.
pub(crate) fn paint(painter: &Painter, rect: Rect, cell: &str) {
    let Some(body) = cell.strip_prefix(SEP) else { return };
    let mut parts = body.splitn(3, '/');
    let (Some(rx), Some(tx)) = (parts.next(), parts.next()) else { return };
    let r = rect.shrink2(egui::vec2(4.0, 3.0));
    // Both lines share the same time axis. Empty leading history takes no
    // space, but gaps inside the available history remain visible.
    let first = rx.chars().zip(tx.chars())
        .position(|(a, b)| a.is_ascii_hexdigit() || b.is_ascii_hexdigit())
        .or_else(|| rx.chars().position(|c| c.is_ascii_hexdigit()))
        .or_else(|| tx.chars().position(|c| c.is_ascii_hexdigit()));
    let Some(first) = first else { return };
    let n = rx.chars().count().max(tx.chars().count()).saturating_sub(first + 1).max(1);
    for (levels, color) in [(rx, RX), (tx, TX)] {
        let mut run: Vec<egui::Pos2> = Vec::new();
        for (i, c) in levels.chars().skip(first).enumerate() {
            match c.to_digit(16) {
                Some(l) => {
                    let x = r.left() + r.width() * i as f32 / n as f32;
                    let y = r.bottom() - r.height() * l as f32 / 15.0;
                    run.push(pos2(x, y));
                }
                None => {
                    if run.len() > 1 {
                        painter.line(std::mem::take(&mut run), Stroke::new(1.2, color));
                    } else if let Some(p) = run.pop() {
                        painter.circle_filled(p, 1.2, color);
                    }
                    run.clear();
                }
            }
        }
        if run.len() > 1 {
            painter.line(run, Stroke::new(1.2, color));
        } else if let Some(p) = run.pop() {
            painter.circle_filled(p, 1.2, color);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_history_fills_width_without_connecting_internal_gaps() {
        let ctx = egui::Context::default();
        let mut frame = ctx.run_ui(egui::RawInput::default(), |ui| {
            let rect = Rect::from_min_size(pos2(0.0, 0.0), egui::vec2(WIDTH, 24.0));
            paint(ui.painter(), rect, "\u{1e}---12-34/---45-67/example");
        });
        frame.textures_delta.clear();
        let paths: Vec<_> = frame.shapes.iter().filter_map(|s| match &s.shape {
            egui::Shape::Path(p) => Some(p),
            _ => None,
        }).collect();
        assert_eq!(paths.len(), 4, "two lines, each interrupted by a gap");
        let first = paths.first().and_then(|p| p.points.first()).unwrap();
        let last = paths.get(1).and_then(|p| p.points.last()).unwrap();
        assert!((first.x - 4.0).abs() < 0.1);
        assert!((last.x - (WIDTH - 4.0)).abs() < 0.1);
    }

    #[test]
    fn a_single_sample_is_visible_and_empty_data_draws_nothing() {
        let ctx = egui::Context::default();
        let mut frame = ctx.run_ui(egui::RawInput::default(), |ui| {
            let rect = Rect::from_min_size(pos2(0.0, 0.0), egui::vec2(WIDTH, 24.0));
            paint(ui.painter(), rect, "\u{1e}---a/----/example");
        });
        frame.textures_delta.clear();
        assert!(frame.shapes.iter().any(|s| matches!(s.shape, egui::Shape::Circle(_))));
        let mut frame = ctx.run_ui(egui::RawInput::default(), |ui| {
            let rect = Rect::from_min_size(pos2(0.0, 0.0), egui::vec2(WIDTH, 24.0));
            paint(ui.painter(), rect, "\u{1e}----/----/example");
        });
        frame.textures_delta.clear();
        assert!(frame.shapes.is_empty());
    }
}
