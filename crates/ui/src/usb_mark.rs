//! The USB mark of an interface (G1.29b): wherever a USB Ethernet adapter's
//! name appears (lists, chips, pickers, window titles), the Phosphor USB
//! icon goes before it, amber when the port it sits on is slower than the
//! adapter, with a tooltip ("USB 3.0 (5 Gbps) · port 4-2 · r8152").
//!
//! One set per frame, built from the cached `interface.list` (its `usb`
//! objects) only when a new list arrives, and kept in egui's memory so the
//! shared painters (`table.rs`, `chip.rs`, the pickers) find it without
//! threading the app through: a lookup by name per cell drawn.

use std::collections::BTreeMap;
use std::sync::Arc;

use egui::{Color32, Context, Id, Visuals};
use serde_json::Value;

/// One USB adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Mark {
    /// The port caps the adapter (amber).
    pub(crate) slow: bool,
    /// "USB 3.0 (5 Gbps) · port 4-2 · r8152", plus the alert when slow.
    pub(crate) tip: String,
}

type Marks = Arc<BTreeMap<String, Mark>>;

fn id() -> Id {
    Id::unique("corerouter-usb-marks")
}

/// The marks of `rows` (`interface.list`).
pub(crate) fn marks(rows: &[Value]) -> BTreeMap<String, Mark> {
    rows.iter()
        .filter_map(|r| {
            let name = r.get("name")?.as_str()?;
            let u = r.get("usb").filter(|u| u.is_object())?;
            let text = |k: &str| u.get(k).and_then(Value::as_str);
            let slow = u.get("slow_port").and_then(Value::as_bool).unwrap_or(false);
            let mut tip = [
                text("speed").map(str::to_owned),
                text("port").map(|p| format!("port {p}")),
                text("driver").map(str::to_owned),
            ]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(" · ");
            if let Some(a) = text("alert").filter(|_| slow) {
                tip.push_str("\nSlow port: ");
                tip.push_str(a);
            }
            Some((name.to_owned(), Mark { slow, tip }))
        })
        .collect()
}

/// Rebuild the set when the list `generation` (its request id) changed.
pub(crate) fn publish(ctx: &Context, generation: Option<u64>, rows: &[Value]) {
    let key = id().with("gen");
    if ctx.data(|d| d.get_temp::<Option<u64>>(key)) == Some(generation) {
        return;
    }
    let m: Marks = Arc::new(marks(rows));
    ctx.data_mut(|d| {
        d.insert_temp(key, generation);
        d.insert_temp(id(), m);
    });
}

/// The mark of interface `name`, if it is a USB adapter.
pub(crate) fn get(ctx: &Context, name: &str) -> Option<Mark> {
    if name.is_empty() || name.len() > 64 {
        return None;
    }
    ctx.data(|d| d.get_temp::<Marks>(id()))
        .and_then(|m| m.get(name.trim()).cloned())
}

/// The icon's colour: the text's, or amber for a slow port.
pub(crate) fn color(v: &Visuals, slow: bool, text: Color32) -> Color32 {
    if slow {
        crate::chip::AMBER.tone(v).ink
    } else {
        text
    }
}

/// The mark of the interface a WinBox-style title names: "Interface
/// <ether4>", "Comment for Interface <ether4>".
pub(crate) fn in_title(ctx: &Context, title: &str) -> Option<Mark> {
    if !title.contains("Interface <") || !crate::icons::ready(ctx) {
        return None;
    }
    get(ctx, inner_name(title)?)
}

/// `name` as a rich text: the icon (amber when slow) and the name, for
/// labels and buttons.
pub(crate) fn rich(ui: &egui::Ui, name: &str) -> egui::text::LayoutJob {
    let mut job = egui::text::LayoutJob::default();
    let style = ui.style();
    let font = egui::TextStyle::Body.resolve(style);
    let text = ui.visuals().text_color();
    if let Some(m) = get(ui.ctx(), name).filter(|_| crate::icons::ready(ui.ctx())) {
        job.append(
            crate::icons::USB,
            0.0,
            egui::TextFormat::simple(crate::icons::font(font.size), color(ui.visuals(), m.slow, text)),
        );
        job.append(name, font.size * 0.3, egui::TextFormat::simple(font, text));
    } else {
        job.append(name, 0.0, egui::TextFormat::simple(font, text));
    }
    job
}

/// The `<…>` of a title.
fn inner_name(title: &str) -> Option<&str> {
    Some(title.split_once('<')?.1.split_once('>')?.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn marks_from_the_list() {
        let rows = vec![
            json!({"name": "ether1", "usb": null}),
            json!({"name": "ether5", "usb": {"port": "5-1", "speed": "USB 3.0 (5 Gbps)", "driver": "r8152", "slow_port": false, "alert": null}}),
            json!({"name": "ether6", "usb": {"port": "6-1", "speed": "USB 2.0 (480 Mbps)", "driver": "r8152", "slow_port": true, "alert": "USB 3.0 adapter negotiated USB 2.0"}}),
        ];
        let m = marks(&rows);
        assert_eq!(m.len(), 2);
        assert_eq!(m["ether5"].tip, "USB 3.0 (5 Gbps) · port 5-1 · r8152");
        assert!(!m["ether5"].slow);
        assert!(m["ether6"].slow);
        assert!(m["ether6"].tip.ends_with("\nSlow port: USB 3.0 adapter negotiated USB 2.0"));
        let ctx = Context::default();
        publish(&ctx, Some(1), &rows);
        assert!(get(&ctx, "ether6").is_some());
        assert!(get(&ctx, "ether1").is_none());
        assert_eq!(
            inner_name("Interface <ether6>"),
            Some("ether6"),
        );
        // Same generation: not rebuilt (a new list replaces it).
        publish(&ctx, Some(1), &[]);
        assert!(get(&ctx, "ether6").is_some());
        publish(&ctx, Some(2), &[]);
        assert!(get(&ctx, "ether6").is_none());
    }
}
