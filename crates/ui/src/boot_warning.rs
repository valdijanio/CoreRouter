//! The top bar's warning while the router's boot left part of its config
//! out of the data plane (G1.3e): `storage.boot_apply_failed` of the
//! summary, one red chip with the sections; hover lists why, ⓘ explains.

use serde_json::Value;

use crate::help::{self, HelpView};
use crate::i18n::tr_in;
use crate::{CoreRouterUi, chip};

const SCOPE: &str = "boot_warning";
pub(crate) const HELP_KEY: &str = "boot_warning.boot_apply";

/// (section, why) of what the boot left out, from the summary.
pub(crate) fn boot_failures(summary: &Value) -> Vec<(String, String)> {
    summary
        .get("storage")
        .and_then(|s| s.get("boot_apply_failed"))
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(16)
        .map(|f| {
            let field = |k| f.get(k).and_then(Value::as_str).unwrap_or("").to_owned();
            // G1.3g: one item of the section (`firewall *5`, `routes *3`).
            let what = match f.get("item").and_then(Value::as_str) {
                Some(item) => format!("{} {item}", field("section")),
                None => field("section"),
            };
            (what, field("error"))
        })
        .collect()
}

impl CoreRouterUi {
    pub(crate) fn boot_apply_warning(&mut self, ui: &mut egui::Ui) {
        let failed = boot_failures(&self.cache.summary);
        if failed.is_empty() {
            return;
        }
        let l = self.lang.labels;
        let tone = chip::Kind::Red.tone(ui.visuals());
        let sections: Vec<&str> = failed.iter().map(|(s, _)| s.as_str()).collect();
        let text = format!(
            "{} {}: {}",
            crate::icons::PROHIBIT,
            tr_in(SCOPE, l, "boot"),
            sections.join(", ")
        );
        let why: Vec<String> = failed
            .iter()
            .map(|(s, e)| format!("{s}: {}", e.chars().take(200).collect::<String>()))
            .collect();
        chip::chip(ui, &text, tone).on_hover_text(format!(
            "{}\n\n{}",
            tr_in(
                SCOPE,
                l,
                "The kernel refused these parts of the saved config at boot; the rest, management included, is up. Retried with a growing wait (up to 60 s)."
            ),
            why.join("\n")
        ));
        let id = egui::Id::unique("boot-warning-help");
        if help::info_button(ui, id.with("i"), tr_in(SCOPE, l, "Why this matters")).clicked() {
            let view = HelpView::new(HELP_KEY, tr_in(SCOPE, l, "Config left out at boot"));
            ui.ctx().data_mut(|d| d.insert_temp(id, Some(view)));
        }
        let mut view: Option<HelpView> = ui.ctx().data(|d| d.get_temp(id)).flatten();
        let was = view.is_some();
        help::modal(ui.ctx(), self.lang, &mut view);
        if was && view.is_none() {
            ui.ctx().data_mut(|d| d.remove::<Option<HelpView>>(id));
        }
        ui.separator();
    }
}

#[cfg(test)]
mod tests {
    use corerouter_engine::{MemoryStorage, Session, shared};
    use corerouter_hal::{Hal, HalError, LinkInfo, LinkState, VirtualHal};
    use corerouter_model::Config;
    use serde_json::json;

    use super::*;

    /// The lab on a kernel that refuses any firewall rule.
    struct NoFirewall(VirtualHal);

    impl Hal for NoFirewall {
        fn describe(&self) -> String {
            "lab refusing the firewall".into()
        }
        fn discover_links(&mut self) -> Result<Vec<LinkInfo>, HalError> {
            self.0.discover_links()
        }
        fn apply(&mut self, from: &Config, to: &Config) -> Result<(), HalError> {
            if !to.ip.firewall.filter.is_empty() {
                return Err(HalError::Rejected("nft: Could not process rule".into()));
            }
            self.0.apply(from, to)
        }
        fn poll(&mut self) -> Vec<LinkState> {
            self.0.poll()
        }
        fn now_unix(&self) -> Option<u64> {
            None
        }
    }

    fn texts(app: &mut CoreRouterUi, ctx: &egui::Context) -> Vec<String> {
        let raw = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(1400.0, 800.0))),
            ..Default::default()
        };
        let mut out = ctx.run_ui(raw, |ui| app.ui(ui));
        out.textures_delta.clear();
        fn walk(s: &egui::Shape, out: &mut Vec<String>) {
            match s {
                egui::Shape::Text(t) => out.push(t.galley.text().to_owned()),
                egui::Shape::Vec(v) => v.iter().for_each(|s| walk(s, out)),
                _ => {}
            }
        }
        let mut texts = Vec::new();
        for c in &out.shapes {
            walk(&c.shape, &mut texts);
        }
        texts
    }

    #[test]
    fn the_top_bar_shows_what_the_boot_left_out() {
        let storage = MemoryStorage::default();
        let mut s = Session::with_storage(Box::new(VirtualHal::default()), Box::new(storage.clone()));
        s.execute("ip.firewall.filter.add", &json!({"action": "drop"})).unwrap();
        drop(s);
        let s = Session::with_storage(Box::new(NoFirewall(VirtualHal::default())), Box::new(storage));
        let mut app = CoreRouterUi::new(shared(s));
        let ctx = egui::Context::default();
        let mut seen = Vec::new();
        for _ in 0..3 {
            seen = texts(&mut app, &ctx);
        }
        assert!(seen.iter().any(|t| t.ends_with("boot: firewall")), "{seen:?}");
        assert_eq!(
            boot_failures(&app.cache.summary),
            [("firewall".to_owned(), "backend rejected the change: nft: Could not process rule".to_owned())]
        );
        // The ⓘ has its explanation in both languages.
        for langs in [
            crate::i18n::Langs::default(),
            crate::i18n::Langs { help: crate::i18n::Lang::En, ..Default::default() },
        ] {
            let (_, text) = crate::i18n::explain(langs, HELP_KEY).unwrap();
            assert!(text.contains("firewall"), "{text}");
        }
    }

    /// G1.3g: one rule out shows as `firewall *5`.
    #[test]
    fn one_rule_out_names_the_rule() {
        let summary = json!({"storage": {"boot_apply_failed": [
            {"section": "firewall", "item": "*5", "error": "Operation not supported"}
        ]}});
        assert_eq!(
            boot_failures(&summary),
            [("firewall *5".to_owned(), "Operation not supported".to_owned())]
        );
    }

    #[test]
    fn no_chip_without_boot_errors() {
        assert!(boot_failures(&json!({"storage": {"backend": "memory"}})).is_empty());
        assert!(boot_failures(&serde_json::Value::Null).is_empty());
    }
}
