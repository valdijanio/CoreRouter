//! The top bar's warning while a learned route takes the replies to a
//! management session (G3.4z): `management_route` of the summary, one
//! amber chip with the peer; hover says which route and why, a click opens
//! Routing › Management Guard (Protect is there), ⓘ explains.

use serde_json::Value;

use crate::help::{self, HelpView};
use crate::i18n::tr_in;
use crate::management_guard::SCOPE;
use crate::{CoreRouterUi, chip, value_text};

pub(crate) const HELP_KEY: &str = "management_guard.route_warning";

/// (peer, sentence, fix) of each covered session, from the summary.
pub(crate) fn findings(summary: &Value) -> Vec<(String, String, Option<String>)> {
    summary
        .get("management_route")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(8)
        .map(|f| {
            let text = |k: &str| f.get(k).filter(|v| !v.is_null()).map(value_text);
            (text("peer").unwrap_or_default(), text("text").unwrap_or_default(), text("fix"))
        })
        .collect()
}

impl CoreRouterUi {
    pub(crate) fn mgmt_route_warning(&mut self, ui: &mut egui::Ui) {
        let found = findings(&self.cache.summary);
        if found.is_empty() {
            return;
        }
        let l = self.lang.labels;
        let peers: Vec<&str> = found.iter().map(|(p, _, _)| p.as_str()).collect();
        let text = format!("{} {}: {}", crate::icons::SIGNPOST, tr_in(SCOPE, l, "mgmt route"), peers.join(", "));
        let mut tip = vec![tr_in(SCOPE, l, "A learned route more specific than the connected network takes the replies to these management sessions. Click: Routing › Management Guard.").to_owned()];
        for (_, why, fix) in &found {
            tip.push(String::new());
            tip.push(why.clone());
            if let Some(f) = fix {
                tip.push(f.clone());
            }
        }
        let resp = chip::chip(ui, &text, chip::Kind::Amber.tone(ui.visuals()));
        let id = egui::Id::unique("mgmt-route-warning");
        if ui.interact(resp.rect, id.with("click"), egui::Sense::click()).on_hover_text(tip.join("\n")).clicked() {
            crate::management_guard::open(self);
        }
        if help::info_button(ui, id.with("i"), tr_in(SCOPE, l, "Management route")).clicked() {
            let view = HelpView::new(HELP_KEY, tr_in(SCOPE, l, "Management route"));
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
