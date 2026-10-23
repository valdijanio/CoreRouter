//! Settings › Settings (G0.15): preferences of this GUI, not of the router.
//! For now the two languages: the labels' and the explanations'. They are
//! stored with the theme (`prefs.rs`), on this computer or in this
//! browser, so nothing here sends a command.
//!
//! A panel (`panel.rs`) and the first window written with translatable
//! labels (`i18n::tr`) and explanations (ⓘ, `help.rs`): the pattern
//! `docs/ui-style.md` describes for a new window.

use egui::{ComboBox, Grid, Id, Ui};
use serde_json::Value;

use crate::backend::RequestId;
use crate::help::{self, HelpView};
use crate::i18n::{Lang, tr};
use crate::panel::{Panel, PanelState, Query, WinDef};
use crate::CoreRouterUi;

const NAME: &str = "settings";
/// The window's id (`Win::Panel`).
pub(crate) const WIN: &str = "settings";

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[WinDef {
        id: WIN,
        group: "Settings",
        title: "Settings",
        size: [420.0, 200.0],
        escape: false,
    }],
    new: || Box::new(SettingsPanel::default()),
};

#[derive(Default)]
pub(crate) struct SettingsPanel {
    /// The explanation open (ⓘ).
    pub(crate) help: Option<HelpView>,
}

impl PanelState for SettingsPanel {
    fn queries(&self, _app: &CoreRouterUi) -> Vec<Query> {
        Vec::new()
    }

    fn arrived(&mut self, _: &mut CoreRouterUi, _: &'static str, _: RequestId, _: Value) {}

    fn window(&mut self, app: &mut CoreRouterUi, _win: &'static str, ui: &mut Ui) {
        let l = app.lang.labels;
        ui.strong(tr(l, "Language"));
        Grid::new("settings-language")
            .num_columns(3)
            .spacing([12.0, 6.0])
            .show(ui, |ui| {
                for (label, key, pick) in [
                    ("Labels", "settings.labels_lang", &mut app.lang.labels),
                    ("Explanations", "settings.help_lang", &mut app.lang.help),
                ] {
                    ui.label(tr(l, label));
                    ComboBox::from_id_salt(("settings-lang", key))
                        .selected_text(pick.name())
                        .show_ui(ui, |ui| {
                            for lang in Lang::ALL {
                                ui.selectable_value(pick, lang, lang.name());
                            }
                        });
                    if help::info_button(ui, Id::unique(("settings-help", key)), tr(l, label))
                        .clicked()
                    {
                        self.help = Some(HelpView::new(key, tr(l, label)));
                    }
                    ui.end_row();
                }
            });
        ui.add_space(4.0);
        ui.weak(tr(l, "Stored on this computer, not on the router."));
    }

    fn dialogs(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, _area: egui::Rect) {
        help::modal(ctx, app.lang, &mut self.help);
    }
}
