//! The ⓘ button next to a parameter and the explanation modal it opens
//! (G0.15): the text of `i18n::explain` in the language of the
//! explanations, plus sections the window computes (a recommended value,
//! the equivalent command). The icon is painted: the default fonts have no
//! ⓘ glyph.

use egui::{Context, Id, Response, RichText, ScrollArea, Sense, Stroke, Ui, vec2};

use crate::i18n::{self, Langs, tr};

/// What the modal shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HelpView {
    /// `i18n::explain` key.
    pub key: String,
    /// Already in the labels' language (a parameter name).
    pub title: String,
    /// Computed sections: (heading, Markdown); the heading is an English
    /// text given to `tr` in the language of the explanations.
    pub extra: Vec<(&'static str, String)>,
}

impl HelpView {
    pub fn new(key: impl Into<String>, title: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            title: title.into(),
            extra: Vec::new(),
        }
    }

    /// Add a computed section (heading in English, given to `tr`).
    pub fn with(mut self, heading: &'static str, body: impl Into<String>) -> Self {
        self.extra.push((heading, body.into()));
        self
    }
}

/// A small round "i"; `tip` on hover. Clicked: open the explanation.
pub(crate) fn info_button(ui: &mut Ui, id: Id, tip: &str) -> Response {
    let h = ui.spacing().interact_size.y;
    let (rect, _) = ui.allocate_exact_size(vec2(h * 0.8, h), Sense::hover());
    let resp = ui.interact(rect, id, Sense::click()).on_hover_text(tip);
    let v = ui.visuals();
    let ink = if resp.hovered() {
        v.strong_text_color()
    } else {
        v.weak_text_color()
    };
    let c = rect.center();
    let r = h * 0.32;
    let p = ui.painter();
    p.circle_stroke(c, r, Stroke::new(1.2, ink));
    p.circle_filled(c + vec2(0.0, -r * 0.48), r * 0.13, ink);
    p.line_segment(
        [c + vec2(0.0, -r * 0.15), c + vec2(0.0, r * 0.55)],
        Stroke::new(r * 0.24, ink),
    );
    resp
}

/// Draw the modal while `view` is set; Close, Esc or a click outside
/// clears it.
pub(crate) fn modal(ctx: &Context, langs: Langs, view: &mut Option<HelpView>) {
    let Some(v) = view.as_ref() else {
        return;
    };
    let h = langs.help;
    let shown = egui::Modal::new(Id::unique("corerouter-help-modal")).show(ctx, |ui| {
        ui.set_max_width(520.0);
        ui.label(RichText::new(&v.title).strong().heading());
        ui.separator();
        let mut close = false;
        ScrollArea::vertical().max_height(420.0).show(ui, |ui| {
            match i18n::explain(langs, &v.key) {
                Some((_, text)) => crate::markdown::show(ui, text),
                None => {
                    ui.weak(tr(h, "No explanation yet."));
                }
            }
            for (heading, body) in &v.extra {
                ui.add_space(6.0);
                ui.label(RichText::new(tr(h, heading)).strong());
                crate::markdown::show(ui, body);
            }
        });
        ui.separator();
        ui.horizontal(|ui| {
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                close = ui.button(tr(langs.labels, "Close")).clicked();
            });
        });
        close
    });
    if shown.inner || shown.should_close() {
        *view = None;
    }
}

