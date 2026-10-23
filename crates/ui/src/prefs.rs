//! Preferences of the window, not of the router: the theme (light, dark or
//! the system's), which tables show comments inline and the languages of
//! the labels and of the explanations (G0.15). They never go
//! through the engine; the app stores them where eframe keeps app state
//! (a file natively, `localStorage` on the web) as the JSON of
//! [`CoreRouterUi::prefs`].

use egui::{Color32, Id, Rect, Sense, Stroke, ThemePreference, Ui, pos2, vec2};
use serde_json::{Value, json};

use crate::CoreRouterUi;
use crate::i18n::Lang;

/// Larger stored preferences are ignored: they were not written by us.
const MAX_PREFS: usize = 16 * 1024;

/// The choices of the theme switch, left to right.
const THEMES: [(ThemePreference, &str, &str); 3] = [
    (
        ThemePreference::System,
        "system",
        "Theme: follow the system",
    ),
    (ThemePreference::Light, "light", "Theme: light"),
    (ThemePreference::Dark, "dark", "Theme: dark"),
];

pub(crate) fn theme_id(pref: ThemePreference) -> Id {
    Id::unique(("corerouter-theme", theme_name(pref)))
}

fn theme_name(pref: ThemePreference) -> &'static str {
    THEMES
        .iter()
        .find(|(p, ..)| *p == pref)
        .map_or("system", |(_, name, _)| name)
}

fn theme_in(v: &Value) -> Option<ThemePreference> {
    THEMES
        .iter()
        .find(|(_, name, _)| v.get("theme").and_then(Value::as_str) == Some(*name))
        .map(|(pref, ..)| *pref)
}

/// The theme of stored preferences, for screens drawn before a router is
/// picked (the connect screen).
pub fn stored_theme(text: &str) -> Option<ThemePreference> {
    if text.len() > MAX_PREFS {
        return None;
    }
    theme_in(&serde_json::from_str::<Value>(text).ok()?)
}

impl CoreRouterUi {
    /// The preferences as JSON, for the app to store.
    pub fn prefs(&self) -> String {
        let mut inline = self.tables.inline_comments();
        inline.extend(
            self.panels
                .iter()
                .flatten()
                .flat_map(|p| p.tables())
                .filter(|(_, t)| t.inline_comments)
                .map(|(salt, _)| salt),
        );
        json!({
            "theme": theme_name(self.theme),
            "inline_comments": inline,
            "labels_lang": self.lang.labels.code(),
            "help_lang": self.lang.help.code(),
            "menu": self.menu.prefs(),
        })
        .to_string()
    }

    /// Restore stored preferences. Anything unreadable is ignored and the
    /// defaults stay: a damaged file must not stop the GUI from starting.
    pub fn apply_prefs(&mut self, text: &str) {
        if text.len() > MAX_PREFS {
            return;
        }
        let Ok(v) = serde_json::from_str::<Value>(text) else {
            return;
        };
        if let Some(pref) = theme_in(&v) {
            self.theme = pref;
        }
        let lang = |k: &str| v.get(k).and_then(Value::as_str).and_then(Lang::from_code);
        if let Some(l) = lang("labels_lang") {
            self.lang.labels = l;
        }
        if let Some(l) = lang("help_lang") {
            self.lang.help = l;
        }
        if let Some(m) = v.get("menu") {
            self.menu.apply_prefs(m);
        }
        if let Some(list) = v.get("inline_comments").and_then(Value::as_array) {
            let panels = self.panels.iter_mut().flatten().flat_map(|p| p.tables_mut());
            for (salt, table) in self.tables.each().into_iter().chain(panels) {
                table.inline_comments = list.iter().any(|s| s.as_str() == Some(salt));
            }
        }
    }

    pub fn theme(&self) -> ThemePreference {
        self.theme
    }

    pub fn set_theme(&mut self, pref: ThemePreference) {
        self.theme = pref;
    }

    /// Make the context use the chosen theme (at start-up, after a click).
    pub(crate) fn sync_theme(&self, ctx: &egui::Context) {
        if ctx.options(|o| o.theme_preference) != self.theme {
            ctx.set_theme(self.theme);
            ctx.request_repaint();
        }
    }

    /// The System / Light / Dark switch at the right of the top bar.
    pub(crate) fn theme_switch(&mut self, ui: &mut Ui) {
        let h = ui.spacing().interact_size.y;
        let size = vec2(h * 1.25, h);
        let v = ui.visuals().clone();
        let mut picked = None;
        let mut whole = Rect::NOTHING;
        // Right-to-left layout: add the last choice first.
        for (pref, _, tip) in THEMES.iter().rev() {
            let (rect, _) = ui.allocate_exact_size(size, Sense::hover());
            let resp = ui
                .interact(rect, theme_id(*pref), Sense::click())
                .on_hover_text(*tip);
            whole = whole.union(rect);
            let on = self.theme == *pref;
            // Opaque backgrounds: the moon is cut out of its circle by
            // painting the background over it.
            let bg = if on {
                v.panel_fill.lerp_to_gamma(v.selection.bg_fill, 0.55)
            } else if resp.hovered() {
                v.widgets.hovered.weak_bg_fill
            } else {
                v.panel_fill
            };
            let ink = if on {
                v.strong_text_color()
            } else {
                v.weak_text_color()
            };
            ui.painter().rect_filled(rect.shrink(1.0), 3.0, bg);
            paint_theme_icon(ui, rect, *pref, ink, bg);
            if resp.clicked() {
                picked = Some(*pref);
            }
        }
        ui.painter().rect_stroke(
            whole,
            4.0,
            v.widgets.noninteractive.bg_stroke,
            egui::StrokeKind::Inside,
        );
        if let Some(pref) = picked {
            self.theme = pref;
            self.sync_theme(ui.ctx());
        }
    }
}

/// Sun (light), moon (dark), half-filled disc (follow the system).
fn paint_theme_icon(ui: &Ui, rect: Rect, pref: ThemePreference, ink: Color32, bg: Color32) {
    let p = ui.painter();
    let c = rect.center();
    let r = rect.height() * 0.24;
    match pref {
        ThemePreference::Light => {
            p.circle_filled(c, r * 0.55, ink);
            let stroke = Stroke::new(1.5, ink);
            for k in 0..8 {
                let a = k as f32 * std::f32::consts::FRAC_PI_4;
                let d = vec2(a.cos(), a.sin());
                p.line_segment([c + d * r * 0.85, c + d * r * 1.3], stroke);
            }
        }
        ThemePreference::Dark => {
            p.circle_filled(c, r, ink);
            p.circle_filled(c + vec2(r * 0.55, -r * 0.45), r * 0.85, bg);
        }
        ThemePreference::System => {
            p.circle_stroke(c, r, Stroke::new(1.5, ink));
            let half: Vec<_> = (0..=16)
                .map(|k| {
                    let a = std::f32::consts::FRAC_PI_2 + k as f32 * std::f32::consts::PI / 16.0;
                    pos2(c.x + r * a.cos(), c.y + r * a.sin())
                })
                .collect();
            p.add(egui::Shape::convex_polygon(half, ink, Stroke::NONE));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_engine::{Session, shared};

    fn app() -> CoreRouterUi {
        CoreRouterUi::new(shared(Session::virtual_lab()))
    }

    #[test]
    fn prefs_round_trip() {
        let mut a = app();
        assert_eq!(a.theme(), ThemePreference::System);
        a.set_theme(ThemePreference::Light);
        a.tables.addresses.inline_comments = true;
        a.lang.labels = Lang::Pt;
        a.lang.help = Lang::En;
        let saved = a.prefs();

        let mut b = app();
        b.apply_prefs(&saved);
        assert_eq!(b.theme(), ThemePreference::Light);
        assert!(b.tables.addresses.inline_comments);
        assert!(!b.tables.interfaces.inline_comments);
        assert_eq!((b.lang.labels, b.lang.help), (Lang::Pt, Lang::En));
        assert_eq!(b.prefs(), saved);
    }

    #[test]
    fn hostile_prefs_keep_the_defaults() {
        let mut a = app();
        let junk = [
            "",
            "{",
            "[]",
            "null",
            r#"{"theme": 7, "inline_comments": "interfaces"}"#,
            r#"{"theme": "neon", "inline_comments": [1, null, {}]}"#,
            r#"{"labels_lang": "klingon", "help_lang": 7}"#,
            r#"{"labels_lang": null, "help_lang": ["pt"]}"#,
        ];
        for j in junk {
            a.apply_prefs(j);
            assert_eq!(a.theme(), ThemePreference::System, "{j}");
            assert!(!a.tables.interfaces.inline_comments, "{j}");
            assert_eq!(a.lang, crate::i18n::Langs::default(), "{j}");
        }
        let huge = format!(r#"{{"theme": "dark", "pad": "{}"}}"#, "x".repeat(MAX_PREFS));
        a.apply_prefs(&huge);
        assert_eq!(a.theme(), ThemePreference::System);
    }
}
