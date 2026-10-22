//! Chips (pills): small rounded labels next to a value, and coloured chips
//! keyed by an id (an AS, a VLAN, a list name) whose colour comes from a hash
//! of the key, the same everywhere. The house style of the GUI: use these,
//! not text in brackets nor ad-hoc colours (docs/ui-style.md). First used by
//! the MTR (G6.3d).

use std::collections::BTreeMap;

use egui::{Color32, Ui};

/// A pill's colours: soft fill, ink of the same hue, optional border.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct Tone {
    pub(crate) fill: Color32,
    pub(crate) ink: Color32,
    pub(crate) border: Option<Color32>,
}

/// One hue for both themes: darker ink on the light one, lighter on the
/// dark one; the fill is the ink washed out, so it reads on striped rows.
pub(crate) struct Hue {
    light: (u8, u8, u8),
    dark: (u8, u8, u8),
}

impl Hue {
    pub(crate) fn tone(&self, v: &egui::Visuals) -> Tone {
        let ((r, g, b), wash) = if v.dark_mode {
            (self.dark, 0.20)
        } else {
            (self.light, 0.12)
        };
        let ink = Color32::from_rgb(r, g, b);
        Tone {
            fill: ink.gamma_multiply(wash),
            ink,
            border: None,
        }
    }
}

/// Warning: something the operator should notice ("CGNAT").
pub(crate) const AMBER: Hue = Hue {
    light: (140, 85, 0),
    dark: (245, 195, 105),
};

/// Information: an extra detail ("MPLS 85260").
pub(crate) const BLUE: Hue = Hue {
    light: (30, 95, 175),
    dark: (140, 190, 245),
};

/// Healthy: a state that is as it should be ("running"; G0.10).
pub(crate) const GREEN: Hue = Hue {
    light: (25, 125, 60),
    dark: (125, 215, 145),
};

/// Broken: a state that needs the operator ("failed"; G0.10).
pub(crate) const RED: Hue = Hue {
    light: (180, 40, 40),
    dark: (245, 140, 135),
};

/// The palette of keyed chips: eight hues far enough apart that two
/// neighbours (operators side by side on a path, VLANs in a list) never look
/// alike, each legible on both themes.
pub(crate) const PALETTE: [Hue; 8] = [
    BLUE,
    Hue {
        light: (0, 120, 120),
        dark: (110, 215, 205),
    },
    Hue {
        light: (35, 125, 50),
        dark: (140, 215, 140),
    },
    Hue {
        light: (110, 110, 0),
        dark: (210, 205, 110),
    },
    Hue {
        light: (175, 80, 10),
        dark: (250, 170, 110),
    },
    Hue {
        light: (180, 35, 55),
        dark: (245, 145, 155),
    },
    Hue {
        light: (110, 60, 180),
        dark: (195, 165, 245),
    },
    Hue {
        light: (160, 40, 140),
        dark: (240, 150, 220),
    },
];

/// Which palette entry a key gets (an AS number, a VLAN id, `key_of(name)`):
/// Fibonacci hashing, so the colour is fixed by the key alone (the same AS
/// looks the same on every hop and in every run) and consecutive numbers
/// always land on different entries (consecutive products differ by 0.618
/// of the range, more than 1/8).
pub(crate) fn hashed(key: u64) -> usize {
    let h = (key as u32).wrapping_mul(0x9E37_79B9);
    (h >> 29) as usize
}

/// The colour of each key down a list (the ASs of a path): its own
/// (`hashed`), except when the key right before it (a different one)
/// already has it; then the next one, so a change always shows (a hand-over
/// between operators). A key keeps the colour it got first.
pub(crate) fn hues_along(keys: impl IntoIterator<Item = u64>) -> BTreeMap<u64, usize> {
    let mut out: BTreeMap<u64, usize> = BTreeMap::new();
    let mut prev: Option<usize> = None;
    for key in keys {
        let hue = *out.entry(key).or_insert_with(|| {
            let own = hashed(key);
            if prev == Some(own) {
                (own + 1) % PALETTE.len()
            } else {
                own
            }
        });
        prev = Some(hue);
    }
    out
}

/// The tone of palette entry `hue` (from `hashed`/`hues_along`).
pub(crate) fn palette_tone(v: &egui::Visuals, hue: usize) -> Tone {
    PALETTE
        .get(hue)
        .map_or_else(|| neutral_tone(v), |h| h.tone(v))
}

/// Discreet: a fact worth a glance ("privada").
pub(crate) fn neutral_tone(v: &egui::Visuals) -> Tone {
    Tone {
        fill: v.widgets.noninteractive.weak_bg_fill,
        ink: v.weak_text_color(),
        border: Some(v.widgets.noninteractive.bg_stroke.color),
    }
}

/// Font size of the pills: a step below the table's.
fn small(ui: &Ui) -> f32 {
    ui.style()
        .text_styles
        .get(&egui::TextStyle::Body)
        .map_or(11.0, |f| f.size * 0.85)
}

/// A small rounded pill, never taller than a table row.
pub(crate) fn chip(ui: &mut Ui, text: &str, tone: Tone) -> egui::Response {
    let font = egui::FontId::proportional(small(ui));
    let galley = ui
        .painter()
        .layout_no_wrap(text.to_owned(), font, tone.ink);
    let pad = egui::vec2(7.0, 2.0);
    let h = (galley.size().y + 2.0 * pad.y).min(ui.spacing().interact_size.y - 2.0);
    let (rect, resp) = ui.allocate_exact_size(
        egui::vec2(galley.size().x + 2.0 * pad.x, h),
        egui::Sense::hover(),
    );
    if ui.is_rect_visible(rect) {
        let stroke = tone
            .border
            .map_or(egui::Stroke::NONE, |c| egui::Stroke::new(1.0, c));
        ui.painter()
            .rect(rect, 8.0, tone.fill, stroke, egui::StrokeKind::Inside);
        let at = rect.center() - galley.size() / 2.0;
        ui.painter().galley(at, galley, tone.ink);
    }
    resp
}


// ---- chips inside a table cell (G4.2a) ------------------------------------

/// Separates a table cell's text from its chips (`table::show` paints
/// them): `cell("lab-laptop", &[("DNS", Kind::Blue)])`.
pub(crate) const SEP: char = '\u{1f}';

/// The tone of a chip in a cell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    Neutral,
    Amber,
    Blue,
    Green,
    Red,
    /// A palette entry (`hashed`).
    Hashed(usize),
}

impl Kind {
    fn code(self) -> char {
        match self {
            Self::Neutral => 'n',
            Self::Amber => 'a',
            Self::Blue => 'b',
            Self::Green => 'g',
            Self::Red => 'r',
            Self::Hashed(i) => char::from_digit(u32::try_from(i % PALETTE.len()).unwrap_or(0), 10).unwrap_or('0'),
        }
    }

    fn of(code: char) -> Self {
        match code {
            'a' => Self::Amber,
            'b' => Self::Blue,
            'g' => Self::Green,
            'r' => Self::Red,
            d if d.is_ascii_digit() => Self::Hashed(d.to_digit(10).map_or(0, |n| n as usize)),
            _ => Self::Neutral,
        }
    }

    pub(crate) fn tone(self, v: &egui::Visuals) -> Tone {
        match self {
            Self::Neutral => neutral_tone(v),
            Self::Amber => AMBER.tone(v),
            Self::Blue => BLUE.tone(v),
            Self::Green => GREEN.tone(v),
            Self::Red => RED.tone(v),
            Self::Hashed(i) => palette_tone(v, i),
        }
    }
}

/// A cell: `text`, then `chips` on the same line.
pub(crate) fn cell(text: &str, chips: &[(&str, Kind)]) -> String {
    let mut out = text.replace(SEP, " ");
    for (label, kind) in chips {
        out.push(SEP);
        out.push(kind.code());
        out.push_str(&label.replace(SEP, " "));
    }
    out
}

/// A cell's text and its chips.
pub(crate) fn split(cell: &str) -> (&str, Vec<(Kind, &str)>) {
    let mut parts = cell.split(SEP);
    let text = parts.next().unwrap_or("");
    let chips = parts
        .filter_map(|p| {
            let mut c = p.chars();
            let code = c.next()?;
            Some((Kind::of(code), c.as_str()))
        })
        .collect();
    (text, chips)
}

const CELL_GAP: f32 = 6.0;
const CELL_PAD: egui::Vec2 = egui::vec2(6.0, 1.0);

/// Width of a cell's chips (after its text).
pub(crate) fn cell_chips_width(painter: &egui::Painter, chips: &[(Kind, &str)], size: f32) -> f32 {
    chips
        .iter()
        .map(|(_, label)| {
            let g = painter.layout_no_wrap((*label).to_owned(), egui::FontId::proportional(size), Color32::PLACEHOLDER);
            CELL_GAP + g.size().x + 2.0 * CELL_PAD.x
        })
        .sum()
}

/// Paint a cell's chips from `x` on the line centred at `y`, at most
/// `height` tall.
pub(crate) fn paint_cell_chips(painter: &egui::Painter, v: &egui::Visuals, x: f32, y: f32, height: f32, chips: &[(Kind, &str)], size: f32) {
    let mut x = x;
    for (kind, label) in chips {
        let tone = kind.tone(v);
        let g = painter.layout_no_wrap((*label).to_owned(), egui::FontId::proportional(size), tone.ink);
        let h = (g.size().y + 2.0 * CELL_PAD.y).min(height - 2.0);
        x += CELL_GAP;
        let rect = egui::Rect::from_min_size(egui::pos2(x, y - h / 2.0), egui::vec2(g.size().x + 2.0 * CELL_PAD.x, h));
        let stroke = tone.border.map_or(egui::Stroke::NONE, |c| egui::Stroke::new(1.0, c));
        painter.rect(rect, 8.0, tone.fill, stroke, egui::StrokeKind::Inside);
        painter.galley(rect.center() - g.size() / 2.0, g, tone.ink);
        x = rect.right();
    }
}

/// Font size of chips in a table: a step below the body.
pub(crate) fn cell_size(font: &egui::FontId) -> f32 {
    font.size * 0.85
}

#[cfg(test)]
mod cell_tests {
    use super::*;

    #[test]
    fn cells_carry_their_chips() {
        let c = cell("lab-laptop", &[("DNS", Kind::Blue), ("ONU 1/1/3", Kind::Hashed(3))]);
        let (text, chips) = split(&c);
        assert_eq!(text, "lab-laptop");
        assert_eq!(chips, vec![(Kind::Blue, "DNS"), (Kind::Hashed(3), "ONU 1/1/3")]);
        assert_eq!(split("plain"), ("plain", vec![]));
    }
}
