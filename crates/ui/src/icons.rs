//! The icons of the side menu (G0.23): Phosphor Icons (MIT), the regular
//! weight, as text in a font family of their own. Only the glyphs below are
//! embedded: `assets/phosphor/Phosphor-subset.ttf` is cut from the full
//! font by `scripts/icons-subset.sh`, which reads the code points of this
//! file — add a constant, run the script, commit both. A test checks that
//! the font has every glyph listed here.
//!
//! `egui-phosphor` was the plan, but its 0.14 needs egui 0.36 and this
//! workspace is on 0.37: two eguis in one build. The font is the crate's
//! (same file), the names are Phosphor's.

use egui::{Color32, FontData, FontFamily, FontId, Ui};
use egui::epaint::text::{FontInsert, FontPriority, InsertFontFamily};

/// The subset of `Phosphor.ttf` (regular) with the code points below.
const FONT: &[u8] = include_bytes!("../assets/phosphor/Phosphor-subset.ttf");
const NAME: &str = "phosphor";

pub(crate) const ARROW_BEND_UP_RIGHT: &str = "\u{E026}";
pub(crate) const ARROWS_LEFT_RIGHT: &str = "\u{E0A0}";
pub(crate) const ARROWS_SPLIT: &str = "\u{ED3C}";
pub(crate) const BROADCAST: &str = "\u{E0F2}";
pub(crate) const CARET_DOWN: &str = "\u{E136}";
pub(crate) const CARET_RIGHT: &str = "\u{E13A}";
pub(crate) const CHART_BAR: &str = "\u{E150}";
pub(crate) const CLOCK: &str = "\u{E19A}";
pub(crate) const CLOCK_COUNTER_CLOCKWISE: &str = "\u{E1A0}";
pub(crate) const DATABASE: &str = "\u{E1DE}";
pub(crate) const FOLDERS: &str = "\u{E260}";
pub(crate) const GAUGE: &str = "\u{E628}";
pub(crate) const GEAR: &str = "\u{E270}";
pub(crate) const GEAR_SIX: &str = "\u{E272}";
pub(crate) const GLOBE: &str = "\u{E288}";
pub(crate) const GLOBE_HEMISPHERE_WEST: &str = "\u{E28C}";
pub(crate) const GRAPH: &str = "\u{EB58}";
pub(crate) const HARD_DRIVES: &str = "\u{E2A0}";
pub(crate) const HEARTBEAT: &str = "\u{E2AC}";
pub(crate) const IDENTIFICATION_BADGE: &str = "\u{E6F6}";
pub(crate) const KEY: &str = "\u{E2D6}";
pub(crate) const LAPTOP: &str = "\u{E586}";
pub(crate) const LINK: &str = "\u{E2E2}";
pub(crate) const LIST_BULLETS: &str = "\u{E2F2}";
pub(crate) const LOCK_SIMPLE: &str = "\u{E308}";
pub(crate) const MAGNIFYING_GLASS: &str = "\u{E30C}";
pub(crate) const MAP_PIN: &str = "\u{E316}";
pub(crate) const NOTEBOOK: &str = "\u{E34E}";
pub(crate) const PATH: &str = "\u{E39C}";
pub(crate) const PAUSE: &str = "\u{E39E}";
pub(crate) const PLAY: &str = "\u{E3D0}";
pub(crate) const PLUGS: &str = "\u{EB56}";
pub(crate) const PLUGS_CONNECTED: &str = "\u{EB5A}";
pub(crate) const PROHIBIT: &str = "\u{E3DE}";
pub(crate) const PULSE: &str = "\u{E000}";
pub(crate) const PUSH_PIN: &str = "\u{E3E2}";
pub(crate) const SCROLL: &str = "\u{EB7A}";
pub(crate) const SHARE_NETWORK: &str = "\u{E408}";
pub(crate) const SHIELD_CHECK: &str = "\u{E40C}";
pub(crate) const SIGNPOST: &str = "\u{E89C}";
pub(crate) const SKIP_BACK: &str = "\u{E5A4}";
pub(crate) const SKIP_FORWARD: &str = "\u{E5A6}";
pub(crate) const SLIDERS_HORIZONTAL: &str = "\u{E434}";
pub(crate) const SQUARES_FOUR: &str = "\u{E464}";
pub(crate) const STACK: &str = "\u{E466}";
pub(crate) const STACK_SIMPLE: &str = "\u{E468}";
pub(crate) const STAR: &str = "\u{E46A}";
pub(crate) const TAG: &str = "\u{E478}";
pub(crate) const TERMINAL: &str = "\u{E47E}";
pub(crate) const TERMINAL_WINDOW: &str = "\u{EAE8}";
pub(crate) const TREE_STRUCTURE: &str = "\u{E67C}";
pub(crate) const TREE_VIEW: &str = "\u{EE48}";
pub(crate) const USB: &str = "\u{E956}";
pub(crate) const USERS_THREE: &str = "\u{E68E}";
pub(crate) const WRENCH: &str = "\u{E5D4}";

/// The icons' family, apart from text: egui's own emoji font uses the
/// same private-use code points for other pictures.
pub(crate) fn family() -> FontFamily {
    FontFamily::Name(NAME.into())
}

pub(crate) fn font(size: f32) -> FontId {
    FontId::new(size, family())
}

/// Install the icon font (once per context; a no-op after). It takes effect
/// at once when no text was laid out yet this frame, else next frame.
pub(crate) fn install(ctx: &egui::Context) {
    ctx.add_font(FontInsert::new(
        NAME,
        FontData::from_static(FONT),
        vec![InsertFontFamily {
            family: family(),
            priority: FontPriority::Highest,
        }],
    ));
}

/// Whether the icons can be drawn this frame (installed and active).
pub(crate) fn ready(ctx: &egui::Context) -> bool {
    ctx.fonts(|f| f.definitions().families.contains_key(&family()))
}

/// Paint `icon` centred in `rect`; nothing before the font is active.
pub(crate) fn paint(ui: &Ui, rect: egui::Rect, icon: &str, size: f32, color: Color32) {
    if !ready(ui.ctx()) {
        return;
    }
    ui.painter().text(
        rect.center(),
        egui::Align2::CENTER_CENTER,
        icon,
        font(size),
        color,
    );
}

/// Every constant above, for the test that the font has them.
#[cfg(test)]
pub(crate) const ALL: &[&str] = &[
    ARROW_BEND_UP_RIGHT,
    ARROWS_LEFT_RIGHT,
    ARROWS_SPLIT,
    BROADCAST,
    CARET_DOWN,
    CARET_RIGHT,
    CHART_BAR,
    CLOCK,
    CLOCK_COUNTER_CLOCKWISE,
    DATABASE,
    FOLDERS,
    GAUGE,
    GEAR,
    GEAR_SIX,
    GLOBE,
    GLOBE_HEMISPHERE_WEST,
    GRAPH,
    HARD_DRIVES,
    HEARTBEAT,
    IDENTIFICATION_BADGE,
    KEY,
    LAPTOP,
    LINK,
    LIST_BULLETS,
    LOCK_SIMPLE,
    MAGNIFYING_GLASS,
    MAP_PIN,
    NOTEBOOK,
    PATH,
    PAUSE,
    PLAY,
    PLUGS,
    PLUGS_CONNECTED,
    PROHIBIT,
    PULSE,
    PUSH_PIN,
    SCROLL,
    SHARE_NETWORK,
    SHIELD_CHECK,
    SIGNPOST,
    SKIP_BACK,
    SKIP_FORWARD,
    SLIDERS_HORIZONTAL,
    SQUARES_FOUR,
    STACK,
    STACK_SIMPLE,
    STAR,
    TAG,
    TERMINAL,
    TERMINAL_WINDOW,
    TREE_STRUCTURE,
    TREE_VIEW,
    USB,
    USERS_THREE,
    WRENCH,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_font_has_every_icon() {
        let ctx = egui::Context::default();
        install(&ctx);
        ctx.run_ui(egui::RawInput::default(), |_| {})
            .drop_without_applying_deltas();
        assert!(ready(&ctx));
        for icon in ALL {
            let has = ctx.fonts_mut(|f| f.has_glyphs(&font(14.0), icon));
            assert!(has, "icon {icon:?} missing: run scripts/icons-subset.sh");
        }
    }
}
