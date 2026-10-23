//! Quick search of the side menu (G0.23b): the field at the top of the menu
//! and the Ctrl+K palette. A window is found by its title, its menu label,
//! its group (`IP DNS Static`), its RouterOS path (`/ip dns static`) and the
//! synonyms of `menu::CATALOG` (nat, masquerade, rota padrão, lease…), in
//! English or Portuguese, with or without accents. The router's commands
//! (`engine.list`) are found by their id or path (`ip dns static add`).
//! Pure: the menu and the palette draw what [`search`] returns.

use egui::{Id, Key, Modifiers};

use crate::i18n::{Lang, tr};
use crate::menu;
use crate::windows::Win;
use crate::CoreRouterUi;

/// One result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Hit {
    Win(Win),
    /// A command id (`ip.dns.static.add`): opens a terminal with it.
    Command(String),
}

/// Most commands listed for one query: windows come first.
const MAX_COMMANDS: usize = 8;
/// Longest query looked at (a paste stays cheap).
pub(crate) const MAX_QUERY: usize = 80;
/// Windows the palette lists (the menu's own list scrolls).
const PALETTE_WINDOWS: usize = 12;

/// Lowercase, no accents, `/ . ›` as spaces, single spaces: "/IP › DNS
/// Estático" and "ip dns estatico" compare equal.
pub(crate) fn fold(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars().flat_map(char::to_lowercase) {
        let c = match c {
            'á' | 'à' | 'â' | 'ã' | 'ä' => 'a',
            'é' | 'è' | 'ê' | 'ë' => 'e',
            'í' | 'ì' | 'î' | 'ï' => 'i',
            'ó' | 'ò' | 'ô' | 'õ' | 'ö' => 'o',
            'ú' | 'ù' | 'û' | 'ü' => 'u',
            'ç' => 'c',
            '/' | '.' | '›' | ',' => ' ',
            c => c,
        };
        if c == ' ' && (out.is_empty() || out.ends_with(' ')) {
            continue;
        }
        out.push(c);
    }
    out.truncate(out.trim_end().len());
    out
}

/// The texts a window is found by, folded: (text, weight).
fn haystack(win: Win) -> Vec<(String, u32)> {
    let mut out = Vec::new();
    let title = win.title();
    let label = menu::label(win);
    for (t, w) in [(title, 50), (label, 40)] {
        out.push((fold(t), w));
        out.push((fold(tr(Lang::Pt, t)), w));
    }
    let entry = menu::entry(win);
    let group = crate::windows::menu()
        .into_iter()
        .find(|(_, items)| items.contains(&win))
        .map(|(g, _)| g)
        .unwrap_or_default();
    let sub = entry.and_then(|e| e.sub).unwrap_or_default();
    // "IP" is the RouterOS name; operators also look for IPv4 there.
    let alias = if group == "IP" { " ipv4" } else { "" };
    out.push((fold(&format!("{group}{alias} {sub} {label}")), 30));
    if let Some(e) = entry {
        if !e.path.is_empty() {
            out.push((fold(e.path), 45));
        }
        out.extend(e.synonyms.iter().map(|s| (fold(s), 35)));
    }
    out
}

/// How well `q` (folded, non-empty) names `win`; 0 = not at all. Every
/// word of the query must be in one of the window's texts.
fn score(win: Win, q: &str) -> u32 {
    let hay = haystack(win);
    let words: Vec<&str> = q.split(' ').collect();
    let all = words
        .iter()
        .all(|w| hay.iter().any(|(t, _)| t.contains(w)));
    if !all {
        return 0;
    }
    hay.iter()
        .map(|(t, w)| {
            if t == q {
                w * 20
            } else if t.starts_with(q) {
                w * 10
            } else if t.contains(q) {
                w * 4
            } else {
                *w
            }
        })
        .max()
        .unwrap_or(1)
}

/// The windows and commands `query` finds, best first. `commands`: the
/// router's command ids.
pub(crate) fn search<'a>(query: &str, commands: impl IntoIterator<Item = &'a str>) -> Vec<Hit> {
    let q: String = query.chars().take(MAX_QUERY).collect();
    let q = fold(&q);
    if q.is_empty() {
        return Vec::new();
    }
    let mut wins: Vec<(u32, Win)> = Win::all()
        .into_iter()
        .map(|w| (score(w, &q), w))
        .filter(|(s, _)| *s > 0)
        .collect();
    wins.sort_by(|(sa, a), (sb, b)| sb.cmp(sa).then_with(|| a.title().cmp(b.title())));
    let mut out: Vec<Hit> = wins.into_iter().map(|(_, w)| Hit::Win(w)).collect();
    if q.chars().count() >= 2 {
        let words: Vec<&str> = q.split(' ').collect();
        let mut cmds: Vec<&str> = commands
            .into_iter()
            .filter(|id| {
                let f = fold(id);
                words.iter().all(|w| f.contains(w))
            })
            .collect();
        cmds.sort_by_key(|id| (id.len(), *id));
        out.extend(
            cmds.into_iter()
                .take(MAX_COMMANDS)
                .map(|id| Hit::Command(id.to_owned())),
        );
    }
    out
}

/// A command as the terminal types it: `ip.dns.static.add` →
/// `/ip dns static add `.
pub(crate) fn terminal_line(id: &str) -> String {
    format!("/{} ", id.replace('.', " "))
}

/// The fields keep the arrows and Esc (the menu and the palette use them),
/// instead of egui moving or dropping the focus.
pub(crate) const KEEP_KEYS: egui::EventFilter = egui::EventFilter {
    tab: false,
    horizontal_arrows: true,
    vertical_arrows: true,
    escape: true,
};

/// Id of the palette's field.
pub(crate) fn palette_id() -> Id {
    Id::unique("corerouter-menu-palette")
}

impl CoreRouterUi {
    /// The Ctrl+K palette: a field and what it finds (the recent windows
    /// while empty); arrows pick, Enter or a click opens, Esc closes.
    pub(crate) fn palette(&mut self, ctx: &egui::Context) {
        let Some(mut p) = self.menu.palette.take() else {
            return;
        };
        let labels = self.lang.labels;
        let empty = p.query.trim().is_empty();
        let mut hits = if empty {
            self.recent_hits()
        } else {
            self.menu_search(&p.query)
        };
        let wins = hits.iter().filter(|h| matches!(h, Hit::Win(_))).count();
        if wins > PALETTE_WINDOWS {
            // The best windows, and the commands after them.
            let mut seen = 0;
            hits.retain(|h| match h {
                Hit::Win(_) => {
                    seen += 1;
                    seen <= PALETTE_WINDOWS
                }
                Hit::Command(_) => true,
            });
        }
        let [down, up, enter] = [Key::ArrowDown, Key::ArrowUp, Key::Enter]
            .map(|k| ctx.input_mut(|i| i.consume_key(Modifiers::NONE, k)));
        if down {
            p.hit = p.hit.saturating_add(1);
        }
        if up {
            p.hit = p.hit.saturating_sub(1);
        }
        p.hit = p.hit.min(hits.len().saturating_sub(1));
        let mut chosen = if enter { hits.get(p.hit).cloned() } else { None };
        let shown = egui::Modal::new(Id::unique("corerouter-palette")).show(ctx, |ui| {
            ui.set_width(520.0);
            let resp = ui.add(
                egui::TextEdit::singleline(&mut p.query)
                    .id(palette_id())
                    .event_filter(KEEP_KEYS)
                    .hint_text(tr(labels, "Type a window, a RouterOS path or a command"))
                    .char_limit(MAX_QUERY)
                    .desired_width(f32::INFINITY),
            );
            if p.fresh {
                resp.request_focus();
                p.fresh = false;
            }
            if resp.changed() {
                p.hit = 0;
            }
            ui.add_space(4.0);
            if empty && !hits.is_empty() {
                ui.weak(tr(labels, "Recent"));
            }
            // No scroll area: one inside the modal shrinks to its minimum
            // height; the list is short instead.
            ui.spacing_mut().item_spacing.y = 0.0;
            self.hit_rows(ui, "palette", &hits, p.hit)
        });
        if let Some(i) = shown.inner {
            chosen = hits.get(i).cloned();
        }
        if let Some(h) = chosen {
            self.activate(&h);
        } else if !shown.should_close() {
            self.menu.palette = Some(p);
        }
    }
}
