//! WinBox-style list tables, shared by every list window.
//!
//! What the table does on its own: whole-row selection (click, Ctrl+click,
//! Shift+click, click on empty space, Ctrl+A, ↑/↓), the quick-find filter,
//! and the context menus on a row and on empty space. What it does *not* do
//! is decide what an action means: it hands the window a [`Menu`] to fill and
//! reports double clicks and shortcuts in [`TableOutput`]; the window turns
//! those into `CoreRouterUi::run` calls. Shortcuts follow the WinBox v3/v4
//! tables (help.mikrotik.com, WinBox page): Delete removes, Ctrl+E enables,
//! Ctrl+D disables, Ctrl+M comments, Ctrl+F jumps to the find field.
//!
//! Comments: a table whose columns include [`comment`] shows the item's
//! comment either in that column or, with "Inline Comments" ticked in its
//! context menu, as a band above the item (WinBox v4 "Comment Type: header",
//! the `;;;` line of the RouterOS terminal). The band belongs to the item:
//! clicking, double clicking and right clicking it act on the item. Both
//! ways draw the comment with the same colours ([`comment_style`]): the
//! accent blue for an enabled item, dark grey for a disabled (dimmed) one.

use std::borrow::Cow;
use std::collections::{BTreeSet, HashSet};
use std::ops::Deref;

use egui::{
    Align2, Button, Color32, EventFilter, Id, Key, Modifiers, Rect, ScrollArea, Sense, Stroke,
    TextEdit, TextStyle, Ui, Visuals, pos2, vec2,
};

/// Horizontal padding inside each cell, in points.
const CELL_PAD: f32 = 6.0;
/// Rows the table lays out at most; a longer list is cut (and says so).
pub(crate) const MAX_ROWS: usize = 10_000;
/// Left edge of an inline comment's text: room for the accent bar and icon.
const NOTE_INDENT: f32 = 30.0;
/// Characters of a comment drawn inline; the rest is cut with "…".
const NOTE_CHARS: usize = 512;
/// Room for the speech-bubble icon before a comment in the Comment column.
const CELL_ICON: f32 = 18.0;
/// Room for a column title's ⓘ.
const HELP_W: f32 = 18.0;
/// Characters of a cell drawn; a longer value ends in "…" and the whole
/// text is in the tooltip (docs/ui-style.md › Tabelas). Keeps one huge
/// comment from making its column thousands of points wide.
pub(crate) const CELL_CHARS: usize = 120;
/// Characters of a cut cell the tooltip shows.
const TIP_CHARS: usize = 4096;

pub(crate) struct Column {
    pub title: &'static str,
    /// Numbers read better right-aligned.
    pub right: bool,
    /// The item's comment: drawn above the row with Inline Comments on.
    pub comment: bool,
    /// Secondary text (why a route is inactive): drawn in the weak colour.
    pub weak: bool,
    /// Explanation key (`i18n::explain`) of the column: an ⓘ after its
    /// title, whose click comes back in [`TableOutput::help`]. Empty: none.
    pub help: &'static str,
}

impl Column {
    /// This column with an ⓘ opening explanation `key`.
    pub(crate) const fn help(mut self, key: &'static str) -> Self {
        self.help = key;
        self
    }
}

pub(crate) const fn col(title: &'static str) -> Column {
    Column {
        title,
        right: false,
        comment: false,
        weak: false,
        help: "",
    }
}

pub(crate) const fn num(title: &'static str) -> Column {
    Column {
        title,
        right: true,
        comment: false,
        weak: false,
        help: "",
    }
}

/// A column of secondary text, in grey (G1.27: the reason of a route).
pub(crate) const fn weak(title: &'static str) -> Column {
    Column {
        title,
        right: false,
        comment: false,
        weak: true,
        help: "",
    }
}

/// The "Comment" column, which Inline Comments turns into a band.
pub(crate) const fn comment() -> Column {
    Column {
        title: "Comment",
        right: false,
        comment: true,
        weak: false,
        help: "",
    }
}

pub(crate) struct Row {
    /// Stable identity (interface name, address id …): selection survives
    /// refreshes and reordering because it is kept by key, not by index.
    pub key: String,
    pub cells: Vec<String>,
    /// Drawn greyed out, like a disabled item in WinBox.
    pub dimmed: bool,
    /// A section header (firewall): one full-width band with the title,
    /// which is the text of the comment column (or the first cell).
    pub section: bool,
    /// Text colour of an enabled, unselected row (e.g. by firewall action).
    pub tint: Option<Color32>,
}

impl Row {
    fn matches(&self, needle: &str) -> bool {
        needle.is_empty() || self.cells.iter().any(|c| c.to_lowercase().contains(needle))
    }
}

/// The selected keys of a table: in display order (what actions act on)
/// and as a set, so a window asking "is this row selected?" for each of
/// 10 000 rows does not scan the whole selection each time.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Selection {
    keys: Vec<String>,
    set: HashSet<String>,
}

impl Selection {
    pub fn contains(&self, key: &str) -> bool {
        self.set.contains(key)
    }

    pub fn as_slice(&self) -> &[String] {
        &self.keys
    }

    /// The keys in display order.
    pub fn into_vec(self) -> Vec<String> {
        self.keys
    }
}

impl<'a> IntoIterator for &'a Selection {
    type Item = &'a String;
    type IntoIter = std::slice::Iter<'a, String>;

    fn into_iter(self) -> Self::IntoIter {
        self.keys.iter()
    }
}

impl FromIterator<String> for Selection {
    fn from_iter<I: IntoIterator<Item = String>>(iter: I) -> Self {
        let keys: Vec<String> = iter.into_iter().collect();
        let set = keys.iter().cloned().collect();
        Self { keys, set }
    }
}

impl Deref for Selection {
    type Target = [String];

    fn deref(&self) -> &[String] {
        &self.keys
    }
}

/// What a context menu is about.
pub(crate) enum Menu<'a> {
    /// Right click on a row: act on these selected keys (display order).
    Rows(&'a Selection),
    /// Right click on the empty space below the rows.
    Empty,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Shortcut {
    Remove,
    Enable,
    Disable,
    Comment,
    /// Enter: open the selected items, like a double click.
    Open,
}

#[derive(Default)]
pub(crate) struct TableOutput {
    /// Key of the row that was double-clicked.
    pub opened: Option<String>,
    /// Key of the row clicked this frame (G1.27: an ECMP group opens).
    pub clicked: Option<String>,
    /// Key of the item whose inline comment was double-clicked: edit the
    /// comment (a window without a comment dialog treats it as `opened`).
    pub comment: Option<String>,
    pub shortcut: Option<Shortcut>,
    /// A row was dragged and dropped (tables with [`TableState::reorder`]):
    /// (dragged key, key of the row it lands above; `None` = after the last).
    pub dropped: Option<(String, Option<String>)>,
    /// The ⓘ of a column title was clicked: its explanation key.
    pub help: Option<&'static str>,
    /// The chip under the pointer: (row key, column, chip index), and
    /// whether it was clicked this frame (G0.25: the subscriber chip shows
    /// its sources and opens its item).
    pub chip: Option<(String, usize, usize)>,
    pub chip_clicked: bool,
}

/// UI-local state of one table: selection, Shift anchor, find text, and
/// how comments are shown.
#[derive(Default)]
pub(crate) struct TableState {
    selected: BTreeSet<String>,
    anchor: Option<String>,
    pub filter: String,
    /// Comments as a band above each item instead of a column.
    pub inline_comments: bool,
    /// Column names hidden by the operator; independent of inline comments.
    pub hidden_columns: BTreeSet<String>,
    /// Rows can be dragged to a new place (order matters: firewall rules).
    pub reorder: bool,
    /// Items whose own window is open, set by the list before each frame:
    /// a mark at the left end of the row, and a click on the mark brings
    /// that window to the front (as a double click on the row does).
    pub open: BTreeSet<String>,
    /// [`Self::reveal`]: the selection waits for the rows to arrive.
    revealing: bool,
}

impl TableState {
    pub fn is_selected(&self, key: &str) -> bool {
        self.selected.contains(key)
    }

    /// Selected keys in display order.
    pub fn selection(&self, rows: &[Row]) -> Selection {
        if self.selected.is_empty() {
            return Selection::default();
        }
        self.visible(rows)
            .filter(|r| self.selected.contains(&r.key))
            .map(|r| r.key.clone())
            .collect()
    }

    /// Rows that pass the find filter, in display order.
    pub fn visible<'a>(&self, rows: &'a [Row]) -> impl Iterator<Item = &'a Row> {
        let needle = self.filter.trim().to_lowercase();
        rows.iter()
            .take(MAX_ROWS)
            .filter(move |r| r.matches(&needle))
    }

    /// Plain click selects one row, Ctrl toggles one, Shift selects from the
    /// anchor (the last plain or Ctrl click) to this row; Ctrl+Shift adds
    /// that range to the selection.
    pub fn click(&mut self, key: &str, ctrl: bool, shift: bool, order: &[&str]) {
        if shift && let Some(range) = self.range_to(key, order) {
            if !ctrl {
                self.selected.clear();
            }
            self.selected.extend(range);
            return;
        }
        if ctrl {
            if !self.selected.remove(key) {
                self.selected.insert(key.to_owned());
            }
        } else {
            self.selected.clear();
            self.selected.insert(key.to_owned());
        }
        self.anchor = Some(key.to_owned());
    }

    fn range_to(&self, key: &str, order: &[&str]) -> Option<Vec<String>> {
        let anchor = self.anchor.as_deref()?;
        let a = order.iter().position(|k| *k == anchor)?;
        let b = order.iter().position(|k| *k == key)?;
        let (lo, hi) = (a.min(b), a.max(b));
        Some(
            order
                .get(lo..=hi)?
                .iter()
                .map(|k| (*k).to_owned())
                .collect(),
        )
    }

    pub fn select_only(&mut self, key: &str) {
        self.selected.clear();
        self.selected.insert(key.to_owned());
        self.anchor = Some(key.to_owned());
    }

    /// Select `key` in a table that may not have its rows yet (a window
    /// opened to show that item): the selection holds until rows arrive,
    /// and the find filter is cleared so the row shows.
    pub fn reveal(&mut self, key: &str) {
        self.select_only(key);
        self.filter.clear();
        self.revealing = true;
    }

    pub fn select_all(&mut self, rows: &[Row]) {
        self.selected = self.visible(rows).map(|r| r.key.clone()).collect();
    }

    pub fn clear(&mut self) {
        self.selected.clear();
        self.anchor = None;
    }

    /// Esc: clear the find text if any, else the selection if any. Returns
    /// whether there was something to clear (else the window closes).
    pub fn escape(&mut self) -> bool {
        if !self.filter.is_empty() {
            self.filter.clear();
        } else if !self.selected.is_empty() {
            self.clear();
        } else {
            return false;
        }
        true
    }

    /// ↑/↓: move the selection one row (Shift extends it from the anchor).
    fn step(&mut self, down: bool, shift: bool, order: &[&str]) {
        let cursor = order
            .iter()
            .enumerate()
            .filter(|(_, k)| self.selected.contains(**k))
            .map(|(i, _)| i)
            .reduce(|a, b| if down { a.max(b) } else { a.min(b) });
        let next = match cursor {
            None if down => 0,
            None => order.len().saturating_sub(1),
            Some(i) if down => (i + 1).min(order.len().saturating_sub(1)),
            Some(i) => i.saturating_sub(1),
        };
        if let Some(key) = order.get(next) {
            self.click(key, false, shift, order);
        }
    }

    /// Forget rows that are gone or filtered out: actions never touch rows
    /// the operator cannot see.
    fn retain(&mut self, order: &[&str]) {
        if std::mem::take(&mut self.revealing) && order.is_empty() {
            self.revealing = true;
            return;
        }
        // A set: `order.contains` per key was O(rows × selected) per frame.
        let shown: HashSet<&str> = order.iter().copied().collect();
        self.selected.retain(|k| shown.contains(k.as_str()));
    }
}

pub(crate) fn table_id(salt: &str) -> Id {
    Id::unique(("corerouter-table", salt))
}

pub(crate) fn row_id(salt: &str, key: &str) -> Id {
    table_id(salt).with(key)
}

fn filter_id(salt: &str) -> Id {
    table_id(salt).with("find")
}

/// The quick-find field at the right of a toolbar (Ctrl+F focuses it).
pub(crate) fn find_field(ui: &mut Ui, salt: &str, state: &mut TableState) {
    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
        ui.add(
            TextEdit::singleline(&mut state.filter)
                .id(filter_id(salt))
                .hint_text("Find")
                .desired_width(140.0),
        );
    });
}

/// A toolbar or menu entry that is greyed out with the reason as tooltip
/// when `enabled` is an `Err`.
pub(crate) fn action(ui: &mut Ui, text: &str, enabled: Result<(), String>) -> bool {
    match enabled {
        Ok(()) => ui.button(text).clicked(),
        Err(why) => {
            ui.add_enabled(false, Button::new(text))
                .on_disabled_hover_text(why);
            false
        }
    }
}

/// Toolbar icons, painted (egui's bundled font has no ✓/✗ glyphs) in the
/// WinBox colours: blue add, red remove/disable, green enable, yellow note;
/// a deeper shade of each on the light theme, so they keep their contrast.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Icon {
    Add,
    Remove,
    Enable,
    Disable,
    Comment,
}

impl Icon {
    fn color(self, dark: bool) -> Color32 {
        match (self, dark) {
            (Icon::Add, true) => Color32::from_rgb(80, 150, 240),
            (Icon::Add, false) => Color32::from_rgb(30, 105, 210),
            (Icon::Remove | Icon::Disable, true) => Color32::from_rgb(225, 80, 70),
            (Icon::Remove | Icon::Disable, false) => Color32::from_rgb(200, 45, 35),
            (Icon::Enable, true) => Color32::from_rgb(70, 185, 90),
            (Icon::Enable, false) => Color32::from_rgb(30, 140, 55),
            (Icon::Comment, true) => Color32::from_rgb(235, 195, 70),
            (Icon::Comment, false) => Color32::from_rgb(215, 160, 20),
        }
    }

    fn paint(self, painter: &egui::Painter, rect: Rect, color: Color32) {
        let c = rect.center();
        let r = rect.height() * 0.28;
        let stroke = Stroke::new(2.0, color);
        match self {
            Icon::Add => {
                painter.line_segment([c - vec2(r, 0.0), c + vec2(r, 0.0)], stroke);
                painter.line_segment([c - vec2(0.0, r), c + vec2(0.0, r)], stroke);
            }
            Icon::Remove => {
                painter.line_segment([c - vec2(r, 0.0), c + vec2(r, 0.0)], stroke);
            }
            Icon::Enable => {
                let tick = vec![
                    c + vec2(-r, 0.0),
                    c + vec2(-r * 0.3, r * 0.75),
                    c + vec2(r, -r * 0.8),
                ];
                painter.line(tick, stroke);
            }
            Icon::Disable => {
                painter.line_segment([c + vec2(-r, -r), c + vec2(r, r)], stroke);
                painter.line_segment([c + vec2(-r, r), c + vec2(r, -r)], stroke);
            }
            Icon::Comment => {
                let note = Rect::from_center_size(c, vec2(2.0 * r, 2.0 * r));
                painter.rect_filled(note, 1.0, color);
                let ink = Stroke::new(1.0, Color32::from_gray(60));
                for dy in [-0.4, 0.0, 0.4] {
                    let y = c.y + dy * r;
                    painter.line_segment(
                        [pos2(note.left() + 2.0, y), pos2(note.right() - 2.0, y)],
                        ink,
                    );
                }
            }
        }
    }
}

pub(crate) fn tool_id(salt: &str, icon: Icon) -> Id {
    table_id(salt).with(("tool", icon))
}

/// A WinBox toolbar button. Greyed out, with the reason in its tooltip, when
/// `enabled` is an `Err`.
pub(crate) fn tool(
    ui: &mut Ui,
    salt: &str,
    icon: Icon,
    tip: &str,
    enabled: Result<(), String>,
) -> egui::Response {
    let h = ui.spacing().interact_size.y;
    let (rect, _) = ui.allocate_exact_size(vec2(h * 1.5, h), Sense::hover());
    let sense = if enabled.is_ok() {
        Sense::click()
    } else {
        Sense::hover()
    };
    let resp = ui.interact(rect, tool_id(salt, icon), sense);
    let (visuals, color) = match &enabled {
        Ok(()) => (
            *ui.style().interact(&resp),
            icon.color(ui.visuals().dark_mode),
        ),
        Err(_) => (
            ui.visuals().widgets.noninteractive,
            ui.visuals().weak_text_color(),
        ),
    };
    if ui.is_rect_visible(rect) {
        ui.painter().rect(
            rect,
            visuals.corner_radius,
            visuals.weak_bg_fill,
            visuals.bg_stroke,
            egui::StrokeKind::Inside,
        );
        icon.paint(ui.painter(), rect, color);
    }
    match enabled {
        Ok(()) => resp.on_hover_text(tip),
        Err(why) => resp.on_hover_text(format!("{tip}: {why}")),
    }
}

/// Draw the table: header, rows, selection, menus and shortcuts. `reserve`
/// is the height to leave below it (for a form under the table).
pub(crate) fn show(
    ui: &mut Ui,
    salt: &str,
    reserve: f32,
    state: &mut TableState,
    columns: &[Column],
    rows: &[Row],
    mut menu: impl FnMut(&mut Ui, Menu<'_>),
) -> TableOutput {
    let mut out = TableOutput::default();
    let visible: Vec<&Row> = state.visible(rows).collect();
    let order: Vec<&str> = visible.iter().map(|r| r.key.as_str()).collect();
    state.retain(&order);

    let id = table_id(salt);
    let font = TextStyle::Body.resolve(ui.style());
    let visuals = ui.visuals().clone();
    let row_h = ui.spacing().interact_size.y;

    // With Inline Comments the comment column turns into a band above the
    // item; the cell text stays in the row, so Find still matches it.
    let note_col = columns.iter().position(|c| c.comment);
    let inline = state.inline_comments && note_col.is_some();
    let shown: Vec<usize> = (0..columns.len())
        .filter(|&i| !(inline && note_col == Some(i)))
        .filter(|&i| columns.get(i).is_some_and(|c| !state.hidden_columns.contains(c.title)))
        .collect();
    let notes: Vec<Option<String>> = visible
        .iter()
        .map(|r| {
            note_col
                .filter(|_| inline && !r.section)
                .and_then(|i| r.cells.get(i))
                .and_then(|c| note_text(c))
        })
        .collect();

    // Column widths fit the widest cell as drawn: a cell longer than
    // CELL_CHARS is cut with "…" (its tooltip has it all).
    let mut layout: Vec<(usize, f32)> = shown
        .iter()
        .filter_map(|&i| {
            let c = columns.get(i)?;
            let icon = if c.help.is_empty() { 0.0 } else { HELP_W };
            Some((i, icon + text_width(ui, c.title, &font)))
        })
        .collect();
    for r in visible.iter().filter(|r| !r.section) {
        for (i, w) in &mut layout {
            if let Some(cell) = r.cells.get(*i) {
                let icon = if note_col == Some(*i) && !cell.trim().is_empty() {
                    CELL_ICON
                } else {
                    0.0
                };
                let cw = if cell.starts_with(crate::spark::SEP) {
                    crate::spark::WIDTH
                } else {
                    text_width(ui, &shown_text(cell), &font)
                };
                *w = w.max(icon + cw);
            }
        }
    }
    for (_, w) in &mut layout {
        *w += 2.0 * CELL_PAD;
    }
    let notes_w = notes
        .iter()
        .flatten()
        .map(|n| NOTE_INDENT + text_width(ui, n, &font) + 2.0 * CELL_PAD)
        .fold(0.0, f32::max);
    let content_w = layout.iter().map(|(_, w)| w).sum::<f32>().max(notes_w);

    let status_h = row_h + ui.spacing().item_spacing.y + reserve;
    ScrollArea::both()
        .id_salt(id)
        .auto_shrink([false, false])
        .max_height((ui.available_height() - status_h).max(row_h * 3.0))
        .show(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 0.0;
            let width = content_w.max(ui.available_width());
            let (head, _) = ui.allocate_exact_size(vec2(width, row_h), Sense::hover());
            paint_cells(
                ui,
                head,
                &layout,
                columns,
                |i| columns.get(i).map_or("", |c| c.title),
                Ink {
                    text: visuals.strong_text_color(),
                    note: None,
                },
                &font,
            );
            ui.painter().hline(
                head.x_range(),
                head.bottom(),
                visuals.widgets.noninteractive.bg_stroke,
            );
            // The ⓘ of each explained column: after a left title, before a
            // right-aligned one.
            let mut x = head.left();
            for &(i, w) in &layout {
                if let Some(c) = columns.get(i).filter(|c| !c.help.is_empty()) {
                    let left = if c.right {
                        x + CELL_PAD
                    } else {
                        x + CELL_PAD + text_width(ui, c.title, &font) + 2.0
                    };
                    let at = Rect::from_min_size(pos2(left, head.top()), vec2(HELP_W, row_h));
                    let tip = format!("What is {}?", c.title);
                    let clicked = ui
                        .scope_builder(egui::UiBuilder::new().max_rect(at), |ui| {
                            crate::help::info_button(ui, id.with(("help", i)), &tip).clicked()
                        })
                        .inner;
                    if clicked {
                        out.help = Some(c.help);
                    }
                }
                x += w;
            }

            // Empty space below the rows: clears the selection on click and
            // owns the "Add / Select All / Refresh" menu. Registered before
            // the rows so a row on top of it wins the hit test.
            let top = ui.cursor().min.y;
            let bands = notes.iter().flatten().count();
            let rows_h = row_h * (visible.len() + bands) as f32;
            let body = Rect::from_min_size(
                pos2(head.left(), top),
                vec2(width, rows_h.max(ui.available_height())),
            );
            let bg = ui.interact(body, id, Sense::click());
            let row_sense = if state.reorder {
                Sense::click_and_drag()
            } else {
                Sense::click()
            };
            // Where each item is, for a drop; and the item being dragged.
            let mut placed: Vec<(&str, Rect)> = Vec::with_capacity(visible.len());
            let mut dragging: Option<(&str, bool)> = None;
            // The selection the row menu acts on: once per frame, not once
            // per row (that was O(rows²) every frame).
            let sel = state.selection(rows);
            // Only the rows in view are drawn and take input: a 10 000-row
            // list costs what one screenful does. The others only take
            // their place (and a dragged row keeps its input off screen).
            let clip = ui.clip_rect();
            let dragged = ui.ctx().dragged_id();
            let mut y = top;

            for (i, (row, note)) in visible.iter().zip(&notes).enumerate() {
                // One item: the comment band (if any) and the row under it.
                let item_h = if note.is_some() { 2.0 * row_h } else { row_h };
                let item = Rect::from_min_size(pos2(head.left(), y), vec2(width, item_h));
                y += item_h;
                placed.push((row.key.as_str(), item));
                let rid = row_id(salt, &row.key);
                if !clip.intersects(item) && dragged != Some(rid) {
                    continue;
                }
                let resp = ui.interact(item, rid, row_sense);
                if resp.dragged() || resp.drag_stopped() {
                    dragging = Some((row.key.as_str(), resp.drag_stopped()));
                }
                let selected = state.is_selected(&row.key);
                let fill = if selected {
                    Some(visuals.selection.bg_fill)
                } else if resp.hovered() {
                    Some(visuals.widgets.hovered.weak_bg_fill)
                } else if i % 2 == 1 {
                    Some(visuals.faint_bg_color)
                } else {
                    None
                };
                if let Some(fill) = fill {
                    ui.painter().rect_filled(item, 0.0, fill);
                }
                let rect = Rect::from_min_max(pos2(item.left(), item.bottom() - row_h), item.max);
                let band = Rect::from_min_max(item.min, pos2(item.right(), rect.top()));
                let style = comment_style(&visuals, row.dimmed, selected);
                if let Some(note) = note {
                    paint_note(ui, band, note, &style, &font);
                }
                let color = match (selected, row.dimmed, row.tint) {
                    (true, _, _) => visuals.selection.stroke.color,
                    (false, true, _) => visuals.weak_text_color(),
                    (false, false, Some(tint)) => tint,
                    (false, false, None) => visuals.text_color(),
                };
                if row.section {
                    let title = note_col
                        .and_then(|c| row.cells.get(c))
                        .or_else(|| row.cells.iter().find(|c| !c.trim().is_empty()))
                        .map(String::as_str)
                        .unwrap_or("");
                    paint_section(ui, rect, title, &style, selected, &font);
                } else {
                    paint_cells(
                        ui,
                        rect,
                        &layout,
                        columns,
                        |c| row.cells.get(c).map_or("", String::as_str),
                        Ink {
                            text: color,
                            note: note_col.filter(|_| !inline).map(|c| (c, &style)),
                        },
                        &font,
                    );
                }
                // A cut cell: the whole value in the tooltip.
                let resp = match cut_under_pointer(ui, &resp, rect, &layout, row) {
                    Some(full) => resp.on_hover_text(full),
                    None => resp,
                };

                if resp.hovered()
                    && !row.section
                    && let Some((col, n)) = chip_under_pointer(ui, rect, &layout, columns, row, &font)
                {
                    out.chip = Some((row.key.clone(), col, n));
                    out.chip_clicked = resp.clicked();
                }
                if state.open.contains(&row.key) && open_mark(ui, salt, &row.key, rect, selected) {
                    out.opened = Some(row.key.clone());
                }
                if resp.clicked() {
                    out.clicked = Some(row.key.clone());
                    let m = ui.input(|i| i.modifiers);
                    state.click(&row.key, m.command, m.shift, &order);
                    ui.memory_mut(|mem| mem.request_focus(id));
                }
                if resp.secondary_clicked() {
                    // WinBox: right click on an unselected row makes it the
                    // selection; on a selected one it keeps the selection.
                    if !selected {
                        state.select_only(&row.key);
                    }
                    ui.memory_mut(|mem| mem.request_focus(id));
                }
                if resp.double_clicked() {
                    let on_note = note.is_some()
                        && ui
                            .input(|i| i.pointer.latest_pos())
                            .is_some_and(|p| band.contains(p));
                    if on_note {
                        out.comment = Some(row.key.clone());
                    } else {
                        out.opened = Some(row.key.clone());
                    }
                }
                let inline_comments = &mut state.inline_comments;
                resp.context_menu(|ui| {
                    menu(ui, Menu::Rows(&sel));
                    inline_toggle(ui, note_col.is_some(), inline_comments);
                });
            }
            if let Some((key, done)) = dragging {
                let target = drop_target(ui, &placed, key);
                if done {
                    if let Some(t) = target {
                        out.dropped = Some((key.to_owned(), t.map(str::to_owned)));
                    }
                } else if let Some(t) = target {
                    // The insertion line where the row would land.
                    let y = match t {
                        Some(k) => placed.iter().find(|(p, _)| *p == k).map(|(_, r)| r.top()),
                        None => placed.last().map(|(_, r)| r.bottom()),
                    };
                    if let Some(y) = y {
                        ui.painter().hline(
                            head.x_range(),
                            y,
                            Stroke::new(2.0, visuals.selection.bg_fill),
                        );
                    }
                }
            }
            ui.advance_cursor_after_rect(body);

            // Only a real click: the table holds the focus under this id,
            // and egui turns Enter/Space on a focused widget into a click.
            if bg.clicked_by(egui::PointerButton::Primary) || bg.secondary_clicked() {
                state.clear();
                ui.memory_mut(|mem| mem.request_focus(id));
            }
            let inline_comments = &mut state.inline_comments;
            bg.context_menu(|ui| {
                menu(ui, Menu::Empty);
                inline_toggle(ui, note_col.is_some(), inline_comments);
            });
        });

    keyboard(ui, salt, state, &order, rows, &mut out);

    let total = rows.len();
    let shown = visible.len();
    let picked = state.selected.len();
    let mut status = if shown == total {
        format!("{total} items")
    } else {
        format!("{shown} of {total} items")
    };
    if picked > 0 {
        status.push_str(&format!(" ({picked} selected)"));
    }
    if total > MAX_ROWS {
        status.push_str(&format!(", only the first {MAX_ROWS} are listed"));
    }
    ui.weak(status);
    out
}

/// Width of the open-window mark, and of the strip a click on it takes.
const MARK_W: f32 = 3.0;
const MARK_HIT: f32 = 8.0;

/// The mark of a row whose window is open. Returns whether it was clicked.
fn open_mark(ui: &mut Ui, salt: &str, key: &str, row: Rect, selected: bool) -> bool {
    let v = ui.visuals();
    let color = if selected {
        v.selection.stroke.color
    } else {
        v.selection.bg_fill
    };
    let bar = Rect::from_min_size(row.min, vec2(MARK_W, row.height())).shrink2(vec2(0.0, 2.0));
    ui.painter().rect_filled(bar, 1.0, color);
    let hit = Rect::from_min_size(row.min, vec2(MARK_HIT, row.height()));
    ui.interact(hit, mark_id(salt, key), Sense::click())
        .on_hover_text("Its window is open: click to bring it to the front")
        .clicked()
}

/// Id of the open-window mark of row `key` (the tests click it).
pub(crate) fn mark_id(salt: &str, key: &str) -> Id {
    row_id(salt, key).with("open-mark")
}

/// Where a dragged row lands: `Some(Some(k))` above row `k`, `Some(None)`
/// after the last row, `None` when it would not move (its own place).
fn drop_target<'a>(ui: &Ui, placed: &[(&'a str, Rect)], key: &str) -> Option<Option<&'a str>> {
    let y = ui.input(|i| i.pointer.latest_pos())?.y;
    let at = placed.iter().position(|(_, r)| y < r.center().y);
    let from = placed.iter().position(|(k, _)| *k == key)?;
    match at {
        // Above itself or above the row right after it: same place.
        Some(i) if i == from || i == from + 1 => None,
        Some(i) => placed.get(i).map(|(k, _)| Some(*k)),
        None if from + 1 == placed.len() => None,
        None => Some(None),
    }
}

/// A section header row: a band in the comment colours with the title in
/// bold, across the whole table.
fn paint_section(
    ui: &Ui,
    rect: Rect,
    title: &str,
    style: &CommentStyle,
    selected: bool,
    font: &egui::FontId,
) {
    let painter = ui.painter_at(rect);
    if let (Some(wash), false) = (style.wash, selected) {
        painter.rect_filled(rect, 0.0, wash);
    }
    painter.rect_filled(
        Rect::from_min_size(rect.min, vec2(4.0, rect.height())),
        0.0,
        style.accent,
    );
    let text = egui::RichText::new(title).strong();
    let galley = egui::WidgetText::from(text).into_galley(
        ui,
        Some(egui::TextWrapMode::Truncate),
        rect.width() - 2.0 * CELL_PAD - 10.0,
        egui::FontSelection::FontId(font.clone()),
    );
    painter.galley(
        pos2(
            rect.left() + 10.0 + CELL_PAD,
            rect.center().y - galley.size().y / 2.0,
        ),
        galley,
        style.ink,
    );
}

/// The "Inline Comments" entry closing every context menu of a table that
/// has a comment column.
fn inline_toggle(ui: &mut Ui, has_comments: bool, on: &mut bool) {
    if !has_comments {
        return;
    }
    ui.separator();
    if ui.checkbox(on, "Inline Comments").clicked() {
        ui.close();
    }
}

/// A comment as one line for the band; `None` when there is nothing to show.
fn note_text(cell: &str) -> Option<String> {
    let flat = cell.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.is_empty() {
        return None;
    }
    if flat.chars().count() <= NOTE_CHARS {
        return Some(flat);
    }
    let mut cut: String = flat.chars().take(NOTE_CHARS).collect();
    cut.push('…');
    Some(cut)
}

/// Colours of an item's comment, the same in the inline band and in the
/// Comment column: `ink` for the text, `accent` for the bar and the
/// speech-bubble icon, `wash` behind the band (`None` on a selected item,
/// which keeps the selection fill).
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct CommentStyle {
    pub ink: Color32,
    pub accent: Color32,
    pub wash: Option<Color32>,
}

/// The one place comment colours are decided. An enabled item gets a calm
/// blue that reads on both themes; a disabled one (the row's `dimmed`, the
/// flag X greying the whole row) gets dark grey, so the comment fades with
/// its item. On a selected row everything takes the selection's text
/// colour, legible on the selection fill in both themes.
pub(crate) fn comment_style(v: &Visuals, disabled: bool, selected: bool) -> CommentStyle {
    let (ink, accent) = match (disabled, v.dark_mode) {
        (false, true) => (
            Color32::from_rgb(170, 205, 250),
            Color32::from_rgb(105, 160, 235),
        ),
        (false, false) => (
            Color32::from_rgb(25, 80, 160),
            Color32::from_rgb(35, 105, 200),
        ),
        (true, true) => (Color32::from_gray(125), Color32::from_gray(100)),
        (true, false) => (Color32::from_gray(85), Color32::from_gray(110)),
    };
    if selected {
        let ink = v.selection.stroke.color;
        return CommentStyle {
            ink,
            accent: ink,
            wash: None,
        };
    }
    let wash = accent.gamma_multiply(if v.dark_mode { 0.16 } else { 0.10 });
    CommentStyle {
        ink,
        accent,
        wash: Some(wash),
    }
}

/// Speech bubble centred at `c`: a rounded body with a tail at its lower left.
fn paint_bubble(painter: &egui::Painter, c: egui::Pos2, color: Color32) {
    let body = Rect::from_center_size(c, vec2(12.0, 8.0));
    painter.rect_filled(body, 2.5, color);
    painter.add(egui::Shape::convex_polygon(
        vec![
            pos2(body.left() + 2.0, body.bottom() - 0.5),
            pos2(body.left() + 6.0, body.bottom() - 0.5),
            pos2(body.left() + 1.5, body.bottom() + 3.5),
        ],
        color,
        Stroke::NONE,
    ));
}

/// A comment in italics, its left edge at `x`, centred on `y`.
fn paint_comment_text(
    painter: &egui::Painter,
    x: f32,
    y: f32,
    text: &str,
    ink: Color32,
    font: &egui::FontId,
) {
    let job = egui::text::LayoutJob::single_section(
        text.to_owned(),
        egui::TextFormat {
            font_id: font.clone(),
            color: ink,
            italics: true,
            ..Default::default()
        },
    );
    let galley = painter.layout_job(job);
    let at = pos2(x, y - galley.size().y / 2.0);
    painter.galley(at, galley, ink);
}

/// The band above a commented item: a faint wash, a bar and a
/// speech-bubble icon at the left, and the comment in italics.
fn paint_note(ui: &Ui, band: Rect, text: &str, style: &CommentStyle, font: &egui::FontId) {
    let painter = ui.painter();
    if let Some(wash) = style.wash {
        painter.rect_filled(band, 0.0, wash);
    }
    let bar = Rect::from_min_size(band.min, vec2(3.0, band.height()));
    painter.rect_filled(bar, 0.0, style.accent);
    paint_bubble(
        painter,
        pos2(band.left() + 16.0, band.center().y - 1.0),
        style.accent,
    );
    paint_comment_text(
        painter,
        band.left() + NOTE_INDENT,
        band.center().y,
        text,
        style.ink,
        font,
    );
}

/// Shortcuts act only while the table has keyboard focus (it gets it from a
/// click on it), so typing in a form or the find field never removes rows.
fn keyboard(
    ui: &mut Ui,
    salt: &str,
    state: &mut TableState,
    order: &[&str],
    rows: &[Row],
    out: &mut TableOutput,
) {
    let id = table_id(salt);
    if !ui.memory(|m| m.has_focus(id)) {
        return;
    }
    ui.memory_mut(|m| {
        m.set_focus_lock_filter(
            id,
            EventFilter {
                vertical_arrows: true,
                ..EventFilter::default()
            },
        );
    });
    let (all, find, up, down, shift) = ui.input_mut(|i| {
        (
            i.consume_key(Modifiers::COMMAND, Key::A),
            i.consume_key(Modifiers::COMMAND, Key::F),
            i.consume_key(Modifiers::NONE, Key::ArrowUp)
                || i.consume_key(Modifiers::SHIFT, Key::ArrowUp),
            i.consume_key(Modifiers::NONE, Key::ArrowDown)
                || i.consume_key(Modifiers::SHIFT, Key::ArrowDown),
            i.modifiers.shift,
        )
    });
    if all {
        state.select_all(rows);
    }
    if find {
        ui.memory_mut(|m| m.request_focus(filter_id(salt)));
    }
    if up || down {
        state.step(down, shift, order);
    }
    out.shortcut = ui.input_mut(|i| {
        [
            (Modifiers::NONE, Key::Delete, Shortcut::Remove),
            (Modifiers::COMMAND, Key::E, Shortcut::Enable),
            (Modifiers::COMMAND, Key::D, Shortcut::Disable),
            (Modifiers::COMMAND, Key::M, Shortcut::Comment),
            (Modifiers::NONE, Key::Enter, Shortcut::Open),
        ]
        .into_iter()
        .find(|(m, k, _)| i.consume_key(*m, *k))
        .map(|(_, _, s)| s)
    });
}

/// A cell as the table draws it: on one line, its text cut at
/// [`CELL_CHARS`] with "…" (the chips after it stay).
pub(crate) fn shown_text(cell: &str) -> Cow<'_, str> {
    let (text, chips) = match cell.find(crate::chip::SEP) {
        Some(at) => (cell.get(..at).unwrap_or(cell), cell.get(at..).unwrap_or("")),
        None => (cell, ""),
    };
    let long = text.char_indices().nth(CELL_CHARS).is_some();
    if !long && !text.contains(['\n', '\r', '\t']) {
        return Cow::Borrowed(cell);
    }
    let mut out: String = text
        .chars()
        .take(if long { CELL_CHARS - 1 } else { CELL_CHARS })
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if long {
        out.push('…');
    }
    out.push_str(chips);
    Cow::Owned(out)
}

/// The whole text of the cut cell under the pointer, for its tooltip.
fn cut_under_pointer(
    ui: &Ui,
    resp: &egui::Response,
    rect: Rect,
    layout: &[(usize, f32)],
    row: &Row,
) -> Option<String> {
    if !resp.hovered() || row.section {
        return None;
    }
    let x = ui.input(|i| i.pointer.latest_pos())?.x;
    let mut left = rect.left();
    let col = layout.iter().find_map(|&(i, w)| {
        let hit = x >= left && x < left + w;
        left += w;
        hit.then_some(i)
    })?;
    let cell = row.cells.get(col)?;
    if let Some(tip) = crate::spark::tip(cell) {
        return Some(tip.to_owned());
    }
    let (text, _) = crate::chip::split(cell);
    // Only a cut cell has a tooltip.
    text.char_indices().nth(CELL_CHARS)?;
    let mut tip: String = text.chars().take(TIP_CHARS).collect();
    if text.char_indices().nth(TIP_CHARS).is_some() {
        tip.push('…');
    }
    Some(tip)
}

/// The chip under the pointer in a row: (column, chip index). Chips follow
/// the text of a left-aligned cell, as `paint_cells` draws them.
fn chip_under_pointer(
    ui: &Ui,
    rect: Rect,
    layout: &[(usize, f32)],
    columns: &[Column],
    row: &Row,
    font: &egui::FontId,
) -> Option<(usize, usize)> {
    let p = ui.input(|i| i.pointer.latest_pos())?;
    let mut left = rect.left();
    let (col, cell_left) = layout.iter().find_map(|&(i, w)| {
        let at = left;
        left += w;
        (p.x >= at && p.x < at + w).then_some((i, at))
    })?;
    if columns.get(col).is_some_and(|c| c.right) {
        return None;
    }
    let shown = shown_text(row.cells.get(col)?);
    let (text, chips) = crate::chip::split(&shown);
    let size = crate::chip::cell_size(font);
    let mut x = cell_left
        + CELL_PAD
        + ui.painter()
            .layout_no_wrap(text.to_owned(), font.clone(), egui::Color32::PLACEHOLDER)
            .size()
            .x;
    for (n, (_, label)) in chips.iter().enumerate() {
        let w = crate::chip::cell_chip_width(ui.painter(), label, size);
        if p.x >= x && p.x < x + w {
            return Some((col, n));
        }
        x += w;
    }
    None
}

fn text_width(ui: &Ui, text: &str, font: &egui::FontId) -> f32 {
    let (icon, text) = split_icon(text);
    // A cell may carry chips after its text (`chip::cell`).
    let (text, chips) = crate::chip::split(text);
    (if icon.is_some() { CELL_ICON } else { 0.0 }) + ui.painter()
        .layout_no_wrap(text.to_owned(), font.clone(), egui::Color32::PLACEHOLDER)
        .size()
        .x
        + crate::chip::cell_chips_width(ui.painter(), &chips, crate::chip::cell_size(font))
}

/// Cells may begin with an icon from the project's Phosphor font.
fn split_icon(text: &str) -> (Option<char>, &str) {
    let Some(c) = text.chars().next() else { return (None, text) };
    if ('\u{e000}'..='\u{f8ff}').contains(&c) {
        (Some(c), text.get(c.len_utf8()..).unwrap_or("").trim_start())
    } else {
        (None, text)
    }
}

/// Colours of one line of cells: `text` for plain cells, `note` the Comment
/// column and its colours (icon and italics, like the inline band).
struct Ink<'s> {
    text: Color32,
    note: Option<(usize, &'s CommentStyle)>,
}

/// Paint one line of cells; `layout` is (column index, width) of the
/// columns shown, `text` the cell of a column index.
fn paint_cells<'a>(
    ui: &Ui,
    rect: Rect,
    layout: &[(usize, f32)],
    columns: &[Column],
    text: impl Fn(usize) -> &'a str,
    ink: Ink<'_>,
    font: &egui::FontId,
) {
    let color = ink.text;
    let mut x = rect.left();
    for &(i, w) in layout {
        if let Some((_, style)) = ink.note.filter(|(c, _)| *c == i) {
            let cell = shown_text(text(i));
            let cell = cell.as_ref();
            if !cell.trim().is_empty() {
                let painter = ui.painter();
                let y = rect.center().y;
                paint_bubble(painter, pos2(x + CELL_PAD + 6.0, y - 1.0), style.accent);
                paint_comment_text(painter, x + CELL_PAD + CELL_ICON, y, cell, style.ink, font);
            }
            x += w;
            continue;
        }
        // G4.5: a mini graph instead of text (`spark.rs`).
        if text(i).starts_with(crate::spark::SEP) {
            let cell = Rect::from_min_size(pos2(x, rect.top()), vec2(w, rect.height()));
            crate::spark::paint(ui.painter(), cell, text(i));
            x += w;
            continue;
        }
        let right = columns.get(i).is_some_and(|c| c.right);
        let (anchor, at) = if right {
            (
                Align2::RIGHT_CENTER,
                pos2(x + w - CELL_PAD, rect.center().y),
            )
        } else {
            (Align2::LEFT_CENTER, pos2(x + CELL_PAD, rect.center().y))
        };
        let shown = shown_text(text(i));
        let (icon, shown) = split_icon(&shown);
        let (cell, chips) = crate::chip::split(shown);
        // A weak column greys plain text only (a selected, dimmed or
        // tinted row keeps its colour).
        let weak = columns.get(i).is_some_and(|c| c.weak) && color == ui.visuals().text_color();
        let ink = if weak {
            ui.visuals().weak_text_color()
        } else {
            color
        };
        let at = if let Some(icon) = icon {
            let icon_rect = Rect::from_min_size(pos2(x + CELL_PAD, rect.top()), vec2(CELL_ICON, rect.height()));
            crate::icons::paint(ui, icon_rect, &icon.to_string(), font.size, ink);
            pos2(at.x + CELL_ICON, at.y)
        } else { at };
        let drawn = ui.painter().text(at, anchor, cell, font.clone(), ink);
        if !chips.is_empty() {
            crate::chip::paint_cell_chips(
                ui.painter(),
                ui.visuals(),
                drawn.right(),
                rect.center().y,
                rect.height(),
                &chips,
                crate::chip::cell_size(font),
            );
        }
        x += w;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ORDER: [&str; 5] = ["a", "b", "c", "d", "e"];

    fn sel(s: &TableState) -> Vec<&str> {
        s.selected.iter().map(String::as_str).collect()
    }

    #[test]
    fn click_ctrl_shift_select_like_winbox() {
        let mut s = TableState::default();
        s.click("b", false, false, &ORDER);
        assert_eq!(sel(&s), ["b"]);
        s.click("d", true, false, &ORDER);
        assert_eq!(sel(&s), ["b", "d"]);
        s.click("b", true, false, &ORDER);
        assert_eq!(sel(&s), ["d"], "ctrl+click toggles off");
        // Anchor is the last ctrl click ("b"), so shift+click on "e" → b..=e.
        s.click("e", false, true, &ORDER);
        assert_eq!(sel(&s), ["b", "c", "d", "e"]);
        s.click("a", false, false, &ORDER);
        s.click("b", false, true, &ORDER);
        assert_eq!(sel(&s), ["a", "b"]);
        s.click("d", true, false, &ORDER);
        s.click("e", true, true, &ORDER);
        assert_eq!(sel(&s), ["a", "b", "d", "e"], "ctrl+shift adds a range");
        s.clear();
        assert!(sel(&s).is_empty());
        // Shift with no anchor behaves as a plain click.
        s.click("c", false, true, &ORDER);
        assert_eq!(sel(&s), ["c"]);
    }

    /// A window opened to show one item: the selection waits for its rows.
    #[test]
    fn reveal_waits_for_the_rows() {
        let mut s = TableState {
            filter: "zzz".into(),
            ..TableState::default()
        };
        s.reveal("b");
        assert!(s.filter.is_empty());
        s.retain(&[]);
        assert!(s.is_selected("b"), "no rows yet: kept");
        s.retain(&ORDER);
        assert!(s.is_selected("b"));
        s.retain(&[]);
        assert!(!s.is_selected("b"), "rows came: the usual rule again");
    }

    #[test]
    fn arrows_move_and_extend() {
        let mut s = TableState::default();
        s.step(true, false, &ORDER);
        assert_eq!(sel(&s), ["a"]);
        s.step(true, false, &ORDER);
        s.step(true, true, &ORDER);
        assert_eq!(sel(&s), ["b", "c"]);
        s.select_only("a");
        s.step(false, false, &ORDER);
        assert_eq!(sel(&s), ["a"], "stays at the top");
        s.step(false, false, &[]);
    }

    fn big(n: usize, comment: &str) -> Vec<Row> {
        (0..n)
            .map(|i| Row {
                key: format!("k{i}"),
                cells: vec![format!("item {i}"), comment.to_owned()],
                dimmed: false,
                section: false,
                tint: None,
            })
            .collect()
    }

    /// One frame of `rows` in a 1400×900 window; the texts it painted.
    fn frame(state: &mut TableState, rows: &[Row]) -> Vec<String> {
        let ctx = egui::Context::default();
        let raw = egui::RawInput {
            screen_rect: Some(Rect::from_min_size(pos2(0.0, 0.0), vec2(1400.0, 900.0))),
            ..Default::default()
        };
        let cols = [col("Name"), comment()];
        let mut out = ctx.run_ui(raw, |ui| {
            show(ui, "t", 0.0, state, &cols, rows, |_, _| {});
        });
        out.textures_delta.clear();
        fn walk(shape: &egui::Shape, out: &mut Vec<String>) {
            match shape {
                egui::Shape::Text(t) => out.push(t.galley.text().to_owned()),
                egui::Shape::Vec(v) => v.iter().for_each(|s| walk(s, out)),
                _ => {}
            }
        }
        let mut texts = Vec::new();
        for s in &out.shapes {
            walk(&s.shape, &mut texts);
        }
        texts
    }

    #[test]
    fn only_the_rows_in_view_are_drawn() {
        let rows = big(MAX_ROWS, "note");
        let mut s = TableState::default();
        s.select_all(&rows);
        let texts = frame(&mut s, &rows);
        assert!(texts.iter().any(|t| t == "item 0"));
        assert!(!texts.iter().any(|t| t == "item 9999"), "off screen");
        assert!(texts.len() < 500, "{} texts painted", texts.len());
        assert_eq!(s.selection(&rows).len(), MAX_ROWS, "selection kept");
        assert!(s.selection(&rows).contains("k9999"));
    }

    #[test]
    fn a_long_cell_is_cut_with_an_ellipsis() {
        let huge = "x".repeat(100_000);
        let rows = big(3, &huge);
        let texts = frame(&mut TableState::default(), &rows);
        let longest = texts.iter().map(|t| t.chars().count()).max().unwrap_or(0);
        assert!(longest <= CELL_CHARS, "a cell of {longest} chars drawn");
        assert!(texts.iter().any(|t| t.ends_with('…')));
        assert_eq!(shown_text("short"), "short");
        assert_eq!(shown_text("a\nb"), "a b", "one line per row");
        let chipped = crate::chip::cell(&"y".repeat(500), &[("LAN", crate::chip::Kind::Blue)]);
        let shown = shown_text(&chipped);
        let (text, chips) = crate::chip::split(&shown);
        assert_eq!(text.chars().count(), CELL_CHARS);
        assert_eq!(chips.len(), 1, "the chips stay");
    }

    #[test]
    fn filter_hides_and_drops_selection() {
        let rows: Vec<Row> = ["ether1", "ether2", "vlan100"]
            .iter()
            .map(|n| Row {
                key: (*n).to_owned(),
                cells: vec![(*n).to_owned()],
                dimmed: false,
                section: false,
                tint: None,
            })
            .collect();
        let mut s = TableState::default();
        s.select_all(&rows);
        assert_eq!(s.selection(&rows).len(), 3);
        s.filter = " VLAN ".into();
        assert_eq!(s.selection(&rows).as_slice(), ["vlan100"]);
        let order: Vec<&str> = s.visible(&rows).map(|r| r.key.as_str()).collect();
        s.retain(&order);
        s.filter.clear();
        assert_eq!(s.selection(&rows).as_slice(), ["vlan100"]);
    }
}
