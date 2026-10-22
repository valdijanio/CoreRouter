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
//! clicking, double clicking and right clicking it act on the item.

use std::collections::BTreeSet;

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

pub(crate) struct Column {
    pub title: &'static str,
    /// Numbers read better right-aligned.
    pub right: bool,
    /// The item's comment: drawn above the row with Inline Comments on.
    pub comment: bool,
}

pub(crate) const fn col(title: &'static str) -> Column {
    Column {
        title,
        right: false,
        comment: false,
    }
}

pub(crate) const fn num(title: &'static str) -> Column {
    Column {
        title,
        right: true,
        comment: false,
    }
}

/// The "Comment" column, which Inline Comments turns into a band.
pub(crate) const fn comment() -> Column {
    Column {
        title: "Comment",
        right: false,
        comment: true,
    }
}

pub(crate) struct Row {
    /// Stable identity (interface name, address id …): selection survives
    /// refreshes and reordering because it is kept by key, not by index.
    pub key: String,
    pub cells: Vec<String>,
    /// Drawn greyed out, like a disabled item in WinBox.
    pub dimmed: bool,
}

impl Row {
    fn matches(&self, needle: &str) -> bool {
        needle.is_empty() || self.cells.iter().any(|c| c.to_lowercase().contains(needle))
    }
}

/// What a context menu is about.
pub(crate) enum Menu<'a> {
    /// Right click on a row: act on these selected keys (display order).
    Rows(&'a [String]),
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
    /// Key of the item whose inline comment was double-clicked: edit the
    /// comment (a window without a comment dialog treats it as `opened`).
    pub comment: Option<String>,
    pub shortcut: Option<Shortcut>,
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
}

impl TableState {
    pub fn is_selected(&self, key: &str) -> bool {
        self.selected.contains(key)
    }

    /// Selected keys in display order.
    pub fn selection(&self, rows: &[Row]) -> Vec<String> {
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

    pub fn select_all(&mut self, rows: &[Row]) {
        self.selected = self.visible(rows).map(|r| r.key.clone()).collect();
    }

    pub fn clear(&mut self) {
        self.selected.clear();
        self.anchor = None;
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
        self.selected.retain(|k| order.contains(&k.as_str()));
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
        .collect();
    let notes: Vec<Option<String>> = visible
        .iter()
        .map(|r| {
            note_col
                .filter(|_| inline)
                .and_then(|i| r.cells.get(i))
                .and_then(|c| note_text(c))
        })
        .collect();

    // Column widths fit the widest cell, so no text is ever cut.
    let mut layout: Vec<(usize, f32)> = shown
        .iter()
        .filter_map(|&i| Some((i, text_width(ui, columns.get(i)?.title, &font))))
        .collect();
    for r in &visible {
        for (i, w) in &mut layout {
            if let Some(cell) = r.cells.get(*i) {
                *w = w.max(text_width(ui, cell, &font));
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
                visuals.strong_text_color(),
                &font,
            );
            ui.painter().hline(
                head.x_range(),
                head.bottom(),
                visuals.widgets.noninteractive.bg_stroke,
            );

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

            for (i, (row, note)) in visible.iter().zip(&notes).enumerate() {
                // One item: the comment band (if any) and the row under it.
                let item_h = if note.is_some() { 2.0 * row_h } else { row_h };
                let (item, _) = ui.allocate_exact_size(vec2(width, item_h), Sense::hover());
                let resp = ui.interact(item, row_id(salt, &row.key), Sense::click());
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
                if let Some(note) = note {
                    paint_note(ui, band, note, selected, row.dimmed, &font);
                }
                let color = match (selected, row.dimmed) {
                    (true, _) => visuals.selection.stroke.color,
                    (false, true) => visuals.weak_text_color(),
                    (false, false) => visuals.text_color(),
                };
                paint_cells(
                    ui,
                    rect,
                    &layout,
                    columns,
                    |c| row.cells.get(c).map_or("", String::as_str),
                    color,
                    &font,
                );

                if resp.clicked() {
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
                let sel = state.selection(rows);
                let inline_comments = &mut state.inline_comments;
                resp.context_menu(|ui| {
                    menu(ui, Menu::Rows(&sel));
                    inline_toggle(ui, note_col.is_some(), inline_comments);
                });
            }
            let rest = (body.bottom() - ui.cursor().min.y).max(0.0);
            ui.allocate_space(vec2(width, rest));

            if bg.clicked() || bg.secondary_clicked() {
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

/// Accent of the comment band: a calm blue that reads on both themes.
fn note_accent(v: &Visuals) -> Color32 {
    if v.dark_mode {
        Color32::from_rgb(105, 160, 235)
    } else {
        Color32::from_rgb(35, 105, 200)
    }
}

/// The band above a commented item: a faint accent wash, an accent bar and
/// a speech-bubble icon at the left, and the comment in italics.
fn paint_note(ui: &Ui, band: Rect, text: &str, selected: bool, dimmed: bool, font: &egui::FontId) {
    let v = ui.visuals();
    let painter = ui.painter();
    let accent = note_accent(v);
    let ink = match (selected, v.dark_mode) {
        (true, _) => v.selection.stroke.color,
        (false, true) => Color32::from_rgb(170, 205, 250),
        (false, false) => Color32::from_rgb(25, 80, 160),
    };
    let ink = if dimmed && !selected {
        ink.gamma_multiply(0.6)
    } else {
        ink
    };
    if !selected {
        let wash = accent.gamma_multiply(if v.dark_mode { 0.16 } else { 0.10 });
        painter.rect_filled(band, 0.0, wash);
    }
    let bar = Rect::from_min_size(band.min, vec2(3.0, band.height()));
    painter.rect_filled(bar, 0.0, if selected { ink } else { accent });

    // Speech bubble: a rounded body with a tail at its lower left.
    let c = pos2(band.left() + 16.0, band.center().y - 1.0);
    let body = Rect::from_center_size(c, vec2(12.0, 8.0));
    let icon = if selected { ink } else { accent };
    painter.rect_filled(body, 2.5, icon);
    painter.add(egui::Shape::convex_polygon(
        vec![
            pos2(body.left() + 2.0, body.bottom() - 0.5),
            pos2(body.left() + 6.0, body.bottom() - 0.5),
            pos2(body.left() + 1.5, body.bottom() + 3.5),
        ],
        icon,
        Stroke::NONE,
    ));

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
    let at = pos2(
        band.left() + NOTE_INDENT,
        band.center().y - galley.size().y / 2.0,
    );
    painter.galley(at, galley, ink);
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

fn text_width(ui: &Ui, text: &str, font: &egui::FontId) -> f32 {
    ui.painter()
        .layout_no_wrap(text.to_owned(), font.clone(), egui::Color32::PLACEHOLDER)
        .size()
        .x
}

/// Paint one line of cells; `layout` is (column index, width) of the
/// columns shown, `text` the cell of a column index.
fn paint_cells<'a>(
    ui: &Ui,
    rect: Rect,
    layout: &[(usize, f32)],
    columns: &[Column],
    text: impl Fn(usize) -> &'a str,
    color: egui::Color32,
    font: &egui::FontId,
) {
    let mut x = rect.left();
    for &(i, w) in layout {
        let right = columns.get(i).is_some_and(|c| c.right);
        let (anchor, at) = if right {
            (
                Align2::RIGHT_CENTER,
                pos2(x + w - CELL_PAD, rect.center().y),
            )
        } else {
            (Align2::LEFT_CENTER, pos2(x + CELL_PAD, rect.center().y))
        };
        ui.painter().text(at, anchor, text(i), font.clone(), color);
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

    #[test]
    fn filter_hides_and_drops_selection() {
        let rows: Vec<Row> = ["ether1", "ether2", "vlan100"]
            .iter()
            .map(|n| Row {
                key: (*n).to_owned(),
                cells: vec![(*n).to_owned()],
                dimmed: false,
            })
            .collect();
        let mut s = TableState::default();
        s.select_all(&rows);
        assert_eq!(s.selection(&rows).len(), 3);
        s.filter = " VLAN ".into();
        assert_eq!(s.selection(&rows), ["vlan100"]);
        let order: Vec<&str> = s.visible(&rows).map(|r| r.key.as_str()).collect();
        s.retain(&order);
        s.filter.clear();
        assert_eq!(s.selection(&rows), ["vlan100"]);
    }
}
