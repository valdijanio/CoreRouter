//! Floating windows (WinBox MDI style). Every internal window is drawn by
//! [`Floats::show`], which adds maximize/restore to egui's own title bar:
//! the collapse ▼, the drag to move and the close ✕ stay egui's; a button
//! next to the ✕, a double click on the title and the title's context menu
//! toggle between the work area and the rectangle the window had before.
//!
//! The keyboard of a window lives here too ([`Floats::keys`]): Enter,
//! Ctrl+Enter and Esc reach only the window in front, and none of them
//! while a popup (combo box, menu) is open, so they close the popup instead.
//!
//! Windows form a hierarchy, like owned windows in Windows or WinBox's
//! dialogs over their list ([`Floats::show`] with a parent): a child opens
//! offset over its parent, always stays above it (raising the parent
//! raises its children with it), and closes with it; closing a parent whose
//! children have edits not applied asks first ([`Floats::close_family`]).
//! Asking again for an open window brings it to the front with a short
//! flash of its border ([`Floats::raise`]). Ctrl+Tab / Ctrl+F6 (and with
//! Shift, backwards) go through the windows. The keyboard talks to the
//! *active* window (the one last clicked, raised or opened), which may sit
//! under its own children, as the owner of an owned window does.
//!
//! The state is UI-local: nothing here goes through the engine.

use egui::collapsing_header::CollapsingState;
use egui::{
    Atom, Context, Id, IdMap, IdSalt, IdSet, Key, LayerId, Modifiers, Order, Pos2, Rect, Response,
    Sense, Stroke, StrokeKind, TextEdit, TextStyle, Ui, UiBuilder, Vec2, Window, pos2,
};

/// Placement of the floating windows (UI-local state only).
#[derive(Default)]
pub(crate) struct Floats {
    /// The work area of the last frame (where a window maximizes to).
    pub(crate) area: Option<Rect>,
    /// Maximized windows and the rectangle each had before.
    maximized: IdMap<Rect>,
    /// Windows being put back where they were.
    restore: IdMap<Restore>,
    /// Last rectangle of each window while fully expanded (a collapsed
    /// window is only its title bar, which is not what to restore).
    expanded: IdMap<Rect>,
    /// How the keyboard stood when this frame began, before any widget
    /// reacted to this frame's keys.
    start: Start,
    /// Windows drawn this frame and the last one. egui keeps closed
    /// windows in its layer order: only these can be in front.
    shown: IdSet,
    shown_last: IdSet,
    /// Child → (parent, place in the cascade over the parent).
    parents: IdMap<(Id, u8)>,
    /// The window the keyboard talks to when no widget has the focus.
    active: Option<Id>,
    /// Windows to bring to the front when next drawn.
    raise: IdSet,
    /// Windows raised this frame: their children come up with them.
    lifted: Vec<Id>,
    /// Windows brought to the front this frame by [`Floats::raise`].
    raised: Vec<Id>,
    /// Border flash of a window brought to the front: when it began.
    flash: IdMap<f64>,
    /// Windows with edits not applied (as of the last frame they drew).
    dirty: IdSet,
    titles: IdMap<String>,
    /// Windows told to close (their parent closed).
    closing: IdSet,
    /// A parent whose close waits for the operator's answer.
    confirm: Option<Id>,
    /// Ctrl+Tab this frame: `Some(true)` with Shift (backwards).
    cycle: Option<bool>,
}

#[derive(Default)]
struct Start {
    /// A popup or menu was open: Esc and Enter are its.
    popup: bool,
    /// Layer of the widget with keyboard focus (egui drops the focus on
    /// Esc before the frame, so Esc goes to the window in front).
    focus_layer: Option<LayerId>,
    /// Enter belongs to the focused widget unless it is a text field (a
    /// focused button or checkbox takes Enter as a click).
    enter_is_ours: bool,
    /// A confirmation is up: keys are its.
    modal: bool,
}

/// A key a window reacts to, read by [`Floats::keys`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Keyed {
    /// Enter: OK.
    Enter,
    /// Ctrl+Enter (Cmd+Enter on a Mac): Apply.
    CtrlEnter,
    Escape,
}

/// Which keys a window takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Takes {
    /// A dialog: Enter, Ctrl+Enter and Esc.
    Dialog,
    /// A list window: Esc only (Enter belongs to its table).
    Escape,
}

/// egui draws a window at the size of its contents, which may be a little
/// under the size asked for: ask again, corrected, for a few frames.
struct Restore {
    to: Rect,
    ask: Vec2,
    tries: u8,
}

const RESTORE_TRIES: u8 = 3;

/// How long the border of a window brought to the front flashes, and how
/// long each on/off step lasts.
const FLASH_SECS: f64 = 0.6;
const FLASH_STEP: f64 = 0.1;

/// Where a child opens over its parent: below the parent's title bar,
/// toolbar and table header, and a third of the way across (so "+", Find,
/// the columns and the names of the other rows stay in reach), each next
/// one a step further (wrapping after 8).
pub(crate) fn child_offset(parent: Rect) -> Vec2 {
    Vec2::new((parent.width() * 0.3).clamp(48.0, 240.0), 92.0)
}
pub(crate) const CHILD_STEP: f32 = 24.0;
const CHILD_SLOTS: u8 = 8;

/// Guard against a parent loop (none is ever made, but a loop must not hang).
const MAX_DEPTH: usize = 8;

impl Floats {
    pub(crate) fn is_maximized(&self, id: Id) -> bool {
        self.maximized.contains_key(&id)
    }

    /// Call once at the start of every frame, before any window is drawn.
    pub(crate) fn begin_frame(&mut self, ctx: &Context) {
        self.shown_last = std::mem::take(&mut self.shown);
        self.lifted.clear();
        self.raised.clear();
        let focused = ctx.memory(|m| m.focused());
        self.start = Start {
            popup: egui::Popup::is_any_open(ctx),
            focus_layer: focused
                .and_then(|f| ctx.read_response(f))
                .map(|r| r.layer_id),
            enter_is_ours: focused.is_none_or(|f| TextEdit::load_state(ctx, f).is_some()),
            modal: self.confirm.is_some(),
        };
        // A press on a window makes it the active one (egui raises it).
        let pressed = ctx.input(|i| i.pointer.any_pressed());
        if pressed
            && !self.start.modal
            && let Some(at) = ctx.pointer_interact_pos()
            && let Some(layer) = ctx.layer_id_at(at)
            && layer.order == Order::Middle
            && self.shown_last.contains(&layer.id)
        {
            self.active = Some(layer.id);
            self.lifted.push(layer.id);
        }
        // Ctrl+Tab before any widget sees the Tab (WinBox: Ctrl+F6).
        // With Shift first: Ctrl alone also matches Ctrl+Shift.
        self.cycle = ctx.input_mut(|i| {
            let shift = Modifiers::COMMAND | Modifiers::SHIFT;
            if i.consume_key(shift, Key::Tab) || i.consume_key(shift, Key::F6) {
                Some(true)
            } else if i.consume_key(Modifiers::COMMAND, Key::Tab)
                || i.consume_key(Modifiers::COMMAND, Key::F6)
            {
                Some(false)
            } else {
                None
            }
        });
    }

    /// Whether the window `id` is the one the keyboard talks to: the one
    /// holding the focus, else the active one, else the one in front.
    pub(crate) fn is_front(&self, ctx: &Context, id: Id) -> bool {
        let layer = LayerId::new(Order::Middle, id);
        match self.start.focus_layer {
            Some(focus) if focus.order == Order::Middle => focus == layer,
            _ => self.front(ctx) == Some(layer),
        }
    }

    fn is_shown(&self, id: Id) -> bool {
        self.shown.contains(&id) || self.shown_last.contains(&id)
    }

    /// The active window if still open, else the topmost one still open
    /// (egui's own `top_layer_id` may be one that was just closed).
    fn front(&self, ctx: &Context) -> Option<LayerId> {
        if let Some(a) = self.active.filter(|a| self.is_shown(*a)) {
            return Some(LayerId::new(Order::Middle, a));
        }
        ctx.memory(|m| {
            m.layer_ids()
                .filter(|l| l.order == Order::Middle)
                .filter(|l| self.is_shown(l.id))
                .last()
        })
    }

    /// The window `id` was closed: it is not in front any more, and its
    /// children (already told to close) have no parent.
    pub(crate) fn closed(&mut self, id: Id) {
        self.shown.remove(&id);
        self.shown_last.remove(&id);
        self.parents
            .retain(|child, (parent, _)| *child != id && *parent != id);
        self.dirty.remove(&id);
        self.titles.remove(&id);
        self.flash.remove(&id);
        self.raise.remove(&id);
        if self.active == Some(id) {
            self.active = None;
        }
        if self.confirm == Some(id) {
            self.confirm = None;
        }
    }

    /// Bring the window `id` to the front when it is next drawn, with a
    /// short flash of its border, and give it the keyboard.
    pub(crate) fn raise(&mut self, id: Id) {
        self.raise.insert(id);
    }

    /// Whether the border of `id` is flashing (it was just brought up).
    #[cfg_attr(not(test), expect(dead_code))]
    pub(crate) fn is_flashing(&self, id: Id) -> bool {
        self.flash.contains_key(&id)
    }

    /// The window `id` has edits not applied (shown in the close question).
    pub(crate) fn set_dirty(&mut self, id: Id, dirty: bool) {
        if dirty {
            self.dirty.insert(id);
        } else {
            self.dirty.remove(&id);
        }
    }

    /// The parent of `id`, if it has one still open.
    #[cfg_attr(not(test), expect(dead_code))]
    pub(crate) fn parent(&self, id: Id) -> Option<Id> {
        self.parents.get(&id).map(|(p, _)| *p)
    }

    /// Make `child` (opening now) a child of `parent`, if `parent` is open.
    /// Returns where the child opens: offset over its parent.
    pub(crate) fn adopt(&mut self, ctx: &Context, child: Id, parent: Option<Id>) -> Option<Pos2> {
        if !self.parents.contains_key(&child)
            && !self.shown_last.contains(&child)
            && let Some(p) = parent.filter(|p| *p != child && self.is_shown(*p))
        {
            let taken: Vec<u8> = self
                .parents
                .values()
                .filter(|(q, _)| *q == p)
                .map(|(_, slot)| *slot)
                .collect();
            let slot = (0..CHILD_SLOTS).find(|s| !taken.contains(s)).unwrap_or(0);
            self.parents.insert(child, (p, slot));
        }
        let (p, slot) = self.parents.get(&child)?;
        let parent = ctx.memory(|m| m.area_rect(*p))?;
        Some(parent.min + child_offset(parent) + Vec2::splat(f32::from(*slot) * CHILD_STEP))
    }

    /// The children of `id`, and theirs, back to front.
    fn descendants(&self, ctx: &Context, id: Id) -> Vec<Id> {
        let mut out = Vec::new();
        let mut level = vec![id];
        for _ in 0..MAX_DEPTH {
            let next: Vec<Id> = self
                .parents
                .iter()
                .filter(|(c, (p, _))| level.contains(p) && !out.contains(*c) && **c != id)
                .map(|(c, _)| *c)
                .collect();
            if next.is_empty() {
                break;
            }
            out.extend(next.iter().copied());
            level = next;
        }
        let order = middle_order(ctx);
        out.sort_by_key(|c| order.iter().position(|l| l == c));
        out
    }

    /// The operator closes `id`: its children close with it (returns
    /// true), unless one has edits not applied: then a question asks first
    /// and `id` stays open for now (returns false).
    pub(crate) fn close_family(&mut self, ctx: &Context, id: Id) -> bool {
        let family = self.descendants(ctx, id);
        if family.iter().any(|c| self.dirty.contains(c)) {
            self.confirm = Some(id);
            return false;
        }
        self.closing.extend(family);
        true
    }

    /// Whether `id` was told to close (its parent closed, or the operator
    /// answered "Close All"). Asking clears it.
    pub(crate) fn take_close(&mut self, id: Id) -> bool {
        self.closing.remove(&id)
    }

    /// The key the window `id` was given this frame, consumed so nothing
    /// else acts on it. Call after drawing the window (its widgets see the
    /// keys first: a table takes its own Enter, a text field ends editing).
    pub(crate) fn keys(&self, ctx: &Context, id: Id, takes: Takes) -> Option<Keyed> {
        if self.start.popup || self.start.modal || !self.is_front(ctx, id) {
            return None;
        }
        ctx.input_mut(|i| {
            if i.consume_key(Modifiers::NONE, Key::Escape) {
                return Some(Keyed::Escape);
            }
            if takes != Takes::Dialog || !self.start.enter_is_ours {
                return None;
            }
            if i.consume_key(Modifiers::COMMAND, Key::Enter) {
                Some(Keyed::CtrlEnter)
            } else if i.consume_key(Modifiers::NONE, Key::Enter) {
                Some(Keyed::Enter)
            } else {
                None
            }
        })
    }

    /// Drop what is kept for a window that will never be shown again.
    pub(crate) fn forget(&mut self, id: Id) {
        self.closed(id);
        self.closing.remove(&id);
        self.maximized.remove(&id);
        self.restore.remove(&id);
        self.expanded.remove(&id);
    }

    /// Maximize a window at `rect` now, or restore a maximized one.
    fn toggle(&mut self, id: Id, rect: Rect) {
        if let Some(to) = self.maximized.remove(&id) {
            let ask = to.size();
            self.restore.insert(id, Restore { to, ask, tries: 0 });
        } else {
            // Keep where it is now, at the size it had expanded.
            let size = self.expanded.get(&id).map_or(rect.size(), Rect::size);
            self.maximized
                .insert(id, Rect::from_min_size(rect.min, size));
        }
    }

    /// Show one floating window kept inside `area`. `configure` sets the
    /// rest (default size and position, resizable, collapsible, …).
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn show<'a, R>(
        &mut self,
        ctx: &Context,
        area: Rect,
        id: Id,
        title: &'a str,
        open: &'a mut bool,
        configure: impl FnOnce(Window<'a>) -> Window<'a>,
        add_contents: impl FnOnce(&mut Ui) -> R,
    ) -> Option<R> {
        self.area = Some(area);
        let layer = LayerId::new(Order::Middle, id);
        let new = !self.shown_last.contains(&id);
        self.shown.insert(id);
        if self.titles.get(&id).map(String::as_str) != Some(title) {
            self.titles.insert(id, title.to_owned());
        }
        let raised = self.raise.remove(&id);
        if raised && !new {
            ctx.move_to_top(layer);
            self.lifted.push(id);
            self.raised.push(id);
            self.flash.insert(id, ctx.input(|i| i.time));
        }
        if raised || new {
            // A window opened or asked for again takes the keyboard.
            self.active = Some(id);
            take_focus(ctx, layer);
        }
        let bar = Bar::new(ctx);
        // Room on both sides of the centred title, so a long one is cut
        // before it reaches the maximize button.
        let pad = |side| Atom::custom(IdSalt::new(side), Vec2::new(bar.button, 0.0));
        let window = Window::new((pad("float-pad-left"), title, pad("float-pad-right")))
            .id(id)
            .open(open)
            .constrain_to(area);
        let mut window = configure(window);
        // A collapsed window is only its title bar (also while animating).
        let expanded = CollapsingState::load(ctx, id.with("collapsing"))
            .is_none_or(|c| c.openness(ctx) >= 1.0);
        let fill = self.maximized.contains_key(&id);
        if fill {
            // Every frame, so it follows the area when the app is resized.
            window = window.fixed_rect(area);
        } else if let Some(r) = self.restore.get(&id)
            && (expanded || r.tries == 0)
        {
            // egui keeps what one frame sets. Not `current_pos` (egui's
            // title-bar drag overrides it), and not constrained with the
            // maximized size of the last frame (that moves it to the corner).
            window = window
                .fixed_rect(Rect::from_min_size(r.to.min, r.ask))
                .constrain(false);
        }
        let shown = window.show(ctx, |ui| {
            // egui sizes a window to its contents: claim the whole area.
            if fill {
                ui.set_min_size(ui.available_size());
            }
            add_contents(ui)
        })?;
        let rect = shown.response.rect;
        if expanded && !self.maximized.contains_key(&id) {
            self.expanded.insert(id, rect);
        }
        if let Some(r) = self.restore.get_mut(&id) {
            // Back in place now; only the size may still need asking for.
            r.to = Rect::from_min_size(rect.min, r.to.size());
            let off = r.to.size() - rect.size();
            if !expanded {
                // The size shows once it is expanded again.
                r.tries = r.tries.max(1);
            } else if off.length() < 0.5 || r.tries >= RESTORE_TRIES {
                self.restore.remove(&id);
            } else {
                r.ask += off;
                r.tries += 1;
                ctx.request_repaint();
            }
        }
        if self.title_bar(ctx, &bar, id, rect, shown.response.layer_id) {
            self.toggle(id, rect);
            ctx.request_repaint();
        }
        self.paint_flash(ctx, id, rect, shown.response.layer_id);
        shown.inner
    }

    /// Blink the border of a window just brought to the front.
    fn paint_flash(&mut self, ctx: &Context, id: Id, rect: Rect, layer: LayerId) {
        let Some(start) = self.flash.get(&id).copied() else {
            return;
        };
        let t = ctx.input(|i| i.time) - start;
        if !(0.0..FLASH_SECS).contains(&t) {
            self.flash.remove(&id);
            return;
        }
        // Even steps on, odd steps off.
        if ((t / FLASH_STEP) as u32).is_multiple_of(2) {
            let style = ctx.global_style();
            let stroke = Stroke::new(2.0, style.visuals.selection.bg_fill);
            ctx.layer_painter(layer).rect_stroke(
                rect,
                style.visuals.window_corner_radius,
                stroke,
                StrokeKind::Outside,
            );
        }
        ctx.request_repaint();
    }

    /// Call once at the end of every frame, after every window is drawn:
    /// children above their parents, Ctrl+Tab, and the close question.
    pub(crate) fn end_frame(&mut self, ctx: &Context) {
        let stale: Vec<Id> = self
            .parents
            .keys()
            .copied()
            .filter(|c| !self.is_shown(*c))
            .collect();
        for c in stale {
            self.parents.remove(&c);
        }
        self.titles.retain(|id, _| self.shown.contains(id));
        self.dirty.retain(|id| self.shown.contains(id));

        if let Some(back) = self.cycle.take()
            && !self.start.modal
        {
            self.cycle_windows(ctx, back);
        }

        // Raising a window raises its children with it, and a child below
        // its parent (by any other way) goes back above it. egui keeps the
        // relative order of what is raised in one frame, so a family keeps
        // its own order.
        let order = middle_order(ctx);
        let place = |id: &Id| order.iter().position(|l| l == id);
        let mut lift: Vec<Id> = Vec::new();
        for l in &self.lifted {
            lift.extend(self.descendants(ctx, *l));
        }
        for (child, (parent, _)) in &self.parents {
            let both = self.shown.contains(child) && self.shown.contains(parent);
            if both
                && place(child) < place(parent)
                && !self.lifted.contains(parent)
                && !lift.contains(child)
            {
                lift.push(*child);
                lift.extend(self.descendants(ctx, *child));
            }
        }
        // egui cannot put one of a family above the others in the frame the
        // family comes up: a window asked for then comes up next frame.
        for id in &self.raised {
            if lift.contains(id) {
                self.raise.insert(*id);
            }
        }
        if !lift.is_empty() {
            for id in &lift {
                ctx.move_to_top(LayerId::new(Order::Middle, *id));
            }
            ctx.request_repaint();
        }
        self.confirm_close(ctx);
    }

    /// Ctrl+Tab: the window at the back comes to the front (with its
    /// children); with Shift, the one in front goes to the back.
    fn cycle_windows(&mut self, ctx: &Context, back: bool) {
        let roots: Vec<Id> = middle_order(ctx)
            .into_iter()
            .filter(|id| self.shown.contains(id))
            .filter(|id| {
                self.parents
                    .get(id)
                    .is_none_or(|(p, _)| !self.shown.contains(p))
            })
            .collect();
        let (Some(first), Some(&last)) = (roots.first().copied(), roots.last()) else {
            return;
        };
        if first == last {
            return;
        }
        let (up, front): (Vec<Id>, Option<Id>) = if back {
            let up: Vec<Id> = roots.iter().copied().filter(|r| *r != last).collect();
            let front = up.last().copied();
            (up, front)
        } else {
            (vec![first], Some(first))
        };
        for r in up {
            ctx.move_to_top(LayerId::new(Order::Middle, r));
            self.lifted.push(r);
        }
        if let Some(f) = front {
            // The keyboard goes to the family's window in front.
            let top = self.descendants(ctx, f).last().copied().unwrap_or(f);
            self.active = Some(top);
            take_focus(ctx, LayerId::new(Order::Middle, top));
        }
        ctx.request_repaint();
    }

    /// The question "Close <parent>?" while a child has edits not applied.
    fn confirm_close(&mut self, ctx: &Context) {
        let Some(parent) = self.confirm else {
            return;
        };
        if !self.shown.contains(&parent) {
            self.confirm = None;
            return;
        }
        let family = self.descendants(ctx, parent);
        let dirty: Vec<Id> = family
            .iter()
            .copied()
            .filter(|c| self.dirty.contains(c))
            .collect();
        let name = |id: &Id| self.titles.get(id).map_or("", String::as_str);
        let mut answer = dirty.is_empty().then_some(true);
        if answer.is_none() {
            let shown = egui::Modal::new(parent.with("float-confirm")).show(ctx, |ui| {
                ui.set_max_width(360.0);
                ui.strong(format!("Close {}?", name(&parent)));
                ui.add_space(4.0);
                ui.label(if dirty.len() == 1 {
                    "This window has changes not applied:"
                } else {
                    "These windows have changes not applied:"
                });
                ui.indent("float-confirm-list", |ui| {
                    for c in &dirty {
                        ui.strong(name(c));
                    }
                });
                ui.label("Closing drops them.");
                ui.separator();
                ui.horizontal(|ui| {
                    if ui.button("Close All").clicked() {
                        answer = Some(true);
                    }
                    if ui.button("Cancel").on_hover_text("Esc").clicked() {
                        answer = Some(false);
                    }
                });
            });
            if answer.is_none() && shown.should_close() {
                answer = Some(false);
            }
        }
        match answer {
            Some(true) => {
                self.closing.extend(family);
                self.closing.insert(parent);
                self.confirm = None;
            }
            Some(false) => {
                self.confirm = None;
                // Show what would have been lost.
                if let Some(c) = dirty.last() {
                    self.raise(*c);
                }
            }
            None => {}
        }
    }

    /// The maximize button and the title strip, on the window's own layer
    /// (above egui's title bar, below any window on top). Returns whether
    /// the user asked to maximize or restore.
    fn title_bar(
        &self,
        ctx: &Context,
        bar: &Bar,
        id: Id,
        rect: Rect,
        layer: egui::LayerId,
    ) -> bool {
        let places = bar.places(rect);
        let mut ui = Ui::new(
            ctx.clone(),
            id.with("float-title"),
            UiBuilder::new().layer_id(layer).max_rect(places.row),
        );
        ui.set_clip_rect(rect);
        let maximized = self.is_maximized(id);
        let label = if maximized { "Restore" } else { "Maximize" };

        // Click only: the drag still reaches egui's title bar (to move),
        // the click and double click come here instead of collapsing.
        let strip = ui.interact(places.strip, id.with("float-strip"), Sense::click());
        let button = ui
            .interact(places.button, id.with("float-maximize"), Sense::click())
            .on_hover_text(label);
        paint_button(&ui, &button, maximized);

        let mut toggle = button.clicked() || strip.double_clicked();
        strip.context_menu(|ui| {
            if ui.button(label).clicked() {
                toggle = true;
            }
        });
        toggle
    }
}

/// The windows, back to front (as egui ordered them at the end of the last
/// frame, then the ones that appeared this frame).
fn middle_order(ctx: &Context) -> Vec<Id> {
    ctx.memory(|m| {
        m.layer_ids()
            .filter(|l| l.order == Order::Middle)
            .map(|l| l.id)
            .collect()
    })
}

/// Take the keyboard focus away from a widget in another window, so the
/// keys reach `layer` (which is then the active window).
fn take_focus(ctx: &Context, layer: LayerId) {
    let Some(f) = ctx.memory(|m| m.focused()) else {
        return;
    };
    if ctx.read_response(f).map(|r| r.layer_id) != Some(layer) {
        ctx.memory_mut(|m| m.surrender_focus(f));
    }
}

/// Geometry of egui's window title bar (`egui::containers::window::title_ui`):
/// a row of heading-height squares inside the window frame's margin.
pub(crate) struct Bar {
    /// Window frame stroke + outer margin, around the title row.
    edge_lt: Vec2,
    edge_rb: Vec2,
    /// The title row's own margin (the window margin).
    margin_lt: Vec2,
    margin_rb: Vec2,
    gap: f32,
    /// Side of the square each title button is laid out in.
    button: f32,
    /// Side of the icon painted inside that square.
    icon: f32,
}

/// Where the title bar's parts are in one window.
pub(crate) struct Places {
    pub(crate) row: Rect,
    /// egui's own collapse button (the tests press it).
    #[cfg_attr(not(test), expect(dead_code))]
    pub(crate) collapse: Rect,
    /// egui's own close ✕ (the tests press it).
    #[cfg_attr(not(test), expect(dead_code))]
    pub(crate) close: Rect,
    pub(crate) button: Rect,
    pub(crate) strip: Rect,
}

impl Bar {
    pub(crate) fn new(ctx: &Context) -> Self {
        let style = ctx.global_style();
        let frame = egui::Frame::window(&style);
        let stroke = Vec2::splat(frame.stroke.width);
        let heading = TextStyle::Heading.resolve(&style);
        Self {
            edge_lt: frame.outer_margin.left_top() + stroke,
            edge_rb: frame.outer_margin.right_bottom() + stroke,
            margin_lt: frame.inner_margin.left_top(),
            margin_rb: frame.inner_margin.right_bottom(),
            gap: style.spacing.item_spacing.x,
            button: ctx.fonts_mut(|f| f.row_height(&heading)),
            icon: style.spacing.icon_width,
        }
    }

    pub(crate) fn places(&self, rect: Rect) -> Places {
        let top = rect.min + self.edge_lt;
        let height = self.margin_lt.y + self.button + self.margin_rb.y;
        let row = Rect::from_min_max(top, pos2(rect.max.x - self.edge_rb.x, top.y + height));
        let y = row.min.y + self.margin_lt.y;
        let side = Vec2::splat(self.button);
        let collapse = Rect::from_min_size(pos2(row.min.x + self.margin_lt.x, y), side);
        let close = Rect::from_min_size(pos2(row.max.x - self.margin_rb.x - self.button, y), side);
        let slot = close.translate(Vec2::new(-(self.button + self.gap), 0.0));
        let shrink = (self.button - self.icon).max(0.0) * 0.5;
        Places {
            row,
            collapse,
            close,
            button: slot.shrink(shrink),
            strip: Rect::from_x_y_ranges(collapse.max.x..=slot.min.x, row.y_range()),
        }
    }
}

/// □ to maximize, ❐ to restore; drawn, since the default fonts have no
/// such glyphs. Same look as egui's close button next to it.
fn paint_button(ui: &Ui, response: &Response, maximized: bool) {
    let visuals = ui.style().interact(response);
    let r = response.rect.shrink(2.0).expand(visuals.expansion);
    let stroke: Stroke = visuals.fg_stroke;
    let painter = ui.painter();
    if !maximized {
        painter.rect_stroke(r, 0.0, stroke, StrokeKind::Inside);
        return;
    }
    let s = r.width() * 0.72;
    let front = Rect::from_min_size(pos2(r.min.x, r.max.y - s), Vec2::splat(s));
    let back = Rect::from_min_size(pos2(r.max.x - s, r.min.y), Vec2::splat(s));
    // The back square only shows above and to the right of the front one.
    let line = |a: Pos2, b: Pos2| painter.line_segment([a, b], stroke);
    line(pos2(back.min.x, front.min.y), back.left_top());
    line(back.left_top(), back.right_top());
    line(back.right_top(), back.right_bottom());
    line(back.right_bottom(), pos2(front.max.x, back.max.y));
    painter.rect_stroke(front, 0.0, stroke, StrokeKind::Inside);
}
