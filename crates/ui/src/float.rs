//! Floating windows (WinBox MDI style). Every internal window is drawn by
//! [`Floats::show`], which adds maximize/restore to egui's own title bar:
//! the collapse ▼, the drag to move and the close ✕ stay egui's; a button
//! next to the ✕, a double click on the title and the title's context menu
//! toggle between the work area and the rectangle the window had before.
//!
//! The state is UI-local: nothing here goes through the engine.

use egui::collapsing_header::CollapsingState;
use egui::{
    Atom, Context, Id, IdMap, IdSalt, Pos2, Rect, Response, Sense, Stroke, StrokeKind, TextStyle,
    Ui, UiBuilder, Vec2, Window, pos2,
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
}

/// egui draws a window at the size of its contents, which may be a little
/// under the size asked for: ask again, corrected, for a few frames.
struct Restore {
    to: Rect,
    ask: Vec2,
    tries: u8,
}

const RESTORE_TRIES: u8 = 3;

impl Floats {
    pub(crate) fn is_maximized(&self, id: Id) -> bool {
        self.maximized.contains_key(&id)
    }

    /// Drop what is kept for a window that will never be shown again.
    pub(crate) fn forget(&mut self, id: Id) {
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
        shown.inner
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
