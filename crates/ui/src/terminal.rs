//! "New Terminal" (WinBox's): the RouterOS-style terminal of
//! `corerouter-shell` in a floating window. Several can be open at once.
//!
//! The window only draws and types. The shell decides what a line means
//! and asks for control-channel calls, which go to the router through this
//! UI's backend (local lab or remote daemon, G0.4) like every other panel:
//! nothing reaches the engine except through `engine.*`/`state.inspect`.
//!
//! Keys (input focused): Enter runs, ↑/↓ walk the history, Tab completes
//! (one candidate: inserted; several: their common start and a list to
//! click), `?` or F1 shows help at once and keeps the line, Ctrl+X toggles Safe
//! Mode (as in RouterOS; there is no cut in the terminal), Ctrl+C stops the
//! task a command follows (`ping`: events print as they come), Esc hides the
//! suggestions. Output is selectable; right click copies or clears it.
//! A click anywhere in the window puts the focus back on the input (as in
//! xterm, PuTTY and WinBox); after a drag that selects text, the selection
//! stays and the next key goes to the input.
//!
//! Like every terminal (WinBox's, xterm), a line wider than the window
//! wraps at its width and wraps again when the window is resized; the rows
//! after the first start with a faint `↳ `. The wrap is display only: the
//! output keeps the original lines, and copying (a selection or Copy All)
//! gives them back without the breaks.

use corerouter_shell::{Completion, Job, Line, Reply, Request, Shell, Span, Step, Style};
use egui::text::{CCursor, CCursorRange, LayoutJob, TextFormat};
use egui::{Color32, FontId, Key, Modifiers, TextEdit, TextStyle};

use crate::{CoreRouterUi, Pending, RequestId};

/// What a display wrap inserts in a line (and copying takes out again).
pub(crate) const WRAP: &str = "\n\u{21b3} ";

/// Output lines kept per terminal.
const MAX_OUTPUT: usize = 5000;
/// Commands kept in a terminal's history.
const MAX_HISTORY: usize = 500;

/// A job waiting for its replies.
struct Running {
    job: Job,
    /// Backend request ids, by slot (None: answered on the spot).
    ids: Vec<Option<RequestId>>,
    replies: Vec<Option<Reply>>,
    /// A `Sleep` slot (between polls of a task): its slot, length and,
    /// once a frame saw it, when it ends (UI time, seconds).
    sleep: Option<(usize, f64, Option<f64>)>,
}

pub(crate) struct TermWin {
    pub(crate) id: u64,
    pub(crate) shell: Shell,
    pub(crate) output: Vec<Line>,
    pub(crate) input: String,
    history: Vec<String>,
    /// Position while walking the history with ↑/↓.
    browse: Option<usize>,
    /// What was typed before ↑ (comes back past the newest entry).
    draft: String,
    running: Option<Running>,
    /// Tab's candidates, shown under the input until the line changes.
    pub(crate) suggestions: Option<Completion>,
    /// A line to put back once the job ends (after `?` and Ctrl+X).
    restore: Option<String>,
    focus: bool,
    /// A drag selected output text: the next key takes the focus back.
    refocus_on_key: bool,
    closed: bool,
    /// Height of the input row and suggestions last frame (reserved under
    /// the output so the window keeps its size).
    bottom: f32,
}

pub(crate) fn term_id(id: u64) -> egui::Id {
    egui::Id::unique(("corerouter-terminal", id))
}

pub(crate) fn input_id(id: u64) -> egui::Id {
    egui::Id::unique(("corerouter-terminal-input", id))
}

impl TermWin {
    fn new(id: u64, user: &str) -> Self {
        Self {
            id,
            shell: Shell::new(user),
            output: Vec::new(),
            input: String::new(),
            history: Vec::new(),
            browse: None,
            draft: String::new(),
            running: None,
            suggestions: None,
            restore: None,
            focus: true,
            refocus_on_key: false,
            closed: false,
            bottom: 24.0,
        }
    }

    pub(crate) fn busy(&self) -> bool {
        self.running.is_some()
    }

    fn print(&mut self, lines: impl IntoIterator<Item = Line>) {
        self.output.extend(lines);
        if self.output.len() > MAX_OUTPUT {
            let extra = self.output.len() - MAX_OUTPUT;
            self.output.drain(..extra);
        }
    }

    fn remember(&mut self, line: &str) {
        let l = line.trim();
        let secret = ["password", "secret", "token", "psk"]
            .iter()
            .any(|w| l.to_ascii_lowercase().contains(w));
        if l.is_empty() || secret || self.history.last().is_some_and(|h| h == line) {
            return;
        }
        self.history.push(line.to_owned());
        if self.history.len() > MAX_HISTORY {
            self.history.remove(0);
        }
    }

    fn history_step(&mut self, up: bool) {
        let n = self.history.len();
        let next = match (self.browse, up) {
            (None, true) if n > 0 => {
                self.draft = self.input.clone();
                Some(n - 1)
            }
            (Some(i), true) => Some(i.saturating_sub(1)),
            (Some(i), false) if i + 1 < n => Some(i + 1),
            (Some(_), false) => None,
            (None, _) => return,
        };
        self.browse = next;
        self.input = match next {
            Some(i) => self.history.get(i).cloned().unwrap_or_default(),
            None => std::mem::take(&mut self.draft),
        };
    }
}

/// The color of a span in this theme.
fn color(ui: &egui::Ui, style: Style) -> Color32 {
    let v = ui.visuals();
    let dark = v.dark_mode;
    let pick = |d: Color32, l: Color32| if dark { d } else { l };
    match style {
        Style::Plain | Style::Value => v.text_color(),
        Style::Menu => pick(
            Color32::from_rgb(110, 170, 255),
            Color32::from_rgb(20, 80, 190),
        ),
        Style::Verb => pick(
            Color32::from_rgb(80, 210, 220),
            Color32::from_rgb(0, 120, 140),
        ),
        Style::Key => pick(
            Color32::from_rgb(130, 210, 120),
            Color32::from_rgb(30, 120, 40),
        ),
        Style::Item => pick(
            Color32::from_rgb(220, 140, 230),
            Color32::from_rgb(140, 40, 160),
        ),
        Style::Header => v.strong_text_color(),
        Style::Flag => v.warn_fg_color,
        Style::Comment | Style::Dim => v.weak_text_color(),
        Style::Error => v.error_fg_color,
        Style::Warn => v.warn_fg_color,
        Style::Ok => pick(
            Color32::from_rgb(120, 220, 120),
            Color32::from_rgb(20, 130, 40),
        ),
        Style::Safe => Color32::WHITE,
    }
}

fn job_of(ui: &egui::Ui, spans: &[Span], font: &FontId) -> LayoutJob {
    let mut job = LayoutJob::default();
    for s in spans {
        let mut f = TextFormat::simple(font.clone(), color(ui, s.style));
        match s.style {
            Style::Comment => f.italics = true,
            Style::Safe => f.background = crate::SAFE_MODE_FILL,
            _ => {}
        }
        job.append(&s.text, 0.0, f);
    }
    job
}

/// `spans` as rows of at most `cols` characters: each row after the first
/// starts with [`WRAP`] and holds two characters less. A row ends after its
/// last space when it has one (the space stays, so taking [`WRAP`] out gives
/// the line back), else at `cols`.
pub(crate) fn wrapped(spans: &[Span], cols: usize) -> Vec<Span> {
    let chars: Vec<(char, Style)> = spans
        .iter()
        .flat_map(|s| s.text.chars().map(move |c| (c, s.style)))
        .collect();
    if chars.len() <= cols {
        return spans.to_vec();
    }
    let mut out: Vec<Span> = Vec::new();
    let mut start = 0;
    while start < chars.len() {
        let room = if start == 0 { cols } else { cols.saturating_sub(2) }.max(1);
        let mut end = (start + room).min(chars.len());
        if end < chars.len()
            && let Some(sp) = chars
                .get(start..end)
                .and_then(|row| row.iter().rposition(|(c, _)| *c == ' '))
                .filter(|&sp| sp > 0)
        {
            end = start + sp + 1;
        }
        if start > 0 {
            out.push(Span {
                style: Style::Dim,
                text: WRAP.to_owned(),
            });
        }
        for &(c, style) in chars.get(start..end).unwrap_or_default() {
            match out.last_mut() {
                Some(last) if last.style == style && last.text != WRAP => last.text.push(c),
                _ => out.push(Span {
                    style,
                    text: c.to_string(),
                }),
            }
        }
        start = end;
    }
    out
}

/// Takes the display wraps out of what the terminal's labels copy (egui
/// copies a selection at the end of the frame, so this runs on the output).
pub(crate) struct UnwrapCopy;

impl egui::Plugin for UnwrapCopy {
    fn debug_name(&self) -> &'static str {
        "corerouter-terminal-unwrap-copy"
    }

    fn output_hook(&mut self, _ctx: &egui::Context, output: &mut egui::FullOutput) {
        for c in &mut output.platform_output.commands {
            if let egui::OutputCommand::CopyText(text) = c
                && text.contains(WRAP)
            {
                *text = text.replace(WRAP, "");
            }
        }
    }
}

impl CoreRouterUi {
    /// "New Terminal": one more terminal window, connected at once.
    pub fn new_terminal(&mut self) {
        self.next_dialog += 1;
        let user = self.terminal_user.clone();
        let mut t = TermWin::new(self.next_dialog, &user);
        let job = t.shell.connect();
        self.terminals.push(t);
        let idx = self.terminals.len() - 1;
        self.term_start(idx, job);
    }

    /// Open terminals (tests and the side menu).
    pub fn terminal_count(&self) -> usize {
        self.terminals.len()
    }

    /// Type and run a line in terminal `n` (tests drive the window this
    /// way as well as by keys).
    pub fn terminal_submit(&mut self, n: usize, line: &str) {
        let Some(t) = self.terminals.get_mut(n) else {
            return;
        };
        if t.busy() {
            return;
        }
        let mut echo = Line(t.shell.prompt());
        if t.shell.asking_password() {
            // A password (first login, G0.3b): never shown, never kept.
            t.print([echo]);
        } else {
            echo.0.extend(t.shell.highlight(line));
            t.print([echo]);
            t.remember(line);
        }
        t.browse = None;
        let job = t.shell.submit(line);
        self.term_start(n, job);
    }

    /// The output of terminal `n` as text.
    pub fn terminal_text(&self, n: usize) -> String {
        self.terminals
            .get(n)
            .map(|t| t.output.iter().map(|l| l.text() + "\n").collect::<String>())
            .unwrap_or_default()
    }

    fn term_start(&mut self, idx: usize, job: Job) {
        if let Some(t) = self.terminals.get_mut(idx) {
            t.running = Some(Running {
                job,
                ids: Vec::new(),
                replies: Vec::new(),
                sleep: None,
            });
        }
        self.term_advance(idx, Vec::new());
    }

    /// Step the job of terminal `idx` with `replies` and send what it asks.
    fn term_advance(&mut self, idx: usize, mut replies: Vec<Reply>) {
        loop {
            let Some(t) = self.terminals.get_mut(idx) else {
                return;
            };
            let Some(mut run) = t.running.take() else {
                return;
            };
            let step = t.shell.step(&mut run.job, replies);
            // A task's events, as they come.
            let live = t.shell.take_live();
            t.print(live);
            match step {
                Step::Done(out) => {
                    if out.quit {
                        t.closed = true;
                    }
                    t.print(out.lines);
                    if let Some(line) = t.restore.take() {
                        t.input = line;
                    }
                    t.focus = true;
                    // The tables may show something else now.
                    self.cache.refreshed_at = None;
                    return;
                }
                Step::Send(reqs) => {
                    let term = t.id;
                    run.ids.clear();
                    run.replies.clear();
                    run.sleep = None;
                    for r in reqs {
                        match r {
                            Request::Call { method, params } => {
                                let id = self.backend.submit(&method, params);
                                self.pending.insert(id, Pending::Terminal { term });
                                run.ids.push(Some(id));
                                run.replies.push(None);
                            }
                            Request::Sleep { ms } => {
                                run.sleep = Some((run.replies.len(), ms as f64 / 1000.0, None));
                                run.ids.push(None);
                                run.replies.push(None);
                            }
                            Request::ReadFile { .. } | Request::WriteFile { .. } => {
                                run.ids.push(None);
                                run.replies.push(Some(Err(
                                    "the GUI terminal has no files: paste the script instead \
                                     (or use corerouter-cli shell for import/export files)"
                                        .into(),
                                )));
                            }
                        }
                    }
                    let complete = run.replies.iter().all(Option::is_some);
                    let Some(t) = self.terminals.get_mut(idx) else {
                        return;
                    };
                    if complete {
                        replies = run.replies.drain(..).flatten().collect();
                        t.running = Some(run);
                        continue;
                    }
                    t.running = Some(run);
                    return;
                }
            }
        }
    }

    /// A reply for terminal `term` arrived.
    pub(crate) fn term_reply(&mut self, term: u64, id: RequestId, result: Reply) {
        let Some(idx) = self.terminals.iter().position(|t| t.id == term) else {
            return;
        };
        let Some(t) = self.terminals.get_mut(idx) else {
            return;
        };
        let Some(run) = t.running.as_mut() else {
            return;
        };
        let Some(slot) = run.ids.iter().position(|i| *i == Some(id)) else {
            return;
        };
        if let Some(r) = run.replies.get_mut(slot) {
            *r = Some(result);
        }
        if run.replies.iter().all(Option::is_some) {
            let replies = run.replies.drain(..).flatten().collect();
            self.term_advance(idx, replies);
        }
    }

    /// End the sleep of terminal `idx` when its time came (or Ctrl+C cut it
    /// short), and keep frames coming meanwhile.
    fn term_wake(&mut self, idx: usize, now: f64, cut: bool) {
        let Some(t) = self.terminals.get_mut(idx) else {
            return;
        };
        let Some(run) = t.running.as_mut() else {
            return;
        };
        let Some((slot, secs, due)) = run.sleep else {
            return;
        };
        let due = due.unwrap_or(now + secs);
        if !cut && now < due {
            run.sleep = Some((slot, secs, Some(due)));
            return;
        }
        run.sleep = None;
        if let Some(r) = run.replies.get_mut(slot) {
            *r = Some(Ok(serde_json::Value::Null));
        }
        if run.replies.iter().all(Option::is_some) {
            let replies = run.replies.drain(..).flatten().collect();
            self.term_advance(idx, replies);
        }
    }

    fn term_safe_mode(&mut self, idx: usize) {
        let Some(t) = self.terminals.get_mut(idx) else {
            return;
        };
        if t.busy() {
            return;
        }
        t.restore = Some(std::mem::take(&mut t.input));
        let job = t.shell.toggle_safe_mode();
        self.term_start(idx, job);
    }

    fn term_help(&mut self, idx: usize) {
        let Some(t) = self.terminals.get_mut(idx) else {
            return;
        };
        if t.busy() {
            return;
        }
        let line = t.input.clone();
        let mut echo = Line(t.shell.prompt());
        echo.0.extend(t.shell.highlight(&line));
        echo.push(Style::Plain, "?");
        t.print([echo]);
        t.restore = Some(line.clone());
        let job = t.shell.submit(&format!("{line}?"));
        self.term_start(idx, job);
    }

    /// Tab in terminal `idx` with the cursor at byte `cursor`; returns the
    /// new cursor (bytes).
    pub(crate) fn term_complete(&mut self, idx: usize, cursor: usize) -> usize {
        let Some(t) = self.terminals.get_mut(idx) else {
            return cursor;
        };
        let c = t.shell.complete(&t.input, cursor);
        let insert = match c.candidates.as_slice() {
            [] => {
                t.suggestions = None;
                return cursor;
            }
            [one] => {
                t.suggestions = None;
                one.text.clone()
            }
            _ => {
                let p = c.common_prefix();
                t.suggestions = Some(c.clone());
                p
            }
        };
        let start = c.start.min(cursor);
        let typed = t.input.get(start..cursor).unwrap_or("");
        if insert.len() < typed.len() || !insert.starts_with(typed) && insert.is_empty() {
            return cursor;
        }
        let tail = t.input.get(cursor..).unwrap_or("").to_owned();
        let head = t.input.get(..start).unwrap_or("").to_owned();
        t.input = format!("{head}{insert}{tail}");
        start + insert.len()
    }

    /// Draw every terminal window.
    pub(crate) fn terminals(&mut self, ctx: &egui::Context, area: egui::Rect) {
        let mut idx = 0;
        while idx < self.terminals.len() {
            let Some(t) = self.terminals.get(idx) else {
                break;
            };
            let id = term_id(t.id);
            let title = format!("Terminal {}", t.id);
            let mut open = !t.closed;
            let pos = crate::interfaces::cascade(area, t.id);
            let mut floats = std::mem::take(&mut self.floats);
            floats.show(
                ctx,
                area,
                id,
                &title,
                &mut open,
                |w| w.default_size([760.0, 420.0]).default_pos(pos),
                |ui| self.terminal_body(ui, idx),
            );
            self.floats = floats;
            if open {
                idx += 1;
            } else {
                self.floats.forget(id);
                self.terminals.remove(idx);
            }
        }
    }

    fn terminal_body(&mut self, ui: &mut egui::Ui, idx: usize) {
        let font = TextStyle::Monospace.resolve(ui.style());
        // `print` and `/export` fit this width (like RouterOS) instead of
        // stretching the window; a longer line wraps.
        let glyph = ui.fonts_mut(|f| f.glyph_width(&font, '0')).max(1.0);
        let cols = ((ui.available_width() - 16.0) / glyph).floor().max(20.0) as usize;
        if let Some(t) = self.terminals.get_mut(idx) {
            t.shell.set_width(Some(cols));
        }
        let Some(t) = self.terminals.get(idx) else {
            return;
        };
        let iid = input_id(t.id);
        // A click in this window (not a drag) focuses the input; a key after
        // a drag that selected text does too, without losing the selection.
        let body = ui.max_rect();
        let (clicked_at, dragged_from, keyed) = ui.input(|i| {
            let p = &i.pointer;
            let clicked = p.primary_clicked().then(|| p.interact_pos()).flatten();
            let dragged = (p.primary_released() && !p.primary_clicked())
                .then(|| p.press_origin())
                .flatten();
            let keyed = i.events.iter().any(|e| {
                matches!(e, egui::Event::Text(_) | egui::Event::Key { pressed: true, .. })
            });
            (clicked, dragged, keyed)
        });
        let here = |pos: Option<egui::Pos2>| {
            pos.is_some_and(|p| {
                body.contains(p) && ui.ctx().layer_id_at(p) == Some(ui.layer_id())
            })
        };
        let (clicked, dragged) = (here(clicked_at), here(dragged_from));
        let nothing_focused = ui.memory(|m| m.focused().is_none());
        // A key: focus now, so the input gets it this frame. A click: after
        // the input is drawn (it gives the focus up on a click elsewhere).
        let key_focus = t.refocus_on_key && keyed && nothing_focused;
        let refocus_on_key =
            !clicked && !key_focus && (dragged || (t.refocus_on_key && nothing_focused));
        if key_focus {
            ui.memory_mut(|m| m.request_focus(iid));
        }
        let focused = ui.memory(|m| m.has_focus(iid));

        // Keys the terminal takes before the text field sees them.
        let mut submit = false;
        let mut tab = false;
        let mut hist: Option<bool> = None;
        let mut safe = false;
        let mut help = false;
        let mut escape = false;
        let mut interrupt = false;
        // Typing a password (first login): only Enter means something.
        let asking = t.shell.asking_password();
        if focused {
            ui.input_mut(|i| {
                submit = i.consume_key(Modifiers::NONE, Key::Enter);
                tab = i.consume_key(Modifiers::NONE, Key::Tab);
                if i.consume_key(Modifiers::NONE, Key::ArrowUp) {
                    hist = Some(true);
                } else if i.consume_key(Modifiers::NONE, Key::ArrowDown) {
                    hist = Some(false);
                }
                escape = i.consume_key(Modifiers::NONE, Key::Escape);
                // F1: RouterOS v7's help key.
                let f1 = i.consume_key(Modifiers::NONE, Key::F1);
                // Ctrl+C while a job runs: stop the task it follows (a real
                // keyboard sends Copy).
                if t.busy() {
                    let before = i.events.len();
                    i.events.retain(|e| !matches!(e, egui::Event::Copy));
                    interrupt =
                        before != i.events.len() || i.consume_key(Modifiers::COMMAND, Key::C);
                }
                // Ctrl+X arrives as Cut from a real keyboard.
                let before = i.events.len();
                i.events.retain(|e| !matches!(e, egui::Event::Cut));
                safe = before != i.events.len() || i.consume_key(Modifiers::COMMAND, Key::X);
                let quotes_open = t.input.matches('"').count() % 2 == 1;
                if !quotes_open && !asking {
                    let before = i.events.len();
                    i.events
                        .retain(|e| !matches!(e, egui::Event::Text(s) if s == "?"));
                    help = before != i.events.len();
                }
                help |= f1;
                if asking {
                    (tab, hist, safe, help) = (false, None, false, false);
                }
            });
        }

        let busy = t.busy();
        let now = ui.input(|i| i.time);
        if busy {
            // A task between polls has no reply pending: keep frames coming.
            ui.ctx()
                .request_repaint_after(std::time::Duration::from_millis(50));
        }
        let prompt = t.shell.prompt();
        let output_height = (ui.available_height() - t.bottom - 6.0).max(40.0);
        let mut clear = false;
        let mut copy = false;
        if ui.ctx().plugin_opt::<UnwrapCopy>().is_none() {
            ui.ctx().add_plugin(UnwrapCopy);
        }
        egui::ScrollArea::vertical()
            .id_salt(("terminal-output", t.id))
            .max_height(output_height)
            .auto_shrink([false, false])
            .stick_to_bottom(true)
            .show(ui, |ui| {
                ui.spacing_mut().item_spacing.y = 0.0;
                for line in &t.output {
                    let job = job_of(ui, &wrapped(&line.0, cols), &font);
                    let r = ui.add(egui::Label::new(job).selectable(true).extend());
                    r.context_menu(|ui| {
                        if ui.button("Copy All").clicked() {
                            copy = true;
                            ui.close();
                        }
                        if ui.button("Clear").clicked() {
                            clear = true;
                            ui.close();
                        }
                    });
                }
            });

        let bottom_top = ui.min_rect().bottom();
        // The suggestions of the last Tab.
        let mut picked: Option<String> = None;
        if let Some(s) = &t.suggestions {
            ui.horizontal_wrapped(|ui| {
                for c in &s.candidates {
                    let text = egui::RichText::new(&c.display)
                        .monospace()
                        .color(color(ui, c.style));
                    let b = ui.add(egui::Button::new(text).small().frame(false));
                    let b = if c.help.is_empty() {
                        b
                    } else {
                        b.on_hover_text(&c.help)
                    };
                    if b.clicked() {
                        picked = Some(c.text.clone());
                    }
                }
            });
        }

        let mut input = t.input.clone();
        let secret = t.shell.asking_password();
        let shell_ref = &t.shell;
        let mut layouter = |ui: &egui::Ui, text: &dyn egui::TextBuffer, wrap: f32| {
            let mut job = job_of(ui, &shell_ref.highlight(text.as_str()), &font);
            job.wrap.max_width = wrap;
            ui.fonts_mut(|f| f.layout_job(job))
        };
        let row = ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 0.0;
            ui.label(job_of(ui, &prompt, &font));
            if busy {
                ui.weak("…");
            }
            let edit = TextEdit::singleline(&mut input)
                .id(iid)
                .font(TextStyle::Monospace)
                .frame(egui::Frame::NONE)
                .desired_width(f32::INFINITY)
                .lock_focus(true)
                .return_key(None);
            if secret {
                ui.add(edit.password(true))
            } else {
                ui.add(edit.layouter(&mut layouter))
            }
        });
        let edit = row.inner;
        let bottom = (ui.min_rect().bottom() - bottom_top).max(16.0);
        let cursor = egui::TextEdit::load_state(ui.ctx(), iid)
            .and_then(|s| s.cursor.char_range())
            .map(|r| usize::from(r.primary.index))
            .map(|chars| {
                input
                    .char_indices()
                    .nth(chars)
                    .map_or(input.len(), |(b, _)| b)
            })
            .unwrap_or(input.len());

        let Some(t) = self.terminals.get_mut(idx) else {
            return;
        };
        t.bottom = bottom;
        t.refocus_on_key = refocus_on_key;
        if input != t.input {
            t.input = input;
            t.suggestions = None;
            t.browse = None;
        }
        if clear {
            t.output.clear();
        }
        if copy {
            let all: String = t.output.iter().map(|l| l.text() + "\n").collect();
            ui.ctx().copy_text(all);
        }
        if escape {
            t.suggestions = None;
        }
        if let Some(h) = hist {
            t.history_step(h);
            set_cursor(ui.ctx(), iid, t.input.chars().count());
        }
        if t.focus || clicked {
            t.focus = false;
            edit.request_focus();
            set_cursor(ui.ctx(), iid, t.input.chars().count());
        }
        if let Some(text) = picked {
            let c = t.suggestions.take().map_or(cursor, |s| s.start);
            let head = t.input.get(..c.min(t.input.len())).unwrap_or("").to_owned();
            let tail = t
                .input
                .get(cursor.max(c).min(t.input.len())..)
                .unwrap_or("")
                .to_owned();
            t.input = format!("{head}{text}{tail}");
            let at = head.chars().count() + text.chars().count();
            edit.request_focus();
            set_cursor(ui.ctx(), iid, at);
        }
        if tab {
            let at = self.term_complete(idx, cursor);
            let chars = self
                .terminals
                .get(idx)
                .map_or(0, |t| t.input.get(..at).unwrap_or("").chars().count());
            set_cursor(ui.ctx(), iid, chars);
        }
        if interrupt && let Some(t) = self.terminals.get_mut(idx) {
            t.shell.interrupt();
            let echo = Line::styled(Style::Dim, "^C");
            t.print([echo]);
        }
        self.term_wake(idx, now, interrupt);
        if safe {
            self.term_safe_mode(idx);
        }
        if help {
            self.term_help(idx);
        }
        if submit {
            let line = self.terminals.get_mut(idx).filter(|t| !t.busy()).map(|t| {
                t.suggestions = None;
                std::mem::take(&mut t.input)
            });
            if let Some(line) = line {
                self.terminal_submit(idx, &line);
            }
        }
    }
}

fn set_cursor(ctx: &egui::Context, id: egui::Id, chars: usize) {
    if let Some(mut s) = TextEdit::load_state(ctx, id) {
        s.cursor
            .set_char_range(Some(CCursorRange::one(CCursor::new(chars))));
        s.store(ctx, id);
    }
}
