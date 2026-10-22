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
//! Mode (as in RouterOS; there is no cut in the terminal), Esc hides the
//! suggestions. Output is selectable; right click copies or clears it.

use corerouter_shell::{Completion, Job, Line, Reply, Request, Shell, Span, Step, Style};
use egui::text::{CCursor, CCursorRange, LayoutJob, TextFormat};
use egui::{Color32, FontId, Key, Modifiers, TextEdit, TextStyle};

use crate::{CoreRouterUi, Pending, RequestId};

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
    closed: bool,
    /// Height of the input row and suggestions last frame (reserved under
    /// the output so the window keeps its size).
    bottom: f32,
}

pub(crate) fn term_id(id: u64) -> egui::Id {
    egui::Id::unique(("corerouter-terminal", id))
}

fn input_id(id: u64) -> egui::Id {
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
        echo.0.extend(t.shell.highlight(line));
        t.print([echo]);
        t.remember(line);
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
            match t.shell.step(&mut run.job, replies) {
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
                    for r in reqs {
                        match r {
                            Request::Call { method, params } => {
                                let id = self.backend.submit(&method, params);
                                self.pending.insert(id, Pending::Terminal { term });
                                run.ids.push(Some(id));
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
        let Some(t) = self.terminals.get(idx) else {
            return;
        };
        let iid = input_id(t.id);
        let focused = ui.memory(|m| m.has_focus(iid));

        // Keys the terminal takes before the text field sees them.
        let mut submit = false;
        let mut tab = false;
        let mut hist: Option<bool> = None;
        let mut safe = false;
        let mut help = false;
        let mut escape = false;
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
                // Ctrl+X arrives as Cut from a real keyboard.
                let before = i.events.len();
                i.events.retain(|e| !matches!(e, egui::Event::Cut));
                safe = before != i.events.len() || i.consume_key(Modifiers::COMMAND, Key::X);
                let quotes_open = t.input.matches('"').count() % 2 == 1;
                if !quotes_open {
                    let before = i.events.len();
                    i.events
                        .retain(|e| !matches!(e, egui::Event::Text(s) if s == "?"));
                    help = before != i.events.len();
                }
                help |= f1;
            });
        }

        let busy = t.busy();
        let prompt = t.shell.prompt();
        let output_height = (ui.available_height() - t.bottom - 6.0).max(40.0);
        let mut clear = false;
        let mut copy = false;
        egui::ScrollArea::vertical()
            .id_salt(("terminal-output", t.id))
            .max_height(output_height)
            .auto_shrink([false, false])
            .stick_to_bottom(true)
            .show(ui, |ui| {
                ui.spacing_mut().item_spacing.y = 0.0;
                for line in &t.output {
                    let job = job_of(ui, &line.0, &font);
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
            ui.add(
                TextEdit::singleline(&mut input)
                    .id(iid)
                    .font(TextStyle::Monospace)
                    .frame(egui::Frame::NONE)
                    .desired_width(f32::INFINITY)
                    .lock_focus(true)
                    .return_key(None)
                    .layouter(&mut layouter),
            )
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
        if t.focus {
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
