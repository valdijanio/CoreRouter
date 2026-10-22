//! G0.8: the "New Terminal" window, driven with synthetic events through
//! the real UI (local lab backend; the remote one answers the same calls).

use super::*;
use egui::Key;

const NONE: egui::Modifiers = egui::Modifiers::NONE;

impl Harness {
    /// Open a terminal from the side menu and focus its input.
    fn open_terminal(&mut self) -> usize {
        let n = self.app.terminal_count();
        let at = self.text("New Terminal");
        self.click(at);
        assert_eq!(self.app.terminal_count(), n + 1);
        for _ in 0..3 {
            self.idle();
        }
        n
    }

    fn input(&self, n: usize) -> String {
        self.app.terminals[n].input.clone()
    }

    fn enter(&mut self, line: &str) {
        self.type_text(line);
        self.key(Key::Enter, NONE);
        for _ in 0..3 {
            self.idle();
        }
    }
}

#[test]
fn new_terminal_runs_commands_through_the_backend() {
    let mut h = Harness::new();
    let t = h.open_terminal();
    let banner = h.app.terminal_text(t);
    assert!(banner.contains("CoreRouter"), "{banner}");
    assert!(
        h.has_text_containing("[admin@CoreRouter] >"),
        "prompt drawn"
    );

    h.enter("/ip address add address=10.0.0.1/24 interface=ether1");
    assert_eq!(lock(&h.session).store().running().ip.addresses.len(), 1);
    h.enter("/ip address print");
    let out = h.app.terminal_text(t);
    assert!(out.contains(" 0   10.0.0.1/24"), "{out}");
    assert!(h.has_text_containing("10.0.0.1/24"));
    // The Addresses window sees it on its next refresh.
    assert_eq!(h.input(t), "");

    // Engine errors come as they are.
    h.enter("/ip address add address=10.0.0.2/24 interface=nope");
    assert!(h.app.terminal_text(t).contains("no interface 'nope'"));
}

#[test]
fn history_tab_help_and_ctrl_x() {
    let mut h = Harness::new();
    let t = h.open_terminal();
    h.enter("/system identity set name=lab1");
    h.enter("/ip address print");
    h.key(Key::ArrowUp, NONE);
    assert_eq!(h.input(t), "/ip address print");
    h.key(Key::ArrowUp, NONE);
    assert_eq!(h.input(t), "/system identity set name=lab1");
    h.key(Key::ArrowDown, NONE);
    h.key(Key::ArrowDown, NONE);
    assert_eq!(h.input(t), "");

    // Tab: one candidate is inserted, several are listed.
    h.type_text("/ip addr");
    h.key(Key::Tab, NONE);
    assert_eq!(h.input(t), "/ip address ");
    h.type_text("add int");
    h.key(Key::Tab, NONE);
    assert_eq!(h.input(t), "/ip address add interface=");
    h.type_text("eth");
    h.key(Key::Tab, NONE);
    assert_eq!(h.input(t), "/ip address add interface=ether");
    assert!(h.app.terminals[t].suggestions.is_some());
    assert!(h.has_text("ether7"), "suggestions are drawn");
    // Clicking one inserts it.
    let at = h.text("ether7");
    h.click(at);
    assert_eq!(h.input(t), "/ip address add interface=ether7 ");

    // `?` shows help at once and keeps the line.
    h.type_text("?");
    for _ in 0..3 {
        h.idle();
    }
    assert!(h.app.terminal_text(t).contains("Add Address"));
    assert_eq!(h.input(t), "/ip address add interface=ether7 ");

    // Ctrl+X (a real keyboard sends Cut): Safe Mode, prompt says so.
    h.frame(vec![egui::Event::Cut], CTRL);
    for _ in 0..3 {
        h.idle();
    }
    assert!(lock(&h.session).in_safe_mode());
    assert!(h.app.terminal_text(t).contains("[Safe Mode taken]"));
    assert!(h.has_text_containing("<SAFE>"));
    assert_eq!(
        h.input(t),
        "/ip address add interface=ether7 ",
        "the line stays"
    );
    h.key(Key::X, CTRL);
    for _ in 0..3 {
        h.idle();
    }
    assert!(!lock(&h.session).in_safe_mode());
}

#[test]
fn several_terminals_paste_and_quit() {
    let mut h = Harness::new();
    let a = h.open_terminal();
    let b = h.open_terminal();
    assert_ne!(a, b);
    h.app.terminal_submit(a, "/ip");
    h.app.terminal_submit(b, "/interface");
    for _ in 0..3 {
        h.idle();
    }
    assert_eq!(h.app.terminals[a].shell.cwd(), ["ip"]);
    assert_eq!(h.app.terminals[b].shell.cwd(), ["interface"]);
    // A pasted script is one atomic batch.
    h.app.terminal_submit(
        a,
        "/interface bridge\nadd name=br7\n/interface vlan\nadd name=v7 parent=br7 vlan-id=7\n",
    );
    for _ in 0..3 {
        h.idle();
    }
    assert!(h.app.terminal_text(a).contains("one atomic batch"));
    assert!(lock(&h.session).store().running().interfaces.len() >= 10);
    h.app.terminal_submit(b, "/quit");
    for _ in 0..3 {
        h.idle();
    }
    assert_eq!(h.app.terminal_count(), 1);
}

/// A router whose `ping` starts a task that answers one reply per poll.
#[derive(Default)]
struct PingRouter {
    next: RequestId,
    replies: Vec<Reply>,
    emitted: u64,
    stopped: bool,
    stops: usize,
}

struct Ping(std::rc::Rc<std::cell::RefCell<PingRouter>>);

impl Backend for Ping {
    fn submit(&mut self, method: &str, params: Value) -> RequestId {
        let mut r = self.0.borrow_mut();
        r.next += 1;
        let cmd = params["command"].as_str().unwrap_or_default().to_owned();
        let reply = match (method, cmd.as_str()) {
            ("engine.list", _) => Ok(json!([
                {"id": "tool.ping.start", "label": "Ping", "params": "{address: string, count?: u32} → {id}",
                 "kind": "action", "enabled": true, "alias": "ping", "positional": "address", "task": true},
                {"id": "tool.task.poll", "label": "Poll", "params": "{id: u64, after_seq?: u64} → {}", "kind": "query", "enabled": true},
                {"id": "tool.task.stop", "label": "Stop", "params": "{id: u64} → {}", "kind": "action", "enabled": true},
            ])),
            ("state.inspect", _) => Ok(json!({"identity": "sim"})),
            ("server.info", _) => Ok(json!({"version": "sim"})),
            ("engine.execute", "tool.ping.start") => Ok(json!({"id": 1})),
            ("engine.execute", "tool.task.stop") => {
                r.stopped = true;
                r.stops += 1;
                Ok(json!({"id": 1}))
            }
            ("engine.execute", "tool.task.poll") => {
                let mut events = Vec::new();
                if !r.stopped {
                    r.emitted += 1;
                    events.push(json!({"seq": r.emitted, "host": "8.8.8.8", "time": "1ms"}));
                }
                Ok(
                    json!({"done": r.stopped, "state": if r.stopped {"stopped"} else {"running"},
                          "events": events, "next_seq": r.emitted,
                          "summary": {"sent": r.emitted}}),
                )
            }
            ("engine.execute", _) => Ok(json!([])),
            _ => Ok(json!({})),
        };
        let id = r.next;
        r.replies.push((id, reply));
        id
    }

    fn poll(&mut self) -> Vec<Reply> {
        std::mem::take(&mut self.0.borrow_mut().replies)
    }

    fn link(&self) -> Link {
        Link::Connected {
            target: "sim:1".into(),
        }
    }
}

#[test]
fn ping_streams_live_and_ctrl_c_stops_it() {
    let router = std::rc::Rc::new(std::cell::RefCell::new(PingRouter::default()));
    let mut app = CoreRouterUi::with_backend(Box::new(Ping(router.clone())));
    let ctx = egui::Context::default();
    let mut time = 0.0;
    let mut frame = |app: &mut CoreRouterUi, events: Vec<egui::Event>| {
        let raw = egui::RawInput {
            time: Some(time),
            events,
            ..Default::default()
        };
        time += 0.05;
        ctx.run_ui(raw, |ui| app.ui(ui))
            .drop_without_applying_deltas();
    };
    app.new_terminal();
    for _ in 0..3 {
        frame(&mut app, Vec::new());
    }
    app.terminal_submit(0, "ping 8.8.8.8");
    // Events arrive while the job runs (one poll every 250 ms).
    for _ in 0..30 {
        frame(&mut app, Vec::new());
    }
    let text = app.terminal_text(0);
    assert!(text.contains("SEQ") && text.contains("8.8.8.8"), "{text}");
    assert!(app.terminals[0].busy(), "still pinging");
    let lines_before = text.lines().count();
    for _ in 0..12 {
        frame(&mut app, Vec::new());
    }
    assert!(
        app.terminal_text(0).lines().count() > lines_before,
        "live lines keep coming"
    );
    // Ctrl+C (Copy from a real keyboard) in the focused input stops it.
    frame(&mut app, vec![egui::Event::Copy]);
    for _ in 0..10 {
        frame(&mut app, Vec::new());
    }
    assert_eq!(router.borrow().stops, 1);
    assert!(!app.terminals[0].busy());
    let text = app.terminal_text(0);
    assert!(text.contains("^C") && text.contains("sent:"), "{text}");
}

/// A wide `print` fits the window (like RouterOS) instead of stretching it:
/// the columns that do not fit are named on a last line.
#[test]
fn wide_print_does_not_stretch_the_window() {
    let mut h = Harness::new();
    let t = h.open_terminal();
    let id = crate::terminal::term_id(h.app.terminals[t].id);
    let before = h.win_rect(id).width();
    h.enter("/ip firewall defaults apply wan=ether1 lan=ether2");
    h.enter("/ip firewall filter print");
    for _ in 0..5 {
        h.idle();
    }
    let after = h.win_rect(id).width();
    assert!(
        (after - before).abs() < 1.0,
        "window grew from {before} to {after}"
    );
    let out = h.app.terminal_text(t);
    assert!(out.contains("more column"), "{out}");
}

/// G0.8b: a line wider than the window wraps at its width (no sideways
/// scrolling), wraps again when the window is resized, and copies back as
/// the original line.
#[test]
fn long_lines_wrap_at_the_window_width() {
    let mut h = Harness::new();
    let t = h.open_terminal();
    let id = crate::terminal::term_id(h.app.terminals[t].id);
    let before = h.win_rect(id);
    let long = format!("/ip address print where comment=\"{}\"", "x".repeat(300));
    h.enter(&long);
    for _ in 0..3 {
        h.idle();
    }
    // Stored as typed; shown in rows that start with the mark.
    assert!(h.app.terminal_text(t).contains(&long));
    assert!(h.has_text_containing("\u{21b3} "), "the echo wraps");
    let after = h.win_rect(id);
    assert!(
        (after.width() - before.width()).abs() < 1.0,
        "window grew from {before:?} to {after:?}"
    );
    // Nothing drawn past the window's right edge: no sideways scrolling.
    let right = |h: &Harness| {
        let rects = text_rects(h, "xxxxxxxx");
        assert!(!rects.is_empty(), "the line is drawn");
        rects.iter().map(|r| r.right()).fold(f32::MIN, f32::max)
    };
    assert!(right(&h) < after.right(), "text past the edge");
    let rows = |h: &Harness| {
        h.app.terminals[t]
            .shell
            .width()
            .and_then(|cols| {
                let echo = h.app.terminals[t]
                    .output
                    .iter()
                    .find(|l| l.text().contains("xxxx"))?;
                Some(crate::terminal::wrapped(&echo.0, cols))
            })
            .unwrap()
            .iter()
            .filter(|s| s.text == crate::terminal::WRAP)
            .count()
    };
    let wide_rows = rows(&h);
    assert!(wide_rows >= 2, "{wide_rows}");

    // Narrower window: the same line takes more rows.
    let corner = after.right_bottom() - egui::vec2(2.0, 2.0);
    h.drag(corner, egui::vec2(-300.0, 0.0));
    for _ in 0..3 {
        h.idle();
    }
    let narrow = h.win_rect(id);
    assert!(narrow.width() < after.width() - 100.0, "{narrow:?}");
    assert!(rows(&h) > wide_rows, "{} vs {wide_rows}", rows(&h));
    assert!(right(&h) < narrow.right(), "text past the edge");
}

#[test]
fn wrap_breaks_after_spaces_and_unwraps_exactly() {
    use corerouter_shell::{Line, Style};
    use crate::terminal::{WRAP, wrapped};
    let line = Line::new()
        .with(Style::Error, "failure: no interface 'ether99' ")
        .with(Style::Dim, "(did you mean ether9?)");
    let text = line.text();
    for cols in [10, 17, 24, 40] {
        let spans = wrapped(&line.0, cols);
        let shown: String = spans.iter().map(|s| s.text.as_str()).collect();
        for (i, row) in shown.split('\n').enumerate() {
            assert!(row.chars().count() <= cols, "{cols}: {row:?}");
            assert_eq!(i > 0, row.starts_with("\u{21b3} "), "{row:?}");
        }
        assert_eq!(shown.replace(WRAP, ""), text, "{cols}");
    }
    // Colors stay with their characters.
    let spans = wrapped(&line.0, 20);
    assert!(spans.iter().any(|s| s.style == Style::Error && s.text.contains("failure")));
    assert!(spans.iter().any(|s| s.style == Style::Dim && s.text.contains("ether9?")));
    // Short enough: unchanged.
    assert_eq!(wrapped(&line.0, 200), line.0);
}

/// Copying a selection of wrapped rows gives the original line back.
#[test]
fn copy_takes_the_display_wraps_out() {
    let ctx = egui::Context::default();
    ctx.add_plugin(crate::terminal::UnwrapCopy);
    let wrapped = format!("abc {}def", crate::terminal::WRAP);
    let mut out = ctx.run_ui(egui::RawInput::default(), |ui| {
        ui.ctx().copy_text(wrapped.clone())
    });
    out.textures_delta.clear();
    let copied: Vec<&str> = out
        .platform_output
        .commands
        .iter()
        .filter_map(|c| match c {
            egui::OutputCommand::CopyText(t) => Some(t.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(copied, ["abc def"]);
}

#[test]
fn the_wrap_mark_has_a_glyph() {
    let ctx = egui::Context::default();
    ctx.run_ui(egui::RawInput::default(), |_| {})
        .textures_delta
        .clear();
    let font = egui::FontId::monospace(12.0);
    assert!(ctx.fonts_mut(|f| f.has_glyph(&font, '\u{21b3}')));
}

/// A click anywhere in the output puts the focus back on the input; a drag
/// selects text without taking it, and the next key goes to the input.
#[test]
fn click_in_the_output_focuses_the_input() {
    let mut h = Harness::new();
    let t = h.open_terminal();
    h.enter("/system identity print");
    let iid = crate::terminal::input_id(h.app.terminals[t].id);
    let focused = |h: &Harness| h.ctx.memory(|m| m.has_focus(iid));
    assert!(focused(&h));

    // Focus lost (a click on the desktop), then a click on empty output.
    h.click(egui::pos2(1300.0, 850.0));
    assert!(!focused(&h));
    let win = h.win_rect(crate::terminal::term_id(h.app.terminals[t].id));
    h.click(win.center());
    assert!(focused(&h), "a click in the output focuses the input");
    h.type_text("/ip");
    assert_eq!(h.input(t), "/ip");

    // A drag over the banner selects it and keeps the selection.
    let banner = text_rects(&h, "Tab completes")[0];
    let at = egui::pos2(banner.left() + 4.0, banner.center().y);
    h.drag(at, egui::vec2(120.0, 0.0));
    let selected = |h: &Harness| {
        h.ctx
            .plugin::<egui::text_selection::LabelSelectionState>()
            .lock()
            .has_selection()
    };
    assert!(selected(&h), "the drag selected text");
    h.idle();
    assert!(selected(&h), "the selection stays");
    // The next key goes to the input.
    h.type_text(" a");
    assert!(focused(&h));
    assert_eq!(h.input(t), "/ip a");
}

/// Where the text shapes containing `needle` are drawn.
fn text_rects(h: &Harness, needle: &str) -> Vec<egui::Rect> {
    fn find(shape: &egui::Shape, needle: &str, out: &mut Vec<egui::Rect>) {
        match shape {
            egui::Shape::Text(t) if t.galley.text().contains(needle) => {
                out.push(t.visual_bounding_rect());
            }
            egui::Shape::Vec(v) => v.iter().for_each(|s| find(s, needle, out)),
            _ => {}
        }
    }
    let mut out = Vec::new();
    for s in &h.shapes {
        find(&s.shape, needle, &mut out);
    }
    out
}
