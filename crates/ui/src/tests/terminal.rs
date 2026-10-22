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
