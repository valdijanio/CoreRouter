//! audit-gui: lost replies, big lists and long values, and windows drawn
//! with data (not only over an empty lab).

use super::*;

/// The UI over a router that never answers, drawn at UI time `t`.
struct Mute {
    ctx: egui::Context,
    app: CoreRouterUi,
    wire: Rc<RefCell<Wire>>,
    shapes: Vec<egui::epaint::ClippedShape>,
}

impl Mute {
    fn new() -> Self {
        let wire = Rc::new(RefCell::new(Wire {
            link: Some(Link::Connected {
                target: "r1:7979".into(),
            }),
            ..Wire::default()
        }));
        Self {
            ctx: egui::Context::default(),
            app: CoreRouterUi::with_backend(Box::new(Scripted(wire.clone()))),
            wire,
            shapes: Vec::new(),
        }
    }

    fn at(&mut self, t: f64) {
        let raw = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(1400.0, 900.0),
            )),
            time: Some(t),
            ..Default::default()
        };
        let app = &mut self.app;
        let mut out = self.ctx.run_ui(raw, |ui| app.ui(ui));
        out.textures_delta.clear();
        self.shapes = out.shapes;
    }

    fn sent(&self, command: &str) -> usize {
        self.wire
            .borrow()
            .sent
            .iter()
            .filter(|(_, m, p)| m == command || p["command"] == command)
            .count()
    }

    fn texts(&self) -> Vec<String> {
        fn walk(shape: &egui::Shape, out: &mut Vec<String>) {
            match shape {
                egui::Shape::Text(t) => out.push(t.galley.text().to_owned()),
                egui::Shape::Vec(v) => v.iter().for_each(|s| walk(s, out)),
                _ => {}
            }
        }
        let mut out = Vec::new();
        for s in &self.shapes {
            walk(&s.shape, &mut out);
        }
        out
    }
}

#[test]
fn a_lost_query_reply_does_not_freeze_the_refresh() {
    let mut m = Mute::new();
    m.at(0.0);
    assert_eq!(m.sent("interface.list"), 1);
    // One refresh at a time: while it waits, no new one.
    for t in [1.0, 5.0, 20.0] {
        m.at(t);
    }
    assert_eq!(m.sent("interface.list"), 1);
    assert!(!m.texts().iter().any(|t| t == "stale"));
    // The reply never comes: after the timeout the UI asks again and says
    // its lists may be out of date.
    m.at(QUERY_TIMEOUT_SECS + 0.5);
    m.at(QUERY_TIMEOUT_SECS + 1.0);
    assert_eq!(m.sent("interface.list"), 2, "asked again");
    assert!(m.texts().iter().any(|t| t == "stale"), "{:?}", m.texts());
    assert!(m.app.log().iter().any(|l| l.command == "refresh" && !l.ok));
    // An answer clears it.
    let id = m.wire.borrow().last("interface.list");
    m.wire.borrow_mut().replies.push((id, Ok(json!([]))));
    m.at(QUERY_TIMEOUT_SECS + 1.5);
    assert!(m.app.stale.is_none());
}

#[test]
fn a_lost_poll_polls_again_and_a_lost_action_is_released() {
    let mut m = Mute::new();
    m.app.ping.ping = Some(ping::TaskView::new(7));
    m.at(0.0);
    m.at(1.5);
    let polls = m.sent("tool.task.poll");
    assert!(polls >= 1);
    m.at(10.0);
    assert_eq!(m.sent("tool.task.poll"), polls, "one poll at a time");
    m.at(1.5 + QUERY_TIMEOUT_SECS + 1.0);
    m.at(1.5 + QUERY_TIMEOUT_SECS + 3.0);
    assert!(m.sent("tool.task.poll") > polls, "polled again");
    assert!(
        m.app.ping.ping.as_ref().is_some_and(|t| t.running()),
        "a lost poll does not end the ping"
    );

    m.app.run("system.identity.set", json!({"name": "r1"}));
    m.at(200.0);
    assert_eq!(m.app.busy(), 1);
    m.at(200.0 + ACTION_TIMEOUT_SECS + 1.0);
    assert_eq!(m.app.busy(), 0, "no longer waiting");
    let last = m.app.log().last().unwrap();
    assert!(!last.ok && last.message.contains("no answer"), "{last:?}");
}

#[test]
fn a_hostile_lost_counter_saturates() {
    let mut t = ping::TaskView::new(1);
    t.absorb(&json!({"lost": u64::MAX}));
    t.absorb(&json!({"lost": u64::MAX}));
    assert_eq!(t.lost, u64::MAX);
}

/// A lab with data in every list the windows below show, with long
/// comments (a 4 kB one) and many items.
fn busy_lab() -> Session {
    let mut s = Session::virtual_lab();
    // The engine takes comments of up to 256 characters.
    let long = "a long comment ".repeat(16);
    let mut run = |id: &str, p: Value| {
        s.execute(id, &p).unwrap_or_else(|e| panic!("{id} {p}: {e}"));
    };
    for i in 0..100 {
        run(
            "ip.address.add",
            json!({"address": format!("10.1.{}.{}/32", i / 250, i % 250 + 1), "interface": "ether2", "comment": long}),
        );
    }
    run(
        "ip.route.add",
        json!({"dst_address": "192.0.2.0/24", "gateway": "ether2", "comment": long}),
    );
    run("ip.vrf.add", json!({"name": "cust-a", "interfaces": "ether3", "comment": long}));
    run(
        "ip.firewall.filter.add",
        json!({"in_interface_list": "!LAN", "action": "drop", "comment": long}),
    );
    run("ip.pool.add", json!({"name": "p1", "ranges": "10.9.0.10-10.9.0.200"}));
    run("ip.address.add", json!({"address": "10.9.0.1/24", "interface": "ether4"}));
    run(
        "ip.dhcp-server.add",
        json!({"name": "dhcp1", "interface": "ether4", "address_pool": "p1", "relay_info_trusted": true}),
    );
    s
}

#[test]
fn every_window_renders_with_data_and_long_values() {
    let mut h = Harness::with_session(busy_lab());
    h.app.open_all();
    h.app.new_terminal();
    h.app.cache.refreshed_at = None;
    for _ in 0..4 {
        h.idle();
    }
    let mut texts = Vec::new();
    fn walk(shape: &egui::Shape, out: &mut Vec<String>) {
        match shape {
            egui::Shape::Text(t) => out.push(t.galley.text().to_owned()),
            egui::Shape::Vec(v) => v.iter().for_each(|s| walk(s, out)),
            _ => {}
        }
    }
    for s in &h.shapes {
        walk(&s.shape, &mut texts);
    }
    // No cell is drawn whole: the 4 kB comment ends in "…".
    let longest = texts.iter().map(|t| t.chars().count()).max().unwrap_or(0);
    assert!(longest <= 600, "a text of {longest} chars drawn");
    assert!(texts.iter().any(|t| t.ends_with('…')));
    // No value in brackets (docs/ui-style.md).
    let bracketed: Vec<&String> = texts
        .iter()
        .filter(|t| t.contains("[LAN]") || t.contains("![") || t.contains(" [private]"))
        .collect();
    assert!(bracketed.is_empty(), "{bracketed:?}");
}

#[test]
fn every_interface_tab_renders_with_data() {
    let mut h = Harness::new();
    let at = h.row("ether2");
    h.click(at);
    h.click(at);
    assert!(h.has_text("Interface <ether2>"));
    for tab in crate::iface_tabs::Tab::ALL {
        if let Some(interfaces::Dialog::Props(p)) = h.app.dialogs.first_mut().map(|d| &mut d.dialog)
        {
            p.tab = tab;
        }
        // A few seconds of samples, so the traffic graph has points.
        for _ in 0..4 {
            h.time += 1.1;
            h.idle();
        }
        assert!(h.has_text(tab.label()), "tab {tab:?}");
    }
    assert!(h.has_text("link-ok") || h.has_text("no-link") || h.has_text("Traffic"));
}

#[test]
fn a_full_terminal_lays_out_only_what_is_in_view() {
    let mut h = Harness::new();
    h.app.open.clear();
    h.app.new_terminal();
    let line = "x ".repeat(100);
    let huge = "y".repeat(200_000);
    if let Some(t) = h.app.terminals.first_mut() {
        t.print(std::iter::once(corerouter_shell::Line::plain(&huge)));
        t.print((0..6000).map(|_| corerouter_shell::Line::plain(&line)));
        t.print(std::iter::once(corerouter_shell::Line::plain(&huge)));
    }
    h.idle();
    h.idle();
    let t = h.app.terminals.first().unwrap();
    assert_eq!(t.output.len(), 5000);
    let cut = t
        .output
        .iter()
        .map(corerouter_shell::Line::text)
        .find(|l| l.starts_with("yyy"))
        .unwrap();
    assert_eq!(cut.chars().count(), crate::terminal::MAX_LINE_CHARS + 1, "cut");
    assert!(cut.ends_with('…'));
    let mut labels = 0;
    fn walk(shape: &egui::Shape, n: &mut usize) {
        match shape {
            egui::Shape::Text(t)
                if t.galley.text().starts_with("x x") || t.galley.text().starts_with("yyy") =>
            {
                *n += 1;
            }
            egui::Shape::Vec(v) => v.iter().for_each(|s| walk(s, n)),
            _ => {}
        }
    }
    for s in &h.shapes {
        walk(&s.shape, &mut labels);
    }
    assert!(labels > 0, "the end of the output is in view");
    assert!(labels < 200, "{labels} lines laid out");
    // The whole output is still there to copy.
    assert_eq!(h.app.terminal_text(0).lines().count(), 5000);
}
