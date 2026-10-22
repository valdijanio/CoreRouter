//! G1.20: the internal windows as a hierarchy (a dialog belongs to the
//! list it was opened from), driven with synthetic events through the real
//! UI: asking again brings a dialog to the front, a child opens over its
//! parent and stays above it, closing the parent closes (or asks about) its
//! children, and Ctrl+Tab goes through the windows.

use super::*;
use crate::firewall::Feed;
use crate::float::{CHILD_OFFSET, CHILD_STEP};
use egui::Key;

const NONE: egui::Modifiers = egui::Modifiers::NONE;
const CTRL_SHIFT: egui::Modifiers = egui::Modifiers {
    alt: false,
    ctrl: true,
    shift: true,
    mac_cmd: false,
    command: true,
};

fn ifaces() -> egui::Id {
    win_id(Win::Interfaces)
}

impl Harness {
    fn props_win(&self, name: &str) -> egui::Id {
        let d = self
            .app
            .dialogs
            .iter()
            .find(|d| matches!(&d.dialog, interfaces::Dialog::Props(p) if p.name == name))
            .unwrap_or_else(|| panic!("{name} not open"));
        interfaces::dialog_id(d.id)
    }

    fn props_open(&self, name: &str) -> usize {
        self.app
            .dialogs
            .iter()
            .filter(|d| matches!(&d.dialog, interfaces::Dialog::Props(p) if p.name == name))
            .count()
    }

    /// The windows on screen, back to front.
    fn order(&self) -> Vec<egui::Id> {
        self.ctx.memory(|m| {
            m.layer_ids()
                .filter(|l| l.order == egui::Order::Middle && m.areas().is_visible(l))
                .map(|l| l.id)
                .collect()
        })
    }

    fn top(&self) -> Option<egui::Id> {
        self.order().last().copied()
    }

    fn above(&self, a: egui::Id, b: egui::Id) -> bool {
        let order = self.order();
        let at = |id| order.iter().position(|l| *l == id);
        matches!((at(a), at(b)), (Some(a), Some(b)) if a > b)
    }

    /// A point of window `id` that no other window covers, where a click
    /// only brings the window up: its title bar, else the margin along its
    /// right edge.
    fn spot(&self, id: egui::Id) -> egui::Pos2 {
        let strip = self.title_bar(id).strip;
        let rect = self.win_rect(id);
        let layer = egui::LayerId::new(egui::Order::Middle, id);
        let along = (0..=20).map(|i| i as f32 / 20.0);
        along
            .clone()
            .map(|t| egui::pos2(strip.left() + strip.width() * t, strip.center().y))
            .chain(along.map(|t| {
                egui::pos2(
                    rect.right() - 4.0,
                    strip.bottom() + (rect.bottom() - strip.bottom()) * t,
                )
            }))
            .find(|p| self.ctx.layer_id_at(*p) == Some(layer))
            .unwrap_or_else(|| panic!("window {id:?} is covered"))
    }

    fn double_click(&mut self, pos: egui::Pos2) {
        let ev = |pressed| egui::Event::PointerButton {
            pos,
            button: egui::PointerButton::Primary,
            pressed,
            modifiers: NONE,
        };
        self.frame(vec![egui::Event::PointerMoved(pos)], NONE);
        self.frame(vec![ev(true), ev(false)], NONE);
        self.frame(vec![ev(true), ev(false)], NONE);
        self.idle();
        self.idle();
    }

    fn close_button(&self, id: egui::Id) -> egui::Pos2 {
        self.title_bar(id).close.center()
    }

    /// Let the border flash run out.
    fn settle(&mut self) {
        for _ in 0..40 {
            self.idle();
        }
    }
}

#[test]
fn asking_again_brings_the_dialog_to_the_front() {
    let mut h = Harness::new();
    h.app.open_props("ether1");
    h.idle();
    h.app.open_props("ether2");
    h.idle();
    h.idle();
    let (e1, e2) = (h.props_win("ether1"), h.props_win("ether2"));
    assert_eq!(h.top(), Some(e2), "opened last: in front");
    assert!(!h.app.floats.is_flashing(e2), "a new window does not flash");

    // A double click on ether1's row (its left end: the dialogs open to
    // the right of the list's edge) asks for it again.
    let row = h
        .ctx
        .read_response(table::row_id(interfaces::TABLE, "ether1"))
        .unwrap()
        .rect;
    h.double_click(egui::pos2(row.left() + 12.0, row.center().y));
    assert_eq!(h.props_open("ether1"), 1, "not duplicated");
    assert_eq!(h.top(), Some(e1), "brought to the front");
    assert!(h.app.floats.is_flashing(e1), "its border flashes");
    h.settle();
    assert!(!h.app.floats.is_flashing(e1), "only for a moment");

    // It has the keyboard: Esc closes it, not the one opened last.
    h.key(Key::Escape, NONE);
    assert_eq!(h.props_open("ether1"), 0);
    assert_eq!(h.props_open("ether2"), 1);

    // Enter on the table asks again too.
    h.app.open_props("ether1");
    h.idle();
    h.idle();
    let e1 = h.props_win("ether1");
    h.click(h.spot(e2));
    h.click(egui::pos2(row.left() + 12.0, row.center().y));
    assert!(h.above(e2, e1), "the family came up in its own order");
    h.key(Key::Enter, NONE);
    h.idle();
    assert_eq!(h.props_open("ether1"), 1);
    assert_eq!(h.top(), Some(e1));
}

#[test]
fn a_child_opens_over_its_parent() {
    let mut h = Harness::new();
    h.app.open_props("ether1");
    h.idle();
    h.app.open_props("ether2");
    h.idle();
    h.idle();
    let parent = h.win_rect(ifaces()).min;
    let (e1, e2) = (h.props_win("ether1"), h.props_win("ether2"));
    assert_eq!(h.app.floats.parent(e1), Some(ifaces()));
    let first = h.win_rect(e1).min;
    let second = h.win_rect(e2).min;
    assert!(
        (first - (parent + CHILD_OFFSET)).length() < 1.0,
        "{first:?}"
    );
    assert!(
        (second - (first + egui::Vec2::splat(CHILD_STEP))).length() < 1.0,
        "the next one a step further: {second:?}"
    );

    // The list's toolbar stays in reach above its dialogs.
    let add = h.tool(table::Icon::Add);
    let layer = egui::LayerId::new(egui::Order::Middle, ifaces());
    assert_eq!(h.ctx.layer_id_at(add), Some(layer));

    // Without its list open a dialog has no parent and opens on its own.
    h.app.open.remove(&Win::Interfaces);
    h.idle();
    h.app.open_props("ether3");
    h.idle();
    h.idle();
    assert_eq!(h.app.floats.parent(h.props_win("ether3")), None);
}

#[test]
fn raising_the_parent_raises_its_children() {
    let mut h = Harness::new();
    h.app.open_props("ether1");
    h.idle();
    h.idle();
    let e1 = h.props_win("ether1");
    h.app.open(Win::Addresses);
    h.idle();
    h.idle();
    let addresses = win_id(Win::Addresses);
    assert_eq!(h.top(), Some(addresses));

    // A click on the list brings it up, and its dialog with it, above.
    h.click(h.spot(ifaces()));
    assert!(h.above(ifaces(), addresses), "the list came up");
    assert!(h.above(e1, ifaces()), "its dialog stays above it");
    assert_eq!(h.top(), Some(e1));

    // The keyboard stays with the list that was clicked (like the owner
    // of an owned window): Esc clears its selection, not the dialog.
    h.app.tables.interfaces.select_only("ether2");
    h.key(Key::Escape, NONE);
    assert!(!h.app.tables.interfaces.is_selected("ether2"));
    assert_eq!(h.props_open("ether1"), 1);

    // The menu asks for the open list again: up with its dialog.
    h.click(h.spot(addresses));
    assert!(h.above(addresses, e1));
    h.app.floats.raise(ifaces());
    h.idle();
    h.idle();
    assert!(h.above(ifaces(), addresses));
    assert!(h.above(e1, ifaces()));
}

#[test]
fn every_dialog_belongs_to_its_list() {
    let mut h = Harness::routes();
    lock(&h.session)
        .execute(
            "ip.route.add",
            &json!({"dst_address": "0.0.0.0/0", "gateway": "10.0.0.1"}),
        )
        .unwrap();
    h.app.cache.refreshed_at = None;
    h.idle();
    h.idle();
    h.app.open_route("*1");
    h.idle();
    h.app.open_route("*1");
    h.idle();
    assert_eq!(h.app.route_dialogs.len(), 1);
    let id = interfaces::dialog_id(h.app.route_dialogs[0].id);
    assert_eq!(h.app.floats.parent(id), Some(win_id(Win::Routes)));
    assert!(h.app.floats.is_flashing(id));

    let mut h = Harness::vrfs();
    h.app.open_vrf("blue");
    h.idle();
    h.app.open_vrf("blue");
    h.idle();
    assert_eq!(h.app.vrf_dialogs.len(), 1);
    let id = interfaces::dialog_id(h.app.vrf_dialogs[0].id);
    assert_eq!(h.app.floats.parent(id), Some(win_id(Win::Vrf)));
    assert!(h.app.floats.is_flashing(id));

    let mut h = Harness::new();
    lock(&h.session)
        .execute("ip.firewall.filter.add", &json!({"action": "drop"}))
        .unwrap();
    h.app.open.clear();
    h.app.open(Win::Firewall);
    h.app.open(Win::InterfaceList);
    h.app.cache.refreshed_at = None;
    h.idle();
    h.idle();
    let rule = h.app.fw_rows(Feed::Filter)[0]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let list = h.app.fw_rows(Feed::Lists)[0]["name"]
        .as_str()
        .unwrap()
        .to_owned();
    h.app.open_fw(Feed::Filter, &rule);
    h.app.open_fw(Feed::Lists, &list);
    h.idle();
    h.app.open_fw(Feed::Filter, &rule);
    h.idle();
    assert_eq!(h.app.fw.dialogs.len(), 2);
    let parents: Vec<_> = h
        .app
        .fw
        .dialogs
        .iter()
        .map(|d| h.app.floats.parent(interfaces::dialog_id(d.id)))
        .collect();
    assert_eq!(
        parents,
        [
            Some(win_id(Win::Firewall)),
            Some(win_id(Win::InterfaceList))
        ]
    );
    let rule_win = interfaces::dialog_id(h.app.fw.dialogs[0].id);
    assert!(h.app.floats.is_flashing(rule_win));
}

#[test]
fn closing_the_parent_closes_its_clean_children() {
    let mut h = Harness::new();
    h.app.open_props("ether1");
    h.app
        .interface_act(interfaces::Act::NewVlan { parent: None }, &[]);
    h.idle();
    h.idle();
    assert_eq!(h.app.dialogs.len(), 2);
    h.click(h.close_button(ifaces()));
    assert!(!h.app.open.contains(&Win::Interfaces));
    assert!(h.app.dialogs.is_empty(), "closed with their list");
    assert!(!h.has_text("Close Interfaces?"), "nothing to ask");
}

#[test]
fn closing_the_parent_with_edits_asks_first() {
    let mut h = Harness::new();
    h.app.open_props("ether2");
    h.idle();
    h.app.open_props("ether1");
    h.idle();
    h.idle();
    let (e1, e2) = (h.props_win("ether1"), h.props_win("ether2"));
    let at = h
        .ctx
        .read_response(dialog::field_id(e1, "mtu"))
        .unwrap()
        .rect
        .center();
    h.click(at);
    h.key(Key::A, CTRL);
    h.type_text("1400");
    assert!(h.has_text("Interface <ether1> •"));
    h.click(h.spot(e2));
    assert_eq!(h.top(), Some(e2));

    // ✕ on the list: a question, and everything stays open.
    h.click(h.close_button(ifaces()));
    assert!(h.has_text("Close Interfaces?"));
    assert!(h.has_text("This window has changes not applied:"));
    assert!(h.app.open.contains(&Win::Interfaces));
    assert_eq!(h.app.dialogs.len(), 2);
    // The keys are the question's: Enter applies nothing behind it.
    h.key(Key::Enter, NONE);
    assert_eq!(h.mtu_of("ether1"), json!(1500));

    // Cancel keeps all, and shows the edited dialog.
    h.click(h.text("Cancel"));
    assert!(!h.has_text("Close Interfaces?"));
    assert_eq!(h.app.dialogs.len(), 2);
    assert_eq!(h.top(), Some(e1));
    assert!(h.has_text("Interface <ether1> •"), "edits kept");

    // Esc on the question is Cancel too.
    h.click(h.close_button(ifaces()));
    assert!(h.has_text("Close Interfaces?"));
    h.key(Key::Escape, NONE);
    assert!(!h.has_text("Close Interfaces?"));
    assert_eq!(h.app.dialogs.len(), 2);

    // Close All drops the edits and closes the family.
    h.click(h.close_button(ifaces()));
    h.click(h.text("Close All"));
    h.idle();
    assert!(!h.app.open.contains(&Win::Interfaces));
    assert!(h.app.dialogs.is_empty());
    assert_eq!(h.mtu_of("ether1"), json!(1500), "nothing applied");
}

#[test]
fn ctrl_tab_goes_through_the_windows() {
    let mut h = Harness::new();
    h.app.open_props("ether1");
    h.idle();
    h.idle();
    let e1 = h.props_win("ether1");
    h.app.open(Win::Addresses);
    h.idle();
    h.app.open(Win::Routes);
    h.idle();
    h.idle();
    let (addresses, routes) = (win_id(Win::Addresses), win_id(Win::Routes));
    assert_eq!(h.top(), Some(routes));

    // The window at the back comes up, with its dialog over it.
    h.key(Key::Tab, CTRL);
    assert_eq!(h.top(), Some(e1));
    assert!(h.above(ifaces(), routes));
    h.key(Key::Tab, CTRL);
    assert_eq!(h.top(), Some(addresses));
    // Backwards: the one in front goes to the back.
    h.key(Key::Tab, CTRL_SHIFT);
    assert_eq!(h.top(), Some(e1));
    assert_eq!(h.order().first(), Some(&addresses));
    // The keyboard went with it.
    h.key(Key::Escape, NONE);
    assert_eq!(h.props_open("ether1"), 0);
    // WinBox's Ctrl+F6 does the same.
    h.key(Key::F6, CTRL);
    assert_eq!(h.top(), Some(addresses));
}

impl Harness {
    fn mtu_of(&self, name: &str) -> Value {
        self.iface(name).unwrap()["mtu"].clone()
    }
}

#[test]
fn the_row_of_an_open_dialog_is_marked() {
    let mut h = Harness::new();
    h.app.open_props("ether1");
    h.idle();
    h.app.open_props("ether2");
    h.idle();
    h.idle();
    let mark = |h: &Harness, name: &str| {
        h.ctx
            .read_response(table::mark_id(interfaces::TABLE, name))
            .map(|r| r.rect.center())
    };
    assert!(mark(&h, "ether1").is_some() && mark(&h, "ether2").is_some());
    assert!(mark(&h, "ether3").is_none(), "no window, no mark");

    // A click on the mark brings that window to the front.
    let e1 = h.props_win("ether1");
    assert_ne!(h.top(), Some(e1));
    h.click(mark(&h, "ether1").unwrap());
    assert_eq!(h.top(), Some(e1));
    assert!(h.app.floats.is_flashing(e1));
    assert_eq!(h.props_open("ether1"), 1);

    // Closed: the mark goes.
    h.key(Key::Escape, NONE);
    h.idle();
    assert_eq!(h.props_open("ether1"), 0);
    assert!(!h.app.tables.interfaces.open.contains("ether1"));
    assert!(h.app.tables.interfaces.open.contains("ether2"));
}
