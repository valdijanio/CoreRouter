//! G1.15: Enter / Ctrl+Enter / Esc in dialogs and list windows, driven
//! with synthetic key events through the real UI.

use std::cell::Cell;
use std::collections::BTreeSet;

use super::*;
use crate::dialog;
use egui::Key;

const NONE: egui::Modifiers = egui::Modifiers::NONE;

impl Harness {
    /// The open "Interface <name>" window, if any.
    fn props(&self, name: &str) -> Option<&interfaces::DialogWin> {
        self.app
            .dialogs
            .iter()
            .find(|d| matches!(&d.dialog, interfaces::Dialog::Props(p) if p.name == name))
    }

    fn props_id(&self, name: &str) -> egui::Id {
        let d = self
            .props(name)
            .unwrap_or_else(|| panic!("{name} not open"));
        interfaces::dialog_id(d.id)
    }

    /// Click into a field of a dialog and replace its text.
    fn retype(&mut self, window: egui::Id, param: &str, text: &str) {
        let at = self
            .ctx
            .read_response(dialog::field_id(window, param))
            .unwrap_or_else(|| panic!("no field {param}"))
            .rect
            .center();
        self.click(at);
        self.key(Key::A, CTRL);
        self.type_text(text);
    }

    fn mtu(&self, name: &str) -> Value {
        self.iface(name).unwrap()["mtu"].clone()
    }

    /// Bring a window to the front (a click on it would, where it shows).
    fn raise(&mut self, id: egui::Id) {
        self.ctx
            .move_to_top(egui::LayerId::new(egui::Order::Middle, id));
        self.idle();
    }

    fn has_focus(&self, id: egui::Id) -> bool {
        self.ctx.memory(|m| m.has_focus(id))
    }
}

#[test]
fn enter_saves_and_closes() {
    let mut h = Harness::new();
    h.app.open_props("ether1");
    h.idle();
    h.idle();
    let win = h.props_id("ether1");
    assert!(h.has_text("Interface <ether1>"));
    h.retype(win, "mtu", "1400");
    assert!(
        h.has_text("Interface <ether1> •"),
        "edited: dot in the title"
    );
    h.key(Key::Enter, NONE);
    h.idle();
    assert!(h.props("ether1").is_none(), "Enter = OK closes");
    assert_eq!(h.mtu("ether1"), json!(1400));
}

#[test]
fn enter_with_an_error_stays_open_and_points_at_the_field() {
    let mut h = Harness::new();
    h.app.open_props("ether1");
    h.idle();
    h.idle();
    let win = h.props_id("ether1");
    h.retype(win, "comment", "uplink");
    h.retype(win, "mtu", "10");
    h.key(Key::Enter, NONE);
    h.idle();
    let d = h.props("ether1").expect("still open");
    let error = d.status.error.clone().unwrap_or_default();
    assert!(error.contains("parameter 'mtu'"), "{error}");
    assert!(h.has_text(&error), "error shown in the dialog");
    assert!(h.has_focus(dialog::field_id(win, "mtu")), "cursor on MTU");
    assert_eq!(h.mtu("ether1"), json!(1500), "nothing applied");
    assert!(h.has_text("Interface <ether1> •"), "edits kept");
}

#[test]
fn ctrl_enter_applies_and_stays_open() {
    let mut h = Harness::new();
    h.app.open_props("ether2");
    h.idle();
    h.idle();
    let win = h.props_id("ether2");
    h.retype(win, "mtu", "9000");
    h.key(Key::Enter, CTRL);
    h.idle();
    assert_eq!(h.mtu("ether2"), json!(9000));
    assert!(h.props("ether2").is_some(), "Apply keeps the window");
    assert!(h.has_text("Interface <ether2>"));
    assert!(!h.has_text("Interface <ether2> •"), "saved: no dot");
}

#[test]
fn escape_discards_without_asking() {
    let mut h = Harness::new();
    h.app.open_props("ether1");
    h.idle();
    h.idle();
    let win = h.props_id("ether1");
    h.retype(win, "mtu", "1400");
    let sent = h.log_ids().len();
    h.key(Key::Escape, NONE);
    h.idle();
    assert!(h.props("ether1").is_none(), "Esc = Cancel closes");
    assert_eq!(h.mtu("ether1"), json!(1500));
    assert_eq!(h.log_ids().len(), sent, "nothing sent");
}

/// A router that holds `interface.set` replies until told to answer.
struct Slow {
    inner: Local,
    hold: Rc<Cell<bool>>,
    sets: Rc<Cell<usize>>,
    held_ids: BTreeSet<RequestId>,
    held: Vec<Reply>,
}

impl Backend for Slow {
    fn submit(&mut self, method: &str, params: Value) -> RequestId {
        let set = params["command"] == "interface.set";
        let id = self.inner.submit(method, params);
        if set {
            self.sets.set(self.sets.get() + 1);
            self.held_ids.insert(id);
        }
        id
    }

    fn poll(&mut self) -> Vec<Reply> {
        let (held, mut now): (Vec<Reply>, Vec<Reply>) = self
            .inner
            .poll()
            .into_iter()
            .partition(|(id, _)| self.held_ids.contains(id));
        self.held.extend(held);
        if !self.hold.get() {
            now.append(&mut self.held);
        }
        now
    }

    fn link(&self) -> Link {
        Link::Local
    }
}

#[test]
fn enter_while_saving_applies_once() {
    let mut h = Harness::new();
    let hold = Rc::new(Cell::new(true));
    let sets = Rc::new(Cell::new(0));
    h.app = CoreRouterUi::with_backend(Box::new(Slow {
        inner: Local::new(h.session.clone()),
        hold: hold.clone(),
        sets: sets.clone(),
        held_ids: BTreeSet::new(),
        held: Vec::new(),
    }));
    for _ in 0..3 {
        h.idle();
    }
    h.app.open_props("ether1");
    h.idle();
    h.idle();
    let win = h.props_id("ether1");
    h.retype(win, "mtu", "1400");
    h.key(Key::Enter, NONE);
    assert!(h.has_text("Saving…"), "OK says it is saving");
    h.key(Key::Enter, NONE);
    h.key(Key::Enter, CTRL);
    h.click(h.text("Saving…"));
    assert_eq!(sets.get(), 1, "applied once");
    assert!(h.props("ether1").is_some(), "open until the reply");

    hold.set(false);
    h.idle();
    h.idle();
    assert!(h.props("ether1").is_none(), "closes once accepted");
    assert_eq!(sets.get(), 1);
}

#[test]
fn escape_and_enter_with_a_combo_open_stay_in_the_combo() {
    let mut h = Harness::new();
    h.app
        .interface_act(interfaces::Act::NewVlan { parent: None }, &[]);
    h.idle();
    h.idle();
    assert!(h.has_text("New VLAN Interface"));
    h.click(h.text("parent"));
    assert!(egui::Popup::is_any_open(&h.ctx), "combo open");
    let sent = h.log_ids().len();

    h.key(Key::Enter, NONE);
    assert_eq!(h.log_ids().len(), sent, "Enter did not submit the form");
    assert_eq!(h.app.dialogs.len(), 1);

    if !egui::Popup::is_any_open(&h.ctx) {
        h.click(h.text("parent"));
    }
    h.key(Key::Escape, NONE);
    assert!(!egui::Popup::is_any_open(&h.ctx), "Esc closed the combo");
    assert_eq!(h.app.dialogs.len(), 1, "and only the combo");

    h.key(Key::Escape, NONE);
    assert!(h.app.dialogs.is_empty(), "the next Esc closes the dialog");
    assert_eq!(h.log_ids().len(), sent);
}

#[test]
fn escape_on_a_list_clears_find_then_selection_then_closes() {
    let mut h = Harness::new();
    h.click(h.row("ether1"));
    h.click(h.text("Find"));
    h.type_text("eth");
    assert_eq!(h.app.tables.interfaces.filter, "eth");
    assert!(h.app.tables.interfaces.is_selected("ether1"));

    h.key(Key::Escape, NONE);
    assert_eq!(h.app.tables.interfaces.filter, "", "1: find cleared");
    assert_eq!(h.selected(), ["ether1"]);
    h.key(Key::Escape, NONE);
    assert!(h.selected().is_empty(), "2: selection cleared");
    assert!(h.app.open.contains(&Win::Interfaces));
    h.key(Key::Escape, NONE);
    assert!(!h.app.open.contains(&Win::Interfaces), "3: closed");
}

#[test]
fn keys_reach_only_the_window_in_front() {
    let mut h = Harness::new();
    // Enter on the table (G1.9) opens the selection's properties.
    h.click(h.row("ether1"));
    h.key(Key::Enter, NONE);
    assert!(h.props("ether1").is_some());
    h.click(h.row("ether2"));
    h.key(Key::Enter, NONE);
    assert!(h.props("ether2").is_some());

    // ether2's window opened last: it is in front and takes the Esc.
    h.key(Key::Escape, NONE);
    assert!(h.props("ether2").is_none());
    assert!(h.props("ether1").is_some(), "the window behind stays");
    assert_eq!(
        h.selected(),
        ["ether2"],
        "the list behind keeps its selection"
    );

    // The window clicked last is in front; Esc goes there.
    h.raise(h.props_id("ether1"));
    h.click(h.row("ether3"));
    h.key(Key::Escape, NONE);
    assert!(h.selected().is_empty(), "the list in front cleared");
    assert!(
        h.props("ether1").is_some(),
        "the dialog behind is untouched"
    );

    // Typing in a dialog field never fires the table's shortcuts.
    h.click(h.row("ether3"));
    let win = h.props_id("ether1");
    h.raise(win);
    h.retype(win, "comment", "x");
    assert!(h.has_focus(dialog::field_id(win, "comment")));
    h.key(Key::Delete, NONE);
    h.key(Key::D, CTRL);
    assert_eq!(h.iface("ether3").unwrap()["disabled"], false);
    assert!(h.iface("ether3").is_some());
}

#[test]
fn route_dialogs_take_the_same_keys() {
    let mut h = Harness::routes();
    h.click(h.route_tool(table::Icon::Add).rect.center());
    assert!(h.has_text("New Route"));
    h.click(h.text("0.0.0.0/0"));
    h.type_text("bogus");
    assert!(h.has_text("New Route •"));
    h.click(h.text("10.0.0.1 or ether1"));
    h.type_text("10.0.0.1");
    h.key(Key::Enter, NONE);
    h.idle();
    let d = h.app.route_dialogs.first().expect("error keeps it open");
    let win = interfaces::dialog_id(d.id);
    assert!(h.has_focus(dialog::field_id(win, "dst_address")));

    // Fix the field the cursor is in, then Enter saves and closes.
    h.key(Key::A, CTRL);
    h.type_text("0.0.0.0/0");
    h.key(Key::Enter, NONE);
    h.idle();
    assert!(h.app.route_dialogs.is_empty());
    assert!(h.route("*1").is_some());

    // Esc on a "Route <dst>" window drops the edits.
    h.click(h.route_row("*1"));
    h.key(Key::Enter, NONE);
    h.idle();
    let win = interfaces::dialog_id(h.app.route_dialogs.first().expect("opened").id);
    h.retype(win, "distance", "7");
    h.key(Key::Escape, NONE);
    assert!(h.app.route_dialogs.is_empty());
    assert_eq!(h.route("*1").unwrap()["distance"], json!(1));
}

#[test]
fn escape_right_after_a_dialog_closes_reaches_the_list() {
    let mut h = Harness::new();
    h.click(h.row("ether1"));
    h.key(Key::Enter, NONE);
    assert!(h.props("ether1").is_some());
    // Three Esc in three frames in a row, as fast as a person can type:
    // egui still lists the closed dialog on top for a frame.
    let esc = || egui::Event::Key {
        key: Key::Escape,
        physical_key: None,
        pressed: true,
        repeat: false,
        modifiers: NONE,
    };
    h.frame(vec![esc()], NONE);
    assert!(h.props("ether1").is_none());
    h.frame(vec![esc()], NONE);
    assert!(h.selected().is_empty(), "the list got the second Esc");
    h.frame(vec![esc()], NONE);
    assert!(!h.app.open.contains(&Win::Interfaces));
}

#[test]
fn vrf_dialogs_and_list_take_the_same_keys() {
    let mut h = Harness::vrfs();
    // Enter on the table opens "VRF blue"; Ctrl+Enter applies a comment.
    h.click(h.vrf_row("blue"));
    h.key(Key::Enter, NONE);
    h.idle();
    let d = h.app.vrf_dialogs.first().expect("VRF blue open");
    let win = interfaces::dialog_id(d.id);
    h.retype(win, "comment", "customer A");
    assert!(h.has_text("VRF <blue> •"));
    h.key(Key::Enter, CTRL);
    h.idle();
    assert_eq!(h.vrf("blue").unwrap()["comment"], "customer A");
    assert_eq!(h.app.vrf_dialogs.len(), 1, "Apply keeps it open");
    h.key(Key::Escape, NONE);
    assert!(h.app.vrf_dialogs.is_empty());

    // "New VRF" with a bad name: the error puts the cursor in Name.
    h.click(h.vrf_tool(table::Icon::Add));
    h.idle();
    let d = h.app.vrf_dialogs.first().expect("New VRF open");
    let win = interfaces::dialog_id(d.id);
    h.retype(win, "name", "blue");
    h.key(Key::Enter, NONE);
    h.idle();
    assert!(
        h.app
            .vrf_dialogs
            .first()
            .is_some_and(|d| d.status.error.is_some())
    );
    assert!(h.has_focus(dialog::field_id(win, "name")));
    h.key(Key::Escape, NONE);
    assert!(h.app.vrf_dialogs.is_empty());

    // The list: selection, then the window.
    assert!(h.app.tables.vrfs.is_selected("blue"));
    h.key(Key::Escape, NONE);
    assert!(!h.app.tables.vrfs.is_selected("blue"));
    assert!(h.app.open.contains(&Win::Vrf));
    h.key(Key::Escape, NONE);
    assert!(!h.app.open.contains(&Win::Vrf));
}
