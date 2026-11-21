//! G1.5d: the `warnings` of `ip.route.add`/`set` (G1.5b: a discard route
//! over a connected network) show in the route's window, with the amber
//! "warning" chip, instead of being dropped.

use super::*;
use crate::dialog::Status;
use crate::routes::RouteDialog;

const WARNING: &str = "this blackhole route drops 10.0.0.0/25, part of the connected network 10.0.0.0/24 on ether1: the hosts there stop being reachable";

#[test]
fn a_warned_reply_keeps_the_dialog_open_until_read() {
    let mut s = Status::default();
    s.close_on_success = true;
    s.sent();
    assert!(!s.replied_warned(&Ok(json!({"id": "*1", "warnings": ["a", "a", ""]}))));
    assert_eq!(s.warnings, ["a"], "repeats and empty ones dropped");
    s.sent();
    assert!(s.warnings.is_empty(), "a new try clears them");
    assert!(s.replied_warned(&Ok(json!({"id": "*1", "warnings": []}))));
    s.sent();
    assert!(!s.replied_warned(&Err("bad".into())));
    assert!(s.warnings.is_empty());
}

#[test]
fn new_route_that_warns_opens_its_window_with_the_warning() {
    let mut h = Harness::routes();
    h.click(h.route_tool(table::Icon::Add).rect.center());
    h.click(h.text("0.0.0.0/0"));
    h.type_text("10.0.0.0/25");
    h.click(h.text("blackhole"));
    h.click(h.text("OK"));
    h.idle();
    h.idle();
    let r = h.route("*1").expect("route created");
    assert_eq!(r["type"], "blackhole", "{r}");
    // The New Route window closed; the route's own opened with the warning.
    let [d] = h.app.route_dialogs.as_slice() else {
        panic!("one route window, got {}", h.app.route_dialogs.len())
    };
    assert!(matches!(&d.dialog, RouteDialog::Props { id, .. } if id == "*1"));
    assert_eq!(d.status.warnings, [WARNING]);
    assert!(h.has_text(WARNING) && h.has_text("warning"), "drawn with its chip");

    // OK with nothing changed closes it.
    h.click(h.text("OK"));
    h.idle();
    assert!(h.app.route_dialogs.is_empty());

    // Properties: a change that still warns keeps the window open on OK.
    h.app.open_route("*1");
    h.idle();
    h.idle();
    assert_eq!(h.app.route_dialogs.len(), 1, "the route's window opens");
    h.click(h.text("Disable"));
    h.idle();
    assert!(h.app.route_dialogs.first().is_some_and(|d| d.status.warnings.is_empty()), "a disabled discard route warns of nothing");
    h.click(h.text("Enable"));
    h.idle();
    let d = h.app.route_dialogs.first().expect("still open");
    assert_eq!(d.status.warnings, [WARNING], "enabling it again warns");
}

#[test]
fn a_route_that_does_not_warn_closes_on_ok() {
    let mut h = Harness::routes();
    h.click(h.route_tool(table::Icon::Add).rect.center());
    h.click(h.text("0.0.0.0/0"));
    h.type_text("192.0.2.0/24");
    h.click(h.text("blackhole"));
    h.click(h.text("OK"));
    h.idle();
    h.idle();
    assert!(h.route("*1").is_some());
    assert!(h.app.route_dialogs.is_empty(), "nothing to read: closed");
}
