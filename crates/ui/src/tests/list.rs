//! The list window pattern (G0.24): the bar's reasons, filters, copies,
//! one transaction for a series, and the modal's preview, risk and
//! Apply × OK.

use super::*;
use crate::avail::Avail;
use crate::backend::Link;
use crate::list::{self, Act, Cmds, Filters, Item, Syntax, Tools};
use crate::list_modal::{Field, Input, Modal, Spec};
use crate::table::{Selection, Shortcut};

const CMDS: Cmds = Cmds {
    add: "ip.address.add",
    remove: "ip.address.remove",
    set: Some("ip.address.set"),
    what: "addresses",
};

fn avail(set_enabled: bool) -> Avail {
    let commands = vec![
        json!({"id": "ip.address.add", "enabled": true}),
        json!({"id": "ip.address.remove", "enabled": true}),
        json!({"id": "ip.address.set", "enabled": set_enabled, "disabledReason": "held by the maintenance window"}),
    ];
    Avail::new(
        &Link::Connected {
            target: "r1:7979".into(),
        },
        Some(&commands),
        &Value::Null,
    )
}

fn item(key: &str, disabled: bool, fixed: Option<&str>) -> Item {
    Item {
        key: key.into(),
        disabled,
        fixed: fixed.map(str::to_owned),
    }
}

#[test]
fn the_bar_greys_out_with_the_reason() {
    let can = avail(true);
    let t = Tools::new(&can, &CMDS, &[]);
    assert!(t.add.is_ok());
    assert_eq!(t.remove, Err("Select one or more addresses first".into()));
    assert_eq!(t.comment, Err("Select one or more addresses first".into()));

    // One enabled item: Disable and Remove act, Enable has nothing to do.
    let t = Tools::new(&can, &CMDS, &[item("*1", false, None)]);
    assert!(t.remove.is_ok() && t.disable.is_ok() && t.comment.is_ok());
    assert_eq!(t.enable, Err("Already enabled".into()));
    let t = Tools::new(&can, &CMDS, &[item("*1", true, None)]);
    assert_eq!(t.disable, Err("Already disabled".into()));
    // Mixed: both act.
    let t = Tools::new(&can, &CMDS, &[item("*1", true, None), item("*2", false, None)]);
    assert!(t.enable.is_ok() && t.disable.is_ok());

    // A dynamic item says where it comes from.
    let t = Tools::new(&can, &CMDS, &[item("*1", false, None), item("*D1", false, Some("from the DHCP client"))]);
    for r in [&t.remove, &t.enable, &t.disable, &t.comment] {
        assert_eq!(r, &Err("from the DHCP client".into()));
    }

    // The router's reason wins over the selection's.
    let t = Tools::new(&avail(false), &CMDS, &[item("*1", false, None)]);
    assert_eq!(t.disable, Err("held by the maintenance window".into()));
    assert!(t.remove.is_ok());

    // A list without `set`.
    let no_set = Cmds { set: None, ..CMDS };
    let t = Tools::new(&can, &no_set, &[item("*1", false, None)]);
    assert!(t.disable.as_ref().is_err_and(|e| e.contains("no settings")));
}

#[test]
fn keys_act_only_when_the_button_would() {
    let can = avail(true);
    let sel: Selection = ["*1".to_owned()].into_iter().collect();
    let t = Tools::new(&can, &CMDS, &[item("*1", false, None)]);
    assert_eq!(list::from_shortcut(Some(Shortcut::Disable), &t, &sel), Some(Act::Disable(vec!["*1".into()])));
    assert_eq!(list::from_shortcut(Some(Shortcut::Enable), &t, &sel), None, "already enabled");
    assert_eq!(list::from_shortcut(Some(Shortcut::Open), &t, &sel), Some(Act::Edit("*1".into())));
    assert_eq!(list::from_shortcut(None, &t, &sel), None);
}

#[test]
fn filter_chips_combine_fields() {
    let rows = [
        json!({"family": "ipv4", "state": "active"}),
        json!({"family": "ipv6", "state": "active"}),
        json!({"family": "ipv4", "state": "disabled"}),
    ];
    let mut f = Filters::default();
    assert!(rows.iter().all(|r| f.shows(r)), "nothing on: everything");
    f.toggle("family", "ipv4");
    assert_eq!(rows.iter().filter(|r| f.shows(r)).count(), 2);
    f.toggle("state", "disabled");
    assert_eq!(rows.iter().filter(|r| f.shows(r)).count(), 1, "and across fields");
    f.toggle("family", "ipv6");
    assert_eq!(rows.iter().filter(|r| f.shows(r)).count(), 1, "or inside one");
    f.toggle("state", "disabled");
    f.toggle("family", "ipv4");
    f.toggle("family", "ipv6");
    assert!(rows.iter().all(|r| f.shows(r)), "all off again");
    assert_eq!(list::count(&rows, "state", "active"), 2);
}

#[test]
fn copies_rows_and_commands() {
    let h = Harness::new();
    let row = json!({"id": "*1", "address": "10.0.0.1/24", "interface": "ether1",
        "comment": "lan", "disabled": false, "network": "10.0.0.0/24"});
    let core = list::copy_commands(&h.app, "ip.address.add", &[&row], Syntax::CoreRouter);
    assert_eq!(core, r#"ip.address.add {"address":"10.0.0.1/24","comment":"lan","interface":"ether1"}"#);
    let ros = list::copy_commands(&h.app, "ip.address.add", &[&row, &row], Syntax::RouterOs);
    assert_eq!(
        ros,
        "/ip address add address=10.0.0.1/24 interface=ether1 comment=lan\n\
         /ip address add address=10.0.0.1/24 interface=ether1 comment=lan"
    );
    let r = crate::table::Row {
        key: "*1".into(),
        cells: vec![crate::chip::cell("", &[("active", crate::chip::Kind::Green)]), "10.0.0.1/24".into()],
        dimmed: false,
        section: false,
        tint: None,
    };
    assert_eq!(list::copy_rows(&[&r]), "\t10.0.0.1/24", "chips are not text");
}

#[test]
fn a_series_is_one_transaction() {
    let mut h = Harness::new();
    let add = |a: &str| json!({"command": "ip.address.add", "params": {"address": a, "interface": "ether1"}});
    // The third fails: none of the three stays.
    h.app.run_steps(vec![add("10.20.0.1/24"), add("10.20.0.2/24"), add("bad")], Then::Nothing);
    h.idle();
    let n = |h: &Harness| {
        lock(&h.session)
            .execute("ip.address.list", &Value::Null)
            .unwrap()
            .as_array()
            .map_or(0, Vec::len)
    };
    assert_eq!(n(&h), 0, "{:?}", h.app.log());
    assert!(h.app.log().last().is_some_and(|l| !l.ok && l.command == "engine.batch"));
    h.app.run_steps(vec![add("10.20.0.1/24"), add("10.20.0.2/24")], Then::Nothing);
    h.idle();
    assert_eq!(n(&h), 2);
}

const FIELDS: &[Field] = &[
    Field {
        param: "address",
        label: "Address",
        help: "ip.address.address",
        input: Input::Text("10.0.0.1/24"),
        edit: true,
    },
    Field {
        param: "disabled",
        label: "Disabled",
        help: "ip.address.disabled",
        input: Input::Check,
        edit: false,
    },
];

const SPEC: Spec = Spec {
    panel: "nobody",
    parent: Win::Addresses,
    new_title: "New Address",
    edit_title: "Address",
    help: "ip.address",
    fields: FIELDS,
    preview: "ip.address.preview",
};

#[test]
fn the_modal_sends_its_fields_and_waits_for_a_clean_preview() {
    let mut h = Harness::new();
    let mut values = std::collections::BTreeMap::new();
    values.insert("address", " 10.0.0.1/24 ".to_owned());
    values.insert("disabled", "yes".to_owned());
    let mut m = Modal::open(&mut h.app, None, values.clone());
    assert_eq!(m.params(&SPEC), json!({"address": "10.0.0.1/24", "disabled": true}));
    let mut e = Modal::open(&mut h.app, Some(("*3".into(), "10.0.0.1/24".into())), values);
    assert_eq!(e.params(&SPEC), json!({"address": "10.0.0.1/24", "id": "*3"}), "edit: only what set takes");
    e.status.sent();
    assert!(!e.replied(&mut h.app, &Ok(Value::Null)), "Apply keeps it open");
    e.status.close_on_success = true;
    e.status.sent();
    assert!(e.replied(&mut h.app, &Ok(Value::Null)), "OK closes it");
    e.status.sent();
    assert!(!e.replied(&mut h.app, &Err("parameter 'address': bad".into())), "an error keeps it open");

    // A preview for other fields does not count; an error check blocks;
    // a risk needs the yes, and the yes adds force.
    m.arrived(json!({"commands": [{"command": "ip.address.add", "params": {"address": "10.0.0.1/24"}}]}));
    assert!(m.blocking(&SPEC).is_err(), "not asked for these fields");
    m.mark_asked(&SPEC);
    assert!(m.blocking(&SPEC).is_ok());
    m.arrived(json!({"checks": [{"level": "error", "message": "overlaps", "param": "address"}],
        "commands": [{"command": "ip.address.add", "params": {}}]}));
    assert_eq!(m.blocking(&SPEC), Err("overlaps".into()));
    m.arrived(json!({"risk": "this session arrives through 10.0.0.1",
        "commands": [{"command": "ip.address.set", "params": {"id": "*3"}}]}));
    assert!(m.blocking(&SPEC).is_err());
    assert_eq!(m.steps(&SPEC)[0]["params"], json!({"id": "*3"}));
    m.accept_risk = true;
    assert!(m.blocking(&SPEC).is_ok());
    assert_eq!(m.steps(&SPEC)[0]["params"], json!({"id": "*3", "force": true}));
}
