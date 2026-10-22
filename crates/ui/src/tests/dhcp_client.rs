//! IP › DHCP Client (G4.7a), a panel: list, properties tabs, Renew, New.

use super::*;

#[test]
fn dhcp_client_window_lists_opens_and_adds() {
    let mut s = Session::virtual_lab();
    s.tick(1_000);
    s.execute("ip.dhcp-client.add", &json!({"interface": "ether1"}))
        .unwrap();
    s.dhcp_service(0);
    s.dhcp_service(1_000);
    let mut h = Harness::with_session(s);
    h.app.open.clear();
    h.app.open(Win::Panel(crate::dhcp_client::WIN));
    h.app.cache.refreshed_at = None;
    h.idle();
    h.idle();
    assert!(h.has_text("bound"), "status column");
    let lease = lock(&h.session)
        .execute("ip.dhcp-client.list", &Value::Null)
        .unwrap()[0]["address"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(h.has_text(&lease), "IP Address column");

    let row = h
        .ctx
        .read_response(table::row_id(crate::dhcp_client::TABLE, "*1"))
        .expect("row drawn")
        .rect
        .center();
    h.right_click(row);
    h.click(h.text("Properties…"));
    assert!(h.has_text("DHCP Client <ether1>"));
    let set_tab = |h: &mut Harness, tab: crate::dhcp_client::Tab| {
        if let Some(crate::dhcp_client::DhcpDialog::Props { tab: t, .. }) =
            h.app.panel_mut::<crate::dhcp_client::DhcpPanel>().unwrap().dialogs.first_mut().map(|d| &mut d.dialog)
        {
            *t = tab;
        }
        h.app.cache.refreshed_at = None;
        for _ in 0..3 {
            h.idle();
        }
    };
    set_tab(&mut h, crate::dhcp_client::Tab::Status);
    assert!(h.has_text("100.64.1.1"), "gateway on the Status tab");
    set_tab(&mut h, crate::dhcp_client::Tab::Options);
    assert!(h.has_text("classless-static-route"), "Options tab");
    h.click(h.text("Renew"));
    assert!(
        h.app
            .log()
            .iter()
            .any(|l| l.ok && l.command == "ip.dhcp-client.renew"),
        "{:?}",
        h.app.log()
    );
    h.click(h.text("Cancel"));
    assert!(h.app.panel_mut::<crate::dhcp_client::DhcpPanel>().unwrap().dialogs.is_empty());

    // New: the first interface without a client is picked; OK adds it.
    let add = h
        .ctx
        .read_response(table::tool_id(crate::dhcp_client::TABLE, table::Icon::Add))
        .expect("add tool")
        .rect
        .center();
    h.click(add);
    for _ in 0..6 {
        h.idle();
    }
    assert!(
        h.has_text("New DHCP Client"),
        "{} dialogs, log {:?}",
        h.app.panel_mut::<crate::dhcp_client::DhcpPanel>().unwrap().dialogs.len(),
        h.app.log()
    );
    h.click(h.text("OK"));
    let list = lock(&h.session)
        .execute("ip.dhcp-client.list", &Value::Null)
        .unwrap();
    assert_eq!(list[1]["interface"], "ether2", "{list}");
    // The history reached the Log.
    assert!(
        h.app
            .log()
            .iter()
            .any(|l| l.command == "dhcp-client" && l.message.starts_with("ether1: got")),
        "{:?}",
        h.app.log()
    );
}
