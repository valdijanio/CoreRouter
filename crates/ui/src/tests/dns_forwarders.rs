//! IP › DNS Forwarders (G4.1d), a panel opened from the DNS window.

use super::*;
use crate::dialog::Status;
use crate::dns_forwarders::{Dialog, DialogWin, ForwarderForm, ForwardersPanel, WIN};

fn refresh(h: &mut Harness) {
    h.app.cache.refreshed_at = None;
    for _ in 0..3 {
        h.idle();
    }
}

#[test]
fn forwarders_window_opens_from_dns_lists_and_adds() {
    let mut s = Session::virtual_lab();
    s.execute(
        "ip.dns.forwarders.add",
        &json!({"name": "corp", "dns_servers": ["10.0.0.53"], "doh_servers": ["tls://10.0.0.54#dns.corp.example"]}),
    )
    .unwrap();
    s.execute(
        "ip.dns.static.add",
        &json!({"name": "corp.example", "type": "FWD", "forward_to": "corp"}),
    )
    .unwrap();
    let mut h = Harness::with_session(s);
    h.app.open.clear();
    h.app.open(Win::Panel(crate::dns::WIN));
    refresh(&mut h);
    assert!(h.has_text("Use DoH Server"), "DoH field in the DNS window");
    h.click(h.text("Forwarders"));
    refresh(&mut h);
    assert!(h.app.open.contains(&Win::Panel(WIN)));
    assert!(h.has_text("corp"));
    assert!(h.has_text("tls://10.0.0.54#dns.corp.example"));
    assert!(h.has_text("corp.example"), "used by");

    h.app.panel_mut::<ForwardersPanel>().unwrap().dialogs.push(DialogWin {
        id: 901,
        dialog: Dialog::New(Box::new(ForwarderForm {
            name: "quad9".into(),
            doh_servers: "https://dns.quad9.net/dns-query".into(),
            ..ForwarderForm::default()
        })),
        status: Status::default(),
    });
    refresh(&mut h);
    assert!(h.has_text("New DNS Forwarder •"));
    h.click(h.text("OK"));
    refresh(&mut h);
    let rows = lock(&h.session)
        .execute("ip.dns.forwarders.print", &Value::Null)
        .unwrap();
    assert_eq!(rows[1]["name"], "quad9", "{:?}", h.app.log());
    assert_eq!(rows[1]["doh_servers"], json!(["https://dns.quad9.net/dns-query"]));
}
