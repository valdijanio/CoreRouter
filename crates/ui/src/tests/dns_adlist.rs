//! IP › DNS Adlist (G4.1d), a panel opened from the DNS window.

use super::*;
use crate::dialog::Status;
use crate::dns_adlist::{AdlistForm, AdlistPanel, Dialog, DialogWin, WIN};
use corerouter_engine::dns_adlist::{AdlistBackend, AdlistStatus};
use corerouter_model::ItemId;

struct Loader;

impl AdlistBackend for Loader {
    fn status(&self) -> Vec<AdlistStatus> {
        vec![AdlistStatus {
            id: Some(ItemId(1)),
            state: "loaded",
            name_count: 71_492,
            match_count: 42,
            loaded_secs_ago: Some(180),
            ..AdlistStatus::default()
        }]
    }
    fn reload(&self, _: Option<ItemId>) {}
}

fn refresh(h: &mut Harness) {
    h.app.cache.refreshed_at = None;
    for _ in 0..3 {
        h.idle();
    }
}

#[test]
fn adlist_window_opens_from_dns_lists_and_adds() {
    let mut s = Session::virtual_lab();
    s.execute(
        "ip.dns.adlist.add",
        &json!({"url": "https://lists.example/hosts", "comment": "ads"}),
    )
    .unwrap();
    s.set_adlist_backend(std::sync::Arc::new(Loader));
    let mut h = Harness::with_session(s);
    h.app.open.clear();
    h.app.open(Win::Panel(crate::dns::WIN));
    refresh(&mut h);
    // The DNS window's Adlist button is live now that the panel exists.
    h.click(h.text("Adlist"));
    refresh(&mut h);
    assert!(h.app.open.contains(&Win::Panel(WIN)));
    assert!(h.has_text("https://lists.example/hosts"));
    assert!(h.has_text("71492"), "name count");
    assert!(h.has_text("3 min ago"));
    assert!(h.has_text("71492 names, 42 blocked"));

    // New list through the dialog.
    h.app.panel_mut::<AdlistPanel>().unwrap().dialogs.push(DialogWin {
        id: 900,
        dialog: Dialog::New(Box::new(AdlistForm {
            url: "https://other.example/domains.txt".into(),
            ssl_verify: false,
            ..AdlistForm::default()
        })),
        status: Status::default(),
    });
    refresh(&mut h);
    assert!(h.has_text("New DNS Adlist •"), "dirty: the URL is typed");
    h.click(h.text("OK"));
    refresh(&mut h);
    let rows = lock(&h.session)
        .execute("ip.dns.adlist.print", &Value::Null)
        .unwrap();
    assert_eq!(rows[1]["url"], "https://other.example/domains.txt", "{:?}", h.app.log());
    assert_eq!(rows[1]["ssl_verify"], false);
    assert!(h.app.panel_mut::<AdlistPanel>().unwrap().dialogs.is_empty());
}
