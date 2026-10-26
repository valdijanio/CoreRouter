//! G4.3cd: routes in the PPP window: the Routes field of the secret modal
//! (refusals from the engine's preview), the Routes column of Secrets and
//! of Active Connections (a chip per block and per origin, refusals in
//! red), and Why? with the routes of the session and the ones refused.

use std::sync::{Arc, Mutex};

use corerouter_engine::ppp::PppBackend;
use corerouter_model::MacAddr;
use corerouter_model::framed_route::{RouteOrigin, SessionRoute};
use corerouter_model::ppp::{ActiveSession, HistoryEntry, ServiceStats, Why};
use serde_json::json;

use super::*;
use crate::ppp::{PppPanel, Tab, WIN};

#[derive(Default)]
struct Routed {
    up: Mutex<Vec<ActiveSession>>,
}

fn route(r: &str, origin: RouteOrigin) -> SessionRoute {
    SessionRoute { route: r.into(), origin }
}

impl PppBackend for Routed {
    fn active(&self) -> Vec<ActiveSession> {
        self.up.lock().unwrap().clone()
    }
    fn terminate(&self, _: &[String]) -> usize {
        0
    }
    fn history(&self) -> Vec<HistoryEntry> {
        Vec::new()
    }
    fn why(&self, name: Option<&str>, _: Option<MacAddr>) -> Why {
        let active = self.active().into_iter().find(|a| Some(a.name.as_str()) == name).map(|a| a.id);
        Why { query: name.unwrap_or_default().into(), active, ..Why::default() }
    }
    fn stats(&self) -> ServiceStats {
        ServiceStats { sessions: 2, ..ServiceStats::default() }
    }
}

fn lab() -> Session {
    let mut s = Session::virtual_lab();
    s.execute("ip.pool.add", &json!({"name": "clientes", "ranges": "100.64.0.0/22"})).unwrap();
    s.execute("ppp.secret.add", &json!({"name": "empresa", "password": "x", "routes": "203.0.113.8/29,2001:db8:100::/48"})).unwrap();
    let fake = Arc::new(Routed::default());
    *fake.up.lock().unwrap() = vec![
        ActiveSession {
            id: "*1-1".into(),
            name: "empresa".into(),
            service: "pppoe".into(),
            address: Some(std::net::Ipv4Addr::new(100, 64, 0, 9)),
            routes: vec![
                route("203.0.113.8/29 0.0.0.0 1", RouteOrigin::FramedRoute),
                route("2001:db8:100::/48 :: 1", RouteOrigin::FramedIpv6Route),
                route("198.51.100.0/30", RouteOrigin::Secret),
            ],
            refused_routes: vec!["198.51.100.64/29: sobrepõe 198.51.100.64/28, já roteado para outra (Framed-Route)".into()],
            ..ActiveSession::default()
        },
        ActiveSession { id: "*1-2".into(), name: "casa".into(), service: "pppoe".into(), ..ActiveSession::default() },
    ];
    s.set_ppp_backend(fake);
    s
}

fn refresh(h: &mut Harness) {
    h.app.cache.refreshed_at = None;
    for _ in 0..3 {
        h.idle();
    }
}

fn open() -> Harness {
    let mut h = Harness::with_session(lab());
    h.app.open.clear();
    h.app.open(Win::Panel(WIN));
    refresh(&mut h);
    h
}

#[test]
fn active_connections_show_each_block_with_its_origin() {
    let r = json!({"id": "*1-1", "name": "empresa", "routes": [
        {"route": "203.0.113.8/29 0.0.0.0 1", "origin": "framed-route"},
        {"route": "2001:db8:100::/48", "origin": "framed-ipv6-route"},
        {"route": "198.51.100.0/30", "origin": "secret"}],
        "refused_routes": ["x", "y"]});
    let row = PppPanel::active_row(&r, None);
    let (_, chips) = crate::chip::split(&row.cells[6]);
    let labels: Vec<&str> = chips.iter().map(|(_, t)| *t).collect();
    assert_eq!(
        labels,
        ["203.0.113.8/29", "Framed-Route", "2001:db8:100::/48", "Framed-IPv6-Route", "198.51.100.0/30", "secret", "2 refused"]
    );
    assert!(matches!(chips[6].0, crate::chip::Kind::Red));
    // No routes, no chips.
    assert_eq!(PppPanel::active_row(&json!({"id": "*1-2", "name": "casa"}), None).cells[6], "");
    let h = open();
    assert!(h.has_text_containing("Framed-IPv6-Route"));
}

#[test]
fn secrets_show_and_edit_the_routes() {
    let mut h = open();
    h.app.panel_mut::<PppPanel>().unwrap().tab = Tab::Secrets;
    refresh(&mut h);
    assert!(h.has_text_containing("203.0.113.8/29, 2001:db8:100::/48"));
    let row = PppPanel::secret_row(&json!({"id": "*1", "name": "empresa", "routes": "203.0.113.8/29,2001:db8:100::/48"}));
    assert_eq!(row.cells[4], "203.0.113.8/29, 2001:db8:100::/48");
}

#[test]
fn why_lists_the_routes_and_the_refusals() {
    let mut h = open();
    h.app.with_panel_as::<PppPanel, _>(|p, app| p.open_why(app, "empresa".into(), String::new())).unwrap();
    refresh(&mut h);
    refresh(&mut h);
    assert!(h.has_text_containing("203.0.113.8/29 0.0.0.0 1"), "the route");
    assert!(h.has_text_containing("Framed-Route"), "its origin");
    assert!(h.has_text_containing("já roteado para outra"), "the refusal, in Portuguese");
}

/// Editing a secret never sends an empty password (the field says "empty
/// keeps it"; sent empty, every edit cleared the password), nor clears the
/// routes unless the field was emptied.
#[test]
fn editing_a_secret_keeps_its_password() {
    use crate::list_modal::{Field, Input, Modal, Spec};
    const FIELDS: &[Field] = &[
        Field { param: "name", label: "Name", help: "ppp.secret.name", input: Input::Text(""), edit: true },
        Field { param: "password", label: "Password", help: "ppp.secret.password", input: Input::Secret(""), edit: true },
        Field { param: "routes", label: "Routes", help: "ppp.secret.routes", input: Input::Text(""), edit: true },
    ];
    const SPEC: Spec = Spec { panel: "ppp", parent: Win::Panel(WIN), new_title: "New", edit_title: "Edit", help: "ppp.secrets", fields: FIELDS, preview: "ppp.secret.preview" };
    let mut h = Harness::with_session(lab());
    let mut values = std::collections::BTreeMap::new();
    values.insert("name", "empresa".to_owned());
    values.insert("password", String::new());
    values.insert("routes", "203.0.113.8/29".to_owned());
    let e = Modal::open(&mut h.app, Some(("*1".into(), "empresa".into())), values.clone());
    assert_eq!(e.params(&SPEC), json!({"id": "*1", "name": "empresa", "routes": "203.0.113.8/29"}));
    values.insert("password", "nova".to_owned());
    values.insert("routes", String::new());
    let e = Modal::open(&mut h.app, Some(("*1".into(), "empresa".into())), values);
    assert_eq!(e.params(&SPEC), json!({"id": "*1", "name": "empresa", "password": "nova", "routes": ""}));
}
