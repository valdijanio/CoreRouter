//! G1.6q: the command catalogue (`engine.list`, ~300 KB on a router) is
//! asked for with its etag, and the router sends it only when it changed: on
//! the image an idle GUI pulled ~300 KB/s over the management link, ~250 KB/s
//! of it this list.

use super::*;

/// A router that answers `engine.list {if_none_match}` like the daemon and
/// counts the full catalogues it sent.
#[derive(Default)]
struct Router {
    next: RequestId,
    replies: Vec<Reply>,
    asked: usize,
    sent: usize,
    /// Bumped by the test: the catalogue changed (a command enabled).
    version: u64,
}

struct Counting(std::rc::Rc<std::cell::RefCell<Router>>);

impl Backend for Counting {
    fn submit(&mut self, method: &str, params: Value) -> RequestId {
        let mut r = self.0.borrow_mut();
        r.next += 1;
        let reply = match method {
            "engine.list" => {
                r.asked += 1;
                let etag = format!("v{}", r.version);
                if params["if_none_match"] == json!(etag) {
                    Ok(json!({"etag": etag, "unchanged": true}))
                } else {
                    r.sent += 1;
                    let enabled = r.version > 0;
                    Ok(json!({"etag": etag, "commands": [{"id": "system.analytics.test",
                        "label": "Test", "params": "{} → {requested}", "kind": "action",
                        "enabled": enabled, "disabledReason": if enabled { Value::Null } else { json!("no exporter") }}]}))
                }
            }
            "state.inspect" => Ok(json!({"identity": "sim"})),
            "server.info" => Ok(json!({"version": "sim"})),
            "engine.execute" => Ok(json!([])),
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
fn the_catalogue_comes_again_only_when_it_changed() {
    let router = std::rc::Rc::new(std::cell::RefCell::new(Router::default()));
    let mut app = CoreRouterUi::with_backend(Box::new(Counting(router.clone())));
    let ctx = egui::Context::default();
    let mut time = 0.0;
    let mut run = |app: &mut CoreRouterUi, secs: f64| {
        let end = time + secs;
        while time < end {
            let raw = egui::RawInput {
                time: Some(time),
                ..Default::default()
            };
            time += 0.1;
            ctx.run_ui(raw, |ui| app.ui(ui)).drop_without_applying_deltas();
        }
    };
    run(&mut app, 10.0);
    let (asked, sent) = (router.borrow().asked, router.borrow().sent);
    assert!(asked >= 8, "still asked every refresh: {asked}");
    assert_eq!(sent, 1, "sent once in 10 s");
    assert!(app.can().check("system.analytics.test").is_err(), "disabled, as the router said");
    // The router's state enables the command: the next refresh brings it.
    router.borrow_mut().version = 1;
    run(&mut app, 2.0);
    assert_eq!(router.borrow().sent, 2);
    assert!(app.can().check("system.analytics.test").is_ok(), "enabled without waiting");
}
