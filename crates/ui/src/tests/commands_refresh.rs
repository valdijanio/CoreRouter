//! G1.6q: the command catalogue (`engine.list`, ~300 KB on a router) is not
//! asked for on every one-second refresh: on the image an idle GUI pulled
//! ~300 KB/s over the management link, ~250 KB/s of it this list.

use super::*;

/// A router that counts the catalogue requests and whose revision the test
/// moves.
#[derive(Default)]
struct Router {
    next: RequestId,
    replies: Vec<Reply>,
    lists: usize,
    revision: u64,
}

struct Counting(std::rc::Rc<std::cell::RefCell<Router>>);

impl Backend for Counting {
    fn submit(&mut self, method: &str, _params: Value) -> RequestId {
        let mut r = self.0.borrow_mut();
        r.next += 1;
        let reply = match method {
            "engine.list" => {
                r.lists += 1;
                Ok(json!([{"id": "system.identity.set", "label": "Identity",
                    "params": "{name: string} → {name}", "kind": "action", "enabled": true}]))
            }
            "state.inspect" => Ok(json!({"identity": "sim", "revision": r.revision,
                "pending_changes": 0, "mode": "immediate", "safe_mode": {"active": false}})),
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
fn the_catalogue_is_asked_for_when_it_can_have_changed() {
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
    run(&mut app, 2.0);
    assert!(router.borrow().lists >= 1, "asked for on connect");
    assert!(app.can().check("system.identity.set").is_ok(), "and used");
    let after_connect = router.borrow().lists;
    // 5 s of refreshes with nothing changing: none.
    run(&mut app, 5.0);
    assert_eq!(router.borrow().lists, after_connect, "not every second");
    // A commit elsewhere moves the revision: asked again within 2 s.
    router.borrow_mut().revision = 7;
    run(&mut app, 2.0);
    assert_eq!(router.borrow().lists, after_connect + 1, "after the revision moved");
    // Quiet again: nothing for 10 s, then one by the 15 s mark.
    run(&mut app, 10.0);
    assert_eq!(router.borrow().lists, after_connect + 1, "quiet");
    run(&mut app, 6.0);
    assert_eq!(router.borrow().lists, after_connect + 2, "at least every 15 s");
}
