//! Where the UI's requests go: the in-process lab ([`Local`]) or a router
//! over the network (the apps implement [`Backend`] on the control channel
//! or a WebSocket).
//!
//! Requests and replies use the control-channel methods (`engine.execute`,
//! `engine.list`, `engine.batch`, `state.inspect`, …) so a remote router and
//! the local lab look the same to the panels. Nothing here blocks: `submit`
//! queues, `poll` collects what arrived, and the UI keeps drawing meanwhile.

use std::collections::VecDeque;

use corerouter_engine::{Caller, Shared, lock};
use serde_json::{Value, json};

/// Increases with every `submit` of one backend.
pub type RequestId = u64;

pub type Reply = (RequestId, Result<Value, String>);

/// State of the link to the router, shown in the top bar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Link {
    /// The router runs inside this process (virtual lab).
    Local,
    Connecting {
        target: String,
    },
    Connected {
        target: String,
    },
    Disconnected {
        target: String,
        reason: String,
    },
}

/// A request/response channel to a router.
///
/// Contract: every id returned by `submit` is answered exactly once by a
/// later `poll` (with an error when the link fails), in any order.
pub trait Backend {
    /// Queue `method(params)` and return its id at once.
    fn submit(&mut self, method: &str, params: Value) -> RequestId;
    /// Replies that arrived since the last call.
    fn poll(&mut self) -> Vec<Reply>;
    fn link(&self) -> Link;
}

/// The router in this process: answers on the spot, so the UI behaves as
/// if it were synchronous (tests, `corerouter-gui` without `--connect`, the
/// web demo with `?lab`).
pub struct Local {
    session: Shared,
    next: RequestId,
    ready: VecDeque<Reply>,
    /// Who the commands run as: in-process by default; tests pose as a
    /// control-channel connection to exercise what depends on it (the
    /// lockout check of G2.1b).
    caller: Caller,
}

impl Local {
    pub fn new(session: Shared) -> Self {
        Self::as_caller(session, Caller::local())
    }

    /// The commands run as `caller` (`Session::execute_as`).
    pub fn as_caller(session: Shared, caller: Caller) -> Self {
        Self {
            session,
            next: 0,
            ready: VecDeque::new(),
            caller,
        }
    }

    /// The method table of `corerouter_control::dispatch`, for the methods
    /// a session can answer (this crate does not depend on the network code).
    fn answer(&self, method: &str, params: &Value) -> Result<Value, String> {
        let mut s = lock(&self.session);
        let err = |e: corerouter_engine::EngineError| e.to_string();
        match method {
            "ping" => Ok(json!({ "pong": true })),
            "server.info" => Ok(json!({
                "name": "corerouter",
                "version": corerouter_buildinfo::VERSION,
                "version_full": corerouter_buildinfo::full(),
                "commit": corerouter_buildinfo::COMMIT,
                "build": corerouter_buildinfo::BUILD,
                "commit_time": corerouter_buildinfo::commit_unix(),
                "protocol": corerouter_buildinfo::PROTOCOL,
                "backend": s.backend(),
                "has_ui": true,
            })),
            "engine.list" => Ok(s.list_as(&self.caller)),
            "auth.whoami" => Ok(corerouter_engine::auth::whoami(
                &s,
                &corerouter_engine::Principal::Local,
                "local",
            )),
            "engine.execute" => {
                let id = params
                    .get("command")
                    .and_then(Value::as_str)
                    .ok_or("engine.execute needs {command, params?}")?;
                let p = params.get("params").cloned().unwrap_or(Value::Null);
                s.execute_as(&self.caller.clone().with_via(params), id, &p)
                    .map_err(err)
            }
            "engine.batch" => {
                let steps = params.get("steps").cloned().unwrap_or(Value::Null);
                let atomic = params
                    .get("atomic")
                    .and_then(Value::as_bool)
                    .unwrap_or(true);
                s.batch_as(&self.caller.clone().with_via(params), &steps, atomic)
                    .map_err(err)
            }
            "state.inspect" => {
                let path = params.get("path").and_then(Value::as_str);
                s.inspect_as(&self.caller, path).map_err(err)
            }
            other => Err(format!(
                "unknown method '{}'",
                other.chars().take(64).collect::<String>()
            )),
        }
    }
}

/// `params` of `engine.execute`/`engine.batch` with `via: "gui"` when the
/// sender did not name itself (the terminal says `terminal`): the log shows
/// where a change came from (G4.6d). Every backend sends through this.
pub fn tag_via(method: &str, mut params: Value) -> Value {
    if matches!(method, "engine.execute" | "engine.batch")
        && let Some(o) = params.as_object_mut()
    {
        o.entry("via").or_insert_with(|| json!("gui"));
    }
    params
}

impl Backend for Local {
    fn submit(&mut self, method: &str, params: Value) -> RequestId {
        self.next = self.next.wrapping_add(1);
        let params = tag_via(method, params);
        let reply = self.answer(method, &params);
        self.ready.push_back((self.next, reply));
        self.next
    }

    fn poll(&mut self) -> Vec<Reply> {
        self.ready.drain(..).collect()
    }

    fn link(&self) -> Link {
        Link::Local
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_engine::{Session, shared};

    #[test]
    fn local_answers_in_order_with_rising_ids() {
        let mut b = Local::new(shared(Session::virtual_lab()));
        let a = b.submit("ping", Value::Null);
        let c = b.submit(
            "engine.execute",
            json!({"command": "system.identity.set", "params": {"name": "x"}}),
        );
        let d = b.submit("bogus", Value::Null);
        assert!(a < c && c < d);
        let replies = b.poll();
        assert_eq!(replies.len(), 3);
        assert_eq!(replies[1].1.as_ref().unwrap()["name"], "x");
        assert!(replies[2].1.is_err());
        assert!(b.poll().is_empty());
    }
}
