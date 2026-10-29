//! Method table of the control channel.

use std::sync::atomic::{AtomicU64, Ordering};

use corerouter_engine::off_lock::Reply;
use corerouter_engine::{Caller, Session, Shared, lock};
use serde_json::{Value, json};

pub const NO_UI: &str = "ui.screenshot needs the GUI: start `corerouter-gui --control 7979` \
     and connect with `corerouter-cli mcp --connect 127.0.0.1:7979`";

const METHODS: &[&str] = &[
    "ping",
    "server.info",
    "auth.login",
    "auth.logout",
    "auth.whoami",
    "engine.list",
    "engine.execute",
    "engine.batch",
    "state.inspect",
    "ui.screenshot",
];

/// What a control endpoint is attached to: a bare session (headless), a
/// shared session (daemon), or a session plus a live window (GUI).
pub trait Host {
    fn with_session(
        &mut self,
        f: &mut dyn FnMut(&mut Session) -> Result<Value, String>,
    ) -> Result<Value, String>;

    /// [`Host::with_session`] for a command whose answer may be built
    /// after the session is released ([`Reply::Later`], G0.31b). Here, in
    /// place; a host that locks a shared session overrides it to run
    /// [`Reply::finish`] after unlocking.
    fn with_session_reply(
        &mut self,
        f: &mut dyn FnMut(&mut Session) -> Result<Reply, String>,
    ) -> Result<Value, String> {
        self.with_session(&mut |s| f(s)?.finish().map_err(|e| e.to_string()))
    }

    fn has_ui(&self) -> bool {
        false
    }

    /// `{"mimeType": "image/png", "data": <base64>}`.
    fn screenshot(&mut self) -> Result<Value, String> {
        Err(NO_UI.into())
    }

    /// A host whose session lives elsewhere (the GUI as a client of a
    /// daemon) answers here every method except `ping` and `ui.screenshot`.
    /// `None`: use [`Host::with_session`].
    fn forward(&mut self, _method: &str, _params: &Value) -> Option<Result<Value, String>> {
        None
    }
}

impl Host for Session {
    fn with_session(
        &mut self,
        f: &mut dyn FnMut(&mut Session) -> Result<Value, String>,
    ) -> Result<Value, String> {
        f(self)
    }
}

/// Host over a session shared with other threads (daemon, GUI).
#[derive(Clone)]
pub struct SharedHost(pub Shared);

impl Host for SharedHost {
    fn with_session(
        &mut self,
        f: &mut dyn FnMut(&mut Session) -> Result<Value, String>,
    ) -> Result<Value, String> {
        f(&mut lock(&self.0))
    }

    /// The lock is released before the answer is built: a list of 60 000
    /// routes no longer holds DHCP, PPPoE and the other clients (G0.31b).
    fn with_session_reply(
        &mut self,
        f: &mut dyn FnMut(&mut Session) -> Result<Reply, String>,
    ) -> Result<Value, String> {
        let reply = f(&mut lock(&self.0))?;
        reply.finish().map_err(|e| e.to_string())
    }
}

/// A [`Caller`] for a new connection, unique in this process (TCP and
/// WebSocket share the counter; 0 is [`Caller::LOCAL_ID`]).
pub fn new_caller(kind: &str, peer: impl std::fmt::Display) -> Caller {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    Caller::new(
        NEXT.fetch_add(1, Ordering::Relaxed),
        format!("{kind} {peer}"),
    )
}

/// The connection of `caller` closed: the session undoes its Safe Mode, if
/// it held one. Hosts without a local session (a GUI proxying a daemon) have
/// nothing to do: their own connection to the daemon closes with them.
pub fn hang_up(host: &mut dyn Host, caller: &Caller) {
    let _ = host.with_session(&mut |s| {
        s.hang_up(caller.id);
        Ok(Value::Null)
    });
}

/// `engine.list` with `{if_none_match: etag}` (G1.6q): `{etag, commands}`,
/// or `{etag, unchanged: true}` when the client already has this catalogue
/// (~300 KB that a GUI asked for every second). Without the parameter, the
/// bare list, as before (CLI, MCP, older GUIs).
pub fn catalogue_reply(list: Value, params: &Value) -> Value {
    let Some(seen) = params.get("if_none_match") else {
        return list;
    };
    let etag = catalogue_etag(&list);
    if seen.as_str() == Some(etag.as_str()) {
        json!({ "etag": etag, "unchanged": true })
    } else {
        json!({ "etag": etag, "commands": list })
    }
}

/// FNV-1a (64 bits) of the catalogue's JSON: the same list gives the same
/// tag in any process and across restarts.
fn catalogue_etag(list: &Value) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in list.to_string().bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{h:016x}")
}

/// [`dispatch_as`] for a caller inside this process.
pub fn dispatch(host: &mut dyn Host, method: &str, params: &Value) -> Result<Value, String> {
    dispatch_as(host, &Caller::local(), method, params)
}

/// Answer `method` for the connection `caller`.
pub fn dispatch_as(
    host: &mut dyn Host,
    caller: &Caller,
    method: &str,
    params: &Value,
) -> Result<Value, String> {
    let err = |e: corerouter_engine::EngineError| e.to_string();
    if !matches!(method, "ping" | "ui.screenshot")
        && let Some(answer) = host.forward(method, params)
    {
        return answer;
    }
    match method {
        "ping" => Ok(json!({ "pong": true })),
        "server.info" => {
            let has_ui = host.has_ui();
            host.with_session(&mut |s| {
                Ok(json!({
                    "name": "corerouter",
                    "version": env!("CARGO_PKG_VERSION"),
                    "commit": corerouter_buildinfo::COMMIT,
                    "backend": s.backend(),
                    "has_ui": has_ui,
                }))
            })
        }
        "engine.list" => {
            let list = host.with_session(&mut |s| Ok(s.list_as(caller)))?;
            Ok(catalogue_reply(list, params))
        }
        "engine.execute" => {
            let id = params
                .get("command")
                .and_then(Value::as_str)
                .ok_or("engine.execute needs {command, params?}")?;
            let p = params.get("params").cloned().unwrap_or(Value::Null);
            // `via` names the client program, for the log's origin (G4.6d).
            let caller = caller.clone().with_via(params);
            host.with_session_reply(&mut |s| s.execute_reply_as(&caller, id, &p).map_err(err))
        }
        "engine.batch" => {
            let steps = params.get("steps").cloned().unwrap_or(Value::Null);
            let atomic = params
                .get("atomic")
                .and_then(Value::as_bool)
                .unwrap_or(true);
            let caller = caller.clone().with_via(params);
            host.with_session(&mut |s| s.batch_as(&caller, &steps, atomic).map_err(err))
        }
        "state.inspect" => {
            let path = params.get("path").and_then(Value::as_str);
            host.with_session(&mut |s| s.inspect_as(caller, path).map_err(err))
        }
        "ui.screenshot" => host.screenshot(),
        other => {
            let hint = METHODS
                .iter()
                .find(|m| m.split('.').next() == other.split('.').next())
                .map(|m| format!("; did you mean '{m}'?"))
                .unwrap_or_default();
            Err(format!(
                "unknown method '{}'{hint}; methods: {}",
                other.chars().take(64).collect::<String>(),
                METHODS.join(", ")
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_engine::shared;

    #[test]
    fn dispatches_on_a_bare_session() {
        let mut s = Session::virtual_lab();
        assert_eq!(
            dispatch(&mut s, "ping", &Value::Null).unwrap()["pong"],
            true
        );
        let r = dispatch(
            &mut s,
            "engine.execute",
            &json!({"command": "system.identity.set", "params": {"name": "lab"}}),
        )
        .unwrap();
        assert_eq!(r["name"], "lab");
        assert!(dispatch(&mut s, "ui.screenshot", &Value::Null).is_err());
        assert!(
            dispatch(&mut s, "engine.exec", &Value::Null)
                .unwrap_err()
                .contains("did you mean")
        );
    }

    /// Forwards everything but `ping` and `ui.screenshot`.
    struct Proxy;

    impl Host for Proxy {
        fn with_session(
            &mut self,
            _f: &mut dyn FnMut(&mut Session) -> Result<Value, String>,
        ) -> Result<Value, String> {
            Err("no local session".into())
        }

        fn forward(&mut self, method: &str, _params: &Value) -> Option<Result<Value, String>> {
            Some(Ok(json!({ "forwarded": method })))
        }
    }

    #[test]
    fn the_catalogue_is_not_sent_again_unchanged() {
        let mut h = SharedHost(shared(Session::virtual_lab()));
        let bare = dispatch(&mut h, "engine.list", &Value::Null).unwrap();
        assert!(
            bare.as_array().is_some_and(|l| l.len() > 100),
            "old clients: the list"
        );
        let first = dispatch(&mut h, "engine.list", &json!({"if_none_match": ""})).unwrap();
        let etag = first["etag"].as_str().unwrap().to_owned();
        assert_eq!(first["commands"], bare);
        let again = dispatch(&mut h, "engine.list", &json!({"if_none_match": etag})).unwrap();
        assert_eq!(again, json!({"etag": etag, "unchanged": true}));
        assert!(again.to_string().len() < 100);
        // What greys commands out changed (a pending change): sent again.
        dispatch(
            &mut h,
            "engine.execute",
            &json!({"command": "config.mode.set", "params": {"mode": "transactional"}}),
        )
        .unwrap();
        dispatch(
            &mut h,
            "engine.execute",
            &json!({"command": "system.identity.set", "params": {"name": "x"}}),
        )
        .unwrap();
        let changed = dispatch(&mut h, "engine.list", &json!({"if_none_match": etag})).unwrap();
        assert_ne!(changed["etag"], json!(etag));
        assert!(changed["commands"].is_array());
    }

    #[test]
    fn forwarding_host_keeps_ping_and_screenshot_local() {
        let mut p = Proxy;
        assert_eq!(
            dispatch(&mut p, "engine.list", &Value::Null).unwrap()["forwarded"],
            "engine.list"
        );
        assert_eq!(
            dispatch(&mut p, "ping", &Value::Null).unwrap()["pong"],
            true
        );
        assert_eq!(
            dispatch(&mut p, "ui.screenshot", &Value::Null).unwrap_err(),
            NO_UI
        );
    }
}
