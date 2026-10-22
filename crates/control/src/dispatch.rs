//! Method table of the control channel.

use std::sync::atomic::{AtomicU64, Ordering};

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
                    "backend": s.backend(),
                    "has_ui": has_ui,
                }))
            })
        }
        "engine.list" => host.with_session(&mut |s| Ok(s.list_as(caller))),
        "engine.execute" => {
            let id = params
                .get("command")
                .and_then(Value::as_str)
                .ok_or("engine.execute needs {command, params?}")?;
            let p = params.get("params").cloned().unwrap_or(Value::Null);
            // `via` names the client program, for the log's origin (G4.6d).
            let caller = caller.clone().with_via(params);
            host.with_session(&mut |s| s.execute_as(&caller, id, &p).map_err(err))
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
