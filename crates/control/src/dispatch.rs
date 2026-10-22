//! Method table of the control channel.

use corerouter_engine::{Session, Shared, lock};
use serde_json::{Value, json};

pub const NO_UI: &str = "ui.screenshot needs the GUI: start `corerouter-gui --control 7979` \
     and connect with `corerouter-cli mcp --connect 127.0.0.1:7979`";

const METHODS: &[&str] = &[
    "ping",
    "server.info",
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

pub fn dispatch(host: &mut dyn Host, method: &str, params: &Value) -> Result<Value, String> {
    let err = |e: corerouter_engine::EngineError| e.to_string();
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
        "engine.list" => host.with_session(&mut |s| Ok(s.list())),
        "engine.execute" => {
            let id = params
                .get("command")
                .and_then(Value::as_str)
                .ok_or("engine.execute needs {command, params?}")?;
            let p = params.get("params").cloned().unwrap_or(Value::Null);
            host.with_session(&mut |s| s.execute(id, &p).map_err(err))
        }
        "engine.batch" => {
            let steps = params.get("steps").cloned().unwrap_or(Value::Null);
            let atomic = params
                .get("atomic")
                .and_then(Value::as_bool)
                .unwrap_or(true);
            host.with_session(&mut |s| s.batch(&steps, atomic).map_err(err))
        }
        "state.inspect" => {
            let path = params.get("path").and_then(Value::as_str);
            host.with_session(&mut |s| s.inspect(path).map_err(err))
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
}
