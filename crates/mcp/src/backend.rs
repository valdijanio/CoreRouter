use std::time::Duration;

use corerouter_control::{Client, dispatch};
use corerouter_engine::Session;
use serde_json::Value;

pub trait Backend {
    /// Call a control-channel method ("engine.execute", "state.inspect", "ui.screenshot"...).
    fn call(&mut self, method: &str, params: Value) -> Result<Value, String>;
    /// true when a real window is attached (ui.* methods work).
    fn has_ui(&self) -> bool;
    /// "headless (virtual lab (8 ports))", "remote 127.0.0.1:7979".
    fn describe(&self) -> String;
}

/// In-process engine. Implements the same method names as the control channel.
pub struct Headless {
    session: Session,
}

impl Headless {
    pub fn new(session: Session) -> Self {
        Self { session }
    }
}

impl Backend for Headless {
    fn call(&mut self, method: &str, params: Value) -> Result<Value, String> {
        dispatch(&mut self.session, method, &params)
    }
    fn has_ui(&self) -> bool {
        false
    }
    fn describe(&self) -> String {
        format!("headless ({})", self.session.backend())
    }
}

/// A running daemon or GUI reached over the loopback control port.
pub struct Remote {
    client: Client,
    has_ui: bool,
}

impl Remote {
    pub fn connect(addr: &str) -> Result<Self, String> {
        let mut client = Client::connect(addr, Duration::from_millis(500))?;
        let info = client.call("server.info", Value::Null)?;
        let has_ui = info.get("has_ui").and_then(Value::as_bool).unwrap_or(false);
        Ok(Self { client, has_ui })
    }
}

impl Backend for Remote {
    fn call(&mut self, method: &str, params: Value) -> Result<Value, String> {
        self.client.call(method, params)
    }
    fn has_ui(&self) -> bool {
        self.has_ui
    }
    fn describe(&self) -> String {
        format!(
            "remote {}{}",
            self.client.addr(),
            if self.has_ui { " (with UI)" } else { "" }
        )
    }
}
