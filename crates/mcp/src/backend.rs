use std::time::Duration;

use corerouter_control::dial::{Trust, local_token_hint};
use corerouter_control::{Client, KnownHosts, Login, Target, UNAUTHORIZED, dial, dispatch};
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

/// A running daemon or GUI reached over its control port: loopback with
/// the local token, or TLS with a user and password (G0.3).
pub struct Remote {
    client: Client,
    has_ui: bool,
}

impl Remote {
    /// `addr` on loopback with the local token (the default local setup).
    pub fn connect(addr: &str) -> Result<Self, String> {
        let target = Target::parse(addr)?;
        Self::dial(
            &target,
            &Login::Auto,
            &mut KnownHosts::load_default(),
            &mut corerouter_control::dial::RefuseNew,
        )
    }

    /// Connect, pin the certificate (TLS), log in, and check the login
    /// works, so a missing credential is one clear error up front.
    pub fn dial(
        target: &Target,
        login: &Login,
        known: &mut KnownHosts,
        trust: &mut dyn Trust,
    ) -> Result<Self, String> {
        let mut client = dial(target, Duration::from_millis(2000), login, known, trust)?;
        let info = client.call("server.info", Value::Null)?;
        let has_ui = info.get("has_ui").and_then(Value::as_bool).unwrap_or(false);
        if !matches!(login, Login::Nothing)
            && let Err(e) = client.call("auth.whoami", Value::Null)
        {
            return Err(if e.starts_with(UNAUTHORIZED) && !target.tls {
                format!("{target}: {}", local_token_hint(target.port))
            } else if e.starts_with(UNAUTHORIZED) {
                format!("{target}: log in with a user and password ({e})")
            } else {
                format!("{target}: {e}")
            });
        }
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
            "remote {}{}{}",
            if self.client.is_tls() { "tls://" } else { "" },
            self.client.addr(),
            if self.has_ui { " (with UI)" } else { "" }
        )
    }
}
