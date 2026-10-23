use std::time::Duration;

use corerouter_control::dial::{Expect, Trust, local_token_hint};
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
///
/// An MCP server lives as long as the agent's session, longer than one
/// daemon process: when the router restarts (an upgrade, `land.sh`
/// rebuilding it) the connection is redialled on the next call, reading the
/// new local token, logging in again, and over TLS insisting on the
/// certificate of the first connection (audit-e2e: it used to answer
/// "send: Broken pipe" to every call until the MCP server was restarted).
pub struct Remote {
    /// `None` after the connection broke; the next call redials.
    client: Option<Client>,
    has_ui: bool,
    target: Target,
    login: Login,
    /// TLS: the certificate of the first connection.
    pinned: Option<String>,
}

/// How long a (re)connection may take.
const DIAL_TIMEOUT: Duration = Duration::from_millis(2000);

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
        let (client, has_ui) = Self::open(target, login, known, trust)?;
        Ok(Self {
            pinned: client.fingerprint().map(str::to_owned),
            client: Some(client),
            has_ui,
            target: target.clone(),
            login: login.clone(),
        })
    }

    fn open(
        target: &Target,
        login: &Login,
        known: &mut KnownHosts,
        trust: &mut dyn Trust,
    ) -> Result<(Client, bool), String> {
        let mut client = dial(target, DIAL_TIMEOUT, login, known, trust)?;
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
        Ok((client, has_ui))
    }

    /// A live connection: the one we have, or a new one when the router
    /// closed it (restart) or it broke.
    fn connection(&mut self) -> Result<&mut Client, String> {
        if self.client.as_ref().is_some_and(Client::is_stale) {
            log::info!("mcp: {} closed the connection; reconnecting", self.target);
            self.client = None;
        }
        if self.client.is_none() {
            let mut trust = Expect(self.pinned.clone().unwrap_or_default());
            let (client, has_ui) = Self::open(
                &self.target,
                &self.login,
                &mut KnownHosts::load_default(),
                &mut trust,
            )
            .map_err(|e| format!("the router is unreachable: {e}"))?;
            if self.target.tls && client.fingerprint() != self.pinned.as_deref() {
                return Err(format!(
                    "{}: the certificate changed since this MCP server connected; \
                     nothing was sent",
                    self.target
                ));
            }
            self.has_ui = has_ui;
            self.client = Some(client);
        }
        self.client
            .as_mut()
            .ok_or_else(|| "not connected".to_owned())
    }
}

impl Backend for Remote {
    fn call(&mut self, method: &str, params: Value) -> Result<Value, String> {
        let first = self.connection()?.request(method, params.clone());
        match first {
            // A login session ends after 30 min idle or 12 h (G0.3): the
            // token is checked before anything runs, so log in again and
            // send it once more.
            Ok(Err(e))
                if e.starts_with(UNAUTHORIZED) && matches!(self.login, Login::Password { .. }) =>
            {
                self.client = None;
                match self.connection()?.request(method, params) {
                    Ok(reply) => reply,
                    Err(e) => {
                        self.client = None;
                        Err(e)
                    }
                }
            }
            Ok(reply) => reply,
            Err(e) if e.starts_with("send:") => {
                // Nothing reached the router (it had closed the socket):
                // safe to send once more on a new connection.
                self.client = None;
                match self.connection()?.request(method, params) {
                    Ok(reply) => reply,
                    Err(e) => {
                        self.client = None;
                        Err(e)
                    }
                }
            }
            Err(e) => {
                self.client = None;
                Err(format!(
                    "{e}: the request may or may not have run (check before repeating \
                     it); the next call reconnects"
                ))
            }
        }
    }
    fn has_ui(&self) -> bool {
        self.has_ui
    }
    fn describe(&self) -> String {
        format!(
            "remote {}{}{}",
            if self.target.tls { "tls://" } else { "" },
            self.target.addr(),
            if self.has_ui { " (with UI)" } else { "" }
        )
    }
}
