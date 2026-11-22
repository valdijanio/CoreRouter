//! `/system reboot` and `/system shutdown` (G1.6qa), as in RouterOS: the
//! commands only record the request here; the daemon's `power` service
//! takes it outside the session lock, gives the client a moment to read the
//! answer and asks PID 1 (corerouter-init) for a clean stop: SIGTERM to
//! reboot, SIGUSR2 to power off. Init stops the daemon with SIGTERM, which
//! writes the config checkpoint (G0.27), then FRR, syncs and unmounts
//! `/config`.
//!
//! The engine never stops a machine itself (it also runs in the browser
//! and in tests): off the image the service says so in [`Power::support`]
//! and the commands are disabled with that reason.

use crate::Session;

/// What was asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Reboot,
    Shutdown,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Reboot => "reboot",
            Action::Shutdown => "shutdown",
        }
    }
}

/// A request waiting for the service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub action: Action,
    /// Who asked ("tcp 192.0.2.7:50412"), for the daemon's log line.
    pub by: String,
}

/// Runtime state (`s.ext::<Power>()`), never saved.
#[derive(Debug, Default)]
pub struct Power {
    /// Set by the daemon's `power` service at start: `Ok` on the image,
    /// `Err(why)` elsewhere; `None` without a daemon (the lab, the browser).
    pub support: Option<Result<(), String>>,
    pub requested: Option<Request>,
}

/// The daemon's `power` service says whether it can stop the machine.
pub fn set_support(s: &mut Session, support: Result<(), String>) {
    if let Some(p) = s.ext_mut::<Power>() {
        p.support = Some(support);
    }
}

/// The request to carry out, taken once.
pub fn take_request(s: &mut Session) -> Option<Request> {
    s.ext_mut::<Power>().and_then(|p| p.requested.take())
}

/// Why the router cannot be stopped from here, if it cannot.
pub(crate) fn unsupported(s: &Session) -> Option<String> {
    match s.ext::<Power>().and_then(|p| p.support.as_ref()) {
        Some(Ok(())) => None,
        Some(Err(why)) => Some(why.clone()),
        None => Some("no daemon to carry it out (virtual lab)".into()),
    }
}
