//! The MPLS echo responder (G3.5b) as the daemon's service sees it: what
//! to do (on or off, the rate, the interfaces) from the running config,
//! and its counters, kept in the session for `mpls.settings.get`.
//!
//! The service itself (thread, token bucket, packet I/O) lives in the
//! daemon; the answers come from `corerouter_hal::lsp::respond`.

use std::collections::BTreeMap;

use corerouter_hal::HalError;
use corerouter_hal::lsp::LspResponderIo;
use corerouter_model::IfName;
use serde_json::{Value, json};

use crate::Session;

/// What the service should do now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub enabled: bool,
    /// Replies per second.
    pub rate: u32,
    /// Interfaces that take labeled packets (requests arrive there,
    /// labeled or popped by the penultimate hop).
    pub interfaces: Vec<IfName>,
}

/// The plan from the running config: on when the setting is and some
/// interface takes MPLS.
pub fn plan(s: &Session) -> Plan {
    let cfg = s.store().running();
    let m = &cfg.routing.mpls;
    let interfaces: Vec<IfName> = cfg
        .interfaces
        .keys()
        .filter(|n| m.input_on(n))
        .cloned()
        .collect();
    Plan {
        enabled: m.settings.lsp_ping_responder && !interfaces.is_empty(),
        rate: m.settings.lsp_ping_rate.max(1),
        interfaces,
    }
}

/// The backend's I/O (taken once by the service, under the lock).
pub fn io(s: &Session) -> Result<Box<dyn LspResponderIo>, HalError> {
    s.hal().lsp_responder()
}

/// What the responder did since the daemon started.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Counters {
    pub running: bool,
    /// Requests heard (before the rate limit).
    pub heard: u64,
    pub replied: u64,
    /// Over the rate: dropped (RFC 8029 §5).
    pub rate_limited: u64,
    /// Not answered (reply mode "do not reply", not a request, T flag…).
    pub ignored: u64,
    /// Replies by return code.
    pub codes: BTreeMap<u8, u64>,
    pub error: Option<String>,
    /// Interfaces it could not listen on, and why.
    pub failed: Vec<(IfName, String)>,
}

pub fn set_counters(s: &mut Session, c: Counters) {
    if let Some(slot) = s.ext_mut::<Counters>() {
        *slot = c;
    }
}

/// The counters as JSON (`None`: no responder in this backend).
pub fn counters_json(s: &Session) -> Value {
    let Some(c) = s.ext::<Counters>() else {
        return Value::Null;
    };
    let codes: Vec<Value> = c
        .codes
        .iter()
        .map(|(code, n)| json!({"code": code, "count": n}))
        .collect();
    let failed: Vec<Value> = c
        .failed
        .iter()
        .map(|(i, why)| json!({"interface": i.as_str(), "error": why}))
        .collect();
    json!({
        "running": c.running,
        "heard": c.heard,
        "replied": c.replied,
        "rate_limited": c.rate_limited,
        "ignored": c.ignored,
        "codes": codes,
        "error": c.error,
        "failed": failed,
    })
}
