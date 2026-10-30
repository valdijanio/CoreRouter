//! The MPLS echo responder (G3.5b) and the ICMP errors for expired labeled
//! packets (G3.9d) as the daemon's service sees them: what to do (on or
//! off, the rates, the interfaces) from the running config, and the
//! counters, kept in the session for `mpls.settings.get`.
//!
//! The service itself (thread, token buckets, packet I/O) lives in the
//! daemon; the answers come from `corerouter_hal::lsp::respond` and
//! `corerouter_hal::lsp::expired`.

use std::collections::BTreeMap;

use corerouter_hal::HalError;
use corerouter_hal::lsp::LspResponderIo;
use corerouter_model::IfName;
use serde_json::{Value, json};

use crate::Session;

/// What the service should do now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// Listening at all: some interface takes MPLS and [`Plan::echo`] or
    /// [`Plan::icmp`] is on.
    pub enabled: bool,
    /// Answer MPLS echo requests.
    pub echo: bool,
    /// Replies per second.
    pub rate: u32,
    /// Send ICMP time exceeded for expired labeled packets.
    pub icmp: bool,
    /// Those errors per second.
    pub icmp_rate: u32,
    /// Interfaces that take labeled packets (requests arrive there,
    /// labeled or popped by the penultimate hop).
    pub interfaces: Vec<IfName>,
}

/// The plan from the running config: on when a setting is and some
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
    let (echo, icmp) = (m.settings.lsp_ping_responder, m.settings.icmp_ttl_exceeded);
    Plan {
        enabled: (echo || icmp) && !interfaces.is_empty(),
        echo,
        rate: m.settings.lsp_ping_rate.max(1),
        icmp,
        icmp_rate: m.settings.icmp_rate.max(1),
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
    /// ICMP time exceeded for expired labeled packets (G3.9d).
    pub icmp: IcmpCounters,
}

/// What the ICMP side did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IcmpCounters {
    /// Expired labeled packets heard (before the rate limit).
    pub expired: u64,
    pub sent: u64,
    /// Over `icmp_rate`: no error sent.
    pub rate_limited: u64,
    /// No error by the rules (about an ICMP error, a fragment, no way
    /// back…) or a send that failed; why, with how many.
    pub dropped: u64,
    pub reasons: BTreeMap<String, u64>,
    pub error: Option<String>,
}

/// Reasons kept (a bounded map: they are fixed strings, plus send errors).
const MAX_REASONS: usize = 32;

impl IcmpCounters {
    pub fn drop(&mut self, why: &str) {
        self.dropped += 1;
        if let Some(n) = self.reasons.get_mut(why) {
            *n += 1;
        } else if self.reasons.len() < MAX_REASONS {
            self.reasons.insert(why.to_owned(), 1);
        }
    }
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

/// The ICMP counters as JSON (`None`: no responder in this backend).
pub fn icmp_json(s: &Session) -> Value {
    let Some(c) = s.ext::<Counters>() else {
        return Value::Null;
    };
    let i = &c.icmp;
    let reasons: Vec<Value> = i
        .reasons
        .iter()
        .map(|(why, n)| json!({"reason": why, "count": n}))
        .collect();
    json!({
        "expired": i.expired,
        "sent": i.sent,
        "rate_limited": i.rate_limited,
        "dropped": i.dropped,
        "reasons": reasons,
        "error": i.error,
    })
}
