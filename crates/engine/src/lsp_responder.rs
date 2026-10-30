//! The MPLS echo responder (G3.5b) and the ICMP errors for expired (G3.9d)
//! and too big (G3.9da) labeled packets as the daemon's service sees them: what to do (on or
//! off, the rates, the interfaces) from the running config, and the
//! counters, kept in the session for `mpls.settings.get`.
//!
//! The service itself (thread, token buckets, packet I/O) lives in the
//! daemon; the answers come from `corerouter_hal::lsp::respond` and
//! `corerouter_hal::lsp::expired` and `corerouter_hal::lsp::too_big`.

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
    /// Send ICMP fragmentation needed / packet too big (G3.9da).
    pub too_big: bool,
    /// ICMP errors per second, all sources.
    pub icmp_rate: u32,
    /// ICMP errors per second to one source.
    pub icmp_rate_per_source: u32,
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
    let st = &m.settings;
    let (echo, icmp, too_big) = (st.lsp_ping_responder, st.icmp_ttl_exceeded, st.icmp_too_big);
    Plan {
        enabled: (echo || icmp || too_big) && !interfaces.is_empty(),
        echo,
        rate: st.lsp_ping_rate.max(1),
        icmp,
        too_big,
        icmp_rate: st.icmp_rate.max(1),
        icmp_rate_per_source: st.icmp_rate_per_source.max(1),
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
    /// How frames are heard: the tc tap (G3.9db) or packet sockets, and
    /// why.
    pub tap: String,
    /// ICMP errors for expired (G3.9d) and too big (G3.9da) labeled
    /// packets.
    pub icmp: IcmpCounters,
}

/// What the ICMP side did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IcmpCounters {
    /// Expired labeled packets heard (before the rate limit).
    pub expired: u64,
    /// Labeled packets heard that may be too big (G3.9da).
    pub too_big: u64,
    /// Errors sent, both kinds.
    pub sent: u64,
    /// Of those, fragmentation needed / packet too big.
    pub too_big_sent: u64,
    /// Over `icmp_rate`: no error sent.
    pub rate_limited: u64,
    /// Over `icmp_rate_per_source` (G3.9da): no error sent.
    pub rate_limited_source: u64,
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
        "tap": c.tap,
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
        "too_big": i.too_big,
        "sent": i.sent,
        "too_big_sent": i.too_big_sent,
        "rate_limited": i.rate_limited,
        "rate_limited_source": i.rate_limited_source,
        "dropped": i.dropped,
        "reasons": reasons,
        "error": i.error,
    })
}
