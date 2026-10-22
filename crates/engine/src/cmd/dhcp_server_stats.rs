//! ip.dhcp-server.statistics (G4.2a): how the server is doing — pool use
//! (an alert from 80 %), messages by type, ACKs per second with the peak,
//! the processing time of the replies (p50/p99), and why messages got no
//! answer. The same numbers go to `/metrics` (`system.metrics` carries
//! them, the daemon renders them).

use corerouter_proto_dhcp::server::leases::State;
use corerouter_proto_dhcp::server::request::Kind;
use corerouter_proto_dhcp::server::stats::Drop;
use serde_json::{Value, json};

use super::{CommandSpec, always};
use crate::{Result, Session};

/// A pool this full is shown amber (the operator should grow it).
pub const POOL_ALERT_PERCENT: u64 = 80;

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(query "ip.dhcp-server.statistics.print", "DHCP Statistics", [], None,
        "{} → {since_secs (since start or reset), leases: {bound, offered, conflict, declined}, pools: [{pool, size, bound, offered, held, percent, alert (≥ 80 %)}], received: {discover, request, decline, release, inform}, sent: {offer, ack, nak}, ack_rate (ACKs in the last full second), acks_per_sec (the last 60 s), peak_acks (ACK/s), peak_secs_ago?, latency_us: {p50?, p99?, count} (from the request's arrival to its reply leaving; an OFFER's probe wait is not counted), dropped: [{reason, count, problem}], dropped_total, probes, conflicts, rogue_replies, journal_error?}",
        always, print),
    cmd!(
        "ip.dhcp-server.statistics.reset",
        "Reset DHCP Statistics",
        [],
        None,
        "{} → {reset}",
        always,
        reset
    ),
];

/// The statistics as JSON (also `system.metrics`' `dhcp_server`).
pub(crate) fn snapshot(s: &Session) -> Value {
    let now = s.dhcp_server_clock().unix;
    let Some(core) = s.dhcp_server() else {
        return json!(null);
    };
    let st = core.stats();
    let count = |state: State| core.leases().iter().filter(|l| l.state == state).count();
    let pools: Vec<Value> = core
        .pool_use()
        .into_iter()
        .map(|u| {
            json!({
                "pool": u.pool, "size": u.size, "bound": u.bound, "offered": u.offered,
                "held": u.held, "percent": u.percent(), "alert": u.percent() >= POOL_ALERT_PERCENT,
            })
        })
        .collect();
    let dropped: Vec<Value> = Drop::ALL
        .iter()
        .map(|d| json!({"reason": d.as_str(), "count": st.dropped_of(*d), "problem": d.is_problem()}))
        .collect();
    let window = st.acks_per_sec(now);
    let mut v = json!({
        "since_secs": now.saturating_sub(st.since),
        "leases": {
            "bound": count(State::Bound),
            "offered": count(State::Offered),
            "conflict": count(State::Conflict),
            "declined": count(State::Declined),
        },
        "pools": pools,
        "received": {
            "discover": st.received_of(Kind::Discover),
            "request": st.received_of(Kind::Request),
            "decline": st.received_of(Kind::Decline),
            "release": st.received_of(Kind::Release),
            "inform": st.received_of(Kind::Inform),
        },
        "sent": {
            "offer": st.sent_of(Kind::Offer),
            "ack": st.sent_of(Kind::Ack),
            "nak": st.sent_of(Kind::Nak),
        },
        "ack_rate": window.iter().rev().nth(1).copied().unwrap_or(0),
        "acks_per_sec": window,
        "peak_acks": st.peak_acks,
        "latency_us": {
            "p50": st.quantile_us(0.5),
            "p99": st.quantile_us(0.99),
            "count": st.latency_count(),
            "sum": st.latency_sum_us(),
            "buckets": st.latency_buckets().into_iter().map(|(b, n)| json!([if b == u64::MAX { Value::Null } else { json!(b) }, n])).collect::<Vec<_>>(),
        },
        "dropped": dropped,
        "dropped_total": Drop::ALL.iter().filter(|d| d.is_problem()).map(|d| st.dropped_of(*d)).sum::<u64>(),
        "probes": st.probes,
        "conflicts": st.conflicts,
        "rogue_replies": st.rogue_replies,
    });
    if let Some(o) = v.as_object_mut() {
        if st.peak_acks > 0 {
            o.insert("peak_secs_ago".into(), json!(now.saturating_sub(st.peak_at)));
        }
        if let Some(e) = s.dhcp_server_journal_error() {
            o.insert("journal_error".into(), json!(e));
        }
    }
    v
}

fn print(s: &mut Session, _: &Value) -> Result<Value> {
    let v = snapshot(s);
    if v.is_null() {
        return Ok(json!({
            "since_secs": 0, "leases": {"bound": 0, "offered": 0, "conflict": 0, "declined": 0},
            "pools": [], "received": {}, "sent": {}, "ack_rate": 0, "acks_per_sec": [], "peak_acks": 0,
            "latency_us": {"count": 0}, "dropped": [], "dropped_total": 0, "probes": 0, "conflicts": 0,
            "rogue_replies": 0,
        }));
    }
    Ok(v)
}

fn reset(s: &mut Session, _: &Value) -> Result<Value> {
    let now = s.dhcp_server_clock().unix;
    let done = s.dhcp_server_mut().map(|c| c.reset_stats(now)).is_some();
    Ok(json!({"reset": done}))
}
