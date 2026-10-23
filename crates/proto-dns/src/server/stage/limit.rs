//! Queries per second per client (`max_queries_per_client`), a token
//! bucket with a burst of twice the rate. IPv6 clients count per /64 (one
//! host can use a whole /64). Over the limit, a UDP query is dropped: an
//! answer, even REFUSED, is what a reflection attack wants; over TCP (no
//! spoofing possible) the client gets REFUSED.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;

use hickory_proto::op::ResponseCode;

use crate::resolver::Transport;
use crate::server::explain::Note;
use crate::server::{Forwarder, Query, Reply, Stage, Step};

pub(crate) const STAGE: Stage = Stage {
    name: "limit",
    order: 20,
    handle,
    after: None,
};

/// Clients tracked at once; past it, idle ones are forgotten first.
const MAX_CLIENTS: usize = 65_536;
/// A full table is swept for idle clients at most this often: under a
/// flood from many sources every new one would otherwise scan it all.
const SWEEP_EVERY_MS: u64 = 1000;

#[derive(Debug, Clone, Copy)]
struct Bucket {
    /// Thousandths of a query.
    milli: u64,
    last_ms: u64,
}

#[derive(Default)]
struct Table {
    map: HashMap<IpAddr, Bucket>,
    last_sweep_ms: Option<u64>,
    sweeps: u64,
}

#[derive(Default)]
pub(crate) struct Buckets(Mutex<Table>);

fn client_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => {
            let s = v6.segments();
            IpAddr::from([s[0], s[1], s[2], s[3], 0, 0, 0, 0])
        }
    }
}

impl Buckets {
    /// Whether `client`'s bucket holds a query now, without taking it (a
    /// simulated client, G6.8: it sent nothing).
    pub(crate) fn peek(&self, client: IpAddr, rate: u32, now_ms: u64) -> bool {
        let rate = u64::from(rate);
        let cap = rate * 2 * 1000;
        let table = self.0.lock().unwrap_or_else(|e| e.into_inner());
        table.map.get(&client_key(client)).is_none_or(|b| {
            let refill = now_ms.saturating_sub(b.last_ms).saturating_mul(rate);
            b.milli.saturating_add(refill).min(cap) >= 1000
        })
    }

    /// Takes one query from `client`'s bucket; false when it is empty.
    pub(crate) fn take(&self, client: IpAddr, rate: u32, now_ms: u64) -> bool {
        let rate = u64::from(rate);
        let cap = rate * 2 * 1000;
        let mut table = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let t = &mut *table;
        if t.map.len() >= MAX_CLIENTS && !t.map.contains_key(&client_key(client)) {
            let due = t
                .last_sweep_ms
                .is_none_or(|l| now_ms.saturating_sub(l) >= SWEEP_EVERY_MS);
            if due {
                // Full buckets (idle clients) carry no information.
                t.last_sweep_ms = Some(now_ms);
                t.sweeps = t.sweeps.saturating_add(1);
                t.map.retain(|_, b| {
                    b.milli
                        .saturating_add(now_ms.saturating_sub(b.last_ms).saturating_mul(rate))
                        < cap
                });
            }
            if t.map.len() >= MAX_CLIENTS {
                // Under a spoofed flood from many sources: do not grow; the
                // query goes on, still bounded by max_concurrent_queries.
                return true;
            }
        }
        let b = t.map.entry(client_key(client)).or_insert(Bucket {
            milli: cap,
            last_ms: now_ms,
        });
        // `rate` queries per second = `rate` thousandths per millisecond.
        let refill = now_ms.saturating_sub(b.last_ms).saturating_mul(rate);
        b.milli = b.milli.saturating_add(refill).min(cap);
        b.last_ms = now_ms;
        if b.milli >= 1000 {
            b.milli -= 1000;
            true
        } else {
            false
        }
    }
}

fn handle(f: &Forwarder, q: &mut Query, _: Option<&mut dyn Transport>) -> Step {
    let rate = q.config.config.ip.dns.max_queries_per_client;
    let client = q.client;
    if rate == 0 {
        q.note(|| Note::new("limit.off"));
        return Step::Next;
    }
    if client.is_loopback() {
        q.note(|| Note::new("limit.router"));
        return Step::Next;
    }
    let buckets = f.state::<Buckets>();
    let within = if q.simulated() {
        buckets.peek(client, rate, q.now_ms)
    } else {
        buckets.take(client, rate, q.now_ms)
    };
    if within {
        q.note(|| Note::new("limit.within").arg("client", client).arg("rate", rate));
        return Step::Next;
    }
    let tcp = q.tcp;
    q.note(|| {
        Note::new("limit.over")
            .arg("client", client)
            .arg("rate", rate)
            .arg("action", if tcp { "REFUSED (TCP)" } else { "dropped (UDP)" })
    });
    if q.tcp {
        Step::Reply(Reply::code(ResponseCode::Refused))
    } else {
        Step::Drop
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn burst_then_rate() {
        let b = Buckets::default();
        let c: IpAddr = [192, 168, 88, 10].into();
        let ok = (0..30).filter(|_| b.take(c, 10, 0)).count();
        assert_eq!(ok, 20, "burst of twice the rate");
        assert!(!b.take(c, 10, 50), "half a token after 50 ms");
        assert!(b.take(c, 10, 100), "one per 100 ms at 10/s");
        let other: IpAddr = [192, 168, 88, 11].into();
        assert!(b.take(other, 10, 100), "per client");
    }

    /// A full table of active clients and a flood from new sources: at
    /// most one sweep per second, not one per packet.
    #[test]
    fn a_full_table_is_swept_once_a_second() {
        let b = Buckets::default();
        for i in 0..u32::try_from(MAX_CLIENTS).unwrap() {
            assert!(b.take(IpAddr::from(std::net::Ipv4Addr::from((10u32 << 24) | i)), 10, 0));
        }
        for i in 0..10_000u32 {
            assert!(b.take(IpAddr::from(std::net::Ipv4Addr::from((172u32 << 24) | i)), 10, u64::from(i) / 100));
        }
        let t = b.0.lock().unwrap();
        assert!(t.sweeps <= 1, "{} sweeps", t.sweeps);
        assert_eq!(t.map.len(), MAX_CLIENTS);
    }

    #[test]
    fn peek_takes_nothing() {
        let b = Buckets::default();
        let c: IpAddr = [192, 168, 88, 10].into();
        assert!(b.peek(c, 1, 0), "an unknown client has a full bucket");
        assert!(b.take(c, 1, 0) && b.take(c, 1, 0));
        assert!(!b.peek(c, 1, 0), "empty now");
        assert!(!b.peek(c, 1, 0) && !b.take(c, 1, 0), "peeking took nothing back either");
        assert!(b.peek(c, 1, 1000), "one second later, one token");
    }

    #[test]
    fn ipv6_counts_per_64() {
        let b = Buckets::default();
        let one: IpAddr = "2001:db8:1:2::1".parse().unwrap();
        let two: IpAddr = "2001:db8:1:2::ffff".parse().unwrap();
        for _ in 0..2 {
            assert!(b.take(one, 1, 0));
        }
        assert!(!b.take(two, 1, 0), "same /64, same bucket");
    }
}
