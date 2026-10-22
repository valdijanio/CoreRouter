//! Queries per second per client (`max_queries_per_client`), a token
//! bucket with a burst of twice the rate. IPv6 clients count per /64 (one
//! host can use a whole /64). Over the limit, a UDP query is dropped: an
//! answer, even REFUSED, is what a reflection attack wants; over TCP (no
//! spoofing possible) the client gets REFUSED.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;

use hickory_proto::op::ResponseCode;

use crate::server::{Forwarder, Query, Reply, Stage, Step};
use crate::resolver::Transport;

pub(crate) const STAGE: Stage = Stage {
    name: "limit",
    order: 20,
    handle,
    after: None,
};

/// Clients tracked at once; past it, idle ones are forgotten first.
const MAX_CLIENTS: usize = 65_536;

#[derive(Debug, Clone, Copy)]
struct Bucket {
    /// Thousandths of a query.
    milli: u64,
    last_ms: u64,
}

#[derive(Default)]
pub(crate) struct Buckets(Mutex<HashMap<IpAddr, Bucket>>);

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
    /// Takes one query from `client`'s bucket; false when it is empty.
    pub(crate) fn take(&self, client: IpAddr, rate: u32, now_ms: u64) -> bool {
        let rate = u64::from(rate);
        let cap = rate * 2 * 1000;
        let mut map = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if map.len() >= MAX_CLIENTS && !map.contains_key(&client_key(client)) {
            // Full buckets (idle clients) carry no information.
            map.retain(|_, b| b.milli + now_ms.saturating_sub(b.last_ms) * rate < cap);
            if map.len() >= MAX_CLIENTS {
                // Under a spoofed flood from many sources: do not grow; the
                // query goes on, still bounded by max_concurrent_queries.
                return true;
            }
        }
        let b = map.entry(client_key(client)).or_insert(Bucket {
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
    if rate == 0 || q.client.is_loopback() || f.state::<Buckets>().take(q.client, rate, q.now_ms) {
        return Step::Next;
    }
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
