//! Answer cache by TTL, bounded by a byte budget (RouterOS `cache-size`,
//! in KiB), shared by the router's own lookups and the LAN forwarder. Any
//! record type, positive and negative (RFC 2308). Expired answers are kept
//! for `stale` more milliseconds, to be served when no server answers
//! (RFC 8767). The clock is the caller's (milliseconds of any monotonic
//! clock), so tests drive time and the crate stays wasm-safe.

use std::collections::BTreeMap;
use std::net::IpAddr;

use corerouter_model::dns::{CacheKind, CacheRow};
use hickory_proto::rr::RecordType;

use crate::message::Answer;

/// Negative answers live at most an hour, whatever the SOA says. RFC 2308
/// §5 suggests 1–3 hours as the cap; Unbound (`cache-max-negative-ttl`)
/// and VyOS (`negative-ttl`) both use 3600 s.
pub const MAX_NEGATIVE_TTL: u32 = 3600;
/// RFC 8767 §4: a stale answer goes out with TTL 30 s, so clients come
/// back soon for a fresh one.
pub const STALE_TTL: u32 = 30;
/// Book-keeping per entry on top of the records (estimated: map node,
/// key, vectors, the entry itself).
const ENTRY_OVERHEAD: usize = 128;
/// Per record: owner name, header, rdata (estimated from the wire size).
const RECORD_OVERHEAD: usize = 64;

type Key = (String, u16);

#[derive(Debug, Clone)]
struct Entry {
    answer: Answer,
    expires_ms: u64,
    server: Option<IpAddr>,
    hits: u64,
    size: usize,
}

/// A cached answer with its TTLs set to what is left.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    pub answer: Answer,
    pub ttl: u32,
    pub server: Option<IpAddr>,
    pub stale: bool,
}

#[derive(Debug, Default)]
pub struct Cache {
    map: BTreeMap<Key, Entry>,
    used: usize,
    budget: usize,
    stale_ms: u64,
}

fn key(name: &str, rtype: RecordType) -> Key {
    (name.to_owned(), u16::from(rtype))
}

impl Cache {
    pub fn new(budget_bytes: usize) -> Self {
        Self {
            budget: budget_bytes,
            ..Self::default()
        }
    }

    /// A new budget (config change); evicts down to it.
    pub fn set_budget(&mut self, budget_bytes: usize, now_ms: u64) {
        self.budget = budget_bytes;
        self.shrink(now_ms);
    }

    /// How long past its TTL an answer is kept for serve-stale (0: not).
    pub fn set_stale(&mut self, stale_secs: u32) {
        self.stale_ms = u64::from(stale_secs) * 1000;
    }

    pub fn used_bytes(&self) -> usize {
        self.used
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn flush(&mut self) {
        self.map.clear();
        self.used = 0;
    }

    /// The fresh answer for `name`/`rtype`, counted as a hit. An expired
    /// one stays while it may still be served stale.
    pub fn get(&mut self, name: &str, rtype: RecordType, now_ms: u64) -> Option<Hit> {
        let k = key(name, rtype);
        let stale_ms = self.stale_ms;
        let e = self.map.get_mut(&k)?;
        if e.expires_ms <= now_ms {
            if e.expires_ms.saturating_add(stale_ms) <= now_ms {
                self.remove(&k);
            }
            return None;
        }
        e.hits = e.hits.saturating_add(1);
        let left = secs_left(e.expires_ms, now_ms);
        Some(Hit {
            answer: e.answer.with_ttl(left),
            ttl: left,
            server: e.server,
            stale: false,
        })
    }

    /// RFC 8767 §4: an expired answer, while inside the serve-stale window,
    /// with TTL [`STALE_TTL`]. Only when no server answered.
    pub fn get_stale(&mut self, name: &str, rtype: RecordType, now_ms: u64) -> Option<Hit> {
        let stale_ms = self.stale_ms;
        let e = self.map.get_mut(&key(name, rtype))?;
        if e.expires_ms > now_ms || e.expires_ms.saturating_add(stale_ms) <= now_ms {
            return None;
        }
        e.hits = e.hits.saturating_add(1);
        Some(Hit {
            answer: e.answer.with_ttl(STALE_TTL),
            ttl: STALE_TTL,
            server: e.server,
            stale: true,
        })
    }

    /// Keeps `answer` for its TTL capped at `max_ttl` (and negatives at
    /// [`MAX_NEGATIVE_TTL`]). A TTL of zero is not cached (RFC 1035 §3.2.1:
    /// "zero values are interpreted to mean that the RR can only be used
    /// for the transaction in progress"), nor a negative answer without SOA
    /// (RFC 2308 §5). `wire` is the reply's size, to charge the budget.
    #[allow(clippy::too_many_arguments)]
    pub fn put(
        &mut self,
        name: &str,
        rtype: RecordType,
        answer: &Answer,
        server: Option<IpAddr>,
        now_ms: u64,
        max_ttl: u32,
        wire: usize,
    ) {
        let Some(ttl) = answer.ttl else { return };
        let ttl = match answer.kind(rtype) {
            CacheKind::Records => ttl,
            CacheKind::NxDomain | CacheKind::NoData => ttl.min(MAX_NEGATIVE_TTL),
        }
        .min(max_ttl);
        if ttl == 0 {
            return;
        }
        let records = answer.records.len() + answer.authority.len();
        let size = ENTRY_OVERHEAD + name.len() + records * RECORD_OVERHEAD + wire;
        if size > self.budget {
            return;
        }
        let k = key(name, rtype);
        self.remove(&k);
        self.used += size;
        self.map.insert(
            k,
            Entry {
                answer: answer.clone(),
                expires_ms: now_ms.saturating_add(u64::from(ttl) * 1000),
                server,
                hits: 0,
                size,
            },
        );
        self.shrink(now_ms);
    }

    fn remove(&mut self, k: &Key) {
        if let Some(old) = self.map.remove(k) {
            self.used = self.used.saturating_sub(old.size);
        }
    }

    /// Evicts until under budget: answers past their stale window first,
    /// then those that expire soonest (stale ones are the soonest of all).
    fn shrink(&mut self, now_ms: u64) {
        if self.used <= self.budget {
            return;
        }
        let stale_ms = self.stale_ms;
        let dead: Vec<Key> = self
            .map
            .iter()
            .filter(|(_, e)| e.expires_ms.saturating_add(stale_ms) <= now_ms)
            .map(|(k, _)| k.clone())
            .collect();
        for k in &dead {
            self.remove(k);
        }
        while self.used > self.budget {
            let Some(k) = self
                .map
                .iter()
                .min_by_key(|(_, e)| e.expires_ms)
                .map(|(k, _)| k.clone())
            else {
                self.used = 0;
                break;
            };
            self.remove(&k);
        }
    }

    /// Entries by name (`ip.dns.cache.print`), stale ones included.
    pub fn rows(&self, now_ms: u64) -> Vec<CacheRow> {
        let stale_ms = self.stale_ms;
        self.map
            .iter()
            .filter(|(_, e)| e.expires_ms.saturating_add(stale_ms) > now_ms)
            .map(|((name, t), e)| {
                let rtype = RecordType::from(*t);
                CacheRow {
                    name: name.clone(),
                    qtype: rtype.to_string(),
                    kind: e.answer.kind(rtype),
                    data: e
                        .answer
                        .records
                        .iter()
                        .map(|r| format!("{} {}", r.record_type(), r.data))
                        .collect(),
                    addresses: e.answer.addresses(),
                    ttl: if e.expires_ms > now_ms {
                        secs_left(e.expires_ms, now_ms)
                    } else {
                        0
                    },
                    hits: e.hits,
                    server: e.server,
                    stale: e.expires_ms <= now_ms,
                }
            })
            .collect()
    }
}

fn secs_left(expires_ms: u64, now_ms: u64) -> u32 {
    u32::try_from(expires_ms.saturating_sub(now_ms).div_ceil(1000)).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::Rcode;
    use crate::message::tests::a;

    fn addrs(ip: [u8; 4], ttl: u32) -> Answer {
        Answer::local(Rcode::NoError, vec![a("h.example", ttl, ip)])
    }

    fn negative(rcode: Rcode, ttl: Option<u32>) -> Answer {
        Answer {
            rcode,
            records: Vec::new(),
            authority: Vec::new(),
            ttl,
        }
    }

    const A: RecordType = RecordType::A;
    const WEEK: u32 = 604_800;

    #[test]
    fn entries_expire_with_their_ttl() {
        let mut c = Cache::new(1 << 20);
        c.put(
            "a.example",
            A,
            &addrs([192, 0, 2, 1], 60),
            None,
            0,
            WEEK,
            40,
        );
        let hit = c.get("a.example", A, 1_000).unwrap();
        assert_eq!(hit.ttl, 59);
        assert_eq!(hit.answer.records[0].ttl, 59, "TTL counts down for clients");
        assert!(c.get("a.example", RecordType::AAAA, 1_000).is_none());
        assert!(c.get("a.example", A, 60_000).is_none(), "expired");
        assert!(c.is_empty() && c.used_bytes() == 0);
    }

    #[test]
    fn ttl_is_capped_and_zero_is_not_kept() {
        let mut c = Cache::new(1 << 20);
        c.put("a", A, &addrs([192, 0, 2, 1], 86_400), None, 0, 300, 40);
        assert_eq!(c.get("a", A, 0).unwrap().ttl, 300, "cache_max_ttl");
        c.put("b", A, &addrs([192, 0, 2, 1], 0), None, 0, 300, 40);
        assert!(c.get("b", A, 0).is_none(), "RFC 1035 §3.2.1");
    }

    #[test]
    fn negative_answers_rfc2308() {
        let mut c = Cache::new(1 << 20);
        c.put(
            "nx",
            A,
            &negative(Rcode::NxDomain, Some(86_400)),
            None,
            0,
            WEEK,
            40,
        );
        let hit = c.get("nx", A, 0).unwrap();
        assert_eq!(
            (hit.answer.rcode, hit.ttl),
            (Rcode::NxDomain, MAX_NEGATIVE_TTL)
        );
        c.put(
            "bare",
            A,
            &negative(Rcode::NoError, None),
            None,
            0,
            WEEK,
            40,
        );
        assert!(c.get("bare", A, 0).is_none(), "no SOA, not cached");
    }

    #[test]
    fn budget_evicts_the_soonest_to_expire() {
        let one = ENTRY_OVERHEAD + 2 + RECORD_OVERHEAD + 40;
        let mut c = Cache::new(3 * one);
        for (i, ttl) in [(1u8, 500u32), (2, 100), (3, 900), (4, 700)] {
            c.put(
                &format!("h{i}"),
                A,
                &addrs([192, 0, 2, i], ttl),
                None,
                0,
                WEEK,
                40,
            );
        }
        assert_eq!(c.len(), 3);
        assert!(c.get("h2", A, 0).is_none(), "shortest TTL went first");
        assert!(c.used_bytes() <= 3 * one);
        c.set_budget(0, 0);
        assert!(c.is_empty());
        c.put("x", A, &addrs([192, 0, 2, 9], 60), None, 0, WEEK, 40);
        assert!(c.is_empty(), "cache_size 0 turns the cache off");
    }

    #[test]
    fn stale_answers_rfc8767() {
        let mut c = Cache::new(1 << 20);
        c.set_stale(3600);
        c.put("s", A, &addrs([192, 0, 2, 1], 60), None, 0, WEEK, 40);
        assert!(c.get_stale("s", A, 10_000).is_none(), "fresh is not stale");
        assert!(c.get("s", A, 61_000).is_none(), "expired is not fresh");
        let hit = c.get_stale("s", A, 61_000).unwrap();
        assert!(hit.stale);
        assert_eq!(hit.answer.records[0].ttl, STALE_TTL, "RFC 8767 §4");
        assert!(c.rows(61_000)[0].stale);
        assert!(
            c.get_stale("s", A, 60_000 + 3_600_000).is_none(),
            "window over"
        );
        c.set_stale(0);
        c.put("t", A, &addrs([192, 0, 2, 1], 60), None, 0, WEEK, 40);
        assert!(c.get_stale("t", A, 61_000).is_none(), "serve_stale off");
    }

    #[test]
    fn rows_hits_and_flush() {
        let mut c = Cache::new(1 << 20);
        let srv: IpAddr = [192, 0, 2, 53].into();
        c.put("b", A, &addrs([192, 0, 2, 2], 60), Some(srv), 0, WEEK, 40);
        c.put(
            "a",
            RecordType::AAAA,
            &negative(Rcode::NoError, Some(30)),
            Some(srv),
            0,
            WEEK,
            40,
        );
        c.get("b", A, 1).unwrap();
        c.get("b", A, 2).unwrap();
        let rows = c.rows(10_000);
        assert_eq!(rows.len(), 2);
        assert_eq!(
            (rows[0].name.as_str(), rows[0].ttl, rows[0].qtype.as_str()),
            ("a", 20, "AAAA")
        );
        assert_eq!(rows[0].kind, CacheKind::NoData);
        assert_eq!(rows[1].server, Some(srv));
        assert_eq!(rows[1].hits, 2);
        assert_eq!(rows[1].data, vec!["A 192.0.2.2".to_owned()]);
        c.flush();
        assert!(c.rows(0).is_empty() && c.used_bytes() == 0);
    }
}
