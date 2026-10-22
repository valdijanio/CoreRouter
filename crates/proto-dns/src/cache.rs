//! Answer cache by TTL, bounded by a byte budget (RouterOS `cache-size`,
//! in KiB). The clock is the caller's (milliseconds of any monotonic
//! clock), so tests drive time and the crate stays wasm-safe.

use std::collections::BTreeMap;
use std::net::IpAddr;

use corerouter_model::dns::{CacheRow, CachedData, QType};

use crate::message::Outcome;

/// Negative answers live at most an hour, whatever the SOA says. RFC 2308
/// §5 suggests 1–3 hours as the cap; Unbound (`cache-max-negative-ttl`)
/// and VyOS (`negative-ttl`) both use 3600 s.
pub const MAX_NEGATIVE_TTL: u32 = 3600;
/// Book-keeping per entry on top of the name and addresses (estimated:
/// map node, strings, the entry itself).
const ENTRY_OVERHEAD: usize = 96;

#[derive(Debug, Clone)]
struct Entry {
    data: CachedData,
    expires_ms: u64,
    server: Option<IpAddr>,
    size: usize,
}

#[derive(Debug, Default)]
pub struct Cache {
    map: BTreeMap<(String, QType), Entry>,
    used: usize,
    budget: usize,
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

    /// The cached answer and its seconds left; an expired one is dropped.
    pub fn get(&mut self, key: &str, q: QType, now_ms: u64) -> Option<(CachedData, u32)> {
        let k = (key.to_owned(), q);
        let e = self.map.get(&k)?;
        if e.expires_ms <= now_ms {
            self.remove(&k);
            return None;
        }
        let left = (e.expires_ms - now_ms).div_ceil(1000);
        Some((e.data.clone(), u32::try_from(left).unwrap_or(u32::MAX)))
    }

    /// Keeps `outcome` for its TTL capped at `max_ttl` (and negatives at
    /// [`MAX_NEGATIVE_TTL`]). A TTL of zero is not cached (RFC 1035
    /// §3.2.1: "zero values are interpreted to mean that the RR can only
    /// be used for the transaction in progress").
    pub fn put(
        &mut self,
        key: &str,
        q: QType,
        outcome: &Outcome,
        server: Option<IpAddr>,
        now_ms: u64,
        max_ttl: u32,
    ) {
        let (data, ttl) = match outcome {
            Outcome::Addresses {
                addresses,
                canonical,
                ttl,
            } => (
                CachedData::Addresses {
                    addresses: addresses.clone(),
                    canonical: canonical.clone(),
                },
                *ttl,
            ),
            Outcome::Records {
                records,
                canonical,
                ttl,
            } => (
                CachedData::Records {
                    records: records.clone(),
                    canonical: canonical.clone(),
                },
                *ttl,
            ),
            // RFC 2308 §5: without SOA there is no negative TTL: not cached.
            Outcome::NxDomain { ttl: None } | Outcome::NoData { ttl: None } => return,
            Outcome::NxDomain { ttl: Some(t) } => {
                (CachedData::NxDomain, (*t).min(MAX_NEGATIVE_TTL))
            }
            Outcome::NoData { ttl: Some(t) } => (CachedData::NoData, (*t).min(MAX_NEGATIVE_TTL)),
        };
        let ttl = ttl.min(max_ttl);
        if ttl == 0 {
            return;
        }
        let size = ENTRY_OVERHEAD
            + key.len()
            + match &data {
                CachedData::Addresses {
                    addresses,
                    canonical,
                } => addresses.len() * 16 + canonical.as_ref().map_or(0, String::len),
                CachedData::Records { records, canonical } => {
                    records.iter().map(String::len).sum::<usize>()
                        + canonical.as_ref().map_or(0, String::len)
                }
                _ => 0,
            };
        if size > self.budget {
            return;
        }
        let k = (key.to_owned(), q);
        self.remove(&k);
        self.used += size;
        self.map.insert(
            k,
            Entry {
                data,
                expires_ms: now_ms.saturating_add(u64::from(ttl) * 1000),
                server,
                size,
            },
        );
        self.shrink(now_ms);
    }

    fn remove(&mut self, k: &(String, QType)) {
        if let Some(old) = self.map.remove(k) {
            self.used = self.used.saturating_sub(old.size);
        }
    }

    /// Evicts until under budget: expired entries first, then those that
    /// expire soonest (they are worth least).
    fn shrink(&mut self, now_ms: u64) {
        if self.used <= self.budget {
            return;
        }
        let expired: Vec<(String, QType)> = self
            .map
            .iter()
            .filter(|(_, e)| e.expires_ms <= now_ms)
            .map(|(k, _)| k.clone())
            .collect();
        for k in &expired {
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

    /// Live entries, by name (`ip.dns.cache.print`).
    pub fn rows(&self, now_ms: u64) -> Vec<CacheRow> {
        self.map
            .iter()
            .filter(|(_, e)| e.expires_ms > now_ms)
            .map(|((name, q), e)| CacheRow {
                name: name.clone(),
                qtype: *q,
                data: e.data.clone(),
                ttl: u32::try_from((e.expires_ms - now_ms).div_ceil(1000)).unwrap_or(u32::MAX),
                server: e.server,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addrs(ip: [u8; 4], ttl: u32) -> Outcome {
        Outcome::Addresses {
            addresses: vec![IpAddr::from(ip)],
            canonical: None,
            ttl,
        }
    }

    #[test]
    fn entries_expire_with_their_ttl() {
        let mut c = Cache::new(1 << 20);
        c.put(
            "a.example",
            QType::A,
            &addrs([192, 0, 2, 1], 60),
            None,
            0,
            604_800,
        );
        let (data, left) = c.get("a.example", QType::A, 1_000).unwrap();
        assert_eq!(left, 59);
        assert!(matches!(data, CachedData::Addresses { .. }));
        assert!(c.get("a.example", QType::Aaaa, 1_000).is_none());
        assert!(c.get("a.example", QType::A, 60_000).is_none(), "expired");
        assert!(c.is_empty() && c.used_bytes() == 0);
    }

    #[test]
    fn ttl_is_capped_and_zero_is_not_kept() {
        let mut c = Cache::new(1 << 20);
        c.put("a", QType::A, &addrs([192, 0, 2, 1], 86_400), None, 0, 300);
        assert_eq!(c.get("a", QType::A, 0).unwrap().1, 300, "cache_max_ttl");
        c.put("b", QType::A, &addrs([192, 0, 2, 1], 0), None, 0, 300);
        assert!(c.get("b", QType::A, 0).is_none(), "RFC 1035 §3.2.1");
    }

    #[test]
    fn negative_answers_rfc2308() {
        let mut c = Cache::new(1 << 20);
        c.put(
            "nx",
            QType::A,
            &Outcome::NxDomain { ttl: Some(86_400) },
            None,
            0,
            604_800,
        );
        assert_eq!(
            c.get("nx", QType::A, 0),
            Some((CachedData::NxDomain, MAX_NEGATIVE_TTL))
        );
        c.put(
            "bare",
            QType::A,
            &Outcome::NoData { ttl: None },
            None,
            0,
            604_800,
        );
        assert!(c.get("bare", QType::A, 0).is_none(), "no SOA, not cached");
    }

    #[test]
    fn budget_evicts_the_soonest_to_expire() {
        let mut c = Cache::new(3 * (ENTRY_OVERHEAD + 16 + 2));
        for (i, ttl) in [(1u8, 500u32), (2, 100), (3, 900), (4, 700)] {
            c.put(
                &format!("h{i}"),
                QType::A,
                &addrs([192, 0, 2, i], ttl),
                None,
                0,
                604_800,
            );
        }
        assert_eq!(c.len(), 3);
        assert!(
            c.get("h2", QType::A, 0).is_none(),
            "shortest TTL went first"
        );
        assert!(c.used_bytes() <= 3 * (ENTRY_OVERHEAD + 18));
        c.set_budget(0, 0);
        assert!(c.is_empty());
        c.put("x", QType::A, &addrs([192, 0, 2, 9], 60), None, 0, 604_800);
        assert!(c.is_empty(), "cache_size 0 turns the cache off");
    }

    #[test]
    fn rows_and_flush() {
        let mut c = Cache::new(1 << 20);
        let srv: IpAddr = [192, 0, 2, 53].into();
        c.put(
            "b",
            QType::A,
            &addrs([192, 0, 2, 2], 60),
            Some(srv),
            0,
            604_800,
        );
        c.put(
            "a",
            QType::Aaaa,
            &Outcome::NoData { ttl: Some(30) },
            Some(srv),
            0,
            604_800,
        );
        let rows = c.rows(10_000);
        assert_eq!(rows.len(), 2);
        assert_eq!((rows[0].name.as_str(), rows[0].ttl), ("a", 20));
        assert_eq!(rows[1].server, Some(srv));
        c.flush();
        assert!(c.rows(0).is_empty() && c.used_bytes() == 0);
    }
}
