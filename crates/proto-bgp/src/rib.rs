//! The routes of one neighbor, indexed for `routing.bgp.route.list`
//! (G3.2c): sorted by prefix once, RFC 6811 state of every route computed
//! once, then searched and cut into pages as many times as the window
//! asks, like `ip.route.page` (G1.27c) does for the kernel table.
//!
//! Prefix search is a binary search into the sorted routes (the routes
//! inside a prefix are contiguous); AS-path and community searches look
//! at the interned attribute sets once, not at every route.

use std::net::IpAddr;

use corerouter_model::bgp_rib::{BgpAttrs, BgpRib, BgpRoute};
use corerouter_model::rpki::RpkiState;
use ipnet::IpNet;

use crate::rpki::{VrpTable, key_of, origin_as};

/// How a route's prefix must relate to the one searched (Junos `exact |
/// longer | orlonger`, plus `covering` for "which routes contain it").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Match {
    Exact,
    Longer,
    OrLonger,
    Covering,
}

impl Match {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "exact" => Some(Match::Exact),
            "longer" => Some(Match::Longer),
            "orlonger" => Some(Match::OrLonger),
            "covering" => Some(Match::Covering),
            _ => None,
        }
    }
}

/// An AS-path search: ASNs that must appear one after the other, `^` to
/// anchor at the neighbor's end, `$` at the origin's (Cisco/Junos regex
/// anchors, without the rest of the regex language).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsPathPattern {
    pub asns: Vec<u32>,
    pub start: bool,
    pub end: bool,
}

impl AsPathPattern {
    pub fn parse(s: &str) -> Result<Self, String> {
        let t = s.trim();
        let start = t.starts_with('^');
        let end = t.ends_with('$');
        let body = t.trim_start_matches('^').trim_end_matches('$');
        let mut asns = Vec::new();
        for w in body.split([' ', '_', ',']).filter(|w| !w.is_empty()) {
            asns.push(w.parse::<u32>().map_err(|_| {
                format!(
                    "{:?} is not an AS number (use ^, $ and AS numbers)",
                    w.chars().take(20).collect::<String>()
                )
            })?);
            if asns.len() > 64 {
                return Err("at most 64 AS numbers in a search".into());
            }
        }
        if asns.is_empty() && !(start && end) {
            return Err("an AS-path search needs an AS number (or ^$ for our own routes)".into());
        }
        Ok(AsPathPattern { asns, start, end })
    }

    /// Whether the path as FRR prints it matches.
    pub fn matches(&self, path: &str) -> bool {
        let tokens: Vec<u32> = path
            .split(|c: char| !c.is_ascii_digit())
            .filter(|w| !w.is_empty())
            .filter_map(|w| w.parse().ok())
            .collect();
        let n = self.asns.len();
        if n == 0 {
            return tokens.is_empty();
        }
        if tokens.len() < n {
            return false;
        }
        let last = tokens.len() - n;
        (0..=last)
            .filter(|&i| (!self.start || i == 0) && (!self.end || i == last))
            .any(|i| tokens.get(i..i + n) == Some(self.asns.as_slice()))
    }
}

/// A search of the routes.
#[derive(Debug, Clone, Default)]
pub struct Query {
    pub prefix: Option<(IpNet, Match)>,
    pub as_path: Option<AsPathPattern>,
    /// A standard (`a:b`), large (`a:b:c`) or well-known community.
    pub community: Option<String>,
    pub rpki: Option<RpkiState>,
    pub filtered: Option<bool>,
}

/// Counts of the whole table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Summary {
    pub total: u64,
    pub ipv4: u64,
    pub ipv6: u64,
    pub best: u64,
    pub filtered: u64,
    /// valid, invalid, unknown, unverified.
    pub rpki: [u64; 4],
}

/// A table sorted by prefix, with the RPKI state of each route.
#[derive(Debug, Clone, Default)]
pub struct Indexed {
    pub rib: BgpRib,
    /// (v6, key, len) of each route, sorted: the search key.
    keys: Vec<(bool, u128, u8)>,
    pub states: Vec<RpkiState>,
    pub summary: Summary,
}

fn state_index(s: RpkiState) -> usize {
    match s {
        RpkiState::Valid => 0,
        RpkiState::Invalid => 1,
        RpkiState::Unknown => 2,
        RpkiState::Unverified => 3,
    }
}

fn key(p: &IpNet) -> (bool, u128, u8) {
    let (k, v6) = key_of(p.network());
    (v6, k, p.prefix_len())
}

impl Indexed {
    /// Sort and validate (`vrps` `None`: no validator in sync, every
    /// route `unverified`). `local_as`: the origin of our own routes.
    pub fn new(mut rib: BgpRib, vrps: Option<&VrpTable>, local_as: Option<u32>) -> Indexed {
        rib.routes.sort_unstable_by_key(|r| key(&r.prefix));
        let keys: Vec<(bool, u128, u8)> = rib.routes.iter().map(|r| key(&r.prefix)).collect();
        // Origin AS once per attribute set, not per route.
        let origins: Vec<Option<u32>> = rib
            .attrs
            .iter()
            .map(|a| origin_as(&a.as_path, local_as))
            .collect();
        let mut summary = Summary::default();
        let states: Vec<RpkiState> = rib
            .routes
            .iter()
            .map(|r| {
                let s = match vrps {
                    None => RpkiState::Unverified,
                    Some(t) => {
                        let origin = usize::try_from(r.attrs)
                            .ok()
                            .and_then(|i| origins.get(i))
                            .copied()
                            .flatten();
                        t.validate(r.prefix.network(), r.prefix.prefix_len(), origin)
                    }
                };
                summary.total += 1;
                if r.prefix.addr().is_ipv4() {
                    summary.ipv4 += 1;
                } else {
                    summary.ipv6 += 1;
                }
                summary.best += u64::from(r.best());
                summary.filtered += u64::from(r.filtered());
                if let Some(c) = summary.rpki.get_mut(state_index(s)) {
                    *c += 1;
                }
                s
            })
            .collect();
        Indexed {
            rib,
            keys,
            states,
            summary,
        }
    }

    pub fn route(&self, i: usize) -> Option<(&BgpRoute, Option<&BgpAttrs>, RpkiState)> {
        let r = self.rib.routes.get(i)?;
        Some((
            r,
            self.rib.attrs_of(r),
            self.states.get(i).copied().unwrap_or(RpkiState::Unverified),
        ))
    }

    /// The candidate positions for a prefix search, in order.
    fn candidates(&self, q: &Query) -> Box<dyn Iterator<Item = usize> + '_> {
        let Some((p, m)) = q.prefix else {
            return Box::new(0..self.keys.len());
        };
        let (v6, pk, plen) = key(&p.trunc());
        let host = |len: u8| {
            if len == 0 {
                u128::MAX
            } else {
                !(u128::MAX << (128 - u32::from(len)))
            }
        };
        match m {
            Match::Covering => {
                let mut hits = Vec::new();
                for len in 0..=plen {
                    let mask = if len == 0 {
                        0
                    } else {
                        u128::MAX << (128 - u32::from(len))
                    };
                    let k = (v6, pk & mask, len);
                    if let Ok(i) = self.keys.binary_search(&k) {
                        hits.push(i);
                    }
                }
                Box::new(hits.into_iter())
            }
            Match::Exact => Box::new(self.keys.binary_search(&(v6, pk, plen)).ok().into_iter()),
            Match::Longer | Match::OrLonger => {
                let lo = self.keys.partition_point(|k| *k < (v6, pk, plen));
                let top = pk | host(plen);
                let hi = self.keys.partition_point(|k| *k <= (v6, top, 128));
                let longer = m == Match::Longer;
                Box::new((lo..hi.max(lo)).filter(move |&i| {
                    self.keys
                        .get(i)
                        .is_some_and(|&(f, _, l)| f == v6 && l >= plen && (!longer || l > plen))
                }))
            }
        }
    }

    /// The routes that match `q`: how many in all, and those of the page.
    pub fn search(&self, q: &Query, offset: usize, limit: usize) -> (usize, Vec<usize>) {
        // Attribute sets that pass the attribute searches, computed once.
        let attr_ok: Option<Vec<bool>> =
            (q.as_path.is_some() || q.community.is_some()).then(|| {
                self.rib
                    .attrs
                    .iter()
                    .map(|a| {
                        q.as_path.as_ref().is_none_or(|p| p.matches(&a.as_path))
                            && q.community.as_ref().is_none_or(|c| {
                                a.communities
                                    .iter()
                                    .chain(&a.large_communities)
                                    .any(|x| x.eq_ignore_ascii_case(c))
                            })
                    })
                    .collect()
            });
        let mut total = 0usize;
        let mut page = Vec::with_capacity(limit.min(5_000));
        for i in self.candidates(q) {
            let Some(r) = self.rib.routes.get(i) else {
                continue;
            };
            if let Some(ok) = &attr_ok
                && !usize::try_from(r.attrs)
                    .ok()
                    .and_then(|a| ok.get(a))
                    .copied()
                    .unwrap_or(false)
            {
                continue;
            }
            if let Some(s) = q.rpki
                && self.states.get(i) != Some(&s)
            {
                continue;
            }
            if let Some(f) = q.filtered
                && r.filtered() != f
            {
                continue;
            }
            if total >= offset && page.len() < limit {
                page.push(i);
            }
            total += 1;
        }
        (total, page)
    }
}

/// The address of a route's next hop, for display.
pub fn next_hop(a: Option<&BgpAttrs>) -> Option<IpAddr> {
    a.and_then(|a| a.next_hop)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpki::Vrp;

    fn rib() -> BgpRib {
        let attrs = vec![
            BgpAttrs {
                as_path: "64500 13335".into(),
                communities: vec!["65000:100".into()],
                ..BgpAttrs::default()
            },
            BgpAttrs {
                as_path: "64500 64666".into(),
                large_communities: vec!["65000:1:2".into()],
                ext_communities: Vec::new(),
                ..BgpAttrs::default()
            },
            BgpAttrs {
                as_path: "64500 {64510,64511}".into(),
                ..BgpAttrs::default()
            },
        ];
        let mk = |p: &str, a: u32, flags: u8| BgpRoute {
            prefix: p.parse().unwrap(),
            attrs: a,
            flags,
        };
        BgpRib {
            routes: vec![
                mk("10.1.0.0/16", 0, BgpRoute::BEST),
                mk("10.0.0.0/8", 0, BgpRoute::BEST),
                mk("10.1.2.0/24", 1, BgpRoute::FILTERED),
                mk("10.1.0.0/24", 2, BgpRoute::BEST),
                mk("2001:db8::/32", 0, BgpRoute::BEST),
                mk("11.0.0.0/8", 1, BgpRoute::BEST),
            ],
            attrs,
            pre_policy: true,
            warnings: vec![],
        }
    }

    fn prefixes(ix: &Indexed, q: &Query) -> Vec<String> {
        let (n, page) = ix.search(q, 0, 100);
        assert_eq!(n, page.len());
        page.iter()
            .map(|&i| ix.rib.routes[i].prefix.to_string())
            .collect()
    }

    #[test]
    fn prefix_searches() {
        let ix = Indexed::new(rib(), None, Some(65000));
        let q = |p: &str, m| Query {
            prefix: Some((p.parse().unwrap(), m)),
            ..Query::default()
        };
        assert_eq!(
            prefixes(&ix, &q("10.0.0.0/8", Match::OrLonger)),
            ["10.0.0.0/8", "10.1.0.0/16", "10.1.0.0/24", "10.1.2.0/24"]
        );
        assert_eq!(
            prefixes(&ix, &q("10.0.0.0/8", Match::Longer)),
            ["10.1.0.0/16", "10.1.0.0/24", "10.1.2.0/24"]
        );
        assert_eq!(
            prefixes(&ix, &q("10.1.0.0/16", Match::Exact)),
            ["10.1.0.0/16"]
        );
        assert_eq!(
            prefixes(&ix, &q("10.1.2.3/32", Match::Covering)),
            ["10.0.0.0/8", "10.1.0.0/16", "10.1.2.0/24"]
        );
        assert_eq!(
            prefixes(&ix, &q("2001:db8:1::/48", Match::Covering)),
            ["2001:db8::/32"]
        );
        assert_eq!(prefixes(&ix, &q("0.0.0.0/0", Match::OrLonger)).len(), 5);
        assert_eq!(ix.summary.total, 6);
        assert_eq!(
            (ix.summary.ipv4, ix.summary.ipv6, ix.summary.filtered),
            (5, 1, 1)
        );
        // Pages.
        let (n, page) = ix.search(&Query::default(), 2, 2);
        assert_eq!((n, page.len()), (6, 2));
    }

    #[test]
    fn attribute_and_rpki_searches() {
        let vrps = VrpTable::build(&[Vrp::new("10.0.0.0".parse().unwrap(), 8, 24, 13335).unwrap()]);
        let ix = Indexed::new(rib(), Some(&vrps), Some(65000));
        // 10/8 and 10.1/16 valid; 10.1.2/24 (AS 64666) invalid; 10.1.0/24
        // ends in an AS_SET: invalid; 11/8 and the IPv6 one unknown.
        assert_eq!(ix.summary.rpki, [2, 2, 2, 0]);
        let q = Query {
            rpki: Some(RpkiState::Invalid),
            ..Query::default()
        };
        assert_eq!(prefixes(&ix, &q), ["10.1.0.0/24", "10.1.2.0/24"]);
        let q = Query {
            as_path: Some(AsPathPattern::parse("13335$").unwrap()),
            ..Query::default()
        };
        assert_eq!(prefixes(&ix, &q).len(), 3);
        let q = Query {
            as_path: Some(AsPathPattern::parse("^64666").unwrap()),
            ..Query::default()
        };
        assert!(prefixes(&ix, &q).is_empty());
        let q = Query {
            community: Some("65000:1:2".into()),
            filtered: Some(true),
            ..Query::default()
        };
        assert_eq!(prefixes(&ix, &q), ["10.1.2.0/24"]);
        assert!(AsPathPattern::parse("abc").is_err());
        assert!(AsPathPattern::parse("^$").unwrap().matches(""));
        assert!(
            AsPathPattern::parse("64500 64510")
                .unwrap()
                .matches("64500 {64510,64511}")
        );
    }
}
