//! The routes FRR holds for a BGP neighbor, for the `/routing filter`
//! preview (G3.2b). Reading a table can take seconds (a full table is
//! hundreds of MiB of JSON), so it never runs under the session lock: the
//! preview asks ([`Session::bgp_routes`] files the request and answers
//! "pending"), the daemon's FRR thread takes the requests
//! ([`Session::bgp_routes_wanted`]), reads outside the lock and hands the
//! result back ([`Session::set_bgp_routes`]); the next preview has it.
//! A result is kept for [`FRESH_SECS`].

use std::collections::HashMap;
use std::sync::Arc;

use corerouter_model::bgp_route::BgpRouteEntry;
use corerouter_proto_bgp::filter::{Large, Route};

use crate::Session;

/// How long a read table is used before it is read again.
pub const FRESH_SECS: u64 = 30;
/// Most requests waiting (a preview per connection and direction).
pub const MAX_WANTED: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RouteKey {
    pub instance: String,
    pub neighbor: String,
    /// What the neighbor sent; otherwise our best routes (sent to it).
    pub received: bool,
}

/// A table read: the routes, and how many of them came without their
/// communities (FRR shows those only for accepted routes).
pub type Table = (Arc<Vec<Route>>, usize);

struct Entry {
    at: u64,
    result: Result<Table, String>,
}

/// A [`Session`] extension.
#[derive(Default)]
pub struct BgpRouteCache {
    entries: HashMap<RouteKey, Entry>,
    wanted: Vec<RouteKey>,
}

/// The routes read from FRR, and how many lack their communities.
pub fn to_routes(entries: Vec<BgpRouteEntry>) -> (Vec<Route>, usize) {
    let partial = entries.iter().filter(|e| e.partial).count();
    (entries.into_iter().filter_map(to_route).collect(), partial)
}

/// The policy's view of a route read from FRR (`None`: no prefix).
pub fn to_route(e: BgpRouteEntry) -> Option<Route> {
    let mut r = Route::bgp(e.prefix?, e.as_path);
    let mut c = e.communities;
    c.sort_unstable();
    c.dedup();
    r.communities = c;
    let mut l: Vec<Large> = e.large.into_iter().map(|(a, b, c)| Large(a, b, c)).collect();
    l.sort_unstable();
    l.dedup();
    r.large = l;
    r.med = e.med;
    r.local_pref = e.local_pref;
    Some(r)
}

impl Session {
    /// The routes of `key` if read recently; otherwise the request is
    /// filed for the FRR thread and the last result (stale) or `None`.
    pub fn bgp_routes(&mut self, key: &RouteKey) -> Option<Result<Table, String>> {
        let now = self.hal_now().unwrap_or(0);
        let cache = self.ext_mut::<BgpRouteCache>()?;
        let entry = cache.entries.get(key);
        let fresh = entry.is_some_and(|e| now.saturating_sub(e.at) < FRESH_SECS);
        if !fresh && !cache.wanted.contains(key) && cache.wanted.len() < MAX_WANTED {
            cache.wanted.push(key.clone());
        }
        entry.map(|e| e.result.clone())
    }

    /// The tables previews asked for (taken: the FRR thread reads them).
    pub fn bgp_routes_wanted(&mut self) -> Vec<RouteKey> {
        self.ext_mut::<BgpRouteCache>().map(|c| std::mem::take(&mut c.wanted)).unwrap_or_default()
    }

    /// What the FRR thread read for `key` (routes, how many are partial).
    pub fn set_bgp_routes(&mut self, key: RouteKey, result: Result<(Vec<Route>, usize), String>) {
        let now = self.hal_now().unwrap_or(0);
        if let Some(c) = self.ext_mut::<BgpRouteCache>() {
            // Only the tables still asked about stay (bounded by MAX_WANTED
            // asks per read).
            if c.entries.len() >= MAX_WANTED * 4 {
                c.entries.retain(|_, e| now.saturating_sub(e.at) < FRESH_SECS);
            }
            c.entries.insert(key, Entry { at: now, result: result.map(|(r, n)| (Arc::new(r), n)) });
        }
    }
}

#[cfg(test)]
mod tests {
    use corerouter_hal::VirtualHal;

    use super::*;

    #[test]
    fn a_request_is_filed_once_and_answered() {
        let mut s = Session::new(Box::new(VirtualHal::default()));
        let key = RouteKey { instance: "default".into(), neighbor: "192.0.2.1".into(), received: true };
        assert!(s.bgp_routes(&key).is_none());
        assert!(s.bgp_routes(&key).is_none());
        assert_eq!(s.bgp_routes_wanted(), std::slice::from_ref(&key));
        assert!(s.bgp_routes_wanted().is_empty());
        let e = BgpRouteEntry {
            prefix: Some("192.0.2.0/24".parse().unwrap()),
            as_path: vec![64500],
            communities: vec![3, 1, 3],
            ..Default::default()
        };
        s.set_bgp_routes(key.clone(), Ok(to_routes(vec![e])));
        let (got, partial) = s.bgp_routes(&key).unwrap().unwrap();
        assert_eq!(got[0].communities, [1, 3]);
        assert_eq!(partial, 0);
        assert!(s.bgp_routes_wanted().is_empty());
    }
}
