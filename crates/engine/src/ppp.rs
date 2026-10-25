//! The PPP service (G4.3d) as the engine sees it. The daemon's `pppoe`
//! service owns the AF_PACKET sockets, the `proto-pppoe` servers and the
//! XDP session map, and registers itself here with
//! [`Session::set_ppp_backend`]; `ppp.active.*`, `ppp.why`, `ppp.history`
//! and the "drops N sessions" checks of the config commands read it.
//!
//! Every call is a copy of the service's state taken under its own lock,
//! never a wait on the network: the session lock is held while a command
//! runs, so the backend must answer from memory.

use std::sync::Arc;

use corerouter_model::MacAddr;
use corerouter_model::ppp::{ActiveSession, HOOK_VARS, HistoryEntry, ServiceStats, Why};
use serde_json::Value;

use crate::Session;

/// What the daemon's PPP service offers.
pub trait PppBackend: Send + Sync {
    /// The sessions up now (`/ppp active`).
    fn active(&self) -> Vec<ActiveSession>;
    /// Admin disconnect (LCP Terminate-Request, then PADT; Acct-Stop with
    /// Admin-Reset). Returns how many of `ids` were found.
    fn terminate(&self, ids: &[String]) -> usize;
    /// The last logins, failures and ends, oldest first.
    fn history(&self) -> Vec<HistoryEntry>;
    /// Where the logins of `name` (or of `mac`) get to.
    fn why(&self, name: Option<&str>, mac: Option<MacAddr>) -> Why;
    fn stats(&self) -> ServiceStats;
    /// The sessions up that `keep` accepts, in (name, id) order: how many,
    /// and the first `limit`. The backend walks its table in place and
    /// copies only the page: with 100 000 up, a copy of all of them per GUI
    /// refresh held the engine lock for ~50 ms (G4.3g).
    fn active_page(
        &self,
        keep: &dyn Fn(&ActiveSession) -> bool,
        limit: usize,
    ) -> (usize, Vec<ActiveSession>) {
        let mut all: Vec<ActiveSession> = self.active().into_iter().filter(|a| keep(a)).collect();
        let total = all.len();
        all.sort_by(|a, b| a.name.cmp(&b.name).then(a.id.cmp(&b.id)));
        all.truncate(limit);
        (total, all)
    }
    /// Sessions up per server name.
    fn sessions_by_server(&self) -> std::collections::BTreeMap<String, usize> {
        let mut m = std::collections::BTreeMap::new();
        for a in self.active() {
            *m.entry(a.server).or_insert(0) += 1;
        }
        m
    }
    /// The login of the session holding `ip` now (the identity chip).
    fn who(&self, ip: std::net::Ipv4Addr) -> Option<String> {
        let _ = ip;
        None
    }
    /// The login that held `ip` at Unix second `at` (CGNAT "Who was?"),
    /// from the history kept.
    fn who_at(&self, ip: std::net::Ipv4Addr, at: u64) -> Option<String> {
        let _ = (ip, at);
        None
    }
}

#[derive(Default)]
struct PppRuntime {
    backend: Option<Arc<dyn PppBackend>>,
    /// The IPoE service's sessions (G4.3f), shown with the PPP ones.
    ipoe: Option<Arc<dyn PppBackend>>,
}

/// The PPPoE and the IPoE services as one: `ppp.active` lists both,
/// `ppp.why` asks both.
struct Merged(Vec<Arc<dyn PppBackend>>);

impl PppBackend for Merged {
    fn active(&self) -> Vec<ActiveSession> {
        self.0.iter().flat_map(|b| b.active()).collect()
    }

    fn terminate(&self, ids: &[String]) -> usize {
        self.0.iter().map(|b| b.terminate(ids)).sum()
    }

    fn history(&self) -> Vec<HistoryEntry> {
        let mut all: Vec<HistoryEntry> = self.0.iter().flat_map(|b| b.history()).collect();
        all.sort_by_key(|h| h.at);
        all
    }

    fn why(&self, name: Option<&str>, mac: Option<MacAddr>) -> Why {
        // The one that knows most: up now, else the most attempts seen.
        let answers: Vec<Why> = self.0.iter().map(|b| b.why(name, mac)).collect();
        let score = |w: &Why| (w.active.is_some(), w.attempts.iter().map(|(_, n)| u64::from(*n)).sum::<u64>());
        answers
            .into_iter()
            .max_by_key(score)
            .unwrap_or_default()
    }

    /// The PPPoE service's own stats, whole (its discovery, IPv6, workers
    /// and admission counters: new fields stay right without a change
    /// here), plus what the IPoE half adds: its sessions, authorizations,
    /// data plane and error.
    fn stats(&self) -> ServiceStats {
        let mut parts = self.0.iter().map(|b| b.stats());
        let mut t = parts.next().unwrap_or_default();
        for s in parts {
            t.sessions += s.sessions;
            t.auth_accept += s.auth_accept;
            t.auth_reject += s.auth_reject;
            t.dataplane |= s.dataplane;
            if t.last_error.is_none() {
                t.last_error = s.last_error;
            }
        }
        t
    }

    /// Each half's page, then the union sorted by (name, id) and cut to
    /// `limit`: no backend copies more than `limit` rows.
    fn active_page(
        &self,
        keep: &dyn Fn(&ActiveSession) -> bool,
        limit: usize,
    ) -> (usize, Vec<ActiveSession>) {
        let mut total = 0;
        let mut rows = Vec::new();
        for b in &self.0 {
            let (n, page) = b.active_page(keep, limit);
            total += n;
            rows.extend(page);
        }
        rows.sort_by(|a, b| a.name.cmp(&b.name).then(a.id.cmp(&b.id)));
        rows.truncate(limit);
        (total, rows)
    }

    fn sessions_by_server(&self) -> std::collections::BTreeMap<String, usize> {
        let mut m = std::collections::BTreeMap::new();
        for b in &self.0 {
            for (server, n) in b.sessions_by_server() {
                *m.entry(server).or_insert(0) += n;
            }
        }
        m
    }

    fn who(&self, ip: std::net::Ipv4Addr) -> Option<String> {
        self.0.iter().find_map(|b| b.who(ip))
    }

    fn who_at(&self, ip: std::net::Ipv4Addr, at: u64) -> Option<String> {
        self.0.iter().find_map(|b| b.who_at(ip, at))
    }
}

impl Session {
    pub fn set_ppp_backend(&mut self, backend: Arc<dyn PppBackend>) {
        if let Some(rt) = self.ext_mut::<PppRuntime>() {
            rt.backend = Some(backend);
        }
    }

    /// The IPoE service's view of its sessions (G4.3f), merged into
    /// [`Session::ppp_backend`].
    pub fn set_ipoe_sessions(&mut self, backend: Arc<dyn PppBackend>) {
        if let Some(rt) = self.ext_mut::<PppRuntime>() {
            rt.ipoe = Some(backend);
        }
    }

    /// The daemon's PPP service and IPoE sessions, if it runs them.
    pub fn ppp_backend(&self) -> Option<Arc<dyn PppBackend>> {
        let rt = self.ext::<PppRuntime>()?;
        match (&rt.backend, &rt.ipoe) {
            (Some(a), Some(b)) => Some(Arc::new(Merged(vec![a.clone(), b.clone()]))),
            (Some(a), None) | (None, Some(a)) => Some(a.clone()),
            (None, None) => None,
        }
    }

    /// Active sessions now (empty without the service).
    pub fn ppp_active(&self) -> Vec<ActiveSession> {
        self.ppp_backend().map(|b| b.active()).unwrap_or_default()
    }
}

/// Replace the [`HOOK_VARS`] in the string values of `params`.
pub fn expand_hook(params: &serde_json::Map<String, Value>, vars: &[(&str, String)]) -> Value {
    let mut out = serde_json::Map::new();
    for (k, v) in params {
        let v = match v {
            Value::String(s) => {
                let mut t = s.clone();
                for (name, value) in vars {
                    if HOOK_VARS.contains(name) {
                        t = t.replace(name, value);
                    }
                }
                Value::String(t)
            }
            other => other.clone(),
        };
        out.insert(k.clone(), v);
    }
    Value::Object(out)
}

/// One subscriber address entering or leaving a firewall address list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PppListOp {
    pub list: String,
    pub ip: std::net::Ipv4Addr,
    pub add: bool,
    pub timeout_secs: u64,
    pub comment: String,
}

/// The BNG service's way to the XDP session map (G4.3c) through the HAL:
/// short calls, made once a round under the session lock.
impl Session {
    /// Switch the PPPoE data plane on for `ports` (by name). `Err` says why
    /// not (no XDP, not attached there): the service then uses its slow
    /// path.
    pub fn pppoe_dataplane(&mut self, on: bool, ports: &[corerouter_model::IfName]) -> Result<(), String> {
        self.hal_mut().pppoe_dataplane(on, ports).map_err(|e| e.to_string())
    }

    pub fn pppoe_apply(&mut self, ops: &[corerouter_hal::pppoe::PppoeOp]) -> Result<(), String> {
        self.hal_mut().pppoe_apply(ops).map_err(|e| e.to_string())
    }

    pub fn pppoe_counters(&mut self, slots: &[u32]) -> Vec<(u32, corerouter_hal::pppoe::PppoeCounters)> {
        if slots.is_empty() {
            return Vec::new();
        }
        self.hal_mut().pppoe_counters(slots)
    }
}

impl Session {
    /// The PPP service's address-list entry for a subscriber (the
    /// profile's `address_list`, RADIUS `Mikrotik-Address-List`, a CoA):
    /// a dynamic entry, as `ip.firewall.address-list.add timeout=…` makes
    /// one, without that command's access check. A subscriber's own address
    /// entering a list does not change the operator's way in, and the check
    /// copies every dynamic entry: 10 000 logins paid it 10 000 times.
    pub fn ppp_address_list(
        &mut self,
        list: &str,
        ip: std::net::Ipv4Addr,
        add: bool,
        timeout_secs: u64,
        comment: &str,
    ) -> Result<(), String> {
        let op = PppListOp { list: list.to_owned(), ip, add, timeout_secs, comment: comment.to_owned() };
        self.ppp_address_lists(std::slice::from_ref(&op)).into_iter().next().map_or(Ok(()), Err)
    }

    /// Many [`Session::ppp_address_list`] at once: one data-plane call
    /// (one `nft` run on Linux) for all. Returns the errors, one line each.
    pub fn ppp_address_lists(&mut self, ops: &[PppListOp]) -> Vec<String> {
        use corerouter_hal::DynamicChange;
        use corerouter_model::firewall::{AddrMatch, Name};
        let now = self.now();
        let mut errors = Vec::new();
        // First what goes (one reindex for all), then what comes: a new
        // add replaces an old entry (a fresh timeout).
        let mut parsed = Vec::with_capacity(ops.len());
        let mut drop = std::collections::HashSet::new();
        for op in ops {
            let Ok(list) = op.list.parse::<Name>() else {
                errors.push(format!("address-list '{}': not a list name", op.list));
                continue;
            };
            let address = AddrMatch::Net(ipnet::IpNet::from(std::net::IpAddr::V4(op.ip)));
            if let Some(e) = self.dynamic_addresses.find(&list, &address) {
                drop.insert(e.id);
            }
            parsed.push((op, list, address));
        }
        let gone: Vec<_> = self
            .dynamic_addresses
            .remove_many(&drop)
            .iter()
            .map(|e| e.data_plane(now))
            .collect();
        let mut added = Vec::new();
        for (op, list, address) in parsed {
            if !op.add || self.dynamic_addresses.find(&list, &address).is_some() {
                continue;
            }
            if self.dynamic_addresses.entries().len() >= crate::firewall_dyn::MAX_DYNAMIC {
                errors.push(format!("address-list '{}': at most {} dynamic entries", op.list, crate::firewall_dyn::MAX_DYNAMIC));
                continue;
            }
            let entry = crate::firewall_dyn::DynamicEntry {
                id: self.dynamic_addresses.next_id(),
                list,
                address,
                timeout_secs: op.timeout_secs,
                added: now,
                comment: crate::identity::clean(&op.comment),
            };
            added.push(entry.data_plane(now));
            self.dynamic_addresses.push(entry);
        }
        let mut changes: Vec<DynamicChange<'_>> = gone.iter().map(DynamicChange::Remove).collect();
        changes.extend(added.iter().map(DynamicChange::Add));
        if !changes.is_empty()
            && let Err(e) = self.hal_mut().address_list_dynamic_many(&changes)
        {
            errors.push(e.to_string());
        }
        errors
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::Session;

    #[test]
    fn subscriber_address_lists_add_renew_and_remove() {
        let mut s = Session::virtual_lab();
        let ip = std::net::Ipv4Addr::new(100, 64, 0, 9);
        s.ppp_address_list("online", ip, true, 3600, "ppp joao").unwrap();
        s.ppp_address_list("online", ip, true, 3600, "ppp joao").unwrap();
        let rows = s.execute("ip.firewall.address-list.list", &json!({"list": "online"})).unwrap();
        assert_eq!(rows.as_array().unwrap().len(), 1, "made again, not twice: {rows}");
        assert_eq!(rows[0]["dynamic"], true);
        s.ppp_address_list("online", ip, false, 0, "").unwrap();
        let rows = s.execute("ip.firewall.address-list.list", &json!({"list": "online"})).unwrap();
        assert!(rows.as_array().unwrap().is_empty());
        assert!(s.ppp_address_list("bad name", ip, true, 60, "").is_err());
        // Ten thousand logins stay cheap (no copy of every entry per add).
        let t = std::time::Instant::now();
        for i in 0..10_000u32 {
            s.ppp_address_list("online", std::net::Ipv4Addr::from(0x6440_0000 + i), true, 3600, "").unwrap();
        }
        assert!(t.elapsed() < std::time::Duration::from_secs(20), "{:?}", t.elapsed());
    }
}

#[cfg(test)]
mod merged_tests {
    use std::sync::Arc;

    use corerouter_model::MacAddr;
    use corerouter_model::ppp::{ActiveSession, HistoryEntry, ServiceStats, Why};

    use super::{Merged, PppBackend};

    struct Half(&'static str, Vec<&'static str>, u32);

    impl PppBackend for Half {
        fn active(&self) -> Vec<ActiveSession> {
            self.1
                .iter()
                .enumerate()
                .map(|(i, n)| ActiveSession { id: format!("{}{i}", self.0), name: (*n).into(), server: self.0.into(), ..ActiveSession::default() })
                .collect()
        }
        fn terminate(&self, _: &[String]) -> usize {
            0
        }
        fn history(&self) -> Vec<HistoryEntry> {
            Vec::new()
        }
        fn why(&self, _: Option<&str>, _: Option<MacAddr>) -> Why {
            Why::default()
        }
        fn stats(&self) -> ServiceStats {
            ServiceStats { sessions: self.1.len() as u64, workers: self.2, delegated: u64::from(self.2), ..ServiceStats::default() }
        }
    }

    /// PPPoE and IPoE as one: the page is sorted over both halves and cut,
    /// the total and the per-server counts add up, workers are PPPoE's.
    #[test]
    fn the_union_pages_counts_and_keeps_pppoe_workers() {
        let m = Merged(vec![
            Arc::new(Half("pppoe-ether2", vec!["carla", "ana", "edu"], 4)),
            Arc::new(Half("dhcp1", vec!["bia", "dani"], 0)),
        ]);
        let (total, page) = m.active_page(&|_| true, 3);
        assert_eq!(total, 5);
        let names: Vec<_> = page.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, ["ana", "bia", "carla"]);
        let (total, page) = m.active_page(&|a| a.server == "dhcp1", 10);
        assert_eq!((total, page.len()), (2, 2));
        let by = m.sessions_by_server();
        assert_eq!(by.get("pppoe-ether2"), Some(&3));
        assert_eq!(by.get("dhcp1"), Some(&2));
        let st = m.stats();
        assert_eq!((st.sessions, st.workers), (5, 4));
        // PPPoE's own counters (here `delegated`) come through whole.
        assert_eq!(st.delegated, 4);
    }
}
