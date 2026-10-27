//! Subscriber notices (G4.10) at run time: who is in a profile's list now
//! and since when, who saw the page, the view log (proof of notice), the
//! per-subscriber page variables and the webhook events. Operational state,
//! like the dynamic address lists: never in the config, gone after a
//! restart. The config is `corerouter_model::subscriber_notice`.
//!
//! Data plane: membership is the firewall's address list itself; "seen" is
//! a dynamic entry in the reserved list `sn-seen-<profile>` with the
//! profile's interval as its timeout, so the kernel stops sending the
//! subscriber to the page on its own.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::net::IpAddr;

use corerouter_model::firewall::{AddrMatch, Name};
use corerouter_model::subscriber_notice::{Mode, Profile, seen_list};
use serde::Serialize;

use crate::Session;

/// The view log keeps this many (oldest out first).
pub const MAX_LOG: usize = 10_000;
/// Subscribers with page variables (hostile-input bound, **estimado**).
pub const MAX_VARS: usize = 200_000;
/// Webhook events waiting for the daemon.
pub const MAX_EVENTS: usize = 4096;
/// Bytes of one variable's value.
pub const MAX_VAR_LEN: usize = 256;

/// One page view (or a notice that ran out), as the Log tab shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct View {
    pub at: u64,
    pub address: IpAddr,
    pub profile: String,
    /// `android`, `apple`, … (the probe that brought it), `browser`, or
    /// `timeout` when the notice ended without a view.
    pub via: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub login: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub user_agent: String,
}

/// A subscriber entered (or left) a profile's list: what the webhook sends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Event {
    pub at: u64,
    pub event: &'static str,
    pub address: IpAddr,
    pub profile: String,
    pub mode: &'static str,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub login: String,
}

/// A member of a profile's list now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Member {
    pub address: AddrMatch,
    pub profile: String,
    pub mode: &'static str,
    /// `static` (the config's list), `dynamic` (RADIUS, PPP, DHCP, API).
    pub source: &'static str,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub comment: String,
}

#[derive(Debug, Default)]
pub struct NoticeRuntime {
    /// (profile, address) → first time the tick saw it in the list.
    since: HashMap<(Name, IpAddr), u64>,
    /// (profile, address) → when it last saw the page.
    seen: HashMap<(Name, IpAddr), u64>,
    log: VecDeque<View>,
    vars: HashMap<IpAddr, BTreeMap<String, String>>,
    events: VecDeque<Event>,
    /// Logins whose session address the tick put in a list: login →
    /// (list, address).
    logins: HashMap<String, (Name, std::net::Ipv4Addr)>,
    /// Events dropped because the daemon did not take them in time.
    pub events_dropped: u64,
}

fn single(a: &AddrMatch) -> Option<IpAddr> {
    match a {
        AddrMatch::Net(n) if n.prefix_len() == n.max_prefix_len() => Some(n.addr()),
        _ => None,
    }
}

impl Session {
    fn notice(&self) -> Option<&NoticeRuntime> {
        self.ext::<NoticeRuntime>()
    }

    fn notice_mut(&mut self) -> Option<&mut NoticeRuntime> {
        self.ext_mut::<NoticeRuntime>()
    }

    /// Every member of every enabled profile, static entries first.
    pub fn notice_members(&self) -> Vec<Member> {
        let cfg = self.store().running();
        let sn = &cfg.ip.subscriber_notice;
        let by_list: HashMap<&Name, &Profile> = sn.active().map(|p| (&p.address_list, p)).collect();
        if by_list.is_empty() {
            return Vec::new();
        }
        let mut out = Vec::new();
        for e in cfg.ip.firewall.address_lists.iter().filter(|e| !e.disabled) {
            if let Some(p) = by_list.get(&e.list) {
                out.push(Member {
                    address: e.address,
                    profile: p.name.to_string(),
                    mode: p.mode.as_str(),
                    source: "static",
                    comment: e.comment.clone(),
                });
            }
        }
        for e in self.dynamic_addresses.entries() {
            if let Some(p) = by_list.get(&e.list) {
                out.push(Member {
                    address: e.address,
                    profile: p.name.to_string(),
                    mode: p.mode.as_str(),
                    source: "dynamic",
                    comment: e.comment.clone(),
                });
            }
        }
        out
    }

    /// The profile `ip` is under now (the first enabled one whose list
    /// holds it), with the matching entry's source.
    pub fn notice_profile_of(&self, ip: IpAddr) -> Option<(Profile, &'static str)> {
        let cfg = self.store().running();
        for p in cfg.ip.subscriber_notice.active() {
            let exact = AddrMatch::Net(ipnet::IpNet::from(ip));
            if cfg.ip.firewall.address_lists.holders(&p.address_list, &exact) > 0 {
                return Some((p.clone(), "static"));
            }
            if self.dynamic_addresses.find(&p.address_list, &exact).is_some() {
                return Some((p.clone(), "dynamic"));
            }
            let wider = cfg
                .ip
                .firewall
                .address_lists
                .iter()
                .any(|e| !e.disabled && e.list == p.address_list && e.address.contains(ip));
            if wider {
                return Some((p.clone(), "static"));
            }
            if self
                .dynamic_addresses
                .entries()
                .iter()
                .any(|e| e.list == p.address_list && e.address.contains(ip))
            {
                return Some((p.clone(), "dynamic"));
            }
        }
        None
    }

    /// When `ip` last saw `profile`'s page, if it still counts.
    pub fn notice_seen_at(&self, profile: &Profile, ip: IpAddr) -> Option<u64> {
        let at = *self.notice()?.seen.get(&(profile.name.clone(), ip))?;
        match self.now() {
            Some(now) if profile.mode != Mode::Block && now.saturating_sub(at) >= profile.interval_secs => None,
            _ => Some(at),
        }
    }

    pub fn notice_since(&self, profile: &Name, ip: IpAddr) -> Option<u64> {
        self.notice()?.since.get(&(profile.clone(), ip)).copied()
    }

    /// `ip` saw its page (`via`: the probe's OS or `browser`). Notice and
    /// throttle: it joins `sn-seen-<profile>` for the profile's interval,
    /// so the data plane lets it through. Returns the profile.
    pub fn notice_mark_seen(&mut self, ip: IpAddr, via: &str, user_agent: &str) -> Option<Profile> {
        let (p, _) = self.notice_profile_of(ip)?;
        let now = self.now().unwrap_or(0);
        let login = self.notice_var(ip, "login").unwrap_or_default();
        let rt = self.notice_mut()?;
        rt.seen.insert((p.name.clone(), ip), now);
        if rt.log.len() >= MAX_LOG {
            rt.log.pop_front();
        }
        rt.log.push_back(View {
            at: now,
            address: ip,
            profile: p.name.to_string(),
            via: via.chars().take(32).collect(),
            login,
            user_agent: crate::identity::clean(&user_agent.chars().take(160).collect::<String>()),
        });
        if p.mode != Mode::Block {
            self.notice_pass(&p, ip);
        }
        Some(p)
    }

    /// Put `ip` in the profile's seen list (the data plane stops sending
    /// it to the page until the interval ends).
    fn notice_pass(&mut self, p: &Profile, ip: IpAddr) {
        let IpAddr::V4(v4) = ip else {
            // IPv6 subscribers: the seen list takes them too.
            let _ = self.dns_address_list(&seen_list(&p.name), ip, p.interval_secs.max(1));
            return;
        };
        let op = crate::ppp::PppListOp {
            list: seen_list(&p.name),
            ip: v4,
            add: true,
            timeout_secs: p.interval_secs.max(1),
            comment: format!("notice {}", p.name),
        };
        for e in self.ppp_address_lists(std::slice::from_ref(&op)) {
            log::warn!("subscriber-notice: seen list: {e}");
        }
    }

    pub fn notice_log(&self) -> Vec<View> {
        self.notice().map(|r| r.log.iter().cloned().collect()).unwrap_or_default()
    }

    pub fn notice_var(&self, ip: IpAddr, key: &str) -> Option<String> {
        self.notice()?.vars.get(&ip)?.get(key).cloned()
    }

    pub fn notice_vars(&self, ip: IpAddr) -> BTreeMap<String, String> {
        self.notice().and_then(|r| r.vars.get(&ip).cloned()).unwrap_or_default()
    }

    /// Set (or, with an empty map, clear) `ip`'s page variables.
    pub fn notice_set_vars(&mut self, ip: IpAddr, vars: BTreeMap<String, String>) -> Result<(), String> {
        let rt = self.notice_mut().ok_or("no runtime")?;
        if vars.is_empty() {
            rt.vars.remove(&ip);
            return Ok(());
        }
        if !rt.vars.contains_key(&ip) && rt.vars.len() >= MAX_VARS {
            return Err(format!("at most {MAX_VARS} subscribers with variables"));
        }
        rt.vars.insert(ip, vars);
        Ok(())
    }

    /// Take the webhook events (the daemon's notice service sends them).
    pub fn notice_take_events(&mut self, max: usize) -> Vec<Event> {
        let Some(rt) = self.notice_mut() else { return Vec::new() };
        let n = max.min(rt.events.len());
        rt.events.drain(..n).collect()
    }

    /// One round (the daemon's notice service, every few seconds):
    /// - the sessions of the logins sent to a profile join its list;
    /// - members new to a list get a "since" and a webhook event, members
    ///   gone are forgotten (and get a "left" event);
    /// - a notice not seen within the profile's timeout ends by itself;
    /// - a block member's open connections are ended once.
    ///
    /// O(members): one pass over the lists (**medido** in G4.10b).
    pub fn notice_tick(&mut self) {
        self.notice_logins();
        let now = self.now().unwrap_or(0);
        let cfg = self.store().running().clone();
        let sn = &cfg.ip.subscriber_notice;
        let members = self.notice_members();
        let mut here: HashSet<(Name, IpAddr)> = HashSet::with_capacity(members.len());
        let mut new: Vec<(Profile, IpAddr)> = Vec::new();
        let mut ran_out: Vec<(Profile, IpAddr)> = Vec::new();
        let _ = self.notice_mut();
        {
            let Some(rt) = self.ext::<NoticeRuntime>() else { return };
            for m in &members {
                let Some(ip) = single(&m.address) else { continue };
                let Some(p) = sn.profile(&m.profile) else { continue };
                let key = (p.name.clone(), ip);
                match rt.since.get(&key) {
                    None => new.push((p.clone(), ip)),
                    Some(at) => {
                        let seen = rt.seen.get(&key).is_some_and(|s| *s >= *at);
                        if p.mode != Mode::Block
                            && p.timeout_secs > 0
                            && !seen
                            && now.saturating_sub(*at) >= p.timeout_secs
                        {
                            ran_out.push((p.clone(), ip));
                        }
                    }
                }
                here.insert(key);
            }
        }
        let logins: HashMap<std::net::Ipv4Addr, String> = self
            .notice()
            .map(|r| r.logins.iter().filter(|(l, _)| !l.starts_with(LEASE)).map(|(l, (_, a))| (*a, l.clone())).collect())
            .unwrap_or_default();
        let login_of = |ip: &IpAddr| match ip {
            IpAddr::V4(a) => logins.get(a).cloned().unwrap_or_default(),
            IpAddr::V6(_) => String::new(),
        };
        let mut kill: Vec<IpAddr> = Vec::new();
        if let Some(rt) = self.notice_mut() {
            let gone: Vec<(Name, IpAddr)> = rt.since.keys().filter(|k| !here.contains(*k)).cloned().collect();
            for k in gone {
                rt.since.remove(&k);
                rt.seen.remove(&k);
                let mode = sn.profile(k.0.as_str()).map(|p| p.mode.as_str()).unwrap_or("block");
                push_event(rt, Event { at: now, event: "left", address: k.1, profile: k.0.to_string(), mode, login: login_of(&k.1) });
            }
            for (p, ip) in &new {
                rt.since.insert((p.name.clone(), *ip), now);
                if p.webhook {
                    push_event(rt, Event { at: now, event: "entered", address: *ip, profile: p.name.to_string(), mode: p.mode.as_str(), login: login_of(ip) });
                }
                if p.mode == Mode::Block && p.kill_connections {
                    kill.push(*ip);
                }
            }
            for (p, ip) in &ran_out {
                rt.seen.insert((p.name.clone(), *ip), now);
                if rt.log.len() >= MAX_LOG {
                    rt.log.pop_front();
                }
                rt.log.push_back(View { at: now, address: *ip, profile: p.name.to_string(), via: "timeout".into(), login: login_of(ip), user_agent: String::new() });
            }
        }
        for (p, ip) in ran_out {
            self.notice_pass(&p, ip);
        }
        if !kill.is_empty() {
            self.notice_kill(&kill);
        }
    }

    /// End the open connections from `ips` (an established download would
    /// go on in the fast path, which the block's rules never see).
    fn notice_kill(&mut self, ips: &[IpAddr]) {
        let set: HashSet<IpAddr> = ips.iter().copied().collect();
        let Ok((conns, _)) = self.connections(true) else { return };
        let victims: Vec<_> = conns.iter().filter(|c| set.contains(&c.orig.src)).cloned().collect();
        if !victims.is_empty()
            && let Err(e) = self.hal_mut().connections_kill(&victims)
        {
            log::warn!("subscriber-notice: connections not ended: {e}");
        }
    }

    /// The logins and static leases sent to a profile ("Block (com
    /// página)"): the address of each login's session, and each lease's
    /// address, in the profile's list (and out when the session goes or the
    /// assignment is undone). Keyed by login, or `lease <address>`.
    fn notice_logins(&mut self) {
        let cfg = self.store().running();
        let sn = &cfg.ip.subscriber_notice;
        let lists: HashSet<&Name> = sn.active().map(|p| &p.address_list).collect();
        let had = self.notice().is_some_and(|r| !r.logins.is_empty());
        if lists.is_empty() && !had {
            return;
        }
        let want_of: HashMap<&str, Name> = sn
            .logins
            .iter()
            .filter_map(|l| Some((l.login.as_str(), sn.active().find(|p| p.name == l.profile)?.address_list.clone())))
            .collect();
        let mut want: HashMap<String, (Name, std::net::Ipv4Addr)> = HashMap::new();
        for l in cfg.ip.dhcp_server.leases.iter().filter(|l| !l.disabled) {
            if let Some(list) = l.address_lists.iter().find(|n| lists.contains(n)) {
                want.insert(format!("{LEASE}{}", l.address), (list.clone(), l.address));
            }
        }
        if !want_of.is_empty() {
            for a in self.ppp_active() {
                if let (Some(list), Some(ip)) = (want_of.get(a.name.as_str()), a.address) {
                    want.insert(a.name.clone(), (list.clone(), ip));
                }
            }
        }
        let had: HashMap<String, (Name, std::net::Ipv4Addr)> =
            self.notice().map(|r| r.logins.clone()).unwrap_or_default();
        let mut ops = Vec::new();
        for (login, (list, ip)) in &had {
            if want.get(login) != Some(&(list.clone(), *ip)) {
                ops.push(crate::ppp::PppListOp { list: list.to_string(), ip: *ip, add: false, timeout_secs: 0, comment: String::new() });
            }
        }
        for (login, (list, ip)) in &want {
            if had.get(login) != Some(&(list.clone(), *ip)) {
                ops.push(crate::ppp::PppListOp {
                    list: list.to_string(),
                    ip: *ip,
                    add: true,
                    timeout_secs: 35 * 86_400,
                    comment: format!("notice {login}"),
                });
            }
        }
        if ops.is_empty() {
            return;
        }
        for e in self.ppp_address_lists(&ops) {
            log::warn!("subscriber-notice: login list: {e}");
        }
        if let Some(rt) = self.notice_mut() {
            rt.logins = want;
        }
    }
}

/// The key of a static lease's assignment (not a login).
const LEASE: &str = "lease ";

fn push_event(rt: &mut NoticeRuntime, e: Event) {
    if rt.events.len() >= MAX_EVENTS {
        rt.events.pop_front();
        rt.events_dropped = rt.events_dropped.saturating_add(1);
    }
    rt.events.push_back(e);
}
