//! The DHCPv4 server at run time (G4.2a): the pure server of
//! `proto-dhcp` (`corerouter_proto_dhcp::server::Server`) on the sockets
//! the HAL opens, driven by [`Session::dhcp_server_poll`] — from the
//! daemon's `dhcp-server` service (a few milliseconds apart, under the
//! supervisor) or, without one, from the session clock with the clients
//! ([`Session::dhcp_service`], the GUI's own lab).
//!
//! What it does with the server's [`Effect`]s, in order, each round:
//!
//! 1. journal lines go to the storage in one append, synced, before any
//!    reply of the round leaves (one fsync per round, not per lease: group
//!    commit). The journal is compacted (one line per live record, an
//!    atomic rewrite) hourly or when it has grown to twice the records —
//!    Kea's LFC, in-process. A failed append does not hold the replies
//!    back: availability first (a full disk would otherwise stop every
//!    client on the network), and the error is on the service's row; a
//!    failed compaction is tried again after [`COMPACT_RETRY_SECS`];
//! 2. replies and probes go to the sockets;
//! 3. a bound lease is named in the DNS (A + PTR through
//!    [`Session::dns_dynamic_lease`], G4.1c-3) and joins its firewall
//!    address lists (dynamic entries that time out with the lease); an
//!    ended lease leaves both. The DNS records are saved once per round,
//!    the list entries are checked against lockout once per round, the
//!    lease history gets one append per round (a storm of N bindings was
//!    N history fsyncs, 2N DNS state rewrites and N config clones);
//! 4. log lines go to the router's log (topic `dhcp`).
//!
//! A round reads at most [`RECV_BUDGET`] messages per socket and stops
//! reading after [`ROUND_BUDGET_US`]: the session lock it holds is the one
//! the control channel and the GUI need too.
//!
//! After a restart the bound leases of the journal get their address-list
//! entries back (they are not stored) and their DNS names are adopted, so
//! they leave the zone when the lease ends.
//!
//! Leases are operational state, like RouterOS': never in the config nor a
//! revision; `ip.dhcp-server.lease.make-static` copies one into the config.

use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr};

use corerouter_hal::DynamicChange;
use corerouter_hal::dhcp_server::{DhcpServerPort, Heard, ReplyTo};
use corerouter_model::IfName;
use corerouter_model::firewall::{AddrMatch, Name};
use corerouter_proto_dhcp::server::plan::Plan;
use corerouter_proto_dhcp::server::{Binding, Effect, Level, Now, Server};
use serde_json::json;

use crate::Session;
use crate::dns_dynamic::LeaseName;
use crate::firewall_dyn::{DynamicEntry, MAX_DYNAMIC};

/// The journal's name in the storage (`journal-dhcp-leases.log`).
pub const JOURNAL: &str = "dhcp-leases";
/// Messages read per socket per round (a flood cannot stall the rest).
const RECV_BUDGET: usize = 256;
/// Microseconds a round may spend reading messages (the rest wait for the
/// next round; the session lock is released in between).
pub const ROUND_BUDGET_US: u64 = 20_000;
/// A compaction that failed (a full or read-only disk) is tried again
/// after this, not every round (each try serializes the whole table).
pub const COMPACT_RETRY_SECS: u64 = 60;
/// Retry opening a socket that failed.
const PORT_RETRY_MS: u64 = 10_000;
/// Compact at least this often (Kea's `lfc-interval` default).
const COMPACT_EVERY_SECS: u64 = 3600;
/// Seconds of slack on an address-list entry past the lease's end.
const LIST_SLACK: u64 = 60;

/// One socket.
#[derive(Default)]
struct Slot {
    port: Option<Box<dyn DhcpServerPort>>,
    error: Option<String>,
    retry_at: u64,
}

/// What a lease left outside the server.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Registered {
    dns: Option<(String, String)>,
    lists: Vec<String>,
}

/// The server's run-time state in the session.
#[derive(Default)]
pub struct DhcpServerRuntime {
    core: Option<Server>,
    revision: Option<u32>,
    slots: BTreeMap<IfName, Slot>,
    loaded: bool,
    /// Lines appended since the last compaction.
    appended: u64,
    compacted_at: u64,
    journal_error: Option<String>,
    registered: HashMap<Ipv4Addr, Registered>,
    /// The daemon's service drives it; the session clock leaves it alone.
    external: bool,
    last_ms: u64,
    /// Address-list entries of this round's bindings, (list, address,
    /// timeout): added together, after one lockout check.
    pending_lists: Vec<(String, Ipv4Addr, u64)>,
    /// The journal was just loaded: its bound leases get their lists and
    /// names back.
    restore: bool,
    /// No compaction before this (Unix time) after one failed.
    compact_retry_at: u64,
}

/// A socket, for `ip.dhcp-server.print` and the service's row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortStatus {
    pub interface: IfName,
    pub listening: Option<String>,
    pub error: Option<String>,
}

impl Session {
    /// The daemon's `dhcp-server` service runs the server from now on (the
    /// session clock stops driving it).
    pub fn dhcp_server_driven(&mut self, external: bool) {
        if let Some(rt) = self.ext_mut::<DhcpServerRuntime>() {
            rt.external = external;
        }
    }

    /// Called by the session clock: runs the server when no service does.
    pub(crate) fn dhcp_server_from_clock(&mut self, now_ms: u64) {
        let external = self
            .ext::<DhcpServerRuntime>()
            .is_some_and(|r| r.external);
        if !external {
            self.dhcp_server_poll(now_ms, &|| now_ms.saturating_mul(1000));
        }
    }

    /// The server, if it has run.
    pub fn dhcp_server(&self) -> Option<&Server> {
        self.ext::<DhcpServerRuntime>().and_then(|r| r.core.as_ref())
    }

    pub(crate) fn dhcp_server_mut(&mut self) -> Option<&mut Server> {
        self.ext_mut::<DhcpServerRuntime>().and_then(|r| r.core.as_mut())
    }

    /// The sockets and their state.
    pub fn dhcp_server_ports(&self) -> Vec<PortStatus> {
        self.ext::<DhcpServerRuntime>()
            .map(|r| {
                r.slots
                    .iter()
                    .map(|(i, s)| PortStatus {
                        interface: i.clone(),
                        listening: s.port.as_ref().map(|p| {
                            let d = p.describe();
                            if d.is_empty() { format!("udp 67 on {i}") } else { d }
                        }),
                        error: s.error.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The DNS name lease `ip` has, as (zone, host).
    pub fn dhcp_server_dns(&self, ip: Ipv4Addr) -> Option<(String, String)> {
        self.ext::<DhcpServerRuntime>()
            .and_then(|r| r.registered.get(&ip))
            .and_then(|g| g.dns.clone())
    }

    /// The firewall address lists lease `ip` is in.
    pub fn dhcp_server_lists(&self, ip: Ipv4Addr) -> Option<Vec<String>> {
        self.ext::<DhcpServerRuntime>()
            .and_then(|r| r.registered.get(&ip))
            .map(|g| g.lists.clone())
    }

    /// The journal's last error, if writing it failed.
    pub fn dhcp_server_journal_error(&self) -> Option<String> {
        self.ext::<DhcpServerRuntime>().and_then(|r| r.journal_error.clone())
    }

    fn dhcp_now(&self, now_ms: u64) -> Now {
        Now {
            ms: now_ms,
            unix: self.now().unwrap_or(now_ms / 1000),
        }
    }

    /// One round: config, sockets, messages, timers, effects. `clock_us`
    /// reads a monotonic clock in microseconds (the processing time of each
    /// reply goes into the statistics). Returns whether anything was heard.
    pub fn dhcp_server_poll(&mut self, now_ms: u64, clock_us: &dyn Fn() -> u64) -> bool {
        // The DNS records the round changes are saved once, at its end.
        self.dns_dynamic_defer();
        let heard = self.dhcp_server_round(now_ms, clock_us);
        let now = self.dhcp_now(now_ms);
        self.dns_dynamic_flush(now.unix);
        heard
    }

    fn dhcp_server_round(&mut self, now_ms: u64, clock_us: &dyn Fn() -> u64) -> bool {
        let start = clock_us();
        let now = self.dhcp_now(now_ms);
        let mut fx: Vec<(Effect, Option<u64>)> = Vec::new();
        self.dhcp_server_sync(now, &mut fx);
        self.dhcp_history_load(now);
        self.dhcp_server_restore(now);
        // G4.2b: the relays first; requests for our own servers come back.
        let mut relayed: Vec<(IfName, Heard)> = Vec::new();
        let mut heard = self.dhcp_relay_poll(now, &mut relayed);
        // G4.2c: the DHCPv6 server and relays, on the same round.
        heard |= self.dhcp6_server_poll(now);
        let Some(rt) = self.ext_mut::<DhcpServerRuntime>() else {
            return heard;
        };
        rt.last_ms = now_ms;
        let Some(core) = rt.core.as_mut() else {
            return heard;
        };
        for (iface, h) in relayed {
            let t0 = clock_us();
            fx.extend(core.handle(now, &iface, &h).into_iter().map(|e| (e, Some(t0))));
        }
        for (iface, slot) in rt.slots.iter_mut() {
            let Some(port) = slot.port.as_mut() else {
                continue;
            };
            port.tick(now.unix);
            for _ in 0..RECV_BUDGET {
                if clock_us().saturating_sub(start) >= ROUND_BUDGET_US {
                    // The rest waits for the next round (the lock is let go).
                    break;
                }
                match port.recv() {
                    Ok(Some(h)) => {
                        heard = true;
                        let t0 = clock_us();
                        fx.extend(core.handle(now, iface, &h).into_iter().map(|e| (e, Some(t0))));
                    }
                    Ok(None) => break,
                    Err(e) => {
                        slot.error = Some(e.to_string());
                        break;
                    }
                }
            }
            match port.probe_replies() {
                Ok(replies) => {
                    for (ip, mac) in replies {
                        fx.extend(core.probe_reply(now, iface, ip, mac).into_iter().map(|e| (e, None)));
                    }
                }
                Err(e) => slot.error = Some(e.to_string()),
            }
        }
        fx.extend(core.tick(now).into_iter().map(|e| (e, None)));
        self.dhcp_server_apply(now, fx, clock_us);
        self.dhcp_server_compact(now, false);
        self.dhcp_history_compact(now);
        heard
    }

    /// After the journal was loaded: the bound leases' address-list
    /// entries (not stored) come back, and their DNS names (stored in the
    /// dynamic records) are known again, to be removed when they end.
    fn dhcp_server_restore(&mut self, now: Now) {
        let due = self
            .ext_mut::<DhcpServerRuntime>()
            .is_some_and(|r| std::mem::take(&mut r.restore));
        if !due {
            return;
        }
        let bindings: Vec<Binding> = self
            .dhcp_server()
            .map(|c| c.leases().iter().filter_map(|l| c.binding_of(l)).collect())
            .unwrap_or_default();
        if bindings.is_empty() {
            return;
        }
        let (_, state) = self.dns_dynamic();
        let names: std::collections::HashSet<(&str, &str, Option<IpAddr>)> = state
            .records
            .iter()
            .map(|r| (r.record.zone.as_str(), r.record.name.as_str(), r.record.address))
            .collect();
        for b in bindings {
            let ip = b.lease.address;
            // A name is adopted only if it is in the zone (the client may
            // have asked for none: RFC 4702 N).
            let dns = b
                .dns
                .filter(|(zone, host)| names.contains(&(zone.as_str(), host.as_str(), Some(IpAddr::V4(ip)))));
            let timeout = b.lease.left(now.unix) + LIST_SLACK;
            if let Some(rt) = self.ext_mut::<DhcpServerRuntime>() {
                for l in &b.address_lists {
                    rt.pending_lists.push((l.clone(), ip, timeout));
                }
                rt.registered.insert(
                    ip,
                    Registered {
                        dns,
                        lists: b.address_lists,
                    },
                );
            }
        }
        self.dhcp_lists_flush(now);
    }

    /// Follow the running config: the plan, the journal (first time), the
    /// sockets.
    fn dhcp_server_sync(&mut self, now: Now, fx: &mut Vec<(Effect, Option<u64>)>) {
        let rev = self.store().current_revision();
        let running = self.store().running();
        let empty = running.ip.dhcp_server.servers.is_empty() && running.ip.dhcp_server.alerts.is_empty();
        let changed = self
            .ext::<DhcpServerRuntime>()
            .is_none_or(|r| r.revision != Some(rev) || r.core.is_none());
        if changed {
            let plan = Plan::from_config(self.store().running());
            let journal = if self.ext::<DhcpServerRuntime>().is_none_or(|r| !r.loaded) && !empty {
                Some(self.storage_mut().load_journal(JOURNAL))
            } else {
                None
            };
            let Some(rt) = self.ext_mut::<DhcpServerRuntime>() else {
                return;
            };
            rt.revision = Some(rev);
            match rt.core.as_mut() {
                Some(core) => fx.extend(core.configure(plan).into_iter().map(|e| (e, None))),
                None if empty => {}
                None => {
                    let mut core = Server::new(plan, now.unix);
                    let mut lines = 0;
                    match journal {
                        Some(Ok(Some(text))) => {
                            lines = text.lines().count() as u64;
                            let bad = core.replay(text.lines());
                            if bad > 0 {
                                fx.push((
                                    Effect::Log {
                                        level: Level::Warning,
                                        text: format!("dhcp-server: {bad} unreadable journal lines skipped"),
                                    },
                                    None,
                                ));
                            }
                        }
                        Some(Err(e)) => rt.journal_error = Some(e.to_string()),
                        _ => {}
                    }
                    rt.loaded = true;
                    rt.appended = lines;
                    rt.compacted_at = now.unix;
                    rt.restore = lines > 0;
                    // Records of servers that are gone end now.
                    let plan = core.plan().clone();
                    fx.extend(core.configure(plan).into_iter().map(|e| (e, None)));
                    rt.core = Some(core);
                }
            }
        }
        let wanted = self
            .dhcp_server()
            .map(|c| c.plan().interfaces())
            .unwrap_or_default();
        let mut open = Vec::new();
        if let Some(rt) = self.ext_mut::<DhcpServerRuntime>() {
            rt.slots.retain(|i, _| wanted.contains(i));
            for i in &wanted {
                let s = rt.slots.entry(i.clone()).or_default();
                if s.port.is_none() && s.retry_at <= now.ms {
                    open.push(i.clone());
                }
            }
        }
        for i in open {
            let r = self.hal_mut().dhcp_server_port(&i);
            if let Some(s) = self.ext_mut::<DhcpServerRuntime>().and_then(|rt| rt.slots.get_mut(&i)) {
                match r {
                    Ok(p) => {
                        s.port = Some(p);
                        s.error = None;
                    }
                    Err(e) => {
                        s.error = Some(e.to_string());
                        s.retry_at = now.ms + PORT_RETRY_MS;
                    }
                }
            }
        }
    }

    fn dhcp_server_apply(&mut self, now: Now, fx: Vec<(Effect, Option<u64>)>, clock_us: &dyn Fn() -> u64) {
        if fx.is_empty() {
            return;
        }
        // 1. The journal, synced, before any reply.
        let mut text = String::new();
        let mut n = 0u64;
        for (e, _) in &fx {
            if let Effect::Journal(r) = e
                && let Ok(line) = serde_json::to_string(r)
            {
                text.push_str(&line);
                text.push('\n');
                n += 1;
            }
        }
        if n > 0 {
            let r = self.storage_mut().append_journal(JOURNAL, &text);
            if let Some(rt) = self.ext_mut::<DhcpServerRuntime>() {
                rt.appended += n;
                match r {
                    Ok(()) => rt.journal_error = None,
                    Err(e) => {
                        let first = rt.journal_error.is_none();
                        rt.journal_error = Some(e.to_string());
                        if first {
                            log::error!("dhcp-server: leases not saved: {e}");
                        }
                    }
                }
            }
        }
        let mut later = Vec::new();
        // Replies to the router's own relays go to them, not on the wire.
        let mut to_relays: Vec<Vec<u8>> = Vec::new();
        let relays: Vec<Ipv4Addr> = fx
            .iter()
            .filter_map(|(e, _)| match e {
                Effect::Send { to: ReplyTo::Relay(ip), .. } => Some(*ip),
                _ => None,
            })
            .filter(|ip| self.dhcp_relay_is_ours(*ip))
            .collect();
        // 2. Replies and probes.
        if let Some(rt) = self.ext_mut::<DhcpServerRuntime>() {
            for (e, t0) in fx {
                match e {
                    Effect::Send { to: ReplyTo::Relay(ip), payload, .. } if relays.contains(&ip) => {
                        if let (Some(t0), Some(core)) = (t0, rt.core.as_mut()) {
                            core.stats_mut().latency(clock_us().saturating_sub(t0));
                        }
                        to_relays.push(payload);
                    }
                    Effect::Discover { interface } => {
                        if let Some(port) = rt.slots.get_mut(&interface).and_then(|s| s.port.as_mut()) {
                            let mac = port.mac();
                            let xid = corerouter_hal::dhcp::lab_hash(&now.ms.to_be_bytes());
                            let payload = corerouter_proto_dhcp::server::alert_discover(mac, xid);
                            if let Some(p) = payload
                                && let Err(err) = port.send_discover(&p)
                            {
                                log::debug!("dhcp-server: alert DISCOVER on {interface}: {err}");
                            }
                        }
                    }
                    Effect::Send { interface, payload, src, to, .. } => {
                        let Some(slot) = rt.slots.get_mut(&interface) else {
                            continue;
                        };
                        let Some(port) = slot.port.as_mut() else {
                            continue;
                        };
                        if let Err(err) = port.send(&payload, src, to) {
                            slot.error = Some(format!("send: {err}"));
                        } else if let (Some(t0), Some(core)) = (t0, rt.core.as_mut()) {
                            core.stats_mut().latency(clock_us().saturating_sub(t0));
                        }
                    }
                    Effect::Probe { interface, ip, src } => {
                        if let Some(port) = rt.slots.get_mut(&interface).and_then(|s| s.port.as_mut())
                            && let Err(err) = port.probe(ip, src)
                        {
                            log::debug!("dhcp-server: probe of {ip} on {interface}: {err}");
                        }
                    }
                    Effect::Journal(_) => {}
                    other => later.push(other),
                }
            }
        }
        for r in to_relays {
            self.dhcp_relay_down(&r, None);
        }
        // 3. and 4.
        for e in later {
            match e {
                Effect::Bound(b) => {
                    self.dhcp_bound(&b, now);
                    self.dhcp_history_bound(&b.lease, b.new, now);
                }
                Effect::Gone(l) => {
                    self.dhcp_gone(l.address, now);
                    self.dhcp_history_gone(l.address, now);
                }
                Effect::Log { level, text } => {
                    let topics: &[&str] = match level {
                        Level::Info => &["dhcp", "info"],
                        Level::Warning => &["dhcp", "warning"],
                        Level::Critical => &["dhcp", "critical"],
                    };
                    self.log_event(topics, "dhcp-server", text, json!({}));
                }
                _ => {}
            }
        }
        self.dhcp_lists_flush(now);
        self.dhcp_history_flush();
    }

    fn dhcp_bound(&mut self, b: &Binding, now: Now) {
        let ip = b.lease.address;
        let before = self
            .ext::<DhcpServerRuntime>()
            .and_then(|r| r.registered.get(&ip).cloned())
            .unwrap_or_default();
        let mut reg = Registered {
            dns: b.dns.clone(),
            lists: b.address_lists.clone(),
        };
        if before.dns != reg.dns {
            if let Some((zone, host)) = &before.dns {
                let _ = self.dns_dynamic_release(zone, host, IpAddr::V4(ip), now.unix);
            }
            if let Some((zone, host)) = &reg.dns {
                let lease = LeaseName {
                    zone: zone.clone(),
                    host: host.clone(),
                    address: IpAddr::V4(ip),
                    ttl_secs: b.ttl,
                    // Removed by the server when the lease ends, not by time.
                    expires_unix: None,
                    source: format!("dhcp {}", b.lease.server),
                };
                if let Err(e) = self.dns_dynamic_lease(&lease, now.unix) {
                    self.log_event(
                        &["dhcp", "warning"],
                        "dhcp-server",
                        format!("{ip}: not named in DNS: {e}"),
                        json!({}),
                    );
                    reg.dns = None;
                }
            }
        }
        for l in &before.lists {
            if !reg.lists.contains(l) {
                self.dhcp_list_remove(l, ip);
            }
        }
        // Joined at the end of the round, with the round's other bindings
        // (`dhcp_lists_flush`: one lockout check for all of them).
        let timeout = b.lease.left(now.unix) + LIST_SLACK;
        if let Some(rt) = self.ext_mut::<DhcpServerRuntime>() {
            for l in &reg.lists {
                rt.pending_lists.retain(|(pl, pip, _)| !(pl == l && *pip == ip));
                rt.pending_lists.push((l.clone(), ip, timeout));
            }
            rt.registered.insert(ip, reg);
        }
    }

    fn dhcp_gone(&mut self, ip: Ipv4Addr, now: Now) {
        let Some(reg) = self.ext_mut::<DhcpServerRuntime>().and_then(|r| {
            r.pending_lists.retain(|(_, pip, _)| *pip != ip);
            r.registered.remove(&ip)
        }) else {
            return;
        };
        if let Some((zone, host)) = &reg.dns {
            let _ = self.dns_dynamic_release(zone, host, IpAddr::V4(ip), now.unix);
        }
        for l in &reg.lists {
            self.dhcp_list_remove(l, ip);
        }
    }

    /// The round's address-list entries: one lockout check for all the new
    /// ones (against the running config, borrowed), then each is added;
    /// when the check fails, each is checked alone (and the refused ones
    /// leave the lease's lists).
    fn dhcp_lists_flush(&mut self, now: Now) {
        let pending = self
            .ext_mut::<DhcpServerRuntime>()
            .map(|r| std::mem::take(&mut r.pending_lists))
            .unwrap_or_default();
        if pending.is_empty() {
            return;
        }
        let at = self.now();
        let mut before: Option<Vec<_>> = None;
        let mut after = Vec::new();
        for (list, ip, timeout) in &pending {
            let Ok(name) = list.parse::<Name>() else {
                continue;
            };
            let addr = AddrMatch::Net(ipnet::IpNet::from(IpAddr::V4(*ip)));
            if self.dynamic_addresses.find(&name, &addr).is_some() {
                continue;
            }
            let entry = DynamicEntry {
                id: self.dynamic_addresses.next_id(),
                list: name,
                address: addr,
                timeout_secs: (*timeout).max(1),
                added: Some(now.unix),
                comment: "dhcp".into(),
            };
            let b = before.get_or_insert_with(|| self.dynamic_now());
            if after.is_empty() {
                after = b.clone();
            }
            after.push(entry.data_plane(at));
        }
        let all_ok = match &before {
            None => true,
            Some(b) => {
                let running = self.store().running();
                self.check_lockout(running, running, b, &after).is_ok()
            }
        };
        for (list, ip, timeout) in pending {
            if !self.dhcp_list_put(&list, ip, timeout, now, !all_ok)
                && let Some(reg) = self
                    .ext_mut::<DhcpServerRuntime>()
                    .and_then(|r| r.registered.get_mut(&ip))
            {
                reg.lists.retain(|l| *l != list);
            }
        }
    }

    /// `ip` in firewall list `list` for `timeout` seconds (a dynamic entry,
    /// refreshed when it has less than half left). False if refused.
    /// `check`: the lockout check for this entry alone (else the caller
    /// checked the round's entries together).
    fn dhcp_list_put(&mut self, list: &str, ip: Ipv4Addr, timeout: u64, now: Now, check: bool) -> bool {
        let Ok(name) = list.parse::<Name>() else {
            return false;
        };
        let addr = AddrMatch::Net(ipnet::IpNet::from(IpAddr::V4(ip)));
        let at = self.now();
        if let Some(e) = self.dynamic_addresses.find(&name, &addr) {
            if e.left(at) >= timeout / 2 {
                return true;
            }
            let id = e.id;
            if let Some(old) = self.dynamic_addresses.remove(id) {
                let _ = self
                    .hal_mut()
                    .address_list_dynamic(DynamicChange::Remove(&old.data_plane(at)));
            }
        }
        if self.dynamic_addresses.entries().len() >= MAX_DYNAMIC {
            return false;
        }
        let entry = DynamicEntry {
            id: self.dynamic_addresses.next_id(),
            list: name,
            address: addr,
            timeout_secs: timeout.max(1),
            added: Some(now.unix),
            comment: "dhcp".into(),
        };
        // Operational state, not a commit: the lockout check is here (a
        // list that a drop rule uses could cut the operator off).
        if check {
            let before = self.dynamic_now();
            let mut after = before.clone();
            after.push(entry.data_plane(at));
            let running = self.store().running();
            if let Err(e) = self.check_lockout(running, running, &before, &after) {
                self.log_event(
                    &["dhcp", "warning"],
                    "dhcp-server",
                    format!("{ip} not added to address list {list}: {e}"),
                    json!({}),
                );
                return false;
            }
        }
        if let Err(e) = self
            .hal_mut()
            .address_list_dynamic(DynamicChange::Add(&entry.data_plane(at)))
        {
            log::warn!("dhcp-server: {ip} → {list}: {e}");
            return false;
        }
        self.dynamic_addresses.push(entry);
        true
    }

    fn dhcp_list_remove(&mut self, list: &str, ip: Ipv4Addr) {
        let Ok(name) = list.parse::<Name>() else {
            return;
        };
        let addr = AddrMatch::Net(ipnet::IpNet::from(IpAddr::V4(ip)));
        let at = self.now();
        let Some(id) = self.dynamic_addresses.find(&name, &addr).map(|e| e.id) else {
            return;
        };
        if let Some(old) = self.dynamic_addresses.remove(id) {
            let _ = self
                .hal_mut()
                .address_list_dynamic(DynamicChange::Remove(&old.data_plane(at)));
        }
    }

    /// Rewrite the journal with the live records when it is due (`force`:
    /// now).
    pub(crate) fn dhcp_server_compact(&mut self, now: Now, force: bool) {
        let due = self.ext::<DhcpServerRuntime>().is_some_and(|r| {
            let records = r.core.as_ref().map_or(0, |c| c.leases().len() as u64);
            r.loaded
                && r.appended > 0
                && (force || now.unix >= r.compact_retry_at)
                && (force
                    || r.appended > 2 * records + 1024
                    || now.unix >= r.compacted_at + COMPACT_EVERY_SECS)
        });
        if !due {
            return;
        }
        let Some(text) = self.dhcp_server().map(|c| c.compact(now.unix)) else {
            return;
        };
        let lines = text.lines().count() as u64;
        let r = self.storage_mut().rewrite_journal(JOURNAL, &text);
        if let Some(rt) = self.ext_mut::<DhcpServerRuntime>() {
            rt.compacted_at = now.unix;
            match r {
                Ok(()) => rt.appended = lines,
                Err(e) => {
                    rt.journal_error = Some(e.to_string());
                    rt.compact_retry_at = now.unix + COMPACT_RETRY_SECS;
                }
            }
        }
    }

    /// Run server operations that produce effects (operator commands).
    pub(crate) fn dhcp_server_effects(&mut self, fx: Vec<Effect>) {
        let now_ms = self.ext::<DhcpServerRuntime>().map_or(0, |r| r.last_ms);
        let now = self.dhcp_now(now_ms);
        let ms = now.ms;
        self.dns_dynamic_defer();
        self.dhcp_server_apply(now, fx.into_iter().map(|e| (e, None)).collect(), &|| ms * 1000);
        self.dns_dynamic_flush(now.unix);
    }

    pub(crate) fn dhcp_server_clock(&self) -> Now {
        let now_ms = self.ext::<DhcpServerRuntime>().map_or(0, |r| r.last_ms);
        self.dhcp_now(now_ms)
    }

}
