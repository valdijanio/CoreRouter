//! The DHCP relay at run time (G4.2b): requests heard on each relay's
//! interface go up to its servers ([`corerouter_proto_dhcp::relay::up`]),
//! the servers' replies come back down to the clients
//! ([`corerouter_proto_dhcp::relay::down`]). Driven by the DHCP server's
//! round (`Session::dhcp_server_poll`), on the same sockets the HAL gives
//! the server, plus one UDP socket towards the servers (`DhcpUplink`).
//!
//! A relay whose server is the router itself (a server with `relay` set to
//! the relay's address) talks to it in memory, without a socket: the lab
//! and a router that is both relay and server work the same way.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use corerouter_hal::dhcp_server::{DhcpServerPort, DhcpUplink, Heard};
use corerouter_model::IfName;
use corerouter_proto_dhcp::relay::{self, RelayPlan};
use corerouter_proto_dhcp::server::Now;
use serde::Serialize;

use crate::Session;

const RECV_BUDGET: usize = 256;
const RETRY_MS: u64 = 10_000;

#[derive(Default)]
struct Slot {
    port: Option<Box<dyn DhcpServerPort>>,
    error: Option<String>,
    retry_at: u64,
}

/// What one relay did since the daemon started.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct RelayCounters {
    /// Requests sent up (one per server).
    pub requests: u64,
    /// Replies sent down to clients.
    pub replies: u64,
    /// Not relayed, by reason (`malformed`, `hops`, `send`).
    pub dropped: BTreeMap<String, u64>,
}

#[derive(Default)]
pub struct RelayRuntime {
    revision: Option<u32>,
    plans: Vec<RelayPlan>,
    /// The router's own addresses (servers reached in memory).
    local: Vec<Ipv4Addr>,
    slots: BTreeMap<IfName, Slot>,
    uplink: Option<Box<dyn DhcpUplink>>,
    uplink_error: Option<String>,
    uplink_retry_at: u64,
    counters: BTreeMap<String, RelayCounters>,
}

/// A relay at run time, for `ip.dhcp-relay.print`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayStatus {
    pub name: String,
    pub giaddr: Option<Ipv4Addr>,
    pub listening: bool,
    pub error: Option<String>,
    pub counters: RelayCounters,
}

fn count(c: &mut BTreeMap<String, RelayCounters>, relay: &str, f: impl FnOnce(&mut RelayCounters)) {
    f(c.entry(relay.to_owned()).or_default());
}

fn dropped(c: &mut BTreeMap<String, RelayCounters>, relay: &str, why: &str) {
    count(c, relay, |r| *r.dropped.entry(why.to_owned()).or_default() += 1);
}

impl Session {
    fn relay_sync(&mut self, now: Now) {
        let rev = self.store().current_revision();
        if self.ext::<RelayRuntime>().is_none_or(|r| r.revision != Some(rev)) {
            let running = self.store().running();
            let plans = relay::plans(running);
            let local: Vec<Ipv4Addr> = corerouter_proto_dhcp::server::checks::router_addresses(running)
                .into_iter()
                .map(|(n, _)| n.addr())
                .collect();
            if let Some(rt) = self.ext_mut::<RelayRuntime>() {
                rt.revision = Some(rev);
                rt.slots.retain(|i, _| plans.iter().any(|p| p.interface == *i));
                rt.counters.retain(|n, _| plans.iter().any(|p| p.name == *n));
                rt.plans = plans;
                rt.local = local;
            }
        }
        let Some(rt) = self.ext_mut::<RelayRuntime>() else {
            return;
        };
        let wanted: Vec<IfName> = rt.plans.iter().map(|p| p.interface.clone()).collect();
        let remote = rt
            .plans
            .iter()
            .any(|p| p.servers.iter().any(|s| !rt.local.contains(s)));
        let mut open = Vec::new();
        for i in wanted {
            let s = rt.slots.entry(i.clone()).or_default();
            if s.port.is_none() && s.retry_at <= now.ms {
                open.push(i);
            }
        }
        let want_uplink = remote && rt.uplink.is_none() && rt.uplink_retry_at <= now.ms;
        if !remote {
            rt.uplink = None;
            rt.uplink_error = None;
        }
        for i in open {
            let r = self.hal_mut().dhcp_server_port(&i);
            if let Some(s) = self.ext_mut::<RelayRuntime>().and_then(|rt| rt.slots.get_mut(&i)) {
                match r {
                    Ok(p) => {
                        s.port = Some(p);
                        s.error = None;
                    }
                    Err(e) => {
                        s.error = Some(e.to_string());
                        s.retry_at = now.ms + RETRY_MS;
                    }
                }
            }
        }
        if want_uplink {
            let r = self.hal_mut().dhcp_relay_uplink();
            if let Some(rt) = self.ext_mut::<RelayRuntime>() {
                match r {
                    Ok(u) => {
                        rt.uplink = Some(u);
                        rt.uplink_error = None;
                    }
                    Err(e) => {
                        rt.uplink_error = Some(e.to_string());
                        rt.uplink_retry_at = now.ms + RETRY_MS;
                    }
                }
            }
        }
    }

    /// One round of every relay: requests up (those for the router's own
    /// servers are returned, to hand to the server), replies down. Returns
    /// whether anything was heard.
    pub(crate) fn dhcp_relay_poll(&mut self, now: Now, local: &mut Vec<(IfName, Heard)>) -> bool {
        self.relay_sync(now);
        let Some(rt) = self.ext_mut::<RelayRuntime>() else {
            return false;
        };
        let mut heard = false;
        let RelayRuntime {
            plans,
            local: mine,
            slots,
            uplink,
            counters,
            ..
        } = rt;
        for plan in plans.iter() {
            let Some(slot) = slots.get_mut(&plan.interface) else {
                continue;
            };
            let Some(port) = slot.port.as_mut() else {
                continue;
            };
            port.tick(now.unix);
            for _ in 0..RECV_BUDGET {
                let h = match port.recv() {
                    Ok(Some(h)) => h,
                    Ok(None) => break,
                    Err(e) => {
                        slot.error = Some(e.to_string());
                        break;
                    }
                };
                if !h.to_server {
                    continue;
                }
                heard = true;
                let up = match relay::up(plan, &h.payload, h.src_mac) {
                    Ok(m) => m,
                    Err(why) => {
                        dropped(counters, &plan.name, why.as_str());
                        continue;
                    }
                };
                for server in &plan.servers {
                    if mine.contains(server) {
                        local.push((
                            plan.interface.clone(),
                            Heard {
                                payload: up.clone(),
                                src: plan.giaddr,
                                dst: *server,
                                src_mac: h.src_mac,
                                to_server: true,
                            },
                        ));
                        count(counters, &plan.name, |c| c.requests += 1);
                        continue;
                    }
                    match uplink.as_mut().map(|u| u.send(&up, *server)) {
                        Some(Ok(())) => count(counters, &plan.name, |c| c.requests += 1),
                        Some(Err(e)) => {
                            slot.error = Some(e.to_string());
                            dropped(counters, &plan.name, "send");
                        }
                        None => dropped(counters, &plan.name, "no-uplink"),
                    }
                }
            }
        }
        // Replies from the servers.
        let mut replies = Vec::new();
        if let Some(u) = uplink.as_mut() {
            for _ in 0..RECV_BUDGET {
                match u.recv() {
                    Ok(Some(h)) => replies.push((h.src, h.payload)),
                    Ok(None) | Err(_) => break,
                }
            }
        }
        heard |= !replies.is_empty();
        for (src, r) in replies {
            self.dhcp_relay_down(&r, Some(src));
        }
        heard
    }

    /// Whether `ip` is the `giaddr` of one of the router's relays (a server
    /// reply to it is handed to the relay, not sent).
    pub(crate) fn dhcp_relay_is_ours(&self, ip: Ipv4Addr) -> bool {
        self.ext::<RelayRuntime>()
            .is_some_and(|r| r.plans.iter().any(|p| p.giaddr == ip))
    }

    /// A server's reply for one of our relays: down to its client. `from`:
    /// the address it came from on the uplink (`None`: the router's own
    /// server). The uplink listens on port 67 of every interface: only the
    /// relay's servers may answer through it.
    pub(crate) fn dhcp_relay_down(&mut self, payload: &[u8], from: Option<Ipv4Addr>) {
        let Some(rt) = self.ext_mut::<RelayRuntime>() else {
            return;
        };
        // The relay is the one whose giaddr the reply carries.
        let giaddr = match payload.get(24..28) {
            Some([a, b, c, d]) => Ipv4Addr::new(*a, *b, *c, *d),
            _ => return,
        };
        let Some(plan) = rt.plans.iter().find(|p| p.giaddr == giaddr).cloned() else {
            return;
        };
        if from.is_some_and(|src| !plan.servers.contains(&src)) {
            dropped(&mut rt.counters, &plan.name, relay::RelayDrop::NotFromServer.as_str());
            return;
        }
        match relay::down(&plan, payload) {
            Ok((msg, to, _)) => {
                let sent = rt
                    .slots
                    .get_mut(&plan.interface)
                    .and_then(|s| s.port.as_mut())
                    .map(|p| p.send(&msg, plan.giaddr, to));
                match sent {
                    Some(Ok(())) => count(&mut rt.counters, &plan.name, |c| c.replies += 1),
                    Some(Err(e)) => {
                        if let Some(s) = rt.slots.get_mut(&plan.interface) {
                            s.error = Some(e.to_string());
                        }
                        dropped(&mut rt.counters, &plan.name, "send");
                    }
                    None => dropped(&mut rt.counters, &plan.name, "no-socket"),
                }
            }
            Err(why) => dropped(&mut rt.counters, &plan.name, why.as_str()),
        }
    }

    /// The relays at run time.
    pub fn dhcp_relay_status(&self) -> Vec<RelayStatus> {
        let Some(rt) = self.ext::<RelayRuntime>() else {
            return Vec::new();
        };
        rt.plans
            .iter()
            .map(|p| {
                let slot = rt.slots.get(&p.interface);
                let remote = p.servers.iter().any(|s| !rt.local.contains(s));
                RelayStatus {
                    name: p.name.clone(),
                    giaddr: Some(p.giaddr),
                    listening: slot.is_some_and(|s| s.port.is_some()),
                    error: slot
                        .and_then(|s| s.error.clone())
                        .or_else(|| rt.uplink_error.clone().filter(|_| remote)),
                    counters: rt.counters.get(&p.name).cloned().unwrap_or_default(),
                }
            })
            .collect()
    }
}
