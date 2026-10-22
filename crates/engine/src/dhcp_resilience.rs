//! DHCP client resilience (G4.7c), on top of [`crate::dhcp_client`]:
//!
//! - **remembered lease**: every lease is kept, outside the config and its
//!   revisions, in the storage's `dhcp-leases` state; a client that starts
//!   again (daemon restart, client or interface re-enabled) asks for it with
//!   INIT-REBOOT (RFC 2131 §3.2 / §4.4.2) instead of DISCOVER;
//! - **fallback address**: `fallback_address` goes on the interface after
//!   `fallback_timeout` s without a lease, and leaves when one comes;
//! - **check-gateway**: `arp` / `ping` the lease's gateway every 10 s; after
//!   2 unanswered checks its routes leave the data plane (shown inactive
//!   in `ip.route.list`, so a route with a higher distance takes over) and
//!   come back at the first answer — RouterOS' `check-gateway` rule.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use corerouter_hal::dhcp::MAX_MESSAGE;
use corerouter_hal::probe::{Probe, ProbeSocket, ReplyKind, SocketOptions, overhead};
use corerouter_model::dhcp_client::{CheckGateway, MAX_CLIENTS};
use corerouter_model::{AddressEntry, Config, IfName, ItemId, RouteEntry};
use corerouter_proto_dhcp::client::{Lease, State, restore_lease};
use ipnet::{IpNet, Ipv4Net};
use serde::{Deserialize, Serialize};

use crate::Session;
use crate::dhcp_client::{Runner, dyn_id};

/// Name of the remembered leases in [`crate::ConfigStorage::save_state`].
pub const LEASES_STATE: &str = "dhcp-leases";
/// RouterOS' `check-gateway`: one check every 10 s, the gateway is down
/// after 2 unanswered ones and up again at the first answer.
pub const CHECK_INTERVAL_MS: u64 = 10_000;
pub const CHECK_MISSES: u32 = 2;
/// How long one check waits for its answer (RouterOS' ping timeout is 1 s;
/// a busy CPE answers ARP late, **estimado**).
pub const CHECK_WAIT_MS: u64 = 2_000;
/// Index of the fallback address among the client's dynamic ids.
const FALLBACK_N: usize = 0xFF;

/// A lease kept across restarts: the ACK as received, re-checked like a
/// fresh one when it is read back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Remembered {
    pub client: ItemId,
    pub interface: IfName,
    pub mac: [u8; 6],
    pub address: Ipv4Net,
    pub server: Ipv4Addr,
    #[serde(default)]
    pub server_mac: Option<[u8; 6]>,
    /// The ACK, in hex.
    pub ack: String,
    /// Wall clock (Unix seconds) when it was granted, if the router had one.
    #[serde(default)]
    pub granted_unix: Option<u64>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct LeaseFile {
    #[serde(default)]
    leases: Vec<Remembered>,
}

fn to_hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || s.len() > MAX_MESSAGE * 2 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            s.get(i..i.saturating_add(2))
                .and_then(|b| u8::from_str_radix(b, 16).ok())
        })
        .collect()
}

/// The gateway check of one client.
#[derive(Default)]
pub(crate) struct GatewayCheck {
    /// The gateway being checked.
    pub target: Option<Ipv4Addr>,
    next_at: u64,
    sent_at: Option<u64>,
    misses: u32,
    /// Its routes are withheld.
    pub down: bool,
    seq: u16,
    ping: Option<Box<dyn ProbeSocket>>,
}

impl GatewayCheck {
    /// A new lease: the ping socket's source address may have changed.
    pub(crate) fn new_lease(&mut self) {
        self.ping = None;
        self.sent_at = None;
    }
}

impl Runner {
    /// `ip.dhcp-client.list`'s `gateway_status`.
    pub fn gateway_status(&self) -> &'static str {
        match (&self.gw.target, self.gw.down) {
            (None, _) => "unchecked",
            (Some(_), false) => "up",
            (Some(_), true) => "down",
        }
    }

    /// Whether `route` is one of this client's and waits for its gateway.
    pub fn withholds(&self, route: &RouteEntry) -> bool {
        self.gw.down
            && self.gw.target.is_some_and(|gw| {
                route.gateway.address() == Some(IpAddr::V4(gw))
                    && self.routes.iter().any(|r| r.id == route.id)
            })
    }
}

/// The gateway to check for `routes`: the default route's, else the first.
fn gateway_of(routes: &[RouteEntry]) -> Option<Ipv4Addr> {
    let v4 = |r: &RouteEntry| match r.gateway.address() {
        Some(IpAddr::V4(g)) => Some(g),
        _ => None,
    };
    routes
        .iter()
        .find(|r| r.dst_address.prefix_len() == 0)
        .and_then(v4)
        .or_else(|| routes.iter().find_map(v4))
}

impl crate::dhcp_client::DhcpRuntime {
    /// The lease remembered for client `id`, if any.
    pub fn remembered(&self, id: ItemId) -> Option<&Remembered> {
        self.remembered.get(&id)
    }
}

impl Session {
    /// Read the remembered leases once (the first service call).
    pub(crate) fn dhcp_load_leases(&mut self) {
        if self.dhcp.loaded {
            return;
        }
        self.dhcp.loaded = true;
        let text = match self.storage_mut().load_state(LEASES_STATE) {
            Ok(Some(t)) => t,
            Ok(None) => return,
            Err(e) => {
                log::warn!("dhcp-client: remembered leases not read: {e}");
                return;
            }
        };
        let file: LeaseFile = match serde_json::from_str(&text) {
            Ok(f) => f,
            Err(e) => {
                log::warn!("dhcp-client: remembered leases unreadable, ignored: {e}");
                return;
            }
        };
        for m in file.leases.into_iter().take(MAX_CLIENTS) {
            if from_hex(&m.ack).is_some() {
                self.dhcp.remembered.insert(m.client, m);
            }
        }
    }

    fn dhcp_save_leases(&mut self) {
        let file = LeaseFile {
            leases: self.dhcp.remembered.values().cloned().collect(),
        };
        let saved = serde_json::to_string(&file)
            .map_err(|e| e.to_string())
            .and_then(|t| {
                self.storage_mut()
                    .save_state(LEASES_STATE, &t)
                    .map_err(|e| e.to_string())
            });
        if let Err(e) = saved {
            log::warn!("dhcp-client: leases not remembered: {e}");
        }
    }

    /// Keep `lease` of client `id` for the next start.
    pub(crate) fn dhcp_remember(&mut self, id: ItemId, lease: &Lease) {
        let Some((interface, mac)) = self
            .dhcp
            .runners
            .get(&id)
            .and_then(|r| r.port.as_ref().map(|p| (r.cfg.interface.clone(), p.mac())))
        else {
            return;
        };
        let ack = to_hex(&lease.ack);
        // A remembered lease reused without a server keeps its first age.
        if self.dhcp.remembered.get(&id).is_some_and(|m| m.ack == ack) {
            return;
        }
        let m = Remembered {
            client: id,
            interface,
            mac,
            address: lease.address,
            server: lease.server,
            server_mac: lease.server_mac,
            ack,
            granted_unix: self.now(),
        };
        self.dhcp.remembered.insert(id, m);
        self.dhcp_save_leases();
    }

    /// Forget client `id`'s lease (NAK, release, client removed).
    pub(crate) fn dhcp_forget(&mut self, id: ItemId) {
        if self.dhcp.remembered.remove(&id).is_some() {
            self.dhcp_save_leases();
        }
    }

    /// The remembered lease of client `id` for a start at `now` on
    /// `interface` with `mac`, checked again, or `None`.
    pub(crate) fn dhcp_recall(
        &self,
        id: ItemId,
        interface: &IfName,
        mac: [u8; 6],
        now: u64,
    ) -> Option<Lease> {
        let m = self.dhcp.remembered.get(&id)?;
        if m.interface != *interface || m.mac != mac {
            return None;
        }
        let ack = from_hex(&m.ack)?;
        // A clock that went backwards says nothing about the lease's age.
        let age = self
            .now()
            .zip(m.granted_unix)
            .and_then(|(n, g)| n.checked_sub(g))
            .map(|s| s.saturating_mul(1_000));
        match restore_lease(now, &ack, m.server, m.server_mac, age) {
            Ok(l) => Some(l),
            Err(e) => {
                log::warn!("dhcp-client {id}: remembered lease ignored: {e}");
                None
            }
        }
    }

    /// Change runner `id` with `f` and push the difference it makes to the
    /// data plane (fallback address, withheld routes).
    fn dhcp_change(&mut self, id: ItemId, f: impl FnOnce(&mut Runner)) {
        let running = self.store().running().clone();
        let before = self.effective(&running).into_owned();
        let Some(r) = self.dhcp.runners.get_mut(&id) else {
            return;
        };
        f(r);
        let after = self.effective(&running).into_owned();
        if before != after
            && let Err(e) = self.hal_mut().apply(&before, &after)
        {
            self.dhcp_note_id(id, "error", format!("not applied: {e}"));
        }
    }

    /// Fallback address and gateway check of runner `id` at `now`.
    pub(crate) fn dhcp_resilience(&mut self, id: ItemId, now: u64) {
        self.dhcp_fallback(id, now);
        self.dhcp_check_gateway(id, now);
    }

    fn dhcp_fallback(&mut self, id: ItemId, now: u64) {
        let Some(r) = self.dhcp.runners.get_mut(&id) else {
            return;
        };
        let leased = r.lease().is_some() || r.client.is_none();
        let want = r.cfg.fallback_address;
        let current = r.fallback.as_ref().and_then(|a| match a.address {
            IpNet::V4(n) => Some(n),
            IpNet::V6(_) => None,
        });
        if leased {
            r.searching_since = None;
        }
        let since = *r.searching_since.get_or_insert(now);
        let due = now.saturating_sub(since) >= u64::from(r.cfg.fallback_timeout) * 1_000;
        let target = want.filter(|_| !leased && due);
        if target == current {
            return;
        }
        let iface = r.cfg.interface.clone();
        let (event, message) = match (target, current) {
            (Some(a), _) => (
                "fallback",
                format!(
                    "no lease after {} s: fallback address {a} on {iface}",
                    r.cfg.fallback_timeout
                ),
            ),
            (None, Some(a)) => ("fallback", format!("fallback address {a} removed")),
            (None, None) => return,
        };
        self.dhcp_change(id, |r| {
            r.fallback = target.map(|a| AddressEntry {
                id: dyn_id(r.cfg.id, FALLBACK_N),
                address: IpNet::V4(a),
                interface: r.cfg.interface.clone(),
                disabled: false,
                comment: "fallback".into(),
                from_pool: None,
            });
        });
        self.dhcp_note_id(id, event, message);
    }

    fn dhcp_check_gateway(&mut self, id: ItemId, now: u64) {
        let pinging = self
            .dhcp
            .runners
            .get(&id)
            .is_some_and(|r| r.cfg.check_gateway == CheckGateway::Ping && r.gw.ping.is_none());
        let prober = if pinging {
            Some(self.hal_mut().prober())
        } else {
            None
        };
        let Some(r) = self.dhcp.runners.get_mut(&id) else {
            return;
        };
        let held = matches!(r.state(), State::Bound | State::Renewing | State::Rebinding);
        let target = (r.cfg.check_gateway != CheckGateway::None && held)
            .then(|| gateway_of(&r.routes))
            .flatten();
        if target != r.gw.target {
            let was_down = r.gw.down;
            // The ARP slot is the DHCP probe's now if the client is probing.
            if r.gw.sent_at.is_some()
                && r.cfg.check_gateway == CheckGateway::Arp
                && r.state() != State::Probing
                && let Some(p) = r.port.as_mut()
            {
                p.end_probe();
            }
            let reset = |r: &mut Runner| {
                r.gw = GatewayCheck {
                    target,
                    next_at: now,
                    ..GatewayCheck::default()
                };
            };
            if was_down {
                self.dhcp_change(id, reset);
            } else {
                reset(r);
            }
            return;
        }
        let Some(gw) = target else {
            return;
        };
        let mode = r.cfg.check_gateway;
        if let Some(sent) = r.gw.sent_at {
            let answered = match mode {
                CheckGateway::Arp => r
                    .port
                    .as_mut()
                    .and_then(|p| p.conflict().ok().flatten())
                    .is_some(),
                CheckGateway::Ping => ping_answered(&mut r.gw, gw),
                CheckGateway::None => true,
            };
            let timed_out = now.saturating_sub(sent) >= CHECK_WAIT_MS;
            if !answered && !timed_out {
                return;
            }
            if mode == CheckGateway::Arp
                && let Some(p) = r.port.as_mut()
            {
                p.end_probe();
            }
            r.gw.sent_at = None;
            if answered {
                r.gw.misses = 0;
                if r.gw.down {
                    self.dhcp_change(id, |r| r.gw.down = false);
                    self.dhcp_note_id(
                        id,
                        "gateway",
                        format!("gateway {gw} answers again: its routes are back"),
                    );
                }
            } else {
                r.gw.misses = r.gw.misses.saturating_add(1);
                if r.gw.misses >= CHECK_MISSES && !r.gw.down {
                    let how = mode.as_str();
                    self.dhcp_change(id, |r| r.gw.down = true);
                    self.dhcp_note_id(
                        id,
                        "gateway",
                        format!(
                            "gateway {gw} did not answer {CHECK_MISSES} {how} checks: its routes are inactive"
                        ),
                    );
                }
            }
            return;
        }
        if now < r.gw.next_at {
            return;
        }
        r.gw.next_at = now.saturating_add(CHECK_INTERVAL_MS);
        let sent = match mode {
            CheckGateway::Arp => r
                .port
                .as_mut()
                .map(|p| p.probe(gw).map_err(|e| e.to_string()))
                .unwrap_or_else(|| Err("no socket".into()))
                .map(|_| ()),
            CheckGateway::Ping => {
                let src = r.lease().map(|l| IpAddr::V4(l.address.addr()));
                let device = r.cfg.interface.to_string();
                ping_send(&mut r.gw, gw, src, device, prober)
            }
            CheckGateway::None => Ok(()),
        };
        match sent {
            Ok(()) => {
                if let Some(r) = self.dhcp.runners.get_mut(&id) {
                    r.gw.sent_at = Some(now);
                }
            }
            Err(e) => log::debug!("dhcp-client {id}: gateway check not sent: {e}"),
        }
    }

    pub(crate) fn dhcp_note_id(&mut self, id: ItemId, event: &'static str, message: String) {
        if let Some(iface) = self.dhcp.runners.get(&id).map(|r| r.cfg.interface.clone()) {
            self.dhcp_note(id, iface, event, message);
        }
    }

    /// Lease routes withheld because their gateway is down, with why (for
    /// `ip.route.list`, which shows them inactive).
    pub(crate) fn dhcp_withheld(&self, cfg: &Config) -> Vec<(RouteEntry, String)> {
        let mut out = Vec::new();
        for (id, r) in &self.dhcp.runners {
            let live = cfg
                .ip
                .dhcp_clients
                .iter()
                .any(|c| c.id == *id && !c.disabled && c.interface == r.cfg.interface);
            if !live || !r.gw.down {
                continue;
            }
            for route in r.routes.iter().filter(|rt| r.withholds(rt)) {
                let why = format!(
                    "gateway {} does not answer check-gateway={}",
                    r.gw.target.map(|g| g.to_string()).unwrap_or_default(),
                    r.cfg.check_gateway
                );
                out.push((route.clone(), why));
            }
        }
        out
    }
}

fn ping_send(
    gw: &mut GatewayCheck,
    target: Ipv4Addr,
    src: Option<IpAddr>,
    device: String,
    prober: Option<Result<corerouter_hal::probe::SharedProber, String>>,
) -> Result<(), String> {
    if gw.ping.is_none() {
        let prober = prober.ok_or("no prober")??;
        let options = SocketOptions {
            src,
            device: Some(device),
            ..SocketOptions::default()
        };
        gw.ping = Some(prober.open(&options).map_err(|e| e.to_string())?);
    }
    gw.seq = gw.seq.wrapping_add(1);
    let dst = IpAddr::V4(target);
    let probe = Probe {
        dst,
        seq: gw.seq,
        ttl: None,
        size: overhead(dst).saturating_add(28),
    };
    let sock = gw.ping.as_mut().ok_or("no ping socket")?;
    match sock.send(&probe) {
        Ok(()) => Ok(()),
        // "No route" is an answer: the check fails by timing out.
        Err(corerouter_hal::probe::ProbeError::Unreachable(_)) => Ok(()),
        Err(e) => {
            gw.ping = None;
            Err(e.to_string())
        }
    }
}

fn ping_answered(gw: &mut GatewayCheck, target: Ipv4Addr) -> bool {
    let Some(sock) = gw.ping.as_mut() else {
        return false;
    };
    for _ in 0..16 {
        match sock.recv(Duration::ZERO) {
            Ok(Some(r)) => {
                if r.seq == gw.seq && r.kind == ReplyKind::Echo && r.from == IpAddr::V4(target) {
                    return true;
                }
            }
            Ok(None) => return false,
            Err(_) => {
                gw.ping = None;
                return false;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips_and_refuses_junk() {
        let data = vec![0u8, 1, 0xab, 0xff];
        assert_eq!(from_hex(&to_hex(&data)), Some(data));
        assert_eq!(from_hex("abc"), None);
        assert_eq!(from_hex("zz"), None);
        assert_eq!(from_hex(&"00".repeat(MAX_MESSAGE + 1)), None);
    }
}
