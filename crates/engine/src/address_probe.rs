//! "Is this address already in use on the wire?" before it is added
//! (G1.28): an ARP probe (RFC 5227 §2.1.1: who-has the address, sender IP
//! 0.0.0.0, so nobody's ARP cache learns it) on the interface, then a short
//! wait for an answer. `ip.address.check` starts it and reads it on
//! later calls, so the GUI never waits: it shows "checking…" and asks
//! again.
//!
//! Not the full RFC 5227 claim (PROBE_NUM = 3 probes 1–2 s apart, then
//! announcements): this is a diagnostic before the operator commits, so
//! one probe and one short wait, [`WAIT_SECS`]. The socket is the DHCP
//! client's (`Hal::dhcp_port`): a raw `AF_PACKET` socket on Linux, the lab
//! router answering for itself in the virtual lab.

use std::net::Ipv4Addr;

use corerouter_hal::DhcpPort;
use corerouter_model::IfName;

use crate::Session;

/// How long a probe waits for an answer, in clock ticks of one second:
/// the answer is read between 1 and 2 s after the probe went out.
pub(crate) const WAIT_SECS: u64 = 2;
/// How long an answer stays good for the next previews.
const KEEP_SECS: u64 = 30;
/// Probes at once (a sweep of random previews cannot open sockets without
/// end).
const MAX_PROBES: usize = 8;

/// What a probe found so far.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Found {
    /// Still waiting.
    Running,
    /// Nobody answered within the wait.
    Free,
    /// A host with this MAC answered: it already uses the address.
    Taken([u8; 6]),
    /// The probe could not be sent (no raw socket, no such port).
    Failed(String),
}

struct Probe {
    interface: IfName,
    ip: Ipv4Addr,
    started: u64,
    port: Option<Box<dyn DhcpPort>>,
    found: Found,
}

/// The probes of this session (`Session::ext`): runtime state only.
#[derive(Default)]
pub(crate) struct Probes(Vec<Probe>);

/// `aa:bb:cc:dd:ee:ff`.
pub(crate) fn mac_text(mac: [u8; 6]) -> String {
    mac.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

impl Session {
    fn probe_clock(&self) -> Option<u64> {
        self.hal().monotonic_secs().or_else(|| self.now())
    }

    /// The ARP check of `ip` on `interface`: started on the first call,
    /// read on the next ones.
    pub(crate) fn arp_check(&mut self, interface: &IfName, ip: Ipv4Addr) -> Found {
        let Some(now) = self.probe_clock() else {
            return Found::Failed("this platform has no clock to time the probe".into());
        };
        let fresh = {
            let Some(probes) = self.ext_mut::<Probes>() else {
                return Found::Failed("no room for the probe".into());
            };
            probes.0.retain(|p| {
                now.saturating_sub(p.started) <= KEEP_SECS || p.found == Found::Running
            });
            !probes
                .0
                .iter()
                .any(|p| p.interface == *interface && p.ip == ip)
        };
        if fresh {
            let started = self.start_probe(interface, ip);
            let Some(probes) = self.ext_mut::<Probes>() else {
                return Found::Failed("no room for the probe".into());
            };
            if probes.0.len() >= MAX_PROBES {
                probes.0.remove(0);
            }
            let (port, found) = match started {
                Ok(port) => (Some(port), Found::Running),
                Err(e) => (None, Found::Failed(e)),
            };
            probes.0.push(Probe {
                interface: interface.clone(),
                ip,
                started: now,
                port,
                found,
            });
        }
        let Some(p) = self
            .ext_mut::<Probes>()
            .and_then(|ps| ps.0.iter_mut().find(|p| p.interface == *interface && p.ip == ip))
        else {
            return Found::Failed("the probe went away".into());
        };
        if p.found == Found::Running {
            let answer = p.port.as_mut().map(|port| port.conflict());
            p.found = match answer {
                Some(Ok(Some(mac))) => Found::Taken(mac),
                Some(Err(e)) => Found::Failed(e.to_string()),
                _ if now.saturating_sub(p.started) >= WAIT_SECS => Found::Free,
                _ => Found::Running,
            };
            if p.found != Found::Running {
                if let Some(mut port) = p.port.take() {
                    port.end_probe();
                }
                // The answer is kept from now on.
                p.started = now;
            }
        }
        p.found.clone()
    }

    fn start_probe(&mut self, interface: &IfName, ip: Ipv4Addr) -> Result<Box<dyn DhcpPort>, String> {
        let mut port = self
            .hal_mut()
            .dhcp_port(interface)
            .map_err(|e| e.to_string())?;
        match port.probe(ip) {
            Ok(true) => Ok(port),
            Ok(false) => Err("this platform cannot send ARP probes".into()),
            Err(e) => Err(e.to_string()),
        }
    }
}
