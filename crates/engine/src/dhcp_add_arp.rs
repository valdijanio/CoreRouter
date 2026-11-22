//! DHCP server `add-arp` (G1.27d, RouterOS `/ip dhcp-server add-arp`):
//! each lease bound by a server with `add_arp` becomes a static ARP
//! entry on the server's interface, and goes with the lease. With the
//! interface's `arp=reply-only`, the router reaches only hosts that took
//! a lease: an address typed by hand gets no answer (anti-spoofing, as
//! Cisco's Dynamic ARP Inspection does with DHCP snooping).
//!
//! The entries are not config: one per lease, O(1) to the data plane
//! (`Hal::neighbor_static`), never a whole apply per lease. `ip.arp.list`
//! shows them with source `dhcp` (RouterOS flag H).

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use corerouter_hal::neigh::StaticNeigh;
use corerouter_model::IfName;
use corerouter_proto_dhcp::server::Binding;

use crate::Session;

/// One entry the server put in: where, which MAC, which server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArpLease {
    pub interface: IfName,
    pub mac: [u8; 6],
    pub server: String,
}

/// The `add-arp` entries in the data plane now, by address.
#[derive(Debug, Default)]
pub struct AddArp {
    pub entries: BTreeMap<Ipv4Addr, ArpLease>,
    /// The config revision last checked (servers that turned it off).
    rev: u32,
}

impl Session {
    /// `ip.arp.list`: the `add-arp` entry of `ip` on `interface`, if one.
    pub(crate) fn dhcp_arp_of(&self, interface: &IfName, ip: Ipv4Addr) -> bool {
        self.ext::<AddArp>()
            .and_then(|a| a.entries.get(&ip))
            .is_some_and(|e| e.interface == *interface)
    }

    fn add_arp_apply(&mut self, ops: &[StaticNeigh]) {
        if ops.is_empty() {
            return;
        }
        if let Err(e) = self.hal_mut().neighbor_static(ops) {
            self.log_event(
                &["dhcp", "arp", "warning"],
                "dhcp-server",
                format!("add-arp: {e}"),
                serde_json::json!({}),
            );
        }
    }

    /// A lease bound: its entry, when its server says `add_arp` (a renewal
    /// with the same MAC changes nothing).
    pub(crate) fn dhcp_add_arp_bound(&mut self, b: &Binding) {
        let l = &b.lease;
        let server = self
            .store()
            .running()
            .ip
            .dhcp_server
            .servers
            .iter()
            .find(|s| s.name == l.server && s.add_arp && !s.disabled)
            .map(|s| s.interface.clone());
        let Some(interface) = server else {
            return;
        };
        let want = ArpLease {
            interface: interface.clone(),
            mac: l.mac,
            server: l.server.clone(),
        };
        let Some(a) = self.ext_mut::<AddArp>() else {
            return;
        };
        if a.entries.get(&l.address) == Some(&want) {
            return;
        }
        let mut ops = Vec::new();
        if let Some(old) = a.entries.insert(l.address, want)
            && old.interface != interface
        {
            ops.push(StaticNeigh {
                interface: old.interface,
                address: l.address,
                mac: None,
            });
        }
        ops.push(StaticNeigh {
            interface,
            address: l.address,
            mac: Some(l.mac),
        });
        self.add_arp_apply(&ops);
    }

    /// A lease ended (expired, released, removed): its entry goes.
    pub(crate) fn dhcp_add_arp_gone(&mut self, ip: Ipv4Addr) {
        let Some(old) = self.ext_mut::<AddArp>().and_then(|a| a.entries.remove(&ip)) else {
            return;
        };
        self.add_arp_apply(&[StaticNeigh {
            interface: old.interface,
            address: ip,
            mac: None,
        }]);
    }

    /// After a commit: the entries of servers that no longer say
    /// `add_arp` (or are gone) go. O(entries), once per revision.
    pub(crate) fn dhcp_add_arp_sync(&mut self) {
        let rev = self.store().current_revision();
        let Some(a) = self.ext::<AddArp>() else {
            return;
        };
        if a.rev == rev || a.entries.is_empty() {
            if let Some(a) = self.ext_mut::<AddArp>() {
                a.rev = rev;
            }
            return;
        }
        let keep: Vec<(String, IfName)> = self
            .store()
            .running()
            .ip
            .dhcp_server
            .servers
            .iter()
            .filter(|s| s.add_arp && !s.disabled)
            .map(|s| (s.name.clone(), s.interface.clone()))
            .collect();
        let mut ops = Vec::new();
        if let Some(a) = self.ext_mut::<AddArp>() {
            a.rev = rev;
            a.entries.retain(|ip, e| {
                let live = keep.iter().any(|(n, i)| *n == e.server && *i == e.interface);
                if !live {
                    ops.push(StaticNeigh {
                        interface: e.interface.clone(),
                        address: *ip,
                        mac: None,
                    });
                }
                live
            });
        }
        self.add_arp_apply(&ops);
    }
}
