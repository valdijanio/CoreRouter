//! The virtual lab's DHCPv6 server (G4.7b): one simulated server behind
//! every lab port, deterministic (no network, no clock), so the lab, the
//! GUI screenshots and the CI see the same bindings.
//!
//! Behind port `<name>N` (see [`corerouter_hal::dhcp::lab_net`]):
//!
//! | What | Value |
//! |---|---|
//! | server DUID | DUID-LL of `02:DC:00:00:00:N`, from `fe80::dc:ff:fe00:N` |
//! | address (IA_NA) | `2001:db8:0:N::H` (/128), H = 0x100 + hash of the client MAC |
//! | delegated prefix (IA_PD) | `2001:db8:N:100::/56`, or the hinted length 56..=64 |
//! | lifetimes | preferred 1800 s, valid 3600 s, T1 900 s, T2 1440 s |
//! | DNS, domain | `2001:db8:0:N::1`, `lab.test` |
//!
//! It honours Rapid Commit. The Router Advertisements of the same lab
//! router (prefix `2001:db8:0:N::/64`, default route) are the `VirtualHal`'s.
//! Tests turn [`Knobs`] to play a silent server, one without prefixes, one
//! that forgot our binding, or a preferred one.

use std::net::Ipv6Addr;
use std::sync::{Mutex, PoisonError};

use corerouter_hal::dhcp::{
    Datagram6, Dhcp6Responder, lab_hash, lab_net, lab_router_mac, link_local,
};
use corerouter_model::IfName;
use ipnet::Ipv6Net;

use crate::v6::{self, Builder, msg, opt, status};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Knobs {
    pub preferred: u32,
    pub valid: u32,
    pub t1: u32,
    pub t2: u32,
    pub silent: bool,
    /// Answers IA_PD with NoPrefixAvail.
    pub no_prefix: bool,
    /// Answers IA_NA with NoAddrsAvail.
    pub no_address: bool,
    /// Answers Renew/Rebind with NoBinding (a server that restarted).
    pub no_binding: bool,
    /// Commits at once to a Solicit with Rapid Commit.
    pub rapid_commit: bool,
    /// Preference option (none when 0).
    pub preference: u8,
    /// Calls itself with this MAC (a different server).
    pub mac: Option<[u8; 6]>,
    /// Delegates this prefix instead.
    pub prefix: Option<Ipv6Net>,
}

impl Default for Knobs {
    fn default() -> Self {
        Self {
            preferred: 1_800,
            valid: 3_600,
            t1: 900,
            t2: 1_440,
            silent: false,
            no_prefix: false,
            no_address: false,
            no_binding: false,
            rapid_commit: true,
            preference: 0,
            mac: None,
            prefix: None,
        }
    }
}

#[derive(Debug, Default)]
pub struct LabServer6 {
    knobs: Mutex<Knobs>,
}

impl LabServer6 {
    pub fn new(knobs: Knobs) -> Self {
        Self {
            knobs: Mutex::new(knobs),
        }
    }

    pub fn knobs(&self) -> Knobs {
        self.knobs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub fn set(&self, f: impl FnOnce(&mut Knobs)) {
        f(&mut self.knobs.lock().unwrap_or_else(PoisonError::into_inner));
    }

    /// The address the lab gives `mac` behind `port`.
    pub fn address_for(port: &IfName, mac: [u8; 6]) -> Ipv6Addr {
        let h = 0x100 + lab_hash(&mac) % 0xeff;
        Ipv6Addr::new(
            0x2001,
            0xdb8,
            0,
            u16::from(lab_net(port)),
            0,
            0,
            0,
            u16::try_from(h).unwrap_or(0x100),
        )
    }

    /// The prefix the lab delegates behind `port` with a hint of `len`.
    pub fn prefix_for(port: &IfName, len: Option<u8>) -> Option<Ipv6Net> {
        let len = len.filter(|l| (56..=64).contains(l)).unwrap_or(56);
        Ipv6Net::new(
            Ipv6Addr::new(0x2001, 0xdb8, u16::from(lab_net(port)), 0x100, 0, 0, 0, 0),
            len,
        )
        .ok()
    }

    /// DUID of the server behind `port`.
    pub fn duid_of(port: &IfName) -> Vec<u8> {
        v6::duid_ll(lab_router_mac(lab_net(port)))
    }
}

impl Dhcp6Responder for LabServer6 {
    fn answer(&self, port: &IfName, mac: [u8; 6], payload: &[u8]) -> Vec<Datagram6> {
        let k = self.knobs();
        if k.silent {
            return Vec::new();
        }
        let Ok(req) = v6::decode_client(payload) else {
            return Vec::new();
        };
        let Some(client) = req.client_id.clone() else {
            return Vec::new();
        };
        let n = lab_net(port);
        let me_mac = k.mac.unwrap_or_else(|| lab_router_mac(n));
        let me = v6::duid_ll(me_mac);
        let to_me = req.server_id.as_ref().is_none_or(|s| *s == me);
        let kind = match req.kind {
            msg::SOLICIT if req.rapid_commit && k.rapid_commit => msg::REPLY,
            msg::SOLICIT => msg::ADVERTISE,
            msg::REQUEST | msg::RENEW | msg::RELEASE if to_me => msg::REPLY,
            msg::REBIND => msg::REPLY,
            _ => return Vec::new(),
        };
        let mut b = Builder::new(kind, req.xid)
            .opt(opt::SERVERID, &me)
            .opt(opt::CLIENTID, &client);
        if kind == msg::REPLY && req.kind == msg::SOLICIT {
            b = b.opt(opt::RAPID_COMMIT, &[]);
        }
        if k.preference > 0 && kind == msg::ADVERTISE {
            b = b.opt(opt::PREFERENCE, &[k.preference]);
        }
        if req.kind == msg::RELEASE {
            b = b.opt(
                opt::STATUS_CODE,
                &v6::status_body(status::SUCCESS, "released"),
            );
        } else {
            let lost = k.no_binding && matches!(req.kind, msg::RENEW | msg::REBIND);
            if let Some(ia) = &req.ia_na {
                let body = if lost {
                    v6::ia_na_body(
                        ia.iaid,
                        0,
                        0,
                        &[],
                        Some((status::NO_BINDING, "lab: who are you?")),
                    )
                } else if k.no_address {
                    v6::ia_na_body(
                        ia.iaid,
                        0,
                        0,
                        &[],
                        Some((status::NO_ADDRS_AVAIL, "lab: no addresses")),
                    )
                } else {
                    let a = Self::address_for(port, mac);
                    v6::ia_na_body(ia.iaid, k.t1, k.t2, &[(a, k.preferred, k.valid)], None)
                };
                b = b.opt(opt::IA_NA, &body);
            }
            if let Some(ia) = &req.ia_pd {
                let hint = ia.prefixes.first().map(|p| p.prefix.prefix_len());
                let body = match k.prefix.or_else(|| Self::prefix_for(port, hint)) {
                    _ if lost => v6::ia_pd_body(
                        ia.iaid,
                        0,
                        0,
                        &[],
                        Some((status::NO_BINDING, "lab: who are you?")),
                    ),
                    Some(p) if !k.no_prefix => {
                        v6::ia_pd_body(ia.iaid, k.t1, k.t2, &[(p, k.preferred, k.valid)], None)
                    }
                    _ => v6::ia_pd_body(
                        ia.iaid,
                        0,
                        0,
                        &[],
                        Some((status::NO_PREFIX_AVAIL, "lab: no prefixes")),
                    ),
                };
                b = b.opt(opt::IA_PD, &body);
            }
            let dns = Ipv6Addr::new(0x2001, 0xdb8, 0, u16::from(n), 0, 0, 0, 1);
            b = b.opt(opt::DNS_SERVERS, &dns.octets());
            let mut domain = Vec::new();
            v6::encode_name("lab.test", &mut domain);
            b = b.opt(opt::DOMAIN_LIST, &domain);
        }
        vec![Datagram6 {
            payload: b.bytes(),
            src: link_local(me_mac),
            src_mac: Some(me_mac),
        }]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_numbers_pick_the_prefixes() {
        let e1: IfName = "ether1".parse().unwrap();
        assert_eq!(
            LabServer6::prefix_for(&e1, None).unwrap().to_string(),
            "2001:db8:1:100::/56"
        );
        assert_eq!(
            LabServer6::prefix_for(&e1, Some(60)).unwrap().to_string(),
            "2001:db8:1:100::/60"
        );
        assert_eq!(
            LabServer6::prefix_for(&e1, Some(48)).unwrap().prefix_len(),
            56,
            "hints out of 56..=64 get the default"
        );
        let a = LabServer6::address_for(&e1, [2, 0, 0, 0, 0, 1]);
        assert_eq!(a.segments()[..4], [0x2001, 0xdb8, 0, 1]);
        assert_eq!(
            link_local(lab_router_mac(1)).to_string(),
            "fe80::dc:ff:fe00:1"
        );
    }
}
