//! The DHCPv6 server of one PPP subscriber session (G4.3e), the shape
//! accel-ppp (`ipv6_dhcp`) and RouterOS (the dynamic DHCPv6-PD server of a
//! `/ppp profile`) give it: the session already owns its prefixes (from the
//! pools or RADIUS `Delegated-IPv6-Prefix`, RFC 4818), so there is no lease
//! table to search, no affinity hash and no journal — the binding lives and
//! dies with the session. Pure like [`crate::server6`]: a message in, a
//! reply and an [`Event6`] out.
//!
//! RFC 9915 (ex-8415), by section:
//!
//! - §16: Solicit, Rebind, Confirm without a Client Identifier or with a
//!   Server Identifier are discarded; Request, Renew, Release, Decline
//!   without ours are discarded; an Information-request with an IA is
//!   discarded (§16.12).
//! - §18.3.1 Solicit → Advertise, or Reply at once with Rapid Commit when
//!   both sides want it (§21.14); §18.3.2 Request → Reply; §18.3.4 Renew and
//!   §18.3.5 Rebind extend the binding, and an address or prefix that is not
//!   the session's comes back with lifetimes 0; §18.3.7 Release and §18.3.8
//!   Decline answer Success; §18.3.3 Confirm answers Success only for
//!   addresses inside the session's /64 (NotOnLink otherwise; no addresses:
//!   no Reply); §18.3.6 Information-request answers the DNS options.
//! - §21.4 / §21.21: T1 = 0.5 and T2 = 0.8 of the preferred lifetime.
//! - An IA the session cannot fill carries NoAddrsAvail / NoPrefixAvail
//!   (§18.3.1 and §21.13).
//!
//! One session is one point-to-point link and one CPE: a new DUID (the CPE
//! rebooted with another one) takes the binding over instead of being
//! refused, as accel-ppp does.

use std::net::Ipv6Addr;

use ipnet::Ipv6Net;

use crate::v6::{self, ClientMsg, msg, opt, status};

/// What a session hands out over DHCPv6.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant6 {
    /// Our DUID (§11): the service passes a DUID-LL of the access port.
    pub server_duid: Vec<u8>,
    /// IA_NA: one address (usually the /64 of the session + the
    /// subscriber's IPv6CP identifier).
    pub address: Option<Ipv6Addr>,
    /// The /64 of the link (Confirm checks against it).
    pub link: Option<Ipv6Net>,
    /// IA_PD: the delegated prefix.
    pub prefix: Option<Ipv6Net>,
    pub dns: Vec<Ipv6Addr>,
    pub domains: Vec<String>,
    /// Valid lifetime, seconds (RouterOS `dhcpv6-lease-time`, default 1d);
    /// the preferred one is ⅔ of it, as in [`crate::server6`].
    pub lease_time: u32,
    /// Answer a Solicit with Rapid Commit at once (§18.3.1).
    pub rapid_commit: bool,
}

impl Grant6 {
    /// (T1, T2, preferred, valid) — §21.4/§21.21 recommended ratios.
    pub fn lifetimes(&self) -> (u32, u32, u32, u32) {
        let valid = self.lease_time.max(60);
        let preferred = valid / 3 * 2;
        (preferred / 2, preferred / 5 * 4, preferred, valid)
    }
}

/// A DUID-LL (§11.4) of `mac`: type 3, hardware type 1 (Ethernet).
pub fn duid_ll(mac: [u8; 6]) -> Vec<u8> {
    let mut d = vec![0, 3, 0, 1];
    d.extend_from_slice(&mac);
    d
}

/// What changed in the session's binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event6 {
    /// The client holds `kind` now (Reply to Request/Renew/Rebind, or
    /// Rapid Commit): the route to a delegated prefix goes in.
    Bound {
        kind: crate::server6::IaKind,
        net: Ipv6Net,
        duid: Vec<u8>,
    },
    /// Released by the client (§18.3.7): the route goes out.
    Released {
        kind: crate::server6::IaKind,
        net: Ipv6Net,
    },
    /// Declined (§18.3.8): the address is in use on the CPE's side.
    Declined { addr: Ipv6Addr },
}

/// Counters of one session (the PPP window shows them summed).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stats6 {
    pub received: u64,
    pub replied: u64,
    pub dropped: u64,
}

/// The per-session server.
#[derive(Debug, Clone)]
pub struct Sub6 {
    grant: Grant6,
    /// DUID of the client that holds the binding.
    client: Option<Vec<u8>>,
    pd_bound: bool,
    na_bound: bool,
    pub stats: Stats6,
}

/// The answer to one message.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Answer6 {
    pub reply: Option<Vec<u8>>,
    pub events: Vec<Event6>,
    /// Why nothing was sent (counted, for `ppp.why`).
    pub dropped: Option<&'static str>,
}

impl Sub6 {
    pub fn new(grant: Grant6) -> Self {
        Self {
            grant,
            client: None,
            pd_bound: false,
            na_bound: false,
            stats: Stats6::default(),
        }
    }

    pub fn grant(&self) -> &Grant6 {
        &self.grant
    }

    /// The client holding the binding, if any.
    pub fn client(&self) -> Option<&[u8]> {
        self.client.as_deref()
    }

    /// The delegated prefix, when a client holds it.
    pub fn bound_prefix(&self) -> Option<Ipv6Net> {
        self.grant.prefix.filter(|_| self.pd_bound)
    }

    pub fn bound_address(&self) -> Option<Ipv6Addr> {
        self.grant.address.filter(|_| self.na_bound)
    }

    /// New grant (a CoA, a profile change): bindings of what is no longer
    /// granted end, the rest stay.
    pub fn regrant(&mut self, grant: Grant6) -> Vec<Event6> {
        let mut ev = Vec::new();
        if self.pd_bound && grant.prefix != self.grant.prefix {
            if let Some(net) = self.grant.prefix {
                ev.push(Event6::Released {
                    kind: crate::server6::IaKind::Pd,
                    net,
                });
            }
            self.pd_bound = false;
        }
        if self.na_bound && grant.address != self.grant.address {
            if let Some(a) = self.grant.address {
                ev.push(Event6::Released {
                    kind: crate::server6::IaKind::Na,
                    net: Ipv6Net::from(a),
                });
            }
            self.na_bound = false;
        }
        self.grant = grant;
        ev
    }

    /// One message from the subscriber (the UDP payload).
    pub fn handle(&mut self, bytes: &[u8]) -> Answer6 {
        self.stats.received += 1;
        let a = self.answer(bytes);
        if a.reply.is_some() {
            self.stats.replied += 1;
        } else {
            self.stats.dropped += 1;
        }
        a
    }

    fn answer(&mut self, bytes: &[u8]) -> Answer6 {
        let drop = |why| Answer6 {
            dropped: Some(why),
            ..Answer6::default()
        };
        let Ok(m) = v6::decode_client(bytes) else {
            return drop("malformed DHCPv6 message");
        };
        let ours = m.server_id.as_deref() == Some(self.grant.server_duid.as_slice());
        match m.kind {
            msg::SOLICIT | msg::REBIND | msg::CONFIRM => {
                // §16.2, §16.5, §16.7.
                if m.client_id.is_none() || m.server_id.is_some() {
                    return drop("Solicit/Rebind/Confirm without Client-ID or with a Server-ID");
                }
            }
            msg::REQUEST | msg::RENEW | msg::RELEASE | msg::DECLINE => {
                // §16.4, §16.6, §16.9, §16.10.
                if m.client_id.is_none() || !ours {
                    return drop("not for this server");
                }
            }
            msg::INFORMATION_REQUEST => {
                // §16.12.
                if m.ia_na.is_some() || m.ia_pd.is_some() || (m.server_id.is_some() && !ours) {
                    return drop("Information-request with an IA or another Server-ID");
                }
            }
            _ => return drop("not a client message"),
        }
        match m.kind {
            msg::SOLICIT => {
                if self.grant.rapid_commit && m.rapid_commit {
                    self.bind(&m, msg::REPLY, true)
                } else {
                    self.bind(&m, msg::ADVERTISE, false)
                }
            }
            msg::REQUEST | msg::RENEW | msg::REBIND => self.bind(&m, msg::REPLY, false),
            msg::RELEASE => self.release(&m),
            msg::DECLINE => self.decline(&m),
            msg::CONFIRM => self.confirm(&m),
            _ => Answer6 {
                reply: Some(self.reply(&m, msg::REPLY, Vec::new()).bytes()),
                ..Answer6::default()
            },
        }
    }

    /// Reply skeleton: Server-ID, Client-ID, the requested DNS options.
    fn reply(&self, m: &ClientMsg, kind: u8, ias: Vec<(u16, Vec<u8>)>) -> v6::Builder {
        let mut b = v6::Builder::new(kind, m.xid)
            .opt(opt::SERVERID, &self.grant.server_duid)
            .opt(opt::CLIENTID, m.client_id.as_deref().unwrap_or(&[]));
        for (code, body) in ias {
            b = b.opt(code, &body);
        }
        let asked = |c| m.oro.contains(&c);
        if asked(opt::DNS_SERVERS) && !self.grant.dns.is_empty() {
            let d: Vec<u8> = self
                .grant
                .dns
                .iter()
                .take(8)
                .flat_map(|a| a.octets())
                .collect();
            b = b.opt(opt::DNS_SERVERS, &d);
        }
        if asked(opt::DOMAIN_LIST) && !self.grant.domains.is_empty() {
            let mut d = Vec::new();
            for n in self.grant.domains.iter().take(8) {
                v6::encode_name(n, &mut d);
            }
            b = b.opt(opt::DOMAIN_LIST, &d);
        }
        b
    }

    /// Advertise / Reply with the session's IAs. Entries the client sent
    /// that are not the session's go back with lifetimes 0 (§18.3.4,
    /// §18.3.5).
    fn bind(&mut self, m: &ClientMsg, kind: u8, rapid: bool) -> Answer6 {
        let commit = kind == msg::REPLY;
        let (t1, t2, pl, vl) = self.grant.lifetimes();
        let mut ias = Vec::new();
        let mut events = Vec::new();
        let duid = m.client_id.clone().unwrap_or_default();
        if let Some(ia) = &m.ia_na {
            let mut addrs = Vec::new();
            for a in &ia.addrs {
                if Some(a.addr) != self.grant.address {
                    addrs.push((a.addr, 0, 0));
                }
            }
            let body = match self.grant.address {
                Some(addr) => {
                    addrs.insert(0, (addr, pl, vl));
                    if commit {
                        self.na_bound = true;
                        events.push(Event6::Bound {
                            kind: crate::server6::IaKind::Na,
                            net: Ipv6Net::from(addr),
                            duid: duid.clone(),
                        });
                    }
                    v6::ia_na_body(ia.iaid, t1, t2, &addrs, None)
                }
                None => v6::ia_na_body(
                    ia.iaid,
                    0,
                    0,
                    &addrs,
                    Some((status::NO_ADDRS_AVAIL, "no address for this session")),
                ),
            };
            ias.push((opt::IA_NA, body));
        }
        if let Some(ia) = &m.ia_pd {
            let mut prefixes = Vec::new();
            for p in &ia.prefixes {
                // A hint (Solicit, Request) carries ::/len or a prefix with
                // lifetimes 0: only a held prefix that is not ours is zeroed.
                let hint = matches!(m.kind, msg::SOLICIT | msg::REQUEST);
                if Some(p.prefix) != self.grant.prefix && !hint {
                    prefixes.push((p.prefix, 0, 0));
                }
            }
            let body = match self.grant.prefix {
                Some(net) => {
                    prefixes.insert(0, (net, pl, vl));
                    if commit {
                        self.pd_bound = true;
                        events.push(Event6::Bound {
                            kind: crate::server6::IaKind::Pd,
                            net,
                            duid: duid.clone(),
                        });
                    }
                    v6::ia_pd_body(ia.iaid, t1, t2, &prefixes, None)
                }
                None => v6::ia_pd_body(
                    ia.iaid,
                    0,
                    0,
                    &prefixes,
                    Some((status::NO_PREFIX_AVAIL, "no prefix for this session")),
                ),
            };
            ias.push((opt::IA_PD, body));
        }
        if commit && !events.is_empty() {
            self.client = Some(duid);
        }
        let mut b = self.reply(m, kind, ias);
        if rapid {
            b = b.opt(opt::RAPID_COMMIT, &[]);
        }
        Answer6 {
            reply: Some(b.bytes()),
            events,
            dropped: None,
        }
    }

    fn holder(&self, m: &ClientMsg) -> bool {
        self.client.is_some() && self.client == m.client_id
    }

    fn release(&mut self, m: &ClientMsg) -> Answer6 {
        let mut events = Vec::new();
        if self.holder(m) {
            let pd = m.ia_pd.as_ref().is_some_and(|ia| {
                ia.prefixes
                    .iter()
                    .any(|p| Some(p.prefix) == self.grant.prefix)
            });
            if pd && self.pd_bound {
                self.pd_bound = false;
                if let Some(net) = self.grant.prefix {
                    events.push(Event6::Released {
                        kind: crate::server6::IaKind::Pd,
                        net,
                    });
                }
            }
            let na = m
                .ia_na
                .as_ref()
                .is_some_and(|ia| ia.addrs.iter().any(|a| Some(a.addr) == self.grant.address));
            if na && self.na_bound {
                self.na_bound = false;
                if let Some(a) = self.grant.address {
                    events.push(Event6::Released {
                        kind: crate::server6::IaKind::Na,
                        net: Ipv6Net::from(a),
                    });
                }
            }
        }
        // §18.3.7: Success at the top level whatever was found.
        let b = self
            .reply(m, msg::REPLY, Vec::new())
            .opt(opt::STATUS_CODE, &v6::status_body(status::SUCCESS, ""));
        Answer6 {
            reply: Some(b.bytes()),
            events,
            dropped: None,
        }
    }

    fn decline(&mut self, m: &ClientMsg) -> Answer6 {
        let mut events = Vec::new();
        if let (Some(ia), Some(addr)) = (&m.ia_na, self.grant.address)
            && self.holder(m)
            && ia.addrs.iter().any(|a| a.addr == addr)
        {
            self.na_bound = false;
            events.push(Event6::Declined { addr });
        }
        let b = self
            .reply(m, msg::REPLY, Vec::new())
            .opt(opt::STATUS_CODE, &v6::status_body(status::SUCCESS, ""));
        Answer6 {
            reply: Some(b.bytes()),
            events,
            dropped: None,
        }
    }

    fn confirm(&mut self, m: &ClientMsg) -> Answer6 {
        let addrs: Vec<Ipv6Addr> = m
            .ia_na
            .iter()
            .flat_map(|ia| ia.addrs.iter().map(|a| a.addr))
            .collect();
        // §18.3.3: no addresses → no Reply.
        if addrs.is_empty() {
            return Answer6 {
                dropped: Some("Confirm without addresses"),
                ..Answer6::default()
            };
        }
        let on_link = self
            .grant
            .link
            .is_some_and(|l| addrs.iter().all(|a| l.contains(a)));
        let code = if on_link {
            status::SUCCESS
        } else {
            status::NOT_ON_LINK
        };
        let b = self
            .reply(m, msg::REPLY, Vec::new())
            .opt(opt::STATUS_CODE, &v6::status_body(code, ""));
        Answer6 {
            reply: Some(b.bytes()),
            events: Vec::new(),
            dropped: None,
        }
    }
}

#[cfg(test)]
mod tests;
