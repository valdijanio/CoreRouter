//! Hot standby (G4.3h): an established session leaves one [`Server`] as a
//! [`SessionState`] and continues on another, on the other BNG of the
//! pair, without the subscriber noticing.
//!
//! What must survive is what the CPE checks: the SESSION_ID and the MAC
//! pair (RFC 2516 §4; the AC MAC is the pair's virtual MAC), both
//! Magic-Numbers (RFC 1661 §6.4: an Echo-Reply with another number is
//! dropped, and too many lost echoes end the link), the MRU (our frames
//! must fit, §6.1), and the NCP results (the address IPCP gave, the IPv6CP
//! interface identifiers, RFC 1332 / RFC 5072). The new server takes the
//! session in Opened state on LCP, IPCP and IPv6CP: no renegotiation, no
//! new authentication. Keepalive restarts from the takeover.

use std::net::Ipv4Addr;

use super::{Ipv6Mode, Server, ServerOutput, SessionRef, session};
use crate::eth::Vlans;
use crate::lcp::AuthProto;
use crate::timer::Millis;
use crate::wire::Mac;
use corerouter_proto_radius::rate_limit::RateLimit;

/// An established session, as the other node takes it over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionState {
    pub sid: u16,
    pub ifindex: u32,
    pub vlans: Vlans,
    pub client_mac: Mac,
    /// Our and the peer's Magic-Number (RFC 1661 §6.4).
    pub our_magic: u32,
    pub peer_magic: u32,
    /// The MRU we announced and the peer's (what our frames must fit).
    pub our_mru: u16,
    pub peer_mru: u16,
    pub auth: Option<AuthProto>,
    pub username: Box<[u8]>,
    pub service: Box<[u8]>,
    /// IPCP: the subscriber's address, ours, DNS and NBNS given.
    pub ipv4: Option<Ipv4Addr>,
    pub local_ipv4: Option<Ipv4Addr>,
    pub dns: [Option<Ipv4Addr>; 2],
    pub nbns: [Option<Ipv4Addr>; 2],
    /// IPv6CP: up, with our and the subscriber's interface identifiers.
    pub ipv6: Option<([u8; 8], [u8; 8])>,
    pub v6_mode: Ipv6Mode,
    pub rate_limit: Option<RateLimit>,
    pub session_timeout: Option<u32>,
    /// Milliseconds left of the Session-Timeout, when one runs.
    pub timeout_left_ms: Option<u64>,
    pub circuit_id: Option<Box<[u8]>>,
    pub remote_id: Option<Box<[u8]>>,
}

/// Why a session could not be taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportError {
    /// The SESSION_ID is not this server's (another lane, out of range).
    NotOurs,
    /// A session already holds the SESSION_ID.
    Busy,
}

impl Server {
    /// The state of established session `sid`, for the standby (`None`:
    /// no such session, or not up yet: a session still negotiating is not
    /// worth moving, the CPE retries on the new active).
    pub fn export(&self, now: Millis, sid: u16) -> Option<SessionState> {
        self.slot(sid)?.export(now)
    }

    /// Every established session, in SID order.
    pub fn export_all(&self, now: Millis) -> Vec<SessionState> {
        self.sessions
            .iter()
            .flatten()
            .filter_map(|s| s.export(now))
            .collect()
    }

    /// Takes over `states` (sessions another node established). Each comes
    /// up in Opened state with its keepalive from `now`; no frame is sent
    /// (the CPE must not notice). The free SESSION_IDs are rebuilt once
    /// for the whole batch: importing 65 534 sessions costs O(n), not
    /// O(n²).
    pub fn import(
        &mut self,
        now: Millis,
        states: &[SessionState],
        out: &mut ServerOutput,
    ) -> Vec<Result<SessionRef, ImportError>> {
        let lanes = self.cfg.sid_lane.1.max(1);
        let lane = self.cfg.sid_lane.0 % lanes;
        let mut taken = Vec::with_capacity(states.len());
        let mut results = Vec::with_capacity(states.len());
        for st in states {
            let ours = st.sid != 0 && st.sid <= self.cfg.max_sessions && st.sid % lanes == lane;
            if !ours {
                results.push(Err(ImportError::NotOurs));
                continue;
            }
            if self.slot(st.sid).is_some() {
                results.push(Err(ImportError::Busy));
                continue;
            }
            self.generation = self.generation.wrapping_add(1);
            let (svc, _) = self.cfg.services.lookup(&st.service);
            let s =
                session::Session::import(&self.cfg, &mut self.rng, st, self.generation, svc, now);
            let r = s.reference();
            let host = s.host_key();
            if let Some(slot) = self.sessions.get_mut(usize::from(st.sid)) {
                *slot = Some(Box::new(s));
            }
            self.active += 1;
            self.svc.add(svc);
            self.by_host.insert(host, st.sid);
            taken.push(st.sid);
            results.push(Ok(r));
        }
        if !taken.is_empty() {
            let used: std::collections::HashSet<u16> = taken.iter().copied().collect();
            self.free.retain(|sid| !used.contains(sid));
            for sid in taken {
                // Schedules the keepalive (and the Session-Timeout).
                self.with_session(now, sid, None, out, |_, _| {});
            }
        }
        results
    }
}
