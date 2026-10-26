//! One subscriber session on the access concentrator: the PPP phases of
//! RFC 1661 §3.2 (Establish → Authenticate → Network → Terminate) over the
//! PPPoE link, with the caller answering authentication and addressing.

use super::services::ServiceSlot;
use super::{
    AuthMethod, AuthRequest, AuthVerdict, DownReason, Env, Event, HostKey, Ipv4Assignment,
    Ipv6Mode, ServerConfig, SessionKey, SessionRef,
};
use crate::auth::{self, AUTH_STRING_LEN, ChapValue, MsChapResponse, PapRequest, code as ac};
use crate::descriptor::{SessionDescriptor, vlan_field};
use crate::discovery::{Code, DEFAULT_MRU, DiscoveryWriter};
use crate::eth::Vlans;
use crate::fsm::{Ctx, Fsm, Signals, Tx};
use crate::guard::Rng;
use crate::layers::{Ipcp, Ipv6cp, Lcp, Role};
use crate::lcp::{self, AuthProto, code as lc};
use crate::ncp::NCP_MAX_CODE;
use crate::nd::{IidRole, stable_iid};
use crate::output::Output;
use crate::ppp::{self, Link, SessionWriter, proto};
use crate::timer::Millis;
use crate::wire::Mac;
use corerouter_proto_radius::rate_limit::RateLimit;
use std::net::Ipv4Addr;

/// Longest IPCP request held while the address is being fetched.
const STASH_MAX: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Establish,
    Authenticate,
    Network,
    Terminate,
}

#[derive(Debug, Clone, Default)]
struct AuthState {
    proto: Option<AuthProto>,
    id: u8,
    challenge: [u8; 16],
    /// Challenge retransmissions left (RFC 1994 §4.1).
    retries: u8,
    /// Waiting for the caller's verdict.
    pending: bool,
    done: bool,
    /// MS-CHAPv2 authenticator string, kept to answer a retransmitted
    /// Response after Success.
    success: Option<[u8; AUTH_STRING_LEN]>,
    /// Verdicts to ignore: they answer an attempt LCP renegotiation ended.
    discard: u8,
}

/// What the server knows when it creates a session (after a valid PADR).
pub(crate) struct Init {
    pub gen_: u32,
    pub sid: u16,
    pub ifindex: u32,
    pub vlans: Vlans,
    pub client_mac: Mac,
    pub uniq: u64,
    /// RFC 4638: agreed PPP-Max-Payload, raising the MRU limits.
    pub mru_cap: Option<u16>,
    pub service: Box<[u8]>,
    /// The row of the Service-Name table it landed on (G4.3k).
    pub svc: ServiceSlot,
    pub circuit_id: Option<Box<[u8]>>,
    pub remote_id: Option<Box<[u8]>>,
}

pub(crate) struct Session {
    pub gen_: u32,
    pub sid: u16,
    pub ifindex: u32,
    pub vlans: Vlans,
    pub client_mac: Mac,
    pub uniq: u64,
    /// The PADR's Service-Name and its row (G4.3k).
    pub service: Box<[u8]>,
    pub svc: ServiceSlot,
    link: Link,
    phase: Phase,
    lcp: Fsm,
    lcp_l: Lcp,
    ipcp: Fsm,
    ipcp_l: Ipcp,
    v6: Fsm,
    v6_l: Ipv6cp,
    auth: AuthState,
    /// The peer sent something on LCP (it left Discovery).
    heard: bool,
    echo_at: Millis,
    echo_misses: u8,
    echo_id: u8,
    auth_deadline: Millis,
    setup_deadline: Millis,
    session_deadline: Millis,
    /// Deadline of the live wheel entry (0 = none).
    scheduled: Millis,
    username: Box<[u8]>,
    rate_limit: Option<RateLimit>,
    session_timeout: Option<u32>,
    address_asked: bool,
    ipcp_stash: Option<Box<[u8]>>,
    pub up: bool,
    v4_up: bool,
    v6_up: bool,
    /// IPv6CP for this session (the profile's `use-ipv6`, set before the
    /// Network phase).
    pub v6_mode: Ipv6Mode,
    close_reason: Option<DownReason>,
    pub dead: Option<DownReason>,
    circuit_id: Option<Box<[u8]>>,
    remote_id: Option<Box<[u8]>>,
}

/// Sends control packets on the session's link.
struct SessTx<'a> {
    out: &'a mut Output<Event>,
    link: Link,
    sid: u16,
    ifindex: u32,
    max_info: usize,
}

impl Tx for SessTx<'_> {
    fn send(&mut self, protocol: u16, code: u8, id: u8, body: &[u8]) {
        let start = self.out.buf.len();
        let mut w =
            SessionWriter::control(&mut self.out.buf, &self.link, self.sid, protocol, code, id);
        w.buf().extend_from_slice(body);
        if w.finish(self.max_info).is_ok() {
            self.out.push_frame(self.ifindex, start);
        }
    }
}

/// Runs one automaton event with a fresh context.
macro_rules! fsm {
    ($s:ident, $env:ident, $fsm:ident, $layer:ident, |$f:ident, $c:ident, $l:ident| $body:expr) => {{
        let mut tx = $s.tx(&mut *$env.out);
        let mut $c = Ctx {
            now: $env.now,
            cfg: &$env.cfg.fsm,
            tx: &mut tx,
            scratch: &mut *$env.scratch,
        };
        let $f = &mut $s.$fsm;
        let $l = &mut $s.$layer;
        $body
    }};
}

impl Session {
    pub fn new(cfg: &ServerConfig, rng: &mut Rng, i: Init, now: Millis) -> Session {
        let (our_mru, max_mtu) = match i.mru_cap {
            Some(cap) => (cap, cap),
            None => (cfg.max_mru.min(DEFAULT_MRU), cfg.max_mtu.min(DEFAULT_MRU)),
        };
        let magic = rng.nonzero_u32();
        let mut iid = rng.array::<8>();
        if iid == [0; 8] {
            iid[7] = 1;
        }
        let mut suggest = None;
        if let Some(key) = &cfg.ipv6_iid_key {
            iid = stable_iid(key, i.ifindex, i.vlans, i.client_mac, IidRole::Local);
            suggest = Some(stable_iid(
                key,
                i.ifindex,
                i.vlans,
                i.client_mac,
                IidRole::Peer,
            ));
        }
        let mut v6_l = Ipv6cp::new(iid, rng.nonzero_u32());
        v6_l.suggest = suggest;
        let link = Link {
            dst: i.client_mac,
            src: cfg.ac_mac,
            vlans: i.vlans,
        };
        Session {
            gen_: i.gen_,
            sid: i.sid,
            ifindex: i.ifindex,
            vlans: i.vlans,
            client_mac: i.client_mac,
            uniq: i.uniq,
            service: i.service,
            svc: i.svc,
            link,
            phase: Phase::Establish,
            lcp: Fsm::new(rng.u32() as u8),
            lcp_l: Lcp::new(Role::Server, our_mru, max_mtu, cfg.auth, magic),
            ipcp: Fsm::new(1),
            ipcp_l: Ipcp::server(cfg.local_ipv4),
            v6: Fsm::new(1),
            v6_l,
            auth: AuthState::default(),
            heard: false,
            echo_at: 0,
            echo_misses: 0,
            echo_id: 0,
            auth_deadline: 0,
            setup_deadline: now + cfg.setup_timeout_ms,
            session_deadline: 0,
            scheduled: 0,
            username: Box::default(),
            rate_limit: None,
            session_timeout: None,
            address_asked: false,
            ipcp_stash: None,
            up: false,
            v4_up: false,
            v6_up: false,
            v6_mode: if cfg.ipv6 {
                Ipv6Mode::On
            } else {
                Ipv6Mode::Off
            },
            close_reason: None,
            dead: None,
            circuit_id: i.circuit_id,
            remote_id: i.remote_id,
        }
    }

    fn v6_on(&self) -> bool {
        self.v6_mode != Ipv6Mode::Off
    }

    pub fn reference(&self) -> SessionRef {
        SessionRef {
            sid: self.sid,
            gen_: self.gen_,
        }
    }

    pub fn host_key(&self) -> HostKey {
        HostKey {
            ifindex: self.ifindex,
            vlans: self.vlans,
            mac: self.client_mac,
        }
    }

    pub fn key(&self) -> SessionKey {
        SessionKey {
            ifindex: self.ifindex,
            vlan: vlan_field(self.vlans.outer),
            inner_vlan: vlan_field(self.vlans.inner),
            sid: self.sid,
            client_mac: self.client_mac,
        }
    }

    pub fn assigned_ipv4(&self) -> Option<Ipv4Addr> {
        self.ipcp_l.peer
    }

    /// PADS sent, nothing heard from the peer on LCP yet.
    pub fn in_discovery(&self) -> bool {
        !self.heard
    }

    fn tx<'a>(&self, out: &'a mut Output<Event>) -> SessTx<'a> {
        SessTx {
            out,
            link: self.link,
            sid: self.sid,
            ifindex: self.ifindex,
            max_info: usize::from(self.lcp_l.peer_mru.max(DEFAULT_MRU)),
        }
    }

    fn send(&self, env: &mut Env<'_>, protocol: u16, code: u8, id: u8, body: &[u8]) {
        self.tx(&mut *env.out).send(protocol, code, id, body);
    }

    /// Earliest of the session's own deadlines.
    pub fn next_deadline(&self, cfg: &ServerConfig) -> Option<Millis> {
        let _ = cfg;
        [
            self.lcp.deadline().unwrap_or(0),
            self.ipcp.deadline().unwrap_or(0),
            self.v6.deadline().unwrap_or(0),
            self.auth_deadline,
            self.echo_at,
            if self.up { 0 } else { self.setup_deadline },
            self.session_deadline,
        ]
        .into_iter()
        .filter(|d| *d != 0)
        .min()
    }

    /// Records `d` as the live wheel entry when it is earlier than the one
    /// already scheduled.
    pub fn want_schedule(&mut self, d: Millis, _now: Millis) -> bool {
        if self.scheduled == 0 || d < self.scheduled {
            self.scheduled = d;
            true
        } else {
            false
        }
    }

    /// A wheel entry for `deadline` is the live one.
    pub fn fire(&self, deadline: Millis) -> bool {
        self.scheduled == deadline
    }

    pub fn descriptor(&self, cfg: &ServerConfig) -> SessionDescriptor {
        SessionDescriptor {
            ifindex: self.ifindex,
            sid: self.sid,
            vlan: vlan_field(self.vlans.outer),
            inner_vlan: vlan_field(self.vlans.inner),
            outer_tpid: if self.vlans.inner != 0 {
                self.vlans.outer_tpid
            } else {
                0
            },
            mtu: self.lcp_l.peer_mru,
            client_mac: self.client_mac,
            server_mac: cfg.ac_mac,
            ipv4: if self.v4_up { self.ipcp_l.peer } else { None },
            ipv6_iid: if self.v6_up { self.v6_l.peer_iid } else { None },
            local_iid: self.v6_up.then_some(self.v6_l.local_iid),
            rate_limit: self.rate_limit,
            username: self.username.clone(),
            auth: self.auth.proto,
            circuit_id: self.circuit_id.clone(),
            remote_id: self.remote_id.clone(),
            session_timeout: self.session_timeout,
        }
    }

    /// Right after the PADS: LCP Up + Open (the AC speaks first).
    pub fn start(&mut self, env: &mut Env<'_>) {
        let s = fsm!(self, env, lcp, lcp_l, |f, c, l| {
            f.open(&mut c, l);
            f.up(&mut c, l)
        });
        self.lcp_signals(env, s);
    }

    /// RFC 2516 §5.5: PADT ends the session; nothing is sent after it.
    fn padt(&mut self, env: &mut Env<'_>, reason: DownReason) {
        if self.dead.is_some() {
            return;
        }
        let start = env.out.buf.len();
        let w = DiscoveryWriter::begin(
            &mut env.out.buf,
            self.client_mac,
            env.cfg.ac_mac,
            self.vlans,
            Code::Padt,
            self.sid,
        );
        if w.finish().is_ok() {
            env.out.push_frame(self.ifindex, start);
            env.stats.padt_tx += 1;
        }
        self.dead = Some(reason);
    }

    /// Orderly close: LCP Terminate (RFC 1661 §3.7), PADT when it finishes.
    pub fn close(&mut self, env: &mut Env<'_>, reason: DownReason) {
        if self.dead.is_some() {
            return;
        }
        self.close_reason.get_or_insert(reason);
        if !self.lcp.is_opened() && !self.heard {
            // Nothing negotiated yet: just end it.
            self.padt(env, reason);
            return;
        }
        self.phase = Phase::Terminate;
        let s = fsm!(self, env, lcp, lcp_l, |f, c, _l| f.close::<Lcp>(&mut c));
        self.lcp_signals(env, s);
    }

    /// one-session-per-host: the host started over; its old session is
    /// dead on its side, so no LCP Terminate, just PADT.
    pub fn replace(&mut self, env: &mut Env<'_>) {
        self.padt(env, DownReason::Replaced);
    }

    fn lcp_signals(&mut self, env: &mut Env<'_>, s: Signals) {
        if s.tld {
            // RFC 1661 §3.2: leaving Opened takes the NCPs down.
            self.ipcp.down();
            self.v6.down();
            self.v4_up = false;
            self.v6_up = false;
            self.echo_at = 0;
            if self.phase != Phase::Terminate {
                self.phase = Phase::Establish;
            }
            // RFC 1661 §3.5: a renegotiated link authenticates again. An
            // answer still on its way for the old attempt is dropped.
            if self.auth.pending {
                self.auth.discard = self.auth.discard.saturating_add(1);
            }
            self.auth.pending = false;
            self.auth.done = false;
            self.auth_deadline = 0;
        }
        if s.tlu {
            self.lcp_up(env);
        }
        if s.refused || self.lcp_l.auth_refused {
            self.close_reason.get_or_insert(DownReason::AuthFailed);
        }
        if s.tlf {
            let r = self.close_reason.unwrap_or(DownReason::LcpFailed);
            self.padt(env, r);
        }
    }

    /// One Session-stage packet from the subscriber.
    pub fn receive(&mut self, env: &mut Env<'_>, protocol: u16, info: &[u8]) {
        // Any packet proves the peer alive (RouterOS keepalive semantics).
        self.echo_misses = 0;
        match protocol {
            proto::LCP => {
                self.heard = true;
                self.lcp_packet(env, info);
            }
            // RFC 1994 §4.1: after Success, repeated Responses are allowed
            // during the Network phase (our Success may have been lost).
            proto::PAP | proto::CHAP => {
                if self.phase == Phase::Authenticate
                    || (self.auth.done && self.phase == Phase::Network)
                {
                    self.auth_packet(env, protocol, info);
                }
            }
            proto::IPCP => self.ipcp_packet(env, info),
            proto::IPV6CP if self.v6_on() => self.v6_packet(env, info),
            // Data is the XDP path's; here it is only seen before Up.
            proto::IPV4 | proto::IPV6 => env.stats.ignored += 1,
            _ => {
                // RFC 1661 §5.7: an unknown protocol in Opened gets a
                // Protocol-Reject (the protocol, then the rejected info).
                if self.lcp.is_opened() {
                    let mut body = Vec::with_capacity(info.len().min(64) + 2);
                    body.extend_from_slice(&protocol.to_be_bytes());
                    let room = usize::from(self.lcp_l.peer_mru).saturating_sub(6);
                    body.extend_from_slice(info.get(..room.min(info.len())).unwrap_or(info));
                    let id = self.echo_id.wrapping_add(0x80);
                    self.send(env, proto::LCP, lc::PROTOCOL_REJECT, id, &body);
                }
            }
        }
    }

    fn lcp_packet(&mut self, env: &mut Env<'_>, info: &[u8]) {
        let Ok(pkt) = ppp::parse_control(info) else {
            env.stats.malformed += 1;
            return;
        };
        if pkt.code == lc::TERMINATE_REQUEST && self.close_reason.is_none() {
            self.close_reason = Some(DownReason::PeerTerminate);
        }
        let r = fsm!(self, env, lcp, lcp_l, |f, c, l| f.receive(&mut c, l, pkt));
        if let Some(s) = r {
            self.lcp_signals(env, s);
            return;
        }
        let opened = self.lcp.is_opened();
        match pkt.code {
            // RFC 1661 §5.7: the NCP of the rejected protocol is finished.
            lc::PROTOCOL_REJECT => {
                let rejected = pkt.data.first_chunk::<2>().map(|p| u16::from_be_bytes(*p));
                match rejected {
                    Some(proto::IPCP) => {
                        let s = fsm!(self, env, ipcp, ipcp_l, |f, c, _l| f
                            .reject_fatal::<Ipcp>(&mut c));
                        self.ncp_signals(env, false, s);
                    }
                    Some(proto::IPV6CP) => {
                        let s = fsm!(self, env, v6, v6_l, |f, c, _l| f
                            .reject_fatal::<Ipv6cp>(&mut c));
                        self.ncp_signals(env, true, s);
                    }
                    Some(proto::LCP) => {
                        let s = fsm!(self, env, lcp, lcp_l, |f, c, _l| f
                            .reject_fatal::<Lcp>(&mut c));
                        self.lcp_signals(env, s);
                    }
                    _ => {}
                }
            }
            // RFC 1661 §5.8: Echo only in Opened; a looped echo (our own
            // magic) is not answered.
            lc::ECHO_REQUEST if opened => {
                let peer = lcp::echo_magic(pkt.data);
                if peer.is_some()
                    && (peer != Some(self.lcp_l.our_magic) || self.lcp_l.echo_magic() == 0)
                {
                    let mut body = [0u8; 4];
                    body.copy_from_slice(&self.lcp_l.echo_magic().to_be_bytes());
                    self.send(env, proto::LCP, lc::ECHO_REPLY, pkt.id, &body);
                }
            }
            lc::ECHO_REPLY | lc::DISCARD_REQUEST | lc::IDENTIFICATION | lc::TIME_REMAINING => {}
            lc::ECHO_REQUEST => {}
            _ => {
                let max = usize::from(self.lcp_l.peer_mru);
                fsm!(self, env, lcp, lcp_l, |f, c, _l| f
                    .code_reject::<Lcp>(&mut c, info, max));
            }
        }
    }

    /// LCP Opened (tlu): start the keepalive and the Authenticate phase.
    fn lcp_up(&mut self, env: &mut Env<'_>) {
        if env.cfg.keepalive_interval_ms > 0 {
            self.echo_at = env.now + env.cfg.keepalive_interval_ms;
        }
        self.auth.proto = self.lcp_l.auth_agreed;
        match self.auth.proto {
            None if env.cfg.auth.is_empty() => self.network_up(env),
            // We asked for authentication and the peer acked without it:
            // not possible (the Ack mirrors our request), so refuse.
            None => self.close(env, DownReason::AuthFailed),
            Some(AuthProto::Pap) => {
                // RFC 1334 §2.1: the peer speaks first.
                self.phase = Phase::Authenticate;
                self.auth_deadline = env.now + env.cfg.answer_timeout_ms;
            }
            Some(_) => {
                self.phase = Phase::Authenticate;
                self.auth.challenge = env.rng.array::<16>();
                self.auth.id = env.rng.u32() as u8;
                self.auth.retries = env.cfg.fsm.max_configure;
                self.send_challenge(env);
            }
        }
    }

    /// RFC 1994 §4.1 Challenge (8 octets for MS-CHAPv1, RFC 2433 §5; 16
    /// otherwise), Name = our AC-Name. A new Identifier each time.
    fn send_challenge(&mut self, env: &mut Env<'_>) {
        self.auth.id = self.auth.id.wrapping_add(1);
        let n = match self.auth.proto {
            Some(AuthProto::MsChapV1) => auth::MSCHAP1_CHALLENGE,
            _ => auth::MSCHAP2_CHALLENGE,
        };
        let mut body = Vec::with_capacity(1 + n + env.cfg.ac_name.len());
        let v = ChapValue {
            value: self.auth.challenge.get(..n).unwrap_or(&[]),
            name: &env.cfg.ac_name,
        };
        if v.put(&mut body).is_ok() {
            self.send(env, proto::CHAP, ac::CHAP_CHALLENGE, self.auth.id, &body);
        }
        self.auth.retries = self.auth.retries.saturating_sub(1);
        self.auth_deadline = env.now + env.cfg.fsm.restart_ms;
    }

    fn auth_packet(&mut self, env: &mut Env<'_>, protocol: u16, info: &[u8]) {
        let Ok(pkt) = ppp::parse_control(info) else {
            env.stats.malformed += 1;
            return;
        };
        let pap = protocol == proto::PAP;
        let expected = match (pap, self.auth.proto) {
            (true, Some(AuthProto::Pap)) => ac::PAP_REQUEST,
            (false, Some(p)) if p != AuthProto::Pap => ac::CHAP_RESPONSE,
            _ => return,
        };
        if pkt.code != expected {
            return;
        }
        if self.auth.done {
            // Our Success/Ack was lost; answer the retransmission the same
            // way. CHAP repeats the Response with the challenge's Identifier
            // (RFC 1994 §4.1); PAP changes it on every Authenticate-Request
            // (RFC 1334 §2.2.1), so the Ack takes the new one.
            if pap {
                self.auth.id = pkt.id;
            }
            if pkt.id == self.auth.id {
                self.send_success(env, b"");
            }
            return;
        }
        if self.auth.pending || (!pap && pkt.id != self.auth.id) {
            return;
        }
        let parsed = if pap {
            PapRequest::parse(pkt.data).map(|r| {
                (
                    Box::<[u8]>::from(r.peer_id),
                    AuthMethod::Pap {
                        password: r.password.into(),
                    },
                )
            })
        } else {
            ChapValue::parse(pkt.data).and_then(|v| {
                let ch = self.auth.challenge;
                let method = match self.auth.proto {
                    Some(AuthProto::ChapMd5) => AuthMethod::Chap {
                        id: pkt.id,
                        challenge: ch,
                        response: v
                            .value
                            .try_into()
                            .map_err(|_| crate::wire::WireError::Malformed("CHAP-MD5 response"))?,
                    },
                    Some(AuthProto::MsChapV1) => AuthMethod::MsChapV1 {
                        id: pkt.id,
                        challenge: ch.first_chunk::<8>().copied().unwrap_or([0; 8]),
                        response: MsChapResponse::parse(v.value)?,
                    },
                    _ => AuthMethod::MsChapV2 {
                        id: pkt.id,
                        challenge: ch,
                        response: MsChapResponse::parse(v.value)?,
                    },
                };
                Ok((Box::<[u8]>::from(v.name), method))
            })
        };
        let Ok((username, method)) = parsed else {
            env.stats.malformed += 1;
            return;
        };
        self.auth.id = pkt.id;
        self.auth.pending = true;
        self.auth_deadline = env.now + env.cfg.answer_timeout_ms;
        self.username = username.clone();
        env.out.events.push(Event::Authenticate {
            session: self.reference(),
            request: Box::new(AuthRequest {
                username,
                method,
                client_mac: self.client_mac,
                ifindex: self.ifindex,
                vlans: self.vlans,
                circuit_id: self.circuit_id.clone(),
                remote_id: self.remote_id.clone(),
                service: self.service.clone(),
            }),
        });
    }

    fn send_success(&mut self, env: &mut Env<'_>, message: &[u8]) {
        let mut body = Vec::with_capacity(64 + message.len());
        let (protocol, code) = match self.auth.proto {
            Some(AuthProto::Pap) => {
                auth::put_pap_message(&mut body, message);
                (proto::PAP, ac::PAP_ACK)
            }
            Some(AuthProto::MsChapV2) => {
                // RFC 2759 §5: "S=<auth_string> M=<message>".
                if let Some(s) = self.auth.success {
                    body.extend_from_slice(&s);
                }
                body.extend_from_slice(b" M=");
                body.extend_from_slice(message);
                (proto::CHAP, ac::CHAP_SUCCESS)
            }
            _ => {
                body.extend_from_slice(message);
                (proto::CHAP, ac::CHAP_SUCCESS)
            }
        };
        self.send(env, protocol, code, self.auth.id, &body);
    }

    fn send_failure(&mut self, env: &mut Env<'_>, message: &[u8]) {
        let mut body = Vec::with_capacity(96 + message.len());
        let (protocol, code) = match self.auth.proto {
            Some(AuthProto::Pap) => {
                auth::put_pap_message(&mut body, message);
                (proto::PAP, ac::PAP_NAK)
            }
            Some(AuthProto::MsChapV2) => {
                // RFC 2759 §6: E=691 (authentication failure), R=0 (no retry).
                let next = env.rng.array::<16>();
                auth::put_mschap2_failure(&mut body, 691, &next, message);
                (proto::CHAP, ac::CHAP_FAILURE)
            }
            Some(AuthProto::MsChapV1) => {
                body.extend_from_slice(b"E=691 R=0 V=1");
                (proto::CHAP, ac::CHAP_FAILURE)
            }
            _ => {
                body.extend_from_slice(message);
                (proto::CHAP, ac::CHAP_FAILURE)
            }
        };
        self.send(env, protocol, code, self.auth.id, &body);
    }

    /// The caller's answer to `Event::Authenticate`.
    pub fn auth_verdict(&mut self, env: &mut Env<'_>, verdict: AuthVerdict) {
        if self.auth.discard > 0 {
            self.auth.discard -= 1;
            return;
        }
        if !self.auth.pending || self.phase != Phase::Authenticate {
            return;
        }
        self.auth.pending = false;
        self.auth_deadline = 0;
        let authz = match verdict {
            AuthVerdict::Accept(a)
                if self.auth.proto != Some(AuthProto::MsChapV2) || a.mschap2_success.is_some() =>
            {
                a
            }
            // MS-CHAPv2 without the authenticator string cannot succeed:
            // the peer would refuse our Success (RFC 2759 §8.8).
            AuthVerdict::Accept(_) => {
                self.reject(env, b"no authenticator response");
                return;
            }
            AuthVerdict::Reject { message } => {
                self.reject(env, &message);
                return;
            }
        };
        env.stats.auth_ok += 1;
        self.auth.done = true;
        self.auth.success = authz.mschap2_success;
        self.send_success(env, &authz.message);
        self.rate_limit = authz.rate_limit;
        self.session_timeout = authz.session_timeout;
        if let Some(t) = authz.session_timeout.filter(|t| *t > 0) {
            self.session_deadline = env.now + u64::from(t) * 1000;
        }
        if let Some(a) = authz.ipv4 {
            self.assign(a);
        }
        self.network_up(env);
    }

    fn reject(&mut self, env: &mut Env<'_>, message: &[u8]) {
        env.stats.auth_fail += 1;
        self.send_failure(env, message);
        // RFC 1994 §4.2: on failure the authenticator SHOULD terminate.
        self.close(env, DownReason::AuthFailed);
    }

    fn assign(&mut self, a: Ipv4Assignment) {
        self.ipcp_l.peer = Some(a.address);
        self.ipcp_l.dns = a.dns;
        self.ipcp_l.nbns = a.nbns;
        self.address_asked = true;
    }

    /// RFC 1661 §3.4: the Network phase opens each NCP.
    fn network_up(&mut self, env: &mut Env<'_>) {
        self.phase = Phase::Network;
        if self.ipcp_l.peer.is_none() && !self.address_asked {
            self.address_asked = true;
            env.out.events.push(Event::NeedAddress {
                session: self.reference(),
            });
        }
        let s = fsm!(self, env, ipcp, ipcp_l, |f, c, l| {
            f.open(&mut c, l);
            f.up(&mut c, l)
        });
        self.ncp_signals(env, false, s);
        if self.v6_on() {
            let s = fsm!(self, env, v6, v6_l, |f, c, l| {
                f.open(&mut c, l);
                f.up(&mut c, l)
            });
            self.ncp_signals(env, true, s);
        }
    }

    /// The caller's answer to `Event::NeedAddress`.
    pub fn address(&mut self, env: &mut Env<'_>, a: Option<Ipv4Assignment>) {
        if self.dead.is_some() || self.ipcp_l.peer.is_some() {
            return;
        }
        match a {
            Some(a) => {
                self.assign(a);
                if let Some(stash) = self.ipcp_stash.take() {
                    self.ipcp_packet(env, &stash);
                }
            }
            None => {
                // No IPv4: IPCP cannot open; without IPv6 the session has
                // no network protocol.
                self.ipcp_stash = None;
                let s = fsm!(self, env, ipcp, ipcp_l, |f, c, _l| f.close::<Ipcp>(&mut c));
                self.ncp_signals(env, false, s);
                if !self.v6_on() {
                    self.close(env, DownReason::NcpFailed);
                }
            }
        }
    }

    fn ipcp_packet(&mut self, env: &mut Env<'_>, info: &[u8]) {
        // RFC 1661 §3.4: NCP packets before the Network phase are discarded.
        if self.phase != Phase::Network {
            return;
        }
        let Ok(pkt) = ppp::parse_control(info) else {
            env.stats.malformed += 1;
            return;
        };
        if pkt.code == lc::CONFIGURE_REQUEST && self.ipcp_l.peer.is_none() {
            // The address is on its way: hold the request instead of making
            // the subscriber wait a restart period.
            if info.len() <= STASH_MAX {
                self.ipcp_stash = Some(info.into());
            }
            return;
        }
        let r = fsm!(self, env, ipcp, ipcp_l, |f, c, l| f.receive(&mut c, l, pkt));
        match r {
            Some(s) => self.ncp_signals(env, false, s),
            None if pkt.code > NCP_MAX_CODE => {
                let max = usize::from(self.lcp_l.peer_mru);
                fsm!(self, env, ipcp, ipcp_l, |f, c, _l| f
                    .code_reject::<Ipcp>(&mut c, info, max));
            }
            None => {}
        }
    }

    fn v6_packet(&mut self, env: &mut Env<'_>, info: &[u8]) {
        if self.phase != Phase::Network {
            return;
        }
        let Ok(pkt) = ppp::parse_control(info) else {
            env.stats.malformed += 1;
            return;
        };
        let r = fsm!(self, env, v6, v6_l, |f, c, l| f.receive(&mut c, l, pkt));
        match r {
            Some(s) => self.ncp_signals(env, true, s),
            None => {
                let max = usize::from(self.lcp_l.peer_mru);
                fsm!(self, env, v6, v6_l, |f, c, _l| f
                    .code_reject::<Ipv6cp>(&mut c, info, max));
            }
        }
    }

    fn ncp_signals(&mut self, env: &mut Env<'_>, v6: bool, s: Signals) {
        if s.tld {
            if v6 {
                self.v6_up = false;
            } else {
                self.v4_up = false;
            }
        }
        if s.tlu {
            if v6 {
                self.v6_up = true;
            } else {
                self.v4_up = true;
            }
            let descriptor = Box::new(self.descriptor(env.cfg));
            let session = self.reference();
            if self.up {
                env.out.events.push(Event::Changed {
                    session,
                    descriptor,
                });
            } else {
                self.up = true;
                env.stats.sessions_up += 1;
                env.out.events.push(Event::Up {
                    session,
                    descriptor,
                });
            }
        }
        if s.tlf || s.refused {
            let other_alive = if v6 {
                matches!(
                    self.ipcp.state(),
                    crate::fsm::State::ReqSent
                        | crate::fsm::State::AckRcvd
                        | crate::fsm::State::AckSent
                        | crate::fsm::State::Opened
                )
            } else {
                self.v6_on()
                    && matches!(
                        self.v6.state(),
                        crate::fsm::State::ReqSent
                            | crate::fsm::State::AckRcvd
                            | crate::fsm::State::AckSent
                            | crate::fsm::State::Opened
                    )
            };
            // `use-ipv6=require`: IPv6CP failing ends the session even with
            // IPCP up.
            let required = v6 && self.v6_mode == Ipv6Mode::Require;
            if (!other_alive || required) && self.phase == Phase::Network {
                self.close(env, DownReason::NcpFailed);
            }
        }
    }

    /// A wheel entry fired: run whatever is due.
    pub fn timers(&mut self, env: &mut Env<'_>) {
        self.scheduled = 0;
        let now = env.now;
        if self.lcp.deadline().is_some_and(|d| d <= now) {
            let s = fsm!(self, env, lcp, lcp_l, |f, c, l| f.timeout(&mut c, l));
            self.lcp_signals(env, s);
        }
        if self.dead.is_some() {
            return;
        }
        if self.auth_deadline != 0 && self.auth_deadline <= now {
            self.auth_deadline = 0;
            let chap = !matches!(self.auth.proto, Some(AuthProto::Pap) | None);
            if self.phase == Phase::Authenticate
                && chap
                && !self.auth.pending
                && self.auth.retries > 0
            {
                self.send_challenge(env);
            } else if self.phase == Phase::Authenticate {
                self.close(env, DownReason::AuthTimeout);
            }
        }
        if self.ipcp.deadline().is_some_and(|d| d <= now) {
            let s = fsm!(self, env, ipcp, ipcp_l, |f, c, l| f.timeout(&mut c, l));
            self.ncp_signals(env, false, s);
        }
        if self.v6.deadline().is_some_and(|d| d <= now) {
            let s = fsm!(self, env, v6, v6_l, |f, c, l| f.timeout(&mut c, l));
            self.ncp_signals(env, true, s);
        }
        if self.dead.is_some() {
            return;
        }
        // Echo runs only in Opened (RFC 1661 §5.8); a deadline left from
        // before LCP went down is dropped, not kept firing.
        if self.echo_at != 0 && self.echo_at <= now && !self.lcp.is_opened() {
            self.echo_at = 0;
        }
        if self.echo_at != 0 && self.echo_at <= now && self.lcp.is_opened() {
            if self.echo_misses >= env.cfg.keepalive_misses {
                // The subscriber is gone: it would not answer Terminate.
                env.stats.keepalive_timeouts += 1;
                self.padt(env, DownReason::Keepalive);
                return;
            }
            self.echo_misses += 1;
            self.echo_id = self.echo_id.wrapping_add(1);
            let body = self.lcp_l.echo_magic().to_be_bytes();
            self.send(env, proto::LCP, lc::ECHO_REQUEST, self.echo_id, &body);
            self.echo_at = now + env.cfg.keepalive_interval_ms;
        }
        if !self.up && self.setup_deadline <= now {
            self.setup_deadline = now + env.cfg.fsm.restart_ms * 2;
            if self.phase == Phase::Terminate {
                self.padt(env, self.close_reason.unwrap_or(DownReason::SetupTimeout));
            } else {
                self.close(env, DownReason::SetupTimeout);
            }
        }
        if self.session_deadline != 0 && self.session_deadline <= now {
            self.session_deadline = 0;
            self.close(env, DownReason::SessionTimeout);
        }
    }
}

// --- G4.3h hot standby: the state another node needs, and the session
// rebuilt from it in Opened state (`server::ha`). ---

impl Session {
    pub(crate) fn export(&self, now: Millis) -> Option<super::ha::SessionState> {
        if !self.up || self.dead.is_some() {
            return None;
        }
        Some(super::ha::SessionState {
            sid: self.sid,
            ifindex: self.ifindex,
            vlans: self.vlans,
            client_mac: self.client_mac,
            our_magic: self.lcp_l.our_magic,
            peer_magic: self.lcp_l.peer_magic,
            our_mru: self.lcp_l.our_mru,
            peer_mru: self.lcp_l.peer_mru,
            auth: self.auth.proto,
            username: self.username.clone(),
            service: self.service.clone(),
            ipv4: if self.v4_up { self.ipcp_l.peer } else { None },
            local_ipv4: self.ipcp_l.local,
            dns: self.ipcp_l.dns,
            nbns: self.ipcp_l.nbns,
            ipv6: if self.v6_up {
                self.v6_l.peer_iid.map(|p| (self.v6_l.local_iid, p))
            } else {
                None
            },
            v6_mode: self.v6_mode,
            rate_limit: self.rate_limit,
            session_timeout: self.session_timeout,
            timeout_left_ms: (self.session_deadline > 0)
                .then(|| self.session_deadline.saturating_sub(now).max(1)),
            circuit_id: self.circuit_id.clone(),
            remote_id: self.remote_id.clone(),
        })
    }

    pub(crate) fn import(
        cfg: &ServerConfig,
        rng: &mut Rng,
        st: &super::ha::SessionState,
        gen_: u32,
        svc: super::services::ServiceSlot,
        now: Millis,
    ) -> Session {
        let mut s = Session::new(
            cfg,
            rng,
            Init {
                gen_,
                sid: st.sid,
                ifindex: st.ifindex,
                vlans: st.vlans,
                client_mac: st.client_mac,
                uniq: 0,
                mru_cap: None,
                service: st.service.clone(),
                svc,
                circuit_id: st.circuit_id.clone(),
                remote_id: st.remote_id.clone(),
            },
            now,
        );
        s.lcp = Fsm::opened(rng.u32() as u8);
        s.lcp_l.our_magic = st.our_magic;
        s.lcp_l.peer_magic = st.peer_magic;
        s.lcp_l.our_mru = st.our_mru;
        s.lcp_l.peer_mru = st.peer_mru;
        s.lcp_l.auth_agreed = st.auth;
        s.auth.proto = st.auth;
        s.auth.done = true;
        s.phase = Phase::Network;
        s.heard = true;
        s.username = st.username.clone();
        s.rate_limit = st.rate_limit;
        s.session_timeout = st.session_timeout;
        if let Some(left) = st.timeout_left_ms {
            s.session_deadline = now + left.max(1);
        }
        if st.local_ipv4.is_some() {
            s.ipcp_l.local = st.local_ipv4;
        }
        s.ipcp_l.dns = st.dns;
        s.ipcp_l.nbns = st.nbns;
        if let Some(ip) = st.ipv4 {
            s.ipcp = Fsm::opened(1);
            s.ipcp_l.peer = Some(ip);
            s.address_asked = true;
            s.v4_up = true;
        }
        s.v6_mode = st.v6_mode;
        if let Some((local, peer)) = st.ipv6 {
            s.v6 = Fsm::opened(1);
            s.v6_l.local_iid = local;
            s.v6_l.peer_iid = Some(peer);
            s.v6_up = true;
        }
        s.up = s.v4_up || s.v6_up;
        if cfg.keepalive_interval_ms > 0 {
            s.echo_at = now + cfg.keepalive_interval_ms;
        }
        s
    }
}
