//! One subscriber session on the access concentrator: the PPP phases of
//! RFC 1661 §3.2 (Establish → Authenticate → Network → Terminate) over the
//! PPPoE link, with the caller answering authentication and addressing.

use super::{
    AuthMethod, AuthRequest, AuthVerdict, DownReason, Env, Event, HostKey, Ipv4Assignment,
    ServerConfig, SessionKey, SessionRef,
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
        let mut w = SessionWriter::control(&mut self.out.buf, &self.link, self.sid, protocol, code, id);
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
