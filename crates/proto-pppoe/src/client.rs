//! The subscriber side: PPPoE Discovery as a Host (RFC 2516 §5), then LCP,
//! PAP/CHAP/MS-CHAP as the authenticatee and IPCP/IPv6CP. It drives the
//! server in tests and is the load generator of the mass simulations; the
//! same sans-IO shape as [`crate::server`].

use crate::auth::{self, AUTH_STRING_LEN, ChapValue, MsChapResponse, PapRequest, code as ac};
use crate::discovery::{self, Code, DEFAULT_MRU, Discovery, DiscoveryWriter, tag};
use crate::eth::{self, ETHERTYPE_DISCOVERY, ETHERTYPE_SESSION, Vlans};
use crate::fsm::{Ctx, Fsm, FsmConfig, Scratch, Signals, Tx};
use crate::guard::Rng;
use crate::layers::{AuthSet, Ipcp, Ipv6cp, Lcp, Role};
use crate::lcp::{self, AuthProto, code as lc};
use crate::output::Output;
use crate::ppp::{self, Link, SessionWriter, proto};
use crate::timer::Millis;
use crate::wire::Mac;
use std::net::Ipv4Addr;

#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub mac: Mac,
    pub ifindex: u32,
    pub vlans: Vlans,
    /// Service-Name to ask for (empty = any).
    pub service_name: Vec<u8>,
    /// Host-Uniq (RFC 2516 §5.1, to match replies to this host).
    pub host_uniq: Option<Vec<u8>>,
    pub username: Vec<u8>,
    pub password: String,
    /// Authentication protocols we agree to.
    pub auth: AuthSet,
    pub mru: u16,
    /// RFC 4638 PPP-Max-Payload to ask for.
    pub max_payload: Option<u16>,
    pub want_dns: bool,
    pub ipv6: bool,
    /// First PADI/PADR retransmission (doubles up to 8×).
    pub discovery_timeout_ms: u64,
    pub discovery_attempts: u8,
    pub fsm: FsmConfig,
    /// Line ids a relay agent would add (RFC 4679), for tests.
    pub circuit_id: Option<Vec<u8>>,
    pub remote_id: Option<Vec<u8>>,
}

impl Default for ClientConfig {
    fn default() -> Self {
        ClientConfig {
            mac: Mac([0x02, 0x10, 0, 0, 0, 1]),
            ifindex: 1,
            vlans: Vlans::NONE,
            service_name: Vec::new(),
            host_uniq: None,
            username: b"user".to_vec(),
            password: "pass".into(),
            auth: AuthSet::routeros_default(),
            mru: DEFAULT_MRU,
            max_payload: None,
            want_dns: true,
            ipv6: false,
            discovery_timeout_ms: 1000,
            discovery_attempts: 5,
            fsm: FsmConfig::default(),
            circuit_id: None,
            remote_id: None,
        }
    }
}

/// Why the client stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClientDown {
    NoOffer,
    ServiceError,
    AcSystemError,
    Padt,
    LcpFailed,
    AuthFailed,
    NcpFailed,
    /// [`Client::close`] or [`Client::abort`].
    Local,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientEvent {
    Up {
        sid: u16,
        ac_mac: Mac,
        ipv4: Option<Ipv4Addr>,
        dns: [Option<Ipv4Addr>; 2],
    },
    Down {
        reason: ClientDown,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientPhase {
    Idle,
    Discovering,
    Requesting,
    Establish,
    Authenticate,
    Network,
    Up,
    Terminate,
    Closed(ClientDown),
}

pub type ClientOutput = Output<ClientEvent>;

pub struct Client {
    cfg: ClientConfig,
    phase: ClientPhase,
    ac_mac: Mac,
    sid: u16,
    cookie: Option<Box<[u8]>>,
    relay: Option<Box<[u8]>>,
    attempts: u8,
    disc_deadline: Millis,
    disc_timeout: Millis,
    lcp: Fsm,
    lcp_l: Lcp,
    ipcp: Fsm,
    ipcp_l: Ipcp,
    v6: Fsm,
    v6_l: Ipv6cp,
    auth: Option<AuthProto>,
    auth_id: u8,
    auth_deadline: Millis,
    auth_retries: u8,
    expect: Option<[u8; AUTH_STRING_LEN]>,
    close_reason: Option<ClientDown>,
    scratch: Scratch,
    rng: Rng,
}

struct ClientTx<'a> {
    out: &'a mut ClientOutput,
    link: Link,
    sid: u16,
    ifindex: u32,
}

impl Tx for ClientTx<'_> {
    fn send(&mut self, protocol: u16, code: u8, id: u8, body: &[u8]) {
        let start = self.out.buf.len();
        let mut w =
            SessionWriter::control(&mut self.out.buf, &self.link, self.sid, protocol, code, id);
        w.buf().extend_from_slice(body);
        if w.finish(usize::from(DEFAULT_MRU)).is_ok() {
            self.out.push_frame(self.ifindex, start);
        }
    }
}

macro_rules! cfsm {
    ($s:ident, $now:ident, $out:ident, $fsm:ident, $layer:ident, |$f:ident, $c:ident, $l:ident| $body:expr) => {{
        let mut tx = ClientTx {
            out: &mut *$out,
            link: $s.link(),
            sid: $s.sid,
            ifindex: $s.cfg.ifindex,
        };
        let mut $c = Ctx {
            now: $now,
            cfg: &$s.cfg.fsm,
            tx: &mut tx,
            scratch: &mut $s.scratch,
        };
        let $f = &mut $s.$fsm;
        let $l = &mut $s.$layer;
        $body
    }};
}

impl Client {
    pub fn new(cfg: ClientConfig, seed: [u8; 32]) -> Client {
        let mut rng = Rng::new(seed);
        let mru = match cfg.max_payload {
            Some(p) if p > DEFAULT_MRU => p,
            _ => cfg.mru.min(DEFAULT_MRU),
        };
        let magic = rng.nonzero_u32();
        let mut iid = rng.array::<8>();
        if iid == [0; 8] {
            iid[7] = 2;
        }
        let v6seed = rng.nonzero_u32();
        Client {
            lcp: Fsm::new(rng.u32() as u8),
            lcp_l: Lcp::new(Role::Client, mru, mru, cfg.auth, magic),
            ipcp: Fsm::new(1),
            ipcp_l: Ipcp::client(cfg.want_dns),
            v6: Fsm::new(1),
            v6_l: Ipv6cp::new(iid, v6seed),
            phase: ClientPhase::Idle,
            ac_mac: Mac::BROADCAST,
            sid: 0,
            cookie: None,
            relay: None,
            attempts: 0,
            disc_deadline: 0,
            disc_timeout: cfg.discovery_timeout_ms,
            auth: None,
            auth_id: 0,
            auth_deadline: 0,
            auth_retries: 0,
            expect: None,
            close_reason: None,
            scratch: Scratch::default(),
            rng,
            cfg,
        }
    }

    pub fn phase(&self) -> ClientPhase {
        self.phase
    }

    pub fn session_id(&self) -> u16 {
        self.sid
    }

    pub fn ipv4(&self) -> Option<Ipv4Addr> {
        self.ipcp_l.local.filter(|a| !a.is_unspecified())
    }

    pub fn config(&self) -> &ClientConfig {
        &self.cfg
    }

    fn link(&self) -> Link {
        Link {
            dst: self.ac_mac,
            src: self.cfg.mac,
            vlans: self.cfg.vlans,
        }
    }

    pub fn next_deadline(&self) -> Option<Millis> {
        [
            self.disc_deadline,
            self.auth_deadline,
            self.lcp.deadline().unwrap_or(0),
            self.ipcp.deadline().unwrap_or(0),
            self.v6.deadline().unwrap_or(0),
        ]
        .into_iter()
        .filter(|d| *d != 0)
        .min()
    }

    fn down(&mut self, reason: ClientDown, out: &mut ClientOutput) {
        if matches!(self.phase, ClientPhase::Closed(_)) {
            return;
        }
        self.phase = ClientPhase::Closed(reason);
        self.disc_deadline = 0;
        self.auth_deadline = 0;
        self.lcp = Fsm::new(0);
        self.ipcp = Fsm::new(0);
        self.v6 = Fsm::new(0);
        out.events.push(ClientEvent::Down { reason });
    }

    fn host_tags(&self, w: &mut DiscoveryWriter<'_>) {
        w.tag(tag::SERVICE_NAME, &self.cfg.service_name);
        if let Some(h) = &self.cfg.host_uniq {
            w.tag(tag::HOST_UNIQ, h);
        }
        if let Some(p) = self.cfg.max_payload {
            w.tag_u16(tag::PPP_MAX_PAYLOAD, p);
        }
        if self.cfg.circuit_id.is_some() || self.cfg.remote_id.is_some() {
            w.tag_bbf(
                self.cfg.circuit_id.as_deref(),
                self.cfg.remote_id.as_deref(),
            );
        }
    }

    /// Starts (or restarts) Discovery with a PADI.
    pub fn start(&mut self, now: Millis, out: &mut ClientOutput) {
        *self = Client::new(self.cfg.clone(), self.rng.array::<32>());
        self.phase = ClientPhase::Discovering;
        self.attempts = 0;
        self.disc_timeout = self.cfg.discovery_timeout_ms;
        self.send_padi(now, out);
    }

    fn arm_discovery(&mut self, now: Millis) {
        self.attempts += 1;
        self.disc_deadline = now + self.disc_timeout;
        self.disc_timeout = (self.disc_timeout * 2).min(self.cfg.discovery_timeout_ms * 8);
    }

    fn send_padi(&mut self, now: Millis, out: &mut ClientOutput) {
        let start = out.buf.len();
        let mut w = DiscoveryWriter::begin(
            &mut out.buf,
            Mac::BROADCAST,
            self.cfg.mac,
            self.cfg.vlans,
            Code::Padi,
            0,
        );
        self.host_tags(&mut w);
        if w.finish().is_ok() {
            out.push_frame(self.cfg.ifindex, start);
        }
        self.arm_discovery(now);
    }

    fn send_padr(&mut self, now: Millis, out: &mut ClientOutput) {
        let start = out.buf.len();
        let mut w = DiscoveryWriter::begin(
            &mut out.buf,
            self.ac_mac,
            self.cfg.mac,
            self.cfg.vlans,
            Code::Padr,
            0,
        );
        self.host_tags(&mut w);
        // RFC 2516 §5.3: the AC-Cookie and Relay-Session-Id go back as given.
        if let Some(c) = &self.cookie {
            w.tag(tag::AC_COOKIE, c);
        }
        if let Some(r) = &self.relay {
            w.tag(tag::RELAY_SESSION_ID, r);
        }
        if w.finish().is_ok() {
            out.push_frame(self.cfg.ifindex, start);
        }
        self.arm_discovery(now);
    }

    /// Ends the session at once with a PADT (RFC 2516 §5.5).
    pub fn abort(&mut self, out: &mut ClientOutput) {
        if self.sid != 0 && !matches!(self.phase, ClientPhase::Closed(_)) {
            let start = out.buf.len();
            let w = DiscoveryWriter::begin(
                &mut out.buf,
                self.ac_mac,
                self.cfg.mac,
                self.cfg.vlans,
                Code::Padt,
                self.sid,
            );
            if w.finish().is_ok() {
                out.push_frame(self.cfg.ifindex, start);
            }
        }
        self.down(ClientDown::Local, out);
    }

    /// Orderly close: LCP Terminate, then PADT.
    pub fn close(&mut self, now: Millis, out: &mut ClientOutput) {
        if !self.lcp.is_opened() {
            self.abort(out);
            return;
        }
        self.close_reason = Some(ClientDown::Local);
        self.phase = ClientPhase::Terminate;
        let s = cfsm!(self, now, out, lcp, lcp_l, |f, c, _l| f
            .close::<Lcp>(&mut c));
        self.lcp_signals(now, out, s);
    }

    fn discovery(&mut self, now: Millis, d: &Discovery<'_>, out: &mut ClientOutput) {
        if d.dst != self.cfg.mac || d.vlans != self.cfg.vlans {
            return;
        }
        // Host-Uniq must be ours when we sent one (RFC 2516 §5.2).
        if self.cfg.host_uniq.as_deref() != d.tags.host_uniq && self.cfg.host_uniq.is_some() {
            return;
        }
        match (d.code, self.phase) {
            (Code::Pado, ClientPhase::Discovering) => {
                // RFC 2516 §5.2: a PADO MUST carry AC-Name and our
                // Service-Name; ignore one that does not.
                if d.tags.ac_name.is_none() || !d.src.is_unicast() {
                    return;
                }
                let svc = &self.cfg.service_name;
                if !svc.is_empty() && d.tags.service_name != Some(svc.as_slice()) {
                    return;
                }
                self.ac_mac = d.src;
                self.cookie = d.tags.ac_cookie.map(Into::into);
                self.relay = d.tags.relay_session_id.map(Into::into);
                self.phase = ClientPhase::Requesting;
                self.attempts = 0;
                self.disc_timeout = self.cfg.discovery_timeout_ms;
                self.send_padr(now, out);
            }
            (Code::Pads, ClientPhase::Requesting) if d.src == self.ac_mac => {
                self.disc_deadline = 0;
                if d.tags.service_name_error.is_some() {
                    self.down(ClientDown::ServiceError, out);
                } else if d.tags.ac_system_error.is_some() || d.session_id == 0 {
                    self.down(ClientDown::AcSystemError, out);
                } else {
                    self.sid = d.session_id;
                    self.phase = ClientPhase::Establish;
                    let s = cfsm!(self, now, out, lcp, lcp_l, |f, c, l| {
                        f.open(&mut c, l);
                        f.up(&mut c, l)
                    });
                    self.lcp_signals(now, out, s);
                }
            }
            (Code::Padt, _)
                if d.src == self.ac_mac && d.session_id == self.sid && self.sid != 0 =>
            {
                self.down(ClientDown::Padt, out);
            }
            _ => {}
        }
    }

    pub fn handle_frame(&mut self, now: Millis, frame: &[u8], out: &mut ClientOutput) {
        let Ok(e) = eth::parse(frame) else { return };
        match e.ethertype {
            ETHERTYPE_DISCOVERY => {
                if let Ok(d) = discovery::parse(frame) {
                    self.discovery(now, &d, out);
                }
            }
            ETHERTYPE_SESSION => {
                let Ok(f) = ppp::parse_session(frame) else {
                    return;
                };
                let live = !matches!(self.phase, ClientPhase::Closed(_) | ClientPhase::Idle);
                if live
                    && f.link.src == self.ac_mac
                    && f.link.dst == self.cfg.mac
                    && f.session_id == self.sid
                {
                    self.session(now, f.protocol, f.info, out);
                }
            }
            _ => {}
        }
    }

    fn session(&mut self, now: Millis, protocol: u16, info: &[u8], out: &mut ClientOutput) {
        let Ok(pkt) = ppp::parse_control(info) else {
            return;
        };
        match protocol {
            proto::LCP => {
                if pkt.code == lc::TERMINATE_REQUEST {
                    self.close_reason.get_or_insert(ClientDown::LcpFailed);
                }
                let r = cfsm!(self, now, out, lcp, lcp_l, |f, c, l| f
                    .receive(&mut c, l, pkt));
                match r {
                    Some(s) => self.lcp_signals(now, out, s),
                    None if pkt.code == lc::ECHO_REQUEST && self.lcp.is_opened() => {
                        let body = self.lcp_l.echo_magic().to_be_bytes();
                        let mut tx = ClientTx {
                            out: &mut *out,
                            link: self.link(),
                            sid: self.sid,
                            ifindex: self.cfg.ifindex,
                        };
                        tx.send(proto::LCP, lc::ECHO_REPLY, pkt.id, &body);
                    }
                    None => {}
                }
            }
            proto::PAP | proto::CHAP if self.phase == ClientPhase::Authenticate => {
                self.auth_packet(now, protocol, pkt, out)
            }
            proto::IPCP if matches!(self.phase, ClientPhase::Network | ClientPhase::Up) => {
                if let Some(s) = cfsm!(self, now, out, ipcp, ipcp_l, |f, c, l| f
                    .receive(&mut c, l, pkt))
                {
                    self.ncp_signals(now, out, false, s);
                }
            }
            proto::IPV6CP
                if self.cfg.ipv6
                    && matches!(self.phase, ClientPhase::Network | ClientPhase::Up) =>
            {
                if let Some(s) = cfsm!(self, now, out, v6, v6_l, |f, c, l| f
                    .receive(&mut c, l, pkt))
                {
                    self.ncp_signals(now, out, true, s);
                }
            }
            _ => {}
        }
    }

    fn lcp_signals(&mut self, now: Millis, out: &mut ClientOutput, s: Signals) {
        if s.tld {
            self.ipcp.down();
            self.v6.down();
        }
        if s.tlu {
            self.auth = self.lcp_l.peer_auth;
            match self.auth {
                None => self.network(now, out),
                Some(AuthProto::Pap) => {
                    self.phase = ClientPhase::Authenticate;
                    self.auth_retries = self.cfg.fsm.max_configure;
                    self.send_pap(now, out);
                }
                Some(_) => self.phase = ClientPhase::Authenticate,
            }
        }
        if s.tlf {
            let r = self.close_reason.unwrap_or(ClientDown::LcpFailed);
            let start = out.buf.len();
            let w = DiscoveryWriter::begin(
                &mut out.buf,
                self.ac_mac,
                self.cfg.mac,
                self.cfg.vlans,
                Code::Padt,
                self.sid,
            );
            if w.finish().is_ok() {
                out.push_frame(self.cfg.ifindex, start);
            }
            self.down(r, out);
        }
    }

    fn send_pap(&mut self, now: Millis, out: &mut ClientOutput) {
        self.auth_id = self.auth_id.wrapping_add(1);
        let mut body = Vec::with_capacity(2 + self.cfg.username.len() + self.cfg.password.len());
        let req = PapRequest {
            peer_id: &self.cfg.username,
            password: self.cfg.password.as_bytes(),
        };
        if req.put(&mut body).is_ok() {
            let mut tx = ClientTx {
                out: &mut *out,
                link: self.link(),
                sid: self.sid,
                ifindex: self.cfg.ifindex,
            };
            tx.send(proto::PAP, ac::PAP_REQUEST, self.auth_id, &body);
        }
        self.auth_retries = self.auth_retries.saturating_sub(1);
        self.auth_deadline = now + self.cfg.fsm.restart_ms;
    }

    fn auth_failed(&mut self, now: Millis, out: &mut ClientOutput) {
        self.auth_deadline = 0;
        self.close_reason = Some(ClientDown::AuthFailed);
        self.phase = ClientPhase::Terminate;
        let s = cfsm!(self, now, out, lcp, lcp_l, |f, c, _l| f
            .close::<Lcp>(&mut c));
        self.lcp_signals(now, out, s);
    }

    fn auth_packet(
        &mut self,
        now: Millis,
        protocol: u16,
        pkt: ppp::Control<'_>,
        out: &mut ClientOutput,
    ) {
        match (protocol, pkt.code) {
            (proto::PAP, ac::PAP_ACK) if pkt.id == self.auth_id => {
                self.auth_deadline = 0;
                self.network(now, out);
            }
            (proto::PAP, ac::PAP_NAK) if pkt.id == self.auth_id => self.auth_failed(now, out),
            (proto::CHAP, ac::CHAP_CHALLENGE) => {
                let Ok(v) = ChapValue::parse(pkt.data) else {
                    return;
                };
                let mut value = Vec::with_capacity(auth::MSCHAP_RESPONSE);
                match self.auth {
                    Some(AuthProto::ChapMd5) => {
                        value.extend_from_slice(&auth::chap_md5(
                            pkt.id,
                            self.cfg.password.as_bytes(),
                            v.value,
                        ));
                    }
                    Some(AuthProto::MsChapV1) => {
                        let Ok(ch) = <[u8; 8]>::try_from(v.value) else {
                            return;
                        };
                        let nt = corerouter_proto_radius::mschap::v1_nt_response(
                            &ch,
                            &corerouter_proto_radius::mschap::utf16le(&self.cfg.password),
                        );
                        let r = MsChapResponse {
                            peer_challenge: [0; 16],
                            reserved: [0; 8],
                            nt_response: nt,
                            flags: 1,
                        };
                        value.extend_from_slice(&r.to_bytes());
                    }
                    Some(AuthProto::MsChapV2) => {
                        let Ok(ch) = <[u8; 16]>::try_from(v.value) else {
                            return;
                        };
                        let peer = self.rng.array::<16>();
                        let (r, s) = auth::mschap2_client_response(
                            &ch,
                            &peer,
                            &self.cfg.username,
                            &self.cfg.password,
                        );
                        self.expect = Some(s);
                        value.extend_from_slice(&r.to_bytes());
                    }
                    _ => return,
                }
                self.auth_id = pkt.id;
                let mut body = Vec::with_capacity(1 + value.len() + self.cfg.username.len());
                let cv = ChapValue {
                    value: &value,
                    name: &self.cfg.username,
                };
                if cv.put(&mut body).is_ok() {
                    let mut tx = ClientTx {
                        out: &mut *out,
                        link: self.link(),
                        sid: self.sid,
                        ifindex: self.cfg.ifindex,
                    };
                    tx.send(proto::CHAP, ac::CHAP_RESPONSE, pkt.id, &body);
                }
            }
            (proto::CHAP, ac::CHAP_SUCCESS) if pkt.id == self.auth_id => {
                // RFC 2759 §8.8: check the authenticator before trusting it.
                if let Some(e) = self.expect
                    && !auth::mschap2_check_authenticator(&e, pkt.data)
                {
                    self.auth_failed(now, out);
                    return;
                }
                self.network(now, out);
            }
            (proto::CHAP, ac::CHAP_FAILURE) if pkt.id == self.auth_id => self.auth_failed(now, out),
            _ => {}
        }
    }

    fn network(&mut self, now: Millis, out: &mut ClientOutput) {
        if self.phase == ClientPhase::Network || self.phase == ClientPhase::Up {
            return;
        }
        self.phase = ClientPhase::Network;
        let s = cfsm!(self, now, out, ipcp, ipcp_l, |f, c, l| {
            f.open(&mut c, l);
            f.up(&mut c, l)
        });
        self.ncp_signals(now, out, false, s);
        if self.cfg.ipv6 {
            let s = cfsm!(self, now, out, v6, v6_l, |f, c, l| {
                f.open(&mut c, l);
                f.up(&mut c, l)
            });
            self.ncp_signals(now, out, true, s);
        }
    }

    fn ncp_signals(&mut self, now: Millis, out: &mut ClientOutput, v6: bool, s: Signals) {
        if s.tlu && !v6 && self.phase == ClientPhase::Network {
            self.phase = ClientPhase::Up;
            out.events.push(ClientEvent::Up {
                sid: self.sid,
                ac_mac: self.ac_mac,
                ipv4: self.ipv4(),
                dns: self.ipcp_l.dns,
            });
        }
        if (s.tlf || s.refused) && !v6 {
            self.close_reason = Some(ClientDown::NcpFailed);
            self.phase = ClientPhase::Terminate;
            let s = cfsm!(self, now, out, lcp, lcp_l, |f, c, _l| f
                .close::<Lcp>(&mut c));
            self.lcp_signals(now, out, s);
        }
    }

    pub fn handle_timers(&mut self, now: Millis, out: &mut ClientOutput) {
        if self.disc_deadline != 0 && self.disc_deadline <= now {
            self.disc_deadline = 0;
            if self.attempts >= self.cfg.discovery_attempts {
                self.down(ClientDown::NoOffer, out);
                return;
            }
            match self.phase {
                ClientPhase::Discovering => self.send_padi(now, out),
                ClientPhase::Requesting => self.send_padr(now, out),
                _ => {}
            }
        }
        if self.auth_deadline != 0 && self.auth_deadline <= now {
            self.auth_deadline = 0;
            if self.phase == ClientPhase::Authenticate && self.auth == Some(AuthProto::Pap) {
                if self.auth_retries == 0 {
                    self.auth_failed(now, out);
                } else {
                    self.send_pap(now, out);
                }
            }
        }
        if self.lcp.deadline().is_some_and(|d| d <= now) {
            let s = cfsm!(self, now, out, lcp, lcp_l, |f, c, l| f.timeout(&mut c, l));
            self.lcp_signals(now, out, s);
        }
        if self.ipcp.deadline().is_some_and(|d| d <= now) {
            let s = cfsm!(self, now, out, ipcp, ipcp_l, |f, c, l| f.timeout(&mut c, l));
            self.ncp_signals(now, out, false, s);
        }
        if self.v6.deadline().is_some_and(|d| d <= now) {
            let s = cfsm!(self, now, out, v6, v6_l, |f, c, l| f.timeout(&mut c, l));
            self.ncp_signals(now, out, true, s);
        }
    }
}

/// Echo bodies: our magic (tests use it to check RFC 1661 §5.8).
pub fn echo_magic_of(info: &[u8]) -> Option<u32> {
    ppp::parse_control(info)
        .ok()
        .and_then(|c| lcp::echo_magic(c.data))
}
