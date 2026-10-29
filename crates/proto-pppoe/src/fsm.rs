//! The option negotiation automaton of RFC 1661 §4, shared by LCP, IPCP
//! and IPv6CP.
//!
//! [`Fsm`] holds the state, the restart and failure counters of §4.6 and a
//! copy of our last Configure-Request (§5.2: an Ack must match it exactly);
//! the protocol-specific option logic is a [`Layer`]. Transitions follow the
//! state transition table of §4.1 cell by cell; each arm cites its cell as
//! `state × event → actions/next`. The four layer actions (tlu, tld, tls,
//! tlf) come back as [`Signals`] for the session to act on: LCP's tlu starts
//! authentication, its tlf ends the PPPoE session, an NCP's tlu brings the
//! network up.

use crate::lcp::code;
use crate::ppp::{self, Control};
use crate::timer::Millis;
use crate::wire::WireError;

/// RFC 1661 §4.2 states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum State {
    Initial,
    Starting,
    Closed,
    Stopped,
    Closing,
    Stopping,
    ReqSent,
    AckRcvd,
    AckSent,
    Opened,
}

impl State {
    /// States in which the restart timer runs (§4.6).
    fn timed(self) -> bool {
        matches!(
            self,
            State::Closing | State::Stopping | State::ReqSent | State::AckRcvd | State::AckSent
        )
    }
}

/// RFC 1661 §4.6 parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FsmConfig {
    /// Restart timer: 3 s.
    pub restart_ms: u64,
    /// Max-Terminate: 2.
    pub max_terminate: u8,
    /// Max-Configure: 10.
    pub max_configure: u8,
    /// Max-Failure: 5.
    pub max_failure: u8,
}

impl Default for FsmConfig {
    fn default() -> Self {
        FsmConfig {
            restart_ms: 3000,
            max_terminate: 2,
            max_configure: 10,
            max_failure: 5,
        }
    }
}

/// Where the automaton sends its packets (the session's PPPoE link).
pub trait Tx {
    fn send(&mut self, protocol: u16, code: u8, id: u8, body: &[u8]);
}

/// Reusable buffers, so a negotiation step allocates nothing.
#[derive(Default)]
pub struct Scratch {
    pub req: Vec<u8>,
    pub nak: Vec<u8>,
    pub rej: Vec<u8>,
}

/// The protocol-specific half: which options we ask for and which of the
/// peer's we take.
pub trait Layer {
    const PROTOCOL: u16;
    /// Writes our Configure-Request options.
    fn request(&mut self, out: &mut Vec<u8>);
    /// Classifies the peer's Configure-Request: unacceptable values go to
    /// `nak` (with the value we want), unknown or refused options to `rej`
    /// (verbatim). Malformed options make the packet invalid.
    fn classify(
        &mut self,
        opts: &[u8],
        nak: &mut Vec<u8>,
        rej: &mut Vec<u8>,
    ) -> Result<(), WireError>;
    /// The peer's Configure-Request was acked: record its values.
    fn peer_acked(&mut self, opts: &[u8]);
    /// Our request was acked.
    fn acked(&mut self, opts: &[u8]);
    /// The peer Nak'd some of our options (§5.3): adjust the next request.
    fn naked(&mut self, opts: &[u8]);
    /// The peer rejected some of our options (§5.4): stop asking. `false`
    /// when we cannot do without one of them.
    fn rejected(&mut self, opts: &[u8]) -> bool;
}

/// Layer actions raised by one event (§4.4), in the order to apply them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Signals {
    pub tld: bool,
    pub tlu: bool,
    pub tls: bool,
    pub tlf: bool,
    /// The peer rejected an option we cannot do without; the automaton
    /// already moved to Closing.
    pub refused: bool,
}

/// Everything an event needs besides the automaton and its layer.
pub struct Ctx<'a> {
    pub now: Millis,
    pub cfg: &'a FsmConfig,
    pub tx: &'a mut dyn Tx,
    pub scratch: &'a mut Scratch,
}

/// Longest Configure-Request we remember (ours are under 32 bytes).
const LAST_REQ_MAX: usize = 48;

/// One automaton (≈ 70 bytes).
#[derive(Debug, Clone)]
pub struct Fsm {
    state: State,
    restart: u8,
    failures: u8,
    req_id: u8,
    next_id: u8,
    last_req_len: u8,
    /// Our last Configure-Request got its Ack/Nak/Reject: a copy of the
    /// reply (duplicated or delayed on the wire) must not count twice.
    answered: bool,
    /// Restart timer deadline; 0 = stopped.
    deadline: Millis,
    last_req: [u8; LAST_REQ_MAX],
}

impl Default for Fsm {
    fn default() -> Self {
        Fsm::new(0)
    }
}

impl Fsm {
    /// `first_id` seeds the Identifier sequence (§5: chosen by the sender).
    pub fn new(first_id: u8) -> Fsm {
        Fsm {
            state: State::Initial,
            restart: 0,
            failures: 0,
            req_id: 0,
            next_id: first_id,
            last_req_len: 0,
            answered: false,
            deadline: 0,
            last_req: [0; LAST_REQ_MAX],
        }
    }

    /// An automaton already Opened: a session another node negotiated
    /// and this one takes over (G4.3h hot standby). Nothing is sent; a
    /// later Configure-Request from the peer renegotiates as usual.
    pub fn opened(first_id: u8) -> Fsm {
        Fsm {
            state: State::Opened,
            ..Fsm::new(first_id)
        }
    }

    pub fn state(&self) -> State {
        self.state
    }

    pub fn is_opened(&self) -> bool {
        self.state == State::Opened
    }

    /// When the restart timer fires, if it runs.
    pub fn deadline(&self) -> Option<Millis> {
        (self.deadline != 0).then_some(self.deadline)
    }

    fn set(&mut self, s: State) {
        self.state = s;
        if !s.timed() {
            self.deadline = 0;
        }
    }

    fn take_id(&mut self) -> u8 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        id
    }

    fn arm(&mut self, ctx: &Ctx<'_>) {
        // 0 means "stopped", so a timer due at time 0 is moved to 1 ms.
        self.deadline = ctx.now.saturating_add(ctx.cfg.restart_ms).max(1);
    }

    // §4.4 actions -------------------------------------------------------

    fn irc_configure(&mut self, cfg: &FsmConfig) {
        self.restart = cfg.max_configure;
        self.failures = 0;
    }

    fn irc_terminate(&mut self, cfg: &FsmConfig) {
        self.restart = cfg.max_terminate;
    }

    fn zrc(&mut self, ctx: &Ctx<'_>) {
        self.restart = 0;
        self.arm(ctx);
    }

    fn scr<L: Layer>(&mut self, ctx: &mut Ctx<'_>, layer: &mut L) {
        let buf = &mut ctx.scratch.req;
        buf.clear();
        layer.request(buf);
        let n = buf.len().min(LAST_REQ_MAX);
        if let (Some(d), Some(s)) = (self.last_req.get_mut(..n), buf.get(..n)) {
            d.copy_from_slice(s);
        }
        // A request longer than the copy can never be matched by an Ack;
        // our layers stay far below the limit.
        self.last_req_len = if buf.len() > LAST_REQ_MAX {
            u8::MAX
        } else {
            n as u8
        };
        self.req_id = self.take_id();
        self.answered = false;
        ctx.tx
            .send(L::PROTOCOL, code::CONFIGURE_REQUEST, self.req_id, buf);
        self.restart = self.restart.saturating_sub(1);
        self.arm(ctx);
    }

    fn str_<L: Layer>(&mut self, ctx: &mut Ctx<'_>) {
        let id = self.take_id();
        ctx.tx.send(L::PROTOCOL, code::TERMINATE_REQUEST, id, &[]);
        self.restart = self.restart.saturating_sub(1);
        self.arm(ctx);
    }

    fn sta<L: Layer>(ctx: &mut Ctx<'_>, id: u8) {
        ctx.tx.send(L::PROTOCOL, code::TERMINATE_ACK, id, &[]);
    }

    fn last_req(&self) -> Option<&[u8]> {
        self.last_req.get(..usize::from(self.last_req_len))
    }

    // §4.3 events --------------------------------------------------------

    /// Up: the lower layer is ready.
    pub fn up<L: Layer>(&mut self, ctx: &mut Ctx<'_>, layer: &mut L) -> Signals {
        match self.state {
            // Initial × Up → Closed.
            State::Initial => self.set(State::Closed),
            // Starting × Up → irc, scr / Req-Sent.
            State::Starting => {
                self.irc_configure(ctx.cfg);
                self.scr(ctx, layer);
                self.set(State::ReqSent);
            }
            _ => {}
        }
        Signals::default()
    }

    /// Down: the lower layer went away.
    pub fn down(&mut self) -> Signals {
        let mut s = Signals::default();
        match self.state {
            State::Closed | State::Closing => self.set(State::Initial),
            // Stopped × Down → tls / Starting.
            State::Stopped => {
                s.tls = true;
                self.set(State::Starting);
            }
            State::Stopping | State::ReqSent | State::AckRcvd | State::AckSent => {
                self.set(State::Starting)
            }
            // Opened × Down → tld / Starting.
            State::Opened => {
                s.tld = true;
                self.set(State::Starting);
            }
            State::Initial | State::Starting => {}
        }
        s
    }

    /// Open: administrative open.
    pub fn open<L: Layer>(&mut self, ctx: &mut Ctx<'_>, layer: &mut L) -> Signals {
        let mut s = Signals::default();
        match self.state {
            // Initial × Open → tls / Starting.
            State::Initial => {
                s.tls = true;
                self.set(State::Starting);
            }
            // Closed × Open → irc, scr / Req-Sent.
            State::Closed => {
                self.irc_configure(ctx.cfg);
                self.scr(ctx, layer);
                self.set(State::ReqSent);
            }
            // Closing × Open → Stopping (the "r" restart option is not used).
            State::Closing => self.set(State::Stopping),
            _ => {}
        }
        s
    }

    /// Close: administrative close.
    pub fn close<L: Layer>(&mut self, ctx: &mut Ctx<'_>) -> Signals {
        let mut s = Signals::default();
        match self.state {
            State::Initial | State::Closed | State::Closing => {}
            // Starting × Close → tlf / Initial.
            State::Starting => {
                s.tlf = true;
                self.set(State::Initial);
            }
            State::Stopped => self.set(State::Closed),
            State::Stopping => self.set(State::Closing),
            // Req-Sent/Ack-Rcvd/Ack-Sent × Close → irc, str / Closing.
            State::ReqSent | State::AckRcvd | State::AckSent => {
                self.irc_terminate(ctx.cfg);
                self.str_::<L>(ctx);
                self.set(State::Closing);
            }
            // Opened × Close → tld, irc, str / Closing.
            State::Opened => {
                s.tld = true;
                self.irc_terminate(ctx.cfg);
                self.str_::<L>(ctx);
                self.set(State::Closing);
            }
        }
        s
    }

    /// Sends our Configure-Request again now, without waiting for the
    /// restart timer, while it is still unanswered (Req-Sent, Ack-Sent).
    /// For a request that went out before the peer was listening.
    pub fn resend_request<L: Layer>(&mut self, ctx: &mut Ctx<'_>, layer: &mut L) {
        if matches!(self.state, State::ReqSent | State::AckSent) && self.restart > 0 {
            self.scr(ctx, layer);
        }
    }

    /// Restart timer expiry; call when `now ≥ deadline()`.
    pub fn timeout<L: Layer>(&mut self, ctx: &mut Ctx<'_>, layer: &mut L) -> Signals {
        let mut s = Signals::default();
        if self.deadline == 0 || ctx.now < self.deadline {
            return s;
        }
        self.deadline = 0;
        if self.restart > 0 {
            // TO+.
            match self.state {
                State::Closing | State::Stopping => self.str_::<L>(ctx),
                State::ReqSent | State::AckRcvd => {
                    self.scr(ctx, layer);
                    self.set(State::ReqSent);
                }
                State::AckSent => self.scr(ctx, layer),
                _ => {}
            }
        } else {
            // TO-.
            match self.state {
                State::Closing => {
                    s.tlf = true;
                    self.set(State::Closed);
                }
                State::Stopping | State::ReqSent | State::AckRcvd | State::AckSent => {
                    s.tlf = true;
                    self.set(State::Stopped);
                }
                _ => {}
            }
        }
        s
    }

    /// RXJ-: a catastrophic Code-Reject or Protocol-Reject.
    pub fn reject_fatal<L: Layer>(&mut self, ctx: &mut Ctx<'_>) -> Signals {
        let mut s = Signals::default();
        match self.state {
            State::Closed | State::Stopped => s.tlf = true,
            State::Closing => {
                s.tlf = true;
                self.set(State::Closed);
            }
            State::Stopping | State::ReqSent | State::AckRcvd | State::AckSent => {
                s.tlf = true;
                self.set(State::Stopped);
            }
            // Opened × RXJ- → tld, irc, str / Stopping.
            State::Opened => {
                s.tld = true;
                self.irc_terminate(ctx.cfg);
                self.str_::<L>(ctx);
                self.set(State::Stopping);
            }
            State::Initial | State::Starting => {}
        }
        s
    }

    /// A received control packet with a code of this automaton (1–7).
    /// Codes above 7 are the caller's (LCP echo and friends); this returns
    /// `None` for them so the caller can handle or Code-Reject them.
    pub fn receive<L: Layer>(
        &mut self,
        ctx: &mut Ctx<'_>,
        layer: &mut L,
        pkt: Control<'_>,
    ) -> Option<Signals> {
        // Initial/Starting: the lower layer is not up, packets cannot
        // arrive (§4.1 "-"): drop them.
        if matches!(self.state, State::Initial | State::Starting) {
            return Some(Signals::default());
        }
        Some(match pkt.code {
            code::CONFIGURE_REQUEST => self.rcr(ctx, layer, pkt),
            code::CONFIGURE_ACK => self.rca(ctx, layer, pkt),
            code::CONFIGURE_NAK | code::CONFIGURE_REJECT => self.rcn(ctx, layer, pkt),
            code::TERMINATE_REQUEST => self.rtr::<L>(ctx, pkt.id),
            code::TERMINATE_ACK => self.rta(ctx, layer),
            code::CODE_REJECT => match pkt.data.first() {
                // RXJ- when the peer refused a code the automaton needs.
                Some(c) if (1..=7).contains(c) => self.reject_fatal::<L>(ctx),
                // RXJ+ (echo, discard…): nothing to do.
                _ => Signals::default(),
            },
            _ => return None,
        })
    }

    /// RUC: an unknown code; Code-Reject carries the rejected packet
    /// (§5.6), cut to `max` bytes (the peer's MRU less our header).
    pub fn code_reject<L: Layer>(&mut self, ctx: &mut Ctx<'_>, raw: &[u8], max: usize) {
        if matches!(self.state, State::Initial | State::Starting) {
            return;
        }
        let id = self.take_id();
        let body = raw
            .get(..max.saturating_sub(ppp::CONTROL_HEADER))
            .unwrap_or(raw);
        ctx.tx.send(L::PROTOCOL, code::CODE_REJECT, id, body);
    }

    fn rcr<L: Layer>(&mut self, ctx: &mut Ctx<'_>, layer: &mut L, pkt: Control<'_>) -> Signals {
        let mut s = Signals::default();
        match self.state {
            // Closed × RCR → sta / Closed.
            State::Closed => {
                Self::sta::<L>(ctx, pkt.id);
                return s;
            }
            State::Closing | State::Stopping => return s,
            _ => {}
        }
        // Classify; a malformed request is silently discarded (§5.1).
        let Scratch { nak, rej, .. } = &mut *ctx.scratch;
        nak.clear();
        rej.clear();
        if layer.classify(pkt.data, nak, rej).is_err() || !ppp::options_valid(pkt.data) {
            return s;
        }
        // §4.6 Max-Failure: past it, options we would Nak are rejected.
        if !nak.is_empty() && self.failures >= ctx.cfg.max_failure {
            for o in ppp::options(nak).flatten() {
                if let Some(orig) = ppp::options(pkt.data).flatten().find(|p| p.kind == o.kind) {
                    let _ = ppp::put_opt(rej, orig.kind, orig.data);
                }
            }
            nak.clear();
        }
        let reply = if !rej.is_empty() {
            Some(code::CONFIGURE_REJECT)
        } else if !nak.is_empty() {
            Some(code::CONFIGURE_NAK)
        } else {
            None
        };
        if self.state == State::Stopped {
            // Stopped × RCR± → irc, scr, sca|scn / Ack-Sent|Req-Sent.
            self.irc_configure(ctx.cfg);
            self.scr(ctx, layer);
        }
        if self.state == State::Opened {
            // Opened × RCR± → tld, scr, sca|scn.
            s.tld = true;
            self.scr(ctx, layer);
        }
        if let Some(c) = reply {
            let body = if c == code::CONFIGURE_NAK {
                self.failures = self.failures.saturating_add(1);
                &ctx.scratch.nak
            } else {
                &ctx.scratch.rej
            };
            ctx.tx.send(L::PROTOCOL, c, pkt.id, body);
            if self.state != State::AckRcvd {
                self.set(State::ReqSent);
            }
        } else {
            layer.peer_acked(pkt.data);
            ctx.tx
                .send(L::PROTOCOL, code::CONFIGURE_ACK, pkt.id, pkt.data);
            self.failures = 0;
            match self.state {
                // Ack-Rcvd × RCR+ → sca, tlu / Opened.
                State::AckRcvd => {
                    s.tlu = true;
                    self.set(State::Opened);
                }
                _ => self.set(State::AckSent),
            }
        }
        s
    }

    fn rca<L: Layer>(&mut self, ctx: &mut Ctx<'_>, layer: &mut L, pkt: Control<'_>) -> Signals {
        let mut s = Signals::default();
        // §5.2: Identifier and options must match the last request.
        // §5.2: the reply to our last request, once (pppd's `seen_ack`).
        if pkt.id != self.req_id || self.answered || self.last_req() != Some(pkt.data) {
            return s;
        }
        self.answered = true;
        match self.state {
            State::Closed | State::Stopped => Self::sta::<L>(ctx, pkt.id),
            // Req-Sent × RCA → irc / Ack-Rcvd.
            State::ReqSent => {
                layer.acked(pkt.data);
                self.irc_configure(ctx.cfg);
                self.set(State::AckRcvd);
            }
            // Ack-Rcvd × RCA → scr / Req-Sent (crossed connection).
            State::AckRcvd => {
                self.scr(ctx, layer);
                self.set(State::ReqSent);
            }
            // Ack-Sent × RCA → irc, tlu / Opened.
            State::AckSent => {
                layer.acked(pkt.data);
                self.irc_configure(ctx.cfg);
                s.tlu = true;
                self.set(State::Opened);
            }
            // Opened × RCA → tld, scr / Req-Sent.
            State::Opened => {
                s.tld = true;
                self.scr(ctx, layer);
                self.set(State::ReqSent);
            }
            _ => {}
        }
        s
    }

    fn rcn<L: Layer>(&mut self, ctx: &mut Ctx<'_>, layer: &mut L, pkt: Control<'_>) -> Signals {
        let mut s = Signals::default();
        if pkt.id != self.req_id || self.answered || !ppp::options_valid(pkt.data) {
            return s;
        }
        if pkt.code == code::CONFIGURE_REJECT {
            // §5.4: a Reject lists only options we sent.
            let Some(last) = self.last_req() else {
                return s;
            };
            let subset = ppp::options(pkt.data)
                .flatten()
                .all(|o| ppp::options(last).flatten().any(|m| m == o));
            if !subset {
                return s;
            }
        }
        self.answered = true;
        match self.state {
            State::Closed | State::Stopped => {
                Self::sta::<L>(ctx, pkt.id);
                return s;
            }
            State::Closing | State::Stopping => return s,
            _ => {}
        }
        let ok = if pkt.code == code::CONFIGURE_NAK {
            layer.naked(pkt.data);
            true
        } else {
            layer.rejected(pkt.data)
        };
        if !ok {
            s = self.close::<L>(ctx);
            s.refused = true;
            return s;
        }
        match self.state {
            // Req-Sent × RCN → irc, scr / Req-Sent.
            State::ReqSent => {
                self.irc_configure(ctx.cfg);
                self.scr(ctx, layer);
            }
            // Ack-Rcvd × RCN → scr / Req-Sent.
            State::AckRcvd => {
                self.scr(ctx, layer);
                self.set(State::ReqSent);
            }
            // Ack-Sent × RCN → irc, scr / Ack-Sent.
            State::AckSent => {
                self.irc_configure(ctx.cfg);
                self.scr(ctx, layer);
            }
            // Opened × RCN → tld, scr / Req-Sent.
            State::Opened => {
                s.tld = true;
                self.scr(ctx, layer);
                self.set(State::ReqSent);
            }
            _ => {}
        }
        s
    }

    fn rtr<L: Layer>(&mut self, ctx: &mut Ctx<'_>, id: u8) -> Signals {
        let mut s = Signals::default();
        Self::sta::<L>(ctx, id);
        match self.state {
            State::ReqSent | State::AckRcvd | State::AckSent => self.set(State::ReqSent),
            // Opened × RTR → tld, zrc, sta / Stopping.
            State::Opened => {
                s.tld = true;
                self.zrc(ctx);
                self.set(State::Stopping);
            }
            _ => {}
        }
        s
    }

    fn rta<L: Layer>(&mut self, ctx: &mut Ctx<'_>, layer: &mut L) -> Signals {
        let mut s = Signals::default();
        match self.state {
            State::Closing => {
                s.tlf = true;
                self.set(State::Closed);
            }
            State::Stopping => {
                s.tlf = true;
                self.set(State::Stopped);
            }
            State::AckRcvd => self.set(State::ReqSent),
            // Opened × RTA → tld, scr / Req-Sent.
            State::Opened => {
                s.tld = true;
                self.scr(ctx, layer);
                self.set(State::ReqSent);
            }
            _ => {}
        }
        s
    }
}

#[cfg(test)]
mod tests;
