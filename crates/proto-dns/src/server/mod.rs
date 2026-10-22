//! The LAN forwarder (G4.1b, `allow_remote_requests`): a query from a
//! client goes through a chain of stages, each in its own file under
//! `stage/`, until one answers:
//!
//! ```text
//! acl → limit → special → adlist → static → zones → cache → upstream → statistics
//!  10     20       25        30       40      50      60       90         100
//! ```
//!
//! A stage is a `pub(crate) const STAGE: Stage` (found by `build.rs`, placed
//! by its `order`): it looks at the [`Query`], and says go on
//! ([`Step::Next`]), answer ([`Step::Reply`]), drop, or — only a stage that
//! waits on the network — [`Step::Wait`]. The chain runs on the listener's
//! thread up to the first stage that would wait; the rest runs on a worker
//! ([`Forwarder::finish`]), so a cache hit never queues behind a slow
//! upstream. Its `after` hook sees every reply (address lists, statistics).
//! How to add one: `docs/dns.md`, "Uma etapa nova".
//!
//! No sockets here either: the daemon brings bytes and a [`Transport`]. The
//! config is the running [`Config`] (each stage reads its own section) and
//! the networks `allowed_from` stands for, which the engine computes.

use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, OnceLock, RwLock};

use corerouter_model::Config;
use hickory_proto::op::{Edns, Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{DNSClass, Record, RecordType};
use ipnet::IpNet;

use crate::message::{Answer, QName};
use crate::resolver::{Resolver, Source, Transport};

include!(concat!(env!("OUT_DIR"), "/stages.rs"));

pub use statistics::{ClientStats, Counters, Snapshot, Statistics};

/// The smallest message a client must accept (RFC 1035 §4.2.1).
pub const MIN_UDP: usize = 512;
/// Longest message read from a client (RFC 1035 §4.2.2: TCP length is 16
/// bits). A query is far smaller; anything bigger is not a query.
pub const MAX_QUERY: usize = 65_535;

/// One link of the chain.
pub struct Stage {
    pub name: &'static str,
    /// Position: lower runs first. Leave gaps for stages to come.
    pub order: u16,
    /// Looks at the query. `t` is `None` on the listener's thread: a stage
    /// that needs the network returns [`Step::Wait`] then, and is called
    /// again on a worker with a transport.
    pub handle: fn(&Forwarder, &mut Query, Option<&mut dyn Transport>) -> Step,
    /// Sees every reply the chain gave (whoever answered), and drops too
    /// ([`Query::dropped`]; the reply is then a placeholder SERVFAIL).
    pub after: Option<fn(&Forwarder, &mut Query, &Reply)>,
}

/// What a stage decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    Next,
    Reply(Reply),
    /// No answer at all (floods, junk): nothing to reflect.
    Drop,
    /// Needs the network: run again on a worker.
    Wait,
}

/// An answer to a client, before encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub rcode: ResponseCode,
    pub answers: Vec<Record>,
    pub authority: Vec<Record>,
    /// AA: the router is the authority (static entries, zones).
    pub authoritative: bool,
}

impl Reply {
    pub fn code(rcode: ResponseCode) -> Self {
        Self {
            rcode,
            answers: Vec::new(),
            authority: Vec::new(),
            authoritative: false,
        }
    }

    pub fn from_answer(a: &Answer) -> Self {
        Self {
            rcode: a.rcode.code(),
            answers: a.records.clone(),
            authority: a.authority.clone(),
            authoritative: false,
        }
    }

    /// The A and AAAA addresses answered.
    pub fn addresses(&self) -> Vec<IpAddr> {
        Answer::local(crate::message::Rcode::NoError, self.answers.clone()).addresses()
    }
}

/// Something the daemon does after replying (the forwarder has no access
/// to the rest of the router).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    /// A static entry's `address_list`: add (or refresh) `address` in
    /// firewall list `list` for `timeout_secs`.
    AddressList {
        list: String,
        address: IpAddr,
        timeout_secs: u64,
    },
}

/// What the forwarder works with.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Bumped by [`Forwarder::configure`]; stages that compile config
    /// (regexps) redo it when this changes ([`Forwarder::compiled`]).
    pub generation: u64,
    pub config: Arc<Config>,
    /// What `allowed_from` stands for now (interface lists → networks).
    pub allowed: Vec<IpNet>,
}

/// One query from a client, as it goes down the chain.
#[derive(Debug, Clone)]
pub struct Query {
    pub client: IpAddr,
    pub tcp: bool,
    pub now_ms: u64,
    pub config: Arc<ServerConfig>,
    /// The name asked.
    pub asked: QName,
    /// The name being resolved: the asked one, or a static CNAME's target.
    pub name: QName,
    pub qtype: RecordType,
    /// Records answered before `name` (a static CNAME), put in front.
    pub prefix: Vec<Record>,
    /// A static FWD entry: ask these servers (or this forwarders group)
    /// instead.
    pub forward_to: Option<crate::resolver::Upstreams>,
    /// A static entry's address list, for its `after`.
    pub address_list: Option<String>,
    /// Which stage answered.
    pub answered_by: &'static str,
    /// Where the upstream stage got its answer.
    pub source: Option<Source>,
    pub effects: Vec<Effect>,
    /// The client's message (id, flags, question, EDNS), for the reply.
    request: Message,
    /// Largest reply the client takes over UDP.
    udp_limit: usize,
    reply: Option<Reply>,
    dropped: bool,
}

/// A query waiting for a worker (it needs the network).
#[derive(Debug)]
pub struct Pending {
    query: Query,
    next: usize,
}

/// The chain's result: bytes to send (none: drop) and what to do after.
#[derive(Debug, Default)]
pub struct Done {
    pub reply: Option<Vec<u8>>,
    pub effects: Vec<Effect>,
    pub answered_by: &'static str,
}

pub enum Start {
    Done(Done),
    Pending(Box<Pending>),
}

type AnyArc = Arc<dyn Any + Send + Sync>;

/// The forwarder: the shared resolver, the config, the stages' state.
pub struct Forwarder {
    pub resolver: Arc<Resolver>,
    config: RwLock<Arc<ServerConfig>>,
    states: Mutex<HashMap<TypeId, AnyArc>>,
    compiled: Mutex<HashMap<TypeId, (u64, AnyArc)>>,
}

/// A static entry's `regexp`, compiled as the forwarder matches it.
pub(crate) fn stage_statics_compile(pattern: &str) -> Result<regex::Regex, String> {
    statics::compile(pattern)
}

/// The networks `allowed_from` stands for in `cfg`: its prefixes, and the
/// networks of the addresses of each listed interface list's members
/// (an address still marked `from_pool` holds only the bits after the
/// pool's prefix and is left out). The engine passes the effective config,
/// with the DHCP-learned addresses in and the pools' addresses resolved
/// (`Session::dns_allowed_networks`, G4.1e).
pub fn allowed_networks(cfg: &Config) -> Vec<IpNet> {
    use corerouter_model::dns::AllowedFrom;
    let mut out: Vec<IpNet> = Vec::new();
    for item in &cfg.ip.dns.allowed_from {
        match AllowedFrom::parse(item) {
            Ok(AllowedFrom::Net(n)) => out.push(n),
            Ok(AllowedFrom::List(list)) => {
                for iface in cfg.interface_lists.interfaces_of(&list) {
                    out.extend(
                        cfg.ip
                            .addresses
                            .iter()
                            .filter(|a| {
                                !a.disabled && a.from_pool.is_none() && a.interface == *iface
                            })
                            .map(|a| a.address.trunc()),
                    );
                }
            }
            Err(_) => {}
        }
    }
    out.sort();
    out.dedup();
    out
}

/// The stages in chain order.
pub fn stages() -> &'static [&'static Stage] {
    static SORTED: OnceLock<Vec<&'static Stage>> = OnceLock::new();
    SORTED.get_or_init(|| {
        let mut v: Vec<&'static Stage> = FOUND.to_vec();
        v.sort_by_key(|s| s.order);
        v
    })
}

impl Forwarder {
    pub fn new(resolver: Arc<Resolver>) -> Self {
        Self {
            resolver,
            config: RwLock::new(Arc::new(ServerConfig {
                generation: 0,
                config: Arc::new(Config::default()),
                allowed: Vec::new(),
            })),
            states: Mutex::new(HashMap::new()),
            compiled: Mutex::new(HashMap::new()),
        }
    }

    /// New running config (or new networks behind `allowed_from`).
    pub fn configure(&self, config: Arc<Config>, allowed: Vec<IpNet>) {
        let mut cur = self.config.write().unwrap_or_else(|e| e.into_inner());
        let generation = cur.generation.wrapping_add(1);
        *cur = Arc::new(ServerConfig {
            generation,
            config,
            allowed,
        });
    }

    pub fn config(&self) -> Arc<ServerConfig> {
        self.config
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// The state of type `T` a stage keeps across queries (made on first
    /// use). Stages own their state: nothing to add here for a new one.
    pub fn state<T: Default + Send + Sync + 'static>(&self) -> Arc<T> {
        let mut map = self.states.lock().unwrap_or_else(|e| e.into_inner());
        let entry = map
            .entry(TypeId::of::<T>())
            .or_insert_with(|| Arc::new(T::default()) as AnyArc)
            .clone();
        drop(map);
        match entry.downcast::<T>() {
            Ok(t) => t,
            // Unreachable by construction (keyed by the type); a fresh one
            // keeps the forwarder going.
            Err(_) => Arc::new(T::default()),
        }
    }

    /// `build(config)`, made once per config generation (compiled regexps,
    /// lookup tables).
    pub fn compiled<T: Send + Sync + 'static>(
        &self,
        cfg: &ServerConfig,
        build: fn(&Config) -> T,
    ) -> Arc<T> {
        let mut map = self.compiled.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((generation, v)) = map.get(&TypeId::of::<T>())
            && *generation == cfg.generation
            && let Ok(t) = v.clone().downcast::<T>()
        {
            return t;
        }
        let t = Arc::new(build(&cfg.config));
        map.insert(TypeId::of::<T>(), (cfg.generation, t.clone() as AnyArc));
        t
    }

    /// A message from `client`: runs the chain as far as it can without
    /// waiting on the network.
    pub fn start(&self, packet: &[u8], client: IpAddr, tcp: bool, now_ms: u64) -> Start {
        let request = match parse_request(packet) {
            Ok(m) => m,
            Err(reply) => {
                return Start::Done(Done {
                    reply,
                    effects: Vec::new(),
                    answered_by: "parse",
                });
            }
        };
        let config = self.config();
        let mut query = match Query::new(request, client, tcp, now_ms, config) {
            Ok(q) => q,
            Err(reply) => {
                return Start::Done(Done {
                    reply: Some(reply),
                    effects: Vec::new(),
                    answered_by: "parse",
                });
            }
        };
        match self.run(&mut query, 0, None) {
            Some(i) => Start::Pending(Box::new(Pending { query, next: i })),
            None => Start::Done(self.done(query)),
        }
    }

    /// The rest of the chain, on a worker, with the network.
    pub fn finish(&self, p: Pending, t: &mut dyn Transport) -> Done {
        let Pending { mut query, next } = p;
        query.now_ms = t.now_ms();
        if self.run(&mut query, next, Some(t)).is_some() {
            // A stage waited although it had the network: answer anyway.
            query.reply = Some(Reply::code(ResponseCode::ServFail));
        }
        self.done(query)
    }

    /// No room for it (`max_concurrent_queries`): SERVFAIL, so the client
    /// tries its other server instead of waiting.
    pub fn fail(&self, p: Pending) -> Done {
        let mut query = p.query;
        query.answered_by = "busy";
        query.reply = Some(Reply::code(ResponseCode::ServFail));
        self.done(query)
    }

    /// Stages from `from`; `Some(i)`: stage `i` must wait for a worker.
    fn run(&self, q: &mut Query, from: usize, mut t: Option<&mut dyn Transport>) -> Option<usize> {
        let waiting = t.is_none();
        for (i, stage) in stages().iter().enumerate().skip(from) {
            let tt: Option<&mut dyn Transport> = match t {
                Some(ref mut x) => Some(&mut **x),
                None => None,
            };
            match (stage.handle)(self, q, tt) {
                Step::Next => {}
                Step::Wait if waiting => return Some(i),
                Step::Wait => {
                    q.answered_by = stage.name;
                    q.reply = Some(Reply::code(ResponseCode::ServFail));
                    return None;
                }
                Step::Drop => {
                    q.answered_by = stage.name;
                    q.dropped = true;
                    return None;
                }
                Step::Reply(mut r) => {
                    q.answered_by = stage.name;
                    if !q.prefix.is_empty() {
                        let mut all = q.prefix.clone();
                        all.append(&mut r.answers);
                        r.answers = all;
                    }
                    q.reply = Some(r);
                    return None;
                }
            }
        }
        // Nobody answered (no upstream stage?): a server failure.
        q.reply = Some(Reply::code(ResponseCode::ServFail));
        None
    }

    fn done(&self, mut q: Query) -> Done {
        let reply = q
            .reply
            .take()
            .unwrap_or_else(|| Reply::code(ResponseCode::ServFail));
        for stage in stages() {
            if let Some(after) = stage.after {
                after(self, &mut q, &reply);
            }
        }
        if q.dropped {
            return Done {
                reply: None,
                effects: q.effects,
                answered_by: q.answered_by,
            };
        }
        Done {
            reply: encode(&q, &reply),
            effects: std::mem::take(&mut q.effects),
            answered_by: q.answered_by,
        }
    }
}

impl Query {
    fn new(
        request: Message,
        client: IpAddr,
        tcp: bool,
        now_ms: u64,
        config: Arc<ServerConfig>,
    ) -> Result<Self, Vec<u8>> {
        let q = request.queries.first().cloned();
        let Some(q) = q.filter(|_| request.queries.len() == 1) else {
            // RFC 1035 §4.1.2: one question; anything else is malformed.
            return Err(error(&request, ResponseCode::FormErr));
        };
        if q.query_class() != DNSClass::IN {
            return Err(error(&request, ResponseCode::Refused));
        }
        // Zone transfers are for authoritative servers (G4.1c).
        if matches!(q.query_type(), RecordType::AXFR | RecordType::IXFR) {
            return Err(error(&request, ResponseCode::Refused));
        }
        if q.query_type() == RecordType::OPT {
            return Err(error(&request, ResponseCode::FormErr));
        }
        let max = usize::from(config.config.ip.dns.max_udp_packet_size);
        // RFC 6891 §6.2.3: the client's payload size, at least 512; we
        // never send more than our own limit.
        let udp_limit = request
            .edns
            .as_ref()
            .map_or(MIN_UDP, |e| usize::from(e.max_payload()))
            .clamp(MIN_UDP, max.max(MIN_UDP));
        let asked = QName::from_name(q.name());
        Ok(Self {
            client: client.to_canonical(),
            tcp,
            now_ms,
            config,
            name: asked.clone(),
            asked,
            qtype: q.query_type(),
            prefix: Vec::new(),
            forward_to: None,
            address_list: None,
            answered_by: "",
            source: None,
            effects: Vec::new(),
            request,
            udp_limit,
            reply: None,
            dropped: false,
        })
    }

    /// A stage dropped it: no reply goes out.
    pub fn dropped(&self) -> bool {
        self.dropped
    }

    /// The client's question was sent with EDNS(0).
    pub fn has_edns(&self) -> bool {
        self.request.edns.is_some()
    }
}

/// Reads a client's message. `Err(Some(bytes))`: answer with an error;
/// `Err(None)`: drop (not a query, or not even a header).
fn parse_request(packet: &[u8]) -> Result<Message, Option<Vec<u8>>> {
    if packet.len() < 12 || packet.len() > MAX_QUERY {
        return Err(None);
    }
    // Byte 2, bit 7: QR. A response sent to us is never answered (it could
    // be a reflection loop between two servers).
    if packet.get(2).is_some_and(|b| b & 0x80 != 0) {
        return Err(None);
    }
    match Message::from_vec(packet) {
        Ok(m) if m.metadata.message_type == MessageType::Query => {
            if m.metadata.op_code != OpCode::Query {
                return Err(Some(error(&m, ResponseCode::NotImp)));
            }
            Ok(m)
        }
        Ok(_) => Err(None),
        // RFC 1035 §4.1.1: FORMERR, echoing the id (the header is there).
        Err(_) => {
            let id = u16::from_be_bytes([
                packet.first().copied().unwrap_or(0),
                packet.get(1).copied().unwrap_or(0),
            ]);
            Err(Message::error_msg(id, OpCode::Query, ResponseCode::FormErr)
                .to_vec()
                .ok())
        }
    }
}

/// A bare error reply to `m`.
fn error(m: &Message, rcode: ResponseCode) -> Vec<u8> {
    let mut r = Message::error_msg(m.metadata.id, m.metadata.op_code, rcode);
    r.metadata.recursion_desired = m.metadata.recursion_desired;
    r.metadata.recursion_available = true;
    if m.queries.len() == 1 {
        r.add_queries(m.queries.clone());
    }
    r.to_vec().unwrap_or_default()
}

/// The reply's bytes: the client's id, question (as sent: RFC 1035
/// §2.3.3 case kept) and RD, our RA; EDNS only if the client used it
/// (RFC 6891 §7). Over UDP, a reply larger than the client takes goes
/// without records and with TC set, so it asks again over TCP (RFC 1035
/// §4.2.1, RFC 6891 §7).
fn encode(q: &Query, r: &Reply) -> Option<Vec<u8>> {
    let req = &q.request;
    let mut m = Message::response(req.metadata.id, OpCode::Query);
    m.metadata.recursion_desired = req.metadata.recursion_desired;
    m.metadata.recursion_available = true;
    m.metadata.checking_disabled = req.metadata.checking_disabled;
    m.metadata.authoritative = r.authoritative;
    m.metadata.response_code = r.rcode;
    m.add_queries(req.queries.clone());
    m.add_answers(r.answers.iter().cloned());
    m.add_authorities(r.authority.iter().cloned());
    if req.edns.is_some() {
        let mut e = Edns::new();
        e.set_max_payload(q.config.config.ip.dns.max_udp_packet_size.max(512));
        m.set_edns(e);
    }
    let bytes = m.to_vec().ok()?;
    if q.tcp || bytes.len() <= q.udp_limit {
        return Some(bytes);
    }
    m.answers.clear();
    m.authorities.clear();
    m.metadata.truncation = true;
    m.to_vec().ok()
}

#[cfg(test)]
pub(crate) mod tests;
