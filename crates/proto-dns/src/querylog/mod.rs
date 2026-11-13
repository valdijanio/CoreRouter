//! The forwarder's query log (G4.1zd, `/ip dns log`): what the chain hands
//! over for each query ([`Entry`], from the `querylog` stage), the way it
//! reaches the writer without a shared lock on the answering threads
//! ([`Sink`]), how a client is anonymised ([`Anon`]), the file format
//! ([`format`]) and what a search asks ([`Filter`]). No files and no
//! threads here: the daemon's `dns_log` service writes, rotates and reads.
//!
//! **The hot path.** Each answering thread appends its entry to a buffer
//! of its own stripe ([`STRIPES`], given round-robin like the statistics',
//! G4.1h), ~50 bytes, O(1). A full buffer ([`FLUSH_BYTES`]) goes to the
//! writer with `try_send` on a bounded channel ([`QUEUE`] buffers); when
//! the writer is behind and the channel is full the buffer is dropped and
//! counted, never waited for. **Medido** (`docs/dns-query-log.md`): ~70 ns
//! per query with 1–16 threads; one writer takes ~3 million queries/s.

pub mod format;

use std::cell::Cell;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::sync::{Mutex, MutexGuard, PoisonError};

use corerouter_model::dns_log::{ClientAddress, DnsLog};
use ipnet::IpNet;

use format::{Client, Mode, Record};

/// Who answered, by code (stable on disk: append only).
pub const BY: [&str; 12] = [
    "cache", "upstream", "stale", "static", "adlist", "zones", "special", "refused", "limit",
    "busy", "none", "other",
];

/// The code of a statistics category ([`crate::server::statistics`]).
pub fn by_code(category: &str) -> u8 {
    BY.iter()
        .position(|b| *b == category)
        .and_then(|i| u8::try_from(i).ok())
        .unwrap_or(11)
}

/// The name of code `b`.
pub fn by_name(b: u8) -> &'static str {
    BY.get(usize::from(b)).copied().unwrap_or("other")
}

/// The number of record type `name` (`AAAA`, `https`, `TYPE65`).
pub fn type_code(name: &str) -> Option<u16> {
    use std::str::FromStr;
    hickory_proto::rr::RecordType::from_str(&name.to_ascii_uppercase())
        .ok()
        .map(u16::from)
        .or_else(|| name.to_ascii_uppercase().strip_prefix("TYPE")?.parse().ok())
}

/// One query as the chain saw it (the daemon adds the time to answer).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The forwarder's clock (ms since the daemon started).
    pub at_ms: u64,
    pub client: IpAddr,
    /// Lowercase, no final dot.
    pub name: String,
    pub qtype: u16,
    pub rcode: u8,
    /// [`format::TCP`], [`format::DROPPED`], [`format::TRUNCATED`].
    pub flags: u8,
    pub by: u8,
    pub ede: Option<u16>,
}

/// Stripes of buffers (threads appending at once without waiting).
pub const STRIPES: usize = 16;
/// A stripe's buffer goes to the writer at this size.
pub const FLUSH_BYTES: usize = 16 << 10;
/// Full buffers waiting for the writer, at most (~4 MiB).
pub const QUEUE: usize = 256;

/// Buffers handed to the writer.
#[derive(Debug, Default)]
pub struct Batch {
    pub bytes: Vec<u8>,
    pub entries: u32,
}

#[derive(Default)]
#[repr(align(128))]
struct Stripe(Mutex<Batch>);

/// Where the answering threads put their entries.
pub struct Sink {
    stripes: Vec<Stripe>,
    tx: SyncSender<Batch>,
    rx: Mutex<Receiver<Batch>>,
    on: AtomicBool,
    accepted: AtomicU64,
    dropped: AtomicU64,
}

impl Default for Sink {
    fn default() -> Self {
        let (tx, rx) = sync_channel(QUEUE);
        Self {
            stripes: (0..STRIPES).map(|_| Stripe::default()).collect(),
            tx,
            rx: Mutex::new(rx),
            on: AtomicBool::new(false),
            accepted: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
        }
    }
}

thread_local! {
    static MY_STRIPE: Cell<usize> = const { Cell::new(usize::MAX) };
}
static NEXT_STRIPE: AtomicUsize = AtomicUsize::new(0);

fn my_stripe() -> usize {
    MY_STRIPE.with(|s| {
        let mine = s.get();
        if mine != usize::MAX {
            return mine;
        }
        let given = NEXT_STRIPE.fetch_add(1, Ordering::Relaxed) % STRIPES;
        s.set(given);
        given
    })
}

fn locked<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Sink {
    /// Whether entries are taken (the writer turns it on when it has
    /// somewhere to write; off, [`Sink::push`] returns at once).
    pub fn set_on(&self, on: bool) {
        self.on.store(on, Ordering::Relaxed);
    }

    pub fn is_on(&self) -> bool {
        self.on.load(Ordering::Relaxed)
    }

    /// Entries taken and entries dropped because the writer was behind
    /// (its queue full), since the start.
    pub fn counts(&self) -> (u64, u64) {
        (
            self.accepted.load(Ordering::Relaxed),
            self.dropped.load(Ordering::Relaxed),
        )
    }

    /// One query, answered (or dropped) in `latency_us`.
    pub fn push(&self, e: &Entry, latency_us: u32) {
        if !self.is_on() {
            return;
        }
        let n = self.stripes.len();
        let mine = my_stripe();
        let mut guard = None;
        for k in 0..n {
            if let Some(s) = self.stripes.get((mine + k) % n) {
                match s.0.try_lock() {
                    Ok(g) => {
                        guard = Some(g);
                        break;
                    }
                    Err(std::sync::TryLockError::Poisoned(p)) => {
                        guard = Some(p.into_inner());
                        break;
                    }
                    Err(std::sync::TryLockError::WouldBlock) => {}
                }
            }
        }
        let mut g = match guard {
            Some(g) => g,
            None => match self.stripes.get(mine % n.max(1)) {
                Some(s) => locked(&s.0),
                None => return,
            },
        };
        encode_entry(&mut g.bytes, e, latency_us);
        g.entries += 1;
        self.accepted.fetch_add(1, Ordering::Relaxed);
        if g.bytes.len() >= FLUSH_BYTES {
            let full = std::mem::replace(
                &mut *g,
                Batch {
                    bytes: Vec::with_capacity(FLUSH_BYTES + 512),
                    entries: 0,
                },
            );
            drop(g);
            if let Err(TrySendError::Full(b) | TrySendError::Disconnected(b)) =
                self.tx.try_send(full)
            {
                self.dropped
                    .fetch_add(u64::from(b.entries), Ordering::Relaxed);
            }
        }
    }

    /// Everything waiting: the full buffers, then what each stripe holds
    /// (so a quiet router's entries do not wait for a buffer to fill).
    pub fn drain(&self) -> Vec<Batch> {
        let mut out = Vec::new();
        {
            let rx = locked(&self.rx);
            while let Ok(b) = rx.try_recv() {
                out.push(b);
            }
        }
        for s in &self.stripes {
            let mut g = locked(&s.0);
            if g.entries > 0 {
                out.push(std::mem::take(&mut *g));
            }
        }
        out
    }
}

fn encode_entry(o: &mut Vec<u8>, e: &Entry, latency_us: u32) {
    o.extend_from_slice(&e.at_ms.to_le_bytes());
    o.extend_from_slice(&latency_us.to_le_bytes());
    match e.client {
        IpAddr::V4(a) => {
            o.push(4);
            o.extend_from_slice(&a.octets());
        }
        IpAddr::V6(a) => {
            o.push(6);
            o.extend_from_slice(&a.octets());
        }
    }
    o.extend_from_slice(&e.qtype.to_le_bytes());
    o.push(e.rcode);
    o.push(e.flags);
    o.push(e.by);
    o.extend_from_slice(&e.ede.map_or(u32::MAX, u32::from).to_le_bytes());
    let name = e.name.as_bytes();
    let name = name
        .get(..name.len().min(format::MAX_NAME))
        .unwrap_or_default();
    o.push(name.len() as u8);
    o.extend_from_slice(name);
}

/// The entries of a batch with their time to answer (a bad tail, which
/// [`Sink::push`] never writes, ends it).
pub fn decode_batch(b: &[u8]) -> Vec<(Entry, u32)> {
    let mut out = Vec::new();
    let mut at = 0usize;
    let mut take = |n: usize| -> Option<&[u8]> {
        let s = b.get(at..at.checked_add(n)?)?;
        at += n;
        Some(s)
    };
    let mut one = || -> Option<(Entry, u32)> {
        let mono = u64::from_le_bytes(take(8)?.try_into().ok()?);
        let lat = u32::from_le_bytes(take(4)?.try_into().ok()?);
        let client = match take(1)?.first()? {
            4 => IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(take(4)?).ok()?)),
            6 => IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(take(16)?).ok()?)),
            _ => return None,
        };
        let qtype = u16::from_le_bytes(take(2)?.try_into().ok()?);
        let f = take(3)?;
        let (rcode, flags, by) = (*f.first()?, *f.get(1)?, *f.get(2)?);
        let ede = u32::from_le_bytes(take(4)?.try_into().ok()?);
        let len = usize::from(*take(1)?.first()?);
        let name = String::from_utf8(take(len)?.to_vec()).ok()?;
        Some((
            Entry {
                at_ms: mono,
                client,
                name,
                qtype,
                rcode,
                flags,
                by,
                ede: u16::try_from(ede).ok(),
            },
            lat,
        ))
    };
    while let Some(e) = one() {
        out.push(e);
    }
    out
}

/// How clients are written now: the mode, the prefixes, and for `hashed`
/// the key (random, kept in memory only, replaced every
/// `salt_rotation_hours` by the writer).
#[derive(Clone)]
pub struct Anon {
    mode: Mode,
    key: [u8; 16],
}

impl std::fmt::Debug for Anon {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The key never goes into a log line.
        f.debug_struct("Anon")
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

impl Anon {
    pub fn new(cfg: &DnsLog, key: [u8; 16]) -> Self {
        let mode = match cfg.client_address {
            ClientAddress::Full => Mode::Full,
            ClientAddress::Truncated => Mode::Truncated {
                v4: cfg.ipv4_prefix.clamp(1, 32),
                v6: cfg.ipv6_prefix.clamp(1, 128),
            },
            ClientAddress::Hashed => Mode::Hashed,
            ClientAddress::None => Mode::None,
        };
        Self { mode, key }
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// `ip` as it is written.
    pub fn client(&self, ip: IpAddr) -> Client {
        match self.mode {
            Mode::Full => Client::Addr(ip),
            Mode::Truncated { v4, v6 } => Client::Addr(truncate(ip, v4, v6)),
            Mode::Hashed => {
                use std::hash::Hasher;
                let mut h = siphasher::sip::SipHasher13::new_with_key(&self.key);
                match ip {
                    IpAddr::V4(a) => h.write(&a.octets()),
                    IpAddr::V6(a) => h.write(&a.octets()),
                }
                Client::Hash(h.finish())
            }
            Mode::None => Client::None,
        }
    }
}

/// `ip` with only its first `v4` / `v6` bits (RFC 6235 §4.1.1).
pub fn truncate(ip: IpAddr, v4: u8, v6: u8) -> IpAddr {
    match ip {
        IpAddr::V4(a) => {
            let mask = u32::MAX
                .checked_shl(32 - u32::from(v4.min(32)))
                .unwrap_or(0);
            IpAddr::V4(Ipv4Addr::from(u32::from(a) & mask))
        }
        IpAddr::V6(a) => {
            let mask = u128::MAX
                .checked_shl(128 - u32::from(v6.min(128)))
                .unwrap_or(0);
            IpAddr::V6(Ipv6Addr::from(u128::from(a) & mask))
        }
    }
}

/// Which client a search wants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientMatch {
    /// An address or a network: matches a full address inside it, and a
    /// truncated one whose network overlaps it.
    Net(IpNet),
    /// `h:<hex>` of a `hashed` log.
    Hash(u64),
}

impl ClientMatch {
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        if let Some(h) = s.strip_prefix("h:") {
            return u64::from_str_radix(h, 16)
                .map(Self::Hash)
                .map_err(|_| "h: needs 16 hex digits".into());
        }
        if let Ok(n) = s.parse::<IpNet>() {
            return Ok(Self::Net(n.trunc()));
        }
        s.parse::<IpAddr>()
            .map(|a| Self::Net(IpNet::from(a.to_canonical())))
            .map_err(|_| "an address, a network or h:<hash>".into())
    }

    pub fn matches(&self, c: &Client, mode: Mode) -> bool {
        match (self, c) {
            (Self::Hash(want), Client::Hash(h)) => want == h,
            (Self::Net(want), Client::Addr(a)) => {
                let len = match (mode, a) {
                    (Mode::Truncated { v4, .. }, IpAddr::V4(_)) => v4,
                    (Mode::Truncated { v6, .. }, IpAddr::V6(_)) => v6,
                    (_, IpAddr::V4(_)) => 32,
                    (_, IpAddr::V6(_)) => 128,
                };
                let Ok(have) = IpNet::new(*a, len) else {
                    return false;
                };
                want.contains(&have) || have.contains(want)
            }
            _ => false,
        }
    }
}

/// What a search keeps.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Filter {
    /// Unix ms, inclusive.
    pub from_ms: Option<u64>,
    pub to_ms: Option<u64>,
    pub client: Option<ClientMatch>,
    /// `*.example.com`: the name and everything under it; otherwise the
    /// name contains the text.
    pub name: Option<String>,
    pub qtype: Option<u16>,
    /// 0..=15, or [`RCODE_DROPPED`].
    pub rcode: Option<u8>,
    pub by: Option<u8>,
}

/// `rcode` filter for queries that got no reply.
pub const RCODE_DROPPED: u8 = 16;

impl Filter {
    /// Whether a block with queries from `first` to `last` may hold a match.
    pub fn overlaps(&self, first: u64, last: u64) -> bool {
        self.from_ms.is_none_or(|f| last >= f) && self.to_ms.is_none_or(|t| first <= t)
    }

    pub fn matches(&self, r: &Record, mode: Mode) -> bool {
        if self.from_ms.is_some_and(|f| r.at_ms < f) || self.to_ms.is_some_and(|t| r.at_ms > t) {
            return false;
        }
        if self.qtype.is_some_and(|t| t != r.qtype) || self.by.is_some_and(|b| b != r.by) {
            return false;
        }
        match self.rcode {
            Some(RCODE_DROPPED) if r.flags & format::DROPPED == 0 => return false,
            Some(c) if c != RCODE_DROPPED && (c != r.rcode || r.flags & format::DROPPED != 0) => {
                return false;
            }
            _ => {}
        }
        if let Some(n) = &self.name {
            let ok = match n.strip_prefix("*.") {
                Some(parent) => corerouter_model::dns_log::is_under(&r.name, parent),
                None => r.name.contains(n.as_str()),
            };
            if !ok {
                return false;
            }
        }
        self.client
            .as_ref()
            .is_none_or(|c| c.matches(&r.client, mode))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn entry(i: u32) -> Entry {
        Entry {
            at_ms: u64::from(i),
            client: IpAddr::from([100, 64, 1, (i % 250) as u8]),
            name: format!("n{i}.example.com"),
            qtype: 28,
            rcode: 3,
            flags: format::TCP,
            by: by_code("upstream"),
            ede: if i.is_multiple_of(2) { Some(22) } else { None },
        }
    }

    #[test]
    fn off_takes_nothing() {
        let s = Sink::default();
        s.push(&entry(1), 10);
        assert!(s.drain().is_empty());
        assert_eq!(s.counts(), (0, 0));
    }

    #[test]
    fn entries_reach_the_writer_in_order_per_thread() {
        let s = Sink::default();
        s.set_on(true);
        for i in 0..1000 {
            s.push(&entry(i), i);
        }
        let got: Vec<(Entry, u32)> = s
            .drain()
            .iter()
            .flat_map(|b| decode_batch(&b.bytes))
            .collect();
        assert_eq!(got.len(), 1000);
        for (i, (e, lat)) in got.iter().enumerate() {
            assert_eq!(*e, entry(i as u32));
            assert_eq!(*lat, i as u32);
        }
        assert_eq!(s.counts(), (1000, 0));
    }

    #[test]
    fn a_full_queue_drops_and_counts_never_waits() {
        let s = Arc::new(Sink::default());
        s.set_on(true);
        let per = 200_000u32;
        std::thread::scope(|sc| {
            for _ in 0..4 {
                let s = s.clone();
                sc.spawn(move || {
                    for i in 0..per {
                        s.push(&entry(i), 1);
                    }
                });
            }
        });
        let kept: u64 = s.drain().iter().map(|b| u64::from(b.entries)).sum();
        let (accepted, dropped) = s.counts();
        assert_eq!(accepted, 4 * u64::from(per));
        assert!(dropped > 0, "nobody drained: the queue filled");
        assert_eq!(kept + dropped, accepted);
    }

    #[test]
    fn anonymisation() {
        let cfg = DnsLog::default();
        let a = Anon::new(&cfg, [7; 16]);
        assert_eq!(
            a.client("100.64.12.34".parse().unwrap()),
            Client::Addr("100.64.12.0".parse().unwrap())
        );
        assert_eq!(
            a.client("2804:f00:1234:5678:9abc::1".parse().unwrap()),
            Client::Addr("2804:f00:1234:5600::".parse().unwrap())
        );
        let h = |key, ip: &str| {
            let cfg = DnsLog {
                client_address: ClientAddress::Hashed,
                ..DnsLog::default()
            };
            Anon::new(&cfg, key).client(ip.parse().unwrap())
        };
        assert_eq!(h([1; 16], "10.0.0.1"), h([1; 16], "10.0.0.1"));
        assert_ne!(
            h([1; 16], "10.0.0.1"),
            h([2; 16], "10.0.0.1"),
            "a new key unlinks"
        );
        assert_ne!(h([1; 16], "10.0.0.1"), h([1; 16], "10.0.0.2"));
        assert!(!format!("{:?}", Anon::new(&cfg, [9; 16])).contains('9'));
        assert_eq!(
            truncate("1.2.3.4".parse().unwrap(), 32, 128),
            "1.2.3.4".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            truncate("1.2.3.4".parse().unwrap(), 0, 0),
            "0.0.0.0".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn filters() {
        let mode = Mode::Truncated { v4: 24, v6: 56 };
        let r = Record {
            at_ms: 1000,
            client: Client::Addr("100.64.12.0".parse().unwrap()),
            name: "www.example.com".into(),
            qtype: 1,
            rcode: 3,
            flags: 0,
            by: by_code("cache"),
            ede: None,
            latency_us: 5,
        };
        let f = |f: Filter| f.matches(&r, mode);
        assert!(f(Filter::default()));
        let client = |s| Filter {
            client: Some(ClientMatch::parse(s).unwrap()),
            ..Filter::default()
        };
        assert!(
            f(client("100.64.12.34")),
            "a host inside the truncated network"
        );
        assert!(f(client("100.64.0.0/10")));
        assert!(!f(client("100.64.13.1")));
        assert!(!f(client("h:0000000000000001")));
        let name = |s: &str| Filter {
            name: Some(s.into()),
            ..Filter::default()
        };
        assert!(f(name("*.example.com")) && f(name("example")) && !f(name("*.example.org")));
        assert!(f(Filter {
            rcode: Some(3),
            ..Filter::default()
        }));
        assert!(!f(Filter {
            rcode: Some(RCODE_DROPPED),
            ..Filter::default()
        }));
        assert!(!f(Filter {
            from_ms: Some(1001),
            ..Filter::default()
        }));
        assert!(f(Filter {
            by: Some(by_code("cache")),
            qtype: Some(1),
            ..Filter::default()
        }));
        assert!(ClientMatch::parse("nope").is_err());
        assert_eq!(by_name(by_code("adlist")), "adlist");
        assert_eq!(by_code("a stage to come"), 11);
        assert_eq!(
            (
                type_code("aaaa"),
                type_code("HTTPS"),
                type_code("TYPE65534"),
                type_code("nope")
            ),
            (Some(28), Some(65), Some(65534), None)
        );
    }
}
