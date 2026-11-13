//! The query log's file format (G4.1zd): what goes on disk and the reader,
//! which treats every byte as hostile (a torn write after a power cut, a
//! bad disk, a file put there by hand).
//!
//! A segment file is a run of **blocks**, each self-contained:
//!
//! ```text
//! header (40 bytes, little endian)
//!   0  magic "CRQL"
//!   4  version (1), anonymisation (0 full, 1 truncated, 2 hashed, 3 none),
//!      IPv4 prefix, IPv6 prefix (of `truncated`)
//!   8  first query, unix ms        16  last query, unix ms
//!  24  queries                     28  body length before compression
//!  32  body length on disk         36  CRC-32 of the body on disk
//! body: raw deflate (RFC 1951) of the records
//! ```
//!
//! A record is: time since the previous one (zigzag varint, ms), client
//! (varint: 0 = new, written right after; n = the n-th client of the block),
//! name (likewise, a table per block), type, rcode with flags, who answered,
//! extended error + 1 (0: none) and the time to answer in µs. A name or a
//! client is written once per block: with Zipf-distributed names a record
//! is ~17 bytes before compression and ~12 after (**medido**,
//! `docs/dns-query-log.md`), against ~29 for a compressed text line.
//!
//! The index is the headers: a reader skips a block by its length, so the
//! time range of every block of a file comes from reading 40 bytes per
//! block, and a block whose CRC or contents are wrong ends the file there
//! (what was written before it stays readable).

use std::collections::HashMap;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use flate2::Compression;
use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;

pub const MAGIC: [u8; 4] = *b"CRQL";
pub const VERSION: u8 = 1;
pub const HEADER: usize = 40;
/// Queries in a block at most (the writer closes one at [`BLOCK_QUERIES`]).
pub const MAX_QUERIES: u32 = 1 << 18;
/// Body of a block at most, before and after compression.
pub const MAX_BODY: u32 = 16 << 20;
/// The writer closes a block at this many queries.
pub const BLOCK_QUERIES: u32 = 65_536;
/// Longest name kept (RFC 1035 §2.3.4: 255 octets on the wire; its text
/// without the final dot is shorter, escapes aside).
pub const MAX_NAME: usize = 255;

/// Why a block could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FormatError {
    #[error("short block: {0} bytes")]
    Short(usize),
    #[error("not a query log block")]
    Magic,
    #[error("query log version {0} (this router reads {VERSION})")]
    Version(u8),
    #[error("block too large or empty")]
    Size,
    #[error("checksum mismatch")]
    Crc,
    #[error("bad compressed body")]
    Inflate,
    #[error("bad record {0}")]
    Record(u32),
}

/// How the clients of a block were written ([`crate::querylog::Anon`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Mode {
    Full,
    Truncated { v4: u8, v6: u8 },
    Hashed,
    None,
}

impl Mode {
    fn bytes(self) -> [u8; 3] {
        match self {
            Self::Full => [0, 32, 128],
            Self::Truncated { v4, v6 } => [1, v4, v6],
            Self::Hashed => [2, 0, 0],
            Self::None => [3, 0, 0],
        }
    }

    fn of(b: [u8; 3]) -> Option<Self> {
        match b {
            [0, ..] => Some(Self::Full),
            [1, v4, v6] if (1..=32).contains(&v4) && (1..=128).contains(&v6) => {
                Some(Self::Truncated { v4, v6 })
            }
            [2, ..] => Some(Self::Hashed),
            [3, ..] => Some(Self::None),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Truncated { .. } => "truncated",
            Self::Hashed => "hashed",
            Self::None => "none",
        }
    }
}

/// A client as written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Client {
    None,
    Addr(IpAddr),
    /// A keyed hash of the address.
    Hash(u64),
}

impl Client {
    /// As shown: the address, its network (`truncated`), `h:<16 hex>` or "".
    pub fn show(&self, mode: Mode) -> String {
        match (self, mode) {
            (Self::None, _) => String::new(),
            (Self::Hash(h), _) => format!("h:{h:016x}"),
            (Self::Addr(IpAddr::V4(a)), Mode::Truncated { v4, .. }) if v4 < 32 => format!("{a}/{v4}"),
            (Self::Addr(IpAddr::V6(a)), Mode::Truncated { v6, .. }) if v6 < 128 => format!("{a}/{v6}"),
            (Self::Addr(a), _) => a.to_string(),
        }
    }
}

/// Flags of a record.
pub const TCP: u8 = 1;
/// No reply went out (rate limit over UDP, junk).
pub const DROPPED: u8 = 2;
/// The UDP reply was truncated (TC).
pub const TRUNCATED: u8 = 4;

/// One query, as kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// Unix time, ms.
    pub at_ms: u64,
    pub client: Client,
    /// Lowercase, without the final dot (the root is "").
    pub name: String,
    pub qtype: u16,
    /// 0..=15 (the header's 4 bits).
    pub rcode: u8,
    pub flags: u8,
    /// Who answered ([`crate::querylog::BY`]).
    pub by: u8,
    /// RFC 8914 extended error the reply stands for.
    pub ede: Option<u16>,
    /// From the query read to the reply sent.
    pub latency_us: u32,
}

/// A block's header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub mode: Mode,
    pub first_ms: u64,
    pub last_ms: u64,
    pub count: u32,
    pub raw_len: u32,
    pub body_len: u32,
    pub crc: u32,
}

impl Header {
    /// Bytes of the block on disk, header included.
    pub fn len(&self) -> usize {
        HEADER + self.body_len as usize
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

fn le_u32(b: &[u8], at: usize) -> u32 {
    let mut x = [0u8; 4];
    if let Some(s) = b.get(at..at + 4) {
        x.copy_from_slice(s);
    }
    u32::from_le_bytes(x)
}

fn le_u64(b: &[u8], at: usize) -> u64 {
    let mut x = [0u8; 8];
    if let Some(s) = b.get(at..at + 8) {
        x.copy_from_slice(s);
    }
    u64::from_le_bytes(x)
}

/// The header at the start of `b`.
pub fn read_header(b: &[u8]) -> Result<Header, FormatError> {
    let h = b.get(..HEADER).ok_or(FormatError::Short(b.len()))?;
    if h.get(..4) != Some(&MAGIC[..]) {
        return Err(FormatError::Magic);
    }
    let version = h.get(4).copied().unwrap_or(0);
    if version != VERSION {
        return Err(FormatError::Version(version));
    }
    let mut m = [0u8; 3];
    if let Some(s) = h.get(5..8) {
        m.copy_from_slice(s);
    }
    let mode = Mode::of(m).ok_or(FormatError::Size)?;
    let header = Header {
        mode,
        first_ms: le_u64(h, 8),
        last_ms: le_u64(h, 16),
        count: le_u32(h, 24),
        raw_len: le_u32(h, 28),
        body_len: le_u32(h, 32),
        crc: le_u32(h, 36),
    };
    if header.count == 0
        || header.count > MAX_QUERIES
        || header.raw_len > MAX_BODY
        || header.body_len > MAX_BODY
        || header.last_ms < header.first_ms
    {
        return Err(FormatError::Size);
    }
    Ok(header)
}

/// Every record of the block at the start of `b` (header and body).
pub fn decode_block(b: &[u8]) -> Result<(Header, Vec<Record>), FormatError> {
    let h = read_header(b)?;
    let body = b.get(HEADER..h.len()).ok_or(FormatError::Short(b.len()))?;
    if crc32fast::hash(body) != h.crc {
        return Err(FormatError::Crc);
    }
    let mut raw = Vec::with_capacity(h.raw_len as usize);
    // One byte more than announced: a body that inflates past its length
    // is caught instead of trusted.
    DeflateDecoder::new(body)
        .take(u64::from(h.raw_len) + 1)
        .read_to_end(&mut raw)
        .map_err(|_| FormatError::Inflate)?;
    if raw.len() != h.raw_len as usize {
        return Err(FormatError::Inflate);
    }
    let records = decode_records(&h, &raw)?;
    Ok((h, records))
}

/// The blocks of a segment file in order, up to the first bad one (a torn
/// tail after a power cut). The error says why reading stopped early.
pub fn decode_all(mut b: &[u8]) -> (Vec<(Header, Vec<Record>)>, Option<FormatError>) {
    let mut out = Vec::new();
    while !b.is_empty() {
        match decode_block(b) {
            Ok((h, r)) => {
                b = b.get(h.len()..).unwrap_or_default();
                out.push((h, r));
            }
            Err(e) => return (out, Some(e)),
        }
    }
    (out, None)
}

/// The headers of a segment file and where each block starts, up to the
/// first one that does not fit (the time index; no body is read).
pub fn index(mut b: &[u8]) -> Vec<(usize, Header)> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while let Ok(h) = read_header(b) {
        if b.len() < h.len() {
            break;
        }
        out.push((at, h));
        at += h.len();
        b = b.get(h.len()..).unwrap_or_default();
    }
    out
}

fn varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

fn zigzag(v: i64) -> u64 {
    ((v << 1) ^ (v >> 63)) as u64
}

fn unzigzag(v: u64) -> i64 {
    ((v >> 1) as i64) ^ -((v & 1) as i64)
}

struct Cursor<'a> {
    b: &'a [u8],
    at: usize,
}

impl Cursor<'_> {
    fn byte(&mut self) -> Option<u8> {
        let x = *self.b.get(self.at)?;
        self.at += 1;
        Some(x)
    }

    fn take(&mut self, n: usize) -> Option<&[u8]> {
        let s = self.b.get(self.at..self.at.checked_add(n)?)?;
        self.at += n;
        Some(s)
    }

    fn varint(&mut self) -> Option<u64> {
        let mut v = 0u64;
        for shift in (0..64).step_by(7) {
            let x = self.byte()?;
            v |= u64::from(x & 0x7f) << shift;
            if x < 0x80 {
                return Some(v);
            }
        }
        None
    }
}

/// A name as the log keeps it: printable ASCII (the wire escapes the
/// rest), at most [`MAX_NAME`].
pub fn name_ok(n: &[u8]) -> bool {
    n.len() <= MAX_NAME && n.iter().all(|b| b.is_ascii_graphic())
}

fn decode_records(h: &Header, raw: &[u8]) -> Result<Vec<Record>, FormatError> {
    let mut c = Cursor { b: raw, at: 0 };
    let mut clients: Vec<Client> = Vec::new();
    let mut names: Vec<String> = Vec::new();
    let mut out = Vec::with_capacity(h.count as usize);
    // The first record's time is a delta from 0 (records from several
    // threads are not in order; the header has the smallest and largest).
    let mut at = 0i64;
    for i in 0..h.count {
        let bad = || FormatError::Record(i);
        let dt = unzigzag(c.varint().ok_or_else(bad)?);
        at = at.checked_add(dt).ok_or_else(bad)?;
        let at_ms = u64::try_from(at).map_err(|_| bad())?;
        if at_ms < h.first_ms || at_ms > h.last_ms {
            return Err(bad());
        }
        let client = match c.varint().ok_or_else(bad)? {
            0 => {
                let k = match c.byte().ok_or_else(bad)? {
                    0 => Client::None,
                    4 => {
                        let mut a = [0u8; 4];
                        a.copy_from_slice(c.take(4).ok_or_else(bad)?);
                        Client::Addr(IpAddr::V4(Ipv4Addr::from(a)))
                    }
                    6 => {
                        let mut a = [0u8; 16];
                        a.copy_from_slice(c.take(16).ok_or_else(bad)?);
                        Client::Addr(IpAddr::V6(Ipv6Addr::from(a)))
                    }
                    8 => {
                        let mut a = [0u8; 8];
                        a.copy_from_slice(c.take(8).ok_or_else(bad)?);
                        Client::Hash(u64::from_le_bytes(a))
                    }
                    _ => return Err(bad()),
                };
                clients.push(k);
                k
            }
            n => *usize::try_from(n - 1)
                .ok()
                .and_then(|n| clients.get(n))
                .ok_or_else(bad)?,
        };
        let name = match c.varint().ok_or_else(bad)? {
            0 => {
                let len = usize::from(c.byte().ok_or_else(bad)?);
                let n = c.take(len).ok_or_else(bad)?;
                if !name_ok(n) {
                    return Err(bad());
                }
                let n = String::from_utf8(n.to_vec()).map_err(|_| bad())?;
                names.push(n.clone());
                n
            }
            n => usize::try_from(n - 1)
                .ok()
                .and_then(|n| names.get(n))
                .ok_or_else(bad)?
                .clone(),
        };
        let qtype = u16::try_from(c.varint().ok_or_else(bad)?).map_err(|_| bad())?;
        let rf = c.byte().ok_or_else(bad)?;
        let by = c.byte().ok_or_else(bad)?;
        let ede = match c.varint().ok_or_else(bad)? {
            0 => None,
            e => Some(u16::try_from(e - 1).map_err(|_| bad())?),
        };
        let latency_us = u32::try_from(c.varint().ok_or_else(bad)?).map_err(|_| bad())?;
        out.push(Record {
            at_ms,
            client,
            name,
            qtype,
            rcode: rf & 0x0f,
            flags: rf >> 4,
            by,
            ede,
            latency_us,
        });
    }
    if c.at != raw.len() {
        return Err(FormatError::Record(h.count));
    }
    Ok(out)
}

/// A block being written: the records encoded as they come (one pass, the
/// tables grow inline).
#[derive(Debug)]
pub struct BlockBuilder {
    mode: Mode,
    raw: Vec<u8>,
    clients: HashMap<Client, u64>,
    names: HashMap<String, u64>,
    count: u32,
    first_ms: u64,
    last_ms: u64,
    prev_ms: u64,
}

impl BlockBuilder {
    pub fn new(mode: Mode) -> Self {
        Self {
            mode,
            raw: Vec::with_capacity(1 << 20),
            clients: HashMap::new(),
            names: HashMap::new(),
            count: 0,
            first_ms: 0,
            last_ms: 0,
            prev_ms: 0,
        }
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    pub fn count(&self) -> u32 {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn first_ms(&self) -> u64 {
        self.first_ms
    }

    /// Whether the block is full: [`BLOCK_QUERIES`] or ~8 MiB of body.
    pub fn full(&self) -> bool {
        self.count >= BLOCK_QUERIES || self.raw.len() >= (MAX_BODY as usize) / 2
    }

    /// Adds `r` (its name cut to [`MAX_NAME`] printable bytes; its client
    /// as the caller anonymised it).
    pub fn push(&mut self, r: &Record) {
        if self.count == 0 {
            self.first_ms = r.at_ms;
            self.last_ms = r.at_ms;
        }
        self.first_ms = self.first_ms.min(r.at_ms);
        self.last_ms = self.last_ms.max(r.at_ms);
        let o = &mut self.raw;
        varint(o, zigzag(r.at_ms as i64 - self.prev_ms as i64));
        self.prev_ms = r.at_ms;
        match self.clients.get(&r.client) {
            Some(&i) => varint(o, i + 1),
            None => {
                varint(o, 0);
                match r.client {
                    Client::None => o.push(0),
                    Client::Addr(IpAddr::V4(a)) => {
                        o.push(4);
                        o.extend_from_slice(&a.octets());
                    }
                    Client::Addr(IpAddr::V6(a)) => {
                        o.push(6);
                        o.extend_from_slice(&a.octets());
                    }
                    Client::Hash(h) => {
                        o.push(8);
                        o.extend_from_slice(&h.to_le_bytes());
                    }
                }
                let n = self.clients.len() as u64;
                self.clients.insert(r.client, n);
            }
        }
        match self.names.get(&r.name) {
            Some(&i) => varint(o, i + 1),
            None => {
                varint(o, 0);
                let kept: Vec<u8> = r
                    .name
                    .bytes()
                    .filter(u8::is_ascii_graphic)
                    .take(MAX_NAME)
                    .collect();
                o.push(kept.len() as u8);
                o.extend_from_slice(&kept);
                let n = self.names.len() as u64;
                self.names.insert(r.name.clone(), n);
            }
        }
        varint(o, u64::from(r.qtype));
        o.push((r.rcode & 0x0f) | (r.flags << 4));
        o.push(r.by);
        varint(o, r.ede.map_or(0, |e| u64::from(e) + 1));
        varint(o, u64::from(r.latency_us));
        self.count += 1;
    }

    /// The block (header and compressed body), and a fresh builder in its
    /// place. `None` when it holds nothing.
    pub fn finish(&mut self) -> Option<Vec<u8>> {
        if self.count == 0 {
            return None;
        }
        let mut enc = DeflateEncoder::new(Vec::with_capacity(self.raw.len() / 2), Compression::fast());
        std::io::Write::write_all(&mut enc, &self.raw).ok()?;
        let body = enc.finish().ok()?;
        let mut out = Vec::with_capacity(HEADER + body.len());
        out.extend_from_slice(&MAGIC);
        out.push(VERSION);
        out.extend_from_slice(&self.mode.bytes());
        out.extend_from_slice(&self.first_ms.to_le_bytes());
        out.extend_from_slice(&self.last_ms.to_le_bytes());
        out.extend_from_slice(&self.count.to_le_bytes());
        out.extend_from_slice(&u32::try_from(self.raw.len()).ok()?.to_le_bytes());
        out.extend_from_slice(&u32::try_from(body.len()).ok()?.to_le_bytes());
        out.extend_from_slice(&crc32fast::hash(&body).to_le_bytes());
        out.extend_from_slice(&body);
        *self = Self::new(self.mode);
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn rec(at_ms: u64, client: Client, name: &str) -> Record {
        Record {
            at_ms,
            client,
            name: name.into(),
            qtype: 1,
            rcode: 0,
            flags: TCP,
            by: 0,
            ede: None,
            latency_us: 120,
        }
    }

    #[test]
    fn round_trip_and_tables() {
        let a = Client::Addr("100.64.12.0".parse().unwrap());
        let b = Client::Addr("2804:f00::".parse().unwrap());
        let mut w = BlockBuilder::new(Mode::Truncated { v4: 24, v6: 56 });
        let mut rs = vec![
            rec(1_763_000_000_000, a, "www.example.com"),
            rec(1_763_000_000_005, b, "www.example.com"),
            rec(1_763_000_000_003, a, "api.example.com"),
            rec(1_763_000_000_009, Client::Hash(0xdead_beef), ""),
        ];
        rs[2].ede = Some(18);
        rs[2].rcode = 5;
        rs[2].flags = DROPPED | TRUNCATED;
        for r in &rs {
            w.push(r);
        }
        let block = w.finish().unwrap();
        assert!(w.is_empty());
        let (h, got) = decode_block(&block).unwrap();
        assert_eq!(got, rs);
        assert_eq!((h.first_ms, h.last_ms, h.count), (1_763_000_000_000, 1_763_000_000_009, 4));
        assert_eq!(h.mode, Mode::Truncated { v4: 24, v6: 56 });
        assert_eq!(a.show(h.mode), "100.64.12.0/24");
        assert_eq!(b.show(h.mode), "2804:f00::/56");
        assert_eq!(Client::Hash(1).show(h.mode), "h:0000000000000001");
    }

    #[test]
    fn torn_tail_keeps_what_came_before() {
        let mut w = BlockBuilder::new(Mode::Full);
        let mut file = Vec::new();
        for i in 0..3u64 {
            w.push(&rec(1000 + i, Client::None, "a.example"));
            file.extend(w.finish().unwrap());
        }
        let whole = file.len();
        file.truncate(whole - 3);
        let (blocks, err) = decode_all(&file);
        assert_eq!(blocks.len(), 2);
        assert!(matches!(err, Some(FormatError::Short(_))));
        assert_eq!(index(&file).len(), 2);
        // A flipped bit in the body is caught by the CRC.
        let mut flip = file.clone();
        flip[HEADER + 1] ^= 0x40;
        assert_eq!(decode_block(&flip).err(), Some(FormatError::Crc));
    }

    fn arb_client() -> impl Strategy<Value = Client> {
        prop_oneof![
            Just(Client::None),
            any::<[u8; 4]>().prop_map(|a| Client::Addr(IpAddr::from(a))),
            any::<[u8; 16]>().prop_map(|a| Client::Addr(IpAddr::from(a))),
            any::<u64>().prop_map(Client::Hash),
        ]
    }

    fn arb_record() -> impl Strategy<Value = Record> {
        (
            0u64..10_000,
            arb_client(),
            "[a-z0-9_.-]{0,80}",
            any::<u16>(),
            0u8..16,
            0u8..8,
            any::<u8>(),
            proptest::option::of(any::<u16>()),
            any::<u32>(),
        )
            .prop_map(|(t, client, name, qtype, rcode, flags, by, ede, latency_us)| Record {
                at_ms: 1_700_000_000_000 + t,
                client,
                name,
                qtype,
                rcode,
                flags,
                by,
                ede,
                latency_us,
            })
    }

    proptest! {
        #[test]
        fn any_block_round_trips(rs in proptest::collection::vec(arb_record(), 1..200)) {
            let mut w = BlockBuilder::new(Mode::Hashed);
            for r in &rs {
                w.push(r);
            }
            let block = w.finish().unwrap();
            let (_, got) = decode_block(&block).unwrap();
            prop_assert_eq!(got, rs);
        }

        /// The reader never panics and never trusts a length: whatever it
        /// accepts stays within the limits.
        #[test]
        fn hostile_bytes_never_panic(b in proptest::collection::vec(any::<u8>(), 0..512)) {
            prop_assert_eq!(fuzz_check(&b), Ok(()));
        }

        /// A valid block with bytes changed: refused or read within limits.
        #[test]
        fn mutated_blocks_never_panic(
            rs in proptest::collection::vec(arb_record(), 1..40),
            flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..8),
            fix_crc in any::<bool>(),
        ) {
            let mut w = BlockBuilder::new(Mode::Full);
            for r in &rs {
                w.push(r);
            }
            let mut block = w.finish().unwrap();
            for (at, x) in flips {
                let n = block.len();
                block[at % n] ^= x;
            }
            if fix_crc && block.len() > HEADER {
                let crc = crc32fast::hash(&block[HEADER..]);
                block[36..40].copy_from_slice(&crc.to_le_bytes());
            }
            prop_assert_eq!(fuzz_check(&block), Ok(()));
        }
    }

    /// The fuzz seeds and the crashes it found (`fuzz/seeds/dns_query_log`,
    /// `fuzz/regressions/dns_query_log`) run in every CI. With
    /// `COREROUTER_WRITE_SEEDS=1` the seeds are written again.
    #[test]
    fn fuzz_seeds_and_regressions() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fuzz");
        let seeds = root.join("seeds/dns_query_log");
        if std::env::var_os("COREROUTER_WRITE_SEEDS").is_some() {
            std::fs::create_dir_all(&seeds).unwrap();
            let mut w = BlockBuilder::new(Mode::Truncated { v4: 24, v6: 56 });
            let mut file = Vec::new();
            for b in 0..2u64 {
                for i in 0..20u64 {
                    let mut r = rec(1_763_000_000_000 + b * 100 + i, Client::Addr(IpAddr::from([100, 64, (i % 3) as u8, 0])), &format!("n{}.example.com", i % 5));
                    r.ede = (i % 4 == 0).then_some(18);
                    w.push(&r);
                }
                file.extend(w.finish().unwrap());
            }
            std::fs::write(seeds.join("two-blocks.crql"), &file).unwrap();
            std::fs::write(seeds.join("torn-tail.crql"), &file[..file.len() - 7]).unwrap();
            let mut h = BlockBuilder::new(Mode::Hashed);
            h.push(&rec(5, Client::Hash(7), ""));
            std::fs::write(seeds.join("hashed-root.crql"), h.finish().unwrap()).unwrap();
            std::fs::write(seeds.join("header-only.crql"), &file[..HEADER]).unwrap();
        }
        let mut n = 0;
        for dir in [seeds, root.join("regressions/dns_query_log")] {
            for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
                let b = std::fs::read(e.path()).unwrap();
                assert_eq!(fuzz_check(&b), Ok(()), "{}", e.path().display());
                n += 1;
            }
        }
        assert!(n >= 4, "the seeds are there ({n})");
    }

    #[test]
    fn a_body_that_inflates_past_its_length_is_refused() {
        let mut w = BlockBuilder::new(Mode::Full);
        w.push(&rec(5, Client::None, "x"));
        let mut b = w.finish().unwrap();
        // Announce a shorter raw body than the deflate stream holds.
        let raw = le_u32(&b, 28);
        b[28..32].copy_from_slice(&(raw - 1).to_le_bytes());
        assert_eq!(decode_block(&b).err(), Some(FormatError::Inflate));
    }
}

/// The fuzz oracle (`fuzz/fuzz_targets/dns_query_log.rs`): `b` as a segment
/// file never panics, and what is accepted stays within the limits.
pub fn fuzz_check(b: &[u8]) -> Result<(), String> {
    let (blocks, _) = decode_all(b);
    for (h, rs) in &blocks {
        if h.count > MAX_QUERIES || rs.len() != h.count as usize {
            return Err(format!("block of {} queries read as {}", h.count, rs.len()));
        }
        for r in rs {
            if !name_ok(r.name.as_bytes()) || r.rcode > 15 || r.at_ms < h.first_ms || r.at_ms > h.last_ms {
                return Err(format!("record out of bounds: {r:?}"));
            }
        }
    }
    let _ = index(b);
    Ok(())
}
