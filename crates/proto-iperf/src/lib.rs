//! L2 — the iperf3 test protocol, so Tools › Bandwidth Test (G6.4b) talks
//! to any `iperf3` (client or server). No sockets here: the daemon moves
//! the bytes; this crate says what they mean.
//!
//! What iperf3 (esnet/iperf, `src/iperf_api.c` and friends) puts on the
//! wire, as read from its source (spec in `docs/tools.md` §4.6):
//!
//! - **Control connection** (TCP, port [`PORT`]): the client sends a
//!   37-byte cookie ([`cookie`]: 36 characters of `a-z2-7` and a NUL);
//!   then each side moves the test on with one signed byte, a [`State`].
//! - **JSON messages**: a 4-byte big-endian length, then the JSON text
//!   ([`frame`], [`frame_len`]). The client's parameters ([`Params`]) are at
//!   most [`MAX_PARAMS_JSON`]; results ([`Results`]) have no limit upstream,
//!   we cap them at [`MAX_RESULTS_JSON`].
//! - **Data streams**: TCP streams are new connections that send the cookie
//!   first; a UDP stream starts with the 4 bytes "9876" from the client and
//!   "6789" back. Stream ids go 1, 3, 4, 5… ([`stream_ids`]).
//! - **UDP datagrams**: sender time and a sequence number up front
//!   ([`UdpHeader`]); the receiver counts loss, reordering and jitter
//!   (RFC 1889 §6.3.1) in [`UdpRx`].
//!
//! Everything read here is hostile input: lengths are bounded before any
//! allocation, numbers checked against [`Limits`], and nothing panics.

use serde_json::{Map, Value, json};

/// iperf3's default port, for the control connection and the data streams.
pub const PORT: u16 = 5201;
/// Cookie bytes on the wire: 36 characters and a NUL.
pub const COOKIE_SIZE: usize = 37;
/// Longest parameters message iperf3 accepts (`MAX_PARAMS_JSON_STRING`).
pub const MAX_PARAMS_JSON: usize = 8 * 1024;
/// Longest results message we accept (iperf3 sets no limit).
pub const MAX_RESULTS_JSON: usize = 1 << 20;
/// Most parallel streams (`MAX_STREAMS`).
pub const MAX_STREAMS: u32 = 128;
/// What a UDP stream's client sends first ("9876") and the server answers
/// ("6789"); both sides compare the bytes, whatever their endianness.
pub const UDP_CONNECT_MSG: [u8; 4] = *b"9876";
pub const UDP_CONNECT_REPLY: [u8; 4] = *b"6789";
/// The reply of servers before ~3.12: 987654321 in little-endian order.
pub const UDP_CONNECT_REPLY_LEGACY: [u8; 4] = [0xB1, 0x68, 0xDE, 0x3A];
/// UDP rate when the client gives none: 1 Mibit/s (`UDP_RATE`).
pub const DEFAULT_UDP_RATE: u64 = 1024 * 1024;
/// TCP block size (`DEFAULT_TCP_BLKSIZE`).
pub const DEFAULT_TCP_LEN: u32 = 128 * 1024;
/// UDP block size when the path MTU is not known: a 1500-byte packet.
pub const DEFAULT_UDP_LEN: u32 = 1460;
/// UDP payload bounds (`MIN_UDP_BLOCKSIZE`, `MAX_UDP_BLOCKSIZE`).
pub const MIN_UDP_LEN: u32 = 16;
pub const MAX_UDP_LEN: u32 = 65_507;
/// TCP block bounds (1 byte .. 1 MiB).
pub const MAX_TCP_LEN: u32 = 1 << 20;
/// The version we tell servers we are (the protocol has been stable since
/// 3.0; this only shows in their logs).
pub const CLIENT_VERSION: &str = "3.17 (CoreRouter)";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("the peer sent {0} bytes of JSON, more than the {1} allowed")]
    TooLong(usize, usize),
    #[error("the peer sent an empty JSON message")]
    Empty,
    #[error("the peer sent JSON that does not parse: {0}")]
    Json(String),
    #[error("{0}")]
    Bad(String),
}

/// A control-connection state (`iperf_api.h`), one signed byte on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    TestStart,
    TestRunning,
    TestEnd,
    ParamExchange,
    CreateStreams,
    ServerTerminate,
    ClientTerminate,
    ExchangeResults,
    DisplayResults,
    IperfDone,
    /// The server is busy with another test (or refused this one).
    AccessDenied,
    /// Followed by two big-endian `i32`: iperf's error code and `errno`.
    ServerError,
}

impl State {
    const TABLE: [(State, i8); 12] = [
        (State::TestStart, 1),
        (State::TestRunning, 2),
        (State::TestEnd, 4),
        (State::ParamExchange, 9),
        (State::CreateStreams, 10),
        (State::ServerTerminate, 11),
        (State::ClientTerminate, 12),
        (State::ExchangeResults, 13),
        (State::DisplayResults, 14),
        (State::IperfDone, 16),
        (State::AccessDenied, -1),
        (State::ServerError, -2),
    ];

    pub fn byte(self) -> u8 {
        Self::TABLE
            .iter()
            .find(|(s, _)| *s == self)
            .map_or(0, |(_, v)| v.to_ne_bytes()[0])
    }

    /// `None` for values iperf3 never sends (3, 5–8, 15, anything else).
    pub fn from_byte(b: u8) -> Option<Self> {
        let v = i8::from_ne_bytes([b]);
        Self::TABLE.iter().find(|(_, x)| *x == v).map(|(s, _)| *s)
    }
}

const COOKIE_ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// A cookie from 36 random bytes (`make_cookie`): each byte picks a letter
/// of `a-z2-7`, then the NUL.
pub fn cookie(random: &[u8; 36]) -> [u8; COOKIE_SIZE] {
    let mut c = [0u8; COOKIE_SIZE];
    for (out, r) in c.iter_mut().zip(random.iter()) {
        *out = COOKIE_ALPHABET
            .get(usize::from(*r) % COOKIE_ALPHABET.len())
            .copied()
            .unwrap_or(b'a');
    }
    c
}

/// Whether `c` looks like a cookie (36 printable characters and a NUL).
/// iperf3 itself accepts anything; we only use this to refuse garbage
/// early on our server.
pub fn cookie_is_valid(c: &[u8]) -> bool {
    c.len() == COOKIE_SIZE
        && c.last() == Some(&0)
        && c.iter().take(COOKIE_SIZE - 1).all(|b| b.is_ascii_graphic())
}

/// A JSON message: big-endian `u32` length, then the text (no NUL).
pub fn frame(v: &Value) -> Vec<u8> {
    let text = v.to_string();
    let len = u32::try_from(text.len()).unwrap_or(u32::MAX);
    let mut out = Vec::with_capacity(4 + text.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(text.as_bytes());
    out
}

/// The length a message header announces, if it is within `max`.
pub fn frame_len(header: [u8; 4], max: usize) -> Result<usize, Error> {
    let len = usize::try_from(u32::from_be_bytes(header)).unwrap_or(usize::MAX);
    if len == 0 {
        return Err(Error::Empty);
    }
    if len > max {
        return Err(Error::TooLong(len, max));
    }
    Ok(len)
}

/// The JSON text of a message.
pub fn parse(body: &[u8]) -> Result<Value, Error> {
    serde_json::from_slice(body).map_err(|e| {
        let mut t = e.to_string();
        t.truncate(120);
        Error::Json(t)
    })
}

/// Stream ids in creation order: 1, then 3, 4, 5… (`iperf_add_stream`,
/// a quirk iperf3 keeps for compatibility).
pub fn stream_ids(n: u32) -> Vec<u32> {
    (0..n).map(|i| if i == 0 { 1 } else { i + 2 }).collect()
}

/// TCP or UDP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    Udp,
}

/// Which way the data goes, as the client asks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Client sends, server receives (iperf3's default).
    Send,
    /// `-R`: the server sends.
    Receive,
    /// `--bidir`: both send.
    Both,
}

/// The test the client asks for (`send_parameters`).
#[derive(Debug, Clone, PartialEq)]
pub struct Params {
    pub proto: Proto,
    pub direction: Direction,
    /// Seconds (0 = until `num`/`blockcount`, which we never use).
    pub time: u32,
    pub omit: u32,
    pub parallel: u32,
    /// Block size: TCP write size, UDP payload.
    pub len: u32,
    /// Target rate per stream (bit/s); 0 = unlimited (TCP only).
    pub bandwidth: u64,
    /// IP TOS byte (DSCP << 2).
    pub tos: u8,
    /// 64-bit UDP sequence numbers (both sides must agree).
    pub udp_counters_64bit: bool,
    pub get_server_output: bool,
    pub client_version: String,
}

impl Default for Params {
    fn default() -> Self {
        Self {
            proto: Proto::Tcp,
            direction: Direction::Send,
            time: 10,
            omit: 0,
            parallel: 1,
            len: DEFAULT_TCP_LEN,
            bandwidth: 0,
            tos: 0,
            udp_counters_64bit: false,
            get_server_output: false,
            client_version: CLIENT_VERSION.into(),
        }
    }
}

/// What our server allows (and checks the client's parameters against).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_duration: u32,
    pub max_streams: u32,
    /// Total of `parallel × bandwidth × (2 if both)`, bit/s; `None` = no cap.
    /// A test asking for unlimited TCP is refused when this is set.
    pub max_rate: Option<u64>,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_duration: 60,
            max_streams: MAX_STREAMS,
            max_rate: None,
        }
    }
}

fn num(o: &Map<String, Value>, k: &str) -> Option<u64> {
    o.get(k).and_then(Value::as_u64)
}

/// iperf3 sends some flags as `true` and others as the number 1; a key of
/// the wrong type is ignored, as iperf3 does.
fn flag(o: &Map<String, Value>, k: &str) -> bool {
    match o.get(k) {
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_i64().is_some_and(|v| v != 0),
        _ => false,
    }
}

impl Params {
    /// The JSON the client sends. Flags have the types iperf3 reads
    /// (`reverse` and `bidirectional` as `true`; `udp_counters_64bit` and
    /// `get_server_output` as `1`).
    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert(
            match self.proto {
                Proto::Tcp => "tcp",
                Proto::Udp => "udp",
            }
            .into(),
            json!(true),
        );
        m.insert("omit".into(), json!(self.omit));
        m.insert("time".into(), json!(self.time));
        m.insert("num".into(), json!(0));
        m.insert("blockcount".into(), json!(0));
        m.insert("parallel".into(), json!(self.parallel));
        m.insert("len".into(), json!(self.len));
        match self.direction {
            Direction::Send => {}
            Direction::Receive => {
                m.insert("reverse".into(), json!(true));
            }
            Direction::Both => {
                m.insert("bidirectional".into(), json!(true));
            }
        }
        if self.bandwidth > 0 {
            m.insert("bandwidth".into(), json!(self.bandwidth));
        }
        if self.tos > 0 {
            m.insert("TOS".into(), json!(self.tos));
        }
        if self.udp_counters_64bit {
            m.insert("udp_counters_64bit".into(), json!(1));
        }
        if self.get_server_output {
            m.insert("get_server_output".into(), json!(1));
        }
        m.insert("client_version".into(), json!(self.client_version));
        Value::Object(m)
    }

    /// A client's parameters, checked against iperf3's own bounds and our
    /// `limits` (`get_parameters` plus the server's checks). Keys we do not
    /// use are ignored, like iperf3 ignores what it does not know.
    pub fn from_json(v: &Value, limits: &Limits) -> Result<Params, Error> {
        let o = v
            .as_object()
            .ok_or_else(|| Error::Bad("the parameters are not a JSON object".into()))?;
        let proto = if flag(o, "udp") {
            Proto::Udp
        } else if flag(o, "tcp") {
            Proto::Tcp
        } else if flag(o, "sctp") {
            return Err(Error::Bad("SCTP tests are not supported".into()));
        } else {
            Proto::Tcp
        };
        let direction = match (flag(o, "reverse"), flag(o, "bidirectional")) {
            (_, true) => Direction::Both,
            (true, false) => Direction::Receive,
            _ => Direction::Send,
        };
        let small = |k: &str, max: u64, default: u64| -> Result<u32, Error> {
            let v = num(o, k).unwrap_or(default);
            if v > max {
                return Err(Error::Bad(format!("{k} {v} is above {max}")));
            }
            u32::try_from(v).map_err(|_| Error::Bad(format!("{k} {v} is out of range")))
        };
        let time = small("time", 86_400, 10)?;
        let omit = small("omit", 600, 0)?;
        let parallel = small("parallel", u64::from(MAX_STREAMS), 1)?;
        if parallel == 0 {
            return Err(Error::Bad("parallel must be at least 1".into()));
        }
        if num(o, "num").unwrap_or(0) > 0 || num(o, "blockcount").unwrap_or(0) > 0 {
            return Err(Error::Bad(
                "tests by bytes or blocks (-n, -k) are not supported: use a time (-t)".into(),
            ));
        }
        let len = match (proto, num(o, "len")) {
            (Proto::Udp, None) => DEFAULT_UDP_LEN,
            (Proto::Tcp, None) => DEFAULT_TCP_LEN,
            (Proto::Udp, Some(l))
                if (u64::from(MIN_UDP_LEN)..=u64::from(MAX_UDP_LEN)).contains(&l) =>
            {
                u32::try_from(l).unwrap_or(DEFAULT_UDP_LEN)
            }
            (Proto::Tcp, Some(l)) if (1..=u64::from(MAX_TCP_LEN)).contains(&l) => {
                u32::try_from(l).unwrap_or(DEFAULT_TCP_LEN)
            }
            (_, Some(l)) => return Err(Error::Bad(format!("block length {l} is out of range"))),
        };
        let bandwidth = match (proto, num(o, "bandwidth")) {
            (Proto::Udp, None | Some(0)) => DEFAULT_UDP_RATE,
            (_, b) => b.unwrap_or(0),
        };
        let tos = u8::try_from(num(o, "TOS").unwrap_or(0))
            .map_err(|_| Error::Bad("TOS must be 0..255".into()))?;
        if time == 0 {
            return Err(Error::Bad("a test needs a duration (-t)".into()));
        }
        if time.saturating_add(omit) > limits.max_duration {
            return Err(Error::Bad(format!(
                "the test would run {} s; this server allows at most {} s",
                time.saturating_add(omit),
                limits.max_duration
            )));
        }
        if parallel > limits.max_streams {
            return Err(Error::Bad(format!(
                "{parallel} streams; this server allows at most {}",
                limits.max_streams
            )));
        }
        if let Some(max) = limits.max_rate {
            let ways: u64 = if direction == Direction::Both { 2 } else { 1 };
            let total = bandwidth
                .saturating_mul(u64::from(parallel))
                .saturating_mul(ways);
            if bandwidth == 0 || total > max {
                return Err(Error::Bad(format!(
                    "this server allows at most {max} bit/s in all; ask for a rate (-b) within it"
                )));
            }
        }
        Ok(Params {
            proto,
            direction,
            time,
            omit,
            parallel,
            len,
            bandwidth,
            tos,
            udp_counters_64bit: flag(o, "udp_counters_64bit"),
            get_server_output: flag(o, "get_server_output"),
            client_version: o
                .get("client_version")
                .and_then(Value::as_str)
                .map(|s| s.chars().take(32).collect())
                .unwrap_or_default(),
        })
    }
}

/// One stream's numbers in a results message.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct StreamResult {
    pub id: u32,
    pub bytes: u64,
    /// TCP retransmissions of a sender (-1: not known / receiver).
    pub retransmits: i64,
    /// UDP receiver: seconds.
    pub jitter: f64,
    /// UDP receiver: datagrams lost.
    pub errors: i64,
    /// UDP: datagrams (highest sequence seen, or sent).
    pub packets: i64,
    pub start_time: f64,
    pub end_time: f64,
}

/// A side's results (`send_results` / `get_results`).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Results {
    /// CPU used during the test, percent (iperf3's own process; ours: the
    /// whole router).
    pub cpu_util_total: f64,
    pub cpu_util_user: f64,
    pub cpu_util_system: f64,
    /// -1: this side only received; 0/1: it sent, with retransmit counts or not.
    pub sender_has_retransmits: i64,
    pub streams: Vec<StreamResult>,
    /// The server's text report, when asked (`get_server_output`).
    pub server_output_text: Option<String>,
}

/// Most streams a results message may list.
const MAX_RESULT_STREAMS: usize = 2 * MAX_STREAMS as usize;

impl Results {
    pub fn to_json(&self) -> Value {
        let streams: Vec<Value> = self
            .streams
            .iter()
            .map(|s| {
                json!({
                    "id": s.id,
                    "bytes": s.bytes,
                    "retransmits": s.retransmits,
                    "jitter": s.jitter,
                    "errors": s.errors,
                    "omitted_errors": 0,
                    "packets": s.packets,
                    "omitted_packets": 0,
                    "start_time": s.start_time,
                    "end_time": s.end_time,
                })
            })
            .collect();
        let mut v = json!({
            "cpu_util_total": self.cpu_util_total,
            "cpu_util_user": self.cpu_util_user,
            "cpu_util_system": self.cpu_util_system,
            "sender_has_retransmits": self.sender_has_retransmits,
            "streams": streams,
        });
        if let (Some(t), Value::Object(o)) = (&self.server_output_text, &mut v) {
            o.insert("server_output_text".into(), json!(t));
        }
        v
    }

    /// The peer's results. The keys iperf3 requires must be there.
    pub fn from_json(v: &Value) -> Result<Results, Error> {
        let o = v
            .as_object()
            .ok_or_else(|| Error::Bad("the results are not a JSON object".into()))?;
        let f = |k: &str| -> Result<f64, Error> {
            o.get(k)
                .and_then(Value::as_f64)
                .ok_or_else(|| Error::Bad(format!("the results lack {k}")))
        };
        let streams = o
            .get("streams")
            .and_then(Value::as_array)
            .ok_or_else(|| Error::Bad("the results lack streams".into()))?;
        if streams.len() > MAX_RESULT_STREAMS {
            return Err(Error::Bad(format!(
                "{} streams in the results",
                streams.len()
            )));
        }
        let mut out = Vec::with_capacity(streams.len());
        for s in streams {
            let i = |k: &str| -> Result<i64, Error> {
                s.get(k)
                    .and_then(Value::as_i64)
                    .ok_or_else(|| Error::Bad(format!("a stream of the results lacks {k}")))
            };
            out.push(StreamResult {
                id: u32::try_from(i("id")?).map_err(|_| Error::Bad("bad stream id".into()))?,
                bytes: u64::try_from(i("bytes")?).unwrap_or(0),
                retransmits: i("retransmits")?,
                jitter: s
                    .get("jitter")
                    .and_then(Value::as_f64)
                    .ok_or_else(|| Error::Bad("a stream of the results lacks jitter".into()))?,
                errors: i("errors")?,
                packets: i("packets")?,
                start_time: s.get("start_time").and_then(Value::as_f64).unwrap_or(0.0),
                end_time: s.get("end_time").and_then(Value::as_f64).unwrap_or(0.0),
            });
        }
        Ok(Results {
            cpu_util_total: f("cpu_util_total")?,
            cpu_util_user: f("cpu_util_user")?,
            cpu_util_system: f("cpu_util_system")?,
            sender_has_retransmits: o
                .get("sender_has_retransmits")
                .and_then(Value::as_i64)
                .ok_or_else(|| Error::Bad("the results lack sender_has_retransmits".into()))?,
            streams: out,
            server_output_text: o
                .get("server_output_text")
                .and_then(Value::as_str)
                .map(|t| t.chars().take(16 * 1024).collect()),
        })
    }
}

/// The header that starts every UDP datagram: the sender's clock and a
/// sequence number (from 1), all big-endian.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpHeader {
    pub sec: u32,
    pub usec: u32,
    pub seq: u64,
}

impl UdpHeader {
    /// Bytes it takes: 12, or 16 with 64-bit counters.
    pub fn len(counters_64bit: bool) -> usize {
        if counters_64bit { 16 } else { 12 }
    }

    /// Write it at the start of `buf` (which must hold [`Self::len`] bytes;
    /// a shorter one is left as it is).
    pub fn write(&self, buf: &mut [u8], counters_64bit: bool) {
        let Some(head) = buf.get_mut(..Self::len(counters_64bit)) else {
            return;
        };
        let mut v = Vec::with_capacity(16);
        v.extend_from_slice(&self.sec.to_be_bytes());
        v.extend_from_slice(&self.usec.to_be_bytes());
        if counters_64bit {
            v.extend_from_slice(&self.seq.to_be_bytes());
        } else {
            v.extend_from_slice(
                &u32::try_from(self.seq & 0xFFFF_FFFF)
                    .unwrap_or(0)
                    .to_be_bytes(),
            );
        }
        head.copy_from_slice(&v);
    }

    pub fn read(buf: &[u8], counters_64bit: bool) -> Option<UdpHeader> {
        let w = |at: usize| -> Option<u32> {
            Some(u32::from_be_bytes(buf.get(at..at + 4)?.try_into().ok()?))
        };
        let seq = if counters_64bit {
            u64::from_be_bytes(buf.get(8..16)?.try_into().ok()?)
        } else {
            u64::from(w(8)?)
        };
        Some(UdpHeader {
            sec: w(0)?,
            usec: w(4)?,
            seq,
        })
    }
}

/// What a UDP receiver keeps (`iperf_udp_recv`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct UdpRx {
    /// Highest sequence number seen.
    pub packet_count: u64,
    /// Datagrams lost (a gap in the sequence, less the late arrivals).
    pub errors: u64,
    pub out_of_order: u64,
    /// Seconds, smoothed as RFC 1889 §6.3.1 (A.8).
    pub jitter: f64,
    prev_transit: Option<f64>,
}

impl UdpRx {
    /// One datagram `h`, arrived at `arrival` seconds of the receiver's
    /// clock. Only differences of transit times are used, so the two
    /// clocks need not agree.
    pub fn on_datagram(&mut self, h: &UdpHeader, arrival: f64) {
        if h.seq > self.packet_count {
            self.errors = self.errors.saturating_add(h.seq - self.packet_count - 1);
            self.packet_count = h.seq;
        } else {
            self.out_of_order = self.out_of_order.saturating_add(1);
            self.errors = self.errors.saturating_sub(1);
        }
        let sent = f64::from(h.sec) + f64::from(h.usec) / 1e6;
        let transit = arrival - sent;
        let d = (transit - self.prev_transit.unwrap_or(transit)).abs();
        self.prev_transit = Some(transit);
        self.jitter += (d - self.jitter) / 16.0;
    }

    /// Loss in percent of the datagrams sent.
    pub fn loss_pct(&self) -> f64 {
        if self.packet_count == 0 {
            0.0
        } else {
            self.errors as f64 / self.packet_count as f64 * 100.0
        }
    }
}

/// iperf3's text for an error code a server sends after
/// [`State::ServerError`] (the ones a server refusing a test uses).
pub fn error_text(code: i32) -> String {
    match code {
        0 => {
            "the server reported an error (no code: an authentication failure, or it closed)".into()
        }
        6 => "the server refused the number of streams".into(),
        27 => "the server's total bit-rate limit was exceeded".into(),
        37 => "the test is longer than the server allows".into(),
        109 => "the control connection was closed".into(),
        114 => "the server could not read the parameters".into(),
        121 => "the server is busy running a test; try again later".into(),
        142 => "authorization failed".into(),
        144 => "no data arrived for too long".into(),
        160 => "the server stopped the test: its maximum duration expired".into(),
        208 => "a stream id did not match".into(),
        other => format!("the server reported error {other}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn states_round_trip_as_signed_bytes() {
        for (s, v) in State::TABLE {
            assert_eq!(State::from_byte(s.byte()), Some(s));
            assert_eq!(s.byte(), v.to_ne_bytes()[0]);
        }
        assert_eq!(State::AccessDenied.byte(), 0xFF);
        assert_eq!(State::ServerError.byte(), 0xFE);
        for unused in [0u8, 3, 5, 6, 7, 8, 15, 17, 100] {
            assert_eq!(State::from_byte(unused), None);
        }
    }

    #[test]
    fn cookies() {
        let c = cookie(&[0u8; 36]);
        assert_eq!(&c[..36], "a".repeat(36).as_bytes());
        assert_eq!(c[36], 0);
        let c = cookie(&[31u8; 36]);
        assert_eq!(c[0], b'7');
        assert!(cookie_is_valid(&c));
        assert!(!cookie_is_valid(&c[..36]));
        let mut bad = c;
        bad[3] = 0;
        assert!(!cookie_is_valid(&bad));
    }

    #[test]
    fn framing() {
        let f = frame(&json!({"tcp": true}));
        assert_eq!(&f[..4], &[0, 0, 0, 12]);
        assert_eq!(&f[4..], b"{\"tcp\":true}");
        assert_eq!(frame_len([0, 0, 0, 12], MAX_PARAMS_JSON), Ok(12));
        assert_eq!(frame_len([0, 0, 0, 0], 10), Err(Error::Empty));
        assert_eq!(
            frame_len([0, 0, 0x20, 1], MAX_PARAMS_JSON),
            Err(Error::TooLong(8193, 8192))
        );
        assert!(frame_len([0xFF; 4], MAX_RESULTS_JSON).is_err());
        assert!(parse(b"{not json").is_err());
    }

    #[test]
    fn ids_skip_two() {
        assert_eq!(stream_ids(4), vec![1, 3, 4, 5]);
        assert!(stream_ids(0).is_empty());
    }

    #[test]
    fn params_as_iperf3_sends_them() {
        // What `iperf3 -c x -u -b 10M -P 2 -R -t 5 --get-server-output` sends.
        let v = json!({"udp": true, "omit": 0, "time": 5, "num": 0, "blockcount": 0,
            "parallel": 2, "len": 1448, "reverse": true, "bandwidth": 10_000_000,
            "get_server_output": 1, "client_version": "3.16", "pacing_timer": 1000,
            "gso": 0, "gso_dg_size": 0, "gso_bf_size": 0, "gro": 0, "gro_bf_size": 0});
        let p = Params::from_json(&v, &Limits::default()).unwrap();
        assert_eq!(
            (p.proto, p.direction, p.time, p.parallel, p.len),
            (Proto::Udp, Direction::Receive, 5, 2, 1448)
        );
        assert_eq!(p.bandwidth, 10_000_000);
        assert!(p.get_server_output && !p.udp_counters_64bit);
        // Ours parses back to the same.
        let again = Params::from_json(&p.to_json(), &Limits::default()).unwrap();
        assert_eq!(again, p);
        // A flag of the wrong type is ignored, as iperf3 does.
        let p = Params::from_json(
            &json!({"tcp": true, "time": 3, "reverse": "yes"}),
            &Limits::default(),
        )
        .unwrap();
        assert_eq!(p.direction, Direction::Send);
        let p = Params::from_json(&json!({"udp": true, "time": 3}), &Limits::default()).unwrap();
        assert_eq!(
            (p.bandwidth, p.len),
            (DEFAULT_UDP_RATE, DEFAULT_UDP_LEN),
            "iperf3's UDP defaults"
        );
    }

    #[test]
    fn server_limits_refuse() {
        let lim = Limits {
            max_duration: 30,
            max_streams: 4,
            max_rate: Some(100_000_000),
        };
        let bad = [
            json!({"tcp": true, "time": 31}),
            json!({"tcp": true, "time": 20, "omit": 20}),
            json!({"tcp": true, "time": 5, "parallel": 5}),
            json!({"tcp": true, "time": 5}),
            json!({"udp": true, "time": 5, "bandwidth": 60_000_000, "bidirectional": true}),
            json!({"tcp": true, "time": 5, "num": 1000}),
            json!({"tcp": true, "time": 0}),
            json!({"tcp": true, "time": 5, "parallel": 0}),
            json!({"udp": true, "time": 5, "len": 8}),
            json!({"sctp": true, "time": 5}),
            json!({"tcp": true, "time": 5, "TOS": 300}),
            json!([1, 2]),
        ];
        for v in bad {
            assert!(Params::from_json(&v, &lim).is_err(), "accepted {v}");
        }
        assert!(
            Params::from_json(
                &json!({"udp": true, "time": 5, "bandwidth": 40_000_000, "parallel": 2}),
                &lim
            )
            .is_ok()
        );
    }

    #[test]
    fn results_round_trip_and_required_keys() {
        let r = Results {
            cpu_util_total: 12.5,
            cpu_util_user: 2.5,
            cpu_util_system: 10.0,
            sender_has_retransmits: 1,
            streams: vec![StreamResult {
                id: 1,
                bytes: 1_000_000,
                retransmits: 3,
                jitter: 0.0004,
                errors: 2,
                packets: 900,
                start_time: 0.0,
                end_time: 5.0,
            }],
            server_output_text: Some("done".into()),
        };
        assert_eq!(Results::from_json(&r.to_json()).unwrap(), r);
        let mut v = r.to_json();
        v["streams"][0].as_object_mut().unwrap().remove("jitter");
        assert!(Results::from_json(&v).is_err());
        assert!(Results::from_json(&json!({"streams": []})).is_err());
        // Pre-3.2 servers send no start/end times.
        let old = json!({"cpu_util_total": 1, "cpu_util_user": 0, "cpu_util_system": 1,
            "sender_has_retransmits": -1,
            "streams": [{"id": 1, "bytes": 5, "retransmits": -1, "jitter": 0, "errors": 0, "packets": 0}]});
        assert_eq!(Results::from_json(&old).unwrap().streams[0].end_time, 0.0);
    }

    #[test]
    fn udp_header_both_widths() {
        let h = UdpHeader {
            sec: 7,
            usec: 250_000,
            seq: 0x1_0000_0002,
        };
        let mut b = [0u8; 16];
        h.write(&mut b, true);
        assert_eq!(UdpHeader::read(&b, true), Some(h));
        h.write(&mut b, false);
        assert_eq!(&b[8..12], &[0, 0, 0, 2]);
        assert_eq!(UdpHeader::read(&b, false).unwrap().seq, 2);
        assert_eq!(UdpHeader::read(&b[..11], false), None);
        let mut short = [0u8; 4];
        h.write(&mut short, false);
        assert_eq!(short, [0; 4]);
    }

    #[test]
    fn loss_reordering_and_jitter() {
        let mut rx = UdpRx::default();
        let at = |seq: u64, sent_ms: u32| UdpHeader {
            sec: sent_ms / 1000,
            usec: (sent_ms % 1000) * 1000,
            seq,
        };
        // 1, 2, then 5 (3 and 4 missing), then 3 late.
        rx.on_datagram(&at(1, 0), 100.000);
        rx.on_datagram(&at(2, 10), 100.010);
        rx.on_datagram(&at(5, 40), 100.040);
        assert_eq!((rx.packet_count, rx.errors), (5, 2));
        rx.on_datagram(&at(3, 20), 100.050);
        assert_eq!((rx.errors, rx.out_of_order), (1, 1));
        assert!((rx.loss_pct() - 20.0).abs() < 1e-9);
        // Constant transit: no jitter until the late one (30 ms more).
        assert!((rx.jitter - 0.030 / 16.0).abs() < 1e-9, "{}", rx.jitter);
    }

    proptest! {
        #[test]
        fn hostile_params_never_panic(v in proptest::collection::btree_map("[a-z_A-Z]{1,12}", prop_oneof![
            any::<i64>().prop_map(|n| json!(n)),
            any::<bool>().prop_map(|b| json!(b)),
            any::<f64>().prop_map(|f| json!(f)),
            "[ -~]{0,20}".prop_map(|s| json!(s)),
        ], 0..12)) {
            let v = Value::Object(v.into_iter().collect());
            let _ = Params::from_json(&v, &Limits::default());
            let _ = Results::from_json(&v);
        }

        #[test]
        fn hostile_udp_headers_never_panic(b in proptest::collection::vec(any::<u8>(), 0..20), wide: bool) {
            if let Some(h) = UdpHeader::read(&b, wide) {
                let mut rx = UdpRx::default();
                rx.on_datagram(&h, 0.0);
                rx.on_datagram(&h, f64::MAX);
            }
        }
    }
}
