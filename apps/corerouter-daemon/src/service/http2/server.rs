//! The server side of HTTP/2 (RFC 9113) for DNS over HTTPS (G4.1zf, RFC
//! 8484 §5.2: HTTP/2 is the minimum RECOMMENDED version), with no I/O: the
//! caller feeds the plaintext the TLS connection read ([`Server::receive`]),
//! gets the requests that ended, answers them in any order
//! ([`Server::respond`]) and sends [`Server::take_out`].
//!
//! What a DoH server needs and nothing more:
//!
//! - the client preface, then SETTINGS both ways (§3.4): ours say
//!   MAX_CONCURRENT_STREAMS 100 (§6.5.2 recommends at least 100) and a
//!   16 KiB header list; theirs are applied (INITIAL_WINDOW_SIZE moves every
//!   open stream's window, §6.9.2; MAX_FRAME_SIZE bounds our DATA);
//! - HEADERS + CONTINUATION decoded with the connection's HPACK decoder,
//!   always (a stream refused still updates the table, RFC 7541 §2.2);
//! - DATA flow-controlled: what the client sent is given back at once with
//!   WINDOW_UPDATE (a body is at most 64 KiB); our answers wait for the
//!   client's windows (§6.9) and go out when it opens them;
//! - PING answered, PRIORITY ignored (§5.3.2), unknown frames ignored (§4.1),
//!   no push (§8.4: a server may not need it; DoH clients only take pushes
//!   they asked for, RFC 8484 §5.3).
//!
//! Hostile input ends the connection with GOAWAY: a frame over 16 KiB, a
//! header block over 16 KiB (the CONTINUATION flood, CVE-2024-27316), a
//! body over 64 KiB (413), more than [`MAX_CHURN`] reset streams
//! (rapid reset, CVE-2023-44487), PINGs or SETTINGS in the same window
//! (ENHANCE_YOUR_CALM, §7).

use std::collections::HashMap;

use super::hpack;
use super::{
    CONTINUATION, DATA, END_HEADERS, END_STREAM, GOAWAY, HEADERS, MAX_FRAME, PADDED, PING, PREFACE, PRIORITY, PUSH_PROMISE,
    RST_STREAM, SETTINGS, WINDOW_UPDATE, frame,
};

const ACK: u8 = 0x1;
/// §6.5.2.
const SETTINGS_INITIAL_WINDOW_SIZE: u16 = 0x4;
const SETTINGS_MAX_CONCURRENT_STREAMS: u16 = 0x3;
const SETTINGS_MAX_FRAME_SIZE: u16 = 0x5;
const SETTINGS_MAX_HEADER_LIST_SIZE: u16 = 0x6;
/// §7: error codes.
const PROTOCOL_ERROR: u32 = 0x1;
const FLOW_CONTROL_ERROR: u32 = 0x3;
const FRAME_SIZE_ERROR: u32 = 0x6;
const REFUSED_STREAM: u32 = 0x7;
const COMPRESSION_ERROR: u32 = 0x9;
const ENHANCE_YOUR_CALM: u32 = 0xb;
pub(crate) const NO_ERROR: u32 = 0x0;

/// Streams open at once (what our SETTINGS say).
pub(crate) const MAX_STREAMS: usize = 100;
/// A request body at most: one DNS message (RFC 8484 §6).
pub(crate) const MAX_BODY: usize = 65_535;
/// A header block at most (all HEADERS + CONTINUATION of one request).
const MAX_BLOCK: usize = 16 * 1024;
/// Streams reset or refused, PINGs and SETTINGS frames a connection may
/// spend before it is told to calm down (per connection, its whole life:
/// a DoH client makes a few per query at most).
const MAX_CHURN: u32 = 1000;
/// §6.9.1: the largest flow-control window.
const MAX_WINDOW: i64 = (1 << 31) - 1;
/// §6.9.2: the initial window both sides start with.
const DEFAULT_WINDOW: i64 = 65_535;

/// A request that ended (END_STREAM): what DoH looks at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Request {
    pub stream: u32,
    pub method: String,
    /// `:path`, with its query.
    pub path: String,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
    /// The body passed [`MAX_BODY`] (the request still gets an answer: 413).
    pub too_big: bool,
}

#[derive(Default)]
struct Stream {
    headers: Vec<hpack::Header>,
    body: Vec<u8>,
    too_big: bool,
    /// The client sent END_STREAM: it waits for our answer.
    asked: bool,
    /// Our window on this stream (the client's receive window).
    window: i64,
    /// DATA of our answer the windows did not let out yet.
    pending: Vec<u8>,
}

/// Why the connection ends (GOAWAY sent).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Gone(pub String);

/// One HTTP/2 connection, server side.
pub(crate) struct Server {
    dec: hpack::Decoder,
    inbox: Vec<u8>,
    out: Vec<u8>,
    preface_seen: bool,
    streams: HashMap<u32, Stream>,
    /// The highest stream the client opened.
    last: u32,
    /// HEADERS without END_HEADERS: (stream, block so far, END_STREAM).
    block: Option<(u32, Vec<u8>, bool)>,
    /// Our connection window (the client's).
    window: i64,
    /// The client's SETTINGS_INITIAL_WINDOW_SIZE, for new streams.
    initial: i64,
    /// The client's SETTINGS_MAX_FRAME_SIZE (what our DATA may be).
    max_frame: usize,
    churn: u32,
    /// GOAWAY received: no new streams; answer what is open.
    closing: bool,
}

impl Default for Server {
    fn default() -> Self {
        Self::new()
    }
}

impl Server {
    /// A connection that just negotiated `h2`: our SETTINGS go first
    /// (§3.4, the server preface).
    pub(crate) fn new() -> Self {
        let mut s = Self {
            dec: hpack::Decoder::default(),
            inbox: Vec::new(),
            out: Vec::new(),
            preface_seen: false,
            streams: HashMap::new(),
            last: 0,
            block: None,
            window: DEFAULT_WINDOW,
            initial: DEFAULT_WINDOW,
            max_frame: MAX_FRAME,
            churn: 0,
            closing: false,
        };
        let mut settings = Vec::new();
        for (id, v) in [
            (SETTINGS_MAX_CONCURRENT_STREAMS, u32::try_from(MAX_STREAMS).unwrap_or(100)),
            (SETTINGS_MAX_HEADER_LIST_SIZE, u32::try_from(MAX_BLOCK).unwrap_or(16_384)),
        ] {
            settings.extend_from_slice(&id.to_be_bytes());
            settings.extend_from_slice(&v.to_be_bytes());
        }
        frame(&mut s.out, SETTINGS, 0, 0, &settings);
        s
    }

    /// What goes to the client now.
    pub(crate) fn take_out(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.out)
    }

    /// Streams waiting for an answer.
    pub(crate) fn waiting(&self) -> usize {
        self.streams.values().filter(|s| s.asked).count()
    }

    /// GOAWAY with `code`; the caller closes after sending [`Self::take_out`].
    pub(crate) fn goaway(&mut self, code: u32) {
        let mut p = self.last.to_be_bytes().to_vec();
        p.extend_from_slice(&code.to_be_bytes());
        frame(&mut self.out, GOAWAY, 0, 0, &p);
    }

    fn fail(&mut self, code: u32, why: &str) -> Gone {
        self.goaway(code);
        Gone(why.to_owned())
    }

    fn reset(&mut self, stream: u32, code: u32) -> Result<(), Gone> {
        frame(&mut self.out, RST_STREAM, 0, stream, &code.to_be_bytes());
        self.streams.remove(&stream);
        self.spend()
    }

    /// One more costly frame (reset, PING, SETTINGS); past [`MAX_CHURN`],
    /// the connection goes.
    fn spend(&mut self) -> Result<(), Gone> {
        self.churn += 1;
        if self.churn > MAX_CHURN {
            return Err(self.fail(ENHANCE_YOUR_CALM, "too many resets, PINGs or SETTINGS"));
        }
        Ok(())
    }

    /// The plaintext the connection read; the requests that ended.
    pub(crate) fn receive(&mut self, bytes: &[u8]) -> Result<Vec<Request>, Gone> {
        self.inbox.extend_from_slice(bytes);
        if !self.preface_seen {
            let Some(head) = self.inbox.get(..PREFACE.len()) else {
                return if PREFACE.starts_with(&self.inbox) { Ok(Vec::new()) } else { Err(self.fail(PROTOCOL_ERROR, "no client preface")) };
            };
            if head != PREFACE {
                return Err(self.fail(PROTOCOL_ERROR, "no client preface"));
            }
            self.inbox.drain(..PREFACE.len());
            self.preface_seen = true;
        }
        let mut done = Vec::new();
        while let Some([l0, l1, l2, kind, flags, s0, s1, s2, s3]) = self.inbox.get(..9).and_then(|h| <[u8; 9]>::try_from(h).ok()) {
            let len = usize::from(l0) << 16 | usize::from(l1) << 8 | usize::from(l2);
            let id = u32::from_be_bytes([s0 & 0x7f, s1, s2, s3]);
            if len > MAX_FRAME {
                return Err(self.fail(FRAME_SIZE_ERROR, "frame over 16 KiB"));
            }
            let Some(payload) = self.inbox.get(9..9 + len).map(<[u8]>::to_vec) else { break };
            self.inbox.drain(..9 + len);
            if let Some(r) = self.on_frame(kind, flags, id, &payload)? {
                done.push(r);
            }
        }
        Ok(done)
    }

    fn on_frame(&mut self, kind: u8, flags: u8, id: u32, p: &[u8]) -> Result<Option<Request>, Gone> {
        // §6.10: nothing may come between HEADERS and its CONTINUATIONs.
        if self.block.is_some() && kind != CONTINUATION {
            return Err(self.fail(PROTOCOL_ERROR, "a frame inside a header block"));
        }
        match kind {
            SETTINGS => self.on_settings(flags, id, p).map(|()| None),
            PING => {
                if id != 0 || p.len() != 8 {
                    return Err(self.fail(PROTOCOL_ERROR, "bad PING"));
                }
                if flags & ACK == 0 {
                    self.spend()?;
                    frame(&mut self.out, PING, ACK, 0, p);
                }
                Ok(None)
            }
            WINDOW_UPDATE => self.on_window_update(id, p).map(|()| None),
            HEADERS => {
                if id == 0 || id.is_multiple_of(2) {
                    return Err(self.fail(PROTOCOL_ERROR, "HEADERS on a stream the client may not open"));
                }
                let mut b = unpad(p, flags).ok_or_else(|| self.fail(PROTOCOL_ERROR, "bad padding"))?;
                if flags & PRIORITY != 0 {
                    b = b.get(5..).ok_or_else(|| self.fail(FRAME_SIZE_ERROR, "short PRIORITY"))?;
                }
                let block = b.to_vec();
                let end = flags & END_STREAM != 0;
                if flags & END_HEADERS == 0 {
                    self.block = Some((id, block, end));
                    return Ok(None);
                }
                self.on_headers(id, &block, end)
            }
            CONTINUATION => {
                let Some((sid, mut block, end)) = self.block.take() else {
                    return Err(self.fail(PROTOCOL_ERROR, "CONTINUATION without HEADERS"));
                };
                if sid != id {
                    return Err(self.fail(PROTOCOL_ERROR, "CONTINUATION of another stream"));
                }
                block.extend_from_slice(p);
                if block.len() > MAX_BLOCK {
                    return Err(self.fail(ENHANCE_YOUR_CALM, "header block over 16 KiB"));
                }
                if flags & END_HEADERS == 0 {
                    self.block = Some((sid, block, end));
                    return Ok(None);
                }
                self.on_headers(id, &block, end)
            }
            DATA => self.on_data(flags, id, p),
            RST_STREAM => {
                if id == 0 || p.len() != 4 {
                    return Err(self.fail(PROTOCOL_ERROR, "bad RST_STREAM"));
                }
                self.streams.remove(&id);
                self.spend()?;
                Ok(None)
            }
            GOAWAY => {
                self.closing = true;
                Ok(None)
            }
            PUSH_PROMISE => Err(self.fail(PROTOCOL_ERROR, "a client may not push")),
            // PRIORITY (§5.3.2: deprecated, ignored) and unknown types (§4.1).
            _ => Ok(None),
        }
    }

    fn on_settings(&mut self, flags: u8, id: u32, p: &[u8]) -> Result<(), Gone> {
        if id != 0 || !p.len().is_multiple_of(6) {
            return Err(self.fail(FRAME_SIZE_ERROR, "bad SETTINGS"));
        }
        if flags & ACK != 0 {
            return Ok(());
        }
        self.spend()?;
        for e in p.chunks(6) {
            let Ok([k0, k1, v0, v1, v2, v3]) = <[u8; 6]>::try_from(e) else { continue };
            let k = u16::from_be_bytes([k0, k1]);
            let v = i64::from(u32::from_be_bytes([v0, v1, v2, v3]));
            match k {
                SETTINGS_INITIAL_WINDOW_SIZE => {
                    if v > MAX_WINDOW {
                        return Err(self.fail(FLOW_CONTROL_ERROR, "INITIAL_WINDOW_SIZE over 2^31-1"));
                    }
                    let delta = v - self.initial;
                    self.initial = v;
                    for s in self.streams.values_mut() {
                        s.window += delta;
                    }
                }
                SETTINGS_MAX_FRAME_SIZE => {
                    if !(16_384..=16_777_215).contains(&v) {
                        return Err(self.fail(PROTOCOL_ERROR, "bad MAX_FRAME_SIZE"));
                    }
                    self.max_frame = usize::try_from(v).unwrap_or(MAX_FRAME).min(MAX_FRAME * 4);
                }
                _ => {}
            }
        }
        frame(&mut self.out, SETTINGS, ACK, 0, &[]);
        self.flush_all();
        Ok(())
    }

    fn on_window_update(&mut self, id: u32, p: &[u8]) -> Result<(), Gone> {
        let Ok([b0, b1, b2, b3]) = <[u8; 4]>::try_from(p) else {
            return Err(self.fail(FRAME_SIZE_ERROR, "bad WINDOW_UPDATE"));
        };
        let inc = i64::from(u32::from_be_bytes([b0 & 0x7f, b1, b2, b3]));
        if id == 0 {
            if inc == 0 || self.window + inc > MAX_WINDOW {
                return Err(self.fail(FLOW_CONTROL_ERROR, "bad connection WINDOW_UPDATE"));
            }
            self.window += inc;
        } else if let Some(s) = self.streams.get_mut(&id) {
            if inc == 0 || s.window + inc > MAX_WINDOW {
                return self.reset(id, FLOW_CONTROL_ERROR);
            }
            s.window += inc;
        }
        self.flush_all();
        Ok(())
    }

    fn on_headers(&mut self, id: u32, block: &[u8], end: bool) -> Result<Option<Request>, Gone> {
        if block.len() > MAX_BLOCK {
            return Err(self.fail(ENHANCE_YOUR_CALM, "header block over 16 KiB"));
        }
        // Decoded even when the stream is refused: the HPACK table must
        // stay in step with the client's.
        let headers = self.dec.decode(block).map_err(|e| self.fail(COMPRESSION_ERROR, e.0))?;
        if let Some(s) = self.streams.get_mut(&id) {
            // Trailers: only END_STREAM matters.
            if end {
                s.asked = true;
                return Ok(Some(request(id, s)));
            }
            return Ok(None);
        }
        if id <= self.last {
            return Err(self.fail(PROTOCOL_ERROR, "a stream id that went down"));
        }
        self.last = id;
        if self.closing || self.streams.len() >= MAX_STREAMS {
            self.reset(id, REFUSED_STREAM)?;
            return Ok(None);
        }
        let mut s = Stream { headers, window: self.initial, ..Stream::default() };
        if end {
            s.asked = true;
            let r = request(id, &s);
            self.streams.insert(id, s);
            return Ok(Some(r));
        }
        self.streams.insert(id, s);
        Ok(None)
    }

    fn on_data(&mut self, flags: u8, id: u32, p: &[u8]) -> Result<Option<Request>, Gone> {
        if id == 0 {
            return Err(self.fail(PROTOCOL_ERROR, "DATA on stream 0"));
        }
        let body = unpad(p, flags).ok_or_else(|| self.fail(PROTOCOL_ERROR, "bad padding"))?;
        // What the client spent comes back at once (padding included).
        if !p.is_empty() {
            let inc = u32::try_from(p.len()).unwrap_or(0).to_be_bytes();
            frame(&mut self.out, WINDOW_UPDATE, 0, 0, &inc);
            if self.streams.contains_key(&id) && flags & END_STREAM == 0 {
                frame(&mut self.out, WINDOW_UPDATE, 0, id, &inc);
            }
        }
        let Some(s) = self.streams.get_mut(&id).filter(|s| !s.asked) else {
            // A stream we reset or already answered: §5.1 STREAM_CLOSED.
            return Ok(None);
        };
        if s.body.len() + body.len() > MAX_BODY {
            s.too_big = true;
            s.body.clear();
        } else if !s.too_big {
            s.body.extend_from_slice(body);
        }
        if flags & END_STREAM != 0 {
            s.asked = true;
            return Ok(Some(request(id, s)));
        }
        Ok(None)
    }

    /// The answer of `stream`: `:status`, the other headers, the body (none
    /// for a status without one). A stream the client reset meanwhile is
    /// skipped.
    pub(crate) fn respond(&mut self, stream: u32, status: u16, headers: &[(&str, &str)], body: &[u8]) {
        if !self.streams.contains_key(&stream) {
            return;
        }
        let status = status.to_string();
        let len = body.len().to_string();
        let mut all: Vec<(&str, &str)> = vec![(":status", status.as_str())];
        all.extend_from_slice(headers);
        all.push(("content-length", len.as_str()));
        let block = hpack::encode(&all);
        let flags = END_HEADERS | if body.is_empty() { END_STREAM } else { 0 };
        frame(&mut self.out, HEADERS, flags, stream, &block);
        if body.is_empty() {
            self.streams.remove(&stream);
            return;
        }
        if let Some(s) = self.streams.get_mut(&stream) {
            s.pending = body.to_vec();
        }
        self.flush(stream);
    }

    /// DATA of `stream` as far as both windows go; the last frame ends it.
    fn flush(&mut self, stream: u32) {
        let Some(s) = self.streams.get_mut(&stream) else { return };
        while !s.pending.is_empty() {
            let room = self.window.min(s.window).min(i64::try_from(self.max_frame).unwrap_or(16_384));
            let n = usize::try_from(room).unwrap_or(0).min(s.pending.len());
            if n == 0 {
                return;
            }
            let chunk: Vec<u8> = s.pending.drain(..n).collect();
            let last = s.pending.is_empty();
            frame(&mut self.out, DATA, if last { END_STREAM } else { 0 }, stream, &chunk);
            let spent = i64::try_from(n).unwrap_or(0);
            self.window -= spent;
            s.window -= spent;
        }
        self.streams.remove(&stream);
    }

    fn flush_all(&mut self) {
        let waiting: Vec<u32> = self.streams.iter().filter(|(_, s)| !s.pending.is_empty()).map(|(id, _)| *id).collect();
        for id in waiting {
            self.flush(id);
        }
    }
}

fn request(stream: u32, s: &Stream) -> Request {
    let get = |name: &str| s.headers.iter().find(|(n, _)| n == name).map(|(_, v)| v.clone());
    Request {
        stream,
        method: get(":method").unwrap_or_default(),
        path: get(":path").unwrap_or_default(),
        content_type: get("content-type"),
        body: s.body.clone(),
        too_big: s.too_big,
    }
}

/// §6.1: the payload without its padding.
fn unpad(p: &[u8], flags: u8) -> Option<&[u8]> {
    if flags & PADDED == 0 {
        return Some(p);
    }
    let pad = usize::from(*p.first()?);
    p.get(1..p.len().checked_sub(pad)?)
}


#[cfg(test)]
mod tests {
    use super::*;

    /// The client's preface and an empty SETTINGS.
    fn hello(extra_settings: &[u8]) -> Vec<u8> {
        let mut b = PREFACE.to_vec();
        frame(&mut b, SETTINGS, 0, 0, extra_settings);
        b
    }

    fn get(stream: u32, path: &str) -> Vec<u8> {
        let block = hpack::encode(&[(":method", "GET"), (":scheme", "https"), (":authority", "r"), (":path", path)]);
        let mut b = Vec::new();
        frame(&mut b, HEADERS, END_HEADERS | END_STREAM, stream, &block);
        b
    }

    /// Frames of `out`: (type, flags, stream, payload).
    fn frames(mut out: &[u8]) -> Vec<(u8, u8, u32, Vec<u8>)> {
        let mut v = Vec::new();
        while out.len() >= 9 {
            let len = usize::from(out[0]) << 16 | usize::from(out[1]) << 8 | usize::from(out[2]);
            let id = u32::from_be_bytes([out[5] & 0x7f, out[6], out[7], out[8]]);
            v.push((out[3], out[4], id, out[9..9 + len].to_vec()));
            out = &out[9 + len..];
        }
        v
    }

    #[test]
    fn a_get_and_a_post_are_answered_in_any_order() {
        let mut s = Server::new();
        let first = frames(&s.take_out());
        assert_eq!(first[0].0, SETTINGS, "the server preface");
        let mut b = hello(&[]);
        b.extend(get(1, "/dns-query?dns=AAAB"));
        let block = hpack::encode(&[(":method", "POST"), (":scheme", "https"), (":authority", "r"), (":path", "/dns-query"), ("content-type", "application/dns-message")]);
        frame(&mut b, HEADERS, END_HEADERS, 3, &block);
        frame(&mut b, DATA, END_STREAM, 3, b"\x12\x34abc");
        // Split anywhere: frames are reassembled.
        let (a, c) = b.split_at(30);
        let mut got = s.receive(a).unwrap();
        got.extend(s.receive(c).unwrap());
        assert_eq!(got.len(), 2);
        assert_eq!((got[0].stream, got[0].method.as_str(), got[0].path.as_str()), (1, "GET", "/dns-query?dns=AAAB"));
        assert_eq!((got[1].stream, got[1].body.as_slice()), (3, &b"\x12\x34abc"[..]));
        assert_eq!(got[1].content_type.as_deref(), Some("application/dns-message"));
        assert_eq!(s.waiting(), 2);
        let out = frames(&s.take_out());
        assert!(out.iter().any(|f| f.0 == SETTINGS && f.1 == ACK), "their SETTINGS acknowledged");
        assert!(out.iter().any(|f| f.0 == WINDOW_UPDATE && f.2 == 0), "the body's bytes given back");
        // Stream 3 first.
        s.respond(3, 200, &[("content-type", "application/dns-message")], b"answer3");
        s.respond(1, 404, &[], b"");
        let out = frames(&s.take_out());
        let mut dec = hpack::Decoder::default();
        let h3 = dec.decode(&out[0].3).unwrap();
        assert_eq!((out[0].0, out[0].2), (HEADERS, 3));
        assert!(h3.contains(&(":status".into(), "200".into())) && h3.contains(&("content-length".into(), "7".into())));
        assert_eq!((out[1].0, out[1].1, out[1].3.as_slice()), (DATA, END_STREAM, &b"answer3"[..]));
        let h1 = dec.decode(&out[2].3).unwrap();
        assert!(h1.contains(&(":status".into(), "404".into())));
        assert_eq!(out[2].1 & END_STREAM, END_STREAM, "no body: ends with the headers");
        assert_eq!(s.waiting(), 0);
    }

    #[test]
    fn answers_wait_for_the_clients_window() {
        let mut s = Server::new();
        s.take_out();
        // SETTINGS_INITIAL_WINDOW_SIZE = 4.
        let mut b = hello(&[0, 4, 0, 0, 0, 4]);
        b.extend(get(1, "/q"));
        s.receive(&b).unwrap();
        s.take_out();
        s.respond(1, 200, &[], b"0123456789");
        let out = frames(&s.take_out());
        assert_eq!(out.iter().filter(|f| f.0 == DATA).map(|f| f.3.len()).sum::<usize>(), 4);
        let mut w = Vec::new();
        frame(&mut w, WINDOW_UPDATE, 0, 1, &100u32.to_be_bytes());
        s.receive(&w).unwrap();
        let out = frames(&s.take_out());
        let data: Vec<&(u8, u8, u32, Vec<u8>)> = out.iter().filter(|f| f.0 == DATA).collect();
        assert_eq!(data.iter().map(|f| f.3.len()).sum::<usize>(), 6);
        assert_eq!(data.last().unwrap().1, END_STREAM);
    }

    #[test]
    fn hostile_clients_get_goaway() {
        // Not HTTP/2 at all.
        let mut s = Server::new();
        assert!(s.receive(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").is_err());
        // A header block that never ends (CONTINUATION flood).
        let mut s = Server::new();
        let mut b = hello(&[]);
        frame(&mut b, HEADERS, 0, 1, &[0x82]);
        for _ in 0..20 {
            frame(&mut b, CONTINUATION, 0, 1, &[0u8; 1000]);
        }
        assert!(s.receive(&b).unwrap_err().0.contains("16 KiB"));
        // Rapid reset: open and cancel, again and again.
        let mut s = Server::new();
        let mut b = hello(&[]);
        for i in 0..1100u32 {
            let id = 2 * i + 1;
            let block = hpack::encode(&[(":method", "POST"), (":path", "/q")]);
            frame(&mut b, HEADERS, END_HEADERS, id, &block);
            frame(&mut b, RST_STREAM, 0, id, &8u32.to_be_bytes());
        }
        let e = s.receive(&b).unwrap_err();
        assert!(e.0.contains("too many"), "{e:?}");
        let out = frames(&s.take_out());
        let goaway = out.iter().find(|f| f.0 == GOAWAY).unwrap();
        assert_eq!(goaway.3[4..8], ENHANCE_YOUR_CALM.to_be_bytes());
        // A stream id that goes down, and a client push.
        let mut s = Server::new();
        let mut b = hello(&[]);
        b.extend(get(5, "/q"));
        b.extend(get(3, "/q"));
        assert!(s.receive(&b).is_err());
        let mut s = Server::new();
        let mut b = hello(&[]);
        frame(&mut b, PUSH_PROMISE, END_HEADERS, 1, &[0, 0, 0, 2]);
        assert!(s.receive(&b).is_err());
    }

    #[test]
    fn streams_past_the_limit_are_refused_and_bodies_are_bounded() {
        let mut s = Server::new();
        let mut b = hello(&[]);
        for i in 0..=MAX_STREAMS {
            let id = u32::try_from(2 * i + 1).unwrap();
            let block = hpack::encode(&[(":method", "POST"), (":path", "/q")]);
            frame(&mut b, HEADERS, END_HEADERS, id, &block);
        }
        s.receive(&b).unwrap();
        let out = frames(&s.take_out());
        let refused = out.iter().find(|f| f.0 == RST_STREAM).unwrap();
        assert_eq!((refused.2, refused.3.as_slice()), (201, &REFUSED_STREAM.to_be_bytes()[..]));
        let mut b = Vec::new();
        for _ in 0..5 {
            frame(&mut b, DATA, 0, 1, &[0u8; 16_000]);
        }
        frame(&mut b, DATA, END_STREAM, 1, &[]);
        let got = s.receive(&b).unwrap();
        assert!(got[0].too_big && got[0].body.is_empty());
    }

    proptest::proptest! {
        /// Hostile bytes after a good preface never panic the server.
        #[test]
        fn any_frames_are_an_answer_not_a_panic(b in proptest::collection::vec(proptest::num::u8::ANY, 0..3000)) {
            let mut s = Server::new();
            let mut all = hello(&[]);
            all.extend(b);
            let _ = s.receive(&all);
            let _ = s.take_out();
        }
    }
}
