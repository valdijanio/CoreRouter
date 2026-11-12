//! A small HTTP/2 client (RFC 9113) over the TLS streams of `https.rs`,
//! blocking, for DNS over HTTPS (RFC 8484 §5.2: HTTP/2 is the minimum
//! RECOMMENDED version). Some DoH servers speak nothing else: Unbound's
//! DoH (`https-port`) is HTTP/2 only, and our HTTP/1.1 POST got nothing
//! from it (G4.1s, found by the G4.1r lab). Not a service: no `SERVICE`.
//!
//! One request at a time per connection, each on a new stream (1, 3, 5…);
//! the connection is kept for the next query (`dns_secure.rs` pools it).
//! What a client must handle and nothing more:
//!
//! - the preface and SETTINGS both ways, SETTINGS and PING acknowledged
//!   (§3.4, §6.5.3, §6.7); server push off (`SETTINGS_ENABLE_PUSH` 0);
//! - HEADERS + CONTINUATION decoded with HPACK (`http2/hpack.rs`, RFC
//!   7541), in order, on one decoder per connection (§4.3);
//! - DATA bodies, flow-controlled: the window the server spent is given
//!   back with WINDOW_UPDATE (§6.9), or a long-lived connection stalls
//!   after 64 KiB of answers;
//! - RST_STREAM ends the request; GOAWAY ends the connection (a request
//!   on a stream above its last id was not processed, §6.8: the caller
//!   may ask again on a fresh connection);
//! - frames of unknown type are ignored (§4.1, §5.5).
//!
//! Hostile input: frames above our SETTINGS_MAX_FRAME_SIZE (16 384, the
//! default), a header block over [`MAX_HEADER_BLOCK`] and a body over the
//! caller's `max_body` end the connection with an error; every read waits
//! only until the caller's deadline.

use std::io::{Read, Write};
use std::time::Instant;

use super::https::Stream;

#[path = "http2/hpack.rs"]
mod hpack;
#[path = "http2/tables.rs"]
mod tables;

/// §3.4: the client connection preface.
const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
/// §4.2: SETTINGS_MAX_FRAME_SIZE's default, which we keep.
const MAX_FRAME: usize = 16_384;
/// HEADERS and its CONTINUATIONs together.
const MAX_HEADER_BLOCK: usize = 64 * 1024;
/// The last client stream id before 2^31 (§5.1.1): past it, a new
/// connection.
const LAST_STREAM: u32 = (1 << 31) - 1;

// §6: frame types.
const DATA: u8 = 0x0;
const HEADERS: u8 = 0x1;
const RST_STREAM: u8 = 0x3;
const SETTINGS: u8 = 0x4;
const PUSH_PROMISE: u8 = 0x5;
const PING: u8 = 0x6;
const GOAWAY: u8 = 0x7;
const WINDOW_UPDATE: u8 = 0x8;
const CONTINUATION: u8 = 0x9;
// Flags.
const END_STREAM: u8 = 0x1;
const ACK: u8 = 0x1;
const END_HEADERS: u8 = 0x4;
const PADDED: u8 = 0x8;
const PRIORITY: u8 = 0x20;
// §6.5.2: settings.
const SETTINGS_ENABLE_PUSH: u16 = 0x2;
const SETTINGS_MAX_FRAME_SIZE: u16 = 0x5;

/// The ALPN protocol id of HTTP/2 over TLS (§3.2).
pub(crate) const ALPN: &[u8] = b"h2";

/// A request: the pseudo-headers (`:scheme` is https), the other
/// headers, the body (may be empty).
pub(crate) struct Request<'a> {
    pub(crate) method: &'a str,
    pub(crate) authority: &'a str,
    pub(crate) path: &'a str,
    pub(crate) headers: &'a [(&'a str, &'a str)],
    pub(crate) body: &'a [u8],
}

/// A response: what DoH reads.
#[derive(Debug, Default)]
pub(crate) struct Response {
    pub(crate) status: u16,
    pub(crate) content_type: Option<String>,
    pub(crate) body: Vec<u8>,
}

/// An HTTP/2 connection (client side).
pub(crate) struct Conn {
    stream: Stream,
    decoder: hpack::Decoder,
    next_id: u32,
    /// The server's SETTINGS_MAX_FRAME_SIZE (what we may send).
    peer_max_frame: usize,
    /// GOAWAY seen, an error, or the ids ran out: not for another request.
    done: bool,
}

/// Why a request failed; `retry`: it was never processed (GOAWAY below
/// its stream id, or a connection that closed before any answer), so it
/// may go again on a fresh connection.
#[derive(Debug)]
pub(crate) struct Failure {
    pub(crate) why: String,
    pub(crate) retry: bool,
}

fn fail(why: impl Into<String>) -> Failure {
    Failure {
        why: why.into(),
        retry: false,
    }
}

impl Conn {
    /// The preface and our SETTINGS on a stream whose TLS chose `h2`.
    pub(crate) fn start(mut stream: Stream, deadline: Instant) -> Result<Self, String> {
        stream.deadline(deadline)?;
        let mut out = PREFACE.to_vec();
        let mut settings = Vec::new();
        settings.extend_from_slice(&SETTINGS_ENABLE_PUSH.to_be_bytes());
        settings.extend_from_slice(&0u32.to_be_bytes());
        frame(&mut out, SETTINGS, 0, 0, &settings);
        stream.write_all(&out).map_err(|e| e.to_string())?;
        stream.flush().map_err(|e| e.to_string())?;
        Ok(Self {
            stream,
            decoder: hpack::Decoder::default(),
            next_id: 1,
            peer_max_frame: MAX_FRAME,
            done: false,
        })
    }

    /// Whether another request may use this connection.
    pub(crate) fn reusable(&self) -> bool {
        !self.done
    }

    /// One request; the answer's body at most `max_body` bytes.
    pub(crate) fn request(&mut self, req: &Request<'_>, max_body: usize, deadline: Instant) -> Result<Response, Failure> {
        if self.done {
            return Err(Failure {
                why: "connection closed".into(),
                retry: true,
            });
        }
        let r = self.exchange(req, max_body, deadline);
        if r.is_err() {
            self.done = true;
        }
        r
    }

    fn exchange(&mut self, req: &Request<'_>, max_body: usize, deadline: Instant) -> Result<Response, Failure> {
        let body = req.body;
        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(2);
        if self.next_id > LAST_STREAM {
            self.done = true;
        }
        self.stream.deadline(deadline).map_err(fail)?;
        // §8.3.1: the pseudo-headers first, lowercase names (§8.2.1).
        let len = body.len().to_string();
        let mut all: Vec<(&str, &str)> = vec![
            (":method", req.method),
            (":scheme", "https"),
            (":authority", req.authority),
            (":path", req.path),
        ];
        all.extend_from_slice(req.headers);
        if !body.is_empty() {
            all.push(("content-length", &len));
        }
        let block = hpack::encode(&all);
        if block.len() > self.peer_max_frame || body.len() > self.peer_max_frame {
            return Err(fail("request larger than one frame"));
        }
        let mut out = Vec::with_capacity(block.len() + body.len() + 18);
        let flags = END_HEADERS | if body.is_empty() { END_STREAM } else { 0 };
        frame(&mut out, HEADERS, flags, id, &block);
        if !body.is_empty() {
            frame(&mut out, DATA, END_STREAM, id, body);
        }
        self.stream.write_all(&out).map_err(|e| io_fail(&e))?;
        self.stream.flush().map_err(|e| io_fail(&e))?;

        let mut resp = Response::default();
        let mut block: Vec<u8> = Vec::new();
        let mut in_headers = false;
        // END_STREAM came on a HEADERS whose block is still open.
        let mut ends = false;
        let mut got_status = false;
        let mut answered = false;
        loop {
            if Instant::now() >= deadline {
                return Err(fail("timed out"));
            }
            let (kind, flags, sid, payload) = match self.read_frame() {
                Ok(f) => f,
                // A connection that closes before any byte of the answer:
                // the request was not processed (a server that times out
                // idle connections closes them like this).
                Err(e) => {
                    return Err(Failure {
                        retry: !answered && e.retry,
                        why: e.why,
                    });
                }
            };
            answered |= sid == id;
            // §6.10: nothing but CONTINUATION while a header block is open.
            if in_headers && kind != CONTINUATION {
                return Err(fail("frame inside a header block"));
            }
            match kind {
                SETTINGS if sid == 0 => {
                    if flags & ACK == 0 {
                        self.settings(&payload)?;
                        let mut ack = Vec::new();
                        frame(&mut ack, SETTINGS, ACK, 0, &[]);
                        self.stream.write_all(&ack).map_err(|e| io_fail(&e))?;
                    }
                }
                PING if sid == 0 && flags & ACK == 0 => {
                    let mut pong = Vec::new();
                    frame(&mut pong, PING, ACK, 0, &payload);
                    self.stream.write_all(&pong).map_err(|e| io_fail(&e))?;
                }
                GOAWAY => {
                    let last = be32(&payload) & 0x7fff_ffff;
                    self.done = true;
                    if last < id {
                        return Err(Failure {
                            why: "GOAWAY before our request".into(),
                            retry: true,
                        });
                    }
                }
                RST_STREAM if sid == id => {
                    let code = be32(&payload);
                    // REFUSED_STREAM (0x7): not processed (§8.7).
                    return Err(Failure {
                        why: format!("stream reset (error {code:#x})"),
                        retry: code == 0x7,
                    });
                }
                PUSH_PROMISE => return Err(fail("PUSH_PROMISE with push disabled")),
                HEADERS | CONTINUATION if sid == id => {
                    let mut p: &[u8] = &payload;
                    if kind == HEADERS {
                        p = unpad(p, flags)?;
                        if flags & PRIORITY != 0 {
                            p = p.get(5..).ok_or_else(|| fail("short HEADERS"))?;
                        }
                    } else if !in_headers {
                        return Err(fail("CONTINUATION without HEADERS"));
                    }
                    block.extend_from_slice(p);
                    if block.len() > MAX_HEADER_BLOCK {
                        return Err(fail("header block too large"));
                    }
                    in_headers = flags & END_HEADERS == 0;
                    if !in_headers {
                        let fields = self
                            .decoder
                            .decode(&block)
                            .map_err(|e| fail(format!("HPACK: {}", e.0)))?;
                        block.clear();
                        // The first block has the status; a later one is
                        // trailers (ignored) or, after a 1xx, the real one.
                        for (n, v) in &fields {
                            match n.as_str() {
                                ":status" if !got_status || resp.status / 100 == 1 => {
                                    resp.status = v.parse().map_err(|_| fail("bad :status"))?;
                                    got_status = true;
                                }
                                "content-type" => resp.content_type = Some(v.clone()),
                                _ => {}
                            }
                        }
                    }
                    if kind == HEADERS && flags & END_STREAM != 0 {
                        ends = true;
                    }
                    if ends && !in_headers {
                        return self.finished(resp, got_status);
                    }
                }
                HEADERS | CONTINUATION => {
                    // Another stream's headers still change the decoder.
                    return Err(fail("headers on a stream we did not open"));
                }
                DATA => {
                    let p = unpad(&payload, flags)?;
                    if sid == id {
                        if resp.body.len() + p.len() > max_body {
                            return Err(fail("body too large"));
                        }
                        resp.body.extend_from_slice(p);
                    }
                    // §6.9: the whole frame counts (padding too); give it
                    // back to the connection (the stream ends with this
                    // request anyway).
                    if !payload.is_empty() {
                        let inc = u32::try_from(payload.len()).unwrap_or(0);
                        let mut wu = Vec::new();
                        frame(&mut wu, WINDOW_UPDATE, 0, 0, &inc.to_be_bytes());
                        self.stream.write_all(&wu).map_err(|e| io_fail(&e))?;
                    }
                    if sid == id && flags & END_STREAM != 0 {
                        return self.finished(resp, got_status);
                    }
                }
                // WINDOW_UPDATE (our bodies are one small frame),
                // PRIORITY, acks and unknown types: nothing to do.
                _ => {}
            }
            self.stream.flush().map_err(|e| io_fail(&e))?;
        }
    }

    fn finished(&mut self, resp: Response, got_status: bool) -> Result<Response, Failure> {
        if !got_status {
            return Err(fail("no :status"));
        }
        self.stream.flush().map_err(|e| io_fail(&e))?;
        Ok(resp)
    }

    fn settings(&mut self, p: &[u8]) -> Result<(), Failure> {
        let (settings, rest) = p.as_chunks::<6>();
        if !rest.is_empty() {
            return Err(fail("SETTINGS of a bad length"));
        }
        for [a, b, c, d, e, f] in settings {
            let (id, v) = (u16::from_be_bytes([*a, *b]), u32::from_be_bytes([*c, *d, *e, *f]));
            if id == SETTINGS_MAX_FRAME_SIZE {
                // §6.5.2: 2^14..=2^24-1.
                if !(16_384..=16_777_215).contains(&v) {
                    return Err(fail("bad SETTINGS_MAX_FRAME_SIZE"));
                }
                self.peer_max_frame = usize::try_from(v).unwrap_or(MAX_FRAME);
            }
        }
        Ok(())
    }

    /// §4.1: 9 bytes of header, then the payload.
    fn read_frame(&mut self) -> Result<(u8, u8, u32, Vec<u8>), Failure> {
        let mut head = [0u8; 9];
        if let Err(e) = self.stream.read_exact(&mut head) {
            return Err(Failure {
                why: e.to_string(),
                retry: e.kind() == std::io::ErrorKind::UnexpectedEof,
            });
        }
        let [l0, l1, l2, kind, flags, s0, s1, s2, s3] = head;
        let len = usize::from(l0) << 16 | usize::from(l1) << 8 | usize::from(l2);
        if len > MAX_FRAME {
            return Err(fail("frame larger than SETTINGS_MAX_FRAME_SIZE"));
        }
        let sid = u32::from_be_bytes([s0 & 0x7f, s1, s2, s3]);
        let mut payload = vec![0u8; len];
        self.stream.read_exact(&mut payload).map_err(|e| io_fail(&e))?;
        Ok((kind, flags, sid, payload))
    }
}

/// The first 4 bytes, big endian (0 when shorter).
fn be32(p: &[u8]) -> u32 {
    match p {
        [a, b, c, d, ..] => u32::from_be_bytes([*a, *b, *c, *d]),
        _ => 0,
    }
}

fn io_fail(e: &std::io::Error) -> Failure {
    fail(e.to_string())
}

/// §6.1/§6.2: strip the padding of a PADDED frame.
fn unpad(p: &[u8], flags: u8) -> Result<&[u8], Failure> {
    if flags & PADDED == 0 {
        return Ok(p);
    }
    let (&pad, rest) = p.split_first().ok_or_else(|| fail("padding without its length"))?;
    let keep = rest
        .len()
        .checked_sub(usize::from(pad))
        .ok_or_else(|| fail("padding longer than the frame"))?;
    rest.get(..keep).ok_or_else(|| fail("padding"))
}

/// Appends one frame.
fn frame(out: &mut Vec<u8>, kind: u8, flags: u8, stream: u32, payload: &[u8]) {
    let len = u32::try_from(payload.len()).unwrap_or(0).to_be_bytes();
    out.extend_from_slice(len.get(1..).unwrap_or_default());
    out.push(kind);
    out.push(flags);
    out.extend_from_slice(&(stream & 0x7fff_ffff).to_be_bytes());
    out.extend_from_slice(payload);
}

#[cfg(test)]
#[path = "http2/tests.rs"]
mod tests;
