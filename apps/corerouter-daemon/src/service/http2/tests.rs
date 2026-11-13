//! The client against small HTTP/2 servers on plain TCP (prior knowledge;
//! TLS and ALPN are tested with DoH in `dns_secure.rs`).

use super::*;
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;


/// One frame from `s`.
fn read_frame(s: &mut TcpStream) -> Option<(u8, u8, u32, Vec<u8>)> {
    let mut h = [0u8; 9];
    s.read_exact(&mut h).ok()?;
    let len = usize::from(h[0]) << 16 | usize::from(h[1]) << 8 | usize::from(h[2]);
    let mut p = vec![0u8; len];
    s.read_exact(&mut p).ok()?;
    Some((h[3], h[4], u32::from_be_bytes([h[5] & 0x7f, h[6], h[7], h[8]]), p))
}

fn put(s: &mut TcpStream, kind: u8, flags: u8, id: u32, p: &[u8]) {
    let mut out = Vec::new();
    frame(&mut out, kind, flags, id, p);
    s.write_all(&out).unwrap();
}

/// A server that reads the preface and then, for each request, calls
/// `answer(stream, id, request headers, body, n)` (n: the request's number).
fn serve(answer: fn(&mut TcpStream, u32, &[hpack::Header], &[u8], usize)) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    thread::spawn(move || {
        for s in l.incoming() {
            let mut s = s.unwrap();
            s.set_nodelay(true).unwrap();
            thread::spawn(move || {
                let mut pre = [0u8; 24];
                s.read_exact(&mut pre).unwrap();
                assert_eq!(&pre[..], PREFACE);
                let mut dec = hpack::Decoder::default();
                let mut n = 0;
                let (mut headers, mut body) = (Vec::new(), Vec::new());
                while let Some((kind, flags, id, p)) = read_frame(&mut s) {
                    match kind {
                        SETTINGS if flags & ACK == 0 => {
                            // Push off, as the client must say.
                            assert_eq!(p, [0, 2, 0, 0, 0, 0]);
                            put(&mut s, SETTINGS, 0, 0, &[0, 5, 0, 0, 0x40, 0]);
                            put(&mut s, SETTINGS, ACK, 0, &[]);
                        }
                        HEADERS => {
                            headers = dec.decode(&p).unwrap();
                            if flags & END_STREAM != 0 {
                                answer(&mut s, id, &headers, &body, n);
                                n += 1;
                            }
                        }
                        DATA => {
                            body.extend_from_slice(&p);
                            if flags & END_STREAM != 0 {
                                answer(&mut s, id, &headers, &body, n);
                                body.clear();
                                n += 1;
                            }
                        }
                        _ => {}
                    }
                }
            });
        }
    });
    port
}

fn conn(port: u16) -> Conn {
    // As `https::connect_with` does: no Nagle wait between small frames.
    let s = TcpStream::connect(("127.0.0.1", port)).unwrap();
    s.set_nodelay(true).unwrap();
    Conn::start(Stream::Plain(s), deadline()).unwrap()
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(3)
}

fn ask(c: &mut Conn) -> Result<Response, Failure> {
    c.request(
        &Request {
            method: "POST",
            authority: "dns.example",
            path: "/dns-query",
            headers: &[("content-type", "application/dns-message"), ("accept", "application/dns-message")],
            body: b"QUERY",
        },
        65_535,
        deadline(),
    )
}

/// The status and content type Huffman coded and indexed into the
/// dynamic table, the body in two padded DATA frames; a PING on the way.
fn good(s: &mut TcpStream, id: u32, h: &[hpack::Header], body: &[u8], n: usize) {
    let get = |k: &str| h.iter().find(|(n, _)| n == k).map(|(_, v)| v.as_str());
    assert_eq!(get(":method"), Some("POST"));
    assert_eq!(get(":scheme"), Some("https"));
    assert_eq!(get(":path"), Some("/dns-query"));
    assert_eq!(get("content-length"), Some("5"));
    assert_eq!(body, b"QUERY");
    put(s, PING, 0, 0, b"12345678");
    // :status 200 (indexed 0x88), then content-type literal with
    // incremental indexing the first time, indexed (dynamic, 62) after.
    let mut block = vec![0x88];
    if n == 0 {
        // 0x40 | 31: literal with incremental indexing, name content-type.
        block.push(0x40 | 31);
        block.push(23);
        block.extend_from_slice(b"application/dns-message");
    } else {
        block.push(0x80 | 62);
    }
    put(s, HEADERS, END_HEADERS, id, &block);
    put(s, DATA, PADDED, id, &[3, b'A', b'N', 0, 0, 0]);
    put(s, DATA, END_STREAM, id, &format!("SWER{n}").into_bytes());
}

#[test]
fn requests_reuse_the_connection_and_its_hpack_table() {
    let port = serve(good);
    let mut c = conn(port);
    for n in 0..3 {
        let r = ask(&mut c).unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.content_type.as_deref(), Some("application/dns-message"));
        assert_eq!(r.body, format!("ANSWER{n}").into_bytes());
        assert!(c.reusable());
    }
    assert_eq!(c.next_id, 7, "streams 1, 3, 5");
}

/// Headers split over CONTINUATION, END_STREAM on the HEADERS.
fn continued(s: &mut TcpStream, id: u32, _: &[hpack::Header], _: &[u8], _: usize) {
    put(s, HEADERS, END_STREAM, id, &[0x88]);
    put(s, CONTINUATION, END_HEADERS, id, &[0x0f, 0x10, 3, b'a', b'/', b'b']);
}

#[test]
fn continuation_ends_a_body_less_answer() {
    let mut c = conn(serve(continued));
    let r = ask(&mut c).unwrap();
    assert_eq!((r.status, r.content_type.as_deref(), r.body.len()), (200, Some("a/b"), 0));
}

/// GOAWAY with last id 0: our request was not processed.
fn goaway(s: &mut TcpStream, _: u32, _: &[hpack::Header], _: &[u8], _: usize) {
    put(s, GOAWAY, 0, 0, &[0, 0, 0, 0, 0, 0, 0, 0]);
}

#[test]
fn goaway_before_our_stream_may_be_retried() {
    let mut c = conn(serve(goaway));
    let e = ask(&mut c).unwrap_err();
    assert!(e.retry, "{e:?}");
    assert!(!c.reusable());
}

fn reset(s: &mut TcpStream, id: u32, _: &[hpack::Header], _: &[u8], _: usize) {
    put(s, RST_STREAM, 0, id, &[0, 0, 0, 2]);
}

#[test]
fn a_reset_stream_is_an_error() {
    let mut c = conn(serve(reset));
    let e = ask(&mut c).unwrap_err();
    assert!(e.why.contains("reset") && !e.retry, "{e:?}");
}

fn huge(s: &mut TcpStream, id: u32, _: &[hpack::Header], _: &[u8], _: usize) {
    // A frame header saying 1 MiB.
    s.write_all(&[0x10, 0, 0, DATA, 0, 0, 0, 0, u8::try_from(id).unwrap()]).unwrap();
}

#[test]
fn a_frame_over_our_max_frame_size_ends_the_connection() {
    let mut c = conn(serve(huge));
    let e = ask(&mut c).unwrap_err();
    assert!(e.why.contains("SETTINGS_MAX_FRAME_SIZE"), "{e:?}");
    assert!(!c.reusable());
}

fn closes(s: &mut TcpStream, _: u32, _: &[hpack::Header], _: &[u8], _: usize) {
    let _ = s.shutdown(std::net::Shutdown::Both);
}

#[test]
fn a_connection_closed_before_any_answer_may_be_retried() {
    let mut c = conn(serve(closes));
    let e = ask(&mut c).unwrap_err();
    assert!(e.retry, "{e:?}");
}

/// Answers past 64 KiB on one connection: the client gives the window
/// back, or the server (which counts it) would stop sending.
fn counted(s: &mut TcpStream, id: u32, _: &[hpack::Header], _: &[u8], _: usize) {
    put(s, HEADERS, END_HEADERS, id, &[0x88]);
    put(s, DATA, END_STREAM, id, &[7u8; 4000]);
}

#[test]
fn flow_control_window_is_given_back() {
    // The server side reads the WINDOW_UPDATEs: a raw server here.
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let h = thread::spawn(move || {
        let (mut s, _) = l.accept().unwrap();
        s.set_nodelay(true).unwrap();
        let mut pre = [0u8; 24];
        s.read_exact(&mut pre).unwrap();
        let mut window: i64 = 65_535;
        let mut answered = 0;
        while answered < 40 {
            let (kind, flags, id, p) = read_frame(&mut s).unwrap();
            match kind {
                WINDOW_UPDATE => window += i64::from(u32::from_be_bytes(p[..4].try_into().unwrap())),
                DATA if flags & END_STREAM != 0 => {
                    assert!(window >= 4000, "window spent: {window}");
                    counted(&mut s, id, &[], &[], 0);
                    window -= 4000;
                    answered += 1;
                }
                _ => {}
            }
        }
    });
    let mut c = conn(port);
    for _ in 0..40 {
        assert_eq!(ask(&mut c).unwrap().body.len(), 4000);
    }
    h.join().unwrap();
}

/// Whatever a hostile server sends after the preface: an answer or an
/// error, never a panic or a hang past the deadline (300 random replies,
/// some starting with a valid frame header).
#[test]
fn hostile_servers_never_panic() {
    let mut r = super::hpack::tests::rng(5);
    for i in 0..300 {
        let len = usize::try_from(r() % 400).unwrap();
        let mut junk: Vec<u8> = (0..len).map(|_| r().to_le_bytes()[0]).collect();
        if i % 2 == 0 {
            // A plausible frame header for stream 1, so the parser goes deeper.
            let kind = [DATA, HEADERS, CONTINUATION, SETTINGS, GOAWAY][i % 5];
            let n = u8::try_from(len.min(255)).unwrap();
            junk.splice(0..0, [0, 0, n, kind, (r() & 0xff) as u8, 0, 0, 0, 1]);
        }
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut pre = [0u8; 24];
            let _ = s.read_exact(&mut pre);
            let _ = s.write_all(&junk);
        });
        let s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        let mut c = Conn::start(Stream::Plain(s), deadline()).unwrap();
        let req = Request { method: "POST", authority: "x", path: "/", headers: &[], body: b"q" };
        let _ = c.request(&req, 1024, Instant::now() + Duration::from_millis(200));
        server.join().unwrap();
    }
}
