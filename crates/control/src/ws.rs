//! WebSocket endpoint of the control channel, for the GUI in a browser.
//!
//! Same requests and replies as the TCP channel, one JSON text message each
//! way, each request with its `token` (G0.3: log in with `auth.login`).
//! Synchronous (`tungstenite`), one thread per connection. A plain endpoint
//! is loopback only; one bound to another address is always TLS (`wss://`).
//!
//! A browser lets any page open a WebSocket to `127.0.0.1`, so the handshake
//! is refused (403) when the `Origin` header is not in [`WsPolicy::origins`].
//! A request without `Origin` does not come from a page (browsers always send
//! it) and is treated like a TCP client. On a TLS endpoint
//! [`WsPolicy::same_host`] also allows the page this port served itself
//! (`Origin` = `https://` + the `Host` header).
//!
//! With [`WsPolicy::web_root`] the same port also serves the GUI files over
//! plain HTTP `GET` (the WebFig model), so the default allowed origin is the
//! one that serves the GUI.

use std::fs;
use std::io::{self, Read, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;

use tungstenite::protocol::WebSocketConfig;
use tungstenite::{Message, WebSocket};

use corerouter_engine::Caller;

use crate::auth::Gate;
use crate::dispatch::Host;
use crate::server::{
    Conn, Endpoint, Shutdown, accept_loop, answer_with, line_limit, serve_then_hang_up,
};
use crate::wire::MAX_REQUEST_LINE;

/// Largest HTTP request head (request line + headers).
const MAX_HEAD: usize = 16 * 1024;
/// Largest static file served from `web_root` (the wasm GUI is ~10 MiB).
const MAX_FILE: u64 = 64 * 1024 * 1024;

/// Who may connect and what else the port serves.
#[derive(Debug, Clone, Default)]
pub struct WsPolicy {
    /// Exact `Origin` values allowed to open the WebSocket, e.g.
    /// `http://127.0.0.1:7980`. Empty: only clients without `Origin`.
    pub origins: Vec<String>,
    /// Directory with the built web GUI (`trunk build` → `dist/`).
    pub web_root: Option<PathBuf>,
    /// Also allow `Origin: https://<Host header>`: the page served by this
    /// very port over TLS, whatever address the browser used to reach it.
    pub same_host: bool,
}

impl WsPolicy {
    /// The origins a browser shows for a page served by this port.
    pub fn same_origin(port: u16) -> Vec<String> {
        vec![
            format!("http://127.0.0.1:{port}"),
            format!("http://localhost:{port}"),
        ]
    }

    /// `None` (no `Origin`), an exact match, or (with `same_host`) the
    /// HTTPS origin of the `Host` the browser asked for.
    pub fn origin_allowed(&self, origin: Option<&str>, host: Option<&str>) -> bool {
        origin.is_none_or(|o| {
            self.origins.iter().any(|a| a == o)
                || (self.same_host && host.is_some_and(|h| o == format!("https://{h}")))
        })
    }
}

/// Serve forever on the current thread.
pub fn serve_ws<H: Host + Clone + Send + 'static>(
    endpoint: Endpoint,
    host: H,
    policy: WsPolicy,
    gate: Gate,
) {
    serve_ws_until(endpoint, host, policy, gate, &Shutdown::default());
}

/// Serve on the current thread until `shutdown` is closed.
pub fn serve_ws_until<H: Host + Clone + Send + 'static>(
    endpoint: Endpoint,
    host: H,
    policy: WsPolicy,
    gate: Gate,
    shutdown: &Shutdown,
) {
    let policy = Arc::new(policy);
    accept_loop(endpoint, "ws", shutdown, move |conn, caller, peer| {
        let mut host = host.clone();
        serve_then_hang_up(&mut host, &caller, |host| {
            handle(conn, host, &gate, &caller, peer, &policy)
        })
    });
}

/// Serve on a background thread.
pub fn spawn_ws<H: Host + Clone + Send + 'static>(
    endpoint: Endpoint,
    host: H,
    policy: WsPolicy,
    gate: Gate,
) -> io::Result<thread::JoinHandle<()>> {
    spawn_ws_until(endpoint, host, policy, gate, Shutdown::default())
}

/// [`spawn_ws`] that stops accepting when `shutdown` is closed.
pub fn spawn_ws_until<H: Host + Clone + Send + 'static>(
    endpoint: Endpoint,
    host: H,
    policy: WsPolicy,
    gate: Gate,
    shutdown: Shutdown,
) -> io::Result<thread::JoinHandle<()>> {
    thread::Builder::new()
        .name("ws".into())
        .spawn(move || serve_ws_until(endpoint, host, policy, gate, &shutdown))
}

/// The parts of an HTTP request head this server looks at.
#[derive(Debug, Default, PartialEq, Eq)]
struct Head {
    method: String,
    target: String,
    upgrade: bool,
    origin: Option<String>,
    host: Option<String>,
    /// `Accept-Encoding` takes gzip (G1.6o: the precompressed `.gz`).
    gzip: bool,
}

fn parse_head(raw: &[u8]) -> Option<Head> {
    let text = std::str::from_utf8(raw).ok()?;
    let mut lines = text.split("\r\n");
    let mut first = lines.next()?.split(' ');
    let mut head = Head {
        method: first.next()?.to_owned(),
        target: first.next()?.to_owned(),
        ..Head::default()
    };
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("upgrade") {
            head.upgrade = value.eq_ignore_ascii_case("websocket");
        } else if name.eq_ignore_ascii_case("origin") {
            head.origin = Some(value.to_owned());
        } else if name.eq_ignore_ascii_case("host") {
            head.host = Some(value.to_owned());
        } else if name.eq_ignore_ascii_case("accept-encoding") {
            head.gzip = takes_gzip(value);
        }
    }
    Some(head)
}

/// `Accept-Encoding` lists `gzip` (or `*`) without `q=0` (RFC 9110 §12.5.3).
fn takes_gzip(value: &str) -> bool {
    value.split(',').any(|item| {
        let mut parts = item.split(';').map(str::trim);
        let coding = parts.next().unwrap_or_default();
        let q = parts
            .find_map(|p| p.strip_prefix("q=").or_else(|| p.strip_prefix("Q=")))
            .map_or(Some(1.0), |q| q.trim().parse::<f32>().ok());
        (coding.eq_ignore_ascii_case("gzip") || coding == "*") && q.is_some_and(|q| q > 0.0)
    })
}

/// Read up to the blank line that ends the head. Returns the head and
/// whatever came after it (handed back to the WebSocket handshake).
fn read_head(stream: &mut dyn Conn) -> io::Result<Option<(Vec<u8>, Vec<u8>)>> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 2048];
    loop {
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let rest = buf.split_off(end + 4);
            return Ok(Some((buf, rest)));
        }
        if buf.len() >= MAX_HEAD {
            return Ok(None);
        }
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Ok(None);
        }
        buf.extend_from_slice(chunk.get(..n).unwrap_or_default());
    }
}

/// A stream with bytes already read in front of it.
struct Prefixed {
    front: io::Cursor<Vec<u8>>,
    stream: Box<dyn Conn>,
}

impl Read for Prefixed {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.front.read(buf)?;
        if n > 0 {
            return Ok(n);
        }
        self.stream.read(buf)
    }
}

impl Write for Prefixed {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

fn handle<H: Host>(
    mut stream: Box<dyn Conn>,
    host: &mut H,
    gate: &Gate,
    caller: &Caller,
    peer: Option<IpAddr>,
    policy: &WsPolicy,
) -> io::Result<()> {
    // The whole head within the handshake time, however slowly it trickles.
    let head_time = stream.sock().timeouts().handshake;
    stream.sock().set_deadline(Some(head_time));
    let Some((raw, rest)) = read_head(stream.as_mut())? else {
        return respond(stream.as_mut(), "400 Bad Request", "bad request");
    };
    let Some(head) = parse_head(&raw) else {
        return respond(stream.as_mut(), "400 Bad Request", "bad request");
    };
    if !head.upgrade {
        return static_file(stream.as_mut(), &head, policy.web_root.as_deref());
    }
    if !policy.origin_allowed(head.origin.as_deref(), head.host.as_deref()) {
        log::warn!(
            "ws: refused origin {:?} (allowed: {})",
            head.origin
                .as_deref()
                .unwrap_or_default()
                .chars()
                .take(128)
                .collect::<String>(),
            policy.origins.join(", ")
        );
        return respond(stream.as_mut(), "403 Forbidden", "origin not allowed");
    }
    let mut front = raw;
    front.extend_from_slice(&rest);
    let io = Prefixed {
        front: io::Cursor::new(front),
        stream,
    };
    // Small messages until the connection logs in (see `server::line_limit`).
    let mut io = io;
    let max = line_limit(io.stream.as_mut(), peer);
    let config = WebSocketConfig::default()
        .max_message_size(Some(max))
        .max_frame_size(Some(max));
    let mut ws = tungstenite::accept_with_config(io, Some(config))
        .map_err(|e| io::Error::other(format!("handshake: {e}")))?;
    // Logged out: the short idle limit. Logged in, idle browser tabs are
    // normal: no limit (TCP keepalive finds a dead peer).
    ws.get_mut().stream.sock().handshake_done();
    messages(&mut ws, host, gate, caller, peer)
}

fn messages(
    ws: &mut WebSocket<Prefixed>,
    host: &mut dyn Host,
    gate: &Gate,
    caller: &Caller,
    peer: Option<IpAddr>,
) -> io::Result<()> {
    let closed = |e: tungstenite::Error| match e {
        tungstenite::Error::ConnectionClosed | tungstenite::Error::AlreadyClosed => Ok(()),
        tungstenite::Error::Io(e) => Err(e),
        other => Err(io::Error::other(other.to_string())),
    };
    loop {
        let text = match ws.read() {
            Ok(Message::Text(t)) => t,
            // tungstenite answers pings itself; a close is acknowledged on the next read.
            Ok(Message::Ping(_) | Message::Pong(_) | Message::Close(_)) => continue,
            // Binary or raw frames are not requests: drop the connection.
            Ok(Message::Binary(_) | Message::Frame(_)) => return ws.close(None).or_else(closed),
            Err(e) => return closed(e),
        };
        if text.trim().is_empty() {
            continue;
        }
        let was_authenticated = ws.get_mut().stream.sock().is_authenticated();
        let sock = ws.get_mut().stream.sock();
        let Some(answer) = answer_with(host, gate, caller, peer, &text, &mut || {
            sock.authenticated();
        }) else {
            return ws.close(None).or_else(closed);
        };
        if answer.authenticated && !was_authenticated {
            ws.get_mut().stream.sock().authenticated();
            ws.set_config(|c| {
                c.max_message_size = Some(MAX_REQUEST_LINE);
                c.max_frame_size = Some(MAX_REQUEST_LINE);
            });
        }
        if let Err(e) = ws.send(Message::text(answer.reply.into_text())) {
            return closed(e);
        }
    }
}

/// Minimal reply with a short plain-text body; the connection then closes.
fn respond(stream: &mut dyn Conn, status: &str, body: &str) -> io::Result<()> {
    let reply = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(reply.as_bytes())?;
    stream.flush()
}

/// `GET`/`HEAD` of a file under `root`; anything else is refused.
fn static_file(stream: &mut dyn Conn, head: &Head, root: Option<&Path>) -> io::Result<()> {
    let Some(root) = root else {
        return respond(stream, "404 Not Found", "this port only speaks WebSocket");
    };
    if !matches!(head.method.as_str(), "GET" | "HEAD") {
        return respond(stream, "405 Method Not Allowed", "GET only");
    }
    // G1.6o: a `<file>.gz` (made at build time, as nginx's `gzip_static`)
    // goes to browsers that take gzip: the GUI's 32 MiB wasm crosses the
    // network as ~11 MiB. The router image keeps only the `.gz` of the big
    // files; a client that refuses gzip gets `406` for those.
    let (path, gz) = match resolve(root, &head.target) {
        Some(p) => {
            let gz = head.gzip.then(|| gzipped(root, &p)).flatten();
            (p, gz)
        }
        None => {
            let Some(g) = resolve_gz(root, &head.target) else {
                return respond(stream, "404 Not Found", "not found");
            };
            if !head.gzip {
                return respond(
                    stream,
                    "406 Not Acceptable",
                    "this file is kept gzip-compressed: send Accept-Encoding: gzip",
                );
            }
            (g.with_extension(""), Some(g))
        }
    };
    let (body, encoding) = match &gz {
        Some(g) => (g.as_path(), "Content-Encoding: gzip\r\n"),
        None => (path.as_path(), ""),
    };
    // Streamed, not read into memory: 16 slow readers of the 10 MiB wasm
    // would otherwise hold 160 MiB (the write timeout drops a stalled one).
    let Ok(file) = fs::File::open(body) else {
        return respond(stream, "404 Not Found", "not found");
    };
    let size = file.metadata().map(|m| m.len()).unwrap_or(u64::MAX);
    if size > MAX_FILE {
        return respond(stream, "404 Not Found", "not found");
    }
    // The router's GUI is never framed by another page (clickjacking) and
    // never tells another site where it came from.
    let head_bytes = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {size}\r\n{encoding}\
         Vary: Accept-Encoding\r\nX-Content-Type-Options: nosniff\r\n\
         X-Frame-Options: DENY\r\nReferrer-Policy: no-referrer\r\nCache-Control: no-cache\r\n\
         Connection: close\r\n\r\n",
        mime(&path),
    );
    stream.write_all(head_bytes.as_bytes())?;
    if head.method == "GET" {
        io::copy(&mut file.take(size), stream)?;
    }
    stream.flush()
}

/// The `.gz` of a request target whose plain file is not there.
fn resolve_gz(root: &Path, target: &str) -> Option<PathBuf> {
    let path = target.split(['?', '#']).next()?;
    if path.ends_with('/') || path.ends_with(".gz") {
        return None;
    }
    resolve(root, &format!("{path}.gz"))
}

/// `<path>.gz`, if it is a regular file still under `root`.
fn gzipped(root: &Path, path: &Path) -> Option<PathBuf> {
    let mut name = path.file_name()?.to_os_string();
    name.push(".gz");
    let gz = path.with_file_name(name).canonicalize().ok()?;
    (gz.starts_with(root.canonicalize().ok()?) && gz.is_file()).then_some(gz)
}

/// Map a request target to a regular file inside `root`, or `None`.
/// Refuses `..`, hidden names, backslashes and percent-escapes outright, then
/// checks the canonical path is still under `root` (symlinks).
fn resolve(root: &Path, target: &str) -> Option<PathBuf> {
    let path = target.split(['?', '#']).next()?;
    let path = path.strip_prefix('/')?;
    let mut out = root.to_path_buf();
    let mut any = false;
    for seg in path.split('/').filter(|s| !s.is_empty()) {
        if seg.starts_with('.') || seg.contains(['\\', '%', '\0', ':']) {
            return None;
        }
        out.push(seg);
        any = true;
    }
    if !any || path.ends_with('/') {
        out.push("index.html");
    }
    let canon_root = root.canonicalize().ok()?;
    let canon = out.canonicalize().ok()?;
    (canon.starts_with(&canon_root) && canon.is_file()).then_some(canon)
}

fn mime(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("js") => "text/javascript; charset=utf-8",
        Some("wasm") => "application/wasm",
        Some("css") => "text/css; charset=utf-8",
        Some("json") => "application/json",
        Some("png") => "image/png",
        Some("svg") => "image/svg+xml",
        Some("ico") => "image/x-icon",
        Some("txt") => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SharedHost;
    use crate::server::bind_loopback;
    use corerouter_engine::{Session, shared};
    use serde_json::{Value, json};
    use std::net::TcpStream;
    use std::time::Duration;
    use tungstenite::client::IntoClientRequest;
    use tungstenite::http::HeaderValue;

    /// Every test talks with the local token.
    const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn gate() -> Gate {
        let g = Gate::default();
        g.add_local_token(TOKEN);
        g
    }

    fn start(policy: WsPolicy) -> u16 {
        let listener = bind_loopback(0).unwrap();
        let port = listener.local_addr().unwrap().port();
        let host = SharedHost(shared(Session::virtual_lab()));
        spawn_ws(Endpoint::loopback(listener), host, policy, gate()).unwrap();
        port
    }

    fn connect(
        port: u16,
        origin: Option<&str>,
    ) -> Result<WebSocket<TcpStream>, tungstenite::Error> {
        let mut req = format!("ws://127.0.0.1:{port}/ws")
            .into_client_request()
            .unwrap();
        if let Some(o) = origin {
            req.headers_mut()
                .insert("Origin", HeaderValue::from_str(o).unwrap());
        }
        let stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        tungstenite::client(req, stream)
            .map(|(ws, _)| ws)
            .map_err(|e| match e {
                tungstenite::HandshakeError::Failure(e) => e,
                tungstenite::HandshakeError::Interrupted(_) => tungstenite::Error::AlreadyClosed,
            })
    }

    fn call(ws: &mut WebSocket<TcpStream>, mut req: Value) -> Value {
        req["token"] = json!(TOKEN);
        ws.send(Message::text(req.to_string())).unwrap();
        loop {
            if let Message::Text(t) = ws.read().unwrap() {
                return serde_json::from_str(&t).unwrap();
            }
        }
    }

    #[test]
    fn allowed_origin_runs_commands() {
        let port = start(WsPolicy {
            origins: WsPolicy::same_origin(1234),
            ..WsPolicy::default()
        });
        let mut ws = connect(port, Some("http://127.0.0.1:1234")).unwrap();
        // Without the token: refused.
        ws.send(Message::text(
            json!({"id": 1, "method": "state.inspect"}).to_string(),
        ))
        .unwrap();
        let r: Value = loop {
            if let Message::Text(t) = ws.read().unwrap() {
                break serde_json::from_str(&t).unwrap();
            }
        };
        assert!(r["error"].as_str().unwrap().starts_with("unauthorized"));
        let r = call(
            &mut ws,
            json!({"id": 7, "method": "engine.execute",
                   "params": {"command": "system.identity.set", "params": {"name": "ws"}}}),
        );
        assert_eq!((&r["id"], &r["ok"]), (&json!(7), &json!(true)));
        let r = call(&mut ws, json!({"id": 8, "method": "state.inspect"}));
        assert_eq!(r["result"]["identity"], "ws");
        let r = call(&mut ws, json!({"id": 9, "method": "nope"}));
        assert_eq!(r["ok"], false);
    }

    /// G1.6o: a peer the endpoint's filter refuses (`/ip service address`)
    /// is disconnected without an answer; the others are served.
    #[test]
    fn a_refused_peer_gets_no_answer() {
        for (allowed, served) in [(false, false), (true, true)] {
            let listener = bind_loopback(0).unwrap();
            let port = listener.local_addr().unwrap().port();
            let endpoint =
                Endpoint::loopback(listener).with_allow(std::sync::Arc::new(move |ip: IpAddr| {
                    allowed && ip.is_loopback()
                }));
            spawn_ws(
                endpoint,
                SharedHost(shared(Session::virtual_lab())),
                WsPolicy::default(),
                gate(),
            )
            .unwrap();
            assert_eq!(connect(port, None).is_ok(), served, "allowed={allowed}");
        }
    }

    /// G1.4: the browser tab that holds Safe Mode closes → changes undone.
    #[test]
    fn closing_the_safe_mode_socket_undoes_its_changes() {
        let listener = bind_loopback(0).unwrap();
        let port = listener.local_addr().unwrap().port();
        let session = shared(Session::virtual_lab());
        spawn_ws(
            Endpoint::loopback(listener),
            SharedHost(session.clone()),
            WsPolicy::default(),
            gate(),
        )
        .unwrap();
        let disabled = || {
            corerouter_engine::lock(&session)
                .store()
                .running()
                .interfaces
                .values()
                .any(|i| i.disabled)
        };
        let mut ws = connect(port, None).unwrap();
        for (id, command, params) in [
            (1, "config.safe-mode.enter", json!({})),
            (
                2,
                "interface.set",
                json!({"name": "ether2", "disabled": true}),
            ),
        ] {
            let r = call(
                &mut ws,
                json!({"id": id, "method": "engine.execute",
                       "params": {"command": command, "params": params}}),
            );
            assert_eq!(r["ok"], true, "{r}");
        }
        let r = call(&mut ws, json!({"id": 3, "method": "state.inspect"}));
        assert!(
            r["result"]["safe_mode"]["owner"]
                .as_str()
                .unwrap()
                .starts_with("ws 127.0.0.1:")
        );
        assert!(disabled());
        ws.close(None).unwrap();
        let _ = ws.flush();
        drop(ws);
        let until = std::time::Instant::now() + Duration::from_secs(5);
        while disabled() && std::time::Instant::now() < until {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(!disabled());
    }

    /// No Nagle wait between requests on one socket (see `wire::write_line`).
    #[test]
    fn a_persistent_socket_answers_in_milliseconds() {
        let port = start(WsPolicy::default());
        let mut ws = connect(port, None).unwrap();
        let mut times: Vec<Duration> = (0..40)
            .map(|i| {
                let t = std::time::Instant::now();
                let r = call(&mut ws, json!({"id": i, "method": "ping"}));
                assert_eq!(r["ok"], true);
                t.elapsed()
            })
            .collect();
        times.sort();
        let median = times[20];
        assert!(median < Duration::from_millis(5), "median {median:?}");
    }

    #[test]
    fn foreign_origin_is_refused() {
        let port = start(WsPolicy {
            origins: WsPolicy::same_origin(1234),
            ..WsPolicy::default()
        });
        for bad in ["http://evil.example", "null", "http://127.0.0.1:1235"] {
            match connect(port, Some(bad)) {
                Err(tungstenite::Error::Http(resp)) => assert_eq!(resp.status(), 403),
                other => panic!("{bad}: expected 403, got {:?}", other.map(|_| ())),
            }
        }
        // Not a page (no Origin): allowed, like the TCP channel.
        assert!(connect(port, None).is_ok());
    }

    #[test]
    fn non_json_and_binary_close_the_socket() {
        let port = start(WsPolicy::default());
        let mut ws = connect(port, None).unwrap();
        ws.send(Message::text("GET / HTTP/1.1")).unwrap();
        assert!(matches!(
            ws.read(),
            Ok(Message::Close(_)) | Err(tungstenite::Error::ConnectionClosed)
        ));
        let mut ws = connect(port, None).unwrap();
        ws.send(Message::binary(vec![1u8, 2, 3])).unwrap();
        assert!(matches!(
            ws.read(),
            Ok(Message::Close(_)) | Err(tungstenite::Error::ConnectionClosed)
        ));
    }

    #[test]
    fn oversized_message_is_refused() {
        let port = start(WsPolicy::default());
        let mut ws = connect(port, None).unwrap();
        let big = "x".repeat(MAX_REQUEST_LINE + 1);
        let _ = ws.send(Message::text(big));
        // The server drops the connection instead of buffering it.
        let mut closed = false;
        for _ in 0..4 {
            match ws.read() {
                Ok(Message::Text(_)) => {}
                Ok(_) => {}
                Err(_) => {
                    closed = true;
                    break;
                }
            }
        }
        assert!(closed);
    }

    fn http_get(port: u16, target: &str) -> String {
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        write!(s, "GET {target} HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).unwrap();
        out
    }

    #[test]
    fn serves_the_gui_files_and_nothing_else() {
        let dir = std::env::temp_dir().join(format!("cr-ws-root-{}", std::process::id()));
        let root = dir.join("dist");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("index.html"), "<canvas>").unwrap();
        fs::write(root.join("app_bg.wasm"), b"\0asm").unwrap();
        fs::write(dir.join("secret.txt"), "no").unwrap();
        let port = start(WsPolicy {
            web_root: Some(root),
            ..WsPolicy::default()
        });
        let index = http_get(port, "/?connect=x");
        assert!(index.starts_with("HTTP/1.1 200"), "{index}");
        assert!(index.ends_with("<canvas>"));
        assert!(http_get(port, "/app_bg.wasm").contains("application/wasm"));
        for bad in [
            "/../secret.txt",
            "/%2e%2e/secret.txt",
            "/..\\secret.txt",
            "/.hidden",
            "/missing.js",
            "secret.txt",
        ] {
            assert!(http_get(port, bad).starts_with("HTTP/1.1 404"), "{bad}");
        }
        let _ = fs::remove_dir_all(dir);
    }

    /// G1.6o: the precompressed `.gz` goes to a browser that takes gzip.
    #[test]
    fn serves_the_gzip_copy_to_who_takes_it() {
        let dir = std::env::temp_dir().join(format!("cr-ws-gz-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("index.html"), "<canvas>").unwrap();
        fs::write(dir.join("app_bg.wasm"), b"\0asm-plain").unwrap();
        fs::write(dir.join("app_bg.wasm.gz"), b"gz-bytes").unwrap();
        let port = start(WsPolicy {
            web_root: Some(dir.clone()),
            ..WsPolicy::default()
        });
        let get = |enc: &str| {
            let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
            write!(
                s,
                "GET /app_bg.wasm HTTP/1.1\r\nHost: x\r\nAccept-Encoding: {enc}\r\n\r\n"
            )
            .unwrap();
            let mut out = String::new();
            s.read_to_string(&mut out).unwrap();
            out
        };
        let gz = get("gzip, deflate, br");
        assert!(
            gz.contains("Content-Encoding: gzip\r\n") && gz.ends_with("gz-bytes"),
            "{gz}"
        );
        assert!(gz.contains("application/wasm") && gz.contains("X-Frame-Options: DENY"));
        for plain in ["br", "gzip;q=0", "identity"] {
            let out = get(plain);
            assert!(
                !out.contains("Content-Encoding") && out.ends_with("asm-plain"),
                "{plain}: {out}"
            );
        }
        assert!(takes_gzip("*") && takes_gzip("GZIP;q=0.5") && !takes_gzip("gzip; q=0.0"));
        // Only the .gz kept (the router image): gzip clients get it, others 406.
        fs::write(dir.join("only.js.gz"), b"gz-js").unwrap();
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        write!(s, "GET /only.js HTTP/1.1\r\nAccept-Encoding: gzip\r\n\r\n").unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).unwrap();
        assert!(
            out.contains("text/javascript") && out.ends_with("gz-js"),
            "{out}"
        );
        assert!(http_get(port, "/only.js").starts_with("HTTP/1.1 406"));
        assert!(http_get(port, "/only.js.gz.gz").starts_with("HTTP/1.1 404"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn without_web_root_http_is_refused() {
        let port = start(WsPolicy::default());
        assert!(http_get(port, "/").starts_with("HTTP/1.1 404"));
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.write_all(b"\x16\x03\x01garbage\r\n\r\n").unwrap();
        let mut out = String::new();
        let _ = s.read_to_string(&mut out);
        assert!(out.starts_with("HTTP/1.1 4"), "{out}");
    }

    #[test]
    fn parses_heads() {
        let h = parse_head(
            b"GET /ws HTTP/1.1\r\nHost: a\r\nUpgrade: WebSocket\r\norigin:  http://a:1 \r\n",
        )
        .unwrap();
        assert_eq!(
            h,
            Head {
                method: "GET".into(),
                target: "/ws".into(),
                upgrade: true,
                origin: Some("http://a:1".into()),
                host: Some("a".into()),
                gzip: false,
            }
        );
        assert!(parse_head(b"\xff\xfe").is_none());
        let tls = WsPolicy {
            same_host: true,
            ..WsPolicy::default()
        };
        assert!(tls.origin_allowed(Some("https://10.0.0.1:8730"), Some("10.0.0.1:8730")));
        assert!(!tls.origin_allowed(Some("https://evil.example"), Some("10.0.0.1:8730")));
        assert!(!tls.origin_allowed(Some("http://10.0.0.1:8730"), Some("10.0.0.1:8730")));
        assert!(!WsPolicy::default().origin_allowed(Some("https://a:1"), Some("a:1")));
        assert!(parse_head(b"GET").is_none());
    }
}
