//! Control-channel server: one thread per connection, synchronous, no
//! runtime. Plain TCP on loopback, or TLS on any address (G0.3).

use std::io::{self, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::Duration;

use serde::Deserialize;
use serde_json::value::RawValue;
use serde_json::{Value, json};

use corerouter_engine::{Caller, Link};

use crate::auth::Gate;
use crate::conn::{Slots, Sock, Timeouts, keepalive};
use crate::dispatch::{Host, dispatch_as, hang_up, new_caller};
use crate::tls::{self, ServerStream};
use crate::wire::{Line, MAX_REQUEST_LINE, read_line_bounded, write_line};

pub const MAX_CONNECTIONS: usize = 16;
/// Longest request a network peer may send before it has logged in (a
/// login is a few hundred bytes); [`MAX_REQUEST_LINE`] afterwards. Loopback
/// clients send their token with the first request, so they get the full
/// size from the start (and `params` is parsed only after the token check).
pub const MAX_UNAUTHENTICATED_LINE: usize = 64 * 1024;
/// Largest `id` echoed back; a bigger one is answered with `null`.
const MAX_ID: usize = 1024;
/// Largest `params` parsed before the token check (`auth.login`).
const MAX_OPEN_PARAMS: usize = 4096;
/// Pause after a failed `accept` (out of file descriptors): retrying at once
/// would spin a core and flood the log.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// The envelope of a request. `params` and `id` stay raw text until the
/// token is checked, so a stranger's 16 MiB array is never turned into a
/// tree of values (hundreds of MiB).
#[derive(Deserialize)]
struct Request<'a> {
    #[serde(default, borrow)]
    id: Option<&'a RawValue>,
    method: String,
    #[serde(default, borrow)]
    params: Option<&'a RawValue>,
    /// Session or local token (G0.3); never in a URL.
    #[serde(default)]
    token: Option<String>,
}

fn parse_raw(raw: Option<&RawValue>) -> Result<Value, String> {
    raw.map_or(Ok(Value::Null), |r| {
        serde_json::from_str(r.get()).map_err(|e| format!("params: {e}"))
    })
}

/// Bind `127.0.0.1:port` (0 = ephemeral). Never binds a routable address.
pub fn bind_loopback(port: u16) -> io::Result<TcpListener> {
    TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
}

/// How long [`Shutdown::close`] waits for each accept loop to wake up.
const WAKE_TIMEOUT: Duration = Duration::from_millis(200);

/// Stops the accept loops of [`serve_until`] and `serve_ws_until`: after
/// [`Shutdown::close`] each loop returns at its next accept and drops its
/// listener, so the port closes. Connections already open keep running.
#[derive(Debug, Clone, Default)]
pub struct Shutdown(Arc<ShutdownInner>);

#[derive(Debug, Default)]
struct ShutdownInner {
    closed: AtomicBool,
    /// Where the loops listen, to wake their blocking accept.
    listening: Mutex<Vec<SocketAddr>>,
}

impl Shutdown {
    pub fn is_closed(&self) -> bool {
        self.0.closed.load(Ordering::SeqCst)
    }

    /// Stop accepting on every loop that uses this handle; wakes each one
    /// with a throwaway connection, so they return now, not at the next
    /// client.
    pub fn close(&self) {
        self.0.closed.store(true, Ordering::SeqCst);
        let addrs = self
            .0
            .listening
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        for addr in addrs {
            let _ = TcpStream::connect_timeout(&addr, WAKE_TIMEOUT);
        }
    }

    pub(crate) fn watch(&self, listener: &TcpListener) {
        if let Ok(addr) = listener.local_addr() {
            self.0
                .listening
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(addr);
        }
    }
}

/// A listening socket and how its connections are wrapped.
///
/// [`Endpoint::loopback`] is plain TCP and refuses any peer that is not on
/// this machine. [`Endpoint::tls`] may listen on any address and runs TLS
/// first (G0.3); every request on either still needs a token
/// ([`crate::auth`]).
pub struct Endpoint {
    pub listener: TcpListener,
    pub tls: Option<Arc<rustls::ServerConfig>>,
    pub timeouts: Timeouts,
    /// Which peers may connect (RouterOS `/ip service address`); the others
    /// are disconnected before any handshake, without an answer.
    pub allow: Option<Allow>,
}

/// A peer filter of an [`Endpoint`].
pub type Allow = Arc<dyn Fn(IpAddr) -> bool + Send + Sync>;

impl Endpoint {
    pub fn loopback(listener: TcpListener) -> Self {
        Self {
            listener,
            tls: None,
            timeouts: Timeouts::default(),
            allow: None,
        }
    }

    pub fn tls(listener: TcpListener, config: Arc<rustls::ServerConfig>) -> Self {
        Self {
            listener,
            tls: Some(config),
            timeouts: Timeouts::default(),
            allow: None,
        }
    }

    /// Accept only the peers `allow` says yes to.
    pub fn with_allow(mut self, allow: Allow) -> Self {
        self.allow = Some(allow);
        self
    }

    /// Other socket timeouts than [`Timeouts::default`] (tests, tuning).
    pub fn with_timeouts(mut self, timeouts: Timeouts) -> Self {
        self.timeouts = timeouts;
        self
    }

    /// Shown in caller names: "tcp", "tls", "ws", "wss".
    fn kind(&self, what: &str) -> &'static str {
        match (what, self.tls.is_some()) {
            ("ws", false) => "ws",
            ("ws", true) => "wss",
            (_, false) => "tcp",
            (_, true) => "tls",
        }
    }
}

/// A connection after the optional TLS handshake.
pub trait Conn: Read + Write + Send {
    fn sock(&mut self) -> &mut Sock;

    fn tcp(&self) -> &TcpStream;
}

impl Conn for Sock {
    fn sock(&mut self) -> &mut Sock {
        self
    }

    fn tcp(&self) -> &TcpStream {
        Sock::tcp(self)
    }
}

impl Conn for ServerStream {
    fn sock(&mut self) -> &mut Sock {
        &mut self.sock
    }

    fn tcp(&self) -> &TcpStream {
        self.sock.tcp()
    }
}

/// Run `serve` for one connection, then [`hang_up`] (undo its Safe Mode)
/// even when `serve` panicked: a panic outside the engine's own guard
/// must neither leave a Safe Mode in place nor kill more than this thread.
pub(crate) fn serve_then_hang_up<H: Host>(
    host: &mut H,
    caller: &Caller,
    serve: impl FnOnce(&mut H) -> io::Result<()>,
) -> io::Result<()> {
    let out = catch_unwind(AssertUnwindSafe(|| serve(&mut *host)));
    hang_up(host, caller);
    out.unwrap_or_else(|_| Err(io::Error::other("connection thread panicked")))
}

/// Accept loop shared by the TCP and WebSocket servers: loopback check,
/// connection limit, one thread per connection (TLS handshake included).
/// `serve` gets the connection, its caller and the peer address.
pub(crate) fn accept_loop<F>(endpoint: Endpoint, what: &str, shutdown: &Shutdown, serve: F)
where
    F: Fn(Box<dyn Conn>, Caller, Option<IpAddr>) -> io::Result<()> + Clone + Send + 'static,
{
    let slots = Slots::default();
    let kind = endpoint.kind(what);
    shutdown.watch(&endpoint.listener);
    // A close that ran before `watch` did not wake this loop.
    if shutdown.is_closed() {
        return;
    }
    for conn in endpoint.listener.incoming() {
        if shutdown.is_closed() {
            log::info!("{what}: no longer accepting connections");
            return;
        }
        let mut stream = match conn {
            Ok(s) => s,
            Err(e) => {
                log::warn!("{what}: accept failed: {e}");
                thread::sleep(ACCEPT_BACKOFF);
                continue;
            }
        };
        let peer = stream.peer_addr().ok();
        // One request, one reply: never hold a small write back (Nagle).
        if let Err(e) = stream.set_nodelay(true) {
            log::debug!("{what}: TCP_NODELAY not set: {e}");
        }
        if endpoint.tls.is_none() && !peer.is_some_and(|a| a.ip().is_loopback()) {
            log::warn!("{what}: rejected non-loopback peer");
            continue;
        }
        if let (Some(allow), Some(p)) = (&endpoint.allow, peer)
            && !allow(p.ip())
        {
            log::debug!("{what}: {p} is not allowed to connect; disconnected");
            continue;
        }
        let slot = match slots.take(peer.map(|p| p.ip()), MAX_CONNECTIONS) {
            Ok(slot) => slot,
            Err(why) => {
                log::debug!("{what}: refused a connection: {why}");
                reject(&mut stream, kind, why);
                continue;
            }
        };
        let timeouts = endpoint.timeouts.clone();
        if let Err(e) = stream.set_write_timeout(Some(timeouts.write)) {
            log::debug!("{what}: write timeout not set: {e}");
        }
        if let Err(e) = keepalive(&stream, &timeouts) {
            log::warn!("{what}: TCP keepalive not set: {e}");
        }
        let caller = match (peer, stream.local_addr().ok()) {
            // The lockout check (G2.1b) needs both ends of the connection.
            (Some(p), Some(local)) => new_caller(kind, p).with_link(Link { peer: p, local }),
            (Some(p), None) => new_caller(kind, p),
            (None, _) => new_caller(kind, "?"),
        };
        let tls = endpoint.tls.clone();
        let serve = serve.clone();
        let label = what.to_owned();
        let spawned = thread::Builder::new()
            .name(format!("{what}-conn"))
            .spawn(move || {
                // The slot lives in the socket: given back with it, panic or not.
                let sock = Sock::new(stream, timeouts, Some(slot));
                let conn: io::Result<Box<dyn Conn>> = match tls {
                    None => Ok(Box::new(sock)),
                    Some(cfg) => tls::accept(sock, cfg).map(|s| Box::new(s) as Box<dyn Conn>),
                };
                let result = conn.and_then(|mut c| {
                    c.sock().handshake_done();
                    serve(c, caller, peer.map(|p| p.ip()))
                });
                if let Err(e) = result {
                    log::debug!("{label}: connection closed: {e}");
                }
            });
        if let Err(e) = spawned {
            log::error!("{what}: cannot spawn connection thread: {e}");
        }
    }
}

/// Tell a refused client why, where its protocol allows it before any
/// handshake: a JSON line on plain TCP, `503` on a plain WebSocket/HTTP
/// port; nothing over TLS.
fn reject(stream: &mut TcpStream, kind: &str, why: &str) {
    let _ = stream.set_write_timeout(Some(Duration::from_secs(1)));
    let _ = match kind {
        "tcp" => write_line(stream, &json!({"id": null, "ok": false, "error": why})),
        "ws" => {
            let reply = format!(
                "HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain; charset=utf-8\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{why}",
                why.len()
            );
            stream.write_all(reply.as_bytes())
        }
        _ => Ok(()),
    };
}

/// Serve forever on the current thread.
pub fn serve<H: Host + Clone + Send + 'static>(endpoint: Endpoint, host: H, gate: Gate) {
    serve_until(endpoint, host, gate, &Shutdown::default());
}

/// Serve on the current thread until `shutdown` is closed.
pub fn serve_until<H: Host + Clone + Send + 'static>(
    endpoint: Endpoint,
    host: H,
    gate: Gate,
    shutdown: &Shutdown,
) {
    accept_loop(endpoint, "control", shutdown, move |conn, caller, peer| {
        let mut host = host.clone();
        serve_then_hang_up(&mut host, &caller, |host| {
            handle(conn, host, &gate, &caller, peer)
        })
    });
}

/// Serve on a background thread.
pub fn spawn<H: Host + Clone + Send + 'static>(
    endpoint: Endpoint,
    host: H,
    gate: Gate,
) -> io::Result<thread::JoinHandle<()>> {
    spawn_until(endpoint, host, gate, Shutdown::default())
}

/// [`spawn`] that stops accepting when `shutdown` is closed.
pub fn spawn_until<H: Host + Clone + Send + 'static>(
    endpoint: Endpoint,
    host: H,
    gate: Gate,
    shutdown: Shutdown,
) -> io::Result<thread::JoinHandle<()>> {
    thread::Builder::new()
        .name("control".into())
        .spawn(move || serve_until(endpoint, host, gate, &shutdown))
}

/// Methods answered without a token.
const OPEN_METHODS: &[&str] = &["ping", "server.info"];

/// The reply to one request, and whether its token (or login) was good.
pub(crate) struct Answer {
    pub(crate) reply: Value,
    pub(crate) authenticated: bool,
}

/// The reply to one request, or `None` when it is not a JSON request (the
/// caller then drops the connection). Shared by TCP, TLS and WebSocket.
pub(crate) fn answer(
    host: &mut dyn Host,
    gate: &Gate,
    caller: &Caller,
    peer: Option<IpAddr>,
    text: &str,
) -> Option<Answer> {
    answer_with(host, gate, caller, peer, text, &mut || {})
}

/// [`answer`], calling `on_token` as soon as the request's token is good,
/// before the command runs: a connection waiting its turn for the session
/// (another client's commit) is no longer "logged out", so it does not hold
/// one of the few logged-out slots (audit-e2e: 16 local clients connecting
/// at once got "too many connections that have not logged in" while the
/// first ones' requests queued behind a commit).
pub(crate) fn answer_with(
    host: &mut dyn Host,
    gate: &Gate,
    caller: &Caller,
    peer: Option<IpAddr>,
    text: &str,
    on_token: &mut dyn FnMut(),
) -> Option<Answer> {
    let req = serde_json::from_str::<Request>(text).ok()?;
    let id = req
        .id
        .filter(|r| r.get().len() <= MAX_ID)
        .and_then(|r| serde_json::from_str::<Value>(r.get()).ok())
        .unwrap_or(Value::Null);
    let token = req.token.as_deref();
    let mut authenticated = false;
    let result = match req.method.as_str() {
        m if OPEN_METHODS.contains(&m) => {
            // The exact build tells which known bugs a router has: strangers
            // on the network get it only after logging in. (`ping` checks no
            // token: it is the hot path of health checks.)
            let stranger = m == "server.info" && !peer.is_some_and(|p| p.is_loopback()) && {
                let logged_in = token.is_some() && gate.principal(host, token).is_ok();
                authenticated = logged_in;
                !logged_in
            };
            if stranger {
                Ok(json!({"name": "corerouter", "auth": "required"}))
            } else {
                dispatch_as(host, caller, m, &Value::Null).map(|mut v| {
                    if m == "server.info"
                        && let Some(o) = v.as_object_mut()
                    {
                        o.entry("auth").or_insert(json!("required"));
                    }
                    v
                })
            }
        }
        "auth.login" => {
            if req.params.is_some_and(|r| r.get().len() > MAX_OPEN_PARAMS) {
                Err(format!("auth.login params exceed {MAX_OPEN_PARAMS} bytes"))
            } else {
                parse_raw(req.params).and_then(|p| {
                    let r = gate.login(host, caller, peer, &p);
                    authenticated = r.is_ok();
                    r
                })
            }
        }
        "auth.logout" => gate.logout(host, token),
        method => gate.principal(host, token).and_then(|p| {
            authenticated = true;
            on_token();
            let caller = caller.clone().with_principal(p);
            if method == "auth.whoami" {
                whoami(host, &caller)
            } else {
                parse_raw(req.params).and_then(|params| dispatch_as(host, &caller, method, &params))
            }
        }),
    };
    let reply = match result {
        Ok(result) => json!({"id": id, "ok": true, "result": result}),
        Err(error) => json!({"id": id, "ok": false, "error": error}),
    };
    Some(Answer {
        reply,
        authenticated,
    })
}

/// `auth.whoami`: who this token is and what it may do. For group `full`
/// also `no_password`: the accounts of group full still without a password
/// (G0.3b), so the GUI and the terminal can ask for one.
fn whoami(host: &mut dyn Host, caller: &Caller) -> Result<Value, String> {
    let p = caller.principal.clone();
    host.with_session(&mut |s| Ok(corerouter_engine::auth::whoami(s, &p, &caller.name)))
        .or_else(|_| {
            Ok(json!({
                "user": p.label(),
                "group": if p == corerouter_engine::Principal::Local { json!("full") } else { Value::Null },
                "via": caller.name,
            }))
        })
}

/// The longest request this connection may send now.
pub(crate) fn line_limit(conn: &mut dyn Conn, peer: Option<IpAddr>) -> usize {
    if conn.sock().is_authenticated() || peer.is_some_and(|p| p.is_loopback()) {
        MAX_REQUEST_LINE
    } else {
        MAX_UNAUTHENTICATED_LINE
    }
}

/// Runs until the client hangs up; the caller then calls [`hang_up`].
fn handle<H: Host>(
    stream: Box<dyn Conn>,
    host: &mut H,
    gate: &Gate,
    caller: &Caller,
    peer: Option<IpAddr>,
) -> io::Result<()> {
    let mut reader = BufReader::new(stream);
    loop {
        let max = line_limit(reader.get_mut().as_mut(), peer);
        let line = match read_line_bounded(&mut reader, max)? {
            Line::Eof => return Ok(()),
            Line::TooLong => {
                let error = if max == MAX_REQUEST_LINE {
                    "request line exceeds 16 MiB".to_owned()
                } else {
                    format!("request line exceeds {} KiB before login", max / 1024)
                };
                write_line(
                    reader.get_mut(),
                    &json!({"id": null, "ok": false, "error": error}),
                )?;
                return Ok(());
            }
            Line::Text(t) => t,
        };
        if line.trim().is_empty() {
            continue;
        }
        // Not JSON (e.g. an HTTP request from a web page): drop the connection.
        let conn = reader.get_mut();
        let Some(answer) = answer_with(host, gate, caller, peer, &line, &mut || {
            conn.sock().authenticated();
        }) else {
            return Ok(());
        };
        if answer.authenticated {
            reader.get_mut().sock().authenticated();
        }
        write_line(reader.get_mut(), &answer.reply)?;
    }
}
