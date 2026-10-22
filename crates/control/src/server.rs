//! Control-channel server: one thread per connection, synchronous, no
//! runtime. Plain TCP on loopback, or TLS on any address (G0.3).

use std::io::{self, BufReader, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::Duration;

use serde::Deserialize;
use serde_json::{Value, json};

use corerouter_engine::{Caller, Link};

use crate::auth::Gate;
use crate::dispatch::{Host, dispatch_as, hang_up, new_caller};
use crate::tls::{self, ServerStream};
use crate::wire::{Line, MAX_REQUEST_LINE, read_line_bounded, write_line};

pub const MAX_CONNECTIONS: usize = 16;

#[derive(Deserialize)]
struct Request {
    #[serde(default)]
    id: Value,
    method: String,
    #[serde(default)]
    params: Value,
    /// Session or local token (G0.3); never in a URL.
    #[serde(default)]
    token: Option<String>,
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
}

impl Endpoint {
    pub fn loopback(listener: TcpListener) -> Self {
        Self {
            listener,
            tls: None,
        }
    }

    pub fn tls(listener: TcpListener, config: Arc<rustls::ServerConfig>) -> Self {
        Self {
            listener,
            tls: Some(config),
        }
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
    fn tcp(&self) -> &TcpStream;
}

impl Conn for TcpStream {
    fn tcp(&self) -> &TcpStream {
        self
    }
}

impl Conn for ServerStream {
    fn tcp(&self) -> &TcpStream {
        &self.sock
    }
}

/// Accept loop shared by the TCP and WebSocket servers: loopback check,
/// connection limit, one thread per connection (TLS handshake included).
/// `serve` gets the connection, its caller and the peer address.
pub(crate) fn accept_loop<F>(endpoint: Endpoint, what: &str, shutdown: &Shutdown, serve: F)
where
    F: Fn(Box<dyn Conn>, Caller, Option<IpAddr>) -> io::Result<()> + Clone + Send + 'static,
{
    let active = Arc::new(AtomicUsize::new(0));
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
        if active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
            active.fetch_sub(1, Ordering::SeqCst);
            if endpoint.tls.is_none() {
                let _ = write_line(
                    &mut stream,
                    &json!({"id": null, "ok": false, "error": "too many connections"}),
                );
            }
            continue;
        }
        let counter = Arc::clone(&active);
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
                let conn: io::Result<Box<dyn Conn>> = match tls {
                    None => Ok(Box::new(stream)),
                    Some(cfg) => tls::accept(stream, cfg).map(|s| Box::new(s) as Box<dyn Conn>),
                };
                let result = conn.and_then(|c| serve(c, caller, peer.map(|p| p.ip())));
                if let Err(e) = result {
                    log::debug!("{label}: connection closed: {e}");
                }
                counter.fetch_sub(1, Ordering::SeqCst);
            });
        if let Err(e) = spawned {
            active.fetch_sub(1, Ordering::SeqCst);
            log::error!("{what}: cannot spawn connection thread: {e}");
        }
    }
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
        let out = handle(conn, &mut host, &gate, &caller, peer);
        hang_up(&mut host, &caller);
        out
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

/// The reply to one request, or `None` when it is not a JSON request (the
/// caller then drops the connection). Shared by TCP, TLS and WebSocket.
pub(crate) fn answer(
    host: &mut dyn Host,
    gate: &Gate,
    caller: &Caller,
    peer: Option<IpAddr>,
    text: &str,
) -> Option<Value> {
    let req = serde_json::from_str::<Request>(text).ok()?;
    let token = req.token.as_deref();
    let result = match req.method.as_str() {
        m if OPEN_METHODS.contains(&m) => dispatch_as(host, caller, m, &req.params).map(|mut v| {
            if m == "server.info"
                && let Some(o) = v.as_object_mut()
            {
                o.entry("auth").or_insert(json!("required"));
            }
            v
        }),
        "auth.login" => gate.login(host, caller, peer, &req.params),
        "auth.logout" => gate.logout(host, token),
        method => gate.principal(host, token).and_then(|p| {
            let caller = caller.clone().with_principal(p);
            if method == "auth.whoami" {
                whoami(host, &caller)
            } else {
                dispatch_as(host, &caller, method, &req.params)
            }
        }),
    };
    Some(match result {
        Ok(result) => json!({"id": req.id, "ok": true, "result": result}),
        Err(error) => json!({"id": req.id, "ok": false, "error": error}),
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
        let line = match read_line_bounded(&mut reader, MAX_REQUEST_LINE)? {
            Line::Eof => return Ok(()),
            Line::TooLong => {
                write_line(
                    reader.get_mut(),
                    &json!({"id": null, "ok": false, "error": "request line exceeds 16 MiB"}),
                )?;
                return Ok(());
            }
            Line::Text(t) => t,
        };
        if line.trim().is_empty() {
            continue;
        }
        // Not JSON (e.g. an HTTP request from a web page): drop the connection.
        let Some(reply) = answer(host, gate, caller, peer, &line) else {
            return Ok(());
        };
        write_line(reader.get_mut(), &reply)?;
    }
}
