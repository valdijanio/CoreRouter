//! Loopback TCP server: one thread per connection, synchronous, no runtime.

use std::io::{self, BufReader, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::Duration;

use serde::Deserialize;
use serde_json::{Value, json};

use corerouter_engine::Caller;

use crate::dispatch::{Host, dispatch_as, hang_up, new_caller};
use crate::wire::{Line, MAX_REQUEST_LINE, read_line_bounded};

pub const MAX_CONNECTIONS: usize = 16;

#[derive(Deserialize)]
struct Request {
    #[serde(default)]
    id: Value,
    method: String,
    #[serde(default)]
    params: Value,
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

/// Serve forever on the current thread.
pub fn serve<H: Host + Clone + Send + 'static>(listener: TcpListener, host: H) {
    serve_until(listener, host, &Shutdown::default());
}

/// Serve on the current thread until `shutdown` is closed.
pub fn serve_until<H: Host + Clone + Send + 'static>(
    listener: TcpListener,
    host: H,
    shutdown: &Shutdown,
) {
    let active = Arc::new(AtomicUsize::new(0));
    shutdown.watch(&listener);
    // A close that ran before `watch` did not wake this loop.
    if shutdown.is_closed() {
        return;
    }
    for conn in listener.incoming() {
        if shutdown.is_closed() {
            log::info!("control: no longer accepting connections");
            return;
        }
        let mut stream = match conn {
            Ok(s) => s,
            Err(e) => {
                log::warn!("control: accept failed: {e}");
                continue;
            }
        };
        if !stream.peer_addr().is_ok_and(|a| a.ip().is_loopback()) {
            log::warn!("control: rejected non-loopback peer");
            continue;
        }
        if active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
            active.fetch_sub(1, Ordering::SeqCst);
            let _ = writeln!(
                stream,
                "{}",
                json!({"id": null, "ok": false, "error": "too many connections"})
            );
            continue;
        }
        let mut host = host.clone();
        let counter = Arc::clone(&active);
        let caller = match stream.peer_addr() {
            Ok(peer) => new_caller("tcp", peer),
            Err(_) => new_caller("tcp", "?"),
        };
        let spawned = thread::Builder::new()
            .name("control-conn".into())
            .spawn(move || {
                if let Err(e) = handle(stream, &mut host, &caller) {
                    log::debug!("control: connection closed: {e}");
                }
                hang_up(&mut host, &caller);
                counter.fetch_sub(1, Ordering::SeqCst);
            });
        if let Err(e) = spawned {
            active.fetch_sub(1, Ordering::SeqCst);
            log::error!("control: cannot spawn connection thread: {e}");
        }
    }
}

/// Serve on a background thread.
pub fn spawn<H: Host + Clone + Send + 'static>(
    listener: TcpListener,
    host: H,
) -> io::Result<thread::JoinHandle<()>> {
    thread::Builder::new()
        .name("control".into())
        .spawn(move || serve(listener, host))
}

/// The reply to one request, or `None` when it is not a JSON request (the
/// caller then drops the connection). Shared by TCP and WebSocket.
pub(crate) fn answer(host: &mut dyn Host, caller: &Caller, text: &str) -> Option<Value> {
    let req = serde_json::from_str::<Request>(text).ok()?;
    Some(match dispatch_as(host, caller, &req.method, &req.params) {
        Ok(result) => json!({"id": req.id, "ok": true, "result": result}),
        Err(error) => json!({"id": req.id, "ok": false, "error": error}),
    })
}

/// Runs until the client hangs up; the caller then calls [`hang_up`].
fn handle<H: Host>(stream: TcpStream, host: &mut H, caller: &Caller) -> io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut out = stream;
    loop {
        let line = match read_line_bounded(&mut reader, MAX_REQUEST_LINE)? {
            Line::Eof => return Ok(()),
            Line::TooLong => {
                writeln!(
                    out,
                    "{}",
                    json!({"id": null, "ok": false, "error": "request line exceeds 16 MiB"})
                )?;
                return Ok(());
            }
            Line::Text(t) => t,
        };
        if line.trim().is_empty() {
            continue;
        }
        // Not JSON (e.g. an HTTP request from a web page): drop the connection.
        let Some(reply) = answer(host, caller, &line) else {
            return Ok(());
        };
        writeln!(out, "{reply}")?;
        out.flush()?;
    }
}
