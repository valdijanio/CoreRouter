//! Loopback TCP server: one thread per connection, synchronous, no runtime.

use std::io::{self, BufReader, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

use serde::Deserialize;
use serde_json::{Value, json};

use crate::dispatch::{Host, dispatch};
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

/// Serve forever on the current thread.
pub fn serve<H: Host + Clone + Send + 'static>(listener: TcpListener, host: H) {
    let active = Arc::new(AtomicUsize::new(0));
    for conn in listener.incoming() {
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
        let host = host.clone();
        let counter = Arc::clone(&active);
        let spawned = thread::Builder::new()
            .name("control-conn".into())
            .spawn(move || {
                if let Err(e) = handle(stream, host) {
                    log::debug!("control: connection closed: {e}");
                }
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
pub(crate) fn answer(host: &mut dyn Host, text: &str) -> Option<Value> {
    let req = serde_json::from_str::<Request>(text).ok()?;
    Some(match dispatch(host, &req.method, &req.params) {
        Ok(result) => json!({"id": req.id, "ok": true, "result": result}),
        Err(error) => json!({"id": req.id, "ok": false, "error": error}),
    })
}

fn handle<H: Host>(stream: TcpStream, mut host: H) -> io::Result<()> {
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
        let Some(reply) = answer(&mut host, &line) else {
            return Ok(());
        };
        writeln!(out, "{reply}")?;
        out.flush()?;
    }
}
