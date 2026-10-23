//! Synchronous control-channel client (CLI, MCP `Remote` backend, GUI,
//! tests), over plain TCP or TLS, sending its token with every request.
//! Most callers use [`crate::dial`], which also logs in and pins the TLS
//! certificate.

use std::io::{self, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use serde_json::{Value, json};

use crate::tls::{self, ClientStream, TlsError};
use crate::wire::{Line, MAX_RESPONSE_LINE, read_line_bounded, write_line};

enum Stream {
    Plain(TcpStream),
    Tls(Box<ClientStream>),
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Plain(s) => s.read(buf),
            Self::Tls(s) => s.read(buf),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Plain(s) => s.write(buf),
            Self::Tls(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(s) => s.flush(),
            Self::Tls(s) => s.flush(),
        }
    }
}

pub struct Client {
    reader: BufReader<Stream>,
    next_id: u64,
    addr: String,
    token: Option<String>,
    fingerprint: Option<String>,
}

/// Connect to the first address of `addr` that answers, in resolver order.
fn open(addr: &str, timeout: Duration) -> Result<TcpStream, String> {
    let socks: Vec<SocketAddr> = addr
        .to_socket_addrs()
        .map_err(|e| format!("{addr}: {e}"))?
        .collect();
    let mut last = format!("{addr}: no address");
    let mut found = None;
    for sock in socks {
        match TcpStream::connect_timeout(&sock, timeout) {
            Ok(s) => {
                found = Some(s);
                break;
            }
            Err(e) => last = format!("{addr}: {e}"),
        }
    }
    let stream = found.ok_or(last)?;
    // Requests are small and answered one by one: send each at once.
    stream.set_nodelay(true).map_err(|e| e.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(120)))
        .map_err(|e| e.to_string())?;
    Ok(stream)
}

impl Client {
    /// Plain TCP (the router only accepts it on loopback).
    pub fn connect(addr: &str, timeout: Duration) -> Result<Self, String> {
        let stream = open(addr, timeout)?;
        Ok(Self::over(Stream::Plain(stream), addr, None))
    }

    /// TLS, pinned to `expected` (or to whatever the router shows when
    /// `None`: check [`Client::fingerprint`] before sending anything secret).
    pub fn connect_tls(
        addr: &str,
        timeout: Duration,
        expected: Option<&str>,
    ) -> Result<Self, TlsError> {
        let stream = open(addr, timeout).map_err(TlsError::Other)?;
        stream
            .set_read_timeout(Some(tls::HANDSHAKE_TIMEOUT))
            .map_err(|e| TlsError::Other(e.to_string()))?;
        let (s, fp) = tls::connect(stream, expected)?;
        s.sock
            .set_read_timeout(Some(Duration::from_secs(120)))
            .map_err(|e| TlsError::Other(e.to_string()))?;
        Ok(Self::over(Stream::Tls(Box::new(s)), addr, Some(fp)))
    }

    fn over(stream: Stream, addr: &str, fingerprint: Option<String>) -> Self {
        Self {
            reader: BufReader::new(stream),
            next_id: 0,
            addr: addr.to_owned(),
            token: None,
            fingerprint,
        }
    }

    pub fn addr(&self) -> &str {
        &self.addr
    }

    /// The socket address actually connected to.
    pub fn peer(&self) -> Option<SocketAddr> {
        match self.reader.get_ref() {
            Stream::Plain(s) => s.peer_addr().ok(),
            Stream::Tls(s) => s.sock.peer_addr().ok(),
        }
    }

    /// The router's certificate fingerprint (TLS only).
    pub fn fingerprint(&self) -> Option<&str> {
        self.fingerprint.as_deref()
    }

    pub fn is_tls(&self) -> bool {
        matches!(self.reader.get_ref(), Stream::Tls(_))
    }

    /// True when, between requests, the router has closed this plain
    /// connection (restart, idle cut) or sent bytes nobody asked for: a
    /// request on it would fail or read a stale reply, so long-lived
    /// clients (the MCP backend) reconnect first. Over TLS only a closed
    /// or broken socket counts (session tickets may arrive unasked).
    pub fn is_stale(&self) -> bool {
        if !self.reader.buffer().is_empty() {
            return true;
        }
        let (sock, tls) = match self.reader.get_ref() {
            Stream::Plain(s) => (s, false),
            Stream::Tls(s) => (&s.sock, true),
        };
        if sock.set_nonblocking(true).is_err() {
            return true;
        }
        let mut b = [0u8; 1];
        let peeked = sock.peek(&mut b);
        if sock.set_nonblocking(false).is_err() {
            return true;
        }
        match peeked {
            Err(e) => e.kind() != io::ErrorKind::WouldBlock,
            Ok(0) => true,
            Ok(_) => !tls,
        }
    }

    /// The token sent with every request from now on.
    pub fn set_token(&mut self, token: Option<String>) {
        self.token = token;
    }

    pub fn token(&self) -> Option<&str> {
        self.token.as_deref()
    }

    /// `auth.login`; on success the token is kept for the next requests.
    /// Returns `{token, user, group, idle_timeout_secs}`.
    pub fn login(&mut self, user: &str, password: &str) -> Result<Value, String> {
        let reply = self.call("auth.login", json!({"user": user, "password": password}))?;
        let token = reply
            .get("token")
            .and_then(Value::as_str)
            .ok_or("the router sent no token")?;
        self.token = Some(token.to_owned());
        Ok(reply)
    }

    pub fn call(&mut self, method: &str, params: Value) -> Result<Value, String> {
        self.request(method, params)?
    }

    /// Like [`Client::call`], but tells the two failures apart: the outer
    /// `Err` means the connection is gone (reconnect before the next call),
    /// the inner one is the router refusing the request.
    pub fn request(
        &mut self,
        method: &str,
        params: Value,
    ) -> Result<Result<Value, String>, String> {
        self.next_id = self.next_id.wrapping_add(1);
        let id = self.next_id;
        let mut req = json!({"id": id, "method": method, "params": params});
        if let (Some(t), Some(o)) = (&self.token, req.as_object_mut()) {
            o.insert("token".into(), json!(t));
        }
        write_line(self.reader.get_mut(), &req).map_err(|e| format!("send: {e}"))?;
        let line = match read_line_bounded(&mut self.reader, MAX_RESPONSE_LINE) {
            Ok(Line::Text(t)) => t,
            Ok(Line::TooLong) => return Err("response exceeds 256 MiB".into()),
            Ok(Line::Eof) => return Err("connection closed by the router".into()),
            Err(e) => return Err(format!("receive: {e}")),
        };
        let reply: Value = serde_json::from_str(&line).map_err(|e| format!("bad reply: {e}"))?;
        Ok(reply_result(&reply))
    }
}

/// `{"ok": true, "result"}` | `{"ok": false, "error"}` → `Result`.
pub fn reply_result(reply: &Value) -> Result<Value, String> {
    if reply.get("ok").and_then(Value::as_bool) == Some(true) {
        Ok(reply.get("result").cloned().unwrap_or(Value::Null))
    } else {
        Err(reply
            .get("error")
            .and_then(Value::as_str)
            .unwrap_or("unknown error")
            .to_owned())
    }
}
