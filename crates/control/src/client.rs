//! Synchronous control-channel client (CLI, MCP `Remote` backend, tests).

use std::io::{BufReader, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use serde_json::{Value, json};

use crate::wire::{Line, MAX_RESPONSE_LINE, read_line_bounded};

pub struct Client {
    reader: BufReader<TcpStream>,
    writer: TcpStream,
    next_id: u64,
    addr: String,
}

impl Client {
    pub fn connect(addr: &str, timeout: Duration) -> Result<Self, String> {
        let sock = addr
            .to_socket_addrs()
            .map_err(|e| format!("{addr}: {e}"))?
            .next()
            .ok_or_else(|| format!("{addr}: no address"))?;
        let stream =
            TcpStream::connect_timeout(&sock, timeout).map_err(|e| format!("{addr}: {e}"))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(120)))
            .map_err(|e| e.to_string())?;
        let reader = BufReader::new(stream.try_clone().map_err(|e| e.to_string())?);
        Ok(Self {
            reader,
            writer: stream,
            next_id: 0,
            addr: addr.to_owned(),
        })
    }

    pub fn addr(&self) -> &str {
        &self.addr
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
        let req = json!({"id": id, "method": method, "params": params});
        writeln!(self.writer, "{req}").map_err(|e| format!("send: {e}"))?;
        self.writer.flush().map_err(|e| format!("send: {e}"))?;
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
