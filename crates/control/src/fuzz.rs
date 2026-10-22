//! Fuzz oracles of the control channel (G0.5); see
//! `corerouter_engine::fuzz` for how they run and catch panics.

use std::io::{self, BufRead, Read};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

pub use corerouter_engine::fuzz::panics;
use corerouter_engine::{Caller, Session};
use serde_json::Value;

use crate::auth::{Gate, Limits};
use crate::dispatch::SharedHost;
use crate::server::answer;
use crate::wire::{Line, read_line_bounded};

/// Local token the [`control_line`] gate accepts.
pub const FUZZ_TOKEN: &str = "fuzz-local-token";

/// A reader that hands out at most `step` bytes per `fill_buf`, so lines
/// cross chunk boundaries the way they do on a slow TCP connection.
struct Chunked<'a> {
    data: &'a [u8],
    step: usize,
}

impl Read for Chunked<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let n = self.fill_buf()?.len().min(out.len());
        if let (Some(dst), Some(src)) = (out.get_mut(..n), self.data.get(..n)) {
            dst.copy_from_slice(src);
        }
        self.consume(n);
        Ok(n)
    }
}

impl BufRead for Chunked<'_> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        Ok(self
            .data
            .get(..self.step.min(self.data.len()))
            .unwrap_or_default())
    }
    fn consume(&mut self, n: usize) {
        self.data = self.data.get(n..).unwrap_or_default();
    }
}

/// [`read_line_bounded`] on `data`. The first byte picks the limit (1..=64)
/// and the chunk size (1..=4). Checks that every line fits the limit, holds
/// no `\n`, that the reader always ends, and that without over-long lines
/// the lines rebuild the input.
pub fn wire(data: &[u8]) -> Result<(), String> {
    let Some((&knobs, body)) = data.split_first() else {
        return Ok(());
    };
    let max = usize::from(knobs & 0x3f) + 1;
    let step = usize::from(knobs >> 6) + 1;
    let mut r = Chunked { data: body, step };
    let mut lines = Vec::new();
    let mut too_long = false;
    // Every call but the last consumes at least one byte.
    for _ in 0..=body.len() {
        match read_line_bounded(&mut r, max).map_err(|e| e.to_string())? {
            Line::Eof => {
                if !too_long {
                    let expected: Vec<String> = body
                        .split(|&b| b == b'\n')
                        .map(|l| String::from_utf8_lossy(l.strip_suffix(b"\r").unwrap_or(l)))
                        .map(|l| l.into_owned())
                        .collect();
                    // After a trailing '\n' (or in no input) the empty last
                    // piece is no line.
                    let expected = match expected.split_last() {
                        Some((_, rest)) if body.is_empty() || body.ends_with(b"\n") => {
                            rest.to_vec()
                        }
                        _ => expected,
                    };
                    if lines != expected {
                        return Err(format!("lines {lines:?} do not rebuild {expected:?}"));
                    }
                }
                return Ok(());
            }
            Line::TooLong => too_long = true,
            Line::Text(t) => {
                // Lossy UTF-8 may grow invalid bytes to 3-byte U+FFFD.
                if t.contains('\n') || t.chars().count() > max {
                    return Err(format!("line {t:?} breaks the limit {max}"));
                }
                lines.push(t);
            }
        }
    }
    Err("read_line_bounded did not reach EOF".into())
}

/// One control-channel request line, as TCP, TLS and WebSocket answer it,
/// on a fresh virtual lab. A JSON object without `token` gets the local
/// one, so the fuzzer reaches the commands behind the gate.
pub fn control_line(data: &[u8]) -> Result<(), String> {
    let text = String::from_utf8_lossy(data);
    let line = match serde_json::from_str::<Value>(&text) {
        Ok(Value::Object(mut o)) if !o.contains_key("token") => {
            o.insert("token".into(), FUZZ_TOKEN.into());
            Value::Object(o).to_string()
        }
        _ => text.into_owned(),
    };
    let gate = Gate::new(Limits {
        base_delay: Duration::ZERO,
        max_delay: Duration::ZERO,
        ..Limits::default()
    });
    gate.add_local_token(FUZZ_TOKEN);
    let mut host = SharedHost(corerouter_engine::shared(Session::virtual_lab()));
    let peer = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let caller = Caller::new(1, "fuzz");
    let (reply, panicked) = panics(|| answer(&mut host, &gate, &caller, peer, &line));
    if panicked > 0 {
        return Err(format!("{panicked} panic(s) answering {line}"));
    }
    match reply {
        None => Ok(()), // not a request: the server hangs up
        Some(r) if r.get("ok").and_then(Value::as_bool).is_some() => Ok(()),
        Some(r) => Err(format!("reply without ok: {r}")),
    }
}
