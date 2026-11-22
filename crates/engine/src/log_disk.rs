//! G4.6g: the `disk` action's files, the part without I/O (the writer is the
//! daemon's `service/disk_log.rs`): one event per line of JSON, in
//! `<config-dir>/log/<disk_file_name>.<n>.txt`. As in RouterOS, `.0` is the
//! file being written; when it holds `disk_lines_per_file` it becomes `.1`.
//!
//! The files come back at boot and are hostile input like any other (a torn
//! write, a bad flash, a hand edit): a bad line costs that line, never the
//! boot. What comes back is checked as if it were new: topics from the
//! model's list, message and origin on one line without terminal escapes,
//! everything bounded. The `seq` is not in the file: numbers are per boot.

use corerouter_model::logging::{LogEvent, MAX_TOPICS, TOPICS};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::logging::{bounded, cut, one_line};

/// The subdirectory of the config directory.
pub const DIR: &str = "log";
/// A longer line is damage (an encoded event has at most 2 KiB of detail,
/// about 1 KiB of message and its escapes).
pub const MAX_LINE: usize = 16 << 10;
/// Most lines kept for `log.print` beyond `memory` (the most one `log.print`
/// returns, `cmd::log::MAX_PRINT`: nothing older could be asked for).
pub const WINDOW: usize = 2000;
/// Most bytes of one file read at boot (its tail).
pub const MAX_RESTORE_BYTES: u64 = 8 << 20;
/// Lines waiting for the writer; more are counted and dropped.
pub const MAX_QUEUE: usize = 16_384;
const MAX_ORIGIN: usize = 128;
const MAX_MESSAGE: usize = 2048;

#[derive(Serialize, Deserialize)]
struct Line {
    time: u64,
    topics: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    origin: String,
    message: String,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    detail: Value,
}

/// The line of an event, with its newline (`None`: it does not fit
/// [`MAX_LINE`], or cannot be encoded).
pub fn encode(e: &LogEvent) -> Option<String> {
    let line = Line {
        time: e.time,
        topics: e.topics.clone(),
        origin: e.origin.clone(),
        message: e.message.clone(),
        detail: e.detail.clone(),
    };
    let mut text = serde_json::to_string(&line).ok()?;
    text.push('\n');
    (text.len() <= MAX_LINE).then_some(text)
}

/// One line back into an event, `seq` 0 (the caller numbers it).
pub fn decode(line: &[u8]) -> Result<LogEvent, String> {
    if line.len() > MAX_LINE {
        return Err(format!("line of {} bytes", line.len()));
    }
    let l: Line = serde_json::from_slice(line).map_err(|e| cut(&e.to_string(), 64))?;
    if l.topics.is_empty() || l.topics.len() > MAX_TOPICS {
        return Err(format!("{} topics", l.topics.len()));
    }
    if let Some(t) = l.topics.iter().find(|t| !TOPICS.contains(&t.as_str())) {
        return Err(format!("unknown topic '{}'", cut(t, 16)));
    }
    Ok(LogEvent {
        seq: 0,
        time: l.time,
        topics: l.topics,
        origin: cut(&one_line(&l.origin), MAX_ORIGIN),
        message: cut(&one_line(&l.message), MAX_MESSAGE),
        detail: bounded(&l.detail),
    })
}

/// The events of a file's bytes, and how many lines were bad. A last line
/// without its newline is what a crash leaves: left out, and not counted as
/// damage when it is the only thing wrong.
pub fn decode_all(bytes: &[u8]) -> (Vec<LogEvent>, usize) {
    let (mut out, mut bad) = (Vec::new(), 0);
    let mut lines = bytes.split(|b| *b == b'\n').peekable();
    while let Some(line) = lines.next() {
        // Past the last newline: empty, or the torn line.
        if lines.peek().is_none() {
            break;
        }
        if line.is_empty() {
            continue;
        }
        match decode(line) {
            Ok(e) => out.push(e),
            Err(_) => bad += 1,
        }
    }
    (out, bad)
}

/// `log.3.txt`.
pub fn file_name(name: &str, n: u32) -> String {
    format!("{name}.{n}.txt")
}

/// The `n` of a file of the action named `name` (strict: `log.03.txt`,
/// `log.3.txt.bak` and a neighbor's `log2.3.txt` are not its files).
pub fn file_number(name: &str, file: &str) -> Option<u32> {
    let digits = file.strip_prefix(name)?.strip_prefix('.')?.strip_suffix(".txt")?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) || (digits.len() > 1 && digits.starts_with('0')) {
        return None;
    }
    digits.parse().ok()
}
