//! The vty socket of an FRR daemon (`/var/run/frr/<daemon>.vty`), spoken
//! directly: the protocol `vtysh` itself uses, without starting `vtysh`.
//!
//! One command per request, ended by a NUL byte; the daemon answers with
//! the command's output and then four bytes, `0 0 0 <code>` (FRR
//! `lib/vty.c`, `vtysh_read`: "watchfrr hardcodes this result write").
//! The daemon reads one command at a time and expects the client to wait
//! for each answer. A new connection starts in the view node.

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

/// FRR's command buffer (`VTY_BUFSIZ`); a longer command is refused by the
/// daemon ("Command is too long"), so it is refused here first.
pub const MAX_COMMAND: usize = 4095;

/// `CMD_SUCCESS` and the codes that also mean "done" (lib/command.h).
pub const CMD_SUCCESS: u8 = 0;
pub const CMD_WARNING: u8 = 1;
pub const CMD_SUCCESS_DAEMON: u8 = 10;
pub const CMD_WARNING_CONFIG_FAILED: u8 = 13;

/// A command's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    pub code: u8,
    /// The output, as the daemon wrote it (text, or JSON for `… json`).
    pub output: Vec<u8>,
}

impl Reply {
    pub fn ok(&self) -> bool {
        matches!(self.code, CMD_SUCCESS | CMD_SUCCESS_DAEMON)
    }

    /// The output as text, cut to `max` bytes for error messages (the
    /// daemon's text is not trusted to be short).
    pub fn text(&self, max: usize) -> String {
        let cut = self.output.get(..max).unwrap_or(&self.output);
        String::from_utf8_lossy(cut).trim().to_owned()
    }
}

/// What a code means, for error messages.
pub fn code_name(code: u8) -> &'static str {
    match code {
        0 => "success",
        1 => "warning",
        2 => "unknown command",
        3 => "ambiguous command",
        4 => "incomplete command",
        5 => "too many arguments",
        6 => "nothing to do",
        13 => "configuration failed",
        14 => "not my instance",
        15 => "no level up",
        16 => "no daemon",
        _ => "error",
    }
}

/// One connection to a daemon.
pub struct Vty {
    stream: UnixStream,
    buf: Vec<u8>,
    chunk: Vec<u8>,
    max_reply: usize,
}

impl Vty {
    /// Connect to `path`, with `timeout` on every read and write (a daemon
    /// that stops answering fails the call instead of hanging the caller)
    /// and answers bounded by `max_reply` bytes.
    pub fn connect(path: &Path, timeout: Duration, max_reply: usize) -> io::Result<Self> {
        let stream = UnixStream::connect(path)?;
        stream.set_read_timeout(Some(timeout))?;
        stream.set_write_timeout(Some(timeout))?;
        Ok(Vty {
            stream,
            buf: Vec::with_capacity(64 * 1024),
            chunk: vec![0u8; 256 * 1024],
            max_reply,
        })
    }

    /// Run one command and wait for its answer.
    pub fn run(&mut self, command: &str) -> io::Result<Reply> {
        if command.len() > MAX_COMMAND || command.bytes().any(|b| b == 0 || b == b'\n') {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "command refused: longer than {MAX_COMMAND} bytes or with a NUL/newline: {}",
                    command.chars().take(80).collect::<String>()
                ),
            ));
        }
        let mut msg = Vec::with_capacity(command.len() + 1);
        msg.extend_from_slice(command.as_bytes());
        msg.push(0);
        self.stream.write_all(&msg)?;
        self.read_reply()
    }

    fn read_reply(&mut self) -> io::Result<Reply> {
        self.buf.clear();
        let mut scanned = 0usize;
        loop {
            // The end marker: three NULs and the code. Text never holds a
            // NUL, so the first run of three is the marker.
            let from = scanned.saturating_sub(3);
            if let Some(pos) = self
                .buf
                .get(from..)
                .and_then(|tail| tail.windows(3).position(|w| w == [0, 0, 0]))
                .map(|p| p + from)
                && let Some(&code) = self.buf.get(pos + 3)
            {
                let mut output = std::mem::take(&mut self.buf);
                output.truncate(pos);
                return Ok(Reply { code, output });
            }
            scanned = self.buf.len();
            if self.buf.len() > self.max_reply {
                return Err(io::Error::other(format!(
                    "answer longer than {} bytes",
                    self.max_reply
                )));
            }
            let n = self.stream.read(&mut self.chunk)?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "the daemon closed the vty connection",
                ));
            }
            self.buf
                .extend_from_slice(self.chunk.get(..n).unwrap_or_default());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use std::thread;

    /// A fake daemon: answers each NUL-ended command with `f(command)`,
    /// written in small pieces so the marker can straddle two reads.
    fn fake(f: fn(&str) -> (Vec<u8>, u8)) -> (tempdir::Dir, std::path::PathBuf) {
        let dir = tempdir::Dir::new();
        let path = dir.0.join("bgpd.vty");
        let listener = UnixListener::bind(&path).unwrap();
        thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut pending = Vec::new();
            let mut b = [0u8; 64];
            loop {
                let n = match s.read(&mut b) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => n,
                };
                pending.extend_from_slice(&b[..n]);
                while let Some(end) = pending.iter().position(|&c| c == 0) {
                    let cmd = String::from_utf8(pending[..end].to_vec()).unwrap();
                    pending.drain(..=end);
                    let (out, code) = f(&cmd);
                    let mut msg = out;
                    msg.extend_from_slice(&[0, 0, 0, code]);
                    for piece in msg.chunks(5) {
                        s.write_all(piece).unwrap();
                    }
                }
            }
        });
        (dir, path)
    }

    mod tempdir {
        pub struct Dir(pub std::path::PathBuf);
        impl Dir {
            pub fn new() -> Self {
                let p = std::env::temp_dir().join(format!(
                    "crfrr-{}-{:?}",
                    std::process::id(),
                    std::thread::current().id()
                ));
                let _ = std::fs::remove_dir_all(&p);
                std::fs::create_dir_all(&p).unwrap();
                Dir(p)
            }
        }
        impl Drop for Dir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }

    #[test]
    fn commands_and_answers() {
        let (_d, path) = fake(|cmd| match cmd {
            "show version" => (b"FRRouting 10.7.1 (r1).\n".to_vec(), 0),
            "bad" => (b"% Unknown command: bad\n".to_vec(), 2),
            _ => (Vec::new(), 0),
        });
        let mut v = Vty::connect(&path, Duration::from_secs(5), 1 << 20).unwrap();
        let r = v.run("show version").unwrap();
        assert!(r.ok());
        assert_eq!(r.text(100), "FRRouting 10.7.1 (r1).");
        let r = v.run("bad").unwrap();
        assert_eq!((r.ok(), r.code), (false, 2));
        assert_eq!(code_name(r.code), "unknown command");
        assert!(v.run("").unwrap().output.is_empty());
    }

    #[test]
    fn hostile_commands_and_answers_are_refused() {
        let (_d, path) = fake(|_| (vec![b'x'; 10_000], 0));
        let mut v = Vty::connect(&path, Duration::from_secs(5), 4096).unwrap();
        assert!(v.run("a\0b").is_err());
        assert!(v.run("a\nb").is_err());
        assert!(v.run(&"x".repeat(MAX_COMMAND + 1)).is_err());
        let e = v.run("show").unwrap_err();
        assert!(e.to_string().contains("longer than 4096"));
    }
}
