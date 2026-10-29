//! A package that arrives over the network (G1.6e): the control channel
//! hands its chunks to a bounded queue, and the A/B code reads that queue as
//! a stream ([`ChunkReader`]) — the package goes to the inactive slot as it
//! arrives, never whole in RAM. [`check`] is `system.package.check` on any
//! stream (a file or an upload).

use std::io::Read;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::package::{self, Header, Key};

/// Reads the chunks of an upload of `size` bytes from `rx`. The sender
/// going away before `size` bytes is an abort; no chunk for `stall` is an
/// abandoned upload (the client died); more than `size` bytes is refused.
pub struct ChunkReader {
    rx: Receiver<Vec<u8>>,
    size: u64,
    got: u64,
    stall: Duration,
    buf: Vec<u8>,
    at: usize,
    /// What the stream is, in errors (`upload`, `download`).
    what: &'static str,
    /// Time spent waiting for the network (the rest is the disk's).
    pub waited: Duration,
}

impl ChunkReader {
    pub fn new(rx: Receiver<Vec<u8>>, size: u64, stall: Duration) -> ChunkReader {
        ChunkReader {
            rx,
            size,
            got: 0,
            stall,
            buf: Vec::new(),
            at: 0,
            what: "upload",
            waited: Duration::ZERO,
        }
    }

    /// Names the stream in errors (`download`).
    pub fn named(mut self, what: &'static str) -> ChunkReader {
        self.what = what;
        self
    }

    /// Bytes received so far.
    pub fn received(&self) -> u64 {
        self.got
    }
}

fn io_err(msg: String) -> std::io::Error {
    std::io::Error::other(msg)
}

impl Read for ChunkReader {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        while self.at >= self.buf.len() {
            if self.got >= self.size {
                return Ok(0);
            }
            let t = Instant::now();
            let next = self.rx.recv_timeout(self.stall);
            self.waited += t.elapsed();
            match next {
                Ok(chunk) => {
                    self.got = self.got.saturating_add(chunk.len() as u64);
                    if self.got > self.size {
                        return Err(io_err(format!(
                            "{}: more than the declared {} bytes",
                            self.what, self.size
                        )));
                    }
                    self.buf = chunk;
                    self.at = 0;
                }
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(io_err(format!(
                        "{} aborted after {} of {} bytes",
                        self.what, self.got, self.size
                    )));
                }
                Err(RecvTimeoutError::Timeout) => {
                    return Err(io_err(format!(
                        "{} stalled: no data for {} s after {} of {} bytes",
                        self.what,
                        self.stall.as_secs(),
                        self.got,
                        self.size
                    )));
                }
            }
        }
        let rest = self.buf.get(self.at..).unwrap_or_default();
        let n = rest.len().min(out.len());
        if let (Some(dst), Some(src)) = (out.get_mut(..n), rest.get(..n)) {
            dst.copy_from_slice(src);
        }
        self.at += n;
        Ok(n)
    }
}

/// A package's header, signature and payload hashes, without installing:
/// what `system.package.check` answers. `exact`: the stream's size when
/// known (it must be the manifest's).
pub fn check<R: Read + Send>(
    src: &mut R,
    exact: Option<u64>,
    keys: &[Key],
) -> Result<Value, String> {
    let t = Instant::now();
    let h = Header::read(src)?;
    let signer = h.verify(keys).map(|k| k.id_hex());
    let m = &h.manifest;
    let size = h.len() + m.kernel.size + m.rootfs.size;
    if let Some(len) = exact
        && len != size
    {
        return Err(format!("package is {len} bytes, its manifest says {size}"));
    }
    let mut sink = std::io::sink();
    let mut sink2 = std::io::sink();
    let mut parts: [(u64, &mut dyn std::io::Write); 2] =
        [(m.kernel.size, &mut sink), (m.rootfs.size, &mut sink2)];
    let c = package::copy(src, &mut parts, true, &mut |_| {})?;
    let intact =
        c.sha256.first() == Some(&m.kernel.sha256) && c.sha256.get(1) == Some(&m.rootfs.sha256);
    Ok(json!({
        "version": m.version, "build": m.build, "commit": m.commit, "channel": m.channel,
        "kernel": m.kernel_version, "config_format": m.config_format,
        "size": size,
        "signed_by": signer.as_ref().ok(),
        "signature": signer.as_ref().err().map_or("ok", |e| e.as_str()),
        "intact": intact, "millis": t.elapsed().as_millis() as u64,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc::sync_channel;

    #[test]
    fn reads_chunks_across_boundaries() {
        let (tx, rx) = sync_channel(4);
        tx.send(vec![1, 2, 3]).unwrap();
        tx.send(vec![4]).unwrap();
        tx.send(vec![5, 6]).unwrap();
        drop(tx);
        let mut r = ChunkReader::new(rx, 6, Duration::from_secs(1));
        let mut out = [0u8; 5];
        r.read_exact(&mut out).unwrap();
        assert_eq!(out, [1, 2, 3, 4, 5]);
        let mut rest = Vec::new();
        r.read_to_end(&mut rest).unwrap();
        assert_eq!(rest, [6]);
        assert_eq!(r.received(), 6);
    }

    #[test]
    fn abort_stall_and_overflow_are_errors() {
        let (tx, rx) = sync_channel(4);
        tx.send(vec![0; 10]).unwrap();
        drop(tx);
        let mut r = ChunkReader::new(rx, 20, Duration::from_secs(1));
        let mut out = vec![0u8; 20];
        let e = r.read_exact(&mut out).unwrap_err().to_string();
        assert!(e.contains("aborted after 10 of 20"), "{e}");

        let (tx, rx) = sync_channel::<Vec<u8>>(1);
        let mut r = ChunkReader::new(rx, 20, Duration::from_millis(20));
        let e = r.read(&mut out).unwrap_err().to_string();
        assert!(e.contains("stalled"), "{e}");
        drop(tx);

        let (tx, rx) = sync_channel(1);
        tx.send(vec![0; 30]).unwrap();
        let mut r = ChunkReader::new(rx, 20, Duration::from_secs(1));
        let e = r.read(&mut out).unwrap_err().to_string();
        assert!(e.contains("more than"), "{e}");
    }
}
