//! The link to FRR's `bfdd` as its distributed data plane (G3.6b): `bfdd
//! --dplaneaddr unix:<frr>/bfdd_dplane.sock` listens, this thread connects
//! (again every second while it cannot), reads the `bfddp` stream
//! (`corerouter_proto_bfd::dplane`) and hands each message to the service
//! through a bounded queue. The service writes the answers and the state
//! changes on its own clone of the socket.

use std::io::{ErrorKind, Read};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::mpsc::SyncSender;
use std::time::Duration;

use corerouter_proto_bfd::dplane::{self, FromBfdd, MAX_MESSAGE};

/// What the reader tells the service.
pub(crate) enum DpIn {
    /// A new connection: the service writes on this clone.
    Connected(UnixStream),
    Msg(FromBfdd),
    /// The connection ended (or a message did not parse): the sessions go.
    Lost(String),
}

const SLICE: Duration = Duration::from_millis(200);
const RETRY: Duration = Duration::from_secs(1);
/// Messages waiting for the service (bfdd adds every session at connect).
pub(crate) const QUEUE: usize = 16_384;

/// The reader loop (a helper thread of the service).
pub(crate) fn run(path: PathBuf, tx: SyncSender<DpIn>, health: super::super::Health) {
    let mut warned = false;
    while !health.stopping() {
        let s = match UnixStream::connect(&path) {
            Ok(s) => s,
            Err(e) => {
                if !warned {
                    log::info!("BFD: no bfdd data plane socket at {} yet ({e}); retrying", path.display());
                    warned = true;
                }
                if !health.sleep(RETRY) {
                    return;
                }
                continue;
            }
        };
        warned = false;
        let writer = match s.try_clone() {
            Ok(w) => w,
            Err(e) => {
                let _ = tx.send(DpIn::Lost(e.to_string()));
                continue;
            }
        };
        log::info!("BFD: connected to bfdd ({}) as its data plane", path.display());
        if tx.send(DpIn::Connected(writer)).is_err() {
            return;
        }
        let why = read_loop(s, &tx, &health);
        let _ = tx.send(DpIn::Lost(why));
        if !health.sleep(RETRY) {
            return;
        }
    }
}

fn read_loop(mut s: UnixStream, tx: &SyncSender<DpIn>, health: &super::super::Health) -> String {
    let _ = s.set_read_timeout(Some(SLICE));
    let mut buf: Vec<u8> = Vec::with_capacity(4 * MAX_MESSAGE);
    let mut chunk = [0u8; 4096];
    loop {
        if health.stopping() {
            return "stopping".into();
        }
        match s.read(&mut chunk) {
            Ok(0) => return "bfdd closed the connection".into(),
            Ok(n) => buf.extend_from_slice(chunk.get(..n).unwrap_or(&[])),
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted) => {
                continue;
            }
            Err(e) => return e.to_string(),
        }
        // Whole messages out; a bad header ends the connection (the
        // stream cannot be resynchronized).
        loop {
            let h = match dplane::header(&buf) {
                Ok(Some(h)) => h,
                Ok(None) => break,
                Err(e) => return format!("bfdd sent a bad message: {e}"),
            };
            let len = usize::from(h.length);
            if buf.len() < len {
                break;
            }
            let msg = buf.get(..len).map(|m| dplane::decode(&h, m));
            buf.drain(..len);
            match msg {
                Some(Ok(m)) => {
                    if tx.send(DpIn::Msg(m)).is_err() {
                        return "service gone".into();
                    }
                }
                Some(Err(e)) => return format!("bfdd sent a bad message: {e}"),
                None => break,
            }
        }
    }
}
