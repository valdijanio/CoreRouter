//! The local control socket (G0.11): `control-<port>.sock` next to the
//! local token, in [`crate::local_token::runtime_dir`] (directory 0700,
//! socket 0600), served beside `127.0.0.1:<port>` with the same methods.
//!
//! On loopback TCP every user of the machine shares the source
//! `127.0.0.1`: any unprivileged local user could hold the logged-out
//! slots ([`crate::conn::MAX_UNAUTHENTICATED`]) and slow down or lock out
//! the CLI, MCP server and GUI of the router's own user. On this socket the
//! kernel says who connected (`SO_PEERCRED`: uid and pid, which the peer
//! cannot forge): the router's own operating-system user and root act as
//! [`Principal::Local`] with no token file at all, and **every other uid is
//! refused at once**, before any request: it gets no slot, logged in or
//! not (the directory and the socket mode already keep it out; the check
//! holds even if someone loosens them). A request with a token (a login
//! over the socket, `--user`) acts as that token says.
//!
//! Clients ([`crate::dial`]) prefer the socket for a loopback target and
//! fall back to TCP and the local token; they check the server's uid the
//! same way, so a socket left by another user is never trusted. Linux only
//! (`SO_PEERCRED`); elsewhere the TCP port and the token stay.
//! The same idea as FRR's vtysh sockets (`/var/run/frr/*.vty`, group
//! `frrvty`), OpenWrt's ubus (ACLs by the peer's uid) and the Docker socket.

use std::collections::HashMap;
use std::io::{self, BufReader, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::Duration;

use corerouter_engine::Principal;
use serde_json::json;

use crate::auth::Gate;
use crate::dispatch::{Host, new_caller};
use crate::server::{Shutdown, answer_as, serve_then_hang_up};
use crate::wire::{Line, MAX_REQUEST_LINE, read_line_bounded, write_line};

/// Most connections at once on the socket (all from allowed uids).
pub const MAX_CONNECTIONS: usize = 32;
/// Most of them from one uid, so root's tools and the router user's own
/// share the socket.
pub const MAX_PER_UID: usize = 24;
/// A write that makes no progress this long drops the connection.
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
/// Pause after a failed `accept` (out of file descriptors).
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// The socket of control port `port`.
pub fn path(port: u16) -> Option<PathBuf> {
    crate::local_token::runtime_dir().map(|d| d.join(format!("control-{port}.sock")))
}

/// The uid of this process.
pub fn my_uid() -> u32 {
    rustix::process::getuid().as_raw()
}

/// Who may use the socket: this process's own user, and root (who can read
/// the local token anyway).
pub fn trusted_uid(uid: u32, mine: u32) -> bool {
    uid == mine || uid == 0
}

/// The peer of a connected Unix socket: (uid, pid).
pub fn peer(stream: &UnixStream) -> io::Result<(u32, i32)> {
    let c = rustix::net::sockopt::socket_peercred(stream)?;
    Ok((c.uid.as_raw(), c.pid.as_raw_nonzero().get()))
}

/// A bound socket, removed again when its loop stops.
pub struct Listener {
    listener: UnixListener,
    path: PathBuf,
    /// The inode bound, so a newer router's socket at the same path is
    /// never removed.
    ino: u64,
}

impl Listener {
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The socket file, to remove at exit ([`SocketFile::remove`]): the
    /// accept loop removes it too when it stops, but a process that exits
    /// right after [`Shutdown::close`] may not let it run.
    pub fn file(&self) -> SocketFile {
        SocketFile {
            path: self.path.clone(),
            ino: self.ino,
        }
    }
}

/// A socket file this process bound.
#[derive(Debug, Clone)]
pub struct SocketFile {
    path: PathBuf,
    ino: u64,
}

impl SocketFile {
    /// Remove it if it is still the one bound (a newer router may have
    /// replaced it).
    pub fn remove(&self) {
        if std::fs::symlink_metadata(&self.path).is_ok_and(|m| m.ino() == self.ino) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Bind the socket of `port`: the directory made private, an old socket at
/// that path replaced (a stale one, or another router's: the newest owns
/// the port's token and socket), anything else at the path refused.
pub fn bind(port: u16) -> io::Result<Listener> {
    let path = path(port)
        .ok_or_else(|| io::Error::other("no runtime directory (set COREROUTER_RUNTIME_DIR)"))?;
    bind_at(&path)
}

pub fn bind_at(path: &Path) -> io::Result<Listener> {
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::other("socket path has no directory"))?;
    crate::local_token::create_private_dir(dir)?;
    match std::fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_socket() => {
            // A live one belongs to another router on this port (another
            // network namespace): replaced, as its token file is, so the
            // token and the socket always name the same router.
            if UnixStream::connect(path).is_ok() {
                log::warn!(
                    "{}: another process served this socket; it is replaced (as the local \
                     token file is): its clients now reach this router",
                    path.display()
                );
            }
            std::fs::remove_file(path)?;
        }
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("{} exists and is not a socket", path.display()),
            ));
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let listener = UnixListener::bind(path)?;
    // The directory (0700) already keeps others out; the mode says so too.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    let ino = std::fs::symlink_metadata(path)?.ino();
    Ok(Listener {
        listener,
        path: path.to_owned(),
        ino,
    })
}

#[derive(Default)]
struct Slots {
    total: usize,
    per_uid: HashMap<u32, usize>,
}

/// A taken connection slot, given back on drop.
struct Slot {
    slots: Arc<Mutex<Slots>>,
    uid: u32,
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut t = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
        t.total = t.total.saturating_sub(1);
        let gone = match t.per_uid.get_mut(&self.uid) {
            Some(n) => {
                *n = n.saturating_sub(1);
                *n == 0
            }
            None => false,
        };
        if gone {
            t.per_uid.remove(&self.uid);
        }
    }
}

fn take(slots: &Arc<Mutex<Slots>>, uid: u32) -> Result<Slot, &'static str> {
    let mut t = slots.lock().unwrap_or_else(PoisonError::into_inner);
    if t.total >= MAX_CONNECTIONS {
        return Err("too many connections");
    }
    let mine = t.per_uid.get(&uid).copied().unwrap_or(0);
    if mine >= MAX_PER_UID {
        return Err("too many connections from this user");
    }
    t.total = t.total.saturating_add(1);
    t.per_uid.insert(uid, mine.saturating_add(1));
    Ok(Slot {
        slots: slots.clone(),
        uid,
    })
}

/// Why a peer was refused, as a JSON line (it has not sent anything yet).
fn refuse(stream: &mut UnixStream, why: &str) {
    let _ = stream.set_write_timeout(Some(Duration::from_secs(1)));
    let _ = write_line(stream, &json!({"id": null, "ok": false, "error": why}));
}

/// Serve `listener` on the current thread until `shutdown` is closed; the
/// socket file is removed then (if it is still this one).
pub fn serve_until<H: Host + Clone + Send + 'static>(
    listener: Listener,
    host: H,
    gate: Gate,
    shutdown: &Shutdown,
) {
    let mine = my_uid();
    let slots = Arc::new(Mutex::new(Slots::default()));
    shutdown.watch_unix(&listener.path);
    if !shutdown.is_closed() {
        for conn in listener.listener.incoming() {
            if shutdown.is_closed() {
                break;
            }
            let mut stream = match conn {
                Ok(s) => s,
                Err(e) => {
                    log::warn!("control socket: accept failed: {e}");
                    thread::sleep(ACCEPT_BACKOFF);
                    continue;
                }
            };
            let (uid, pid) = match peer(&stream) {
                Ok(p) => p,
                Err(e) => {
                    log::warn!("control socket: no peer credentials ({e}); disconnected");
                    continue;
                }
            };
            if !trusted_uid(uid, mine) {
                log::warn!(
                    "control socket: uid {uid} (pid {pid}) is not the router's user (uid \
                     {mine}) nor root; refused"
                );
                refuse(
                    &mut stream,
                    "this socket is only for the operating-system user that runs the router \
                     (and root); connect to 127.0.0.1 and log in instead",
                );
                continue;
            }
            let slot = match take(&slots, uid) {
                Ok(s) => s,
                Err(why) => {
                    log::debug!("control socket: refused uid {uid}: {why}");
                    refuse(&mut stream, why);
                    continue;
                }
            };
            if let Err(e) = stream.set_write_timeout(Some(WRITE_TIMEOUT)) {
                log::debug!("control socket: write timeout not set: {e}");
            }
            let caller = new_caller("unix", format_args!("uid={uid} pid={pid}"));
            let mut host = host.clone();
            let gate = gate.clone();
            let spawned = thread::Builder::new()
                .name("control-unix".into())
                .spawn(move || {
                    let _slot = slot;
                    let result = serve_then_hang_up(&mut host, &caller, |host| {
                        handle(stream, host, &gate, &caller)
                    });
                    if let Err(e) = result {
                        log::debug!("control socket: connection closed: {e}");
                    }
                });
            if let Err(e) = spawned {
                log::error!("control socket: cannot spawn connection thread: {e}");
            }
        }
    }
    // Ours still (a newer router may have replaced it): remove it.
    listener.file().remove();
    log::info!("control socket {}: closed", listener.path.display());
}

/// [`serve_until`] on its own thread.
pub fn spawn_until<H: Host + Clone + Send + 'static>(
    listener: Listener,
    host: H,
    gate: Gate,
    shutdown: Shutdown,
) -> io::Result<thread::JoinHandle<()>> {
    thread::Builder::new()
        .name("control-unix".into())
        .spawn(move || serve_until(listener, host, gate, &shutdown))
}

/// One connection, until the client hangs up.
fn handle<H: Host>(
    stream: UnixStream,
    host: &mut H,
    gate: &Gate,
    caller: &corerouter_engine::Caller,
) -> io::Result<()> {
    let mut writer = stream.try_clone()?;
    let mut reader = BufReader::new(stream);
    loop {
        let line = match read_line_bounded(&mut reader, MAX_REQUEST_LINE)? {
            Line::Eof => return Ok(()),
            Line::TooLong => {
                write_line(
                    &mut writer,
                    &json!({"id": null, "ok": false, "error": "request line exceeds 16 MiB"}),
                )?;
                return Ok(());
            }
            Line::Text(t) => t,
        };
        if line.trim().is_empty() {
            continue;
        }
        let Some(answer) = answer_as(
            host,
            gate,
            caller,
            None,
            Some(&Principal::Local),
            &line,
            &mut || {},
        ) else {
            return Ok(());
        };
        answer.reply.send(&mut writer)?;
        writer.flush()?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_routers_user_and_root_are_trusted() {
        assert!(trusted_uid(1000, 1000));
        assert!(trusted_uid(0, 1000));
        assert!(trusted_uid(0, 0));
        assert!(!trusted_uid(1001, 1000));
        assert!(!trusted_uid(65534, 0));
    }

    #[test]
    fn slots_are_capped_in_total_and_per_uid() {
        let slots = Arc::new(Mutex::new(Slots::default()));
        let mut held: Vec<Slot> = (0..MAX_PER_UID)
            .map(|_| take(&slots, 1000).unwrap())
            .collect();
        assert!(take(&slots, 1000).is_err());
        while held.len() < MAX_CONNECTIONS {
            held.push(take(&slots, 0).unwrap());
        }
        assert!(take(&slots, 0).is_err());
        held.clear();
        assert_eq!(slots.lock().unwrap().total, 0);
        assert!(slots.lock().unwrap().per_uid.is_empty());
    }
}
