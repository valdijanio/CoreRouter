//! Passive CRDP listener for a management workstation (the native GUI's
//! connect screen): hears announcements on every interface of this
//! machine, never sends anything.

use std::collections::BTreeMap;
use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};

use corerouter_proto_discovery::{Announcement, MAX_PACKET, NodeId};

use crate::ifaces;
use crate::sock;

/// Re-join `ff02::1` on new interfaces this often.
const RESCAN: Duration = Duration::from_secs(10);
/// Most routers remembered (a flood evicts the oldest).
pub const MAX_HEARD: usize = 1024;

/// One router as last heard.
#[derive(Debug, Clone)]
pub struct Heard {
    pub announcement: Announcement,
    pub from: SocketAddr,
    /// This machine's interface it arrived on, when known.
    pub interface: Option<String>,
    /// The router runs on this machine: reach it over loopback.
    pub local: bool,
    pub at: Instant,
}

impl Heard {
    /// `HOST:PORT` of its control channel, as `--connect` takes it: loopback
    /// for a router on this machine, else its first announced IPv4, else
    /// the packet source (with the scope of a link-local address).
    pub fn connect_to(&self) -> Option<String> {
        let port = self.announcement.control_port?;
        if self.local {
            return Some(format!("127.0.0.1:{port}"));
        }
        if let Some((v4, _)) = self.announcement.ipv4.first() {
            return Some(format!("{v4}:{port}"));
        }
        Some(match self.from {
            SocketAddr::V4(a) => format!("{}:{port}", a.ip()),
            SocketAddr::V6(a) if a.scope_id() != 0 => {
                format!("[{}%{}]:{port}", a.ip(), a.scope_id())
            }
            SocketAddr::V6(a) => format!("[{}]:{port}", a.ip()),
        })
    }

    pub fn expired(&self, now: Instant) -> bool {
        now.duration_since(self.at) >= Duration::from_secs(u64::from(self.announcement.hold_secs))
    }
}

/// Threads that fill a channel; [`Listener::poll`] folds it into the list.
pub struct Listener {
    rx: Receiver<Heard>,
    heard: BTreeMap<NodeId, Heard>,
    stop: Arc<AtomicBool>,
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

impl Listener {
    /// Listen on UDP `port` (IPv4 broadcast and IPv6 `ff02::1`). The threads
    /// stop when the listener is dropped.
    pub fn spawn(port: u16) -> io::Result<Listener> {
        let (tx, rx) = mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let v4 = sock::listen_v4(port);
        let v6 = sock::listen_v6(port);
        if let (Err(e4), Err(e6)) = (&v4, &v6) {
            return Err(io::Error::new(
                e4.kind(),
                format!("UDP {port}: IPv4 {e4}; IPv6 {e6}"),
            ));
        }
        for (name, s) in [("crdp-listen4", v4), ("crdp-listen6", v6)] {
            match s {
                Ok(s) => {
                    let (tx, stop) = (tx.clone(), stop.clone());
                    thread::Builder::new()
                        .name(name.into())
                        .spawn(move || listen(&s, &tx, &stop))?;
                }
                Err(e) => log::warn!("{name}: {e}"),
            }
        }
        Ok(Listener {
            rx,
            heard: BTreeMap::new(),
            stop,
        })
    }

    /// Fold in what arrived and drop what expired. Never blocks.
    pub fn poll(&mut self) -> Vec<&Heard> {
        while let Ok(h) = self.rx.try_recv() {
            let id = h.announcement.node_id;
            if h.announcement.hold_secs == 0 {
                self.heard.remove(&id);
                continue;
            }
            if !self.heard.contains_key(&id) && self.heard.len() >= MAX_HEARD {
                let oldest = self.heard.iter().min_by_key(|(_, h)| h.at).map(|(k, _)| *k);
                if let Some(k) = oldest {
                    self.heard.remove(&k);
                }
            }
            self.heard.insert(id, h);
        }
        let now = Instant::now();
        self.heard.retain(|_, h| !h.expired(now));
        self.heard.values().collect()
    }
}

fn listen(sock: &UdpSocket, tx: &Sender<Heard>, stop: &AtomicBool) {
    let v6 = sock.local_addr().is_ok_and(|a| a.is_ipv6());
    let mut kernel = ifaces::read();
    let mut joined_at: Option<Instant> = None;
    let mut buf = [0u8; MAX_PACKET + 1];
    let mut local: BTreeMap<(IpAddr, u32), bool> = BTreeMap::new();
    while !stop.load(Ordering::Relaxed) {
        if v6 && joined_at.is_none_or(|t| t.elapsed() >= RESCAN) {
            kernel = ifaces::read();
            sock::join_all_nodes(sock, 0);
            for (_, i) in kernel.iter() {
                sock::join_all_nodes(sock, i.index);
            }
            joined_at = Some(Instant::now());
        }
        let Some((announcement, from)) = sock::receive(sock, &mut buf) else {
            continue;
        };
        let scope = match from {
            SocketAddr::V6(a) => a.scope_id(),
            SocketAddr::V4(_) => 0,
        };
        if local.len() > MAX_HEARD {
            local.clear();
        }
        let is_local = *local.entry((from.ip(), scope)).or_insert_with(|| {
            // A link-local address of this machine may arrive with the
            // scope of another of its links (veth pairs, bridges).
            sock::is_local(from.ip(), scope)
                || matches!(from.ip(), IpAddr::V6(a) if kernel.has_address(&a))
        });
        let heard = Heard {
            announcement,
            from,
            interface: (scope != 0)
                .then(|| kernel.name_of(scope).map(str::to_owned))
                .flatten(),
            local: is_local,
            at: Instant::now(),
        };
        if tx.send(heard).is_err() {
            return;
        }
    }
}
