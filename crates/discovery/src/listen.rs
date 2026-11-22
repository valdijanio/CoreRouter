//! Passive CRDP listener for a management workstation (the native GUI's
//! connect screen): hears announcements on every interface of this
//! machine, never sends anything.

use std::collections::BTreeMap;
use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::thread;
use std::time::{Duration, Instant};

use corerouter_proto_discovery::{Announcement, MAX_PACKET, NodeId};

use crate::ifaces;
use crate::sock;

/// Re-join `ff02::1` on new interfaces this often.
const RESCAN: Duration = Duration::from_secs(10);
/// Most routers remembered (a flood evicts the oldest).
pub const MAX_HEARD: usize = 1024;
/// How long "this source is not on this machine" is believed. Short: an
/// address seen while its link was coming up (DAD, or our interface table
/// read before the link existed) turns out to be ours a moment later.
const NOT_LOCAL_TTL: Duration = Duration::from_secs(2);
/// Shortest pause between two re-reads of the interface table for the
/// local check (a flood of unknown sources costs one read a second).
const LOCAL_RESCAN: Duration = Duration::from_secs(1);

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
    /// for a router on this machine, else (G0.3) `tls://` + its first
    /// announced IPv4 (or the packet source, with the scope of a link-local
    /// address) and its TLS port; without one, the plain port, which only
    /// its own machine may use.
    pub fn connect_to(&self) -> Option<String> {
        if self.local {
            let port = self.announcement.control_port?;
            return Some(format!("127.0.0.1:{port}"));
        }
        if let Some(tls) = self.announcement.tls_port {
            return self.remote_addr(tls).map(|a| format!("tls://{a}"));
        }
        self.remote_addr(self.announcement.control_port?)
    }

    /// The router can be managed from this machine (TLS port, or local).
    pub fn reachable(&self) -> bool {
        self.local || self.announcement.tls_port.is_some()
    }

    fn remote_addr(&self, port: u16) -> Option<String> {
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
/// The channel holds at most [`MAX_HEARD`] announcements: the GUI polls
/// only while its connect screen is open, so what arrives meanwhile past
/// that is dropped (a newer copy of each router comes with its next
/// announcement) instead of growing the process without bound.
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
        let (tx, rx) = mpsc::sync_channel(MAX_HEARD);
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

fn listen(sock: &UdpSocket, tx: &SyncSender<Heard>, stop: &AtomicBool) {
    let v6 = sock.local_addr().is_ok_and(|a| a.is_ipv6());
    let mut kernel = ifaces::read();
    let mut read_at = Instant::now();
    let mut joined_at: Option<Instant> = None;
    let mut buf = [0u8; MAX_PACKET + 1];
    // Source → (on this machine, when decided). "Yes" is kept; "no" only
    // for NOT_LOCAL_TTL.
    let mut local: BTreeMap<(IpAddr, u32), (bool, Instant)> = BTreeMap::new();
    while !stop.load(Ordering::Relaxed) {
        if v6 && joined_at.is_none_or(|t| t.elapsed() >= RESCAN) {
            kernel = ifaces::read();
            read_at = Instant::now();
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
        let key = (from.ip(), scope);
        let known = local
            .get(&key)
            .filter(|(yes, at)| *yes || at.elapsed() < NOT_LOCAL_TTL)
            .map(|(yes, _)| *yes);
        let is_local = match known {
            Some(yes) => yes,
            None => {
                if read_at.elapsed() >= LOCAL_RESCAN {
                    kernel = ifaces::read();
                    read_at = Instant::now();
                }
                // A link-local address of this machine may arrive with the
                // scope of another of its links (veth pairs, bridges).
                let yes = sock::is_local(from.ip(), scope)
                    || matches!(from.ip(), IpAddr::V6(a) if kernel.has_address(&a));
                local.insert(key, (yes, Instant::now()));
                yes
            }
        };
        let heard = Heard {
            announcement,
            from,
            interface: (scope != 0)
                .then(|| kernel.name_of(scope).map(str::to_owned))
                .flatten(),
            local: is_local,
            at: Instant::now(),
        };
        match tx.try_send(heard) {
            Ok(()) | Err(TrySendError::Full(_)) => {}
            Err(TrySendError::Disconnected(_)) => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn announcement(n: u32) -> Vec<u8> {
        let mut id = [7u8; 16];
        id[..4].copy_from_slice(&n.to_be_bytes());
        Announcement {
            node_id: NodeId(id),
            hold_secs: 120,
            identity: format!("r{n}"),
            version: "0.1.0".into(),
            platform: "CoreRouter".into(),
            board: String::new(),
            uptime_secs: None,
            interface: "ether1".into(),
            mac: None,
            ipv4: Vec::new(),
            ipv6: Vec::new(),
            control_port: Some(7979),
            ws_port: None,
            tls_port: None,
            wss_port: None,
        }
        .encode()
        .unwrap()
    }

    /// audit-services #8: while the GUI sat connected (no `poll`), every
    /// announcement on the LAN piled up in an unbounded channel.
    #[test]
    fn the_queue_is_bounded_while_nobody_polls() {
        let port = UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let mut l = Listener::spawn(port).unwrap();
        let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
        let total = MAX_HEARD as u32 * 3;
        for n in 0..total {
            tx.send_to(&announcement(n), (Ipv4Addr::LOCALHOST, port))
                .unwrap();
            if n % 64 == 0 {
                thread::sleep(Duration::from_millis(2));
            }
        }
        thread::sleep(Duration::from_millis(300));
        let mut queued = 0;
        while l.rx.try_recv().is_ok() {
            queued += 1;
        }
        assert!(queued > 0);
        assert!(queued <= MAX_HEARD, "{queued} queued");
        // Still listening after the queue was full.
        tx.send_to(&announcement(total + 1), (Ipv4Addr::LOCALHOST, port))
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        while l.poll().is_empty() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(20));
        }
        assert!(!l.poll().is_empty());
    }
}
