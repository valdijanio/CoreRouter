//! The places of TCP 53 (G4.1w): `max_concurrent_tcp_sessions` in all, at
//! most [`per_source`] per address, and who gives a place up when they are
//! all taken.
//!
//! Before, a full server closed every new connection at accept: four
//! addresses holding five connections each that sent one byte and stalled
//! (a quarter of 20 each) took every place, and the LAN client got 0–1
//! answers in 108 tries (`docs/dns-stress.md`, slowloris). Now a new
//! connection takes the place of one that is waiting for a query (never one
//! whose query is being answered):
//!
//! - RFC 7766 §6.2.3: "Servers MAY use zero timeouts when they are
//!   experiencing heavy load or are under attack"; §6.2.4 and RFC 7858
//!   §3.4: clients retry what a closed connection left unanswered.
//! - RFC 9210 §4.2: under pressure, close "the oldest idle connections
//!   first"; the idle time restarts only on a whole message (RFC 7766
//!   §6.2.3), so a connection that never sent one is idle since accept.
//! - Fair by address: the place comes from the address holding the most
//!   places, so one that stalls many connections pays for them, not the
//!   client with one. A victim's address must hold at least two more
//!   places than the newcomer's ([`victim`]); with one more (an even swap,
//!   which would only move the place around) the victim must also have
//!   been idle [`SWAP_IDLE`]. Without that rule a peer reopening what was
//!   closed starts a chain (each reopen closes another, which reopens)
//!   that never ends.
//!
//! The same choice serves DoT and DoH (`dns_tls`, its own places).

use std::collections::HashMap;
use std::net::{IpAddr, Shutdown, TcpStream};
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

/// RFC 9210 §4.5: "25 connections per source IP address is a reasonable
/// starting point".
pub(crate) const PER_SOURCE: u32 = 25;
/// An even swap (the victim's address holds one place more than the
/// newcomer's) only takes a connection idle at least this long.
pub(crate) const SWAP_IDLE: Duration = Duration::from_secs(1);

/// Places one address may hold out of `max`: [`PER_SOURCE`], and never
/// more than half of them (busy connections cannot be taken back, so one
/// address must never hold every place).
pub(crate) fn per_source(max: u32) -> u32 {
    PER_SOURCE.min(max / 2).max(1)
}

/// A connection that may give its place up.
pub(crate) struct Candidate<K> {
    pub key: K,
    pub source: IpAddr,
    /// Since its last whole message (or since accept).
    pub idle: Duration,
}

/// The connection to close so a newcomer from an address that holds
/// `mine` places can have one: from the address with the most places
/// (`held`), the one idle the longest. None: no candidate is fair to take.
pub(crate) fn victim<K: Copy>(
    candidates: impl IntoIterator<Item = Candidate<K>>,
    held: impl Fn(IpAddr) -> u32,
    mine: u32,
) -> Option<K> {
    candidates
        .into_iter()
        .filter_map(|c| {
            let theirs = held(c.source);
            let fair = theirs > mine.saturating_add(1) || (theirs == mine.saturating_add(1) && c.idle >= SWAP_IDLE);
            fair.then_some((theirs, c.idle, c.key))
        })
        .max_by_key(|(theirs, idle, _)| (*theirs, *idle))
        .map(|(_, _, key)| key)
}

/// Waiting for (or reading) a query: may be closed for a newcomer.
const READING: u8 = 0;
/// A query is being answered: keeps its place.
const BUSY: u8 = 1;
/// Closed for a newcomer: its place is already given.
const EVICTED: u8 = 2;

/// What the session thread and the accepting thread share of a connection.
struct Live {
    state: AtomicU8,
    /// Milliseconds since [`Slots::born`] of its last whole message.
    last_ms: AtomicU64,
}

struct Entry {
    source: IpAddr,
    live: Arc<Live>,
    /// A handle on the socket, to shut it down from the accepting thread
    /// (the session thread then sees the end of its read).
    stream: TcpStream,
}

#[derive(Default)]
struct Inner {
    next: u64,
    conns: HashMap<u64, Entry>,
    per_source: HashMap<IpAddr, u32>,
}

impl Inner {
    fn remove(&mut self, id: u64) -> Option<Entry> {
        let e = self.conns.remove(&id)?;
        if let Some(n) = self.per_source.get_mut(&e.source) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                self.per_source.remove(&e.source);
            }
        }
        Some(e)
    }
}

/// The places of the TCP 53 listeners (both families).
pub(crate) struct Slots {
    born: Instant,
    inner: Mutex<Inner>,
    evicted: AtomicU64,
    refused: AtomicU64,
}

/// Why a connection got no place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refused {
    /// Its address holds [`per_source`] places already.
    Source,
    /// Every place is busy, or held by addresses with no more than this one.
    Full,
}

impl Default for Slots {
    fn default() -> Self {
        Self {
            born: Instant::now(),
            inner: Mutex::new(Inner::default()),
            evicted: AtomicU64::new(0),
            refused: AtomicU64::new(0),
        }
    }
}

impl Slots {
    fn now_ms(&self) -> u64 {
        u64::try_from(self.born.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A place for `stream` from `source` out of `max`, closing another
    /// connection if they are all taken and one is fair to take.
    pub(crate) fn admit(self: &Arc<Self>, source: IpAddr, stream: &TcpStream, max: u32) -> Result<Ticket, Refused> {
        let handle = stream.try_clone().map_err(|_| Refused::Full)?;
        let now = self.now_ms();
        let mut inner = self.lock();
        let mine = inner.per_source.get(&source).copied().unwrap_or(0);
        if mine >= per_source(max) {
            self.refused.fetch_add(1, Ordering::Relaxed);
            return Err(Refused::Source);
        }
        let max = usize::try_from(max).unwrap_or(usize::MAX);
        if inner.conns.len() >= max {
            let candidates = inner.conns.iter().filter(|(_, e)| e.live.state.load(Ordering::Acquire) == READING).map(|(id, e)| {
                Candidate {
                    key: *id,
                    source: e.source,
                    idle: Duration::from_millis(now.saturating_sub(e.live.last_ms.load(Ordering::Relaxed))),
                }
            });
            let held = |ip: IpAddr| inner.per_source.get(&ip).copied().unwrap_or(0);
            let chosen = victim(candidates, held, mine);
            // It may have read a whole query meanwhile (then it is BUSY and
            // keeps its place).
            let taken = chosen.filter(|id| {
                inner.conns.get(id).is_some_and(|e| {
                    e.live.state.compare_exchange(READING, EVICTED, Ordering::AcqRel, Ordering::Acquire).is_ok()
                })
            });
            let Some(id) = taken else {
                self.refused.fetch_add(1, Ordering::Relaxed);
                return Err(Refused::Full);
            };
            if let Some(e) = inner.remove(id) {
                // RFC 7766 §6.2.4: whatever it had sent is never answered.
                let _ = e.stream.shutdown(Shutdown::Both);
            }
            self.evicted.fetch_add(1, Ordering::Relaxed);
        }
        let id = inner.next;
        inner.next = inner.next.wrapping_add(1);
        let live = Arc::new(Live { state: AtomicU8::new(READING), last_ms: AtomicU64::new(now) });
        inner.conns.insert(id, Entry { source, live: live.clone(), stream: handle });
        *inner.per_source.entry(source).or_insert(0) += 1;
        Ok(Ticket { slots: self.clone(), id, live })
    }

    /// Connections holding a place now.
    pub(crate) fn open(&self) -> usize {
        self.lock().conns.len()
    }

    /// Connections closed for a newcomer, and newcomers closed at accept.
    pub(crate) fn counts(&self) -> (u64, u64) {
        (self.evicted.load(Ordering::Relaxed), self.refused.load(Ordering::Relaxed))
    }
}

/// A connection's place, given back when dropped (it moves to the session
/// thread).
pub(crate) struct Ticket {
    slots: Arc<Slots>,
    id: u64,
    live: Arc<Live>,
}

impl Ticket {
    /// A whole query came: the connection keeps its place while it is
    /// answered, and its idle time restarts (RFC 7766 §6.2.3). False: it
    /// was closed for a newcomer meanwhile; drop the query.
    pub(crate) fn busy(&self) -> bool {
        self.live.last_ms.store(self.slots.now_ms(), Ordering::Relaxed);
        self.live.state.compare_exchange(READING, BUSY, Ordering::AcqRel, Ordering::Acquire).is_ok()
    }

    /// Answered: waiting for the next query again.
    pub(crate) fn reading(&self) {
        let _ = self.live.state.compare_exchange(BUSY, READING, Ordering::AcqRel, Ordering::Acquire);
    }
}

impl Drop for Ticket {
    fn drop(&mut self) {
        // Evicted: its place was given back then (ids are never reused,
        // so this finds nothing).
        self.slots.lock().remove(self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::net::{Ipv4Addr, TcpListener};

    fn ip(n: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, n))
    }

    fn c(key: u32, n: u8, idle_ms: u64) -> Candidate<u32> {
        Candidate { key, source: ip(n), idle: Duration::from_millis(idle_ms) }
    }

    /// RFC 9210 §4.5: 25 per address; at most half the places.
    #[test]
    fn per_source_follows_rfc_9210_and_half_the_places() {
        assert_eq!(per_source(100), 25);
        assert_eq!(per_source(1000), 25);
        assert_eq!(per_source(20), 10);
        assert_eq!(per_source(4), 2);
        assert_eq!(per_source(1), 1);
    }

    /// RFC 9210 §4.2: the oldest idle first, from the address holding the
    /// most places; never an even swap of a connection that just came.
    #[test]
    fn the_victim_is_the_longest_idle_of_the_greediest_address() {
        let held = |a: IpAddr| match a {
            a if a == ip(1) => 5,
            a if a == ip(2) => 3,
            _ => 1,
        };
        // The newcomer holds nothing: address 1 (5 places) pays, its
        // longest idle; address 2's older connection is not taken.
        let got = victim([c(1, 1, 100), c(2, 1, 900), c(3, 2, 5000), c(4, 3, 9000)], held, 0);
        assert_eq!(got, Some(2));
        // A newcomer holding 4 takes from 5 only after SWAP_IDLE.
        assert_eq!(victim([c(1, 1, 100), c(2, 1, 900)], held, 4), None);
        assert_eq!(victim([c(1, 1, 100), c(2, 1, 1500)], held, 4), Some(2));
        // Never from an address with no more than the newcomer.
        assert_eq!(victim([c(3, 2, 60_000)], held, 3), None);
        assert_eq!(victim([c(4, 3, 60_000)], held, 5), None);
        assert_eq!(victim(Vec::<Candidate<u32>>::new(), held, 0), None);
    }

    fn pair(l: &TcpListener) -> (TcpStream, TcpStream) {
        let client = TcpStream::connect(l.local_addr().unwrap()).unwrap();
        let (server, _) = l.accept().unwrap();
        (client, server)
    }

    /// Full: the newcomer's place comes from a stalled connection, which
    /// the server shuts (its client reads the end); a busy one keeps its
    /// place; a ticket gives its place back when dropped.
    #[test]
    fn a_full_server_takes_a_stalled_place_never_a_busy_one() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let slots = Arc::new(Slots::default());
        let (mut c1, s1) = pair(&l);
        let (_c2, s2) = pair(&l);
        let t1 = slots.admit(ip(1), &s1, 4).unwrap();
        let t2 = slots.admit(ip(1), &s2, 4).unwrap();
        // Address 1 holds per_source(4) = 2.
        let (_c3, s3) = pair(&l);
        assert_eq!(slots.admit(ip(1), &s3, 4).err(), Some(Refused::Source));
        // Two more addresses fill the server.
        let (_c4, s4) = pair(&l);
        let t4 = slots.admit(ip(2), &s4, 4).unwrap();
        assert!(t2.busy(), "t2 is answering a query");
        // Address 3 holds nothing; address 1 holds 2 (> 0 + 1): its idle
        // connection t1 goes, not the busy t2.
        let (_c5, s5) = pair(&l);
        let t5 = slots.admit(ip(3), &s5, 3).unwrap();
        let mut b = [0u8; 1];
        assert_eq!(c1.read(&mut b).unwrap(), 0, "the evicted client sees the end");
        assert!(!t1.busy(), "the evicted session drops what it read");
        assert_eq!(slots.open(), 3);
        assert_eq!(slots.counts(), (1, 1));
        // Address 4 holds nothing; everyone else holds one: no fair victim
        // until the idle ones are SWAP_IDLE old.
        let (_c6, s6) = pair(&l);
        assert_eq!(slots.admit(ip(4), &s6, 3).err(), Some(Refused::Full));
        drop(t1);
        assert_eq!(slots.open(), 3, "dropping an evicted ticket frees nothing more");
        t2.reading();
        drop((t2, t4, t5));
        assert_eq!(slots.open(), 0);
        assert!(slots.lock().per_source.is_empty());
    }
}
