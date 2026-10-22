//! Simulated network for the virtual lab's diagnostic tools.
//!
//! Deterministic: the answer to a probe depends only on its destination,
//! sequence number, TTL and size, so tests and screenshots repeat exactly.
//! It never touches the host network (it runs in wasm, CI and on any OS).
//! The default rules (first match wins) are documented in `docs/tools.md`:
//!
//! | Destination | Behaves like |
//! |---|---|
//! | `127.0.0.0/8`, `::1` | loopback: one hop, ~0.03 ms |
//! | `192.0.2.0/24`, `2001:db8:2::/48` | "host unreachable" from the 3rd hop |
//! | `198.51.100.0/24`, `2001:db8:51::/48` | lossy (25 %) tunnel, path MTU 1400, 6 hops, ~40 ms |
//! | `203.0.113.0/24`, `2001:db8:113::/48` | black hole: routers answer, the host never does |
//! | anything else | 2–11 hops, 2–81 ms, 10 % jitter, path MTU 1500 |
//!
//! Names resolve to `198.18.0.0/15` (RFC 2544 benchmarking space), except
//! `localhost` (`127.0.0.1`, `::1`) and names under `.invalid` (not found).

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

use ipnet::IpNet;

use crate::probe::{Probe, ProbeError, ProbeSocket, Prober, Reply, ReplyKind, SocketOptions};

/// What happens to a probe that reaches the end of a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fate {
    /// The destination answers.
    Reply,
    /// Nothing answers past the last router (a filtered host).
    Silent,
    /// The router at hop `n` answers "host unreachable".
    Unreachable(u8),
}

/// One simulated path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SimPath {
    /// Routers + the destination (1 = directly connected).
    pub hops: u8,
    pub rtt: Duration,
    /// Each reply's RTT varies by up to ± this much.
    pub jitter: Duration,
    /// Percent of probes (0..=100) lost, chosen by hash of the sequence.
    pub loss_pct: u8,
    /// Largest packet that crosses the path with DF set.
    pub mtu: u16,
    pub fate: Fate,
}

/// Paths for destinations inside `prefix`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimRule {
    pub prefix: IpNet,
    pub path: SimPath,
}

/// The lab's [`Prober`]: answers from [`SimRule`]s, or a hash of the
/// destination when no rule matches.
#[derive(Debug, Clone)]
pub struct SimProber {
    rules: Vec<SimRule>,
}

/// MTU of the simulated router's own links: bigger DF packets fail locally.
pub const LOCAL_MTU: u16 = 1500;

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

fn rule(prefix: &str, path: SimPath) -> Option<SimRule> {
    Some(SimRule {
        prefix: prefix.parse().ok()?,
        path,
    })
}

impl Default for SimProber {
    fn default() -> Self {
        let loopback = SimPath {
            hops: 1,
            rtt: Duration::from_micros(30),
            jitter: Duration::from_micros(10),
            loss_pct: 0,
            mtu: u16::MAX,
            fate: Fate::Reply,
        };
        let unreachable = SimPath {
            hops: 5,
            rtt: ms(12),
            jitter: ms(1),
            loss_pct: 0,
            mtu: 1500,
            fate: Fate::Unreachable(3),
        };
        let lossy = SimPath {
            hops: 6,
            rtt: ms(40),
            jitter: ms(8),
            loss_pct: 25,
            mtu: 1400,
            fate: Fate::Reply,
        };
        let black_hole = SimPath {
            hops: 7,
            rtt: ms(30),
            jitter: ms(3),
            loss_pct: 0,
            mtu: 1500,
            fate: Fate::Silent,
        };
        let rules = [
            rule("127.0.0.0/8", loopback),
            rule("::1/128", loopback),
            rule("192.0.2.0/24", unreachable),
            rule("2001:db8:2::/48", unreachable),
            rule("198.51.100.0/24", lossy),
            rule("2001:db8:51::/48", lossy),
            rule("203.0.113.0/24", black_hole),
            rule("2001:db8:113::/48", black_hole),
        ];
        Self {
            rules: rules.into_iter().flatten().collect(),
        }
    }
}

/// FNV-1a: small, stable across platforms and releases.
fn hash(parts: &[&[u8]]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for part in parts {
        for b in *part {
            h ^= u64::from(*b);
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
        h ^= 0xff;
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

fn addr_bytes(a: IpAddr) -> Vec<u8> {
    match a {
        IpAddr::V4(v) => v.octets().to_vec(),
        IpAddr::V6(v) => v.octets().to_vec(),
    }
}

impl SimProber {
    /// Only `rules` (first match wins); other destinations use the hash.
    pub fn with_rules(rules: Vec<SimRule>) -> Self {
        Self { rules }
    }

    /// The path to `dst`.
    pub fn path(&self, dst: IpAddr) -> SimPath {
        if let Some(r) = self.rules.iter().find(|r| r.prefix.contains(&dst)) {
            return r.path;
        }
        let h = hash(&[&addr_bytes(dst)]);
        let rtt = ms(2 + h % 80);
        SimPath {
            hops: 2 + (h % 10) as u8,
            rtt,
            jitter: rtt / 10,
            loss_pct: 0,
            mtu: 1500,
            fate: Fate::Reply,
        }
    }

    /// Address of the router at `hop` (1-based) on the path to `dst`.
    pub fn router(dst: IpAddr, hop: u8) -> IpAddr {
        let h = hash(&[&addr_bytes(dst), &[hop]]);
        let low = (h % 254) as u8 + 1;
        match dst {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::new(100, 64, hop, low)),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::new(
                0xfd00,
                0,
                0,
                0,
                0,
                0,
                u16::from(hop),
                u16::from(low),
            )),
        }
    }

    /// What answers `probe` (sent with DF = `df`), if anything.
    pub fn answer(&self, probe: &Probe, df: bool) -> Option<Reply> {
        let path = self.path(probe.dst);
        let dst = addr_bytes(probe.dst);
        let seq = probe.seq.to_be_bytes();
        let ttl = probe.ttl.unwrap_or(64);
        let h = hash(&[&dst, &seq, &[ttl]]);
        let hops = path.hops.max(1);
        // The link that shrinks the MTU and loses packets sits halfway.
        let narrow = hops.div_ceil(2);
        if path.loss_pct > 0
            && ttl >= narrow
            && hash(&[&dst, &seq]) % 100 < u64::from(path.loss_pct)
        {
            return None;
        }
        // RTT and jitter to hop k grow with k; jitter in [-j, +j].
        let rtt_to = |k: u8| {
            let k = u128::from(k.min(hops));
            let base = path.rtt.as_nanos() * k / u128::from(hops);
            let span = path.jitter.as_nanos() * k / u128::from(hops);
            let offset = if span == 0 {
                0
            } else {
                i128::try_from(u128::from(h) % (2 * span + 1)).unwrap_or(0)
                    - i128::try_from(span).unwrap_or(0)
            };
            let nanos = (i128::try_from(base).unwrap_or(0) + offset).max(1_000);
            Duration::from_nanos(u64::try_from(nanos).unwrap_or(u64::MAX))
        };
        let reply = |from: IpAddr, kind: ReplyKind, k: u8| Reply {
            seq: probe.seq,
            from,
            kind,
            size: Some(probe.size),
            ttl: Some(64u8.saturating_sub(k.saturating_sub(1))),
            rtt: rtt_to(k),
        };
        if df && probe.size > path.mtu && ttl >= narrow {
            let at = narrow.saturating_sub(1).max(1);
            let from = if at >= hops {
                probe.dst
            } else {
                Self::router(probe.dst, at)
            };
            return Some(reply(
                from,
                ReplyKind::TooBig {
                    mtu: Some(path.mtu),
                },
                at,
            ));
        }
        if let Fate::Unreachable(at) = path.fate
            && ttl >= at
        {
            let kind = ReplyKind::Unreachable("host unreachable".into());
            return Some(reply(Self::router(probe.dst, at), kind, at));
        }
        if ttl < hops {
            // Every 7th router (by hash) does not answer TTL exceeded.
            let router = Self::router(probe.dst, ttl);
            if hops > 2 && hash(&[&dst, &[ttl], b"quiet"]).is_multiple_of(7) {
                return None;
            }
            return Some(reply(router, ReplyKind::TtlExceeded, ttl));
        }
        match path.fate {
            Fate::Reply | Fate::Unreachable(_) => Some(reply(probe.dst, ReplyKind::Echo, hops)),
            Fate::Silent => None,
        }
    }
}

impl Prober for SimProber {
    fn describe(&self) -> String {
        "simulated network (deterministic, see docs/tools.md)".into()
    }

    fn resolve(&self, name: &str) -> Result<Vec<IpAddr>, ProbeError> {
        let lower = name.trim_end_matches('.').to_ascii_lowercase();
        if lower == "localhost" {
            return Ok(vec![
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V6(Ipv6Addr::LOCALHOST),
            ]);
        }
        if lower.is_empty() || lower == "invalid" || lower.ends_with(".invalid") {
            return Err(ProbeError::NotFound(name.chars().take(64).collect()));
        }
        let h = hash(&[lower.as_bytes()]);
        let [_, _, _, _, _, a, b, c] = h.to_be_bytes();
        Ok(vec![IpAddr::V4(Ipv4Addr::new(
            198,
            18 + (a & 1),
            b,
            c.max(1),
        ))])
    }

    fn open(&self, options: &SocketOptions) -> Result<Box<dyn ProbeSocket>, ProbeError> {
        Ok(Box::new(SimSocket {
            net: self.clone(),
            df: options.dont_fragment,
            queue: VecDeque::new(),
        }))
    }
}

/// Answers are queued when the probe is sent and handed out at once; their
/// `rtt` is the simulated one.
struct SimSocket {
    net: SimProber,
    df: bool,
    queue: VecDeque<Reply>,
}

impl ProbeSocket for SimSocket {
    fn send(&mut self, probe: &Probe) -> Result<(), ProbeError> {
        let loopback = probe.dst.is_loopback();
        if self.df && !loopback && probe.size > LOCAL_MTU {
            return Err(ProbeError::TooBig(Some(LOCAL_MTU)));
        }
        if let Some(r) = self.net.answer(probe, self.df || probe.dst.is_ipv6()) {
            self.queue.push_back(r);
        }
        Ok(())
    }

    fn recv(&mut self, _wait: Duration) -> Result<Option<Reply>, ProbeError> {
        Ok(self.queue.pop_front())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe(dst: &str, seq: u16, ttl: Option<u8>, size: u16) -> Probe {
        Probe {
            dst: dst.parse().unwrap(),
            seq,
            ttl,
            size,
        }
    }

    #[test]
    fn loopback_answers_fast_and_the_same_every_time() {
        let sim = SimProber::default();
        let a = sim.answer(&probe("127.0.0.1", 1, None, 56), false).unwrap();
        let b = sim.answer(&probe("127.0.0.1", 1, None, 56), false).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.kind, ReplyKind::Echo);
        assert!(a.rtt < Duration::from_millis(1));
    }

    #[test]
    fn ttl_walks_the_routers_then_reaches_the_host() {
        let sim = SimProber::default();
        let dst = "8.8.8.8";
        let hops = sim.path(dst.parse().unwrap()).hops;
        let mut answered = 0;
        for ttl in 1..hops {
            if let Some(r) = sim.answer(&probe(dst, 1, Some(ttl), 56), false) {
                assert_eq!(r.kind, ReplyKind::TtlExceeded);
                assert_eq!(r.from, SimProber::router(dst.parse().unwrap(), ttl));
                answered += 1;
            }
        }
        assert!(answered > 0);
        let last = sim.answer(&probe(dst, 1, Some(hops), 56), false).unwrap();
        assert_eq!(last.kind, ReplyKind::Echo);
    }

    #[test]
    fn lossy_and_black_hole_and_unreachable() {
        let sim = SimProber::default();
        let lost = (0..400)
            .filter(|s| {
                sim.answer(&probe("198.51.100.7", *s, None, 56), false)
                    .is_none()
            })
            .count();
        assert!((60..140).contains(&lost), "lost {lost} of 400");
        assert!(
            sim.answer(&probe("203.0.113.9", 1, None, 56), false)
                .is_none()
        );
        let r = sim.answer(&probe("192.0.2.1", 1, None, 56), false).unwrap();
        assert!(matches!(r.kind, ReplyKind::Unreachable(_)));
    }

    #[test]
    fn df_finds_the_narrow_link() {
        let sim = SimProber::default();
        let ok = sim
            .answer(&probe("198.51.100.1", 2, None, 1400), true)
            .unwrap();
        assert_eq!(ok.kind, ReplyKind::Echo);
        let big = sim
            .answer(&probe("198.51.100.1", 1, None, 1401), true)
            .unwrap();
        assert_eq!(big.kind, ReplyKind::TooBig { mtu: Some(1400) });
        let mut sock = sim
            .open(&SocketOptions {
                dont_fragment: true,
                ..SocketOptions::default()
            })
            .unwrap();
        assert_eq!(
            sock.send(&probe("8.8.8.8", 1, None, 1501)),
            Err(ProbeError::TooBig(Some(1500)))
        );
    }

    #[test]
    fn names_resolve_deterministically() {
        let sim = SimProber::default();
        assert_eq!(sim.resolve("example.com"), sim.resolve("EXAMPLE.com."));
        assert!(sim.resolve("localhost").unwrap().len() == 2);
        assert!(matches!(
            sim.resolve("nope.invalid"),
            Err(ProbeError::NotFound(_))
        ));
    }
}
