//! WireGuard over generic netlink (G1.31): the kernel's `wireguard` family
//! (`include/uapi/linux/wireguard.h`, `drivers/net/wireguard/netlink.c`),
//! without the `wg` tool and without a crate.
//!
//! - [`plan`] compares what the engine wants with what the link holds (a
//!   `WG_CMD_GET_DEVICE` dump) and [`encode`] writes only the difference as
//!   `WG_CMD_SET_DEVICE` requests: a peer that did not change is not sent,
//!   so its session stays up (the kernel's `set_peer` changes only what the
//!   message carries). `WGDEVICE_F_REPLACE_PEERS` is never used: it would
//!   drop every session.
//! - The configured endpoint is only where the first handshake goes; the
//!   kernel then follows the peer (roaming, whitepaper §2.1). So an endpoint
//!   is sent when the peer is new or when the *configured* one changed since
//!   the last push, never because the kernel's current one differs.
//! - Requests are split so no nest passes the 16-bit attribute length
//!   (`MAX_REQUEST`); a peer is never split (its allowed addresses are
//!   bounded by the model).
//! - [`parse`] coalesces the dump: the kernel continues a peer in the next
//!   message when its allowed addresses do not fit (`wireguard.h`, "it is
//!   then up to the receiver to coalesce").
//!
//! Pure and bounded like `genl`: a hostile or truncated dump yields fewer
//! peers, never a panic. The socket part is Linux-only.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use corerouter_hal::wireguard::{Key, WgDevice, WgPeerSpec, WgPeerStatus, WgStatus};
use ipnet::IpNet;

use crate::genl::{Attr, Msg, attrs};

pub(crate) const FAMILY: &str = "wireguard";
const VERSION: u8 = 1;
const CMD_GET: u8 = 0;
const CMD_SET: u8 = 1;

const D_IFNAME: u16 = 2;
const D_PRIVATE_KEY: u16 = 3;
const D_PUBLIC_KEY: u16 = 4;
const D_LISTEN_PORT: u16 = 6;
const D_PEERS: u16 = 8;

const P_PUBLIC_KEY: u16 = 1;
const P_PRESHARED_KEY: u16 = 2;
const P_FLAGS: u16 = 3;
const P_ENDPOINT: u16 = 4;
const P_KEEPALIVE: u16 = 5;
const P_LAST_HANDSHAKE: u16 = 6;
const P_RX_BYTES: u16 = 7;
const P_TX_BYTES: u16 = 8;
const P_ALLOWEDIPS: u16 = 9;

const A_FAMILY: u16 = 1;
const A_IPADDR: u16 = 2;
const A_CIDR: u16 = 3;

const F_REMOVE_ME: u32 = 1;
const F_REPLACE_ALLOWEDIPS: u32 = 2;

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

/// One request stays well under the 64 KiB a nest length can say.
const MAX_REQUEST: usize = 32 * 1024;
/// Peers read from one dump (the model's bound is 20 000 per interface).
pub(crate) const MAX_DUMP_PEERS: usize = 100_000;
/// Allowed addresses read for one peer.
const MAX_DUMP_ALLOWED: usize = 4096;

/// What a link holds, from a `GET_DEVICE` dump.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct KernelDevice {
    /// `None`: no private key yet (a fresh link).
    pub private_key: Option<Key>,
    pub public_key: Key,
    pub listen_port: u16,
    pub peers: Vec<KernelPeer>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct KernelPeer {
    pub public_key: Key,
    pub preshared_key: Key,
    pub endpoint: Option<SocketAddr>,
    pub keepalive: u16,
    /// Seconds and nanoseconds; zero: never.
    pub last_handshake: (i64, i64),
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub allowed: Vec<IpNet>,
}

/// One peer to send: everything it carries, the rest left as is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PeerChange {
    Remove(Key),
    Set {
        public_key: Key,
        /// `Some([0; 32])` removes it.
        preshared_key: Option<Key>,
        endpoint: Option<SocketAddr>,
        keepalive: Option<u16>,
        /// `Some`: replace the whole list with this one.
        allowed: Option<Vec<IpNet>>,
    },
}

/// The difference between a link and what the engine wants.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct SetPlan {
    pub private_key: Option<Key>,
    pub listen_port: Option<u16>,
    pub peers: Vec<PeerChange>,
}

impl SetPlan {
    pub fn is_empty(&self) -> bool {
        self.private_key.is_none() && self.listen_port.is_none() && self.peers.is_empty()
    }
}

fn same_set(a: &[IpNet], b: &[IpNet]) -> bool {
    let mut x: Vec<IpNet> = a.iter().map(IpNet::trunc).collect();
    let mut y: Vec<IpNet> = b.iter().map(IpNet::trunc).collect();
    x.sort_unstable();
    x.dedup();
    y.sort_unstable();
    y.dedup();
    x == y
}

/// What to send so `have` holds `want`. `last`: what was pushed last time
/// (the endpoints the operator configured then), `None` after a restart.
pub(crate) fn plan(want: &WgDevice, have: &KernelDevice, last: Option<&WgDevice>) -> SetPlan {
    let mut p = SetPlan {
        private_key: (have.private_key != Some(want.private_key)).then_some(want.private_key),
        listen_port: (have.listen_port != want.listen_port).then_some(want.listen_port),
        peers: Vec::new(),
    };
    let wanted: BTreeMap<Key, &WgPeerSpec> = want.peers.iter().map(|w| (w.public_key, w)).collect();
    for k in &have.peers {
        if !wanted.contains_key(&k.public_key) {
            p.peers.push(PeerChange::Remove(k.public_key));
        }
    }
    let had: BTreeMap<Key, &KernelPeer> = have.peers.iter().map(|k| (k.public_key, k)).collect();
    let before: BTreeMap<Key, &WgPeerSpec> = last
        .map(|l| l.peers.iter().map(|w| (w.public_key, w)).collect())
        .unwrap_or_default();
    for w in &want.peers {
        match had.get(&w.public_key) {
            None => p.peers.push(PeerChange::Set {
                public_key: w.public_key,
                preshared_key: (w.preshared_key != [0; 32]).then_some(w.preshared_key),
                endpoint: w.endpoint,
                keepalive: (w.persistent_keepalive != 0).then_some(w.persistent_keepalive),
                allowed: Some(w.allowed.clone()),
            }),
            Some(k) => {
                let psk = (k.preshared_key != w.preshared_key).then_some(w.preshared_key);
                let keepalive =
                    (k.keepalive != w.persistent_keepalive).then_some(w.persistent_keepalive);
                let allowed = (!same_set(&k.allowed, &w.allowed)).then(|| w.allowed.clone());
                // Configured endpoint changed (or never pushed by us and
                // the kernel has none): send it. Roaming is left alone.
                let endpoint = match (w.endpoint, before.get(&w.public_key)) {
                    (Some(e), Some(b)) if b.endpoint != Some(e) => Some(e),
                    (Some(e), None) if k.endpoint.is_none() || last.is_none() => Some(e),
                    _ => None,
                }
                .filter(|e| k.endpoint != Some(*e));
                if psk.is_some() || keepalive.is_some() || allowed.is_some() || endpoint.is_some() {
                    p.peers.push(PeerChange::Set {
                        public_key: w.public_key,
                        preshared_key: psk,
                        endpoint,
                        keepalive,
                        allowed,
                    });
                }
            }
        }
    }
    p
}

fn sockaddr(e: &SocketAddr) -> Vec<u8> {
    let mut out = Vec::with_capacity(28);
    match e {
        SocketAddr::V4(a) => {
            out.extend_from_slice(&AF_INET.to_ne_bytes());
            out.extend_from_slice(&a.port().to_be_bytes());
            out.extend_from_slice(&a.ip().octets());
            out.extend_from_slice(&[0; 8]);
        }
        SocketAddr::V6(a) => {
            out.extend_from_slice(&AF_INET6.to_ne_bytes());
            out.extend_from_slice(&a.port().to_be_bytes());
            out.extend_from_slice(&a.flowinfo().to_be_bytes());
            out.extend_from_slice(&a.ip().octets());
            out.extend_from_slice(&a.scope_id().to_ne_bytes());
        }
    }
    out
}

fn read_sockaddr(d: &[u8]) -> Option<SocketAddr> {
    let family = u16::from_ne_bytes(d.get(..2)?.try_into().ok()?);
    let port = u16::from_be_bytes(d.get(2..4)?.try_into().ok()?);
    match family {
        AF_INET => {
            let ip: [u8; 4] = d.get(4..8)?.try_into().ok()?;
            Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(ip), port)))
        }
        AF_INET6 => {
            let flow = u32::from_be_bytes(d.get(4..8)?.try_into().ok()?);
            let ip: [u8; 16] = d.get(8..24)?.try_into().ok()?;
            let scope = u32::from_ne_bytes(d.get(24..28)?.try_into().ok()?);
            Some(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(ip),
                port,
                flow,
                scope,
            )))
        }
        _ => None,
    }
}

fn put_peer(m: &mut Msg, c: &PeerChange) {
    m.begin(0);
    match c {
        PeerChange::Remove(k) => {
            m.bytes(P_PUBLIC_KEY, k).u32(P_FLAGS, F_REMOVE_ME);
        }
        PeerChange::Set {
            public_key,
            preshared_key,
            endpoint,
            keepalive,
            allowed,
        } => {
            m.bytes(P_PUBLIC_KEY, public_key);
            if allowed.is_some() {
                m.u32(P_FLAGS, F_REPLACE_ALLOWEDIPS);
            }
            if let Some(k) = preshared_key {
                m.bytes(P_PRESHARED_KEY, k);
            }
            if let Some(e) = endpoint {
                m.bytes(P_ENDPOINT, &sockaddr(e));
            }
            if let Some(s) = keepalive {
                m.u16(P_KEEPALIVE, *s);
            }
            if let Some(list) = allowed {
                m.begin(P_ALLOWEDIPS);
                for net in list {
                    m.begin(0);
                    match net.addr() {
                        IpAddr::V4(a) => m.u16(A_FAMILY, AF_INET).bytes(A_IPADDR, &a.octets()),
                        IpAddr::V6(a) => m.u16(A_FAMILY, AF_INET6).bytes(A_IPADDR, &a.octets()),
                    };
                    m.u8(A_CIDR, net.prefix_len());
                    m.end();
                }
                m.end();
            }
        }
    }
    m.end();
}

/// Rough size of a peer in a request, to split before it overflows.
fn peer_size(c: &PeerChange) -> usize {
    match c {
        PeerChange::Remove(_) => 48,
        PeerChange::Set { allowed, .. } => 160 + allowed.as_ref().map_or(0, |a| a.len() * 44),
    }
}

/// The `SET_DEVICE` requests for `plan` on link `ifname` (empty plan: none).
/// `seq`: the first sequence number; the next requests count up. The private
/// key goes in the first one only.
pub(crate) fn encode(family: u16, seq: u32, ifname: &str, plan: &SetPlan) -> Vec<(u32, Vec<u8>)> {
    if plan.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut seq = seq;
    let start = |seq: u32| {
        let mut m = Msg::new(family, CMD_SET, VERSION, seq);
        m.str(D_IFNAME, ifname);
        m
    };
    let mut m = start(seq);
    if let Some(k) = &plan.private_key {
        m.bytes(D_PRIVATE_KEY, k);
    }
    if let Some(p) = plan.listen_port {
        m.u16(D_LISTEN_PORT, p);
    }
    let mut open = false;
    for c in &plan.peers {
        if open && m.size() + peer_size(c) > MAX_REQUEST {
            m.end();
            out.push((seq, m.finish()));
            seq = seq.wrapping_add(1);
            m = start(seq);
            open = false;
        }
        if !open {
            m.begin(D_PEERS);
            open = true;
        }
        put_peer(&mut m, c);
    }
    out.push((seq, m.finish()));
    out
}

fn key_of(a: &Attr<'_>) -> Option<Key> {
    a.data.get(..32)?.try_into().ok()
}

fn read_allowed(a: &Attr<'_>, out: &mut Vec<IpNet>) {
    for entry in a.nested() {
        if out.len() >= MAX_DUMP_ALLOWED {
            return;
        }
        let mut family = 0;
        let mut addr = None;
        let mut cidr = None;
        for f in entry.nested() {
            match f.kind {
                A_FAMILY => family = f.u16().unwrap_or(0),
                A_IPADDR => addr = Some(f.data),
                A_CIDR => cidr = f.u8(),
                _ => {}
            }
        }
        let ip = match (family, addr) {
            (AF_INET, Some(d)) => d
                .get(..4)
                .and_then(|b| <[u8; 4]>::try_from(b).ok())
                .map(|b| IpAddr::V4(Ipv4Addr::from(b))),
            (AF_INET6, Some(d)) => d
                .get(..16)
                .and_then(|b| <[u8; 16]>::try_from(b).ok())
                .map(|b| IpAddr::V6(Ipv6Addr::from(b))),
            _ => None,
        };
        if let (Some(ip), Some(c)) = (ip, cidr)
            && let Ok(net) = IpNet::new(ip, c)
        {
            out.push(net);
        }
    }
}

/// The link in the `GET_DEVICE` dump `msgs` (attributes of each message).
pub(crate) fn parse<'a>(msgs: impl IntoIterator<Item = &'a [u8]>) -> KernelDevice {
    let mut dev = KernelDevice::default();
    let mut index: BTreeMap<Key, usize> = BTreeMap::new();
    for msg in msgs {
        for a in attrs(msg) {
            match a.kind {
                D_PRIVATE_KEY => {
                    dev.private_key = key_of(&a).filter(|k| *k != [0; 32]);
                }
                D_PUBLIC_KEY => dev.public_key = key_of(&a).unwrap_or_default(),
                D_LISTEN_PORT => dev.listen_port = a.u16().unwrap_or(0),
                D_PEERS => {
                    for pa in a.nested() {
                        let Some(pk) = pa
                            .nested()
                            .find(|x| x.kind == P_PUBLIC_KEY)
                            .and_then(|x| key_of(&x))
                        else {
                            continue;
                        };
                        let i = match index.get(&pk) {
                            Some(i) => *i,
                            None => {
                                if dev.peers.len() >= MAX_DUMP_PEERS {
                                    continue;
                                }
                                dev.peers.push(KernelPeer {
                                    public_key: pk,
                                    ..KernelPeer::default()
                                });
                                index.insert(pk, dev.peers.len() - 1);
                                dev.peers.len() - 1
                            }
                        };
                        let Some(p) = dev.peers.get_mut(i) else {
                            continue;
                        };
                        for f in pa.nested() {
                            match f.kind {
                                P_PRESHARED_KEY => p.preshared_key = key_of(&f).unwrap_or_default(),
                                P_ENDPOINT => p.endpoint = read_sockaddr(f.data),
                                P_KEEPALIVE => p.keepalive = f.u16().unwrap_or(0),
                                P_LAST_HANDSHAKE => {
                                    let sec = f
                                        .data
                                        .get(..8)
                                        .and_then(|b| b.try_into().ok())
                                        .map(i64::from_ne_bytes);
                                    let nsec = f
                                        .data
                                        .get(8..16)
                                        .and_then(|b| b.try_into().ok())
                                        .map(i64::from_ne_bytes);
                                    p.last_handshake = (sec.unwrap_or(0), nsec.unwrap_or(0));
                                }
                                P_RX_BYTES => p.rx_bytes = f.u64().unwrap_or(0),
                                P_TX_BYTES => p.tx_bytes = f.u64().unwrap_or(0),
                                P_ALLOWEDIPS => read_allowed(&f, &mut p.allowed),
                                _ => {}
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }
    dev
}

/// What the engine reads (`wg show`).
pub(crate) fn status(dev: &KernelDevice) -> WgStatus {
    WgStatus {
        listen_port: dev.listen_port,
        public_key: dev.public_key,
        peers: dev
            .peers
            .iter()
            .map(|p| WgPeerStatus {
                public_key: p.public_key,
                endpoint: p.endpoint,
                last_handshake_unix: u64::try_from(p.last_handshake.0).ok().filter(|s| *s > 0),
                rx_bytes: p.rx_bytes,
                tx_bytes: p.tx_bytes,
            })
            .collect(),
    }
}

/// The `GET_DEVICE` dump request for link `ifname`.
pub(crate) fn get_request(family: u16, seq: u32, ifname: &str) -> Vec<u8> {
    let mut m = Msg::dump(family, CMD_GET, VERSION, seq);
    m.str(D_IFNAME, ifname);
    m.finish()
}

#[cfg(target_os = "linux")]
pub(crate) use io::{read, write};

#[cfg(target_os = "linux")]
mod io {
    use corerouter_hal::wireguard::{WgDevice, WgStatus};

    use super::{FAMILY, KernelDevice, MAX_DUMP_PEERS, encode, get_request, parse, plan, status};
    use crate::genl::{Genl, GenlError};

    fn why(e: &GenlError, what: &str, ifname: &str) -> String {
        match e {
            GenlError::Errno(98) => format!(
                "{what} '{ifname}': the listen port is in use by another program or interface"
            ),
            GenlError::Errno(2) | GenlError::Errno(19) => {
                format!("{what} '{ifname}': no such WireGuard link")
            }
            GenlError::Errno(1) | GenlError::Errno(13) => {
                format!("{what} '{ifname}': not permitted (needs CAP_NET_ADMIN)")
            }
            e => format!("{what} '{ifname}': {e}"),
        }
    }

    fn open() -> Result<(Genl, u16), String> {
        let mut g = Genl::open().map_err(|e| e.to_string())?;
        let fam = g.family(FAMILY).map_err(|e| {
            format!("the kernel has no WireGuard (generic netlink family '{FAMILY}': {e})")
        })?;
        Ok((g, fam))
    }

    fn dump(g: &mut Genl, fam: u16, ifname: &str) -> Result<KernelDevice, String> {
        let seq = g.next_seq();
        let msgs = g
            .call_up_to(get_request(fam, seq, ifname), seq, MAX_DUMP_PEERS)
            .map_err(|e| why(&e, "read WireGuard", ifname))?;
        Ok(parse(msgs.iter().map(|(_, a)| a.as_slice())))
    }

    /// Make link `ifname` hold `want`, sending only the difference.
    /// Returns how many peers changed.
    pub(crate) fn write(
        ifname: &str,
        want: &WgDevice,
        last: Option<&WgDevice>,
    ) -> Result<usize, String> {
        let (mut g, fam) = open()?;
        let have = dump(&mut g, fam, ifname)?;
        let p = plan(want, &have, last);
        let changed = p.peers.len();
        // One sequence number per request: `encode` counts up from `first`.
        let first = g.next_seq();
        let reqs = encode(fam, first, ifname, &p);
        for (i, (seq, mut req)) in reqs.into_iter().enumerate() {
            if i > 0 {
                let _ = g.next_seq();
            }
            let r = g.call(&req, seq);
            // The first request may carry the private key: wipe our copy.
            req.fill(0);
            std::hint::black_box(&req);
            r.map_err(|e| why(&e, "configure WireGuard", ifname))?;
        }
        Ok(changed)
    }

    pub(crate) fn read(ifname: &str) -> Result<WgStatus, String> {
        let (mut g, fam) = open()?;
        Ok(status(&dump(&mut g, fam, ifname)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::genl::{Reply, replies};

    fn key(b: u8) -> Key {
        [b; 32]
    }

    fn peer(k: u8, allowed: &[&str], endpoint: Option<&str>) -> WgPeerSpec {
        WgPeerSpec {
            public_key: key(k),
            preshared_key: [0; 32],
            endpoint: endpoint.and_then(|e| e.parse().ok()),
            persistent_keepalive: 0,
            allowed: allowed.iter().filter_map(|a| a.parse().ok()).collect(),
        }
    }

    fn kernel_of(dev: &WgDevice) -> KernelDevice {
        KernelDevice {
            private_key: Some(dev.private_key),
            public_key: key(0xEE),
            listen_port: dev.listen_port,
            peers: dev
                .peers
                .iter()
                .map(|p| KernelPeer {
                    public_key: p.public_key,
                    preshared_key: p.preshared_key,
                    endpoint: p.endpoint,
                    keepalive: p.persistent_keepalive,
                    allowed: p.allowed.clone(),
                    ..KernelPeer::default()
                })
                .collect(),
        }
    }

    /// The request bodies (the attributes after the generic header).
    fn bodies(reqs: &[(u32, Vec<u8>)]) -> Vec<Vec<u8>> {
        reqs.iter()
            .map(|(_, r)| {
                r.get(crate::genl::NLMSG_HDR + crate::genl::GENL_HDR..)
                    .unwrap_or(&[])
                    .to_vec()
            })
            .collect()
    }

    #[test]
    fn a_fresh_link_gets_everything() {
        let want = WgDevice {
            private_key: key(7),
            listen_port: 13231,
            peers: vec![
                peer(1, &["10.9.0.2/32"], Some("198.51.100.7:13231")),
                peer(2, &["10.20.0.0/16"], None),
            ],
        };
        let p = plan(&want, &KernelDevice::default(), None);
        assert_eq!(p.private_key, Some(key(7)));
        assert_eq!(p.listen_port, Some(13231));
        assert_eq!(p.peers.len(), 2);
        // What we write reads back as what we wanted (the dump uses the
        // same attributes the request does).
        let reqs = encode(28, 5, "wg0", &p);
        assert_eq!(reqs.len(), 1);
        let back = parse(bodies(&reqs).iter().map(Vec::as_slice));
        assert_eq!(back.private_key, Some(key(7)));
        assert_eq!(back.listen_port, 13231);
        assert_eq!(back.peers.len(), 2);
        assert_eq!(
            back.peers.first().and_then(|p| p.endpoint),
            "198.51.100.7:13231".parse().ok()
        );
        assert_eq!(
            back.peers.get(1).map(|p| p.allowed.clone()),
            Some(vec!["10.20.0.0/16".parse().unwrap()])
        );
    }

    #[test]
    fn nothing_changed_sends_nothing() {
        let want = WgDevice {
            private_key: key(7),
            listen_port: 13231,
            peers: vec![peer(
                1,
                &["10.9.0.2/32", "fd00::2/128"],
                Some("[2001:db8::1]:51820"),
            )],
        };
        let p = plan(&want, &kernel_of(&want), Some(&want));
        assert!(p.is_empty(), "{p:?}");
        assert!(encode(28, 1, "wg0", &p).is_empty());
    }

    #[test]
    fn only_the_changed_peer_is_sent_and_others_keep_their_session() {
        let before = WgDevice {
            private_key: key(7),
            listen_port: 13231,
            peers: vec![
                peer(1, &["10.9.0.2/32"], None),
                peer(2, &["10.9.0.3/32"], None),
                peer(3, &["10.9.0.4/32"], None),
            ],
        };
        let mut want = before.clone();
        if let Some(p) = want.peers.get_mut(1) {
            p.persistent_keepalive = 25;
        }
        want.peers.remove(2);
        want.peers.push(peer(4, &["10.9.0.5/32"], None));
        let p = plan(&want, &kernel_of(&before), Some(&before));
        assert_eq!(p.private_key, None);
        assert_eq!(p.listen_port, None);
        assert_eq!(
            p.peers,
            vec![
                PeerChange::Remove(key(3)),
                PeerChange::Set {
                    public_key: key(2),
                    preshared_key: None,
                    endpoint: None,
                    keepalive: Some(25),
                    allowed: None
                },
                PeerChange::Set {
                    public_key: key(4),
                    preshared_key: None,
                    endpoint: None,
                    keepalive: None,
                    allowed: Some(vec!["10.9.0.5/32".parse().unwrap()])
                },
            ]
        );
    }

    #[test]
    fn roaming_is_left_alone_but_a_new_configured_endpoint_is_sent() {
        let want = WgDevice {
            private_key: key(7),
            listen_port: 13231,
            peers: vec![peer(1, &["10.9.0.2/32"], Some("198.51.100.7:13231"))],
        };
        // The peer moved: the kernel follows it; we do not pull it back.
        let mut roamed = kernel_of(&want);
        if let Some(p) = roamed.peers.get_mut(0) {
            p.endpoint = "203.0.113.9:40000".parse().ok();
        }
        assert!(plan(&want, &roamed, Some(&want)).is_empty());
        // The operator changed the configured endpoint: it is sent.
        let mut moved = want.clone();
        if let Some(p) = moved.peers.get_mut(0) {
            p.endpoint = "198.51.100.8:13231".parse().ok();
        }
        let p = plan(&moved, &roamed, Some(&want));
        assert!(matches!(
            p.peers.as_slice(),
            [PeerChange::Set { endpoint: Some(e), allowed: None, .. }] if *e == "198.51.100.8:13231".parse().unwrap()
        ));
    }

    #[test]
    fn a_new_private_key_and_port_are_sent_alone() {
        let before = WgDevice {
            private_key: key(7),
            listen_port: 13231,
            peers: vec![peer(1, &["10.9.0.2/32"], None)],
        };
        let mut want = before.clone();
        want.private_key = key(8);
        want.listen_port = 13232;
        let p = plan(&want, &kernel_of(&before), Some(&before));
        assert_eq!(p.private_key, Some(key(8)));
        assert_eq!(p.listen_port, Some(13232));
        assert!(p.peers.is_empty());
    }

    #[test]
    fn allowed_addresses_compare_as_sets_of_networks() {
        let a: Vec<IpNet> = vec![
            "10.9.0.2/32".parse().unwrap(),
            "10.20.1.0/16".parse().unwrap(),
        ];
        let b: Vec<IpNet> = vec![
            "10.20.0.0/16".parse().unwrap(),
            "10.9.0.2/32".parse().unwrap(),
        ];
        assert!(same_set(&a, &b));
        assert!(!same_set(&a, &b[..1]));
    }

    #[test]
    fn many_peers_split_into_requests_under_the_nest_limit() {
        let want = WgDevice {
            private_key: key(7),
            listen_port: 13231,
            peers: (0..2000u32)
                .map(|i| {
                    let mut k = [0u8; 32];
                    k[..4].copy_from_slice(&i.to_be_bytes());
                    WgPeerSpec {
                        public_key: k,
                        allowed: vec![
                            IpNet::new(IpAddr::V4(Ipv4Addr::from(0x0A40_0000 + i)), 32).unwrap(),
                        ],
                        ..WgPeerSpec::default()
                    }
                })
                .collect(),
        };
        let p = plan(&want, &KernelDevice::default(), None);
        let reqs = encode(28, 100, "wg0", &p);
        assert!(reqs.len() > 1);
        let seqs: Vec<u32> = reqs.iter().map(|(s, _)| *s).collect();
        assert_eq!(seqs, (100..100 + reqs.len() as u32).collect::<Vec<_>>());
        for (_, r) in &reqs {
            assert!(r.len() <= MAX_REQUEST + 512, "{}", r.len());
        }
        let back = parse(bodies(&reqs).iter().map(Vec::as_slice));
        assert_eq!(back.peers.len(), 2000);
        // Only the first request carries the private key.
        let keys = bodies(&reqs)
            .iter()
            .filter(|b| attrs(b).any(|a| a.kind == D_PRIVATE_KEY))
            .count();
        assert_eq!(keys, 1);
    }

    #[test]
    fn a_peer_continued_in_the_next_message_is_coalesced() {
        let mut m1 = Msg::new(28, CMD_GET, 1, 1);
        m1.u16(D_LISTEN_PORT, 51820);
        m1.begin(D_PEERS);
        put_peer(
            &mut m1,
            &PeerChange::Set {
                public_key: key(1),
                preshared_key: None,
                endpoint: None,
                keepalive: Some(25),
                allowed: Some(vec!["10.0.0.0/24".parse().unwrap()]),
            },
        );
        let mut m2 = Msg::new(28, CMD_GET, 1, 1);
        m2.begin(D_PEERS);
        put_peer(
            &mut m2,
            &PeerChange::Set {
                public_key: key(1),
                preshared_key: None,
                endpoint: None,
                keepalive: None,
                allowed: Some(vec!["10.0.1.0/24".parse().unwrap()]),
            },
        );
        let reqs = vec![(1, m1.finish()), (1, m2.finish())];
        let dev = parse(bodies(&reqs).iter().map(Vec::as_slice));
        assert_eq!(dev.peers.len(), 1);
        assert_eq!(dev.peers.first().map(|p| p.allowed.len()), Some(2));
        assert_eq!(dev.peers.first().map(|p| p.keepalive), Some(25));
        // The dump request names the link and asks for a dump.
        let req = get_request(28, 9, "wg0");
        assert!(
            replies(&req, 9)
                .iter()
                .all(|r| !matches!(r, Reply::Error(_)))
        );
    }

    #[test]
    fn last_handshake_zero_is_never() {
        let mut d = KernelDevice::default();
        d.peers.push(KernelPeer {
            public_key: key(1),
            last_handshake: (1_794_500_000, 5),
            ..KernelPeer::default()
        });
        d.peers.push(KernelPeer {
            public_key: key(2),
            ..KernelPeer::default()
        });
        let s = status(&d);
        assert_eq!(
            s.peers.first().and_then(|p| p.last_handshake_unix),
            Some(1_794_500_000)
        );
        assert_eq!(s.peers.get(1).and_then(|p| p.last_handshake_unix), None);
    }

    proptest::proptest! {
        /// Hostile dumps: never a panic, bounded output.
        #[test]
        fn parse_survives_garbage(bufs in proptest::collection::vec(proptest::collection::vec(proptest::prelude::any::<u8>(), 0..512), 0..8)) {
            let d = parse(bufs.iter().map(Vec::as_slice));
            proptest::prop_assert!(d.peers.len() <= MAX_DUMP_PEERS);
        }
    }
}
