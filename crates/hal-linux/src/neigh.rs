//! Neighbor tables over rtnetlink (G1.27d), without `ip neigh` and
//! without the async `rtnetlink` crate: one blocking socket, messages
//! parsed in place.
//!
//! - dump: `RTM_GETNEIGH` + `NLM_F_DUMP`, both families in one request;
//! - events: a socket in group `RTNLGRP_NEIGH` gets every `RTM_NEWNEIGH`
//!   and `RTM_DELNEIGH` as it happens, so the table is kept without
//!   polling; `ENOBUFS` (the reader fell behind) is counted and the
//!   caller dumps again;
//! - static entries: `RTM_NEWNEIGH` with `NUD_PERMANENT` (RouterOS
//!   `/ip arp add`), `NTF_PROXY` for `published`; `RTM_DELNEIGH` removes
//!   one (and flushes learned ones);
//! - the ARP mode of an interface: [`mode_sysctls`] and `IFF_NOARP`.
//!
//! The codec is pure and bounded: a hostile or truncated message yields
//! no neighbor, never a panic (proptest below).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use corerouter_hal::neigh::NeighState;
use corerouter_model::arp::ArpMode;

pub const RTM_NEWNEIGH: u16 = 28;
pub const RTM_DELNEIGH: u16 = 29;
pub const RTM_GETNEIGH: u16 = 30;
/// `RTNLGRP_NEIGH`.
pub const GROUP_NEIGH: u32 = 3;

const AF_UNSPEC: u8 = 0;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;
const NDA_DST: u16 = 1;
const NDA_LLADDR: u16 = 2;
const NDA_CACHEINFO: u16 = 3;
const NTF_PROXY: u8 = 0x08;
const NTF_ROUTER: u8 = 0x80;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_ACK: u16 = 0x4;
const NLM_F_REPLACE: u16 = 0x100;
const NLM_F_CREATE: u16 = 0x400;
const NLM_F_DUMP: u16 = 0x300;
const NLMSG_HDR: usize = 16;
const NDMSG: usize = 12;
/// `clock_t` ticks per second of `nda_cacheinfo` (`USER_HZ`, 100 on
/// every Linux architecture that exports it).
const USER_HZ: u32 = 100;

/// One `RTM_*NEIGH` message, decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawNeigh {
    pub ifindex: u32,
    pub address: IpAddr,
    pub mac: Option<[u8; 6]>,
    /// `None` for `NUD_NONE` (an entry being created).
    pub state: Option<NeighState>,
    pub router: bool,
    /// A proxy entry (`ip neigh add proxy`), not a host.
    pub proxy: bool,
    pub confirmed_secs: Option<u32>,
    pub updated_secs: Option<u32>,
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_ne_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

/// The attributes after the `ndmsg` header: (type, payload), stopping at
/// the first malformed one.
fn rtattrs(mut b: &[u8]) -> impl Iterator<Item = (u16, &[u8])> {
    std::iter::from_fn(move || {
        let len = usize::from(u16_at(b, 0)?);
        let kind = u16_at(b, 2)? & 0x3fff;
        if len < 4 {
            return None;
        }
        let data = b.get(4..len)?;
        b = b.get(len.div_ceil(4) * 4..).unwrap_or(&[]);
        Some((kind, data))
    })
}

/// The body of one `RTM_NEWNEIGH`/`RTM_DELNEIGH` (after the netlink
/// header). Only IPv4/IPv6 with a destination; multicast destinations
/// (the kernel keeps `NOARP` entries for them) are not neighbors.
pub fn parse(body: &[u8]) -> Option<RawNeigh> {
    let hdr = body.get(..NDMSG)?;
    let family = *hdr.first()?;
    let ifindex = u32::try_from(i32::from_ne_bytes(hdr.get(4..8)?.try_into().ok()?)).ok()?;
    let state = u16_at(hdr, 8)?;
    let flags = *hdr.get(10)?;
    let mut address = None;
    let mut mac = None;
    let mut cache = None;
    for (kind, data) in rtattrs(body.get(NDMSG..)?) {
        match (kind, family) {
            (NDA_DST, AF_INET) => {
                address = Some(IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(data).ok()?)));
            }
            (NDA_DST, AF_INET6) => {
                address = Some(IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(data).ok()?)));
            }
            (NDA_LLADDR, _) => mac = <[u8; 6]>::try_from(data).ok(),
            (NDA_CACHEINFO, _) => {
                cache = Some((u32_at(data, 0)?, u32_at(data, 8)?));
            }
            _ => {}
        }
    }
    let address = address?;
    if address.is_multicast() {
        return None;
    }
    let state = NeighState::from_nud(state);
    // A MAC of an entry that never resolved is the kernel's leftover.
    let mac = mac.filter(|_| state.is_some_and(NeighState::resolved));
    Some(RawNeigh {
        ifindex,
        address,
        mac,
        state,
        router: flags & NTF_ROUTER != 0,
        proxy: flags & NTF_PROXY != 0,
        confirmed_secs: cache.map(|(c, _)| c / USER_HZ),
        updated_secs: cache.map(|(_, u)| u / USER_HZ),
    })
}

fn header(buf: &mut Vec<u8>, kind: u16, flags: u16, seq: u32) {
    buf.extend_from_slice(&0u32.to_ne_bytes());
    buf.extend_from_slice(&kind.to_ne_bytes());
    buf.extend_from_slice(&flags.to_ne_bytes());
    buf.extend_from_slice(&seq.to_ne_bytes());
    buf.extend_from_slice(&0u32.to_ne_bytes());
}

fn ndmsg(buf: &mut Vec<u8>, family: u8, ifindex: u32, state: u16, flags: u8) {
    buf.extend_from_slice(&[family, 0, 0, 0]);
    buf.extend_from_slice(&ifindex.to_ne_bytes());
    buf.extend_from_slice(&state.to_ne_bytes());
    buf.push(flags);
    buf.push(0);
}

fn attr(buf: &mut Vec<u8>, kind: u16, data: &[u8]) {
    let len = u16::try_from(4 + data.len()).unwrap_or(u16::MAX);
    buf.extend_from_slice(&len.to_ne_bytes());
    buf.extend_from_slice(&kind.to_ne_bytes());
    buf.extend_from_slice(data);
    while !buf.len().is_multiple_of(4) {
        buf.push(0);
    }
}

fn finish(mut buf: Vec<u8>) -> Vec<u8> {
    let len = u32::try_from(buf.len()).unwrap_or(u32::MAX).to_ne_bytes();
    if let Some(head) = buf.get_mut(..4) {
        head.copy_from_slice(&len);
    }
    buf
}

fn ip_bytes(ip: IpAddr) -> (u8, Vec<u8>) {
    match ip {
        IpAddr::V4(a) => (AF_INET, a.octets().to_vec()),
        IpAddr::V6(a) => (AF_INET6, a.octets().to_vec()),
    }
}

/// Dump both families' tables.
pub fn dump_request(seq: u32) -> Vec<u8> {
    let mut b = Vec::with_capacity(32);
    header(&mut b, RTM_GETNEIGH, NLM_F_REQUEST | NLM_F_DUMP, seq);
    ndmsg(&mut b, AF_UNSPEC, 0, 0, 0);
    finish(b)
}

/// A permanent entry (`ip neigh replace … nud permanent`); with `proxy`,
/// the proxy entry for `ip` instead (`ip neigh add proxy`).
pub fn add_request(ifindex: u32, ip: IpAddr, mac: [u8; 6], proxy: bool, seq: u32) -> Vec<u8> {
    let (family, dst) = ip_bytes(ip);
    let mut b = Vec::with_capacity(48);
    header(
        &mut b,
        RTM_NEWNEIGH,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE,
        seq,
    );
    let flags = if proxy { NTF_PROXY } else { 0 };
    ndmsg(&mut b, family, ifindex, NeighState::Permanent.nud(), flags);
    attr(&mut b, NDA_DST, &dst);
    if !proxy {
        attr(&mut b, NDA_LLADDR, &mac);
    }
    finish(b)
}

pub fn delete_request(ifindex: u32, ip: IpAddr, proxy: bool, seq: u32) -> Vec<u8> {
    let (family, dst) = ip_bytes(ip);
    let mut b = Vec::with_capacity(40);
    header(&mut b, RTM_DELNEIGH, NLM_F_REQUEST | NLM_F_ACK, seq);
    ndmsg(
        &mut b,
        family,
        ifindex,
        0,
        if proxy { NTF_PROXY } else { 0 },
    );
    attr(&mut b, NDA_DST, &dst);
    finish(b)
}

/// `RTM_NEWLINK` setting or clearing `IFF_NOARP` (`ip link set arp off`).
pub fn noarp_request(ifindex: u32, noarp: bool, seq: u32) -> Vec<u8> {
    const RTM_NEWLINK: u16 = 16;
    const IFF_NOARP: u32 = 0x80;
    let mut b = Vec::with_capacity(32);
    header(&mut b, RTM_NEWLINK, NLM_F_REQUEST | NLM_F_ACK, seq);
    // ifinfomsg: family, pad, type, index, flags, change.
    b.extend_from_slice(&[AF_UNSPEC, 0, 0, 0]);
    b.extend_from_slice(&ifindex.to_ne_bytes());
    b.extend_from_slice(&(if noarp { IFF_NOARP } else { 0 }).to_ne_bytes());
    b.extend_from_slice(&IFF_NOARP.to_ne_bytes());
    finish(b)
}

/// The kernel parameters of `/proc/sys/net/ipv4/{conf,neigh}/<if>/` that
/// make RouterOS' `arp` mode, with the values of `mode` (`IFF_NOARP` is
/// set apart: [`noarp_request`]).
///
/// - `proxy-arp`: `conf/proxy_arp` (RFC 1027);
/// - `local-proxy-arp`: `conf/proxy_arp_pvlan` (answers for hosts of the
///   same port, RFC 3069 private VLAN);
/// - `reply-only`: no solicitations at all (`ucast/mcast/app_solicit` 0):
///   an address without a static entry goes `failed` at once instead of
///   being resolved. What the kernel still learns from requests to us is
///   removed as it appears (the daemon's neighbor service, by event).
pub fn mode_sysctls(mode: ArpMode) -> [(&'static str, &'static str, i64); 5] {
    let solicit = if mode == ArpMode::ReplyOnly { 0 } else { 3 };
    [
        ("conf", "proxy_arp", i64::from(mode == ArpMode::ProxyArp)),
        (
            "conf",
            "proxy_arp_pvlan",
            i64::from(mode == ArpMode::LocalProxyArp),
        ),
        ("neigh", "ucast_solicit", solicit),
        ("neigh", "mcast_solicit", solicit),
        ("neigh", "app_solicit", 0),
    ]
}

/// One netlink header in `buf`: (length, type, flags, seq).
pub fn nlmsg_header(buf: &[u8]) -> Option<(usize, u16, u16, u32)> {
    let len = usize::try_from(u32_at(buf, 0)?).ok()?;
    if len < NLMSG_HDR {
        return None;
    }
    Some((len, u16_at(buf, 4)?, u16_at(buf, 6)?, u32_at(buf, 8)?))
}

#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};
    use std::os::fd::AsFd;
    use std::time::{Duration, Instant};

    use corerouter_hal::HalError;
    use corerouter_hal::neigh::{
        ArpPinger, ArpReply, MAX_NEIGHBORS, NeighEvent, Neighbor, NeighborFeed,
    };
    use corerouter_model::IfName;
    use netlink_sys::{Socket, protocols::NETLINK_ROUTE};
    use nix::poll::{PollFd, PollFlags, PollTimeout, poll};

    use super::{RTM_DELNEIGH, RTM_NEWNEIGH, RawNeigh, nlmsg_header, parse};

    const NLMSG_ERROR: u16 = 2;
    const NLMSG_DONE: u16 = 3;
    /// The dump was interrupted by a change (`NLM_F_DUMP_INTR`): read again.
    const NLM_F_DUMP_INTR: u16 = 0x10;
    const ENOBUFS: i32 = 105;
    /// 16 MiB: ~150 thousand events of slack (**estimado**, ~100 bytes
    /// each) while the reader is busy (a flood of new hosts, a flush).
    const RCVBUF: usize = 16 << 20;
    /// A dump of a million entries takes about a second (**estimado**).
    const DEADLINE: Duration = Duration::from_secs(20);

    fn io(e: impl std::fmt::Display) -> HalError {
        HalError::Io(format!("neighbor netlink: {e}"))
    }

    fn open() -> Result<Socket, HalError> {
        let mut sock = Socket::new(NETLINK_ROUTE).map_err(io)?;
        sock.bind_auto().map_err(io)?;
        use nix::sys::socket::{setsockopt, sockopt};
        if setsockopt(&sock.as_fd(), sockopt::RcvBufForce, &RCVBUF).is_err() {
            let _ = setsockopt(&sock.as_fd(), sockopt::RcvBuf, &RCVBUF);
        }
        Ok(sock)
    }

    /// Messages answering `seq` until `NLMSG_DONE` or the ACK/error, each
    /// handed to `each` as (type, flags, body after the netlink header).
    fn read(
        sock: &mut Socket,
        buf: &mut [u8],
        seq: u32,
        mut each: impl FnMut(u16, u16, &[u8]),
    ) -> Result<(), HalError> {
        let start = Instant::now();
        loop {
            let left = DEADLINE.saturating_sub(start.elapsed());
            if left.is_zero() {
                return Err(HalError::Io(
                    "neighbors: the kernel did not answer in time".into(),
                ));
            }
            let ms = u16::try_from(left.as_millis().min(1000)).unwrap_or(1000);
            let mut fds = [PollFd::new(sock.as_fd(), PollFlags::POLLIN)];
            if poll(&mut fds, PollTimeout::from(ms)).map_err(io)? == 0 {
                continue;
            }
            let n = sock.recv(&mut &mut buf[..], 0).map_err(io)?;
            let mut rest = buf.get(..n).unwrap_or(&[]);
            while let Some((len, kind, flags, mseq)) = nlmsg_header(rest) {
                let msg = rest.get(..len).unwrap_or(rest);
                rest = rest.get(len.div_ceil(4) * 4..).unwrap_or(&[]);
                if mseq != seq {
                    continue;
                }
                match kind {
                    NLMSG_DONE => return Ok(()),
                    NLMSG_ERROR => {
                        let code = msg
                            .get(16..20)
                            .and_then(|b| b.try_into().ok())
                            .map_or(0, i32::from_ne_bytes);
                        return if code == 0 {
                            Ok(())
                        } else {
                            Err(HalError::Rejected(
                                std::io::Error::from_raw_os_error(code.saturating_neg())
                                    .to_string(),
                            ))
                        };
                    }
                    _ => each(kind, flags, msg.get(16..).unwrap_or(&[])),
                }
            }
        }
    }

    /// Interface index → name, from one `RTM_GETLINK` dump; read again
    /// when an index is not known (a link was created).
    #[derive(Default)]
    pub struct Names(HashMap<u32, IfName>);

    impl Names {
        pub fn refresh(&mut self) -> Result<(), HalError> {
            self.0 = crate::netlink::links()?
                .into_iter()
                .filter_map(|l| Some((l.index, l.name.parse().ok()?)))
                .collect();
            Ok(())
        }

        pub fn name(&mut self, index: u32) -> Option<IfName> {
            if !self.0.contains_key(&index) {
                let _ = self.refresh();
            }
            self.0.get(&index).cloned()
        }

        pub fn index(&mut self, name: &IfName) -> Option<u32> {
            let find =
                |m: &HashMap<u32, IfName>| m.iter().find(|(_, n)| *n == name).map(|(i, _)| *i);
            if let Some(i) = find(&self.0) {
                return Some(i);
            }
            let _ = self.refresh();
            find(&self.0)
        }
    }

    fn host(r: RawNeigh, names: &mut Names) -> Option<Neighbor> {
        if r.proxy {
            return None;
        }
        Some(Neighbor {
            interface: names.name(r.ifindex)?,
            address: r.address,
            mac: r.mac,
            state: r.state?,
            router: r.router,
            confirmed_secs: r.confirmed_secs,
            updated_secs: r.updated_secs,
        })
    }

    /// Every entry of both tables (at most [`MAX_NEIGHBORS`]); `false`
    /// when there were more. A dump the kernel marks interrupted is read
    /// again (three times at most).
    pub fn dump(
        sock: &mut Socket,
        buf: &mut [u8],
        names: &mut Names,
        out: &mut Vec<Neighbor>,
    ) -> Result<bool, HalError> {
        let mark = out.len();
        for attempt in 0..3u32 {
            out.truncate(mark);
            let seq = 0x4e00_0000 | attempt;
            sock.send(&super::dump_request(seq), 0).map_err(io)?;
            let mut more = false;
            let mut torn = false;
            read(sock, buf, seq, |kind, flags, body| {
                torn |= flags & NLM_F_DUMP_INTR != 0;
                if kind != RTM_NEWNEIGH {
                    return;
                }
                if out.len() - mark >= MAX_NEIGHBORS {
                    more = true;
                    return;
                }
                if let Some(n) = parse(body).and_then(|r| host(r, names)) {
                    out.push(n);
                }
            })?;
            if !torn {
                return Ok(!more);
            }
        }
        Ok(true)
    }

    /// One dump on a fresh socket.
    pub fn neighbors() -> Result<Vec<Neighbor>, HalError> {
        let mut sock = open()?;
        let mut names = Names::default();
        names.refresh()?;
        let mut out = Vec::new();
        dump(&mut sock, &mut vec![0u8; 1 << 17], &mut names, &mut out)?;
        Ok(out)
    }

    /// Requests one at a time on one socket; how many the kernel
    /// accepted, plus the first refusal for which `ignore` says no.
    fn each_request(
        reqs: impl Iterator<Item = Vec<u8>>,
        ignore: impl Fn(&str) -> bool,
    ) -> Result<usize, HalError> {
        let mut sock = open()?;
        let mut buf = vec![0u8; 8192];
        let mut done = 0;
        for (i, req) in reqs.enumerate() {
            let seq = u32::try_from(i)
                .unwrap_or(u32::MAX)
                .wrapping_add(0x4e10_0000);
            sock.send(&req, 0).map_err(io)?;
            match read(&mut sock, &mut buf, seq, |_, _, _| {}) {
                Ok(()) => done += 1,
                Err(HalError::Rejected(e)) if ignore(&e) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(done)
    }

    /// Remove entries; one already gone is not an error.
    pub fn remove(items: &[(IfName, IpAddr)]) -> Result<usize, HalError> {
        let mut names = Names::default();
        names.refresh()?;
        let reqs: Vec<Vec<u8>> = items
            .iter()
            .enumerate()
            .filter_map(|(i, (n, ip))| {
                let seq = u32::try_from(i)
                    .unwrap_or(u32::MAX)
                    .wrapping_add(0x4e10_0000);
                Some(super::delete_request(names.index(n)?, *ip, false, seq))
            })
            .collect();
        each_request(reqs.into_iter(), |e| e.contains("No such file"))
    }

    /// One static change: add (or replace) `mac` for `ip`, or remove it.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct StaticOp {
        pub interface: IfName,
        pub ip: IpAddr,
        /// `None`: remove.
        pub mac: Option<[u8; 6]>,
        pub proxy: bool,
    }

    /// Run `ops` in order; the first refusal stops them.
    pub fn statics(ops: &[StaticOp]) -> Result<(), HalError> {
        let mut names = Names::default();
        names.refresh()?;
        let mut sock = open()?;
        let mut buf = vec![0u8; 8192];
        for (i, op) in ops.iter().enumerate() {
            let seq = u32::try_from(i)
                .unwrap_or(u32::MAX)
                .wrapping_add(0x4e20_0000);
            let Some(index) = names.index(&op.interface) else {
                return Err(HalError::Rejected(format!(
                    "static ARP {}: no interface {}",
                    op.ip, op.interface
                )));
            };
            let req = match op.mac {
                Some(mac) => super::add_request(index, op.ip, mac, op.proxy, seq),
                None => super::delete_request(index, op.ip, op.proxy, seq),
            };
            sock.send(&req, 0).map_err(io)?;
            match read(&mut sock, &mut buf, seq, |_, _, _| {}) {
                Ok(()) => {}
                Err(HalError::Rejected(e)) if op.mac.is_none() && e.contains("No such file") => {}
                Err(HalError::Rejected(e)) => {
                    return Err(HalError::Rejected(format!(
                        "static ARP {} on {}: {e}",
                        op.ip, op.interface
                    )));
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Set or clear `IFF_NOARP` on `name`.
    pub fn set_noarp(name: &IfName, noarp: bool) -> Result<(), HalError> {
        let mut names = Names::default();
        let index = names
            .index(name)
            .ok_or_else(|| HalError::Rejected(format!("no interface {name}")))?;
        each_request(
            std::iter::once(super::noarp_request(index, noarp, 0x4e10_0000)),
            |_| false,
        )
        .map(|_| ())
    }

    /// The live feed: a socket in `RTNLGRP_NEIGH`, plus one for dumps.
    pub struct Feed {
        events: Socket,
        dumps: Socket,
        buf: Vec<u8>,
        names: Names,
        lost: u64,
    }

    impl Feed {
        pub fn open() -> Result<Self, HalError> {
            let events = open()?;
            events.add_membership(super::GROUP_NEIGH).map_err(io)?;
            events.set_non_blocking(true).map_err(io)?;
            let mut names = Names::default();
            names.refresh()?;
            Ok(Self {
                events,
                dumps: open()?,
                buf: vec![0u8; 1 << 17],
                names,
                lost: 0,
            })
        }

        fn take(&mut self, n: usize, out: &mut Vec<NeighEvent>) {
            let Self { buf, names, .. } = self;
            let mut rest = buf.get(..n).unwrap_or(&[]);
            while let Some((len, kind, _, _)) = nlmsg_header(rest) {
                let msg = rest.get(..len).unwrap_or(rest);
                rest = rest.get(len.div_ceil(4) * 4..).unwrap_or(&[]);
                let Some(raw) = parse(msg.get(16..).unwrap_or(&[])) else {
                    continue;
                };
                if raw.proxy {
                    continue;
                }
                let Some(interface) = names.name(raw.ifindex) else {
                    continue;
                };
                // An entry going back to NUD_NONE/NUD_FAILED-then-gone
                // arrives as DELNEIGH; a NEWNEIGH without state is one
                // being created: nothing to show yet.
                match (kind, raw.state) {
                    (RTM_DELNEIGH, _) => out.push(NeighEvent::Remove {
                        interface,
                        address: raw.address,
                    }),
                    (RTM_NEWNEIGH, Some(state)) => out.push(NeighEvent::Upsert(Neighbor {
                        interface,
                        address: raw.address,
                        mac: raw.mac,
                        state,
                        router: raw.router,
                        confirmed_secs: raw.confirmed_secs,
                        updated_secs: raw.updated_secs,
                    })),
                    _ => {}
                }
            }
        }
    }

    impl NeighborFeed for Feed {
        fn dump(&mut self, out: &mut Vec<Neighbor>) -> Result<bool, HalError> {
            let mut buf = std::mem::take(&mut self.buf);
            let r = dump(&mut self.dumps, &mut buf, &mut self.names, out);
            self.buf = buf;
            r
        }

        fn recv(
            &mut self,
            wait_ms: u32,
            max: usize,
            out: &mut Vec<NeighEvent>,
        ) -> Result<(), HalError> {
            let start = out.len();
            let ms = u16::try_from(wait_ms).unwrap_or(u16::MAX);
            let mut fds = [PollFd::new(self.events.as_fd(), PollFlags::POLLIN)];
            if poll(&mut fds, PollTimeout::from(ms)).map_err(io)? == 0 {
                return Ok(());
            }
            while out.len() - start < max {
                let mut buf = std::mem::take(&mut self.buf);
                let got = self.events.recv(&mut &mut buf[..], 0);
                self.buf = buf;
                match got {
                    Ok(n) => self.take(n, out),
                    Err(e) if e.raw_os_error() == Some(ENOBUFS) => self.lost += 1,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(io(e)),
                }
            }
            Ok(())
        }

        fn lost(&self) -> u64 {
            self.lost
        }

        fn name(&self) -> &'static str {
            "netlink"
        }
    }

    /// What `apply` put in the kernel of `ip.arp` (G1.27d): the static
    /// entries, and the ARP mode of each interface with the values the
    /// kernel had before CoreRouter first changed them (taking a mode out
    /// puts them back, like `system.tuning`).
    #[derive(Debug, Default)]
    pub struct Applied {
        /// (interface, address, published) → MAC.
        statics: std::collections::BTreeMap<(IfName, Ipv4Addr, bool), [u8; 6]>,
        /// Per interface: the original of each parameter it changed.
        orig: std::collections::BTreeMap<IfName, Vec<(String, String)>>,
        /// Interfaces CoreRouter set `IFF_NOARP` on.
        noarp: std::collections::BTreeSet<IfName>,
    }

    fn sysctl_path(family: &str, dir: &str, name: &IfName, key: &str) -> String {
        format!("/proc/sys/net/{family}/{dir}/{name}/{key}")
    }

    impl Applied {
        /// Bring the kernel to `to`'s `ip.arp`, for interfaces `has`
        /// (managed, present). On a refusal what this call did is undone.
        pub fn sync(
            &mut self,
            to: &corerouter_model::Config,
            has: &dyn Fn(&IfName) -> bool,
        ) -> Result<(), HalError> {
            let want: std::collections::BTreeMap<_, _> = to
                .ip
                .arp
                .active(|n| has(n))
                .flat_map(|e| {
                    let host = ((e.interface.clone(), e.address, false), e.mac.0);
                    let proxy = ((e.interface.clone(), e.address, true), e.mac.0);
                    std::iter::once(host).chain(e.published.then_some(proxy))
                })
                .collect();
            let mut ops = Vec::new();
            let mut undo = Vec::new();
            for ((n, ip, proxy), mac) in &self.statics {
                if !want.contains_key(&(n.clone(), *ip, *proxy)) {
                    ops.push(StaticOp {
                        interface: n.clone(),
                        ip: IpAddr::V4(*ip),
                        mac: None,
                        proxy: *proxy,
                    });
                    undo.push(StaticOp {
                        interface: n.clone(),
                        ip: IpAddr::V4(*ip),
                        mac: Some(*mac),
                        proxy: *proxy,
                    });
                }
            }
            for ((n, ip, proxy), mac) in &want {
                if self.statics.get(&(n.clone(), *ip, *proxy)) != Some(mac) {
                    ops.push(StaticOp {
                        interface: n.clone(),
                        ip: IpAddr::V4(*ip),
                        mac: Some(*mac),
                        proxy: *proxy,
                    });
                    let back = self.statics.get(&(n.clone(), *ip, *proxy)).copied();
                    undo.push(StaticOp {
                        interface: n.clone(),
                        ip: IpAddr::V4(*ip),
                        mac: back,
                        proxy: *proxy,
                    });
                }
            }
            if let Err(e) = statics(&ops) {
                undo.reverse();
                if let Err(back) = statics(&undo) {
                    log::error!("restoring static ARP entries: {back}");
                }
                return Err(e);
            }
            self.statics = want;
            self.modes(to, has);
            Ok(())
        }

        /// The ARP mode and timeout of every interface (best effort: a
        /// parameter the kernel lacks is logged, never refuses the
        /// commit, like the RA settings).
        fn modes(&mut self, to: &corerouter_model::Config, has: &dyn Fn(&IfName) -> bool) {
            use corerouter_model::arp::ArpMode;
            let names: std::collections::BTreeSet<IfName> = to
                .ip
                .arp
                .interfaces
                .keys()
                .chain(self.orig.keys())
                .chain(self.noarp.iter())
                .filter(|n| has(n))
                .cloned()
                .collect();
            for name in names {
                let set = to.ip.arp.interface(&name);
                if set.is_default() {
                    // Back to what the kernel had.
                    for (path, v) in self.orig.remove(&name).unwrap_or_default() {
                        if let Err(e) = std::fs::write(&path, &v) {
                            log::warn!("{path}: {e}");
                        }
                    }
                } else {
                    let mut wanted: Vec<(String, String)> = super::mode_sysctls(set.mode)
                        .into_iter()
                        .map(|(dir, key, v)| (sysctl_path("ipv4", dir, &name, key), v.to_string()))
                        .collect();
                    if let Some(t) = set.timeout_secs {
                        wanted.push((
                            sysctl_path("ipv4", "neigh", &name, "base_reachable_time_ms"),
                            (u64::from(t) * 1000).to_string(),
                        ));
                    }
                    let orig = self.orig.entry(name.clone()).or_default();
                    // A parameter no longer wanted goes back first.
                    orig.retain(|(path, v)| {
                        if wanted.iter().any(|(p, _)| p == path) {
                            return true;
                        }
                        if let Err(e) = std::fs::write(path, v) {
                            log::warn!("{path}: {e}");
                        }
                        false
                    });
                    for (path, v) in wanted {
                        if !orig.iter().any(|(p, _)| *p == path) {
                            match std::fs::read_to_string(&path) {
                                Ok(old) => orig.push((path.clone(), old.trim().to_owned())),
                                Err(e) => {
                                    log::warn!("{path}: {e}");
                                    continue;
                                }
                            }
                        }
                        if let Err(e) = std::fs::write(&path, &v) {
                            log::warn!("{path}: {e}");
                        }
                    }
                }
                let off = set.mode == ArpMode::Disabled;
                if off != self.noarp.contains(&name) {
                    match set_noarp(&name, off) {
                        Ok(()) if off => {
                            self.noarp.insert(name.clone());
                        }
                        Ok(()) => {
                            self.noarp.remove(&name);
                        }
                        Err(e) => log::warn!("{name}: arp {}: {e}", if off { "off" } else { "on" }),
                    }
                }
            }
        }
    }

    /// ARP requests over `AF_PACKET` on one interface (`arping`).
    pub struct Pinger {
        name: IfName,
        mac: [u8; 6],
        sock: socket2::Socket,
    }

    impl Pinger {
        pub fn open(name: &IfName) -> Result<Self, HalError> {
            let fail = |e: std::io::Error| HalError::Io(format!("{name}: ARP socket: {e}"));
            let info = crate::l2::if_info(name).map_err(fail)?;
            let sock = crate::dhcp::packet_socket(&info.link, 0x0806).map_err(fail)?;
            Ok(Self {
                name: name.clone(),
                mac: info.mac,
                sock,
            })
        }
    }

    impl ArpPinger for Pinger {
        fn ping(
            &mut self,
            src: Ipv4Addr,
            target: Ipv4Addr,
            timeout: Duration,
        ) -> Result<Option<ArpReply>, HalError> {
            use nix::sys::socket::{LinkAddr, MsgFlags, recvfrom, send};
            use std::os::fd::AsRawFd;
            /// `PACKET_OUTGOING`: our own request, looped back.
            const PACKET_OUTGOING: u8 = 4;
            let start = Instant::now();
            // RFC 826: sender = our MAC and address, target = who we ask.
            send(
                self.sock.as_raw_fd(),
                &crate::dhcp_server::arp_request(self.mac, src, target),
                MsgFlags::empty(),
            )
            .map_err(|e| HalError::Io(format!("{}: ARP request: {e}", self.name)))?;
            let mut buf = [0u8; 128];
            while let Some(left) = timeout.checked_sub(start.elapsed()) {
                let ms = u16::try_from(left.as_millis().max(1)).unwrap_or(u16::MAX);
                let mut fds = [PollFd::new(self.sock.as_fd(), PollFlags::POLLIN)];
                if poll(&mut fds, PollTimeout::from(ms)).map_err(io)? == 0 {
                    continue;
                }
                while let Ok((n, from)) = recvfrom::<LinkAddr>(self.sock.as_raw_fd(), &mut buf) {
                    if from.is_some_and(|a| a.pkttype() == PACKET_OUTGOING) {
                        continue;
                    }
                    let frame = buf.get(..n).unwrap_or(&[]);
                    if let Some(mac) = crate::dhcp::arp_claims(frame, target, self.mac) {
                        return Ok(Some(ArpReply {
                            mac,
                            rtt: start.elapsed(),
                        }));
                    }
                }
            }
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// A message as the kernel sends it (the body after the netlink
    /// header), built like a request.
    fn body(family: u8, ifindex: u32, state: u16, flags: u8, attrs: &[(u16, &[u8])]) -> Vec<u8> {
        let mut b = Vec::new();
        ndmsg(&mut b, family, ifindex, state, flags);
        for (k, d) in attrs {
            attr(&mut b, *k, d);
        }
        b
    }

    #[test]
    fn a_reachable_ipv4_entry() {
        let mac = [0, 0x50, 0x56, 1, 2, 3];
        let mut ci = Vec::new();
        for v in [250u32, 100, 1200, 1] {
            ci.extend_from_slice(&v.to_ne_bytes());
        }
        let b = body(
            AF_INET,
            7,
            0x02,
            0,
            &[
                (NDA_DST, &[10, 0, 0, 2]),
                (NDA_LLADDR, &mac),
                (NDA_CACHEINFO, &ci),
            ],
        );
        let n = parse(&b).unwrap();
        assert_eq!(n.ifindex, 7);
        assert_eq!(n.address, "10.0.0.2".parse::<IpAddr>().unwrap());
        assert_eq!(n.mac, Some(mac));
        // RFC 4861 §7.3.2: REACHABLE.
        assert_eq!(n.state, Some(NeighState::Reachable));
        assert_eq!(n.confirmed_secs, Some(2));
        assert_eq!(n.updated_secs, Some(12));
    }

    #[test]
    fn an_incomplete_entry_has_no_mac_and_a_router_flag_is_kept() {
        let b = body(
            AF_INET,
            1,
            0x01,
            0,
            &[(NDA_DST, &[10, 0, 0, 9]), (NDA_LLADDR, &[0; 6])],
        );
        let n = parse(&b).unwrap();
        assert_eq!((n.state, n.mac), (Some(NeighState::Incomplete), None));
        let six = "2001:db8::1".parse::<Ipv6Addr>().unwrap().octets();
        let b = body(
            AF_INET6,
            1,
            0x04,
            NTF_ROUTER,
            &[(NDA_DST, &six), (NDA_LLADDR, &[2; 6])],
        );
        let n = parse(&b).unwrap();
        assert!(n.router);
        assert_eq!(n.state, Some(NeighState::Stale));
    }

    #[test]
    fn multicast_and_addressless_messages_are_not_neighbors() {
        let ff02 = "ff02::1".parse::<Ipv6Addr>().unwrap().octets();
        assert!(parse(&body(AF_INET6, 1, 0x40, 0, &[(NDA_DST, &ff02)])).is_none());
        assert!(parse(&body(AF_INET, 1, 0x02, 0, &[])).is_none());
        // A wrong-size address is skipped, not trusted.
        assert!(parse(&body(AF_INET, 1, 0x02, 0, &[(NDA_DST, &[1, 2, 3])])).is_none());
    }

    #[test]
    fn requests_parse_back() {
        let ip: IpAddr = "192.0.2.7".parse().unwrap();
        let req = add_request(3, ip, [2, 0, 0, 0, 0, 7], false, 9);
        let (len, kind, flags, seq) = nlmsg_header(&req).unwrap();
        assert_eq!((len, kind, seq), (req.len(), RTM_NEWNEIGH, 9));
        assert_ne!(flags & NLM_F_CREATE, 0);
        let n = parse(&req[16..]).unwrap();
        assert_eq!((n.ifindex, n.address), (3, ip));
        assert_eq!(n.state, Some(NeighState::Permanent));
        assert_eq!(n.mac, Some([2, 0, 0, 0, 0, 7]));
        let del = delete_request(3, ip, true, 10);
        let n = parse(&del[16..]).unwrap();
        assert!(n.proxy);
        assert_eq!(nlmsg_header(&dump_request(1)).unwrap().1, RTM_GETNEIGH);
    }

    #[test]
    fn modes_map_to_kernel_parameters() {
        let get = |m, k: &str| {
            mode_sysctls(m)
                .into_iter()
                .find(|(_, n, _)| *n == k)
                .map(|(_, _, v)| v)
        };
        assert_eq!(get(ArpMode::ProxyArp, "proxy_arp"), Some(1));
        assert_eq!(get(ArpMode::LocalProxyArp, "proxy_arp_pvlan"), Some(1));
        assert_eq!(get(ArpMode::ReplyOnly, "ucast_solicit"), Some(0));
        assert_eq!(get(ArpMode::Enabled, "mcast_solicit"), Some(3));
        assert_eq!(get(ArpMode::Enabled, "proxy_arp"), Some(0));
    }

    proptest! {
        #[test]
        fn hostile_bytes_never_panic(junk in proptest::collection::vec(any::<u8>(), 0..256)) {
            let _ = parse(&junk);
            let _ = nlmsg_header(&junk);
        }
    }
}
