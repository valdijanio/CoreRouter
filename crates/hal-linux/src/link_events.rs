//! Link events (G1.3d): a socket in `RTNLGRP_LINK` gets an `RTM_NEWLINK`
//! or `RTM_DELLINK` for every link created, removed, renamed or changed,
//! as it happens. The daemon's poll looks once a second, so a port gone and
//! back in between (a fast replug, a USB driver reset) went unseen; with
//! the events the engine looks at once, and the poll stays the safety net
//! for events the kernel dropped (`ENOBUFS`).
//!
//! Only the link names are read here; what changed is the engine's poll
//! to find out (`Session::link_events`). One message per change, ~0.7–1.5
//! KB, none while nothing changes (**medido**, 2026-10-30).

use std::collections::BTreeSet;

const RTM_NEWLINK: u16 = 16;
const RTM_DELLINK: u16 = 17;
const IFLA_IFNAME: u16 = 3;
/// `struct nlmsghdr`, then `struct ifinfomsg`.
const NLMSG_HDR: usize = 16;
const IFINFOMSG: usize = 16;
/// `IFNAMSIZ` with the NUL.
const IFNAMSIZ: usize = 16;
/// Names kept per wait; past this the caller looks at everything.
pub const MAX_NAMES: usize = 4096;

/// The names of the links that the `RTM_NEWLINK`/`RTM_DELLINK` messages in
/// `buf` (one `recv`) are about, added to `out`. Anything malformed is
/// skipped; `false` when `out` would pass [`MAX_NAMES`].
pub fn parse(buf: &[u8], out: &mut BTreeSet<String>) -> bool {
    let mut rest = buf;
    while rest.len() >= NLMSG_HDR {
        let len = rest
            .get(..4)
            .and_then(|b| b.try_into().ok())
            .map_or(0, u32::from_ne_bytes) as usize;
        let kind = rest
            .get(4..6)
            .and_then(|b| b.try_into().ok())
            .map_or(0, u16::from_ne_bytes);
        if len < NLMSG_HDR || len > rest.len() {
            return true;
        }
        let msg = rest.get(..len).unwrap_or(&[]);
        rest = rest.get(len.div_ceil(4) * 4..).unwrap_or(&[]);
        if kind != RTM_NEWLINK && kind != RTM_DELLINK {
            continue;
        }
        if let Some(name) = ifname(msg.get(NLMSG_HDR + IFINFOMSG..).unwrap_or(&[])) {
            if out.len() >= MAX_NAMES && !out.contains(&name) {
                return false;
            }
            out.insert(name);
        }
    }
    true
}

/// `IFLA_IFNAME` among the attributes.
fn ifname(mut attrs: &[u8]) -> Option<String> {
    while attrs.len() >= 4 {
        let len = usize::from(u16::from_ne_bytes(attrs.get(..2)?.try_into().ok()?));
        let kind = u16::from_ne_bytes(attrs.get(2..4)?.try_into().ok()?);
        if len < 4 || len > attrs.len() {
            return None;
        }
        if kind == IFLA_IFNAME {
            let v = attrs.get(4..len)?;
            let v = v.split(|b| *b == 0).next().unwrap_or(v);
            if v.is_empty() || v.len() >= IFNAMSIZ {
                return None;
            }
            return std::str::from_utf8(v).ok().map(str::to_owned);
        }
        attrs = attrs.get(len.div_ceil(4) * 4..).unwrap_or(&[]);
    }
    None
}

#[cfg(target_os = "linux")]
pub use linux::{Events, LinkEvents};

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::BTreeSet;
    use std::os::fd::AsFd;

    use corerouter_hal::HalError;
    use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_ROUTE};
    use nix::poll::{PollFd, PollFlags, PollTimeout, poll};

    const RTMGRP_LINK: u32 = 1;
    const ENOBUFS: i32 = 105;
    /// 4 MiB: a commit that makes a thousand VLANs sends ~1.5 MB of events
    /// (**estimado**, ~1.5 KB each, **medido**).
    const RCVBUF: usize = 4 << 20;

    fn io(e: impl std::fmt::Display) -> HalError {
        HalError::Io(format!("link events: {e}"))
    }

    /// What one wait brought.
    #[derive(Debug, Default, PartialEq, Eq)]
    pub enum Events {
        /// Nothing in time.
        #[default]
        None,
        /// These links changed.
        Names(BTreeSet<String>),
        /// The kernel dropped events, or more than
        /// [`super::MAX_NAMES`] links changed: look at everything.
        Lost,
    }

    /// A socket in `RTNLGRP_LINK`.
    pub struct LinkEvents {
        sock: Socket,
        buf: Vec<u8>,
    }

    impl LinkEvents {
        pub fn open() -> Result<Self, HalError> {
            let mut sock = Socket::new(NETLINK_ROUTE).map_err(io)?;
            sock.bind(&SocketAddr::new(0, RTMGRP_LINK)).map_err(io)?;
            use nix::sys::socket::{setsockopt, sockopt};
            if setsockopt(&sock.as_fd(), sockopt::RcvBufForce, &RCVBUF).is_err() {
                let _ = setsockopt(&sock.as_fd(), sockopt::RcvBuf, &RCVBUF);
            }
            sock.set_non_blocking(true).map_err(io)?;
            Ok(Self {
                sock,
                buf: vec![0; 64 << 10],
            })
        }

        /// Waits up to `ms` for the first event, then takes everything
        /// already queued.
        pub fn wait(&mut self, ms: u16) -> Result<Events, HalError> {
            let mut fds = [PollFd::new(self.sock.as_fd(), PollFlags::POLLIN)];
            if poll(&mut fds, PollTimeout::from(ms)).map_err(io)? == 0 {
                return Ok(Events::None);
            }
            let mut names = BTreeSet::new();
            let mut lost = false;
            loop {
                match self.sock.recv(&mut &mut self.buf[..], 0) {
                    Ok(0) => break,
                    Ok(n) => {
                        let got = self.buf.get(..n).unwrap_or(&[]);
                        lost |= !super::parse(got, &mut names);
                    }
                    Err(e) if e.raw_os_error() == Some(ENOBUFS) => lost = true,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) => return Err(io(e)),
                }
            }
            Ok(if lost {
                Events::Lost
            } else if names.is_empty() {
                Events::None
            } else {
                Events::Names(names)
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// One link message as the kernel sends it.
    fn msg(kind: u16, name: &str) -> Vec<u8> {
        let mut attr = Vec::new();
        let alen = 4 + name.len() + 1;
        attr.extend_from_slice(&u16::try_from(alen).unwrap().to_ne_bytes());
        attr.extend_from_slice(&IFLA_IFNAME.to_ne_bytes());
        attr.extend_from_slice(name.as_bytes());
        attr.push(0);
        while attr.len() % 4 != 0 {
            attr.push(0);
        }
        // An attribute before the name (IFLA_MTU).
        let mut mtu = vec![8, 0, 4, 0];
        mtu.extend_from_slice(&1500u32.to_ne_bytes());
        let len = NLMSG_HDR + IFINFOMSG + mtu.len() + attr.len();
        let mut m = Vec::new();
        m.extend_from_slice(&u32::try_from(len).unwrap().to_ne_bytes());
        m.extend_from_slice(&kind.to_ne_bytes());
        m.extend_from_slice(&[0; 10]);
        m.extend_from_slice(&[0; IFINFOMSG]);
        m.extend_from_slice(&mtu);
        m.extend_from_slice(&attr);
        m
    }

    #[test]
    fn names_of_new_and_removed_links() {
        let mut buf = msg(RTM_DELLINK, "ether4");
        buf.extend(msg(RTM_NEWLINK, "ether4"));
        buf.extend(msg(20, "10.0.0.1")); // RTM_NEWADDR: not a link
        buf.extend(msg(RTM_NEWLINK, "vlan100"));
        let mut out = BTreeSet::new();
        assert!(parse(&buf, &mut out));
        assert_eq!(out.into_iter().collect::<Vec<_>>(), ["ether4", "vlan100"]);
    }

    #[test]
    fn too_many_names_say_so() {
        let mut out: BTreeSet<String> = (0..MAX_NAMES).map(|i| format!("v{i}")).collect();
        assert!(parse(&msg(RTM_NEWLINK, "v1"), &mut out), "known name");
        assert!(!parse(&msg(RTM_NEWLINK, "ether1"), &mut out));
    }

    #[test]
    fn truncated_and_lying_lengths_are_skipped() {
        let m = msg(RTM_NEWLINK, "ether1");
        for cut in 0..m.len() {
            let mut out = BTreeSet::new();
            assert!(parse(m.get(..cut).unwrap(), &mut out));
            assert!(out.is_empty(), "cut at {cut}: {out:?}");
        }
        // Longer than IFNAMSIZ allows.
        let mut out = BTreeSet::new();
        assert!(parse(&msg(RTM_NEWLINK, "0123456789abcdef"), &mut out));
        assert!(out.is_empty());
    }

    proptest! {
        /// Hostile bytes never panic and never pass the cap.
        #[test]
        fn parse_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
            let mut out = BTreeSet::new();
            parse(&bytes, &mut out);
            prop_assert!(out.len() <= MAX_NAMES);
            prop_assert!(out.iter().all(|n| !n.is_empty() && n.len() < IFNAMSIZ));
        }
    }
}
