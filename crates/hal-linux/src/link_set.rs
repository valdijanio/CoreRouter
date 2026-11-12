//! G1.30m: small, synchronous link changes for the Wi-Fi radios' threads,
//! which are not in the async runtime of the configuration's apply
//! (`netlink.rs`): rename a link, give it a master (a bridge or a bond) or
//! none, give it a MAC. One `RTM_NEWLINK` with an ack each. (A wireless
//! netdev is deleted by nl80211, not here: cfg80211 registers no
//! `rtnl_link_ops`.)
//!
//! Used where a link comes and goes on its own, outside a commit: a
//! station-bridge joins its bridge once its frames carry four addresses,
//! and the four-address link of a peer (`<radio>.sta<aid>`, made by
//! hostapd) gets the peer's name and master when the peer associates.

use std::io;

use netlink_sys::{Socket, SocketAddr as NlAddr, protocols::NETLINK_ROUTE};

const RTM_NEWLINK: u16 = 16;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_ACK: u16 = 4;
const NLMSG_ERROR: u16 = 2;
const IFLA_IFNAME: u16 = 3;
const IFLA_MASTER: u16 = 10;
const IFF_UP: u32 = 1;
/// `IFNAMSIZ` − 1.
const MAX_NAME: usize = 15;

fn index(name: &str) -> io::Result<i32> {
    let i = nix::net::if_::if_nametoindex(name)
        .map_err(|e| io::Error::other(format!("{name}: {e}")))?;
    i32::try_from(i).map_err(|_| io::Error::other("ifindex out of range"))
}

fn attr(out: &mut Vec<u8>, kind: u16, value: &[u8]) {
    let len = 4 + value.len();
    out.extend_from_slice(&u16::try_from(len).unwrap_or(0).to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(value);
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
}

/// One link request and its ack.
fn request(kind: u16, index: i32, flags: u32, change: u32, attrs: &[u8]) -> io::Result<()> {
    let total = 32 + attrs.len();
    let mut msg = Vec::with_capacity(total);
    msg.extend_from_slice(&u32::try_from(total).unwrap_or(0).to_ne_bytes());
    msg.extend_from_slice(&kind.to_ne_bytes());
    msg.extend_from_slice(&(NLM_F_REQUEST | NLM_F_ACK).to_ne_bytes());
    msg.extend_from_slice(&1u32.to_ne_bytes()); // seq
    msg.extend_from_slice(&0u32.to_ne_bytes()); // pid
    msg.extend_from_slice(&[0, 0]); // ifi_family, pad
    msg.extend_from_slice(&0u16.to_ne_bytes()); // ifi_type
    msg.extend_from_slice(&index.to_ne_bytes());
    msg.extend_from_slice(&flags.to_ne_bytes());
    msg.extend_from_slice(&change.to_ne_bytes());
    msg.extend_from_slice(attrs);
    let mut sock = Socket::new(NETLINK_ROUTE)?;
    sock.bind_auto()?;
    sock.send_to(&msg, &NlAddr::new(0, 0), 0)?;
    let (reply, _) = sock.recv_from_full()?;
    let u16_at = |i: usize| {
        reply
            .get(i..i + 2)
            .and_then(|b| b.try_into().ok())
            .map(u16::from_ne_bytes)
    };
    let i32_at = |i: usize| {
        reply
            .get(i..i + 4)
            .and_then(|b| b.try_into().ok())
            .map(i32::from_ne_bytes)
    };
    match (u16_at(4), i32_at(16)) {
        (Some(NLMSG_ERROR), Some(0)) => Ok(()),
        (Some(NLMSG_ERROR), Some(e)) => Err(io::Error::from_raw_os_error(-e)),
        _ => Err(io::Error::other("unexpected netlink reply")),
    }
}

fn set_up(index: i32, up: bool) -> io::Result<()> {
    request(RTM_NEWLINK, index, if up { IFF_UP } else { 0 }, IFF_UP, &[])
}

/// Rename `from` to `to`: down, renamed, up again (the kernel refuses to
/// rename a link that is up).
pub(crate) fn rename(from: &str, to: &str) -> io::Result<()> {
    if to.is_empty() || to.len() > MAX_NAME {
        return Err(io::Error::other("bad interface name"));
    }
    let i = index(from)?;
    set_up(i, false)?;
    let mut name = to.as_bytes().to_vec();
    name.push(0);
    let mut a = Vec::new();
    attr(&mut a, IFLA_IFNAME, &name);
    let r = request(RTM_NEWLINK, i, 0, 0, &a);
    set_up(i, true)?;
    r
}

/// Give `name` the master `master` (a bridge or a bond), or none. A bond
/// takes a slave only while it is down: it goes down first and comes up
/// after.
pub(crate) fn set_master(name: &str, master: Option<&str>) -> io::Result<()> {
    let i = index(name)?;
    let m = match master {
        Some(m) => index(m)?,
        None => 0,
    };
    let mut a = Vec::new();
    attr(&mut a, IFLA_MASTER, &m.to_ne_bytes());
    let bond = master.is_some_and(|m| {
        std::path::Path::new("/sys/class/net")
            .join(m)
            .join("bonding")
            .exists()
    });
    if bond {
        set_up(i, false)?;
    }
    let r = request(RTM_NEWLINK, i, 0, 0, &a);
    if bond {
        set_up(i, true)?;
    }
    r
}

/// `IFLA_ADDRESS`.
const IFLA_ADDRESS: u16 = 1;

/// The MAC of `name` now (`/sys/class/net/<name>/address`).
pub(crate) fn mac_of(name: &str) -> Option<[u8; 6]> {
    let text = std::fs::read_to_string(
        std::path::Path::new("/sys/class/net")
            .join(name)
            .join("address"),
    )
    .ok()?;
    let mut out = [0u8; 6];
    let mut parts = text.trim().split(':');
    for b in &mut out {
        *b = u8::from_str_radix(parts.next()?, 16).ok()?;
    }
    parts.next().is_none().then_some(out)
}

/// Give `name` the MAC `mac`, leaving it down (mac80211 takes a new
/// address only on an interface that is down: `iface.c`,
/// `_ieee80211_change_mac`); whoever brings it up next (hostapd) does.
pub(crate) fn set_mac(name: &str, mac: [u8; 6]) -> io::Result<()> {
    let i = index(name)?;
    set_up(i, false)?;
    let mut a = Vec::new();
    attr(&mut a, IFLA_ADDRESS, &mac);
    request(RTM_NEWLINK, i, 0, 0, &a)
}

/// The master of `name` now, by name; `None`: none (or no such link).
pub(crate) fn master_of(name: &str) -> Option<String> {
    let p = std::path::Path::new("/sys/class/net")
        .join(name)
        .join("master");
    std::fs::read_link(p)
        .ok()
        .and_then(|t| t.file_name().map(|f| f.to_string_lossy().into_owned()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attributes_are_padded_and_names_checked() {
        let mut a = Vec::new();
        attr(&mut a, IFLA_IFNAME, b"peer1\0");
        assert_eq!(a.len(), 12);
        assert_eq!(a.get(0..2), Some(&10u16.to_ne_bytes()[..]));
        assert!(rename("x", "").is_err());
        assert!(rename("x", "a-name-too-long-x").is_err());
    }
}
