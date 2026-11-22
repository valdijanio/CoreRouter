//! G1.30m: small, synchronous link changes for the Wi-Fi radios' threads,
//! which are not in the async runtime of the configuration's apply
//! (`netlink.rs`): give a link a master (a bridge or a bond) or none, bring
//! it up, make a bridge or a veth pair, delete one. One `RTM_NEWLINK` or
//! `RTM_DELLINK` with an ack each.
//!
//! Used where links come and go on their own, outside a commit: a
//! station-bridge joins its bridge once its frames carry four addresses,
//! and a peer's link is made when the peer associates (`crate::wifi_ap`).

use std::io;

use netlink_sys::{Socket, SocketAddr as NlAddr, protocols::NETLINK_ROUTE};

const RTM_NEWLINK: u16 = 16;
const RTM_DELLINK: u16 = 17;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_ACK: u16 = 4;
const NLM_F_EXCL: u16 = 0x200;
const NLM_F_CREATE: u16 = 0x400;
const NLMSG_ERROR: u16 = 2;
const IFLA_IFNAME: u16 = 3;
const IFLA_MASTER: u16 = 10;
const IFLA_LINKINFO: u16 = 18;
const IFLA_INFO_KIND: u16 = 1;
const IFLA_INFO_DATA: u16 = 2;
/// `VETH_INFO_PEER` (`include/uapi/linux/veth.h`).
const VETH_INFO_PEER: u16 = 1;
/// `NLA_F_NESTED`.
const NESTED: u16 = 0x8000;
const IFF_UP: u32 = 1;
/// `IFNAMSIZ` − 1.
const MAX_NAME: usize = 15;

fn index(name: &str) -> io::Result<i32> {
    let i = nix::net::if_::if_nametoindex(name)
        .map_err(|e| io::Error::other(format!("{name}: {e}")))?;
    i32::try_from(i).map_err(|_| io::Error::other("ifindex out of range"))
}

fn checked(name: &str) -> io::Result<()> {
    if name.is_empty() || name.len() > MAX_NAME {
        return Err(io::Error::other("bad interface name"));
    }
    Ok(())
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

fn name_attr(out: &mut Vec<u8>, name: &str) {
    let mut n = name.as_bytes().to_vec();
    n.push(0);
    attr(out, IFLA_IFNAME, &n);
}

/// An `ifinfomsg` (16 bytes): family, type, index, flags, change.
fn ifinfo(index: i32, flags: u32, change: u32) -> Vec<u8> {
    let mut m = Vec::with_capacity(16);
    m.extend_from_slice(&[0, 0]); // ifi_family, pad
    m.extend_from_slice(&0u16.to_ne_bytes()); // ifi_type
    m.extend_from_slice(&index.to_ne_bytes());
    m.extend_from_slice(&flags.to_ne_bytes());
    m.extend_from_slice(&change.to_ne_bytes());
    m
}

/// One link request and its ack.
fn request(
    kind: u16,
    extra: u16,
    index: i32,
    flags: u32,
    change: u32,
    attrs: &[u8],
) -> io::Result<()> {
    let body = ifinfo(index, flags, change);
    let total = 16 + body.len() + attrs.len();
    let mut msg = Vec::with_capacity(total);
    msg.extend_from_slice(&u32::try_from(total).unwrap_or(0).to_ne_bytes());
    msg.extend_from_slice(&kind.to_ne_bytes());
    msg.extend_from_slice(&(NLM_F_REQUEST | NLM_F_ACK | extra).to_ne_bytes());
    msg.extend_from_slice(&1u32.to_ne_bytes()); // seq
    msg.extend_from_slice(&0u32.to_ne_bytes()); // pid
    msg.extend_from_slice(&body);
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

/// Bring `name` up.
pub(crate) fn up(name: &str) -> io::Result<()> {
    request(RTM_NEWLINK, 0, index(name)?, IFF_UP, IFF_UP, &[])
}

/// Give `name` the master `master` (a bridge or a bond), or none. A bond
/// takes a slave only while it is down: it goes down first and comes up
/// after. (Never call it with a bond on an AP_VLAN: down, it loses its
/// station, `net/mac80211/iface.c` `ieee80211_do_stop`.)
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
        request(RTM_NEWLINK, 0, i, 0, IFF_UP, &[])?;
    }
    let r = request(RTM_NEWLINK, 0, i, 0, 0, &a);
    if bond {
        request(RTM_NEWLINK, 0, i, IFF_UP, IFF_UP, &[])?;
    }
    r
}

/// A bridge `name`, up.
pub(crate) fn add_bridge(name: &str) -> io::Result<()> {
    checked(name)?;
    let mut info = Vec::new();
    attr(&mut info, IFLA_INFO_KIND, b"bridge");
    let mut a = Vec::new();
    name_attr(&mut a, name);
    attr(&mut a, IFLA_LINKINFO | NESTED, &info);
    request(
        RTM_NEWLINK,
        NLM_F_CREATE | NLM_F_EXCL,
        0,
        IFF_UP,
        IFF_UP,
        &a,
    )
}

/// A veth pair `name` ↔ `peer`, both down.
pub(crate) fn add_veth(name: &str, peer: &str) -> io::Result<()> {
    checked(name)?;
    checked(peer)?;
    let mut peer_msg = ifinfo(0, 0, 0);
    name_attr(&mut peer_msg, peer);
    let mut data = Vec::new();
    attr(&mut data, VETH_INFO_PEER | NESTED, &peer_msg);
    let mut info = Vec::new();
    attr(&mut info, IFLA_INFO_KIND, b"veth");
    attr(&mut info, IFLA_INFO_DATA | NESTED, &data);
    let mut a = Vec::new();
    name_attr(&mut a, name);
    attr(&mut a, IFLA_LINKINFO | NESTED, &info);
    request(RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL, 0, 0, 0, &a)
}

/// Delete link `name` (a bridge or a veth this made; a wireless netdev is
/// not deleted this way: cfg80211 registers no `rtnl_link_ops`).
pub(crate) fn delete(name: &str) -> io::Result<()> {
    request(RTM_DELLINK, 0, index(name)?, 0, 0, &[])
}

/// G1.30m: a bond with `name` (a Wi-Fi backhaul link) among its slaves
/// takes frames on every slave, active or not (`all_slaves_active`). Over
/// a point-to-point link each end picks its active slave on its own: in
/// active-backup one end sent on the first link while the other listened
/// on the second, and the bond dropped what came on the backup (measured
/// in the lab). Not for Ethernet bonds, where a switch floods to every
/// port and the backups would deliver duplicates.
pub(crate) fn bond_takes_all(name: &str) {
    let Some(master) = master_of(name) else {
        return;
    };
    let knob = std::path::Path::new("/sys/class/net")
        .join(&master)
        .join("bonding")
        .join("all_slaves_active");
    if std::fs::read_to_string(&knob).is_ok_and(|v| v.trim() == "0")
        && let Err(e) = std::fs::write(&knob, "1")
    {
        log::warn!("bond {master} of {name}: all_slaves_active: {e}");
    }
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
        name_attr(&mut a, "peer1");
        assert_eq!(a.len(), 12);
        assert_eq!(a.get(0..2), Some(&10u16.to_ne_bytes()[..]));
        assert_eq!(ifinfo(7, 1, 1).len(), 16);
        assert!(add_bridge("").is_err());
        assert!(add_veth("peer1", "a-name-too-long-x").is_err());
    }
}
