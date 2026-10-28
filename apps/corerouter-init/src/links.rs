//! The links as the kernel has them (G1.6m): the physical Ethernet ports
//! from `/sys/class/net`, and `RTM_NEWLINK` to bring a link up or down and
//! rename it, so the image needs no `ip` binary. Used by PID 1 (port names,
//! `lo`) and the installer (its port list).

use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::ports::{self, Found};

const SYS_NET: &str = "/sys/class/net";
const IFF_UP: u32 = 1;

fn read(path: &Path) -> String {
    fs::read_to_string(path)
        .map(|s| s.trim().to_owned())
        .unwrap_or_default()
}

fn names() -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir(SYS_NET)
        .map(|d| {
            d.flatten()
                .filter_map(|e| e.file_name().into_string().ok())
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

/// Waits until the set of links stops changing for `quiet` (drivers that
/// probe late, like `ice` loading its firmware), at most `max`.
pub fn settle(quiet: Duration, max: Duration) {
    let start = Instant::now();
    let mut last = names();
    let mut since = Instant::now();
    while start.elapsed() < max {
        std::thread::sleep(Duration::from_millis(50));
        let now = names();
        if now != last {
            last = now;
            since = Instant::now();
        } else if since.elapsed() >= quiet {
            return;
        }
    }
}

/// A physical Ethernet port (`type` 1, a `device` behind it).
fn port(name: &str) -> Option<Found> {
    let dir = Path::new(SYS_NET).join(name);
    if read(&dir.join("type")) != "1" {
        return None;
    }
    let dev = fs::canonicalize(dir.join("device")).ok()?;
    Some(Found {
        kernel: name.to_owned(),
        mac: read(&dir.join("address")).to_ascii_lowercase(),
        path: dev.to_string_lossy().chars().take(256).collect(),
        dev_port: read(&dir.join("dev_port")).parse().unwrap_or(0),
    })
}

/// The ports the kernel named (`eth<N>`): the ones PID 1 renames.
pub fn kernel_named_ports() -> Vec<Found> {
    names()
        .iter()
        .filter(|n| ports::is_kernel_name(n))
        .filter_map(|n| port(n))
        .collect()
}

/// Every physical Ethernet port, in bus order, with its carrier: what the
/// installer lists.
pub fn ports_with_link() -> Vec<(Found, bool)> {
    let mut v: Vec<Found> = names().iter().filter_map(|n| port(n)).collect();
    ports::bus_order(&mut v);
    v.into_iter()
        .map(|f| {
            let up = read(&Path::new(SYS_NET).join(&f.kernel).join("carrier")) == "1";
            (f, up)
        })
        .collect()
}

fn index(name: &str) -> Option<i32> {
    read(&Path::new(SYS_NET).join(name).join("ifindex"))
        .parse()
        .ok()
}

fn is_up(name: &str) -> bool {
    let f = read(&Path::new(SYS_NET).join(name).join("flags"));
    u32::from_str_radix(f.trim_start_matches("0x"), 16).is_ok_and(|f| f & IFF_UP != 0)
}

/// One `RTM_NEWLINK` on link `index`: `flags` under `change`, and a new
/// name when given. Waits for the kernel's ack.
pub fn setlink(index: i32, flags: u32, change: u32, name: Option<&str>) -> std::io::Result<()> {
    use netlink_sys::{Socket, SocketAddr as NlAddr, protocols::NETLINK_ROUTE};
    const RTM_NEWLINK: u16 = 16;
    const NLM_F_REQUEST: u16 = 1;
    const NLM_F_ACK: u16 = 4;
    const NLMSG_ERROR: u16 = 2;
    const IFLA_IFNAME: u16 = 3;
    let mut attr = Vec::new();
    if let Some(n) = name {
        if n.is_empty() || n.len() > 15 {
            return Err(std::io::Error::other("bad interface name"));
        }
        let len = 4 + n.len() + 1;
        attr.extend_from_slice(&u16::try_from(len).unwrap_or(0).to_ne_bytes());
        attr.extend_from_slice(&IFLA_IFNAME.to_ne_bytes());
        attr.extend_from_slice(n.as_bytes());
        attr.push(0);
        while attr.len() % 4 != 0 {
            attr.push(0);
        }
    }
    let total = 32 + attr.len();
    let mut msg = Vec::with_capacity(total);
    msg.extend_from_slice(&u32::try_from(total).unwrap_or(0).to_ne_bytes()); // nlmsg_len
    msg.extend_from_slice(&RTM_NEWLINK.to_ne_bytes());
    msg.extend_from_slice(&(NLM_F_REQUEST | NLM_F_ACK).to_ne_bytes());
    msg.extend_from_slice(&1u32.to_ne_bytes()); // seq
    msg.extend_from_slice(&0u32.to_ne_bytes()); // pid
    msg.extend_from_slice(&[0, 0]); // ifi_family, pad
    msg.extend_from_slice(&0u16.to_ne_bytes()); // ifi_type
    msg.extend_from_slice(&index.to_ne_bytes()); // ifi_index
    msg.extend_from_slice(&flags.to_ne_bytes()); // ifi_flags
    msg.extend_from_slice(&change.to_ne_bytes()); // ifi_change
    msg.extend_from_slice(&attr);
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
        (Some(NLMSG_ERROR), Some(e)) => Err(std::io::Error::from_raw_os_error(-e)),
        _ => Err(std::io::Error::other("unexpected netlink reply")),
    }
}

/// `ip link set lo up` (ifindex 1 is always `lo` in the initial namespace).
pub fn loopback_up() -> std::io::Result<()> {
    setlink(1, IFF_UP, IFF_UP, None)
}

/// Renames `from` to `to`. The kernel refuses to rename a link that is up
/// (a port the kernel's `ip=` configured): it goes down for the rename and
/// up again (its IPv4 addresses stay; routes through it are dropped).
pub fn rename(from: &str, to: &str) -> std::io::Result<()> {
    let i = index(from).ok_or_else(|| std::io::Error::other("no such link"))?;
    let up = is_up(from);
    if up {
        setlink(i, 0, IFF_UP, None)?;
    }
    let r = setlink(i, 0, 0, Some(to));
    if up {
        setlink(i, IFF_UP, IFF_UP, None)?;
    }
    r
}
