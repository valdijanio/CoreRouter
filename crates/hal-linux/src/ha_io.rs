//! The access-side hello of BNG redundancy (G4.3h): `AF_PACKET` sockets
//! for EtherType 0x88b5 on the access ports. Bytes only: the hello itself
//! (HMAC, roles) is `proto-ha`'s, glued by the daemon.
//!
//! The group address 03:43:52:48:41:00 is not in a NIC's multicast filter
//! and `PACKET_ADD_MEMBERSHIP` has no safe binding, so a port turns
//! `allmulticast` on while open (only if it was off), as LLDP does. And the
//! subscribers send to the pair's **virtual MAC**, which is not the card's:
//! a port is also put in `promiscuous` mode while open (only if it was not;
//! a BNG's access port usually is). Our own transmissions come back as
//! `PACKET_OUTGOING` and are dropped. No `unsafe` (socket2, nix,
//! rtnetlink).

use std::io;
use std::os::fd::AsRawFd;

use corerouter_model::IfName;
use nix::ifaddrs::getifaddrs;
use nix::net::if_::InterfaceFlags;
use nix::sys::socket::{LinkAddr, MsgFlags, bind, recvfrom, send};
use socket2::{Domain, Protocol, Socket, Type};

use crate::l2::{if_info, io_err, set_allmulti};

pub const ETHERTYPE: u16 = 0x88b5;
pub const GROUP: [u8; 6] = [0x03, 0x43, 0x52, 0x48, 0x41, 0x00];
const PACKET_OUTGOING: u8 = 4;
const FRAME_MAX: usize = 1514;
/// Frames read per port per call (hellos are a few per second).
const RECV_BUDGET: usize = 32;

/// One access port.
pub struct HaPort {
    name: IfName,
    sock: Socket,
    ifindex: u32,
    mac: [u8; 6],
    allmulti_by_us: bool,
    promisc_by_us: bool,
}

impl HaPort {
    pub fn open(name: &IfName) -> io::Result<Self> {
        let info = if_info(name)?;
        let ifindex = u32::try_from(info.link.ifindex())
            .map_err(|_| io::Error::other(format!("{name}: interface index out of range")))?;
        let proto = Protocol::from(i32::from(ETHERTYPE.to_be()));
        let sock = Socket::new(Domain::PACKET, Type::RAW, Some(proto))?;
        sock.set_nonblocking(true)?;
        bind(sock.as_raw_fd(), &info.link).map_err(io_err)?;
        let allmulti_by_us = !info.allmulti;
        if allmulti_by_us {
            set_allmulti(ifindex, true)?;
        }
        let promisc_by_us = !flags(name).contains(InterfaceFlags::IFF_PROMISC);
        if promisc_by_us {
            set_promisc(ifindex, true)?;
        }
        Ok(Self {
            name: name.clone(),
            sock,
            ifindex,
            mac: info.mac,
            allmulti_by_us,
            promisc_by_us,
        })
    }

    pub fn name(&self) -> &IfName {
        &self.name
    }

    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }

    /// Sends `body` (what follows the EtherType) to the group, from `src`
    /// (the virtual MAC while active: the switches learn it on this port).
    pub fn send(&self, src: [u8; 6], body: &[u8]) -> io::Result<()> {
        let mut f = Vec::with_capacity(14 + body.len().max(46));
        f.extend_from_slice(&GROUP);
        f.extend_from_slice(&src);
        f.extend_from_slice(&ETHERTYPE.to_be_bytes());
        f.extend_from_slice(body);
        if f.len() < 60 {
            f.resize(60, 0);
        }
        send(self.sock.as_raw_fd(), &f, MsgFlags::empty()).map_err(io_err)?;
        Ok(())
    }

    /// The hello bodies waiting (to the group, not our own), non-blocking.
    pub fn recv(&self, mut f: impl FnMut(&[u8])) -> usize {
        let mut buf = [0u8; FRAME_MAX];
        let mut n = 0;
        for _ in 0..RECV_BUDGET {
            let (len, from) = match recvfrom::<LinkAddr>(self.sock.as_raw_fd(), &mut buf) {
                Ok(r) => r,
                Err(_) => break,
            };
            if from.is_some_and(|a| a.pkttype() == PACKET_OUTGOING) {
                continue;
            }
            let frame = buf.get(..len).unwrap_or(&[]);
            let Some((dst, rest)) = frame.split_first_chunk::<6>() else {
                continue;
            };
            let Some((_src, rest)) = rest.split_first_chunk::<6>() else {
                continue;
            };
            let Some((ty, body)) = rest.split_first_chunk::<2>() else {
                continue;
            };
            if *dst == GROUP && u16::from_be_bytes(*ty) == ETHERTYPE {
                f(body);
                n += 1;
            }
        }
        n
    }
}

impl Drop for HaPort {
    fn drop(&mut self) {
        if self.promisc_by_us
            && let Err(e) = set_promisc(self.ifindex, false)
        {
            log::warn!("ppp-ha: could not restore promiscuous off on {}: {e}", self.name);
        }
        if self.allmulti_by_us
            && let Err(e) = set_allmulti(self.ifindex, false)
        {
            log::warn!(
                "ppp-ha: could not restore allmulticast off on {}: {e}",
                self.name
            );
        }
    }
}

fn flags(name: &IfName) -> InterfaceFlags {
    getifaddrs()
        .ok()
        .and_then(|mut it| it.find(|a| a.interface_name == name.as_str()).map(|a| a.flags))
        .unwrap_or(InterfaceFlags::empty())
}

/// Turns `promiscuous` on or off on one interface over rtnetlink.
fn set_promisc(ifindex: u32, on: bool) -> io::Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()?;
    rt.block_on(async {
        let (conn, handle, _) = rtnetlink::new_connection()?;
        let task = tokio::spawn(conn);
        let out = handle
            .link()
            .set(rtnetlink::LinkUnspec::new_with_index(ifindex).promiscuous(on).build())
            .execute()
            .await
            .map_err(|e| io::Error::other(format!("promiscuous {on} on ifindex {ifindex}: {e}")));
        task.abort();
        out
    })
}

/// The interface is up and has carrier (`IFF_RUNNING`): the `track` list.
pub fn running(name: &IfName) -> bool {
    getifaddrs().is_ok_and(|mut it| {
        it.any(|a| {
            a.interface_name == name.as_str() && a.flags.contains(InterfaceFlags::IFF_RUNNING)
        })
    })
}
