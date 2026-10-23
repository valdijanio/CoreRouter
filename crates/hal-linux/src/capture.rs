//! Packet capture for Torch and the sniffer (G6.4a) over `AF_PACKET`.
//!
//! One `SOCK_RAW` / `ETH_P_ALL` socket per device (the interface, and its
//! VLAN interfaces when Torch groups by VLAN), each bound to its device
//! with the address `getifaddrs` reports (`l2::if_info`), so the kernel
//! hands it only that device's frames, both directions (`PACKET_OUTGOING`
//! marks the ones the host sent).
//!
//! A classic BPF filter on each socket does the work that must not reach
//! user space (`Documentation/networking/filter.rst`):
//! - sampling: `ld rand; mod #N; jeq #0` keeps one frame in N, chosen at
//!   random by the kernel (`SKF_AD_RANDOM`), so above ~500 kpps most frames
//!   are never copied. Changing the rate swaps the filter
//!   (`SO_ATTACH_FILTER` replaces it atomically).
//! - VLANs: when the VLAN interfaces are captured too, the parent drops
//!   its tagged frames (`SKF_AD_VLAN_TAG_PRESENT` for a tag the NIC
//!   stripped, the EtherType for one still in the frame): each is counted
//!   once, on its VLAN device, which says which VLAN it is. Reading the
//!   stripped tag needs `PACKET_AUXDATA`, a socket option no safe API
//!   offers (`unsafe` is not allowed here).
//!
//! The filter keeps the whole frame: truncating it there would also cut
//! the length `MSG_TRUNC` reports. The copy is cut by the receive buffer
//! (`snaplen`), and `MSG_TRUNC` gives the length on the wire.
//!
//! Not `TPACKET_V3`: its ring is shared memory, which needs `mmap` and
//! `unsafe`; the place for a faster path is XDP (G2.5), behind the same
//! `PacketCapture` trait.

use std::io::{self, IoSliceMut};
use std::os::fd::{AsFd, AsRawFd};
use std::time::{Duration, Instant};

use corerouter_hal::capture::{
    CaptureError, CaptureSocket, CaptureSpec, Dir, FrameBatch, LinkTotals, MAX_DEVICES,
    MAX_SNAPLEN, PacketCapture,
};
use corerouter_model::IfName;
use nix::errno::Errno;
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::sys::socket::{LinkAddr, MsgFlags, bind, recvmsg};
use socket2::{Domain, Protocol, SockFilter, Socket, Type};

/// `ETH_P_ALL`: every protocol.
const ETH_P_ALL: u16 = 0x0003;
/// `PACKET_OUTGOING`: a frame this host sent.
const PACKET_OUTGOING: u8 = 4;
/// Receive buffer asked for (the kernel caps it at `rmem_max`).
const RCVBUF: usize = 8 << 20;
/// Frames dropped right after opening (queued before the filter).
const DRAIN: usize = 4096;
/// What the filter accepts: the whole frame.
const ACCEPT_ALL: u32 = 0x0004_0000;

// Classic BPF (linux/filter.h).
const LD_W_ABS: u16 = 0x20;
const LD_H_ABS: u16 = 0x28;
const JEQ_K: u16 = 0x15;
const RET_K: u16 = 0x06;
const ALU_MOD_K: u16 = 0x94;
/// `SKF_AD_OFF` (-0x1000) and the ancillary loads used here.
const SKF_AD_OFF: u32 = 0xFFFF_F000;
const SKF_AD_VLAN_TAG_PRESENT: u32 = 48;
const SKF_AD_RANDOM: u32 = 56;

/// One classic BPF instruction: code, jt, jf, k.
pub(crate) type Ins = (u16, u8, u8, u32);

/// The program of one socket: drop tagged frames (`drop_tagged`, on a
/// parent whose VLANs are captured on their own devices), then keep one in
/// `sample`. The last two instructions are "accept" and "drop".
pub(crate) fn program(drop_tagged: bool, sample: u32) -> Vec<Ins> {
    // (code, k, jump): `Some(true)` drops on a match, `Some(false)` drops
    // on a mismatch, `None` is not a jump.
    let mut body: Vec<(u16, u32, Option<bool>)> = Vec::new();
    if drop_tagged {
        body.push((LD_W_ABS, SKF_AD_OFF + SKF_AD_VLAN_TAG_PRESENT, None));
        body.push((JEQ_K, 1, Some(true)));
        body.push((LD_H_ABS, 12, None));
        for ethertype in [0x8100u32, 0x88A8, 0x9100] {
            body.push((JEQ_K, ethertype, Some(true)));
        }
    }
    if sample > 1 {
        body.push((LD_W_ABS, SKF_AD_OFF + SKF_AD_RANDOM, None));
        body.push((ALU_MOD_K, sample, None));
        body.push((JEQ_K, 0, Some(false)));
    }
    let n = body.len();
    let mut out: Vec<Ins> = body
        .into_iter()
        .enumerate()
        .map(|(i, (code, k, jump))| {
            // Offsets count from the next instruction: accept is at n,
            // drop at n + 1. At most 6 + 3 instructions: they fit a u8.
            let to_accept = u8::try_from(n - i - 1).unwrap_or(u8::MAX);
            let to_drop = u8::try_from(n - i).unwrap_or(u8::MAX);
            match jump {
                Some(true) => (code, to_drop, 0, k),
                Some(false) => (code, to_accept, to_drop, k),
                None => (code, 0, 0, k),
            }
        })
        .collect();
    out.push((RET_K, 0, 0, ACCEPT_ALL));
    out.push((RET_K, 0, 0, 0));
    out
}

pub(crate) fn filter(drop_tagged: bool, sample: u32) -> Vec<SockFilter> {
    program(drop_tagged, sample)
        .into_iter()
        .map(|(code, jt, jf, k)| SockFilter::new(code, jt, jf, k))
        .collect()
}

/// Run `program` on a frame the way the kernel would, with the ancillary
/// values given (tests only: the kernel is the real interpreter).
#[cfg(test)]
fn run(p: &[Ins], frame: &[u8], tag_present: bool, random: u32) -> u32 {
    let mut a = 0u32;
    let mut pc = 0usize;
    while let Some(&(code, jt, jf, k)) = p.get(pc) {
        pc += 1;
        match code {
            LD_W_ABS if k == SKF_AD_OFF + SKF_AD_VLAN_TAG_PRESENT => a = u32::from(tag_present),
            LD_W_ABS if k == SKF_AD_OFF + SKF_AD_RANDOM => a = random,
            LD_H_ABS => {
                let at = k as usize;
                a = u32::from(u16::from_be_bytes([frame[at], frame[at + 1]]));
            }
            ALU_MOD_K => a %= k,
            JEQ_K => pc += usize::from(if a == k { jt } else { jf }),
            RET_K => return k,
            other => panic!("opcode {other:#x}"),
        }
    }
    panic!("fell off the end")
}

fn io_err(e: Errno) -> io::Error {
    io::Error::from_raw_os_error(e as i32)
}

fn unavailable(what: &str, e: &io::Error) -> CaptureError {
    match e.raw_os_error() {
        Some(1 | 13) => CaptureError::Unavailable(format!(
            "{what}: permission denied (capturing needs CAP_NET_RAW)"
        )),
        _ => CaptureError::Io(format!("{what}: {e}")),
    }
}

/// Capture on the host kernel's interfaces.
#[derive(Debug, Clone, Default)]
pub struct HostCapture;

struct Side {
    sock: Socket,
    vlan: Option<u16>,
    /// A parent whose VLANs have sockets of their own.
    drop_tagged: bool,
}

pub struct HostSocket {
    sides: Vec<Side>,
    /// The first device, for its counters.
    name: String,
    opened: Instant,
    buf: Vec<u8>,
    /// Socket to read first, so a busy one does not starve the others.
    next: usize,
}

impl PacketCapture for HostCapture {
    fn describe(&self) -> String {
        "AF_PACKET (sampling in a kernel BPF filter)".into()
    }

    fn open(&self, spec: &CaptureSpec) -> Result<Box<dyn CaptureSocket>, CaptureError> {
        let Some(first) = spec.devices.first() else {
            return Err(CaptureError::NoDevice("no interface to capture".into()));
        };
        if spec.devices.len() > MAX_DEVICES {
            return Err(CaptureError::Io(format!(
                "at most {MAX_DEVICES} interfaces in one capture"
            )));
        }
        let has_vlans = spec.devices.iter().any(|d| d.vlan.is_some());
        let mut sides = Vec::with_capacity(spec.devices.len());
        for (i, dev) in spec.devices.iter().enumerate() {
            let name = dev
                .name
                .parse::<IfName>()
                .map_err(|e| CaptureError::NoDevice(format!("'{}': {e}", dev.name)))?;
            let info = crate::l2::if_info(&name).map_err(|_| {
                CaptureError::NoDevice(format!("no interface '{name}' in the kernel"))
            })?;
            let drop_tagged = i == 0 && has_vlans && dev.vlan.is_none();
            let sock = open_bound(&info.link, drop_tagged, spec.sample.max(1))
                .map_err(|e| unavailable(&format!("capturing on {name}"), &e))?;
            sides.push(Side {
                sock,
                vlan: dev.vlan,
                drop_tagged,
            });
        }
        Ok(Box::new(HostSocket {
            sides,
            name: first.name.clone(),
            opened: Instant::now(),
            buf: vec![0u8; usize::from(spec.snaplen.clamp(14, MAX_SNAPLEN))],
            next: 0,
        }))
    }
}

fn open_bound(link: &LinkAddr, drop_tagged: bool, sample: u32) -> io::Result<Socket> {
    let proto = Protocol::from(i32::from(ETH_P_ALL.to_be()));
    let sock = Socket::new(Domain::PACKET, Type::RAW, Some(proto))?;
    sock.set_nonblocking(true)?;
    // Best effort: the kernel caps it at net.core.rmem_max.
    let _ = sock.set_recv_buffer_size(RCVBUF);
    sock.attach_filter(&filter(drop_tagged, sample))?;
    bind(sock.as_raw_fd(), link).map_err(io_err)?;
    // Frames that arrived before the bind and the filter: drop them.
    let mut buf = [0u8; 64];
    for _ in 0..DRAIN {
        let mut iov = [IoSliceMut::new(&mut buf)];
        if recvmsg::<LinkAddr>(sock.as_raw_fd(), &mut iov, None, MsgFlags::MSG_DONTWAIT).is_err() {
            break;
        }
    }
    Ok(sock)
}

impl HostSocket {
    /// Read what one socket has queued, without waiting.
    fn drain(&mut self, i: usize, batch: &mut FrameBatch) -> Result<(), CaptureError> {
        let Some(side) = self.sides.get(i) else {
            return Ok(());
        };
        let fd = side.sock.as_raw_fd();
        let vlan = side.vlan;
        while !batch.is_full() {
            let mut iov = [IoSliceMut::new(&mut self.buf)];
            let msg = match recvmsg::<LinkAddr>(
                fd,
                &mut iov,
                None,
                MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_TRUNC,
            ) {
                Ok(m) => m,
                Err(Errno::EAGAIN | Errno::EINTR) => return Ok(()),
                Err(e) => return Err(CaptureError::Io(format!("reading frames: {e}"))),
            };
            // MSG_TRUNC: the frame's whole length, not what was copied.
            let wire = msg.bytes;
            let dir = match msg.address.map(|a| a.pkttype()) {
                Some(PACKET_OUTGOING) => Dir::Tx,
                _ => Dir::Rx,
            };
            let kept = wire.min(self.buf.len());
            let at = self.opened.elapsed();
            batch.push(
                at,
                dir,
                vlan,
                u32::try_from(wire).unwrap_or(u32::MAX),
                self.buf.get(..kept).unwrap_or(&[]),
            );
        }
        Ok(())
    }
}

impl CaptureSocket for HostSocket {
    fn recv(&mut self, wait: Duration, batch: &mut FrameBatch) -> Result<(), CaptureError> {
        let n = self.sides.len();
        let first = self.next;
        self.next = (self.next + 1) % n.max(1);
        let read_all = |me: &mut Self, batch: &mut FrameBatch| -> Result<(), CaptureError> {
            for k in 0..n {
                me.drain((first + k) % n, batch)?;
            }
            Ok(())
        };
        read_all(self, batch)?;
        if !batch.is_empty() || wait.is_zero() {
            return Ok(());
        }
        let timeout = PollTimeout::try_from(wait).unwrap_or(PollTimeout::MAX);
        let mut fds: Vec<PollFd> = self
            .sides
            .iter()
            .map(|s| PollFd::new(s.sock.as_fd(), PollFlags::POLLIN))
            .collect();
        match poll(&mut fds, timeout) {
            Ok(0) | Err(Errno::EINTR) => return Ok(()),
            Ok(_) => {}
            Err(e) => return Err(CaptureError::Io(format!("poll: {e}"))),
        }
        drop(fds);
        read_all(self, batch)
    }

    fn set_sampling(&mut self, one_in: u32) -> Result<(), CaptureError> {
        for s in &self.sides {
            s.sock
                .attach_filter(&filter(s.drop_tagged, one_in.max(1)))
                .map_err(|e| CaptureError::Io(format!("changing the sampling: {e}")))?;
        }
        Ok(())
    }

    fn totals(&mut self) -> Option<LinkTotals> {
        let l = crate::netlink::link_detail(&self.name).ok()??.link;
        Some(LinkTotals {
            rx_packets: l.rx_packets,
            tx_packets: l.tx_packets,
            rx_bytes: l.rx_bytes,
            tx_bytes: l.tx_bytes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(ethertype: u16) -> Vec<u8> {
        let mut f = vec![0u8; 12];
        f.extend_from_slice(&ethertype.to_be_bytes());
        f
    }

    #[test]
    fn plain_filter_takes_everything() {
        let p = program(false, 1);
        assert_eq!(p.len(), 2);
        assert_eq!(run(&p, &frame(0x0800), true, 7), ACCEPT_ALL);
    }

    #[test]
    fn parent_drops_tagged_frames_either_way() {
        let p = program(true, 1);
        assert_eq!(run(&p, &frame(0x0800), false, 0), ACCEPT_ALL);
        assert_eq!(
            run(&p, &frame(0x0800), true, 0),
            0,
            "tag stripped by the NIC"
        );
        for t in [0x8100, 0x88A8, 0x9100] {
            assert_eq!(run(&p, &frame(t), false, 0), 0, "tag {t:#x} in the frame");
        }
    }

    #[test]
    fn sampling_keeps_one_in_n() {
        for drop_tagged in [false, true] {
            let p = program(drop_tagged, 8);
            let kept = (0..800u32)
                .filter(|r| run(&p, &frame(0x86DD), false, *r) != 0)
                .count();
            assert_eq!(kept, 100);
            assert_eq!(
                run(&p, &frame(0x8100), false, 0),
                u32::from(!drop_tagged) * ACCEPT_ALL
            );
        }
    }
}
