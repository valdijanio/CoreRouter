//! G4.1zo: which UDP socket of a family gets a datagram. The forwarder
//! binds [`SOCKETS`] sockets per family to port 53 with `SO_REUSEPORT` and
//! attaches this classic BPF program to the group
//! (`SO_ATTACH_REUSEPORT_CBPF`, Linux 4.5): it picks the socket by a hash
//! of the source address (IPv4 whole, IPv6 by its /64, like the per-client
//! limit), so every datagram of one client lands in the same socket
//! whatever its source port.
//!
//! What it buys: one socket, as before, is one receive queue for every
//! client. A flood from one address filled it, and the kernel dropped the
//! other clients' queries with the junk (**medido** in the VM, one reader:
//! 65 % of a legitimate client lost under 1 M junk messages a second from
//! one address, with the default limit of 200 a second). Now the flood
//! fills only its own socket's queue and keeps that socket's readers busy;
//! the other sockets, their readers and the clients that hash to them do
//! not see it.
//! The clients that share the flood's socket (a quarter of them) still
//! share its queue: the per-client limit, applied before the parse, drops
//! the flood there at the cost of a table lookup.
//!
//! Each socket keeps the readers the one socket had (`udp_threads`): a
//! single busy client (a resolver or a CGNAT box sending all its
//! subscribers' queries from one address) still has all of them. With one
//! reader per socket it had one: in the VM, one source at saturation fell
//! from 155 000 to 78 000 cache hits a second; with the readers kept,
//! 136 000 (**medido**, within the VM's ±30 % from run to run).
//!
//! The kernel numbers the sockets of a group in the order they were bound
//! (socket(7): an index past the group falls back to the plain hash of the
//! four-tuple, it is not dropped).

/// Sockets per family.
pub(crate) const SOCKETS: u32 = 4;

/// One classic BPF instruction (`struct sock_filter`): code, jt, jf, k.
pub(crate) type Insn = (u16, u8, u8, u32);

// linux/filter.h (classic BPF), the codes this program uses.
const LD_W_ABS: u16 = 0x00 | 0x00 | 0x20; // BPF_LD | BPF_W | BPF_ABS
const TAX: u16 = 0x07; // BPF_MISC | BPF_TAX
const XOR_X: u16 = 0x04 | 0xa0 | 0x08; // BPF_ALU | BPF_XOR | BPF_X
const MUL_K: u16 = 0x04 | 0x20; // BPF_ALU | BPF_MUL | BPF_K
const RSH_K: u16 = 0x04 | 0x70; // BPF_ALU | BPF_RSH | BPF_K
const MOD_K: u16 = 0x04 | 0x90; // BPF_ALU | BPF_MOD | BPF_K
const RET_A: u16 = 0x06 | 0x10; // BPF_RET | BPF_A
/// `SKF_NET_OFF`: loads relative to the network header (the program runs
/// with the packet's data at the UDP payload).
const NET: u32 = 0xfff0_0000;
/// Knuth's multiplicative hash: the high bits mix every bit of the source.
const GOLDEN: u32 = 0x9e37_79b1;

/// The program for `sockets` sockets of the IPv4 (`v6` false) or the IPv6
/// family: source address (or its /64) → hash → index.
pub(crate) fn program(v6: bool, sockets: u32) -> Vec<Insn> {
    let mut p = if v6 {
        // The source is bytes 8..24 of the IPv6 header: the /64 is the
        // first two words.
        vec![(LD_W_ABS, 0, 0, NET + 8), (TAX, 0, 0, 0), (LD_W_ABS, 0, 0, NET + 12), (XOR_X, 0, 0, 0)]
    } else {
        // Bytes 12..16 of the IPv4 header.
        vec![(LD_W_ABS, 0, 0, NET + 12)]
    };
    p.extend([
        (MUL_K, 0, 0, GOLDEN),
        (RSH_K, 0, 0, 16),
        (MOD_K, 0, 0, sockets.max(1)),
        (RET_A, 0, 0, 0),
    ]);
    p
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    /// Runs `p` on a network header (only what [`program`] uses).
    fn run(p: &[Insn], header: &[u8]) -> u32 {
        let (mut a, mut x) = (0u32, 0u32);
        for &(code, _, _, k) in p {
            match code {
                LD_W_ABS => {
                    let at = (k - NET) as usize;
                    a = u32::from_be_bytes(header[at..at + 4].try_into().unwrap());
                }
                TAX => x = a,
                XOR_X => a ^= x,
                MUL_K => a = a.wrapping_mul(k),
                RSH_K => a >>= k,
                MOD_K => a %= k,
                RET_A => return a,
                other => panic!("code {other:#x}"),
            }
        }
        panic!("no return")
    }

    fn v4(src: Ipv4Addr) -> Vec<u8> {
        let mut h = vec![0u8; 20];
        h[12..16].copy_from_slice(&src.octets());
        h
    }

    fn v6(src: Ipv6Addr) -> Vec<u8> {
        let mut h = vec![0u8; 40];
        h[8..24].copy_from_slice(&src.octets());
        h
    }

    #[test]
    fn a_lan_spreads_over_every_socket() {
        let p = program(false, SOCKETS);
        let mut per = [0u32; SOCKETS as usize];
        for i in 1..=254u8 {
            let s = run(&p, &v4(Ipv4Addr::new(192, 168, 88, i)));
            per[s as usize] += 1;
        }
        // 254 hosts of a /24: none of the four gets less than half its share.
        assert!(per.iter().all(|n| *n >= 254 / 4 / 2), "{per:?}");
    }

    #[test]
    fn ipv6_hashes_the_64_only() {
        let p = program(true, SOCKETS);
        let a = run(&p, &v6("2001:db8:1:2::1".parse().unwrap()));
        // Another host of the same /64 (a client rotating its address).
        assert_eq!(a, run(&p, &v6("2001:db8:1:2:aaaa:bbbb:cccc:dddd".parse().unwrap())));
        let mut per = [0u32; SOCKETS as usize];
        for i in 0..256u16 {
            per[run(&p, &v6(Ipv6Addr::new(0x2001, 0xdb8, 0x10, i, 0, 0, 0, 1))) as usize] += 1;
        }
        assert!(per.iter().all(|n| *n >= 256 / 4 / 2), "{per:?}");
    }

    #[test]
    fn the_index_is_always_inside_the_group() {
        for n in [1, 2, 3, 4, 7] {
            let p = program(false, n);
            for i in 0..1000u32 {
                assert!(run(&p, &v4(Ipv4Addr::from(i.wrapping_mul(2_654_435_761)))) < n);
            }
        }
        assert_eq!(program(false, 0).get(3).map(|i| i.3), Some(1), "never a division by 0");
    }
}
