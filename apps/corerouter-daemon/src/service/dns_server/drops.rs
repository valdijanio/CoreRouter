//! Datagrams the kernel dropped on the forwarder's UDP sockets (G4.1h):
//! the last column of `/proc/net/udp` and `/proc/net/udp6` (`sk_drops`,
//! net/ipv4/udp.c `udp4_format_sock`), for the sockets bound to the
//! forwarder's addresses. A queue that overflows is the first sign the
//! readers cannot keep up; read once a second by "dns-server".

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// The drops of the sockets bound to `at`, summed (0 where `/proc` is not).
pub(super) fn udp_drops(at: &[SocketAddr]) -> u64 {
    if at.is_empty() {
        return 0;
    }
    ["/proc/net/udp", "/proc/net/udp6"]
        .iter()
        .filter_map(|p| std::fs::read_to_string(p).ok())
        .map(|text| drops_in(&text, at))
        .sum()
}

/// The drops in one `/proc/net/udp*` table of the sockets bound to `at`.
pub(super) fn drops_in(table: &str, at: &[SocketAddr]) -> u64 {
    table
        .lines()
        .skip(1)
        .filter_map(|line| {
            let mut cols = line.split_whitespace();
            let local = parse_addr(cols.nth(1)?)?;
            let drops: u64 = cols.last()?.parse().ok()?;
            at.contains(&local).then_some(drops)
        })
        .sum()
}

/// `0100007F:0035` (IPv4) or 32 hex digits and a port (IPv6). The kernel
/// prints each 32-bit word of the address as a host-order integer, so its
/// bytes in memory order are the address's.
fn parse_addr(text: &str) -> Option<SocketAddr> {
    let (addr, port) = text.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let word = |i: usize| -> Option<[u8; 4]> {
        let w = u32::from_str_radix(addr.get(i * 8..i * 8 + 8)?, 16).ok()?;
        Some(w.to_ne_bytes())
    };
    let ip = match addr.len() {
        8 => IpAddr::V4(Ipv4Addr::from(word(0)?)),
        32 => {
            let mut b = [0u8; 16];
            for (i, chunk) in b.chunks_mut(4).enumerate() {
                chunk.copy_from_slice(&word(i)?);
            }
            IpAddr::V6(Ipv6Addr::from(b))
        }
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_endian = "little")]
    fn reads_the_drops_of_our_sockets_only() {
        // Two sockets on port 53 (ours on 127.0.0.1, systemd-resolved's on
        // 127.0.0.53) and one IPv6 on [::1]:53.
        let v4 = "   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n\
          12: 0100007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 4242 2 0000000000000000 17\n\
          13: 3500007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   991        0 4243 2 0000000000000000 900\n";
        let v6 = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n\
          40: 00000000000000000000000001000000:0035 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 4244 2 0000000000000000 5\n";
        let at: Vec<SocketAddr> = vec!["127.0.0.1:53".parse().unwrap(), "[::1]:53".parse().unwrap()];
        assert_eq!(drops_in(v4, &at), 17, "systemd-resolved's socket is not ours");
        assert_eq!(drops_in(v6, &at), 5);
        assert_eq!(drops_in("header\nbroken line\n", &at), 0);
        assert_eq!(udp_drops(&[]), 0);
    }

    #[test]
    fn this_hosts_table_parses() {
        // Whatever the host has, a socket of ours shows up with its drops.
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let at = vec![sock.local_addr().unwrap()];
        if std::path::Path::new("/proc/net/udp").exists() {
            let text = std::fs::read_to_string("/proc/net/udp").unwrap();
            assert!(text.lines().skip(1).any(|l| l.split_whitespace().nth(1).and_then(parse_addr) == at.first().copied()));
            assert_eq!(udp_drops(&at), 0);
        }
    }
}
