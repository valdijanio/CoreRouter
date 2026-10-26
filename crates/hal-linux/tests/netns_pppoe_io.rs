//! G4.3l: the PPPoE access port's sockets (`pppoe_io::PppoePort`) against
//! a real kernel, inside a throwaway network namespace — no root:
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-hal-linux --test netns_pppoe_io
//! ```
//!
//! One end of a veth sends PPPoE untagged, in one 802.1Q tag and in two
//! tags (802.1ad or 802.1Q outer); the other end's sockets must hand each
//! frame to the BNG exactly once, with its tags back in the frame, and
//! nothing else. Before G4.3l a frame of VLAN 100 reached the untagged
//! socket as untagged and the VLAN socket not at all (sockets bound to
//! 0x8863 get the frame after the kernel cleared its tag).
//!
//! Helpers outside `#[test]` fns may unwrap/panic too.
#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::process::Command;
use std::time::{Duration, Instant};

use corerouter_hal_linux::pppoe_io::{Listen, PppoePort};
use corerouter_model::IfName;

const ENV: &str = "COREROUTER_NETNS_TESTS";

fn in_netns() -> bool {
    if std::env::var_os(ENV).is_none_or(|v| v != "1") {
        eprintln!(
            "skipped: set {ENV}=1 and run inside `unshare --user --map-root-user --net` (cargo xtask netns)"
        );
        return false;
    }
    let out = Command::new("ip")
        .args(["-o", "link", "show"])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let names: Vec<&str> = text
        .lines()
        .filter_map(|l| l.split(':').nth(1))
        .map(str::trim)
        .collect();
    assert!(
        names.iter().all(|n| *n == "lo" || n.starts_with("pio")),
        "{ENV}=1 but this namespace has {names:?}; refusing to touch it"
    );
    true
}

fn ip(args: &[&str]) {
    let out = Command::new("ip").args(args).output().unwrap();
    assert!(
        out.status.success(),
        "ip {}: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr)
    );
}

fn n(s: &str) -> IfName {
    s.parse().unwrap()
}

const CPE: [u8; 6] = [0x02, 0x33, 0, 0, 0, 1];

/// dst, src, then the tags (TPID, TCI) and the EtherType, a PPPoE header
/// and some payload.
fn frame(dst: [u8; 6], tags: &[(u16, u16)], ethertype: u16) -> Vec<u8> {
    let mut f = dst.to_vec();
    f.extend_from_slice(&CPE);
    for (tpid, tci) in tags {
        f.extend_from_slice(&tpid.to_be_bytes());
        f.extend_from_slice(&tci.to_be_bytes());
    }
    f.extend_from_slice(&ethertype.to_be_bytes());
    f.extend_from_slice(&[0x11, 0x09, 0, 0, 0, 4, 1, 1, 0, 0]);
    f.resize(f.len().max(64), 0);
    f
}

/// Everything `port` reads within `ms`.
fn drain(port: &mut PppoePort, ms: u64) -> Vec<Vec<u8>> {
    let mut got = Vec::new();
    let deadline = Instant::now() + Duration::from_millis(ms);
    while Instant::now() < deadline {
        port.recv(|f| got.push(f.to_vec())).unwrap();
        std::thread::sleep(Duration::from_millis(5));
    }
    got
}

#[test]
fn every_tagging_reaches_its_socket_once_with_its_tags() {
    if !in_netns() {
        return;
    }
    ip(&["link", "set", "lo", "up"]);
    ip(&[
        "link", "add", "pioa", "type", "veth", "peer", "name", "piob",
    ]);
    ip(&["link", "set", "pioa", "up"]);
    ip(&["link", "set", "piob", "up"]);
    let cpe = PppoePort::open(&n("pioa"), &[], true).unwrap();
    let mut bng = PppoePort::open_for(
        &n("piob"),
        &[
            Listen::Untagged,
            Listen::Vlan(100),
            Listen::Stacked {
                outer: 200,
                tpid: 0x88a8,
            },
            Listen::Stacked {
                outer: 300,
                tpid: 0x8100,
            },
        ],
    )
    .unwrap();
    let bng_mac = bng.mac();
    let bcast = [0xff; 6];
    // (frame sent, frame the BNG must read; None: dropped)
    let pcp = 5 << 13;
    let cases: Vec<(Vec<u8>, Option<Vec<u8>>)> = vec![
        // Untagged Discovery and Session.
        (frame(bcast, &[], 0x8863), Some(frame(bcast, &[], 0x8863))),
        (
            frame(bng_mac, &[], 0x8864),
            Some(frame(bng_mac, &[], 0x8864)),
        ),
        // One 802.1Q tag; the PCP bits are not kept.
        (
            frame(bcast, &[(0x8100, pcp | 100)], 0x8863),
            Some(frame(bcast, &[(0x8100, 100)], 0x8863)),
        ),
        (
            frame(bng_mac, &[(0x8100, 100)], 0x8864),
            Some(frame(bng_mac, &[(0x8100, 100)], 0x8864)),
        ),
        // A VLAN not listened to, and the right VID with the wrong TPID.
        (frame(bcast, &[(0x8100, 101)], 0x8863), None),
        (frame(bcast, &[(0x88a8, 100)], 0x8863), None),
        // QinQ: S-tag 802.1ad 200, C-tag 3044.
        (
            frame(bcast, &[(0x88a8, 200), (0x8100, 3044)], 0x8863),
            Some(frame(bcast, &[(0x88a8, 200), (0x8100, 3044)], 0x8863)),
        ),
        (
            frame(bng_mac, &[(0x88a8, 200), (0x8100, 1)], 0x8864),
            Some(frame(bng_mac, &[(0x88a8, 200), (0x8100, 1)], 0x8864)),
        ),
        // QinQ with an 802.1Q outer tag (older access gear).
        (
            frame(bcast, &[(0x8100, 300), (0x8100, 7)], 0x8863),
            Some(frame(bcast, &[(0x8100, 300), (0x8100, 7)], 0x8863)),
        ),
        // Outer 300 with the wrong TPID; outer 200 with one tag only.
        (frame(bcast, &[(0x88a8, 300), (0x8100, 7)], 0x8863), None),
        (frame(bcast, &[(0x88a8, 200)], 0x8863), None),
        // Not PPPoE.
        (frame(bcast, &[], 0x0800), None),
        (frame(bcast, &[(0x88a8, 200), (0x8100, 3044)], 0x0800), None),
    ];
    for (i, (sent, want)) in cases.iter().enumerate() {
        cpe.send(sent).unwrap();
        let got = drain(&mut bng, 150);
        match want {
            None => assert!(
                got.is_empty(),
                "case {i}: should be dropped, read {got:02x?}"
            ),
            Some(w) => assert_eq!(
                got,
                vec![w.clone()],
                "case {i}: once, tags back in the frame"
            ),
        }
    }
}
