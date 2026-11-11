//! System › Tuning (G1.26) against a real kernel, inside a throwaway
//! network namespace — no root, nothing reaches the host:
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-hal-linux --test netns_tuning
//! ```
//!
//! A namespace has its own copy of the per-namespace parameters (ECMP
//! hash, rp_filter, forwarding, TCP of the control plane), which `apply`
//! writes and puts back; the host-wide ones (`netdev_budget`, neighbor
//! tables) are absent and the read-only ones (`rmem_max`, `kernel.panic`)
//! refuse, and either way the whole change is rolled back. Port settings
//! (G1.26b) run on a veth with four queues: its channels, `txqueuelen`,
//! root qdisc and `rp_filter` change and come back; rings and coalescing
//! are the "this NIC does not let" path. `netdevsim`
//! cannot help here: creating one needs root in the host's namespace.
//!
//! Helpers outside `#[test]` fns may unwrap/panic too.
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::process::Command;
use std::sync::{Mutex, OnceLock};

use corerouter_hal::Hal;
use corerouter_hal_linux::{LinuxHal, Policy};
use corerouter_model::Config;
use corerouter_model::tuning::PARAMS;

const ENV: &str = "COREROUTER_NETNS_TESTS";

/// The tests share the namespace: one at a time.
static SERIAL: Mutex<()> = Mutex::new(());

fn in_netns() -> bool {
    if std::env::var_os(ENV).is_none_or(|v| v != "1") {
        eprintln!(
            "skipped: set {ENV}=1 and run inside `unshare --user --map-root-user --net` \
             (cargo xtask netns)"
        );
        return false;
    }
    static FRESH: OnceLock<Result<(), String>> = OnceLock::new();
    let fresh = FRESH.get_or_init(|| {
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
        if names == ["lo"] {
            Ok(())
        } else {
            Err(format!(
                "{ENV}=1 but this network namespace has {names:?}, not just lo; refusing to \
                 touch it (run inside `unshare --user --map-root-user --net`)"
            ))
        }
    });
    if let Err(e) = fresh {
        panic!("{e}");
    }
    true
}

fn read(name: &str) -> Option<i64> {
    let path = format!("/proc/sys/{}", name.replace('.', "/"));
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

fn with(values: &[(&str, i64)]) -> Config {
    let mut c = Config::default();
    for (n, v) in values {
        c.system.tuning.sysctl.insert((*n).to_owned(), *v);
    }
    c
}

const HASH: &str = "net.ipv4.fib_multipath_hash_policy";
const HASH6: &str = "net.ipv6.fib_multipath_hash_policy";
const SOMAXCONN: &str = "net.core.somaxconn";

#[test]
fn per_namespace_parameters_are_written_and_put_back() {
    if !in_netns() {
        return;
    }
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let mut hal = LinuxHal::new();
    let names: Vec<&str> = PARAMS.iter().map(|p| p.name).collect();
    let now = hal.sysctls(&names).unwrap();
    assert_eq!(now[HASH], read(HASH));
    assert!(now[SOMAXCONN].is_some());
    assert_eq!(
        now["net.core.netdev_budget"], None,
        "host-wide: not in a namespace"
    );

    let (hash, hash6, somax) = (
        read(HASH).unwrap(),
        read(HASH6).unwrap(),
        read(SOMAXCONN).unwrap(),
    );
    let base = Config::default();
    let tuned = with(&[(HASH, 1), (HASH6, 1), (SOMAXCONN, somax + 1024)]);
    hal.apply(&base, &tuned).unwrap();
    assert_eq!(read(HASH), Some(1));
    assert_eq!(read(HASH6), Some(1));
    assert_eq!(read(SOMAXCONN), Some(somax + 1024));

    // Changing one keeps the others; taking all out restores the originals.
    let more = with(&[(HASH, 2), (HASH6, 1), (SOMAXCONN, somax + 1024)]);
    hal.apply(&tuned, &more).unwrap();
    assert_eq!(read(HASH), Some(2));
    hal.apply(&more, &base).unwrap();
    assert_eq!(read(HASH), Some(hash));
    assert_eq!(read(HASH6), Some(hash6));
    assert_eq!(read(SOMAXCONN), Some(somax));
}

#[test]
fn a_refused_parameter_rolls_the_whole_change_back() {
    if !in_netns() {
        return;
    }
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let mut hal = LinuxHal::new();
    let hash = read(HASH).unwrap();
    let base = Config::default();
    // Read-only in a namespace other than the host's.
    let bad = with(&[(HASH, 1), ("net.core.rmem_max", 8 << 20)]);
    let err = hal.apply(&base, &bad).unwrap_err().to_string();
    assert!(err.contains("read-only here"), "{err}");
    assert_eq!(read(HASH), Some(hash), "rolled back");
    // Absent in a namespace.
    let absent = with(&[(HASH, 1), ("net.core.netdev_budget", 600)]);
    let err = hal.apply(&base, &absent).unwrap_err().to_string();
    assert!(err.contains("does not have it"), "{err}");
    assert_eq!(read(HASH), Some(hash));
}

#[test]
fn reads_the_machine_and_the_counters() {
    if !in_netns() {
        return;
    }
    let mut hal = LinuxHal::new();
    let si = hal.system_info().unwrap();
    assert!(si.cpus > 0 && si.mem_kib > 0, "{si:?}");
    assert!(si.kernel_version().is_some(), "{}", si.kernel);
    let k = hal.kernel_stats().unwrap();
    assert!(
        !k.softnet.is_empty(),
        "softnet_stat is per host, readable here"
    );
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

fn ports(values: &[(&str, i64)]) -> Config {
    let mut c = Config::default();
    let port = c
        .system
        .tuning
        .ports
        .entry("pa".parse().unwrap())
        .or_default();
    for (k, v) in values {
        port.insert((*k).to_owned(), *v);
    }
    c
}

#[test]
fn port_settings_are_written_and_put_back() {
    if !in_netns() {
        return;
    }
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    ip(&[
        "link",
        "add",
        "pa",
        "numtxqueues",
        "4",
        "numrxqueues",
        "4",
        "type",
        "veth",
        "peer",
        "name",
        "pb",
        "numtxqueues",
        "4",
        "numrxqueues",
        "4",
    ]);
    ip(&["link", "set", "pa", "up"]);
    ip(&["link", "set", "pb", "up"]);
    let mut hal = LinuxHal::with_policy(Policy {
        manage: vec!["pa".into()],
        unmanaged: Vec::new(),
    });
    let name = "pa".parse().unwrap();
    let before = hal.port_tuning(&name).unwrap();
    let v = |t: &corerouter_hal::tuning::PortTuning, k: &str| t.values.get(k).copied().flatten();
    assert_eq!(v(&before, "txqueuelen"), Some(1000), "{before:?}");
    assert_eq!(v(&before, "qdisc"), Some(4), "veth: noqueue");
    assert!(v(&before, "rp_filter").is_some());
    assert_eq!(v(&before, "rx_ring"), None, "veth has no rings");
    assert_eq!(before.max.get("rx_channels"), Some(&4), "{before:?}");

    let base = Config::default();
    let tuned = ports(&[
        ("txqueuelen", 5000),
        ("qdisc", 0),
        ("rp_filter", 2),
        ("rx_channels", 2),
    ]);
    hal.apply(&base, &tuned).unwrap();
    let now = hal.port_tuning(&name).unwrap();
    assert_eq!(v(&now, "txqueuelen"), Some(5000));
    assert_eq!(v(&now, "qdisc"), Some(0), "fq_codel");
    assert_eq!(v(&now, "rp_filter"), Some(2));
    assert_eq!(v(&now, "rx_channels"), Some(2));

    // A knob this NIC lacks: the whole change goes back.
    let bad = ports(&[
        ("txqueuelen", 7000),
        ("qdisc", 0),
        ("rp_filter", 2),
        ("rx_channels", 2),
        ("rx_ring", 512),
    ]);
    let err = hal.apply(&tuned, &bad).unwrap_err().to_string();
    assert!(err.contains("does not let"), "{err}");
    assert_eq!(
        v(&hal.port_tuning(&name).unwrap(), "txqueuelen"),
        Some(5000)
    );

    // Taken out: the port's own values.
    hal.apply(&tuned, &base).unwrap();
    let back = hal.port_tuning(&name).unwrap();
    for k in ["txqueuelen", "qdisc", "rp_filter", "rx_channels"] {
        assert_eq!(v(&back, k), v(&before, k), "{k}");
    }

    // A link CoreRouter does not manage (`--unmanaged pa`) is never touched.
    let mut other = LinuxHal::with_policy(Policy {
        manage: Vec::new(),
        unmanaged: vec!["pa".into()],
    });
    other.apply(&base, &tuned).unwrap();
    assert_eq!(
        v(&other.port_tuning(&name).unwrap(), "txqueuelen"),
        Some(1000)
    );
    ip(&["link", "del", "pa"]);
}

// ---- G1.26i: a router forwards by default ------------------------------

const FWD4: &str = corerouter_model::tuning::IP_FORWARD;
const FWD6: &str = corerouter_model::tuning::IPV6_FORWARDING;

fn write(name: &str, value: i64) {
    let path = format!("/proc/sys/{}", name.replace('.', "/"));
    std::fs::write(&path, format!("{value}\n")).unwrap_or_else(|e| panic!("{path}: {e}"));
}

fn wait_for(what: &str, mut ok: impl FnMut() -> bool) {
    let until = std::time::Instant::now() + std::time::Duration::from_secs(15);
    while !ok() {
        assert!(
            std::time::Instant::now() < until,
            "timed out waiting for {what}"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

fn ip_out(args: &[&str]) -> String {
    let out = Command::new("ip").args(args).output().unwrap();
    assert!(out.status.success(), "ip {}", args.join(" "));
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// What a kernel boots with (a host, RFC 1122 §3.1) becomes a router on
/// the first apply, with nothing in the config; the operator's 0 is kept,
/// per family; taking it out goes back to forwarding, and so does a 0
/// that something else wrote.
#[test]
fn a_router_forwards_by_default_and_the_config_can_turn_it_off() {
    if !in_netns() {
        return;
    }
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    write(FWD4, 0);
    write(FWD6, 0);
    let mut hal = LinuxHal::new();
    let base = Config::default();
    assert!(base.system.tuning.sysctl.is_empty());
    hal.apply(&base, &base).unwrap();
    assert_eq!(
        (read(FWD4), read(FWD6)),
        (Some(1), Some(1)),
        "the start-up apply"
    );
    // New interfaces follow (`conf/default`), as `inet_forward_change` and
    // `addrconf_fixup_forwarding` leave it.
    assert_eq!(read("net.ipv4.conf.default.forwarding"), Some(1));
    assert_eq!(read("net.ipv6.conf.default.forwarding"), Some(1));

    // IPv4 off, by the operator: kept, and IPv6 goes on forwarding.
    let v4_off = with(&[(FWD4, 0)]);
    hal.apply(&base, &v4_off).unwrap();
    assert_eq!((read(FWD4), read(FWD6)), (Some(0), Some(1)));
    // Another commit does not bring it back.
    let more = with(&[(FWD4, 0), (HASH, 1)]);
    hal.apply(&v4_off, &more).unwrap();
    assert_eq!((read(FWD4), read(FWD6)), (Some(0), Some(1)));
    let both_off = with(&[(FWD4, 0), (FWD6, 0), (HASH, 1)]);
    hal.apply(&more, &both_off).unwrap();
    assert_eq!((read(FWD4), read(FWD6)), (Some(0), Some(0)));

    // A router restarted with that config stays off (a new HAL, as a boot).
    let mut boot = LinuxHal::new();
    boot.apply(&base, &both_off).unwrap();
    assert_eq!((read(FWD4), read(FWD6)), (Some(0), Some(0)));

    // Taken out of the config: CoreRouter's default again, not the 0 the
    // kernel had.
    boot.apply(&both_off, &base).unwrap();
    assert_eq!((read(FWD4), read(FWD6)), (Some(1), Some(1)));

    // Something else turned it off: the next apply turns it back on.
    write(FWD4, 0);
    boot.apply(&base, &with(&[(HASH, 1)])).unwrap();
    assert_eq!(read(FWD4), Some(1));
    boot.apply(&with(&[(HASH, 1)]), &base).unwrap();
}

/// IPv6 on a veth: up, with a link-local address that passed DAD.
fn veth_up(a: &str, b: &str) {
    ip(&["link", "add", a, "type", "veth", "peer", "name", b]);
    ip(&["link", "set", a, "up"]);
    ip(&["link", "set", b, "up"]);
    for dev in [a, b] {
        wait_for("a link-local address", || {
            let s = ip_out(&["-6", "addr", "show", "dev", dev, "scope", "link"]);
            s.contains("fe80::") && !s.contains("tentative")
        });
    }
}

fn index_of(dev: &str) -> u32 {
    let text = ip_out(&["-o", "link", "show", "dev", dev]);
    text.split(':').next().unwrap().trim().parse().unwrap()
}

fn mac_of(dev: &str) -> [u8; 6] {
    let text = ip_out(&["-o", "link", "show", "dev", dev]);
    let mac = text
        .split("link/ether ")
        .nth(1)
        .unwrap()
        .split(' ')
        .next()
        .unwrap();
    corerouter_hal_linux::ra::parse_mac(mac).unwrap()
}

fn icmp6(dev: &str) -> socket2::Socket {
    use socket2::{Domain, Protocol, Socket, Type};
    let s = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6)).unwrap();
    s.bind_device(Some(dev.as_bytes())).unwrap();
    s.set_multicast_hops_v6(255).unwrap();
    s.set_multicast_if_v6(index_of(dev)).unwrap();
    s
}

/// A Router Advertisement (RFC 4861 §4.2) from `dev`: a default router for
/// 1800 s and the on-link, autonomous prefix 2001:db8:26::/64 (§4.6.2).
fn send_ra(dev: &str) {
    let mut m = vec![134, 0, 0, 0, 64, 0];
    m.extend_from_slice(&1800u16.to_be_bytes());
    m.extend_from_slice(&[0; 8]);
    m.extend_from_slice(&[1, 1]);
    m.extend_from_slice(&mac_of(dev));
    m.extend_from_slice(&[3, 4, 64, 0xc0]);
    m.extend_from_slice(&86_400u32.to_be_bytes());
    m.extend_from_slice(&14_400u32.to_be_bytes());
    m.extend_from_slice(&[0; 4]);
    m.extend_from_slice(
        &"2001:db8:26::"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    let all_nodes = std::net::SocketAddrV6::new("ff02::1".parse().unwrap(), 0, 0, index_of(dev));
    icmp6(dev).send_to(&m, &all_nodes.into()).unwrap();
}

fn ra_route(dev: &str) -> bool {
    ip_out(&["-6", "route", "show", "default"])
        .lines()
        .any(|l| l.contains(&format!("dev {dev} ")) && l.contains("proto ra"))
}

/// A config that accepts RAs on `dev` (as a WAN with a DHCPv6 client does
/// under the default `auto`).
fn accepting(dev: &str) -> Config {
    let mut c = Config::default();
    let name: corerouter_model::IfName = dev.parse().unwrap();
    c.interfaces.insert(
        name.clone(),
        corerouter_model::Interface::new(name, corerouter_model::InterfaceKind::Ethernet),
    );
    c.ipv6.settings.accept_router_advertisements = corerouter_model::ipv6::AcceptRa::Yes;
    c
}

/// Linux drops the RA routes of every interface whose `accept_ra` is not 2
/// the moment IPv6 forwarding turns on (`addrconf_fixup_forwarding` →
/// `rt6_purge_dflt_routers`, net/ipv6/addrconf.c:914 and route.c:4527 in
/// 6.18.59), and a forwarding kernel does not ask for another. The boot
/// apply, which turns forwarding on, settles `accept_ra` first: the WAN
/// keeps the default route it already had.
#[test]
fn the_wan_keeps_its_ra_route_when_forwarding_turns_on() {
    if !in_netns() {
        return;
    }
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    write(FWD4, 0);
    write(FWD6, 0);
    veth_up("wa0", "wb0");
    assert_eq!(
        read("net.ipv6.conf.wa0.accept_ra"),
        Some(1),
        "the kernel's default"
    );
    send_ra("wb0");
    wait_for("the RA's default route", || ra_route("wa0"));

    // The kernel alone: forwarding on, the route is gone at once, and the
    // next RA is ignored (`ipv6_accept_ra`, include/net/ipv6.h:531).
    write(FWD6, 1);
    assert!(!ra_route("wa0"), "purged with forwarding");
    send_ra("wb0");
    std::thread::sleep(std::time::Duration::from_millis(300));
    assert!(!ra_route("wa0"), "accept_ra=1 ignores RAs while forwarding");

    // Back to a host that learned its route, then CoreRouter starts.
    write(FWD6, 0);
    send_ra("wb0");
    wait_for("the RA's default route again", || ra_route("wa0"));
    let mut hal = LinuxHal::new();
    let cfg = accepting("wa0");
    hal.apply(&Config::default(), &cfg).unwrap();
    assert_eq!(read(FWD6), Some(1));
    assert_eq!(read("net.ipv6.conf.wa0.forwarding"), Some(1));
    assert_eq!(read("net.ipv6.conf.wa0.accept_ra"), Some(2));
    assert!(
        ra_route("wa0"),
        "the default route survived forwarding going on"
    );

    // And RAs keep being taken while forwarding: a new one refreshes the
    // SLAAC address the prefix gives.
    ip(&["-6", "addr", "flush", "dev", "wa0", "scope", "global"]);
    send_ra("wb0");
    wait_for("SLAAC while forwarding", || {
        ip_out(&["-6", "addr", "show", "dev", "wa0", "scope", "global"]).contains("2001:db8:26:")
    });
    hal.apply(&cfg, &Config::default()).unwrap();
    ip(&["link", "del", "wa0"]);
}

/// A forwarding kernel sends no Router Solicitation by itself, so the
/// interface that starts accepting RAs with its link already up gets one
/// from CoreRouter (RFC 4861 §6.3.7), with its link-layer address (§4.1).
#[test]
fn an_interface_that_starts_accepting_asks_for_an_ra() {
    if !in_netns() {
        return;
    }
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    write(FWD6, 1);
    veth_up("sa0", "sb0");
    // The far end, listening on the all-routers group.
    let listen = icmp6("sb0");
    listen
        .join_multicast_v6(&"ff02::2".parse().unwrap(), index_of("sb0"))
        .unwrap();
    listen
        .set_read_timeout(Some(std::time::Duration::from_millis(200)))
        .unwrap();
    let solicitations = move || {
        use std::io::Read;
        let mut got = Vec::new();
        let mut buf = [0u8; 256];
        while let Ok(n) = (&listen).read(&mut buf) {
            if buf.first() == Some(&133) {
                got.push(buf.iter().take(n).copied().collect::<Vec<u8>>());
            }
        }
        got
    };
    assert!(
        solicitations().is_empty(),
        "forwarding: the kernel asks nothing"
    );

    let mut hal = LinuxHal::new();
    let cfg = accepting("sa0");
    hal.apply(&Config::default(), &cfg).unwrap();
    assert_eq!(read("net.ipv6.conf.sa0.accept_ra"), Some(2));
    let mut got = Vec::new();
    wait_for("the router solicitation", || {
        got.extend(solicitations());
        !got.is_empty()
    });
    let mut want = vec![133, 0];
    want.extend_from_slice(&got[0][2..4]);
    want.extend_from_slice(&[0, 0, 0, 0, 1, 1]);
    want.extend_from_slice(&mac_of("sa0"));
    assert_eq!(got[0], want, "RS with the source link-layer address option");

    // Applying again changes nothing and asks nothing.
    hal.apply(&cfg, &cfg).unwrap();
    assert!(solicitations().is_empty());
    hal.apply(&cfg, &Config::default()).unwrap();
    ip(&["link", "del", "sa0"]);
}
