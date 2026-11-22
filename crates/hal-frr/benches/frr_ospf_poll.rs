//! G3.4n: what the daemon's FRR poll costs on our side when the OSPF
//! network grows. Every 2 s (`service/frr.rs`, `TICK`) it reads
//! `show ip ospf neighbor json`, `show ip ospf interface json` and
//! `show ip ospf json` per instance; the LSDB window adds
//! `show ip ospf route json`. The JSON here follows FRR 10.7.1
//! (`ospfd/ospf_vty.c`: `show_ip_ospf_neighbour_brief`,
//! `show_ip_ospf_interface_sub`, `show_ip_ospf_route_network`): the same
//! fields, in the same order, with the same kinds of values.
//!
//! - `parse/*`: the parsers alone, over a buffer.
//! - `poll/*`: one whole poll (`version`, `ospf_state`, `ospf_stub_state`)
//!   through [`FrrReader`] against a fake `ospfd`/`zebra` on Unix sockets,
//!   so the connections, the `enable` and the copies count too.
//!
//! `cargo xtask bench frr_ospf_poll`; alone:
//! `cargo bench -p corerouter-hal-frr --bench frr_ospf_poll`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::fmt::Write as _;
use std::hint::black_box;

use corerouter_hal::routing::RoutingReader;
use corerouter_hal_frr::ospf::{interfaces_v2, neighbors_v2, routes_v2};
use criterion::{Criterion, criterion_group, criterion_main};

fn ip(i: usize) -> String {
    format!("10.{}.{}.{}", (i >> 16) & 255, (i >> 8) & 255, i & 255)
}

/// `show ip ospf neighbor json` with `n` neighbors, one per interface.
pub fn neighbors_json(n: usize) -> String {
    let mut s = String::from(r#"{"neighbors":{"#);
    for i in 0..n {
        if i > 0 {
            s.push(',');
        }
        let _ = write!(
            s,
            r#""{}":[{{"nbrState":"Full/DR","nbrPriority":1,"converged":"Full","role":"DR","upTimeInMsec":{},"routerDeadIntervalTimerDueMsec":{},"upTime":"1d02h03m","deadTime":"35.123s","ifaceAddress":"{}","ifaceName":"ether{}:{}","linkStateRetransmissionListCounter":0,"linkStateRequestListCounter":0,"databaseSummaryListCounter":0}}]"#,
            ip(0x0100_0000 + i),
            93_784_000 + i,
            35_000 - i % 1000,
            ip(0x0200_0000 + i * 4 + 2),
            i,
            ip(0x0200_0000 + i * 4 + 1),
        );
    }
    s.push_str("}}");
    s
}

/// `show ip ospf interface json` with `n` OSPF interfaces.
pub fn interfaces_json(n: usize) -> String {
    let mut s = String::from(r#"{"interfaces":{"#);
    for i in 0..n {
        if i > 0 {
            s.push(',');
        }
        let a = ip(0x0200_0000 + i * 4 + 1);
        let _ = write!(
            s,
            r#""ether{i}":{{"ifUp":true,"ifIndex":{},"mtuBytes":1500,"bandwidthMbit":10000,"ifFlags":"<UP,LOWER_UP,BROADCAST,RUNNING,MULTICAST>","ospfEnabled":true,"ospfRunning":true,"ipAddress":"{a}","ipAddressPrefixlen":30,"ospfIfType":"Broadcast","localIfUsed":"{}","area":"0.0.0.0","routerId":"10.255.0.1","networkType":"BROADCAST","cost":10,"transmitDelaySecs":1,"state":"DROther","priority":1,"opaqueCapable":true,"drId":"{}","drAddress":"{}","bdrId":"10.255.0.1","bdrAddress":"{a}","mcastMemberOspfAllRouters":true,"mcastMemberOspfDesignatedRouters":true,"timerMsecs":10000,"timerDeadSecs":40,"timerWaitSecs":40,"timerRetransmitSecs":5,"timerRetransmitWindowMsecs":50,"timerHelloInMsecs":{},"nbrCount":1,"nbrAdjacentCount":1,"grHelloDelaySecs":10,"prefixSuppression":false,"lsaRetransmissions":0}}"#,
            i + 3,
            ip(0x0200_0000 + i * 4 + 3),
            ip(0x0100_0000 + i),
            ip(0x0200_0000 + i * 4 + 2),
            1_000 + i % 9_000,
        );
    }
    s.push_str(r#"}}"#);
    s
}

/// `show ip ospf route json` with `n` network routes (a third external,
/// two next hops each) and the routers that reach them.
pub fn routes_json(n: usize) -> String {
    let mut s = String::from("{");
    for i in 0..n {
        let kind = match i % 3 {
            0 => r#""routeType":"N","transit":false,"cost":20,"area":"0.0.0.0""#,
            1 => r#""routeType":"N IA","cost":30,"area":"0.0.0.0""#,
            _ => r#""routeType":"N E2","cost":20,"type2cost":1,"tag":0"#,
        };
        let _ = write!(
            s,
            r#""{}/24":{{{kind},"nexthops":[{{"ip":"{}","via":"ether{}","advertisedRouter":"{}"}},{{"ip":"{}","via":"ether{}","advertisedRouter":"{}"}}]}},"#,
            std::net::Ipv4Addr::from(u32::try_from((0x14_0000 + i) << 8).unwrap()),
            ip(0x0200_0000 + (i % 500) * 4 + 2),
            i % 500,
            ip(0x0100_0000 + i % 2000),
            ip(0x0200_0000 + (i % 500 + 1) * 4 + 2),
            (i + 1) % 500,
            ip(0x0100_0000 + (i + 7) % 2000),
        );
    }
    for r in 0..100 {
        let _ = write!(
            s,
            r#""{}":{{"routeType":"R ","cost":10,"area":"0.0.0.0","routerType":"asbr","nexthops":[{{"ip":"10.2.0.2","via":"ether0"}}]}},"#,
            ip(0x0100_0000 + r)
        );
    }
    s.pop();
    s.push('}');
    s
}

#[cfg(unix)]
mod fake {
    //! A fake FRR: answers each NUL-ended command on `<daemon>.vty`
    //! from a table, the way `lib/vty.c` does (output, then `0 0 0 code`).

    use std::collections::HashMap;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixListener;
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use std::thread;

    pub struct Dir(pub PathBuf);
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    pub fn serve(dir: &Path, daemon: &str, answers: Arc<HashMap<String, Vec<u8>>>) {
        let path = dir.join(format!("{daemon}.vty"));
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        thread::spawn(move || {
            for s in listener.incoming() {
                let Ok(mut s) = s else { return };
                let answers = Arc::clone(&answers);
                thread::spawn(move || {
                    let mut pending = Vec::new();
                    let mut b = vec![0u8; 4096];
                    loop {
                        let n = match s.read(&mut b) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => n,
                        };
                        pending.extend_from_slice(&b[..n]);
                        while let Some(end) = pending.iter().position(|&c| c == 0) {
                            let cmd = String::from_utf8_lossy(&pending[..end]).into_owned();
                            pending.drain(..=end);
                            let out = answers.get(&cmd).map(Vec::as_slice).unwrap_or_default();
                            if s.write_all(out).is_err() || s.write_all(&[0, 0, 0, 0]).is_err() {
                                return;
                            }
                        }
                    }
                });
            }
        });
    }
}

fn parse(c: &mut Criterion) {
    let mut g = c.benchmark_group("ospf_poll_parse");
    g.sample_size(20);
    for n in [50, 500] {
        let j = neighbors_json(n);
        assert_eq!(neighbors_v2(&j, "v2").unwrap().len(), n);
        g.bench_function(format!("neighbors_{n}"), |b| {
            b.iter(|| neighbors_v2(black_box(&j), "v2").unwrap().len())
        });
    }
    for n in [500, 4_000] {
        let j = interfaces_json(n);
        assert_eq!(interfaces_v2(&j, "v2").unwrap().len(), n);
        eprintln!("interfaces {n}: {} KiB of JSON", j.len() >> 10);
        g.bench_function(format!("interfaces_{n}"), |b| {
            b.iter(|| interfaces_v2(black_box(&j), "v2").unwrap().len())
        });
    }
    for n in [10_000, 200_000] {
        let j = routes_json(n);
        assert_eq!(routes_v2(&j, "v2").unwrap().len(), n);
        eprintln!("routes {n}: {} KiB of JSON", j.len() >> 10);
        g.bench_function(format!("routes_{n}"), |b| {
            b.iter(|| routes_v2(black_box(&j), "v2").unwrap().len())
        });
    }
    g.finish();
}

#[cfg(unix)]
fn poll(c: &mut Criterion) {
    use std::collections::HashMap;
    use std::sync::Arc;

    use corerouter_hal_frr::{Frr, FrrReader};
    use corerouter_model::Config;
    use corerouter_model::ospf::OspfInstance;

    let mut g = c.benchmark_group("ospf_poll");
    g.sample_size(20);
    for (ifs, nbrs) in [(500, 50), (4_000, 500)] {
        let dir = fake::Dir(
            std::env::temp_dir().join(format!("cr-frr-poll-{}-{ifs}", std::process::id())),
        );
        let _ = std::fs::remove_dir_all(&dir.0);
        std::fs::create_dir_all(&dir.0).unwrap();
        let mut ospfd = HashMap::new();
        ospfd.insert("enable".to_owned(), Vec::new());
        ospfd.insert(
            "show ip ospf neighbor json".to_owned(),
            neighbors_json(nbrs).into_bytes(),
        );
        ospfd.insert(
            "show ip ospf interface json".to_owned(),
            interfaces_json(ifs).into_bytes(),
        );
        ospfd.insert(
            "show ip ospf json".to_owned(),
            br#"{"routerId":"10.255.0.1","areas":{"0.0.0.0":{"nbrFullAdjacentCounter":1}}}"#
                .to_vec(),
        );
        fake::serve(&dir.0, "ospfd", Arc::new(ospfd));
        let mut zebra = HashMap::new();
        zebra.insert("enable".to_owned(), Vec::new());
        zebra.insert(
            "show version".to_owned(),
            b"FRRouting 10.7.1 (bench).\n".to_vec(),
        );
        fake::serve(&dir.0, "zebra", Arc::new(zebra));
        let mut cfg = Config::default();
        cfg.routing.ospf.instances.insert(
            "v2".into(),
            OspfInstance {
                name: "v2".into(),
                version: Default::default(),
                vrf: "main".into(),
                router_id: Some("10.255.0.1".parse().unwrap()),
                redistribute: Vec::new(),
                out_filter_chain: None,
                originate_default: Default::default(),
                subscriber_pools: false,
                stub_router: false,
                stub_router_on_startup: None,
                max_lsa: None,
                disabled: false,
                comment: String::new(),
            },
        );
        let mut reader = FrrReader(Frr::new(&dir.0));
        let (n, i) = reader.ospf_state(&cfg).unwrap();
        assert_eq!((n.len(), i.len()), (nbrs, ifs));
        g.bench_function(format!("tick_{ifs}_ifs_{nbrs}_nbrs"), |b| {
            b.iter(|| {
                let v = reader.version().unwrap();
                let (n, i) = reader.ospf_state(&cfg).unwrap();
                let st = reader.ospf_stub_state(&cfg).unwrap();
                black_box((v, n.len(), i.len(), st.len()))
            })
        });
        // The same tick on new connections each time (what the poll did
        // before G3.4n kept them): the difference is the pool's gain.
        g.bench_function(format!("tick_{ifs}_ifs_{nbrs}_nbrs_new_connections"), |b| {
            b.iter(|| {
                let mut reader = FrrReader(Frr::new(&dir.0));
                let v = reader.version().unwrap();
                let (n, i) = reader.ospf_state(&cfg).unwrap();
                let st = reader.ospf_stub_state(&cfg).unwrap();
                black_box((v, n.len(), i.len(), st.len()))
            })
        });
        // The config the poll reads, as the daemon builds it each tick.
        g.bench_function(format!("routing_only_copy_{ifs}"), |b| {
            b.iter(|| {
                let c = Config {
                    routing: cfg.routing.clone(),
                    ..Config::default()
                };
                black_box(c)
            })
        });
        drop(dir);
    }
    g.finish();
}

#[cfg(not(unix))]
fn poll(_: &mut Criterion) {}

criterion_group!(benches, parse, poll);
criterion_main!(benches);
