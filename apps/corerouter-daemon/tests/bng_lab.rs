//! G4.3g: the mass BNG lab. BNG Blaster (rtbrick, BSD-3) emulates
//! thousands of PPPoE subscribers against a `--backend linux` daemon, inside
//! throwaway network namespaces. `cargo xtask bng-lab` builds this binary in
//! release and runs it; by hand:
//!
//! ```sh
//! cargo test --release -p corerouter-daemon --test bng_lab --no-run
//! COREROUTER_BNG_LAB=1 BNGBLASTER=/usr/sbin/bngblaster \
//!     unshare --user --map-root-user --net -- <binary> bng_lab --exact --nocapture
//! ```
//!
//! ```text
//!   namespace A: the daemon (BNG)           namespace B: the subscribers
//!   acc0..accN ───────── veth ─────────── cpe0..cpeN   BNG Blaster access
//!   wan0 198.51.100.1/24 ─ veth ───────── blnet        BNG Blaster network
//!   acc9 ──────────────── veth ────────── cpe9         pppd + pppoe.so (root)
//! ```
//!
//! The stages, per scale (`BNG_LAB_SCALES`, default 1000,10000,100000):
//! setup with the protections off, keepalive and session traffic held,
//! an outage (BNG Blaster killed, no PADT) and the mass reconnect with the
//! protections at their defaults, teardown. Then, on `BNG_LAB_RADIUS`
//! subscribers authenticated by `proto_radius::testserver` with a
//! `Mikrotik-Rate-Limit`: streams both ways at twice the rate (policer
//! accuracy, XDP only), a CoA that lifts the rate of a tenth of them, and a
//! Disconnect-Request for another tenth under load. With root
//! (`BNG_LAB_ROOT=1`): XDP on the ports and the Linux client (`pppd`).
//!
//! What it measured goes to `$BNG_LAB_OUT/summary.json` and `summary.md`;
//! BNG Blaster's reports, logs and the captures stay next to them.
//!
//! Helpers outside `#[test]` fns may unwrap/panic too.
#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::io::{Read, Write};
use std::net::{Ipv4Addr, UdpSocket};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::*;
use corerouter_proto_radius::dynauth::{self, RequestKind};
use corerouter_proto_radius::packet::{AttrList, Code, Packet, PushAttr, attr};
use corerouter_proto_radius::testserver::TestServer;
use serde_json::{Value, json};

/// Sessions per access port: a PPPoE server numbers its sessions in 16
/// bits (RFC 2516 §4: SESSION_ID 0x0001..0xFFFE).
const PER_PORT: usize = 50_000;
const SECRET: &str = "lab-segredo";
const DAC_PORT: u16 = 3799;

fn env_or<T: std::str::FromStr>(k: &str, d: T) -> T {
    std::env::var(k)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(d)
}

fn ok(command: &str, params: Value) -> Value {
    call(None, command, params).unwrap_or_else(|e| panic!("{command}: {e}"))
}

fn batch(steps: Vec<Value>) {
    for chunk in steps.chunks(10_000) {
        let mut c = client(CONTROL, token_of(None)).unwrap();
        c.call("engine.batch", json!({"steps": chunk, "atomic": true}))
            .unwrap();
    }
}

fn active() -> usize {
    ok("ppp.active.list", json!({"limit": 1}))["total"]
        .as_u64()
        .unwrap_or(0) as usize
}

fn wait_long(what: &str, secs: u64, mut done: impl FnMut() -> bool) -> Option<f64> {
    let t = Instant::now();
    while t.elapsed() < Duration::from_secs(secs) {
        if done() {
            return Some(t.elapsed().as_secs_f64());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    eprintln!("lab: timed out after {secs} s waiting for {what}");
    None
}

fn sh(program: &str, args: &[&str]) -> String {
    let out = Command::new(program).args(args).output().unwrap();
    assert!(
        out.status.success(),
        "{program} {}: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// `/proc/<pid>` numbers of the daemon: RSS (KiB) and CPU time (s).
fn rss_kib(pid: u32) -> u64 {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .unwrap_or_default()
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))
        .and_then(|v| v.trim().trim_end_matches("kB").trim().parse().ok())
        .unwrap_or(0)
}

fn cpu_secs(pid: u32) -> f64 {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
    // Fields after the command name (which may hold spaces): utime is the
    // 14th field, stime the 15th (proc(5)).
    let rest = stat.rsplit_once(')').map_or("", |(_, r)| r);
    let f: Vec<&str> = rest.split_whitespace().collect();
    let ticks: f64 = f.get(11).and_then(|v| v.parse().ok()).unwrap_or(0.0)
        + f.get(12).and_then(|v| v.parse().ok()).unwrap_or(0.0);
    let hz: f64 = sh("getconf", &["CLK_TCK"]).trim().parse().unwrap_or(100.0);
    ticks / hz
}

/// One line of the summary.
#[derive(Clone)]
struct Row {
    scenario: String,
    metric: String,
    value: f64,
    unit: &'static str,
    note: String,
}

#[derive(Default)]
struct Summary {
    rows: Vec<Row>,
    checks: Vec<(String, bool, String)>,
}

impl Summary {
    fn put(&mut self, scenario: &str, metric: &str, value: f64, unit: &'static str, note: &str) {
        println!("MEASURED bng-lab {scenario}: {metric} = {value:.3} {unit} {note}");
        self.rows.push(Row {
            scenario: scenario.into(),
            metric: metric.into(),
            value,
            unit,
            note: note.into(),
        });
    }

    fn check(&mut self, what: &str, pass: bool, detail: String) {
        println!(
            "CHECK bng-lab {}: {what} {detail}",
            if pass { "ok" } else { "FAIL" }
        );
        self.checks.push((what.into(), pass, detail));
    }

    fn write(&self, out: &Path, meta: &Value) {
        let rows: Vec<Value> = self
            .rows
            .iter()
            .map(|r| json!({"scenario": r.scenario, "metric": r.metric, "value": r.value, "unit": r.unit, "note": r.note}))
            .collect();
        let checks: Vec<Value> = self
            .checks
            .iter()
            .map(|(w, p, d)| json!({"check": w, "pass": p, "detail": d}))
            .collect();
        let doc = json!({"meta": meta, "measured": rows, "checks": checks});
        std::fs::write(
            out.join("summary.json"),
            serde_json::to_string_pretty(&doc).unwrap(),
        )
        .unwrap();
        let mut md = String::from("# BNG lab (G4.3g)\n\n");
        for (k, v) in meta.as_object().into_iter().flatten() {
            md.push_str(&format!(
                "- {k}: {}\n",
                v.as_str().map_or(v.to_string(), str::to_owned)
            ));
        }
        md.push_str("\n| Cenário | Métrica | Valor | Unidade | Nota |\n|---|---|---:|---|---|\n");
        for r in &self.rows {
            md.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n",
                r.scenario,
                r.metric,
                fmt_num(r.value),
                r.unit,
                r.note
            ));
        }
        md.push_str("\n| Verificação | Resultado | Detalhe |\n|---|---|---|\n");
        for (w, p, d) in &self.checks {
            md.push_str(&format!(
                "| {w} | {} | {d} |\n",
                if *p { "ok" } else { "FALHOU" }
            ));
        }
        std::fs::write(out.join("summary.md"), md).unwrap();
    }
}

fn fmt_num(v: f64) -> String {
    if v.abs() >= 100.0 || v.fract() == 0.0 {
        format!("{v:.0}")
    } else {
        format!("{v:.3}")
    }
}

/// BNG Blaster, running in namespace B.
struct Blaster {
    child: Child,
    sock: PathBuf,
    report: PathBuf,
}

impl Blaster {
    fn start(lab: &Lab, name: &str, cfg: &Value, extra: &[&str]) -> Self {
        let cfg_path = lab.out.join(format!("{name}.json"));
        std::fs::write(&cfg_path, serde_json::to_string_pretty(cfg).unwrap()).unwrap();
        let sock = PathBuf::from(format!("/tmp/crbng-{}-{name}.sock", std::process::id()));
        let _ = std::fs::remove_file(&sock);
        let report = lab.out.join(format!("{name}-report.json"));
        let _ = std::fs::remove_file(&report);
        let log = std::fs::File::create(lab.out.join(format!("{name}.log"))).unwrap();
        let mut c = in_ns(Some(lab.b.0.id()), &lab.blaster.to_string_lossy());
        c.arg("-C")
            .arg(&cfg_path)
            .arg("-S")
            .arg(&sock)
            .arg("-J")
            .arg(&report)
            .arg("-L")
            .arg(lab.out.join(format!("{name}-blaster.log")))
            .args(["-l", "error", "-l", "pppoe", "-l", "info"])
            .args(extra)
            .stdin(Stdio::null())
            .stdout(log.try_clone().unwrap())
            .stderr(log);
        let child = c.spawn().unwrap();
        let b = Self {
            child,
            sock,
            report,
        };
        let t = Instant::now();
        while !b.sock.exists() && t.elapsed() < Duration::from_secs(20) {
            std::thread::sleep(Duration::from_millis(50));
        }
        b
    }

    /// One control-socket command (BNG Blaster's JSON API).
    fn cmd(&self, command: &str, args: Value) -> Option<Value> {
        let mut s = UnixStream::connect(&self.sock).ok()?;
        s.set_read_timeout(Some(Duration::from_secs(10))).ok()?;
        let req = if args.is_null() {
            json!({"command": command})
        } else {
            json!({"command": command, "arguments": args})
        };
        s.write_all(req.to_string().as_bytes()).ok()?;
        let mut buf = String::new();
        s.read_to_string(&mut buf).ok()?;
        serde_json::from_str(&buf).ok()
    }

    fn counters(&self) -> (u64, u64) {
        let c = self
            .cmd("session-counters", Value::Null)
            .unwrap_or(Value::Null);
        let c = &c["session-counters"];
        (
            c["sessions-established"].as_u64().unwrap_or(0),
            c["sessions-flapped"].as_u64().unwrap_or(0),
        )
    }

    fn established(&self) -> u64 {
        self.counters().0
    }

    /// SIGINT: the sessions are torn down (PADT) and the report written.
    fn stop(mut self, secs: u64) -> Value {
        let _ = Command::new("kill")
            .args(["-INT", &self.child.id().to_string()])
            .status();
        let t = Instant::now();
        while t.elapsed() < Duration::from_secs(secs) {
            if let Ok(Some(_)) = self.child.try_wait() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        std::fs::read_to_string(&self.report)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or(Value::Null)
    }

    /// SIGKILL: an outage, no PADT, no report.
    fn kill(mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for Blaster {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.sock);
    }
}

/// The two namespaces, the daemon and BNG Blaster's binary.
struct Lab {
    daemon: Kill,
    b: Kill,
    out: PathBuf,
    blaster: PathBuf,
    root: bool,
    ports: usize,
    xdp: bool,
}

impl Lab {
    fn new(ports: usize, out: PathBuf, blaster: PathBuf, root: bool) -> Self {
        ip(None, &["link", "set", "lo", "up"]);
        // Namespace B, held open by a sleeper for the whole lab (the
        // shared `namespace_b` lives 5 minutes; the 100k stage is longer).
        let b = Kill(
            Command::new("unshare")
                .args(["--net", "--", "sleep", "86400"])
                .spawn()
                .unwrap(),
        );
        let here = netns_of(std::process::id());
        wait_for("B's namespace", || {
            netns_of(b.0.id()).is_some_and(|ns| Some(ns) != here)
        });
        let bpid = b.0.id().to_string();
        let mut links: Vec<(String, String)> = (0..ports)
            .map(|i| (format!("acc{i}"), format!("cpe{i}")))
            .collect();
        links.push(("wan0".into(), "blnet".into()));
        if root {
            links.push(("acc9".into(), "cpe9".into()));
        }
        for (here, there) in &links {
            ip(
                None,
                &["link", "add", here, "type", "veth", "peer", "name", there],
            );
            ip(None, &["link", "set", there, "netns", &bpid]);
            ip(None, &["link", "set", here, "up"]);
            ip(Some(b.0.id()), &["link", "set", there, "up"]);
        }
        ip(Some(b.0.id()), &["link", "set", "lo", "up"]);
        // B is only a wire for BNG Blaster: no IPv6 chatter, no stack
        // answering for its addresses.
        let _ = in_ns(Some(b.0.id()), "sh")
            .args([
                "-c",
                "echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6; echo 1 > /proc/sys/net/ipv6/conf/default/disable_ipv6",
            ])
            .status();
        std::fs::write("/proc/sys/net/ipv4/ip_forward", "1").unwrap();
        // A namespace inherits the host's IPv4 settings (rp_filter 2 on
        // most distributions): the decapsulated packets arrive on the
        // access ports from addresses with no route back through them.
        let mut confs = vec!["all".to_owned(), "default".to_owned()];
        confs.extend(links.iter().map(|(here, _)| here.clone()));
        for k in confs {
            let _ = std::fs::write(format!("/proc/sys/net/ipv4/conf/{k}/rp_filter"), "0");
        }
        let dir = out.join("daemon");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let log = std::fs::File::create(out.join("daemon.log")).unwrap();
        let mut c = in_ns(None, DAEMON);
        c.args([
            "--backend",
            "linux",
            "--no-discovery",
            "--manage",
            "acc*,wan0",
            "--control",
            "7979",
            "--config-dir",
        ])
        .arg(&dir)
        .arg("--token-file")
        .arg(token_file(None, &dir))
        .env("RUST_LOG", "warn")
        .stdout(Stdio::null())
        .stderr(log);
        let daemon = Kill(c.spawn().unwrap());
        wait_for("the daemon", || {
            call(None, "interface.list", json!({})).is_ok()
        });
        ok(
            "ip.address.add",
            json!({"address": "198.51.100.1/24", "interface": "wan0"}),
        );
        let mut xdp = false;
        if root {
            // G4.3c: the data plane on the access ports and the uplink
            // (generic mode: veth).
            let mut all: Vec<String> = (0..ports).map(|i| format!("acc{i}")).collect();
            all.push("acc9".into());
            all.push("wan0".into());
            for i in &all {
                ok(
                    "ip.firewall.xdp.interface.add",
                    json!({"interface": i, "mode": "generic"}),
                );
            }
            xdp = true;
        }
        Self {
            daemon,
            b,
            out,
            blaster,
            root,
            ports,
            xdp,
        }
    }

    fn pid(&self) -> u32 {
        self.daemon.0.id()
    }

    fn servers(&self, protections: bool) {
        let (padi, mac, rate) = if protections {
            (2000, 1, 2000)
        } else {
            (0, 0, 0)
        };
        let mut names: Vec<String> = (0..self.ports).map(|i| format!("acc{i}")).collect();
        if self.root {
            names.push("acc9".into());
        }
        for n in names {
            let id = format!("pppoe-{n}");
            let exists = ok("interface.pppoe-server.server.list", json!({}))
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r["name"] == id);
            let p = json!({"padi_limit": padi, "mac_padi_limit": mac, "new_session_rate": rate, "keepalive_timeout": 30});
            if exists {
                let mut p = p;
                p["id"] = json!(id);
                ok("interface.pppoe-server.server.set", p);
            } else {
                let mut p = p;
                p["interface"] = json!(n);
                p["authentication"] = json!("chap,pap");
                ok("interface.pppoe-server.server.add", p);
            }
        }
    }

    fn dataplane(&self) -> String {
        // `dataplane`: true when the sessions are in the XDP map.
        match ok("interface.pppoe-server.monitor", json!({}))["dataplane"].as_bool() {
            Some(true) => "XDP".into(),
            Some(false) => "caminho lento".into(),
            None => "?".into(),
        }
    }
}

/// BNG Blaster's config: `n` PPPoE subscribers `{user}{session-global}`
/// (password `test`), spread over the access ports, untagged (N:1).
fn blaster_config(n: usize, user: &str, pps: f64, streams: Option<Value>) -> Value {
    let ports = n.div_ceil(PER_PORT).max(1);
    let access: Vec<Value> = (0..ports)
        .map(|i| {
            json!({
                "interface": format!("cpe{i}"),
                "type": "pppoe",
                "vlan-mode": "N:1",
                "session-limit": PER_PORT,
                "stream-group-id": 1,
            })
        })
        .collect();
    let mut cfg = json!({
        "interfaces": {
            "tx-interval": 1.0,
            "rx-interval": 1.0,
            "network": {"interface": "blnet", "address": "198.51.100.2/24", "gateway": "198.51.100.1"},
            "access": access,
        },
        "sessions": {
            "count": n,
            "max-outstanding": env_or("BNG_LAB_OUTSTANDING", 4000usize),
            "start-rate": env_or("BNG_LAB_START_RATE", 10_000usize),
            "stop-rate": env_or("BNG_LAB_STOP_RATE", 10_000usize),
            "reconnect": true,
        },
        "pppoe": {"reconnect": true, "discovery-timeout": 3, "discovery-retry": 30, "host-uniq": true},
        "ppp": {
            "mru": 1492,
            "authentication": {"username": format!("{user}{{session-global}}"), "password": "test", "timeout": 5, "retry": 30, "protocol": "CHAP"},
            "lcp": {"conf-request-timeout": 2, "conf-request-retry": 30, "keepalive-interval": 10, "keepalive-retry": 3},
            "ipcp": {"enable": true, "request-dns1": true, "request-dns2": false},
            "ip6cp": {"enable": false},
        },
        "dhcpv6": {"enable": false},
        "session-traffic": {"autostart": true, "ipv4-pps": pps},
    });
    if let Some(s) = streams {
        cfg["streams"] = s;
        cfg["session-traffic"] = json!({"autostart": false, "ipv4-pps": 0});
    }
    cfg
}

fn report_num(r: &Value, k: &str) -> f64 {
    r["report"][k].as_f64().unwrap_or(f64::NAN)
}

/// One scale: setup, keepalive + traffic held, outage and mass reconnect,
/// teardown.
fn scale(lab: &Lab, n: usize, s: &mut Summary) {
    let tag = format!("{}k", n / 1000);
    let sc = |x: &str| format!("{tag} {x}");
    lab.servers(false);
    // Session traffic, 1 pps each way per session (BNG Blaster makes no
    // flow below 1 pps): every session up to 10 000; above, a sample of
    // 10 000 spread over all of them (one in n/10 000), started by hand,
    // so the slow path (one thread) is not what the stage measures.
    let sample = n.min(10_000);
    let mut cfg = blaster_config(n, "user", 1.0, None);
    if sample < n {
        cfg["session-traffic"]["autostart"] = json!(false);
    }
    let pid = lab.pid();
    let rss0 = rss_kib(pid);
    let cpu0 = cpu_secs(pid);
    let t = Instant::now();
    let bl = Blaster::start(lab, &format!("scale-{tag}"), &cfg, &[]);
    let limit = 60 + (n as u64) / 200;
    let took = wait_long("setup", limit, || bl.established() as usize >= n);
    let daemon_up = wait_long("ppp.active", 30, || active() >= n).is_some();
    let plane = lab.dataplane();
    match took {
        Some(secs) => {
            s.put(
                &sc("setup"),
                "sessões estabelecidas",
                n as f64,
                "sessões",
                "",
            );
            s.put(
                &sc("setup"),
                "tempo até todas",
                secs,
                "s",
                "relógio do laboratório",
            );
            s.put(
                &sc("setup"),
                "taxa de estabelecimento",
                n as f64 / secs,
                "sessões/s",
                &format!("proteções desligadas; CHAP; BNG Blaster start-rate 10000; plano {plane}"),
            );
        }
        None => s.put(
            &sc("setup"),
            "sessões estabelecidas (incompleto)",
            bl.established() as f64,
            "sessões",
            &format!("de {n} em {limit} s"),
        ),
    }
    s.check(
        &sc("setup completo"),
        took.is_some() && daemon_up,
        format!("{} de {n}", active()),
    );
    let cpu1 = cpu_secs(pid);
    let rss1 = rss_kib(pid);
    s.put(
        &sc("setup"),
        "CPU do daemon por sessão",
        (cpu1 - cpu0) * 1e6 / n as f64,
        "µs/sessão",
        "utime+stime durante o setup",
    );
    // Below 10 000 the allocator's own moves (the secrets' batch freed,
    // arenas trimmed) are bigger than what the sessions take.
    if n >= 10_000 {
        s.put(
            &sc("setup"),
            "memória do daemon por sessão",
            (rss1.saturating_sub(rss0) as f64 * 1024.0) / n as f64,
            "B/sessão",
            &format!("RSS {rss0} → {rss1} KiB"),
        );
    }
    if sample < n {
        let step = n / sample;
        for id in (1..=n).step_by(step).take(sample) {
            let _ = bl.cmd("session-traffic-start", json!({"session-id": id}));
        }
    }

    // Keepalive and session traffic held: LCP echo every 10 s from each
    // side's view, no flaps.
    let hold = env_or("BNG_LAB_HOLD", 30u64);
    let (_, flapped0) = bl.counters();
    let c0 = cpu_secs(pid);
    std::thread::sleep(Duration::from_secs(hold));
    let c1 = cpu_secs(pid);
    let (est, flapped1) = bl.counters();
    s.put(
        &sc("keepalive"),
        "CPU do daemon em regime",
        (c1 - c0) * 100.0 / hold as f64,
        "% de um núcleo",
        &format!(
            "{hold} s, LCP echo a cada 10 s, tráfego de 1 pps cada sentido em {sample} sessões"
        ),
    );
    s.check(
        &sc("sem quedas no regime"),
        flapped1 == flapped0 && est as usize >= n && active() >= n,
        format!("flapped {flapped0} → {flapped1}, estabelecidas {est}"),
    );
    let st = bl
        .cmd("session-traffic", Value::Null)
        .unwrap_or(Value::Null);
    let st = &st["session-traffic"];
    let total = st["total-flows"].as_f64().unwrap_or(0.0);
    let verified = st["verified-flows"].as_f64().unwrap_or(0.0);
    let want = 2.0 * sample as f64;
    s.put(
        &sc("tráfego"),
        "fluxos verificados",
        verified,
        "fluxos",
        &if sample < n {
            format!("de {want}: amostra de {sample} sessões (uma a cada {}), os dois sentidos; {total} fluxos criados", n / sample)
        } else {
            format!("de {total} (um por sessão e sentido)")
        },
    );
    s.check(
        &sc("tráfego nas sessões medidas"),
        total >= want && verified >= want,
        format!("{verified}/{want}"),
    );

    // Outage: every CPE gone at once (no PADT); they come back with the
    // protections at their defaults, as an operator runs them.
    lab.servers(true);
    let throttled0 = ok("interface.pppoe-server.monitor", json!({}))["throttled"]
        .as_f64()
        .unwrap_or(0.0);
    bl.kill();
    let t2 = Instant::now();
    let bl = Blaster::start(lab, &format!("reconnect-{tag}"), &cfg, &[]);
    let limit = 60 + (n as u64) / 100;
    let took = wait_long("reconnect", limit, || bl.established() as usize >= n);
    match took {
        Some(secs) => s.put(
            &sc("reconexão em massa"),
            "tempo até todas de volta",
            secs,
            "s",
            &format!(
                "{:.0} sessões/s; proteções padrão (new-session-rate 2000, padi 2000, 1/MAC)",
                n as f64 / secs
            ),
        ),
        None => s.put(
            &sc("reconexão em massa"),
            "de volta (incompleto)",
            bl.established() as f64,
            "sessões",
            &format!("de {n} em {limit} s"),
        ),
    }
    let mon = ok("interface.pppoe-server.monitor", json!({}));
    s.put(
        &sc("reconexão em massa"),
        "PADI/sessões contidos pelo limite",
        mon["throttled"].as_f64().unwrap_or(0.0) - throttled0,
        "pedidos",
        "interface.pppoe-server.monitor throttled",
    );
    s.check(
        &sc("reconexão completa"),
        took.is_some() && wait_long("ppp.active", 60, || active() == n).is_some(),
        format!(
            "ativas {} (as antigas substituídas, uma por host)",
            active()
        ),
    );

    // The same outage with the protections off: how fast the BNG takes
    // the whole wave when nothing paces it.
    lab.servers(false);
    bl.kill();
    let bl = Blaster::start(lab, &format!("reconnect-free-{tag}"), &cfg, &[]);
    let limit = 60 + (n as u64) / 100;
    let took = wait_long("reconnect (no protections)", limit, || {
        bl.established() as usize >= n
    });
    if let Some(secs) = took {
        s.put(
            &sc("reconexão sem proteções"),
            "tempo até todas de volta",
            secs,
            "s",
            &format!(
                "{:.0} sessões/s; padi-limit, mac-padi-limit e new-session-rate em 0",
                n as f64 / secs
            ),
        );
    }
    s.check(
        &sc("reconexão sem proteções completa"),
        took.is_some() && wait_long("ppp.active", 60, || active() == n).is_some(),
        format!("ativas {}", active()),
    );

    // Teardown: SIGINT, BNG Blaster sends PADT for each.
    let t3 = Instant::now();
    let report = bl.stop(120 + n as u64 / 500);
    let gone = wait_long("teardown", 120, || active() == 0);
    if let Some(secs) = gone {
        s.put(
            &sc("encerramento"),
            "PADT de todas processados",
            secs.max(t3.elapsed().as_secs_f64()),
            "s",
            &format!("{:.0} sessões/s", n as f64 / t3.elapsed().as_secs_f64()),
        );
    }
    s.check(
        &sc("encerramento completo"),
        gone.is_some(),
        format!("ativas {}", active()),
    );
    let r = report_num(&report, "setup-rate-cps");
    if r.is_finite() {
        s.put(
            &sc("reconexão sem proteções"),
            "taxa segundo o BNG Blaster",
            r,
            "sessões/s",
            "report setup-rate-cps",
        );
    }
    let _ = (t, t2);
}

/// The RADIUS test server on 127.0.0.1, in a thread; returns the ports.
struct Radius {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
    auth: u16,
    acct: u16,
    stats: Arc<Mutex<(u64, u64)>>,
}

impl Radius {
    /// `capacity`: requests answered per second at most (0: as fast as it
    /// can), the rest queued: a saturated MK-Auth/IXC-class server, whose
    /// answer time grows with its queue.
    fn start(users: usize, rate: &str, capacity: u32) -> Self {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let acct = UdpSocket::bind("127.0.0.1:0").unwrap();
        let auth = sock.local_addr().unwrap().port();
        let acct_port = acct.local_addr().unwrap().port();
        let mut srv = TestServer::new(SECRET.as_bytes(), 7);
        for i in 1..=users {
            let mut reply = AttrList::new();
            reply.push_vsa(14988, 8, rate.as_bytes()).unwrap();
            srv.add_user(&format!("rad{i}"), "test", reply);
        }
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = stop.clone();
        let stats = Arc::new(Mutex::new((0u64, 0u64)));
        let stats2 = stats.clone();
        let thread = std::thread::spawn(move || {
            sock.set_read_timeout(Some(Duration::from_millis(5)))
                .unwrap();
            acct.set_read_timeout(Some(Duration::from_millis(5)))
                .unwrap();
            let mut buf = [0u8; 4096];
            let t0 = Instant::now();
            let mut queue: std::collections::VecDeque<(usize, std::net::SocketAddr, Vec<u8>)> =
                std::collections::VecDeque::new();
            let mut tokens = f64::from(capacity);
            let mut at = Instant::now();
            while !stop2.load(Ordering::Relaxed) {
                for (k, s) in [&sock, &acct].into_iter().enumerate() {
                    while let Ok((n, from)) = s.recv_from(&mut buf) {
                        queue.push_back((k, from, buf[..n].to_vec()));
                    }
                }
                if capacity > 0 {
                    let dt = at.elapsed().as_secs_f64();
                    at = Instant::now();
                    tokens = (tokens + dt * f64::from(capacity)).min(f64::from(capacity) / 10.0);
                }
                while let Some((k, from, data)) = queue.front().cloned() {
                    if capacity > 0 {
                        if tokens < 1.0 {
                            break;
                        }
                        tokens -= 1.0;
                    }
                    queue.pop_front();
                    let s = if k == 0 { &sock } else { &acct };
                    if let Some(r) = srv.handle(from, &data, t0.elapsed().as_millis() as u64) {
                        let _ = s.send_to(&r.bytes, r.to);
                    }
                }
                *stats2.lock().unwrap() = (srv.stats.accepts, srv.stats.accounting);
                srv.accounting.clear();
            }
        });
        Self {
            stop,
            thread: Some(thread),
            auth,
            acct: acct_port,
            stats,
        }
    }
}

impl Drop for Radius {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// CoA or Disconnect for `user`; the answer's code and the round trip.
fn dynauth_req(
    dac: &UdpSocket,
    id: u8,
    kind: RequestKind,
    user: &str,
    rate: Option<&str>,
) -> (Option<Code>, f64) {
    let mut l = AttrList::new();
    l.push_text(attr::USER_NAME, user).unwrap();
    if let Some(r) = rate {
        l.push_vsa(14988, 8, r.as_bytes()).unwrap();
    }
    let req = dynauth::build_request(kind, id, &l, SECRET.as_bytes(), true);
    let t = Instant::now();
    dac.send_to(&req, ("127.0.0.1", DAC_PORT)).unwrap();
    let mut buf = [0u8; 4096];
    match dac.recv_from(&mut buf) {
        Ok((n, _)) => (
            Packet::parse(&buf[..n]).ok().map(|p| p.code()),
            t.elapsed().as_secs_f64() * 1000.0,
        ),
        Err(_) => (None, f64::NAN),
    }
}

/// Bits per second received by each session's streams, per direction,
/// over `secs`: from the rx-packets deltas (the policer counts the IP
/// length, the stream's `length`).
fn stream_rates(bl: &Blaster, sessions: &[usize], length: f64, secs: u64) -> Vec<(f64, f64)> {
    let read = |id: usize| -> (f64, f64) {
        let v = bl
            .cmd("session-streams", json!({"session-id": id}))
            .unwrap_or(Value::Null);
        // Every flow object in the answer (the nesting changed between
        // releases): one with a direction and its received packets.
        fn walk(v: &Value, acc: &mut (f64, f64)) {
            match v {
                Value::Object(o) => {
                    if let (Some(d), Some(rx)) = (
                        o.get("direction").and_then(Value::as_str),
                        o.get("rx-packets").and_then(Value::as_f64),
                    ) {
                        match d {
                            "upstream" => acc.0 += rx,
                            "downstream" => acc.1 += rx,
                            _ => {}
                        }
                        return;
                    }
                    o.values().for_each(|x| walk(x, acc));
                }
                Value::Array(a) => a.iter().for_each(|x| walk(x, acc)),
                _ => {}
            }
        }
        let mut acc = (0.0, 0.0);
        walk(&v, &mut acc);
        if id == 1 {
            let _ = std::fs::write(
                bl.report.with_file_name("session-streams-1.json"),
                serde_json::to_string_pretty(&v).unwrap_or_default(),
            );
        }
        acc
    };
    let a: Vec<(f64, f64)> = sessions.iter().map(|&i| read(i)).collect();
    let t = Instant::now();
    std::thread::sleep(Duration::from_secs(secs));
    let b: Vec<(f64, f64)> = sessions.iter().map(|&i| read(i)).collect();
    let dt = t.elapsed().as_secs_f64();
    a.iter()
        .zip(&b)
        .map(|(x, y)| {
            (
                (y.0 - x.0) * length * 8.0 / dt,
                (y.1 - x.1) * length * 8.0 / dt,
            )
        })
        .collect()
}

fn stats(v: &[f64]) -> (f64, f64, f64) {
    let n = v.len().max(1) as f64;
    let mean = v.iter().sum::<f64>() / n;
    let min = v.iter().copied().fold(f64::INFINITY, f64::min);
    let max = v.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    (mean, min, max)
}

/// RADIUS, the policer, CoA and Disconnect under load.
fn radius_policer(lab: &Lab, k: usize, s: &mut Summary) {
    let sc = |x: &str| format!("RADIUS {k} {x}");
    // RouterOS rate-limit, rx/tx from the router: upload 1M, download 2M.
    let (up, down) = (1_000_000.0, 2_000_000.0);
    let rad = Radius::start(k, "1M/2M", 0);
    ok(
        "radius.add",
        json!({"address": "127.0.0.1", "authentication_port": rad.auth, "accounting_port": rad.acct, "service": "ppp", "secret": SECRET}),
    );
    ok(
        "ppp.aaa.set",
        json!({"use_radius": true, "interim_update": 60}),
    );
    ok(
        "radius.incoming.set",
        json!({"accept": true, "port": DAC_PORT}),
    );
    wait_for("radius incoming", || {
        !ok("radius.incoming.get", json!({}))["listening"].is_null()
    });
    lab.servers(false);
    // Streams at twice the rate both ways, 1000-byte IP packets.
    let length = 1000.0;
    let streams = json!([{
        "name": "policer",
        "stream-group-id": 1,
        "type": "ipv4",
        "direction": "both",
        "length": 1000,
        "pps": 2.0 * down / (length * 8.0),
        "pps-upstream": 2.0 * up / (length * 8.0),
    }]);
    let cfg = blaster_config(k, "rad", 0.0, Some(streams));
    let bl = Blaster::start(lab, "radius", &cfg, &["-j", "streams"]);
    let took = wait_long("radius setup", 120, || bl.established() as usize >= k);
    if let Some(secs) = took {
        s.put(
            &sc("setup"),
            "taxa de estabelecimento com RADIUS",
            k as f64 / secs,
            "sessões/s",
            "Access-Request/Accept pelo proto_radius::testserver em 127.0.0.1",
        );
    }
    let (accepts, accts) = *rad.stats.lock().unwrap();
    s.check(
        &sc("todas autenticadas pelo RADIUS"),
        took.is_some() && accepts as usize >= k,
        format!("{accepts} Access-Accept, {accts} Accounting"),
    );
    let rows = ok("ppp.active.list", json!({"limit": 1}))["rows"].clone();
    s.check(
        &sc("Mikrotik-Rate-Limit aplicado"),
        rows[0]["rate_limit"] == "1M/2M",
        format!("{}", rows[0]["rate_limit"]),
    );
    std::thread::sleep(Duration::from_secs(3));
    let ids: Vec<usize> = (1..=k).collect();
    let window = env_or("BNG_LAB_WINDOW", 10u64);
    let rates = stream_rates(&bl, &ids, length, window);
    let ups: Vec<f64> = rates.iter().map(|r| r.0 / up).collect();
    let downs: Vec<f64> = rates.iter().map(|r| r.1 / down).collect();
    let (mu, minu, maxu) = stats(&ups);
    let (md, mind, maxd) = stats(&downs);
    let plane = lab.dataplane();
    let note = format!("{k} sessões, oferecido 2× o limite, janela {window} s, plano {plane}");
    s.put(
        &sc("policer"),
        "subida medida / limite (média)",
        mu,
        "×",
        &note,
    );
    s.put(
        &sc("policer"),
        "subida medida / limite (mín–máx)",
        minu,
        "×",
        &format!("máx {maxu:.3}"),
    );
    s.put(
        &sc("policer"),
        "descida medida / limite (média)",
        md,
        "×",
        &note,
    );
    s.put(
        &sc("policer"),
        "descida medida / limite (mín–máx)",
        mind,
        "×",
        &format!("máx {maxd:.3}"),
    );
    if lab.xdp {
        s.check(
            &sc("policer dentro de 5%"),
            (mu - 1.0).abs() <= 0.05 && (md - 1.0).abs() <= 0.05,
            format!("subida {mu:.3}, descida {md:.3}"),
        );
    } else {
        // The slow path has no policer (G4.3c polices in XDP): the offered
        // traffic passes, which says the slow path forwards 2× the rate.
        s.check(
            &sc("caminho lento encaminha o oferecido"),
            mu > 1.5 && md > 1.5,
            format!("subida {mu:.3}, descida {md:.3} (sem policer fora do XDP)"),
        );
    }

    // CoA: the first tenth gets 2M/4M (= what is offered), the rest stays.
    let tenth = (k / 10).max(1);
    let dac = UdpSocket::bind("127.0.0.1:0").unwrap();
    dac.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let mut acks = 0;
    let mut rtt = Vec::new();
    for i in 1..=tenth {
        let (code, ms) = dynauth_req(
            &dac,
            i as u8,
            RequestKind::Coa,
            &format!("rad{i}"),
            Some("2M/4M"),
        );
        if code == Some(Code::CoaAck) {
            acks += 1;
            rtt.push(ms);
        }
    }
    let (rt, _, rtmax) = stats(&rtt);
    s.put(
        &sc("CoA"),
        "CoA-ACK",
        acks as f64,
        "respostas",
        &format!("de {tenth}; ida e volta média {rt:.2} ms, máx {rtmax:.2} ms"),
    );
    s.check(&sc("CoA aceito"), acks == tenth, format!("{acks}/{tenth}"));
    std::thread::sleep(Duration::from_secs(2));
    let lifted: Vec<usize> = (1..=tenth).collect();
    let rest: Vec<usize> = (tenth + 1..=k).collect();
    let r_l = stream_rates(&bl, &lifted, length, window);
    let r_r = stream_rates(&bl, &rest, length, window);
    let (lu, _, _) = stats(&r_l.iter().map(|r| r.0 / (2.0 * up)).collect::<Vec<_>>());
    let (ld, _, _) = stats(&r_l.iter().map(|r| r.1 / (2.0 * down)).collect::<Vec<_>>());
    let (ru, _, _) = stats(&r_r.iter().map(|r| r.0 / up).collect::<Vec<_>>());
    let (rd, _, _) = stats(&r_r.iter().map(|r| r.1 / down).collect::<Vec<_>>());
    s.put(
        &sc("CoA"),
        "com CoA: subida / novo limite",
        lu,
        "×",
        "2M/4M = o oferecido",
    );
    s.put(&sc("CoA"), "com CoA: descida / novo limite", ld, "×", "");
    s.put(&sc("CoA"), "sem CoA: subida / limite", ru, "×", "1M/2M");
    s.put(&sc("CoA"), "sem CoA: descida / limite", rd, "×", "");
    if lab.xdp {
        s.check(
            &sc("CoA mudou só quem devia"),
            lu > 0.95 && ld > 0.95 && (ru - 1.0).abs() <= 0.05 && (rd - 1.0).abs() <= 0.05,
            format!("com {lu:.3}/{ld:.3}, sem {ru:.3}/{rd:.3}"),
        );
    }
    let rows = ok("ppp.active.list", json!({"find": "rad1", "limit": 1}))["rows"].clone();
    s.check(
        &sc("ppp.active mostra o novo rate"),
        rows[0]["rate_limit"] == "2M/4M",
        format!("{}", rows[0]["rate_limit"]),
    );

    // Disconnect-Request for the second tenth while everything flows.
    let (_, flapped0) = bl.counters();
    let t = Instant::now();
    let mut acks = 0;
    for i in tenth + 1..=2 * tenth {
        let (code, _) = dynauth_req(
            &dac,
            i as u8,
            RequestKind::Disconnect,
            &format!("rad{i}"),
            None,
        );
        if code == Some(Code::DisconnectAck) {
            acks += 1;
        }
    }
    let sent = t.elapsed().as_secs_f64();
    s.put(
        &sc("Disconnect"),
        "Disconnect-ACK",
        acks as f64,
        "respostas",
        &format!("de {tenth} em {:.0} ms", sent * 1000.0),
    );
    s.check(
        &sc("Disconnect aceito"),
        acks == tenth,
        format!("{acks}/{tenth}"),
    );
    let dropped = wait_long("the disconnected drop", 30, || {
        bl.counters().1 >= flapped0 + tenth as u64
    });
    let back = wait_long("the disconnected come back", 60, || {
        bl.established() as usize >= k && active() >= k
    });
    if let (Some(_), Some(b)) = (dropped, back) {
        s.put(
            &sc("Disconnect"),
            "derrubadas e de volta (BNG Blaster reconecta)",
            b + sent,
            "s",
            "",
        );
    }
    s.check(
        &sc("Disconnect derrubou e voltaram"),
        dropped.is_some() && back.is_some(),
        format!("flapped {flapped0} → {}", bl.counters().1),
    );
    let others: Vec<usize> = (2 * tenth + 1..=k).collect();
    let r_o = stream_rates(&bl, &others, length, 3);
    let (od, _, _) = stats(&r_o.iter().map(|r| r.1 / down).collect::<Vec<_>>());
    s.put(
        &sc("Disconnect"),
        "as outras seguem: descida / limite",
        od,
        "×",
        "durante e depois das derrubadas",
    );

    let report = bl.stop(60);
    let _ = std::fs::write(
        lab.out.join("radius-streams.json"),
        serde_json::to_string_pretty(&report["streams"]).unwrap_or_default(),
    );
    wait_long("radius teardown", 60, || active() == 0);
    ok("ppp.aaa.set", json!({"use_radius": false}));
    for r in ok("radius.list", json!({}))
        .as_array()
        .into_iter()
        .flatten()
    {
        ok("radius.remove", json!({"id": r["id"]}));
    }
}

/// RADIUS timeouts and resends of the configured servers so far.
fn radius_counts() -> (u64, u64) {
    ok("radius.monitor", json!({}))
        .as_array()
        .into_iter()
        .flatten()
        .fold((0, 0), |(t, r), m| {
            (
                t + m["timeouts"].as_u64().unwrap_or(0),
                r + m["resends"].as_u64().unwrap_or(0),
            )
        })
}

/// The mass reconnect against a RADIUS server that answers at most
/// `capacity` requests a second (G4.3g): every CPE at once, with
/// `new_session_rate` off, fixed at 2000 and `auto`. Off buries the
/// server in retransmissions; fixed above its capacity fills its queue
/// past the timeout; auto should follow it.
fn radius_wave(lab: &Lab, n: usize, capacity: u32, s: &mut Summary) {
    let rad = Radius::start(n, "10M/20M", capacity);
    ok(
        "radius.add",
        json!({"address": "127.0.0.1", "authentication_port": rad.auth, "accounting_port": rad.acct, "service": "ppp", "secret": SECRET}),
    );
    ok(
        "ppp.aaa.set",
        json!({"use_radius": true, "interim_update": 0}),
    );
    let sc = format!("onda {}k RADIUS {capacity}/s", n / 1000);
    for (mode, rate) in [
        ("desligado", json!(0)),
        ("fixo 2000", json!(2000)),
        ("auto", json!("auto")),
    ] {
        for name in (0..lab.ports).map(|i| format!("pppoe-acc{i}")) {
            ok(
                "interface.pppoe-server.server.set",
                json!({"id": name, "new_session_rate": rate, "padi_limit": 0, "mac_padi_limit": 0}),
            );
        }
        // The service reads the config once a second.
        std::thread::sleep(Duration::from_millis(1500));
        let (t0, r0) = radius_counts();
        let mut cfg = blaster_config(n, "rad", 0.0, None);
        // Every CPE at once, as after a power cut: BNG Blaster's own pacing
        // out of the way.
        cfg["sessions"]["max-outstanding"] = json!(n.min(60_000));
        cfg["sessions"]["start-rate"] = json!(50_000);
        cfg["session-traffic"] = json!({"autostart": false, "ipv4-pps": 0});
        let tag = mode.replace(' ', "-");
        let bl = Blaster::start(lab, &format!("wave-{tag}"), &cfg, &[]);
        let limit = 120 + n as u64 / 200;
        let mut peak = 0u64;
        let t = Instant::now();
        let took = wait_long("the wave", limit, || {
            let m = ok("interface.pppoe-server.monitor", json!({}));
            peak = peak.max(m["admission_rate"].as_u64().unwrap_or(0));
            bl.established() as usize >= n
        });
        let (t1, r1) = radius_counts();
        let note = format!(
            "timeouts do RADIUS {}, retransmissões {}{}",
            t1 - t0,
            r1 - r0,
            if mode == "auto" {
                format!(", pico do limite {peak}/s")
            } else {
                String::new()
            }
        );
        match took {
            Some(secs) => s.put(
                &sc,
                &format!("{mode}: todas no ar"),
                secs,
                "s",
                &format!("{:.0} sessões/s; {note}", n as f64 / secs),
            ),
            None => s.put(
                &sc,
                &format!("{mode}: no ar (incompleto)"),
                bl.established() as f64,
                "sessões",
                &format!("de {n} em {limit} s; {note}"),
            ),
        }
        s.check(
            &format!("{sc} {mode} completa"),
            took.is_some(),
            format!("{:.0} s", t.elapsed().as_secs_f64()),
        );
        let _ = bl.stop(120 + n as u64 / 500);
        wait_long("wave teardown", 180, || active() == 0);
    }
    ok("ppp.aaa.set", json!({"use_radius": false}));
    for r in ok("radius.list", json!({}))
        .as_array()
        .into_iter()
        .flatten()
    {
        ok("radius.remove", json!({"id": r["id"]}));
    }
    drop(rad);
}

/// A short run of one subscriber with BNG Blaster's capture, for the
/// goldens of `proto-pppoe`.
fn capture(lab: &Lab, s: &mut Summary) {
    lab.servers(false);
    let cfg = blaster_config(1, "user", 1.0, None);
    let pcap = lab.out.join("bngblaster-1.pcap");
    let bl = Blaster::start(lab, "capture", &cfg, &["-P", &pcap.to_string_lossy()]);
    let up = wait_long("one session", 30, || bl.established() >= 1);
    std::thread::sleep(Duration::from_secs(3));
    let _ = bl.stop(30);
    wait_long("capture teardown", 30, || active() == 0);
    s.check(
        "captura BNG Blaster (1 sessão)",
        up.is_some() && pcap.exists(),
        pcap.display().to_string(),
    );
}

/// The Linux client: `pppd` with the kernel PPPoE plugin (root only:
/// `/dev/ppp`).
fn pppd(lab: &Lab, s: &mut Summary) {
    let b = lab.b.0.id();
    let plugin = ["rp-pppoe.so", "pppoe.so"]
        .into_iter()
        .find(|p| {
            std::fs::read_dir("/usr/lib/pppd")
                .into_iter()
                .flatten()
                .flatten()
                .any(|d| d.path().join(p).exists())
        })
        .unwrap_or("pppoe.so");
    let pcap = lab.out.join("pppd.pcap");
    let dump = in_ns(Some(b), "tcpdump")
        .args(["-i", "cpe9", "-U", "-s", "0", "-w"])
        .arg(&pcap)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()
        .map(Kill);
    std::thread::sleep(Duration::from_millis(500));
    let log = lab.out.join("pppd.log");
    let run = |user: &str, unit: &str| -> Kill {
        Kill(
            in_ns(Some(b), "pppd")
                .args([
                    "plugin",
                    plugin,
                    "nic-cpe9",
                    "user",
                    user,
                    "password",
                    "test",
                    "noauth",
                    "nodetach",
                    "noipdefault",
                    "nodefaultroute",
                    "noccp",
                    "novj",
                    "nopcomp",
                    "noaccomp",
                    "lcp-echo-interval",
                    "1",
                    "lcp-echo-failure",
                    "3",
                    "unit",
                    unit,
                    "ip-up-script",
                    "/bin/true",
                    "ip-down-script",
                    "/bin/true",
                    "logfile",
                ])
                .arg(&log)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        )
    };
    let ppp_ip = |unit: &str| -> Option<Ipv4Addr> {
        let out = in_ns(Some(b), "ip")
            .args(["-4", "-o", "addr", "show", "dev", &format!("ppp{unit}")])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        text.split("inet ")
            .nth(1)?
            .split(['/', ' '])
            .next()?
            .parse()
            .ok()
    };
    // The internet for pppd: blnet (BNG Blaster's network port until
    // now) moves to a namespace C where the kernel answers on
    // 198.51.100.2; a reply from the BNG itself would need the kernel path
    // to the subscriber with XDP (G4.3ca).
    let c = Kill(
        Command::new("unshare")
            .args(["--net", "--", "sleep", "86400"])
            .spawn()
            .unwrap(),
    );
    let bns = netns_of(b);
    wait_for("C's namespace", || {
        netns_of(c.0.id()).is_some_and(|ns| Some(ns) != bns)
    });
    let cpid = c.0.id();
    ip(
        Some(b),
        &["link", "set", "blnet", "netns", &cpid.to_string()],
    );
    for a in [
        vec!["link", "set", "lo", "up"],
        vec!["addr", "add", "198.51.100.2/24", "dev", "blnet"],
        vec!["link", "set", "blnet", "up"],
        vec!["route", "add", "100.64.0.0/10", "via", "198.51.100.1"],
    ] {
        ip(Some(cpid), &a);
    }
    let p = run("user1", "0");
    let up = wait_long("pppd up", 30, || ppp_ip("0").is_some());
    let ip = ppp_ip("0");
    s.check(
        "pppd: sessão sobe",
        up.is_some(),
        format!("{ip:?} em {:?} s", up),
    );
    let row = ok("ppp.active.list", json!({"find": "user1", "limit": 1}))["rows"][0].clone();
    s.check(
        "pppd: daemon vê a sessão",
        row["server"] == "pppoe-acc9",
        format!("encoding {}, mtu {}", row["encoding"], row["mtu"]),
    );
    let _ = in_ns(Some(b), "ip")
        .args(["route", "add", "198.51.100.0/24", "dev", "ppp0"])
        .status();
    let ping = in_ns(Some(b), "ping")
        .args(["-c", "3", "-W", "2", "198.51.100.2"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    s.check(
        "pppd: ping pelo túnel",
        ping,
        "198.51.100.2 via ppp0 e o BNG".into(),
    );
    // LCP echo every second: still up after 5.
    std::thread::sleep(Duration::from_secs(5));
    s.check(
        "pppd: keepalive (LCP echo 1 s)",
        ppp_ip("0").is_some(),
        String::new(),
    );
    // Termination from the BNG: pppd must notice (LCP TermReq / PADT).
    let id = row["id"].as_str().unwrap_or("").to_owned();
    ok("ppp.active.remove", json!({"id": id}));
    let gone = wait_long("pppd down", 15, || ppp_ip("0").is_none());
    s.check(
        "pppd: derrubada pelo BNG",
        gone.is_some(),
        format!("{gone:?} s"),
    );
    drop(p);
    wait_long("pppd's session gone", 15, || active() == 0);
    // Termination from the client: SIGTERM, pppd sends LCP TermReq + PADT.
    let p = Kill(
        in_ns(Some(b), "pppd")
            .args([
                "plugin",
                plugin,
                "nic-cpe9",
                "user",
                "user2",
                "password",
                "test",
                "noauth",
                "nodetach",
                "noipdefault",
                "nodefaultroute",
                "unit",
                "1",
                "ip-up-script",
                "/bin/true",
                "ip-down-script",
                "/bin/true",
                "logfile",
            ])
            .arg(&log)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let up = wait_long("pppd 2 up", 30, || ppp_ip("1").is_some());
    let _ = Command::new("kill")
        .args(["-TERM", &p.0.id().to_string()])
        .status();
    let left = wait_long("the daemon sees PADT", 15, || active() == 0);
    s.check(
        "pppd: cliente encerra (PADT)",
        up.is_some() && left.is_some(),
        format!("{left:?} s"),
    );
    drop(p);
    drop(dump);
    drop(c);
    s.check("captura pppd", pcap.exists(), pcap.display().to_string());
}

#[test]
fn bng_lab() {
    if std::env::var_os("COREROUTER_BNG_LAB").is_none_or(|v| v != "1") {
        eprintln!("skipped: cargo xtask bng-lab (needs BNG Blaster)");
        return;
    }
    let names = sh("ip", &["-o", "link", "show"]);
    assert_eq!(
        names.lines().count(),
        1,
        "COREROUTER_BNG_LAB=1 but this namespace has more than lo; refusing to touch it"
    );
    let blaster =
        PathBuf::from(std::env::var("BNGBLASTER").unwrap_or_else(|_| "bngblaster".into()));
    let out = PathBuf::from(
        std::env::var("BNG_LAB_OUT").unwrap_or_else(|_| "/tmp/corerouter-bng-lab".into()),
    );
    std::fs::create_dir_all(&out).unwrap();
    let root = std::env::var_os("BNG_LAB_ROOT").is_some_and(|v| v == "1");
    let scales: Vec<usize> = std::env::var("BNG_LAB_SCALES")
        .unwrap_or_else(|_| "1000,10000,100000".into())
        .split(',')
        .filter_map(|v| v.trim().parse().ok())
        .collect();
    let k = env_or("BNG_LAB_RADIUS", 100usize);
    let max = scales.iter().copied().max().unwrap_or(1000).max(k);
    let ports = max.div_ceil(PER_PORT).max(1);
    let lab = Lab::new(ports, out.clone(), blaster.clone(), root);
    let mut s = Summary::default();

    ok(
        "ip.pool.add",
        json!({"name": "lab", "ranges": "100.64.0.0/14"}),
    );
    ok(
        "ppp.profile.set",
        json!({"id": "default", "remote_address": "lab", "local_address": "100.127.255.254", "dns_server": "198.51.100.53"}),
    );
    let t = Instant::now();
    let steps: Vec<Value> = (1..=max)
        .map(|i| json!({"command": "ppp.secret.add", "params": {"name": format!("user{i}"), "password": "test"}}))
        .collect();
    batch(steps);
    s.put(
        "config",
        "ppp.secret.add em lote",
        max as f64 / t.elapsed().as_secs_f64(),
        "secrets/s",
        &format!("{max} secrets por engine.batch (10 mil por transação)"),
    );
    lab.servers(false);
    wait_for("the pppoe service", || {
        ok("system.service.print", json!({}))
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["name"] == "pppoe" && r["state"] == "running")
    });
    std::thread::sleep(Duration::from_secs(1));

    let only: Vec<String> = std::env::var("BNG_LAB_ONLY")
        .unwrap_or_default()
        .split(',')
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
        .collect();
    let want = |x: &str| only.is_empty() || only.iter().any(|o| o == x);
    if want("capture") {
        capture(&lab, &mut s);
    }
    if want("scale") {
        for &n in &scales {
            scale(&lab, n, &mut s);
        }
    }
    if want("radius") {
        radius_policer(&lab, k, &mut s);
    }
    if want("wave") {
        let n = env_or("BNG_LAB_WAVE", 100_000usize).min(max);
        radius_wave(&lab, n, env_or("BNG_LAB_RADIUS_CAP", 3000u32), &mut s);
    }
    if root && want("pppd") {
        pppd(&lab, &mut s);
    }

    let version = Command::new(&blaster)
        .arg("-v")
        .output()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .next()
                .unwrap_or("")
                .to_owned()
        })
        .unwrap_or_default();
    let cpu = std::fs::read_to_string("/proc/cpuinfo")
        .unwrap_or_default()
        .lines()
        .find_map(|l| l.strip_prefix("model name"))
        .map(|v| v.trim_start_matches([' ', '\t', ':']).to_owned())
        .unwrap_or_default();
    let meta = json!({
        "data": sh("date", &["-u", "+%Y-%m-%d %H:%M UTC"]).trim(),
        "máquina": format!("{cpu}, {} CPUs", std::thread::available_parallelism().map_or(0, |n| n.get())),
        "kernel": sh("uname", &["-r"]).trim(),
        "build": if cfg!(debug_assertions) { "debug" } else { "release" },
        "plano de dados": lab.dataplane(),
        "root": root,
        "BNG Blaster": version,
        "portas de acesso": ports,
    });
    s.write(&out, &meta);
    eprintln!("lab: summary in {}", out.join("summary.md").display());
    let failed: Vec<&String> = s.checks.iter().filter(|c| !c.1).map(|c| &c.0).collect();
    assert!(failed.is_empty(), "lab checks failed: {failed:?}");
}

/// Not a test: BNG Blaster's configs of every stage into
/// `$BNG_LAB_DUMP`, to check them against the JSON schema it ships
/// (`/usr/share/bngblaster/bngblaster-config.json`).
#[test]
#[ignore]
fn dump_configs() {
    let dir = PathBuf::from(std::env::var("BNG_LAB_DUMP").unwrap());
    std::fs::create_dir_all(&dir).unwrap();
    let streams = json!([{"name": "policer", "stream-group-id": 1, "type": "ipv4", "direction": "both", "length": 1000, "pps": 500.0, "pps-upstream": 250.0}]);
    for (name, cfg) in [
        ("scale-100k", blaster_config(100_000, "user", 0.2, None)),
        ("radius", blaster_config(100, "rad", 0.0, Some(streams))),
    ] {
        std::fs::write(
            dir.join(format!("{name}.json")),
            serde_json::to_string_pretty(&cfg).unwrap(),
        )
        .unwrap();
    }
}
