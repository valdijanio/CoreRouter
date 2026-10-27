//! G3.1: how to talk to FRR, measured against a real FRR (run as root in
//! the lab VM: `scripts/frr-compare.sh`, docs/architecture.md "Plano de
//! controle").
//!
//! Compares, on the same configs:
//! - (a) `frr-reload.py --reload <file>` (Python, starts vtysh) and reading
//!   state with `vtysh -c '… json'`;
//! - (b) hal-frr: diff in Rust, typed on the daemons' vty sockets, state
//!   read on the same sockets, no process;
//! - (c) mixed: the Rust diff fed to `vtysh -f` (one process per apply).
//!
//! Usage: `frr_compare <vty dir> [routes]` (default /var/run/frr, 1000000).

use std::error::Error;
use std::fmt::Write as _;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use corerouter_hal_frr::conf::{self, Conf};
use corerouter_hal_frr::render::{self, Daemon, Owned};
use corerouter_hal_frr::{Frr, MAX_REPLY};

type Res<T> = Result<T, Box<dyn Error>>;

/// What the benchmark owns: BGP, and prefix-lists where they are typed:
/// mgmtd (which hands them to zebra, a converted daemon) and bgpd (not
/// converted).
const OWNED: Owned = &[
    ("router bgp ", &[Daemon::Bgpd]),
    ("ip prefix-list ", &[Daemon::Mgmtd, Daemon::Bgpd]),
];
/// Where the result is checked: zebra too.
const CHECK: Owned = &[
    ("router bgp ", &[Daemon::Bgpd]),
    (
        "ip prefix-list ",
        &[Daemon::Zebra, Daemon::Mgmtd, Daemon::Bgpd],
    ),
];
const RELOAD: &str = "/usr/lib/frr/frr-reload.py";
const PEERS: u32 = 100;
const ENTRIES: u32 = 10_000;

fn bgp(router_id: &str, desc: &str) -> String {
    let mut s =
        format!("router bgp 65000\n bgp router-id {router_id}\n no bgp default ipv4-unicast\n");
    for i in 0..PEERS {
        let _ = writeln!(
            s,
            " neighbor 127.1.{}.{} remote-as {}",
            i / 200,
            i % 200 + 1,
            65001 + i
        );
        let _ = writeln!(
            s,
            " neighbor 127.1.{}.{} description {desc}{i}",
            i / 200,
            i % 200 + 1
        );
    }
    s.push_str("exit\n");
    s
}

fn prefix_lists(n: u32) -> String {
    let mut s = String::new();
    for i in 0..n {
        let _ = writeln!(
            s,
            "ip prefix-list BIG seq {} permit 10.{}.{}.0/24",
            (i + 1) * 5,
            i / 256,
            i % 256
        );
    }
    s
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

/// Peak RSS (KiB) of this process so far.
fn hwm_kib() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    status
        .lines()
        .find_map(|l| l.strip_prefix("VmHWM:"))
        .and_then(|v| v.trim().trim_end_matches("kB").trim().parse().ok())
        .unwrap_or(0)
}

/// Run `cmd`, returning wall time and the peak RSS (KiB) seen by polling
/// /proc while it runs (the process tree's root only).
fn timed(cmd: &mut Command) -> Res<(Duration, u64, Vec<u8>)> {
    let t = Instant::now();
    let child = cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
    let pid = child.id();
    let peak = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let p2 = peak.clone();
    let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let d2 = done.clone();
    let poll = std::thread::spawn(move || {
        while !d2.load(std::sync::atomic::Ordering::Relaxed) {
            if let Ok(s) = std::fs::read_to_string(format!("/proc/{pid}/status"))
                && let Some(v) = s
                    .lines()
                    .find_map(|l| l.strip_prefix("VmHWM:"))
                    .and_then(|v| v.trim().trim_end_matches("kB").trim().parse::<u64>().ok())
            {
                p2.fetch_max(v, std::sync::atomic::Ordering::Relaxed);
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    });
    let out = child.wait_with_output()?;
    let el = t.elapsed();
    done.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = poll.join();
    if !out.status.success() {
        return Err(format!(
            "{:?} failed: {}",
            cmd,
            String::from_utf8_lossy(&out.stderr)
                .chars()
                .take(400)
                .collect::<String>()
        )
        .into());
    }
    Ok((
        el,
        peak.load(std::sync::atomic::Ordering::Relaxed),
        out.stdout,
    ))
}

struct Report(String);

impl Report {
    fn row(&mut self, what: &str, how: &str, t: Duration, mem: Option<u64>, extra: &str) {
        let mem = mem.map_or("—".into(), |k| format!("{:.1} MiB", k as f64 / 1024.0));
        let line = format!("| {what} | {how} | {:.1} ms | {mem} | {extra} |", ms(t));
        println!("{line}");
        self.0.push_str(&line);
        self.0.push('\n');
    }
}

/// The whole frr.conf frr-reload.py wants: what FRR runs outside the
/// owned contexts, plus `owned`.
fn full_conf(frr: &Frr, owned: &str) -> Res<String> {
    let mut vty = frr.connect(Daemon::Bgpd)?;
    let r = vty.run("show running-config")?;
    let all = Conf::parse(&String::from_utf8_lossy(&r.output))?;
    let rest = all.owned(|l| !OWNED.iter().any(|(p, _)| l.starts_with(p)));
    Ok(format!("{}{owned}", rest.render()))
}

fn apply_rust(frr: &Frr, text: &str) -> Res<Duration> {
    let t = Instant::now();
    frr.sync(&Conf::parse(text)?)?;
    Ok(t.elapsed())
}

fn apply_reload(frr: &Frr, text: &str) -> Res<(Duration, u64)> {
    let file = "/tmp/crfrr-compare.conf";
    std::fs::write(file, full_conf(frr, text)?)?;
    let (t, mem, _) = timed(Command::new(RELOAD).args(["--reload", file]))?;
    Ok((t, mem))
}

fn apply_vtysh_f(frr: &Frr, text: &str) -> Res<(Duration, u64)> {
    let t0 = Instant::now();
    let mut vty = frr.connect(Daemon::Bgpd)?;
    let now = frr.running(&mut vty, Daemon::Bgpd)?;
    let script = conf::diff(&now, &Conf::parse(text)?);
    let file = "/tmp/crfrr-compare.vtysh";
    let body = format!("{}\n", script.join("\n"));
    std::fs::write(file, body)?;
    let (_, mem, _) = timed(Command::new("vtysh").args(["-f", file]))?;
    Ok((t0.elapsed(), mem))
}

/// "" when every daemon runs its part of `text`, else how far it is.
fn check(frr: &Frr, text: &str) -> Res<String> {
    let frr = Frr::new(frr.dir()).with_owned(CHECK);
    let want = Conf::parse(text)?;
    let mut left = Vec::new();
    for d in [Daemon::Bgpd, Daemon::Zebra, Daemon::Mgmtd] {
        let mut vty = frr.connect(d)?;
        let now = frr.running(&mut vty, d)?;
        let part = want
            .clone()
            .owned(|l| render::daemons_of(CHECK, l).contains(&d));
        left.extend(
            conf::diff(&now, &part)
                .into_iter()
                .map(|l| format!("{}: {l}", d.name())),
        );
    }
    Ok(match left.first() {
        None => "resultado conferido".into(),
        Some(first) => format!("DIFERENTE: faltam {} comando(s), ex. `{first}`", left.len()),
    })
}

fn main() -> Res<()> {
    let args: Vec<String> = std::env::args().collect();
    let dir = args.get(1).map_or("/var/run/frr", String::as_str);
    let routes: u32 = args.get(2).map_or(Ok(1_000_000), |s| s.parse())?;
    // `routes-only`: skip the applies (the script loads the routes between
    // two runs, so zebra's import does not slow the applies down).
    let routes_only = args.get(3).is_some_and(|a| a == "routes-only");
    let frr = Frr::new(dir).with_owned(OWNED);
    let big = Frr::new(dir).with_owned(OWNED).with_max_reply(4 << 30);
    println!("{}", frr.version()?);
    let mut rep = Report(String::new());
    println!("| Medida | Forma | Tempo | Memória (pico) | Nota |\n|---|---|---|---|---|");

    if !routes_only {
        let base = bgp("10.0.0.1", "peer");
        let small = bgp("10.0.0.2", "peer");
        let small2 = bgp("10.0.0.2", "edge");
        let with_big = format!("{small2}{}", prefix_lists(ENTRIES));
        let with_big2 = format!("{small2}{}", prefix_lists(ENTRIES / 2));

        // Start from nothing owned.
        apply_rust(&frr, "")?;
        let t = apply_rust(&frr, &base)?;
        rep.row(
            "carga inicial (BGP com 100 vizinhos, 201 linhas)",
            "(b) vty Rust",
            t,
            None,
            "",
        );

        for (label, from, to) in [
            ("mudança pequena (router-id)", &base, &small),
            ("mudança pequena (100 descrições)", &small, &small2),
            ("mudança grande (+10 mil prefix-list)", &small2, &with_big),
            ("mudança grande (−5 mil prefix-list)", &with_big, &with_big2),
        ] {
            for how in [
                "(b) vty Rust",
                "(c) diff Rust + vtysh -f",
                "(a) frr-reload.py",
            ] {
                // Each run starts from `from`.
                apply_rust(&frr, from)?;
                let (t, mem) = match how {
                    "(b) vty Rust" => {
                        let before = hwm_kib();
                        let t = apply_rust(&frr, to)?;
                        (t, Some(hwm_kib().max(before)))
                    }
                    "(c) diff Rust + vtysh -f" => {
                        let (t, m) = apply_vtysh_f(&frr, to)?;
                        (t, Some(m))
                    }
                    _ => {
                        let (t, m) = apply_reload(&frr, to)?;
                        (t, Some(m))
                    }
                };
                let ok = check(&frr, to)?;
                rep.row(label, how, t, mem, &ok);
            }
        }

        // State: 100 sessions (configured; they stay Active, the JSON per
        // neighbor is the same size as an established one's minus the
        // address-family block).
        apply_rust(&frr, &small2)?;
        let cfg = corerouter_model::Config::default();
        let n = 20;
        let t = Instant::now();
        let mut count = 0;
        for _ in 0..n {
            let mut vty = frr.connect(Daemon::Bgpd)?;
            let r = vty.run("show bgp vrf all neighbors json")?;
            let text = String::from_utf8_lossy(&r.output);
            count = corerouter_hal_frr::state::bgp_sessions(&text, None, &|v| v.to_owned())?.len();
        }
        rep.row(
            "ler 100 sessões (neighbors json + parse)",
            "(b) vty Rust",
            t.elapsed() / n,
            Some(hwm_kib()),
            &format!("{count} sessões, média de {n}"),
        );
        let _ = cfg;
        let mut tv = Duration::ZERO;
        let mut mv = 0;
        for _ in 0..n {
            let t = Instant::now();
            let (_, m, out) =
                timed(Command::new("vtysh").args(["-c", "show bgp vrf all neighbors json"]))?;
            let text = String::from_utf8_lossy(&out);
            count = corerouter_hal_frr::state::bgp_sessions(&text, None, &|v| v.to_owned())?.len();
            tv += t.elapsed();
            mv = mv.max(m);
        }
        rep.row(
            "ler 100 sessões (neighbors json + parse)",
            "(a) vtysh -c",
            tv / n,
            Some(mv),
            &format!("{count} sessões, média de {n}"),
        );
    }

    // 1 M routes in zebra (kernel routes it imported).
    if routes > 0 {
        // scripts/frr-compare.sh put them in the kernel; zebra imports them.
        let t = Instant::now();
        loop {
            let mut z = frr.connect(Daemon::Zebra)?;
            let r = z.run("show ip route summary json")?;
            let v: serde_json::Value = serde_json::from_slice(&r.output)?;
            let fib = v
                .get("routesTotal")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            if fib >= u64::from(routes) || t.elapsed() > Duration::from_secs(600) {
                println!(
                    "zebra: {fib} rotas na FIB depois de {:.1} s",
                    t.elapsed().as_secs_f64()
                );
                break;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        let before = hwm_kib();
        let t = Instant::now();
        let mut z = big.connect(Daemon::Zebra)?;
        let r = z.run("show ip route json")?;
        let read = t.elapsed();
        let bytes = r.output.len();
        rep.row(
            "ler 1 M rotas (show ip route json, só bytes)",
            "(b) vty Rust",
            read,
            Some(hwm_kib().max(before)),
            &format!("{:.0} MiB de JSON", bytes as f64 / 1048576.0),
        );
        let t = Instant::now();
        let v: serde_json::Value = serde_json::from_slice(&r.output)?;
        let n_pfx = v.as_object().map_or(0, serde_json::Map::len);
        drop(v);
        rep.row(
            "ler 1 M rotas (parse serde_json::Value)",
            "(b) vty Rust",
            t.elapsed(),
            Some(hwm_kib()),
            &format!("{n_pfx} prefixos"),
        );
        drop(r);
        let (t, m, out) = timed(Command::new("vtysh").args(["-c", "show ip route json"]))?;
        rep.row(
            "ler 1 M rotas (show ip route json, só bytes)",
            "(a) vtysh -c",
            t,
            Some(m),
            &format!("{:.0} MiB de JSON", out.len() as f64 / 1048576.0),
        );
        drop(out);
        let t = Instant::now();
        let mut z = frr.connect(Daemon::Zebra)?;
        let r = z.run("show ip route summary json")?;
        rep.row(
            "resumo de 1 M rotas (summary json)",
            "(b) vty Rust",
            t.elapsed(),
            None,
            &format!("{} bytes", r.output.len()),
        );
        let (t, m, _) = timed(Command::new("vtysh").args(["-c", "show ip route summary json"]))?;
        rep.row(
            "resumo de 1 M rotas (summary json)",
            "(a) vtysh -c",
            t,
            Some(m),
            "",
        );
    }
    // Leave nothing owned behind.
    apply_rust(&frr, "")?;
    let _ = MAX_REPLY;
    std::fs::write("/tmp/frr-compare.md", rep.0)?;
    Ok(())
}
