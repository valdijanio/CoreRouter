//! Parsers against real files of one machine (AMD Ryzen AI Max+ 395,
//! NVMe, Realtek r8169, MediaTek mt7925 wifi; `tests/fixtures/resource`),
//! odd and truncated content, and garbage (proptest).

use std::path::{Path, PathBuf};

use proptest::prelude::*;

use super::*;

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/resource")
}

fn fixture(rel: &str) -> String {
    std::fs::read_to_string(fixtures().join(rel)).unwrap()
}

fn fake_statvfs(p: &Path) -> Option<(u64, u64, u64)> {
    match p.to_str()? {
        "/" => Some((1_000_000_000_000, 400_000_000_000, 350_000_000_000)),
        "/boot/efi" => Some((1_000_000_000, 900_000_000, 900_000_000)),
        _ => None,
    }
}

fn collector() -> Collector {
    let root = fixtures();
    Collector::at(&root.join("proc"), &root.join("sys")).with_statvfs(fake_statvfs)
}

#[test]
fn stat_has_every_core_of_the_ryzen() {
    let (all, cores) = parse_stat(&fixture("proc/stat"));
    assert_eq!(cores.len(), 32);
    assert_eq!(all.user, 64_457_081);
    assert_eq!(all.softirq, 1_562_653);
    let sum: u64 = cores.iter().map(CpuTimes::total).sum();
    // The `cpu` line is the sum of the cores, give or take a tick each.
    assert!(
        all.total().abs_diff(sum) <= 4 * 32,
        "{} vs {sum}",
        all.total()
    );
    assert!(all.busy() < all.total());
}

#[test]
fn meminfo_in_bytes() {
    let m = parse_meminfo(&fixture("proc/meminfo"));
    assert_eq!(m.total, 65_462_728 * 1024);
    assert_eq!(m.available, 44_848_892 * 1024);
    assert!(m.available <= m.total && m.available > 0);
    assert!(m.swap_total >= m.swap_free);
    // Old kernels without MemAvailable.
    let old = parse_meminfo("MemTotal: 1000 kB\nMemFree: 100 kB\nBuffers: 50 kB\nCached: 200 kB\n");
    assert_eq!(old.available, 350 * 1024);
    // `MemTotalX:` is not `MemTotal:`.
    assert_eq!(parse_meminfo("MemTotalX: 5 kB\n").total, 0);
}

#[test]
fn loadavg_uptime_and_pressure() {
    let l = parse_loadavg(&fixture("proc/loadavg")).unwrap();
    assert!((l.one - 10.36).abs() < 0.001);
    assert_eq!((l.running, l.tasks), (5, 6068));
    assert_eq!(parse_uptime(&fixture("proc/uptime")), Some(971_095_790));
    let p = parse_psi(&fixture("proc/pressure/memory")).unwrap();
    assert_eq!((p.some60, p.full10), (0.0, Some(0.0)));
    let io = parse_psi("some avg10=0.10 avg60=0.11 avg300=0.16 total=4364652636\nfull avg10=0.05 avg60=0.08 avg300=0.14 total=4192263736\n").unwrap();
    assert!((io.some60 - 0.11).abs() < 0.001);
    assert!((io.full300.unwrap() - 0.14).abs() < 0.001);
    // cpu before 5.13: no `full` line.
    let cpu = parse_psi("some avg10=1.00 avg60=2.00 avg300=3.00 total=5\n").unwrap();
    assert_eq!(cpu.full10, None);
    assert_eq!(parse_psi("some avg10=x avg60=1 avg300=1"), None);
    assert_eq!(parse_loadavg("nan 1 1 1/1 1"), None);
    assert_eq!(parse_uptime("-5 0"), None);
    assert_eq!(parse_uptime("inf 0"), None);
}

#[test]
fn softirqs_and_interrupts_per_cpu() {
    let mut irqs = parse_softirqs(&fixture("proc/softirqs"));
    assert_eq!(irqs.len(), 32);
    assert_eq!(irqs.first().unwrap().net_rx, 20_089_864);
    assert!(irqs.iter().all(|c| c.softirqs >= c.net_rx + c.net_tx));
    parse_interrupts(&fixture("proc/interrupts"), &mut irqs);
    assert!(irqs.iter().all(|c| c.irqs > 0));
    // ERR:/MIS: rows (one count) are not added to CPU0.
    let mut two = vec![CpuIrqs::default(); 2];
    parse_interrupts("  CPU0 CPU1\n 0: 5 7 IO-APIC\nERR: 1000\n", &mut two);
    assert_eq!((two[0].irqs, two[1].irqs), (5, 7));
}

#[test]
fn diskstats_vmstat_net_and_mounts() {
    let d = parse_diskstats(&fixture("proc/diskstats"));
    let nvme = d.iter().find(|d| d.name == "nvme0n1").unwrap();
    assert_eq!(nvme.read_sectors, 489_241_630);
    assert_eq!(nvme.write_sectors, 8_588_740_842);
    let (oom, si, so) = parse_vmstat(&fixture("proc/vmstat"));
    assert!(oom.is_some() && si.is_some() && so.is_some());
    assert_eq!(parse_vmstat("oom_kill_x 5\noom_kill 3\n").0, Some(3));
    let net = parse_net_dev(&fixture("proc/net/dev"));
    let wifi = net.iter().find(|n| n.name == "wlp195s0").unwrap();
    assert_eq!(wifi.rx_bytes, 61_845_906_659);
    assert_eq!(wifi.tx_dropped, 150);
    assert!(net.iter().all(|n| !n.name.contains('|')), "headers skipped");
    let m = parse_mounts(&fixture("proc/mounts"));
    assert!(
        m.iter().any(|(_, mnt, fs)| mnt == "/" && fs == "ext4"),
        "{m:?}"
    );
    let m = parse_mounts(
        "/dev/sda1 /mnt/my\\040disk ext4 rw 0 0\n/dev/sda1 /again ext4 rw 0 0\ntmpfs /tmp tmpfs rw 0 0\n",
    );
    assert_eq!(
        m,
        vec![("/dev/sda1".into(), "/mnt/my disk".into(), "ext4".into())]
    );
}

#[test]
fn open_descriptors_are_counted() {
    let dir = std::env::temp_dir().join(format!("cr-fds-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    for f in ["0", "1", "2"] {
        std::fs::write(dir.join(f), "").unwrap();
    }
    assert_eq!(count_fds(&dir), Some(3));
    std::fs::remove_dir_all(&dir).unwrap();
    assert_eq!(count_fds(&dir), None, "unreadable: not zero");
    let own = count_fds(Path::new("/proc/self/fd")).unwrap();
    assert!(own >= 3, "{own}");
}

#[test]
fn process_names_with_spaces_and_parentheses() {
    let p = parse_pid_stat(&fixture("proc/1/stat"), 4096).unwrap();
    assert_eq!(
        (p.pid, p.ppid, p.name.as_str(), p.state),
        (1, 0, "systemd", 'S')
    );
    assert_eq!(p.cpu_ticks, 2712 + 1922);
    assert_eq!(p.rss_bytes, 3328 * 4096);
    let odd = "42 (a (b) c) R 1 0 0 0 -1 0 0 0 0 0 7 3 0 0 20 0 5 0 1 1 9 1";
    let p = parse_pid_stat(odd, 4096).unwrap();
    assert_eq!(
        (p.name.as_str(), p.cpu_ticks, p.threads, p.rss_bytes),
        ("a (b) c", 10, 5, 9 * 4096)
    );
    assert_eq!(parse_pid_stat("42 (cut", 4096), None);
    assert_eq!(
        parse_pid_stat("42 (x) R 1", 4096),
        None,
        "no utime: not a process"
    );
}

#[test]
fn hwmon_drops_nonsense_limits() {
    let files: Vec<(String, String)> = [
        ("temp1_input", "34850"),
        ("temp1_label", "Composite"),
        ("temp1_max", "89850"),
        ("temp1_crit", "94850"),
        ("temp2_input", "36850"),
        ("temp2_max", "65261850"),
        ("temp2_min", "-273150"),
        ("temp3_input", "999999999"),
        ("fan1_input", "1830"),
        ("in0_input", "12060"),
        ("in0_label", "12V"),
        ("power1_average", "15000000"),
        ("tempX_input", "1"),
    ]
    .iter()
    .map(|(a, b)| ((*a).to_owned(), (*b).to_owned()))
    .collect();
    let s = parse_hwmon("nvme", &files);
    let t1 = s.iter().find(|s| s.label == "Composite").unwrap();
    assert_eq!(
        (t1.value, t1.max, t1.crit),
        (34.85, Some(89.85), Some(94.85))
    );
    let t2 = s.iter().find(|s| s.label == "temp2").unwrap();
    assert_eq!(t2.max, None, "65261 °C is a placeholder");
    assert!(
        s.iter().all(|s| s.label != "temp3"),
        "a broken reading is left out"
    );
    assert!(
        s.iter()
            .any(|s| s.kind == SensorKind::Fan && s.value == 1830.0)
    );
    assert!(
        s.iter()
            .any(|s| s.label == "12V" && (s.value - 12.06).abs() < 1e-9)
    );
    assert!(
        s.iter()
            .any(|s| s.kind == SensorKind::Power && (s.value - 15.0).abs() < 1e-9)
    );
}

#[test]
fn the_whole_machine_from_the_fixture_tree() {
    let mut c = collector();
    let s = c.sample(Want {
        processes: true,
        now_ms: None,
    });
    assert_eq!(s.cores.len(), 32);
    assert_eq!(s.uptime_ms, 971_095_790);
    assert_eq!(
        s.cpu_model.as_deref(),
        Some("AMD RYZEN AI MAX+ 395 w/ Radeon 8060S")
    );
    assert_eq!(s.board.as_deref(), Some("NucBox_EVO-X2"));
    assert_eq!(s.core_mhz.len(), 2, "two cpufreq dirs in the fixture");
    assert_eq!(s.max_mhz, Some(5187));
    assert!(s.pressure.cpu.is_some() && s.pressure.memory.is_some() && s.pressure.io.is_some());
    assert_eq!(s.irqs.len(), 32);
    assert_eq!(
        s.disk_io.len(),
        1,
        "partitions and loops left out: {:?}",
        s.disk_io
    );
    let root = s.disks.iter().find(|d| d.mount == "/").unwrap();
    assert_eq!(root.available, 350_000_000_000);
    // Sensors: k10temp Tctl, the NVMe's three, the r8169, the wifi, amdgpu…
    let tctl = s.sensors.iter().find(|x| x.label == "Tctl").unwrap();
    assert_eq!(tctl.chip, "k10temp");
    let acpi = s
        .sensors
        .iter()
        .find(|x| x.chip.starts_with("acpitz"))
        .unwrap();
    assert_eq!(acpi.crit, Some(110.0), "the thermal zone's critical trip");
    assert!(
        s.sensors.iter().all(|x| x.chip != "thermal"),
        "no duplicate row"
    );
    assert!(s.sensors.iter().any(|x| x.chip == "mt7925_phy0"));
    let r8169 = s
        .sensors
        .iter()
        .find(|x| x.chip.starts_with("r8169"))
        .unwrap();
    assert_eq!(r8169.max, Some(120.0));
    let wifi = s.net.iter().find(|n| n.name == "wlp195s0").unwrap();
    assert!(wifi.up);
    assert_eq!(wifi.speed_mbps, None);
    assert!(!s.net.iter().find(|n| n.name == "lo").unwrap().up);
    assert_eq!((s.conntrack, s.conntrack_max), (Some(1873), Some(262_144)));
    let procs = s.processes.unwrap();
    assert_eq!(procs.len(), 2);
    assert!(procs.iter().any(|p| p.name == "cp"));
}

#[test]
fn an_empty_or_missing_tree_reads_as_nothing() {
    let dir = std::env::temp_dir().join(format!("cr-res-empty-{}", std::process::id()));
    let mut c = Collector::at(&dir.join("proc"), &dir.join("sys"));
    let s = c.sample(Want {
        processes: true,
        now_ms: Some(5),
    });
    assert_eq!(s.uptime_ms, 5, "the caller's clock stands in");
    assert!(s.cores.is_empty() && s.sensors.is_empty() && s.net.is_empty());
    assert_eq!(s.processes, Some(Vec::new()));
}

#[test]
fn the_real_machine_reads_cheaply() {
    // Not a benchmark (docs/changes `## perf` has the numbers): the real
    // /proc parses into something sane.
    let mut c = Collector::default();
    let s = c.sample(Want {
        processes: true,
        now_ms: None,
    });
    assert!(!s.cores.is_empty());
    assert!(s.memory.total > 0);
    assert!(s.processes.is_some_and(|p| !p.is_empty()));
}

fn truncations(text: &str) -> impl Iterator<Item = &str> {
    (0..text.len())
        .step_by(7)
        .filter_map(move |i| text.get(..i))
}

#[test]
fn every_truncation_of_every_fixture_parses() {
    for f in [
        "proc/stat",
        "proc/meminfo",
        "proc/softirqs",
        "proc/diskstats",
        "proc/vmstat",
        "proc/net/dev",
        "proc/mounts",
        "proc/1/stat",
        "proc/loadavg",
        "proc/pressure/memory",
    ] {
        let text = fixture(f);
        for t in truncations(&text) {
            let _ = parse_stat(t);
            let _ = parse_meminfo(t);
            let mut v = parse_softirqs(t);
            parse_interrupts(t, &mut v);
            let _ = parse_diskstats(t);
            let _ = parse_vmstat(t);
            let _ = parse_net_dev(t);
            let _ = parse_mounts(t);
            let _ = parse_pid_stat(t, 4096);
            let _ = parse_loadavg(t);
            let _ = parse_psi(t);
            let _ = parse_uptime(t);
            let _ = parse_cpu_model(t);
        }
    }
}

proptest! {
    #[test]
    fn parsers_never_panic(text in "\\PC{0,400}", page in 0u64..u64::MAX) {
        let _ = parse_stat(&text);
        let _ = parse_meminfo(&text);
        let mut v = parse_softirqs(&text);
        parse_interrupts(&text, &mut v);
        let _ = parse_diskstats(&text);
        let _ = parse_vmstat(&text);
        let _ = parse_net_dev(&text);
        let _ = parse_mounts(&text);
        let _ = parse_pid_stat(&text, page);
        let _ = parse_loadavg(&text);
        let _ = parse_psi(&text);
        let _ = parse_uptime(&text);
        let _ = parse_cpu_model(&text);
        let _ = unescape(&text);
    }

    #[test]
    fn table_like_garbage_never_panics(
        rows in proptest::collection::vec(("[A-Z_0-9]{0,8}", proptest::collection::vec("-?[0-9]{0,22}|x", 0..40)), 0..20),
        cols in 0usize..40,
    ) {
        let header: String = (0..cols).map(|i| format!(" CPU{i}")).collect();
        let body: String = rows.iter().map(|(n, v)| format!("{n}: {}\n", v.join(" "))).collect();
        let text = format!("{header}\n{body}");
        let mut v = parse_softirqs(&text);
        parse_interrupts(&text, &mut v);
        prop_assert!(v.len() <= MAX_CPUS);
        let stat: String = rows.iter().map(|(n, v)| format!("cpu{} {}\n", n.len(), v.join(" "))).collect();
        let _ = parse_stat(&stat);
    }

    #[test]
    fn hwmon_values_stay_in_range(
        files in proptest::collection::vec(("(temp|fan|in|power)[0-9]{1,2}_(input|max|crit|label|average)", "-?[0-9]{0,12}|nan|inf|.{0,10}"), 0..30),
    ) {
        for s in parse_hwmon("x", &files) {
            prop_assert!(s.value.is_finite());
            if s.kind == SensorKind::Temperature {
                prop_assert!(TEMP_RANGE.contains(&s.value));
                prop_assert!(s.crit.is_none_or(|c| c > 0.0 && c <= 200.0));
            }
        }
    }
}
