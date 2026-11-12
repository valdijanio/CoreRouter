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
    assert_eq!(procs.len(), 3);
    assert!(procs.iter().any(|p| p.name == "cp"));
    // G1.6qd: FRR's bgpd among the router's own; this test is no pid there.
    let names: Vec<&str> = s.router.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, ["bgpd"]);
    assert_eq!(
        (s.router[0].threads, s.router[0].rss_bytes),
        (6, 104_960 * 4096)
    );
}

#[test]
fn the_router_processes_are_found_and_kept() {
    let mut c = collector().with_own_pid(2_889_393);
    let s = c.sample(Want::default());
    assert!(s.processes.is_none(), "the full list stays on demand");
    let names: Vec<&str> = s.router.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(
        names,
        ["corerouter-daemon", "bgpd"],
        "the daemon first, by its own name"
    );
    assert_eq!(s.router[0].pid, 2_889_393);
    assert_eq!(
        c.router_pids.as_ref().map(|(_, p)| p.clone()),
        Some(vec![412])
    );
    // A pid that is gone brings the scan forward (FRR restarted).
    c.router_pids = Some((s.uptime_ms, vec![77]));
    let s = c.sample(Want::default());
    assert_eq!(
        s.router.iter().map(|p| p.pid).collect::<Vec<_>>(),
        [2_889_393, 412]
    );
    // A pid reused by another program is not FRR's any more.
    c.router_pids = Some((s.uptime_ms, vec![1]));
    let s = c.sample(Want::default());
    assert_eq!(s.router.last().map(|p| p.pid), Some(412));
    assert_eq!(stat_name("9 (a (b)) S 1"), Some("a (b)"));
    assert_eq!(stat_name("9 (cut"), None);
}

/// G1.6zf: two NVMe disks, two SATA disks, two AMD sockets and a card's
/// ports all read as one name each without this: `system.health.print` had
/// `nvme-composite` twice.
#[test]
fn chips_of_the_same_driver_are_told_apart() {
    let dir = std::env::temp_dir().join(format!("cr-res-chips-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let hwmon = dir.join("sys/class/hwmon");
    let chip = |n: u32, name: &str, files: &[(&str, &str)]| -> PathBuf {
        let d = hwmon.join(format!("hwmon{n}"));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("name"), format!("{name}\n")).unwrap();
        for (f, v) in files {
            std::fs::write(d.join(f), v).unwrap();
        }
        d
    };
    let temp = [("temp1_input", "41000")];
    chip(
        0,
        "coretemp",
        &[("temp1_input", "50000"), ("temp1_label", "Package id 0")],
    );
    // The NVMe controllers: `device` is a link to `nvme0`, `nvme1`.
    for n in 0..2 {
        let d = chip(
            1 + n,
            "nvme",
            &[("temp1_input", "38850"), ("temp1_label", "Composite")],
        );
        let ctrl = dir.join(format!("sys/devices/nvme{n}"));
        std::fs::create_dir_all(&ctrl).unwrap();
        std::os::unix::fs::symlink(&ctrl, d.join("device")).unwrap();
    }
    // SATA disks: the SCSI device has `block/<disk>`.
    for (n, disk) in [(3, "sda"), (4, "sdb")] {
        std::fs::create_dir_all(chip(n, "drivetemp", &temp).join("device/block").join(disk))
            .unwrap();
    }
    // A card's port: the PCI function has `net/<port>`.
    std::fs::create_dir_all(chip(5, "ixgbe", &temp).join("device/net/ether3")).unwrap();
    // Nothing to tell them apart but the order.
    chip(
        6,
        "k10temp",
        &[("temp1_input", "44000"), ("temp1_label", "Tctl")],
    );
    chip(
        7,
        "k10temp",
        &[("temp1_input", "45000"), ("temp1_label", "Tctl")],
    );
    // A device whose name only starts like the chip's is not a number of it.
    let d = chip(10, "nvme", &temp);
    let other = dir.join("sys/devices/nvme-fabric");
    std::fs::create_dir_all(&other).unwrap();
    std::os::unix::fs::symlink(&other, d.join("device")).unwrap();
    // The motherboard's chip: named after its model, bound to the family's
    // driver. Its limits are the firmware's alarm settings: left out.
    let d = chip(
        11,
        "nct6798",
        &[
            ("temp1_input", "34000"),
            ("temp1_label", "SYSTIN"),
            ("temp3_input", "127000"),
            ("temp3_label", "AUXTIN1"),
            ("temp3_max", "80000"),
            ("temp3_crit", "100000"),
            ("fan2_input", "1180"),
            ("in0_input", "1016"),
        ],
    );
    let driver = dir.join("sys/bus/platform/drivers/nct6775");
    std::fs::create_dir_all(&driver).unwrap();
    std::fs::create_dir_all(d.join("device")).unwrap();
    std::os::unix::fs::symlink(&driver, d.join("device/driver")).unwrap();
    let c = Collector::at(&dir.join("proc"), &dir.join("sys"));
    let all = c.sensors();
    let board: Vec<&Sensor> = all.iter().filter(|s| s.board).collect();
    assert_eq!(board.len(), 4);
    assert!(
        board
            .iter()
            .all(|s| s.chip == "nct6798" && s.max.is_none() && s.crit.is_none())
    );
    assert_eq!(
        board.iter().find(|s| s.label == "AUXTIN1").map(|s| s.value),
        Some(127.0),
        "shown as read"
    );
    let chips: Vec<String> = all
        .into_iter()
        .filter(|s| !s.board)
        .map(|s| s.chip)
        .collect();
    assert_eq!(
        chips,
        [
            "coretemp",
            "nvme0",
            "nvme1",
            "drivetemp sda",
            "drivetemp sdb",
            "ixgbe ether3",
            "k10temp",
            "k10temp 2",
            "nvme",
        ]
    );
    std::fs::remove_dir_all(&dir).unwrap();
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
    assert_eq!(s.router.first().map(|p| p.pid), Some(std::process::id()));
    assert!(
        s.router[0].fds.is_some_and(|n| n > 0),
        "this process's descriptors"
    );
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

/// G1.6zy: a Skylake-SP controller with two modules, one with corrected
/// errors (the sysfs of `skx_edac`, Documentation/ABI/testing/sysfs-devices-edac).
#[test]
fn edac_modules_and_their_errors() {
    let dir = std::env::temp_dir().join(format!("cr-res-edac-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mc = dir.join("sys/devices/system/edac/mc/mc0");
    std::fs::create_dir_all(&mc).unwrap();
    for (f, v) in [
        ("mc_name", "Skylake Socket#0 IMC#0\n"),
        ("ce_count", "3\n"),
        ("ue_count", "0\n"),
        ("ce_noinfo_count", "1\n"),
        ("ue_noinfo_count", "0\n"),
    ] {
        std::fs::write(mc.join(f), v).unwrap();
    }
    for (n, ce) in [(0, "2"), (1, "0")] {
        let d = mc.join(format!("dimm{n}"));
        std::fs::create_dir_all(&d).unwrap();
        for (f, v) in [
            ("dimm_label", format!("CPU_SrcID#0_MC#0_Chan#{n}_DIMM#0\n")),
            ("dimm_location", format!("channel {n} slot 0 \n")),
            ("size", "32768\n".into()),
            ("dimm_mem_type", "Registered-DDR4\n".into()),
            ("dimm_edac_mode", "SECDED\n".into()),
            ("dimm_ce_count", format!("{ce}\n")),
            ("dimm_ue_count", "0\n".into()),
        ] {
            std::fs::write(d.join(f), v).unwrap();
        }
    }
    let proc = dir.join("proc");
    std::fs::create_dir_all(&proc).unwrap();
    std::fs::write(
        proc.join("meminfo"),
        "MemTotal: 1000 kB\nHardwareCorrupted:     4 kB\n",
    )
    .unwrap();
    let mut c = Collector::at(&proc, &dir.join("sys"));
    let m = c.edac_cached(
        0,
        std::fs::read_to_string(proc.join("meminfo"))
            .ok()
            .as_deref(),
    );
    assert_eq!((m.controllers, m.dimms.len(), m.ce_noinfo), (1, 2, 1));
    let d0 = &m.dimms[0];
    assert_eq!(
        (d0.controller.as_str(), d0.name.as_str(), d0.ce, d0.size_mb),
        ("mc0", "dimm0", 2, 32768)
    );
    assert_eq!(d0.label, "CPU_SrcID#0_MC#0_Chan#0_DIMM#0");
    assert_eq!(d0.location, "channel 0 slot 0");
    assert_eq!(d0.controller_name, "Skylake Socket#0 IMC#0");
    assert_eq!(m.hardware_corrupted_kib, Some(4));
    // No EDAC at all: nothing, and the reading goes on.
    let none = Collector::at(&proc, &dir.join("nothing")).edac();
    assert_eq!(none, MemoryErrors::default());
    let _ = std::fs::remove_dir_all(&dir);
}

/// G4.8g: two DDR5 modules (spd5118 at 0x50 and 0x52: slots 0 and 2) and a
/// DDR4 one's JC42.4 sensor (0x19: slot 1), named by slot; the high limit
/// the firmware programs is not a limit.
#[test]
fn memory_module_sensors_by_slot() {
    let dir = std::env::temp_dir().join(format!("cr-res-dimm-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let hwmon = dir.join("sys/class/hwmon");
    let chip = |n: u32, name: &str, client: &str| {
        let d = hwmon.join(format!("hwmon{n}"));
        std::fs::create_dir_all(&d).unwrap();
        for (f, v) in [
            ("name", format!("{name}\n")),
            ("temp1_input", "41250\n".into()),
            ("temp1_max", "55000\n".into()),
            ("temp1_crit", "85000\n".into()),
        ] {
            std::fs::write(d.join(f), v).unwrap();
        }
        let c = dir
            .join("sys/devices/pci0000:00/0000:00:1f.4/i2c-0")
            .join(client);
        std::fs::create_dir_all(&c).unwrap();
        std::os::unix::fs::symlink(&c, d.join("device")).unwrap();
    };
    chip(0, "spd5118", "0-0050");
    chip(1, "spd5118", "0-0052");
    chip(2, "jc42", "0-0019");
    // Not a module's address: the plain name.
    chip(3, "jc42", "3-0030");
    let all = Collector::at(&dir.join("proc"), &dir.join("sys")).sensors();
    let chips: Vec<&str> = all.iter().map(|s| s.chip.as_str()).collect();
    assert_eq!(
        chips,
        ["spd5118 dimm0", "spd5118 dimm2", "jc42 dimm1", "jc42"]
    );
    assert!(
        all.iter()
            .all(|s| s.max.is_none() && s.crit == Some(85.0) && !s.board && s.value == 41.25)
    );
    let _ = std::fs::remove_dir_all(&dir);
}
