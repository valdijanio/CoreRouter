//! What the kernel wrote when the previous boot died (G1.6zx): the records
//! of `/sys/fs/pstore`, read by the daemon's `crash-log` service at boot,
//! saved under `/config/crash/` and then erased from the firmware's store.
//!
//! When the kernel panics (or oopses) it hands the end of its log to the
//! pstore backend (`fs/pstore/platform.c`, `pstore_dump`): ACPI ERST on a
//! server, UEFI variables (`efi_pstore`) on any UEFI machine. The log is cut
//! in parts, newest first, each a file `dmesg-<backend>-<id>` whose first
//! line is `<Reason>#<count> Part<n>` and whose time (`mtime`) is the
//! moment it was written. This module turns those files into one
//! [`Crash`] per dump (pure: the daemon reads and erases, here only the
//! text is looked at), keeps the last [`MAX_KEPT`] in the session
//! ([`CrashLog`], `system.crash.print`) and says in the router's log what
//! happened, in which boot and on which slot.
//!
//! The NVRAM policy ([`efi_store_ok`]) is here too: the UEFI variables the
//! dumps go to are the ones the A/B update writes its boot entries to.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::Session;

/// Files of `/sys/fs/pstore` looked at, at most (a store holds a few dozen).
pub const MAX_FILES: usize = 256;
/// Bytes read of one file: a part is `record_size` (EFI: 1 KiB compressed,
/// a few KiB of text); ERST and RAM records are bigger.
pub const MAX_FILE_BYTES: usize = 64 << 10;
/// Lines kept of one dump (the newest), and the length of one.
pub const MAX_LINES: usize = 2000;
pub const MAX_LINE: usize = 512;
/// Dumps one boot reports and the session keeps (newest first).
pub const MAX_KEPT: usize = 8;
/// Lines of the trace that go to the router's log, after the summary.
pub const LOG_TRACE_LINES: usize = 24;
/// Parts of one dump more than this many seconds apart are two dumps (two
/// boots both write `Panic#1`).
const SAME_DUMP_SECS: u64 = 120;

/// One file of `/sys/fs/pstore`, as the daemon read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PstoreFile {
    pub name: String,
    /// Unix seconds of the record (the file's `mtime`; 0 when the backend
    /// gave none).
    pub mtime: u64,
    pub text: String,
}

/// One dump: the end of the kernel log of a boot that ended badly.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Crash {
    /// Unix seconds when it was written (`None`: the backend had no clock).
    pub time: Option<u64>,
    /// `panic`, `oops`, `emergency`, `shutdown`, or the record type of a
    /// record that is not a kernel log (`mce`).
    pub reason: String,
    /// `efi_pstore`, `erst`, `ramoops`.
    pub backend: String,
    /// Seconds since that boot started, at the last line of the dump.
    pub uptime_s: Option<f64>,
    /// When that boot started (`time` − `uptime_s`).
    pub boot_start: Option<u64>,
    /// The A/B slot of that boot, when the dump reaches back to the
    /// kernel's command line (`corerouter.slot=`): a boot that died early.
    pub slot: Option<String>,
    /// The kernel release of the `CPU: … Not tainted 6.18.59 #1` line.
    pub kernel: Option<String>,
    /// The line that says what happened (`Kernel panic - not syncing: …`).
    pub summary: String,
    /// The dump, oldest line first, without the `<level>` prefix.
    pub lines: Vec<String>,
    /// Parts found, and whether parts 1..=n were all there.
    pub parts: u32,
    pub complete: bool,
    /// The `/sys/fs/pstore` files it came from (erased once saved).
    pub files: Vec<String>,
}

impl Crash {
    /// The file name it is saved under in `/config/crash/`: sortable by
    /// time, unique per dump.
    pub fn file_name(&self) -> String {
        let t = self.time.unwrap_or(0);
        let reason: String = self.reason.chars().filter(char::is_ascii_alphanumeric).take(16).collect();
        // Part 1 (the newest text): the files are in part order, highest first.
        let first = self.files.last().map(String::as_str).unwrap_or("");
        let id: String = first.rsplit('-').next().unwrap_or("").chars().filter(char::is_ascii_digit).take(24).collect();
        format!("{t:012}-{reason}-{id}.json")
    }
}

/// `<type>-<backend>-<id>` (`dmesg-efi_pstore-1731398400101001`), with the
/// `.enc.z` of a record the kernel could not decompress.
fn split_name(name: &str) -> Option<(&str, &str)> {
    let name = name.strip_suffix(".enc.z").unwrap_or(name);
    let (kind, rest) = name.split_once('-')?;
    let (backend, id) = rest.rsplit_once('-')?;
    (!kind.is_empty() && !backend.is_empty() && !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit()))
        .then_some((kind, backend))
}

/// `Panic#2 Part3` → (`panic`, 2, 3).
fn header(line: &str) -> Option<(String, u32, u32)> {
    let (why, rest) = line.trim().split_once('#')?;
    let (count, part) = rest.split_once(" Part")?;
    let count = count.parse().ok()?;
    let part = part.trim().parse().ok()?;
    (!why.is_empty() && why.bytes().all(|b| b.is_ascii_alphabetic())).then(|| (why.to_ascii_lowercase(), count, part))
}

/// `<4>[   12.345678] msg` → (Some(12.345678), "[   12.345678] msg").
fn body_line(raw: &str) -> (Option<f64>, String) {
    let l = raw.trim_end_matches(['\r', '\0']);
    let l = match l.strip_prefix('<').and_then(|r| r.split_once('>')) {
        Some((lvl, rest)) if !lvl.is_empty() && lvl.len() <= 3 && lvl.bytes().all(|b| b.is_ascii_digit()) => rest,
        _ => l,
    };
    let t = l
        .strip_prefix('[')
        .and_then(|r| r.split_once(']'))
        .and_then(|(n, _)| n.trim().parse::<f64>().ok())
        .filter(|t| t.is_finite() && *t >= 0.0);
    (t, clip(l, MAX_LINE))
}

fn clip(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_owned();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s.get(..end).unwrap_or_default().to_owned()
}

/// The message of a line, without its `[time]`.
fn message(l: &str) -> &str {
    match l.strip_prefix('[').and_then(|r| r.split_once(']')) {
        Some((_, m)) => m.trim_start(),
        None => l,
    }
}

/// What the dump says happened.
fn summary_of(lines: &[String]) -> String {
    let msg = |l: &String| message(l).trim_end_matches(" ]---").trim_start_matches("---[ end ").to_owned();
    if let Some(l) = lines.iter().rev().find(|l| l.contains("Kernel panic - not syncing")) {
        return clip(message(l).trim_start_matches("---[ end ").trim_end_matches(" ]---"), 300);
    }
    const FIRST: [&str; 8] = [
        "BUG:",
        "Oops:",
        "general protection fault",
        "soft lockup",
        "hard LOCKUP",
        "Unable to handle",
        "kernel BUG at",
        "Machine check",
    ];
    lines
        .iter()
        .find(|l| FIRST.iter().any(|p| l.contains(p)))
        .or_else(|| lines.iter().rev().find(|l| !message(l).trim().is_empty()))
        .map(|l| clip(&msg(l), 300))
        .unwrap_or_default()
}

/// The release of `CPU: 0 UID: 0 PID: 1 Comm: sh Not tainted 6.18.59 #1` or
/// `Tainted: G   W   6.18.59 #1`.
fn kernel_of(lines: &[String]) -> Option<String> {
    lines.iter().find_map(|l| {
        let (_, after) = l.split_once("ainted")?;
        after
            .split_ascii_whitespace()
            .find(|w| w.starts_with(|c: char| c.is_ascii_digit()) && w.contains('.'))
            .map(|w| clip(w, 64))
    })
}

/// `corerouter.slot=b` of the kernel's `Command line:` (only in a dump that
/// reaches back to the start of the boot).
fn slot_of(lines: &[String]) -> Option<String> {
    lines.iter().find(|l| l.contains("Command line:")).and_then(|l| {
        l.split_ascii_whitespace()
            .find_map(|w| w.strip_prefix("corerouter.slot="))
            .filter(|s| !s.is_empty() && s.len() <= 8 && s.bytes().all(|b| b.is_ascii_alphanumeric()))
            .map(str::to_owned)
    })
}

/// One part, parsed.
struct Part {
    file: String,
    backend: String,
    reason: String,
    count: u32,
    part: u32,
    mtime: u64,
    body: Vec<String>,
}

/// Turn the files of `/sys/fs/pstore` into dumps, newest first. A file
/// that is not a pstore record is left out (and not erased); a record that
/// is not a kernel log (`mce-erst-…`) is a dump of its own with its text.
pub fn parse(files: &[PstoreFile]) -> Vec<Crash> {
    let mut parts: Vec<Part> = Vec::new();
    let mut other: Vec<Crash> = Vec::new();
    for f in files.iter().take(MAX_FILES) {
        let Some((kind, backend)) = split_name(&f.name) else {
            continue;
        };
        let text = clip(&f.text, MAX_FILE_BYTES);
        let mut lines = text.lines();
        let head = if kind == "dmesg" { lines.next().and_then(header) } else { None };
        let Some((reason, count, part)) = head else {
            let body: Vec<String> = text.lines().take(MAX_LINES).map(|l| body_line(l).1).collect();
            other.push(Crash {
                time: (f.mtime > 0).then_some(f.mtime),
                reason: clip(kind, 32),
                backend: clip(backend, 32),
                summary: summary_of(&body),
                lines: body,
                parts: 1,
                complete: true,
                files: vec![f.name.clone()],
                ..Crash::default()
            });
            continue;
        };
        parts.push(Part {
            file: f.name.clone(),
            backend: clip(backend, 32),
            reason,
            count,
            part,
            mtime: f.mtime,
            body: lines.map(|l| body_line(l).1).collect(),
        });
    }
    // Same backend, reason and count, written within SAME_DUMP_SECS, with
    // no part number twice: one dump.
    parts.sort_by(|a, b| (&a.backend, &a.reason, a.count, a.mtime, a.part).cmp(&(&b.backend, &b.reason, b.count, b.mtime, b.part)));
    let mut groups: Vec<Vec<Part>> = Vec::new();
    for p in parts {
        let joins = groups.last().and_then(|g| g.last()).is_some_and(|q| {
            q.backend == p.backend
                && q.reason == p.reason
                && q.count == p.count
                && p.mtime.saturating_sub(q.mtime) <= SAME_DUMP_SECS
        }) && groups.last().is_some_and(|g| g.iter().all(|q| q.part != p.part));
        match groups.last_mut() {
            Some(g) if joins => g.push(p),
            _ => groups.push(vec![p]),
        }
    }
    let mut out: Vec<Crash> = groups.into_iter().map(assemble).collect();
    out.extend(other);
    out.sort_by(|a, b| b.time.cmp(&a.time));
    out.truncate(MAX_KEPT);
    out
}

/// Parts of one dump → the dump: the highest part is the oldest text.
fn assemble(mut g: Vec<Part>) -> Crash {
    g.sort_by(|a, b| b.part.cmp(&a.part));
    let n = g.len();
    let max = g.first().map_or(0, |p| p.part);
    let complete = usize::try_from(max).is_ok_and(|m| m == n);
    let time = g.iter().map(|p| p.mtime).max().filter(|t| *t > 0);
    let files: Vec<String> = g.iter().map(|p| p.file.clone()).collect();
    let (backend, reason) = g.first().map(|p| (p.backend.clone(), p.reason.clone())).unwrap_or_default();
    let mut lines: Vec<String> = g.into_iter().flat_map(|p| p.body).filter(|l| !l.is_empty()).collect();
    if lines.len() > MAX_LINES {
        lines.drain(..lines.len() - MAX_LINES);
    }
    let uptime_s = lines.iter().rev().find_map(|l| body_line(l).0);
    let boot_start = match (time, uptime_s) {
        (Some(t), Some(u)) if u >= 0.0 => {
            // Truncation is wanted: whole seconds.
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let u = u as u64;
            t.checked_sub(u)
        }
        _ => None,
    };
    Crash {
        time,
        summary: summary_of(&lines),
        kernel: kernel_of(&lines),
        slot: slot_of(&lines),
        reason,
        backend,
        uptime_s,
        boot_start,
        parts: u32::try_from(n).unwrap_or(u32::MAX),
        complete,
        files,
        lines,
    }
}

/// `2026-11-12 03:04:05 UTC`.
pub fn utc(secs: u64) -> String {
    let days = i64::try_from(secs / 86_400).unwrap_or(0);
    let rem = secs % 86_400;
    // Howard Hinnant's days → civil date.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC", rem / 3600, rem % 3600 / 60, rem % 60)
}

/// `47 s`, `12 min 3 s`, `3 h 05 min`, `2 d 4 h`.
pub fn span(secs: u64) -> String {
    match secs {
        0..60 => format!("{secs} s"),
        60..3600 => format!("{} min {} s", secs / 60, secs % 60),
        3600..86_400 => format!("{} h {:02} min", secs / 3600, secs % 3600 / 60),
        _ => format!("{} d {} h", secs / 86_400, secs % 86_400 / 3600),
    }
}

/// The router-log lines of a dump found at this boot: what happened, when,
/// in which boot (first, `system,critical`), then the trace from the line
/// that says it (`system,error`, at most [`LOG_TRACE_LINES`]).
pub fn log_lines(c: &Crash) -> Vec<(&'static str, String)> {
    let what = match c.reason.as_str() {
        "panic" => "a kernel panic".to_owned(),
        "oops" => "a kernel oops".to_owned(),
        "emergency" => "an emergency restart".to_owned(),
        other => format!("a kernel record ({other})"),
    };
    let mut boot = Vec::new();
    if let Some(s) = c.boot_start {
        boot.push(format!("boot started {}", utc(s)));
    }
    if let Some(s) = &c.slot {
        boot.push(format!("slot {s}"));
    }
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    if let Some(u) = c.uptime_s {
        boot.push(format!("{} after start", span(u as u64)));
    }
    if let Some(t) = c.time {
        boot.push(format!("at {}", utc(t)));
    }
    if let Some(k) = &c.kernel {
        boot.push(format!("kernel {k}"));
    }
    boot.push(format!("{} record", c.backend));
    let mut out = vec![(
        "critical",
        format!("previous boot ended in {what} ({}): {}", boot.join(", "), c.summary),
    )];
    let start = c.lines.iter().position(|l| message(l).starts_with(c.summary.as_str()) || l.contains(c.summary.as_str()));
    let from = start.map_or(c.lines.len().saturating_sub(LOG_TRACE_LINES), |i| i.saturating_sub(2));
    out.extend(
        c.lines
            .iter()
            .skip(from)
            .take(LOG_TRACE_LINES)
            .map(|l| ("error", format!("kernel: {}", clip(message(l), 300)))),
    );
    out
}

/// Free NVRAM, in bytes, that the UEFI store must keep for the dumps to go
/// on (G1.6zx, docs/os-image.md: room for [`DUMPS_KEPT_ROOM`] full dumps,
/// the A/B update's boot entries and the firmware's own reserve).
pub const EFI_MIN_FREE: u64 = DUMP_BYTES * DUMPS_KEPT_ROOM + BOOT_ENTRIES_BYTES + KERNEL_RESERVE;
/// One dump in UEFI variables, at most (**medido**, OVMF, `kmsg_bytes`
/// 10240: 10 variables of 1 KiB plus their names and headers).
pub const DUMP_BYTES: u64 = 12 << 10;
pub const DUMPS_KEPT_ROOM: u64 = 2;
/// The A/B update's `Boot####` entries, `BootOrder` and `BootNext`, with
/// room to spare (each entry ~200 B).
pub const BOOT_ENTRIES_BYTES: u64 = 4 << 10;
/// What Linux refuses to go below (`EFI_MIN_RESERVE`,
/// arch/x86/platform/efi/quirks.c).
pub const KERNEL_RESERVE: u64 = 5 << 10;

/// Keep the UEFI backend on with this much NVRAM left? Unknown sizes (a
/// firmware without `QueryVariableInfo`) keep it: the kernel's own reserve
/// still holds.
pub fn efi_store_ok(free: Option<u64>) -> bool {
    free.is_none_or(|f| f >= EFI_MIN_FREE)
}

/// The UEFI variable store, as the service found it.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct EfiStore {
    /// Bytes (`statfs` of efivarfs; `None`: the firmware does not say).
    pub total: Option<u64>,
    pub free: Option<u64>,
    /// The `efi_pstore` backend is armed (`pstore_disable` = N).
    pub enabled: bool,
    /// The service turned it off: too little NVRAM left.
    pub turned_off: bool,
}

/// The crash records of the router (`Session::ext`), fed by the daemon.
#[derive(Debug, Default)]
pub struct CrashLog {
    /// The service ran (the lab and the browser never feed it).
    pub fed: bool,
    /// The dumps kept under `/config/crash/`, newest first.
    pub crashes: Vec<Crash>,
    /// How many of them were found at this boot (the newest ones).
    pub new_this_boot: usize,
    /// The backend the kernel writes to now (`erst`, `efi_pstore`), if any.
    pub backend: Option<String>,
    pub efi: Option<EfiStore>,
    /// Records that could not be saved or erased, why.
    pub problems: Vec<String>,
}

impl CrashLog {
    pub fn to_json(&self, limit: usize, with_lines: bool) -> Value {
        let crashes: Vec<Value> = self
            .crashes
            .iter()
            .take(limit)
            .enumerate()
            .map(|(i, c)| {
                let mut v = json!({
                    "time": c.time,
                    "reason": c.reason,
                    "backend": c.backend,
                    "uptime_s": c.uptime_s,
                    "boot_start": c.boot_start,
                    "slot": c.slot,
                    "kernel": c.kernel,
                    "summary": c.summary,
                    "parts": c.parts,
                    "complete": c.complete,
                    "this_boot": i < self.new_this_boot,
                });
                if with_lines && let Some(o) = v.as_object_mut() {
                    o.insert("lines".into(), json!(c.lines));
                }
                v
            })
            .collect();
        json!({
            "fed": self.fed,
            "backend": self.backend,
            "efi": self.efi,
            "problems": self.problems,
            "crashes": crashes,
        })
    }
}

/// What the service hands over at boot.
#[derive(Debug, Default)]
pub struct Found {
    /// Dumps found in pstore now (newest first), already saved.
    pub new: Vec<Crash>,
    /// Dumps saved by earlier boots (newest first).
    pub saved: Vec<Crash>,
    pub backend: Option<String>,
    pub efi: Option<EfiStore>,
    pub problems: Vec<String>,
}

impl Session {
    /// The crash-log service's report (G1.6zx): keep it for
    /// `system.crash.print` and the health check, and say each new dump in
    /// the router's log. Returns the lines logged.
    pub fn crash_found(&mut self, f: Found) -> usize {
        let mut logged = 0;
        for c in f.new.iter().rev() {
            for (level, msg) in log_lines(c) {
                self.log_event(&["system", level], crate::logging::DAEMON, msg, Value::Null);
                logged += 1;
            }
        }
        for p in &f.problems {
            self.log_event(&["system", "warning"], crate::logging::DAEMON, format!("crash log: {p}"), Value::Null);
            logged += 1;
        }
        if let Some(e) = f.efi.as_ref().filter(|e| e.turned_off) {
            self.log_store_off(e);
            logged += 1;
        }
        let Some(log) = self.ext_mut::<CrashLog>() else {
            return logged;
        };
        log.fed = true;
        log.new_this_boot = f.new.len().min(MAX_KEPT);
        log.crashes = f.new.into_iter().chain(f.saved).take(MAX_KEPT).collect();
        log.backend = f.backend;
        log.efi = f.efi;
        log.problems = f.problems;
        logged
    }

    /// The service turned `efi_pstore` off during the boot (the NVRAM ran
    /// short after the start: oopses that wrote dumps).
    pub fn crash_store_turned_off(&mut self, e: EfiStore) {
        self.log_store_off(&e);
        if let Some(log) = self.ext_mut::<CrashLog>() {
            log.efi = Some(e);
        }
    }

    fn log_store_off(&mut self, e: &EfiStore) {
        self.log_event(
            &["system", "warning"],
            crate::logging::DAEMON,
            format!(
                "crash log: UEFI variable store has {} bytes free (needs {EFI_MIN_FREE}): kernel panics are no longer recorded there until the next boot",
                e.free.unwrap_or(0)
            ),
            Value::Null,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(name: &str, mtime: u64, text: &str) -> PstoreFile {
        PstoreFile { name: name.into(), mtime, text: text.into() }
    }

    /// What `echo c > /proc/sysrq-trigger` leaves, cut in two parts (the
    /// newest text is Part1), as efi_pstore names them.
    fn sysrq_panic(t: u64) -> Vec<PstoreFile> {
        let part2 = "Panic#1 Part2\n\
            <6>[    0.000000] Linux version 6.18.59 (buildroot@buildroot) #1 SMP PREEMPT_DYNAMIC\n\
            <6>[    0.000000] Command line: console=ttyS0 root=/dev/dm-0 corerouter.slot=b panic=10 quiet\n\
            <6>[   41.100000] sysrq: Trigger a crash\n";
        let part1 = "Panic#1 Part1\n\
            <0>[   41.100100] Kernel panic - not syncing: sysrq triggered crash\n\
            <4>[   41.100200] CPU: 1 UID: 0 PID: 345 Comm: sh Not tainted 6.18.59 #1 PREEMPT(voluntary)\n\
            <4>[   41.100300] Call Trace:\n\
            <4>[   41.100400]  <TASK>\n\
            <4>[   41.100500]  dump_stack_lvl+0x5d/0x80\n\
            <4>[   41.100600]  panic+0x118/0x2e0\n\
            <0>[   41.101000] ---[ end Kernel panic - not syncing: sysrq triggered crash ]---\n";
        vec![
            file(&format!("dmesg-efi_pstore-{}101001", t), t, part1),
            file(&format!("dmesg-efi_pstore-{}102001", t), t, part2),
        ]
    }

    #[test]
    fn two_parts_make_one_dump_in_order_with_its_boot() {
        let t = 1_763_000_000;
        let got = parse(&sysrq_panic(t));
        assert_eq!(got.len(), 1, "{got:?}");
        let c = &got[0];
        assert_eq!((c.reason.as_str(), c.backend.as_str(), c.parts, c.complete), ("panic", "efi_pstore", 2, true));
        assert_eq!(c.summary, "Kernel panic - not syncing: sysrq triggered crash");
        assert!(c.lines[0].contains("Linux version"), "oldest first: {:?}", c.lines);
        assert!(c.lines.last().unwrap().contains("---[ end"));
        assert_eq!(c.slot.as_deref(), Some("b"));
        assert_eq!(c.kernel.as_deref(), Some("6.18.59"));
        assert_eq!(c.uptime_s, Some(41.101));
        assert_eq!(c.boot_start, Some(t - 41));
        assert_eq!(c.files.len(), 2);
        let lines = log_lines(c);
        assert_eq!(lines[0].0, "critical");
        assert!(lines[0].1.starts_with("previous boot ended in a kernel panic (boot started"), "{}", lines[0].1);
        assert!(lines[0].1.contains("slot b") && lines[0].1.contains("41 s after start"), "{}", lines[0].1);
        assert!(lines[0].1.ends_with(": Kernel panic - not syncing: sysrq triggered crash"));
        assert!(lines.iter().any(|(_, l)| l == "kernel: panic+0x118/0x2e0"), "{lines:?}");
        assert!(lines.len() <= 1 + LOG_TRACE_LINES);
    }

    #[test]
    fn two_boots_that_both_panicked_are_two_dumps() {
        let mut files = sysrq_panic(1_763_000_000);
        files.extend(sysrq_panic(1_763_090_000));
        let got = parse(&files);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].time, Some(1_763_090_000), "newest first");
        assert!(got.iter().all(|c| c.complete && c.parts == 2));
    }

    #[test]
    fn a_missing_part_and_an_oops_then_a_panic() {
        let t = 1_763_000_000;
        let files = vec![
            file("dmesg-erst-6800000000001", t, "Oops#1 Part1\n<4>[  900.1] BUG: kernel NULL pointer dereference, address: 0000000000000008\n<4>[  900.2] RIP: 0010:foo+0x1/0x2\n"),
            file("dmesg-erst-6800000000002", t + 1, "Panic#2 Part1\n<0>[  901.0] Kernel panic - not syncing: Fatal exception\n"),
            file("dmesg-erst-6800000000003", t + 1, "Panic#2 Part3\n<4>[  899.0] earlier\n"),
        ];
        let got = parse(&files);
        assert_eq!(got.len(), 2, "{got:?}");
        let panic = got.iter().find(|c| c.reason == "panic").unwrap();
        assert!(!panic.complete && panic.parts == 2);
        let oops = got.iter().find(|c| c.reason == "oops").unwrap();
        assert_eq!(oops.summary, "BUG: kernel NULL pointer dereference, address: 0000000000000008");
        assert_eq!(oops.slot, None, "a late dump does not reach the command line");
    }

    #[test]
    fn other_records_and_strange_names() {
        let files = vec![
            file("mce-erst-77", 5, "CPU 0: Machine Check Exception: 5 Bank 1"),
            file("not-a-record", 5, "x"),
            file("dmesg-efi_pstore-12x", 5, "Panic#1 Part1\n"),
            file("dmesg-efi_pstore-1.enc.z", 5, "\u{1}\u{2}binary"),
        ];
        let got = parse(&files);
        assert_eq!(got.len(), 2, "{got:?}");
        assert!(got.iter().any(|c| c.reason == "mce" && c.summary.contains("Machine Check")));
        // Not decompressed: kept as a record of its own, never lost.
        assert!(got.iter().any(|c| c.files == ["dmesg-efi_pstore-1.enc.z"]));
    }

    #[test]
    fn file_names_and_times() {
        let c = &parse(&sysrq_panic(1_763_000_000))[0];
        assert_eq!(c.file_name(), "001763000000-panic-1763000000101001.json");
        assert_eq!(utc(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(utc(1_763_000_000), "2025-11-13 02:13:20 UTC");
        assert_eq!(utc(951_782_400), "2000-02-29 00:00:00 UTC");
        assert_eq!(span(41), "41 s");
        assert_eq!(span(3725), "1 h 02 min");
        assert_eq!(span(200_000), "2 d 7 h");
    }

    #[test]
    fn nvram_policy() {
        assert!(efi_store_ok(None));
        assert!(efi_store_ok(Some(EFI_MIN_FREE)));
        assert!(!efi_store_ok(Some(EFI_MIN_FREE - 1)));
    }

    #[test]
    fn the_session_keeps_them_and_logs_once() {
        let mut s = Session::virtual_lab();
        let new = parse(&sysrq_panic(1_763_000_000));
        let n = s.crash_found(Found { new, saved: vec![], backend: Some("efi_pstore".into()), ..Found::default() });
        assert!(n >= 2);
        let log = s.execute("log.print", &json!({"find": "previous boot"})).unwrap();
        assert_eq!(log.as_array().unwrap().len(), 1, "{log}");
        assert!(log[0]["topics"].to_string().contains("critical"), "{log}");
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(64))]
        /// Hostile records (the store is the firmware's): never a panic,
        /// always within the bounds.
        #[test]
        fn any_files_parse_within_bounds(names in proptest::collection::vec("[a-z_]{1,8}-[a-z_]{1,10}-[0-9]{1,20}", 0..12),
                                         texts in proptest::collection::vec("(Panic|Oops)#[0-9]{1,2} Part[0-9]{1,2}\n(<[0-9]>\\[ *[0-9.]{1,12}\\] .{0,40}\n){0,20}", 0..12),
                                         mtime in 0u64..2_000_000_000) {
            let files: Vec<PstoreFile> = names.iter().zip(texts.iter().cycle()).map(|(n, t)| file(n, mtime, t)).collect();
            let got = parse(&files);
            proptest::prop_assert!(got.len() <= MAX_KEPT);
            for c in &got {
                proptest::prop_assert!(c.lines.len() <= MAX_LINES);
                proptest::prop_assert!(c.lines.iter().all(|l| l.len() <= MAX_LINE));
                let _ = log_lines(c);
                let _ = c.file_name();
            }
        }
    }
}
