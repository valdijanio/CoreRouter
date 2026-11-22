//! The host's OS log (G4.8b): the kernel ring (`/dev/kmsg`) and the systemd
//! journal (`journalctl -o json`), read by the daemon's `oslog` service on
//! its own thread — never under the session lock — and parsed by
//! `corerouter_hal::oslog`.
//!
//! - **kmsg**: opened non-blocking; each `read` is one record, `EAGAIN`
//!   means nothing new, `EPIPE` means the ring overwrote records we had
//!   not read yet (we go on from the oldest left). With
//!   `kernel.dmesg_restrict = 1` it needs `CAP_SYSLOG`; refused, the source
//!   says so and the kernel lines come from the journal instead. Times:
//!   boot time (wall clock minus `CLOCK_BOOTTIME`) plus the record's.
//! - **journal**: `journalctl` run without a shell, with a cursor
//!   (`--after-cursor`), its output capped in lines and bytes, a deadline,
//!   and the process always killed and reaped. A pure-Rust reader of the
//!   journal files is gap G4.8ba. The production image (Buildroot, no
//!   systemd) has no journal: kmsg alone.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, ErrorKind, Read};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use corerouter_hal::oslog::{
    self, MAX_RECORD, OsLine, OsLogBatch, OsSource, SourceState, kmsg_line, parse_journal,
    parse_kmsg, valid_cursor,
};

/// Lines of the journal read on the first poll (the recent past).
pub const BACKFILL: usize = 500;
/// How long one `journalctl` may run.
pub const JOURNAL_TIMEOUT: Duration = Duration::from_secs(5);
/// Bytes of `journalctl` output read in one poll at most.
const MAX_OUTPUT: usize = 8 << 20;
/// Bytes of its error output kept (the reason when it fails).
const MAX_STDERR: u64 = 4096;
/// The journal fields we use (journalctl adds the cursor and the times).
const FIELDS: &str = "MESSAGE,PRIORITY,SYSLOG_FACILITY,SYSLOG_IDENTIFIER,_SYSTEMD_UNIT,_PID,_COMM,_TRANSPORT,_BOOT_ID";

/// The boot running now (`/proc/sys/kernel/random/boot_id`, without the
/// dashes, as the journal writes it); "" when unreadable.
pub fn boot_id() -> String {
    std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map(|s| s.trim().replace('-', ""))
        .ok()
        .filter(|s| s.len() == 32 && s.chars().all(|c| c.is_ascii_hexdigit()))
        .unwrap_or_default()
}

/// Wall clock at boot in µs: now minus `CLOCK_BOOTTIME`. The printk clock
/// of `/dev/kmsg` runs on through a suspend like BOOTTIME (**medido** on a
/// laptop 11 days up: kmsg 973 250 s, BOOTTIME 973 236 s, MONOTONIC
/// 617 565 s), so MONOTONIC would put lines days in the future. 0 if
/// unknown.
fn boot_realtime_us() -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_micros()).unwrap_or(0))
        .unwrap_or(0);
    let mono = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
    let mono_us = u64::try_from(mono.tv_sec)
        .unwrap_or(0)
        .saturating_mul(1_000_000)
        .saturating_add(u64::try_from(mono.tv_nsec / 1000).unwrap_or(0));
    now.saturating_sub(mono_us)
}

/// The kernel ring.
pub struct Kmsg {
    path: PathBuf,
    file: Option<File>,
    reason: Option<String>,
    lines: u64,
    /// Records the ring overwrote before we read them.
    pub lost: u64,
    last_seq: Option<u64>,
}

impl Kmsg {
    pub fn open(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let mut me = Self {
            path,
            file: None,
            reason: None,
            lines: 0,
            lost: 0,
            last_seq: None,
        };
        me.reopen();
        me
    }

    fn reopen(&mut self) {
        let flags = i32::try_from(rustix::fs::OFlags::NONBLOCK.bits()).unwrap_or(0o4000);
        match OpenOptions::new()
            .read(true)
            .custom_flags(flags)
            .open(&self.path)
        {
            Ok(f) => {
                self.file = Some(f);
                self.reason = None;
            }
            Err(e) => {
                self.file = None;
                self.reason = Some(match e.kind() {
                    ErrorKind::PermissionDenied => format!(
                        "unavailable: {} refused ({e}); kernel.dmesg_restrict is 1 and the \
                         daemon lacks CAP_SYSLOG — the kernel lines come from the journal",
                        self.path.display()
                    ),
                    ErrorKind::NotFound => {
                        format!("unavailable: {} does not exist", self.path.display())
                    }
                    _ => format!("unavailable: {}: {e}", self.path.display()),
                });
            }
        }
    }

    pub fn ok(&self) -> bool {
        self.file.is_some()
    }

    pub fn state(&self) -> SourceState {
        match &self.reason {
            None => SourceState::ok("kmsg", self.lines),
            Some(r) => SourceState::unavailable("kmsg", r.clone(), self.lines),
        }
    }

    /// The records written since the last read, at most `max`.
    pub fn read(&mut self, max: usize, boot: &str) -> Vec<OsLine> {
        let mut out = Vec::new();
        let Some(file) = self.file.as_mut() else {
            return out;
        };
        let at_boot = boot_realtime_us();
        let mut buf = vec![0u8; MAX_RECORD];
        while out.len() < max {
            match file.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    let Some(raw) = buf.get(..n) else { break };
                    match parse_kmsg(raw) {
                        Ok(r) if r.continuation => {}
                        Ok(r) => {
                            if let Some(last) = self.last_seq
                                && r.seq > last.saturating_add(1)
                            {
                                self.lost = self.lost.saturating_add(r.seq - last - 1);
                            }
                            self.last_seq = Some(r.seq);
                            out.push(kmsg_line(&r, at_boot, boot));
                        }
                        Err(e) => log::debug!("kmsg: record skipped: {e}"),
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                // EPIPE: overwritten before we read it; the next read goes on.
                Err(e) if e.kind() == ErrorKind::BrokenPipe => {
                    self.lost = self.lost.saturating_add(1);
                }
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) => {
                    self.reason = Some(format!("unavailable: {}: {e}", self.path.display()));
                    self.file = None;
                    break;
                }
            }
        }
        self.lines = self.lines.saturating_add(out.len() as u64);
        out
    }
}

/// The systemd journal through `journalctl`.
pub struct Journal {
    program: PathBuf,
    cursor: Option<String>,
    reason: Option<String>,
    lines: u64,
    /// Leave out the kernel's lines (kmsg reads them first-hand).
    pub skip_kernel: bool,
}

impl Journal {
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            cursor: None,
            reason: None,
            lines: 0,
            skip_kernel: false,
        }
    }

    pub fn state(&self) -> SourceState {
        match &self.reason {
            None => SourceState::ok("journal", self.lines),
            Some(r) => SourceState::unavailable("journal", r.clone(), self.lines),
        }
    }

    /// The arguments of the next run: after the cursor, or the last
    /// [`BACKFILL`] lines the first time.
    pub fn args(&self) -> Vec<String> {
        let mut a: Vec<String> = ["-o", "json", "--no-pager", "-q"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        a.push(format!("--output-fields={FIELDS}"));
        match &self.cursor {
            Some(c) => a.push(format!("--after-cursor={c}")),
            None => {
                a.push("-n".into());
                a.push(BACKFILL.to_string());
            }
        }
        a
    }

    /// The entries written since the last read, at most `max`.
    pub fn read(&mut self, max: usize, timeout: Duration) -> Vec<OsLine> {
        let mut cmd = Command::new(&self.program);
        cmd.args(self.args()).env("SYSTEMD_COLORS", "0");
        let run = run_capped(&mut cmd, max, MAX_OUTPUT, timeout);
        let mut out = Vec::new();
        let (lines, stderr, timed_out) = match run {
            Ok(r) => r,
            Err(e) => {
                self.reason = Some(e);
                return out;
            }
        };
        for l in &lines {
            match parse_journal(l) {
                Ok(e) => {
                    if valid_cursor(&e.cursor) {
                        self.cursor = Some(e.cursor);
                    }
                    if self.skip_kernel && e.line.source == OsSource::Kernel {
                        continue;
                    }
                    out.push(e.line);
                }
                Err(e) => log::debug!("journal: line skipped: {e}"),
            }
        }
        self.reason = if timed_out && lines.is_empty() {
            Some(format!(
                "unavailable: journalctl gave nothing in {} s",
                timeout.as_secs()
            ))
        } else if lines.is_empty() && self.cursor.is_none() && !stderr.trim().is_empty() {
            // "No journal files were opened due to insufficient permissions."
            Some(format!(
                "unavailable: journalctl: {}",
                oslog::clean(stderr.trim(), 200)
            ))
        } else {
            None
        };
        self.lines = self.lines.saturating_add(out.len() as u64);
        out
    }
}

/// Run `cmd` (no shell), reading at most `max_lines` lines and `max_bytes`
/// bytes of its output within `timeout`; then kill it if it still runs and
/// always reap it. Gives the lines, the start of its error output, and
/// whether the deadline cut it.
pub fn run_capped(
    cmd: &mut Command,
    max_lines: usize,
    max_bytes: usize,
    timeout: Duration,
) -> Result<(Vec<String>, String, bool), String> {
    let name = cmd.get_program().to_string_lossy().into_owned();
    // Its own process group, so a kill reaches whatever it started too.
    cmd.process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut spawned = cmd.spawn();
    // ETXTBSY: the program file was just written (an update in progress,
    // or a test's stand-in); try again shortly.
    for _ in 0..5 {
        match &spawned {
            Err(e) if e.raw_os_error() == Some(26) => {
                std::thread::sleep(Duration::from_millis(20));
                spawned = cmd.spawn();
            }
            _ => break,
        }
    }
    let mut child = spawned.map_err(|e| match e.kind() {
        ErrorKind::NotFound => {
            format!("unavailable: {name} not found (no systemd journal on this system)")
        }
        _ => format!("unavailable: cannot run {name}: {e}"),
    })?;
    let (tx, rx) = mpsc::channel();
    let stdout = child.stdout.take();
    let reader = std::thread::Builder::new()
        .name("oslog-journal".into())
        .spawn(move || {
            let mut lines = Vec::new();
            if let Some(out) = stdout {
                let mut r = BufReader::new(out);
                let mut bytes = 0usize;
                let mut buf = Vec::new();
                while lines.len() < max_lines && bytes < max_bytes {
                    buf.clear();
                    // One line, capped: a longer one is read to its end and dropped.
                    match (&mut r)
                        .take(MAX_RECORD as u64 * 4)
                        .read_until(b'\n', &mut buf)
                    {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            bytes = bytes.saturating_add(n);
                            if buf.last() != Some(&b'\n') && n >= MAX_RECORD * 4 {
                                let mut rest = Vec::new();
                                if r.read_until(b'\n', &mut rest).is_err() {
                                    break;
                                }
                                continue;
                            }
                            lines.push(String::from_utf8_lossy(&buf).trim_end().to_owned());
                        }
                    }
                }
            }
            let _ = tx.send(lines);
        });
    // Its own thread too: a process that never closes stderr must not
    // hold us past the deadline.
    let (etx, erx) = mpsc::channel();
    let err = child.stderr.take();
    let err_reader = std::thread::Builder::new()
        .name("oslog-journal-err".into())
        .spawn(move || {
            let mut text = String::new();
            if let Some(e) = err {
                let _ = e.take(MAX_STDERR).read_to_string(&mut text);
            }
            let _ = etx.send(text);
        });
    let (lines, timed_out) = match rx.recv_timeout(timeout) {
        Ok(l) => (l, false),
        Err(_) => {
            stop(&mut child);
            // The pipe closed with the process: what was read so far.
            (
                rx.recv_timeout(Duration::from_secs(1)).unwrap_or_default(),
                true,
            )
        }
    };
    stop(&mut child);
    let stderr = erx.recv_timeout(Duration::from_secs(1)).unwrap_or_default();
    // Both pipes close with the process group: the threads end on their
    // own; join only those already done, never wait on a stuck pipe.
    for h in [reader, err_reader].into_iter().flatten() {
        if h.is_finished() {
            let _ = h.join();
        }
    }
    Ok((lines, stderr, timed_out))
}

/// Kill `child` if it still runs (it may have hit our caps) and reap it.
fn stop(child: &mut Child) {
    let deadline = Instant::now() + Duration::from_millis(200);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(5)),
            _ => {
                if let Some(pid) = i32::try_from(child.id())
                    .ok()
                    .and_then(rustix::process::Pid::from_raw)
                {
                    let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
                }
                let _ = child.kill();
                let _ = child.wait();
                return;
            }
        }
    }
}

/// The host's OS log: kmsg first-hand, the journal for the rest (and for
/// the kernel too when kmsg is refused).
pub struct HostOsLog {
    pub kmsg: Kmsg,
    pub journal: Journal,
    boot: String,
}

impl HostOsLog {
    pub fn new() -> Self {
        Self::with("/dev/kmsg", "journalctl")
    }

    /// Other paths (tests: a fake journalctl, a file instead of kmsg).
    pub fn with(kmsg: impl Into<PathBuf>, journalctl: impl Into<PathBuf>) -> Self {
        let kmsg = Kmsg::open(kmsg);
        let mut journal = Journal::new(journalctl);
        journal.skip_kernel = kmsg.ok();
        Self {
            kmsg,
            journal,
            boot: boot_id(),
        }
    }

    /// Kernel lines only (the journal is read by [`Self::read_journal`],
    /// less often: it costs a process).
    pub fn read_kmsg(&mut self, max: usize) -> Vec<OsLine> {
        let lines = self.kmsg.read(max, &self.boot);
        self.journal.skip_kernel = self.kmsg.ok();
        lines
    }

    pub fn read_journal(&mut self, max: usize) -> Vec<OsLine> {
        self.journal.read(max, JOURNAL_TIMEOUT)
    }

    /// Both, and how they are.
    pub fn poll(&mut self, max: usize) -> OsLogBatch {
        let mut lines = self.read_kmsg(max);
        lines.extend(self.read_journal(max.saturating_sub(lines.len())));
        OsLogBatch {
            lines,
            sources: self.sources(),
            boot: self.boot.clone(),
        }
    }

    pub fn sources(&self) -> Vec<SourceState> {
        vec![self.kmsg.state(), self.journal.state()]
    }

    pub fn boot(&self) -> &str {
        &self.boot
    }
}

impl Default for HostOsLog {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("cr-oslog-{}-{name}", std::process::id()));
        let _ = std::fs::create_dir_all(&d);
        d
    }

    /// A stand-in for journalctl: a script printing the fixture.
    fn fake_journalctl(dir: &std::path::Path, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join("journalctl");
        std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    const JOURNAL: &str = "../hal/tests/fixtures/oslog/journal.jsonl";

    #[test]
    fn journal_reads_the_fixture_then_goes_on_after_the_cursor() {
        let dir = scratch("cursor");
        let fixture = std::fs::canonicalize(JOURNAL).unwrap();
        // First run: no cursor, prints all; later runs: print nothing new,
        // but record the arguments they got.
        let args = dir.join("args");
        let prog = fake_journalctl(
            &dir,
            &format!(
                "echo \"$@\" >> {a}\ncase \"$*\" in *after-cursor*) ;; *) cat {f} ;; esac",
                a = args.display(),
                f = fixture.display()
            ),
        );
        let mut j = Journal::new(&prog);
        let lines = j.read(10_000, Duration::from_secs(5));
        assert!(lines.len() > 100, "{}", lines.len());
        assert!(j.state().ok);
        let cursor = j.cursor.clone().unwrap();
        assert!(j.read(10_000, Duration::from_secs(5)).is_empty());
        let seen = std::fs::read_to_string(&args).unwrap();
        let mut runs = seen.lines();
        assert!(runs.next().unwrap().contains("-n 500"));
        assert!(
            runs.next()
                .unwrap()
                .contains(&format!("--after-cursor={cursor}"))
        );
        // Kernel lines left out when kmsg has them.
        let mut j = Journal::new(&prog);
        j.skip_kernel = true;
        assert!(
            j.read(10_000, Duration::from_secs(5))
                .iter()
                .all(|l| l.source != OsSource::Kernel)
        );
    }

    #[test]
    fn journal_output_is_capped_killed_and_reaped() {
        let dir = scratch("capped");
        let line = r#"{"__CURSOR":"c","MESSAGE":"x","PRIORITY":"6"}"#;
        // Endless output: we stop at 100 lines and kill it.
        let prog = fake_journalctl(&dir, &format!("while :; do echo '{line}'; done"));
        let t = Instant::now();
        let (lines, _, timed_out) = run_capped(
            &mut Command::new(&prog),
            100,
            MAX_OUTPUT,
            Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(lines.len(), 100);
        assert!(!timed_out && t.elapsed() < Duration::from_secs(3));
        // Hangs without a word: the deadline kills it.
        let prog = fake_journalctl(&dir, "sleep 30");
        let t = Instant::now();
        let (lines, _, timed_out) = run_capped(
            &mut Command::new(&prog),
            100,
            MAX_OUTPUT,
            Duration::from_millis(300),
        )
        .unwrap();
        assert!(lines.is_empty() && timed_out);
        assert!(t.elapsed() < Duration::from_secs(3), "{:?}", t.elapsed());
        // A line longer than any record is dropped, the next one kept.
        let prog = fake_journalctl(
            &dir,
            &format!("head -c 70000 /dev/zero | tr '\\0' a; echo; echo '{line}'"),
        );
        let (lines, _, _) = run_capped(
            &mut Command::new(&prog),
            100,
            MAX_OUTPUT,
            Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(lines, vec![line.to_owned()]);
    }

    #[test]
    fn unavailable_sources_say_why() {
        let dir = scratch("missing");
        let mut j = Journal::new(dir.join("no-such-journalctl"));
        assert!(j.read(10, Duration::from_secs(1)).is_empty());
        let s = j.state();
        assert!(!s.ok && s.reason.unwrap().contains("not found"));
        let prog = fake_journalctl(
            &dir,
            "echo 'No journal files were opened due to insufficient permissions.' >&2",
        );
        let mut j = Journal::new(&prog);
        assert!(j.read(10, Duration::from_secs(5)).is_empty());
        assert!(
            j.state()
                .reason
                .unwrap()
                .contains("insufficient permissions")
        );
        let k = Kmsg::open(dir.join("no-kmsg"));
        assert!(!k.ok() && k.state().reason.unwrap().contains("does not exist"));
    }

    #[test]
    fn kmsg_reads_records_from_the_device() {
        // /dev/kmsg is readable without root unless dmesg_restrict=1; then
        // the refusal must name the reason.
        let mut k = Kmsg::open("/dev/kmsg");
        if !k.ok() {
            assert!(k.state().reason.unwrap().contains("unavailable"));
            return;
        }
        // The whole ring: its newest lines are the ones a wrong clock moves.
        let lines = k.read(100_000, &boot_id());
        assert!(!lines.is_empty(), "the ring is never empty after boot");
        assert!(
            lines
                .iter()
                .all(|l| l.time_us > 1_600_000_000_000_000 && l.severity <= 7)
        );
        // Never in the future (a suspended machine's MONOTONIC would be).
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_micros() as u64;
        assert!(
            lines.iter().all(|l| l.time_us <= now + 60_000_000),
            "a kmsg line in the future"
        );
        // Non-blocking: a second read returns at once.
        let t = Instant::now();
        let _ = k.read(100, "");
        assert!(t.elapsed() < Duration::from_secs(5));
    }

    /// This machine's real journal, by hand (`cargo test -p corerouter-hal-linux
    /// --lib real_journal -- --ignored`): every line parses. Not in CI, and its
    /// lines are never written to the repository.
    #[test]
    #[ignore = "reads the local journal; run by hand"]
    fn real_journal_parses() {
        let (lines, err, _) = run_capped(
            Command::new("journalctl").args(["-o", "json", "--no-pager", "-q", "-n", "5000"]),
            5000,
            MAX_OUTPUT,
            Duration::from_secs(30),
        )
        .unwrap();
        assert!(!lines.is_empty(), "no journal here: {err}");
        let bad: Vec<String> = lines
            .iter()
            .filter_map(|l| parse_journal(l).err().map(|e| e.to_string()))
            .collect();
        assert!(
            bad.is_empty(),
            "{} of {} lines refused: {:?}",
            bad.len(),
            lines.len(),
            bad.first()
        );
    }

    #[test]
    fn boot_id_is_32_hex_digits() {
        let b = boot_id();
        assert!(b.is_empty() || b.len() == 32);
    }
}
