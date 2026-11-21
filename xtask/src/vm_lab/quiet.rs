//! G0.26d: a quiet CCD for a measurement. While a `vm-lab run --perf` round
//! holds VM 1's lock, this user's host processes (the other sessions'
//! `cargo`/`rustc`, the app, the desktop) leave VM 1's host CPUs; when the
//! round ends they get their CPUs back. No root: a user may change the CPU
//! affinity of their own processes (`taskset`, util-linux), and nothing of
//! the system's settings changes.
//!
//! - Every `SCAN_EVERY` a thread looks at `/proc`: a process of this user
//!   whose `Cpus_allowed_list` touches the measurement CPUs gets them taken
//!   out (`taskset -a -p -c`, every thread). A process started later by one
//!   already moved inherits the mask and costs nothing; one started from
//!   elsewhere is caught at the next scan.
//! - The original mask of each process is kept, with its start time (a
//!   reused pid is not someone else's), in `vm/quiet.state`, rewritten on
//!   each change. The end puts each mask back, and widens the processes
//!   born during the round with exactly the quiet mask to every online CPU.
//! - If the `vm-lab run` dies before (Ctrl-C, kill), the next `vm-lab`
//!   command finds the state file with a dead owner and puts everything back
//!   (`recover`).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// How often the thread looks for new processes on the measurement CPUs.
const SCAN_EVERY: Duration = Duration::from_secs(2);
/// The state file in `vm/`.
pub(super) const STATE: &str = "quiet.state";
/// What the round script prints (stderr) once it holds the lock: the host
/// starts quieting then, never while the round only waits for the lock.
pub(super) const MARKER: &str = "vm-lab: quiet: lock taken";
/// How long the round waits, after `MARKER`, for the host's go (the file
/// `go_file`): the first pass, then the command. Past it the command runs
/// anyway (a host that could not quiet still answers; this is the bound).
pub(super) const GO_WAIT_S: u32 = 15;

/// The file in the VM the host creates once the first pass is done.
pub(super) fn go_file(round: &str) -> String {
    let safe: String = round
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '.')
        .collect();
    format!("/run/corerouter-lab.quiet.{safe}")
}

/// A CPU list as the kernel writes it (`0-7,16-23`).
pub(super) fn parse_cpus(list: &str) -> Option<BTreeSet<u32>> {
    let mut set = BTreeSet::new();
    for part in list.trim().split(',').filter(|p| !p.is_empty()) {
        match part.split_once('-') {
            Some((a, b)) => {
                let (a, b): (u32, u32) = (a.trim().parse().ok()?, b.trim().parse().ok()?);
                if a > b || b > 4095 {
                    return None;
                }
                set.extend(a..=b);
            }
            None => {
                set.insert(part.trim().parse().ok()?);
            }
        }
    }
    Some(set)
}

/// The kernel's list form of `set` (`0-7,16-23`).
pub(super) fn format_cpus(set: &BTreeSet<u32>) -> String {
    let mut parts = Vec::new();
    let mut it = set.iter().copied().peekable();
    while let Some(lo) = it.next() {
        let mut hi = lo;
        while it.peek() == Some(&(hi + 1)) {
            hi += 1;
            it.next();
        }
        parts.push(if hi == lo {
            lo.to_string()
        } else {
            format!("{lo}-{hi}")
        });
    }
    parts.join(",")
}

/// The mask a process gets: its own without the measurement CPUs. `None`:
/// leave it (it does not touch them, or it would have no CPU left).
pub(super) fn quiet_mask(current: &BTreeSet<u32>, avoid: &BTreeSet<u32>) -> Option<BTreeSet<u32>> {
    if current.is_disjoint(avoid) {
        return None;
    }
    let rest: BTreeSet<u32> = current.difference(avoid).copied().collect();
    (!rest.is_empty()).then_some(rest)
}

/// What `/proc/<pid>/status` and `stat` say about a process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ProcInfo {
    pub uid: u32,
    pub cpus: BTreeSet<u32>,
    /// Kernel threads have no user memory (`VmSize` absent): never touched.
    pub user_space: bool,
}

/// The fields of `/proc/<pid>/status` this module needs.
pub(super) fn parse_status(text: &str) -> Option<ProcInfo> {
    let field = |k: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(k)?.strip_prefix(':'))
            .map(str::trim)
    };
    let uid = field("Uid")?.split_whitespace().next()?.parse().ok()?;
    let cpus = parse_cpus(field("Cpus_allowed_list")?)?;
    Some(ProcInfo {
        uid,
        cpus,
        user_space: field("VmSize").is_some(),
    })
}

fn read_proc(pid: u32) -> Option<(ProcInfo, u64)> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    Some((parse_status(&status)?, super::start_ticks(pid)?))
}

/// One moved process: who, and the mask it had.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Moved {
    pub pid: u32,
    pub start: u64,
    pub original: BTreeSet<u32>,
}

/// `vm/quiet.state`: `owner=<round>`, `avoid=<cpus>`, then one
/// `<pid> <start> <original cpus>` line per moved process.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct State {
    pub owner: String,
    pub avoid: BTreeSet<u32>,
    pub moved: Vec<Moved>,
}

impl State {
    pub(super) fn render(&self) -> String {
        let mut s = format!("owner={}\navoid={}\n", self.owner, format_cpus(&self.avoid));
        for m in &self.moved {
            s.push_str(&format!(
                "{} {} {}\n",
                m.pid,
                m.start,
                format_cpus(&m.original)
            ));
        }
        s
    }

    pub(super) fn parse(text: &str) -> Option<State> {
        let mut lines = text.lines();
        let owner = lines.next()?.strip_prefix("owner=")?.trim().to_owned();
        let avoid = parse_cpus(lines.next()?.strip_prefix("avoid=")?)?;
        let moved = lines
            .filter_map(|l| {
                let mut f = l.split_whitespace();
                Some(Moved {
                    pid: f.next()?.parse().ok()?,
                    start: f.next()?.parse().ok()?,
                    original: parse_cpus(f.next()?)?,
                })
            })
            .collect();
        Some(State {
            owner,
            avoid,
            moved,
        })
    }
}

/// What the end does with one process of this user.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Back {
    /// Its mask again (it was moved and still has the quiet mask).
    Original(BTreeSet<u32>),
    /// Born during the round with the quiet mask: every online CPU.
    Online,
    /// Nothing (not ours to change, or someone set another mask meanwhile).
    Leave,
}

/// `recorded`: the original mask when this process was moved (same pid and
/// start time). `quiet`: the mask the moved processes got (`online − avoid`).
pub(super) fn back(
    recorded: Option<&BTreeSet<u32>>,
    current: &BTreeSet<u32>,
    avoid: &BTreeSet<u32>,
    quiet: &BTreeSet<u32>,
) -> Back {
    match recorded {
        // Still without the measurement CPUs: ours to give back.
        Some(orig) if current.is_disjoint(avoid) && orig != current => Back::Original(orig.clone()),
        Some(_) => Back::Leave,
        None if current == quiet => Back::Online,
        None => Back::Leave,
    }
}

fn online() -> BTreeSet<u32> {
    std::fs::read_to_string("/sys/devices/system/cpu/online")
        .ok()
        .and_then(|t| parse_cpus(&t))
        .unwrap_or_default()
}

fn own_uid() -> Option<u32> {
    read_proc(std::process::id()).map(|(p, _)| p.uid)
}

/// `taskset -a -p -c <cpus> <pid>`: every thread of `pid`.
fn set_affinity(pid: u32, cpus: &BTreeSet<u32>) -> bool {
    Command::new("taskset")
        .args(["-a", "-p", "-c", &format_cpus(cpus), &pid.to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn pids() -> Vec<u32> {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|e| e.file_name().to_str()?.parse().ok())
        .collect()
}

/// Which processes a scan may touch: this user's (`Uid`), or, in tests,
/// only the listed pids.
#[derive(Clone)]
pub(super) enum Scope {
    User(u32),
    #[cfg(test)]
    Only(Vec<u32>),
}

impl Scope {
    fn candidates(&self) -> Vec<u32> {
        match self {
            Scope::User(_) => pids(),
            #[cfg(test)]
            Scope::Only(p) => p.clone(),
        }
    }

    fn takes(&self, info: &ProcInfo) -> bool {
        match self {
            Scope::User(uid) => info.uid == *uid && info.user_space,
            #[cfg(test)]
            Scope::Only(_) => true,
        }
    }
}

/// The quieting: a thread that keeps the measurement CPUs free of this
/// user's processes until `stop`.
pub(super) struct Quiet {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<State>>,
    state_path: PathBuf,
    scope: Scope,
    started: Instant,
}

impl Quiet {
    /// Starts the thread. `avoid`: the measurement VM's host CPUs.
    pub(super) fn start(
        state_path: &Path,
        owner: &str,
        avoid: BTreeSet<u32>,
        scope: Scope,
    ) -> Result<Quiet, String> {
        let stop = Arc::new(AtomicBool::new(false));
        let mut state = State {
            owner: owner.to_owned(),
            avoid,
            moved: Vec::new(),
        };
        super::write(state_path, &state.render())?;
        // The first pass before returning: the caller lets the round's
        // command start only after it (G0.26d: a pass of ~300 `taskset`
        // overlapped the first repetition, 1149–1433 ms against ~860,
        // **measured**).
        let me = std::process::id();
        let first = Instant::now();
        scan(&scope, me, &mut state);
        super::write(state_path, &state.render())?;
        eprintln!(
            "vm-lab: quiet: {} host process(es) off CPUs {} in {:.1} s for the measurement \
             (--no-quiet leaves them)",
            state.moved.len(),
            format_cpus(&state.avoid),
            first.elapsed().as_secs_f64()
        );
        let (flag, path, sc) = (Arc::clone(&stop), state_path.to_path_buf(), scope.clone());
        let thread = std::thread::Builder::new()
            .name("vm-lab-quiet".into())
            .spawn(move || {
                while !flag.load(Ordering::Relaxed) {
                    // Short naps, so `stop` is seen quickly.
                    let until = Instant::now() + SCAN_EVERY;
                    while Instant::now() < until && !flag.load(Ordering::Relaxed) {
                        std::thread::sleep(Duration::from_millis(100));
                    }
                    if flag.load(Ordering::Relaxed) {
                        break;
                    }
                    let before = state.moved.len();
                    scan(&sc, me, &mut state);
                    if state.moved.len() != before {
                        let _ = super::write(&path, &state.render());
                    }
                }
                state
            })
            .map_err(|e| format!("vm-lab-quiet thread: {e}"))?;
        Ok(Quiet {
            stop,
            thread: Some(thread),
            state_path: state_path.to_path_buf(),
            scope,
            started: Instant::now(),
        })
    }

    /// Stops the thread and gives every CPU back.
    pub(super) fn finish(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let Some(state) = self.thread.take().and_then(|t| t.join().ok()) else {
            // The thread died: the file has what it moved.
            recover_file(&self.state_path, &self.scope);
            return;
        };
        let (back_n, widened) = restore(&state, &self.scope);
        let _ = std::fs::remove_file(&self.state_path);
        eprintln!(
            "vm-lab: quiet: CPUs back after {:.0} s ({back_n} restored, {widened} born during the round widened)",
            self.started.elapsed().as_secs_f64()
        );
    }
}

impl Drop for Quiet {
    /// An early return or a panic of the caller still gives the CPUs back.
    fn drop(&mut self) {
        if self.thread.is_some() {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(t) = self.thread.take()
                && let Ok(state) = t.join()
            {
                restore(&state, &self.scope);
                let _ = std::fs::remove_file(&self.state_path);
            }
        }
    }
}

/// Moves what touches `state.avoid` (other than `me`) and records it.
fn scan(scope: &Scope, me: u32, state: &mut State) {
    for pid in scope.candidates() {
        if pid == me {
            continue;
        }
        let Some((info, start)) = read_proc(pid) else {
            continue;
        };
        if !scope.takes(&info) {
            continue;
        }
        let Some(mask) = quiet_mask(&info.cpus, &state.avoid) else {
            continue;
        };
        let known = state.moved.iter().any(|m| m.pid == pid && m.start == start);
        if set_affinity(pid, &mask) && !known {
            state.moved.push(Moved {
                pid,
                start,
                original: info.cpus,
            });
        }
    }
}

/// Puts the masks back: `(restored, widened)`.
fn restore(state: &State, scope: &Scope) -> (usize, usize) {
    let all = online();
    let quiet: BTreeSet<u32> = all.difference(&state.avoid).copied().collect();
    let recorded: BTreeMap<(u32, u64), &BTreeSet<u32>> = state
        .moved
        .iter()
        .map(|m| ((m.pid, m.start), &m.original))
        .collect();
    let (mut restored, mut widened) = (0, 0);
    for pid in scope.candidates() {
        let Some((info, start)) = read_proc(pid) else {
            continue;
        };
        if !scope.takes(&info) {
            continue;
        }
        match back(
            recorded.get(&(pid, start)).copied(),
            &info.cpus,
            &state.avoid,
            &quiet,
        ) {
            Back::Original(orig) => restored += usize::from(set_affinity(pid, &orig)),
            Back::Online => widened += usize::from(set_affinity(pid, &all)),
            Back::Leave => {}
        }
    }
    (restored, widened)
}

fn recover_file(path: &Path, scope: &Scope) -> Option<(usize, usize)> {
    let state = State::parse(&std::fs::read_to_string(path).ok()?)?;
    let n = restore(&state, scope);
    let _ = std::fs::remove_file(path);
    Some(n)
}

/// A `vm-lab run --perf` that died while quieting left `vm/quiet.state`
/// behind: put every CPU back. A live owner (its round still measuring) is
/// left alone.
pub(super) fn recover(dir: &Path) {
    let path = dir.join(STATE);
    let Ok(text) = std::fs::read_to_string(&path) else {
        return;
    };
    let Some(state) = State::parse(&text) else {
        let _ = std::fs::remove_file(&path);
        return;
    };
    if super::round_alive(&state.owner) {
        return;
    }
    let Some(uid) = own_uid() else {
        return;
    };
    if let Some((r, w)) = recover_file(&path, &Scope::User(uid)) {
        eprintln!(
            "vm-lab: quiet: a `vm-lab run --perf` (round {}) ended without giving the CPUs back; \
             done now ({r} restored, {w} widened)",
            state.owner
        );
    }
}

/// The scope of a real round: this user's processes.
pub(super) fn user_scope() -> Result<Scope, String> {
    own_uid()
        .map(Scope::User)
        .ok_or_else(|| "cannot read this process's uid in /proc".to_owned())
}

/// Copies `from` to our stderr and returns once `MARKER` went by (`true`)
/// or the stream ended (`false`); the caller keeps copying with
/// `std::io::copy`. Byte chunks, not lines: cargo's progress bar uses `\r`.
pub(super) fn relay_until_marker(
    from: &mut impl std::io::Read,
    to: &mut impl std::io::Write,
) -> bool {
    let mut tail: Vec<u8> = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = match from.read(&mut buf) {
            Ok(0) | Err(_) => return false,
            Ok(n) => n,
        };
        let Some(chunk) = buf.get(..n) else {
            return false;
        };
        let _ = to.write_all(chunk);
        let _ = to.flush();
        tail.extend_from_slice(chunk);
        if tail.windows(MARKER.len()).any(|w| w == MARKER.as_bytes()) {
            return true;
        }
        // Keep only what a marker split across chunks needs.
        let keep = MARKER.len().saturating_sub(1);
        if tail.len() > keep {
            tail.drain(..tail.len() - keep);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(list: &str) -> BTreeSet<u32> {
        parse_cpus(list).unwrap()
    }

    #[test]
    fn cpu_lists_parse_and_print_like_the_kernel() {
        assert_eq!(format_cpus(&set("0-7,16-23")), "0-7,16-23");
        assert_eq!(format_cpus(&set("3,1,2,9")), "1-3,9");
        assert_eq!(set("5").len(), 1);
        assert_eq!(set("0-31\n").len(), 32);
        assert!(parse_cpus("7-3").is_none());
        assert!(parse_cpus("x").is_none());
        assert!(parse_cpus("0-99999").is_none());
        assert_eq!(format_cpus(&BTreeSet::new()), "");
    }

    #[test]
    fn only_processes_on_the_measurement_cpus_move_and_never_to_nothing() {
        let avoid = set("8-15,24-31");
        assert_eq!(quiet_mask(&set("0-31"), &avoid), Some(set("0-7,16-23")));
        assert_eq!(quiet_mask(&set("0-7"), &avoid), None, "already off them");
        assert_eq!(quiet_mask(&set("8-15"), &avoid), None, "would have no CPU");
        assert_eq!(quiet_mask(&set("4-11"), &avoid), Some(set("4-7")));
    }

    #[test]
    fn status_gives_uid_cpus_and_kernel_threads_apart() {
        let user = "Name:\tcargo\nUid:\t29999\t29999\t29999\t29999\nVmSize:\t  1000 kB\nCpus_allowed_list:\t0-31\n";
        let p = parse_status(user).unwrap();
        assert_eq!((p.uid, p.cpus.len(), p.user_space), (29999, 32, true));
        let kthread = "Name:\tkworker/0:1\nUid:\t0\t0\t0\t0\nCpus_allowed_list:\t0\n";
        assert!(!parse_status(kthread).unwrap().user_space);
        assert!(parse_status("Name:\tx\n").is_none());
    }

    #[test]
    fn the_state_file_round_trips() {
        let s = State {
            owner: "123.456".into(),
            avoid: set("8-15,24-31"),
            moved: vec![
                Moved {
                    pid: 10,
                    start: 99,
                    original: set("0-31"),
                },
                Moved {
                    pid: 11,
                    start: 7,
                    original: set("0-3,8"),
                },
            ],
        };
        assert_eq!(State::parse(&s.render()), Some(s));
        assert_eq!(State::parse("garbage"), None);
        // A broken line is skipped, not the whole file.
        let t = "owner=1.2\navoid=8-15\n10 99 0-31\nbad line\n";
        assert_eq!(State::parse(t).unwrap().moved.len(), 1);
    }

    #[test]
    fn the_end_gives_back_only_what_the_round_took() {
        let avoid = set("8-15,24-31");
        let quiet = set("0-7,16-23");
        let orig = set("0-31");
        // Moved, still quiet: its mask again.
        assert_eq!(
            back(Some(&orig), &quiet, &avoid, &quiet),
            Back::Original(orig.clone())
        );
        // Moved, but someone gave it the measurement CPUs again: leave it.
        assert_eq!(back(Some(&orig), &set("0-31"), &avoid, &quiet), Back::Leave);
        // Born during the round from a moved parent: every CPU.
        assert_eq!(back(None, &quiet, &avoid, &quiet), Back::Online);
        // Not moved, other mask (pinned by its owner): leave it.
        assert_eq!(back(None, &set("2-3"), &avoid, &quiet), Back::Leave);
    }

    #[test]
    fn the_marker_is_found_across_chunks_and_everything_is_relayed() {
        struct Chunks(Vec<Vec<u8>>);
        impl std::io::Read for Chunks {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.0.is_empty() {
                    return Ok(0);
                }
                let c = self.0.remove(0);
                buf[..c.len()].copy_from_slice(&c);
                Ok(c.len())
            }
        }
        let text = format!("compiling\r50%\rvm-lab: x\n{MARKER}\nrest");
        let bytes = text.as_bytes();
        let cut = text.find(MARKER).unwrap() + 5;
        let mut from = Chunks(vec![bytes[..cut].to_vec(), bytes[cut..].to_vec()]);
        let mut to = Vec::new();
        assert!(relay_until_marker(&mut from, &mut to));
        assert_eq!(to, bytes);
        let mut none = Chunks(vec![b"no marker here\n".to_vec()]);
        let mut to = Vec::new();
        assert!(!relay_until_marker(&mut none, &mut to));
        assert_eq!(to, b"no marker here\n");
    }

    /// The real thing on a child of this test: moved off a CPU, then back.
    #[test]
    fn a_child_leaves_the_cpus_and_gets_them_back() {
        if Command::new("taskset").arg("--version").output().is_err() {
            eprintln!("skip: no taskset");
            return;
        }
        let all = online();
        let Some(&last) = all.iter().next_back() else {
            return;
        };
        if all.len() < 2 {
            eprintln!("skip: one CPU");
            return;
        }
        let avoid: BTreeSet<u32> = [last].into();
        let mut child = Command::new("sleep").arg("30").spawn().unwrap();
        let pid = child.id();
        let cpus = |pid| read_proc(pid).unwrap().0.cpus;
        let before = cpus(pid);
        let dir = std::env::temp_dir().join(format!("vmlab-quiet-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join(STATE);
        let q = Quiet::start(&path, "1.1", avoid.clone(), Scope::Only(vec![pid])).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while cpus(pid).contains(&last) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        let during = cpus(pid);
        // The file is rewritten right after the move.
        let mut file = None;
        while Instant::now() < deadline {
            file = std::fs::read_to_string(&path)
                .ok()
                .and_then(|t| State::parse(&t))
                .filter(|f| !f.moved.is_empty());
            if file.is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let file = file.unwrap();
        q.finish();
        let after = cpus(pid);
        let _ = child.kill();
        let _ = child.wait();
        let gone = !path.exists();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(!during.contains(&last), "{during:?}");
        assert_eq!(file.moved.first().map(|m| m.pid), Some(pid));
        assert_eq!(after, before);
        assert!(gone, "the state file is removed at the end");
    }
}
