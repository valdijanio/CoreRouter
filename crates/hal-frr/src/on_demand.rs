//! G1.6i: FRR's protocol daemons run only while the config uses them.
//!
//! The image's init (`corerouter-init`) always runs mgmtd, zebra and
//! staticd; bgpd, ospfd, ospf6d, ldpd and bfdd it runs only when they are
//! named in a file the daemon writes ([`OnDemand`], one name per line). A
//! router without routing protocols idles 28 MiB lower on the image
//! (98,9 → 70,9 MiB, **medido**, `docs/os-image.md`).
//!
//! The order keeps routes and the other daemons safe:
//!
//! - before a sync, the file names what the new config needs *and* what it
//!   named before, and the sync waits for the new daemons' vty sockets, so
//!   the config is typed into a running daemon;
//! - after the sync succeeds, the file names only what the config needs: a
//!   daemon leaves only once its config (and so its routes) was removed by
//!   the sync, the same way an operator's `no router ospf` would.
//!
//! A failed sync leaves the larger set: the rollback may need it, and the
//! next successful sync trims it.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::conf::{Conf, Node};
use crate::render::Daemon;

/// The daemons the init starts only on demand, in its start order.
pub const ON_DEMAND: [Daemon; 5] = [
    Daemon::Bgpd,
    Daemon::Ospfd,
    Daemon::Ospf6d,
    Daemon::Ldpd,
    Daemon::Bfdd,
];
/// How long a sync waits for a daemon the init was just asked for. A cold
/// bgpd opens its vty ~0,1 s after the start on the image (**estimado**);
/// past this the sync goes on and fails on that daemon with its own error.
pub const START_WAIT: Duration = Duration::from_secs(10);
/// Longest file read back (five names and a comment line fit in 100 bytes).
const MAX_FILE: u64 = 4096;
const POLL: Duration = Duration::from_millis(20);

/// The daemons `parts` (the render split by daemon) needs running. bfdd is
/// also needed by a protocol that asks it for sessions (`neighbor X bfd`,
/// `ip ospf bfd`, `ipv6 ospf6 bfd`), not only by its own `bfd` context.
pub fn needed(parts: &[(Daemon, Conf)]) -> Vec<Daemon> {
    let mut out: Vec<Daemon> = ON_DEMAND
        .into_iter()
        .filter(|d| parts.iter().any(|(p, c)| p == d && !c.nodes.is_empty()))
        .collect();
    let bfd = parts.iter().any(|(_, c)| c.nodes.iter().any(asks_bfd));
    if bfd && !out.contains(&Daemon::Bfdd) {
        out.push(Daemon::Bfdd);
    }
    order(out)
}

fn asks_bfd(n: &Node) -> bool {
    let line = n.line.trim_start();
    let is_bfd = !line.starts_with("description")
        && !line.contains(" description ")
        && line.split_whitespace().any(|w| w == "bfd");
    is_bfd || n.children.iter().any(asks_bfd)
}

fn order(set: Vec<Daemon>) -> Vec<Daemon> {
    ON_DEMAND.into_iter().filter(|d| set.contains(d)).collect()
}

/// The names in the file's text (unknown lines are ignored: the file is
/// also read by the init, which keeps its own list).
pub fn parse(text: &str) -> Vec<Daemon> {
    let set = text
        .lines()
        .map(str::trim)
        .filter_map(|l| ON_DEMAND.into_iter().find(|d| d.name() == l))
        .collect();
    order(set)
}

pub fn render(set: &[Daemon]) -> String {
    let mut s = String::from("# FRR daemons the running config uses (corerouter-daemon, G1.6i)\n");
    for d in set {
        s.push_str(d.name());
        s.push('\n');
    }
    s
}

/// The file the init reads.
#[derive(Debug, Clone)]
pub struct OnDemand {
    file: PathBuf,
    wait: Duration,
}

impl OnDemand {
    pub fn new(file: impl Into<PathBuf>) -> Self {
        OnDemand {
            file: file.into(),
            wait: START_WAIT,
        }
    }

    /// Waits at most `wait` for a daemon (the tests shorten it).
    pub fn with_wait(mut self, wait: Duration) -> Self {
        self.wait = wait;
        self
    }

    pub fn file(&self) -> &Path {
        &self.file
    }

    /// What the file names now (nothing when it is missing).
    pub fn current(&self) -> Vec<Daemon> {
        use std::io::Read;
        let mut text = String::new();
        let read = std::fs::File::open(&self.file)
            .and_then(|f| f.take(MAX_FILE).read_to_string(&mut text));
        match read {
            Ok(_) => parse(&text),
            Err(_) => Vec::new(),
        }
    }

    /// Writes `set` when it differs from the file (temporary file and
    /// rename: the init never reads half a list).
    pub fn write(&self, set: &[Daemon]) -> std::io::Result<()> {
        if self.current() == set && self.file.exists() {
            return Ok(());
        }
        let tmp = self.file.with_extension("tmp");
        std::fs::write(&tmp, render(set))?;
        std::fs::rename(&tmp, &self.file)?;
        log::info!(
            "FRR daemons on demand: {}",
            if set.is_empty() {
                "none".to_owned()
            } else {
                set.iter().map(|d| d.name()).collect::<Vec<_>>().join(" ")
            }
        );
        Ok(())
    }

    /// Before a sync: asks for `needed` without letting go of what was
    /// asked before, then waits until each daemon of `needed` answers on
    /// `socket(d)`. A write that fails is logged; the sync then reports
    /// the daemon that is not there.
    pub fn before_sync(&self, needed: &[Daemon], socket: impl Fn(Daemon) -> PathBuf) {
        let mut set = self.current();
        set.extend(needed.iter().copied());
        if let Err(e) = self.write(&order(set)) {
            log::warn!("{}: {e}", self.file.display());
        }
        let deadline = Instant::now() + self.wait;
        for d in needed {
            let path = socket(*d);
            let started = Instant::now();
            let mut waited = false;
            while !answers(&path) {
                if Instant::now() >= deadline {
                    log::warn!(
                        "FRR {} did not open {} in {} s (see /var/log/frr-{}.log)",
                        d.name(),
                        path.display(),
                        self.wait.as_secs(),
                        d.name()
                    );
                    break;
                }
                waited = true;
                std::thread::sleep(POLL);
            }
            if waited {
                log::info!(
                    "FRR {} started on demand in {} ms",
                    d.name(),
                    started.elapsed().as_millis()
                );
            }
        }
    }

    /// After a successful sync: only what the config uses.
    pub fn after_sync(&self, needed: &[Daemon]) {
        if let Err(e) = self.write(needed) {
            log::warn!("{}: {e}", self.file.display());
        }
    }
}

#[cfg(unix)]
fn answers(path: &Path) -> bool {
    std::os::unix::net::UnixStream::connect(path).is_ok()
}

#[cfg(not(unix))]
fn answers(_path: &Path) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conf(text: &str) -> Conf {
        Conf::parse(text).unwrap()
    }

    /// A directory of its own, removed at the end.
    struct Dir(PathBuf);
    impl Dir {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!("crfrr-od-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            Dir(p)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn needs_only_the_daemons_with_config() {
        let parts = vec![
            (
                Daemon::Bgpd,
                conf("router bgp 65000\n neighbor 192.0.2.1 remote-as 65001\n"),
            ),
            (Daemon::Ospfd, Conf::default()),
        ];
        assert_eq!(needed(&parts), vec![Daemon::Bgpd]);
        assert!(needed(&[]).is_empty());
    }

    #[test]
    fn a_protocol_asking_for_bfd_needs_bfdd() {
        let bgp = conf("router bgp 65000\n neighbor 192.0.2.1 bfd\n");
        assert_eq!(
            needed(&[(Daemon::Bgpd, bgp)]),
            vec![Daemon::Bgpd, Daemon::Bfdd]
        );
        let ospf = conf("interface ether1\n ip ospf bfd\n ip ospf bfd profile fast\n");
        assert_eq!(
            needed(&[(Daemon::Ospfd, ospf)]),
            vec![Daemon::Ospfd, Daemon::Bfdd]
        );
        // A word in a description is not a session.
        let desc = conf("router bgp 65000\n neighbor 192.0.2.1 description bfd link\n");
        assert_eq!(needed(&[(Daemon::Bgpd, desc)]), vec![Daemon::Bgpd]);
    }

    #[test]
    fn the_file_round_trips_and_ignores_unknown_lines() {
        let set = vec![Daemon::Bgpd, Daemon::Ldpd];
        assert_eq!(parse(&render(&set)), set);
        assert_eq!(
            parse("zebra\nospfd\n../../etc\nbgpd\n"),
            vec![Daemon::Bgpd, Daemon::Ospfd]
        );
    }

    #[test]
    fn before_keeps_the_old_set_and_after_trims_it() {
        let dir = Dir::new("sets");
        let od = OnDemand::new(dir.path().join("frr-daemons")).with_wait(Duration::ZERO);
        assert!(od.current().is_empty());
        od.before_sync(&[Daemon::Ospfd], |d| dir.path().join(d.name()));
        assert_eq!(od.current(), vec![Daemon::Ospfd]);
        od.after_sync(&[Daemon::Ospfd]);
        // BGP comes, OSPF goes: both run until the sync removed OSPF.
        od.before_sync(&[Daemon::Bgpd], |d| dir.path().join(d.name()));
        assert_eq!(od.current(), vec![Daemon::Bgpd, Daemon::Ospfd]);
        od.after_sync(&[Daemon::Bgpd]);
        assert_eq!(od.current(), vec![Daemon::Bgpd]);
        od.after_sync(&[]);
        assert!(od.current().is_empty());
    }

    #[test]
    fn waits_for_the_socket_of_a_new_daemon() {
        let dir = Dir::new("wait");
        let sock = dir.path().join("bgpd.vty");
        let od = OnDemand::new(dir.path().join("frr-daemons"));
        let s2 = sock.clone();
        // The "init" starts bgpd 100 ms after the file asks for it.
        let t = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            std::os::unix::net::UnixListener::bind(&s2).unwrap()
        });
        let t0 = Instant::now();
        od.before_sync(&[Daemon::Bgpd], |_| sock.clone());
        let waited = t0.elapsed();
        let _listener = t.join().unwrap();
        assert!(waited >= Duration::from_millis(90), "{waited:?}");
        assert!(waited < START_WAIT, "{waited:?}");
    }
}
