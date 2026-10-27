//! Platform — FRRouting driver (G3.1).
//!
//! On every commit that touches routing, [`Frr`] renders the config with the
//! `proto-*` crates ([`render`]), reads what each FRR daemon runs (`show
//! running-config` on its vty socket), and types only the difference
//! ([`conf::diff`]) in the daemon's configuration mode. No process is
//! started (no `vtysh`, no `frr-reload.py`), FRR is never restarted, and a
//! session the commit does not change stays up. If a command fails, what
//! was typed is undone the same way (diff back to the config read before)
//! and the commit fails.
//!
//! Diffing against the daemon's own running config, not against the
//! previous CoreRouter config, makes the same call a full resync after FRR
//! restarts (the `frr` service of the daemon calls it then).
//!
//! State is read by [`FrrReader`] on its own connections, from a thread of
//! the daemon, never under the session lock. See `docs/architecture.md`
//! ("Plano de controle") for why the vty socket and not `frr-reload.py` or
//! mgmtd, with the numbers.

pub mod conf;
pub mod render;
pub mod state;
pub mod vty;

use std::path::{Path, PathBuf};
use std::time::Duration;

use corerouter_hal::HalError;
use corerouter_hal::routing::{RoutingDaemon, RoutingReader};
use corerouter_model::Config;
use corerouter_model::routing_state::BgpSession;

use crate::conf::Conf;
use crate::render::Daemon;
use crate::vty::Vty;

/// Where FRR puts the vty sockets (`--vty_socket` changes it).
pub const DEFAULT_DIR: &str = "/var/run/frr";
/// How long one command may take before the daemon is declared hung.
pub const TIMEOUT: Duration = Duration::from_secs(30);
/// Largest answer read for a config or a session list (64 MiB: a running
/// config of a million lines is ~40 MiB, **estimado**).
pub const MAX_REPLY: usize = 64 << 20;
/// Longest error text kept from the daemon.
const MAX_ERROR: usize = 400;

/// The FRR suite, reached through its vty sockets in `dir`.
#[derive(Debug, Clone)]
pub struct Frr {
    dir: PathBuf,
    timeout: Duration,
    max_reply: usize,
    owned: render::Owned,
}

/// What one sync did, for the log and the benchmarks.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Synced {
    /// Commands typed, per daemon (empty when nothing changed).
    pub commands: Vec<(Daemon, usize)>,
    /// Lines FRR prints differently from the render: the next sync would
    /// type them again. Empty when the render is canonical.
    pub leftover: Vec<String>,
}

fn io_err(d: Daemon, e: std::io::Error) -> HalError {
    HalError::Io(format!("FRR {}: {e}", d.name()))
}

impl Frr {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Frr {
            dir: dir.into(),
            timeout: TIMEOUT,
            max_reply: MAX_REPLY,
            owned: render::OWNED,
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Answers up to `max` bytes (the route-table benchmark reads more).
    pub fn with_max_reply(mut self, max: usize) -> Self {
        self.max_reply = max;
        self
    }

    /// Own other contexts than [`render::OWNED`] (the benchmarks own
    /// prefix-lists before a `proto-*` renders them).
    pub fn with_owned(mut self, owned: render::Owned) -> Self {
        self.owned = owned;
        self
    }

    pub fn socket(&self, d: Daemon) -> PathBuf {
        self.dir.join(format!("{}.vty", d.name()))
    }

    /// A connection to `d`, in the enable node (`show running-config`
    /// lives there; a vty connection starts in the view node).
    pub fn connect(&self, d: Daemon) -> Result<Vty, HalError> {
        let mut vty = Vty::connect(&self.socket(d), self.timeout, self.max_reply).map_err(|e| {
            HalError::Io(format!(
                "FRR {} is not reachable at {}: {e}",
                d.name(),
                self.socket(d).display()
            ))
        })?;
        vty.run("enable").map_err(|e| io_err(d, e))?;
        Ok(vty)
    }

    /// The part of `d`'s running config CoreRouter owns.
    pub fn running(&self, vty: &mut Vty, d: Daemon) -> Result<Conf, HalError> {
        let r = vty.run("show running-config").map_err(|e| io_err(d, e))?;
        if !r.ok() {
            return Err(HalError::Rejected(format!(
                "FRR {}: show running-config: {}",
                d.name(),
                r.text(MAX_ERROR)
            )));
        }
        let text = String::from_utf8_lossy(&r.output);
        Conf::parse(&text)
            .map(|c| c.owned(|line| render::daemons_of(self.owned, line).contains(&d)))
            .map_err(|e| HalError::Rejected(format!("FRR {} running config: {e}", d.name())))
    }

    /// Type `script` in `d`'s configuration mode; the first command that
    /// fails stops it.
    ///
    /// The script runs between `XFRR_start_configuration` and
    /// `XFRR_end_configuration`, as `vtysh -f` sends a file (FRR
    /// `lib/lib_vty.c`): the northbound-converted commands (prefix-lists,
    /// route-maps) are committed together at the end instead of one by
    /// one, and bgpd holds new peers down until the end, so a session never
    /// comes up before the policy typed with it. The end marker is sent on
    /// every path: without it bgpd waits 600 s (`BGP_PRE_CONFIG_MAX_WAIT`).
    pub fn push(&self, vty: &mut Vty, d: Daemon, script: &[String]) -> Result<(), HalError> {
        let enter = vty.run("configure terminal");
        match enter {
            Ok(r) if r.ok() => {}
            Ok(r) => {
                return Err(HalError::Rejected(format!(
                    "FRR {}: configure terminal: {}",
                    d.name(),
                    r.text(MAX_ERROR)
                )));
            }
            Err(e) => return Err(io_err(d, e)),
        }
        let mut failed = None;
        let mut depth = 0usize;
        match vty.run("XFRR_start_configuration") {
            Ok(r) if r.ok() => {
                for (i, line) in script.iter().enumerate() {
                    let cmd = line.trim_start();
                    let r = vty.run(cmd).map_err(|e| io_err(d, e))?;
                    if !r.ok() {
                        failed = Some(format!(
                            "FRR {} refused `{}`: {} ({})",
                            d.name(),
                            cmd.trim_end(),
                            r.text(MAX_ERROR),
                            vty::code_name(r.code)
                        ));
                        break;
                    }
                    depth = depth_after(script, i);
                }
            }
            Ok(r) => failed = Some(format!("FRR {}: {}", d.name(), r.text(MAX_ERROR))),
            Err(e) => return Err(io_err(d, e)),
        }
        // The end marker is typed in the configuration node.
        for _ in 0..depth {
            vty.run("exit").map_err(|e| io_err(d, e))?;
        }
        let end = vty
            .run("XFRR_end_configuration")
            .map_err(|e| io_err(d, e))?;
        if failed.is_none() && !end.ok() {
            failed = Some(format!(
                "FRR {} refused the change at commit: {} ({})",
                d.name(),
                end.text(MAX_ERROR),
                vty::code_name(end.code)
            ));
        }
        // Back to the view node whatever happened: the next command on this
        // connection must not land in a half-entered context.
        vty.run("end").map_err(|e| io_err(d, e))?;
        failed.map_or(Ok(()), |f| Err(HalError::Rejected(f)))
    }

    /// Make FRR run `desired` (the owned contexts), typing only the
    /// difference. On a refused command every daemon already changed is
    /// put back to what it ran before, and the error says which command.
    pub fn sync(&self, desired: &Conf) -> Result<Synced, HalError> {
        let wanted = render::by_daemon(self.owned, desired);
        let mut done: Vec<(Daemon, Vty, Conf)> = Vec::new();
        let mut synced = Synced::default();
        let daemons = Daemon::ALL
            .into_iter()
            .filter(|d| self.owned.iter().any(|(_, ds)| ds.contains(d)));
        for d in daemons {
            let target = wanted
                .iter()
                .find(|(w, _)| *w == d)
                .map(|(_, c)| c.clone())
                .unwrap_or_default();
            let mut vty = match self.connect(d) {
                Ok(v) => v,
                // A daemon that is not running only matters when it has
                // something to run.
                Err(_) if target.nodes.is_empty() => continue,
                Err(e) => {
                    rollback(self, done);
                    return Err(e);
                }
            };
            let before = match self.running(&mut vty, d) {
                Ok(b) => b,
                Err(e) => {
                    rollback(self, done);
                    return Err(e);
                }
            };
            let script = conf::diff(&before, &target);
            if script.is_empty() {
                continue;
            }
            if let Err(e) = self.push(&mut vty, d, &script) {
                done.push((d, vty, before));
                rollback(self, done);
                return Err(e);
            }
            synced.commands.push((d, script.len()));
            // What FRR made of it: a canonical render diffs to nothing.
            if let Ok(after) = self.running(&mut vty, d) {
                synced.leftover.extend(
                    conf::diff(&after, &target)
                        .into_iter()
                        .map(|l| format!("{}: {l}", d.name())),
                );
            }
            done.push((d, vty, before));
        }
        if !synced.leftover.is_empty() {
            log::warn!(
                "FRR prints {} line(s) differently from CoreRouter's render; they are typed again on \
                 every sync: {:?}",
                synced.leftover.len(),
                synced.leftover.iter().take(5).collect::<Vec<_>>()
            );
        }
        Ok(synced)
    }

    /// The version line of `show version` on zebra (or bgpd): "frr 10.7.1".
    pub fn version(&self) -> Result<String, HalError> {
        let mut last = HalError::Io("no FRR daemon answers".into());
        for d in [Daemon::Zebra, Daemon::Bgpd] {
            match self
                .connect(d)
                .and_then(|mut v| v.run("show version").map_err(|e| io_err(d, e)))
            {
                Ok(r) => return Ok(version_line(&String::from_utf8_lossy(&r.output))),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    /// The BGP sessions of `cfg`'s instances, read from bgpd.
    pub fn bgp_sessions(&self, cfg: &Config) -> Result<Vec<BgpSession>, HalError> {
        let instance_of = |vrf: &str| {
            if vrf == "default" {
                corerouter_proto_bgp::DEFAULT_INSTANCE.to_owned()
            } else {
                vrf.to_owned()
            }
        };
        let views: Vec<&str> = cfg
            .routing
            .bgp
            .keys()
            .map(String::as_str)
            .filter(|n| *n != corerouter_proto_bgp::DEFAULT_INSTANCE)
            .collect();
        let mut vty = match self.connect(Daemon::Bgpd) {
            Ok(v) => v,
            // No bgpd and no instance: nothing to read, not an error.
            Err(_) if cfg.routing.bgp.is_empty() => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let mut read = |cmd: String, vrf: Option<&str>| -> Result<Vec<BgpSession>, HalError> {
            let r = vty.run(&cmd).map_err(|e| io_err(Daemon::Bgpd, e))?;
            let text = String::from_utf8_lossy(&r.output);
            // An instance that does not exist yet answers a warning, not JSON.
            if !r.ok() || text.trim().is_empty() {
                return Ok(Vec::new());
            }
            state::bgp_sessions(&text, vrf, &instance_of).map_err(HalError::Rejected)
        };
        let mut out = read("show bgp vrf all neighbors json".into(), None)?;
        for v in views {
            out.extend(read(format!("show bgp view {v} neighbors json"), Some(v))?);
        }
        Ok(out)
    }
}

/// How many contexts deep the vty is after running `script[i]`: a script
/// indents each context's commands by one space under its header and
/// leaves it with `exit`/`exit-address-family` at the header's indentation.
fn depth_after(script: &[String], i: usize) -> usize {
    let indent = |l: &str| l.len() - l.trim_start().len();
    let Some(line) = script.get(i) else { return 0 };
    let here = indent(line);
    if matches!(line.trim(), "exit" | "exit-address-family") {
        return here;
    }
    match script.get(i + 1) {
        Some(next) if indent(next) > here => here + 1,
        _ => here,
    }
}

/// Undo `done` (last first): back to the config each daemon ran before.
fn rollback(frr: &Frr, done: Vec<(Daemon, Vty, Conf)>) {
    for (d, mut vty, before) in done.into_iter().rev() {
        let undo = frr
            .running(&mut vty, d)
            .map(|now| conf::diff(&now, &before));
        match undo.and_then(|script| frr.push(&mut vty, d, &script)) {
            Ok(()) => log::info!("FRR {}: change undone", d.name()),
            Err(e) => log::error!(
                "FRR {}: the change could not be undone ({e}); the next sync puts back the \
                 running config",
                d.name()
            ),
        }
    }
}

/// "FRRouting 10.7.1 (host) on Linux(…)." → "frr 10.7.1".
fn version_line(text: &str) -> String {
    let first = text.lines().next().unwrap_or_default();
    match first.strip_prefix("FRRouting ") {
        Some(rest) => format!("frr {}", rest.split(' ').next().unwrap_or_default()),
        None => first.chars().take(60).collect(),
    }
}

impl RoutingDaemon for Frr {
    fn describe(&self) -> String {
        format!("frr (vty sockets in {})", self.dir.display())
    }

    fn apply(&mut self, _from: &Config, to: &Config) -> Result<(), HalError> {
        let desired = render::render(to).map_err(|e| HalError::Rejected(e.to_string()))?;
        let synced = self.sync(&desired)?;
        for (d, n) in &synced.commands {
            log::info!("FRR {}: {n} command(s) applied", d.name());
        }
        Ok(())
    }

    fn reader(&self) -> Box<dyn RoutingReader> {
        Box::new(FrrReader(self.clone()))
    }
}

/// [`RoutingReader`] of FRR: its own connections, a thread of its own.
pub struct FrrReader(pub Frr);

impl RoutingReader for FrrReader {
    fn bgp_sessions(&mut self, cfg: &Config) -> Result<Vec<BgpSession>, HalError> {
        self.0.bgp_sessions(cfg)
    }

    fn version(&mut self) -> Result<String, HalError> {
        self.0.version()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn depth_follows_the_script() {
        let s: Vec<String> = [
            "router bgp 1",
            " address-family ipv4 unicast",
            "  network 10.0.0.0/8",
            " exit-address-family",
            " bgp router-id 1.1.1.1",
            "exit",
            "ip prefix-list L seq 5 permit 10.0.0.0/8",
        ]
        .map(String::from)
        .to_vec();
        let d: Vec<usize> = (0..s.len()).map(|i| depth_after(&s, i)).collect();
        assert_eq!(d, [1, 2, 2, 1, 1, 0, 0]);
    }

    #[test]
    fn version_lines() {
        assert_eq!(
            version_line("FRRouting 10.7.1 (r1) on Linux(6.8.0).\nCopyright\n"),
            "frr 10.7.1"
        );
        assert_eq!(version_line(""), "");
    }

    #[test]
    fn no_daemon_and_nothing_to_run_is_not_an_error() {
        let frr = Frr::new("/nonexistent/corerouter-frr");
        assert_eq!(frr.sync(&Conf::default()), Ok(Synced::default()));
        assert_eq!(frr.bgp_sessions(&Config::default()), Ok(Vec::new()));
        let mut cfg = Config::default();
        cfg.routing.bgp.insert(
            "default".into(),
            corerouter_model::BgpInstance {
                name: "default".into(),
                asn: corerouter_model::Asn(65000),
                router_id: [10, 0, 0, 1].into(),
                disabled: false,
                comment: String::new(),
            },
        );
        let e = render::render(&cfg).map(|c| frr.sync(&c));
        assert!(matches!(e, Ok(Err(HalError::Io(m))) if m.contains("bgpd is not reachable")));
    }
}
