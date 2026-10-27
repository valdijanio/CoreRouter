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
pub mod rib;
pub mod state;
pub mod vty;

use std::path::{Path, PathBuf};
use std::time::Duration;

use corerouter_hal::HalError;
use corerouter_hal::routing::{BgpClear, RoutingDaemon, RoutingReader, SecretOpener};
use corerouter_model::Config;
use corerouter_model::bgp_rib::{BgpPrefix, BgpRib, Direction};
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
#[derive(Clone)]
pub struct Frr {
    dir: PathBuf,
    timeout: Duration,
    max_reply: usize,
    owned: render::Owned,
    /// Opens the sealed TCP MD5 keys (the engine's, G3.2a).
    secrets: Option<SecretOpener>,
}

impl std::fmt::Debug for Frr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Frr")
            .field("dir", &self.dir)
            .field("timeout", &self.timeout)
            .field("owned", &self.owned)
            .finish_non_exhaustive()
    }
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
            secrets: None,
        }
    }

    /// What FRR should run for `cfg`, keys opened with the engine's opener.
    pub fn render(&self, cfg: &Config) -> Result<Conf, HalError> {
        let open = |s: &corerouter_model::sealed::Sealed| match &self.secrets {
            Some(o) => o(s),
            None => (!s.is_sealed()).then(|| s.stored().to_owned()),
        };
        render::render(cfg, &open).map_err(|e| HalError::Rejected(e.to_string()))
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
        // mgmtd (FRR 9+) takes changes only with its datastores locked, as
        // vtysh does for a file.
        let enter = vty.run(if d == Daemon::Mgmtd {
            "configure terminal file-lock"
        } else {
            "configure terminal"
        });
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
                            conf::redact(cmd.trim_end()),
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
    ///
    /// Each daemon is its own process with its own vty, so they are
    /// changed at the same time, one named thread each (a shared
    /// prefix-list goes to mgmtd and bgpd: the commit takes the slower of
    /// the two, not their sum; docs/architecture.md has the numbers).
    pub fn sync(&self, desired: &Conf) -> Result<Synced, HalError> {
        let wanted = render::by_daemon(self.owned, desired);
        let jobs: Vec<(Daemon, Conf)> = Daemon::ALL
            .into_iter()
            .filter(|d| self.owned.iter().any(|(_, ds)| ds.contains(d)))
            .map(|d| {
                let target = wanted
                    .iter()
                    .find(|(w, _)| *w == d)
                    .map(|(_, c)| c.clone())
                    .unwrap_or_default();
                (d, target)
            })
            .collect();
        let outcomes: Vec<Outcome> = if jobs.len() < 2 {
            jobs.iter().map(|(d, t)| self.sync_one(*d, t)).collect()
        } else {
            std::thread::scope(|scope| {
                let handles: Vec<_> = jobs
                    .iter()
                    .map(|(d, t)| {
                        let d = *d;
                        std::thread::Builder::new()
                            .name(format!("frr-{}", d.name()))
                            .spawn_scoped(scope, move || self.sync_one(d, t))
                            .map_err(|e| (d, e))
                    })
                    .collect();
                handles
                    .into_iter()
                    .map(|h| match h {
                        Ok(h) => h.join().unwrap_or_else(|_| {
                            Outcome::Failed(None, HalError::Io("FRR apply thread panicked".into()))
                        }),
                        Err((d, e)) => Outcome::Failed(
                            None,
                            HalError::Io(format!("FRR {}: cannot start a thread: {e}", d.name())),
                        ),
                    })
                    .collect()
            })
        };
        let mut synced = Synced::default();
        let mut done = Vec::new();
        let mut error = None;
        for o in outcomes {
            match o {
                Outcome::Unchanged => {}
                Outcome::Applied(d, vty, before, n, leftover) => {
                    synced.commands.push((d, n));
                    synced.leftover.extend(leftover);
                    done.push((d, vty, before));
                }
                Outcome::Failed(undo, e) => {
                    done.extend(undo);
                    error.get_or_insert(e);
                }
            }
        }
        if let Some(e) = error {
            rollback(self, done);
            return Err(e);
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

    /// One daemon's part of [`Frr::sync`].
    fn sync_one(&self, d: Daemon, target: &Conf) -> Outcome {
        let mut vty = match self.connect(d) {
            Ok(v) => v,
            // A daemon that is not running only matters when it has
            // something to run.
            Err(_) if target.nodes.is_empty() => return Outcome::Unchanged,
            Err(e) => return Outcome::Failed(None, e),
        };
        let before = match self.running(&mut vty, d) {
            Ok(b) => b,
            Err(e) => return Outcome::Failed(None, e),
        };
        let script = conf::diff(&before, target);
        if script.is_empty() {
            return Outcome::Unchanged;
        }
        if let Err(e) = self.push(&mut vty, d, &script) {
            return Outcome::Failed(Some((d, vty, before)), e);
        }
        // What FRR made of it: a canonical render diffs to nothing.
        let leftover = match self.running(&mut vty, d) {
            Ok(after) => conf::diff(&after, target)
                .into_iter()
                .map(|l| format!("{}: {}", d.name(), conf::redact(&l)))
                .collect(),
            Err(_) => Vec::new(),
        };
        Outcome::Applied(d, vty, before, script.len(), leftover)
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

    /// The PIDs of the daemons CoreRouter configures, from the `.pid`
    /// files FRR writes beside the sockets: a restart changes them.
    pub fn incarnation(&self) -> Option<String> {
        let mut out = String::new();
        for d in Daemon::ALL {
            if self.owned.iter().any(|(_, ds)| ds.contains(&d)) {
                let pid =
                    std::fs::read_to_string(self.dir.join(format!("{}.pid", d.name()))).ok()?;
                out.push_str(&format!("{}={} ", d.name(), pid.trim()));
            }
        }
        Some(out)
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
/// Largest route table read from bgpd (G3.2c): ~1 KiB per route of JSON
/// at most, for [`rib::MAX_ROUTES`] routes, **estimado**.
pub const MAX_TABLE: u64 = 4 << 30;

impl Frr {
    /// `view X ` for a non-default instance (a name CoreRouter validated;
    /// checked again: it goes into a command line).
    fn view(instance: &str) -> Result<String, HalError> {
        if instance == corerouter_proto_bgp::DEFAULT_INSTANCE {
            Ok(String::new())
        } else if !instance.is_empty()
            && instance.len() <= 64
            && instance
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            Ok(format!("view {instance} "))
        } else {
            Err(HalError::Rejected(format!(
                "bad instance name {instance:?}"
            )))
        }
    }

    /// The routes of `neighbor`, one way, IPv4 and IPv6 unicast, parsed as
    /// bgpd prints them. Received: before the inbound policy when the
    /// neighbor keeps its Adj-RIB-In (`soft-reconfiguration inbound`, which
    /// CoreRouter turns on with RPKI), with the refused ones flagged; the
    /// accepted ones otherwise.
    pub fn bgp_routes(
        &self,
        instance: &str,
        neighbor: &str,
        direction: Direction,
    ) -> Result<BgpRib, HalError> {
        let addr: std::net::IpAddr = neighbor
            .parse()
            .map_err(|_| HalError::Rejected(format!("{neighbor:?} is not a neighbor address")))?;
        let view = Self::view(instance)?;
        let mut vty = self.connect(Daemon::Bgpd)?;
        let io = |e: std::io::Error| io_err(Daemon::Bgpd, e);
        // One table, streamed into `b`; `Ok(None)`: the family is not
        // active with this neighbor (FRR says so in text).
        let table = |vty: &mut Vty,
                     cmd: String,
                     b: &mut rib::Builder|
         -> Result<Option<rib::Parsed>, HalError> {
            let mut stream = vty.run_stream(&cmd, MAX_TABLE).map_err(io)?;
            let mut first = [0u8; 1];
            let n = std::io::Read::read(&mut stream, &mut first).map_err(io)?;
            if n == 0 || first[0] != b'{' {
                // Text, not JSON: "% No such neighbor or address family".
                let code = stream.finish().map_err(io)?;
                log::debug!("FRR bgpd: {cmd}: no table (code {code})");
                return Ok(None);
            }
            let chained = std::io::Read::chain(&first[..], &mut stream);
            let parsed = rib::parse_table(chained, b).map_err(HalError::Rejected)?;
            let code = stream.finish().map_err(io)?;
            if code != vty::CMD_SUCCESS {
                b.warn(format!("{cmd}: {}", vty::code_name(code)));
            }
            Ok(Some(parsed))
        };
        let mut b = rib::Builder::new(direction == Direction::Received, None);
        let mut filtered: Vec<ipnet::IpNet> = Vec::new();
        for afi in ["ipv4", "ipv6"] {
            let base = format!("show bgp {view}{afi} unicast neighbors {addr}");
            match direction {
                Direction::Advertised => {
                    table(&mut vty, format!("{base} advertised-routes json"), &mut b)?;
                }
                Direction::Received => {
                    let got = table(&mut vty, format!("{base} received-routes json"), &mut b)?;
                    if got.as_ref().is_some_and(|p| p.warning.is_some()) {
                        // No Adj-RIB-In: what was accepted, from the table.
                        let mut acc = rib::Builder::new(false, Some(addr.to_string()));
                        table(&mut vty, format!("{base} routes json"), &mut acc)?;
                        b.extend(acc.finish());
                        b.set_pre_policy(false);
                    } else if got.is_some() {
                        let mut f = rib::Builder::new(false, None);
                        table(&mut vty, format!("{base} filtered-routes json"), &mut f)?;
                        filtered.extend(f.finish().routes.into_iter().map(|r| r.prefix));
                    }
                }
            }
        }
        let mut out = b.finish();
        if !filtered.is_empty() {
            filtered.sort_unstable();
            for r in &mut out.routes {
                if filtered.binary_search(&r.prefix).is_ok() {
                    r.flags |= corerouter_model::bgp_rib::BgpRoute::FILTERED;
                    r.flags &= !corerouter_model::bgp_rib::BgpRoute::BEST;
                }
            }
        }
        Ok(out)
    }

    /// Every path of `prefix` (or the longest match of an address).
    pub fn bgp_prefix(&self, instance: &str, prefix: &str) -> Result<BgpPrefix, HalError> {
        let v6 = match prefix.parse::<ipnet::IpNet>() {
            Ok(n) => n.addr().is_ipv6(),
            Err(_) => prefix
                .parse::<std::net::IpAddr>()
                .map_err(|_| {
                    HalError::Rejected(format!("{prefix:?} is not a prefix or an address"))
                })?
                .is_ipv6(),
        };
        let view = Self::view(instance)?;
        let afi = if v6 { "ipv6" } else { "ipv4" };
        let cmd = format!("show bgp {view}{afi} unicast {prefix} json");
        let mut vty = self.connect(Daemon::Bgpd)?;
        let r = vty.run(&cmd).map_err(|e| io_err(Daemon::Bgpd, e))?;
        let text = String::from_utf8_lossy(&r.output);
        let mut p = rib::parse_prefix(&text).map_err(HalError::Rejected)?;
        // The table's default local-pref, for paths without one.
        let head = vty
            .run(&format!("show bgp {view}{afi} unicast summary json"))
            .ok()
            .map(|r| String::from_utf8_lossy(&r.output).into_owned())
            .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok());
        let fam = head
            .as_ref()
            .and_then(|h| h.get(format!("{afi}Unicast")).or(Some(h)));
        p.local_as = fam
            .and_then(|f| f.get("as"))
            .and_then(serde_json::Value::as_u64)
            .and_then(|a| u32::try_from(a).ok());
        Ok(p)
    }

    /// bgpd's own RTR state, one line; `None` without the rpki module.
    pub fn rpki_state(&self) -> Option<String> {
        let mut vty = self.connect(Daemon::Bgpd).ok()?;
        let r = vty.run("show rpki cache-connection").ok()?;
        if !r.ok() {
            return None;
        }
        let text = r.text(400);
        let line = text.split_whitespace().collect::<Vec<_>>().join(" ");
        (!line.is_empty()).then_some(line)
    }
}

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

/// What one daemon's sync did.
enum Outcome {
    Unchanged,
    /// Changed: its connection, what it ran before, commands typed, lines
    /// FRR prints differently.
    Applied(Daemon, Vty, Conf, usize, Vec<String>),
    /// Refused or unreachable; with the connection and the config before
    /// when something may have been typed (to undo).
    Failed(Option<(Daemon, Vty, Conf)>, HalError),
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
        let desired = self.render(to)?;
        let synced = self.sync(&desired)?;
        for (d, n) in &synced.commands {
            log::info!("FRR {}: {n} command(s) applied", d.name());
        }
        Ok(())
    }

    fn reader(&self) -> Box<dyn RoutingReader> {
        Box::new(FrrReader(self.clone()))
    }

    fn set_secrets(&mut self, open: SecretOpener) {
        self.secrets = Some(open);
    }

    fn bgp_clear(&mut self, instance: &str, neighbor: &str, how: BgpClear) -> Result<(), HalError> {
        self.clear(instance, neighbor, how)
    }
}

impl Frr {
    /// `clear bgp [view V] NEIGHBOR [soft in|out]` on bgpd (the enable
    /// node). `neighbor` must be an address: it goes on the vty.
    pub fn clear(&self, instance: &str, neighbor: &str, how: BgpClear) -> Result<(), HalError> {
        let addr: std::net::IpAddr = neighbor
            .parse()
            .map_err(|_| HalError::Rejected(format!("{neighbor:?} is not a neighbor address")))?;
        let view = if instance == corerouter_proto_bgp::DEFAULT_INSTANCE {
            String::new()
        } else if instance
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            format!("view {instance} ")
        } else {
            return Err(HalError::Rejected(format!(
                "bad instance name {instance:?}"
            )));
        };
        let tail = match how {
            BgpClear::Hard => "",
            BgpClear::SoftIn => " soft in",
            BgpClear::SoftOut => " soft out",
        };
        let cmd = format!("clear bgp {view}{addr}{tail}");
        let mut vty = self.connect(Daemon::Bgpd)?;
        let r = vty.run(&cmd).map_err(|e| io_err(Daemon::Bgpd, e))?;
        let text = r.text(MAX_ERROR);
        // bgpd answers a warning with success for an unknown neighbor.
        if !r.ok() || text.contains("%") {
            return Err(HalError::Rejected(format!("FRR bgpd: {cmd}: {text}")));
        }
        Ok(())
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

    fn incarnation(&mut self) -> Option<String> {
        self.0.incarnation()
    }

    fn bgp_routes(
        &mut self,
        instance: &str,
        neighbor: &str,
        direction: Direction,
    ) -> Result<BgpRib, HalError> {
        self.0.bgp_routes(instance, neighbor, direction)
    }

    fn bgp_prefix(&mut self, instance: &str, prefix: &str) -> Result<BgpPrefix, HalError> {
        self.0.bgp_prefix(instance, prefix)
    }

    fn rpki_state(&mut self) -> Option<String> {
        self.0.rpki_state()
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
        let e = frr.render(&cfg).map(|c| frr.sync(&c));
        assert!(matches!(e, Ok(Err(HalError::Io(m))) if m.contains("bgpd is not reachable")));
    }
}
