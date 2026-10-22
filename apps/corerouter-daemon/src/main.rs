//! `corerouter-daemon [--control <port>] [--backend virtual|linux] [--config-dir <dir>]
//!  [--listen <addr:port>] [--ws <port> [--ws-origin <origin>]... [--web-root <dir>]]
//!  [--ws-listen <addr:port>] [--token-file <path>] [--reset-admin-password]
//!  [--discovery-port <port> | --no-discovery] [--discovery-transport interfaces|loopback]
//!  [--manage <names>] [--unmanaged <names>]`
//!
//! The virtual backend is the default: touching a real kernel must be an
//! explicit choice.
//!
//! Authentication and TLS (G0.3, docs/control-protocol.md): every request
//! needs a token. The control port and `--ws` stay on 127.0.0.1, plain;
//! local clients send the local token from `--token-file` (default
//! `corerouter_control::local_token::path`, readable only by this OS user).
//! `--listen` / `--ws-listen` open the same channel on any address, always
//! TLS, always with a login. The certificate is made once in the config
//! dir (`tls-cert.pem`, `tls-key.pem` 0600) and its fingerprint is logged
//! at start-up so operators can compare it with what their client shows.
//! With no account yet, `admin` (group full) is created **without a
//! password**, as RouterOS does (G0.3b): it logs in with an empty password
//! from this machine only, the GUI and the terminal ask it to set one, and
//! while any account of group full has no password every login from the
//! network is refused (the TLS listeners still start, with a warning).
//! `--reset-admin-password` takes `admin`'s password away again (and
//! re-enables it in group full): the way back in for a lost password.
//!
//! `--ws` serves the control methods over WebSocket for the GUI in a browser
//! (G0.4). Only pages from an allowed origin may connect: by default the
//! origin of this port itself, which serves the GUI with `--web-root`.
//!
//! Persistence (G0.6): every commit is saved to `--config-dir` and restored at
//! start-up. Without the flag the linux backend uses `/config` (the writable
//! partition of the router image) and the virtual lab keeps nothing.
//!
//! Safe Mode (G1.4): a clock thread ticks the session every second (timeouts),
//! and a control or WebSocket connection that closes undoes the Safe Mode it
//! held. Changes made in Safe Mode are saved only when it is confirmed.
//!
//! Neighbor discovery (G5.1, docs/discovery.md): CRDP announces on the
//! interfaces listed with `ip.neighbor.discovery.set` (none by default) and
//! fills `ip.neighbor.list`. The node id is kept in `<config-dir>/node-id`.
//! With the linux backend (G5.2) the same interfaces also send and receive
//! LLDP, and MNDP from MikroTiks is listened to (never sent); the virtual
//! lab has no real links, so it runs CRDP only.
//! The virtual lab (G5.4) has no real ports: CRDP goes over this host's
//! loopback, and a new lab announces on ether1 out of the box, so labs on
//! one computer see each other. The linux backend uses the real interfaces
//! and announces on none until told to. `--discovery-transport` overrides the
//! choice (a lab run in a network namespace over veths named like its ports
//! uses `interfaces`; that is how the netns test exercises the real path).
//!
//! Ownership (G1.18, docs/architecture.md): the linux backend manages the
//! physical ports, veths whose peer is in the same namespace, and what
//! CoreRouter created; other links (docker0, a container's veth, ppp, `lo`)
//! are listed as unmanaged and never touched. `--manage` adds veth/dummy
//! links, `--unmanaged` sets ports aside (names or `prefix*`, comma-separated).
//!
//! Graceful shutdown (G5.5): on SIGINT (Ctrl+C) or SIGTERM (`kill`) the
//! daemon stops accepting control and WebSocket connections, sends the
//! discovery goodbye (CRDP hold 0, and with the linux backend LLDP TTL 0)
//! on every interface it announced on, waiting at most [`GOODBYE_WAIT`],
//! then takes the session lock for good (a commit in progress finishes, no
//! new one starts, so no save is cut short) and exits with code 0. A second
//! signal during the shutdown exits at once (code 130). Safe Mode active at
//! that moment is not undone here: its changes were never saved, so the
//! next start comes up on the config from before it, as G1.4 defines.
//! The signals come from `signal-hook`'s `flag::register` (its handler only
//! sets an atomic flag, polled here every [`SIGNAL_POLL`]): no `unsafe`
//! here, no async runtime, and the same path on unix and Windows.
//!
//! NTP and remote syslog (G4.6): the SNTP client of `system.ntp.client.set`
//! measures the clock offset (it does not set the clock yet) and reports
//! to `system.ntp.client.get`; `system.logging.*` rules send config changes,
//! failed commands and NTP state changes to remote syslog collectors (RFC
//! 5424 over UDP). Both run with either backend: they are this process
//! talking to the network, like the control channel.

#[cfg(target_os = "linux")]
mod link_discovery;
mod node_id;
mod ntp_client;
mod remote_log;

use std::path::PathBuf;
use std::process::ExitCode;
use std::thread;
use std::time::{Duration, Instant};

use corerouter_control::tls::ServerIdentity;
use corerouter_control::{
    DEFAULT_PORT, Endpoint, Gate, SharedHost, Shutdown, WsPolicy, bind_loopback, local_token,
    serve_until, spawn_clock, spawn_until, spawn_ws_until, thread_runner,
};
use corerouter_discovery::{Agent, AgentConfig, Transport, enable_lab_default};
use corerouter_engine::{ConfigStorage, MemoryStorage, Session, lock, shared};
use corerouter_hal::{Hal, Prober, VirtualHal};
use corerouter_storage_fs::FileStorage;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use signal_hook::consts::{SIGINT, SIGTERM};

const USAGE: &str = "\
usage: corerouter-daemon [--control <port>] [--backend virtual|linux] [--config-dir <dir>]
                         [--listen <addr:port>] [--ws <port> [--ws-origin <origin>]...
                         [--web-root <dir>]] [--ws-listen <addr:port>]
                         [--token-file <path>] [--reset-admin-password]
                         [--discovery-port <port> | --no-discovery]
                         [--discovery-transport interfaces|loopback]
                         [--lab-ping auto|host|sim]
                         [--manage <names>] [--unmanaged <names>]

  --control <port>      plain control channel on 127.0.0.1:<port> (default 7979)
  --listen <addr:port>  control channel over TLS on any address, e.g. 0.0.0.0:8729 or
                        [::]:8729; login required (the local token is not accepted there)
  --token-file <path>   where to write the local token (default: see docs/control-protocol.md)
  --reset-admin-password  leave `admin` (group full, enabled) without a password, as on
                        the first start, and go on running; set a new one from this
                        machine (network logins are refused until then)
  --ws <port>           WebSocket for the web GUI on 127.0.0.1:<port>
  --ws-listen <a:port>  the same over TLS (wss://, https:// for --web-root) on any address
  --ws-origin <origin>  also allow pages from <origin> (e.g. http://127.0.0.1:8080 for
                        `trunk serve`); the default is only http://127.0.0.1:<port>
                        and http://localhost:<port>
  --web-root <dir>      serve the built web GUI (`trunk build` -> dist/) on the --ws port
  --discovery-port <p>  UDP port of CRDP neighbor discovery (default 7979)
  --no-discovery        no neighbor discovery at all (CRDP, and with the linux
                        backend LLDP and MNDP)
  --discovery-transport where CRDP announces: `interfaces` (host interfaces named like the
                        router's; default of --backend linux) or `loopback` (this host
                        only, labs see each other; default of --backend virtual)
  --lab-ping <how>      what Tools > Ping/MTR reach in the virtual lab: `host` (this
                        host's ICMP: needs ping_group_range or CAP_NET_RAW), `sim`
                        (the simulated network of docs/tools.md) or `auto` (host when
                        allowed, else sim; the default)
  --manage <names>      linux backend: also manage these veth/dummy links (comma-separated
                        names or prefix*, e.g. `lab*`)
  --unmanaged <names>   linux backend: never touch these links, physical ports included";

/// Longest wait for the discovery goodbyes when shutting down.
const GOODBYE_WAIT: Duration = Duration::from_secs(1);
/// How often the signal flags are looked at.
const SIGNAL_POLL: Duration = Duration::from_millis(50);
/// Exit code of a second signal during the shutdown (128 + SIGINT, as a
/// shell reports an interrupted command).
const EXIT_INTERRUPTED: i32 = 130;

/// Writable config partition of the router image (docs/architecture.md 1.1).
const PRODUCTION_CONFIG_DIR: &str = "/config";

struct Args {
    port: u16,
    listen: Option<std::net::SocketAddr>,
    ws_listen: Option<std::net::SocketAddr>,
    token_file: Option<PathBuf>,
    reset_admin: bool,
    backend: String,
    config_dir: Option<PathBuf>,
    ws: Option<u16>,
    ws_origins: Vec<String>,
    web_root: Option<PathBuf>,
    /// `None`: `--no-discovery`.
    discovery_port: Option<u16>,
    /// `None`: chosen by the backend.
    discovery_transport: Option<Transport>,
    /// Virtual lab tools: `auto`, `host` or `sim`.
    lab_ping: String,
    /// `--manage` / `--unmanaged` (linux backend).
    policy: corerouter_hal_linux::Policy,
}

fn parse_args() -> Result<Args, String> {
    let mut out = Args {
        port: DEFAULT_PORT,
        listen: None,
        ws_listen: None,
        token_file: None,
        reset_admin: false,
        backend: "virtual".into(),
        config_dir: None,
        ws: None,
        ws_origins: Vec::new(),
        web_root: None,
        discovery_port: Some(corerouter_discovery::PORT),
        discovery_transport: None,
        lab_ping: "auto".into(),
        policy: corerouter_hal_linux::Policy::default(),
    };
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--control" => {
                let v = args.next().ok_or("--control needs a port")?;
                out.port = v.parse().map_err(|_| format!("bad port '{v}'"))?;
            }
            "--backend" => out.backend = args.next().ok_or("--backend needs a value")?,
            "--listen" | "--ws-listen" => {
                let v = args.next().ok_or_else(|| format!("{a} needs ADDR:PORT"))?;
                let addr = v
                    .parse()
                    .map_err(|_| format!("{a}: '{v}' is not ADDR:PORT ([::]:8729 for IPv6)"))?;
                if a == "--listen" {
                    out.listen = Some(addr);
                } else {
                    out.ws_listen = Some(addr);
                }
            }
            "--token-file" => {
                let v = args.next().ok_or("--token-file needs a path")?;
                out.token_file = Some(PathBuf::from(v));
            }
            "--reset-admin-password" => out.reset_admin = true,
            "--config-dir" => {
                let v = args.next().ok_or("--config-dir needs a directory")?;
                out.config_dir = Some(PathBuf::from(v));
            }
            "--ws" => {
                let v = args.next().ok_or("--ws needs a port")?;
                out.ws = Some(v.parse().map_err(|_| format!("bad port '{v}'"))?);
            }
            "--ws-origin" => {
                let v = args.next().ok_or("--ws-origin needs an origin")?;
                if !(v.starts_with("http://") || v.starts_with("https://")) || v.ends_with('/') {
                    return Err(format!(
                        "--ws-origin is scheme://host[:port] as the browser sends it, got '{v}'"
                    ));
                }
                out.ws_origins.push(v);
            }
            "--web-root" => {
                let v = args.next().ok_or("--web-root needs a directory")?;
                out.web_root = Some(PathBuf::from(v));
            }
            "--discovery-port" => {
                let v = args.next().ok_or("--discovery-port needs a port")?;
                out.discovery_port = Some(v.parse().map_err(|_| format!("bad port '{v}'"))?);
            }
            "--no-discovery" => out.discovery_port = None,
            "--discovery-transport" => {
                let v = args.next().ok_or("--discovery-transport needs a value")?;
                out.discovery_transport = Some(match v.as_str() {
                    "interfaces" => Transport::Interfaces,
                    "loopback" => Transport::Loopback,
                    _ => {
                        return Err(format!(
                            "bad --discovery-transport '{}' (interfaces | loopback)",
                            v.chars().take(32).collect::<String>()
                        ));
                    }
                });
            }
            "--lab-ping" => {
                let v = args.next().ok_or("--lab-ping needs auto, host or sim")?;
                if !matches!(v.as_str(), "auto" | "host" | "sim") {
                    return Err(format!(
                        "bad --lab-ping '{}' (auto | host | sim)",
                        v.chars().take(32).collect::<String>()
                    ));
                }
                out.lab_ping = v;
            }
            "--manage" => {
                let v = args.next().ok_or("--manage needs interface names")?;
                out.policy.manage = corerouter_hal_linux::Policy::patterns(&v)?;
            }
            "--unmanaged" => {
                let v = args.next().ok_or("--unmanaged needs interface names")?;
                out.policy.unmanaged = corerouter_hal_linux::Policy::patterns(&v)?;
            }
            "-h" | "--help" => return Err(USAGE.into()),
            other => return Err(format!("unknown argument '{other}'\n{USAGE}")),
        }
    }
    if out.ws.is_none()
        && out.ws_listen.is_none()
        && (!out.ws_origins.is_empty() || out.web_root.is_some())
    {
        return Err("--ws-origin and --web-root need --ws <port> or --ws-listen".into());
    }
    Ok(out)
}

/// Start the WebSocket endpoints on their own threads, if asked for.
/// `local_gate` takes the local token (loopback); `remote_gate` only logins.
fn websocket(
    args: &Args,
    host: &SharedHost,
    (local_gate, remote_gate): (&Gate, &Gate),
    tls: Option<&ServerIdentity>,
    shutdown: &Shutdown,
) -> Result<(), String> {
    if let Some(root) = &args.web_root
        && !root.join("index.html").is_file()
    {
        return Err(format!(
            "--web-root {}: no index.html (build it with `trunk build` in apps/corerouter-gui)",
            root.display()
        ));
    }
    if let Some(port) = args.ws {
        let listener =
            bind_loopback(port).map_err(|e| format!("cannot open --ws port {port}: {e}"))?;
        let mut origins = WsPolicy::same_origin(port);
        origins.extend(args.ws_origins.iter().cloned());
        log::info!(
            "WebSocket on ws://127.0.0.1:{port}/ws (loopback only, login required); \
             allowed page origins: {}",
            origins.join(", ")
        );
        if let Some(root) = &args.web_root {
            log::info!(
                "web GUI from {} at http://127.0.0.1:{port}/",
                root.display()
            );
        }
        let policy = WsPolicy {
            origins,
            web_root: args.web_root.clone(),
            same_host: false,
        };
        spawn_ws_until(
            Endpoint::loopback(listener),
            host.clone(),
            policy,
            local_gate.clone(),
            shutdown.clone(),
        )
        .map_err(|e| format!("cannot start the WebSocket thread: {e}"))?;
    }
    if let (Some(addr), Some(id)) = (args.ws_listen, tls) {
        let listener = std::net::TcpListener::bind(addr)
            .map_err(|e| format!("cannot open --ws-listen {addr}: {e}"))?;
        log::info!(
            "WebSocket over TLS on wss://{addr}/ws (login required){}",
            if args.web_root.is_some() {
                format!("; web GUI at https://{addr}/")
            } else {
                String::new()
            }
        );
        let policy = WsPolicy {
            origins: args.ws_origins.clone(),
            web_root: args.web_root.clone(),
            same_host: true,
        };
        spawn_ws_until(
            Endpoint::tls(listener, id.config.clone()),
            host.clone(),
            policy,
            remote_gate.clone(),
            shutdown.clone(),
        )
        .map_err(|e| format!("cannot start the WebSocket TLS thread: {e}"))?;
    }
    Ok(())
}

/// The lab's diagnostic tools: this host's ICMP or the simulated network.
fn lab_tools(lab: VirtualHal, how: &str) -> Result<VirtualHal, String> {
    #[cfg(target_os = "linux")]
    let host = corerouter_hal_linux::icmp::HostProber::detect();
    #[cfg(not(target_os = "linux"))]
    let host: Result<corerouter_hal::SimProber, String> =
        Err("host ICMP is only implemented on Linux".into());
    match (how, host) {
        ("sim", _) => Ok(lab),
        (_, Ok(p)) => {
            log::info!(
                "virtual lab tools use this host's network: {}",
                p.describe()
            );
            Ok(lab.with_prober(Arc::new(p)))
        }
        ("host", Err(e)) => Err(format!("--lab-ping host: {e}")),
        (_, Err(e)) => {
            log::info!("virtual lab tools use the simulated network ({e})");
            Ok(lab)
        }
    }
}

/// The TLS identity, when something listens with TLS: kept in the config
/// dir, or made for this run only (the virtual lab without one).
fn tls_identity(
    args: &Args,
    config_dir: Option<&std::path::Path>,
) -> Result<Option<ServerIdentity>, String> {
    if args.listen.is_none() && args.ws_listen.is_none() {
        return Ok(None);
    }
    let id = match config_dir {
        Some(dir) => {
            let (id, created) = corerouter_control::tls::load_or_create(dir)
                .map_err(|e| format!("TLS certificate in {}: {e}", dir.display()))?;
            if created {
                log::info!(
                    "made a new self-signed TLS certificate in {}",
                    dir.display()
                );
            }
            id
        }
        None => {
            log::warn!(
                "no --config-dir: the TLS certificate is new on every start, so clients \
                 that remembered it will refuse the next one"
            );
            let (cert, key) = corerouter_control::tls::generate()?;
            corerouter_control::tls::identity_from_pem(cert.as_bytes(), key.as_bytes())?
        }
    };
    log::info!("TLS certificate fingerprint: {}", id.fingerprint);
    Ok(Some(id))
}

/// First start (no account at all): `admin` in group full without a
/// password. `--reset-admin-password`: no password for admin again.
fn bootstrap_admin(session: &corerouter_engine::Shared, reset: bool) {
    if let Some(what) = lock(session).bootstrap_admin(reset) {
        log::warn!(
            "{what}: log in as admin with an empty password from this machine \
             (GUI or `corerouter-cli shell`) and set one"
        );
    }
}

/// Listening on the network while an account of group full has no
/// password: the listener runs, but refuses every login until one is set.
fn warn_open_admin(session: &corerouter_engine::Shared, args: &Args) {
    let missing = lock(session).admins_without_password();
    let remote: Vec<String> = [args.listen, args.ws_listen]
        .into_iter()
        .flatten()
        .filter(|a| !a.ip().is_loopback())
        .map(|a| a.to_string())
        .collect();
    if !missing.is_empty() && !remote.is_empty() {
        log::warn!(
            "{} listen(s) on the network, but user(s) {} of group full have no password: \
             every network login is refused until a password is set (user.set from this \
             machine)",
            remote.join(", "),
            missing.join(", ")
        );
    }
}

/// Write the local token where local clients look for it.
fn write_local_token(args: &Args, token: &str) -> Option<PathBuf> {
    let written = match &args.token_file {
        Some(path) => write_token_at(path, token).map(|()| path.clone()),
        None => local_token::create(args.port, token),
    };
    match written {
        Ok(path) => {
            log::info!(
                "local token for CLI/MCP on this machine: {}",
                path.display()
            );
            Some(path)
        }
        Err(e) => {
            log::warn!(
                "local token not written ({e}): local clients must log in with a user \
                 and password"
            );
            None
        }
    }
}

fn write_token_at(path: &std::path::Path, token: &str) -> std::io::Result<()> {
    use std::io::Write as _;
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)?;
    }
    let _ = std::fs::remove_file(path);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path)?;
    writeln!(f, "{token}")
}

fn backend(
    name: &str,
    policy: &corerouter_hal_linux::Policy,
    lab_ping: &str,
) -> Result<Box<dyn Hal>, String> {
    let _ = policy; // only the linux backend has one
    match name {
        "virtual" => Ok(Box::new(lab_tools(VirtualHal::default(), lab_ping)?)),
        #[cfg(target_os = "linux")]
        "linux" => Ok(Box::new(corerouter_hal_linux::LinuxHal::with_policy(
            policy.clone(),
        ))),
        #[cfg(not(target_os = "linux"))]
        "linux" => Err("the linux backend only exists on Linux".into()),
        other => Err(format!("unknown backend '{other}' (virtual | linux)")),
    }
}

/// An explicit `--config-dir` that cannot be opened is a startup error. The
/// implicit `/config` of the linux backend degrades to memory instead: a
/// router that boots without persistence still forwards traffic, and
/// `state.inspect` shows `storage.backend`.
/// The storage, and its directory when it is on disk.
fn storage(args: &Args) -> Result<(Box<dyn ConfigStorage>, Option<PathBuf>), String> {
    let (dir, explicit) = match (&args.config_dir, args.backend.as_str()) {
        (Some(d), _) => (d.clone(), true),
        (None, "linux") => (PathBuf::from(PRODUCTION_CONFIG_DIR), false),
        (None, _) => return Ok((Box::new(MemoryStorage::default()), None)),
    };
    match FileStorage::open(&dir) {
        Ok(fs) => Ok((Box::new(fs), Some(dir))),
        Err(e) if explicit => Err(format!("cannot use --config-dir {}: {e}", dir.display())),
        Err(e) => {
            log::error!(
                "cannot use {}: {e}; config will NOT survive a restart",
                dir.display()
            );
            Ok((Box::new(MemoryStorage::default()), None))
        }
    }
}

/// LLDP + passive MNDP (G5.2): only on a real kernel, and not with
/// `--no-discovery`. Never stops the daemon.
#[cfg(target_os = "linux")]
fn link_discovery(
    args: &Args,
    session: &corerouter_engine::Shared,
    node_id: corerouter_discovery::NodeId,
) -> Option<link_discovery::LinkDiscovery> {
    if args.discovery_port.is_none() || args.backend != "linux" {
        return None;
    }
    let local = link_discovery::LocalSystem {
        chassis: node_id.to_string(),
        description: format!("CoreRouter {}", env!("CARGO_PKG_VERSION")),
    };
    match link_discovery::LinkDiscovery::spawn(session.clone(), local, corerouter_proto_mndp::PORT)
    {
        Ok(l) => Some(l),
        Err(e) => {
            log::error!("LLDP/MNDP are off: cannot start their thread: {e}");
            None
        }
    }
}

fn signal_name(sig: i32) -> &'static str {
    match sig {
        SIGINT => "SIGINT",
        SIGTERM => "SIGTERM",
        _ => "signal",
    }
}

/// SIGINT and SIGTERM, one flag each, set by signal-hook's handler.
struct Signals(Vec<(i32, Arc<AtomicBool>)>);

impl Signals {
    fn register() -> std::io::Result<Self> {
        let mut flags = Vec::new();
        for sig in [SIGINT, SIGTERM] {
            let flag = Arc::new(AtomicBool::new(false));
            signal_hook::flag::register(sig, flag.clone())?;
            flags.push((sig, flag));
        }
        Ok(Self(flags))
    }

    /// Block until a signal arrives (one that came earlier counts); clears it.
    fn wait(&self) -> i32 {
        loop {
            for (sig, flag) in &self.0 {
                if flag.swap(false, Ordering::SeqCst) {
                    return *sig;
                }
            }
            thread::sleep(SIGNAL_POLL);
        }
    }
}

/// Discovery threads that say goodbye on the way out.
struct Discovery {
    crdp: Option<Agent>,
    #[cfg(target_os = "linux")]
    lldp: Option<link_discovery::LinkDiscovery>,
}

/// Block until SIGINT/SIGTERM, then shut down as the module doc says.
/// Never returns: exits the process.
fn run_until_signal(
    signals: Signals,
    session: &corerouter_engine::Shared,
    shutdown: &Shutdown,
    discovery: Discovery,
    token_file: Option<PathBuf>,
) -> ! {
    let sig = signals.wait();
    log::info!(
        "{}: shutting down (again to exit at once)",
        signal_name(sig)
    );
    let spawned = thread::Builder::new()
        .name("signals".into())
        .spawn(move || {
            let sig = signals.wait();
            log::warn!("{}: exiting now, without goodbye", signal_name(sig));
            std::process::exit(EXIT_INTERRUPTED);
        });
    if let Err(e) = spawned {
        log::warn!("a second signal will not cut the shutdown short: {e}");
    }
    shutdown.close();
    if let Some(f) = token_file {
        let _ = std::fs::remove_file(f);
    }
    let deadline = Instant::now() + GOODBYE_WAIT;
    let left = || deadline.saturating_duration_since(Instant::now());
    #[cfg(target_os = "linux")]
    let lldp = discovery
        .lldp
        .map(|l| thread::spawn(move || l.shutdown(GOODBYE_WAIT)));
    let crdp = discovery.crdp.map(|a| a.shutdown(left()));
    match crdp {
        Some(Some(n)) => log::info!("shutting down: sent CRDP goodbye on {n} interface(s)"),
        Some(None) => log::warn!(
            "shutting down: CRDP goodbye not sent within {} ms; neighbors forget us \
             after their hold time",
            GOODBYE_WAIT.as_millis()
        ),
        None => log::info!("shutting down: neighbor discovery was off, no goodbye"),
    }
    #[cfg(target_os = "linux")]
    if let Some(t) = lldp {
        while !t.is_finished() && !left().is_zero() {
            thread::sleep(Duration::from_millis(10));
        }
        match t.is_finished().then(|| t.join().ok().flatten()).flatten() {
            Some(n) => log::info!("shutting down: sent LLDP shutdown on {n} port(s)"),
            None => log::warn!("shutting down: LLDP shutdown not sent in time"),
        }
    }
    // Held until the process ends: a commit in progress finishes first and
    // no new one (no new save) starts.
    let s = corerouter_engine::lock(session);
    if s.in_safe_mode() {
        log::warn!(
            "shutting down in Safe Mode: its changes were not saved; the next start \
             uses the config from before Safe Mode"
        );
    }
    log::info!("stopped");
    std::process::exit(0)
}

fn main() -> ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(
        "warn,corerouter_daemon=info,corerouter_control=info,corerouter_engine=info,\
         corerouter_discovery=info",
    ))
    .init();
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    // First, so a signal during start-up is kept in its flag instead of
    // killing the process before the goodbye exists.
    let signals = match Signals::register() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("cannot handle SIGINT/SIGTERM: {e}");
            return ExitCode::FAILURE;
        }
    };
    let hal = match backend(&args.backend, &args.policy, &args.lab_ping) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let (storage, config_dir) = match storage(&args) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let storage_name = storage.describe();
    let mut session = Session::with_storage(hal, storage);
    session.set_runner(thread_runner());
    let session = shared(session);
    if let Err(e) = spawn_clock(session.clone()) {
        eprintln!("cannot start the clock thread: {e}");
        return ExitCode::FAILURE;
    }
    let listener = match bind_loopback(args.port) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("cannot open control port {}: {e}", args.port);
            return ExitCode::FAILURE;
        }
    };
    log::info!(
        "corerouter-daemon {} on 127.0.0.1:{} (backend: {}, storage: {storage_name}; \
         login or local token required)",
        env!("CARGO_PKG_VERSION"),
        args.port,
        args.backend
    );
    bootstrap_admin(&session, args.reset_admin);
    warn_open_admin(&session, &args);
    let tls = match tls_identity(&args, config_dir.as_deref()) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    let gate = Gate::default();
    let token = match corerouter_control::auth::new_token() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("cannot make the local token: {e}");
            return ExitCode::FAILURE;
        }
    };
    gate.add_local_token(&token);
    let token_file = write_local_token(&args, &token);
    let node_id = node_id::load_or_create(config_dir.as_deref());
    let crdp = match args.discovery_port {
        None => None,
        Some(port) => {
            let transport = args
                .discovery_transport
                .unwrap_or(match args.backend.as_str() {
                    "virtual" => Transport::Loopback,
                    _ => Transport::Interfaces,
                });
            if transport == Transport::Loopback {
                let mut s = lock(&session);
                if s.storage_status().loaded_from.is_none()
                    && let Err(e) = enable_lab_default(&mut s)
                {
                    log::warn!("virtual lab: discovery default not set: {e}");
                }
            }
            let cfg = AgentConfig {
                port,
                node_id,
                control_port: Some(args.port),
                ws_port: args.ws,
                tls_port: args.listen.map(|a| a.port()),
                wss_port: args.ws_listen.map(|a| a.port()),
                board: format!("{} {}", std::env::consts::ARCH, args.backend),
                transport,
            };
            match Agent::spawn(session.clone(), cfg) {
                Ok(a) => Some(a),
                Err(e) => {
                    // A router without discovery still forwards traffic.
                    log::error!("neighbor discovery is off: cannot open UDP {port}: {e}");
                    None
                }
            }
        }
    };
    // Neither stops the daemon: a router without them still forwards.
    if let Err(e) = ntp_client::spawn(session.clone(), corerouter_proto_ntp::PORT) {
        log::error!("NTP client is off: cannot start its thread: {e}");
    }
    if let Err(e) = remote_log::spawn(session.clone()) {
        log::error!("remote logging is off: cannot start its thread: {e}");
    }
    let discovery = Discovery {
        crdp,
        #[cfg(target_os = "linux")]
        lldp: link_discovery(&args, &session, node_id),
    };
    let shutdown = Shutdown::default();
    let host = SharedHost(session.clone());
    // The TLS endpoints never take the local token: it proves a local
    // OS user, which a remote peer is not.
    let remote_gate = Gate::default();
    if let Err(e) = websocket(&args, &host, (&gate, &remote_gate), tls.as_ref(), &shutdown) {
        eprintln!("{e}");
        return ExitCode::FAILURE;
    }
    if let (Some(addr), Some(id)) = (args.listen, &tls) {
        let started = std::net::TcpListener::bind(addr)
            .map_err(|e| format!("cannot open --listen {addr}: {e}"))
            .and_then(|l| {
                spawn_until(
                    Endpoint::tls(l, id.config.clone()),
                    host.clone(),
                    remote_gate.clone(),
                    shutdown.clone(),
                )
                .map_err(|e| format!("cannot start the TLS control thread: {e}"))
            });
        match started {
            Ok(_) => log::info!("control channel over TLS on {addr} (login required)"),
            Err(e) => {
                eprintln!("{e}");
                return ExitCode::FAILURE;
            }
        }
    }
    let stop = shutdown.clone();
    let control = thread::Builder::new()
        .name("control".into())
        .spawn(move || serve_until(Endpoint::loopback(listener), host, gate, &stop));
    if let Err(e) = control {
        eprintln!("cannot start the control thread: {e}");
        return ExitCode::FAILURE;
    }
    run_until_signal(signals, &session, &shutdown, discovery, token_file)
}
