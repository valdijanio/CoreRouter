//! `corerouter-daemon [--control <port>] [--backend virtual|linux] [--config-dir <dir>]
//!  [--ws <port> [--ws-origin <origin>]... [--web-root <dir>]]
//!  [--discovery-port <port> | --no-discovery] [--discovery-transport interfaces|loopback]`
//!
//! The virtual backend is the default: touching a real kernel must be an
//! explicit choice. TLS/auth for remote management is docs/gaps.md G0.3, so
//! both the control port and the WebSocket listen on 127.0.0.1 only.
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
//! Graceful shutdown (G5.5): on SIGINT (Ctrl+C) or SIGTERM (`kill`) the
//! daemon stops accepting control and WebSocket connections, sends the
//! discovery goodbye (CRDP hold 0, and with the linux backend LLDP TTL 0)
//! on every interface it announced on, waiting at most [`GOODBYE_WAIT`],
//! then takes the session lock for good (a commit in progress finishes, no
//! new one starts, so no save is cut short) and exits with code 0. A second
//! signal during the shutdown exits at once (code 130). Safe Mode active at
//! that moment is not undone here: its changes were never saved, so the
//! next start comes up on the config from before it, as G1.4 defines.
//! The signals come from `signal-hook`'s iterator (a pipe written by its
//! handler, read on a thread): no `unsafe` here and no async runtime.

#[cfg(target_os = "linux")]
mod link_discovery;
mod node_id;

use std::path::PathBuf;
use std::process::ExitCode;
use std::thread;
use std::time::{Duration, Instant};

use corerouter_control::{
    DEFAULT_PORT, SharedHost, Shutdown, WsPolicy, bind_loopback, serve_until, spawn_clock,
    spawn_ws_until,
};
use corerouter_discovery::{Agent, AgentConfig, Transport, enable_lab_default};
use corerouter_engine::{ConfigStorage, MemoryStorage, Session, lock, shared};
use corerouter_hal::{Hal, VirtualHal};
use corerouter_storage_fs::FileStorage;
use signal_hook::consts::{SIGINT, SIGTERM};
use signal_hook::iterator::Signals;

const USAGE: &str = "\
usage: corerouter-daemon [--control <port>] [--backend virtual|linux] [--config-dir <dir>]
                         [--ws <port> [--ws-origin <origin>]... [--web-root <dir>]]
                         [--discovery-port <port> | --no-discovery]
                         [--discovery-transport interfaces|loopback]

  --ws <port>           WebSocket for the web GUI on 127.0.0.1:<port>
  --ws-origin <origin>  also allow pages from <origin> (e.g. http://127.0.0.1:8080 for
                        `trunk serve`); the default is only http://127.0.0.1:<port>
                        and http://localhost:<port>
  --web-root <dir>      serve the built web GUI (`trunk build` -> dist/) on the --ws port
  --discovery-port <p>  UDP port of CRDP neighbor discovery (default 7979)
  --no-discovery        no neighbor discovery at all (CRDP, and with the linux
                        backend LLDP and MNDP)
  --discovery-transport where CRDP announces: `interfaces` (host interfaces named like the
                        router's; default of --backend linux) or `loopback` (this host
                        only, labs see each other; default of --backend virtual)";

/// Longest wait for the discovery goodbyes when shutting down.
const GOODBYE_WAIT: Duration = Duration::from_secs(1);
/// Exit code of a second signal during the shutdown (128 + SIGINT, as a
/// shell reports an interrupted command).
const EXIT_INTERRUPTED: i32 = 130;

/// Writable config partition of the router image (docs/architecture.md 1.1).
const PRODUCTION_CONFIG_DIR: &str = "/config";

struct Args {
    port: u16,
    backend: String,
    config_dir: Option<PathBuf>,
    ws: Option<u16>,
    ws_origins: Vec<String>,
    web_root: Option<PathBuf>,
    /// `None`: `--no-discovery`.
    discovery_port: Option<u16>,
    /// `None`: chosen by the backend.
    discovery_transport: Option<Transport>,
}

fn parse_args() -> Result<Args, String> {
    let mut out = Args {
        port: DEFAULT_PORT,
        backend: "virtual".into(),
        config_dir: None,
        ws: None,
        ws_origins: Vec::new(),
        web_root: None,
        discovery_port: Some(corerouter_discovery::PORT),
        discovery_transport: None,
    };
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--control" => {
                let v = args.next().ok_or("--control needs a port")?;
                out.port = v.parse().map_err(|_| format!("bad port '{v}'"))?;
            }
            "--backend" => out.backend = args.next().ok_or("--backend needs a value")?,
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
            "-h" | "--help" => return Err(USAGE.into()),
            other => return Err(format!("unknown argument '{other}'\n{USAGE}")),
        }
    }
    if out.ws.is_none() && (!out.ws_origins.is_empty() || out.web_root.is_some()) {
        return Err("--ws-origin and --web-root need --ws <port>".into());
    }
    Ok(out)
}

/// Start the WebSocket endpoint on its own thread, if asked for.
fn websocket(args: &Args, host: SharedHost, shutdown: &Shutdown) -> Result<(), String> {
    let Some(port) = args.ws else {
        return Ok(());
    };
    if let Some(root) = &args.web_root
        && !root.join("index.html").is_file()
    {
        return Err(format!(
            "--web-root {}: no index.html (build it with `trunk build` in apps/corerouter-gui)",
            root.display()
        ));
    }
    let listener = bind_loopback(port).map_err(|e| format!("cannot open --ws port {port}: {e}"))?;
    let mut origins = WsPolicy::same_origin(port);
    origins.extend(args.ws_origins.iter().cloned());
    log::info!(
        "WebSocket on ws://127.0.0.1:{port}/ws (loopback only; NO authentication or TLS \
         until G0.3); allowed page origins: {}",
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
    };
    spawn_ws_until(listener, host, policy, shutdown.clone())
        .map(|_| ())
        .map_err(|e| format!("cannot start the WebSocket thread: {e}"))
}

fn backend(name: &str) -> Result<Box<dyn Hal>, String> {
    match name {
        "virtual" => Ok(Box::new(VirtualHal::default())),
        #[cfg(target_os = "linux")]
        "linux" => Ok(Box::new(corerouter_hal_linux::LinuxHal::new())),
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

/// Discovery threads that say goodbye on the way out.
struct Discovery {
    crdp: Option<Agent>,
    #[cfg(target_os = "linux")]
    lldp: Option<link_discovery::LinkDiscovery>,
}

/// Block until SIGINT/SIGTERM, then shut down as the module doc says.
/// Never returns: exits the process.
fn run_until_signal(
    mut signals: Signals,
    session: &corerouter_engine::Shared,
    shutdown: &Shutdown,
    discovery: Discovery,
) -> ! {
    let sig = signals.forever().next().unwrap_or(SIGTERM);
    log::info!(
        "{}: shutting down (again to exit at once)",
        signal_name(sig)
    );
    let spawned = thread::Builder::new()
        .name("signals".into())
        .spawn(move || {
            if let Some(sig) = signals.forever().next() {
                log::warn!("{}: exiting now, without goodbye", signal_name(sig));
                std::process::exit(EXIT_INTERRUPTED);
            }
        });
    if let Err(e) = spawned {
        log::warn!("a second signal will not cut the shutdown short: {e}");
    }
    shutdown.close();
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
    // First, so a signal during start-up waits in the queue instead of
    // killing the process before the goodbye exists.
    let signals = match Signals::new([SIGINT, SIGTERM]) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("cannot handle SIGINT/SIGTERM: {e}");
            return ExitCode::FAILURE;
        }
    };
    let hal = match backend(&args.backend) {
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
    let session = shared(Session::with_storage(hal, storage));
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
         loopback only, no authentication until G0.3)",
        env!("CARGO_PKG_VERSION"),
        args.port,
        args.backend
    );
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
    let discovery = Discovery {
        crdp,
        #[cfg(target_os = "linux")]
        lldp: link_discovery(&args, &session, node_id),
    };
    let shutdown = Shutdown::default();
    let host = SharedHost(session.clone());
    if let Err(e) = websocket(&args, host.clone(), &shutdown) {
        eprintln!("{e}");
        return ExitCode::FAILURE;
    }
    let stop = shutdown.clone();
    let control = thread::Builder::new()
        .name("control".into())
        .spawn(move || serve_until(listener, host, &stop));
    if let Err(e) = control {
        eprintln!("cannot start the control thread: {e}");
        return ExitCode::FAILURE;
    }
    run_until_signal(signals, &session, &shutdown, discovery)
}
