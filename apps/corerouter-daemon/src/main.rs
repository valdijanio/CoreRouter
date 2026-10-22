//! `corerouter-daemon [--control <port>] [--backend virtual|linux] [--config-dir <dir>]
//!  [--ws <port> [--ws-origin <origin>]... [--web-root <dir>]]
//!  [--discovery-port <port> | --no-discovery]`
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

mod node_id;

use std::path::PathBuf;
use std::process::ExitCode;

use corerouter_control::{
    DEFAULT_PORT, SharedHost, WsPolicy, bind_loopback, serve, spawn_clock, spawn_ws,
};
use corerouter_discovery::{Agent, AgentConfig};
use corerouter_engine::{ConfigStorage, MemoryStorage, Session, shared};
use corerouter_hal::{Hal, VirtualHal};
use corerouter_storage_fs::FileStorage;

const USAGE: &str = "\
usage: corerouter-daemon [--control <port>] [--backend virtual|linux] [--config-dir <dir>]
                         [--ws <port> [--ws-origin <origin>]... [--web-root <dir>]]
                         [--discovery-port <port> | --no-discovery]

  --ws <port>           WebSocket for the web GUI on 127.0.0.1:<port>
  --ws-origin <origin>  also allow pages from <origin> (e.g. http://127.0.0.1:8080 for
                        `trunk serve`); the default is only http://127.0.0.1:<port>
                        and http://localhost:<port>
  --web-root <dir>      serve the built web GUI (`trunk build` -> dist/) on the --ws port
  --discovery-port <p>  UDP port of CRDP neighbor discovery (default 7979)
  --no-discovery        do not open the CRDP port at all";

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
fn websocket(args: &Args, host: SharedHost) -> Result<(), String> {
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
    spawn_ws(listener, host, policy)
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
    // Kept alive until `serve` returns (never, in practice).
    let _discovery = match args.discovery_port {
        None => None,
        Some(port) => {
            let cfg = AgentConfig {
                port,
                node_id: node_id::load_or_create(config_dir.as_deref()),
                control_port: Some(args.port),
                ws_port: args.ws,
                board: format!("{} {}", std::env::consts::ARCH, args.backend),
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
    let host = SharedHost(session);
    if let Err(e) = websocket(&args, host.clone()) {
        eprintln!("{e}");
        return ExitCode::FAILURE;
    }
    serve(listener, host);
    ExitCode::SUCCESS
}
