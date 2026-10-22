//! `corerouter-daemon [--control <port>] [--backend virtual|linux] [--config-dir <dir>]`
//!
//! The virtual backend is the default: touching a real kernel must be an
//! explicit choice. TLS/auth for remote management is docs/gaps.md G0.3.
//!
//! Persistence (G0.6): every commit is saved to `--config-dir` and restored at
//! start-up. Without the flag the linux backend uses `/config` (the writable
//! partition of the router image) and the virtual lab keeps nothing.

use std::path::PathBuf;
use std::process::ExitCode;

use corerouter_control::{DEFAULT_PORT, SharedHost, bind_loopback, serve};
use corerouter_engine::{ConfigStorage, MemoryStorage, Session, shared};
use corerouter_hal::{Hal, VirtualHal};
use corerouter_storage_fs::FileStorage;

const USAGE: &str =
    "usage: corerouter-daemon [--control <port>] [--backend virtual|linux] [--config-dir <dir>]";

/// Writable config partition of the router image (docs/architecture.md 1.1).
const PRODUCTION_CONFIG_DIR: &str = "/config";

struct Args {
    port: u16,
    backend: String,
    config_dir: Option<PathBuf>,
}

fn parse_args() -> Result<Args, String> {
    let mut out = Args {
        port: DEFAULT_PORT,
        backend: "virtual".into(),
        config_dir: None,
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
            "-h" | "--help" => return Err(USAGE.into()),
            other => return Err(format!("unknown argument '{other}'\n{USAGE}")),
        }
    }
    Ok(out)
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
fn storage(args: &Args) -> Result<Box<dyn ConfigStorage>, String> {
    let (dir, explicit) = match (&args.config_dir, args.backend.as_str()) {
        (Some(d), _) => (d.clone(), true),
        (None, "linux") => (PathBuf::from(PRODUCTION_CONFIG_DIR), false),
        (None, _) => return Ok(Box::new(MemoryStorage::default())),
    };
    match FileStorage::open(&dir) {
        Ok(fs) => Ok(Box::new(fs)),
        Err(e) if explicit => Err(format!("cannot use --config-dir {}: {e}", dir.display())),
        Err(e) => {
            log::error!(
                "cannot use {}: {e}; config will NOT survive a restart",
                dir.display()
            );
            Ok(Box::new(MemoryStorage::default()))
        }
    }
}

fn main() -> ExitCode {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(
        "warn,corerouter_daemon=info,corerouter_control=info,corerouter_engine=info",
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
    let storage = match storage(&args) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let storage_name = storage.describe();
    let session = shared(Session::with_storage(hal, storage));
    let listener = match bind_loopback(args.port) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("cannot open control port {}: {e}", args.port);
            return ExitCode::FAILURE;
        }
    };
    log::info!(
        "corerouter-daemon {} on 127.0.0.1:{} (backend: {}, storage: {storage_name})",
        env!("CARGO_PKG_VERSION"),
        args.port,
        args.backend
    );
    serve(listener, SharedHost(session));
    ExitCode::SUCCESS
}
