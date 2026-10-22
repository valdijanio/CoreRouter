//! `corerouter-daemon [--control <port>] [--backend virtual|linux]`
//!
//! The virtual backend is the default: touching a real kernel must be an
//! explicit choice. TLS/auth for remote management is docs/gaps.md G0.3.

use std::process::ExitCode;

use corerouter_control::{DEFAULT_PORT, SharedHost, bind_loopback, serve};
use corerouter_engine::{Session, shared};
use corerouter_hal::{Hal, VirtualHal};

const USAGE: &str = "usage: corerouter-daemon [--control <port>] [--backend virtual|linux]";

struct Args {
    port: u16,
    backend: String,
}

fn parse_args() -> Result<Args, String> {
    let mut out = Args {
        port: DEFAULT_PORT,
        backend: "virtual".into(),
    };
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--control" => {
                let v = args.next().ok_or("--control needs a port")?;
                out.port = v.parse().map_err(|_| format!("bad port '{v}'"))?;
            }
            "--backend" => out.backend = args.next().ok_or("--backend needs a value")?,
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
    let session = shared(Session::new(hal));
    let listener = match bind_loopback(args.port) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("cannot open control port {}: {e}", args.port);
            return ExitCode::FAILURE;
        }
    };
    log::info!(
        "corerouter-daemon {} on 127.0.0.1:{} (backend: {})",
        env!("CARGO_PKG_VERSION"),
        args.port,
        args.backend
    );
    serve(listener, SharedHost(session));
    ExitCode::SUCCESS
}
