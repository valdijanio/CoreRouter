use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::mpsc;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;

use base64::Engine as _;
use corerouter_control::{Client, Host, SharedHost, bind_loopback, spawn};
use corerouter_discovery::{Heard, Listener};
use corerouter_engine::{Session, shared};
use corerouter_ui::{ConnectScreen, CoreRouterUi, NeighborRow, SavedRouter};
use eframe::egui;
use serde_json::{Value, json};

use crate::remote::Remote;
use crate::{GuiApp, Platform};

const USAGE: &str = "\
usage: corerouter-gui [--connect HOST:PORT] [--control <port>]
                      [--discovery-port <port>] [--saved-list <file>]

  --connect HOST:PORT     manage a corerouter-daemon (its control port, e.g. 127.0.0.1:7979)
                          right away; without it the GUI opens on the connect screen
  --control <port>        serve the control channel on 127.0.0.1:<port> (ui.screenshot;
                          once connected, every other method is passed on to the daemon)
  --discovery-port <port> UDP port the connect screen listens on for CRDP (default 7979)
  --saved-list <file>     the connect screen's Saved tab (default
                          $XDG_CONFIG_HOME/corerouter/saved-routers.json)";

/// Largest saved-list file read (a hostile or broken file stays bounded).
const MAX_SAVED_FILE: u64 = 1 << 20;

const PROXY_TIMEOUT: Duration = Duration::from_secs(2);

/// Where the session lives.
#[derive(Clone)]
enum Target {
    /// The connect screen: no router picked yet.
    Choosing,
    Local(SharedHost),
    /// The daemon at `addr`; each control connection opens its own client.
    Remote {
        addr: String,
    },
}

/// Control host with a live window: the session's methods (local, or passed
/// on to the daemon), plus `ui.screenshot` captured from the next frame.
struct GuiHost {
    /// Set when the operator picks a router on the connect screen.
    target: Arc<Mutex<Target>>,
    proxy: Option<Client>,
    ctx: Arc<OnceLock<egui::Context>>,
}

impl Clone for GuiHost {
    fn clone(&self) -> Self {
        Self {
            target: Arc::clone(&self.target),
            proxy: None,
            ctx: Arc::clone(&self.ctx),
        }
    }
}

impl GuiHost {
    fn target(&self) -> Target {
        self.target
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn pass_on(&mut self, addr: &str, method: &str, params: &Value) -> Result<Value, String> {
        let answer = self.ask_daemon(addr, method, params);
        if method != "server.info" {
            return answer;
        }
        // The window is here even when the daemon is not: clients that
        // start with `server.info` (MCP, `corerouter-cli screenshot`) still
        // get to take a screenshot.
        let mut info = answer.unwrap_or_else(|e| {
            json!({
                "name": "corerouter",
                "version": env!("CARGO_PKG_VERSION"),
                "backend": null,
                "router_error": e,
            })
        });
        if let Some(o) = info.as_object_mut() {
            o.insert("has_ui".into(), json!(true));
            o.insert("via".into(), json!("corerouter-gui"));
            o.insert("router".into(), json!(addr));
        }
        Ok(info)
    }

    fn ask_daemon(&mut self, addr: &str, method: &str, params: &Value) -> Result<Value, String> {
        let client = match &mut self.proxy {
            Some(c) => c,
            None => self.proxy.insert(Client::connect(addr, PROXY_TIMEOUT)?),
        };
        match client.request(method, params.clone()) {
            Ok(answer) => answer,
            Err(e) => {
                self.proxy = None;
                Err(format!("{addr}: {e}"))
            }
        }
    }
}

impl Host for GuiHost {
    fn with_session(
        &mut self,
        f: &mut dyn FnMut(&mut Session) -> Result<Value, String>,
    ) -> Result<Value, String> {
        match self.target() {
            Target::Local(mut h) => h.with_session(f),
            Target::Remote { addr } => Err(format!("this GUI manages {addr}")),
            Target::Choosing => Err(CHOOSING.into()),
        }
    }

    fn forward(&mut self, method: &str, params: &Value) -> Option<Result<Value, String>> {
        match self.target() {
            Target::Local(_) => None,
            Target::Remote { addr } => Some(self.pass_on(&addr, method, params)),
            // Still answer server.info, so clients that start with it can
            // take a screenshot of the connect screen.
            Target::Choosing if method == "server.info" => Some(Ok(json!({
                "name": "corerouter",
                "version": env!("CARGO_PKG_VERSION"),
                "backend": null,
                "has_ui": true,
                "via": "corerouter-gui",
                "router": null,
                "router_error": CHOOSING,
            }))),
            Target::Choosing => Some(Err(CHOOSING.into())),
        }
    }

    fn has_ui(&self) -> bool {
        true
    }

    fn screenshot(&mut self) -> Result<Value, String> {
        let ctx = self.ctx.get().ok_or("the window is not up yet")?.clone();
        let (tx, rx) = mpsc::channel();
        ctx.request_screenshot(move |img| {
            let _ = tx.send(img);
        });
        ctx.request_repaint();
        let img = rx
            .recv_timeout(Duration::from_secs(5))
            .map_err(|_| "screenshot timed out (is the window minimized?)".to_owned())?;
        let png = encode_png(&img)?;
        Ok(json!({
            "mimeType": "image/png",
            "width": img.size[0],
            "height": img.size[1],
            "data": base64::engine::general_purpose::STANDARD.encode(png),
        }))
    }
}

fn encode_png(img: &egui::ColorImage) -> Result<Vec<u8>, String> {
    let [w, h] = img.size;
    let w = u32::try_from(w).map_err(|_| "image too wide")?;
    let h = u32::try_from(h).map_err(|_| "image too tall")?;
    let rgba: Vec<u8> = img
        .pixels
        .iter()
        .flat_map(|c| c.to_srgba_unmultiplied())
        .collect();
    let mut out = Vec::new();
    {
        let mut enc = png::Encoder::new(&mut out, w, h);
        enc.set_color(png::ColorType::Rgba);
        enc.set_depth(png::BitDepth::Eight);
        let mut writer = enc.write_header().map_err(|e| e.to_string())?;
        writer.write_image_data(&rgba).map_err(|e| e.to_string())?;
    }
    Ok(out)
}

const CHOOSING: &str = "the GUI is on its connect screen: no router picked yet";

#[derive(Debug, Default, PartialEq, Eq)]
struct Args {
    control: Option<u16>,
    connect: Option<String>,
    discovery_port: Option<u16>,
    saved_list: Option<PathBuf>,
}

/// `HOST:PORT` as `--connect` and the connect screen take it.
fn check_addr(addr: &str) -> Result<(), String> {
    if addr
        .rsplit_once(':')
        .is_none_or(|(h, p)| h.is_empty() || p.parse::<u16>().is_err())
    {
        return Err(format!(
            "Connect to needs HOST:PORT (the router's control port, e.g. 127.0.0.1:7979), got '{}'",
            addr.chars().take(64).collect::<String>()
        ));
    }
    Ok(())
}

fn parse_args(args: impl IntoIterator<Item = String>) -> Result<Args, String> {
    let mut out = Args::default();
    let mut args = args.into_iter();
    while let Some(a) = args.next() {
        match a.as_str() {
            "--control" => {
                let port = args.next().ok_or("--control needs a port")?;
                out.control = Some(port.parse().map_err(|_| format!("bad port '{port}'"))?);
            }
            "--connect" => {
                let addr = args.next().ok_or("--connect needs HOST:PORT")?;
                check_addr(&addr)
                    .map_err(|_| format!("--connect needs HOST:PORT, got '{addr}'"))?;
                out.connect = Some(addr);
            }
            "--discovery-port" => {
                let port = args.next().ok_or("--discovery-port needs a port")?;
                out.discovery_port = Some(port.parse().map_err(|_| format!("bad port '{port}'"))?);
            }
            "--saved-list" => {
                let file = args.next().ok_or("--saved-list needs a file")?;
                out.saved_list = Some(PathBuf::from(file));
            }
            "-h" | "--help" => return Err(USAGE.into()),
            other => return Err(format!("unknown argument '{other}'\n{USAGE}")),
        }
    }
    Ok(out)
}

pub fn main() -> ExitCode {
    env_logger::Builder::from_env(
        env_logger::Env::default()
            .default_filter_or("warn,corerouter_gui=info,corerouter_control=info"),
    )
    .init();
    let args = match parse_args(std::env::args().skip(1)) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let ctx_slot = Arc::new(OnceLock::new());
    let target = Arc::new(Mutex::new(Target::Choosing));
    let app = match &args.connect {
        Some(addr) => match Remote::spawn(addr) {
            Ok(remote) => {
                // Auth/TLS are G0.3: only reach daemons over loopback or a tunnel.
                log::info!("managing the router at {addr} (no authentication: G0.3)");
                set_target(&target, Target::Remote { addr: addr.clone() });
                GuiApp::router(CoreRouterUi::with_backend(Box::new(remote)))
            }
            Err(e) => {
                eprintln!("cannot start the connection thread: {e}");
                return ExitCode::FAILURE;
            }
        },
        None => {
            let (screen, platform) = NativePlatform::start(&args, Arc::clone(&target));
            GuiApp::connect(screen, Box::new(platform))
        }
    };

    if let Some(port) = args.control {
        let host = GuiHost {
            target,
            proxy: None,
            ctx: Arc::clone(&ctx_slot),
        };
        match bind_loopback(port).and_then(|l| spawn(l, host)) {
            Ok(_) => log::info!("control channel on 127.0.0.1:{port}"),
            Err(e) => {
                eprintln!("cannot open control port {port}: {e}");
                return ExitCode::FAILURE;
            }
        }
    }

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("CoreRouter")
            .with_inner_size([1280.0, 800.0]),
        ..Default::default()
    };
    let result = eframe::run_native(
        "CoreRouter",
        options,
        Box::new(move |cc| {
            let _ = ctx_slot.set(cc.egui_ctx.clone());
            Ok(Box::new(app))
        }),
    );
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("GUI failed: {e}");
            ExitCode::FAILURE
        }
    }
}

fn set_target(slot: &Mutex<Target>, target: Target) {
    *slot.lock().unwrap_or_else(PoisonError::into_inner) = target;
}

/// The connect screen on the desktop: neighbors heard directly on this
/// machine's interfaces, saved list in a file.
struct NativePlatform {
    listener: Option<Listener>,
    saved_path: Option<PathBuf>,
    target: Arc<Mutex<Target>>,
}

impl NativePlatform {
    fn start(args: &Args, target: Arc<Mutex<Target>>) -> (ConnectScreen, Self) {
        let saved_path = args.saved_list.clone().or_else(default_saved_path);
        let saved = saved_path.as_deref().map(load_saved).unwrap_or_default();
        let mut screen = ConnectScreen::new(saved);
        let port = args.discovery_port.unwrap_or(corerouter_discovery::PORT);
        let listener = match Listener::spawn(port) {
            Ok(l) => {
                screen.set_source(format!(
                    "Listening for CRDP announcements on UDP {port} (this machine never sends any)"
                ));
                Some(l)
            }
            Err(e) => {
                screen.set_source(format!("Cannot listen for neighbors: {e}"));
                None
            }
        };
        (
            screen,
            Self {
                listener,
                saved_path,
                target,
            },
        )
    }
}

impl Platform for NativePlatform {
    fn neighbors(&mut self) -> Vec<NeighborRow> {
        let Some(l) = self.listener.as_mut() else {
            return Vec::new();
        };
        l.poll().into_iter().map(heard_row).collect()
    }

    fn store_saved(&mut self, saved: &[SavedRouter]) {
        let Some(path) = &self.saved_path else {
            return;
        };
        if let Err(e) = write_saved(path, saved) {
            log::error!("cannot save the router list to {}: {e}", path.display());
        }
    }

    fn connect(&mut self, addr: &str) -> Result<CoreRouterUi, String> {
        check_addr(addr)?;
        let remote =
            Remote::spawn(addr).map_err(|e| format!("cannot start the connection thread: {e}"))?;
        log::info!("managing the router at {addr} (no authentication: G0.3)");
        set_target(
            &self.target,
            Target::Remote {
                addr: addr.to_owned(),
            },
        );
        self.listener = None;
        Ok(CoreRouterUi::with_backend(Box::new(remote)))
    }

    fn lab(&mut self) -> CoreRouterUi {
        let session = shared(Session::virtual_lab());
        set_target(
            &self.target,
            Target::Local(SharedHost(Arc::clone(&session))),
        );
        self.listener = None;
        CoreRouterUi::new(session)
    }
}

fn heard_row(h: &Heard) -> NeighborRow {
    let a = &h.announcement;
    let address = a
        .ipv4
        .first()
        .map(|(ip, _)| ip.to_string())
        .unwrap_or_else(|| h.from.ip().to_string());
    let uptime = a
        .uptime_secs
        .map(|u| u.saturating_add(h.at.elapsed().as_secs()));
    NeighborRow {
        key: a.node_id.to_string(),
        interface: h.interface.clone().unwrap_or_default(),
        protocol: "CRDP".into(),
        address: if h.local {
            format!("{address} (this machine)")
        } else {
            address
        },
        mac: a.mac.map(|m| mac_text(&m)).unwrap_or_default(),
        identity: a.identity.clone(),
        version: a.version.clone(),
        board: a.board.clone(),
        uptime_secs: uptime,
        connect_to: h.connect_to(),
    }
}

fn mac_text(m: &[u8; 6]) -> String {
    m.iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// `$XDG_CONFIG_HOME` (or `~/.config`, or `%APPDATA%`)`/corerouter/saved-routers.json`.
fn default_saved_path() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .or_else(|| std::env::var_os("APPDATA").map(PathBuf::from))?;
    Some(base.join("corerouter").join("saved-routers.json"))
}

fn load_saved(path: &std::path::Path) -> Vec<SavedRouter> {
    use std::io::Read as _;
    let mut text = String::new();
    let read =
        std::fs::File::open(path).and_then(|f| f.take(MAX_SAVED_FILE).read_to_string(&mut text));
    match read {
        Ok(_) => match serde_json::from_str::<Value>(&text) {
            Ok(v) => SavedRouter::list_from_json(&v),
            Err(e) => {
                log::warn!(
                    "{} is not a router list ({e}); starting empty",
                    path.display()
                );
                Vec::new()
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => {
            log::warn!("cannot read {}: {e}", path.display());
            Vec::new()
        }
    }
}

/// Temp file + rename: a crash never leaves half a list.
fn write_saved(path: &std::path::Path, saved: &[SavedRouter]) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let text = serde_json::to_string_pretty(&SavedRouter::list_to_json(saved))
        .map_err(std::io::Error::other)?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, text)?;
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Args, String> {
        parse_args(args.iter().map(|s| (*s).to_owned()))
    }

    #[test]
    fn parses_connect_and_control() {
        assert_eq!(parse(&[]).unwrap(), Args::default());
        let a = parse(&["--connect", "127.0.0.1:7979", "--control", "7990"]).unwrap();
        assert_eq!(a.connect.as_deref(), Some("127.0.0.1:7979"));
        assert_eq!(a.control, Some(7990));
        for bad in ["127.0.0.1", ":7979", "h:99999", "h:x"] {
            assert!(parse(&["--connect", bad]).is_err(), "{bad}");
        }
        assert!(parse(&["--connect"]).is_err());
    }

    #[test]
    fn control_port_passes_methods_on_to_the_daemon() {
        let daemon = bind_loopback(0).unwrap();
        let addr = daemon.local_addr().unwrap().to_string();
        spawn(daemon, SharedHost(shared(Session::virtual_lab()))).unwrap();
        let mut host = GuiHost {
            target: Arc::new(Mutex::new(Target::Remote { addr })),
            proxy: None,
            ctx: Arc::new(OnceLock::new()),
        };
        let r = corerouter_control::dispatch(
            &mut host,
            "engine.execute",
            &json!({"command": "system.identity.set", "params": {"name": "via-gui"}}),
        )
        .unwrap();
        assert_eq!(r["name"], "via-gui");
        let info = corerouter_control::dispatch(&mut host, "server.info", &Value::Null).unwrap();
        assert_eq!(info["has_ui"], true);
        // The window is not up in a test: the screenshot is answered here.
        let shot = corerouter_control::dispatch(&mut host, "ui.screenshot", &Value::Null);
        assert!(shot.unwrap_err().contains("not up yet"));
    }

    #[test]
    fn connect_screen_still_answers_server_info_and_screenshot() {
        let mut host = GuiHost {
            target: Arc::new(Mutex::new(Target::Choosing)),
            proxy: None,
            ctx: Arc::new(OnceLock::new()),
        };
        let info = corerouter_control::dispatch(&mut host, "server.info", &Value::Null).unwrap();
        assert_eq!(info["has_ui"], true);
        let err = corerouter_control::dispatch(&mut host, "engine.list", &Value::Null);
        assert!(err.unwrap_err().contains("connect screen"));
        let shot = corerouter_control::dispatch(&mut host, "ui.screenshot", &Value::Null);
        assert!(shot.unwrap_err().contains("not up yet"));
        // Picking the lab switches the same host over.
        set_target(
            &host.target,
            Target::Local(SharedHost(shared(Session::virtual_lab()))),
        );
        assert!(corerouter_control::dispatch(&mut host, "engine.list", &Value::Null).is_ok());
    }

    #[test]
    fn saved_list_file_round_trip() {
        let path = std::env::temp_dir()
            .join(format!("crdp-gui-{}", std::process::id()))
            .join("saved.json");
        assert!(load_saved(&path).is_empty(), "missing file: empty list");
        let list = vec![SavedRouter {
            address: "127.0.0.1:7979".into(),
            group: "lab".into(),
            comment: String::new(),
        }];
        write_saved(&path, &list).unwrap();
        assert_eq!(load_saved(&path), list);
        std::fs::write(&path, "{not json").unwrap();
        assert!(load_saved(&path).is_empty());
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
        assert!(check_addr("[fe80::1%2]:7979").is_ok());
        assert!(check_addr("10.0.0.1").is_err());
    }

    #[test]
    fn server_info_answers_without_the_daemon() {
        let gone = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = gone.local_addr().unwrap().to_string();
        drop(gone);
        let mut host = GuiHost {
            target: Arc::new(Mutex::new(Target::Remote { addr })),
            proxy: None,
            ctx: Arc::new(OnceLock::new()),
        };
        let info = corerouter_control::dispatch(&mut host, "server.info", &Value::Null).unwrap();
        assert_eq!(info["has_ui"], true);
        assert!(info["router_error"].is_string());
        assert!(corerouter_control::dispatch(&mut host, "engine.list", &Value::Null).is_err());
    }
}
