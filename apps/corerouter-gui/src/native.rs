use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::mpsc;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;

use base64::Engine as _;
use corerouter_control::dial::local_token_hint;
use corerouter_control::{
    Client, Endpoint, Gate, Host, KnownHosts, Login, SharedHost, Target as RouterAddr,
    UNAUTHORIZED, bind_loopback, local_token, spawn, spawn_clock,
};
use corerouter_discovery::{Heard, Listener};
use corerouter_engine::{Session, shared};
use corerouter_ui::connect::{self, DEFAULT_LOGIN, explain};
use corerouter_ui::{ConnectScreen, CoreRouterUi, Credentials, Failure, NeighborRow, SavedRouter};
use eframe::egui;
use serde_json::{Value, json};

use crate::remote::{Dialer, Remote};
use crate::{Connected, GuiApp, Platform};

const USAGE: &str = "\
usage: corerouter-gui [--connect HOST:PORT | tls://HOST:PORT] [--user USER]
                      [--control <port>] [--discovery-port <port>] [--saved-list <file>]

  --connect HOST:PORT     manage a corerouter-daemon right away: 127.0.0.1:PORT with the
                          router's local token (same OS user), else (and at any other
                          address, over TLS) as --user (password from $COREROUTER_PASSWORD,
                          or typed on the connect screen); without it the GUI opens on the
                          connect screen
  --user USER             login name for --connect (default admin)
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
    /// The daemon behind `dialer`; each control connection opens its own
    /// client, logged in as the window's user.
    Remote {
        dialer: Box<Dialer>,
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

    fn pass_on(&mut self, dialer: &Dialer, method: &str, params: &Value) -> Result<Value, String> {
        let addr = dialer.target.to_string();
        let answer = self.ask_daemon(dialer, method, params);
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

    fn ask_daemon(
        &mut self,
        dialer: &Dialer,
        method: &str,
        params: &Value,
    ) -> Result<Value, String> {
        let client = match &mut self.proxy {
            Some(c) => c,
            None => self.proxy.insert(dialer.dial_shared()?),
        };
        match client.request(method, params.clone()) {
            // The window's session was renewed: use the new token next time.
            Ok(Err(e)) if e.starts_with(UNAUTHORIZED) => {
                self.proxy = None;
                Err(e)
            }
            Ok(answer) => answer,
            Err(e) => {
                self.proxy = None;
                Err(format!("{}: {e}", dialer.target))
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
            Target::Remote { dialer } => Err(format!("this GUI manages {}", dialer.target)),
            Target::Choosing => Err(CHOOSING.into()),
        }
    }

    fn forward(&mut self, method: &str, params: &Value) -> Option<Result<Value, String>> {
        match self.target() {
            Target::Local(_) => None,
            Target::Remote { dialer } => Some(self.pass_on(&dialer, method, params)),
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
    user: Option<String>,
    discovery_port: Option<u16>,
    saved_list: Option<PathBuf>,
}

/// `HOST:PORT` or `tls://HOST:PORT` as `--connect` and the connect screen take it.
fn check_addr(addr: &str) -> Result<RouterAddr, String> {
    RouterAddr::parse(addr).map_err(|_| {
        format!(
            "Connect to needs HOST:PORT (e.g. 127.0.0.1:7979, or a router's TLS port \
             10.0.0.1:8729), got '{}'",
            addr.chars().take(64).collect::<String>()
        )
    })
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
            "--user" => out.user = Some(args.next().ok_or("--user needs a name")?),
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
    let (mut screen, mut platform) = NativePlatform::start(&args, Arc::clone(&target));
    // `--connect`: the same path as the Connect button, so a first TLS
    // connection still asks about the certificate on the connect screen.
    let mut ready = None;
    if let Some(addr) = &args.connect {
        screen.connect_to = addr.clone();
        let creds = Credentials {
            address: addr.clone(),
            user: args.user.clone().unwrap_or_else(|| DEFAULT_LOGIN.into()),
            password: std::env::var("COREROUTER_PASSWORD").unwrap_or_default(),
            remember: false,
            legacy: false,
        };
        screen.set_login(&creds.user);
        match platform.connect(&creds) {
            Ok(Connected::Ready(r)) => ready = Some(*r),
            Ok(Connected::Trust(c, fp)) => screen.ask_trust(c, fp),
            Err(e) => screen.fail(e),
        }
    }
    let app = match ready {
        Some(r) => GuiApp::router(r),
        None => GuiApp::connect(screen, Box::new(platform)),
    };

    if let Some(port) = args.control {
        let host = GuiHost {
            target,
            proxy: None,
            ctx: Arc::clone(&ctx_slot),
        };
        // Like the daemon: the local token, for the CLI/MCP of this OS user.
        let gate = Gate::default();
        match corerouter_control::auth::new_token() {
            Ok(token) => {
                gate.add_local_token(&token);
                match local_token::create(port, &token) {
                    Ok(path) => log::info!("local token for CLI/MCP: {}", path.display()),
                    Err(e) => log::warn!("local token not written: {e}"),
                }
            }
            Err(e) => log::warn!("no local token: {e}"),
        }
        match bind_loopback(port).and_then(|l| spawn(Endpoint::loopback(l), host, gate)) {
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
            // Also names eframe's storage dir (window preferences): its
            // own, never a router's config dir such as ~/.local/share/corerouter.
            .with_app_id("corerouter-gui")
            .with_inner_size([1280.0, 800.0]),
        ..Default::default()
    };
    let result = eframe::run_native(
        "CoreRouter",
        options,
        Box::new(move |cc| {
            let _ = ctx_slot.set(cc.egui_ctx.clone());
            corerouter_ui::export::install(&cc.egui_ctx, Arc::new(save_export));
            corerouter_ui::export::install_open(&cc.egui_ctx, Arc::new(open_file));
            corerouter_ui::export::install_read_at(&cc.egui_ctx, Arc::new(read_at));
            Ok(Box::new(app.with_storage(cc)))
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
/// machine's interfaces, saved list in a file, passwords (when asked to
/// remember) in the operating system's keyring.
struct NativePlatform {
    listener: Option<Listener>,
    saved_path: Option<PathBuf>,
    target: Arc<Mutex<Target>>,
    keyring: bool,
}

/// Keyring service name; the account is `user@address`.
const KEYRING_SERVICE: &str = "corerouter";

/// Whether the OS keyring answers at all (a probe entry that does not exist).
fn keyring_probe() -> Result<String, String> {
    let entry = keyring::Entry::new(KEYRING_SERVICE, "probe@corerouter")
        .map_err(|e| format!("no secure password store: {e}"))?;
    match entry.get_password() {
        Ok(_) | Err(keyring::Error::NoEntry) => Ok("the system keyring".into()),
        Err(e) => Err(format!("no secure password store: {e}")),
    }
}

fn keyring_entry(address: &str, user: &str) -> Option<keyring::Entry> {
    keyring::Entry::new(KEYRING_SERVICE, &format!("{user}@{address}")).ok()
}

impl NativePlatform {
    fn start(args: &Args, target: Arc<Mutex<Target>>) -> (ConnectScreen, Self) {
        let saved_path = args.saved_list.clone().or_else(default_saved_path);
        let saved = saved_path.as_deref().map(load_saved).unwrap_or_default();
        let mut screen = ConnectScreen::new(saved);
        let keyring = keyring_probe();
        let has_keyring = keyring.is_ok();
        screen.set_keyring(keyring);
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
                keyring: has_keyring,
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

    fn connect(&mut self, creds: &Credentials) -> Result<Connected, Failure> {
        let target = check_addr(&creds.address)?;
        let addr = target.addr();
        if target.tls && creds.user.is_empty() {
            return Err(Failure::from(format!(
                "{target} is reached over TLS: type a Login and Password"
            )));
        }
        let mut password = creds.password.clone();
        if password.is_empty() && self.keyring && !creds.user.is_empty() {
            password = keyring_entry(&addr, &creds.user)
                .and_then(|e| e.get_password().ok())
                .unwrap_or_default();
        }
        let fingerprint = if target.tls {
            match KnownHosts::load_default().get(&addr) {
                Some(fp) => Some(fp.to_owned()),
                None => {
                    // First time: look at the certificate, send nothing, ask.
                    let c = Client::connect_tls(&addr, PROXY_TIMEOUT, None)
                        .map_err(|e| explain(&format!("{target}: {e}")))?;
                    let fp = c.fingerprint().unwrap_or_default().to_owned();
                    return Ok(Connected::Trust(creds.clone(), fp));
                }
            }
        } else {
            None
        };
        let local = if target.tls {
            None
        } else {
            local_token::read(target.port)
        };
        let way = log_in(
            &target,
            &creds.user,
            &password,
            fingerprint,
            creds.legacy,
            local,
        )?;
        if way.how == How::Password
            && creds.remember
            && !creds.password.is_empty()
            && let Some(entry) = keyring_entry(&addr, &creds.user)
            && let Err(e) = entry.set_password(&creds.password)
        {
            log::warn!("password not remembered: {e}");
        }
        let remote = Remote::spawn(way.dialer.clone(), Some(way.client))
            .map_err(|e| format!("cannot start the connection thread: {e}"))?;
        match way.how {
            How::Token => log::info!("managing the router at {target} (local token)"),
            How::Password => log::info!("managing the router at {target} as {}", creds.user),
            How::Legacy => log::warn!(
                "managing the router at {target}: an old version without login (update it)"
            ),
        }
        set_target(
            &self.target,
            Target::Remote {
                dialer: Box::new(way.dialer),
            },
        );
        self.listener = None;
        Ok(Connected::Ready(Box::new(CoreRouterUi::with_backend(
            Box::new(remote),
        ))))
    }

    fn trust(&mut self, address: &str, fingerprint: &str) -> Result<(), String> {
        let target = check_addr(address)?;
        KnownHosts::load_default()
            .remember(&target.addr(), fingerprint)
            .map_err(|e| format!("cannot save the known hosts file: {e}"))
    }

    fn lab(&mut self) -> CoreRouterUi {
        let mut lab = Session::virtual_lab();
        // Tools > Ping / MTR run as background tasks on threads.
        lab.set_runner(corerouter_control::thread_runner());
        let session = shared(lab);
        // Safe Mode timeouts need a clock; the lab has no other.
        if let Err(e) = spawn_clock(Arc::clone(&session)) {
            log::warn!("no clock thread ({e}): Safe Mode timeouts are unavailable");
        }
        set_target(
            &self.target,
            Target::Local(SharedHost(Arc::clone(&session))),
        );
        self.listener = None;
        CoreRouterUi::new(session)
    }
}

/// How the GUI got into a router.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum How {
    /// The local token of a router run by this operating-system user.
    Token,
    /// Login and Password (a session token, renewed by the worker).
    Password,
    /// "Connect anyway": a router older than the login (G0.3c).
    Legacy,
}

struct Way {
    dialer: Dialer,
    client: Client,
    how: How,
}

/// Get into the router at `target` (G0.3c). On this machine: an old router
/// without login is told apart first (and managed only when `legacy`, the
/// operator's "Connect anyway"); then the local token `local`, when this
/// user could read it and the router takes it; else `user` + `password`
/// (an empty password is fine here, G0.3b). Elsewhere: TLS pinned to
/// `fingerprint`, then `user` + `password`. A failure is one sentence for
/// the operator, the router's own words in its detail.
fn log_in(
    target: &RouterAddr,
    user: &str,
    password: &str,
    fingerprint: Option<String>,
    legacy: bool,
    local: Option<String>,
) -> Result<Way, Failure> {
    let with_password = Login::Password {
        user: user.to_owned(),
        password: password.to_owned(),
    };
    if target.tls {
        let dialer = Dialer::new(target.clone(), with_password, fingerprint);
        let mut client = dialer.dial().map_err(|e| explain(&e))?;
        check_whoami(target, &mut client, String::new())?;
        return Ok(Way {
            dialer,
            client,
            how: How::Password,
        });
    }
    let probe = Dialer::new(target.clone(), Login::Nothing, None);
    let mut client = probe.dial().map_err(|e| explain(&e))?;
    let info = client
        .call("server.info", Value::Null)
        .map_err(|e| explain(&format!("{target}: {e}")))?;
    if connect::old_router_info(&info) {
        if legacy {
            return Ok(Way {
                dialer: probe,
                client,
                how: How::Legacy,
            });
        }
        return Err(old_router(target, &info));
    }
    let token_note = match local {
        Some(token) => {
            client.set_token(Some(token));
            match client.call("auth.whoami", Value::Null) {
                Ok(_) => {
                    return Ok(Way {
                        dialer: Dialer::new(target.clone(), Login::Auto, None),
                        client,
                        how: How::Token,
                    });
                }
                Err(e) => {
                    client.set_token(None);
                    format!("the local token was refused ({e})")
                }
            }
        }
        None => local_token_hint(target.port),
    };
    if user.is_empty() {
        return Err(Failure::new(
            "Type a Login (and its Password, if the account has one)",
            format!("{target}: {token_note}"),
        ));
    }
    let detail = |e: &str| format!("{target}: {e}\nnot by the local token: {token_note}");
    if let Err(e) = client.login(user, password) {
        let mut f = explain(&e);
        if connect::old_router_error(&e) {
            f.offer_anyway = true;
        }
        f.detail = detail(&e);
        return Err(f);
    }
    check_whoami(target, &mut client, token_note)?;
    Ok(Way {
        dialer: Dialer::new(target.clone(), with_password, None),
        client,
        how: How::Password,
    })
}

/// The login worked: one call that needs it, so a missing right is one
/// clear error up front.
fn check_whoami(target: &RouterAddr, client: &mut Client, note: String) -> Result<(), Failure> {
    client.call("auth.whoami", Value::Null).map_err(|e| {
        let mut f = explain(&e);
        f.offer_anyway = connect::old_router_error(&e) && !target.tls;
        f.detail = if note.is_empty() {
            format!("{target}: {e}")
        } else {
            format!("{target}: {e}\n{note}")
        };
        f
    })?;
    Ok(())
}

/// A router older than the login on this machine: say so, offer "Connect
/// anyway".
fn old_router(target: &RouterAddr, info: &Value) -> Failure {
    let version: String = info
        .get("version")
        .and_then(Value::as_str)
        .unwrap_or("?")
        .chars()
        .take(64)
        .collect();
    Failure {
        text: connect::OLD_ROUTER.into(),
        detail: format!(
            "{target}: corerouter-daemon {version} answers server.info without \"auth\" \
             (older than G0.3): it has no users and no login. This GUI is {}.",
            env!("CARGO_PKG_VERSION")
        ),
        offer_anyway: true,
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
        remote: !h.reachable(),
    }
}

fn mac_text(m: &[u8; 6]) -> String {
    m.iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Where exports go: `$XDG_DOWNLOAD_DIR`, else `~/Downloads`, else home.
fn download_dir() -> PathBuf {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from);
    std::env::var_os("XDG_DOWNLOAD_DIR")
        .map(PathBuf::from)
        .filter(|d| d.is_dir())
        .or_else(|| {
            home.as_ref()
                .map(|h| h.join("Downloads"))
                .filter(|d| d.is_dir())
        })
        .or(home)
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Save what a window exports (G4.5: a graph's CSV or PNG) in the
/// Downloads folder, never over an existing file (`-1`, `-2`… appended).
/// A file the operator names (PPP › Secrets › Import from MikroTik), at
/// most 32 MiB; `~/` is the home folder.
fn open_file(path: &str) -> Result<Vec<u8>, String> {
    use std::io::Read as _;
    const MAX: u64 = 32 * 1024 * 1024;
    let path = path.trim();
    let path = match (path.strip_prefix("~/"), std::env::var_os("HOME")) {
        (Some(rest), Some(home)) => std::path::Path::new(&home).join(rest),
        _ => std::path::PathBuf::from(path),
    };
    let f = std::fs::File::open(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut bytes = Vec::new();
    f.take(MAX + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if bytes.len() as u64 > MAX {
        return Err(format!("{}: larger than 32 MiB", path.display()));
    }
    Ok(bytes)
}

/// G1.6e: a piece of a file (System › Packages sends a package in chunks).
fn read_at(path: &str, offset: u64, len: usize) -> Result<(Vec<u8>, u64), String> {
    use std::io::{Read as _, Seek as _};
    let path = path.trim();
    let path = match (path.strip_prefix("~/"), std::env::var_os("HOME")) {
        (Some(rest), Some(home)) => std::path::Path::new(&home).join(rest),
        _ => std::path::PathBuf::from(path),
    };
    let mut f = std::fs::File::open(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let size = f
        .metadata()
        .map_err(|e| format!("{}: {e}", path.display()))?
        .len();
    f.seek(std::io::SeekFrom::Start(offset))
        .map_err(|e| format!("{}: {e}", path.display()))?;
    let mut bytes = Vec::with_capacity(len.min(4 << 20));
    f.take(len.min(4 << 20) as u64)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    Ok((bytes, size))
}

fn save_export(name: &str, export: corerouter_ui::export::Export) -> Result<String, String> {
    use corerouter_ui::export::Export;
    let bytes = match export {
        Export::Text(t) => t.into_bytes(),
        Export::Image(img) => encode_png(&img)?,
    };
    // Only the file name: a name with a path in it stays in the folder.
    let name = std::path::Path::new(name)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("export");
    let dir = download_dir();
    let (stem, ext) = name.rsplit_once('.').unwrap_or((name, ""));
    for n in 0..1000 {
        let file = if n == 0 {
            name.to_owned()
        } else {
            format!("{stem}-{n}.{ext}")
        };
        let path = dir.join(file);
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut f) => {
                use std::io::Write as _;
                f.write_all(&bytes)
                    .map_err(|e| format!("{}: {e}", path.display()))?;
                return Ok(format!("saved {}", path.display()));
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(format!("{}: {e}", path.display())),
        }
    }
    Err(format!("{}: too many files named {name}", dir.display()))
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
        let gate = Gate::default();
        gate.add_local_token(&"ab".repeat(32));
        spawn(
            Endpoint::loopback(daemon),
            SharedHost(shared(Session::virtual_lab())),
            gate,
        )
        .unwrap();
        let dialer = Dialer::new(
            RouterAddr::parse(&addr).unwrap(),
            Login::Token("ab".repeat(32)),
            None,
        );
        let mut host = GuiHost {
            target: Arc::new(Mutex::new(Target::Remote {
                dialer: Box::new(dialer),
            })),
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
            user: "admin".into(),
        }];
        write_saved(&path, &list).unwrap();
        assert_eq!(load_saved(&path), list);
        std::fs::write(&path, "{not json").unwrap();
        assert!(load_saved(&path).is_empty());
        std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
        assert!(check_addr("[fe80::1%2]:7979").is_ok());
        assert!(check_addr("10.0.0.1").is_err());
    }

    /// A router of this version on loopback: `admin` without a password
    /// (G0.3b), `op` with one, and the local token `ab…`.
    fn router() -> RouterAddr {
        let mut s = Session::virtual_lab();
        s.bootstrap_admin(false);
        s.execute(
            "user.add",
            &json!({"name": "op", "group": "write", "password": "op-password"}),
        )
        .unwrap();
        let listener = bind_loopback(0).unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let gate = Gate::default();
        gate.add_local_token(&"ab".repeat(32));
        spawn(Endpoint::loopback(listener), SharedHost(shared(s)), gate).unwrap();
        RouterAddr::parse(&addr).unwrap()
    }

    fn whoami(way: &mut Way) -> String {
        let me = way.client.call("auth.whoami", Value::Null).unwrap();
        me["user"].as_str().unwrap().to_owned()
    }

    #[test]
    fn local_token_first_then_login_and_password() {
        let r = router();
        let token = Some("ab".repeat(32));
        // The token readable and taken: no password needed.
        let mut way = log_in(&r, "admin", "", None, false, token).unwrap();
        assert_eq!(way.how, How::Token);
        assert_eq!(whoami(&mut way), "local");
        // Not readable (the daemon runs as another OS user): Login and
        // Password; admin has none yet and this is loopback.
        let mut way = log_in(&r, DEFAULT_LOGIN, "", None, false, None).unwrap();
        assert_eq!(way.how, How::Password);
        assert_eq!(whoami(&mut way), "admin");
        // A stale token is no dead end either.
        let mut way = log_in(&r, "op", "op-password", None, false, Some("cd".repeat(32))).unwrap();
        assert_eq!((way.how, whoami(&mut way)), (How::Password, "op".into()));
        // The worker logs in again on its own after a reconnection.
        assert_eq!(
            way.dialer
                .dial()
                .unwrap()
                .call("auth.whoami", Value::Null)
                .unwrap()["user"],
            "op"
        );
    }

    #[test]
    fn a_failed_login_says_it_shortly_with_the_details_aside() {
        let r = router();
        let f = log_in(&r, "op", "wrong", None, false, None).err().unwrap();
        assert_eq!(f.text, connect::BAD_LOGIN);
        assert!(!f.offer_anyway);
        // The technical part is still there, under "Details".
        assert!(
            f.detail.contains(corerouter_control::auth::INVALID_LOGIN),
            "{}",
            f.detail
        );
        assert!(f.detail.contains("local token"), "{}", f.detail);
        // No Login and no token: ask for one.
        let f = log_in(&r, "", "", None, false, None).err().unwrap();
        assert!(f.text.starts_with("Type a Login"), "{}", f.text);
        // Nobody at that port.
        let gone = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = RouterAddr::parse(&gone.local_addr().unwrap().to_string()).unwrap();
        drop(gone);
        let f = log_in(&addr, "admin", "", None, false, None).err().unwrap();
        assert!(f.text.starts_with("Nothing answers"), "{f:?}");
    }

    #[test]
    fn explain_knows_the_control_channel_errors() {
        use corerouter_control::auth::{INVALID_LOGIN, NO_PASSWORD_REMOTE};
        let f = explain(&format!("tls://10.0.0.1:8729: {NO_PASSWORD_REMOTE}"));
        assert_eq!(f.text, connect::SET_PASSWORD_FIRST);
        assert!(f.detail.contains(NO_PASSWORD_REMOTE));
        assert_eq!(explain(INVALID_LOGIN).text, connect::BAD_LOGIN);
        // Unknown errors stay as they are.
        let f = explain("certificate CHANGED");
        assert_eq!(
            (f.text.as_str(), f.detail.as_str()),
            ("certificate CHANGED", "")
        );
    }

    /// A daemon from before G0.3 (6fbab48): no `auth` in `server.info`,
    /// no `auth.*` methods, and the `token` field of a request ignored.
    fn old_router() -> RouterAddr {
        use std::io::{BufRead, BufReader, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(mut out) = conn else { return };
                std::thread::spawn(move || {
                    let reader = BufReader::new(out.try_clone().unwrap());
                    for line in reader.lines() {
                        let Ok(line) = line else { return };
                        let req: Value = serde_json::from_str(&line).unwrap();
                        let reply = match req["method"].as_str().unwrap_or("") {
                            "server.info" => json!({"id": req["id"], "ok": true, "result":
                                {"name": "corerouter", "version": "0.1.0", "backend": "virtual",
                                 "has_ui": false}}),
                            "ping" => {
                                json!({"id": req["id"], "ok": true, "result": {"pong": true}})
                            }
                            m if m.starts_with("auth.") => json!({"id": req["id"], "ok": false,
                                "error": format!("unknown method '{m}'; methods: ping, server.info, \
                                 engine.list, engine.execute")}),
                            _ => json!({"id": req["id"], "ok": true, "result": []}),
                        };
                        if writeln!(out, "{reply}").is_err() {
                            return;
                        }
                    }
                });
            }
        });
        RouterAddr::parse(&addr).unwrap()
    }

    #[test]
    fn an_old_router_is_named_and_can_be_managed_anyway() {
        let r = old_router();
        let f = log_in(&r, "admin", "", None, false, Some("ab".repeat(32)))
            .err()
            .unwrap();
        assert_eq!(f.text, connect::OLD_ROUTER);
        assert!(f.offer_anyway);
        assert!(f.detail.contains("0.1.0"), "{}", f.detail);
        assert!(!f.text.contains("unknown method"));
        // "Connect anyway": no login at all, and requests work.
        let mut way = log_in(&r, "admin", "", None, true, None).unwrap();
        assert_eq!(way.how, How::Legacy);
        assert!(way.client.call("engine.list", Value::Null).is_ok());
        // Older still or behind a proxy: told apart by the error too.
        let f = check_whoami(&r, &mut way.client, String::new())
            .err()
            .unwrap();
        assert_eq!(f.text, connect::OLD_ROUTER);
        assert!(f.offer_anyway);
    }

    #[test]
    fn server_info_answers_without_the_daemon() {
        let gone = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = gone.local_addr().unwrap().to_string();
        drop(gone);
        let mut host = GuiHost {
            target: Arc::new(Mutex::new(Target::Remote {
                dialer: Box::new(Dialer::new(
                    RouterAddr::parse(&addr).unwrap(),
                    Login::Auto,
                    None,
                )),
            })),
            proxy: None,
            ctx: Arc::new(OnceLock::new()),
        };
        let info = corerouter_control::dispatch(&mut host, "server.info", &Value::Null).unwrap();
        assert_eq!(info["has_ui"], true);
        assert!(info["router_error"].is_string());
        assert!(corerouter_control::dispatch(&mut host, "engine.list", &Value::Null).is_err());
    }
}
