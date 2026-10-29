//! CoreRouter GUI.
//!
//! Native: `corerouter-gui [--connect HOST:PORT | corerouter://HOST]
//! [--control <port>]` manages a `corerouter-daemon` over its control
//! channel (like WinBox). Without either it opens on the connect screen (WinBox login style): routers
//! heard with CRDP, the saved list, and a "Virtual lab" button for the
//! in-process lab. `--control` serves the control channel (including
//! `ui.screenshot`) so an agent can drive and *see* the app.
//!
//! Web: same UI on a `<canvas id="corerouter">`, talking to the daemon's
//! WebSocket: `?connect=ws://…` goes straight to it, `?lab` runs the virtual
//! lab in the browser, and otherwise the connect screen lists the neighbors
//! of the daemon that served the page (`ip.neighbor.list`).

use std::time::Duration;

use corerouter_ui::{
    ConnectAction, ConnectScreen, CoreRouterUi, Credentials, Failure, NeighborRow, SavedRouter,
};

mod export;
#[cfg(not(target_arch = "wasm32"))]
mod link;
#[cfg(not(target_arch = "wasm32"))]
mod native;
#[cfg(not(target_arch = "wasm32"))]
mod remote;
#[cfg(target_arch = "wasm32")]
mod web;

/// Storage key of the window preferences (theme, inline comments). eframe
/// keeps them in a file under the user's data dir, or in `localStorage`.
const PREFS_KEY: &str = "corerouter.prefs";

/// How often the connect screen redraws while it waits for announcements.
const CONNECT_REPAINT: Duration = Duration::from_millis(500);

/// What differs between the native app and the browser on the connect screen.
trait Platform {
    /// Rows of the Neighbors tab.
    fn neighbors(&mut self) -> Vec<NeighborRow>;
    /// Keep the Saved tab (address, group, comment; never a password).
    fn store_saved(&mut self, saved: &[SavedRouter]);
    /// Log in to the router at `creds.address` and start managing it, or
    /// say why not (one sentence, the technical part as its detail).
    fn connect(&mut self, creds: &Credentials) -> Result<Connected, Failure>;
    /// The operator accepted this certificate for `address` (G0.3 TOFU).
    fn trust(&mut self, address: &str, fingerprint: &str) -> Result<(), String>;
    /// The in-process virtual lab.
    fn lab(&mut self) -> CoreRouterUi;
    /// The password saved in the secure store for `address` and `user`
    /// (G0.3e: shown in the Password field, never used behind it).
    fn saved_password(&mut self, _address: &str, _user: &str) -> Option<String> {
        None
    }
    /// Delete the password saved for `address` and `user`.
    fn forget_password(&mut self, _address: &str, _user: &str) -> Result<(), String> {
        Ok(())
    }
}

/// Answer the screen's question about a saved password, if it has one.
fn look_up_saved(screen: &mut ConnectScreen, platform: &mut dyn Platform) {
    if let Some((address, user)) = screen.wants_saved_password() {
        let password = platform.saved_password(&address, &user);
        screen.set_saved_password(&address, &user, password);
    }
}

/// What [`Platform::connect`] got to.
enum Connected {
    Ready(Box<CoreRouterUi>),
    /// First TLS connection: ask the operator about this fingerprint (the
    /// browser checks certificates itself, so only natively).
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    Trust(Credentials, String),
    /// The router shows another certificate than the remembered one
    /// (G0.3d): ask, PuTTY style.
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    Changed(Box<CertChange>),
}

/// A certificate that differs from the remembered one.
#[cfg_attr(target_arch = "wasm32", allow(dead_code))]
struct CertChange {
    creds: Credentials,
    old: String,
    /// When `old` was accepted, already a date.
    since: String,
    new: String,
}

impl CertChange {
    fn ask(self, screen: &mut ConnectScreen) {
        screen.ask_changed(self.creds, self.old, self.since, self.new);
    }
}

enum Screen {
    Connect(Box<ConnectScreen>, Box<dyn Platform>),
    Router(Box<CoreRouterUi>),
}

struct GuiApp {
    screen: Screen,
    /// Window preferences as last loaded or saved; applied to the router
    /// UI once one is picked on the connect screen.
    prefs: Option<String>,
}

impl GuiApp {
    fn router(ui: CoreRouterUi) -> Self {
        Self {
            screen: Screen::Router(Box::new(ui)),
            prefs: None,
        }
    }

    fn connect(screen: ConnectScreen, platform: Box<dyn Platform>) -> Self {
        Self {
            screen: Screen::Connect(Box::new(screen), platform),
            prefs: None,
        }
    }

    /// Load the saved preferences (eframe storage) into the app.
    fn with_storage(mut self, cc: &eframe::CreationContext<'_>) -> Self {
        self.prefs = cc.storage.and_then(|s| s.get_string(PREFS_KEY));
        // The connect screen wears the stored theme too.
        if let Some(theme) = self.prefs.as_deref().and_then(corerouter_ui::stored_theme) {
            cc.egui_ctx.set_theme(theme);
        }
        if let (Screen::Router(r), Some(prefs)) = (&mut self.screen, &self.prefs) {
            r.apply_prefs(prefs);
        }
        self
    }
}

impl GuiApp {
    /// Switch to managing a router.
    fn show(&mut self, ui: &mut eframe::egui::Ui, mut r: CoreRouterUi) {
        if let Some(prefs) = &self.prefs {
            r.apply_prefs(prefs);
        }
        self.screen = Screen::Router(Box::new(r));
        ui.ctx().request_repaint();
    }
}

impl eframe::App for GuiApp {
    fn ui(&mut self, ui: &mut eframe::egui::Ui, _frame: &mut eframe::Frame) {
        let next = match &mut self.screen {
            Screen::Router(r) => {
                r.ui(ui);
                export::save_all(r);
                None
            }
            Screen::Connect(screen, platform) => {
                ui.ctx().request_repaint_after(CONNECT_REPAINT);
                let rows = platform.neighbors();
                let action = screen.ui(ui, &rows);
                look_up_saved(screen, platform.as_mut());
                if let Some(saved) = screen.take_saved_change() {
                    platform.store_saved(&saved);
                }
                let lab = matches!(action, Some(ConnectAction::VirtualLab));
                let creds = match action {
                    None => None,
                    Some(ConnectAction::VirtualLab) => None,
                    Some(ConnectAction::Connect(c) | ConnectAction::Once(c)) => Some(c),
                    Some(ConnectAction::ForgetPassword { address, user }) => {
                        if let Err(e) = platform.forget_password(&address, &user) {
                            screen.set_error(e);
                        }
                        None
                    }
                    Some(ConnectAction::Trust {
                        creds,
                        fingerprint,
                        forget_password,
                    }) => {
                        if forget_password
                            && let Err(e) = platform.forget_password(&creds.address, &creds.user)
                        {
                            log::warn!("saved password not forgotten: {e}");
                        }
                        match platform.trust(&creds.address, &fingerprint) {
                            Ok(()) => Some(creds),
                            Err(e) => {
                                screen.set_error(e);
                                None
                            }
                        }
                    }
                };
                if lab {
                    Some(platform.lab())
                } else {
                    match creds.map(|c| platform.connect(&c)) {
                        None => None,
                        Some(Ok(Connected::Ready(r))) => {
                            screen.connected();
                            Some(*r)
                        }
                        Some(Ok(Connected::Trust(c, fp))) => {
                            screen.ask_trust(c, fp);
                            None
                        }
                        Some(Ok(Connected::Changed(change))) => {
                            change.ask(screen);
                            None
                        }
                        Some(Err(e)) => {
                            screen.fail(e);
                            None
                        }
                    }
                }
            }
        };
        if let Some(r) = next {
            self.show(ui, r);
        }
    }

    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        if let Screen::Router(r) = &self.screen {
            self.prefs = Some(r.prefs());
        }
        if let Some(prefs) = &self.prefs {
            storage.set_string(PREFS_KEY, prefs.clone());
        }
    }

    /// Only our own preferences are kept, not egui's window layout.
    fn persist_egui_memory(&self) -> bool {
        false
    }

    /// Saved on exit too; a short interval also covers a killed process or
    /// a closed browser tab.
    fn auto_save_interval(&self) -> std::time::Duration {
        std::time::Duration::from_secs(2)
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn main() -> std::process::ExitCode {
    native::main()
}

#[cfg(target_arch = "wasm32")]
fn main() {
    use corerouter_engine::{Session, shared};
    use eframe::wasm_bindgen::JsCast as _;

    let canvas = eframe::web_sys::window()
        .and_then(|w| w.document())
        .and_then(|d| d.get_element_by_id("corerouter"))
        .and_then(|e| e.dyn_into::<eframe::web_sys::HtmlCanvasElement>().ok());
    let Some(canvas) = canvas else {
        log::error!("no <canvas id=\"corerouter\"> in the page");
        return;
    };
    let app = match web::choice() {
        web::Choice::Lab => GuiApp::router(CoreRouterUi::new(shared(Session::virtual_lab()))),
        web::Choice::Screen(home) => {
            let (screen, platform) = web::connect_screen(home);
            GuiApp::connect(screen, Box::new(platform))
        }
    };
    wasm_bindgen_futures::spawn_local(async move {
        let started = eframe::WebRunner::new()
            .start(
                canvas,
                eframe::WebOptions::default(),
                Box::new(move |cc| Ok(Box::new(app.with_storage(cc)))),
            )
            .await;
        if let Err(e) = started {
            log::error!("failed to start eframe: {e:?}");
        }
    });
}
