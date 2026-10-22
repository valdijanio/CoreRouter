//! CoreRouter GUI.
//!
//! Native: `corerouter-gui [--connect HOST:PORT] [--control <port>]` manages a
//! `corerouter-daemon` over its control channel (like WinBox). Without
//! `--connect` it opens on the connect screen (WinBox login style): routers
//! heard with CRDP, the saved list, and a "Virtual lab" button for the
//! in-process lab. `--control` serves the control channel (including
//! `ui.screenshot`) so an agent can drive and *see* the app.
//!
//! Web: same UI on a `<canvas id="corerouter">`, talking to the daemon's
//! WebSocket: `?connect=ws://…` goes straight to it, `?lab` runs the virtual
//! lab in the browser, and otherwise the connect screen lists the neighbors
//! of the daemon that served the page (`ip.neighbor.list`).

use std::time::Duration;

use corerouter_ui::{ConnectAction, ConnectScreen, CoreRouterUi, NeighborRow, SavedRouter};

#[cfg(not(target_arch = "wasm32"))]
mod native;
#[cfg(not(target_arch = "wasm32"))]
mod remote;
#[cfg(target_arch = "wasm32")]
mod web;

/// How often the connect screen redraws while it waits for announcements.
const CONNECT_REPAINT: Duration = Duration::from_millis(500);

/// What differs between the native app and the browser on the connect screen.
trait Platform {
    /// Rows of the Neighbors tab.
    fn neighbors(&mut self) -> Vec<NeighborRow>;
    /// Keep the Saved tab (address, group, comment; never a password).
    fn store_saved(&mut self, saved: &[SavedRouter]);
    /// Start managing the router at `addr`, or say why not.
    fn connect(&mut self, addr: &str) -> Result<CoreRouterUi, String>;
    /// The in-process virtual lab.
    fn lab(&mut self) -> CoreRouterUi;
}

enum Screen {
    Connect(Box<ConnectScreen>, Box<dyn Platform>),
    Router(Box<CoreRouterUi>),
}

struct GuiApp {
    screen: Screen,
}

impl GuiApp {
    fn router(ui: CoreRouterUi) -> Self {
        Self {
            screen: Screen::Router(Box::new(ui)),
        }
    }

    fn connect(screen: ConnectScreen, platform: Box<dyn Platform>) -> Self {
        Self {
            screen: Screen::Connect(Box::new(screen), platform),
        }
    }
}

impl eframe::App for GuiApp {
    fn ui(&mut self, ui: &mut eframe::egui::Ui, _frame: &mut eframe::Frame) {
        let next = match &mut self.screen {
            Screen::Router(r) => {
                r.ui(ui);
                None
            }
            Screen::Connect(screen, platform) => {
                ui.ctx().request_repaint_after(CONNECT_REPAINT);
                let rows = platform.neighbors();
                let action = screen.ui(ui, &rows);
                if let Some(saved) = screen.take_saved_change() {
                    platform.store_saved(&saved);
                }
                match action {
                    None => None,
                    Some(ConnectAction::VirtualLab) => Some(platform.lab()),
                    Some(ConnectAction::Connect(addr)) => match platform.connect(&addr) {
                        Ok(r) => Some(r),
                        Err(e) => {
                            screen.set_error(e);
                            None
                        }
                    },
                }
            }
        };
        if let Some(r) = next {
            self.screen = Screen::Router(Box::new(r));
            ui.ctx().request_repaint();
        }
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
        web::Choice::Connect(url) => {
            // Auth/TLS are G0.3: the daemon only listens on loopback.
            log::info!("managing the router at {url}");
            GuiApp::router(CoreRouterUi::with_backend(Box::new(web::WsBackend::new(
                url,
            ))))
        }
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
                Box::new(move |_cc| Ok(Box::new(app))),
            )
            .await;
        if let Err(e) = started {
            log::error!("failed to start eframe: {e:?}");
        }
    });
}
