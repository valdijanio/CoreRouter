//! CoreRouter GUI.
//!
//! Native: `corerouter-gui [--connect HOST:PORT] [--control <port>]` manages a
//! `corerouter-daemon` over its control channel (like WinBox), or runs an
//! in-process virtual lab without `--connect`. `--control` serves the control
//! channel (including `ui.screenshot`) so an agent can drive and *see* the app.
//!
//! Web: same UI on a `<canvas id="corerouter">`, talking to the daemon's
//! WebSocket (`?connect=ws://…`, or the page's own origin when the daemon
//! serves the GUI); `?lab` runs the virtual lab in the browser instead.

use corerouter_ui::CoreRouterUi;

#[cfg(not(target_arch = "wasm32"))]
mod native;
#[cfg(not(target_arch = "wasm32"))]
mod remote;
#[cfg(target_arch = "wasm32")]
mod web;

struct GuiApp {
    ui: CoreRouterUi,
}

impl eframe::App for GuiApp {
    fn ui(&mut self, ui: &mut eframe::egui::Ui, _frame: &mut eframe::Frame) {
        self.ui.ui(ui);
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
    let ui = match web::choice() {
        web::Choice::Lab => CoreRouterUi::new(shared(Session::virtual_lab())),
        web::Choice::Connect(url) => {
            // Auth/TLS are G0.3: the daemon only listens on loopback.
            log::info!("managing the router at {url}");
            CoreRouterUi::with_backend(Box::new(web::WsBackend::new(url)))
        }
    };
    wasm_bindgen_futures::spawn_local(async move {
        let started = eframe::WebRunner::new()
            .start(
                canvas,
                eframe::WebOptions::default(),
                Box::new(move |_cc| Ok(Box::new(GuiApp { ui }))),
            )
            .await;
        if let Err(e) = started {
            log::error!("failed to start eframe: {e:?}");
        }
    });
}
