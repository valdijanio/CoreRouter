//! CoreRouter GUI.
//!
//! Native: `corerouter-gui [--control <port>]` runs the virtual lab and, with
//! `--control`, serves the control channel (including `ui.screenshot`) so an
//! agent can drive and *see* the app. Web: same UI on a `<canvas id="corerouter">`.
//! Remote mode (UI as a client of a real router) is docs/gaps.md G0.4.

use corerouter_engine::Shared;
use corerouter_ui::CoreRouterUi;

#[cfg(not(target_arch = "wasm32"))]
mod native;

struct GuiApp {
    ui: CoreRouterUi,
}

impl GuiApp {
    fn new(session: Shared) -> Self {
        Self {
            ui: CoreRouterUi::new(session),
        }
    }
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
    wasm_bindgen_futures::spawn_local(async move {
        let session = shared(Session::virtual_lab());
        let started = eframe::WebRunner::new()
            .start(
                canvas,
                eframe::WebOptions::default(),
                Box::new(move |_cc| Ok(Box::new(GuiApp::new(session)))),
            )
            .await;
        if let Err(e) = started {
            log::error!("failed to start eframe: {e:?}");
        }
    });
}
