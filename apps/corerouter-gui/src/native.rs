use std::process::ExitCode;
use std::sync::mpsc;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use base64::Engine as _;
use corerouter_control::{Host, SharedHost, bind_loopback, spawn};
use corerouter_engine::{Session, Shared, shared};
use eframe::egui;
use serde_json::{Value, json};

use crate::GuiApp;

const USAGE: &str = "usage: corerouter-gui [--control <port>]";

/// Control host with a live window: everything `SharedHost` does, plus
/// `ui.screenshot` captured from the next rendered frame.
#[derive(Clone)]
struct GuiHost {
    inner: SharedHost,
    ctx: Arc<OnceLock<egui::Context>>,
}

impl Host for GuiHost {
    fn with_session(
        &mut self,
        f: &mut dyn FnMut(&mut Session) -> Result<Value, String>,
    ) -> Result<Value, String> {
        self.inner.with_session(f)
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

fn parse_args() -> Result<Option<u16>, String> {
    let mut control = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--control" => {
                let port = args.next().ok_or("--control needs a port")?;
                control = Some(port.parse().map_err(|_| format!("bad port '{port}'"))?);
            }
            "-h" | "--help" => return Err(USAGE.into()),
            other => return Err(format!("unknown argument '{other}'\n{USAGE}")),
        }
    }
    Ok(control)
}

pub fn main() -> ExitCode {
    env_logger::Builder::from_env(
        env_logger::Env::default()
            .default_filter_or("warn,corerouter_gui=info,corerouter_control=info"),
    )
    .init();
    let control = match parse_args() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let session: Shared = shared(Session::virtual_lab());
    let ctx_slot = Arc::new(OnceLock::new());

    if let Some(port) = control {
        let host = GuiHost {
            inner: SharedHost(Arc::clone(&session)),
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
            Ok(Box::new(GuiApp::new(session)))
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
