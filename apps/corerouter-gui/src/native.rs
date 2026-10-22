use std::process::ExitCode;
use std::sync::mpsc;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use base64::Engine as _;
use corerouter_control::{Client, Host, SharedHost, bind_loopback, spawn, spawn_clock};
use corerouter_engine::{Session, shared};
use corerouter_ui::CoreRouterUi;
use eframe::egui;
use serde_json::{Value, json};

use crate::GuiApp;
use crate::remote::Remote;

const USAGE: &str = "\
usage: corerouter-gui [--connect HOST:PORT] [--control <port>]

  --connect HOST:PORT   manage a corerouter-daemon (its control port, e.g. 127.0.0.1:7979)
                        instead of an in-process virtual lab
  --control <port>      serve the control channel on 127.0.0.1:<port> (ui.screenshot;
                        with --connect, every other method is passed on to the daemon)";

const PROXY_TIMEOUT: Duration = Duration::from_secs(2);

/// Where the session lives.
#[derive(Clone)]
enum Target {
    Local(SharedHost),
    /// The daemon at `addr`; each control connection opens its own client.
    Remote {
        addr: String,
    },
}

/// Control host with a live window: the session's methods (local, or passed
/// on to the daemon), plus `ui.screenshot` captured from the next frame.
struct GuiHost {
    target: Target,
    proxy: Option<Client>,
    ctx: Arc<OnceLock<egui::Context>>,
}

impl Clone for GuiHost {
    fn clone(&self) -> Self {
        Self {
            target: self.target.clone(),
            proxy: None,
            ctx: Arc::clone(&self.ctx),
        }
    }
}

impl GuiHost {
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
        match &mut self.target {
            Target::Local(h) => h.with_session(f),
            Target::Remote { addr } => Err(format!("this GUI manages {addr}")),
        }
    }

    fn forward(&mut self, method: &str, params: &Value) -> Option<Result<Value, String>> {
        let Target::Remote { addr } = &self.target else {
            return None;
        };
        let addr = addr.clone();
        Some(self.pass_on(&addr, method, params))
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

#[derive(Debug, Default, PartialEq, Eq)]
struct Args {
    control: Option<u16>,
    connect: Option<String>,
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
                if addr
                    .rsplit_once(':')
                    .is_none_or(|(h, p)| h.is_empty() || p.parse::<u16>().is_err())
                {
                    return Err(format!("--connect needs HOST:PORT, got '{addr}'"));
                }
                out.connect = Some(addr);
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
    let (ui, target) = match &args.connect {
        Some(addr) => match Remote::spawn(addr) {
            Ok(remote) => {
                // Auth/TLS are G0.3: only reach daemons over loopback or a tunnel.
                log::info!("managing the router at {addr} (no authentication: G0.3)");
                (
                    CoreRouterUi::with_backend(Box::new(remote)),
                    Target::Remote { addr: addr.clone() },
                )
            }
            Err(e) => {
                eprintln!("cannot start the connection thread: {e}");
                return ExitCode::FAILURE;
            }
        },
        None => {
            let session = shared(Session::virtual_lab());
            // Safe Mode timeouts need a clock; the lab has no other.
            if let Err(e) = spawn_clock(Arc::clone(&session)) {
                log::warn!("no clock thread ({e}): Safe Mode timeouts are unavailable");
            }
            (
                CoreRouterUi::new(Arc::clone(&session)),
                Target::Local(SharedHost(session)),
            )
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
            Ok(Box::new(GuiApp::new(ui, cc)))
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
            target: Target::Remote { addr },
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
    fn server_info_answers_without_the_daemon() {
        let gone = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = gone.local_addr().unwrap().to_string();
        drop(gone);
        let mut host = GuiHost {
            target: Target::Remote { addr },
            proxy: None,
            ctx: Arc::new(OnceLock::new()),
        };
        let info = corerouter_control::dispatch(&mut host, "server.info", &Value::Null).unwrap();
        assert_eq!(info["has_ui"], true);
        assert!(info["router_error"].is_string());
        assert!(corerouter_control::dispatch(&mut host, "engine.list", &Value::Null).is_err());
    }
}
