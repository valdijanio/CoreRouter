//! corerouter-cli — talks to a router over the control channel, or runs a
//! throwaway in-process virtual lab when no `--connect` is given.

use std::io::{self, BufReader};
use std::process::ExitCode;

use base64::Engine as _;
use corerouter_control::DEFAULT_PORT;
use corerouter_engine::Session;
use corerouter_mcp::{Backend, Headless, Remote};
use serde_json::{Value, json};

mod shell;

const USAGE: &str = "\
usage: corerouter-cli <command> [--connect HOST:PORT]

  list [prefix]               list commands (id, params, enabled)
  run <id> [json-params]      run one command, e.g. run ip.address.add '{\"address\":\"10.0.0.1/24\",\"interface\":\"ether1\"}'
  inspect [path]              state summary, or one subtree (interfaces, routing.bgp, running.ip, journal)
  screenshot <out.png>        save the GUI window (needs --connect to corerouter-gui --control)
  mcp [--headless]            MCP server on stdio; default tries 127.0.0.1:7979, then headless
  shell [--user NAME]         RouterOS-style terminal (/ip address print; Tab, ?, Ctrl+X); see docs/terminal.md

Without --connect, list/run/inspect/shell use a fresh in-process virtual lab (nothing persists).";

fn main() -> ExitCode {
    // stderr only: in `mcp` mode stdout carries the protocol.
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn"))
        .target(env_logger::Target::Stderr)
        .init();
    match real_main() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}

fn real_main() -> Result<(), String> {
    let mut connect: Option<String> = None;
    let mut headless = false;
    let mut user: Option<String> = None;
    let mut pos: Vec<String> = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--connect" => connect = Some(args.next().ok_or("--connect needs HOST:PORT")?),
            "--headless" => headless = true,
            "--user" => user = Some(args.next().ok_or("--user needs a name")?),
            "-h" | "--help" => return Err(USAGE.into()),
            _ => pos.push(a),
        }
    }
    let mut pos = pos.into_iter();
    let cmd = pos.next().ok_or(USAGE)?;

    if cmd == "mcp" {
        return mcp(connect, headless);
    }

    let mut backend: Box<dyn Backend> = match &connect {
        Some(addr) => Box::new(Remote::connect(addr)?),
        None => Box::new(Headless::new(Session::virtual_lab())),
    };
    if cmd == "shell" {
        let user = user
            .or_else(|| std::env::var("USER").ok())
            .unwrap_or_else(|| "admin".into());
        return shell::run(backend.as_mut(), &user);
    }
    let result = match cmd.as_str() {
        "list" => {
            let prefix = pos.next().unwrap_or_default();
            let list = backend.call("engine.list", Value::Null)?;
            for c in list.as_array().into_iter().flatten() {
                let id = c.get("id").and_then(Value::as_str).unwrap_or("");
                if !id.starts_with(&prefix) {
                    continue;
                }
                let params = c.get("params").and_then(Value::as_str).unwrap_or("");
                let off = c
                    .get("disabledReason")
                    .and_then(Value::as_str)
                    .map(|r| format!("  [disabled: {r}]"))
                    .unwrap_or_default();
                println!("{id:<28} {params}{off}");
            }
            return Ok(());
        }
        "run" => {
            let id = pos.next().ok_or("run needs a command id")?;
            let params: Value = match pos.next() {
                Some(raw) => serde_json::from_str(&raw).map_err(|e| format!("params: {e}"))?,
                None => Value::Null,
            };
            backend.call("engine.execute", json!({"command": id, "params": params}))?
        }
        "inspect" => backend.call("state.inspect", json!({"path": pos.next()}))?,
        "screenshot" => {
            let out = pos.next().ok_or("screenshot needs an output path")?;
            let img = backend.call("ui.screenshot", Value::Null)?;
            let data = img
                .get("data")
                .and_then(Value::as_str)
                .ok_or("reply has no image data")?;
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(data)
                .map_err(|e| format!("bad base64: {e}"))?;
            std::fs::write(&out, bytes).map_err(|e| format!("{out}: {e}"))?;
            json!({"saved": out, "width": img.get("width"), "height": img.get("height")})
        }
        other => return Err(format!("unknown command '{other}'\n\n{USAGE}")),
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&result).unwrap_or_else(|_| result.to_string())
    );
    Ok(())
}

fn mcp(connect: Option<String>, headless: bool) -> Result<(), String> {
    let mut backend: Box<dyn Backend> = if headless {
        Box::new(Headless::new(Session::virtual_lab()))
    } else if let Some(addr) = connect {
        Box::new(Remote::connect(&addr)?)
    } else {
        match Remote::connect(&format!("127.0.0.1:{DEFAULT_PORT}")) {
            Ok(r) => Box::new(r),
            Err(e) => {
                log::info!("no router on port {DEFAULT_PORT} ({e}); using headless");
                Box::new(Headless::new(Session::virtual_lab()))
            }
        }
    };
    let stdin = io::stdin();
    corerouter_mcp::serve(
        backend.as_mut(),
        BufReader::new(stdin.lock()),
        io::stdout().lock(),
    )
    .map_err(|e| format!("mcp: {e}"))
}
