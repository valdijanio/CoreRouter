//! corerouter-cli — talks to a router over the control channel, or runs a
//! throwaway in-process virtual lab when no `--connect` is given.

use std::io::{self, BufReader};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use base64::Engine as _;
use corerouter_control::DEFAULT_PORT;
use corerouter_engine::Session;
use corerouter_mcp::{Backend, Headless, Remote};
use serde_json::{Value, json};

const USAGE: &str = "\
usage: corerouter-cli <command> [--connect HOST:PORT]

  list [prefix]               list commands (id, params, enabled)
  run <id> [json-params]      run one command, e.g. run ip.address.add '{\"address\":\"10.0.0.1/24\",\"interface\":\"ether1\"}'
  watch <id> [json-params]    start a tool task and print it until done (Ctrl+C stops it), e.g.
                              watch tool.ping.start '{\"address\":\"8.8.8.8\",\"count\":4}'
  inspect [path]              state summary, or one subtree (interfaces, routing.bgp, running.ip, journal)
  screenshot <out.png>        save the GUI window (needs --connect to corerouter-gui --control)
  mcp [--headless]            MCP server on stdio; default tries 127.0.0.1:7979, then headless

Without --connect, list/run/inspect use a fresh in-process virtual lab (nothing persists).";

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
    let mut pos: Vec<String> = Vec::new();
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--connect" => connect = Some(args.next().ok_or("--connect needs HOST:PORT")?),
            "--headless" => headless = true,
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
        None => Box::new(Headless::new(lab())),
    };
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
        "watch" => {
            let id = pos.next().ok_or("watch needs a command id")?;
            let params: Value = match pos.next() {
                Some(raw) => serde_json::from_str(&raw).map_err(|e| format!("params: {e}"))?,
                None => Value::Null,
            };
            return watch(backend.as_mut(), &id, params);
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

/// Start a tool task and print its events (RouterOS style) until it ends.
/// Ctrl+C asks the router to stop it, then prints the statistics.
fn watch(backend: &mut dyn Backend, id: &str, params: Value) -> Result<(), String> {
    use corerouter_engine::tools::text;
    let interrupted = Arc::new(AtomicBool::new(false));
    signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&interrupted))
        .map_err(|e| format!("cannot catch Ctrl+C: {e}"))?;
    let started = backend.call("engine.execute", json!({"command": id, "params": params}))?;
    let task = started
        .get("task_id")
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("{id} started no task: {started}"))?;
    let mut after = 0u64;
    let mut stopping = false;
    let mut header = false;
    loop {
        if interrupted.load(Ordering::Relaxed) && !stopping {
            stopping = true;
            backend.call(
                "engine.execute",
                json!({"command": "tool.task.stop", "params": {"id": task}}),
            )?;
        }
        let p = backend.call(
            "engine.execute",
            json!({"command": "tool.task.poll", "params": {"id": task, "after_seq": after}}),
        )?;
        let kind = p.get("kind").and_then(Value::as_str).unwrap_or("");
        if !header {
            header = true;
            if let Some(h) = text::header(kind) {
                println!("{h}");
            }
        }
        if let Some(n) = p.get("lost").and_then(Value::as_u64).filter(|n| *n > 0) {
            println!("({n} events not shown: too far behind)");
        }
        for ev in p
            .get("events")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            println!("{}", text::line(kind, ev));
        }
        after = p.get("next_seq").and_then(Value::as_u64).unwrap_or(after);
        if p.get("done").and_then(Value::as_bool) == Some(true) {
            for l in text::summary(kind, p.get("summary").unwrap_or(&Value::Null)) {
                println!("{l}");
            }
            let state = p.get("state").and_then(Value::as_str).unwrap_or("");
            return match (state, p.get("reason").and_then(Value::as_str)) {
                ("failed", Some(why)) => Err(why.to_owned()),
                _ => Ok(()),
            };
        }
        if p.get("more") != Some(&Value::Bool(true)) {
            std::thread::sleep(Duration::from_millis(200));
        }
    }
}

/// The in-process lab, with threads for the tools' background tasks.
fn lab() -> Session {
    let mut s = Session::virtual_lab();
    s.set_runner(corerouter_control::thread_runner());
    s
}

fn mcp(connect: Option<String>, headless: bool) -> Result<(), String> {
    let mut backend: Box<dyn Backend> = if headless {
        Box::new(Headless::new(lab()))
    } else if let Some(addr) = connect {
        Box::new(Remote::connect(&addr)?)
    } else {
        match Remote::connect(&format!("127.0.0.1:{DEFAULT_PORT}")) {
            Ok(r) => Box::new(r),
            Err(e) => {
                log::info!("no router on port {DEFAULT_PORT} ({e}); using headless");
                Box::new(Headless::new(lab()))
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
