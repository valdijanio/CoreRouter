//! `corerouter-init run <command> [<params json>]`: one command on the
//! loopback control channel with the local token, the answer on stdout.
//! The image has no CLI; this is the maintenance shell's
//! (`corerouter.shell=`) way to reach the daemon, and what
//! `cargo xtask os ab-test` drives the A/B tests with.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use crate::plan;

/// Longest answer printed (a `system.package.print` is ~4 KiB).
const MAX_REPLY: u64 = 1 << 20;

pub fn main(args: &[String]) -> i32 {
    let (Some(command), params) = (args.first(), args.get(1)) else {
        let _ = writeln!(
            std::io::stderr(),
            "usage: corerouter-init run <command> [<params json>]"
        );
        return 2;
    };
    let params: serde_json::Value = match params.map(|p| serde_json::from_str(p)) {
        None => serde_json::json!({}),
        Some(Ok(v)) => v,
        Some(Err(e)) => {
            let _ = writeln!(std::io::stderr(), "params: {e}");
            return 2;
        }
    };
    let token_file = format!("{}/control-{}.token", plan::RUNTIME_DIR, plan::CONTROL_PORT);
    let token = match std::fs::read_to_string(&token_file) {
        Ok(t) => t.trim().to_owned(),
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "{token_file}: {e}");
            return 1;
        }
    };
    let req = serde_json::json!({
        "id": 1,
        "method": "engine.execute",
        "params": {"command": command, "params": params},
        "token": token,
    });
    let addr = SocketAddr::from(([127, 0, 0, 1], plan::CONTROL_PORT));
    let reply = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).and_then(|mut s| {
        s.set_read_timeout(Some(Duration::from_secs(30)))?;
        s.write_all(format!("{req}\n").as_bytes())?;
        let mut line = String::new();
        BufReader::new(s.take(MAX_REPLY)).read_line(&mut line)?;
        Ok(line)
    });
    match reply {
        Ok(line) => {
            let _ = writeln!(std::io::stdout(), "{}", line.trim_end());
            if line.contains("\"ok\":true") { 0 } else { 1 }
        }
        Err(e) => {
            let _ = writeln!(std::io::stderr(), "control channel: {e}");
            1
        }
    }
}
