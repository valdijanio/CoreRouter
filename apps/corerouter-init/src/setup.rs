//! `corerouter-init setup <tty>…` (G1.6c): the first-boot setup on the
//! consoles, started by PID 1 when the router answers but has no address
//! on any port. The image has no shell: without it a person at the console
//! of a fresh router could do nothing. Like the first login of a CHR or a
//! VyOS box, it asks for the management port, address and gateway and the
//! `admin` password (network logins are refused until it has one), and
//! applies them as commands on the control channel. It ends once an
//! address exists, whoever set it.

use std::time::Duration;

use serde_json::{Value, json};

use crate::console::Console;
use crate::ctl;
use crate::plan::Mgmt;

fn addresses() -> usize {
    ctl::call("ip.address.list", &json!({}))
        .ok()
        .and_then(|v| v.as_array().map(Vec::len))
        .unwrap_or(0)
}

fn admin_without_password() -> bool {
    ctl::call("user.list", &json!({})).ok().is_some_and(|v| {
        v.as_array().is_some_and(|us| {
            us.iter().any(|u| {
                u.get("name").and_then(Value::as_str) == Some("admin")
                    && u.get("no_password").and_then(Value::as_bool) == Some(true)
            })
        })
    })
}

fn ports() -> Vec<(String, bool)> {
    ctl::call("interface.list", &json!({"type": "ether"}))
        .ok()
        .and_then(|v| {
            v.as_array().map(|a| {
                a.iter()
                    .filter_map(|i| {
                        Some((
                            i.get("name")?.as_str()?.to_owned(),
                            i.get("running").and_then(Value::as_bool).unwrap_or(false),
                        ))
                    })
                    .collect()
            })
        })
        .unwrap_or_default()
}

pub fn main(ttys: &[String]) -> i32 {
    let con = Console::open(ttys);
    if con.names().is_empty() {
        return 1;
    }
    loop {
        if addresses() > 0 {
            return 0;
        }
        con.say("\nCoreRouter: no management address is set. Press Enter to set one (the router keeps running).");
        if con.ask("", Some(Duration::from_secs(600))).is_none() {
            continue;
        }
        if addresses() > 0 {
            con.say("An address was set meanwhile: nothing to do.");
            return 0;
        }
        match ask_and_apply(&con) {
            Ok(Some(addr)) => {
                con.say(&format!(
                    "\nDone. Manage it from another machine: corerouter-gui --connect tls://{addr}:8729 (user admin)."
                ));
                return 0;
            }
            Ok(None) => con.say("Cancelled: nothing was changed."),
            Err(e) => con.say(&format!("Not applied: {e}")),
        }
    }
}

/// The questions, then the commands. `Ok(None)`: cancelled.
fn ask_and_apply(con: &Console) -> Result<Option<String>, String> {
    let ps = ports();
    let list: Vec<String> = ps
        .iter()
        .map(|(n, up)| format!("{n}{}", if *up { " (link up)" } else { "" }))
        .collect();
    con.say(&format!(
        "Ports: {}",
        if list.is_empty() {
            "none found".into()
        } else {
            list.join(", ")
        }
    ));
    let first = ps
        .iter()
        .find(|(_, up)| *up)
        .or(ps.first())
        .map(|(n, _)| n.clone())
        .unwrap_or_default();
    let Some(port) = con.ask(&format!("Port [{first}]: "), None) else {
        return Ok(None);
    };
    let port = if port.is_empty() { first } else { port };
    let Some(addr) = con.ask("Address/prefix (e.g. 192.0.2.10/24; empty: cancel): ", None) else {
        return Ok(None);
    };
    if addr.is_empty() {
        return Ok(None);
    }
    let gw = con.ask("Gateway (empty: none): ", None).unwrap_or_default();
    let spec = if gw.is_empty() {
        format!("{port},{addr}")
    } else {
        format!("{port},{addr},{gw}")
    };
    let m = Mgmt::parse(&spec)?;
    let mut password = None;
    if admin_without_password() {
        con.say(
            "The admin user has no password: logins from the network are refused until it has one.",
        );
        loop {
            let Some(a) = con.ask_secret("New admin password (empty: keep none for now): ") else {
                return Ok(None);
            };
            if a.is_empty() {
                break;
            }
            let b = con.ask_secret("Again: ").unwrap_or_default();
            if a == b {
                password = Some(a);
                break;
            }
            con.say("They differ; again.");
        }
    }
    for (cmd, params) in m.commands() {
        ctl::call(cmd, &params).map_err(|e| format!("{cmd}: {e}"))?;
        con.say(&format!("  {cmd}: ok"));
    }
    if let Some(p) = password {
        ctl::call("user.set", &json!({"name": "admin", "password": p}))
            .map_err(|e| format!("admin password: {e}"))?;
        con.say("  admin password: set");
    }
    Ok(Some(m.address.split('/').next().unwrap_or("").to_owned()))
}
