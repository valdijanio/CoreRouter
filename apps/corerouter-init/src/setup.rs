//! `corerouter-init setup <tty>…` (G1.6c, G1.6m): the router's consoles,
//! started by PID 1 once the router answers. The image has no shell: without
//! this, a person at the console of a fresh router could do nothing. Like
//! the first login of a CHR or a VyOS box, while no port has an address it
//! asks for the management port, address and gateway and the `admin`
//! password (optional: as on a CHR, the network takes the empty one until
//! it has one, with a warning everywhere — G0.3d), shows what it is
//! about to do, and applies it as commands on the control channel only on a
//! yes. With an address set, Enter shows the router's status and how to
//! reach it.
//!
//! G1.6m, from a first install on a VM: the invitation is shown again every
//! few minutes and a waiting question every half minute (whoever attaches
//! the serial console later saw an empty screen); no question has a default
//! that a stray Enter accepts (one put the address on the wrong cable); the
//! port is confirmed by its link and MAC; and the text says there is no
//! command shell here and what to use instead.

use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::console::Console;
use crate::ctl;
use crate::plan::Mgmt;

/// The invitation, again, while no port has an address.
const BANNER_EVERY: Duration = Duration::from_secs(300);
/// A question waiting for an answer is shown again this often.
const PROMPT_EVERY: Duration = Duration::from_secs(30);
/// A setup left half-way is dropped after this long (nothing applied).
const ABANDONED: Duration = Duration::from_secs(1800);
/// How often a quiet console checks whether an address appeared.
const POLL: Duration = Duration::from_secs(10);

const NO_SHELL: &str =
    "This console has no command shell: it only offers this setup and shows the router's status.";

fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// `(address/prefix, interface)` of every address.
fn addresses() -> Option<Vec<(String, String)>> {
    ctl::call("ip.address.list", &json!({})).ok().and_then(|v| {
        v.as_array().map(|a| {
            a.iter()
                .filter_map(|x| {
                    Some((
                        x.get("address")?.as_str()?.to_owned(),
                        x.get("interface")?.as_str()?.to_owned(),
                    ))
                })
                .collect()
        })
    })
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

fn banner() -> String {
    format!(
        "\nCoreRouter {}: no port has a management address yet. The router is running.\n{NO_SHELL}\n\
         Press Enter to set the management port, address, gateway and admin password.\n\
         Afterwards manage it over the network: the GUI (corerouter-gui --connect tls://<address>:8729)\n\
         or the CLI (corerouter-cli --connect tls://<address>:8729 --user admin).",
        version()
    )
}

fn connect_hint(addr: &str) -> String {
    let host = addr.split('/').next().unwrap_or("");
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    format!(
        "  GUI: corerouter-gui --connect tls://{host}:8729 (user admin)\n  CLI: corerouter-cli --connect tls://{host}:8729 --user admin"
    )
}

fn status(addrs: &[(String, String)]) -> String {
    let mut s = format!("\nCoreRouter {}. {NO_SHELL}\nAddresses:", version());
    for (a, i) in addrs.iter().take(8) {
        s.push_str(&format!("\n  {a} on {i}"));
    }
    if let Some((a, _)) = addrs.first() {
        s.push_str(&format!(
            "\nManage it from another machine:\n{}",
            connect_hint(a)
        ));
    }
    s.push_str("\nChange addresses there (IP > Addresses). This setup comes back when no port has an address.");
    s
}

pub fn main(ttys: &[String]) -> i32 {
    let con = Console::open(ttys);
    if con.names().is_empty() {
        // Nothing to serve; PID 1 does not start it again.
        return 0;
    }
    let mut next_banner = Instant::now();
    let mut had: Option<bool> = None;
    loop {
        let Some(addrs) = addresses() else {
            // The daemon is restarting: try again shortly.
            std::thread::sleep(POLL);
            continue;
        };
        let have = !addrs.is_empty();
        if have {
            if had == Some(false) {
                con.say("\nAn address was set: the first-boot setup is closed.");
                con.say(&status(&addrs));
            }
            had = Some(true);
            if con.ask("", Some(POLL)).is_some() {
                con.say(&status(&addrs));
            }
            continue;
        }
        had = Some(false);
        if Instant::now() >= next_banner {
            con.say(&banner());
            next_banner = Instant::now() + BANNER_EVERY;
        }
        if con.ask("", Some(POLL)).is_none() {
            continue;
        }
        if addresses().is_some_and(|a| !a.is_empty()) {
            continue;
        }
        match ask_and_apply(&con) {
            Ok(Some(addr)) => {
                con.say(&format!(
                    "\nDone. Manage it from another machine:\n{}",
                    connect_hint(&addr)
                ));
                had = Some(true);
            }
            Ok(None) => con.say("Cancelled: nothing was changed."),
            Err(e) => con.say(&format!("Not applied: {e}")),
        }
        next_banner = Instant::now() + BANNER_EVERY;
    }
}

/// One question; `None`: no answer for [`ABANDONED`] or the console went.
fn ask(con: &Console, prompt: &str) -> Option<String> {
    con.ask_shown(prompt, PROMPT_EVERY, ABANDONED)
}

fn yes(answer: Option<&str>) -> bool {
    answer.is_some_and(|a| a.eq_ignore_ascii_case("y") || a.eq_ignore_ascii_case("yes"))
}

/// A port picked by number or name from `ports` (`name`, `MAC`, link).
pub fn pick<'a>(
    answer: &str,
    ports: &'a [(String, String, bool)],
) -> Option<&'a (String, String, bool)> {
    let a = answer.trim();
    if let Ok(n) = a.parse::<usize>() {
        return n.checked_sub(1).and_then(|i| ports.get(i));
    }
    ports.iter().find(|p| p.0 == a)
}

pub fn describe(p: &(String, String, bool)) -> String {
    format!(
        "{} ({}, {})",
        p.0,
        if p.2 { "link up" } else { "no link" },
        p.1
    )
}

/// The questions, a summary, then the commands. `Ok(None)`: cancelled.
fn ask_and_apply(con: &Console) -> Result<Option<String>, String> {
    let ports: Vec<(String, String, bool)> = crate::links::ports_with_link()
        .into_iter()
        .map(|(f, up)| (f.kernel, f.mac, up))
        .collect();
    con.say("\nEthernet ports (empty answer: cancel):");
    for (i, p) in ports.iter().enumerate() {
        con.say(&format!("  {}) {}", i + 1, describe(p)));
    }
    if ports.is_empty() {
        con.say("  none found: type the port name.");
    }
    let port = loop {
        let Some(a) = ask(con, "Management port (number or name): ") else {
            return Ok(None);
        };
        if a.is_empty() {
            return Ok(None);
        }
        let Some(p) = pick(&a, &ports)
            .cloned()
            .or_else(|| ports.is_empty().then(|| (a.clone(), "?".to_owned(), false)))
        else {
            con.say("No such port; use a number from the list or a name.");
            continue;
        };
        if yes(ask(con, &format!("Use {}? [y/N] ", describe(&p))).as_deref()) {
            break p.0;
        }
    };
    let m = loop {
        let Some(addr) = ask(con, "Address/prefix (e.g. 192.0.2.10/24; empty: cancel): ") else {
            return Ok(None);
        };
        if addr.is_empty() {
            return Ok(None);
        }
        let Some(gw) = ask(con, "Gateway (empty: none): ") else {
            return Ok(None);
        };
        let spec = if gw.is_empty() {
            format!("{port},{addr}")
        } else {
            format!("{port},{addr},{gw}")
        };
        match Mgmt::parse(&spec) {
            Ok(m) => break m,
            Err(e) => con.say(&format!("{e}; again.")),
        }
    };
    let mut password = None;
    if admin_without_password() {
        con.say(
            "The admin user has no password. You can set one now or later: until then anyone \
             who reaches the router logs in as admin with an empty password.",
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
    con.say(&summary(&m, password.is_some()));
    if !yes(ask(con, "Apply? [y/N] ").as_deref()) {
        return Ok(None);
    }
    for (cmd, params) in m.commands() {
        ctl::call(cmd, &params).map_err(|e| format!("{cmd}: {e}"))?;
        con.say(&format!("  {cmd}: ok"));
    }
    if let Some(p) = password {
        ctl::call("user.set", &json!({"name": "admin", "password": p}))
            .map_err(|e| format!("admin password: {e}"))?;
        con.say("  admin password: set");
    } else {
        con.say(NO_PASSWORD_YET);
    }
    Ok(Some(m.address))
}

/// The last words of a setup that kept admin without a password (G0.3d).
pub const NO_PASSWORD_YET: &str = "  admin has no password: log in from the network as admin with an \
     empty password (GUI or CLI, over TLS) and set one there. Until then anyone who reaches \
     the router can do the same; the GUI, the CLI and the health checks keep warning.";

pub fn summary(m: &Mgmt, password: bool) -> String {
    format!(
        "\nAbout to apply:\n  port      {}\n  address   {}\n  gateway   {}\n  admin     {}",
        m.interface,
        m.address,
        m.gateway.as_deref().unwrap_or("none"),
        if password {
            "new password"
        } else {
            "no password (empty password works from the network; set one later)"
        }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ports() -> Vec<(String, String, bool)> {
        vec![
            ("ether1".into(), "52:54:00:00:00:01".into(), false),
            ("ether2".into(), "52:54:00:00:00:02".into(), true),
        ]
    }

    #[test]
    fn a_port_is_picked_by_number_or_name_never_by_default() {
        let p = ports();
        assert_eq!(pick("2", &p).map(|x| x.0.as_str()), Some("ether2"));
        assert_eq!(pick(" ether1 ", &p).map(|x| x.0.as_str()), Some("ether1"));
        for bad in ["", "0", "3", "eth0", "-1"] {
            assert!(pick(bad, &p).is_none(), "{bad}");
        }
        assert_eq!(describe(&p[1]), "ether2 (link up, 52:54:00:00:00:02)");
    }

    #[test]
    fn only_an_explicit_yes_confirms() {
        assert!(yes(Some("y")) && yes(Some("YES")));
        for a in [None, Some(""), Some("n"), Some("s"), Some("yy")] {
            assert!(!yes(a), "{a:?}");
        }
    }

    #[test]
    fn texts_say_there_is_no_shell_and_how_to_connect() {
        assert!(banner().contains("no command shell"));
        let s = status(&[("192.0.2.10/24".into(), "ether1".into())]);
        assert!(s.contains("192.0.2.10/24 on ether1"));
        assert!(s.contains("tls://192.0.2.10:8729"));
        assert!(connect_hint("2001:db8::1/64").contains("tls://[2001:db8::1]:8729"));
        let m = Mgmt::parse("ether2,192.0.2.10/24,192.0.2.1").unwrap();
        let t = summary(&m, true);
        assert!(t.contains("port      ether2") && t.contains("gateway   192.0.2.1"));
        // G0.3d: no password is a choice, and the text says what it means.
        let t = summary(&m, false);
        assert!(t.contains("empty password works from the network"), "{t}");
        assert!(!t.contains("refused"), "{t}");
        assert!(NO_PASSWORD_YET.contains("empty password") && NO_PASSWORD_YET.contains("set one"));
    }
}
