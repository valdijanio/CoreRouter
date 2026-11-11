//! The first-boot setup on a Wi-Fi port (G1.30, `docs/wifi.md`): a notebook
//! or a mini PC whose only way to the network is its radio. Asked on the
//! console, after the port is picked: the country (a radio does not turn on
//! without one), the network out of a scan (or a hidden one, typed), and its
//! passphrase, never shown. Everything goes through the control channel
//! (`interface.wifi.*`): the engine validates, this file asks.
//!
//! A scan needs the radio on, so the country is set and the radio turned on
//! before the last question, and the setup says so. Cancelled, the radio
//! goes off again; the country stays (it is a fact about where the router
//! is, and nothing transmits by it alone). The network itself is applied
//! only on the final yes ([`join`]), and taken back if the radio does not
//! get on it.
//!
//! Names of networks are hostile (anybody in range picks one): they are
//! shown through `style::ascii`, never as they came.

use std::cmp::Reverse;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::console::Console;
use crate::ctl;
use crate::style::{self, dim, good, title, warn};

/// How long a scan may take (a radio listens on some 40 channels).
const SCAN_WAIT: Duration = Duration::from_secs(20);
/// How long the radio gets to join after the final yes.
const JOIN_WAIT: Duration = Duration::from_secs(30);
/// Networks listed; a console has 24 rows.
const MAX_LISTED: usize = 12;

/// A radio as the router has it (`interface.wifi.list`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Radio {
    pub name: String,
    pub mac: String,
}

fn text(v: &Value, k: &str) -> String {
    v.get(k).and_then(Value::as_str).unwrap_or("").to_owned()
}

/// The router's radios; none when it has no Wi-Fi (or the daemon is away).
pub fn radios() -> Vec<Radio> {
    ctl::call("interface.wifi.list", &json!({}))
        .ok()
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default()
        .iter()
        .map(|r| Radio {
            name: style::ascii(&text(r, "name")),
            mac: style::ascii(&text(r, "mac_address")).to_ascii_lowercase(),
        })
        .filter(|r| !r.name.is_empty())
        .collect()
}

/// A network a person can pick.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Net {
    /// As the access point announces it: what the command takes.
    pub ssid: String,
    pub signal: i64,
    /// `2ghz`, `5ghz`, `6ghz`.
    pub band: String,
    /// `wpa2`, `wpa2-wpa3`, `wpa3`, `open`.
    pub security: String,
}

/// What a scan (`interface.wifi.networks`) offers: the strongest access
/// point of each named network that can be joined, strongest first, and how
/// many networks were left out (802.1X, WEP: the engine says which).
pub fn nets(reply: &Value) -> (Vec<Net>, usize) {
    let mut all: Vec<(Net, bool)> = reply
        .get("networks")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|n| !text(n, "ssid").is_empty())
        .map(|n| {
            (
                Net {
                    ssid: text(n, "ssid"),
                    signal: n.get("signal").and_then(Value::as_i64).unwrap_or(-100),
                    band: text(n, "band"),
                    security: text(n, "security"),
                },
                n.get("joinable").and_then(Value::as_bool) == Some(true),
            )
        })
        .collect();
    all.sort_by_key(|(n, _)| Reverse(n.signal));
    let mut out: Vec<Net> = Vec::new();
    let mut left: Vec<String> = Vec::new();
    for (n, joinable) in all {
        if !joinable {
            if !left.contains(&n.ssid) {
                left.push(n.ssid);
            }
        } else if !out.iter().any(|o| o.ssid == n.ssid) {
            out.push(n);
        }
    }
    left.retain(|s| !out.iter().any(|o| &o.ssid == s));
    (out, left.len())
}

fn band_label(band: &str) -> &'static str {
    match band {
        "2ghz" => "2.4 GHz",
        "5ghz" => "5 GHz",
        "6ghz" => "6 GHz",
        _ => "",
    }
}

fn security_label(security: &str) -> &'static str {
    match security {
        "wpa3" => "WPA3",
        "wpa2-wpa3" => "WPA2/WPA3",
        "wpa2" => "WPA2",
        "open" => "open",
        _ => "?",
    }
}

/// The networks as a numbered table.
pub fn net_table(nets: &[Net]) -> String {
    let mut out = format!(
        "  {}",
        title(&format!(
            "{:>3}  {:<33}{:<10}{:<9}SECURITY",
            "#", "NETWORK", "SIGNAL", "BAND"
        ))
    );
    for (i, n) in nets.iter().take(MAX_LISTED).enumerate() {
        let name: String = style::ascii(&n.ssid).chars().take(32).collect();
        let security = security_label(&n.security);
        out.push_str(&format!(
            "\n  {:>3}  {:<33}{:<10}{:<9}{}",
            i + 1,
            name,
            format!("{} dBm", n.signal),
            band_label(&n.band),
            if n.security == "open" {
                warn(security)
            } else {
                security.to_owned()
            },
        ));
    }
    out
}

/// What was typed at the network question.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pick {
    /// The network at this index of the list.
    Net(usize),
    Rescan,
    Hidden,
    Cancel,
    Unknown,
}

pub fn pick(answer: &str, listed: usize) -> Pick {
    let a = answer.trim();
    match a.to_ascii_lowercase().as_str() {
        "" => Pick::Cancel,
        "r" => Pick::Rescan,
        "h" => Pick::Hidden,
        _ => match a.parse::<usize>() {
            Ok(n) if (1..=listed).contains(&n) => Pick::Net(n - 1),
            _ => Pick::Unknown,
        },
    }
}

/// What the questions ended with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Chosen {
    pub ssid: String,
    pub open: bool,
    pub hidden: bool,
    pub passphrase: String,
    pub country: String,
    /// The radio was off before the scan turned it on: off again on cancel.
    pub was_off: bool,
}

impl Chosen {
    /// The parameters of `interface.wifi.set` (and, with `id` for `name`,
    /// of its preview).
    pub fn params(&self, key: &str, radio: &str) -> Value {
        let mut p = json!({
            key: radio,
            "ssid": self.ssid,
            "security": if self.open { "open" } else { "auto" },
            "hidden": self.hidden,
            "disabled": false,
        });
        if !self.open
            && let Some(o) = p.as_object_mut()
        {
            o.insert("passphrase".into(), json!(self.passphrase));
        }
        p
    }

    /// The network on the summary: its name and what protects it.
    pub fn summary(&self) -> String {
        format!(
            "{} ({}{})",
            style::ascii(&self.ssid),
            if self.open {
                warn("open, no encryption")
            } else {
                "WPA2/WPA3, passphrase not shown".to_owned()
            },
            if self.hidden { ", hidden" } else { "" }
        )
    }
}

/// The radio off again, when the scan turned it on.
pub fn undo(radio: &str, was_off: bool) {
    if was_off {
        let _ = ctl::call("interface.wifi.disable", &json!({ "name": radio }));
    }
}

/// The first error the engine's preview has for `c`, if any.
fn refused(radio: &str, c: &Chosen) -> Option<String> {
    let p = ctl::call("interface.wifi.preview", &c.params("id", radio)).ok()?;
    p.get("checks")?
        .as_array()?
        .iter()
        .find(|k| k.get("level").and_then(Value::as_str) == Some("error"))
        .map(|k| style::ascii(&text(k, "message")))
}

/// One scan: asked, waited for, and what it heard.
fn scan(con: &Console, radio: &str) -> Result<(Vec<Net>, usize), String> {
    con.say(&dim(&format!("  Scanning on {radio}...")));
    ctl::call("interface.wifi.scan", &json!({ "name": radio }))?;
    let start = Instant::now();
    loop {
        std::thread::sleep(Duration::from_millis(500));
        let reply = ctl::call("interface.wifi.networks", &json!({ "name": radio }))?;
        let scanning = reply.get("scanning").and_then(Value::as_bool) == Some(true);
        if !scanning {
            if let Some(e) = reply.get("error").and_then(Value::as_str) {
                return Err(format!("the scan failed: {}", style::ascii(e)));
            }
            return Ok(nets(&reply));
        }
        if start.elapsed() > SCAN_WAIT {
            return Err(format!("the scan did not end in {} s", SCAN_WAIT.as_secs()));
        }
    }
}

/// The Wi-Fi questions for `radio`. `ask` is the setup's question (an empty
/// answer or none cancels). `Ok(None)`: cancelled, the radio as it was.
pub fn questions(
    con: &Console,
    ask: &dyn Fn(&str) -> Option<String>,
    radio: &str,
) -> Result<Option<Chosen>, String> {
    // The country: asked once, kept by the router.
    let set = ctl::call("interface.wifi.country.get", &json!({}))?;
    let country = match set.get("country").and_then(Value::as_str) {
        Some(c) => {
            con.say(&format!("  Country: {} (already set)", style::ascii(c)));
            c.to_owned()
        }
        None => {
            con.say(&style::block(
                2,
                "",
                0,
                "Wi-Fi needs the country the router is in: it decides the channels and the \
                 power the radio may use. It is set as soon as you answer.",
            ));
            loop {
                let q = style::prompt("Country code", None, Some("two letters, e.g. BR"));
                let Some(a) = ask(&q).filter(|a| !a.is_empty()) else {
                    return Ok(None);
                };
                match ctl::call(
                    "interface.wifi.country.set",
                    &json!({ "country": a.trim() }),
                ) {
                    Ok(v) => break text(&v, "country"),
                    Err(e) => con.say(&style::block(
                        2,
                        "",
                        0,
                        &format!("{}. Try again.", style::ascii(&e)),
                    )),
                }
            }
        }
    };
    // The radio on, for the scan.
    let was_off = ctl::call("interface.wifi.list", &json!({}))?
        .as_array()
        .into_iter()
        .flatten()
        .find(|r| text(r, "name") == radio)
        .and_then(|r| r.get("disabled").and_then(Value::as_bool))
        .unwrap_or(true);
    if was_off {
        ctl::call("interface.wifi.enable", &json!({ "name": radio }))?;
        con.say(&dim(&format!(
            "  {radio} is on now, to scan. If you cancel, it goes off again."
        )));
    }
    let chosen = network(con, ask, radio, &country, was_off);
    if !matches!(chosen, Ok(Some(_))) {
        undo(radio, was_off);
    }
    chosen
}

fn network(
    con: &Console,
    ask: &dyn Fn(&str) -> Option<String>,
    radio: &str,
    country: &str,
    was_off: bool,
) -> Result<Option<Chosen>, String> {
    let mut listed: Option<(Vec<Net>, usize)> = None;
    loop {
        let (nets, left) = match listed.take() {
            Some(l) => l,
            None => scan(con, radio)?,
        };
        if nets.is_empty() {
            con.say("  No network in range that can be joined.");
        } else {
            con.say(&net_table(&nets));
        }
        if nets.len() > MAX_LISTED {
            con.say(&dim(&format!(
                "  ({} weaker networks not listed)",
                nets.len() - MAX_LISTED
            )));
        }
        if left > 0 {
            con.say(&dim(&format!(
                "  ({left} more cannot be joined: 802.1X, OWE or WEP)"
            )));
        }
        let q = style::prompt(
            "Network",
            None,
            Some("number, r: scan again, h: hidden network"),
        );
        let Some(a) = ask(&q) else {
            return Ok(None);
        };
        let shown = nets.len().min(MAX_LISTED);
        let (ssid, open, hidden) = match pick(&a, shown) {
            Pick::Cancel => return Ok(None),
            Pick::Rescan => continue,
            Pick::Unknown => {
                con.say("  Use a number from the list, r or h.");
                listed = Some((nets, left));
                continue;
            }
            Pick::Net(i) => match nets.get(i) {
                Some(n) => (n.ssid.clone(), n.security == "open", false),
                None => continue,
            },
            Pick::Hidden => {
                let q = style::prompt(
                    "Network name",
                    None,
                    Some("exactly as the access point has it"),
                );
                let Some(name) = ask(&q).filter(|n| !n.is_empty()) else {
                    return Ok(None);
                };
                let q = style::prompt("Does it have a passphrase?", Some("Y/n"), None);
                let Some(k) = ask(&q) else {
                    return Ok(None);
                };
                (
                    name,
                    k.eq_ignore_ascii_case("n") || k.eq_ignore_ascii_case("no"),
                    true,
                )
            }
        };
        let mut c = Chosen {
            ssid,
            open,
            hidden,
            passphrase: String::new(),
            country: country.to_owned(),
            was_off,
        };
        if open {
            con.say(&style::block(
                2,
                &warn("WARNING"),
                9,
                "this network has no encryption: anybody in range reads what is not encrypted \
                 by itself. The router's own management is (TLS).",
            ));
            let q = style::prompt(
                &format!("Use {} anyway?", style::ascii(&c.ssid)),
                Some("y/N"),
                None,
            );
            let yes = ask(&q)
                .is_some_and(|a| a.eq_ignore_ascii_case("y") || a.eq_ignore_ascii_case("yes"));
            if !yes {
                listed = Some((nets, left));
                continue;
            }
            if let Some(why) = refused(radio, &c) {
                con.say(&style::block(2, "", 0, &format!("{why}.")));
                listed = Some((nets, left));
                continue;
            }
            return Ok(Some(c));
        }
        loop {
            let q = style::prompt(
                &format!("Passphrase for {}", style::ascii(&c.ssid)),
                None,
                Some("not shown"),
            );
            let Some(p) = con.ask_secret(&q).filter(|p| !p.is_empty()) else {
                return Ok(None);
            };
            c.passphrase = p;
            match refused(radio, &c) {
                None => return Ok(Some(c)),
                Some(why) => con.say(&style::block(2, "", 0, &format!("{why}. Try again."))),
            }
        }
    }
}

/// The final yes: the radio is told its network, and has [`JOIN_WAIT`] to
/// get on it. If it does not, the network is taken back (and the radio
/// turned off, if the setup turned it on) and the reason comes back.
pub fn join(con: &Console, radio: &str, c: &Chosen) -> Result<(), String> {
    ctl::call("interface.wifi.set", &c.params("name", radio))
        .map_err(|e| format!("interface.wifi.set: {e}"))?;
    con.say(&format!("  {}  interface.wifi.set", good("OK")));
    con.say(&dim(&format!(
        "  Joining {} (up to {} s)...",
        style::ascii(&c.ssid),
        JOIN_WAIT.as_secs()
    )));
    let start = Instant::now();
    let mut why = String::new();
    while start.elapsed() < JOIN_WAIT {
        std::thread::sleep(Duration::from_millis(500));
        let Ok(m) = ctl::call("interface.wifi.monitor", &json!({ "name": radio })) else {
            continue;
        };
        if text(&m, "state") == "connected" {
            con.say(&format!(
                "  {}  {radio}: connected to {} ({} dBm)",
                good("OK"),
                style::ascii(&c.ssid),
                m.get("signal").and_then(Value::as_i64).unwrap_or(0)
            ));
            return Ok(());
        }
        if let Some(f) = m.get("failure").filter(|f| !f.is_null()) {
            why = style::ascii(&text(f, "text"));
            // The access point said no: waiting longer changes nothing.
            if matches!(text(f, "code").as_str(), "wrong-key" | "rejected") {
                break;
            }
        }
    }
    let _ = ctl::call("interface.wifi.set", &json!({"name": radio, "ssid": ""}));
    undo(radio, c.was_off);
    if why.is_empty() {
        why = format!("no answer in {} s", JOIN_WAIT.as_secs());
    }
    Err(format!(
        "{radio} did not get on {}: {why}. The network was taken back; press Enter to start over",
        style::ascii(&c.ssid)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn heard() -> Value {
        json!({"name": "wifi1", "scanning": false, "age_secs": 1, "error": null, "networks": [
            {"ssid": "Vizinho_2G", "signal": -78, "band": "2ghz", "security": "wpa2", "joinable": true},
            {"ssid": "Casa", "signal": -61, "band": "2ghz", "security": "wpa2-wpa3", "joinable": true},
            {"ssid": "Casa", "signal": -52, "band": "5ghz", "security": "wpa2-wpa3", "joinable": true},
            {"ssid": "", "signal": -40, "band": "5ghz", "security": "wpa2", "joinable": true},
            {"ssid": "Corp", "signal": -70, "band": "5ghz", "security": "enterprise", "joinable": false},
            {"ssid": "Cafe", "signal": -80, "band": "2ghz", "security": "open", "joinable": true},
        ]})
    }

    #[test]
    fn a_scan_becomes_one_line_per_network_strongest_first() {
        let (nets, left) = nets(&heard());
        let names: Vec<&str> = nets.iter().map(|n| n.ssid.as_str()).collect();
        assert_eq!(
            names,
            ["Casa", "Vizinho_2G", "Cafe"],
            "hidden and 802.1X are not offered"
        );
        assert_eq!(
            (nets[0].signal, nets[0].band.as_str()),
            (-52, "5ghz"),
            "its strongest access point"
        );
        assert_eq!(left, 1, "Corp cannot be joined");
        let table = net_table(&nets);
        let lines: Vec<&str> = table.lines().collect();
        assert_eq!(lines.len(), 4);
        assert!(
            lines[1].contains("  1  Casa")
                && lines[1].contains("-52 dBm")
                && lines[1].contains("5 GHz")
        );
        assert!(lines[1].ends_with("WPA2/WPA3"), "{}", lines[1]);
        assert!(lines[3].contains("  3  Cafe") && lines[3].contains("open"));
    }

    #[test]
    fn a_hostile_network_name_cannot_draw_on_the_console() {
        let reply = json!({"networks": [
            {"ssid": "\u{1b}[2J\u{1b}[31mFREE", "signal": -30, "band": "2ghz", "security": "open", "joinable": true},
        ]});
        let (nets, _) = nets(&reply);
        let table = net_table(&nets);
        let row = table.lines().nth(1).unwrap();
        assert!(!row.contains('\u{1b}'), "{row:?}");
        assert!(row.contains("FREE"));
        // The command still gets the name as the access point has it.
        assert_eq!(nets[0].ssid, "\u{1b}[2J\u{1b}[31mFREE");
    }

    #[test]
    fn what_is_typed_at_the_network_question() {
        assert_eq!(pick("2", 3), Pick::Net(1));
        assert_eq!(pick(" 3 ", 3), Pick::Net(2));
        assert_eq!(pick("4", 3), Pick::Unknown);
        assert_eq!(pick("0", 3), Pick::Unknown);
        assert_eq!(pick("R", 3), Pick::Rescan);
        assert_eq!(pick("h", 3), Pick::Hidden);
        assert_eq!(pick("", 3), Pick::Cancel);
        assert_eq!(pick("Casa", 3), Pick::Unknown);
    }

    #[test]
    fn the_command_carries_the_passphrase_and_the_summary_does_not() {
        let c = Chosen {
            ssid: "Casa".into(),
            open: false,
            hidden: false,
            passphrase: "uma-senha-qualquer".into(),
            country: "BR".into(),
            was_off: true,
        };
        let p = c.params("name", "wifi1");
        assert_eq!(p["name"], "wifi1");
        assert_eq!(
            (p["ssid"].as_str(), p["security"].as_str()),
            (Some("Casa"), Some("auto"))
        );
        assert_eq!(p["passphrase"], "uma-senha-qualquer");
        assert_eq!(p["disabled"], false);
        assert!(!c.summary().contains("uma-senha"), "{}", c.summary());
        assert!(c.summary().contains("Casa"));
        let open = Chosen {
            open: true,
            hidden: true,
            passphrase: String::new(),
            ..c
        };
        let p = open.params("id", "wifi1");
        assert_eq!(
            (p["id"].as_str(), p["security"].as_str()),
            (Some("wifi1"), Some("open"))
        );
        assert!(p.get("passphrase").is_none());
        assert_eq!(p["hidden"], true);
        assert!(open.summary().contains("no encryption") && open.summary().contains("hidden"));
    }
}
