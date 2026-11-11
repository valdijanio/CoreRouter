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
//!
//! G1.6zg (`docs/console.md`): one status screen ([`screen`]) for both
//! states, with who the router is, how to reach it (the TLS certificate's
//! fingerprint included), the ports with link and address and what needs
//! attention; the questions in numbered steps; colour and layout from
//! `style`. The live image drew its status twice: now one screen per
//! change.

use std::io::Write;
use std::os::unix::process::CommandExt;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use crate::console::Console;
use crate::ctl;
use crate::plan::Mgmt;
use crate::style::{self, bad, dim, good, key, title, warn};

/// The invitation, again, while no port has an address.
const BANNER_EVERY: Duration = Duration::from_secs(300);
/// A question waiting for an answer is shown again this often.
const PROMPT_EVERY: Duration = Duration::from_secs(30);
/// A setup left half-way is dropped after this long (nothing applied).
const ABANDONED: Duration = Duration::from_secs(1800);
/// How often a quiet console checks whether an address appeared.
const POLL: Duration = Duration::from_secs(10);
/// G1.6zg: how long the first screen waits for a DHCP client that is still
/// asking (the live image has one on every port), so it shows the address
/// instead of "no address yet" and, a moment later, everything again.
const DHCP_WAIT: Duration = Duration::from_secs(8);
/// The status screen with everything on it fits a 25-line VGA text screen
/// (its first line is blank and may scroll away; the last line of the
/// screen is the cursor's); the port table gets what is left.
const SCREEN_ROWS: usize = 24;
/// The port table never shrinks below this many ports.
const MIN_PORT_ROWS: usize = 3;
/// The control channel's TLS port (`plan::TLS_LISTEN`).
const TLS_PORT: u16 = 8729;

/// How a port's link reads on the console.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Link {
    Up,
    /// The port is on and has no carrier.
    Down,
    /// The port is off (disabled): whether a cable is in cannot be told.
    Off,
    /// A Wi-Fi radio (G1.30): no cable to tell about.
    Wifi,
}

impl Link {
    fn cell(self) -> String {
        match self {
            Link::Up => good("up"),
            Link::Down => "down".to_owned(),
            Link::Off => dim("off"),
            Link::Wifi => "Wi-Fi".to_owned(),
        }
    }

    fn phrase(self) -> &'static str {
        match self {
            Link::Up => "link up",
            Link::Down => "no link",
            Link::Off => "port off, link unknown",
            Link::Wifi => "Wi-Fi radio",
        }
    }
}

/// A physical Ethernet port as the kernel has it: what the setup and the
/// installer let the person choose from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Nic {
    pub name: String,
    pub mac: String,
    pub link: Link,
}

/// The physical ports, in bus order. A port that is off has no carrier to
/// read (the router's ports start off on a first boot): it says so instead
/// of "no link".
pub fn nics() -> Vec<Nic> {
    crate::links::ports_with_link()
        .into_iter()
        .map(|(f, carrier)| {
            let link = if carrier {
                Link::Up
            } else if admin_up(&f.kernel) {
                Link::Down
            } else {
                Link::Off
            };
            Nic {
                name: f.kernel,
                mac: f.mac,
                link,
            }
        })
        .collect()
}

/// `IFF_UP` of `/sys/class/net/<name>/flags`.
fn admin_up(name: &str) -> bool {
    std::fs::read_to_string(format!("/sys/class/net/{name}/flags"))
        .ok()
        .and_then(|f| u32::from_str_radix(f.trim().trim_start_matches("0x"), 16).ok())
        .is_some_and(|f| f & 1 != 0)
}

/// The ports as a table, numbered to be picked by number when `numbered`.
pub fn nic_table(nics: &[Nic], numbered: bool) -> String {
    let num = |n: &str| {
        if numbered {
            format!("{n:>3}  ")
        } else {
            String::new()
        }
    };
    let mut out = format!(
        "  {}",
        title(&format!("{}{:<17}{:<7}MAC", num("#"), "PORT", "LINK"))
    );
    for (i, n) in nics.iter().enumerate() {
        out.push_str(&format!(
            "\n  {}{:<17}{}{}",
            num(&(i + 1).to_string()),
            n.name,
            style::cell(&n.link.cell(), 7),
            n.mac
        ));
    }
    out
}

/// The version of this image: the build's, the same the daemon reports
/// (`0.1.0-dev.<N>`), known before the daemon answers anything.
fn version() -> &'static str {
    corerouter_buildinfo::VERSION
}

/// The machine, as its firmware names it (DMI): `<vendor> <product>`, the
/// placeholders board makers leave in skipped. Empty when there is nothing.
pub fn machine() -> String {
    let read = |f: &str| {
        style::ascii(&std::fs::read_to_string(format!("/sys/class/dmi/id/{f}")).unwrap_or_default())
    };
    machine_name(&read("sys_vendor"), &read("product_name"))
}

fn machine_name(vendor: &str, product: &str) -> String {
    const PLACEHOLDERS: [&str; 6] = [
        "to be filled by o.e.m.",
        "system manufacturer",
        "system product name",
        "default string",
        "not specified",
        "none",
    ];
    let real = |s: &str| !s.is_empty() && !PLACEHOLDERS.contains(&s.to_ascii_lowercase().as_str());
    match (real(vendor), real(product)) {
        (true, true) if product.starts_with(vendor) => product.to_owned(),
        (true, true) => format!("{vendor} {product}"),
        (true, false) => vendor.to_owned(),
        (false, true) => product.to_owned(),
        (false, false) => String::new(),
    }
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

/// A DHCP client is on (the live image has one on every port): an address
/// may be seconds away, as soon as the port's link comes up.
fn dhcp_asking() -> bool {
    ctl::call("ip.dhcp-client.list", &json!({}))
        .ok()
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default()
        .iter()
        .any(|c| {
            !c.get("flags")
                .and_then(Value::as_str)
                .is_some_and(|f| f.contains('X') || f.contains('I'))
        })
}

/// A port, or anything else with an address, on the status screen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Port {
    pub name: String,
    pub link: Link,
    pub addresses: Vec<String>,
}

/// What the status screen shows: gathered from the daemon ([`gather`]),
/// drawn by [`screen`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub version: String,
    /// `system.identity`, when it is not the factory's.
    pub identity: String,
    pub machine: String,
    pub live: bool,
    pub ports: Vec<Port>,
    /// The port of the web access (`ip.service` www-ssl), when it is on.
    pub web: Option<u16>,
    /// `SHA256:AB:…` of the router's TLS certificate.
    pub fingerprint: Option<String>,
    pub no_password: bool,
    /// Health checks in warning or error, by name (the password's aside).
    pub health: Vec<String>,
}

impl Snapshot {
    /// The address to manage the router at: the first one on a port with
    /// link, else the first one.
    fn management(&self) -> Option<&str> {
        let first = |up: bool| {
            self.ports
                .iter()
                .filter(|p| !up || p.link == Link::Up)
                .find_map(|p| p.addresses.first())
        };
        first(true).or_else(|| first(false)).map(String::as_str)
    }
}

fn gather(live: bool, addrs: &[(String, String)]) -> Snapshot {
    let list = |cmd: &str| {
        ctl::call(cmd, &json!({}))
            .ok()
            .and_then(|v| v.as_array().cloned())
            .unwrap_or_default()
    };
    let text = |v: &Value, k: &str| style::ascii(v.get(k).and_then(Value::as_str).unwrap_or(""));
    let flag = |v: &Value, k: &str| v.get(k).and_then(Value::as_bool) == Some(true);
    let of = |name: &str| -> Vec<String> {
        addrs
            .iter()
            .filter(|(_, i)| i == name)
            .map(|(a, _)| style::ascii(a))
            .collect()
    };
    let mut ports: Vec<Port> = list("interface.list")
        .iter()
        .filter_map(|i| {
            let name = text(i, "name");
            let addresses = of(&name);
            let kind = text(i, "type");
            let shown = kind == "ether" || kind == "wifi" || !addresses.is_empty();
            (shown && !name.is_empty()).then(|| Port {
                link: if flag(i, "disabled") {
                    Link::Off
                } else if flag(i, "running") {
                    Link::Up
                } else {
                    Link::Down
                },
                name,
                addresses,
            })
        })
        .collect();
    // An address on something `interface.list` did not show still counts.
    for (_, i) in addrs {
        let name = style::ascii(i);
        if !ports.iter().any(|p| p.name == name) {
            ports.push(Port {
                name,
                link: Link::Up,
                addresses: of(i),
            });
        }
    }
    let web = list("ip.service.print")
        .iter()
        .find(|s| text(s, "name") == "www-ssl" && flag(s, "enabled"))
        .and_then(|s| s.get("port").and_then(Value::as_u64))
        .and_then(|p| u16::try_from(p).ok());
    let identity = ctl::call("system.identity.get", &json!({}))
        .ok()
        .map(|v| text(&v, "name"))
        .filter(|n| n != "CoreRouter" && n != crate::plan::LIVE_HOSTNAME)
        .unwrap_or_default();
    let health = ctl::call("system.health.check", &json!({}))
        .ok()
        .and_then(|v| v.get("checks").and_then(Value::as_array).cloned())
        .unwrap_or_default()
        .iter()
        .filter(|c| {
            matches!(text(c, "severity").as_str(), "warning" | "error")
                && text(c, "key") != "auth.no_password"
        })
        .map(|c| text(c, "name"))
        .collect();
    Snapshot {
        version: version().to_owned(),
        identity,
        machine: machine(),
        live,
        ports,
        web,
        fingerprint: fingerprint(),
        no_password: admin_without_password(),
        health,
    }
}

/// `SHA256:AB:CD:…` of the router's TLS certificate, as the GUI, the CLI
/// and a browser show it on the first connection (`control::tls`): from the
/// console, the one place that is not the network, it can be compared.
fn fingerprint() -> Option<String> {
    let pem = std::fs::read_to_string(format!("{}/tls-cert.pem", crate::plan::CONFIG_DIR)).ok()?;
    pem_fingerprint(&pem)
}

/// The SHA-256 of the first certificate of a PEM file.
fn pem_fingerprint(pem: &str) -> Option<String> {
    let body: String = pem
        .lines()
        .skip_while(|l| !l.starts_with("-----BEGIN CERTIFICATE"))
        .skip(1)
        .take_while(|l| !l.starts_with("-----END"))
        .collect();
    let der = base64(&body)?;
    if der.is_empty() {
        return None;
    }
    let hex: Vec<String> = ring::digest::digest(&ring::digest::SHA256, &der)
        .as_ref()
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect();
    Some(format!("SHA256:{}", hex.join(":")))
}

/// Standard base64 (RFC 4648 §4), padding optional; `None` on anything else
/// or on more than a certificate can be.
fn base64(text: &str) -> Option<Vec<u8>> {
    const MAX: usize = 64 << 10;
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for b in text.bytes().filter(|b| !b.is_ascii_whitespace()) {
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((acc >> bits) & 0xff).ok()?);
            if out.len() > MAX {
                return None;
            }
        }
    }
    Some(out)
}

/// `address/prefix` as the host of a URL (IPv6 in brackets).
fn host_of(addr: &str) -> String {
    let host = addr.split('/').next().unwrap_or("");
    if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    }
}

/// How to reach the router at `addr`, the first line the one to look at.
fn reach(addr: &str, web: Option<u16>, fingerprint: Option<&str>) -> Vec<String> {
    let host = host_of(addr);
    let mut out = Vec::new();
    if let Some(port) = web {
        let url = if port == 443 {
            format!("https://{host}/")
        } else {
            format!("https://{host}:{port}/")
        };
        out.push(format!("  Web   {}  {}", key(&url), dim("(user admin)")));
    }
    let target = format!("--connect tls://{host}:{TLS_PORT}");
    let gui = format!("corerouter-gui {target}");
    let cli = format!("  CLI   corerouter-cli {target} --user admin");
    if style::width(&cli) <= style::WIDTH {
        out.push(format!(
            "  GUI   {}",
            if web.is_some() { gui } else { key(&gui) }
        ));
        out.push(cli);
    } else {
        // A full IPv6 address: the two commands do not fit a line.
        out.push(format!("  GUI, CLI   {target}"));
    }
    if let Some(fp) = fingerprint {
        // Two lines of 16 bytes: the whole of it does not fit one.
        let (a, b) = fp.split_at(fp.len().min(55));
        out.push(format!("  Cert  {a}"));
        if !b.is_empty() {
            out.push(format!("        {b}"));
        }
    }
    out
}

/// The port table of the status screen, at most `rows` ports: the ones with
/// an address first, then the ones with link, in the router's order.
fn port_table(ports: &[Port], rows: usize) -> Vec<String> {
    let mut out = vec![format!(
        "  {}",
        title(&format!("{:<17}{:<7}ADDRESS", "PORT", "LINK"))
    )];
    let rank = |p: &Port| {
        if !p.addresses.is_empty() {
            0
        } else if p.link == Link::Up {
            1
        } else {
            2
        }
    };
    let mut keep: Vec<usize> = (0..ports.len()).collect();
    keep.sort_by_key(|&i| ports.get(i).map(rank));
    keep.truncate(rows);
    keep.sort_unstable();
    for p in keep.iter().filter_map(|&i| ports.get(i)) {
        let addr = match p.addresses.as_slice() {
            [] => "-".to_owned(),
            [a] => a.clone(),
            [a, more @ ..] => format!("{a} (+{} more)", more.len()),
        };
        // 17 + 7 columns before it; an address is foreign text.
        let addr = style::clip(&addr, style::WIDTH - 26);
        out.push(format!(
            "  {}{}{addr}",
            style::cell(&style::clip(&p.name, 16), 17),
            style::cell(&p.link.cell(), 7)
        ));
    }
    if ports.is_empty() {
        out.push("  no port found".to_owned());
    } else if keep.len() < ports.len() {
        out.push(dim(&format!(
            "  ... and {} more (all of them in the GUI: Interfaces)",
            ports.len() - keep.len()
        )));
    }
    out
}

/// The status screen: who this is, how to reach it, the ports, what needs
/// attention, and what this console does. One screen for both states (an
/// address or none yet), at most [`SCREEN_ROWS`] lines of at most
/// [`style::WIDTH`] columns.
pub fn screen(s: &Snapshot) -> String {
    let mut product = format!("CoreRouter {}", s.version).trim_end().to_owned();
    if !s.identity.is_empty() {
        product.push_str(&format!("  {}", style::clip(&s.identity, 24)));
    }
    let mut top = vec![style::header(&product, &s.machine)];
    let mgmt = s.management();
    match mgmt {
        Some(addr) => top.extend(reach(addr, s.web, s.fingerprint.as_deref())),
        None => top.push(format!(
            "  The router is running, but {}.",
            warn("no port has a management address yet")
        )),
    }
    let warning = |text: &str| style::block(2, &warn("WARNING"), 9, text);
    let mut bottom = Vec::new();
    if s.live {
        bottom.push(warning(LIVE_NOTICE));
    }
    if s.no_password {
        bottom.push(warning(if mgmt.is_some() {
            "admin has no password: anyone who reaches the router logs in as admin with an \
             empty password. Set one from the GUI or the CLI."
        } else {
            "admin has no password: anyone who reaches the router will log in as admin \
             with an empty password. The setup asks for one."
        }));
    }
    if !s.health.is_empty() {
        bottom.push(warning(&format!(
            "health: {} (details in the GUI)",
            style::clip(&s.health.join(", "), 44)
        )));
    }
    if !bottom.is_empty() {
        bottom.push(String::new());
    }
    bottom.push(style::block(
        2,
        "",
        0,
        &if mgmt.is_some() {
            format!(
                "{NO_SHELL} Press {} to show this status again.",
                key("Enter")
            )
        } else {
            format!(
                "Press {} to set the management port, address, gateway and admin password. \
                 {NO_SHELL} Afterwards manage the router over the network.",
                key("Enter")
            )
        },
    ));
    let lines = |v: &[String]| v.iter().map(|b| b.lines().count().max(1)).sum::<usize>();
    // The header's leading blank line, the blank lines around the table,
    // its header and the "... and N more" line.
    let fixed = lines(&top) + lines(&bottom) + 4;
    let rows = SCREEN_ROWS.saturating_sub(fixed).max(MIN_PORT_ROWS);
    let mut out = top;
    out.push(String::new());
    out.extend(port_table(&s.ports, rows));
    out.push(String::new());
    out.extend(bottom);
    out.join("\n")
}

/// What this console is, in one sentence (G1.6m).
pub const NO_SHELL: &str = "This console has no command shell.";

/// G1.6y: what the console of the live ISO says on top of the rest.
const LIVE_NOTICE: &str = "live image, NOT INSTALLED: it runs from memory and nothing is written to a \
     disk until you ask. Install it from the GUI or the browser, or type i and Enter here.";

fn is_live() -> bool {
    let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
    crate::plan::BootOptions::parse(&cmdline).mode == crate::plan::Mode::Live
}

/// The console installer of the live image (`i`): it ends in a reboot.
fn console_install(line: &str, live: bool) {
    if live && line.trim().eq_ignore_ascii_case("i") {
        // A new process image: this one's threads read the same consoles.
        let e = std::process::Command::new("/proc/self/exe")
            .arg("install-here")
            .exec();
        let _ = writeln!(std::io::stderr(), "console installer: {e}");
    }
}

/// Before the first screen: a DHCP client that is asking gets a moment.
fn wait_for_dhcp(con: &Console) {
    if !addresses().is_some_and(|a| a.is_empty()) || !dhcp_asking() {
        return;
    }
    con.say(&dim(&format!(
        "\nCoreRouter: waiting up to {} s for an address from DHCP...",
        DHCP_WAIT.as_secs()
    )));
    let start = Instant::now();
    while start.elapsed() < DHCP_WAIT {
        std::thread::sleep(Duration::from_millis(500));
        if addresses().is_some_and(|a| !a.is_empty()) {
            return;
        }
    }
}

pub fn main(ttys: &[String]) -> i32 {
    let con = Console::open(ttys);
    if con.names().is_empty() {
        // Nothing to serve; PID 1 does not start it again.
        return 0;
    }
    let live = is_live();
    let mut next_banner = Instant::now();
    // What the last screen showed: an address or none; `None`: show it again.
    let mut shown: Option<bool> = None;
    wait_for_dhcp(&con);
    loop {
        let Some(addrs) = addresses() else {
            // The daemon is restarting: try again shortly.
            std::thread::sleep(POLL);
            continue;
        };
        let have = !addrs.is_empty();
        if have && shown == Some(false) {
            con.say(&format!(
                "\n  {}  An address was set: the first-boot setup is closed.",
                good("OK")
            ));
        }
        // One screen per change (G1.6zg: the live image drew it twice).
        if shown != Some(have) || (!have && Instant::now() >= next_banner) {
            con.say(&screen(&gather(live, &addrs)));
            next_banner = Instant::now() + BANNER_EVERY;
            shown = Some(have);
        }
        let Some(line) = con.ask("", Some(POLL)) else {
            continue;
        };
        console_install(&line, live);
        // Enter: the screen again, with what is true now.
        shown = None;
        if have || addresses().is_some_and(|a| !a.is_empty()) {
            continue;
        }
        match ask_and_apply(&con) {
            Ok(Some(a)) if a.is_empty() => con.say(&format!(
                "\n  {}  Done: the router is on the network and asks for its address by DHCP.",
                good("OK")
            )),
            Ok(Some(_)) => con.say(&format!(
                "\n  {}  Done: the router has its management address.",
                good("OK")
            )),
            Ok(None) => con.say("\n  Cancelled: nothing was changed."),
            Err(e) => con.say(&format!(
                "\n{}",
                style::block(2, &bad("FAILED"), 8, &format!("not applied: {e}"))
            )),
        }
    }
}

/// One question; `None`: no answer for [`ABANDONED`] or the console went.
fn ask(con: &Console, prompt: &str) -> Option<String> {
    con.ask_shown(prompt, PROMPT_EVERY, ABANDONED)
}

fn yes(answer: Option<&str>) -> bool {
    answer.is_some_and(|a| a.eq_ignore_ascii_case("y") || a.eq_ignore_ascii_case("yes"))
}

/// A port picked by number or name.
pub fn pick<'a>(answer: &str, nics: &'a [Nic]) -> Option<&'a Nic> {
    let a = answer.trim();
    if let Ok(n) = a.parse::<usize>() {
        return n.checked_sub(1).and_then(|i| nics.get(i));
    }
    nics.iter().find(|p| p.name == a)
}

pub fn describe(p: &Nic) -> String {
    format!("{} ({}, {})", p.name, p.link.phrase(), p.mac)
}

/// The first words of the setup.
fn intro() -> String {
    format!(
        "\n{}\n  An empty answer cancels. Nothing changes before the last question.",
        title("First-boot setup")
    )
}

/// The questions, a summary, then the commands. `Ok(None)`: cancelled.
/// `Ok(Some(""))`: applied, with the address still to come from DHCP.
fn ask_and_apply(con: &Console) -> Result<Option<String>, String> {
    // A radio is a port to pick too (G1.30): a notebook may have no other.
    let mut nics = nics();
    nics.extend(crate::setup_wifi::radios().into_iter().map(|r| Nic {
        name: r.name,
        mac: r.mac,
        link: Link::Wifi,
    }));
    con.say(&intro());
    let wifi_steps = nics.iter().any(|n| n.link == Link::Wifi);
    let first = |steps: usize| style::step(1, steps, "Management port");
    // The number of steps is known once the port is: say the longer one
    // only when the port picked is a radio.
    con.say(&first(4));
    if nics.is_empty() {
        con.say("  No Ethernet port found: type the port's name.");
    } else {
        con.say(&nic_table(&nics, true));
    }
    if wifi_steps {
        con.say(&dim(
            "  A Wi-Fi port asks for its network next (one more step).",
        ));
    }
    let port = loop {
        let Some(a) = ask(con, &style::prompt("Port", None, Some("number or name"))) else {
            return Ok(None);
        };
        if a.is_empty() {
            return Ok(None);
        }
        let Some(p) = pick(&a, &nics).cloned().or_else(|| {
            nics.is_empty().then(|| Nic {
                name: a.clone(),
                mac: "?".to_owned(),
                link: Link::Off,
            })
        }) else {
            con.say("  No such port: use a number from the list or a name.");
            continue;
        };
        let q = style::prompt(&format!("Use {}?", describe(&p)), Some("y/N"), None);
        if yes(ask(con, &q).as_deref()) {
            break p;
        }
    };
    if port.link != Link::Wifi {
        return rest(con, &port.name, None, 4);
    }
    con.say(&style::step(2, 5, "Wi-Fi network"));
    let question = |q: &str| ask(con, q);
    let kept = "  The radio is as it was. The country stays set.";
    let Some(chosen) = crate::setup_wifi::questions(con, &question, &port.name)? else {
        con.say(&dim(kept));
        return Ok(None);
    };
    let done = rest(con, &port.name, Some(&chosen), 5);
    if !matches!(done, Ok(Some(_))) {
        // Cancelled or failed after the scan turned the radio on.
        crate::setup_wifi::undo(&port.name, chosen.was_off);
    }
    if matches!(done, Ok(None)) {
        con.say(&dim(kept));
    }
    done
}

/// Where the address comes from.
enum Address {
    Fixed(Mgmt),
    /// Asked from the network the radio joins (a Wi-Fi port only).
    Dhcp,
}

/// The steps after the port (and, on a radio, its network): the address,
/// the admin password, the summary and the commands.
fn rest(
    con: &Console,
    port: &str,
    wifi: Option<&crate::setup_wifi::Chosen>,
    steps: usize,
) -> Result<Option<String>, String> {
    let at = steps.saturating_sub(2);
    con.say(&style::step(at, steps, "Address"));
    let address = loop {
        let q = if wifi.is_some() {
            style::prompt("Address/prefix", Some("dhcp"), Some("e.g. 192.0.2.10/24"))
        } else {
            style::prompt("Address/prefix", None, Some("e.g. 192.0.2.10/24"))
        };
        let Some(addr) = ask(con, &q) else {
            return Ok(None);
        };
        if addr.is_empty() || addr.eq_ignore_ascii_case("dhcp") {
            if wifi.is_some() {
                break Address::Dhcp;
            }
            if addr.is_empty() {
                return Ok(None);
            }
        }
        let Some(gw) = ask(con, &style::prompt("Gateway", Some("none"), None)) else {
            return Ok(None);
        };
        let spec = if gw.is_empty() {
            format!("{port},{addr}")
        } else {
            format!("{port},{addr},{gw}")
        };
        match Mgmt::parse(&spec) {
            Ok(m) => break Address::Fixed(m),
            Err(e) => con.say(&style::block(2, "", 0, &format!("{e}. Try again."))),
        }
    };
    con.say(&style::step(at + 1, steps, "Admin password"));
    let mut password = None;
    if admin_without_password() {
        con.say(&style::block(
            2,
            &warn("WARNING"),
            9,
            "admin has no password. Set one now or later: until then anyone who reaches the \
             router logs in as admin with an empty password.",
        ));
        loop {
            let q = style::prompt("New admin password", Some("none for now"), None);
            let Some(a) = con.ask_secret(&q) else {
                return Ok(None);
            };
            if a.is_empty() {
                break;
            }
            let b = con
                .ask_secret(&style::prompt("Repeat the password", None, None))
                .unwrap_or_default();
            if a == b {
                password = Some(a);
                break;
            }
            con.say("  The two differ. Try again.");
        }
    } else {
        con.say("  admin already has a password: it stays.");
    }
    con.say(&style::step(steps, steps, "Apply"));
    let (shown_address, gateway) = match &address {
        Address::Fixed(m) => (m.address.as_str(), m.gateway.as_deref()),
        Address::Dhcp => ("from DHCP, on the network joined", None),
    };
    con.say(&summary_rows(
        port,
        wifi.map(|c| (c.summary(), c.country.clone())),
        shown_address,
        gateway,
        password.is_some(),
    ));
    if !yes(ask(con, &style::prompt("Apply?", Some("y/N"), None)).as_deref()) {
        return Ok(None);
    }
    if let Some(c) = wifi {
        crate::setup_wifi::join(con, port, c)?;
    }
    let got = match &address {
        Address::Fixed(m) => {
            for (cmd, params) in m.commands() {
                // The radio is on already, with its network.
                if wifi.is_some() && cmd == "interface.set" {
                    continue;
                }
                ctl::call(cmd, &params).map_err(|e| format!("{cmd}: {e}"))?;
                con.say(&format!("  {}  {cmd}", good("OK")));
            }
            m.address.clone()
        }
        Address::Dhcp => {
            ctl::call("ip.dhcp-client.add", &json!({ "interface": port }))
                .map_err(|e| format!("ip.dhcp-client.add: {e}"))?;
            con.say(&format!("  {}  ip.dhcp-client.add", good("OK")));
            leased(con, port)
        }
    };
    if let Some(p) = password {
        ctl::call("user.set", &json!({"name": "admin", "password": p}))
            .map_err(|e| format!("admin password: {e}"))?;
        con.say(&format!("  {}  admin password set", good("OK")));
    } else {
        con.say(&no_password_yet());
    }
    Ok(Some(got))
}

/// The address `port` got from DHCP, waited for a moment; empty: none yet
/// (the client keeps asking, and the status screen shows it when it comes).
fn leased(con: &Console, port: &str) -> String {
    let start = Instant::now();
    while start.elapsed() < DHCP_WAIT * 2 {
        if let Some((a, _)) = addresses()
            .unwrap_or_default()
            .into_iter()
            .find(|(_, i)| i == port)
        {
            con.say(&format!(
                "  {}  {port}: {} from DHCP",
                good("OK"),
                style::ascii(&a)
            ));
            return a;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    con.say(&dim(&format!(
        "  No address from DHCP on {port} yet: the client keeps asking."
    )));
    String::new()
}

/// The last words of a setup that kept admin without a password (G0.3d).
pub fn no_password_yet() -> String {
    style::block(
        2,
        &warn("WARNING"),
        9,
        "admin has no password: log in from the network as admin with an empty password \
         (GUI or CLI, over TLS) and set one there. Until then anyone who reaches the router \
         can do the same; the GUI, the CLI and the health checks keep warning.",
    )
}

#[cfg(test)]
pub fn summary(m: &Mgmt, password: bool) -> String {
    summary_rows(
        &m.interface,
        None,
        &m.address,
        m.gateway.as_deref(),
        password,
    )
}

/// The summary before the last question; `wifi`: the network and the
/// country of a Wi-Fi port.
pub fn summary_rows(
    port: &str,
    wifi: Option<(String, String)>,
    address: &str,
    gateway: Option<&str>,
    password: bool,
) -> String {
    let row = |label: &str, value: &str| format!("  {label:<10}{value}");
    let mut rows = vec![row("Port", port)];
    if let Some((network, country)) = &wifi {
        rows.push(row("Network", network));
        rows.push(row("Country", country));
    }
    rows.extend([
        row("Address", address),
        row("Gateway", gateway.unwrap_or("none")),
        row(
            "Admin",
            &if password {
                "new password".to_owned()
            } else {
                format!(
                    "{} (the empty one works from the network; set one later)",
                    warn("no password")
                )
            },
        ),
    ]);
    rows.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::style::tests::check;

    fn nics() -> Vec<Nic> {
        vec![
            Nic {
                name: "ether1".into(),
                mac: "52:54:00:00:00:01".into(),
                link: Link::Off,
            },
            Nic {
                name: "ether2".into(),
                mac: "52:54:00:00:00:02".into(),
                link: Link::Up,
            },
        ]
    }

    fn port(name: &str, link: Link, addresses: &[&str]) -> Port {
        Port {
            name: name.into(),
            link,
            addresses: addresses.iter().map(|a| (*a).to_owned()).collect(),
        }
    }

    /// A router with everything the screen can show.
    fn busy() -> Snapshot {
        Snapshot {
            version: "0.1.0-dev.553".into(),
            identity: "border-1".into(),
            machine: "QEMU Standard PC (Q35 + ICH9, 2009)".into(),
            live: true,
            ports: (1..=48)
                .map(|n| match n {
                    1 => port(
                        "ether1",
                        Link::Up,
                        &["10.0.2.15/24", "192.0.2.1/30", "198.51.100.9/29"],
                    ),
                    7 => port(
                        "ether7",
                        Link::Down,
                        &["2001:db8:1234:5678:9abc:def0:1234:5678/64"],
                    ),
                    20 => port("ether20", Link::Up, &[]),
                    n => port(&format!("ether{n}"), Link::Off, &[]),
                })
                .collect(),
            web: Some(443),
            fingerprint: pem_fingerprint(CERT),
            no_password: true,
            health: vec![
                "NIC errors".into(),
                "Temperature".into(),
                "Config disk".into(),
            ],
        }
    }

    const CERT: &str =
        "junk\n-----BEGIN CERTIFICATE-----\naGVsbG8g\nd29ybGQ=\n-----END CERTIFICATE-----\n";

    #[test]
    fn a_port_is_picked_by_number_or_name_never_by_default() {
        let p = nics();
        assert_eq!(pick("2", &p).map(|x| x.name.as_str()), Some("ether2"));
        assert_eq!(
            pick(" ether1 ", &p).map(|x| x.name.as_str()),
            Some("ether1")
        );
        for bad in ["", "0", "3", "eth0", "-1"] {
            assert!(pick(bad, &p).is_none(), "{bad}");
        }
        assert_eq!(describe(&p[1]), "ether2 (link up, 52:54:00:00:00:02)");
        // A port that is off cannot tell whether a cable is in.
        assert_eq!(
            describe(&p[0]),
            "ether1 (port off, link unknown, 52:54:00:00:00:01)"
        );
        let t = nic_table(&p, true);
        check("nic table", &t);
        let t = style::render(&t, false);
        assert!(
            t.contains("  1  ether1           off    52:54:00:00:00:01"),
            "{t}"
        );
        assert!(
            t.contains("  2  ether2           up     52:54:00:00:00:02"),
            "{t}"
        );
        let t = style::render(&nic_table(&p, false), false);
        assert!(
            t.contains("\n   ether2           up     52:54:00:00:00:02"),
            "{t}"
        );
    }

    #[test]
    fn only_an_explicit_yes_confirms() {
        assert!(yes(Some("y")) && yes(Some("YES")));
        for a in [None, Some(""), Some("n"), Some("s"), Some("yy")] {
            assert!(!yes(a), "{a:?}");
        }
    }

    #[test]
    fn the_status_screen_fits_a_vga_text_screen_whatever_the_router_has() {
        let mut cases = vec![busy(), Snapshot::default()];
        // No web access, no certificate, an IPv6-only management address.
        let mut v6 = busy();
        v6.ports = vec![port(
            "ether1",
            Link::Up,
            &["2001:db8:1234:5678:9abc:def0:1234:5678/64"],
        )];
        v6.web = None;
        v6.fingerprint = None;
        cases.push(v6);
        // The same on a port other than 443, and hostile names everywhere.
        let mut odd = busy();
        odd.web = Some(8443);
        odd.machine = "M".repeat(300);
        odd.identity = "i".repeat(300);
        odd.health = vec!["h".repeat(300)];
        odd.ports
            .push(port(&"p".repeat(300), Link::Up, &[&"a".repeat(300)]));
        cases.push(odd.clone());
        for (n, s) in cases.iter().enumerate() {
            let t = screen(s);
            check(&format!("screen {n}"), &t);
            let rows = style::render(&t, false).lines().count();
            assert!(rows <= SCREEN_ROWS, "screen {n}: {rows} rows\n{t}");
        }
    }

    #[test]
    fn the_status_screen_says_who_where_and_what_needs_attention() {
        let t = style::render(&screen(&busy()), false);
        let has = |s: &str| assert!(t.contains(s), "{s:?} not in:\n{t}");
        has("CoreRouter 0.1.0-dev.553  border-1");
        has("QEMU Standard PC (Q35 + ICH9, 2009)");
        // The address of the first port with link, the web access first.
        has("  Web   https://10.0.2.15/  (user admin)");
        has("  GUI   corerouter-gui --connect tls://10.0.2.15:8729");
        has("  CLI   corerouter-cli --connect tls://10.0.2.15:8729 --user admin");
        has("  Cert  SHA256:");
        // Ports with an address first, then the ones with link; the rest is
        // counted.
        has("  ether1           up     10.0.2.15/24 (+2 more)");
        has("  ether7           down   2001:db8:1234:5678:9abc:def0:1234:5678/64");
        has("  ether20          up     -");
        has("more (all of them in the GUI: Interfaces)");
        has("  WARNING  live image, NOT INSTALLED");
        has("type i and Enter here");
        has("  WARNING  admin has no password");
        has("  WARNING  health: NIC errors, Temperature, Config disk");
        has("This console has no command shell.");
        // The colour only repeats what the words say.
        let lit = style::render(&screen(&busy()), true);
        assert!(lit.contains("\u{1b}[1;33mWARNING\u{1b}[0m"), "{lit}");
        assert!(
            lit.contains("\u{1b}[1;36mhttps://10.0.2.15/\u{1b}[0m"),
            "{lit}"
        );
        assert!(lit.contains("\u{1b}[32mup\u{1b}[0m"), "{lit}");
    }

    #[test]
    fn without_an_address_the_screen_invites_to_the_setup() {
        let s = Snapshot {
            version: "0.1.0".into(),
            ports: vec![
                port("ether1", Link::Off, &[]),
                port("ether2", Link::Off, &[]),
            ],
            no_password: true,
            ..Snapshot::default()
        };
        let t = screen(&s);
        check("no address", &t);
        let t = style::render(&t, false);
        assert!(t.contains("no port has a management address yet"), "{t}");
        assert!(t.contains("Press Enter to set the management port"), "{t}");
        assert!(t.contains("no command shell"), "{t}");
        assert!(t.contains("  ether1           off    -"), "{t}");
        assert!(t.contains("The setup asks for one."), "{t}");
        assert!(!t.contains("tls://"), "{t}");
        // An address on a port without link is still the way in; one with
        // link wins.
        let mut s = s;
        s.ports = vec![
            port("ether1", Link::Down, &["192.0.2.10/24"]),
            port("bridge1", Link::Up, &["2001:db8::1/64"]),
        ];
        assert_eq!(s.management(), Some("2001:db8::1/64"));
        let t = style::render(&screen(&s), false);
        assert!(t.contains("tls://[2001:db8::1]:8729"), "{t}");
        s.ports.truncate(1);
        assert_eq!(s.management(), Some("192.0.2.10/24"));
    }

    #[test]
    fn the_certificate_fingerprint_is_the_one_the_clients_show() {
        // SHA-256 of "hello world", the way `control::tls::fingerprint`
        // writes it.
        assert_eq!(
            pem_fingerprint(CERT).as_deref(),
            Some(
                "SHA256:B9:4D:27:B9:93:4D:3E:08:A5:2E:52:D7:DA:7D:AB:FA:C4:84:EF:E3:7A:53:80:EE:90:88:F7:AC:E2:EF:CD:E9"
            )
        );
        assert_eq!(base64("aGVsbG8"), Some(b"hello".to_vec()));
        assert_eq!(base64("aGVs bG8gd29y\nbGQ="), Some(b"hello world".to_vec()));
        for bad in [
            "",
            "no certificate here",
            "-----BEGIN CERTIFICATE-----\n!!!\n-----END",
        ] {
            assert_eq!(pem_fingerprint(bad), None, "{bad}");
        }
        assert_eq!(base64(&"A".repeat(200_000)), None);
        // Two lines of 16 bytes on the screen.
        let lines = reach("192.0.2.10/24", Some(443), pem_fingerprint(CERT).as_deref());
        let plain: Vec<String> = lines.iter().map(|l| style::render(l, false)).collect();
        assert_eq!(
            plain[3],
            "   Cert  SHA256:B9:4D:27:B9:93:4D:3E:08:A5:2E:52:D7:DA:7D:AB:FA:"
        );
        assert_eq!(
            plain[4],
            "         C4:84:EF:E3:7A:53:80:EE:90:88:F7:AC:E2:EF:CD:E9"
        );
    }

    #[test]
    fn the_machine_is_named_without_the_makers_placeholders() {
        assert_eq!(
            machine_name("QEMU", "Standard PC (Q35 + ICH9, 2009)"),
            "QEMU Standard PC (Q35 + ICH9, 2009)"
        );
        assert_eq!(machine_name("LENOVO", "20XW0055BR"), "LENOVO 20XW0055BR");
        assert_eq!(
            machine_name("Supermicro", "Supermicro X11"),
            "Supermicro X11"
        );
        assert_eq!(machine_name("To Be Filled By O.E.M.", "Default string"), "");
        assert_eq!(machine_name("System manufacturer", "B450M"), "B450M");
        assert_eq!(machine_name("", ""), "");
    }

    #[test]
    fn the_setup_texts_say_what_is_about_to_happen() {
        let m = Mgmt::parse("ether2,192.0.2.10/24,192.0.2.1").unwrap();
        let t = summary(&m, true);
        check("summary", &t);
        let t = style::render(&t, false);
        assert!(
            t.contains("  Port      ether2") && t.contains("  Gateway   192.0.2.1"),
            "{t}"
        );
        assert!(t.contains("  Admin     new password"), "{t}");
        // G0.3d: no password is a choice, and the text says what it means.
        let t = summary(&m, false);
        check("summary, no password", &t);
        let t = style::render(&t, false);
        assert!(t.contains("the empty one works from the network"), "{t}");
        assert!(!t.contains("refused"), "{t}");
        check("intro", &intro());
        let t = no_password_yet();
        check("no password yet", &t);
        assert!(t.contains("empty password") && t.contains("set one"));
        assert_eq!(host_of("2001:db8::1/64"), "[2001:db8::1]");
    }

    /// G1.30: a Wi-Fi port adds its network and country to the summary, and
    /// the radio is a port of the list like the others.
    #[test]
    fn a_wifi_port_in_the_list_and_in_the_summary() {
        let mut all = nics();
        all.push(Nic {
            name: "wifi1".into(),
            mac: "4c:79:6e:ab:cd:ef".into(),
            link: Link::Wifi,
        });
        let table = style::render(&nic_table(&all, true), false);
        assert!(
            table.contains("  3  wifi1            Wi-Fi  4c:79:6e:ab:cd:ef"),
            "{table}"
        );
        assert_eq!(pick("3", &all).map(|n| n.name.as_str()), Some("wifi1"));
        assert_eq!(describe(&all[2]), "wifi1 (Wi-Fi radio, 4c:79:6e:ab:cd:ef)");
        let t = style::render(
            &summary_rows(
                "wifi1",
                Some(("Casa (WPA2/WPA3, passphrase not shown)".into(), "BR".into())),
                "from DHCP, on the network joined",
                None,
                true,
            ),
            false,
        );
        let lines: Vec<&str> = t.lines().map(str::trim).collect();
        assert_eq!(
            lines.get(..5),
            Some(
                &[
                    "Port      wifi1",
                    "Network   Casa (WPA2/WPA3, passphrase not shown)",
                    "Country   BR",
                    "Address   from DHCP, on the network joined",
                    "Gateway   none",
                ][..]
            ),
            "{t}"
        );
    }
}
