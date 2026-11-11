//! Wi-Fi in station mode on Linux (G1.30): `wpa_supplicant` does the
//! joining, this drives it.
//!
//! Why a supplicant at all: on every driver of the image (iwlwifi, mt76,
//! rtw88, rtw89) the SAE exchange and the 4-way handshake run in user space
//! (mac80211 has `.auth` and `.assoc` only, `net/mac80211/cfg.c`), and
//! writing those is writing a supplicant (`docs/wifi.md`). What is ours is
//! everything around it: one process for all radios, started when the first
//! radio is opened, with no configuration file and no D-Bus; each radio added
//! through the global control socket (`INTERFACE_ADD` with an empty
//! configuration: the networks live in the supplicant's memory only) and
//! told its network through its own socket.
//!
//! The control protocol (`wpa_supplicant/ctrl_iface_unix.c`): a UNIX
//! datagram socket, one datagram per command and per reply, text. After
//! `ATTACH`, events arrive on the same socket between replies, so a radio
//! has two sockets, one for commands and one for events, as `wpa_cli` does.
//! A command over 8192 bytes gets no reply at all: commands are bounded
//! here and every wait has a deadline.
//!
//! The passphrase goes over that socket (`SET_NETWORK <id> psk "…"`), never
//! to a file; the supplicant zeroes the command buffer and prints
//! `[REMOVED]` in its debug log. It is never in an error message here.

use corerouter_hal::wifi::{
    BssSecurity, JoinSecurity, WifiBss, WifiEvent, WifiFailure, WifiNetwork, WifiState, WifiStatus,
};

/// The longest command sent (the supplicant drops one over 8192 bytes
/// without an answer).
pub(crate) const MAX_COMMAND: usize = 4096;
/// The longest SSID, bytes.
const MAX_SSID: usize = 32;

/// `aa\x20b` as the supplicant prints an SSID (`printf_encode`) → bytes.
fn unescape(text: &str) -> Vec<u8> {
    let b = text.as_bytes();
    let mut out = Vec::with_capacity(b.len().min(MAX_SSID));
    let mut i = 0;
    while let Some(&c) = b.get(i) {
        if out.len() >= MAX_SSID {
            break;
        }
        if c != b'\\' {
            out.push(c);
            i += 1;
            continue;
        }
        match b.get(i + 1) {
            Some(b'x') => {
                let hex = b
                    .get(i + 2..i + 4)
                    .and_then(|h| std::str::from_utf8(h).ok());
                match hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                    Some(v) => {
                        out.push(v);
                        i += 4;
                    }
                    None => {
                        out.push(c);
                        i += 1;
                    }
                }
            }
            Some(&e) => {
                out.push(match e {
                    b'n' => b'\n',
                    b'r' => b'\r',
                    b't' => b'\t',
                    b'e' => 0x1b,
                    other => other,
                });
                i += 2;
            }
            None => {
                out.push(c);
                i += 1;
            }
        }
    }
    out
}

/// An SSID for a table: what is not text is shown as `?`, never a control
/// character.
fn ssid_text(escaped: &str) -> String {
    String::from_utf8_lossy(&unescape(escaped))
        .chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

/// `key=value` lines of a reply.
fn field<'a>(reply: &'a str, key: &str) -> Option<&'a str> {
    reply.lines().find_map(|l| {
        let (k, v) = l.split_once('=')?;
        (k == key).then_some(v)
    })
}

/// A MAC as the supplicant prints it, checked.
fn mac(text: &str) -> Option<String> {
    let t = text.trim();
    let ok = t.len() == 17
        && t.bytes().enumerate().all(|(i, b)| {
            if i % 3 == 2 {
                b == b':'
            } else {
                b.is_ascii_hexdigit()
            }
        });
    ok.then(|| t.to_ascii_lowercase())
}

/// What a BSS's `flags=` (`[WPA2-PSK+SAE-CCMP][ESS]`) offer.
pub(crate) fn bss_security(flags: &str) -> BssSecurity {
    let (mut psk, mut sae, mut eap, mut owe, mut legacy) = (false, false, false, false, false);
    for token in flags.split(['[', ']']).filter(|t| !t.is_empty()) {
        if token == "WEP" {
            legacy = true;
        } else if let Some(rest) = token
            .strip_prefix("WPA2-")
            .or_else(|| token.strip_prefix("RSN-"))
        {
            eap |= rest.contains("EAP") || rest.contains("802.1X");
            sae |= rest.contains("SAE");
            psk |= rest.contains("PSK");
            owe |= rest.contains("OWE");
        } else if token.starts_with("WPA-") {
            // WPA1: TKIP.
            legacy = true;
        }
    }
    match (psk, sae, eap, owe, legacy) {
        (true, true, ..) => BssSecurity::Wpa2Wpa3,
        (false, true, ..) => BssSecurity::Wpa3,
        (true, false, ..) => BssSecurity::Wpa2,
        (false, false, true, ..) => BssSecurity::Enterprise,
        (false, false, false, true, _) => BssSecurity::Owe,
        (false, false, false, false, true) => BssSecurity::Legacy,
        (false, false, false, false, false) => BssSecurity::Open,
    }
}

/// One reply to `BSS <n>`; `None`: no such entry (the end of the list).
pub(crate) fn parse_bss(reply: &str) -> Option<WifiBss> {
    let bssid = mac(field(reply, "bssid")?)?;
    let frequency_mhz = field(reply, "freq")?.trim().parse::<u32>().ok()?;
    let signal_dbm = field(reply, "level")
        .and_then(|l| l.trim().parse::<i32>().ok())
        .unwrap_or(-100)
        .clamp(-120, 0);
    Some(WifiBss {
        ssid: field(reply, "ssid").map(ssid_text).unwrap_or_default(),
        bssid,
        frequency_mhz,
        signal_dbm,
        security: bss_security(field(reply, "flags").unwrap_or("")),
    })
}

/// A reply to `STATUS`, and to `SIGNAL_POLL` when there is a link.
pub(crate) fn parse_status(status: &str, signal: Option<&str>) -> WifiStatus {
    let state = match field(status, "wpa_state").unwrap_or("") {
        "COMPLETED" => WifiState::Connected,
        "AUTHENTICATING" | "ASSOCIATING" | "ASSOCIATED" | "4WAY_HANDSHAKE" | "GROUP_HANDSHAKE" => {
            WifiState::Connecting
        }
        "SCANNING" | "DISCONNECTED" => WifiState::Searching,
        "INTERFACE_DISABLED" => WifiState::Blocked,
        _ => WifiState::Idle,
    };
    let on = state == WifiState::Connected;
    let number = |text: Option<&str>| text.and_then(|t| t.trim().parse::<i32>().ok());
    let key_mgmt = field(status, "key_mgmt").map(str::trim);
    WifiStatus {
        state,
        ssid: field(status, "ssid")
            .map(ssid_text)
            .filter(|s| !s.is_empty()),
        bssid: field(status, "bssid").and_then(mac).filter(|_| on),
        frequency_mhz: field(status, "freq")
            .and_then(|f| f.trim().parse().ok())
            .filter(|_| on),
        signal_dbm: signal
            .and_then(|s| number(field(s, "RSSI")))
            .map(|v| v.clamp(-120, 0))
            .filter(|_| on),
        rate_mbps: signal
            .and_then(|s| number(field(s, "LINKSPEED")))
            .and_then(|v| u32::try_from(v).ok())
            .filter(|_| on),
        security: key_mgmt.filter(|_| on).map(|k| {
            if k.contains("SAE") {
                "wpa3".to_owned()
            } else if k.contains("PSK") {
                "wpa2".to_owned()
            } else if k == "NONE" {
                "open".to_owned()
            } else {
                k.chars().take(24).collect::<String>().to_ascii_lowercase()
            }
        }),
        pmf: field(status, "pmf")
            .map(|p| matches!(p.trim(), "1" | "2"))
            .or(on.then_some(false)),
    }
}

/// `key=value` of an event line (`reason=3 locally_generated=1`).
fn event_field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    line.split_ascii_whitespace().find_map(|w| {
        let (k, v) = w.split_once('=')?;
        (k == key).then_some(v)
    })
}

/// IEEE 802.11 reason codes (Table 9-49), the ones a station meets.
fn reason_text(code: u32, local: bool) -> String {
    let what = match code {
        2 => "the previous authentication is no longer valid",
        3 if local => "left",
        3 => "the access point sent it away (deauthenticated)",
        4 => "no activity for too long",
        5 => "the access point is too busy",
        6 | 7 => "the access point lost this station's state",
        8 => "the access point dissociated it",
        15 => "the key exchange timed out",
        16 => "the group key update timed out",
        23 => "802.1X authentication failed",
        34 => "too many frames lost (poor signal)",
        _ => "",
    };
    match (what.is_empty(), local) {
        (true, true) => format!("left (reason {code})"),
        (true, false) => format!("the access point ended it (reason {code})"),
        (false, _) => format!("{what} (reason {code})"),
    }
}

/// IEEE 802.11 status codes (Table 9-50) an access point refuses with.
fn status_text(code: u32) -> String {
    let what = match code {
        1 => "unspecified failure",
        10 => "it does not accept this station's capabilities",
        12 => "association denied",
        17 => "it cannot take more stations",
        18 => "this station supports none of its required rates",
        30 => "try again later",
        31 => "its management frame protection policy forbids it",
        40..=46 => "it does not accept the security this station offered",
        53 => "the cached key is not valid any more",
        77 => "it does not accept the SAE group",
        _ => "",
    };
    if what.is_empty() {
        format!("status {code}")
    } else {
        format!("{what} (status {code})")
    }
}

/// One unsolicited line of the supplicant → what the engine is told.
/// `None`: nothing it needs.
pub(crate) fn parse_event(line: &str) -> Option<WifiEvent> {
    // `<3>CTRL-EVENT-…`: the priority is not needed.
    let line = line.trim();
    let line = match line.strip_prefix('<') {
        Some(rest) => rest.split_once('>').map_or(line, |(_, l)| l),
        None => line,
    };
    let (name, rest) = line.split_once(' ').unwrap_or((line, ""));
    let code = |key: &str| event_field(rest, key).and_then(|v| v.parse::<u32>().ok());
    match name {
        "CTRL-EVENT-CONNECTED" => {
            // "- Connection to aa:bb:cc:dd:ee:ff completed [id=0 id_str=]"
            let bssid = rest
                .split_ascii_whitespace()
                .find_map(mac)
                .unwrap_or_default();
            Some(WifiEvent::Connected { bssid })
        }
        "CTRL-EVENT-DISCONNECTED" => {
            let local = event_field(rest, "locally_generated") == Some("1");
            Some(WifiEvent::Disconnected {
                reason: reason_text(code("reason").unwrap_or(0), local),
            })
        }
        "CTRL-EVENT-SSID-TEMP-DISABLED" => {
            Some(WifiEvent::Failed(match event_field(rest, "reason") {
                Some("WRONG_KEY") => WifiFailure::WrongKey,
                Some("CONN_FAILED") => WifiFailure::NoAnswer,
                Some("AUTH_FAILED") => WifiFailure::Rejected("authentication failed".into()),
                Some("NO_PSK_AVAILABLE") => {
                    WifiFailure::Other("the network needs a passphrase and none is set".into())
                }
                other => WifiFailure::Other(format!(
                    "the supplicant gave the network up for now ({})",
                    other
                        .unwrap_or("no reason")
                        .chars()
                        .take(32)
                        .collect::<String>()
                )),
            }))
        }
        "CTRL-EVENT-NETWORK-NOT-FOUND" => Some(WifiEvent::Failed(WifiFailure::NotFound)),
        "CTRL-EVENT-AUTH-REJECT" => {
            let status = code("status_code").unwrap_or(1);
            // SAE: the access point could not verify the confirm, which is
            // what a wrong passphrase looks like (hostapd answers 15, others 1).
            let sae = event_field(rest, "auth_type") == Some("3");
            Some(WifiEvent::Failed(if sae && matches!(status, 1 | 15) {
                WifiFailure::WrongKey
            } else {
                WifiFailure::Rejected(status_text(status))
            }))
        }
        "CTRL-EVENT-ASSOC-REJECT" => Some(WifiEvent::Failed(WifiFailure::Rejected(status_text(
            code("status_code").unwrap_or(1),
        )))),
        "CTRL-EVENT-SCAN-RESULTS" => Some(WifiEvent::ScanDone),
        "CTRL-EVENT-SCAN-FAILED" => Some(WifiEvent::ScanFailed(format!(
            "the driver refused the scan ({})",
            event_field(rest, "ret")
                .unwrap_or("?")
                .chars()
                .take(8)
                .collect::<String>()
        ))),
        "CTRL-EVENT-REGDOM-CHANGE" => {
            let alpha2 = event_field(rest, "alpha2")
                .filter(|a| a.len() == 2 && a.bytes().all(|b| b.is_ascii_uppercase()))
                .map(str::to_owned);
            Some(WifiEvent::Country(alpha2))
        }
        _ => None,
    }
}

/// The frequencies of a band as `freq_list` takes them: every 5 MHz.
fn freq_list((lo, hi): (u32, u32)) -> String {
    let lo = lo.max(2400);
    let hi = hi.min(7200);
    (lo..=hi)
        .step_by(5)
        .map(|f| f.to_string())
        .collect::<Vec<_>>()
        .join(" ")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A quoted string of the supplicant's configuration syntax: it ends at the
/// last `"` of the value, so what is inside needs no escaping, but a line
/// break would end the command.
fn quoted(text: &str) -> Option<String> {
    (!text.chars().any(char::is_control)).then(|| format!("\"{text}\""))
}

/// The `SET_NETWORK` lines of `net`, as `(field, value)`; the fields named
/// in [`SECRET_FIELDS`] carry the key. `None`: something in it cannot be
/// written in the supplicant's syntax.
pub(crate) fn network_fields(net: &WifiNetwork) -> Option<Vec<(&'static str, String)>> {
    if net.ssid.is_empty() || net.ssid.len() > MAX_SSID {
        return None;
    }
    // Hex, not quoted: any byte of a name is safe that way.
    let mut out = vec![("ssid", hex(net.ssid.as_bytes()))];
    if net.hidden {
        out.push(("scan_ssid", "1".into()));
    }
    let raw_key = net.key.len() == 64 && net.key.bytes().all(|b| b.is_ascii_hexdigit());
    let psk = || {
        if raw_key {
            Some(net.key.clone())
        } else {
            quoted(&net.key)
        }
    };
    match net.security {
        JoinSecurity::Open => out.push(("key_mgmt", "NONE".into())),
        JoinSecurity::Wpa2 => {
            out.push(("key_mgmt", "WPA-PSK WPA-PSK-SHA256".into()));
            out.push(("psk", psk()?));
            out.push(("ieee80211w", "1".into()));
        }
        JoinSecurity::Wpa3 => {
            if raw_key {
                return None;
            }
            out.push(("key_mgmt", "SAE".into()));
            out.push(("sae_password", quoted(&net.key)?));
            out.push(("ieee80211w", "2".into()));
        }
        JoinSecurity::Auto => {
            if raw_key {
                return None;
            }
            // SAE first; with no `sae_password` the supplicant uses the
            // passphrase of `psk` for it.
            out.push(("key_mgmt", "SAE WPA-PSK WPA-PSK-SHA256".into()));
            out.push(("psk", quoted(&net.key)?));
            out.push(("ieee80211w", "1".into()));
        }
    }
    if net.security != JoinSecurity::Open {
        // RSN only (no WPA1), and never TKIP for this station's own frames.
        out.push(("proto", "RSN".into()));
        out.push(("pairwise", "CCMP GCMP CCMP-256 GCMP-256".into()));
    }
    if let Some(b) = net.bssid.as_deref().and_then(mac) {
        out.push(("bssid", b));
    }
    if let Some(band) = net.band_mhz {
        let list = freq_list(band);
        out.push(("scan_freq", list.clone()));
        out.push(("freq_list", list));
    }
    Some(out)
}

/// The fields whose value is the key: never in a message.
pub(crate) const SECRET_FIELDS: [&str; 2] = ["psk", "sae_password"];

#[cfg(target_os = "linux")]
pub use io::{LinuxWifiPort, radio, regdomain, set_country};

#[cfg(target_os = "linux")]
mod io {
    use std::os::unix::net::UnixDatagram;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    use corerouter_hal::HalError;
    use corerouter_hal::wifi::{
        MAX_EVENTS, MAX_SCAN_RESULTS, WifiBss, WifiEvent, WifiNetwork, WifiPort, WifiRadio,
        WifiState, WifiStatus,
    };
    use corerouter_model::IfName;

    use super::{MAX_COMMAND, SECRET_FIELDS, network_fields, parse_bss, parse_event, parse_status};
    use crate::genl::{Genl, Msg};

    /// A reply slower than this is a supplicant that hangs: the radio is
    /// given up and opened again later. Local replies take 10 to 200 µs.
    const REPLY_TIMEOUT: Duration = Duration::from_millis(300);
    /// How long a supplicant just started gets to open its socket.
    const START_TIMEOUT: Duration = Duration::from_secs(2);
    /// The supplicant's reply buffer is 4096 bytes; a little more.
    const MAX_REPLY: usize = 8192;
    const DEFAULT_BINARY: &str = "/usr/sbin/wpa_supplicant";
    /// `sun_path` is 108 bytes.
    const MAX_SOCKET_PATH: usize = 100;

    const NL80211_FAMILY: &str = "nl80211";
    const NL80211_CMD_REQ_SET_REG: u8 = 27;
    const NL80211_CMD_GET_REG: u8 = 31;
    const NL80211_ATTR_REG_ALPHA2: u16 = 33;
    /// cfg80211 in the kernel (see `crate::wifi_links`).
    const CFG80211: &str = "/sys/module/cfg80211";

    static CLIENT: AtomicU64 = AtomicU64::new(0);

    fn io_err(what: &str, e: impl std::fmt::Display) -> HalError {
        HalError::Io(format!("wpa_supplicant: {what}: {e}"))
    }

    /// Where the supplicant's sockets live: `<runtime>/wpa`, ours alone.
    fn dir() -> Result<PathBuf, HalError> {
        let base = std::env::var_os("COREROUTER_RUNTIME_DIR")
            .filter(|d| !d.is_empty())
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("XDG_RUNTIME_DIR")
                    .filter(|d| !d.is_empty())
                    .map(|d| PathBuf::from(d).join("corerouter"))
            })
            .unwrap_or_else(|| PathBuf::from("/run/corerouter"));
        let dir = base.join("wpa");
        if dir.as_os_str().len() > MAX_SOCKET_PATH - 32 {
            return Err(HalError::Io(format!(
                "the runtime directory {} is too long for a socket path",
                dir.display()
            )));
        }
        std::fs::create_dir_all(dir.join("if")).map_err(|e| io_err("runtime directory", e))?;
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
        Ok(dir)
    }

    fn binary() -> PathBuf {
        std::env::var_os("COREROUTER_WPA_SUPPLICANT")
            .filter(|b| !b.is_empty())
            .map_or_else(|| PathBuf::from(DEFAULT_BINARY), PathBuf::from)
    }

    /// One client socket of a control interface.
    struct Ctrl {
        sock: UnixDatagram,
        local: PathBuf,
    }

    impl Ctrl {
        fn connect(dir: &Path, server: &Path) -> std::io::Result<Self> {
            let n = CLIENT.fetch_add(1, Ordering::Relaxed);
            let local = dir.join(format!("c{}-{n}", std::process::id()));
            let _ = std::fs::remove_file(&local);
            let sock = UnixDatagram::bind(&local)?;
            let made = Self { sock, local };
            made.sock.connect(server)?;
            made.sock.set_read_timeout(Some(REPLY_TIMEOUT))?;
            made.sock.set_write_timeout(Some(REPLY_TIMEOUT))?;
            Ok(made)
        }

        /// One command, one reply. `what` names it in an error (a command
        /// with a key in it is never shown).
        fn request(&self, command: &str, what: &str) -> Result<String, HalError> {
            if command.len() > MAX_COMMAND {
                return Err(HalError::Rejected(format!(
                    "wpa_supplicant: {what}: too long"
                )));
            }
            self.sock
                .send(command.as_bytes())
                .map_err(|e| io_err(what, e))?;
            let deadline = Instant::now() + REPLY_TIMEOUT;
            let mut buf = vec![0u8; MAX_REPLY];
            loop {
                let n = self.sock.recv(&mut buf).map_err(|e| io_err(what, e))?;
                let reply = String::from_utf8_lossy(buf.get(..n).unwrap_or_default());
                // An event that slipped in (a socket that is attached).
                if reply.starts_with('<') {
                    if Instant::now() >= deadline {
                        return Err(io_err(what, "no reply"));
                    }
                    continue;
                }
                return Ok(reply.into_owned());
            }
        }

        /// A command whose reply is `OK`.
        fn ok(&self, command: &str, what: &str) -> Result<(), HalError> {
            let r = self.request(command, what)?;
            if r.trim() == "OK" {
                Ok(())
            } else {
                Err(HalError::Rejected(format!(
                    "wpa_supplicant refused {what} ({})",
                    r.trim().chars().take(32).collect::<String>()
                )))
            }
        }

        /// What arrived without being asked for, without waiting.
        fn pending(&self, max: usize) -> Vec<String> {
            let mut out = Vec::new();
            if self.sock.set_nonblocking(true).is_err() {
                return out;
            }
            let mut buf = vec![0u8; MAX_REPLY];
            while out.len() < max {
                match self.sock.recv(&mut buf) {
                    Ok(n) => out.push(
                        String::from_utf8_lossy(buf.get(..n).unwrap_or_default()).into_owned(),
                    ),
                    Err(_) => break,
                }
            }
            let _ = self.sock.set_nonblocking(false);
            out
        }
    }

    impl Drop for Ctrl {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.local);
        }
    }

    /// The global control socket, with the supplicant started if it is not
    /// there (or does not answer).
    fn global(dir: &Path, bin: &Path) -> Result<Ctrl, HalError> {
        let sock = dir.join("global");
        let ping = |c: &Ctrl| c.request("PING", "PING").is_ok_and(|r| r.trim() == "PONG");
        if let Ok(c) = Ctrl::connect(dir, &sock)
            && ping(&c)
        {
            return Ok(c);
        }
        // A socket nobody answers on is a dead one's.
        let _ = std::fs::remove_file(&sock);
        // `-B`: it forks and the process started here ends at once; the
        // supplicant itself is PID 1's child from then on, and outlives a
        // restart of this daemon with the radio still on its network.
        let status = Command::new(bin)
            .arg("-B")
            .arg("-g")
            .arg(&sock)
            .arg("-P")
            .arg(dir.join("wpa_supplicant.pid"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|e| HalError::Io(format!("cannot start {}: {e}", bin.display())))?;
        if !status.success() {
            return Err(HalError::Io(format!(
                "{} did not start: {status}",
                bin.display()
            )));
        }
        let deadline = Instant::now() + START_TIMEOUT;
        loop {
            if let Ok(c) = Ctrl::connect(dir, &sock)
                && ping(&c)
            {
                return Ok(c);
            }
            if Instant::now() >= deadline {
                return Err(HalError::Io(format!(
                    "{} started and does not answer on {}",
                    bin.display(),
                    sock.display()
                )));
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Lift the soft block of the radio behind `name` (the airplane-mode
    /// key, a state the firmware kept): an interface the configuration has
    /// enabled is meant to be on. A hard block (a switch) cannot be lifted.
    fn unblock(name: &str) {
        let phy = Path::new("/sys/class/net").join(name).join("phy80211");
        let Ok(dir) = std::fs::read_dir(&phy) else {
            return;
        };
        for e in dir.flatten() {
            if e.file_name().to_string_lossy().starts_with("rfkill") {
                let _ = std::fs::write(e.path().join("soft"), "0");
            }
        }
    }

    /// One radio, through its own control socket.
    pub struct LinuxWifiPort {
        name: String,
        dir: PathBuf,
        cmd: Ctrl,
        events: Ctrl,
        queued: Vec<WifiEvent>,
        blocked: bool,
    }

    impl LinuxWifiPort {
        pub fn open(name: &IfName) -> Result<Self, HalError> {
            Self::open_at(name, dir()?, &binary())
        }

        /// [`open`](Self::open) with the sockets' directory and the
        /// supplicant's binary given.
        fn open_at(name: &IfName, dir: PathBuf, binary: &Path) -> Result<Self, HalError> {
            let global = global(&dir, binary)?;
            let ifaces = dir.join("if");
            let known = global.request("INTERFACES", "INTERFACES")?;
            if !known.lines().any(|l| l.trim() == name.as_str()) {
                // <ifname> TAB <config file: none> TAB <driver> TAB <ctrl dir>
                global.ok(
                    &format!("INTERFACE_ADD {name}\t\tnl80211\t{}", ifaces.display()),
                    "the radio (INTERFACE_ADD)",
                )?;
            }
            unblock(name.as_str());
            let sock = ifaces.join(name.as_str());
            let cmd = Ctrl::connect(&dir, &sock).map_err(|e| io_err("the radio's socket", e))?;
            let events = Ctrl::connect(&dir, &sock).map_err(|e| io_err("the radio's socket", e))?;
            events.ok("ATTACH", "ATTACH")?;
            // Management frame protection where the access point has it, and
            // both ways of deriving the SAE password element (H2E is what
            // 6 GHz and WPA3-only networks ask for).
            for (set, what) in [("SET pmf 1", "pmf"), ("SET sae_pwe 2", "sae_pwe")] {
                cmd.ok(set, what)?;
            }
            Ok(Self {
                name: name.to_string(),
                dir,
                cmd,
                events,
                queued: Vec::new(),
                blocked: false,
            })
        }

        fn forget_networks(&self) -> Result<(), HalError> {
            self.cmd.ok("REMOVE_NETWORK all", "REMOVE_NETWORK")
        }
    }

    impl WifiPort for LinuxWifiPort {
        fn join(&mut self, net: &WifiNetwork) -> Result<(), HalError> {
            let fields = network_fields(net).ok_or_else(|| {
                HalError::Rejected("the network cannot be written for wpa_supplicant".into())
            })?;
            self.forget_networks()?;
            let id = self.cmd.request("ADD_NETWORK", "ADD_NETWORK")?;
            let id: u32 = id
                .trim()
                .parse()
                .map_err(|_| HalError::Rejected("wpa_supplicant refused a new network".into()))?;
            for (field, value) in fields {
                // The key is in the command and nowhere else.
                let what = if SECRET_FIELDS.contains(&field) {
                    "the passphrase"
                } else {
                    field
                };
                self.cmd
                    .ok(&format!("SET_NETWORK {id} {field} {value}"), what)?;
            }
            unblock(&self.name);
            self.cmd
                .ok(&format!("SELECT_NETWORK {id}"), "SELECT_NETWORK")
        }

        fn leave(&mut self) -> Result<(), HalError> {
            self.forget_networks()?;
            // `FAIL` when it is not connected: nothing to leave.
            let _ = self.cmd.request("DISCONNECT", "DISCONNECT")?;
            Ok(())
        }

        fn scan(&mut self) -> Result<(), HalError> {
            let r = self.cmd.request("SCAN", "SCAN")?;
            match r.trim() {
                // One is running already: its end is the answer.
                "OK" | "FAIL-BUSY" => Ok(()),
                other => Err(HalError::Rejected(format!(
                    "the scan was refused ({})",
                    other.chars().take(32).collect::<String>()
                ))),
            }
        }

        fn scan_results(&mut self) -> Result<Vec<WifiBss>, HalError> {
            // `SCAN_RESULTS` is cut at the reply buffer (some 40 lines);
            // one `BSS <n>` per entry is not.
            let mut out = Vec::new();
            for n in 0..MAX_SCAN_RESULTS {
                let r = self.cmd.request(&format!("BSS {n}"), "BSS")?;
                match parse_bss(&r) {
                    Some(b) => out.push(b),
                    None => break,
                }
            }
            out.sort_by_key(|b| std::cmp::Reverse(b.signal_dbm));
            Ok(out)
        }

        fn status(&mut self) -> Result<WifiStatus, HalError> {
            let status = self.cmd.request("STATUS", "STATUS")?;
            let connected = status.lines().any(|l| l == "wpa_state=COMPLETED");
            let signal = if connected {
                self.cmd.request("SIGNAL_POLL", "SIGNAL_POLL").ok()
            } else {
                None
            };
            let st = parse_status(&status, signal.as_deref());
            let blocked = st.state == WifiState::Blocked;
            if blocked != self.blocked {
                self.blocked = blocked;
                if self.queued.len() < MAX_EVENTS {
                    self.queued.push(WifiEvent::Blocked(blocked));
                }
            }
            Ok(st)
        }

        fn events(&mut self) -> Vec<WifiEvent> {
            let mut out = std::mem::take(&mut self.queued);
            let room = MAX_EVENTS.saturating_sub(out.len());
            out.extend(
                self.events
                    .pending(room)
                    .iter()
                    .filter_map(|l| parse_event(l)),
            );
            out
        }
    }

    impl Drop for LinuxWifiPort {
        /// The radio leaves the supplicant, and the supplicant ends with
        /// its last radio. Not at a daemon's exit (nothing is dropped
        /// then): the radio stays on its network across a restart.
        fn drop(&mut self) {
            let Ok(global) = Ctrl::connect(&self.dir, &self.dir.join("global")) else {
                return;
            };
            let _ = global.request(
                &format!("INTERFACE_REMOVE {}", self.name),
                "INTERFACE_REMOVE",
            );
            if global
                .request("INTERFACES", "INTERFACES")
                .is_ok_and(|l| l.trim().is_empty())
            {
                let _ = global.request("TERMINATE", "TERMINATE");
            }
        }
    }

    /// Ask the kernel for the regulatory domain of `country` (`None`: the
    /// world domain, `00`). A user hint (`NL80211_CMD_REQ_SET_REG`): the
    /// kernel looks it up in the signed `regulatory.db` and applies it to
    /// every radio that is not self-managed.
    pub fn set_country(country: Option<&str>) -> Result<(), HalError> {
        let alpha2 = country.unwrap_or("00");
        let ok = alpha2.len() == 2 && alpha2.bytes().all(|b| b.is_ascii_uppercase() || b == b'0');
        if !ok {
            return Err(HalError::Rejected(format!(
                "'{}' is not a regulatory domain",
                alpha2.chars().take(8).collect::<String>()
            )));
        }
        // See `crate::wifi_links`: asking for the family by name would make
        // the kernel load cfg80211 on a machine with no radio.
        if !Path::new(CFG80211).exists() {
            return Err(HalError::Unsupported(
                "the kernel's Wi-Fi stack is not loaded (no radio in this machine)".into(),
            ));
        }
        let fail =
            |e: crate::genl::GenlError| HalError::Io(format!("regulatory domain {alpha2}: {e}"));
        let mut genl = Genl::open().map_err(fail)?;
        let family = genl.family(NL80211_FAMILY).map_err(fail)?;
        let seq = genl.next_seq();
        let mut m = Msg::new(family, NL80211_CMD_REQ_SET_REG, 0, seq);
        m.str(NL80211_ATTR_REG_ALPHA2, alpha2);
        genl.call(m.finish(), seq).map(|_| ()).map_err(fail)
    }

    /// The regulatory domain the kernel applies now (`NL80211_CMD_GET_REG`
    /// with no radio named: the global one). Asked of the kernel and not
    /// taken from the supplicant's events: the country is set before any
    /// radio is on, when nobody is listening for the change.
    pub fn regdomain() -> Option<String> {
        if !Path::new(CFG80211).exists() {
            return None;
        }
        let mut genl = Genl::open().ok()?;
        let family = genl.family(NL80211_FAMILY).ok()?;
        let seq = genl.next_seq();
        let m = Msg::new(family, NL80211_CMD_GET_REG, 0, seq);
        let reply = genl.call(m.finish(), seq).ok()?;
        reply
            .iter()
            .find_map(|(_, a)| {
                crate::genl::find(crate::genl::attrs(a), NL80211_ATTR_REG_ALPHA2)?.str()
            })
            .filter(|a| a.len() == 2 && a.bytes().all(|b| b.is_ascii_uppercase() || b == b'0'))
    }

    /// The drivers whose card keeps its own regulatory domain
    /// (`REGULATORY_WIPHY_SELF_MANAGED`: iwlmvm and iwlmld, ath11k, ath12k
    /// in Linux 6.18): a country hint does not move them.
    const SELF_MANAGED: [&str; 3] = ["iwlwifi", "ath11k", "ath12k"];

    /// What sysfs says about the radio behind `name`.
    pub fn radio(name: &IfName) -> Option<WifiRadio> {
        let dev = Path::new("/sys/class/net").join(name.as_str());
        if !dev.join("phy80211").exists() {
            return None;
        }
        let driver = std::fs::read_link(dev.join("device/driver"))
            .ok()
            .and_then(|l| l.file_name().map(|f| f.to_string_lossy().into_owned()))
            .map(|d| d.chars().take(32).collect::<String>());
        let self_managed = driver
            .as_deref()
            .is_some_and(|d| SELF_MANAGED.iter().any(|s| d.starts_with(s)));
        Some(WifiRadio {
            driver,
            self_managed,
        })
    }

    #[cfg(test)]
    mod tests {
        use std::sync::mpsc;

        use corerouter_hal::wifi::{JoinSecurity, WifiFailure};

        use super::*;

        /// A stand-in for the supplicant: the global socket and one radio's,
        /// answering what the real one answers, and telling the test every
        /// command it got.
        fn fake(dir: &Path, radio: &str) -> mpsc::Receiver<String> {
            std::fs::create_dir_all(dir.join("if")).unwrap();
            let global = UnixDatagram::bind(dir.join("global")).unwrap();
            let iface = UnixDatagram::bind(dir.join("if").join(radio)).unwrap();
            let (tx, rx) = mpsc::channel();
            let radio = radio.to_owned();
            for (sock, is_global) in [(global, true), (iface, false)] {
                let tx = tx.clone();
                let radio = radio.clone();
                std::thread::Builder::new()
                    .name("fake-wpa".into())
                    .spawn(move || {
                        let mut buf = vec![0u8; 8192];
                        let mut monitor: Option<PathBuf> = None;
                        let mut added = false;
                        while let Ok((n, from)) = sock.recv_from(&mut buf) {
                            let cmd = String::from_utf8_lossy(&buf[..n]).into_owned();
                            let Some(from) = from.as_pathname().map(Path::to_path_buf) else {
                                continue;
                            };
                            if tx.send(cmd.clone()).is_err() {
                                break;
                            }
                            let word = cmd.split([' ', '\t']).next().unwrap_or("");
                            let reply: String = match (is_global, word) {
                                (_, "PING") => "PONG\n".into(),
                                (true, "INTERFACES") if added => format!("{radio}\n"),
                                (true, "INTERFACES") => String::new(),
                                (true, "INTERFACE_ADD") => {
                                    added = true;
                                    "OK\n".into()
                                }
                                (true, "INTERFACE_REMOVE") => {
                                    added = false;
                                    "OK\n".into()
                                }
                                (false, "ATTACH") => {
                                    monitor = Some(from.clone());
                                    "OK\n".into()
                                }
                                (false, "ADD_NETWORK") => "0\n".into(),
                                (false, "STATUS") => "wpa_state=COMPLETED\nbssid=d8:47:32:aa:bb:cc\nfreq=5220\nssid=Casa\nkey_mgmt=SAE\npmf=2\n".into(),
                                (false, "SIGNAL_POLL") => "RSSI=-52\nLINKSPEED=866\n".into(),
                                (false, "BSS") if cmd == "BSS 0" => "bssid=d8:47:32:aa:bb:cc\nfreq=5220\nlevel=-52\nflags=[WPA2-SAE-CCMP]\nssid=Casa\n".into(),
                                (false, "BSS") => String::new(),
                                (false, "SET_NETWORK") if cmd.contains(" bssid ") => "FAIL\n".into(),
                                (false, "SELECT_NETWORK") => {
                                    // Events reach the socket that attached.
                                    if let Some(m) = &monitor {
                                        for e in [
                                            "<3>CTRL-EVENT-SCAN-STARTED ",
                                            "<3>CTRL-EVENT-SSID-TEMP-DISABLED id=0 ssid=\"Casa\" auth_failures=1 duration=10 reason=WRONG_KEY",
                                        ] {
                                            let _ = sock.send_to(e.as_bytes(), m);
                                        }
                                    }
                                    "OK\n".into()
                                }
                                _ => "OK\n".into(),
                            };
                            let _ = sock.send_to(reply.as_bytes(), &from);
                        }
                    })
                    .unwrap();
            }
            rx
        }

        fn temp(tag: &str) -> PathBuf {
            let d = std::env::temp_dir().join(format!("cr-wpa-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d).unwrap();
            d
        }

        #[test]
        fn a_radio_is_told_its_network_and_the_key_is_in_one_command_only() {
            let dir = temp("join");
            let seen = fake(&dir, "wlan7");
            let name: IfName = "wlan7".parse().unwrap();
            // The supplicant answers already: nothing is started.
            let mut port =
                LinuxWifiPort::open_at(&name, dir.clone(), Path::new("/nonexistent/wpa")).unwrap();
            let opened: Vec<String> = seen.try_iter().collect();
            assert!(
                opened
                    .iter()
                    .any(|c| c.starts_with("INTERFACE_ADD wlan7\t\tnl80211\t")),
                "{opened:?}"
            );
            assert!(
                opened.iter().any(|c| c == "ATTACH") && opened.iter().any(|c| c == "SET pmf 1")
            );

            let key = "a-passphrase-nobody-sees";
            let net = WifiNetwork {
                ssid: "Casa".into(),
                security: JoinSecurity::Auto,
                key: key.into(),
                hidden: true,
                band_mhz: Some((5150, 5895)),
                bssid: None,
            };
            port.join(&net).unwrap();
            let sent: Vec<String> = seen.try_iter().collect();
            assert_eq!(sent.first().map(String::as_str), Some("REMOVE_NETWORK all"));
            assert_eq!(sent.last().map(String::as_str), Some("SELECT_NETWORK 0"));
            assert!(
                sent.iter().any(|c| c == "SET_NETWORK 0 ssid 43617361"),
                "{sent:?}"
            );
            assert!(sent.iter().any(|c| c == "SET_NETWORK 0 scan_ssid 1"));
            let with_key: Vec<&String> = sent.iter().filter(|c| c.contains(key)).collect();
            assert_eq!(with_key.len(), 1, "{sent:?}");
            assert_eq!(*with_key[0], format!("SET_NETWORK 0 psk \"{key}\""));
            assert!(sent.iter().all(|c| c.len() <= MAX_COMMAND));

            // What the supplicant said meanwhile, in the engine's words.
            assert_eq!(port.events(), [WifiEvent::Failed(WifiFailure::WrongKey)]);
            assert!(port.events().is_empty());
            let st = port.status().unwrap();
            assert_eq!(
                (st.state, st.signal_dbm, st.rate_mbps),
                (WifiState::Connected, Some(-52), Some(866))
            );
            port.scan().unwrap();
            let heard = port.scan_results().unwrap();
            assert_eq!(heard.len(), 1);
            assert_eq!(heard[0].ssid, "Casa");

            // A field the supplicant refuses: the error names the field,
            // and a refused passphrase would say "the passphrase", not it.
            let mut pinned = net.clone();
            pinned.bssid = Some("d8:47:32:aa:bb:cc".into());
            let e = port.join(&pinned).unwrap_err().to_string();
            assert!(e.contains("refused bssid") && !e.contains(key), "{e}");
            port.leave().unwrap();
            assert!(seen.try_iter().any(|c| c == "DISCONNECT"));

            // Dropped, the radio leaves the supplicant, which is told to end
            // when it was the last one.
            drop(port);
            let end: Vec<String> = seen.try_iter().collect();
            assert!(end.iter().any(|c| c == "INTERFACE_REMOVE wlan7"), "{end:?}");
            assert_eq!(end.last().map(String::as_str), Some("TERMINATE"));
            // Its client sockets are gone from the directory.
            let left: Vec<String> = std::fs::read_dir(&dir)
                .unwrap()
                .flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|n| n.starts_with('c'))
                .collect();
            assert!(left.is_empty(), "{left:?}");
            let _ = std::fs::remove_dir_all(&dir);
        }

        #[test]
        fn a_supplicant_that_is_not_there_or_does_not_answer() {
            // No socket and no binary: the error says what could not start.
            let dir = temp("absent");
            let name: IfName = "wlan7".parse().unwrap();
            let e = LinuxWifiPort::open_at(&name, dir.clone(), Path::new("/nonexistent/wpa"))
                .err()
                .unwrap()
                .to_string();
            assert!(e.contains("cannot start /nonexistent/wpa"), "{e}");
            // A socket nobody reads: the wait ends at the deadline.
            let silent = UnixDatagram::bind(dir.join("mute")).unwrap();
            let c = Ctrl::connect(&dir, &dir.join("mute")).unwrap();
            let t = Instant::now();
            assert!(c.request("PING", "PING").is_err());
            assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
            // A command too long for the supplicant's buffer is not sent.
            let e = c
                .request(&"x".repeat(MAX_COMMAND + 1), "a long one")
                .unwrap_err();
            assert!(e.to_string().contains("too long"), "{e}");
            drop(silent);
            assert!(set_country(Some("brazil")).is_err());
            assert!(set_country(Some("b1")).is_err());
            let _ = std::fs::remove_dir_all(&dir);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn wanted(security: JoinSecurity, key: &str) -> WifiNetwork {
        WifiNetwork {
            ssid: "Casa do Valdi".into(),
            security,
            key: key.into(),
            hidden: false,
            band_mhz: None,
            bssid: None,
        }
    }

    fn value<'a>(fields: &'a [(&'static str, String)], name: &str) -> Option<&'a str> {
        fields
            .iter()
            .find(|(f, _)| *f == name)
            .map(|(_, v)| v.as_str())
    }

    #[test]
    fn a_network_as_the_supplicant_takes_it() {
        let f = network_fields(&wanted(JoinSecurity::Auto, "uma senha \"boa\"")).unwrap();
        // The name in hex: no byte of it can end the command.
        assert_eq!(value(&f, "ssid"), Some("4361736120646f2056616c6469"));
        assert_eq!(value(&f, "key_mgmt"), Some("SAE WPA-PSK WPA-PSK-SHA256"));
        assert_eq!(value(&f, "psk"), Some("\"uma senha \"boa\"\""));
        assert_eq!(value(&f, "ieee80211w"), Some("1"));
        assert_eq!(value(&f, "proto"), Some("RSN"));
        assert!(!value(&f, "pairwise").unwrap().contains("TKIP"));
        assert_eq!(value(&f, "scan_ssid"), None);

        let f = network_fields(&wanted(JoinSecurity::Wpa3, "so-wpa3-aqui")).unwrap();
        assert_eq!(value(&f, "key_mgmt"), Some("SAE"));
        assert_eq!(value(&f, "sae_password"), Some("\"so-wpa3-aqui\""));
        assert_eq!(value(&f, "ieee80211w"), Some("2"), "WPA3 requires PMF");
        assert_eq!(value(&f, "psk"), None);

        // The 64-digit key is WPA2's, unquoted.
        let hex_key = "0f".repeat(32);
        let f = network_fields(&wanted(JoinSecurity::Wpa2, &hex_key)).unwrap();
        assert_eq!(value(&f, "psk"), Some(hex_key.as_str()));
        assert!(network_fields(&wanted(JoinSecurity::Wpa3, &hex_key)).is_none());
        assert!(network_fields(&wanted(JoinSecurity::Auto, &hex_key)).is_none());

        let mut open = wanted(JoinSecurity::Open, "");
        open.hidden = true;
        open.bssid = Some("D8:47:32:AA:BB:CC".into());
        open.band_mhz = Some((2400, 2500));
        let f = network_fields(&open).unwrap();
        assert_eq!(value(&f, "key_mgmt"), Some("NONE"));
        assert_eq!(value(&f, "scan_ssid"), Some("1"));
        assert_eq!(value(&f, "bssid"), Some("d8:47:32:aa:bb:cc"));
        assert!(
            value(&f, "freq_list")
                .unwrap()
                .starts_with("2400 2405 2410 2415")
        );
        assert_eq!(value(&f, "psk"), None);
        assert_eq!(value(&f, "proto"), None);

        // What cannot be written is refused, not sent.
        assert!(network_fields(&wanted(JoinSecurity::Auto, "senha\ncom quebra")).is_none());
        let mut bad = wanted(JoinSecurity::Open, "");
        bad.ssid = String::new();
        assert!(network_fields(&bad).is_none());
        bad.ssid = "x".repeat(33);
        assert!(network_fields(&bad).is_none());
        // Every command fits the supplicant's buffer, with room.
        let mut wide = wanted(JoinSecurity::Auto, &"p".repeat(63));
        wide.band_mhz = Some((5925, 7125));
        for (field, v) in network_fields(&wide).unwrap() {
            assert!(
                field.len() + v.len() + 32 < MAX_COMMAND,
                "{field}: {}",
                v.len()
            );
        }
    }

    #[test]
    fn what_a_scan_heard() {
        let reply = "id=3\nbssid=D8:47:32:AA:BB:CC\nfreq=5220\nbeacon_int=100\ncapabilities=0x1511\n\
                     qual=0\nnoise=-92\nlevel=-52\ntsf=0000000000000000\nage=2\nie=3000\n\
                     flags=[WPA2-PSK+SAE-CCMP][WPS][ESS]\nssid=Casa\\x20do\\x20Valdi\nsnr=40\n";
        let b = parse_bss(reply).unwrap();
        assert_eq!(b.ssid, "Casa do Valdi");
        assert_eq!(b.bssid, "d8:47:32:aa:bb:cc");
        assert_eq!((b.frequency_mhz, b.signal_dbm), (5220, -52));
        assert_eq!(b.security, BssSecurity::Wpa2Wpa3);
        // The end of the list, and junk.
        for junk in [
            "",
            "FAIL\n",
            "bssid=xx\nfreq=1\n",
            "bssid=d8:47:32:aa:bb:cc\nfreq=many\n",
        ] {
            assert_eq!(parse_bss(junk), None, "{junk:?}");
        }
        // A hidden network, and a name that is not text.
        let hidden =
            parse_bss("bssid=02:00:00:00:00:01\nfreq=2412\nlevel=-70\nflags=[ESS]\nssid=\n")
                .unwrap();
        assert_eq!(
            (hidden.ssid.as_str(), hidden.security),
            ("", BssSecurity::Open)
        );
        let odd = parse_bss(
            "bssid=02:00:00:00:00:01\nfreq=2412\nlevel=7\nssid=a\\nb\\x00\\xff\\\\\\\"\n",
        )
        .unwrap();
        assert_eq!(odd.ssid, "a?b?\u{fffd}\\\"");
        assert_eq!(odd.signal_dbm, 0, "clamped");

        for (flags, want) in [
            ("[ESS]", BssSecurity::Open),
            ("[WPA2-PSK-CCMP][ESS]", BssSecurity::Wpa2),
            ("[WPA-PSK-TKIP][WPA2-PSK-CCMP+TKIP][ESS]", BssSecurity::Wpa2),
            ("[WPA2-SAE-CCMP][ESS]", BssSecurity::Wpa3),
            ("[WPA2-SAE+PSK-CCMP]", BssSecurity::Wpa2Wpa3),
            (
                "[WPA2-PSK+PSK-SHA256+SAE-CCMP][SAE-H2E]",
                BssSecurity::Wpa2Wpa3,
            ),
            ("[WPA2-EAP-CCMP][ESS]", BssSecurity::Enterprise),
            ("[RSN-EAP-SUITE-B-192-GCMP-256]", BssSecurity::Enterprise),
            ("[WPA2-OWE-CCMP][ESS]", BssSecurity::Owe),
            ("[OWE-TRANS][ESS]", BssSecurity::Open),
            ("[WEP][ESS]", BssSecurity::Legacy),
            ("[WPA-PSK-TKIP][ESS]", BssSecurity::Legacy),
            ("", BssSecurity::Open),
        ] {
            assert_eq!(bss_security(flags), want, "{flags}");
        }
    }

    #[test]
    fn the_link_as_the_supplicant_reports_it() {
        let status = "bssid=d8:47:32:aa:bb:cc\nfreq=5220\nssid=Casa\nid=0\nmode=station\n\
                      wifi_generation=6\npairwise_cipher=CCMP\ngroup_cipher=CCMP\nkey_mgmt=SAE\n\
                      pmf=2\nmgmt_group_cipher=BIP\nsae_group=19\nwpa_state=COMPLETED\n\
                      address=4c:79:6e:ab:cd:ef\n";
        let signal = "RSSI=-52\nLINKSPEED=866\nNOISE=9999\nFREQUENCY=5220\nWIDTH=80 MHz\n";
        let st = parse_status(status, Some(signal));
        assert_eq!(st.state, WifiState::Connected);
        assert_eq!(st.ssid.as_deref(), Some("Casa"));
        assert_eq!(st.bssid.as_deref(), Some("d8:47:32:aa:bb:cc"));
        assert_eq!(
            (st.frequency_mhz, st.signal_dbm, st.rate_mbps),
            (Some(5220), Some(-52), Some(866))
        );
        assert_eq!((st.security.as_deref(), st.pmf), (Some("wpa3"), Some(true)));
        for (state, want) in [
            ("SCANNING", WifiState::Searching),
            ("DISCONNECTED", WifiState::Searching),
            ("AUTHENTICATING", WifiState::Connecting),
            ("ASSOCIATING", WifiState::Connecting),
            ("4WAY_HANDSHAKE", WifiState::Connecting),
            ("INACTIVE", WifiState::Idle),
            ("INTERFACE_DISABLED", WifiState::Blocked),
            ("SOMETHING_NEW", WifiState::Idle),
        ] {
            let st = parse_status(
                &format!("wpa_state={state}\nbssid=d8:47:32:aa:bb:cc\nfreq=5220\n"),
                None,
            );
            assert_eq!(st.state, want, "{state}");
            assert_eq!(
                (st.bssid, st.frequency_mhz),
                (None, None),
                "no link, no link data"
            );
        }
        assert_eq!(parse_status("", None), WifiStatus::default());
        let wpa2 = parse_status("wpa_state=COMPLETED\nkey_mgmt=WPA2-PSK\n", None);
        assert_eq!(
            (wpa2.security.as_deref(), wpa2.pmf),
            (Some("wpa2"), Some(false))
        );
        let open = parse_status(
            "wpa_state=COMPLETED\nkey_mgmt=NONE\n",
            Some("RSSI=5\nLINKSPEED=-1\n"),
        );
        assert_eq!(
            (open.security.as_deref(), open.signal_dbm, open.rate_mbps),
            (Some("open"), Some(0), None)
        );
    }

    #[test]
    fn events_in_words() {
        use WifiEvent::{Connected, Country, Disconnected, Failed, ScanDone, ScanFailed};
        let cases: [(&str, Option<WifiEvent>); 14] = [
            (
                "<3>CTRL-EVENT-CONNECTED - Connection to d8:47:32:AA:bb:cc completed [id=0 id_str=]",
                Some(Connected {
                    bssid: "d8:47:32:aa:bb:cc".into(),
                }),
            ),
            (
                "<3>CTRL-EVENT-DISCONNECTED bssid=d8:47:32:aa:bb:cc reason=3 locally_generated=1",
                Some(Disconnected {
                    reason: "left (reason 3)".into(),
                }),
            ),
            (
                "<3>CTRL-EVENT-DISCONNECTED bssid=d8:47:32:aa:bb:cc reason=4",
                Some(Disconnected {
                    reason: "no activity for too long (reason 4)".into(),
                }),
            ),
            (
                "<3>CTRL-EVENT-SSID-TEMP-DISABLED id=0 ssid=\"Casa\" auth_failures=1 duration=10 reason=WRONG_KEY",
                Some(Failed(WifiFailure::WrongKey)),
            ),
            (
                "<3>CTRL-EVENT-NETWORK-NOT-FOUND ",
                Some(Failed(WifiFailure::NotFound)),
            ),
            (
                "<3>CTRL-EVENT-AUTH-REJECT d8:47:32:aa:bb:cc auth_type=3 auth_transaction=2 status_code=15",
                Some(Failed(WifiFailure::WrongKey)),
            ),
            (
                "<3>CTRL-EVENT-AUTH-REJECT d8:47:32:aa:bb:cc auth_type=0 auth_transaction=2 status_code=17",
                Some(Failed(WifiFailure::Rejected(
                    "it cannot take more stations (status 17)".into(),
                ))),
            ),
            (
                "<3>CTRL-EVENT-ASSOC-REJECT bssid=d8:47:32:aa:bb:cc status_code=30",
                Some(Failed(WifiFailure::Rejected(
                    "try again later (status 30)".into(),
                ))),
            ),
            ("<3>CTRL-EVENT-SCAN-RESULTS ", Some(ScanDone)),
            (
                "<3>CTRL-EVENT-SCAN-FAILED ret=-16",
                Some(ScanFailed("the driver refused the scan (-16)".into())),
            ),
            (
                "<3>CTRL-EVENT-REGDOM-CHANGE init=USER type=COUNTRY alpha2=BR",
                Some(Country(Some("BR".into()))),
            ),
            (
                "<3>CTRL-EVENT-REGDOM-CHANGE init=CORE type=WORLD",
                Some(Country(None)),
            ),
            ("<3>CTRL-EVENT-SCAN-STARTED ", None),
            (
                "<4>WPA: 4-Way Handshake failed - pre-shared key may be incorrect",
                None,
            ),
        ];
        for (line, want) in cases {
            assert_eq!(parse_event(line), want, "{line}");
        }
        for junk in [
            "",
            "<",
            "<3>",
            "<<<>>>",
            "CTRL-EVENT-DISCONNECTED reason=x",
            "\0",
        ] {
            let _ = parse_event(junk);
        }
    }

    proptest! {
        /// Whatever the supplicant (or something on its socket) says, the
        /// parsers neither panic nor hand back more than they may.
        #[test]
        fn hostile_replies_are_bounded(text in ".{0,600}", bytes in proptest::collection::vec(any::<u8>(), 0..600)) {
            let lossy = String::from_utf8_lossy(&bytes).into_owned();
            for t in [&text, &lossy] {
                if let Some(b) = parse_bss(t) {
                    prop_assert!(b.ssid.len() <= 4 * MAX_SSID);
                    prop_assert!(!b.ssid.chars().any(char::is_control));
                    prop_assert!((-120..=0).contains(&b.signal_dbm));
                    prop_assert_eq!(b.bssid.len(), 17);
                }
                let st = parse_status(t, Some(t));
                prop_assert!(st.ssid.is_none_or(|s| !s.chars().any(char::is_control)));
                let _ = parse_event(t);
                let _ = bss_security(t);
                prop_assert!(unescape(t).len() <= MAX_SSID);
            }
        }
    }
}
