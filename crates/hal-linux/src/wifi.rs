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
        // wpa_supplicant 2.12 `wpa_supplicant_signal_poll`: `NOISE=%d` is
        // `WPA_INVALID_NOISE` (9999, `src/drivers/driver.h`) when the
        // driver has no survey.
        noise_dbm: signal
            .and_then(|s| number(field(s, "NOISE")))
            .filter(|v| (-150..0).contains(v))
            .filter(|_| on),
        width_mhz: signal
            .and_then(|s| field(s, "WIDTH"))
            .and_then(width)
            .filter(|_| on),
        center_mhz: signal
            .and_then(|s| number(field(s, "CENTER_FRQ1")))
            .and_then(|v| u32::try_from(v).ok())
            .filter(|v| (1..100_000).contains(v))
            .filter(|_| on),
        // `wpa_supplicant_ctrl_iface_status`: 7 EHT, 6 HE, 5 VHT, 4 HT;
        // absent for a legacy link.
        generation: field(status, "wifi_generation")
            .and_then(|g| g.trim().parse::<u8>().ok())
            .filter(|g| (4..=7).contains(g))
            .filter(|_| on),
        // `wpa_sm_get_status` (`src/rsn_supp/wpa.c`): `wpa_cipher_txt`.
        cipher: field(status, "pairwise_cipher")
            .map(str::trim)
            .filter(|c| {
                !c.is_empty()
                    && *c != "NONE"
                    && c.len() <= 24
                    && c.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
            .map(str::to_owned)
            .filter(|_| on),
        link: None,
    }
}

/// `WIDTH=` of `SIGNAL_POLL` (`channel_width_to_string`, wpa_supplicant
/// 2.12 `src/drivers/driver_common.c`): `20 MHz (no HT)`, `20 MHz` …
/// `320 MHz`; `80+80 MHz` is as wide as 160.
fn width(text: &str) -> Option<u32> {
    let t = text.trim();
    if t.starts_with("80+80") {
        return Some(160);
    }
    let mhz = t
        .strip_suffix(" (no HT)")
        .unwrap_or(t)
        .strip_suffix(" MHz")?;
    mhz.parse::<u32>()
        .ok()
        .filter(|w| matches!(w, 20 | 40 | 80 | 160 | 320))
}

/// The firmware's version in one line of the kernel log, and whose it is:
/// the device (`0000:c3:00.0`, `2-1:1.0`) of a `dev_info` line
/// (`<driver> <device>: <text>`), or the driver of a `pr_info` one
/// (`<driver>: <text>`). The drivers of the image say it as
/// - rtw88/rtw89: `Firmware version 0.29.29.5 (af1ab4bf), cmd version 0, type 5`
/// - iwlwifi: `loaded firmware version 89.202a2f7b.0 so-a0-gf-a0-89.ucode op_mode iwlmvm`
/// - mt76 (mt7921, mt7925): `WM Firmware Version: ____010000, Build Time: 20230526130958`
/// - ath10k/ath11k: `firmware ver WLAN.RM.4.4.1-…`, `fw_version 0x1106196e …`
pub(crate) fn firmware_line(message: &str) -> Option<(String, String)> {
    const MAX_KEY: usize = 32;
    const MAX_VERSION: usize = 48;
    let message = message.get(..message.len().min(512)).unwrap_or("");
    let (driver, rest) = message.split_once(' ')?;
    let token_ok =
        |t: &str| !t.is_empty() && t.len() <= MAX_KEY && t.bytes().all(|b| b.is_ascii_graphic());
    let (key, text) = match driver.strip_suffix(':') {
        Some(d) => (d, rest),
        None => {
            let (device, text) = rest.split_once(": ")?;
            (device, text)
        }
    };
    if !token_ok(key) {
        return None;
    }
    let lower = text.to_ascii_lowercase();
    let at = ["firmware version", "fw_version", "firmware ver"]
        .iter()
        .find_map(|p| lower.find(p).map(|i| i.saturating_add(p.len())))?;
    let version = text
        .get(at..)?
        .trim_start_matches([':', '=', ' '])
        .split([' ', ','])
        .next()?
        .trim_end_matches([';', '.', ')']);
    let ok = !version.is_empty()
        && version.len() <= MAX_VERSION
        && version.bytes().all(|b| b.is_ascii_graphic());
    ok.then(|| (key.to_owned(), version.to_owned()))
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
    use std::collections::BTreeMap;
    use std::os::unix::net::UnixDatagram;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex, PoisonError, mpsc};
    use std::time::{Duration, Instant};

    use corerouter_hal::HalError;
    use corerouter_hal::oslog::OsSource;
    use corerouter_hal::wifi::{
        MAX_EVENTS, MAX_SCAN_RESULTS, WifiBss, WifiEvent, WifiFailure, WifiLink, WifiNetwork,
        WifiPort, WifiRadio, WifiState, WifiStatus,
    };
    use corerouter_model::IfName;

    use super::{
        MAX_COMMAND, SECRET_FIELDS, firmware_line, network_fields, parse_bss, parse_event,
        parse_status,
    };
    use crate::genl::{Genl, Msg};
    use crate::nl80211::Nl80211;

    /// A reply slower than this is a supplicant that hangs: the radio is
    /// given up and opened again later. Local replies take 10 to 200 µs.
    /// Nobody waits for it but the radio's own thread.
    const REPLY_TIMEOUT: Duration = Duration::from_secs(2);
    /// `INTERFACE_ADD` answers only after the driver brought the interface
    /// up (wpa_supplicant 2.12: `ctrl_iface.c` `wpa_supplicant_global_iface_add`
    /// → `wpa_supplicant_add_iface` → `wpa_supplicant_init_iface` →
    /// `wpas_init_driver` → `driver_nl80211.c`
    /// `wpa_driver_nl80211_finish_drv_init` → `linux_set_iface_flags(…, 1)`),
    /// and on a card that is where the firmware is loaded into the chip
    /// (Linux 6.18: `ieee80211_open` → `drv_start`; rtw89 `rtw89_core_start`
    /// → `rtw89_mac_init`): hundreds of milliseconds to seconds, where the
    /// simulated radio answers at once.
    const ADD_TIMEOUT: Duration = Duration::from_secs(20);
    /// How often the radio's thread looks at its socket of events.
    const POLL: Duration = Duration::from_millis(100);
    /// How old the status the tick reads may be.
    const STATUS_EVERY: Duration = Duration::from_secs(1);
    /// Orders waiting for the radio's thread; more is "busy".
    const MAX_ORDERS: usize = 8;
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
        /// A reply never came: it may still come, and would be read as the
        /// answer to the next command. The socket is not used again.
        stale: std::cell::Cell<bool>,
    }

    impl Ctrl {
        fn connect(dir: &Path, server: &Path) -> std::io::Result<Self> {
            let n = CLIENT.fetch_add(1, Ordering::Relaxed);
            let local = dir.join(format!("c{}-{n}", std::process::id()));
            let _ = std::fs::remove_file(&local);
            let sock = UnixDatagram::bind(&local)?;
            let made = Self {
                sock,
                local,
                stale: std::cell::Cell::new(false),
            };
            made.sock.connect(server)?;
            made.sock.set_write_timeout(Some(REPLY_TIMEOUT))?;
            Ok(made)
        }

        /// One command, one reply. `what` names it in an error (a command
        /// with a key in it is never shown).
        fn request(&self, command: &str, what: &str) -> Result<String, HalError> {
            self.request_within(command, what, REPLY_TIMEOUT)
        }

        /// [`request`](Self::request) with its own deadline. A reply that
        /// does not come in time ends the socket: the next command on it
        /// fails at once instead of reading that reply as its own.
        fn request_within(
            &self,
            command: &str,
            what: &str,
            within: Duration,
        ) -> Result<String, HalError> {
            if command.len() > MAX_COMMAND {
                return Err(HalError::Rejected(format!(
                    "wpa_supplicant: {what}: too long"
                )));
            }
            if self.stale.get() {
                return Err(io_err(what, "an earlier reply never came"));
            }
            let late = |e: &dyn std::fmt::Display| {
                self.stale.set(true);
                io_err(what, e)
            };
            self.sock.send(command.as_bytes()).map_err(|e| late(&e))?;
            let deadline = Instant::now() + within;
            let mut buf = vec![0u8; MAX_REPLY];
            loop {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Err(late(&"no reply"));
                }
                self.sock
                    .set_read_timeout(Some(left))
                    .map_err(|e| late(&e))?;
                let n = self.sock.recv(&mut buf).map_err(|e| late(&e))?;
                let reply = String::from_utf8_lossy(buf.get(..n).unwrap_or_default());
                // An event that slipped in (a socket that is attached).
                if reply.starts_with('<') {
                    continue;
                }
                return Ok(reply.into_owned());
            }
        }

        /// A command whose reply is `OK`.
        fn ok(&self, command: &str, what: &str) -> Result<(), HalError> {
            self.ok_within(command, what, REPLY_TIMEOUT)
        }

        fn ok_within(&self, command: &str, what: &str, within: Duration) -> Result<(), HalError> {
            let r = self.request_within(command, what, within)?;
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

    /// One radio, through its own control socket: every call here waits
    /// for the supplicant. Only the radio's thread ([`LinuxWifiPort`]) has
    /// one.
    struct Direct {
        name: String,
        dir: PathBuf,
        cmd: Ctrl,
        events: Ctrl,
        queued: Vec<WifiEvent>,
        blocked: bool,
        /// nl80211, for the link's rates and counters (G1.30g); opened when
        /// first connected, dropped after a failure and opened again.
        nl: Option<Nl80211>,
    }

    impl Direct {
        /// The supplicant started if it is not there, and the radio handed
        /// to it; the sockets' directory and the supplicant's binary given.
        fn open_at(name: &IfName, dir: PathBuf, binary: &Path) -> Result<Self, HalError> {
            let global = global(&dir, binary)?;
            let ifaces = dir.join("if");
            let known = global.request("INTERFACES", "INTERFACES")?;
            if !known.lines().any(|l| l.trim() == name.as_str()) {
                // <ifname> TAB <config file: none> TAB <driver> TAB <ctrl dir>
                global.ok_within(
                    &format!("INTERFACE_ADD {name}\t\tnl80211\t{}", ifaces.display()),
                    "the radio (INTERFACE_ADD)",
                    ADD_TIMEOUT,
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
                nl: None,
            })
        }

        /// What the kernel keeps about the link to `bssid`; `None` when it
        /// cannot be read (no cfg80211, the interface gone, a driver
        /// without station info): the supplicant's numbers stand alone.
        fn link(&mut self, bssid: Option<&str>) -> Option<WifiLink> {
            let ifindex = nix::net::if_::if_nametoindex(self.name.as_str()).ok()?;
            if self.nl.is_none() {
                self.nl = Nl80211::open();
            }
            match self.nl.as_mut()?.station(ifindex, bssid) {
                Ok(l) => l,
                Err(e) => {
                    log::debug!("wifi {}: nl80211 station: {e}", self.name);
                    self.nl = None;
                    None
                }
            }
        }

        fn forget_networks(&self) -> Result<(), HalError> {
            self.cmd.ok("REMOVE_NETWORK all", "REMOVE_NETWORK")
        }
    }

    impl WifiPort for Direct {
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
            // A driver without the numbers answers `FAIL`; a reply that
            // never comes is the supplicant's, not the driver's.
            let signal = if connected {
                Some(self.cmd.request("SIGNAL_POLL", "SIGNAL_POLL")?)
            } else {
                None
            };
            let mut st = parse_status(&status, signal.as_deref());
            if connected {
                st.link = self.link(st.bssid.as_deref());
            }
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

    impl Drop for Direct {
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

    /// What the radio's thread leaves for the tick to read.
    #[derive(Default)]
    struct Seen {
        status: WifiStatus,
        scan: Vec<WifiBss>,
        events: Vec<WifiEvent>,
        /// The radio could not be opened or stopped answering: the thread
        /// ended. Said by the next `status`.
        failed: Option<String>,
    }

    enum Order {
        Join(Box<WifiNetwork>),
        Leave,
        Scan,
    }

    /// One radio as the engine holds it. Nothing here waits: the engine
    /// calls it from its tick, with the session locked, and the supplicant
    /// answers when it answers (seconds, when a card loads its firmware; never,
    /// when it hangs). A thread of the radio's own ([`run`]) talks to the
    /// supplicant; orders go to it by a bounded queue and what it learns
    /// comes back in [`Seen`]. Measured on the image with the supplicant
    /// stopped: a command waited up to 918 ms for the session before this,
    /// with the sockets read from the tick.
    pub struct LinuxWifiPort {
        orders: mpsc::SyncSender<Order>,
        seen: Arc<Mutex<Seen>>,
    }

    fn seen(s: &Mutex<Seen>) -> std::sync::MutexGuard<'_, Seen> {
        s.lock().unwrap_or_else(PoisonError::into_inner)
    }

    impl LinuxWifiPort {
        pub fn open(name: &IfName) -> Result<Self, HalError> {
            Self::open_at(name, dir()?, binary())
        }

        /// [`open`](Self::open) with the sockets' directory and the
        /// supplicant's binary given. Returns at once: the radio is opened
        /// by its thread, and a failure there is what `status` says next.
        fn open_at(name: &IfName, dir: PathBuf, binary: PathBuf) -> Result<Self, HalError> {
            let (orders, rx) = mpsc::sync_channel(MAX_ORDERS);
            let shared = Arc::new(Mutex::new(Seen::default()));
            let (theirs, name) = (Arc::clone(&shared), name.clone());
            std::thread::Builder::new()
                .name(format!("wifi-{name}"))
                .spawn(move || run(&name, dir, &binary, &rx, &theirs))
                .map_err(|e| HalError::Io(format!("the radio's thread: {e}")))?;
            Ok(Self {
                orders,
                seen: shared,
            })
        }

        fn order(&self, o: Order, what: &str) -> Result<(), HalError> {
            self.orders.try_send(o).map_err(|e| match e {
                mpsc::TrySendError::Full(_) => {
                    HalError::Io(format!("the radio is busy: {what} not taken, try again"))
                }
                mpsc::TrySendError::Disconnected(_) => HalError::Io(
                    seen(&self.seen)
                        .failed
                        .clone()
                        .unwrap_or_else(|| "the radio's thread ended".into()),
                ),
            })
        }
    }

    impl WifiPort for LinuxWifiPort {
        fn join(&mut self, net: &WifiNetwork) -> Result<(), HalError> {
            // Said here, where the caller can still be told.
            if network_fields(net).is_none() {
                return Err(HalError::Rejected(
                    "the network cannot be written for wpa_supplicant".into(),
                ));
            }
            self.order(Order::Join(Box::new(net.clone())), "the network")
        }

        fn leave(&mut self) -> Result<(), HalError> {
            self.order(Order::Leave, "leaving")
        }

        fn scan(&mut self) -> Result<(), HalError> {
            self.order(Order::Scan, "the scan")
        }

        fn scan_results(&mut self) -> Result<Vec<WifiBss>, HalError> {
            Ok(seen(&self.seen).scan.clone())
        }

        fn status(&mut self) -> Result<WifiStatus, HalError> {
            let s = seen(&self.seen);
            match &s.failed {
                Some(why) => Err(HalError::Io(why.clone())),
                None => Ok(s.status.clone()),
            }
        }

        fn events(&mut self) -> Vec<WifiEvent> {
            std::mem::take(&mut seen(&self.seen).events)
        }
    }

    /// The lock a radio's thread holds while it lives, by the radio's name.
    fn turn_of(name: &str) -> Arc<Mutex<()>> {
        static TURNS: Mutex<BTreeMap<String, Arc<Mutex<()>>>> = Mutex::new(BTreeMap::new());
        let mut turns = TURNS.lock().unwrap_or_else(PoisonError::into_inner);
        Arc::clone(turns.entry(name.to_owned()).or_default())
    }

    /// The radio's thread: opens the radio, then takes the orders and keeps
    /// [`Seen`] current, until the port is dropped (the queue closes) or
    /// the supplicant stops answering. The radio leaves the supplicant on
    /// the way out ([`Direct`]'s drop).
    fn run(
        name: &IfName,
        dir: PathBuf,
        binary: &Path,
        orders: &mpsc::Receiver<Order>,
        shared: &Mutex<Seen>,
    ) {
        let fail = |e: HalError| seen(shared).failed = Some(e.to_string());
        // One thread per radio at a time: a radio turned off and on again
        // has a thread still taking it out of the supplicant, and the new
        // one waits for that (it would find the radio "already there", and
        // lose it a moment later). Declared before the port: released
        // after the port's drop.
        let turn = turn_of(name.as_str());
        let _mine = turn.lock().unwrap_or_else(PoisonError::into_inner);
        let mut port = match Direct::open_at(name, dir, binary) {
            Ok(p) => p,
            Err(e) => return fail(e),
        };
        let mut status_at: Option<Instant> = None;
        loop {
            let mut events = Vec::new();
            let done = match orders.recv_timeout(POLL) {
                Ok(Order::Join(net)) => port.join(&net).map_err(|e| ("the network", e)),
                Ok(Order::Leave) => port.leave().map_err(|e| ("leaving", e)),
                Ok(Order::Scan) => port.scan().map_err(|e| ("the scan", e)),
                Err(mpsc::RecvTimeoutError::Timeout) => Ok(()),
                Err(mpsc::RecvTimeoutError::Disconnected) => return,
            };
            match done {
                Ok(()) => {}
                // The supplicant said no: the radio is fine.
                Err(("the scan", HalError::Rejected(why))) => {
                    events.push(WifiEvent::ScanFailed(why));
                }
                Err((_, HalError::Rejected(why))) => {
                    events.push(WifiEvent::Failed(WifiFailure::Other(why)));
                }
                // It did not answer: start over.
                Err((_, e)) => return fail(e),
            }
            events.extend(port.events());
            let heard = events.contains(&WifiEvent::ScanDone);
            let scan = if heard {
                match port.scan_results() {
                    Ok(s) => Some(s),
                    Err(e) => return fail(e),
                }
            } else {
                None
            };
            let due = status_at.is_none_or(|t| t.elapsed() >= STATUS_EVERY);
            let status = if due || !events.is_empty() {
                status_at = Some(Instant::now());
                match port.status() {
                    Ok(st) => Some(st),
                    Err(e) => return fail(e),
                }
            } else {
                None
            };
            // `status` may have queued one more (the radio blocked).
            events.extend(port.events());
            if scan.is_none() && status.is_none() && events.is_empty() {
                continue;
            }
            // The state first, then the events that send the tick to read it.
            let mut s = seen(shared);
            if let Some(scan) = scan {
                s.scan = scan;
            }
            if let Some(st) = status {
                s.status = st;
            }
            let room = MAX_EVENTS.saturating_sub(s.events.len());
            s.events.extend(events.into_iter().take(room));
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

    /// The last part of a sysfs link (`phy0`, `0000:c3:00.0`, `iwlwifi`),
    /// bounded.
    fn link_name(path: &Path) -> Option<String> {
        std::fs::read_link(path)
            .ok()
            .and_then(|l| l.file_name().map(|f| f.to_string_lossy().into_owned()))
            .map(|d| d.chars().take(32).collect::<String>())
            .filter(|d| !d.is_empty())
    }

    /// What sysfs, nl80211 and the kernel log say about the radio behind
    /// `name`. Asked every few seconds by a window that shows it: two
    /// nl80211 requests and the kernel log's new lines.
    pub fn radio(name: &IfName) -> Option<WifiRadio> {
        let dev = Path::new("/sys/class/net").join(name.as_str());
        if !dev.join("phy80211").exists() {
            return None;
        }
        let driver = link_name(&dev.join("device/driver"));
        let self_managed = driver
            .as_deref()
            .is_some_and(|d| SELF_MANAGED.iter().any(|s| d.starts_with(s)));
        let mut r = WifiRadio {
            driver: driver.clone(),
            self_managed,
            phy: link_name(&dev.join("phy80211")),
            ..WifiRadio::default()
        };
        // Each part on its own: a driver without one still has the others.
        if let Ok(ifindex) = nix::net::if_::if_nametoindex(name.as_str())
            && let Some(mut nl) = Nl80211::open()
        {
            match nl.tx_power(ifindex) {
                Ok(p) => r.tx_power_dbm = p,
                Err(e) => log::debug!("wifi {name}: nl80211 interface: {e}"),
            }
            match nl.wiphy(ifindex) {
                Ok(w) => {
                    r.bands = w.bands();
                    r.antennas_tx = w.antennas_tx;
                    r.antennas_rx = w.antennas_rx;
                    r.phy = w.name.or(r.phy);
                }
                Err(e) => log::debug!("wifi {name}: nl80211 wiphy: {e}"),
            }
        }
        r.blocked = r
            .phy
            .as_deref()
            .and_then(|p| rfkill(&Path::new("/sys/class/ieee80211").join(p)));
        let device = link_name(&dev.join("device"));
        r.firmware = firmware(device.as_deref(), driver.as_deref());
        Some(r)
    }

    /// How the radio's rfkill switches stand (`/sys/class/ieee80211/<phy>/
    /// rfkill<n>/{hard,soft}`): `hard` wins over `soft`; `None` when free.
    fn rfkill(phy: &Path) -> Option<String> {
        let read = |p: PathBuf| {
            std::fs::read_to_string(p)
                .ok()
                .is_some_and(|t| t.trim() == "1")
        };
        let (mut hard, mut soft) = (false, false);
        for e in std::fs::read_dir(phy)
            .ok()?
            .flatten()
            .take(MAX_SYSFS_ENTRIES)
        {
            if !e.file_name().to_string_lossy().starts_with("rfkill") {
                continue;
            }
            hard |= read(e.path().join("hard"));
            soft |= read(e.path().join("soft"));
        }
        if hard {
            Some("hard".into())
        } else if soft {
            Some("soft".into())
        } else {
            None
        }
    }

    /// Entries of a phy's sysfs directory looked at (some ten).
    const MAX_SYSFS_ENTRIES: usize = 64;
    /// Firmware versions remembered, by device or driver.
    const MAX_FIRMWARES: usize = 32;
    /// Kernel log records read per call at most: the whole ring the first
    /// time (some thousands), the new ones after.
    const MAX_KMSG_RECORDS: usize = 65_536;
    const KMSG_BATCH: usize = 1024;

    /// The kernel log, read on from where it was left, and the firmware
    /// versions it announced, by device (or driver).
    struct FirmwareLog {
        kmsg: crate::oslog::Kmsg,
        seen: BTreeMap<String, String>,
    }

    static FIRMWARE: Mutex<Option<FirmwareLog>> = Mutex::new(None);

    /// The firmware the driver announced for `device` (its newest line), or
    /// for the driver when it does not name the device. There is no nl80211
    /// attribute for it, and ethtool's `ETHTOOL_GDRVINFO` is an ioctl
    /// (`unsafe` here); the drivers all log it when they load it.
    fn firmware(device: Option<&str>, driver: Option<&str>) -> Option<String> {
        let mut guard = FIRMWARE.lock().unwrap_or_else(PoisonError::into_inner);
        let log = guard.get_or_insert_with(|| FirmwareLog {
            kmsg: crate::oslog::Kmsg::open("/dev/kmsg"),
            seen: BTreeMap::new(),
        });
        let mut read = 0usize;
        while read < MAX_KMSG_RECORDS {
            let lines = log.kmsg.read(KMSG_BATCH, "");
            read = read.saturating_add(lines.len());
            for l in &lines {
                // A program can write to /dev/kmsg; only the kernel counts.
                if l.source != OsSource::Kernel {
                    continue;
                }
                if let Some((key, version)) = firmware_line(&l.message)
                    && (log.seen.len() < MAX_FIRMWARES || log.seen.contains_key(&key))
                {
                    log.seen.insert(key, version);
                }
            }
            if lines.len() < KMSG_BATCH {
                break;
            }
        }
        device
            .and_then(|d| log.seen.get(d))
            .or_else(|| driver.and_then(|d| log.seen.get(d)))
            .cloned()
    }

    #[cfg(test)]
    mod tests {
        use corerouter_hal::wifi::{JoinSecurity, WifiFailure};

        use super::*;

        /// A stand-in for the supplicant: the global socket and one radio's,
        /// answering what the real one answers, and telling the test every
        /// command it got.
        fn fake(dir: &Path, radio: &str) -> mpsc::Receiver<String> {
            fake_slow(dir, radio, Duration::ZERO)
        }

        /// [`fake`] whose `INTERFACE_ADD` takes `add` to answer, as on a
        /// card that loads its firmware when the interface comes up.
        fn fake_slow(dir: &Path, radio: &str, add: Duration) -> mpsc::Receiver<String> {
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
                                    std::thread::sleep(add);
                                    added = true;
                                    "OK\n".into()
                                }
                                // A reply that comes after the asker gave up.
                                (_, "LATE") => {
                                    std::thread::sleep(Duration::from_millis(300));
                                    "LATE-REPLY\n".into()
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
                                (false, "STATUS") => "wpa_state=COMPLETED\nbssid=d8:47:32:aa:bb:cc\nfreq=5220\nssid=Casa\nwifi_generation=5\npairwise_cipher=CCMP\nkey_mgmt=SAE\npmf=2\n".into(),
                                (false, "SIGNAL_POLL") => "RSSI=-52\nLINKSPEED=866\nNOISE=-91\nFREQUENCY=5220\nWIDTH=80 MHz\nCENTER_FRQ1=5210\n".into(),
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
        fn rfkill_hard_wins_over_soft() {
            let dir = temp("rfkill");
            let phy = dir.join("phy9");
            let switch = |n: &str, hard: &str, soft: &str| {
                let d = phy.join(n);
                std::fs::create_dir_all(&d).unwrap();
                std::fs::write(d.join("hard"), hard).unwrap();
                std::fs::write(d.join("soft"), soft).unwrap();
            };
            std::fs::create_dir_all(phy.join("device")).unwrap();
            assert_eq!(rfkill(&phy), None);
            switch("rfkill3", "0\n", "0\n");
            assert_eq!(rfkill(&phy), None);
            switch("rfkill3", "0\n", "1\n");
            assert_eq!(rfkill(&phy).as_deref(), Some("soft"));
            switch("rfkill4", "1\n", "0\n");
            assert_eq!(rfkill(&phy).as_deref(), Some("hard"));
            assert_eq!(rfkill(&dir.join("missing")), None);
            let _ = std::fs::remove_dir_all(&dir);
        }

        #[test]
        fn a_radio_is_told_its_network_and_the_key_is_in_one_command_only() {
            let dir = temp("join");
            let seen = fake(&dir, "wlan7");
            let name: IfName = "wlan7".parse().unwrap();
            // The supplicant answers already: nothing is started.
            let mut port =
                Direct::open_at(&name, dir.clone(), Path::new("/nonexistent/wpa")).unwrap();
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
            assert_eq!(
                (st.noise_dbm, st.width_mhz, st.center_mhz, st.generation),
                (Some(-91), Some(80), Some(5210), Some(5))
            );
            assert_eq!(st.cipher.as_deref(), Some("CCMP"));
            // No such interface in this namespace: no nl80211 link, and the
            // rest stands.
            assert_eq!(st.link, None);
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
            let e = Direct::open_at(&name, dir.clone(), Path::new("/nonexistent/wpa"))
                .err()
                .unwrap()
                .to_string();
            assert!(e.contains("cannot start /nonexistent/wpa"), "{e}");
            // A socket nobody reads: the wait ends at the deadline.
            let silent = UnixDatagram::bind(dir.join("mute")).unwrap();
            let c = Ctrl::connect(&dir, &dir.join("mute")).unwrap();
            let t = Instant::now();
            assert!(
                c.request_within("PING", "PING", Duration::from_millis(100))
                    .is_err()
            );
            assert!(t.elapsed() < Duration::from_secs(1), "{:?}", t.elapsed());
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

        fn until(what: &str, mut ok: impl FnMut() -> bool) {
            let deadline = Instant::now() + Duration::from_secs(5);
            while !ok() {
                assert!(Instant::now() < deadline, "never: {what}");
                std::thread::sleep(Duration::from_millis(10));
            }
        }

        /// A card loads its firmware when the interface comes up, and the
        /// supplicant answers `INTERFACE_ADD` only then: the port is there
        /// at once, takes its orders, and nothing the tick calls waits.
        #[test]
        fn a_radio_slow_to_come_up_is_waited_for_by_its_thread_not_by_the_caller() {
            let dir = temp("slow");
            let add = Duration::from_millis(800);
            let seen = fake_slow(&dir, "wlan7", add);
            let name: IfName = "wlan7".parse().unwrap();
            let t = Instant::now();
            let mut port =
                LinuxWifiPort::open_at(&name, dir.clone(), PathBuf::from("/nonexistent/wpa"))
                    .unwrap();
            let net = WifiNetwork {
                ssid: "Casa".into(),
                security: JoinSecurity::Auto,
                key: "a-passphrase-nobody-sees".into(),
                hidden: false,
                band_mhz: None,
                bssid: None,
            };
            port.join(&net).unwrap();
            port.scan().unwrap();
            assert_eq!(
                port.status().unwrap().state,
                WifiState::Idle,
                "not there yet"
            );
            assert!(port.events().is_empty() && port.scan_results().unwrap().is_empty());
            assert!(
                t.elapsed() < Duration::from_millis(300),
                "the caller waited: {:?}",
                t.elapsed()
            );
            // The radio's thread waited, and then did what was asked, in order.
            let mut events = Vec::new();
            until("the link", || {
                events.extend(port.events());
                port.status().unwrap().state == WifiState::Connected
            });
            assert!(t.elapsed() >= add, "{:?}", t.elapsed());
            until("the supplicant's word", || {
                events.extend(port.events());
                events.contains(&WifiEvent::Failed(WifiFailure::WrongKey))
            });
            let sent: Vec<String> = seen.try_iter().collect();
            let at = |word: &str| {
                sent.iter()
                    .position(|c| c.starts_with(word))
                    .unwrap_or_else(|| panic!("{word} not sent: {sent:?}"))
            };
            assert!(
                at("INTERFACE_ADD") < at("SELECT_NETWORK") && at("SELECT_NETWORK") < at("SCAN")
            );
            // Reading what the thread saw never waits either.
            let t = Instant::now();
            for _ in 0..100 {
                let _ = (port.status(), port.events(), port.scan_results());
            }
            assert!(
                t.elapsed() < Duration::from_millis(100),
                "{:?}",
                t.elapsed()
            );
            // Dropped: the thread ends, and the radio leaves the supplicant.
            drop(port);
            let mut gone = false;
            until("INTERFACE_REMOVE", || {
                gone |= seen.try_iter().any(|c| c == "INTERFACE_REMOVE wlan7");
                gone
            });
            let _ = std::fs::remove_dir_all(&dir);
        }

        /// Off and on again at once: the new thread waits for the old one
        /// to take the radio out of the supplicant, then puts it back.
        #[test]
        fn a_radio_turned_off_and_on_again_is_removed_before_it_is_added() {
            let dir = temp("again");
            let seen = fake(&dir, "wlan7");
            let name: IfName = "wlan7".parse().unwrap();
            let bin = PathBuf::from("/nonexistent/wpa");
            let mut first = LinuxWifiPort::open_at(&name, dir.clone(), bin.clone()).unwrap();
            until("the first link", || {
                first.status().unwrap().state == WifiState::Connected
            });
            drop(first);
            let mut second = LinuxWifiPort::open_at(&name, dir.clone(), bin).unwrap();
            let mut sent: Vec<String> = Vec::new();
            until("the second INTERFACE_ADD", || {
                sent.extend(seen.try_iter());
                sent.iter()
                    .filter(|c| c.starts_with("INTERFACE_ADD"))
                    .count()
                    == 2
            });
            let words: Vec<&str> = sent
                .iter()
                .filter_map(|c| c.split([' ', '\t']).next())
                .filter(|w| w.starts_with("INTERFACE_"))
                .collect();
            assert_eq!(
                words,
                ["INTERFACE_ADD", "INTERFACE_REMOVE", "INTERFACE_ADD"],
                "{sent:?}"
            );
            until("the second link", || {
                second.status().unwrap().state == WifiState::Connected
            });
            let _ = std::fs::remove_dir_all(&dir);
        }

        /// A reply that comes after its deadline stays in the socket: read
        /// as the answer to the next command, a `PONG` would pass for an
        /// `OK`. The socket is not used again.
        #[test]
        fn a_late_reply_is_never_taken_for_the_next_command() {
            let dir = temp("late");
            let _seen = fake(&dir, "wlan7");
            let c = Ctrl::connect(&dir, &dir.join("global")).unwrap();
            assert!(
                c.request_within("LATE", "LATE", Duration::from_millis(50))
                    .is_err()
            );
            // The late reply is in the socket by now.
            std::thread::sleep(Duration::from_millis(400));
            let e = c.request("PING", "PING").unwrap_err().to_string();
            assert!(e.contains("an earlier reply never came"), "{e}");
            // A socket of its own is in step.
            let fresh = Ctrl::connect(&dir, &dir.join("global")).unwrap();
            assert_eq!(fresh.request("PING", "PING").unwrap().trim(), "PONG");
            let _ = std::fs::remove_dir_all(&dir);
        }

        /// A radio that cannot be opened: the port is handed out all the
        /// same, and its next `status` says why (the engine then drops it
        /// and tries again later).
        #[test]
        fn a_radio_that_cannot_be_opened_says_so_in_its_status() {
            let dir = temp("unopened");
            let name: IfName = "wlan7".parse().unwrap();
            let mut port =
                LinuxWifiPort::open_at(&name, dir.clone(), PathBuf::from("/nonexistent/wpa"))
                    .unwrap();
            until("the failure", || port.status().is_err());
            let e = port.status().unwrap_err().to_string();
            assert!(e.contains("cannot start /nonexistent/wpa"), "{e}");
            // Its thread is gone: an order says the same, and does not wait.
            until("the thread's end", || port.scan().is_err());
            let e = port.scan().unwrap_err().to_string();
            assert!(e.contains("cannot start /nonexistent/wpa"), "{e}");
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
        // G1.30g: 9999 is "no noise reading"; no CENTER_FRQ1 in this reply.
        assert_eq!(
            (st.noise_dbm, st.width_mhz, st.center_mhz),
            (None, Some(80), None)
        );
        assert_eq!(
            (st.generation, st.cipher.as_deref(), st.link.as_ref()),
            (Some(6), Some("CCMP"), None)
        );
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
    fn noise_width_centre_generation_and_cipher() {
        let status = "wpa_state=COMPLETED\nbssid=d8:47:32:aa:bb:cc\nfreq=5955\n\
                      wifi_generation=7\npairwise_cipher=GCMP-256\nkey_mgmt=SAE\n";
        // wpa_supplicant 2.12 prints these in this order.
        let signal = "RSSI=-61\nLINKSPEED=2882\nNOISE=-92\nFREQUENCY=5955\n\
                      WIDTH=320 MHz\nCENTER_FRQ1=6105\nAVG_RSSI=-60\n";
        let st = parse_status(status, Some(signal));
        assert_eq!(
            (st.noise_dbm, st.width_mhz, st.center_mhz, st.generation),
            (Some(-92), Some(320), Some(6105), Some(7))
        );
        assert_eq!(st.cipher.as_deref(), Some("GCMP-256"));
        for (text, want) in [
            ("20 MHz (no HT)", Some(20)),
            ("20 MHz", Some(20)),
            ("40 MHz", Some(40)),
            ("80+80 MHz", Some(160)),
            ("160 MHz", Some(160)),
            ("unknown", None),
            ("33 MHz", None),
            ("", None),
        ] {
            assert_eq!(width(text), want, "{text}");
        }
        // Not connected: none of it, whatever the replies say.
        let idle = parse_status(&status.replace("COMPLETED", "SCANNING"), Some(signal));
        assert_eq!(
            (idle.noise_dbm, idle.width_mhz, idle.center_mhz),
            (None, None, None)
        );
        assert_eq!((idle.generation, idle.cipher), (None, None));
        // Open network, legacy link, nonsense numbers.
        let open = parse_status(
            "wpa_state=COMPLETED\npairwise_cipher=NONE\nwifi_generation=9\n",
            Some("NOISE=12\nCENTER_FRQ1=-5\nWIDTH=80 MHz junk\n"),
        );
        assert_eq!(
            (open.noise_dbm, open.center_mhz, open.width_mhz),
            (None, None, None)
        );
        assert_eq!((open.generation, open.cipher), (None, None));
        let odd = parse_status(
            "wpa_state=COMPLETED\npairwise_cipher=CC\u{1b}MP\n",
            Some("NOISE=-9999\n"),
        );
        assert_eq!((odd.cipher, odd.noise_dbm), (None, None));
    }

    #[test]
    fn the_firmware_a_driver_announced() {
        for (line, key, version) in [
            (
                "rtw89_8852be 0000:c3:00.0: Firmware version 0.29.29.5 (af1ab4bf), cmd version 0, type 5",
                "0000:c3:00.0",
                "0.29.29.5",
            ),
            (
                "iwlwifi 0000:00:14.3: loaded firmware version 89.202a2f7b.0 so-a0-gf-a0-89.ucode op_mode iwlmvm",
                "0000:00:14.3",
                "89.202a2f7b.0",
            ),
            (
                "mt7921e 0000:01:00.0: WM Firmware Version: ____010000, Build Time: 20230526130958",
                "0000:01:00.0",
                "____010000",
            ),
            (
                "mt7921u 2-1:1.0: WM Firmware Version: ____010000, Build Time: 20230526130958",
                "2-1:1.0",
                "____010000",
            ),
            (
                "rtw_8822ce 0000:02:00.0: Firmware version 9.9.4, H2C version 15",
                "0000:02:00.0",
                "9.9.4",
            ),
            (
                "ath11k_pci 0000:03:00.0: fw_version 0x1106196e fw_build_timestamp 2024-01-12 11:24",
                "0000:03:00.0",
                "0x1106196e",
            ),
            (
                "ath10k_pci 0000:02:00.0: firmware ver WLAN.RM.4.4.1-00309- api 6 features wowlan",
                "0000:02:00.0",
                "WLAN.RM.4.4.1-00309-",
            ),
            ("somedrv: firmware version 1.2.3 loaded", "somedrv", "1.2.3"),
        ] {
            assert_eq!(
                firmware_line(line),
                Some((key.to_owned(), version.to_owned())),
                "{line}"
            );
        }
        for line in [
            "",
            "r8169 0000:05:00.0 eth0: link up",
            "mt7921e 0000:01:00.0: HW/SW Version: 0x8a108a10, Build Time: 20230526130917a",
            "rtw89_8852be 0000:c3:00.0: Firmware version ",
            "x 0000:c3:00.0: firmware version \u{1b}[31m",
        ] {
            assert_eq!(firmware_line(line), None, "{line}");
        }
        // A version past 48 characters, a device past 32: not taken.
        let long = format!("drv 0000:01:00.0: firmware version {}", "9".repeat(49));
        assert_eq!(firmware_line(&long), None);
        let dev = format!("drv {}: firmware version 1.0", "d".repeat(33));
        assert_eq!(firmware_line(&dev), None);
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
                prop_assert!(st.cipher.is_none_or(|c| c.len() <= 24));
                if let Some((key, version)) = firmware_line(t) {
                    prop_assert!(key.len() <= 32 && version.len() <= 48);
                }
                let _ = parse_event(t);
                let _ = bss_security(t);
                prop_assert!(unescape(t).len() <= MAX_SSID);
            }
        }
    }
}
