//! A Wi-Fi radio as an access point on Linux (G1.30a): `hostapd` 2.12,
//! driven through its control sockets, with nothing written to a file.
//!
//! One `hostapd` serves every radio of the router, started with only its
//! global socket (`-g <runtime>/hostapd/global`). A radio joins it by a
//! dynamic `ADD <ifname> <ctrl dir> nl80211` (hostapd 2.12
//! `src/ap/hostapd.c` `hostapd_add_iface`: an interface with the defaults
//! and no configuration file), gets its settings one `SET` at a time on its
//! own socket (`hostapd/ctrl_iface.c` `hostapd_ctrl_iface_set` →
//! `hostapd_set_iface` → `hostapd_config_fill`, the same parser as the
//! file's) and starts with `ENABLE`. The passphrase goes in a `SET` and
//! nowhere else. A change of settings is `REMOVE` and a fresh `ADD`: no
//! field of the settings before survives into the new ones.
//!
//! As with the station (`crate::wifi`), nothing waits in the engine's
//! tick: each radio has a thread (`wifi-ap-<name>`) that is the only one to
//! talk to hostapd, with a bounded queue of orders.

use corerouter_hal::wifi_ap::{
    ApSecurity, ApState, MAX_AP_EVENTS, WifiAp, WifiApEvent, channel_block,
};

use crate::wifi::MAX_COMMAND;

/// IEEE 802.11: an SSID is at most 32 bytes.
const MAX_SSID: usize = 32;

/// The channel number of a centre frequency, MHz (IEEE 802.11-2020
/// §17.3.8.4.2 and §19.3.15: 2.4 GHz from 2407, 5 GHz from 5000).
fn channel_of(mhz: u32) -> Option<u32> {
    match mhz {
        2484 => Some(14),
        2412..=2472 if (mhz - 2407).is_multiple_of(5) => Some((mhz - 2407) / 5),
        5160..=5885 if mhz.is_multiple_of(5) => Some((mhz - 5000) / 5),
        _ => None,
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

/// A name hostapd can take as a bridge (an interface name).
fn ifname_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() < 16
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

/// The fields of `ap` as hostapd's `SET` takes them, in an order each
/// `SET` passes hostapd's check of the settings so far
/// (`hostapd_config_check` after every field). `None`: `ap` cannot be
/// written (a field hostapd would read differently, or a channel that is
/// not one): said before anything is sent.
pub(crate) fn ap_fields(ap: &WifiAp) -> Option<Vec<(&'static str, String)>> {
    let ssid = ap.ssid.as_bytes();
    if ssid.is_empty() || ssid.len() > MAX_SSID {
        return None;
    }
    let country = ap.country.as_bytes();
    if country.len() != 2 || !country.iter().all(u8::is_ascii_uppercase) {
        return None;
    }
    let channel = channel_of(ap.frequency_mhz)?;
    let five = ap.frequency_mhz >= 5000;
    let block = channel_block(ap.frequency_mhz, ap.width_mhz)?;
    let mut f: Vec<(&'static str, String)> = vec![
        ("country_code", ap.country.clone()),
        // hostapd: ieee80211h needs ieee80211d (the country element).
        ("ieee80211d", "1".into()),
    ];
    if ap.radar {
        // IEEE 802.11h: radar detection and transmit power control.
        f.push(("ieee80211h", "1".into()));
    }
    f.push(("hw_mode", if five { "a" } else { "g" }.into()));
    f.push(("channel", channel.to_string()));
    // HT and later need WMM (QoS).
    f.push(("wmm_enabled", "1".into()));
    if ap.ht {
        f.push(("ieee80211n", "1".into()));
        match block.above {
            Some(true) => f.push(("ht_capab", "[HT40+]".into())),
            Some(false) => f.push(("ht_capab", "[HT40-]".into())),
            None => {}
        }
    } else if ap.width_mhz > 20 {
        return None;
    }
    // VHT and HE operating widths: 0 is 20 or 40 MHz (HT says which), 1
    // is 80, 2 is 160 (hostapd.conf `vht_oper_chwidth`).
    let oper = match ap.width_mhz {
        80 => Some(1),
        160 => Some(2),
        _ => None,
    };
    if five && ap.vht {
        f.push(("ieee80211ac", "1".into()));
        if let Some(w) = oper {
            f.push(("vht_oper_chwidth", w.to_string()));
            f.push((
                "vht_oper_centr_freq_seg0_idx",
                channel_of(block.center_mhz)?.to_string(),
            ));
        }
    } else if oper.is_some() && !ap.he {
        return None;
    }
    if ap.he {
        f.push(("ieee80211ax", "1".into()));
        if five && let Some(w) = oper {
            f.push(("he_oper_chwidth", w.to_string()));
            f.push((
                "he_oper_centr_freq_seg0_idx",
                channel_of(block.center_mhz)?.to_string(),
            ));
        }
    }
    // `ssid2` in hex: any byte, nothing for the text protocol to read.
    f.push(("ssid2", hex(ssid)));
    if ap.hidden {
        f.push(("ignore_broadcast_ssid", "1".into()));
    }
    // Open system authentication (SAE has its own).
    f.push(("auth_algs", "1".into()));
    let key = ap.key.as_str();
    let hex_key = key.len() == 64 && key.bytes().all(|b| b.is_ascii_hexdigit());
    let passphrase =
        (8..=63).contains(&key.len()) && key.bytes().all(|b| (0x20..=0x7e).contains(&b));
    let (mgmt, mfp) = match ap.security {
        ApSecurity::Open => {
            if !key.is_empty() {
                return None;
            }
            ("", None)
        }
        // SAE proves knowledge of the passphrase itself.
        ApSecurity::Wpa3 | ApSecurity::Wpa2Wpa3 if !passphrase => return None,
        ApSecurity::Wpa2 if !(passphrase || hex_key) => return None,
        // IEEE 802.11-2020 §12.6.3: WPA3 requires management frame
        // protection; the transition mode offers it (WPA3-Personal
        // specification v3.2 §2.4), and so does WPA2 here.
        ApSecurity::Wpa3 => ("SAE", Some("2")),
        ApSecurity::Wpa2Wpa3 => ("WPA-PSK SAE", Some("1")),
        ApSecurity::Wpa2 => ("WPA-PSK", Some("1")),
    };
    if !mgmt.is_empty() {
        if hex_key {
            f.push(("wpa_psk", key.to_ascii_lowercase()));
        } else {
            f.push(("wpa_passphrase", key.to_owned()));
        }
        if let Some(w) = mfp {
            f.push(("ieee80211w", w.into()));
        }
        if mgmt.contains("SAE") {
            // Both ways to the SAE password element (H2E is what WPA3-only
            // and 6 GHz clients ask for).
            f.push(("sae_pwe", "2".into()));
        }
        if ap.security == ApSecurity::Wpa2Wpa3 {
            // A WPA3 client of a transition network uses MFP.
            f.push(("sae_require_mfp", "1".into()));
        }
        f.push(("rsn_pairwise", "CCMP".into()));
        f.push(("wpa_key_mgmt", mgmt.into()));
        f.push(("wpa", "2".into()));
    }
    if let Some(b) = &ap.bridge {
        if !ifname_ok(b) {
            return None;
        }
        f.push(("bridge", b.clone()));
    }
    let fits = f
        .iter()
        .all(|(k, v)| k.len() + v.len() + 8 < MAX_COMMAND && !v.contains(['\n', '\r', '\0']));
    fits.then_some(f)
}

/// The fields whose value is a secret: an error names them, never their
/// value.
pub(crate) const SECRET_FIELDS: [&str; 2] = ["wpa_passphrase", "wpa_psk"];

fn mac_of(text: &str) -> Option<String> {
    let t = text.trim();
    let ok = t.len() == 17
        && t.split(':').count() == 6
        && t.split(':')
            .all(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_hexdigit()));
    ok.then(|| t.to_ascii_lowercase())
}

fn kv<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    text.split_whitespace()
        .find_map(|w| w.strip_prefix(key).and_then(|v| v.strip_prefix('=')))
}

/// One event line of hostapd's monitor socket (`<3>AP-STA-CONNECTED
/// 02:00:00:00:01:00`), in the engine's terms; `None`: not one it uses.
/// Names from hostapd 2.12 `src/common/wpa_ctrl.h`.
pub(crate) fn parse_event(line: &str) -> Option<WifiApEvent> {
    // `<level>` first.
    let body = line.trim().split_once('>').map_or(line.trim(), |(_, b)| b);
    let (name, rest) = body.split_once(' ').unwrap_or((body, ""));
    match name {
        "AP-ENABLED" => Some(WifiApEvent::Up),
        "AP-DISABLED" => Some(WifiApEvent::Down {
            reason: "the access point stopped".into(),
        }),
        "INTERFACE-DISABLED" => Some(WifiApEvent::Down {
            reason: "the radio went down (driver, rfkill or the interface removed)".into(),
        }),
        "AP-STA-CONNECTED" => Some(WifiApEvent::Joined {
            mac: mac_of(rest.split_whitespace().next()?)?,
        }),
        "AP-STA-DISCONNECTED" => Some(WifiApEvent::Left {
            mac: mac_of(rest.split_whitespace().next()?)?,
        }),
        // The 4-way handshake failed on the client's MIC: its passphrase
        // is not this one (hostapd `wpa_auth.c`, `wpa_receive`).
        "AP-STA-POSSIBLE-PSK-MISMATCH" => Some(WifiApEvent::Refused {
            mac: mac_of(rest.split_whitespace().next()?)?,
            reason: "wrong passphrase on the client".into(),
        }),
        "DFS-CAC-START" => Some(WifiApEvent::RadarCheck {
            secs: kv(rest, "cac_time")
                .and_then(|v| v.trim_end_matches('s').parse().ok())
                .unwrap_or(60),
        }),
        "DFS-RADAR-DETECTED" => Some(WifiApEvent::Radar {
            frequency_mhz: kv(rest, "freq").and_then(|v| v.parse().ok()).unwrap_or(0),
        }),
        _ => None,
    }
}

/// hostapd's `STATUS` of an interface: where it is, its channel, the
/// radar check left (hostapd 2.12 `src/ap/ctrl_iface_ap.c`
/// `hostapd_ctrl_iface_status`, `hostapd_state_text`).
pub(crate) fn parse_status(reply: &str) -> (ApState, Option<u32>, Option<u32>) {
    let mut state = ApState::Starting;
    let (mut freq, mut cac) = (None, None);
    for line in reply.lines() {
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        match k {
            "state" => {
                state = match v.trim() {
                    "ENABLED" => ApState::Running,
                    "DFS" => ApState::RadarCheck,
                    "NO_IR" => ApState::NoIr,
                    "DISABLED" => ApState::Stopped,
                    _ => ApState::Starting,
                }
            }
            "freq" => freq = v.trim().parse().ok().filter(|f| *f > 0),
            "cac_time_left_seconds" => cac = v.trim().parse().ok(),
            _ => {}
        }
    }
    (state, freq, cac)
}

/// One `STA` reply: the MAC (first line), whether it is authorized, what
/// it joined with and the generation it speaks (hostapd 2.12
/// `hostapd_ctrl_iface_sta_mib`: `flags=[AUTH][ASSOC][AUTHORIZED][HT]…`,
/// and `wpa_get_mib_sta`: `AKMSuiteSelector=000fac-8`).
pub(crate) fn parse_sta(reply: &str) -> Option<(String, bool, Option<String>, Option<u8>)> {
    let mut lines = reply.lines();
    let mac = mac_of(lines.next()?)?;
    let (mut authorized, mut security, mut generation) = (false, None, None);
    for line in lines {
        if let Some(flags) = line.strip_prefix("flags=") {
            authorized = flags.contains("[AUTHORIZED]");
            generation = if flags.contains("[EHT]") {
                Some(7)
            } else if flags.contains("[HE]") {
                Some(6)
            } else if flags.contains("[VHT]") {
                Some(5)
            } else if flags.contains("[HT]") {
                Some(4)
            } else {
                None
            };
        } else if let Some(akm) = line.strip_prefix("AKMSuiteSelector=") {
            // IEEE 802.11-2020 Table 9-151: 2 PSK, 6 PSK-SHA256, 8 SAE,
            // 24 SAE with any group.
            security = match akm.trim().rsplit('-').next() {
                Some("8" | "24") => Some("wpa3".to_owned()),
                Some("2" | "6") => Some("wpa2".to_owned()),
                _ => None,
            };
        }
    }
    if security.is_none() && authorized {
        security = Some("open".into());
    }
    Some((mac, authorized, security, generation))
}

fn push(events: &mut Vec<WifiApEvent>, e: WifiApEvent) {
    if events.len() < MAX_AP_EVENTS {
        events.push(e);
    }
}

#[cfg(target_os = "linux")]
pub use io::LinuxWifiApPort;

#[cfg(target_os = "linux")]
mod io {
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::{Arc, Mutex, PoisonError, mpsc};
    use std::time::{Duration, Instant};

    use corerouter_hal::HalError;
    use corerouter_hal::wifi::WifiLink;
    use corerouter_hal::wifi_ap::{
        ApState, MAX_AP_EVENTS, MAX_CLIENTS, WifiAp, WifiApEvent, WifiApPort, WifiApStatus,
        WifiClient,
    };
    use corerouter_model::IfName;

    use super::{SECRET_FIELDS, ap_fields, parse_event, parse_sta, parse_status, push};
    use crate::nl80211::Nl80211;
    use crate::wifi::{Ctrl, runtime_dir, turn_of, unblock};

    const WHO: &str = "hostapd";
    const DEFAULT_BINARY: &str = "/usr/sbin/hostapd";
    /// How long a hostapd just started gets to open its socket.
    const START_TIMEOUT: Duration = Duration::from_secs(2);
    /// `ADD` and `ENABLE` wait for the driver: the interface changes type
    /// and comes up, and on a card that may load firmware (seconds; see
    /// `crate::wifi`, `ADD_TIMEOUT`).
    const ENABLE_TIMEOUT: Duration = Duration::from_secs(20);
    const POLL: Duration = Duration::from_millis(100);
    const STATUS_EVERY: Duration = Duration::from_secs(1);
    const MAX_ORDERS: usize = 8;

    fn binary() -> PathBuf {
        std::env::var_os("COREROUTER_HOSTAPD")
            .filter(|b| !b.is_empty())
            .map_or_else(|| PathBuf::from(DEFAULT_BINARY), PathBuf::from)
    }

    /// Held while an interface goes into hostapd or the last one leaves
    /// (and hostapd is ended): one radio's thread must not end hostapd
    /// while another's is adding to it.
    static HOSTAPD: Mutex<()> = Mutex::new(());

    /// End hostapd when it has no interface left (as the supplicant ends
    /// with its last radio): each interface has its socket in `if/`.
    fn end_if_idle(dir: &Path) {
        let busy = std::fs::read_dir(dir.join("if")).map_or(true, |mut d| d.next().is_some());
        if busy {
            return;
        }
        let Some(pid) = std::fs::read_to_string(dir.join("hostapd.pid"))
            .ok()
            .and_then(|p| p.trim().parse::<i32>().ok())
            .filter(|p| *p > 1)
        else {
            return;
        };
        // Only if that pid is hostapd still.
        let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
        if comm.trim() == "hostapd" {
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::from_raw(pid),
                nix::sys::signal::Signal::SIGTERM,
            );
            let _ = std::fs::remove_file(dir.join("global"));
        }
    }

    fn io_err(what: &str, e: impl std::fmt::Display) -> HalError {
        HalError::Io(format!("hostapd: {what}: {e}"))
    }

    /// hostapd's global socket, with hostapd started if it is not there.
    fn global(dir: &Path, bin: &Path) -> Result<Ctrl, HalError> {
        let sock = dir.join("global");
        let ping = |c: &Ctrl| c.request("PING", "PING").is_ok_and(|r| r.trim() == "PONG");
        if let Ok(c) = Ctrl::connect_as(WHO, dir, &sock)
            && ping(&c)
        {
            return Ok(c);
        }
        let _ = std::fs::remove_file(&sock);
        // `-B`: it forks; from then on it is PID 1's child and outlives a
        // restart of this daemon with the access points still up. No `-d`,
        // `-f` or `-s`: its log would carry the values of `SET`.
        let status = Command::new(bin)
            .arg("-B")
            .arg("-g")
            .arg(&sock)
            .arg("-P")
            .arg(dir.join("hostapd.pid"))
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
            if let Ok(c) = Ctrl::connect_as(WHO, dir, &sock)
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

    /// The station side lets go of the radio: an interface in
    /// wpa_supplicant (a daemon restarted after the mode changed) would
    /// fight hostapd over it.
    fn leave_supplicant(name: &str) {
        let Ok(dir) = runtime_dir("wpa") else {
            return;
        };
        let sock = dir.join("global");
        if !sock.exists() {
            return;
        }
        if let Ok(c) = Ctrl::connect_as("wpa_supplicant", &dir, &sock) {
            let _ = c.request(&format!("INTERFACE_REMOVE {name}"), "INTERFACE_REMOVE");
        }
    }

    /// One radio in hostapd; only the radio's thread has one.
    struct Direct {
        name: String,
        dir: PathBuf,
        binary: PathBuf,
        /// The interface's own sockets while it is in hostapd.
        socks: Option<(Ctrl, Ctrl)>,
        queued: Vec<WifiApEvent>,
        nl: Option<Nl80211>,
        error: Option<String>,
        told: Option<WifiAp>,
    }

    impl Direct {
        fn new(name: &IfName, dir: PathBuf, binary: PathBuf) -> Self {
            Self {
                name: name.to_string(),
                dir,
                binary,
                socks: None,
                queued: Vec::new(),
                nl: None,
                error: None,
                told: None,
            }
        }

        /// Take the interface out of hostapd (its clients leave).
        fn remove(&mut self) -> Result<(), HalError> {
            self.socks = None;
            if !self.dir.join("global").exists() {
                return Ok(());
            }
            let global = global(&self.dir, &self.binary)?;
            // `FAIL` when it is not there: nothing to remove.
            let _ = global.request(&format!("REMOVE {}", self.name), "REMOVE")?;
            Ok(())
        }

        /// [`remove`](Self::remove), and hostapd ended if it was the last.
        fn leave(&mut self) -> Result<(), HalError> {
            let _one = HOSTAPD.lock().unwrap_or_else(PoisonError::into_inner);
            let done = self.remove();
            end_if_idle(&self.dir);
            done
        }

        fn start(&mut self, ap: &WifiAp) -> Result<(), HalError> {
            let fields = ap_fields(ap).ok_or_else(|| {
                HalError::Rejected("the access point cannot be written for hostapd".into())
            })?;
            self.told = Some(ap.clone());
            self.error = None;
            leave_supplicant(&self.name);
            unblock(&self.name);
            let ifaces = self.dir.join("if");
            {
                let _one = HOSTAPD.lock().unwrap_or_else(PoisonError::into_inner);
                self.remove()?;
                let global = global(&self.dir, &self.binary)?;
                // <ifname> <ctrl dir> <driver>: an interface with the
                // defaults and no file (hostapd_add_iface).
                global.ok_within(
                    &format!("ADD {} {} nl80211", self.name, ifaces.display()),
                    "the radio (ADD)",
                    ENABLE_TIMEOUT,
                )?;
            }
            let sock = ifaces.join(&self.name);
            let cmd = Ctrl::connect_as(WHO, &self.dir, &sock)
                .map_err(|e| io_err("the radio's socket", e))?;
            let events = Ctrl::connect_as(WHO, &self.dir, &sock)
                .map_err(|e| io_err("the radio's socket", e))?;
            events.ok("ATTACH", "ATTACH")?;
            for (field, value) in fields {
                let what = if SECRET_FIELDS.contains(&field) {
                    "the passphrase"
                } else {
                    field
                };
                cmd.ok(&format!("SET {field} {value}"), what)?;
            }
            let enabled = cmd.ok_within("ENABLE", "ENABLE", ENABLE_TIMEOUT);
            self.socks = Some((cmd, events));
            if let Err(e) = enabled {
                let why = match e {
                    HalError::Rejected(_) => format!(
                        "hostapd would not start the access point on {} MHz, {} MHz wide: the \
                         driver refused the channel, the width or the mode",
                        ap.frequency_mhz, ap.width_mhz
                    ),
                    other => other.to_string(),
                };
                self.error = Some(why.clone());
                push(&mut self.queued, WifiApEvent::Failed(why));
            }
            Ok(())
        }

        /// The clients: who is there from hostapd, the link from nl80211.
        fn clients(&mut self) -> Result<Vec<WifiClient>, HalError> {
            let Some((cmd, _)) = &self.socks else {
                return Ok(Vec::new());
            };
            let mut out: Vec<WifiClient> = Vec::new();
            let mut reply = cmd.request("STA-FIRST", "STA-FIRST")?;
            while out.len() < MAX_CLIENTS {
                let Some((mac, authorized, security, generation)) = parse_sta(&reply) else {
                    break;
                };
                reply = cmd.request(&format!("STA-NEXT {mac}"), "STA-NEXT")?;
                out.push(WifiClient {
                    mac,
                    authorized,
                    security,
                    generation,
                    link: WifiLink::default(),
                });
            }
            if !out.is_empty()
                && let Ok(ifindex) = nix::net::if_::if_nametoindex(self.name.as_str())
            {
                if self.nl.is_none() {
                    self.nl = Nl80211::open();
                }
                let links = match self.nl.as_mut().map(|nl| nl.stations(ifindex)) {
                    Some(Ok(l)) => l,
                    Some(Err(e)) => {
                        log::debug!("wifi {}: nl80211 stations: {e}", self.name);
                        self.nl = None;
                        Vec::new()
                    }
                    None => Vec::new(),
                };
                for c in &mut out {
                    if let Some((_, l)) = links.iter().find(|(m, _)| *m == c.mac) {
                        c.link = l.clone();
                    }
                }
            }
            out.sort_by_key(|c| std::cmp::Reverse(c.link.signal_avg_dbm.unwrap_or(-200)));
            Ok(out)
        }

        fn status(&mut self) -> Result<WifiApStatus, HalError> {
            let Some((cmd, _)) = &self.socks else {
                return Ok(WifiApStatus {
                    state: if self.error.is_some() {
                        ApState::Failed
                    } else {
                        ApState::Stopped
                    },
                    error: self.error.clone(),
                    ..WifiApStatus::default()
                });
            };
            let (mut state, freq, cac) = parse_status(&cmd.request("STATUS", "STATUS")?);
            if self.error.is_some() && state != ApState::Running {
                state = ApState::Failed;
            }
            let clients = if state == ApState::Running {
                self.clients()?
            } else {
                Vec::new()
            };
            Ok(WifiApStatus {
                state,
                frequency_mhz: freq,
                width_mhz: self.told.as_ref().map(|t| t.width_mhz),
                radar_check_secs: cac,
                error: self.error.clone(),
                clients,
            })
        }

        fn events(&mut self) -> Vec<WifiApEvent> {
            let mut out = std::mem::take(&mut self.queued);
            if let Some((_, ev)) = &self.socks {
                let room = MAX_AP_EVENTS.saturating_sub(out.len());
                out.extend(ev.pending(room).iter().filter_map(|l| parse_event(l)));
            }
            for e in &out {
                if let WifiApEvent::Up = e {
                    self.error = None;
                }
                if let WifiApEvent::Radar { frequency_mhz } = e {
                    self.error = Some(format!(
                        "radar heard on {frequency_mhz} MHz: the channel is closed for 30 minutes \
                         (choose another, or a channel without radar detection)"
                    ));
                }
            }
            out
        }
    }

    impl Drop for Direct {
        /// The radio leaves hostapd. Not at a daemon's exit (nothing is
        /// dropped then): the access point stays up across a restart.
        fn drop(&mut self) {
            if self.socks.is_some() || self.told.is_some() {
                let _ = self.leave();
            }
        }
    }

    #[derive(Default)]
    struct Seen {
        status: WifiApStatus,
        events: Vec<WifiApEvent>,
        failed: Option<String>,
    }

    enum Order {
        Start(Box<WifiAp>),
        Stop,
    }

    /// One radio as the engine holds it; nothing here waits (see
    /// `crate::wifi::LinuxWifiPort`).
    pub struct LinuxWifiApPort {
        orders: mpsc::SyncSender<Order>,
        seen: Arc<Mutex<Seen>>,
    }

    fn seen(s: &Mutex<Seen>) -> std::sync::MutexGuard<'_, Seen> {
        s.lock().unwrap_or_else(PoisonError::into_inner)
    }

    impl LinuxWifiApPort {
        pub fn open(name: &IfName) -> Result<Self, HalError> {
            let dir = runtime_dir("hostapd")?;
            let (orders, rx) = mpsc::sync_channel(MAX_ORDERS);
            let shared = Arc::new(Mutex::new(Seen::default()));
            let (theirs, radio, bin) = (Arc::clone(&shared), name.clone(), binary());
            std::thread::Builder::new()
                .name(format!("wifi-ap-{radio}"))
                .spawn(move || run(&radio, dir, bin, &rx, &theirs))
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

    impl WifiApPort for LinuxWifiApPort {
        fn start(&mut self, ap: &WifiAp) -> Result<(), HalError> {
            if ap_fields(ap).is_none() {
                return Err(HalError::Rejected(
                    "the access point cannot be written for hostapd".into(),
                ));
            }
            self.order(Order::Start(Box::new(ap.clone())), "the access point")
        }

        fn stop(&mut self) -> Result<(), HalError> {
            self.order(Order::Stop, "stopping")
        }

        fn status(&mut self) -> Result<WifiApStatus, HalError> {
            let s = seen(&self.seen);
            match &s.failed {
                Some(why) => Err(HalError::Io(why.clone())),
                None => Ok(s.status.clone()),
            }
        }

        fn events(&mut self) -> Vec<WifiApEvent> {
            std::mem::take(&mut seen(&self.seen).events)
        }
    }

    /// The radio's thread: takes the orders and keeps [`Seen`] current
    /// until the port is dropped or hostapd stops answering.
    fn run(
        name: &IfName,
        dir: PathBuf,
        binary: PathBuf,
        orders: &mpsc::Receiver<Order>,
        shared: &Mutex<Seen>,
    ) {
        let fail = |e: HalError| seen(shared).failed = Some(e.to_string());
        // One thread per radio at a time, station or access point (the
        // same turn as `crate::wifi`): the one before lets go first.
        let turn = turn_of(name.as_str());
        let _mine = turn.lock().unwrap_or_else(PoisonError::into_inner);
        let mut port = Direct::new(name, dir, binary);
        let mut status_at: Option<Instant> = None;
        loop {
            let done = match orders.recv_timeout(POLL) {
                Ok(Order::Start(ap)) => port.start(&ap),
                Ok(Order::Stop) => {
                    port.told = None;
                    port.error = None;
                    port.leave()
                }
                Err(mpsc::RecvTimeoutError::Timeout) => Ok(()),
                Err(mpsc::RecvTimeoutError::Disconnected) => return,
            };
            let mut events = Vec::new();
            match done {
                Ok(()) => {}
                Err(HalError::Rejected(why)) => {
                    port.error = Some(why.clone());
                    events.push(WifiApEvent::Failed(why));
                }
                Err(e) => return fail(e),
            }
            events.extend(port.events());
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
            if status.is_none() && events.is_empty() {
                continue;
            }
            let mut s = seen(shared);
            if let Some(st) = status {
                s.status = st;
            }
            let room = MAX_AP_EVENTS.saturating_sub(s.events.len());
            s.events.extend(events.into_iter().take(room));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ap(security: ApSecurity, key: &str, mhz: u32, width: u32) -> WifiAp {
        WifiAp {
            ssid: "Loja ç".into(),
            security,
            key: key.into(),
            hidden: false,
            frequency_mhz: mhz,
            width_mhz: width,
            center_mhz: mhz,
            country: "BR".into(),
            bridge: Some("bridge1".into()),
            ht: true,
            vht: true,
            he: true,
            radar: false,
        }
    }

    fn value<'a>(f: &'a [(&'static str, String)], k: &str) -> Option<&'a str> {
        f.iter().find(|(n, _)| *n == k).map(|(_, v)| v.as_str())
    }

    #[test]
    fn an_access_point_as_hostapd_takes_it() {
        let f = ap_fields(&ap(ApSecurity::Wpa2Wpa3, "senha-boa-123", 5200, 80)).unwrap();
        assert_eq!(value(&f, "hw_mode"), Some("a"));
        assert_eq!(value(&f, "channel"), Some("40"));
        // 40 is the upper of 36/40; the 80 MHz block 36-48 is centred on 42.
        assert_eq!(value(&f, "ht_capab"), Some("[HT40-]"));
        assert_eq!(value(&f, "vht_oper_chwidth"), Some("1"));
        assert_eq!(value(&f, "vht_oper_centr_freq_seg0_idx"), Some("42"));
        assert_eq!(value(&f, "he_oper_centr_freq_seg0_idx"), Some("42"));
        assert_eq!(value(&f, "wpa_key_mgmt"), Some("WPA-PSK SAE"));
        assert_eq!(value(&f, "ieee80211w"), Some("1"));
        assert_eq!(value(&f, "sae_pwe"), Some("2"));
        assert_eq!(value(&f, "country_code"), Some("BR"));
        assert_eq!(value(&f, "bridge"), Some("bridge1"));
        // The SSID in hex, bytes and all.
        assert_eq!(value(&f, "ssid2"), Some("4c6f6a6120c3a7"));
        // ieee80211d before ieee80211h; the passphrase before the AKM.
        let at = |k: &str| f.iter().position(|(n, _)| *n == k).unwrap();
        assert!(at("wpa_passphrase") < at("wpa_key_mgmt"));
        assert!(at("wpa_key_mgmt") < at("wpa"));

        let f = ap_fields(&ap(ApSecurity::Wpa3, "senha-boa-123", 2412, 40)).unwrap();
        assert_eq!(value(&f, "hw_mode"), Some("g"));
        assert_eq!(value(&f, "ht_capab"), Some("[HT40+]"));
        assert_eq!(value(&f, "ieee80211ac"), None, "no VHT on 2.4 GHz");
        assert_eq!(value(&f, "wpa_key_mgmt"), Some("SAE"));
        assert_eq!(value(&f, "ieee80211w"), Some("2"));

        let mut a = ap(ApSecurity::Wpa2, &"ab".repeat(32), 5260, 20);
        a.radar = true;
        a.hidden = true;
        let f = ap_fields(&a).unwrap();
        assert_eq!(value(&f, "wpa_psk").map(str::len), Some(64));
        assert_eq!(value(&f, "wpa_passphrase"), None);
        assert_eq!(value(&f, "ieee80211h"), Some("1"));
        assert_eq!(value(&f, "ignore_broadcast_ssid"), Some("1"));
        assert_eq!(value(&f, "ht_capab"), None);

        let f = ap_fields(&ap(ApSecurity::Open, "", 2437, 20)).unwrap();
        assert_eq!(value(&f, "wpa"), None);
    }

    #[test]
    fn what_hostapd_is_not_given() {
        for bad in [
            ap(ApSecurity::Wpa3, &"ab".repeat(32), 5180, 20), // SAE needs the passphrase
            ap(ApSecurity::Wpa2, "short", 5180, 20),
            ap(ApSecurity::Open, "a-key-given", 5180, 20),
            ap(ApSecurity::Wpa2, "senha-boa-123", 5181, 20), // not a channel
            ap(ApSecurity::Wpa2, "senha-boa-123", 2437, 80), // no 80 on 2.4
            ap(ApSecurity::Wpa2, "senha-boa-123", 2484, 40),
        ] {
            assert!(ap_fields(&bad).is_none(), "{bad:?}");
        }
        let mut a = ap(ApSecurity::Wpa2, "senha-boa-123", 5180, 20);
        a.ssid = "x".repeat(33);
        assert!(ap_fields(&a).is_none());
        let mut a = ap(ApSecurity::Wpa2, "senha\nboa-123", 5180, 20);
        assert!(ap_fields(&a).is_none());
        a.key = "senha-boa-123".into();
        a.bridge = Some("br 0".into());
        assert!(ap_fields(&a).is_none());
        a.bridge = None;
        a.country = "br".into();
        assert!(ap_fields(&a).is_none());
    }

    #[test]
    fn events_in_words() {
        assert_eq!(parse_event("<3>AP-ENABLED "), Some(WifiApEvent::Up));
        assert_eq!(
            parse_event("<3>AP-STA-CONNECTED 02:00:00:00:01:00 keyid=x"),
            Some(WifiApEvent::Joined {
                mac: "02:00:00:00:01:00".into()
            })
        );
        assert_eq!(
            parse_event("<3>AP-STA-DISCONNECTED 02:00:00:00:01:0A"),
            Some(WifiApEvent::Left {
                mac: "02:00:00:00:01:0a".into()
            })
        );
        assert!(matches!(
            parse_event("<3>AP-STA-POSSIBLE-PSK-MISMATCH 02:00:00:00:01:00"),
            Some(WifiApEvent::Refused { .. })
        ));
        assert_eq!(
            parse_event(
                "<3>DFS-CAC-START freq=5260 chan=52 sec_chan=0, width=0, seg0=0, seg1=0, cac_time=60s"
            ),
            Some(WifiApEvent::RadarCheck { secs: 60 })
        );
        assert_eq!(
            parse_event(
                "<3>DFS-RADAR-DETECTED success=1 freq=5260 ht_enabled=1 chan_offset=0 chan_width=1 cf1=5260 cf2=0"
            ),
            Some(WifiApEvent::Radar {
                frequency_mhz: 5260
            })
        );
        assert_eq!(parse_event("<3>AP-STA-CONNECTED garbage"), None);
        assert_eq!(parse_event("<2>WPS-SOMETHING"), None);
    }

    #[test]
    fn status_and_stations() {
        let (s, f, c) = parse_status("state=ENABLED\nphy=phy0\nfreq=5180\nnum_sta[0]=2\n");
        assert_eq!((s, f, c), (ApState::Running, Some(5180), None));
        let (s, _, c) = parse_status("state=DFS\nfreq=5260\ncac_time_left_seconds=42\n");
        assert_eq!((s, c), (ApState::RadarCheck, Some(42)));
        assert_eq!(parse_status("state=NO_IR\n").0, ApState::NoIr);
        assert_eq!(parse_status("state=HT_SCAN\n").0, ApState::Starting);

        let sta = "02:00:00:00:01:00\nflags=[AUTH][ASSOC][AUTHORIZED][WMM][MFP][HT][VHT][HE]\n\
                   aid=1\nAKMSuiteSelector=000fac-8\nsignal=-31\n";
        assert_eq!(
            parse_sta(sta),
            Some((
                "02:00:00:00:01:00".into(),
                true,
                Some("wpa3".into()),
                Some(6)
            ))
        );
        let sta = "02:00:00:00:02:00\nflags=[AUTH][ASSOC][WMM][HT]\nAKMSuiteSelector=000fac-2\n";
        assert_eq!(
            parse_sta(sta),
            Some((
                "02:00:00:00:02:00".into(),
                false,
                Some("wpa2".into()),
                Some(4)
            ))
        );
        // The end of STA-NEXT: an empty reply, or FAIL.
        assert_eq!(parse_sta(""), None);
        assert_eq!(parse_sta("FAIL\n"), None);
    }
}
