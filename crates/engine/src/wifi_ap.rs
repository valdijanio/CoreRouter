//! Wi-Fi access points at run time (G1.30a): what the running
//! configuration says each radio in `ap` mode announces, told to the
//! platform once per change, and what came of it (up, radar check, failed,
//! the clients).
//!
//! The channel and width are decided here, before the platform sees them
//! ([`plan`]): against what the radio reports for the country in force
//! (channels allowed, no-IR, radar, widest channel, the standards it
//! speaks), so that a channel an access point may not start on is refused
//! by the command, with the reason, instead of failing inside hostapd. The
//! same [`plan`] picks the channel when none is set: the quietest of the
//! last scan ([`crate::wifi_air::suggest`]), without radar detection.
//!
//! Per radio and per tick the work is one read of the platform's events;
//! the status (and the clients) every [`STATUS_EVERY_MS`]. Nothing here
//! grows with traffic, and the clients are at most
//! [`corerouter_hal::wifi_ap::MAX_CLIENTS`] per radio.

use corerouter_hal::wifi::WifiRadio;
use corerouter_hal::wifi_ap::{
    ApSecurity, ApState, WifiAp, WifiApEvent, WifiApPort, WifiApStatus, channel_block,
};
use corerouter_model::wifi::{AP_WIDTHS, WifiBand, WifiConfig, WifiSecurity};
use corerouter_model::{Config, IfName};

use crate::Session;
use crate::wifi::channel;

/// Before a radio whose port did not open is tried again.
const OPEN_RETRY_MS: u64 = 5_000;
/// How often an access point's state and clients are read.
pub(crate) const STATUS_EVERY_MS: u64 = 2_000;

/// What an access point will run on: decided from the configuration and
/// the radio.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    pub frequency_mhz: u32,
    pub width_mhz: u32,
    pub center_mhz: u32,
    /// Radar detection first (a DFS channel): 60 s before the first beacon,
    /// 10 min on the weather radar channels.
    pub radar: bool,
    /// The channel was chosen, not configured.
    pub auto: bool,
    pub ht: bool,
    pub vht: bool,
    pub he: bool,
}

/// The quietest channel the last scan found in a band, among the allowed
/// ones (MHz, radar).
pub type Suggest<'a> = dyn Fn(&'static str, &[(u32, bool)]) -> Option<u32> + 'a;

/// The radio's band of `name` (`2ghz`, `5ghz`, `6ghz`).
fn band_of<'a>(radio: &'a WifiRadio, name: &str) -> Option<&'a corerouter_hal::wifi::WifiBand> {
    radio.bands.iter().find(|b| b.band == name)
}

fn band_name(b: WifiBand) -> &'static str {
    b.as_str()
}

/// Where and how wide `st` (in `ap` mode) runs on `radio`, or why it
/// cannot. `radio` `None`: the hardware is not known yet (the radio has
/// not been opened): the configuration is taken as it is, with the usual
/// defaults. `suggested`: the quietest channel the last scan found, per
/// band (`crate::wifi_air::suggest`).
pub fn plan(
    st: &WifiConfig,
    radio: Option<&WifiRadio>,
    suggested: &Suggest<'_>,
) -> Result<Plan, String> {
    if radio.and_then(|r| r.ap) == Some(false) {
        return Err(format!(
            "this radio's driver ({}) has no access point mode",
            radio.and_then(|r| r.driver.as_deref()).unwrap_or("unknown")
        ));
    }
    let band = match (st.frequency, st.band) {
        (Some(f), _) => WifiBand::of_mhz(f)
            .ok_or_else(|| format!("{f} MHz is not in a Wi-Fi band (2.4, 5 or 6 GHz)"))?,
        (None, Some(b)) => b,
        // 5 GHz when the radio may start a network there (wider, quieter),
        // else 2.4.
        (None, None) => {
            let five = radio.is_none_or(|r| {
                band_of(r, "5ghz").is_some_and(|b| {
                    b.channels.iter().any(|c| !c.disabled && !c.no_ir && !c.radar)
                })
            });
            if five { WifiBand::Band5 } else { WifiBand::Band2 }
        }
    };
    if band == WifiBand::Band6 {
        return Err(
            "an access point on 6 GHz is not supported yet: use 2ghz or 5ghz".to_owned(),
        );
    }
    let five = band == WifiBand::Band5;
    let rb = match radio {
        Some(r) => Some(band_of(r, band_name(band)).ok_or_else(|| {
            format!("this radio has no {} band", if five { "5 GHz" } else { "2.4 GHz" })
        })?),
        None => None,
    };
    let speaks = |s: &str| rb.is_none_or(|b| b.standards.iter().any(|x| x == s));
    let (ht, vht, he) = (speaks("n"), five && speaks("ac"), speaks("ax") && rb.is_some());
    let max_width = rb.and_then(|b| b.max_width_mhz).unwrap_or(if five { 80 } else { 40 });
    // A channel an access point may start on: allowed in the country, not
    // passive (no-IR).
    let usable = |mhz: u32| -> Result<bool, String> {
        let Some(b) = rb else {
            return Ok(false);
        };
        let c = b.channels.iter().find(|c| c.mhz == mhz).ok_or_else(|| {
            format!(
                "channel {} ({mhz} MHz) is not one this radio has",
                channel(mhz).unwrap_or(0)
            )
        })?;
        if c.disabled {
            return Err(format!(
                "channel {} ({mhz} MHz) is not allowed in the country in force",
                channel(mhz).unwrap_or(0)
            ));
        }
        if c.no_ir {
            return Err(format!(
                "channel {} ({mhz} MHz) is passive in the country in force (no-IR): a station \
                 may answer there, an access point may not start",
                channel(mhz).unwrap_or(0)
            ));
        }
        Ok(c.radar)
    };
    let (frequency, auto) = match st.frequency {
        Some(f) => (f, false),
        None => {
            let allowed: Vec<(u32, bool)> = rb
                .map(|b| {
                    b.channels
                        .iter()
                        .filter(|c| !c.disabled && !c.no_ir && !c.radar)
                        .map(|c| (c.mhz, false))
                        .collect()
                })
                .unwrap_or_default();
            if rb.is_some() && allowed.is_empty() {
                return Err(format!(
                    "no channel of the {} band lets an access point start without radar \
                     detection in the country in force: set frequency (a DFS channel waits a \
                     minute for radar first)",
                    if five { "5 GHz" } else { "2.4 GHz" }
                ));
            }
            let pick = suggested(band_name(band), &allowed)
                .or_else(|| allowed.first().map(|(f, _)| *f))
                .unwrap_or(if five { 5180 } else { 2437 });
            (pick, true)
        }
    };
    let mut radar = usable(frequency)?;
    let wanted = match st.width {
        Some(w) if !AP_WIDTHS.contains(&w) => {
            return Err(format!("{w} MHz is not a channel width: use 20, 40, 80 or 160"));
        }
        Some(w) if w > max_width => {
            return Err(format!(
                "this radio goes up to {max_width} MHz on this band, not {w}"
            ));
        }
        Some(w) if w > 20 && !ht => {
            return Err("this radio has no 802.11n here: only 20 MHz".to_owned());
        }
        Some(w) if w >= 80 && !vht && !(five && he) => {
            return Err(format!("{w} MHz needs 802.11ac or ax on 5 GHz"));
        }
        Some(w) => vec![w],
        // The widest that fits, up to 80 MHz on 5 GHz (160 MHz halves the
        // channels and usually crosses radar channels); 20 on 2.4 GHz (40
        // there takes two of the three channels that do not overlap).
        None if five => [80, 40, 20]
            .into_iter()
            .filter(|w| *w <= max_width && (*w == 20 || (*w == 40 && ht) || vht || he))
            .collect(),
        None => vec![20],
    };
    let mut last = None;
    for w in &wanted {
        let Some(block) = channel_block(frequency, *w) else {
            last = Some(format!(
                "channel {} has no {w} MHz block",
                channel(frequency).unwrap_or(0)
            ));
            continue;
        };
        let mut r = radar;
        let mut bad = None;
        if rb.is_some() {
            for m in &block.members {
                match usable(*m) {
                    Ok(d) => r |= d,
                    Err(e) => {
                        bad = Some(format!("{w} MHz on channel {}: {e}", channel(frequency).unwrap_or(0)));
                        break;
                    }
                }
            }
        }
        // A width chosen for the operator stays clear of radar channels.
        if st.width.is_none() && auto && r {
            bad = Some("radar".into());
        }
        match bad {
            None => {
                radar = r;
                return Ok(Plan {
                    frequency_mhz: frequency,
                    width_mhz: *w,
                    center_mhz: block.center_mhz,
                    radar,
                    auto,
                    ht,
                    vht,
                    he,
                });
            }
            Some(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| "no channel width fits".to_owned()))
}

fn ap_security(s: WifiSecurity) -> ApSecurity {
    match s {
        WifiSecurity::Auto => ApSecurity::Wpa2Wpa3,
        WifiSecurity::Wpa3 => ApSecurity::Wpa3,
        WifiSecurity::Wpa2 => ApSecurity::Wpa2,
        WifiSecurity::Open => ApSecurity::Open,
    }
}

/// What an access point was last told: everything but the key in clear
/// (the sealed box stands for it).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Told {
    ssid: String,
    security: WifiSecurity,
    key_box: String,
    hidden: bool,
    plan: Plan,
    country: String,
    bridge: Option<IfName>,
}

/// One access point at run time.
#[derive(Default)]
pub(crate) struct ApRadio {
    port: Option<Box<dyn WifiApPort>>,
    retry_at: u64,
    told: Option<Told>,
    pub(crate) status: WifiApStatus,
    status_at: u64,
    /// Why the platform could not open the radio, take the settings, or
    /// start.
    pub(crate) error: Option<String>,
    /// What it runs on now (or would, when it starts).
    pub(crate) plan: Option<Plan>,
    pub(crate) up_since_ms: Option<u64>,
}

/// The suggestion of the last scan of radio `name`, per band.
pub(crate) fn suggestion(s: &Session, name: &IfName, band: &'static str, allowed: &[(u32, bool)]) -> Option<u32> {
    let r = s.wifi()?.radios.get(name)?;
    if r.scan.is_empty() {
        return None;
    }
    crate::wifi_air::suggest(band, &r.scan, &r.survey, allowed).map(|g| g.frequency_mhz)
}

impl Session {
    /// [`plan`] for radio `name` of `cfg`, with what this session knows of
    /// the radio and the last scan.
    pub(crate) fn wifi_ap_plan(&mut self, name: &IfName, st: &WifiConfig) -> Result<Plan, String> {
        // Read now: the channels depend on the country in force, which may
        // have changed since the radio was opened (a world domain makes
        // 5 GHz passive). One read costs 0.4 ms (G1.30g, measured).
        let hw = self.hal_mut().wifi_radio(name).or_else(|| {
            self.wifi()
                .and_then(|rt| rt.radios.get(name))
                .and_then(|r| r.hardware.clone())
        });
        // Kept for the commands that read it without the platform (the
        // preview of interface.wifi.set).
        if let (Some(h), Some(rt)) = (&hw, self.wifi_rt()) {
            rt.radios.entry(name.clone()).or_default().hardware = Some(h.clone());
        }
        let me: &Session = self;
        plan(st, hw.as_ref(), &|band, allowed| suggestion(me, name, band, allowed))
    }

    /// One radio in `ap` mode (or not: `want` `None` closes its access
    /// point).
    pub(crate) fn wifi_ap_step(&mut self, name: &IfName, want: Option<&WifiConfig>, now: u64) {
        let cfg: &Config = self.store().running();
        let country = cfg.system.wifi.country.map(|c| c.to_string());
        let bridge = cfg.interfaces.get(name).and_then(|i| i.bridge.clone());
        let mut notes: Vec<(&'static str, String)> = Vec::new();
        let Some(st) = want else {
            if let Some(mut r) = self.wifi_rt().and_then(|rt| rt.aps.remove(name))
                && let Some(p) = r.port.as_mut()
            {
                let _ = p.stop();
                if r.status.state == ApState::Running {
                    notes.push(("disconnected", "access point stopped".into()));
                }
            }
            self.wifi_notes(name, notes);
            return;
        };
        let Some(country) = country else { return };
        // 1. Open.
        let has_port = self
            .wifi_rt()
            .map(|rt| rt.aps.entry(name.clone()).or_default())
            .is_some_and(|r| r.port.is_some());
        if !has_port {
            let due = self
                .wifi()
                .and_then(|rt| rt.aps.get(name))
                .is_some_and(|r| r.retry_at <= now);
            if !due {
                return;
            }
            let opened = self.hal_mut().wifi_ap_port(name);
            let Some(r) = self.wifi_rt().and_then(|rt| rt.aps.get_mut(name)) else {
                return;
            };
            match opened {
                Ok(p) => {
                    r.port = Some(p);
                    r.told = None;
                    r.error = None;
                }
                Err(e) => {
                    let msg = e.to_string();
                    r.retry_at = now.saturating_add(OPEN_RETRY_MS);
                    if r.error.as_deref() != Some(msg.as_str()) {
                        notes.push(("error", format!("cannot open the access point: {msg}")));
                        r.error = Some(msg);
                    }
                    self.wifi_notes(name, notes);
                    return;
                }
            }
        }
        // 2. Tell it, once per change. The channel is planned again only
        // when the settings change: a chosen channel stays chosen.
        let same = self
            .wifi()
            .and_then(|rt| rt.aps.get(name))
            .and_then(|r| r.told.as_ref())
            .is_some_and(|t| {
                t.ssid == st.ssid
                    && t.security == st.security
                    && t.key_box == st.passphrase.stored()
                    && t.hidden == st.hidden
                    && t.country == country
                    && t.bridge == bridge
                    && (st.frequency.is_none() || st.frequency == Some(t.plan.frequency_mhz))
                    && st.width.is_none_or(|w| w == t.plan.width_mhz)
            });
        if !same {
            let planned = self.wifi_ap_plan(name, st);
            let key = if st.security.keyed() {
                crate::sealing::key(self).ok().and_then(|k| k.open(&st.passphrase))
            } else {
                Some(String::new())
            };
            let Some(r) = self.wifi_rt().and_then(|rt| rt.aps.get_mut(name)) else {
                return;
            };
            let (plan, key) = match (planned, key) {
                (Ok(p), Some(k)) => (p, k),
                (Err(e), _) => {
                    if r.error.as_deref() != Some(e.as_str()) {
                        notes.push(("error", format!("access point not started: {e}")));
                        r.error = Some(e);
                    }
                    self.wifi_notes(name, notes);
                    return;
                }
                (_, None) => {
                    let e = format!(
                        "the passphrase of '{name}' cannot be opened (the router's secret key \
                         changed): set it again with interface.wifi.set"
                    );
                    if r.error.as_deref() != Some(e.as_str()) {
                        notes.push(("error", e.clone()));
                        r.error = Some(e);
                    }
                    self.wifi_notes(name, notes);
                    return;
                }
            };
            let ap = WifiAp {
                ssid: st.ssid.clone(),
                security: ap_security(st.security),
                key,
                hidden: st.hidden,
                frequency_mhz: plan.frequency_mhz,
                width_mhz: plan.width_mhz,
                center_mhz: plan.center_mhz,
                country: country.clone(),
                bridge: bridge.as_ref().map(ToString::to_string),
                ht: plan.ht,
                vht: plan.vht,
                he: plan.he,
                radar: plan.radar,
            };
            let Some(p) = r.port.as_mut() else { return };
            match p.start(&ap) {
                Ok(()) => {
                    notes.push((
                        "joining",
                        format!(
                            "starting access point '{}' on channel {} ({} MHz, {} MHz wide{}{})",
                            st.ssid,
                            channel(plan.frequency_mhz).unwrap_or(0),
                            plan.frequency_mhz,
                            plan.width_mhz,
                            if plan.auto { ", chosen" } else { "" },
                            if plan.radar { ", radar check first" } else { "" }
                        ),
                    ));
                    r.told = Some(Told {
                        ssid: st.ssid.clone(),
                        security: st.security,
                        key_box: st.passphrase.stored().to_owned(),
                        hidden: st.hidden,
                        plan: plan.clone(),
                        country,
                        bridge,
                    });
                    r.plan = Some(plan);
                    r.error = None;
                    r.status_at = 0;
                    r.up_since_ms = None;
                }
                Err(e) => {
                    let e = e.to_string();
                    r.port = None;
                    r.retry_at = now.saturating_add(OPEN_RETRY_MS);
                    if r.error.as_deref() != Some(e.as_str()) {
                        notes.push(("error", e.clone()));
                        r.error = Some(e);
                    }
                    self.wifi_notes(name, notes);
                    return;
                }
            }
        }
        // 3. What happened.
        if let Some(r) = self.wifi_rt().and_then(|rt| rt.aps.get_mut(name)) {
            let events = r.port.as_mut().map(|p| p.events()).unwrap_or_default();
            let mut refresh = !events.is_empty();
            for e in events {
                match e {
                    WifiApEvent::Up => {
                        r.up_since_ms = Some(now);
                        r.error = None;
                        notes.push(("connected", "access point up".into()));
                    }
                    WifiApEvent::Down { reason } => {
                        r.up_since_ms = None;
                        notes.push(("disconnected", format!("access point down: {reason}")));
                    }
                    WifiApEvent::RadarCheck { secs } => notes.push((
                        "joining",
                        format!("listening for radar for {secs} s before the first beacon"),
                    )),
                    WifiApEvent::Radar { frequency_mhz } => notes.push((
                        "failed",
                        format!("radar heard on {frequency_mhz} MHz: the channel must be left"),
                    )),
                    WifiApEvent::Joined { mac } => notes.push(("client", format!("{mac} joined"))),
                    WifiApEvent::Left { mac } => notes.push(("client", format!("{mac} left"))),
                    WifiApEvent::Refused { mac, reason } => {
                        notes.push(("client", format!("{mac} refused: {reason}")));
                    }
                    WifiApEvent::Failed(why) => {
                        r.error = Some(why.clone());
                        notes.push(("failed", why));
                    }
                }
            }
            refresh |= now.saturating_sub(r.status_at) >= STATUS_EVERY_MS || r.status_at == 0;
            if refresh && let Some(p) = r.port.as_mut() {
                r.status_at = now.max(1);
                match p.status() {
                    Ok(st) => {
                        if st.state == ApState::Running && r.up_since_ms.is_none() {
                            r.up_since_ms = Some(now);
                        }
                        r.status = st;
                    }
                    Err(e) => {
                        let msg = e.to_string();
                        r.port = None;
                        r.told = None;
                        r.status = WifiApStatus::default();
                        r.up_since_ms = None;
                        r.retry_at = now.saturating_add(OPEN_RETRY_MS);
                        if r.error.as_deref() != Some(msg.as_str()) {
                            notes.push(("error", format!("the access point stopped answering: {msg}")));
                            r.error = Some(msg);
                        }
                    }
                }
            }
        }
        self.wifi_notes(name, notes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_hal::wifi::{WifiBand as HwBand, WifiChannel};

    fn radio() -> WifiRadio {
        let ch = |mhz: u32| WifiChannel {
            mhz,
            max_power_dbm: Some(20),
            radar: (5260..=5700).contains(&mhz),
            disabled: mhz == 5825,
            no_ir: matches!(mhz, 2467 | 2472 | 5745),
        };
        WifiRadio {
            ap: Some(true),
            bands: vec![
                HwBand {
                    band: "2ghz".into(),
                    standards: ["b", "g", "n", "ax"].map(String::from).to_vec(),
                    max_width_mhz: Some(40),
                    channels: (0..13).map(|i| ch(2412 + 5 * i)).collect(),
                },
                HwBand {
                    band: "5ghz".into(),
                    standards: ["a", "n", "ac", "ax"].map(String::from).to_vec(),
                    max_width_mhz: Some(160),
                    channels: [5180, 5200, 5220, 5240, 5260, 5280, 5300, 5320, 5745, 5765, 5785, 5805, 5825]
                        .into_iter()
                        .map(ch)
                        .collect(),
                },
            ],
            ..WifiRadio::default()
        }
    }

    fn ap(freq: Option<u32>, width: Option<u32>) -> WifiConfig {
        WifiConfig {
            mode: corerouter_model::wifi::WifiMode::Ap,
            ssid: "Loja".into(),
            frequency: freq,
            width,
            ..WifiConfig::default()
        }
    }

    fn none(_: &'static str, _: &[(u32, bool)]) -> Option<u32> {
        None
    }

    #[test]
    fn automatic_channel_and_width() {
        let r = radio();
        let p = plan(&ap(None, None), Some(&r), &none).unwrap();
        assert_eq!((p.frequency_mhz, p.width_mhz, p.center_mhz), (5180, 80, 5210));
        assert!(p.auto && !p.radar && p.vht && p.he);
        // The scan's suggestion wins.
        let quiet = |b: &'static str, _: &[(u32, bool)]| (b == "5ghz").then_some(5220);
        assert_eq!(plan(&ap(None, None), Some(&r), &quiet).unwrap().frequency_mhz, 5220);
        let mut two = ap(None, None);
        two.band = Some(WifiBand::Band2);
        let p = plan(&two, Some(&r), &none).unwrap();
        assert_eq!((p.frequency_mhz, p.width_mhz, p.vht), (2412, 20, false));
        // Without the hardware: the usual defaults.
        let p = plan(&ap(None, None), None, &none).unwrap();
        assert_eq!((p.frequency_mhz, p.width_mhz), (5180, 80));
    }

    #[test]
    fn what_the_radio_does_not_allow() {
        let r = radio();
        for (f, w, why) in [
            (Some(2467), None, "no-IR"),
            (Some(5825), None, "not allowed"),
            (Some(5181), None, "not one this radio has"),
            (Some(2412), Some(80), "up to 40"),
            (Some(5180), Some(30), "not a channel width"),
            // 149..161 has 149 (5745) passive.
            (Some(5765), Some(80), "no-IR"),
            (Some(5955), None, "6 GHz"),
        ] {
            let e = plan(&ap(f, w), Some(&r), &none).unwrap_err();
            assert!(e.contains(why), "{f:?} {w:?}: {e}");
        }
        let mut no_ap = radio();
        no_ap.ap = Some(false);
        assert!(plan(&ap(None, None), Some(&no_ap), &none).unwrap_err().contains("no access point"));
    }

    #[test]
    fn radar_channels_are_allowed_when_asked_for() {
        let r = radio();
        let p = plan(&ap(Some(5260), Some(80)), Some(&r), &none).unwrap();
        assert!(p.radar);
        assert_eq!(p.center_mhz, 5290);
        // 160 MHz on 36 crosses 52-64: radar too.
        let p = plan(&ap(Some(5180), Some(160)), Some(&r), &none).unwrap();
        assert!(p.radar && p.center_mhz == 5250);
    }
}
