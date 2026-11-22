//! /interface wifi (G1.30): a Wi-Fi radio in station mode, the router as a
//! client of a network (management, or an uplink). The interface is there
//! because the card is (`interface.wifi.adopt`, run by the tick, like an
//! Ethernet port's); these commands say which network it joins and show
//! what came of it. Names are RouterOS v7's `/interface/wifi` (`ssid`,
//! `passphrase`, `country`, `scan`); the radio itself runs in
//! `crate::wifi`.
//!
//! What the commands refuse, so that the mistake is not made:
//! - an interface is not enabled without a country (the validation, at the
//!   commit): in the world domain a radio may not transmit on 5 GHz at all,
//!   and with the wrong country it transmits where it must not;
//! - changing the network of the radio this connection comes through needs
//!   Safe Mode (losing the connection undoes it) or `force`;
//! - a station is never a bridge port (`interface.bridge.port.add`).

use corerouter_hal::wifi::{BssSecurity, WifiState};
use corerouter_model::sealed::Sealed;
use corerouter_model::wifi::{
    BridgeProtocol, Country, StationBridge, WifiBand, WifiConfig, WifiMode, WifiSecurity,
    passphrase_problem, ssid_problem,
};
use corerouter_model::{Config, IfName, Interface, InterfaceKind, MacAddr};
use serde_json::{Value, json};

use super::args::{opt_bool, opt_str, opt_text, opt_u32, req_parse, req_str};
use super::ethernet::guard_link;
use super::interface::refuse_unmanaged;
use super::{CommandSpec, always};
use crate::wifi::channel;
use crate::{EngineError, Result, Session};

/// IEEE 802.11: the largest frame body.
const MAX_MTU: u32 = 2304;
const MIN_MTU: u32 = 68;
/// A passphrase or a 64-digit key: nothing longer is looked at.
const MAX_KEY: usize = 64;

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(
        "interface.wifi.set",
        "Set Wi-Fi",
        ["Interfaces", "Wi-Fi"],
        None,
        "{name: string, mode?: string (station | ap | station-bridge; ap: announce the network instead of joining it, G1.30a; station-bridge: a client with four-address frames, a bridge port and bonding slave, G1.30m), bridge_protocol?: string (station-bridge: multi-ap | wds; multi-ap: Wi-Fi EasyMesh backhaul, between CoreRouters; wds: plain four addresses, for OpenWrt), station_bridge?: string (access point: no | yes | only; takes the registered peers, interface.wifi.peer.add; only: no plain clients), ssid?: string (the network's name, 1 to 32 bytes; empty: forget the network), security?: string (auto | wpa3 | wpa2 | open; auto: WPA3 if the access point offers it, else WPA2; as an access point, both at once), passphrase?: string (write-only, sealed at rest: 8 to 63 characters, or the 64-digit key with security=wpa2; another ssid needs its own), hidden?: bool (the network does not announce its name), band?: string (2ghz | 5ghz | 6ghz; empty or any: whichever the network is on; as an access point, the band of an automatic channel), bssid?: string (only this access point; empty: any; station only), frequency?: string (access point: MHz (5180), a channel (36) or auto: the quietest channel without radar detection), width?: string (access point: 20 | 40 | 80 | 160 MHz or auto: 20 on 2.4 GHz, up to 80 on 5 GHz), disabled?: bool (default true: a radio is off until it is told to join a network), comment?: string, mtu?: int (68..=2304), force?: bool (change the network or the mode of the radio this connection comes through, outside Safe Mode)} → {name, warnings}",
        has_radios,
        set
    ),
    cmd!(
        "interface.wifi.enable",
        "Enable Wi-Fi",
        [],
        None,
        "{name: string} → {name}",
        has_radios,
        enable
    ),
    cmd!(
        "interface.wifi.disable",
        "Disable Wi-Fi",
        [],
        None,
        "{name: string, force?: bool (the radio this connection comes through, outside Safe Mode)} → {name, warnings}",
        has_radios,
        disable
    ),
    cmd!(
        "interface.wifi.reconnect",
        "Reconnect Wi-Fi",
        [],
        None,
        "{name: string, force?: bool (the radio this connection comes through, outside Safe Mode)} → {name, warnings}",
        has_radios,
        reconnect
    ),
    cmd!(
        "interface.wifi.adopt",
        "Adopt Wi-Fi Radio",
        [],
        None,
        "{name: string (a Wi-Fi radio the router has and the configuration does not)} → {name, mtu, mac, disabled}",
        always,
        adopt
    )
    .positional("name"),
    cmd!(
        "interface.wifi.country.set",
        "Set Wi-Fi Country",
        [],
        None,
        "{country: string (ISO 3166-1, two letters: BR, US, DE; empty: none, with every Wi-Fi interface disabled)} → {country}",
        always,
        country_set
    )
    .positional("country"),
    cmd!(query "interface.wifi.country.get", "Wi-Fi Country", [], None,
        "{} → {country, in_force (what the kernel applies now; 00: the world domain), error, enabled (Wi-Fi interfaces that need it)}",
        always, country_get),
    cmd!(query "interface.wifi.list", "Wi-Fi", ["Interfaces", "Wi-Fi"], None,
        "{show_sensitive?: bool (the passphrases in clear; group full)} → [{name, mode (station | ap), ssid, security, passphrase, hidden, band, bssid, mtu, mac_address, disabled, comment, running, state (disabled | no-country | idle | searching | connecting | connected | blocked | error | absent; access point: starting | radar-check | no-ir | running | failed), connected_bssid, frequency, channel, signal, rate, failure, driver, bridge_protocol (G1.30m), station_bridge (G1.30m), configured_frequency, configured_width, width (access point), clients (access point)}]",
        always, list),
    cmd!(query "interface.wifi.monitor", "Wi-Fi Monitor", [], None,
        "{name: string} → {name, mode (ap: an access point's own fields: width, center_frequency, auto_channel, radar, radar_check_secs, standard, uptime_secs, clients, error), state, ssid, bssid, frequency, band, channel, signal, rate, security, pmf, uptime_secs, reconnects, failure: {code (wrong-key | not-found | rejected | no-answer | error), text, time}, error, country, country_in_force, country_error, driver, self_managed, quality (excellent | good | fair | poor), noise, snr, width, center_frequency, generation, standard, cipher, tx_rate: {mbps, mode, mcs, nss, width, guard_ns, text}, rx_rate: {mbps, mode, mcs, nss, width, guard_ns, text}, signal_avg, beacon_signal, chain_signal: [int], tx_packets, rx_packets, tx_retries, tx_failed, retry_percent, beacon_loss, inactive_ms, addresses: [{address, dynamic}]}",
        has_radios, monitor),
    cmd!(query "interface.wifi.radio", "Wi-Fi Radio", [], None,
        "{name: string} → {name, phy, driver, firmware, self_managed, blocked (soft | hard | null), standards: [string], bands: [{band (2ghz | 5ghz | 6ghz), standards: [string], max_width, allowed, dfs, max_power, channels: [{mhz, channel, max_power, radar, disabled}]}], antennas_tx, antennas_rx, tx_power, max_tx_power (here, on the channel in use), frequency, country, country_in_force}",
        has_radios, radio),
    cmd!(query "interface.wifi.scan", "Wi-Fi Scan", [], None,
        "{name: string} → {name, scanning} (the networks: interface.wifi.networks, a few seconds later)",
        has_radios, scan),
    cmd!(query "interface.wifi.networks", "Wi-Fi Networks", [], None,
        "{name: string} → {name, scanning, age_secs, error, networks: [{ssid (empty: hidden), bssid, signal, frequency, band, channel, security (open | owe | legacy | wpa2 | wpa2-wpa3 | wpa3 | enterprise), joinable, why_not, connected, width, center_frequency, center_frequency2, low, high, generation, stations, utilization (%), same_channel, overlaps: [int], contenders: [bssid], contention (same-channel | covered | overlap)}], suggested: [{band, channel, frequency, networks, score (%), dfs}]}",
        has_radios, networks),
    cmd!(query "interface.wifi.history", "Wi-Fi History", [], None,
        "{name?: string, limit?: int (newest first, default 100)} → [{seq, time, name, event (joining | connected | disconnected | failed | blocked | unblocked | error), message}]",
        always, history),
    cmd!(query "interface.wifi.preview", "Wi-Fi Preview", [], None,
        "{id: string (the radio), mode?: string, frequency?: string, width?: string, bridge_protocol?: string, station_bridge?: string, ssid?: string, security?: string, passphrase?: string, hidden?: bool, band?: string, bssid?: string, disabled?: bool, comment?: string, mtu?: int 68..2304} → {computed: [{label, value}], checks: [{level, check, message, param}], commands: [{command, params}], risk}",
        has_radios, preview),
];

fn radios(cfg: &Config) -> impl Iterator<Item = (&IfName, &Interface, &WifiConfig)> {
    cfg.interfaces.iter().filter_map(|(n, i)| match &i.kind {
        InterfaceKind::Wifi(st) => Some((n, i, &**st)),
        _ => None,
    })
}

pub(super) fn has_radios(s: &Session) -> std::result::Result<(), String> {
    if radios(s.store().candidate()).next().is_none() {
        Err("this router has no Wi-Fi radio".into())
    } else {
        Ok(())
    }
}

pub(super) fn radio_of<'a>(cfg: &'a Config, name: &IfName) -> Result<(&'a Interface, &'a WifiConfig)> {
    match cfg.interfaces.get(name) {
        Some(i) => match &i.kind {
            InterfaceKind::Wifi(st) => Ok((i, st)),
            k => Err(EngineError::bad(
                "name",
                format!("'{name}' is a {}, not a Wi-Fi interface", k.label()),
            )),
        },
        None => Err(EngineError::bad(
            "name",
            format!("no Wi-Fi interface '{name}' (see interface.wifi.list)"),
        )),
    }
}

fn seal(s: &mut Session, key: &str) -> Result<Sealed> {
    let k = crate::sealing::key(s).map_err(EngineError::Internal)?;
    k.seal(key).map_err(EngineError::Internal)
}

fn set(s: &mut Session, p: &Value) -> Result<Value> {
    refuse_unmanaged(s, p, &["name"])?;
    let name: IfName = req_parse(p, "name")?;
    let force = opt_bool(p, "force")?.unwrap_or(false);
    let cfg = s.store().candidate();
    let (iface, old) = radio_of(cfg, &name)?;
    let was_off = iface.disabled;
    let mut st = old.clone();
    let old = old.clone();

    if let Some(ssid) = opt_text(p, "ssid", 4 * corerouter_model::wifi::MAX_SSID)? {
        if ssid.is_empty() {
            // Forget the network, and its passphrase with it.
            st.ssid.clear();
            st.passphrase = Sealed::default();
        } else if let Some(why) = ssid_problem(&ssid) {
            return Err(EngineError::bad("ssid", why));
        } else {
            // Another network: the passphrase of the one before is not its
            // own. Kept, it gave "probably a wrong passphrase" minutes
            // later instead of "needs its passphrase" now.
            if ssid != st.ssid {
                st.passphrase = Sealed::default();
            }
            st.ssid = ssid;
        }
    }
    if let Some(sec) = opt_str(p, "security")? {
        st.security = WifiSecurity::parse(sec.trim()).ok_or_else(|| {
            EngineError::bad(
                "security",
                format!(
                    "'{}' is not a security: use auto, wpa3, wpa2 or open",
                    sec.chars().take(16).collect::<String>()
                ),
            )
        })?;
    }
    if let Some(h) = opt_bool(p, "hidden")? {
        st.hidden = h;
    }
    if let Some(b) = opt_str(p, "band")? {
        let b = b.trim();
        st.band = if b.is_empty() || b == "any" {
            None
        } else {
            Some(WifiBand::parse(b).ok_or_else(|| {
                EngineError::bad(
                    "band",
                    format!(
                        "'{}' is not a band: use 2ghz, 5ghz, 6ghz or any",
                        b.chars().take(16).collect::<String>()
                    ),
                )
            })?)
        };
    }
    if let Some(b) = opt_str(p, "bssid")? {
        let b = b.trim();
        st.bssid = if b.is_empty() {
            None
        } else {
            Some(b.parse::<MacAddr>().map_err(|e| EngineError::bad("bssid", e.to_string()))?)
        };
    }
    // G1.30a: the mode and an access point's channel.
    if let Some(m) = opt_str(p, "mode")? {
        st.mode = WifiMode::parse(m.trim()).ok_or_else(|| {
            EngineError::bad(
                "mode",
                format!(
                    "'{}' is not a mode: use station, ap or station-bridge",
                    m.chars().take(16).collect::<String>()
                ),
            )
        })?;
    }
    // G1.30m: a station-bridge's protocol, an access point's peers.
    if let Some(b) = opt_str(p, "bridge_protocol")? {
        st.bridge_protocol = BridgeProtocol::parse(b.trim()).ok_or_else(|| {
            EngineError::bad(
                "bridge_protocol",
                format!(
                    "'{}' is not a bridge protocol: use multi-ap or wds",
                    b.chars().take(16).collect::<String>()
                ),
            )
        })?;
    }
    if let Some(b) = opt_str(p, "station_bridge")? {
        st.station_bridge = StationBridge::parse(b.trim()).ok_or_else(|| {
            EngineError::bad(
                "station_bridge",
                format!(
                    "'{}' is not a choice: use no, yes or only",
                    b.chars().take(16).collect::<String>()
                ),
            )
        })?;
    }
    if let Some(f) = super::wifi_ap::parse_frequency(p)? {
        st.frequency = f;
    }
    if let Some(w) = super::wifi_ap::parse_width(p)? {
        st.width = w;
    }
    let mtu = match opt_u32(p, "mtu")? {
        Some(m) if (MIN_MTU..=MAX_MTU).contains(&m) => u16::try_from(m).ok(),
        Some(m) => {
            return Err(EngineError::bad(
                "mtu",
                format!("{m} is out of range: {MIN_MTU}..={MAX_MTU}"),
            ));
        }
        None => None,
    };
    let comment = opt_text(p, "comment", 256)?;
    let disabled = opt_bool(p, "disabled")?;

    // The passphrase, against the security it will be used with.
    let given = opt_str(p, "passphrase")?;
    if let Some(k) = given {
        if k.len() > MAX_KEY {
            return Err(EngineError::bad(
                "passphrase",
                format!("the passphrase has {} characters; WPA takes 8 to 63", k.len()),
            ));
        }
        if k.is_empty() {
            st.passphrase = Sealed::default();
        } else if let Some(why) = passphrase_problem(k, st.security) {
            return Err(EngineError::bad("passphrase", why));
        }
    }
    if !st.security.keyed() {
        st.passphrase = Sealed::default();
    }
    if let Some(k) = given.filter(|k| !k.is_empty() && st.security.keyed()) {
        st.passphrase = seal(s, k)?;
    } else if st.security.keyed() && st.security != old.security && !st.passphrase.is_empty() {
        // The stored one against the new security (a 64-digit key and WPA3).
        let key = crate::sealing::key(s).map_err(EngineError::Internal)?;
        if let Some(why) = key
            .open(&st.passphrase)
            .and_then(|k| passphrase_problem(&k, st.security))
        {
            return Err(EngineError::bad("security", why));
        }
    }
    if !st.ssid.is_empty() && st.security.keyed() && st.passphrase.is_empty() {
        return Err(EngineError::bad(
            "passphrase",
            format!(
                "network '{}' needs its passphrase (or security=open, if it has none)",
                st.ssid
            ),
        ));
    }
    // No country, no radio: the validation says so at the commit, so that
    // a batch (an import) may set the two in any order.
    let off = disabled.unwrap_or(was_off);

    // G1.30a: what the radio can do as an access point, and what changing
    // the mode means.
    let iface_now = iface_of(s, &name)?;
    let mut warnings = super::wifi_ap::check(s, &name, &iface_now, &st, old.mode)?;
    // Losing the network this connection comes through.
    let cuts = (!was_off && off) || (!was_off && st != old);
    if cuts
        && let Some(w) = guard_link(
            s,
            &name,
            force,
            "changing its network, or turning it off, cuts this connection if the new settings \
             do not work",
        )?
    {
        warnings.push(w);
    }
    if !st.ssid.is_empty() && st.security == WifiSecurity::Open {
        warnings.push(format!(
            "'{}' is an open network: anybody in range reads the traffic that is not encrypted \
             by itself",
            st.ssid
        ));
    }
    if st.security == WifiSecurity::Wpa2 && st.security != old.security {
        warnings.push(
            "security=wpa2 never uses WPA3, even if the access point offers it; auto does".into(),
        );
    }
    // A network the last scan heard only with a security a station does
    // not join (802.1X, OWE, WEP): typed by hand it would end in "not
    // found", which says nothing of why. The scan knows why.
    if let Some(why) = unjoinable(s, &name, &st.ssid) {
        warnings.push(format!(
            "'{}' was heard only as a network this radio cannot join: {why}",
            st.ssid
        ));
    }
    let cfg = s.store_mut().candidate_mut();
    let Some(iface) = cfg.interfaces.get_mut(&name) else {
        return Err(EngineError::bad("name", format!("no Wi-Fi interface '{name}'")));
    };
    iface.disabled = off;
    if let Some(m) = mtu {
        iface.mtu = m;
    }
    if let Some(c) = comment {
        iface.comment = c;
    }
    iface.kind = InterfaceKind::Wifi(Box::new(st));
    Ok(json!({ "name": name, "warnings": warnings }))
}

fn iface_of(s: &Session, name: &IfName) -> Result<Interface> {
    radio_of(s.store().candidate(), name).map(|(i, _)| i.clone())
}

fn enable(s: &mut Session, p: &Value) -> Result<Value> {
    let name: IfName = req_parse(p, "name")?;
    radio_of(s.store().candidate(), &name)?;
    if let Some(i) = s.store_mut().candidate_mut().interfaces.get_mut(&name) {
        i.disabled = false;
    }
    Ok(json!({ "name": name }))
}

fn disable(s: &mut Session, p: &Value) -> Result<Value> {
    let name: IfName = req_parse(p, "name")?;
    let force = opt_bool(p, "force")?.unwrap_or(false);
    let (iface, _) = radio_of(s.store().candidate(), &name)?;
    let mut warnings = Vec::new();
    if !iface.disabled
        && let Some(w) = guard_link(s, &name, force, "turning it off cuts this connection")?
    {
        warnings.push(w);
    }
    if let Some(i) = s.store_mut().candidate_mut().interfaces.get_mut(&name) {
        i.disabled = true;
    }
    Ok(json!({ "name": name, "warnings": warnings }))
}

fn reconnect(s: &mut Session, p: &Value) -> Result<Value> {
    let name: IfName = req_parse(p, "name")?;
    let force = opt_bool(p, "force")?.unwrap_or(false);
    let (iface, st) = radio_of(s.store().running(), &name)?;
    if iface.disabled || st.ssid.is_empty() {
        return Err(EngineError::bad(
            "name",
            format!("'{name}' is not joining a network (disabled, or no ssid set)"),
        ));
    }
    let mut warnings = Vec::new();
    if let Some(w) = guard_link(s, &name, force, "reconnecting drops it for a few seconds")? {
        warnings.push(w);
    }
    if !s.wifi_rejoin(&name) {
        return Err(EngineError::bad(
            "name",
            format!("the radio of '{name}' is not running yet: try again in a moment"),
        ));
    }
    Ok(json!({ "name": name, "warnings": warnings }))
}

fn adopt(s: &mut Session, p: &Value) -> Result<Value> {
    let name: IfName = req_parse(p, "name")?;
    if s.store().candidate().interfaces.contains_key(&name) {
        return Err(EngineError::bad(
            "name",
            format!("'{name}' is in the configuration already"),
        ));
    }
    let links = s
        .hal_mut()
        .discover_links()
        .map_err(|e| EngineError::Hal(e.to_string()))?;
    let link = links
        .into_iter()
        .find(|l| l.name == name && l.wifi)
        .ok_or_else(|| {
            EngineError::bad(
                "name",
                format!("'{name}' is not a Wi-Fi radio this router has (see interface.list)"),
            )
        })?;
    let mut iface = Interface::new(name.clone(), InterfaceKind::Wifi(Box::default()));
    iface.mtu = link.mtu;
    iface.mac = link.mac.as_deref().and_then(|m| m.parse().ok());
    // As the kernel has it (down, on a card nobody set up): applying the
    // adoption changes nothing. Without a country it cannot be up at all.
    iface.disabled = !link.up || s.store().candidate().system.wifi.country.is_none();
    let out = json!({
        "name": name,
        "mtu": iface.mtu,
        "mac": iface.mac.map(|m| m.to_string()),
        "disabled": iface.disabled,
    });
    s.store_mut().candidate_mut().interfaces.insert(name, iface);
    Ok(out)
}

fn country_set(s: &mut Session, p: &Value) -> Result<Value> {
    let text = req_str(p, "country")?.trim();
    let country = if text.is_empty() || text.eq_ignore_ascii_case("none") {
        None
    } else {
        Some(text.parse::<Country>().map_err(|e| EngineError::bad("country", e))?)
    };
    let cfg = s.store().candidate();
    if country.is_none() {
        let on: Vec<&str> = radios(cfg)
            .filter(|(_, i, _)| !i.disabled)
            .map(|(n, _, _)| n.as_str())
            .collect();
        if !on.is_empty() {
            return Err(EngineError::bad(
                "country",
                format!(
                    "{} cannot run without a country: disable it first (interface.wifi.disable)",
                    on.join(", ")
                ),
            ));
        }
    }
    s.store_mut().candidate_mut().system.wifi.country = country;
    Ok(json!({ "country": country.map(|c| c.to_string()) }))
}

fn country_get(s: &mut Session, _: &Value) -> Result<Value> {
    let cfg = s.store().candidate();
    let enabled: Vec<String> = radios(cfg)
        .filter(|(_, i, _)| !i.disabled)
        .map(|(n, _, _)| n.to_string())
        .collect();
    let country = cfg.system.wifi.country.map(|c| c.to_string());
    let in_force = s.hal_mut().wifi_regdomain();
    Ok(json!({
        "country": country,
        "in_force": in_force,
        "error": s.wifi().and_then(|rt| rt.country_error.clone()),
        "enabled": enabled,
    }))
}

/// The state word of a radio, for the list and the monitor.
fn state_of(s: &Session, cfg: &Config, name: &IfName, iface: &Interface, present: bool) -> &'static str {
    if !present {
        return "absent";
    }
    if iface.disabled {
        return "disabled";
    }
    if cfg.system.wifi.country.is_none() {
        return "no-country";
    }
    if matches!(&iface.kind, InterfaceKind::Wifi(st) if st.mode == WifiMode::Ap) {
        return super::wifi_ap::ap_state(s, name);
    }
    match s.wifi().and_then(|rt| rt.radios.get(name)) {
        Some(r) if r.error.is_some() => "error",
        // With no network to look for, the supplicant's own scans (after a
        // change of country, say) are not a search for anything: the
        // radio read "searching" for good, with nothing configured
        // (seen on the image, 2026-11-11).
        Some(r)
            if matches!(r.status.state, WifiState::Searching | WifiState::Connecting)
                && !matches!(&iface.kind, InterfaceKind::Wifi(st) if !st.ssid.is_empty()) =>
        {
            WifiState::Idle.as_str()
        }
        Some(r) => r.status.state.as_str(),
        None => WifiState::Idle.as_str(),
    }
}

pub(super) fn band_of(mhz: Option<u32>) -> Option<&'static str> {
    mhz.and_then(WifiBand::of_mhz).map(WifiBand::as_str)
}

fn list(s: &mut Session, p: &Value) -> Result<Value> {
    // Whoever reads a passphrase joins the network: group full only.
    let key = if opt_bool(p, "show_sensitive")?.unwrap_or(false) {
        s.permit(crate::auth::Group::Full)
            .map_err(|reason| EngineError::Denied {
                id: "interface.wifi.list".into(),
                reason: format!("show_sensitive: {reason}"),
            })?;
        Some(crate::sealing::key(s).map_err(EngineError::Internal)?)
    } else {
        None
    };
    let (rows, _) = super::interface::typed(s, |k| matches!(k, InterfaceKind::Wifi(_)));
    let cfg = s.store().candidate();
    let out: Vec<Value> = rows
        .into_iter()
        .filter_map(|(i, live)| {
            let InterfaceKind::Wifi(st) = &i.kind else {
                return None;
            };
            let r = s.wifi().and_then(|rt| rt.radios.get(&i.name));
            let status = r.map(|r| &r.status);
            let pw = match &key {
                Some(k) => Value::from(k.open(&st.passphrase).unwrap_or_default()),
                None if st.passphrase.is_empty() => Value::from(""),
                None => Value::from("***"),
            };
            let mac = live
                .as_ref()
                .and_then(|l| l.mac.clone())
                .or_else(|| i.mac.map(|m| m.to_string()));
            let frequency = status.and_then(|st| st.frequency_mhz);
            let mut row = json!({
                "name": i.name,
                "mode": st.mode.as_str(),
                "ssid": st.ssid,
                "security": st.security.as_str(),
                "passphrase": pw,
                "hidden": st.hidden,
                "band": st.band.map(WifiBand::as_str),
                "bssid": st.bssid.map(|m| m.to_string()),
                "mtu": i.mtu,
                "mac_address": mac,
                "disabled": i.disabled,
                "comment": i.comment,
                "running": live.as_ref().is_some_and(|l| l.running),
                "state": state_of(s, cfg, &i.name, &i, live.is_some()),
                "connected_bssid": status.and_then(|st| st.bssid.clone()),
                "frequency": frequency,
                "channel": frequency.and_then(channel),
                "signal": status.and_then(|st| st.signal_dbm),
                "rate": status.and_then(|st| st.rate_mbps),
                "failure": r.and_then(|r| r.failure.as_ref()).map(|(f, _)| f.code()),
                "driver": r.and_then(|r| r.hardware.as_ref()).and_then(|h| h.driver.clone()),
                "bridge_protocol": st.bridge_protocol.as_str(),
                "station_bridge": st.station_bridge.as_str(),
                "configured_frequency": st.frequency,
                "configured_width": st.width,
                "width": Value::Null,
                "clients": Value::Null,
            });
            // G1.30a: an access point's channel and clients.
            if st.mode == WifiMode::Ap
                && let (Value::Object(o), Value::Object(ap)) =
                    (&mut row, super::wifi_ap::list_fields(s, &i.name))
            {
                o.extend(ap);
            }
            Some(row)
        })
        .collect();
    Ok(Value::Array(out))
}

fn monitor(s: &mut Session, p: &Value) -> Result<Value> {
    let name: IfName = req_parse(p, "name")?;
    let live = s.hal_mut().poll();
    let present = live.iter().any(|l| l.name == name);
    let in_force = s.hal_mut().wifi_regdomain();
    let cfg = s.store().candidate();
    let (iface, st) = radio_of(cfg, &name)?;
    // G1.30a: an access point has its own.
    if st.mode == WifiMode::Ap {
        let mut out = super::wifi_ap::monitor(s, &name, st);
        let mac = live
            .iter()
            .find(|l| l.name == name)
            .and_then(|l| l.mac.clone())
            .or_else(|| iface.mac.map(|m| m.to_string()));
        let driver = s
            .wifi()
            .and_then(|rt| rt.radios.get(&name))
            .and_then(|r| r.hardware.as_ref())
            .and_then(|h| h.driver.clone());
        if let Value::Object(o) = &mut out {
            // An access point's BSSID is its radio's MAC.
            o.insert("bssid".into(), json!(mac));
            o.insert("driver".into(), json!(driver));
            o.insert("name".into(), json!(name));
            o.insert("state".into(), json!(state_of(s, cfg, &name, iface, present)));
            o.insert("country".into(), json!(cfg.system.wifi.country.map(|c| c.to_string())));
            o.insert("country_in_force".into(), json!(in_force));
            o.insert("addresses".into(), addresses_on(s, &name));
        }
        return Ok(out);
    }
    let rt = s.wifi();
    let now = rt.map_or(0, |rt| rt.now_ms);
    let r = rt.and_then(|rt| rt.radios.get(&name));
    let status = r.map(|r| &r.status);
    let frequency = status.and_then(|st| st.frequency_mhz);
    let mut out = json!({
        "name": name,
        "state": state_of(s, cfg, &name, iface, present),
        "ssid": status.and_then(|x| x.ssid.clone()).or_else(|| (!st.ssid.is_empty()).then(|| st.ssid.clone())),
        "bssid": status.and_then(|x| x.bssid.clone()),
        "frequency": frequency,
        "band": band_of(frequency),
        "channel": frequency.and_then(channel),
        "signal": status.and_then(|x| x.signal_dbm),
        "rate": status.and_then(|x| x.rate_mbps),
        "security": status.and_then(|x| x.security.clone()),
        "pmf": status.and_then(|x| x.pmf),
        "uptime_secs": r.and_then(|r| r.connected_since_ms).map(|t| now.saturating_sub(t) / 1000),
        "reconnects": r.map_or(0, |r| r.reconnects),
        "failure": r.and_then(|r| r.failure.as_ref()).map(|(f, time)| json!({
            "code": f.code(), "text": f.text(), "time": time,
        })),
        "error": r.and_then(|r| r.error.clone()),
        "country": cfg.system.wifi.country.map(|c| c.to_string()),
        "country_in_force": in_force,
        "country_error": rt.and_then(|rt| rt.country_error.clone()),
        "driver": r.and_then(|r| r.hardware.as_ref()).and_then(|h| h.driver.clone()),
        "self_managed": r.and_then(|r| r.hardware.as_ref()).map(|h| h.self_managed),
    });
    // G1.30g: the link in detail, for the Wi-Fi tab of "Interface <name>".
    if let (Value::Object(o), Some(st)) = (&mut out, status) {
        let connected = st.state == corerouter_hal::wifi::WifiState::Connected;
        let link = st.link.as_ref().filter(|_| connected);
        let signal = st.signal_dbm.filter(|_| connected);
        let noise = st.noise_dbm.filter(|_| connected);
        let tx_packets = link.and_then(|l| l.tx_packets);
        let retries = link.and_then(|l| l.tx_retries);
        let detail = json!({
            "quality": signal.map(quality),
            "noise": noise,
            "snr": signal.zip(noise).map(|(s, n)| s - n),
            "width": st.width_mhz.filter(|_| connected),
            "center_frequency": st.center_mhz.filter(|_| connected),
            "generation": st.generation.filter(|_| connected),
            "standard": st.generation.filter(|_| connected).and_then(standard_of),
            "cipher": st.cipher.clone().filter(|_| connected),
            "tx_rate": link.and_then(|l| l.tx.as_ref()).map(rate_json),
            "rx_rate": link.and_then(|l| l.rx.as_ref()).map(rate_json),
            "signal_avg": link.and_then(|l| l.signal_avg_dbm),
            "beacon_signal": link.and_then(|l| l.beacon_signal_dbm),
            "chain_signal": link.map(|l| l.chain_signal_dbm.clone()).unwrap_or_default(),
            "tx_packets": tx_packets,
            "rx_packets": link.and_then(|l| l.rx_packets),
            "tx_retries": retries,
            "tx_failed": link.and_then(|l| l.tx_failed),
            "retry_percent": retry_percent(retries, tx_packets),
            "beacon_loss": link.and_then(|l| l.beacon_loss),
            "inactive_ms": link.and_then(|l| l.inactive_ms),
        });
        if let Value::Object(d) = detail {
            o.extend(d);
        }
    }
    let addresses = addresses_on(s, &name);
    if let Value::Object(o) = &mut out {
        o.insert("addresses".into(), addresses);
    }
    Ok(out)
}

/// How a station's signal reads to an operator. Thresholds as the Wi-Fi
/// design guides put them (Cisco's −67 dBm for voice, −75 for data):
/// excellent from −55 dBm, good from −67, fair from −75, poor below.
fn quality(dbm: i32) -> &'static str {
    match dbm {
        d if d >= -55 => "excellent",
        d if d >= -67 => "good",
        d if d >= -75 => "fair",
        _ => "poor",
    }
}

/// `6` → `802.11ax`.
pub(super) fn standard_of(generation: u8) -> Option<&'static str> {
    match generation {
        4 => Some("802.11n"),
        5 => Some("802.11ac"),
        6 => Some("802.11ax"),
        7 => Some("802.11be"),
        _ => None,
    }
}

/// Retries per hundred frames sent, one decimal; `None` before the first.
pub(super) fn retry_percent(retries: Option<u64>, packets: Option<u64>) -> Option<f64> {
    let (r, p) = (retries?, packets?);
    (p > 0).then(|| ((r as f64 / p as f64) * 1000.0).round() / 10.0)
}

/// A rate as JSON, with the line the GUI shows: `576.5 Mbit/s, HE-MCS 11,
/// 2 streams, 80 MHz, GI 0.8 µs`.
pub(super) fn rate_json(r: &corerouter_hal::wifi::WifiRate) -> Value {
    let mbps = r.kbps.map(|k| (f64::from(k) / 100.0).round() / 10.0);
    let mut parts = Vec::new();
    if let Some(m) = mbps {
        parts.push(format!("{m} Mbit/s"));
    }
    match (r.mode.as_deref(), r.mcs) {
        (Some(mode), Some(mcs)) if mode != "legacy" => {
            parts.push(format!("{}-MCS {mcs}", mode.to_ascii_uppercase()));
        }
        (Some("legacy"), _) => parts.push("legacy".into()),
        _ => {}
    }
    if let Some(n) = r.nss {
        parts.push(if n == 1 { "1 stream".into() } else { format!("{n} streams") });
    }
    if let Some(w) = r.width_mhz {
        parts.push(format!("{w} MHz"));
    }
    if let Some(g) = r.guard_ns {
        parts.push(format!("GI {} µs", f64::from(g) / 1000.0));
    }
    json!({
        "mbps": mbps,
        "mode": r.mode,
        "mcs": r.mcs,
        "nss": r.nss,
        "width": r.width_mhz,
        "guard_ns": r.guard_ns,
        "text": parts.join(", "),
    })
}

/// The addresses on `name` now (static and the ones a DHCP client got).
fn addresses_on(s: &Session, name: &IfName) -> Value {
    let cfg = s.effective(s.store().candidate());
    Value::Array(
        cfg.ip
            .addresses
            .iter()
            .filter(|a| &a.interface == name && !a.disabled)
            .take(16)
            .map(|a| {
                json!({
                    "address": a.address.to_string(),
                    "dynamic": crate::dhcp_client::is_dynamic(a.id),
                })
            })
            .collect(),
    )
}

/// G1.30g: what the radio behind `name` is and can do.
fn radio(s: &mut Session, p: &Value) -> Result<Value> {
    let name: IfName = req_parse(p, "name")?;
    let cfg = s.store().candidate();
    radio_of(cfg, &name)?;
    let country = cfg.system.wifi.country.map(|c| c.to_string());
    let frequency = s
        .wifi()
        .and_then(|rt| rt.radios.get(&name))
        .filter(|r| r.status.state == corerouter_hal::wifi::WifiState::Connected)
        .and_then(|r| r.status.frequency_mhz);
    let in_force = s.hal_mut().wifi_regdomain();
    let Some(r) = s.hal_mut().wifi_radio(&name) else {
        return Ok(json!({
            "name": name, "driver": null, "bands": [], "standards": [],
            "frequency": frequency, "country": country, "country_in_force": in_force,
        }));
    };
    let mut standards: Vec<String> = Vec::new();
    for b in &r.bands {
        for st in &b.standards {
            if !standards.contains(st) {
                standards.push(st.clone());
            }
        }
    }
    let order = ["a", "b", "g", "n", "ac", "ax", "be"];
    standards.sort_by_key(|x| order.iter().position(|o| o == x).unwrap_or(order.len()));
    let max_here = frequency.and_then(|f| {
        r.bands
            .iter()
            .flat_map(|b| &b.channels)
            .find(|c| c.mhz == f)
            .and_then(|c| c.max_power_dbm)
    });
    let bands: Vec<Value> = r
        .bands
        .iter()
        .map(|b| {
            let allowed = b.channels.iter().filter(|c| !c.disabled).count();
            let dfs = b.channels.iter().filter(|c| !c.disabled && c.radar).count();
            json!({
                "band": b.band,
                "standards": b.standards,
                "max_width": b.max_width_mhz,
                "allowed": allowed,
                "dfs": dfs,
                "max_power": b.channels.iter().filter(|c| !c.disabled).filter_map(|c| c.max_power_dbm).max(),
                "channels": b.channels.iter().map(|c| json!({
                    "mhz": c.mhz,
                    "channel": channel(c.mhz),
                    "max_power": c.max_power_dbm,
                    "radar": c.radar,
                    "disabled": c.disabled,
                })).collect::<Vec<_>>(),
            })
        })
        .collect();
    Ok(json!({
        "name": name,
        "phy": r.phy,
        "driver": r.driver,
        "firmware": r.firmware,
        "self_managed": r.self_managed,
        "blocked": r.blocked,
        "standards": standards,
        "bands": bands,
        "antennas_tx": r.antennas_tx,
        "antennas_rx": r.antennas_rx,
        "tx_power": r.tx_power_dbm,
        "max_tx_power": max_here,
        "frequency": frequency,
        "country": country,
        "country_in_force": in_force,
    }))
}

/// Why radio `name` cannot scan now, if it cannot.
pub(super) fn not_running(cfg: &Config, name: &IfName) -> Result<()> {
    let (iface, _) = radio_of(cfg, name)?;
    if cfg.system.wifi.country.is_none() {
        return Err(EngineError::bad(
            "name",
            "set the country first (interface.wifi.country.set country=BR): it says which \
             channels the radio may scan"
                .to_owned(),
        ));
    }
    if iface.disabled {
        return Err(EngineError::bad(
            "name",
            format!("'{name}' is disabled: enable it to scan (interface.wifi.enable)"),
        ));
    }
    Ok(())
}

fn scan(s: &mut Session, p: &Value) -> Result<Value> {
    let name: IfName = req_parse(p, "name")?;
    not_running(s.store().running(), &name)?;
    // Enabled a moment ago: open the radio now, not at the next tick.
    let now = s.wifi().map_or(0, |rt| rt.now_ms);
    s.wifi_service(now);
    s.wifi_scan(&name).map_err(|e| EngineError::bad("name", e))?;
    Ok(json!({ "name": name, "scanning": true }))
}

/// Can the router join a network secured like this, and why not.
pub(super) fn joinable(sec: BssSecurity) -> Option<&'static str> {
    match sec {
        BssSecurity::Open | BssSecurity::Wpa2 | BssSecurity::Wpa2Wpa3 | BssSecurity::Wpa3 => None,
        BssSecurity::Owe => Some("opportunistic encryption (OWE) is not supported yet"),
        BssSecurity::Legacy => Some("WEP or WPA with TKIP: broken, never joined"),
        BssSecurity::Enterprise => {
            Some("802.1X (a user and password, or a certificate) is not supported yet")
        }
    }
}

/// Why `ssid` cannot be joined, when every access point the last scan of
/// `name` heard with that name is of a kind a station does not join.
/// `None`: not heard (nothing to say), or at least one can be joined.
fn unjoinable(s: &Session, name: &IfName, ssid: &str) -> Option<&'static str> {
    if ssid.is_empty() {
        return None;
    }
    let r = s.wifi()?.radios.get(name)?;
    let mut why = None;
    for b in r.scan.iter().filter(|b| b.ssid == ssid) {
        why = Some(joinable(b.security)?);
    }
    why
}

fn networks(s: &mut Session, p: &Value) -> Result<Value> {
    // G1.30i: with the air of each network (cmd/wifi_scan.rs).
    super::wifi_scan::networks(s, p)
}

fn history(s: &mut Session, p: &Value) -> Result<Value> {
    let name = super::args::opt_parse::<IfName>(p, "name")?;
    let limit = opt_u32(p, "limit")?.unwrap_or(100).min(1000) as usize;
    let Some(rt) = s.wifi() else {
        return Ok(json!([]));
    };
    let rows: Vec<Value> = rt
        .history()
        .rev()
        .filter(|h| name.as_ref().is_none_or(|n| *n == h.name))
        .take(limit)
        .map(|h| {
            json!({
                "seq": h.seq, "time": h.time, "name": h.name, "event": h.event,
                "message": h.message,
            })
        })
        .collect();
    Ok(Value::Array(rows))
}

/// The edit modal's preview (G0.24): `interface.wifi.set` of the radio
/// named by `id`, tried on the candidate and undone, so the checks and the
/// warnings are exactly the command's. On top of them: whether the last
/// scan heard the network, and the country a radio needs before it is on
/// (the commit would refuse it; the modal says so before).
fn preview(s: &mut Session, p: &Value) -> Result<Value> {
    let mut q = p.clone();
    if let Some(o) = q.as_object_mut() {
        if let Some(id) = o.remove("id") {
            o.insert("name".into(), id);
        }
        // An empty field of the modal is "not given" where empty is not a
        // value. (An empty ssid forgets the network; an empty band or
        // bssid is "any".)
        for k in ["security", "passphrase", "mtu", "mode"] {
            if o
                .get(k)
                .and_then(Value::as_str)
                .is_some_and(|t| t.trim().is_empty())
            {
                o.remove(k);
            }
        }
        if let Some(n) = o
            .get("mtu")
            .and_then(Value::as_str)
            .and_then(|t| t.trim().parse::<u64>().ok())
        {
            o.insert("mtu".into(), json!(n));
        }
    }
    let name = q
        .get("name")
        .and_then(Value::as_str)
        .and_then(|n| n.parse::<IfName>().ok());
    let mut needs_country = false;
    let mut out = super::ppp_common::preview(
        s,
        &q,
        ("interface.wifi.set", "interface.wifi.set"),
        (set, set),
        |s, _| {
            let cfg = s.store().candidate();
            let Some((iface, st)) = name.as_ref().and_then(|n| radio_of(cfg, n).ok()) else {
                return Vec::new();
            };
            if st.mode == WifiMode::Ap
                && let Some(n) = name.as_ref()
            {
                return super::wifi_ap::computed(s, n, iface, st);
            }
            let line = |label: &str, value: String| json!({"label": label, "value": value});
            if st.ssid.is_empty() {
                return vec![line("Network", "none: the radio joins nothing".into())];
            }
            let heard = name
                .as_ref()
                .and_then(|n| s.wifi().and_then(|rt| rt.radios.get(n)))
                .map(|r| {
                    let best = r
                        .scan
                        .iter()
                        .filter(|b| b.ssid == st.ssid)
                        .max_by_key(|b| b.signal_dbm);
                    match (best, r.scanned_at) {
                        (Some(b), _) => format!(
                            "yes: {} dBm, {}{}",
                            b.signal_dbm,
                            match band_of(Some(b.frequency_mhz)) {
                                Some("2ghz") => "2.4 GHz",
                                Some("5ghz") => "5 GHz",
                                Some("6ghz") => "6 GHz",
                                _ => "?",
                            },
                            channel(b.frequency_mhz)
                                .map(|c| format!(" channel {c}"))
                                .unwrap_or_default(),
                        ),
                        (None, Some(_)) if st.hidden => {
                            "a hidden network does not show in a scan".to_owned()
                        }
                        (None, Some(_)) => "not heard in the last scan".to_owned(),
                        (None, None) => "no scan yet".to_owned(),
                    }
                })
                .unwrap_or_else(|| "no scan yet".to_owned());
            vec![
                line("Network", st.ssid.clone()),
                line(
                    "Security",
                    match st.security {
                        WifiSecurity::Auto => "WPA3 if the access point offers it, else WPA2",
                        WifiSecurity::Wpa3 => "WPA3 only",
                        WifiSecurity::Wpa2 => "WPA2 only",
                        WifiSecurity::Open => "none (open network)",
                    }
                    .to_owned(),
                ),
                line("In range", heard),
                line(
                    "Radio",
                    if iface.disabled { "off" } else { "on" }.to_owned(),
                ),
            ]
        },
    )?;
    if let Some(n) = &name
        && let Ok((iface, _)) = radio_of(s.store().candidate(), n)
    {
        // What the candidate would be: the radio as the modal leaves it.
        let off = q
            .get("disabled")
            .and_then(Value::as_bool)
            .unwrap_or(iface.disabled);
        needs_country = !off && s.store().candidate().system.wifi.country.is_none();
    }
    let valid = out
        .get("commands")
        .and_then(Value::as_array)
        .is_some_and(|c| !c.is_empty());
    if needs_country
        && valid
        && let Some(checks) = out.get_mut("checks").and_then(Value::as_array_mut)
    {
        checks.push(json!({
            "level": "error",
            "check": "country",
            "message": corerouter_model::wifi::NO_COUNTRY,
            "param": "disabled",
        }));
    }
    Ok(out)
}


#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn quality_follows_the_design_thresholds() {
        for (dbm, q) in [
            (-40, "excellent"),
            (-55, "excellent"),
            (-56, "good"),
            (-67, "good"),
            (-68, "fair"),
            (-75, "fair"),
            (-76, "poor"),
            (-95, "poor"),
        ] {
            assert_eq!(quality(dbm), q, "{dbm}");
        }
    }

    #[test]
    fn a_rate_reads_as_one_line() {
        let he = corerouter_hal::wifi::WifiRate {
            kbps: Some(576_500),
            mode: Some("he".into()),
            mcs: Some(11),
            nss: Some(2),
            width_mhz: Some(80),
            guard_ns: Some(800),
        };
        let v = rate_json(&he);
        assert_eq!(v["mbps"], 576.5);
        assert_eq!(v["text"], "576.5 Mbit/s, HE-MCS 11, 2 streams, 80 MHz, GI 0.8 µs");
        let legacy = corerouter_hal::wifi::WifiRate {
            kbps: Some(5_500),
            mode: Some("legacy".into()),
            ..Default::default()
        };
        assert_eq!(rate_json(&legacy)["text"], "5.5 Mbit/s, legacy");
        assert_eq!(rate_json(&Default::default())["text"], "");
        assert_eq!(retry_percent(Some(65), Some(3084)), Some(2.1));
        assert_eq!(retry_percent(Some(1), Some(0)), None);
        assert_eq!(standard_of(6), Some("802.11ax"));
        assert_eq!(standard_of(3), None);
    }
}
