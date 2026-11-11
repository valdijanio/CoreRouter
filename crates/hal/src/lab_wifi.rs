//! The virtual lab's Wi-Fi (G1.30): radios and an "air" with a handful of
//! made-up networks, so the commands, the windows and the tests have a
//! station to drive without a card. A radio takes one poll to find a network
//! and one more to get in (or to be refused), which is what the engine sees
//! of a real one, only faster.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use corerouter_model::IfName;

use crate::HalError;
use crate::wifi::{
    BssSecurity, JoinSecurity, MAX_EVENTS, WifiBss, WifiEvent, WifiFailure, WifiNetwork, WifiPort,
    WifiRadio, WifiState, WifiStatus,
};

/// The passphrase of the lab's main network (`CoreRouter-Lab`).
pub const LAB_PASSPHRASE: &str = "corerouter-lab";

/// One network of the lab's air.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabNetwork {
    pub ssid: String,
    pub bssid: String,
    pub frequency_mhz: u32,
    pub signal_dbm: i32,
    pub security: BssSecurity,
    pub key: String,
    /// Does not announce its name: a scan shows it nameless.
    pub hidden: bool,
}

fn net(
    ssid: &str,
    last: u8,
    frequency_mhz: u32,
    signal_dbm: i32,
    security: BssSecurity,
    key: &str,
) -> LabNetwork {
    LabNetwork {
        ssid: ssid.into(),
        bssid: format!("02:c0:fe:00:00:{last:02x}"),
        frequency_mhz,
        signal_dbm,
        security,
        key: key.into(),
        hidden: false,
    }
}

/// What a lab radio hears. Two access points of one network on two bands,
/// a WPA3-only one, a neighbour's, an open one, a hidden one and an
/// enterprise one (which the router cannot join yet).
pub fn default_networks() -> Vec<LabNetwork> {
    let mut hidden = net("Oculta", 6, 5180, -65, BssSecurity::Wpa2, "rede-escondida");
    hidden.hidden = true;
    vec![
        net(
            "CoreRouter-Lab",
            1,
            5220,
            -52,
            BssSecurity::Wpa2Wpa3,
            LAB_PASSPHRASE,
        ),
        net(
            "CoreRouter-Lab",
            2,
            2437,
            -61,
            BssSecurity::Wpa2Wpa3,
            LAB_PASSPHRASE,
        ),
        net(
            "Lab-WPA3",
            3,
            5745,
            -58,
            BssSecurity::Wpa3,
            "wpa3-only-pass",
        ),
        net(
            "Vizinho_2G",
            4,
            2462,
            -78,
            BssSecurity::Wpa2,
            "outro-segredo",
        ),
        net("Cafe", 5, 2412, -80, BssSecurity::Open, ""),
        hidden,
        net("Corp", 7, 5500, -70, BssSecurity::Enterprise, ""),
    ]
}

#[derive(Debug, Default)]
struct Radio {
    want: Option<WifiNetwork>,
    /// Polls since `want` was set.
    polls: u32,
    state: WifiState,
    on: Option<LabNetwork>,
    events: Vec<WifiEvent>,
    scanned: Option<Vec<WifiBss>>,
    scanning: bool,
    joins: u32,
}

#[derive(Debug)]
struct Air {
    networks: Vec<LabNetwork>,
    radios: BTreeMap<IfName, Radio>,
    country: Option<String>,
    blocked: bool,
    country_calls: u32,
}

/// The lab's air: shared by the HAL, its radios and a test that wants to
/// change what is in range.
#[derive(Debug, Clone)]
pub struct LabWifi(Arc<Mutex<Air>>);

impl Default for LabWifi {
    fn default() -> Self {
        Self(Arc::new(Mutex::new(Air {
            networks: default_networks(),
            radios: BTreeMap::new(),
            country: None,
            blocked: false,
            country_calls: 0,
        })))
    }
}

fn push(events: &mut Vec<WifiEvent>, e: WifiEvent) {
    if events.len() < MAX_EVENTS {
        events.push(e);
    }
}

/// Does `n` fit what the station was told to join?
fn offers(n: &LabNetwork, want: &WifiNetwork) -> bool {
    let named = n.ssid == want.ssid && (!n.hidden || want.hidden);
    let band = want
        .band_mhz
        .is_none_or(|(lo, hi)| (lo..=hi).contains(&n.frequency_mhz));
    let bssid = want
        .bssid
        .as_ref()
        .is_none_or(|b| b.eq_ignore_ascii_case(&n.bssid));
    let security = match want.security {
        JoinSecurity::Open => n.security == BssSecurity::Open,
        JoinSecurity::Wpa2 => matches!(n.security, BssSecurity::Wpa2 | BssSecurity::Wpa2Wpa3),
        JoinSecurity::Wpa3 => matches!(n.security, BssSecurity::Wpa3 | BssSecurity::Wpa2Wpa3),
        JoinSecurity::Auto => matches!(
            n.security,
            BssSecurity::Wpa2 | BssSecurity::Wpa2Wpa3 | BssSecurity::Wpa3
        ),
    };
    named && band && bssid && security
}

impl Air {
    /// One step of radio `name` towards its network.
    fn step(&mut self, name: &IfName) {
        let blocked = self.blocked;
        let networks = &self.networks;
        let Some(r) = self.radios.get_mut(name) else {
            return;
        };
        if r.scanning {
            r.scanning = false;
            let mut seen: Vec<WifiBss> = networks
                .iter()
                .map(|n| WifiBss {
                    ssid: if n.hidden {
                        String::new()
                    } else {
                        n.ssid.clone()
                    },
                    bssid: n.bssid.clone(),
                    frequency_mhz: n.frequency_mhz,
                    signal_dbm: n.signal_dbm,
                    security: n.security,
                })
                .collect();
            seen.sort_by_key(|b| std::cmp::Reverse(b.signal_dbm));
            r.scanned = Some(seen);
            push(&mut r.events, WifiEvent::ScanDone);
        }
        if blocked {
            if r.state != WifiState::Blocked {
                r.state = WifiState::Blocked;
                r.on = None;
                push(&mut r.events, WifiEvent::Blocked(true));
            }
            return;
        }
        if r.state == WifiState::Blocked {
            r.state = WifiState::Idle;
            r.polls = 0;
            push(&mut r.events, WifiEvent::Blocked(false));
        }
        let Some(want) = r.want.clone() else {
            return;
        };
        if r.state == WifiState::Connected {
            // The access point went away (a test took it off the air).
            if !r.on.as_ref().is_some_and(|on| networks.contains(on)) {
                r.on = None;
                r.state = WifiState::Searching;
                r.polls = 0;
                push(
                    &mut r.events,
                    WifiEvent::Disconnected {
                        reason: "the access point stopped answering (beacon loss)".into(),
                    },
                );
            }
            return;
        }
        r.polls = r.polls.saturating_add(1);
        let best = networks
            .iter()
            .filter(|n| offers(n, &want))
            .max_by_key(|n| n.signal_dbm);
        match (r.polls, best) {
            // Looking for a network starts with a scan, and its end is said
            // like any other (the supplicant's `CTRL-EVENT-SCAN-RESULTS`).
            (1, _) => {
                r.state = WifiState::Searching;
                r.scanning = true;
            }
            (_, None) => {
                // Keeps looking, and says so once per round of the scan.
                if r.polls == 2 {
                    push(&mut r.events, WifiEvent::Failed(WifiFailure::NotFound));
                }
                r.state = WifiState::Searching;
            }
            (2, Some(_)) => r.state = WifiState::Connecting,
            (_, Some(n)) if n.key == want.key => {
                r.state = WifiState::Connected;
                r.on = Some(n.clone());
                push(
                    &mut r.events,
                    WifiEvent::Connected {
                        bssid: n.bssid.clone(),
                    },
                );
            }
            (3, Some(_)) => {
                push(&mut r.events, WifiEvent::Failed(WifiFailure::WrongKey));
                r.state = WifiState::Searching;
            }
            // What the supplicant does after a wrong key: it leaves that
            // access point alone, so its next scan "finds none" with the
            // network on the list, and then it pauses the network.
            (4, Some(_)) => {
                push(&mut r.events, WifiEvent::Failed(WifiFailure::NotFound));
                r.state = WifiState::Searching;
            }
            (5, Some(_)) => {
                push(&mut r.events, WifiEvent::Failed(WifiFailure::NoAnswer));
                r.state = WifiState::Searching;
            }
            (_, Some(_)) => r.state = WifiState::Searching,
        }
    }
}

impl LabWifi {
    fn air(&self) -> MutexGuard<'_, Air> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Put radio `name` in the lab.
    pub fn add_radio(&self, name: IfName) {
        self.air().radios.entry(name).or_default();
    }

    pub fn has_radio(&self, name: &IfName) -> bool {
        self.air().radios.contains_key(name)
    }

    pub fn radio_names(&self) -> Vec<IfName> {
        self.air().radios.keys().cloned().collect()
    }

    /// The radio's port.
    pub fn port(&self, name: &IfName) -> Result<Box<dyn WifiPort>, HalError> {
        if !self.has_radio(name) {
            return Err(HalError::Unsupported(format!(
                "'{name}' is not a Wi-Fi radio of the lab"
            )));
        }
        Ok(Box::new(LabPort {
            air: self.clone(),
            name: name.clone(),
        }))
    }

    pub fn radio(&self, name: &IfName) -> Option<WifiRadio> {
        self.has_radio(name).then(|| WifiRadio {
            driver: Some("lab_wifi".into()),
            self_managed: false,
        })
    }

    /// The regulatory domain the lab was asked for.
    pub fn country(&self) -> Option<String> {
        self.air().country.clone()
    }

    pub fn set_country(&self, country: Option<&str>) {
        let mut air = self.air();
        air.country = country.map(str::to_owned);
        air.country_calls = air.country_calls.saturating_add(1);
        let c = air.country.clone();
        for r in air.radios.values_mut() {
            push(&mut r.events, WifiEvent::Country(c.clone()));
        }
    }

    /// How many times the domain was asked for (a test's: once per change).
    pub fn country_calls(&self) -> u32 {
        self.air().country_calls
    }

    /// Is radio `name` on a network now?
    pub fn connected(&self, name: &IfName) -> bool {
        self.air()
            .radios
            .get(name)
            .is_some_and(|r| r.state == WifiState::Connected)
    }

    /// Times radio `name` was told to join (a test's: no rejoin on a tick).
    pub fn joins(&self, name: &IfName) -> u32 {
        self.air().radios.get(name).map_or(0, |r| r.joins)
    }

    /// Take the networks named `ssid` off the air (a test's).
    pub fn remove_network(&self, ssid: &str) {
        self.air().networks.retain(|n| n.ssid != ssid);
    }

    pub fn add_network(&self, n: LabNetwork) {
        self.air().networks.push(n);
    }

    /// Block or unblock every radio, as an airplane-mode key does.
    pub fn set_blocked(&self, blocked: bool) {
        self.air().blocked = blocked;
    }
}

struct LabPort {
    air: LabWifi,
    name: IfName,
}

impl WifiPort for LabPort {
    fn join(&mut self, net: &WifiNetwork) -> Result<(), HalError> {
        let mut air = self.air.air();
        let Some(r) = air.radios.get_mut(&self.name) else {
            return Err(HalError::Io(format!("radio '{}' is gone", self.name)));
        };
        if r.state == WifiState::Connected {
            push(
                &mut r.events,
                WifiEvent::Disconnected {
                    reason: "left for another network".into(),
                },
            );
        }
        r.want = Some(net.clone());
        r.polls = 0;
        r.on = None;
        r.state = WifiState::Searching;
        r.joins = r.joins.saturating_add(1);
        Ok(())
    }

    fn leave(&mut self) -> Result<(), HalError> {
        let mut air = self.air.air();
        if let Some(r) = air.radios.get_mut(&self.name) {
            if r.state == WifiState::Connected {
                push(
                    &mut r.events,
                    WifiEvent::Disconnected {
                        reason: "left (told to)".into(),
                    },
                );
            }
            r.want = None;
            r.on = None;
            if r.state != WifiState::Blocked {
                r.state = WifiState::Idle;
            }
        }
        Ok(())
    }

    fn scan(&mut self) -> Result<(), HalError> {
        let mut air = self.air.air();
        if air.blocked {
            return Err(HalError::Rejected("the radio is blocked (rfkill)".into()));
        }
        match air.radios.get_mut(&self.name) {
            Some(r) => {
                r.scanning = true;
                Ok(())
            }
            None => Err(HalError::Io(format!("radio '{}' is gone", self.name))),
        }
    }

    fn scan_results(&mut self) -> Result<Vec<WifiBss>, HalError> {
        let air = self.air.air();
        Ok(air
            .radios
            .get(&self.name)
            .and_then(|r| r.scanned.clone())
            .unwrap_or_default())
    }

    fn status(&mut self) -> Result<WifiStatus, HalError> {
        let air = self.air.air();
        let Some(r) = air.radios.get(&self.name) else {
            return Err(HalError::Io(format!("radio '{}' is gone", self.name)));
        };
        let on = r.on.as_ref();
        Ok(WifiStatus {
            state: r.state,
            ssid: on
                .map(|n| n.ssid.clone())
                .or_else(|| r.want.as_ref().map(|w| w.ssid.clone())),
            bssid: on.map(|n| n.bssid.clone()),
            frequency_mhz: on.map(|n| n.frequency_mhz),
            signal_dbm: on.map(|n| n.signal_dbm),
            rate_mbps: on.map(|n| if n.frequency_mhz > 5000 { 866 } else { 144 }),
            security: on.map(|n| {
                match (n.security, r.want.as_ref().map(|w| w.security)) {
                    (BssSecurity::Open, _) => "open",
                    (BssSecurity::Wpa2, _) | (_, Some(JoinSecurity::Wpa2)) => "wpa2",
                    _ => "wpa3",
                }
                .to_owned()
            }),
            pmf: on.map(|n| matches!(n.security, BssSecurity::Wpa3 | BssSecurity::Wpa2Wpa3)),
        })
    }

    fn events(&mut self) -> Vec<WifiEvent> {
        let mut air = self.air.air();
        air.step(&self.name);
        air.radios
            .get_mut(&self.name)
            .map(|r| std::mem::take(&mut r.events))
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lab() -> (LabWifi, Box<dyn WifiPort>, IfName) {
        let lab = LabWifi::default();
        let name: IfName = "wifi1".parse().unwrap();
        lab.add_radio(name.clone());
        let port = lab.port(&name).unwrap();
        (lab, port, name)
    }

    fn want(ssid: &str, key: &str, security: JoinSecurity) -> WifiNetwork {
        WifiNetwork {
            ssid: ssid.into(),
            security,
            key: key.into(),
            hidden: false,
            band_mhz: None,
            bssid: None,
        }
    }

    fn settle(p: &mut dyn WifiPort) -> Vec<WifiEvent> {
        // Without the scan every search starts with.
        (0..6)
            .flat_map(|_| p.events())
            .filter(|e| *e != WifiEvent::ScanDone)
            .collect()
    }

    #[test]
    fn joins_the_strongest_access_point_of_the_network() {
        let (lab, mut p, name) = lab();
        assert_eq!(p.status().unwrap().state, WifiState::Idle);
        p.join(&want("CoreRouter-Lab", LAB_PASSPHRASE, JoinSecurity::Auto))
            .unwrap();
        assert_eq!(p.status().unwrap().state, WifiState::Searching);
        let ev = settle(&mut *p);
        assert_eq!(
            ev,
            [WifiEvent::Connected {
                bssid: "02:c0:fe:00:00:01".into()
            }]
        );
        let st = p.status().unwrap();
        assert_eq!(st.state, WifiState::Connected);
        assert_eq!((st.frequency_mhz, st.signal_dbm), (Some(5220), Some(-52)));
        assert_eq!(st.security.as_deref(), Some("wpa3"));
        assert!(lab.connected(&name));
        // Held to 2.4 GHz, it takes the other access point.
        let mut n = want("CoreRouter-Lab", LAB_PASSPHRASE, JoinSecurity::Auto);
        n.band_mhz = Some((2400, 2500));
        p.join(&n).unwrap();
        settle(&mut *p);
        assert_eq!(p.status().unwrap().frequency_mhz, Some(2437));
        p.leave().unwrap();
        assert_eq!(p.status().unwrap().state, WifiState::Idle);
        assert!(!lab.connected(&name));
    }

    #[test]
    fn says_why_it_did_not_get_in() {
        let (lab, mut p, _) = lab();
        p.join(&want("CoreRouter-Lab", "senha-errada", JoinSecurity::Auto))
            .unwrap();
        assert_eq!(
            settle(&mut *p),
            [
                WifiEvent::Failed(WifiFailure::WrongKey),
                WifiEvent::Failed(WifiFailure::NotFound),
                WifiEvent::Failed(WifiFailure::NoAnswer)
            ],
            "the cause, then what the supplicant does about it"
        );
        p.join(&want("Nao-Existe", "12345678", JoinSecurity::Auto))
            .unwrap();
        assert_eq!(settle(&mut *p), [WifiEvent::Failed(WifiFailure::NotFound)]);
        // WPA3 only against a WPA2-only network: not offered.
        p.join(&want("Vizinho_2G", "outro-segredo", JoinSecurity::Wpa3))
            .unwrap();
        assert_eq!(settle(&mut *p), [WifiEvent::Failed(WifiFailure::NotFound)]);
        // A hidden network answers only a probe by name.
        p.join(&want("Oculta", "rede-escondida", JoinSecurity::Auto))
            .unwrap();
        assert_eq!(settle(&mut *p), [WifiEvent::Failed(WifiFailure::NotFound)]);
        let mut hidden = want("Oculta", "rede-escondida", JoinSecurity::Auto);
        hidden.hidden = true;
        p.join(&hidden).unwrap();
        assert!(matches!(settle(&mut *p)[..], [WifiEvent::Connected { .. }]));
        // The access point goes away; the radio looks for it again.
        lab.remove_network("Oculta");
        assert!(matches!(
            settle(&mut *p)[..],
            [WifiEvent::Disconnected { .. }, ..]
        ));
        assert_eq!(p.status().unwrap().state, WifiState::Searching);
    }

    #[test]
    fn scans_and_is_blocked() {
        let (lab, mut p, _) = lab();
        assert!(p.scan_results().unwrap().is_empty());
        p.scan().unwrap();
        assert_eq!(p.events(), [WifiEvent::ScanDone]);
        let seen = p.scan_results().unwrap();
        assert_eq!(seen.len(), default_networks().len());
        assert_eq!(seen[0].ssid, "CoreRouter-Lab");
        assert!(seen.windows(2).all(|w| w[0].signal_dbm >= w[1].signal_dbm));
        assert!(
            seen.iter().any(|b| b.ssid.is_empty()),
            "the hidden one has no name"
        );
        lab.set_blocked(true);
        assert!(p.scan().is_err());
        assert_eq!(p.events(), [WifiEvent::Blocked(true)]);
        assert_eq!(p.status().unwrap().state, WifiState::Blocked);
        lab.set_blocked(false);
        assert_eq!(p.events(), [WifiEvent::Blocked(false)]);
        lab.set_country(Some("BR"));
        assert_eq!(p.events(), [WifiEvent::Country(Some("BR".into()))]);
        assert_eq!(lab.country().as_deref(), Some("BR"));
        assert!(lab.port(&"ether1".parse().unwrap()).is_err());
    }
}
