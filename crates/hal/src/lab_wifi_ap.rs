//! The virtual lab's access point (G1.30a): a radio of the lab announces a
//! network, and two made-up clients join it a moment later (a WPA3 phone
//! and a WPA2 laptop). A DFS channel spends two polls in the radar check
//! first. The engine's tests and the GUI run on it.

use crate::HalError;
use crate::lab_wifi::LabWifi;
use crate::wifi::WifiLink;
use crate::wifi_ap::{
    ApSecurity, ApState, MAX_AP_EVENTS, WifiAp, WifiApEvent, WifiApPort, WifiApStatus, WifiClient,
};
use corerouter_model::IfName;

/// The lab's clients: MAC, signal, generation, whether it speaks WPA3, the
/// rate (kbit/s) it gets.
const CLIENTS: [(&str, i32, u8, bool, u32); 2] = [
    ("02:00:00:00:a0:01", -48, 6, true, 864_800),
    ("02:00:00:00:a0:02", -67, 5, false, 292_500),
];

/// One lab radio as an access point.
#[derive(Debug, Default)]
pub struct LabAp {
    told: Option<WifiAp>,
    /// Status reads since `told` was set.
    polls: u32,
    state: ApState,
    clients: Vec<WifiClient>,
    events: Vec<WifiApEvent>,
    starts: u32,
}

impl LabAp {
    pub(crate) fn up(&self) -> bool {
        self.state == ApState::Running
    }

    fn push(&mut self, e: WifiApEvent) {
        if self.events.len() < MAX_AP_EVENTS {
            self.events.push(e);
        }
    }

    /// One step of the lab's time: radar check, up, clients.
    fn step(&mut self) {
        let Some(ap) = self.told.clone() else {
            return;
        };
        self.polls = self.polls.saturating_add(1);
        let checking = ap.radar && self.polls <= 2;
        match self.state {
            ApState::Starting if checking => {
                self.state = ApState::RadarCheck;
                self.push(WifiApEvent::RadarCheck { secs: 60 });
            }
            ApState::Starting | ApState::RadarCheck if !checking => {
                self.state = ApState::Running;
                self.push(WifiApEvent::Up);
            }
            ApState::Running if self.clients.len() < CLIENTS.len() => {
                if let Some((mac, signal, generation, wpa3, kbps)) =
                    CLIENTS.get(self.clients.len()).copied()
                {
                    let security = match ap.security {
                        ApSecurity::Open => "open",
                        ApSecurity::Wpa3 => "wpa3",
                        ApSecurity::Wpa2 => "wpa2",
                        ApSecurity::Wpa2Wpa3 if wpa3 => "wpa3",
                        ApSecurity::Wpa2Wpa3 => "wpa2",
                    };
                    // A WPA2-only laptop does not join a WPA3-only network.
                    if ap.security == ApSecurity::Wpa3 && !wpa3 {
                        return;
                    }
                    let rate = crate::wifi::WifiRate {
                        kbps: Some(kbps),
                        ..crate::wifi::WifiRate::default()
                    };
                    self.clients.push(WifiClient {
                        mac: mac.into(),
                        authorized: true,
                        security: Some(security.into()),
                        generation: Some(generation),
                        link: WifiLink {
                            tx: Some(rate.clone()),
                            rx: Some(rate),
                            signal_avg_dbm: Some(signal),
                            tx_packets: Some(1_000),
                            rx_packets: Some(1_200),
                            tx_retries: Some(40),
                            tx_failed: Some(0),
                            connected_secs: Some(u64::from(self.polls)),
                            inactive_ms: Some(20),
                            ..WifiLink::default()
                        },
                    });
                    self.push(WifiApEvent::Joined { mac: mac.into() });
                }
            }
            _ => {}
        }
    }
}

/// A lab radio's access point port.
pub struct LabApPort {
    pub(crate) air: LabWifi,
    pub(crate) name: IfName,
}

impl LabWifi {
    /// G1.30a: times radio `name`'s access point was started (a test's: no
    /// restart on a tick).
    pub fn ap_starts(&self, name: &IfName) -> u32 {
        self.with_ap(name, |a| a.starts)
    }

    /// G1.30a: the settings the access point of `name` was given.
    pub fn ap_told(&self, name: &IfName) -> Option<WifiAp> {
        self.with_ap(name, |a| a.told.clone())
    }
}

impl WifiApPort for LabApPort {
    fn start(&mut self, ap: &WifiAp) -> Result<(), HalError> {
        if ap.ssid.is_empty() {
            return Err(HalError::Rejected("no SSID".into()));
        }
        self.air.with_ap(&self.name, |a| {
            for c in std::mem::take(&mut a.clients) {
                a.push(WifiApEvent::Left { mac: c.mac });
            }
            a.told = Some(ap.clone());
            a.polls = 0;
            a.state = ApState::Starting;
            a.starts = a.starts.saturating_add(1);
        });
        Ok(())
    }

    fn stop(&mut self) -> Result<(), HalError> {
        self.air.with_ap(&self.name, |a| {
            for c in std::mem::take(&mut a.clients) {
                a.push(WifiApEvent::Left { mac: c.mac });
            }
            a.told = None;
            a.state = ApState::Stopped;
        });
        Ok(())
    }

    fn status(&mut self) -> Result<WifiApStatus, HalError> {
        Ok(self.air.with_ap(&self.name, |a| {
            a.step();
            WifiApStatus {
                state: a.state,
                frequency_mhz: a.told.as_ref().map(|t| t.frequency_mhz),
                width_mhz: a.told.as_ref().map(|t| t.width_mhz),
                radar_check_secs: (a.state == ApState::RadarCheck)
                    .then(|| 60u32.saturating_sub(a.polls.saturating_mul(20))),
                error: None,
                clients: a.clients.clone(),
            }
        }))
    }

    fn events(&mut self) -> Vec<WifiApEvent> {
        self.air
            .with_ap(&self.name, |a| std::mem::take(&mut a.events))
    }
}

impl Drop for LabApPort {
    /// Like hostapd's `REMOVE`: the access point goes with its port.
    fn drop(&mut self) {
        self.air.with_ap(&self.name, |a| {
            a.told = None;
            a.clients.clear();
            a.state = ApState::Stopped;
        });
    }
}
