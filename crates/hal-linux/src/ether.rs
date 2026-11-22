//! What `interface.ethernet.set` asks of a NIC (G1.20), as a target state
//! over what the port had before CoreRouter touched it. Pure, so the
//! rules are tested everywhere; `ethtool.rs` reads and writes the state.
//!
//! A setting the config leaves out (`None`, an offload not listed) means
//! "as the port was": [`target`] fills it from the snapshot taken before
//! the first change, so taking a setting out of the config, a rollback or
//! a Safe Mode undo all put the driver's own value back.

use std::collections::BTreeMap;

use corerouter_hal::nic::mode_speed;
use corerouter_model::{EthernetSettings, FlowControl};

/// A port's link settings as ethtool reports them. Link modes are only
/// the rate modes (`1000baseT/Full`); `Autoneg`, `Pause`, `TP`… are never
/// changed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct EtherState {
    pub autoneg: Option<bool>,
    pub speed_mbps: Option<u32>,
    pub full_duplex: Option<bool>,
    pub advertising: Vec<String>,
    pub supported: Vec<String>,
    /// Pause frames: (autoneg, rx, tx); `None` when the driver has none.
    pub pause: Option<(bool, bool, bool)>,
    /// Features the driver lets change, and whether each is on.
    pub features: BTreeMap<String, bool>,
}

/// The link part of a target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Link {
    /// Auto-negotiate, advertising these rate modes.
    Auto(Vec<String>),
    /// Forced rate and duplex.
    Forced { speed_mbps: u32, full_duplex: bool },
}

/// What the port should look like.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Target {
    pub link: Option<Link>,
    pub pause: Option<(bool, bool, bool)>,
    pub features: BTreeMap<String, bool>,
}

/// Rate modes only, as ethtool names them.
pub(crate) fn rate_modes(modes: &[String]) -> Vec<String> {
    let mut v: Vec<String> = modes
        .iter()
        .filter(|m| mode_speed(m).is_some())
        .cloned()
        .collect();
    v.sort();
    v.dedup();
    v
}

/// `want` over `orig`. Fields neither sets stay `None` (nothing to do).
pub(crate) fn target(orig: &EtherState, want: &EthernetSettings) -> Target {
    let autoneg = want.auto_negotiation.or(orig.autoneg);
    let link = match autoneg {
        Some(true) => {
            let modes = want.advertise.clone().unwrap_or_else(|| {
                // Back to auto-negotiation after a forced rate: advertise
                // what the port did before, or everything it can.
                if orig.autoneg == Some(true) && !orig.advertising.is_empty() {
                    orig.advertising.clone()
                } else {
                    orig.supported.clone()
                }
            });
            Some(Link::Auto(rate_modes(&modes)))
        }
        Some(false) => match (
            want.speed_mbps.or(orig.speed_mbps),
            want.full_duplex.or(orig.full_duplex),
        ) {
            (Some(speed_mbps), duplex) => Some(Link::Forced {
                speed_mbps,
                full_duplex: duplex.unwrap_or(true),
            }),
            (None, _) => None,
        },
        None => None,
    };
    let pause = match (want.rx_flow_control, want.tx_flow_control, orig.pause) {
        (None, None, p) => p,
        (rx, tx, p) => {
            let (_, orx, otx) = p.unwrap_or((false, false, false));
            let auto = rx == Some(FlowControl::Auto) || tx == Some(FlowControl::Auto);
            let on = |f: Option<FlowControl>, old: bool| f.map_or(old, |f| f != FlowControl::Off);
            Some((auto, on(rx, orx), on(tx, otx)))
        }
    };
    let mut features = orig.features.clone();
    for (name, on) in &want.offloads {
        features.insert(name.clone(), *on);
    }
    Target {
        link,
        pause,
        features,
    }
}

/// Features of `t` that differ from `now` (only those get sent).
pub(crate) fn feature_changes(t: &Target, now: &BTreeMap<String, bool>) -> BTreeMap<String, bool> {
    t.features
        .iter()
        .filter(|(n, on)| now.get(*n) != Some(*on))
        .map(|(n, on)| (n.clone(), *on))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| (*x).to_owned()).collect()
    }

    fn orig() -> EtherState {
        EtherState {
            autoneg: Some(true),
            speed_mbps: Some(1000),
            full_duplex: Some(true),
            advertising: s(&["100baseT/Full", "1000baseT/Full"]),
            supported: s(&["10baseT/Half", "100baseT/Full", "1000baseT/Full"]),
            pause: Some((true, true, false)),
            features: [
                ("rx-gro".to_owned(), true),
                ("tx-tcp-segmentation".to_owned(), true),
            ]
            .into_iter()
            .collect(),
        }
    }

    #[test]
    fn empty_settings_restore_the_snapshot() {
        let t = target(&orig(), &EthernetSettings::default());
        assert_eq!(
            t.link,
            Some(Link::Auto(s(&["1000baseT/Full", "100baseT/Full"])))
        );
        assert_eq!(t.pause, Some((true, true, false)));
        assert_eq!(t.features, orig().features);
        assert!(feature_changes(&t, &orig().features).is_empty());
    }

    #[test]
    fn forcing_and_back() {
        let want = EthernetSettings {
            auto_negotiation: Some(false),
            speed_mbps: Some(100),
            full_duplex: Some(true),
            ..EthernetSettings::default()
        };
        let t = target(&orig(), &want);
        assert_eq!(
            t.link,
            Some(Link::Forced {
                speed_mbps: 100,
                full_duplex: true
            })
        );
        // A port that was forced before: auto again advertises everything.
        let forced = EtherState {
            autoneg: Some(false),
            ..orig()
        };
        let back = EthernetSettings {
            auto_negotiation: Some(true),
            ..EthernetSettings::default()
        };
        assert_eq!(
            target(&forced, &back).link,
            Some(Link::Auto(s(&[
                "1000baseT/Full",
                "100baseT/Full",
                "10baseT/Half"
            ])))
        );
    }

    #[test]
    fn advertise_keeps_only_rate_modes() {
        let want = EthernetSettings {
            advertise: Some(s(&["100baseT/Full", "Pause", "Autoneg"])),
            ..EthernetSettings::default()
        };
        assert_eq!(
            target(&orig(), &want).link,
            Some(Link::Auto(s(&["100baseT/Full"])))
        );
    }

    #[test]
    fn flow_control_maps_to_pause() {
        let want = EthernetSettings {
            rx_flow_control: Some(FlowControl::Off),
            tx_flow_control: Some(FlowControl::Auto),
            ..EthernetSettings::default()
        };
        assert_eq!(target(&orig(), &want).pause, Some((true, false, true)));
        let only_tx = EthernetSettings {
            tx_flow_control: Some(FlowControl::On),
            ..EthernetSettings::default()
        };
        assert_eq!(target(&orig(), &only_tx).pause, Some((false, true, true)));
    }

    #[test]
    fn offloads_overlay_and_diff() {
        let mut want = EthernetSettings::default();
        want.offloads.insert("rx-gro".into(), false);
        let t = target(&orig(), &want);
        let changes = feature_changes(&t, &orig().features);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes.get("rx-gro"), Some(&false));
    }
}
