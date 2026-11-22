//! The fast path (G2.4): what a port's card can do for the flowtable, and
//! what the backend installed.
//!
//! Hardware flow offload in Linux goes through the driver's
//! `ndo_setup_tc(TC_SETUP_FT)`. For NVIDIA ConnectX (mlx5) that exists
//! only on switchdev representors (the uplink one included), with
//! `hw-tc-offload` on: a port in the default `legacy` eSwitch mode, or
//! with the feature off, takes the flowtable in software only. Field
//! reports (VyOS T7747) show hardware offload refused or silently not
//! used even then, so the backend always falls back to software and the
//! conntrack's `HW_OFFLOAD` bit is the only proof.

use serde::Serialize;

/// The eSwitch mode of a card (`devlink dev eswitch show`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EswitchMode {
    Legacy,
    Switchdev,
}

impl EswitchMode {
    pub fn as_str(self) -> &'static str {
        match self {
            EswitchMode::Legacy => "legacy",
            EswitchMode::Switchdev => "switchdev",
        }
    }
}

/// What the fast path needs to know about one port.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Eswitch {
    pub driver: Option<String>,
    pub firmware: Option<String>,
    /// `pci/0000:03:00.0`: the devlink handle.
    pub devlink: Option<String>,
    /// `None`: the driver has no devlink eSwitch.
    pub mode: Option<EswitchMode>,
    /// A switchdev representor (`phys_port_name` like `p0` or `pf0vf1`).
    pub representor: bool,
    /// `ethtool -k`'s `hw-tc-offload`; `None`: the driver lacks it.
    pub hw_tc_offload: Option<bool>,
    pub notes: Vec<String>,
}

/// What the backend installed at the last apply.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct FastPathState {
    /// The flowtable is in the kernel.
    pub active: bool,
    /// It was installed with `flags offload` (the card was asked).
    pub hardware: bool,
    /// Its ports.
    pub devices: Vec<String>,
    /// Why hardware (or the whole fast path) is not in place, when it was
    /// asked for.
    pub note: Option<String>,
}
