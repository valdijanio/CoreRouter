//! Port state over the `ethtool` generic netlink family (G1.19): link
//! modes, link info, link state, pause, features, rings, channels and the
//! standard statistics groups; plus driver/firmware versions from
//! `devlink`, when the driver registers one.
//!
//! G1.20 adds the writes (`LINKMODES_SET`, `PAUSE_SET`, `FEATURES_SET`),
//! the module EEPROM (`MODULE_EEPROM_GET`) and the cable test
//! (`CABLE_TEST_ACT`, whose result comes as a `monitor` group
//! notification).
//!
//! Netlink only: the `ETHTOOL_G*` ioctls (driver info, LED blink) would
//! need `unsafe`, so what only they report is left out. Each query that
//! the driver does not implement becomes a note, never an error.

use std::collections::BTreeMap;
use std::time::Duration;

use corerouter_hal::nic::MAX_ITEMS;
use corerouter_hal::{
    CablePair, CableTest, CableTestResult, EthernetMonitor, HalError, NicHardware, Offload,
};

use crate::ether::{EtherState, Link, rate_modes};
use crate::genl::{Attr, Attrs, Genl, GenlError, Msg, attrs, find};

const VERSION: u8 = 1;

// Requests (`ETHTOOL_MSG_*`).
const LINKINFO_GET: u8 = 2;
const LINKMODES_GET: u8 = 4;
const LINKMODES_SET: u8 = 5;
const LINKSTATE_GET: u8 = 6;
const FEATURES_GET: u8 = 11;
const FEATURES_SET: u8 = 12;
const RINGS_GET: u8 = 15;
const CHANNELS_GET: u8 = 17;
const PAUSE_GET: u8 = 21;
const PAUSE_SET: u8 = 22;
const CABLE_TEST_ACT: u8 = 26;
const MODULE_EEPROM_GET: u8 = 31;
const STATS_GET: u8 = 32;

// Kernel → user (`ETHTOOL_MSG_*_NTF`).
const CABLE_TEST_NTF: u8 = 27;

// `ETHTOOL_A_LINKMODES_*`, `ETHTOOL_A_PAUSE_*`, `ETHTOOL_A_FEATURES_*`.
const LINKMODES_AUTONEG: u16 = 2;
const LINKMODES_OURS: u16 = 3;
const LINKMODES_SPEED: u16 = 5;
const LINKMODES_DUPLEX: u16 = 6;
const PAUSE_AUTONEG: u16 = 2;
const PAUSE_RX: u16 = 3;
const PAUSE_TX: u16 = 4;
const FEATURES_HW: u16 = 2;
const FEATURES_WANTED: u16 = 3;
const FEATURES_ACTIVE: u16 = 4;

// `ETHTOOL_A_MODULE_EEPROM_*`.
const EEPROM_OFFSET: u16 = 2;
const EEPROM_LENGTH: u16 = 3;
const EEPROM_PAGE: u16 = 4;
const EEPROM_BANK: u16 = 5;
const EEPROM_I2C: u16 = 6;
const EEPROM_DATA: u16 = 7;

// Cable test notification (`ETHTOOL_A_CABLE_*`).
const NTF_HEADER: u16 = 1;
const NTF_STATUS: u16 = 2;
const NTF_NEST: u16 = 3;
const NTF_COMPLETED: u8 = 2;
const NEST_RESULT: u16 = 1;
const NEST_FAULT_LENGTH: u16 = 2;
const RESULT_PAIR: u16 = 1;
const RESULT_CODE: u16 = 2;
const FAULT_PAIR: u16 = 1;
const FAULT_CM: u16 = 2;

// `ETHTOOL_A_HEADER_*`; every request's header is its attribute 1, except
// STATS (2).
const HEADER_DEV_NAME: u16 = 2;
const HEADER_FLAGS: u16 = 3;
const FLAG_STATS: u32 = 1 << 2;

// Bit sets (`ETHTOOL_A_BITSET_*`).
const BITSET_NOMASK: u16 = 1;
const BITSET_SIZE: u16 = 2;
const BITSET_BITS: u16 = 3;
const BITSET_VALUE: u16 = 4;
const BITS_BIT: u16 = 1;
const BIT_NAME: u16 = 2;
const BIT_VALUE: u16 = 3;

const SPEED_UNKNOWN: u32 = u32::MAX;

/// What one port says, query by query; each `None` is in `notes`.
pub(crate) struct Ethtool {
    genl: Genl,
    family: u16,
    dev: String,
    pub notes: Vec<String>,
}

impl Ethtool {
    pub fn open(dev: &str) -> Result<Self, GenlError> {
        let mut genl = Genl::open()?;
        let family = genl.family("ethtool")?;
        Ok(Self {
            genl,
            family,
            dev: dev.to_owned(),
            notes: Vec::new(),
        })
    }

    /// One GET; the reply's attributes, or `None` with a note saying why.
    fn get(&mut self, what: &str, cmd: u8, header: u16, flags: u32) -> Option<Vec<u8>> {
        self.get_with(what, cmd, header, flags, |_| {})
    }

    fn get_with(
        &mut self,
        what: &str,
        cmd: u8,
        header: u16,
        flags: u32,
        more: impl FnOnce(&mut Msg),
    ) -> Option<Vec<u8>> {
        match self.request(cmd, header, flags, more) {
            Ok(mut replies) if !replies.is_empty() => Some(replies.swap_remove(0).1),
            Ok(_) => {
                self.notes.push(format!("{what}: no answer"));
                None
            }
            Err(e) => {
                self.notes.push(format!("{what}: {e}"));
                None
            }
        }
    }

    /// One request about this port: header attribute `header`, then `more`.
    fn request(
        &mut self,
        cmd: u8,
        header: u16,
        flags: u32,
        more: impl FnOnce(&mut Msg),
    ) -> Result<Vec<(u8, Vec<u8>)>, GenlError> {
        let seq = self.genl.next_seq();
        let mut m = Msg::new(self.family, cmd, VERSION, seq);
        m.begin(header).str(HEADER_DEV_NAME, &self.dev);
        if flags != 0 {
            m.u32(HEADER_FLAGS, flags);
        }
        m.end();
        more(&mut m);
        self.genl.call(m.finish(), seq)
    }

    /// What `interface.ethernet.set` may change, as the port is now.
    pub fn state(&mut self) -> Result<EtherState, String> {
        let mut st = EtherState::default();
        let a = self
            .request(LINKMODES_GET, 1, 0, |_| {})
            .map_err(|e| format!("link modes: {e}"))?;
        if let Some((_, a)) = a.first() {
            for at in attrs(a) {
                match at.kind {
                    LINKMODES_AUTONEG => st.autoneg = at.u8().map(|v| v != 0),
                    LINKMODES_OURS => {
                        let ours = bitset(at.nested());
                        let all: Vec<String> = ours.iter().map(|(n, _)| n.clone()).collect();
                        let on: Vec<String> = ours
                            .into_iter()
                            .filter(|(_, on)| *on)
                            .map(|(n, _)| n)
                            .collect();
                        st.supported = rate_modes(&all);
                        st.advertising = rate_modes(&on);
                    }
                    LINKMODES_SPEED => {
                        st.speed_mbps = at.u32().filter(|s| *s != SPEED_UNKNOWN && *s != 0);
                    }
                    LINKMODES_DUPLEX => {
                        st.full_duplex = match at.u8() {
                            Some(0) => Some(false),
                            Some(1) => Some(true),
                            _ => None,
                        }
                    }
                    _ => {}
                }
            }
        }
        if let Ok(r) = self.request(PAUSE_GET, 1, 0, |_| {})
            && let Some((_, a)) = r.first()
        {
            let flag = |k: u16| find(attrs(a), k).and_then(|x| x.u8()).map(|v| v != 0);
            if let (Some(an), Some(rx), Some(tx)) =
                (flag(PAUSE_AUTONEG), flag(PAUSE_RX), flag(PAUSE_TX))
            {
                st.pause = Some((an, rx, tx));
            }
        }
        if let Ok(r) = self.request(FEATURES_GET, 1, 0, |_| {})
            && let Some((_, a)) = r.first()
        {
            let names = |kind: u16| -> Vec<String> {
                find(attrs(a), kind)
                    .map(|b| {
                        bitset(b.nested())
                            .into_iter()
                            .filter(|(_, on)| *on)
                            .map(|(n, _)| n)
                            .collect()
                    })
                    .unwrap_or_default()
            };
            let active = names(FEATURES_ACTIVE);
            st.features = names(FEATURES_HW)
                .into_iter()
                .take(MAX_ITEMS)
                .map(|f| {
                    let on = active.contains(&f);
                    (f, on)
                })
                .collect();
        }
        Ok(st)
    }

    /// `LINKMODES_SET`: auto-negotiate advertising `modes` (only the rate
    /// modes of `supported` change), or force a rate and duplex.
    pub fn set_link(&mut self, link: &Link, supported: &[String]) -> Result<(), GenlError> {
        self.request(LINKMODES_SET, 1, 0, |m| match link {
            Link::Auto(modes) => {
                m.u8(LINKMODES_AUTONEG, 1);
                // A bit set with a mask: listed bits change, VALUE = on.
                m.begin(LINKMODES_OURS).begin(BITSET_BITS);
                for name in supported.iter().take(MAX_ITEMS) {
                    m.begin(BITS_BIT).str(BIT_NAME, name);
                    if modes.contains(name) {
                        m.flag(BIT_VALUE);
                    }
                    m.end();
                }
                m.end().end();
            }
            Link::Forced {
                speed_mbps,
                full_duplex,
            } => {
                m.u8(LINKMODES_AUTONEG, 0)
                    .u32(LINKMODES_SPEED, *speed_mbps)
                    .u8(LINKMODES_DUPLEX, u8::from(*full_duplex));
            }
        })
        .map(|_| ())
    }

    /// `PAUSE_SET`.
    pub fn set_pause(&mut self, (autoneg, rx, tx): (bool, bool, bool)) -> Result<(), GenlError> {
        self.request(PAUSE_SET, 1, 0, |m| {
            m.u8(PAUSE_AUTONEG, u8::from(autoneg))
                .u8(PAUSE_RX, u8::from(rx))
                .u8(PAUSE_TX, u8::from(tx));
        })
        .map(|_| ())
    }

    /// `FEATURES_SET` of `changes` (feature → on).
    pub fn set_features(&mut self, changes: &BTreeMap<String, bool>) -> Result<(), GenlError> {
        if changes.is_empty() {
            return Ok(());
        }
        self.request(FEATURES_SET, 1, 0, |m| {
            m.begin(FEATURES_WANTED).begin(BITSET_BITS);
            for (name, on) in changes.iter().take(MAX_ITEMS) {
                m.begin(BITS_BIT).str(BIT_NAME, name);
                if *on {
                    m.flag(BIT_VALUE);
                }
                m.end();
            }
            m.end().end();
        })
        .map(|_| ())
    }

    /// `len` bytes (at most 128, not across offset 128) of `page` at I²C
    /// address `i2c`, from `offset`.
    pub fn module_eeprom(
        &mut self,
        i2c: u8,
        page: u8,
        offset: u32,
        len: u32,
    ) -> Result<Vec<u8>, GenlError> {
        let r = self.request(MODULE_EEPROM_GET, 1, 0, |m| {
            m.u32(EEPROM_OFFSET, offset)
                .u32(EEPROM_LENGTH, len)
                .u8(EEPROM_PAGE, page)
                .u8(EEPROM_BANK, 0)
                .u8(EEPROM_I2C, i2c);
        })?;
        r.first()
            .and_then(|(_, a)| find(attrs(a), EEPROM_DATA))
            .map(|d| {
                d.data
                    .iter()
                    .take(corerouter_hal::sff::HALF_PAGE)
                    .copied()
                    .collect()
            })
            .ok_or_else(|| GenlError::Io("no EEPROM data in the answer".into()))
    }

    /// `/interface ethernet monitor`, minus what rtnetlink adds.
    pub fn monitor(&mut self, m: &mut EthernetMonitor) {
        if let Some(a) = self.get("link modes", LINKMODES_GET, 1, 0) {
            for at in attrs(&a) {
                match at.kind {
                    2 => m.autoneg = at.u8().map(|v| v != 0),
                    3 => {
                        let ours = bitset(at.nested());
                        m.supported = ours.iter().map(|(n, _)| n.clone()).collect();
                        m.advertising = ours
                            .into_iter()
                            .filter(|(_, on)| *on)
                            .map(|(n, _)| n)
                            .collect();
                    }
                    4 => {
                        m.partner_advertising = bitset(at.nested())
                            .into_iter()
                            .filter(|(_, on)| *on)
                            .map(|(n, _)| n)
                            .collect();
                    }
                    5 => m.speed_mbps = at.u32().filter(|s| *s != SPEED_UNKNOWN && *s != 0),
                    6 => {
                        m.full_duplex = match at.u8() {
                            Some(0) => Some(false),
                            Some(1) => Some(true),
                            _ => None,
                        }
                    }
                    _ => {}
                }
            }
        }
        if let Some(a) = self.get("link info", LINKINFO_GET, 1, 0) {
            for at in attrs(&a) {
                match at.kind {
                    2 => m.port = at.u8().map(port_name),
                    4 => m.mdix = at.u8().and_then(mdix_name),
                    5 => m.mdix_ctrl = at.u8().and_then(mdix_name),
                    _ => {}
                }
            }
        }
        if let Some(a) = self.get("link state", LINKSTATE_GET, 1, 0) {
            for at in attrs(&a) {
                if at.kind == 5 {
                    m.down_reason = at.u8().map(down_reason);
                }
            }
        }
        if let Some(a) = self.get("flow control", PAUSE_GET, 1, 0) {
            for at in attrs(&a) {
                match at.kind {
                    2 => m.flow_control_autoneg = at.u8().map(|v| v != 0),
                    3 => m.rx_flow_control = at.u8().map(|v| v != 0),
                    4 => m.tx_flow_control = at.u8().map(|v| v != 0),
                    _ => {}
                }
            }
        }
    }

    /// Rings, channels and offloads into `hw`.
    pub fn hardware(&mut self, hw: &mut NicHardware) {
        if let Some(a) = self.get("rings", RINGS_GET, 1, 0) {
            for at in attrs(&a) {
                match at.kind {
                    2 => hw.ring_rx_max = at.u32(),
                    5 => hw.ring_tx_max = at.u32(),
                    6 => hw.ring_rx = at.u32(),
                    9 => hw.ring_tx = at.u32(),
                    _ => {}
                }
            }
        }
        if let Some(a) = self.get("channels", CHANNELS_GET, 1, 0) {
            for at in attrs(&a) {
                match at.kind {
                    5 => hw.combined_channels_max = at.u32(),
                    9 => hw.combined_channels = at.u32(),
                    _ => {}
                }
            }
        }
        if let Some(a) = self.get("offloads", FEATURES_GET, 1, 0) {
            let set = |kind: u16| -> Vec<String> {
                find(attrs(&a), kind)
                    .map(|b| {
                        bitset(b.nested())
                            .into_iter()
                            .filter(|(_, on)| *on)
                            .map(|(n, _)| n)
                            .collect()
                    })
                    .unwrap_or_default()
            };
            // `ethtool -k` shows "[fixed]" for what is not in `hw`.
            let hw_set = set(2);
            let active = set(4);
            let known = |f: &&&str| active.iter().chain(&hw_set).any(|x| x == **f);
            hw.offloads = OFFLOADS
                .iter()
                .filter_map(|(name, features)| {
                    // The first alternative the kernel knows.
                    let feature = features.iter().find(known).or_else(|| features.first())?;
                    Some(Offload {
                        name: (*name).into(),
                        feature: (*feature).into(),
                        active: active.iter().any(|a| a == feature),
                        fixed: !hw_set.iter().any(|x| x == feature),
                    })
                })
                .collect();
        }
    }

    /// Pause-frame counters (`ethtool -I -a`), if the driver keeps them.
    pub fn pause_stats(&mut self) -> Option<Vec<(String, u64)>> {
        let a = self.get("pause counters", PAUSE_GET, 1, FLAG_STATS)?;
        let stats = find(attrs(&a), 5)?;
        let mut out = Vec::new();
        for s in stats.nested() {
            match s.kind {
                2 => out.push(("tx_pause_frames".to_owned(), s.u64()?)),
                3 => out.push(("rx_pause_frames".to_owned(), s.u64()?)),
                _ => {}
            }
        }
        Some(out)
    }

    /// The standard groups (`ethtool -S --all-groups`): eth-phy, eth-mac,
    /// eth-ctrl, rmon, each only when the driver fills it.
    pub fn std_stats(&mut self) -> Vec<(&'static str, Vec<(String, u64)>)> {
        let Some(a) = self.get_with("standard counters", STATS_GET, 2, 0, |m| {
            // All four groups, as a compact bit set.
            m.begin(3)
                .flag(BITSET_NOMASK)
                .u32(BITSET_SIZE, 4)
                .u32(BITSET_VALUE, 0b1111)
                .end();
        }) else {
            return Vec::new();
        };
        let mut out: Vec<(&'static str, Vec<(String, u64)>)> = Vec::new();
        for grp in attrs(&a).filter(|g| g.kind == 4) {
            let Some(id) = find(grp.nested(), 2).and_then(|x| x.u32()) else {
                continue;
            };
            let Some((group, names)) = STD_GROUPS.get(usize::try_from(id).unwrap_or(usize::MAX))
            else {
                continue;
            };
            let mut counters = Vec::new();
            for at in grp.nested() {
                match at.kind {
                    4 => {
                        for v in at.nested() {
                            let name = names
                                .get(usize::from(v.kind))
                                .map_or_else(|| format!("stat_{}", v.kind), |n| (*n).to_owned());
                            if let Some(val) = v.u64() {
                                counters.push((name, val));
                            }
                        }
                    }
                    5 | 6 => {
                        let dir = if at.kind == 5 { "rx" } else { "tx" };
                        if let Some(c) = bucket(dir, at) {
                            counters.push(c);
                        }
                    }
                    _ => {}
                }
                if counters.len() >= MAX_ITEMS {
                    break;
                }
            }
            if !counters.is_empty() {
                out.push((group, counters));
            }
        }
        out
    }
}

/// A cable test of one port over ethtool netlink: start it, then wait for
/// the `monitor` group notification that carries the result.
pub(crate) struct LinuxCableTest {
    pub dev: String,
}

/// How long a PHY may take (they need 1–10 s).
const CABLE_TEST_SECS: u64 = 30;
const CABLE_TEST_SLICE_MS: u16 = 200;

impl CableTest for LinuxCableTest {
    fn run(&mut self, wait: &dyn Fn(Duration) -> bool) -> Result<CableTestResult, HalError> {
        let io = |e: GenlError| HalError::Io(e.to_string());
        let mut genl = Genl::open().map_err(io)?;
        let (family, group) = genl.family_and_group("ethtool", "monitor").map_err(io)?;
        let group = group.ok_or_else(|| {
            HalError::Unsupported("this kernel's ethtool netlink has no monitor group".into())
        })?;
        // Join before starting, so the result cannot slip past.
        genl.join(group).map_err(io)?;
        let seq = genl.next_seq();
        let mut m = Msg::new(family, CABLE_TEST_ACT, VERSION, seq);
        m.begin(1).str(HEADER_DEV_NAME, &self.dev).end();
        genl.call(m.finish(), seq).map_err(|e| {
            if e.unsupported() {
                HalError::Unsupported(format!(
                    "the PHY of '{}' cannot test cables ({e})",
                    self.dev
                ))
            } else {
                HalError::Rejected(format!("cable test of '{}': {e}", self.dev))
            }
        })?;
        let rounds = CABLE_TEST_SECS * 1000 / u64::from(CABLE_TEST_SLICE_MS);
        for _ in 0..rounds {
            if !wait(Duration::ZERO) {
                return Err(HalError::Io("stopped".into()));
            }
            for (cmd, a) in genl.notifications(CABLE_TEST_SLICE_MS).map_err(io)? {
                if cmd == CABLE_TEST_NTF
                    && let Some(result) = cable_result(&a, &self.dev)
                {
                    return Ok(result);
                }
            }
        }
        Err(HalError::Io(format!(
            "no cable test result from '{}' in {CABLE_TEST_SECS} s",
            self.dev
        )))
    }
}

/// The result in a `CABLE_TEST_NTF` for `dev`, once it says completed.
pub(crate) fn cable_result(ntf: &[u8], dev: &str) -> Option<CableTestResult> {
    let ours = find(attrs(ntf), NTF_HEADER)
        .and_then(|h| find(h.nested(), HEADER_DEV_NAME))
        .and_then(|n| n.str())
        .is_some_and(|n| n == dev);
    let done = find(attrs(ntf), NTF_STATUS).and_then(|s| s.u8()) == Some(NTF_COMPLETED);
    if !ours || !done {
        return None;
    }
    let mut pairs: BTreeMap<u8, (String, Option<f64>)> = BTreeMap::new();
    if let Some(nest) = find(attrs(ntf), NTF_NEST) {
        for item in nest.nested().take(16) {
            match item.kind {
                NEST_RESULT => {
                    let pair = find(item.nested(), RESULT_PAIR).and_then(|x| x.u8());
                    let code = find(item.nested(), RESULT_CODE).and_then(|x| x.u8());
                    if let (Some(p), Some(c)) = (pair, code) {
                        pairs.entry(p).or_insert((String::new(), None)).0 = cable_code(c).into();
                    }
                }
                NEST_FAULT_LENGTH => {
                    let pair = find(item.nested(), FAULT_PAIR).and_then(|x| x.u8());
                    let cm = find(item.nested(), FAULT_CM).and_then(|x| x.u32());
                    if let (Some(p), Some(cm)) = (pair, cm) {
                        pairs.entry(p).or_insert(("unknown".into(), None)).1 =
                            Some(f64::from(cm) / 100.0);
                    }
                }
                _ => {}
            }
        }
    }
    let mut out = CableTestResult::default();
    for (p, (status, distance_m)) in pairs {
        out.pairs.push(CablePair {
            pair: char::from(b'A'.saturating_add(p.min(25))).to_string(),
            status: if status.is_empty() {
                "unknown".into()
            } else {
                status
            },
            distance_m,
        });
    }
    if out.pairs.is_empty() {
        out.notes.push("the PHY reported no pairs".into());
    }
    Some(out)
}

/// `ETHTOOL_A_CABLE_RESULT_CODE_*`.
fn cable_code(c: u8) -> &'static str {
    match c {
        1 => "ok",
        2 => "open",
        3 => "short",
        4 => "cross-short",
        5 => "impedance-mismatch",
        6 => "noise",
        _ => "unknown",
    }
}

/// One RMON histogram bucket: `rx_65_127` = 1234.
fn bucket(dir: &str, at: Attr<'_>) -> Option<(String, u64)> {
    let low = find(at.nested(), 7)?.u32()?;
    let hi = find(at.nested(), 8)?.u32()?;
    let val = find(at.nested(), 9)?.u64()?;
    let name = match (low, hi) {
        (l, 0) => format!("{dir}_{l}_max"),
        (l, h) if l == h => format!("{dir}_{l}"),
        (l, h) => format!("{dir}_{l}_{h}"),
    };
    Some((name, val))
}

/// Verbose bit set → (bit name, set?). With a mask, the listed bits are
/// the mask and the value flag says which are set; without (`NOMASK`),
/// the listed bits are the set ones. A compact set (no names) gives
/// `bit N`.
pub(crate) fn bitset(set: Attrs<'_>) -> Vec<(String, bool)> {
    let nomask = set.clone().any(|a| a.kind == BITSET_NOMASK);
    if let Some(bits) = find(set.clone(), BITSET_BITS) {
        return bits
            .nested()
            .filter(|b| b.kind == BITS_BIT)
            .take(MAX_ITEMS)
            .filter_map(|b| {
                let name = find(b.nested(), BIT_NAME)?.str()?;
                let on = nomask || b.nested().any(|x| x.kind == BIT_VALUE);
                Some((name, on))
            })
            .collect();
    }
    let size = find(set.clone(), BITSET_SIZE)
        .and_then(|a| a.u32())
        .unwrap_or(0);
    let value = find(set, BITSET_VALUE).map(|a| a.data).unwrap_or(&[]);
    (0..size.min(u32::try_from(MAX_ITEMS).unwrap_or(0)))
        .filter_map(|i| {
            let byte = value.get(usize::try_from(i / 8).ok()?)?;
            let on = byte & (1 << (i % 8)) != 0;
            on.then(|| (format!("bit {i}"), true))
        })
        .collect()
}

fn port_name(p: u8) -> String {
    match p {
        0 => "twisted-pair",
        1 => "aui",
        2 => "bnc",
        3 => "mii",
        4 => "fibre",
        5 => "direct-attach",
        0xef => "none",
        _ => "other",
    }
    .into()
}

fn mdix_name(v: u8) -> Option<String> {
    match v {
        1 => Some("mdi".into()),
        2 => Some("mdi-x".into()),
        3 => Some("auto".into()),
        _ => None,
    }
}

/// `ethtool_link_ext_state`.
fn down_reason(v: u8) -> String {
    match v {
        0 => "autoneg",
        1 => "link-training-failure",
        2 => "link-logical-mismatch",
        3 => "bad-signal-integrity",
        4 => "no-cable",
        5 => "cable-issue",
        6 => "eeprom-issue",
        7 => "calibration-failure",
        8 => "power-budget-exceeded",
        9 => "overheat",
        10 => "module",
        _ => "other",
    }
    .into()
}

/// Offloads shown, each with the kernel features that implement it (the
/// first one the kernel knows is used).
const OFFLOADS: &[(&str, &[&str])] = &[
    ("TSO", &["tx-tcp-segmentation"]),
    ("TSO6", &["tx-tcp6-segmentation"]),
    ("GSO", &["tx-generic-segmentation"]),
    ("GRO", &["rx-gro"]),
    ("GRO (hardware)", &["rx-gro-hw"]),
    ("LRO", &["rx-lro"]),
    ("RX checksum", &["rx-checksum"]),
    (
        "TX checksum",
        &[
            "tx-checksum-ip-generic",
            "tx-checksum-ipv4",
            "tx-checksum-ipv6",
        ],
    ),
    ("Scatter-gather", &["tx-scatter-gather"]),
    ("RX VLAN", &["rx-vlan-hw-parse"]),
    ("TX VLAN", &["tx-vlan-hw-insert"]),
    ("VLAN filter", &["rx-vlan-filter"]),
    ("RX hashing", &["rx-hashing"]),
    ("N-tuple filters", &["rx-ntuple-filter"]),
];

/// `ETHTOOL_STATS_*` groups and their counters, by attribute number.
const STD_GROUPS: [(&str, &[&str]); 4] = [
    ("eth-phy", &["symbol_errors"]),
    (
        "eth-mac",
        &[
            "tx_frames_ok",
            "single_collisions",
            "multiple_collisions",
            "rx_frames_ok",
            "fcs_errors",
            "alignment_errors",
            "tx_octets_ok",
            "deferred",
            "late_collisions",
            "excessive_collisions",
            "tx_mac_errors",
            "carrier_sense_errors",
            "rx_octets_ok",
            "rx_mac_errors",
            "tx_multicast",
            "tx_broadcast",
            "excessive_deferral",
            "rx_multicast",
            "rx_broadcast",
            "in_range_length_errors",
            "out_of_range_length",
            "frame_too_long",
        ],
    ),
    (
        "eth-ctrl",
        &[
            "tx_control_frames",
            "rx_control_frames",
            "rx_unsupported_opcodes",
        ],
    ),
    ("rmon", &["undersize", "oversize", "fragments", "jabbers"]),
];

// devlink (`DEVLINK_*`): driver, serial and firmware versions.
const DEVLINK_CMD_INFO_GET: u8 = 51;
const DEVLINK_ATTR_BUS_NAME: u16 = 1;
const DEVLINK_ATTR_DEV_NAME: u16 = 2;
const DEVLINK_ATTR_INFO_DRIVER_NAME: u16 = 98;
const DEVLINK_ATTR_INFO_SERIAL_NUMBER: u16 = 99;
const DEVLINK_ATTR_INFO_VERSION_RUNNING: u16 = 101;
const DEVLINK_ATTR_INFO_VERSION_NAME: u16 = 103;
const DEVLINK_ATTR_INFO_VERSION_VALUE: u16 = 104;

/// Firmware and serial from `devlink dev info <bus>/<dev>`. `Err` is a
/// note: most drivers of simple NICs register no devlink instance.
pub(crate) fn devlink_info(bus: &str, dev: &str, hw: &mut NicHardware) -> Result<(), String> {
    let mut genl = Genl::open().map_err(|e| e.to_string())?;
    let family = genl
        .family("devlink")
        .map_err(|e| format!("no devlink in this kernel ({e})"))?;
    let seq = genl.next_seq();
    let mut m = Msg::new(family, DEVLINK_CMD_INFO_GET, VERSION, seq);
    m.str(DEVLINK_ATTR_BUS_NAME, bus)
        .str(DEVLINK_ATTR_DEV_NAME, dev);
    let replies = genl.call(m.finish(), seq).map_err(|e| {
        if e.unsupported() || e == GenlError::Errno(19) {
            "the driver has no devlink info".to_owned()
        } else {
            e.to_string()
        }
    })?;
    let Some((_, a)) = replies.first() else {
        return Err("devlink: no answer".into());
    };
    let mut running = Vec::new();
    for at in attrs(a) {
        match at.kind {
            DEVLINK_ATTR_INFO_DRIVER_NAME if hw.driver.is_none() => hw.driver = at.str(),
            DEVLINK_ATTR_INFO_SERIAL_NUMBER => hw.serial = at.str().filter(|s| !s.is_empty()),
            DEVLINK_ATTR_INFO_VERSION_RUNNING => {
                let name = find(at.nested(), DEVLINK_ATTR_INFO_VERSION_NAME).and_then(|x| x.str());
                let value =
                    find(at.nested(), DEVLINK_ATTR_INFO_VERSION_VALUE).and_then(|x| x.str());
                if let (Some(n), Some(v)) = (name, value)
                    && running.len() < 16
                {
                    running.push((n, v));
                }
            }
            _ => {}
        }
    }
    hw.firmware = match running.iter().find(|(n, _)| n == "fw") {
        Some((_, v)) => Some(v.clone()),
        None if running.is_empty() => None,
        None => Some(
            running
                .iter()
                .map(|(n, v)| format!("{n} {v}"))
                .collect::<Vec<_>>()
                .join(", "),
        ),
    };
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A nested attribute, encoded by hand.
    fn nla(kind: u16, data: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&((4 + data.len()) as u16).to_ne_bytes());
        b.extend_from_slice(&kind.to_ne_bytes());
        b.extend_from_slice(data);
        b.resize(b.len().div_ceil(4) * 4, 0);
        b
    }

    fn bit(name: &str, on: bool) -> Vec<u8> {
        let mut inner = nla(BIT_NAME, format!("{name}\0").as_bytes());
        if on {
            inner.extend(nla(BIT_VALUE, &[]));
        }
        nla(BITS_BIT, &inner)
    }

    #[test]
    fn verbose_bitsets_with_and_without_mask() {
        let bits = [bit("100baseT/Full", true), bit("1000baseT/Full", false)].concat();
        let masked = nla(BITSET_BITS, &bits);
        assert_eq!(
            bitset(attrs(&masked)),
            [
                ("100baseT/Full".to_owned(), true),
                ("1000baseT/Full".to_owned(), false)
            ]
        );
        let nomask = [
            nla(BITSET_NOMASK, &[]),
            nla(BITSET_BITS, &bit("rx-gro", false)),
        ]
        .concat();
        assert_eq!(bitset(attrs(&nomask)), [("rx-gro".to_owned(), true)]);
    }

    #[test]
    fn compact_bitset_names_bits_by_index() {
        let set = [
            nla(BITSET_SIZE, &10u32.to_ne_bytes()),
            nla(BITSET_VALUE, &[0b0000_0101, 0b10]),
        ]
        .concat();
        let on: Vec<String> = bitset(attrs(&set)).into_iter().map(|(n, _)| n).collect();
        assert_eq!(on, ["bit 0", "bit 2", "bit 9"]);
    }

    fn ntf(dev: &str, status: u8, items: &[Vec<u8>]) -> Vec<u8> {
        [
            nla(
                NTF_HEADER,
                &nla(HEADER_DEV_NAME, format!("{dev}\0").as_bytes()),
            ),
            nla(NTF_STATUS, &[status]),
            nla(NTF_NEST, &items.concat()),
        ]
        .concat()
    }

    #[test]
    fn cable_test_notification_per_pair() {
        let result = |pair: u8, code: u8| {
            nla(
                NEST_RESULT,
                &[nla(RESULT_PAIR, &[pair]), nla(RESULT_CODE, &[code])].concat(),
            )
        };
        let fault = |pair: u8, cm: u32| {
            nla(
                NEST_FAULT_LENGTH,
                &[nla(FAULT_PAIR, &[pair]), nla(FAULT_CM, &cm.to_ne_bytes())].concat(),
            )
        };
        let msg = ntf(
            "eth0",
            NTF_COMPLETED,
            &[
                result(0, 1),
                result(1, 2),
                fault(1, 2350),
                result(2, 3),
                fault(2, 400),
                result(3, 4),
            ],
        );
        let r = cable_result(&msg, "eth0").unwrap();
        let got: Vec<(&str, &str, Option<f64>)> = r
            .pairs
            .iter()
            .map(|p| (p.pair.as_str(), p.status.as_str(), p.distance_m))
            .collect();
        assert_eq!(
            got,
            [
                ("A", "ok", None),
                ("B", "open", Some(23.5)),
                ("C", "short", Some(4.0)),
                ("D", "cross-short", None)
            ]
        );
        // Started, or another port: not ours yet.
        assert_eq!(cable_result(&ntf("eth0", 1, &[]), "eth0"), None);
        assert_eq!(cable_result(&msg, "eth1"), None);
        let empty = cable_result(&ntf("eth0", NTF_COMPLETED, &[]), "eth0").unwrap();
        assert!(empty.pairs.is_empty() && !empty.notes.is_empty());
    }

    proptest::proptest! {
        /// Hostile notifications: never a panic, at most 16 pairs.
        #[test]
        fn hostile_cable_notifications(body in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..256),
                                       status in 0u8..4) {
            let msg = ntf("eth0", status, &[body]);
            if let Some(r) = cable_result(&msg, "eth0") {
                proptest::prop_assert!(r.pairs.len() <= 16);
            }
        }
    }

    #[test]
    fn rmon_buckets_are_named_by_range() {
        let b = |l: u32, h: u32| {
            [
                nla(7, &l.to_ne_bytes()),
                nla(8, &h.to_ne_bytes()),
                nla(9, &5u64.to_ne_bytes()),
            ]
            .concat()
        };
        let one = nla(5, &b(64, 64));
        let at = attrs(&one).next().unwrap();
        assert_eq!(bucket("rx", at), Some(("rx_64".into(), 5)));
        let range = nla(6, &b(65, 127));
        assert_eq!(
            bucket("tx", attrs(&range).next().unwrap()),
            Some(("tx_65_127".into(), 5))
        );
        let top = nla(5, &b(1519, 0));
        assert_eq!(
            bucket("rx", attrs(&top).next().unwrap()),
            Some(("rx_1519_max".into(), 5))
        );
    }
}
