//! Pluggable module EEPROMs (G1.20): what `/interface ethernet monitor`
//! shows about an SFP/SFP+/SFP28 (SFF-8472) or QSFP/QSFP+/QSFP28
//! (SFF-8636) module and its digital diagnostics (DOM/DDM), decoded from
//! the raw pages in pure code.
//!
//! The bytes come from the module itself (any vendor, any firmware, any
//! counterfeit): every read is bounds-checked, short pages give `None`,
//! and values that do not come out as finite numbers are dropped. Nothing
//! here can panic (see the proptest at the bottom).
//!
//! What a backend reads, per [`diag_page`]:
//! - page 0 of I²C address 0x50: bytes 0..256 (lower and upper half);
//! - SFF-8472 with diagnostics: bytes 0..128 of address 0x51 ("A2h");
//! - SFF-8636 with paging: upper page 03h (bytes 128..256 of page 3), the
//!   alarm and warning thresholds.
//!
//! CMIS modules (QSFP-DD, OSFP) are named but not decoded yet.

use serde::Serialize;

/// Half a page: what one `MODULE_EEPROM_GET` may return.
pub const HALF_PAGE: usize = 128;

/// A0h / page 0 bytes [`decode`] uses.
pub const PAGE0_LEN: usize = 256;

/// "No light": the floor of power readings, like most vendors' tools.
pub const MIN_DBM: f64 = -40.0;

/// Where a reading stands against the module's own thresholds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Level {
    Ok,
    LowWarning,
    HighWarning,
    LowAlarm,
    HighAlarm,
}

impl Level {
    pub fn label(self) -> &'static str {
        match self {
            Level::Ok => "ok",
            Level::LowWarning => "low-warning",
            Level::HighWarning => "high-warning",
            Level::LowAlarm => "low-alarm",
            Level::HighAlarm => "high-alarm",
        }
    }

    pub fn is_alarm(self) -> bool {
        matches!(self, Level::LowAlarm | Level::HighAlarm)
    }
}

/// Alarm and warning thresholds the module reports for one reading, in
/// the reading's unit.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct Limits {
    pub high_alarm: f64,
    pub high_warning: f64,
    pub low_warning: f64,
    pub low_alarm: f64,
}

impl Limits {
    /// Thresholds that make sense: finite, ordered, not all zero (a
    /// module that does not program them).
    fn checked(self) -> Option<Self> {
        let all = [
            self.high_alarm,
            self.high_warning,
            self.low_warning,
            self.low_alarm,
        ];
        let sane = all.iter().all(|v| v.is_finite())
            && all.iter().any(|v| *v != 0.0)
            && self.high_alarm >= self.high_warning
            && self.high_warning >= self.low_warning
            && self.low_warning >= self.low_alarm
            && self.high_alarm > self.low_alarm;
        sane.then_some(self)
    }

    pub fn level(&self, v: f64) -> Level {
        if v > self.high_alarm {
            Level::HighAlarm
        } else if v < self.low_alarm {
            Level::LowAlarm
        } else if v > self.high_warning {
            Level::HighWarning
        } else if v < self.low_warning {
            Level::LowWarning
        } else {
            Level::Ok
        }
    }
}

/// One DOM reading.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Reading {
    /// `temperature`, `supply-voltage`, `tx-bias-current`, `tx-power`,
    /// `rx-power` (RouterOS `sfp-*` names without the prefix).
    pub name: &'static str,
    /// Lane 1..=4 of a QSFP; `None` for a single-lane module.
    pub lane: Option<u8>,
    pub value: f64,
    /// `C`, `V`, `mA`, `dBm`.
    pub unit: &'static str,
    pub limits: Option<Limits>,
    /// `None` without thresholds.
    pub level: Option<Level>,
}

impl Reading {
    /// `rx-power` or `rx-power lane 2`.
    pub fn key(&self) -> String {
        match self.lane {
            Some(l) => format!("{} lane {l}", self.name),
            None => self.name.to_owned(),
        }
    }
}

/// Rated reach on one medium.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LinkLength {
    /// `smf` (9 µm), `om1` (62.5 µm), `om2` (50 µm), `om3`, `om4`, or
    /// `cable` (the length of a DAC/AOC assembly).
    pub medium: &'static str,
    pub meters: u32,
}

/// What a module says about itself.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct SfpModule {
    pub module_present: bool,
    /// `SFP/SFP+/SFP28`, `QSFP+`, `QSFP28`, … (SFF-8024 identifier).
    pub kind: Option<String>,
    /// Management interface: `SFF-8472`, `SFF-8636`, `CMIS`.
    pub spec: Option<String>,
    /// `LC`, `SC`, `copper-pigtail`, `RJ45`, `MPO 1x12`, …
    pub connector: Option<String>,
    /// Standards it claims: `10GBASE-SR`, `1000BASE-LX`, `100GBASE-SR4`, …
    pub compliance: Vec<String>,
    /// A passive or active copper cable (DAC/AOC copper): no laser.
    pub cable: bool,
    pub nominal_rate_mbd: Option<u32>,
    pub vendor_name: Option<String>,
    /// IEEE company id, `00:90:65`.
    pub vendor_oui: Option<String>,
    pub vendor_part_number: Option<String>,
    pub vendor_revision: Option<String>,
    pub vendor_serial: Option<String>,
    /// `2024-04-13`.
    pub manufacturing_date: Option<String>,
    pub wavelength_nm: Option<f64>,
    pub link_length: Vec<LinkLength>,
    /// Receiver sees no signal (any lane).
    pub rx_loss: Option<bool>,
    pub tx_fault: Option<bool>,
    /// Base and extended checksums both match (SFF-8472 / 8636).
    pub checksum_ok: Option<bool>,
    pub dom: Vec<Reading>,
    pub notes: Vec<String>,
}

impl SfpModule {
    /// A cage with nothing in it.
    pub fn empty(why: impl Into<String>) -> Self {
        Self {
            notes: vec![why.into()],
            ..Self::default()
        }
    }

    /// Readings outside their warning (or alarm) band.
    pub fn alerts(&self) -> impl Iterator<Item = &Reading> {
        self.dom
            .iter()
            .filter(|r| r.level.is_some_and(|l| l != Level::Ok))
    }
}

/// The extra page a backend must read for the diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagPage {
    /// No diagnostics, or not decoded.
    None,
    /// SFF-8472 "A2h": I²C address 0x51, bytes 0..128.
    A2,
    /// SFF-8636 upper page 03h: page 3, bytes 128..256 of address 0x50.
    Page3,
}

const ID_SFP: u8 = 0x03;
const ID_QSFP: u8 = 0x0C;
const ID_QSFP_PLUS: u8 = 0x0D;
const ID_QSFP28: u8 = 0x11;
/// Connector "no separable connector": a cable assembly (DAC, AOC).
const NO_SEPARABLE: u8 = 0x23;

/// Bounded byte access: out of range reads as missing.
#[derive(Clone, Copy)]
struct Bytes<'a>(&'a [u8]);

impl Bytes<'_> {
    fn u8(&self, at: usize) -> Option<u8> {
        self.0.get(at).copied()
    }

    fn bit(&self, at: usize, bit: u8) -> bool {
        self.u8(at).is_some_and(|b| b & (1 << bit) != 0)
    }

    fn u16(&self, at: usize) -> Option<u16> {
        Some(u16::from_be_bytes([self.u8(at)?, self.u8(at + 1)?]))
    }

    fn i16(&self, at: usize) -> Option<i16> {
        Some(i16::from_be_bytes([self.u8(at)?, self.u8(at + 1)?]))
    }

    fn f32(&self, at: usize) -> Option<f32> {
        let b = self.0.get(at..at + 4)?;
        Some(f32::from_be_bytes([
            *b.first()?,
            *b.get(1)?,
            *b.get(2)?,
            *b.get(3)?,
        ]))
    }

    /// Printable ASCII of `range`, trimmed; `None` when empty.
    fn text(&self, from: usize, to: usize) -> Option<String> {
        let raw = self.0.get(from..to)?;
        let s: String = raw
            .iter()
            .map(|b| match b {
                0x20..=0x7E => char::from(*b),
                _ => ' ',
            })
            .collect();
        let s = s.trim();
        (!s.is_empty()).then(|| s.to_owned())
    }

    /// `sum(from..to) & 0xFF == at`.
    fn checksum(&self, from: usize, to: usize, at: usize) -> Option<bool> {
        let sum = self
            .0
            .get(from..to)?
            .iter()
            .fold(0u8, |a, b| a.wrapping_add(*b));
        Some(self.u8(at)? == sum)
    }
}

/// SFF-8024 identifier (byte 0) → name and management interface.
fn identifier(id: u8) -> (String, Option<&'static str>) {
    let (name, spec) = match id {
        0x01 => ("GBIC", None),
        0x02 => ("soldered", Some("SFF-8472")),
        ID_SFP => ("SFP/SFP+/SFP28", Some("SFF-8472")),
        ID_QSFP => ("QSFP", Some("SFF-8636")),
        ID_QSFP_PLUS => ("QSFP+", Some("SFF-8636")),
        0x0E => ("CXP", None),
        ID_QSFP28 => ("QSFP28", Some("SFF-8636")),
        0x18 => ("QSFP-DD", Some("CMIS")),
        0x19 => ("OSFP", Some("CMIS")),
        0x1A => ("SFP-DD", None),
        0x1B => ("DSFP", None),
        0x1E => ("QSFP+ (CMIS)", Some("CMIS")),
        _ => return (format!("unknown (0x{id:02x})"), None),
    };
    (name.to_owned(), spec)
}

/// SFF-8024 connector type.
fn connector(c: u8) -> Option<String> {
    let s = match c {
        0x00 => return None,
        0x01 => "SC",
        0x02 => "FC style 1",
        0x03 => "FC style 2",
        0x04 => "BNC/TNC",
        0x05 => "FC coax",
        0x06 => "FiberJack",
        0x07 => "LC",
        0x08 => "MT-RJ",
        0x09 => "MU",
        0x0A => "SG",
        0x0B => "optical-pigtail",
        0x0C => "MPO 1x12",
        0x0D => "MPO 2x16",
        0x20 => "HSSDC II",
        0x21 => "copper-pigtail",
        0x22 => "RJ45",
        0x23 => "no-separable-connector",
        0x24 => "MXC 2x16",
        0x25 => "CS",
        0x26 => "SN",
        0x27 => "MPO 2x12",
        0x28 => "MPO 1x16",
        _ => return Some(format!("0x{c:02x}")),
    };
    Some(s.to_owned())
}

/// SFF-8024 extended compliance (SFF-8472 byte 36, SFF-8636 byte 192).
fn extended(c: u8) -> Option<&'static str> {
    Some(match c {
        0x01 => "100G AOC / 25GAUI C2M AOC",
        0x02 => "100GBASE-SR4 / 25GBASE-SR",
        0x03 => "100GBASE-LR4 / 25GBASE-LR",
        0x04 => "100GBASE-ER4 / 25GBASE-ER",
        0x05 => "100GBASE-SR10",
        0x06 => "100G CWDM4",
        0x07 => "100G PSM4",
        0x08 => "100G ACC / 25GAUI C2M ACC",
        0x0B => "100GBASE-CR4 / 25GBASE-CR CA-L",
        0x0C => "25GBASE-CR CA-S",
        0x0D => "25GBASE-CR CA-N",
        0x10 => "40GBASE-ER4",
        0x11 => "4x10GBASE-SR",
        0x12 => "40G PSM4",
        0x16 => "10GBASE-T (SFI)",
        0x17 => "100G CLR4",
        0x18 => "100G AOC / 25GAUI C2M AOC (low BER)",
        0x19 => "100G ACC / 25GAUI C2M ACC (low BER)",
        0x1A => "100GE-DWDM2",
        0x1C => "10GBASE-T (short reach)",
        0x1D => "5GBASE-T",
        0x1E => "2.5GBASE-T",
        0x20 => "100G SWDM4",
        0x21 => "100G PAM4 BiDi",
        0x25 => "100GBASE-DR",
        0x26 => "100G-FR",
        0x27 => "100G-LR",
        _ => return None,
    })
}

/// Power in units of 0.1 µW → dBm, floored at [`MIN_DBM`].
fn dbm(tenth_uw: f64) -> f64 {
    let mw = tenth_uw / 10_000.0;
    if mw <= 0.0 {
        return MIN_DBM;
    }
    (10.0 * mw.log10()).max(MIN_DBM)
}

/// One reading, kept only when the number is finite.
fn reading(
    name: &'static str,
    lane: Option<u8>,
    value: Option<f64>,
    unit: &'static str,
    limits: Option<Limits>,
) -> Option<Reading> {
    let value = value.filter(|v| v.is_finite())?;
    let limits = limits.and_then(Limits::checked);
    Some(Reading {
        name,
        lane,
        value,
        unit,
        level: limits.map(|l| l.level(value)),
        limits,
    })
}

/// Thresholds stored as (high alarm, low alarm, high warning, low
/// warning), each converted by `conv` — the order both specs use.
fn limits(
    b: Bytes<'_>,
    at: usize,
    conv: impl Fn(Bytes<'_>, usize) -> Option<f64>,
) -> Option<Limits> {
    Some(Limits {
        high_alarm: conv(b, at)?,
        low_alarm: conv(b, at + 2)?,
        high_warning: conv(b, at + 4)?,
        low_warning: conv(b, at + 6)?,
    })
}

/// `YYMMDD` (+ lot code) → `20YY-MM-DD`.
fn date(b: Bytes<'_>, at: usize) -> Option<String> {
    let d = b.text(at, at + 6)?;
    let ok = d.len() == 6 && d.bytes().all(|c| c.is_ascii_digit());
    let (yy, rest) = d.split_at_checked(2)?;
    let (mm, dd) = rest.split_at_checked(2)?;
    ok.then(|| format!("20{yy}-{mm}-{dd}"))
}

fn oui(b: Bytes<'_>, at: usize) -> Option<String> {
    let (x, y, z) = (b.u8(at)?, b.u8(at + 1)?, b.u8(at + 2)?);
    (x | y | z != 0).then(|| format!("{x:02x}:{y:02x}:{z:02x}"))
}

/// Which extra page the diagnostics need, from page 0 (at least the
/// lower half; the upper half matters for nothing here).
pub fn diag_page(page0: &[u8]) -> DiagPage {
    let b = Bytes(page0);
    match b.u8(0) {
        Some(ID_SFP | 0x02) => {
            // Byte 92: bit 6 diagnostics implemented, bit 2 "address
            // change required" (an old scheme nobody should drive).
            if b.bit(92, 6) && !b.bit(92, 2) {
                DiagPage::A2
            } else {
                DiagPage::None
            }
        }
        // Byte 2 bit 2: flat memory, no page 03h.
        Some(ID_QSFP | ID_QSFP_PLUS | ID_QSFP28) if !b.bit(2, 2) => DiagPage::Page3,
        _ => DiagPage::None,
    }
}

/// Decode page 0 (`PAGE0_LEN` bytes, fewer give fewer fields) and the
/// page [`diag_page`] asked for, if it was read.
pub fn decode(page0: &[u8], diag: Option<&[u8]>) -> SfpModule {
    let b = Bytes(page0);
    let Some(id) = b.u8(0) else {
        return SfpModule::empty("the module EEPROM could not be read");
    };
    if page0.iter().take(HALF_PAGE).all(|x| *x == 0xFF) || id == 0 {
        return SfpModule {
            module_present: true,
            notes: vec!["the module EEPROM is blank or unreadable".into()],
            ..SfpModule::default()
        };
    }
    let (kind, spec) = identifier(id);
    let mut m = SfpModule {
        module_present: true,
        kind: Some(kind),
        spec: spec.map(str::to_owned),
        ..SfpModule::default()
    };
    match spec {
        Some("SFF-8472") => sff8472(b, diag.map(Bytes), &mut m),
        Some("SFF-8636") => sff8636(b, diag.map(Bytes), &mut m),
        Some(other) => m.notes.push(format!(
            "{other} modules are identified only (not decoded yet)"
        )),
        None => m.notes.push("not a module type CoreRouter decodes".into()),
    }
    m
}

/// SFF-8472 calibration constants ("A2h" bytes 56..92).
struct Calibration {
    external: bool,
    rx: [f64; 5],
    bias: (f64, f64),
    tx: (f64, f64),
    temp: (f64, f64),
    vcc: (f64, f64),
}

impl Calibration {
    fn read(a2: Bytes<'_>, external: bool) -> Self {
        let slope = |at: usize| a2.u16(at).map_or(1.0, |v| f64::from(v) / 256.0);
        let offset = |at: usize| a2.i16(at).map_or(0.0, f64::from);
        let float = |at: usize| a2.f32(at).map_or(0.0, f64::from);
        if !external {
            return Self {
                external,
                rx: [0.0, 1.0, 0.0, 0.0, 0.0],
                bias: (1.0, 0.0),
                tx: (1.0, 0.0),
                temp: (1.0, 0.0),
                vcc: (1.0, 0.0),
            };
        }
        Self {
            external,
            // Rx_PWR(4) is first (byte 56), Rx_PWR(0) last (byte 72).
            rx: [float(72), float(68), float(64), float(60), float(56)],
            bias: (slope(76), offset(78)),
            tx: (slope(80), offset(82)),
            temp: (slope(84), offset(86)),
            vcc: (slope(88), offset(90)),
        }
    }

    fn linear((slope, offset): (f64, f64), raw: f64) -> f64 {
        slope * raw + offset
    }

    fn rx(&self, raw: f64) -> f64 {
        self.rx.iter().rev().fold(0.0, |acc, c| acc * raw + c)
    }
}

fn sff8472(b: Bytes<'_>, a2: Option<Bytes<'_>>, m: &mut SfpModule) {
    m.connector = b.u8(2).and_then(connector);
    let flags: &[(usize, u8, &str)] = &[
        (3, 4, "10GBASE-SR"),
        (3, 5, "10GBASE-LR"),
        (3, 6, "10GBASE-LRM"),
        (3, 7, "10GBASE-ER"),
        (6, 0, "1000BASE-SX"),
        (6, 1, "1000BASE-LX"),
        (6, 2, "1000BASE-CX"),
        (6, 3, "1000BASE-T"),
        (6, 4, "100BASE-LX"),
        (6, 5, "100BASE-FX"),
        (6, 6, "BASE-BX10"),
        (6, 7, "BASE-PX"),
        (8, 2, "passive copper cable"),
        (8, 3, "active cable"),
    ];
    m.compliance = flags
        .iter()
        .filter(|(at, bit, _)| b.bit(*at, *bit))
        .map(|(_, _, n)| (*n).to_owned())
        .collect();
    if let Some(x) = b.u8(36).and_then(extended) {
        m.compliance.push(x.to_owned());
    }
    m.cable = b.bit(8, 2) || b.bit(8, 3);
    m.nominal_rate_mbd = match (b.u8(12), b.u8(66)) {
        (Some(0xFF), Some(r)) if r != 0 => Some(u32::from(r) * 250),
        (Some(r), _) if r != 0 => Some(u32::from(r) * 100),
        _ => None,
    };
    let mut lengths = Vec::new();
    match (b.u8(14), b.u8(15)) {
        (Some(km), _) if km != 0 => lengths.push(("smf", u32::from(km) * 1000)),
        (_, Some(hm)) if hm != 0 => lengths.push(("smf", u32::from(hm) * 100)),
        _ => {}
    }
    for (at, medium, unit) in [(17, "om1", 10), (16, "om2", 10), (19, "om3", 10)] {
        if let Some(v) = b.u8(at).filter(|v| *v != 0) {
            lengths.push((medium, u32::from(v) * unit));
        }
    }
    if let Some(v) = b.u8(18).filter(|v| *v != 0) {
        // Byte 18 is the length (m) of a cable assembly, OM4 (10 m) otherwise.
        lengths.push(if m.cable || b.u8(2) == Some(NO_SEPARABLE) {
            ("cable", u32::from(v))
        } else {
            ("om4", u32::from(v) * 10)
        });
    }
    m.link_length = lengths
        .into_iter()
        .map(|(medium, meters)| LinkLength { medium, meters })
        .collect();
    m.vendor_name = b.text(20, 36);
    m.vendor_oui = oui(b, 37);
    m.vendor_part_number = b.text(40, 56);
    m.vendor_revision = b.text(56, 60);
    if !m.cable {
        m.wavelength_nm = b.u16(60).filter(|w| *w != 0).map(f64::from);
    }
    m.vendor_serial = b.text(68, 84);
    m.manufacturing_date = date(b, 84);
    m.checksum_ok = match (b.checksum(0, 63, 63), b.checksum(64, 95, 95)) {
        (Some(base), Some(ext)) => Some(base && ext),
        _ => None,
    };
    if m.checksum_ok == Some(false) {
        m.notes
            .push("EEPROM checksum mismatch: the module data may be wrong".into());
    }
    if !b.bit(92, 6) {
        m.notes.push("the module has no diagnostics (DOM)".into());
        return;
    }
    let Some(a2) = a2 else {
        m.notes.push("diagnostics page (A2h) not read".into());
        return;
    };
    let external = b.bit(92, 4) && !b.bit(92, 5);
    let cal = Calibration::read(a2, external);
    if cal.external {
        m.notes.push("externally calibrated module".into());
    }
    let temp = |x: Bytes<'_>, at: usize| {
        let raw = f64::from(x.i16(at)?);
        Some(Calibration::linear(cal.temp, raw) / 256.0)
    };
    let vcc = |x: Bytes<'_>, at: usize| {
        let raw = f64::from(x.u16(at)?);
        Some(Calibration::linear(cal.vcc, raw) / 10_000.0)
    };
    let bias = |x: Bytes<'_>, at: usize| {
        let raw = f64::from(x.u16(at)?);
        Some(Calibration::linear(cal.bias, raw) * 0.002)
    };
    let tx = |x: Bytes<'_>, at: usize| {
        let raw = f64::from(x.u16(at)?);
        Some(dbm(Calibration::linear(cal.tx, raw)))
    };
    let rx = |x: Bytes<'_>, at: usize| Some(dbm(cal.rx(f64::from(x.u16(at)?))));
    m.dom = [
        reading("temperature", None, temp(a2, 96), "C", limits(a2, 0, temp)),
        reading("supply-voltage", None, vcc(a2, 98), "V", limits(a2, 8, vcc)),
        reading(
            "tx-bias-current",
            None,
            bias(a2, 100),
            "mA",
            limits(a2, 16, bias),
        ),
        reading("tx-power", None, tx(a2, 102), "dBm", limits(a2, 24, tx)),
        reading("rx-power", None, rx(a2, 104), "dBm", limits(a2, 32, rx)),
    ]
    .into_iter()
    .flatten()
    .collect();
    if !b.bit(92, 3) {
        m.notes.push("rx-power is OMA, not average power".into());
    }
    // A0h byte 93: soft RX_LOS (bit 4) and TX_FAULT (bit 5) monitoring;
    // the states are A2h byte 110 bits 1 and 2.
    if b.bit(93, 4) {
        m.rx_loss = a2.u8(110).map(|s| s & 0x02 != 0);
    }
    if b.bit(93, 5) {
        m.tx_fault = a2.u8(110).map(|s| s & 0x04 != 0);
    }
}

fn sff8636(b: Bytes<'_>, page3: Option<Bytes<'_>>, m: &mut SfpModule) {
    // Upper page 00h is bytes 128..256 of page 0.
    m.connector = b.u8(130).and_then(connector);
    let flags: &[(usize, u8, &str)] = &[
        (131, 0, "40G active cable (XLPPI)"),
        (131, 1, "40GBASE-LR4"),
        (131, 2, "40GBASE-SR4"),
        (131, 3, "40GBASE-CR4"),
        (131, 4, "10GBASE-SR"),
        (131, 5, "10GBASE-LR"),
        (131, 6, "10GBASE-LRM"),
    ];
    m.compliance = flags
        .iter()
        .filter(|(at, bit, _)| b.bit(*at, *bit))
        .map(|(_, _, n)| (*n).to_owned())
        .collect();
    if b.bit(131, 7)
        && let Some(x) = b.u8(192).and_then(extended)
    {
        m.compliance.push(x.to_owned());
    }
    // Byte 147 bits 7..4: transmitter technology; 0xA and up is copper.
    m.cable = b.u8(147).is_some_and(|t| t >> 4 >= 0xA);
    m.nominal_rate_mbd = match (b.u8(140), b.u8(222)) {
        (Some(0xFF), Some(r)) if r != 0 => Some(u32::from(r) * 250),
        (Some(r), _) if r != 0 => Some(u32::from(r) * 100),
        _ => None,
    };
    let mut lengths = Vec::new();
    for (at, medium, unit) in [
        (142, "smf", 1000),
        (143, "om3", 2),
        (144, "om2", 1),
        (145, "om1", 1),
    ] {
        if let Some(v) = b.u8(at).filter(|v| *v != 0) {
            lengths.push((medium, u32::from(v) * unit));
        }
    }
    if let Some(v) = b.u8(146).filter(|v| *v != 0) {
        // A cable assembly (DAC or AOC) in meters, OM4 in 2 m otherwise.
        lengths.push(if m.cable || b.u8(130) == Some(NO_SEPARABLE) {
            ("cable", u32::from(v))
        } else {
            ("om4", u32::from(v) * 2)
        });
    }
    m.link_length = lengths
        .into_iter()
        .map(|(medium, meters)| LinkLength { medium, meters })
        .collect();
    m.vendor_name = b.text(148, 164);
    m.vendor_oui = oui(b, 165);
    m.vendor_part_number = b.text(168, 184);
    m.vendor_revision = b.text(184, 186);
    if !m.cable {
        m.wavelength_nm = b.u16(186).filter(|w| *w != 0).map(|w| f64::from(w) / 20.0);
    }
    m.vendor_serial = b.text(196, 212);
    m.manufacturing_date = date(b, 212);
    m.checksum_ok = match (b.checksum(128, 191, 191), b.checksum(192, 223, 223)) {
        (Some(base), Some(ext)) => Some(base && ext),
        _ => None,
    };
    if m.checksum_ok == Some(false) {
        m.notes
            .push("EEPROM checksum mismatch: the module data may be wrong".into());
    }
    if b.bit(2, 0) {
        m.notes
            .push("the module says its data is not ready yet".into());
    }
    // Latched flags, lower page: byte 3 RX LOS, byte 4 TX fault (lanes 1..4).
    m.rx_loss = b.u8(3).map(|v| v & 0x0F != 0);
    m.tx_fault = b.u8(4).map(|v| v & 0x0F != 0);

    // Thresholds in page 03h, bytes 128..256 (here 0..128).
    let p3 = page3.unwrap_or(Bytes(&[]));
    if page3.is_none() && !b.bit(2, 2) {
        m.notes.push("threshold page (03h) not read".into());
    }
    let temp = |x: Bytes<'_>, at: usize| Some(f64::from(x.i16(at)?) / 256.0);
    let vcc = |x: Bytes<'_>, at: usize| Some(f64::from(x.u16(at)?) / 10_000.0);
    let bias = |x: Bytes<'_>, at: usize| Some(f64::from(x.u16(at)?) * 0.002);
    let pwr = |x: Bytes<'_>, at: usize| Some(dbm(f64::from(x.u16(at)?)));
    let mut dom: Vec<Reading> = [
        reading("temperature", None, temp(b, 22), "C", limits(p3, 0, temp)),
        reading("supply-voltage", None, vcc(b, 26), "V", limits(p3, 16, vcc)),
    ]
    .into_iter()
    .flatten()
    .collect();
    // Byte 220 bit 2: TX power monitoring implemented.
    let tx_power = b.bit(220, 2);
    for lane in 0u8..4 {
        let at = usize::from(lane) * 2;
        let n = Some(lane + 1);
        dom.extend(reading(
            "tx-bias-current",
            n,
            bias(b, 42 + at),
            "mA",
            limits(p3, 56, bias),
        ));
        if tx_power {
            dom.extend(reading(
                "tx-power",
                n,
                pwr(b, 50 + at),
                "dBm",
                limits(p3, 64, pwr),
            ));
        }
        dom.extend(reading(
            "rx-power",
            n,
            pwr(b, 34 + at),
            "dBm",
            limits(p3, 48, pwr),
        ));
    }
    m.dom = dom;
    if !b.bit(220, 3) {
        m.notes.push("rx-power is OMA, not average power".into());
    }
}

/// A module for the virtual lab: an SFF-8472 SFP+ 10GBASE-SR with
/// internally calibrated diagnostics and sensible thresholds. `temp_c`,
/// `rx_dbm` and `tx_dbm` set the readings, so a test can push one past
/// its limits. Returns (A0h, A2h).
pub fn lab_sfp_plus(serial: &str, temp_c: f64, tx_dbm: f64, rx_dbm: f64) -> (Vec<u8>, Vec<u8>) {
    let mut a0 = vec![0u8; PAGE0_LEN];
    let put = |buf: &mut Vec<u8>, at: usize, bytes: &[u8]| {
        if let Some(slot) = buf.get_mut(at..at + bytes.len()) {
            slot.copy_from_slice(bytes);
        }
    };
    let pad = |s: &str, n: usize| {
        let mut v: Vec<u8> = s.bytes().take(n).collect();
        v.resize(n, b' ');
        v
    };
    put(&mut a0, 0, &[ID_SFP, 0x04, 0x07]); // SFP, LC
    put(&mut a0, 3, &[0x10]); // 10GBASE-SR
    put(&mut a0, 11, &[0x06, 0x67]); // 64B/66B, 10.3 GBd
    put(&mut a0, 16, &[0x08, 0x03, 0x00, 0x1E]); // OM2 80 m, OM1 30 m, OM3 300 m
    put(&mut a0, 20, &pad("CoreRouter Lab", 16));
    put(&mut a0, 37, &[0x00, 0x00, 0x00]);
    put(&mut a0, 40, &pad("CR-SFP10G-SR", 16));
    put(&mut a0, 56, &pad("A", 4));
    put(&mut a0, 60, &850u16.to_be_bytes());
    put(&mut a0, 65, &[0x1A]); // TX_DISABLE, TX_FAULT, LOS implemented
    put(&mut a0, 68, &pad(serial, 16));
    put(&mut a0, 84, b"260115  ");
    put(&mut a0, 92, &[0x68, 0xF0, 0x08]); // DDM, internal cal, average power
    let base = a0
        .get(..63)
        .map_or(0, |s| s.iter().fold(0u8, |a, b| a.wrapping_add(*b)));
    put(&mut a0, 63, &[base]);
    let ext = a0
        .get(64..95)
        .map_or(0, |s| s.iter().fold(0u8, |a, b| a.wrapping_add(*b)));
    put(&mut a0, 95, &[ext]);

    let mut a2 = vec![0u8; HALF_PAGE];
    let t = |c: f64| ((c * 256.0) as i16).to_be_bytes();
    let v = |volts: f64| ((volts * 10_000.0) as u16).to_be_bytes();
    let i = |ma: f64| ((ma / 0.002) as u16).to_be_bytes();
    let p = |dbm: f64| ((10f64.powf(dbm / 10.0) * 10_000.0).round() as u16).to_be_bytes();
    let four = |f: &dyn Fn(f64) -> [u8; 2], ha: f64, la: f64, hw: f64, lw: f64| {
        [f(ha), f(la), f(hw), f(lw)].concat()
    };
    put(&mut a2, 0, &four(&t, 78.0, -8.0, 73.0, -3.0));
    put(&mut a2, 8, &four(&v, 3.63, 2.97, 3.46, 3.13));
    put(&mut a2, 16, &four(&i, 13.0, 3.0, 12.0, 4.0));
    put(&mut a2, 24, &four(&p, 1.0, -7.3, -1.0, -6.0));
    put(&mut a2, 32, &four(&p, 1.0, -13.9, -1.0, -9.9));
    put(&mut a2, 96, &t(temp_c));
    put(&mut a2, 98, &v(3.29));
    put(&mut a2, 100, &i(6.6));
    put(&mut a2, 102, &p(tx_dbm));
    put(&mut a2, 104, &p(rx_dbm));
    // RX_LOS when there is no light.
    put(&mut a2, 110, &[if rx_dbm <= -30.0 { 0x02 } else { 0x00 }]);
    (a0, a2)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn get<'a>(m: &'a SfpModule, key: &str) -> &'a Reading {
        m.dom
            .iter()
            .find(|r| r.key() == key)
            .unwrap_or_else(|| panic!("no {key} in {:?}", m.dom))
    }

    #[test]
    fn lab_module_round_trips() {
        let (a0, a2) = lab_sfp_plus("CRV00008", 41.5, -2.3, -3.1);
        assert_eq!(diag_page(&a0), DiagPage::A2);
        let m = decode(&a0, Some(&a2));
        assert!(m.module_present);
        assert_eq!(m.kind.as_deref(), Some("SFP/SFP+/SFP28"));
        assert_eq!(m.connector.as_deref(), Some("LC"));
        assert_eq!(m.compliance, ["10GBASE-SR"]);
        assert_eq!(m.vendor_name.as_deref(), Some("CoreRouter Lab"));
        assert_eq!(m.vendor_part_number.as_deref(), Some("CR-SFP10G-SR"));
        assert_eq!(m.vendor_serial.as_deref(), Some("CRV00008"));
        assert_eq!(m.manufacturing_date.as_deref(), Some("2026-01-15"));
        assert_eq!(m.wavelength_nm, Some(850.0));
        assert_eq!(m.nominal_rate_mbd, Some(10_300));
        assert_eq!(m.checksum_ok, Some(true));
        assert_eq!(m.rx_loss, Some(false));
        let t = get(&m, "temperature");
        assert!((t.value - 41.5).abs() < 0.01, "{t:?}");
        assert_eq!(t.level, Some(Level::Ok));
        assert!((get(&m, "rx-power").value + 3.1).abs() < 0.05);
        assert!((get(&m, "supply-voltage").value - 3.29).abs() < 0.001);
        assert!((get(&m, "tx-bias-current").value - 6.6).abs() < 0.01);
        assert_eq!(m.alerts().count(), 0);
        let lim = get(&m, "rx-power").limits.unwrap();
        assert!((lim.low_alarm + 13.9).abs() < 0.05, "{lim:?}");
    }

    #[test]
    fn readings_past_thresholds_raise_levels() {
        let (a0, a2) = lab_sfp_plus("X", 75.0, -2.0, -12.0);
        let m = decode(&a0, Some(&a2));
        assert_eq!(get(&m, "temperature").level, Some(Level::HighWarning));
        assert_eq!(get(&m, "rx-power").level, Some(Level::LowWarning));
        let (a0, a2) = lab_sfp_plus("X", 30.0, -2.0, -40.0);
        let m = decode(&a0, Some(&a2));
        let rx = get(&m, "rx-power");
        assert_eq!(rx.value, MIN_DBM);
        assert_eq!(rx.level, Some(Level::LowAlarm));
        assert_eq!(m.rx_loss, Some(true));
        assert_eq!(m.alerts().count(), 1);
    }

    #[test]
    fn limits_order_and_sanity() {
        let l = Limits {
            high_alarm: 10.0,
            high_warning: 5.0,
            low_warning: -5.0,
            low_alarm: -10.0,
        };
        assert_eq!(l.level(0.0), Level::Ok);
        assert_eq!(l.level(5.0), Level::Ok);
        assert_eq!(l.level(6.0), Level::HighWarning);
        assert_eq!(l.level(11.0), Level::HighAlarm);
        assert_eq!(l.level(-7.0), Level::LowWarning);
        assert_eq!(l.level(-11.0), Level::LowAlarm);
        let zero = Limits {
            high_alarm: 0.0,
            high_warning: 0.0,
            low_warning: 0.0,
            low_alarm: 0.0,
        };
        assert_eq!(zero.checked(), None, "unprogrammed thresholds");
        let upside = Limits {
            high_alarm: -10.0,
            low_alarm: 10.0,
            ..l
        };
        assert_eq!(upside.checked(), None);
    }

    #[test]
    fn dbm_conversion() {
        assert!((dbm(10_000.0) - 0.0).abs() < 1e-9, "1 mW is 0 dBm");
        assert!((dbm(5_012.0) + 3.0).abs() < 0.01);
        assert_eq!(dbm(0.0), MIN_DBM);
        assert_eq!(dbm(1.0), MIN_DBM, "0.1 µW floors at -40 dBm");
    }

    #[test]
    fn empty_and_blank_eeproms() {
        assert!(!decode(&[], None).module_present);
        let blank = decode(&[0xFF; 256], None);
        assert!(blank.module_present);
        assert_eq!(blank.kind, None);
        assert_eq!(diag_page(&[0xFF; 256]), DiagPage::None);
    }

    #[test]
    fn cmis_is_named_not_decoded() {
        let mut p = vec![0u8; 256];
        p[0] = 0x18;
        let m = decode(&p, None);
        assert_eq!(m.kind.as_deref(), Some("QSFP-DD"));
        assert_eq!(m.spec.as_deref(), Some("CMIS"));
        assert!(m.dom.is_empty());
        assert_eq!(diag_page(&p), DiagPage::None);
    }

    #[test]
    fn external_calibration_applies_slopes_and_polynomial() {
        let (mut a0, mut a2) = lab_sfp_plus("X", 0.0, 0.0, 0.0);
        a0[92] = 0x58; // DDM, external calibration, average power
        // Temperature: slope 2.0, offset +256 (= +1 °C after /256).
        a2[84..86].copy_from_slice(&512u16.to_be_bytes());
        a2[86..88].copy_from_slice(&256i16.to_be_bytes());
        a2[96..98].copy_from_slice(&(10i16 * 256).to_be_bytes());
        // Rx power = 2 * raw (Rx_PWR(1) = 2.0, the rest 0).
        for at in [56, 60, 64, 72] {
            a2[at..at + 4].copy_from_slice(&0f32.to_be_bytes());
        }
        a2[68..72].copy_from_slice(&2f32.to_be_bytes());
        a2[104..106].copy_from_slice(&5_000u16.to_be_bytes());
        let m = decode(&a0, Some(&a2));
        assert!((get(&m, "temperature").value - 21.0).abs() < 1e-9);
        assert!(
            (get(&m, "rx-power").value - 0.0).abs() < 1e-9,
            "2 × 0.5 mW = 1 mW"
        );
    }

    proptest! {
        /// Hostile EEPROMs: decoding never panics and every reading kept
        /// is a finite number.
        #[test]
        fn hostile_eeproms_decode_without_panic(
            page0 in proptest::collection::vec(any::<u8>(), 0..300),
            diag in proptest::option::of(proptest::collection::vec(any::<u8>(), 0..200)),
            id in prop_oneof![Just(0x03u8), Just(0x0D), Just(0x11), any::<u8>()],
        ) {
            let mut page0 = page0;
            if let Some(first) = page0.first_mut() {
                *first = id;
            }
            let _ = diag_page(&page0);
            let m = decode(&page0, diag.as_deref());
            for r in &m.dom {
                prop_assert!(r.value.is_finite());
                if let Some(l) = r.limits {
                    prop_assert!(l.high_alarm.is_finite() && l.low_alarm.is_finite());
                }
            }
            prop_assert!(m.dom.len() <= 14);
        }
    }
}
