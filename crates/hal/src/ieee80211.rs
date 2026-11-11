//! What a Wi-Fi radio in monitor mode hands over (G1.30j): a radiotap
//! header (how the frame was heard) and the 802.11 frame itself. Pure
//! parsers over hostile bytes, shared by every backend and by the engine's
//! snooper and capture; also the builder of radiotap headers the virtual
//! lab sends (and the tests round-trip).
//!
//! Sources, by section:
//! - radiotap: <https://www.radiotap.org> (the header, the field list with
//!   each field's alignment and size, "Alignment in Radiotap": a field is
//!   aligned to its natural size counted from the header's first byte);
//! - IEEE Std 802.11-2020: §9.2.4.1 Frame Control, §9.2.4.1.3 Type and
//!   Subtype (Table 9-1), §9.3.1 control frames, §9.3.2 data frames, §9.3.3
//!   management frames, §9.4.1.7 Reason Code (Table 9-49), §9.4.2 elements
//!   (SSID 0, DSSS Parameter Set 3, RSN 48, Vendor Specific 221), §9.4.2.24
//!   RSNE (AKM suites, Table 9-151), §12.7.2 EAPOL-Key frames (Key
//!   Information), §12.7.6 the 4-way handshake;
//! - the rates: §19.5 (HT MCS tables), §21.5 (VHT), §27.5 (HE), computed
//!   from the data subcarriers, the bits per subcarrier and the coding rate
//!   instead of copied tables.
//!
//! Nothing here allocates: the snooper calls it for every frame (the
//! numbers are in `crates/engine/benches/wifi_snoop.rs`).

use crate::wifi::BssSecurity;

/// pcap's link type for radiotap + 802.11 (tcpdump.org/linktypes.html).
pub const LINKTYPE_IEEE802_11_RADIOTAP: u32 = 127;
/// Longest radiotap header looked at (mac80211 writes some 60 bytes; the
/// length field allows 65535).
pub const MAX_RADIOTAP: usize = 1024;
/// Present words followed at most (one per antenna on a busy card).
const MAX_PRESENT_WORDS: usize = 16;

// Radiotap Flags field (radiotap.org/fields/Flags).
pub const RT_FLAG_SHORT_PREAMBLE: u8 = 0x02;
/// The frame ends with its 4-byte FCS.
pub const RT_FLAG_FCS: u8 = 0x10;
/// The receiver says the FCS was wrong.
pub const RT_FLAG_BAD_FCS: u8 = 0x40;
pub const RT_FLAG_SHORT_GI: u8 = 0x80;

/// The modulation family a frame was sent with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Phy {
    /// DSSS/CCK (802.11b) or OFDM (a/g): the radiotap Rate field.
    #[default]
    Legacy,
    /// 802.11n (radiotap MCS field).
    Ht,
    /// 802.11ac (radiotap VHT field).
    Vht,
    /// 802.11ax (radiotap HE field).
    He,
}

impl Phy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Legacy => "legacy",
            Self::Ht => "ht",
            Self::Vht => "vht",
            Self::He => "he",
        }
    }
}

/// How a frame was heard: what the radiotap header says.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Radiotap {
    /// Bytes of the header: the 802.11 frame starts here.
    pub len: usize,
    /// The Flags field (`RT_FLAG_*`), 0 when absent.
    pub flags: u8,
    /// The card's microsecond clock when the frame began.
    pub tsft: Option<u64>,
    /// The legacy rate, in 500 kbit/s units.
    pub rate_500k: Option<u8>,
    pub freq_mhz: Option<u16>,
    pub signal_dbm: Option<i8>,
    pub noise_dbm: Option<i8>,
    pub phy: Phy,
    /// MCS index of the PHY (HT: 0..=31 with the streams folded in).
    pub mcs: Option<u8>,
    /// Spatial streams (VHT, HE; HT's come from the MCS).
    pub nss: Option<u8>,
    pub width_mhz: Option<u16>,
    /// Guard interval, ns (800/400 for HT and VHT, 800/1600/3200 for HE).
    pub guard_ns: Option<u16>,
    /// Retries the sender's own card reported (frames the router sent).
    pub data_retries: Option<u8>,
}

impl Radiotap {
    pub fn bad_fcs(&self) -> bool {
        self.flags & RT_FLAG_BAD_FCS != 0
    }

    /// Bytes of FCS at the end of the frame.
    pub fn fcs_len(&self) -> usize {
        if self.flags & RT_FLAG_FCS != 0 { 4 } else { 0 }
    }
}

fn le16(d: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(d.get(at..at + 2)?.try_into().ok()?))
}

fn le32(d: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(d.get(at..at + 4)?.try_into().ok()?))
}

fn le64(d: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(d.get(at..at + 8)?.try_into().ok()?))
}

/// (alignment, size) of the fields of the default namespace, by bit
/// (radiotap.org/fields/defined). `None`: not known here (the TLV list,
/// bit 28, and anything later): parsing stops there.
const FIELDS: [Option<(usize, usize)>; 28] = [
    Some((8, 8)),  // 0 TSFT
    Some((1, 1)),  // 1 Flags
    Some((1, 1)),  // 2 Rate
    Some((2, 4)),  // 3 Channel
    Some((1, 2)),  // 4 FHSS
    Some((1, 1)),  // 5 dBm antenna signal
    Some((1, 1)),  // 6 dBm antenna noise
    Some((2, 2)),  // 7 Lock quality
    Some((2, 2)),  // 8 TX attenuation
    Some((2, 2)),  // 9 dB TX attenuation
    Some((1, 1)),  // 10 dBm TX power
    Some((1, 1)),  // 11 Antenna
    Some((1, 1)),  // 12 dB antenna signal
    Some((1, 1)),  // 13 dB antenna noise
    Some((2, 2)),  // 14 RX flags
    Some((2, 2)),  // 15 TX flags
    Some((1, 1)),  // 16 RTS retries
    Some((1, 1)),  // 17 data retries
    Some((4, 8)),  // 18 XChannel
    Some((1, 3)),  // 19 MCS
    Some((4, 8)),  // 20 A-MPDU status
    Some((2, 12)), // 21 VHT
    Some((8, 12)), // 22 timestamp
    Some((2, 12)), // 23 HE
    Some((2, 12)), // 24 HE-MU
    Some((2, 6)),  // 25 HE-MU-other-user
    Some((1, 1)),  // 26 0-length PSDU
    Some((2, 4)),  // 27 L-SIG
];

/// VHT bandwidth code → MHz (radiotap.org/fields/VHT, "bandwidth").
fn vht_width(code: u8) -> Option<u16> {
    match code & 0x1f {
        0 => Some(20),
        1..=3 => Some(40),
        4..=10 => Some(80),
        11..=25 => Some(160),
        _ => None,
    }
}

/// Parse the radiotap header at the start of `d`. Only the first present
/// word is read (it is in the default namespace, and its fields come
/// first); the extended words (per antenna, vendor namespaces) are skipped.
pub fn radiotap(d: &[u8]) -> Option<Radiotap> {
    if *d.first()? != 0 {
        return None; // version 0 is the only one
    }
    let len = usize::from(le16(d, 2)?);
    if len < 8 || len > d.len() || len > MAX_RADIOTAP {
        return None;
    }
    let hdr = d.get(..len)?;
    let present = le32(hdr, 4)?;
    // The present words: while bit 31 is set, another follows.
    let mut at = 8;
    let mut word = present;
    let mut words = 1;
    while word & 0x8000_0000 != 0 {
        if words >= MAX_PRESENT_WORDS {
            return None;
        }
        word = le32(hdr, at)?;
        at += 4;
        words += 1;
    }
    let mut r = Radiotap {
        len,
        ..Radiotap::default()
    };
    let (mut ht, mut vht, mut he) = (false, false, false);
    for (bit, field) in FIELDS.iter().enumerate() {
        if present & (1 << bit) == 0 {
            continue;
        }
        let Some((align, size)) = *field else { break };
        at = at.div_ceil(align) * align;
        let Some(f) = hdr.get(at..at + size) else {
            break; // a field cut short: keep what came before it
        };
        match bit {
            0 => r.tsft = le64(f, 0),
            1 => r.flags = *f.first()?,
            2 => r.rate_500k = f.first().copied().filter(|&v| v != 0),
            3 => r.freq_mhz = le16(f, 0).filter(|&v| v != 0),
            5 => r.signal_dbm = f.first().map(|&v| v as i8),
            6 => r.noise_dbm = f.first().map(|&v| v as i8),
            17 => r.data_retries = f.first().copied(),
            18 if r.freq_mhz.is_none() => r.freq_mhz = le16(f, 4).filter(|&v| v != 0),
            19 => {
                let (known, flags, mcs) = (f.first()?, f.get(1)?, f.get(2)?);
                ht = true;
                if known & 0x01 != 0 {
                    r.width_mhz = Some(if flags & 0x03 == 1 { 40 } else { 20 });
                }
                if known & 0x02 != 0 {
                    r.mcs = Some(*mcs);
                    if *mcs < 32 {
                        r.nss = Some(mcs / 8 + 1);
                    }
                }
                if known & 0x04 != 0 {
                    r.guard_ns = Some(if flags & 0x04 != 0 { 400 } else { 800 });
                }
            }
            21 => {
                let known = le16(f, 0)?;
                let (flags, bw) = (*f.get(2)?, *f.get(3)?);
                let mcs_nss = *f.get(4)?;
                vht = true;
                if known & 0x0004 != 0 {
                    r.guard_ns = Some(if flags & 0x04 != 0 { 400 } else { 800 });
                }
                if known & 0x0040 != 0 {
                    r.width_mhz = vht_width(bw);
                }
                let nss = mcs_nss & 0x0f;
                if nss != 0 {
                    r.nss = Some(nss);
                    r.mcs = Some(mcs_nss >> 4);
                }
            }
            23 => {
                let (d1, d2, d3) = (le16(f, 0)?, le16(f, 2)?, le16(f, 4)?);
                let (d5, d6) = (le16(f, 8)?, le16(f, 10)?);
                he = true;
                if d1 & 0x0020 != 0 {
                    r.mcs = Some(((d3 >> 8) & 0x0f) as u8);
                }
                if d1 & 0x4000 != 0 {
                    r.width_mhz = match d5 & 0x0f {
                        0 => Some(20),
                        1 => Some(40),
                        2 => Some(80),
                        3 => Some(160),
                        _ => None, // a resource unit of an OFDMA frame
                    };
                }
                if d2 & 0x0002 != 0 {
                    r.guard_ns = match (d5 >> 4) & 0x03 {
                        0 => Some(800),
                        1 => Some(1600),
                        2 => Some(3200),
                        _ => None,
                    };
                }
                let nsts = (d6 & 0x0f) as u8;
                if nsts != 0 {
                    r.nss = Some(nsts);
                }
            }
            _ => {}
        }
        at += size;
    }
    r.phy = if he {
        Phy::He
    } else if vht {
        Phy::Vht
    } else if ht {
        Phy::Ht
    } else {
        Phy::Legacy
    };
    if r.guard_ns.is_none()
        && r.flags & RT_FLAG_SHORT_GI != 0
        && matches!(r.phy, Phy::Ht | Phy::Vht)
    {
        r.guard_ns = Some(400);
    }
    Some(r)
}

// ---------------------------------------------------------------------------
// Rates and airtime.

/// Bits per subcarrier and coding rate (numerator, denominator) of MCS
/// 0..=13 (§19.5, §21.5, §27.5; 12 and 13 are 802.11be's 4096-QAM).
const MCS_MOD: [(u64, u64, u64); 14] = [
    (1, 1, 2),
    (2, 1, 2),
    (2, 3, 4),
    (4, 1, 2),
    (4, 3, 4),
    (6, 2, 3),
    (6, 3, 4),
    (6, 5, 6),
    (8, 3, 4),
    (8, 5, 6),
    (10, 3, 4),
    (10, 5, 6),
    (12, 3, 4),
    (12, 5, 6),
];

/// Data subcarriers by channel width: HT/VHT (§19.3.7, §21.3.7) and HE
/// (§27.3.7, full-band 242/484/996/2×996-tone RUs).
fn data_subcarriers(phy: Phy, width: u16) -> Option<u64> {
    match (phy, width) {
        (Phy::Ht | Phy::Vht, 20) => Some(52),
        (Phy::Ht | Phy::Vht, 40) => Some(108),
        (Phy::Vht, 80) => Some(234),
        (Phy::Vht, 160) => Some(468),
        (Phy::He, 20) => Some(234),
        (Phy::He, 40) => Some(468),
        (Phy::He, 80) => Some(980),
        (Phy::He, 160) => Some(1960),
        _ => None,
    }
}

/// The rate the frame was sent at, kbit/s.
pub fn rate_kbps(r: &Radiotap) -> Option<u32> {
    if r.phy == Phy::Legacy {
        return r.rate_500k.map(|v| u32::from(v) * 500);
    }
    let width = r.width_mhz.unwrap_or(20);
    let (mcs, nss) = match r.phy {
        Phy::Ht => {
            let m = r.mcs?;
            if m >= 32 {
                return None;
            }
            (m % 8, m / 8 + 1)
        }
        _ => (r.mcs?, r.nss.unwrap_or(1)),
    };
    let (bits, num, den) = *MCS_MOD.get(usize::from(mcs))?;
    let nsd = data_subcarriers(r.phy, width)?;
    // Symbol: 3.2 µs + GI (HT/VHT), 12.8 µs + GI (HE).
    let symbol_ns: u64 = match r.phy {
        Phy::He => 12_800 + u64::from(r.guard_ns.unwrap_or(800)),
        _ => 3_200 + u64::from(r.guard_ns.unwrap_or(800)),
    };
    let kbps = nsd * bits * num * u64::from(nss) * 1_000_000 / (den * symbol_ns);
    u32::try_from(kbps).ok()
}

/// A guess at how long the frame held the channel, µs: the preamble and
/// the bits at their rate. Neither the gaps between frames nor the
/// back-off are counted, so a channel's sum is a floor (the snooper says
/// "estimated").
pub fn airtime_us(r: &Radiotap, frame_len: usize) -> u32 {
    let bits = (frame_len as u64).saturating_mul(8);
    let freq = r.freq_mhz.unwrap_or(0);
    // Without a rate: the lowest of the band (control frames go at a
    // basic rate).
    let kbps = u64::from(rate_kbps(r).unwrap_or(if freq >= 4900 { 6000 } else { 1000 })).max(1);
    let us = match r.phy {
        Phy::Legacy if kbps <= 11_000 && freq < 4900 => {
            // DSSS/CCK: a 192 µs long preamble, 96 µs short (§16.2.2).
            let preamble = if r.flags & RT_FLAG_SHORT_PREAMBLE != 0 {
                96
            } else {
                192
            };
            preamble + bits * 1000 / kbps
        }
        Phy::Legacy => {
            // OFDM: 20 µs of preamble and SIGNAL, 4 µs symbols carrying
            // SERVICE (16) + data + tail (6) (§17.4.3).
            let per_symbol = (kbps * 4 / 1000).max(1);
            20 + 4 * (16 + bits + 6).div_ceil(per_symbol)
        }
        _ => {
            // HT/VHT/HE: the legacy preamble, the PHY's own training
            // fields per stream, then the bits.
            let nss = u64::from(r.nss.unwrap_or(1));
            let preamble = match r.phy {
                Phy::He => 36 + 8 * nss,
                _ => 32 + 4 * nss,
            };
            preamble + bits * 1000 / kbps
        }
    };
    u32::try_from(us).unwrap_or(u32::MAX)
}

// ---------------------------------------------------------------------------
// The 802.11 frame.

pub type Mac = [u8; 6];

pub const BROADCAST: Mac = [0xff; 6];

/// Group (multicast or broadcast) address: the I/G bit.
pub fn is_group(m: &Mac) -> bool {
    m[0] & 0x01 != 0
}

/// A locally administered address (randomised by phones, or an AP's
/// extra BSSIDs).
pub fn is_local(m: &Mac) -> bool {
    m[0] & 0x02 != 0
}

/// `aa:bb:cc:dd:ee:ff`.
pub fn mac_text(m: &Mac) -> String {
    let [a, b, c, d, e, f] = *m;
    format!("{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{f:02x}")
}

/// `aa:bb:cc:dd:ee:ff` or `aa-bb-…`, any case.
pub fn parse_mac(s: &str) -> Option<Mac> {
    let mut out = [0u8; 6];
    let mut parts = s.trim().split([':', '-']);
    for b in &mut out {
        let p = parts.next()?;
        if p.len() != 2 {
            return None;
        }
        *b = u8::from_str_radix(p, 16).ok()?;
    }
    parts.next().is_none().then_some(out)
}

/// The frame's type (§9.2.4.1.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Mgmt,
    Control,
    Data,
    /// Type 3 (DMG beacons, S1G): not read further.
    Extension,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mgmt => "mgmt",
            Self::Control => "control",
            Self::Data => "data",
            Self::Extension => "extension",
        }
    }
}

// Frame Control, second byte (§9.2.4.1.1).
pub const FC_TO_DS: u8 = 0x01;
pub const FC_FROM_DS: u8 = 0x02;
pub const FC_RETRY: u8 = 0x08;
pub const FC_PWR_MGT: u8 = 0x10;
pub const FC_PROTECTED: u8 = 0x40;
pub const FC_ORDER: u8 = 0x80;

// Management subtypes (Table 9-1).
pub const ST_ASSOC_REQ: u8 = 0;
pub const ST_ASSOC_RESP: u8 = 1;
pub const ST_REASSOC_REQ: u8 = 2;
pub const ST_REASSOC_RESP: u8 = 3;
pub const ST_PROBE_REQ: u8 = 4;
pub const ST_PROBE_RESP: u8 = 5;
pub const ST_BEACON: u8 = 8;
pub const ST_DISASSOC: u8 = 10;
pub const ST_AUTH: u8 = 11;
pub const ST_DEAUTH: u8 = 12;
pub const ST_ACTION: u8 = 13;
// Control subtypes.
pub const ST_BLOCK_ACK_REQ: u8 = 8;
pub const ST_BLOCK_ACK: u8 = 9;
pub const ST_PS_POLL: u8 = 10;
pub const ST_RTS: u8 = 11;
pub const ST_CTS: u8 = 12;
pub const ST_ACK: u8 = 13;
pub const ST_CF_END: u8 = 14;

/// The header of one 802.11 frame; `body` is what follows it (without the
/// FCS), possibly cut short by the capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame<'a> {
    pub kind: Kind,
    pub subtype: u8,
    /// Frame Control's flags byte (`FC_*`).
    pub flags: u8,
    pub duration: u16,
    /// Receiver.
    pub addr1: Mac,
    /// Transmitter (absent from CTS and ACK).
    pub addr2: Option<Mac>,
    pub addr3: Option<Mac>,
    pub seq: Option<u16>,
    pub header_len: usize,
    pub body: &'a [u8],
}

fn mac_at(d: &[u8], at: usize) -> Option<Mac> {
    d.get(at..at + 6)?.try_into().ok()
}

/// Parse the frame in `d` (the bytes after the radiotap header; `fcs`
/// bytes of FCS at its end are left out of the body).
pub fn frame(d: &[u8], fcs: usize) -> Option<Frame<'_>> {
    let fc0 = *d.first()?;
    let flags = *d.get(1)?;
    if fc0 & 0x03 != 0 {
        return None; // protocol version 0 only (PV1 is S1G's short frames)
    }
    let kind = match (fc0 >> 2) & 0x03 {
        0 => Kind::Mgmt,
        1 => Kind::Control,
        2 => Kind::Data,
        _ => Kind::Extension,
    };
    let subtype = fc0 >> 4;
    let duration = le16(d, 2)?;
    let addr1 = mac_at(d, 4)?;
    let d = d.get(..d.len().saturating_sub(fcs)).unwrap_or(&[]);
    let (addr2, addr3, seq, header_len) = match kind {
        Kind::Mgmt => {
            let order = if flags & FC_ORDER != 0 { 4 } else { 0 };
            (mac_at(d, 10), mac_at(d, 16), le16(d, 22), 24 + order)
        }
        Kind::Data => {
            let wds = flags & (FC_TO_DS | FC_FROM_DS) == FC_TO_DS | FC_FROM_DS;
            let qos = subtype & 0x08 != 0;
            let mut len = 24 + if wds { 6 } else { 0 };
            if qos {
                len += 2;
                if flags & FC_ORDER != 0 {
                    len += 4;
                }
            }
            (mac_at(d, 10), mac_at(d, 16), le16(d, 22), len)
        }
        Kind::Control => match subtype {
            ST_CTS | ST_ACK => (None, None, None, 10),
            _ => (mac_at(d, 10), None, None, 16),
        },
        Kind::Extension => (None, None, None, 10),
    };
    if d.len() < header_len.min(10) {
        return None;
    }
    let body = d.get(header_len..).unwrap_or(&[]);
    Some(Frame {
        kind,
        subtype,
        flags,
        duration,
        addr1,
        addr2,
        addr3,
        seq,
        header_len,
        body,
    })
}

impl Frame<'_> {
    pub fn retry(&self) -> bool {
        self.flags & FC_RETRY != 0
    }

    pub fn protected(&self) -> bool {
        self.flags & FC_PROTECTED != 0
    }

    pub fn to_ds(&self) -> bool {
        self.flags & FC_TO_DS != 0
    }

    pub fn from_ds(&self) -> bool {
        self.flags & FC_FROM_DS != 0
    }

    pub fn is(&self, kind: Kind, subtype: u8) -> bool {
        self.kind == kind && self.subtype == subtype
    }

    /// The network the frame belongs to, when the header says (§9.3.2.1,
    /// Table 9-30 for data frames).
    pub fn bssid(&self) -> Option<Mac> {
        match self.kind {
            Kind::Mgmt => self.addr3,
            Kind::Data => match (self.to_ds(), self.from_ds()) {
                (false, false) => self.addr3,
                (true, false) => Some(self.addr1),
                (false, true) => self.addr2,
                (true, true) => None,
            },
            Kind::Control => match self.subtype {
                ST_PS_POLL => Some(self.addr1),
                ST_CF_END => self.addr2,
                _ => None,
            },
            Kind::Extension => None,
        }
    }

    /// `beacon`, `qos-data`, `ack`… (Table 9-1).
    pub fn type_name(&self) -> &'static str {
        match (self.kind, self.subtype) {
            (Kind::Mgmt, ST_ASSOC_REQ) => "assoc-req",
            (Kind::Mgmt, ST_ASSOC_RESP) => "assoc-resp",
            (Kind::Mgmt, ST_REASSOC_REQ) => "reassoc-req",
            (Kind::Mgmt, ST_REASSOC_RESP) => "reassoc-resp",
            (Kind::Mgmt, ST_PROBE_REQ) => "probe-req",
            (Kind::Mgmt, ST_PROBE_RESP) => "probe-resp",
            (Kind::Mgmt, ST_BEACON) => "beacon",
            (Kind::Mgmt, 9) => "atim",
            (Kind::Mgmt, ST_DISASSOC) => "disassoc",
            (Kind::Mgmt, ST_AUTH) => "auth",
            (Kind::Mgmt, ST_DEAUTH) => "deauth",
            (Kind::Mgmt, ST_ACTION | 14) => "action",
            (Kind::Mgmt, _) => "mgmt",
            (Kind::Control, 2) => "trigger",
            (Kind::Control, 5) => "ndp-announce",
            (Kind::Control, ST_BLOCK_ACK_REQ) => "block-ack-req",
            (Kind::Control, ST_BLOCK_ACK) => "block-ack",
            (Kind::Control, ST_PS_POLL) => "ps-poll",
            (Kind::Control, ST_RTS) => "rts",
            (Kind::Control, ST_CTS) => "cts",
            (Kind::Control, ST_ACK) => "ack",
            (Kind::Control, ST_CF_END | 15) => "cf-end",
            (Kind::Control, _) => "control",
            (Kind::Data, 4) => "null",
            (Kind::Data, 12) => "qos-null",
            (Kind::Data, s) if s & 0x08 != 0 => "qos-data",
            (Kind::Data, _) => "data",
            (Kind::Extension, _) => "extension",
        }
    }
}

/// An SSID as heard: up to 32 bytes, kept without allocating.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Ssid {
    bytes: [u8; 32],
    len: u8,
}

impl Ssid {
    pub fn new(b: &[u8]) -> Self {
        let mut s = Self::default();
        let n = b.len().min(32);
        if let (Some(dst), Some(src)) = (s.bytes.get_mut(..n), b.get(..n)) {
            dst.copy_from_slice(src);
        }
        s.len = n as u8;
        s
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.get(..usize::from(self.len)).unwrap_or(&[])
    }

    /// Empty or all zeros: the access point hides its name (§11.1.3.1).
    pub fn is_hidden(&self) -> bool {
        self.as_bytes().iter().all(|&b| b == 0)
    }

    /// For people: lossy UTF-8, control characters as `\xNN`.
    pub fn text(&self) -> String {
        let s = String::from_utf8_lossy(self.as_bytes());
        let mut out = String::with_capacity(s.len());
        for c in s.chars() {
            if c.is_control() {
                out.push_str(&format!("\\x{:02x}", u32::from(c) & 0xff));
            } else {
                out.push(c);
            }
        }
        out
    }
}

/// What the elements of a beacon or probe response say (§9.4.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Elements {
    pub ssid: Option<Ssid>,
    /// DSSS Parameter Set: the channel the access point sits on.
    pub channel: Option<u8>,
    pub rsn: bool,
    pub wpa1: bool,
    pub psk: bool,
    pub sae: bool,
    pub dot1x: bool,
    pub owe: bool,
}

impl Elements {
    /// The security on offer; `privacy` is the Capability field's bit.
    pub fn security(&self, privacy: bool) -> BssSecurity {
        if self.rsn {
            if self.owe {
                return BssSecurity::Owe;
            }
            return match (self.psk, self.sae, self.dot1x) {
                (true, true, _) => BssSecurity::Wpa2Wpa3,
                (false, true, _) => BssSecurity::Wpa3,
                (true, false, _) => BssSecurity::Wpa2,
                (false, false, true) => BssSecurity::Enterprise,
                // An RSNE without a known AKM: say "legacy", not "open".
                _ => BssSecurity::Legacy,
            };
        }
        if self.wpa1 || privacy {
            BssSecurity::Legacy
        } else {
            BssSecurity::Open
        }
    }
}

/// Walk the elements in `d`; an element cut short ends the walk.
pub fn elements(d: &[u8]) -> Elements {
    let mut e = Elements::default();
    let mut at = 0;
    while let (Some(&id), Some(&len)) = (d.get(at), d.get(at + 1)) {
        let len = usize::from(len);
        let Some(v) = d.get(at + 2..at + 2 + len) else {
            break;
        };
        match id {
            0 if e.ssid.is_none() && len <= 32 => e.ssid = Some(Ssid::new(v)),
            3 if len == 1 => e.channel = v.first().copied(),
            48 => {
                e.rsn = true;
                rsn_akms(v, &mut e);
            }
            221 if v.get(..4) == Some(&[0x00, 0x50, 0xf2, 0x01]) => e.wpa1 = true,
            _ => {}
        }
        at += 2 + len;
    }
    e
}

/// The AKM suites of an RSNE (§9.4.2.24.3, Table 9-151): version 2, group
/// cipher 4, pairwise count 2 + 4 each, AKM count 2 + 4 each.
fn rsn_akms(v: &[u8], e: &mut Elements) {
    let Some(pairwise) = le16(v, 6) else { return };
    let at = 8 + 4 * usize::from(pairwise);
    let Some(count) = le16(v, at) else { return };
    for i in 0..usize::from(count).min(16) {
        let Some(suite) = v.get(at + 2 + 4 * i..at + 6 + 4 * i) else {
            return;
        };
        if suite.get(..3) != Some(&[0x00, 0x0f, 0xac]) {
            continue;
        }
        match suite.get(3) {
            Some(1 | 3 | 5 | 11 | 12 | 13) => e.dot1x = true,
            Some(2 | 4 | 6) => e.psk = true,
            Some(8 | 9 | 24 | 25) => e.sae = true,
            Some(18) => e.owe = true,
            _ => {}
        }
    }
}

/// What a frame says that the snooper keeps, beyond its header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Info {
    /// Beacon or probe response: the network announcing itself.
    Announce {
        probe_resp: bool,
        elements: Elements,
        security: BssSecurity,
    },
    /// A station looking for a network (`None`: any).
    ProbeReq(Option<Ssid>),
    /// (Re)association request: the name the station asks for.
    AssocReq(Option<Ssid>),
    Auth {
        algorithm: u16,
        seq: u16,
        status: u16,
    },
    /// Deauthentication or disassociation, with the reason (`None`: the
    /// frame is protected, §12.6.19, so the reason is ciphered).
    Leave {
        deauth: bool,
        reason: Option<u16>,
    },
    /// An EAPOL-Key frame of the 4-way handshake (`Some(1..=4)`), or of
    /// the group key handshake (`None`).
    EapolKey(Option<u8>),
    /// Another EAPOL frame (EAP of 802.1X, EAPOL-Start…).
    Eapol,
    Other,
}

/// LLC/SNAP header for EAPOL (EtherType 0x888E), §12.7.2.
const SNAP_EAPOL: [u8; 8] = [0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e];

/// Which message of the 4-way handshake an EAPOL-Key frame is (§12.7.6):
/// Key Information's Ack, MIC, Secure and Install bits.
fn eapol_key(eapol: &[u8]) -> Option<Info> {
    // version 1, type 1, length 2, descriptor type 1, key information 2.
    if *eapol.get(1)? != 3 {
        return Some(Info::Eapol);
    }
    let info = u16::from_be_bytes(eapol.get(5..7)?.try_into().ok()?);
    let pairwise = info & 0x0008 != 0;
    if !pairwise {
        return Some(Info::EapolKey(None));
    }
    let (install, ack, mic, secure) = (
        info & 0x0040 != 0,
        info & 0x0080 != 0,
        info & 0x0100 != 0,
        info & 0x0200 != 0,
    );
    let msg = match (ack, mic, install, secure) {
        (true, false, _, _) => 1,
        (true, true, _, _) => 3,
        (false, true, _, false) => 2,
        (false, true, _, true) => 4,
        _ => return Some(Info::Eapol),
    };
    Some(Info::EapolKey(Some(msg)))
}

/// Read the body of `f` as far as the snooper cares.
pub fn info(f: &Frame<'_>) -> Info {
    let b = f.body;
    match f.kind {
        Kind::Mgmt => match f.subtype {
            ST_BEACON | ST_PROBE_RESP => {
                // timestamp 8, beacon interval 2, capability 2 (§9.3.3.2).
                let privacy = le16(b, 10).is_some_and(|c| c & 0x0010 != 0);
                let elements = elements(b.get(12..).unwrap_or(&[]));
                Info::Announce {
                    probe_resp: f.subtype == ST_PROBE_RESP,
                    security: elements.security(privacy),
                    elements,
                }
            }
            ST_PROBE_REQ => Info::ProbeReq(elements(b).ssid.filter(|s| !s.is_hidden())),
            // capability 2, listen interval 2 (+ current AP 6 when re-).
            ST_ASSOC_REQ => Info::AssocReq(elements(b.get(4..).unwrap_or(&[])).ssid),
            ST_REASSOC_REQ => Info::AssocReq(elements(b.get(10..).unwrap_or(&[])).ssid),
            ST_AUTH => match (le16(b, 0), le16(b, 2), le16(b, 4)) {
                (Some(algorithm), Some(seq), Some(status)) => Info::Auth {
                    algorithm,
                    seq,
                    status,
                },
                _ => Info::Other,
            },
            ST_DEAUTH | ST_DISASSOC => Info::Leave {
                deauth: f.subtype == ST_DEAUTH,
                reason: if f.protected() { None } else { le16(b, 0) },
            },
            _ => Info::Other,
        },
        Kind::Data if !f.protected() && b.get(..8) == Some(&SNAP_EAPOL) => {
            eapol_key(b.get(8..).unwrap_or(&[])).unwrap_or(Info::Eapol)
        }
        _ => Info::Other,
    }
}

/// Words for a reason code (Table 9-49), the common ones.
pub fn reason_text(code: u16) -> &'static str {
    match code {
        1 => "unspecified",
        2 => "previous authentication no longer valid",
        3 => "the station is leaving (or has left)",
        4 => "inactivity",
        5 => "the access point cannot handle all associated stations",
        6 => "class 2 frame from a station not authenticated",
        7 => "class 3 frame from a station not associated",
        8 => "the station is leaving the network",
        9 => "(re)association without authentication",
        10 => "power capability unacceptable",
        11 => "supported channels unacceptable",
        12 => "BSS transition management",
        13 => "invalid element",
        14 => "message integrity code (MIC) failure",
        15 => "4-way handshake timeout (wrong passphrase?)",
        16 => "group key handshake timeout",
        17 => "the 4-way handshake element differs",
        18 => "invalid group cipher",
        19 => "invalid pairwise cipher",
        20 => "invalid AKM",
        23 => "802.1X authentication failed",
        24 => "cipher suite rejected by policy",
        34 => "too many frames not acknowledged (poor channel)",
        _ => "other",
    }
}

/// The channel number of a frequency (§E.1; 2.4, 5 and 6 GHz).
pub fn channel_of(mhz: u32) -> Option<u32> {
    match mhz {
        2484 => Some(14),
        2412..=2472 => Some((mhz - 2407) / 5),
        5955..=7115 => Some((mhz - 5950) / 5),
        5160..=5885 => Some((mhz - 5000) / 5),
        _ => None,
    }
}

/// The centre of the `width` MHz channel that holds 20 MHz channel
/// `primary` (§E.1, the 5 and 6 GHz channel plans: 40 MHz pairs, 80 and
/// 160 MHz blocks). `None`: no such channel there (2.4 GHz is 20 MHz here).
pub fn center_mhz(primary: u32, width: u32) -> Option<u32> {
    if width == 20 {
        return Some(primary);
    }
    let (base, top) = match primary {
        5170..=5330 | 5490..=5730 | 5735..=5895 => (5170u32, 5895u32),
        5945..=7125 => (5945, 7125),
        _ => return None,
    };
    if primary > top {
        return None;
    }
    // Blocks of `width` MHz, aligned to the plan's start: 5170 (channel
    // 34's edge) for 36–144, 5735 for 149–177, 5945 for 6 GHz.
    let start = if (5735..=5895).contains(&primary) {
        5735
    } else {
        base
    };
    let block = (primary - start) / width;
    let center = start + block * width + width / 2;
    // A block that runs past the plan, or across 5330–5490, is not one.
    let lo = center - width / 2;
    let hi = center + width / 2;
    let gap = lo < 5490 && hi > 5330 && start == 5170;
    (hi <= top && !gap).then_some(center)
}

/// `2ghz`, `5ghz`, `6ghz`.
pub fn band_of(mhz: u32) -> Option<&'static str> {
    match mhz {
        2400..=2500 => Some("2ghz"),
        4900..=5925 => Some("5ghz"),
        5926..=7125 => Some("6ghz"),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Building radiotap headers (the virtual lab, tests).

/// What a built header says.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RadioSpec {
    pub flags: u8,
    pub freq_mhz: u16,
    pub signal_dbm: i8,
    pub noise_dbm: i8,
    pub phy: Phy,
    /// Legacy: the rate in 500 kbit/s units.
    pub rate_500k: u8,
    pub mcs: u8,
    pub nss: u8,
    pub width_mhz: u16,
    pub short_gi: bool,
}

fn pad(out: &mut Vec<u8>, start: usize, align: usize) {
    while !(out.len() - start).is_multiple_of(align) {
        out.push(0);
    }
}

/// Append a radiotap header for `s` to `out`, as mac80211 would write it
/// (`net/mac80211/rx.c`, `ieee80211_add_rx_radiotap_header`): Flags,
/// Rate (legacy), Channel, signal, noise, then MCS, VHT or HE.
pub fn build_radiotap(out: &mut Vec<u8>, s: &RadioSpec) {
    let start = out.len();
    let mut present: u32 = (1 << 1) | (1 << 3) | (1 << 5) | (1 << 6);
    match s.phy {
        Phy::Legacy => present |= 1 << 2,
        Phy::Ht => present |= 1 << 19,
        Phy::Vht => present |= 1 << 21,
        Phy::He => present |= 1 << 23,
    }
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&present.to_le_bytes());
    out.push(s.flags);
    if s.phy == Phy::Legacy {
        out.push(s.rate_500k);
    }
    pad(out, start, 2);
    out.extend_from_slice(&s.freq_mhz.to_le_bytes());
    let chan_flags: u16 = if s.freq_mhz >= 4900 { 0x0140 } else { 0x00a0 };
    out.extend_from_slice(&chan_flags.to_le_bytes());
    out.push(s.signal_dbm as u8);
    out.push(s.noise_dbm as u8);
    match s.phy {
        Phy::Legacy => {}
        Phy::Ht => {
            let bw = if s.width_mhz >= 40 { 1 } else { 0 };
            let gi = if s.short_gi { 0x04 } else { 0 };
            out.extend_from_slice(&[0x07, bw | gi, s.mcs]);
        }
        Phy::Vht => {
            pad(out, start, 2);
            let bw = match s.width_mhz {
                40 => 1,
                80 => 4,
                160 => 11,
                _ => 0,
            };
            out.extend_from_slice(&0x0044u16.to_le_bytes());
            out.push(if s.short_gi { 0x04 } else { 0 });
            out.push(bw);
            out.extend_from_slice(&[(s.mcs << 4) | (s.nss & 0x0f), 0, 0, 0]);
            out.extend_from_slice(&[0, 0, 0, 0]);
        }
        Phy::He => {
            pad(out, start, 2);
            let bw: u16 = match s.width_mhz {
                40 => 1,
                80 => 2,
                160 => 3,
                _ => 0,
            };
            let d1: u16 = 0x0020 | 0x4000; // data MCS, bandwidth known
            let d2: u16 = 0x0002; // GI known
            let d3: u16 = u16::from(s.mcs & 0x0f) << 8;
            let d5: u16 = bw;
            let d6: u16 = u16::from(s.nss & 0x0f);
            for v in [d1, d2, d3, 0, d5, d6] {
                out.extend_from_slice(&v.to_le_bytes());
            }
        }
    }
    let len = u16::try_from(out.len() - start).unwrap_or(u16::MAX);
    if let Some(l) = out.get_mut(start + 2..start + 4) {
        l.copy_from_slice(&len.to_le_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// The radiotap.org example "Radiotap header with TSFT, Flags, Rate,
    /// Channel, dBm Antenna Signal, Antenna and RX flags", as a Linux
    /// mac80211 card writes it (a 2.4 GHz frame at 1 Mbit/s, -59 dBm).
    const RADIOTAP_ORG: [u8; 26] = [
        0x00, 0x00, 0x1a, 0x00, // version, pad, length 26
        0x2f, 0x48, 0x00, 0x00, // TSFT Flags Rate Channel Signal Antenna RX-flags
        0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, // TSFT
        0x10, // Flags: FCS at the end
        0x02, // Rate: 1 Mbit/s
        0x6c, 0x09, 0xa0, 0x00, // 2412 MHz, CCK 2 GHz
        0xc5, // -59 dBm
        0x01, // antenna 1
        0x00, 0x00, // RX flags
    ];

    #[test]
    fn the_radiotap_org_example() {
        let r = radiotap(&RADIOTAP_ORG).unwrap();
        assert_eq!(r.len, 26);
        assert_eq!(r.tsft, Some(0xfedc_ba98_7654_3210));
        assert_eq!(r.flags, RT_FLAG_FCS);
        assert_eq!(r.fcs_len(), 4);
        assert_eq!(r.rate_500k, Some(2));
        assert_eq!(r.freq_mhz, Some(2412));
        assert_eq!(r.signal_dbm, Some(-59));
        assert_eq!(r.phy, Phy::Legacy);
        assert_eq!(rate_kbps(&r), Some(1000));
    }

    #[test]
    fn extended_present_words_are_skipped() {
        // Word 0: Flags, Channel, signal, ext + radiotap namespace; word 1:
        // signal and antenna of chain 0 (the layout mac80211 uses with
        // several antennas).
        let mut d = vec![0, 0, 0, 0];
        d.extend_from_slice(
            &((1u32 << 1) | (1 << 3) | (1 << 5) | (1 << 29) | (1 << 31)).to_le_bytes(),
        );
        d.extend_from_slice(&((1u32 << 5) | (1 << 11)).to_le_bytes());
        d.push(0); // flags
        d.push(0); // pad to 2
        d.extend_from_slice(&5180u16.to_le_bytes());
        d.extend_from_slice(&0x0140u16.to_le_bytes());
        d.push(-40i8 as u8); // signal (word 0)
        d.extend_from_slice(&[-42i8 as u8, 0]); // chain 0: signal, antenna
        let len = d.len() as u16;
        d[2..4].copy_from_slice(&len.to_le_bytes());
        let r = radiotap(&d).unwrap();
        assert_eq!((r.freq_mhz, r.signal_dbm), (Some(5180), Some(-40)));
    }

    #[test]
    fn rates_from_the_standard_tables() {
        let ht = |mcs, width, short_gi| Radiotap {
            phy: Phy::Ht,
            mcs: Some(mcs),
            width_mhz: Some(width),
            guard_ns: Some(if short_gi { 400 } else { 800 }),
            ..Radiotap::default()
        };
        // §19.5 Table 19-27: MCS 7, 20 MHz: 65.0 / 72.2 Mbit/s.
        assert_eq!(rate_kbps(&ht(7, 20, false)), Some(65_000));
        assert_eq!(rate_kbps(&ht(7, 20, true)), Some(72_222));
        // MCS 15 (two streams), 40 MHz, short GI: 300 Mbit/s.
        assert_eq!(rate_kbps(&ht(15, 40, true)), Some(300_000));
        // §21.5: VHT 80 MHz MCS 9, one stream, short GI: 433.3 Mbit/s.
        let vht = Radiotap {
            phy: Phy::Vht,
            mcs: Some(9),
            nss: Some(1),
            width_mhz: Some(80),
            guard_ns: Some(400),
            ..Radiotap::default()
        };
        assert_eq!(rate_kbps(&vht), Some(433_333));
        // §27.5: HE 80 MHz MCS 11, two streams, 0.8 µs GI: 1201 Mbit/s.
        let he = Radiotap {
            phy: Phy::He,
            mcs: Some(11),
            nss: Some(2),
            width_mhz: Some(80),
            guard_ns: Some(800),
            ..Radiotap::default()
        };
        assert_eq!(rate_kbps(&he), Some(1_200_980));
        // HE 20 MHz MCS 0 one stream: 8.6 Mbit/s.
        let he0 = Radiotap {
            mcs: Some(0),
            nss: Some(1),
            width_mhz: Some(20),
            ..he
        };
        assert_eq!(rate_kbps(&he0), Some(8_602));
    }

    #[test]
    fn airtime_grows_with_size_and_shrinks_with_rate() {
        let slow = Radiotap {
            rate_500k: Some(12),
            freq_mhz: Some(5180),
            ..Radiotap::default()
        };
        let fast = Radiotap {
            phy: Phy::He,
            mcs: Some(9),
            nss: Some(2),
            width_mhz: Some(80),
            freq_mhz: Some(5180),
            ..Radiotap::default()
        };
        // 1500 bytes at 6 Mbit/s: 20 + 4 × ⌈12022/24⌉ = 2024 µs.
        assert_eq!(airtime_us(&slow, 1500), 2024);
        // 960 Mbit/s: 12.5 µs of bits after a 52 µs HE preamble.
        assert_eq!(airtime_us(&fast, 1500), 64);
        assert!(airtime_us(&slow, 100) < airtime_us(&slow, 1500));
        // An ACK at 1 Mbit/s with a long preamble: 192 + 112 µs.
        let dsss = Radiotap {
            rate_500k: Some(2),
            freq_mhz: Some(2412),
            ..Radiotap::default()
        };
        assert_eq!(airtime_us(&dsss, 14), 304);
    }

    fn beacon(ssid: &[u8], rsn: Option<&[u8]>, privacy: bool) -> Vec<u8> {
        let mut f = vec![0x80, 0x00, 0, 0];
        f.extend_from_slice(&BROADCAST);
        f.extend_from_slice(&[2, 0xc0, 0xfe, 0, 0, 1]);
        f.extend_from_slice(&[2, 0xc0, 0xfe, 0, 0, 1]);
        f.extend_from_slice(&[0x10, 0x00]);
        f.extend_from_slice(&[0; 8]);
        f.extend_from_slice(&100u16.to_le_bytes());
        f.extend_from_slice(&(if privacy { 0x0011u16 } else { 0x0001 }).to_le_bytes());
        f.push(0);
        f.push(ssid.len() as u8);
        f.extend_from_slice(ssid);
        f.extend_from_slice(&[3, 1, 36]);
        if let Some(r) = rsn {
            f.push(48);
            f.push(r.len() as u8);
            f.extend_from_slice(r);
        }
        f
    }

    /// RSNE: version 1, CCMP group, one CCMP pairwise, the given AKMs.
    fn rsne(akms: &[u8]) -> Vec<u8> {
        let mut r = vec![1, 0, 0x00, 0x0f, 0xac, 4, 1, 0, 0x00, 0x0f, 0xac, 4];
        r.extend_from_slice(&(akms.len() as u16).to_le_bytes());
        for a in akms {
            r.extend_from_slice(&[0x00, 0x0f, 0xac, *a]);
        }
        r.extend_from_slice(&[0, 0]);
        r
    }

    #[test]
    fn beacons_say_name_channel_and_security() {
        for (akms, want) in [
            (vec![2], BssSecurity::Wpa2),
            (vec![8], BssSecurity::Wpa3),
            (vec![2, 8], BssSecurity::Wpa2Wpa3),
            (vec![1], BssSecurity::Enterprise),
            (vec![18], BssSecurity::Owe),
        ] {
            let b = beacon(b"Casa", Some(&rsne(&akms)), true);
            let f = frame(&b, 0).unwrap();
            assert_eq!(f.type_name(), "beacon");
            assert_eq!(f.bssid(), Some([2, 0xc0, 0xfe, 0, 0, 1]));
            let Info::Announce {
                elements,
                security,
                probe_resp,
            } = info(&f)
            else {
                panic!("not an announcement")
            };
            assert!(!probe_resp);
            assert_eq!(security, want, "{akms:?}");
            assert_eq!(elements.ssid.unwrap().text(), "Casa");
            assert_eq!(elements.channel, Some(36));
        }
        let open = beacon(b"Cafe", None, false);
        let Info::Announce { security, .. } = info(&frame(&open, 0).unwrap()) else {
            panic!()
        };
        assert_eq!(security, BssSecurity::Open);
        let wep = beacon(b"Velha", None, true);
        let Info::Announce { security, .. } = info(&frame(&wep, 0).unwrap()) else {
            panic!()
        };
        assert_eq!(security, BssSecurity::Legacy);
        // A hidden network: an empty name, or zeros of the right length.
        for ssid in [&b""[..], &[0u8; 6][..]] {
            let b = beacon(ssid, None, false);
            let Info::Announce { elements, .. } = info(&frame(&b, 0).unwrap()) else {
                panic!()
            };
            assert!(elements.ssid.unwrap().is_hidden());
        }
    }

    #[test]
    fn deauth_reason_and_data_addresses() {
        let ap = [2, 0xc0, 0xfe, 0, 0, 1];
        let sta = [2, 0x5e, 0x10, 0, 0, 0x14];
        let mut d = vec![0xc0, 0x00, 0x3a, 0x01];
        d.extend_from_slice(&sta);
        d.extend_from_slice(&ap);
        d.extend_from_slice(&ap);
        d.extend_from_slice(&[0x20, 0x00]);
        d.extend_from_slice(&7u16.to_le_bytes());
        let f = frame(&d, 0).unwrap();
        assert_eq!(f.type_name(), "deauth");
        assert_eq!(
            info(&f),
            Info::Leave {
                deauth: true,
                reason: Some(7)
            }
        );
        assert!(reason_text(7).contains("not associated"));
        // Protected (802.11w): the reason is ciphered.
        d[1] = FC_PROTECTED;
        assert_eq!(
            info(&frame(&d, 0).unwrap()),
            Info::Leave {
                deauth: true,
                reason: None
            }
        );
        // QoS data from the station to the AP, retried, with an FCS.
        let mut q = vec![0x88, FC_TO_DS | FC_RETRY | FC_PROTECTED, 0, 0];
        q.extend_from_slice(&ap);
        q.extend_from_slice(&sta);
        q.extend_from_slice(&[0xff; 6]);
        q.extend_from_slice(&[0x30, 0x00, 0x00, 0x00]);
        q.extend_from_slice(&[0xaa; 40]);
        q.extend_from_slice(&[1, 2, 3, 4]);
        let f = frame(&q, 4).unwrap();
        assert_eq!(f.type_name(), "qos-data");
        assert_eq!(f.header_len, 26);
        assert_eq!(f.body.len(), 40);
        assert!(f.retry() && f.protected() && f.to_ds());
        assert_eq!(f.bssid(), Some(ap));
        assert_eq!(f.addr2, Some(sta));
        // An ACK: only the receiver.
        let ack = [0xd4, 0, 0, 0, 2, 0x5e, 0x10, 0, 0, 0x11];
        let f = frame(&ack, 0).unwrap();
        assert_eq!((f.type_name(), f.addr2, f.bssid()), ("ack", None, None));
    }

    /// One EAPOL-Key frame, from the AP (`from_ap`) with Key Information `ki`.
    fn eapol(ki: u16, from_ap: bool) -> Vec<u8> {
        let mut d = vec![0x88, if from_ap { FC_FROM_DS } else { FC_TO_DS }, 0, 0];
        d.extend_from_slice(&[2, 0, 0, 0, 0, 1]);
        d.extend_from_slice(&[2, 0, 0, 0, 0, 2]);
        d.extend_from_slice(&[2, 0, 0, 0, 0, 1]);
        d.extend_from_slice(&[0, 0, 7, 0]);
        d.extend_from_slice(&SNAP_EAPOL);
        d.extend_from_slice(&[2, 3, 0, 95, 2]);
        d.extend_from_slice(&ki.to_be_bytes());
        d.extend_from_slice(&[0; 90]);
        d
    }

    #[test]
    fn the_four_messages_of_the_handshake() {
        // §12.7.6.2–5 (Key Information of each message, with HMAC-SHA1/AES
        // descriptor version 2).
        for (ki, msg) in [(0x008a, 1), (0x010a, 2), (0x13ca, 3), (0x030a, 4)] {
            let d = eapol(ki, msg % 2 == 1);
            assert_eq!(
                info(&frame(&d, 0).unwrap()),
                Info::EapolKey(Some(msg)),
                "{ki:#x}"
            );
        }
        // Group key handshake.
        assert_eq!(
            info(&frame(&eapol(0x1382, true), 0).unwrap()),
            Info::EapolKey(None)
        );
    }

    #[test]
    fn built_headers_parse_back() {
        for phy in [Phy::Legacy, Phy::Ht, Phy::Vht, Phy::He] {
            let s = RadioSpec {
                flags: 0,
                freq_mhz: 5220,
                signal_dbm: -61,
                noise_dbm: -95,
                phy,
                rate_500k: 12,
                mcs: 7,
                nss: 2,
                width_mhz: 40,
                short_gi: true,
            };
            let mut out = Vec::new();
            build_radiotap(&mut out, &s);
            let r = radiotap(&out).unwrap();
            assert_eq!(r.len, out.len());
            assert_eq!(r.phy, phy);
            assert_eq!(r.freq_mhz, Some(5220));
            assert_eq!((r.signal_dbm, r.noise_dbm), (Some(-61), Some(-95)));
            assert!(rate_kbps(&r).is_some(), "{phy:?}");
        }
    }

    #[test]
    fn wide_channels_center_where_the_plan_says() {
        // §E.1: 36/40 → 38, 36–48 → 42, 36–64 → 50; 100–112 → 106;
        // 149–161 → 155; 6 GHz 1–13 → 7.
        assert_eq!(center_mhz(5180, 40), Some(5190));
        assert_eq!(center_mhz(5200, 40), Some(5190));
        assert_eq!(center_mhz(5220, 80), Some(5210));
        assert_eq!(center_mhz(5320, 80), Some(5290));
        assert_eq!(center_mhz(5180, 160), Some(5250));
        assert_eq!(center_mhz(5500, 80), Some(5530));
        assert_eq!(center_mhz(5745, 80), Some(5775));
        assert_eq!(center_mhz(5955, 80), Some(5985));
        assert_eq!(center_mhz(2437, 40), None);
        assert_eq!(center_mhz(2437, 20), Some(2437));
    }

    #[test]
    fn channels_and_macs() {
        assert_eq!(channel_of(2412), Some(1));
        assert_eq!(channel_of(2484), Some(14));
        assert_eq!(channel_of(5180), Some(36));
        assert_eq!(channel_of(5955), Some(1));
        assert_eq!(band_of(5955), Some("6ghz"));
        assert_eq!(
            parse_mac("AA-bb-cc-dd-ee-ff"),
            Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
        assert_eq!(parse_mac("aa:bb:cc:dd:ee"), None);
        assert_eq!(parse_mac("aa:bb:cc:dd:ee:ff:00"), None);
        assert_eq!(mac_text(&[0xaa, 0, 1, 2, 3, 0xff]), "aa:00:01:02:03:ff");
        assert!(is_group(&BROADCAST) && !is_group(&[2, 0, 0, 0, 0, 1]));
        assert_eq!(Ssid::new(b"a\x01b").text(), "a\\x01b");
    }

    proptest! {
        #[test]
        fn garbage_never_panics(d in proptest::collection::vec(any::<u8>(), 0..400)) {
            if let Some(r) = radiotap(&d) {
                prop_assert!(r.len <= d.len());
                let _ = rate_kbps(&r);
                let _ = airtime_us(&r, d.len());
                if let Some(f) = frame(d.get(r.len..).unwrap_or(&[]), r.fcs_len()) {
                    let _ = info(&f);
                    let _ = f.bssid();
                }
            }
            if let Some(f) = frame(&d, 0) {
                let _ = info(&f);
            }
            let _ = elements(&d);
        }

        #[test]
        fn radiotap_with_garbage_fields_never_panics(
            present in any::<u32>(),
            tail in proptest::collection::vec(any::<u8>(), 0..120),
        ) {
            let mut d = vec![0, 0, 0, 0];
            d.extend_from_slice(&present.to_le_bytes());
            d.extend_from_slice(&tail);
            let len = d.len() as u16;
            d[2..4].copy_from_slice(&len.to_le_bytes());
            let _ = radiotap(&d);
        }

        #[test]
        fn built_headers_round_trip(
            freq in 2400u16..7200,
            signal in -100i8..0,
            mcs in 0u8..12,
            nss in 1u8..5,
            phy in 0u8..4,
        ) {
            let phy = [Phy::Legacy, Phy::Ht, Phy::Vht, Phy::He][usize::from(phy)];
            let s = RadioSpec { freq_mhz: freq, signal_dbm: signal, noise_dbm: -95, phy, rate_500k: 12, mcs, nss, width_mhz: 80, ..RadioSpec::default() };
            let mut out = Vec::new();
            build_radiotap(&mut out, &s);
            let r = radiotap(&out).unwrap();
            prop_assert_eq!(r.freq_mhz, Some(freq));
            prop_assert_eq!(r.signal_dbm, Some(signal));
            prop_assert_eq!(r.phy, phy);
        }
    }
}
