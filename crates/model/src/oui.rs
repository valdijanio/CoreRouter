//! Vendor of a MAC address (G1.27d): the IEEE MA-L public listing
//! (`oui.csv`, standards-oui.ieee.org) in a compact form, looked up with
//! no start-up cost.
//!
//! The table is bytes, searched in place:
//!
//! ```text
//! "CROUI1\0\0"                     magic
//! u32 count, u32 names_len          big-endian
//! u8 date_len, date (ASCII)         the day the listing was read
//! [u8; 32] sha256                   of the oui.csv it came from
//! u32 source_size                   bytes of that oui.csv
//! count × [prefix: 3 bytes][name offset: 3 bytes]   sorted by prefix
//! names: (u8 len, bytes)*           each organization once
//! ```
//!
//! A built-in table is embedded (`data/oui.bin`, made by `cargo xtask oui`
//! from the listing, see `docs/third-party.md`); the router can download
//! a newer one (`ip.arp.vendors.update`), which wins over it.
//!
//! Hostile input: the downloaded CSV is parsed field by field with every
//! length bounded, and a table is checked whole ([`Table::new`]) before
//! use; a lookup never reads past the bytes.

use std::collections::HashMap;

/// The table built into the program.
pub static BUILTIN: &[u8] = include_bytes!("../data/oui.bin");

const MAGIC: &[u8; 8] = b"CROUI1\0\0";
const RECORD: usize = 6;
/// Longest organization name kept (bytes; cut at a character).
pub const MAX_NAME: usize = 64;
/// Assignments one table may hold (the MA-L listing has ~40 000).
pub const MAX_ENTRIES: usize = 1 << 17;
/// Largest `oui.csv` taken (the listing is ~4 MB).
pub const MAX_CSV: usize = 16 << 20;

/// What a table says of itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Meta {
    pub entries: usize,
    pub date: String,
    pub sha256: [u8; 32],
    pub source_size: u32,
}

impl Meta {
    pub fn sha256_hex(&self) -> String {
        self.sha256.iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// A checked table, borrowed or owned.
#[derive(Debug, Clone)]
pub struct Table<'a> {
    bytes: &'a [u8],
    count: usize,
    records: usize,
    names: usize,
    meta_end: usize,
}

fn be32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn be24(b: &[u8], at: usize) -> Option<u32> {
    let x = b.get(at..at + 3)?;
    Some(u32::from(*x.first()?) << 16 | u32::from(*x.get(1)?) << 8 | u32::from(*x.get(2)?))
}

impl<'a> Table<'a> {
    /// Check `bytes` whole: header, sorted records, names inside.
    pub fn new(bytes: &'a [u8]) -> Result<Self, String> {
        let t = Self::new_unchecked(bytes)?;
        let mut last = None;
        for i in 0..t.count {
            let (prefix, off) = t.record(i).ok_or("truncated record")?;
            if last.is_some_and(|l| l >= prefix) {
                return Err("records not sorted".into());
            }
            last = Some(prefix);
            t.name_at(off as usize).ok_or("a name outside the table")?;
        }
        Ok(t)
    }

    /// The header only, for a table already checked with [`Table::new`]
    /// (a lookup still never reads past the bytes).
    pub fn new_unchecked(bytes: &'a [u8]) -> Result<Self, String> {
        if bytes.get(..8) != Some(MAGIC.as_slice()) {
            return Err("not an OUI table".into());
        }
        let count = be32(bytes, 8).ok_or("truncated header")? as usize;
        let names_len = be32(bytes, 12).ok_or("truncated header")? as usize;
        if count > MAX_ENTRIES {
            return Err(format!("{count} entries: at most {MAX_ENTRIES}"));
        }
        let date_len = usize::from(*bytes.get(16).ok_or("truncated header")?);
        let meta_end = 17 + date_len + 32 + 4;
        let records = meta_end;
        let names = records
            .checked_add(count.checked_mul(RECORD).ok_or("too many entries")?)
            .ok_or("too many entries")?;
        if names.checked_add(names_len) != Some(bytes.len()) {
            return Err("sizes do not match".into());
        }
        Ok(Self {
            bytes,
            count,
            records,
            names,
            meta_end,
        })
    }

    fn record(&self, i: usize) -> Option<(u32, u32)> {
        let at = self.records + i * RECORD;
        Some((be24(self.bytes, at)?, be24(self.bytes, at + 3)?))
    }

    fn name_at(&self, off: usize) -> Option<&'a str> {
        let at = self.names.checked_add(off)?;
        let len = usize::from(*self.bytes.get(at)?);
        std::str::from_utf8(self.bytes.get(at + 1..at + 1 + len)?).ok()
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn meta(&self) -> Meta {
        let date_len = usize::from(self.bytes.get(16).copied().unwrap_or(0));
        let date = self
            .bytes
            .get(17..17 + date_len)
            .and_then(|d| std::str::from_utf8(d).ok())
            .unwrap_or_default()
            .to_owned();
        let at = 17 + date_len;
        let mut sha256 = [0u8; 32];
        if let Some(s) = self.bytes.get(at..at + 32) {
            sha256.copy_from_slice(s);
        }
        Meta {
            entries: self.count,
            date,
            sha256,
            source_size: be32(self.bytes, self.meta_end - 4).unwrap_or(0),
        }
    }

    /// The organization the first three bytes of `mac` were assigned to.
    /// A locally administered or group address has none (IEEE 802-2014
    /// §8.2: the U/L and I/G bits).
    pub fn vendor(&self, mac: [u8; 6]) -> Option<&'a str> {
        if mac[0] & 0b11 != 0 {
            return None;
        }
        let want = u32::from(mac[0]) << 16 | u32::from(mac[1]) << 8 | u32::from(mac[2]);
        let (mut lo, mut hi) = (0usize, self.count);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let (prefix, off) = self.record(mid)?;
            match prefix.cmp(&want) {
                std::cmp::Ordering::Equal => return self.name_at(off as usize),
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
            }
        }
        None
    }
}

/// One CSV line's fields (RFC 4180 quoting); `None` on a malformed line.
fn fields(line: &str) -> Option<Vec<String>> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut chars = line.chars().peekable();
    let mut quoted = false;
    while let Some(c) = chars.next() {
        match (c, quoted) {
            ('"', true) if chars.peek() == Some(&'"') => {
                chars.next();
                cur.push('"');
            }
            ('"', true) => quoted = false,
            ('"', false) if cur.is_empty() => quoted = true,
            (',', false) => out.push(std::mem::take(&mut cur)),
            (c, _) => cur.push(c),
        }
        if cur.len() > 4096 || out.len() > 16 {
            return None;
        }
    }
    if quoted {
        return None;
    }
    out.push(cur);
    Some(out)
}

/// An organization name as shown: one line, no control characters,
/// spaces collapsed, at most [`MAX_NAME`] bytes.
fn clean(name: &str) -> String {
    let mut out = String::new();
    for word in name.split(|c: char| c.is_whitespace() || c.is_control()) {
        if word.is_empty() {
            continue;
        }
        if !out.is_empty() {
            out.push(' ');
        }
        out.push_str(word);
    }
    if out.len() > MAX_NAME {
        let mut end = MAX_NAME;
        while !out.is_char_boundary(end) {
            end -= 1;
        }
        out.truncate(end);
    }
    out
}

/// The MA-L assignments of an `oui.csv` (`Registry,Assignment,
/// Organization Name,Organization Address`), sorted, one per prefix.
/// Lines that are not MA-L or do not parse are skipped and counted.
pub fn parse_csv(text: &str) -> Result<(Vec<(u32, String)>, usize), String> {
    if text.len() > MAX_CSV {
        return Err(format!("larger than {MAX_CSV} bytes"));
    }
    let mut out = Vec::new();
    let mut skipped = 0usize;
    for (i, line) in text.lines().enumerate() {
        let line = line.trim_end_matches('\r');
        if i == 0 && line.starts_with("Registry") {
            continue;
        }
        let parsed = fields(line).and_then(|f| {
            let reg = f.first()?;
            let hex = f.get(1)?;
            let name = clean(f.get(2)?);
            if reg != "MA-L" || hex.len() != 6 || name.is_empty() {
                return None;
            }
            let prefix = u32::from_str_radix(hex, 16).ok()?;
            Some((prefix, name))
        });
        match parsed {
            Some(p) => out.push(p),
            None if line.trim().is_empty() => {}
            None => skipped += 1,
        }
        if out.len() > MAX_ENTRIES {
            return Err(format!("more than {MAX_ENTRIES} assignments"));
        }
    }
    out.sort_by_key(|(p, _)| *p);
    out.dedup_by_key(|(p, _)| *p);
    if out.is_empty() {
        return Err("no MA-L assignment found: not the IEEE oui.csv?".into());
    }
    Ok((out, skipped))
}

/// The table bytes of `entries` (sorted, unique prefixes, as
/// [`parse_csv`] gives them).
pub fn build(entries: &[(u32, String)], date: &str, sha256: [u8; 32], source_size: u32) -> Vec<u8> {
    let mut names: Vec<u8> = Vec::new();
    let mut at: HashMap<&str, u32> = HashMap::new();
    let mut records = Vec::with_capacity(entries.len() * RECORD);
    for (prefix, name) in entries {
        let off = *at.entry(name.as_str()).or_insert_with(|| {
            let off = u32::try_from(names.len()).unwrap_or(u32::MAX);
            let bytes = name.as_bytes();
            let len = bytes.len().min(MAX_NAME);
            names.push(u8::try_from(len).unwrap_or(u8::MAX));
            names.extend_from_slice(bytes.get(..len).unwrap_or_default());
            off
        });
        records.extend_from_slice(&prefix.to_be_bytes()[1..]);
        records.extend_from_slice(&off.to_be_bytes()[1..]);
    }
    let date: String = date.chars().filter(char::is_ascii).take(32).collect();
    let mut out = Vec::with_capacity(64 + records.len() + names.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&u32::try_from(entries.len()).unwrap_or(0).to_be_bytes());
    out.extend_from_slice(&u32::try_from(names.len()).unwrap_or(0).to_be_bytes());
    out.push(u8::try_from(date.len()).unwrap_or(0));
    out.extend_from_slice(date.as_bytes());
    out.extend_from_slice(&sha256);
    out.extend_from_slice(&source_size.to_be_bytes());
    out.extend_from_slice(&records);
    out.extend_from_slice(&names);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const CSV: &str = "Registry,Assignment,Organization Name,Organization Address\r\n\
MA-L,286FB9,\"Nokia Shanghai Bell Co., Ltd.\",\"No.388 Ning Qiao Road\"\r\n\
MA-L,005056,\"VMware, Inc.\",3401 Hillview Avenue PALO ALTO CA US 94304 \r\n\
MA-M,0050C2A,Not a MA-L,x\r\n\
MA-L,000C42,Routerboard.com,Mikrotikls SIA Riga LV\r\n\
MA-L,4C5E0C,Routerboard.com,Riga LV\r\n\
MA-L,zzzzzz,Bad,x\r\n";

    fn table() -> Vec<u8> {
        let (entries, skipped) = parse_csv(CSV).unwrap();
        assert_eq!((entries.len(), skipped), (4, 2));
        build(&entries, "2026-10-27", [7; 32], 123)
    }

    #[test]
    fn lookups_find_the_organization() {
        let bytes = table();
        let t = Table::new(&bytes).unwrap();
        assert_eq!(t.vendor([0x00, 0x50, 0x56, 1, 2, 3]), Some("VMware, Inc."));
        assert_eq!(t.vendor([0x28, 0x6F, 0xB9, 0, 0, 0]), Some("Nokia Shanghai Bell Co., Ltd."));
        assert_eq!(t.vendor([0x4C, 0x5E, 0x0C, 9, 9, 9]), Some("Routerboard.com"));
        assert_eq!(t.vendor([0x00, 0x11, 0x22, 0, 0, 0]), None);
        // Locally administered (bit 1) and group (bit 0): no vendor.
        assert_eq!(t.vendor([0x02, 0x50, 0x56, 0, 0, 0]), None);
        let m = t.meta();
        assert_eq!((m.entries, m.date.as_str(), m.source_size), (4, "2026-10-27", 123));
        assert_eq!(m.sha256_hex().len(), 64);
        // One name for the two Routerboard.com prefixes.
        assert!(bytes.windows(15).filter(|w| *w == b"Routerboard.com").count() == 1);
    }

    #[test]
    fn the_built_in_table_is_valid() {
        let t = Table::new(BUILTIN).unwrap();
        assert!(t.len() > 30_000, "{}", t.len());
        assert_eq!(t.vendor([0x00, 0x50, 0x56, 0, 0, 0]), Some("VMware, Inc."));
    }

    #[test]
    fn broken_tables_are_refused() {
        let good = table();
        assert!(Table::new(&good[..good.len() - 1]).is_err());
        assert!(Table::new(b"garbage").is_err());
        let mut unsorted = good.clone();
        // Swap the first two records' prefixes.
        let r = 8 + 4 + 4 + 1 + 10 + 32 + 4;
        let (a, b) = (unsorted[r..r + 3].to_vec(), unsorted[r + 6..r + 9].to_vec());
        unsorted[r..r + 3].copy_from_slice(&b);
        unsorted[r + 6..r + 9].copy_from_slice(&a);
        assert!(Table::new(&unsorted).is_err());
        assert!(parse_csv("Registry,Assignment\n").is_err());
    }

    #[test]
    fn names_are_cleaned() {
        assert_eq!(clean("  A\t\u{7}B   C "), "A B C");
        assert!(clean(&"é".repeat(100)).len() <= MAX_NAME);
    }

    proptest! {
        #[test]
        fn hostile_csv_and_tables_never_panic(junk in proptest::collection::vec(any::<u8>(), 0..2048)) {
            let text = String::from_utf8_lossy(&junk);
            let _ = parse_csv(&text);
            if let Ok(t) = Table::new(&junk) {
                let _ = t.vendor([0, 0, 0, 0, 0, 0]);
                let _ = t.meta();
            }
        }

        #[test]
        fn every_built_entry_is_found(prefixes in proptest::collection::btree_set(0u32..0x00ff_ffff, 1..200)) {
            let entries: Vec<(u32, String)> = prefixes.iter().map(|p| (p & 0xfcffff, format!("Org {p}"))).collect();
            let mut entries = entries;
            entries.sort_by_key(|(p, _)| *p);
            entries.dedup_by_key(|(p, _)| *p);
            let bytes = build(&entries, "d", [0; 32], 0);
            let t = Table::new(&bytes).unwrap();
            for (p, name) in &entries {
                let mac = [(p >> 16) as u8, (p >> 8) as u8, *p as u8, 0, 0, 0];
                prop_assert_eq!(t.vendor(mac), Some(name.as_str()));
            }
        }
    }
}
