//! Lease history (G4.2b): who had which address, from when to when — what
//! an ISP answers when asked "who was 100.64.3.20 at 14:02 on the 3rd"
//! (Brazil's Marco Civil da Internet, art. 13, has providers keep
//! connection records for a year).
//!
//! One [`Entry`] per binding: opened when a lease is bound to a client,
//! its end moved by each renewal, closed when the lease ends (release,
//! expiry, decline, the operator). Entries go to their own journal, the
//! same way leases do: one JSON line per change, the last line of an
//! entry (address + start) wins, compaction drops what is older than the
//! retention.

use std::collections::{HashMap, VecDeque};
use std::fmt::Write as _;
use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

use super::agent;
use super::leases::Lease;

/// Entries kept in memory (**estimado**: a year of a few thousand
/// subscribers with daily churn; ~150 bytes each). Past it the oldest
/// leave memory first; the journal on disk keeps them (it is not compacted
/// while one of them is inside the retention: [`History::can_compact`]).
pub const MAX_ENTRIES: usize = 500_000;
/// Rows one query returns at most.
pub const MAX_ROWS: usize = 10_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    #[serde(rename = "a")]
    pub address: Ipv4Addr,
    #[serde(rename = "s")]
    pub server: String,
    #[serde(rename = "m", with = "mac")]
    pub mac: [u8; 6],
    #[serde(rename = "c", default, skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(rename = "h", default, skip_serializing_if = "String::is_empty")]
    pub host_name: String,
    /// Option 82 circuit and remote id, as text (`agent::text`).
    #[serde(rename = "ci", default, skip_serializing_if = "String::is_empty")]
    pub circuit_id: String,
    #[serde(rename = "ri", default, skip_serializing_if = "String::is_empty")]
    pub remote_id: String,
    /// Unix time it was bound.
    #[serde(rename = "b")]
    pub start: u64,
    /// When it ended (closed) or will end unless renewed (open).
    #[serde(rename = "e")]
    pub until: u64,
    #[serde(rename = "x", default)]
    pub closed: bool,
}

mod mac {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(m: &[u8; 6], s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(&super::super::leases::hex_plain(m))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 6], D::Error> {
        let t = String::deserialize(d)?;
        super::super::leases::unhex(&t)
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| serde::de::Error::custom("bad MAC"))
    }
}

impl Entry {
    fn of(l: &Lease, now: u64) -> Self {
        let info = l.relay_info.as_deref().unwrap_or(&[]);
        Self {
            address: l.address,
            server: l.server.clone(),
            mac: l.mac,
            client_id: l
                .client_id
                .as_deref()
                .map(corerouter_model::dhcp_server::format_client_id),
            host_name: l.host_name.clone(),
            circuit_id: agent::get(info, agent::CIRCUIT_ID)
                .map(agent::text)
                .unwrap_or_default(),
            remote_id: agent::get(info, agent::REMOTE_ID)
                .map(agent::text)
                .unwrap_or_default(),
            start: now,
            until: l.expires,
            closed: false,
        }
    }

    /// Whether the address was this entry's at Unix time `t`.
    pub fn covers(&self, t: u64) -> bool {
        self.start <= t && t < self.until.max(self.start.saturating_add(1))
    }
}

/// What a query asks.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Query {
    pub address: Option<Ipv4Addr>,
    pub mac: Option<[u8; 6]>,
    /// Who had it at this instant.
    pub at: Option<u64>,
    /// Entries that overlap [from, to].
    pub from: Option<u64>,
    pub to: Option<u64>,
    /// Text anywhere in host name, client id, circuit or remote id.
    pub text: Option<String>,
}

#[derive(Debug, Default, Clone)]
pub struct History {
    /// Oldest first. A deque: at the cap each new binding drops the front
    /// in O(1) (a `Vec::drain` plus an index rebuild was ~5 ms a binding
    /// at 500k entries, under the session lock: **medido**).
    entries: VecDeque<Entry>,
    /// Sequence number of `entries[0]`: entries are numbered as they come
    /// in, so dropping the front does not move the others' numbers.
    base: u64,
    /// Address → sequence number of its open entry.
    open: HashMap<Ipv4Addr, u64>,
    /// The latest end of an entry the cap dropped from memory: until that
    /// is past the retention, the journal is the only copy of it, and a
    /// compaction (written from memory) would erase it.
    evicted_until: Option<u64>,
}

impl History {
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn at(&self, seq: u64) -> Option<usize> {
        usize::try_from(seq.checked_sub(self.base)?).ok()
    }

    fn get_mut(&mut self, seq: u64) -> Option<&mut Entry> {
        let i = self.at(seq)?;
        self.entries.get_mut(i)
    }

    fn reindex(&mut self) {
        let base = self.base;
        self.open = self
            .entries
            .iter()
            .zip(base..)
            .filter(|(e, _)| !e.closed)
            .map(|(e, seq)| (e.address, seq))
            .collect();
    }

    fn trim(&mut self) {
        while self.entries.len() > MAX_ENTRIES {
            let Some(e) = self.entries.pop_front() else {
                break;
            };
            if !e.closed && self.open.get(&e.address) == Some(&self.base) {
                self.open.remove(&e.address);
            }
            self.evicted_until = Some(self.evicted_until.unwrap_or(0).max(e.until));
            self.base = self.base.saturating_add(1);
        }
    }

    /// Whether a compaction at `now` keeps every entry inside `retention`
    /// (none was dropped from memory by the cap, or those are all past it).
    pub fn can_compact(&self, now: u64, retention: u64) -> bool {
        retention == 0
            || self
                .evicted_until
                .is_none_or(|u| u.saturating_add(retention) <= now)
    }

    /// Entries the cap dropped from memory that the retention still keeps
    /// (on disk only), and until when: `Some(latest end)`.
    pub fn evicted_until(&self) -> Option<u64> {
        self.evicted_until
    }

    /// A lease bound to a new client: a new entry (the address's open one,
    /// if any, closes now). Returns the journal lines.
    pub fn open(&mut self, l: &Lease, now: u64) -> Vec<Entry> {
        let mut out = self.close(l.address, now);
        let e = Entry::of(l, now);
        let seq = self.base.saturating_add(self.entries.len() as u64);
        self.entries.push_back(e.clone());
        self.open.insert(l.address, seq);
        out.push(e);
        self.trim();
        out
    }

    /// The lease was renewed: its end moves.
    pub fn renew(&mut self, l: &Lease) -> Vec<Entry> {
        let Some(seq) = self.open.get(&l.address).copied() else {
            return Vec::new();
        };
        let Some(e) = self.get_mut(seq) else {
            return Vec::new();
        };
        if e.mac != l.mac {
            return Vec::new();
        }
        e.until = l.expires;
        if e.host_name.is_empty() {
            e.host_name = l.host_name.clone();
        }
        vec![e.clone()]
    }

    /// The lease of `address` ended at `now`.
    pub fn close(&mut self, address: Ipv4Addr, now: u64) -> Vec<Entry> {
        let Some(seq) = self.open.remove(&address) else {
            return Vec::new();
        };
        let Some(e) = self.get_mut(seq) else {
            return Vec::new();
        };
        e.until = e.until.min(now).max(e.start);
        e.closed = true;
        vec![e.clone()]
    }

    /// Entries still open whose lease is not bound any more (the daemon
    /// was down when it ended): closed at their known end.
    pub fn settle(&mut self, bound: impl Fn(Ipv4Addr, [u8; 6]) -> bool) -> Vec<Entry> {
        let stale: Vec<Ipv4Addr> = self
            .open
            .iter()
            .filter_map(|(a, seq)| {
                let e = self.entries.get(self.at(*seq)?)?;
                Some((*a, e.mac))
            })
            .filter(|(a, m)| !bound(*a, *m))
            .map(|(a, _)| a)
            .collect();
        let mut out = Vec::new();
        for a in stale {
            let until = self
                .open
                .get(&a)
                .and_then(|seq| self.at(*seq))
                .and_then(|i| self.entries.get(i))
                .map_or(0, |e| e.until);
            out.extend(self.close(a, until));
        }
        out
    }

    /// Journal lines in: the last one of each (address, start) wins.
    /// Returns the lines that did not parse.
    pub fn replay<'a>(&mut self, lines: impl Iterator<Item = &'a str>) -> usize {
        let mut bad = 0;
        let mut at: HashMap<(Ipv4Addr, u64), usize> = self
            .entries
            .iter()
            .enumerate()
            .map(|(i, e)| ((e.address, e.start), i))
            .collect();
        // A hostile or runaway journal: its newest lines (the last wins).
        for line in super::leases::newest(lines, super::leases::MAX_RECORDS) {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            match serde_json::from_str::<Entry>(line) {
                Ok(e) => match at.get(&(e.address, e.start)).copied() {
                    Some(i) => {
                        if let Some(slot) = self.entries.get_mut(i) {
                            *slot = e;
                        }
                    }
                    None => {
                        at.insert((e.address, e.start), self.entries.len());
                        self.entries.push_back(e);
                    }
                },
                Err(_) => bad += 1,
            }
        }
        self.entries.make_contiguous().sort_by_key(|e| e.start);
        self.reindex();
        self.trim();
        bad
    }

    /// Entries ended more than `retention` seconds before `now` go (all of
    /// them with 0); the rest, one line each (the compacted journal).
    pub fn compact(&mut self, now: u64, retention: u64) -> String {
        if retention == 0 {
            // No history kept at all.
            self.entries.clear();
            self.open.clear();
            self.evicted_until = None;
            return String::new();
        }
        self.entries
            .retain(|e| !e.closed || e.until.saturating_add(retention) > now);
        self.reindex();
        if self.can_compact(now, retention) {
            self.evicted_until = None;
        }
        let mut out = String::with_capacity(self.entries.len() * 140);
        for e in &self.entries {
            if let Ok(l) = serde_json::to_string(e) {
                out.push_str(&l);
                out.push('\n');
            }
        }
        out
    }

    /// The entries that answer `q`, newest first, at most `limit`.
    pub fn query(&self, q: &Query, limit: usize) -> Vec<&Entry> {
        let needle = q.text.as_ref().map(|t| t.to_lowercase());
        self.entries
            .iter()
            .rev()
            .filter(|e| q.address.is_none_or(|a| a == e.address))
            .filter(|e| q.mac.is_none_or(|m| m == e.mac))
            .filter(|e| q.at.is_none_or(|t| e.covers(t)))
            .filter(|e| q.from.is_none_or(|f| e.until >= f))
            .filter(|e| q.to.is_none_or(|t| e.start <= t))
            .filter(|e| {
                needle.as_ref().is_none_or(|n| {
                    [&e.host_name, &e.circuit_id, &e.remote_id]
                        .iter()
                        .any(|f| f.to_lowercase().contains(n))
                        || e.client_id
                            .as_deref()
                            .is_some_and(|c| c.contains(n.as_str()))
                })
            })
            .take(limit.min(MAX_ROWS))
            .collect()
    }
}

/// RFC 3339 UTC of a Unix time (no time-zone database here: the router's
/// records are in UTC, as logs should be).
pub fn utc(t: u64) -> String {
    let days = t / 86_400;
    let secs = t % 86_400;
    // Howard Hinnant's civil_from_days.
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        secs / 60 % 60,
        secs % 60
    )
}

/// RFC 3339 back to Unix time (`2026-10-03T14:02:00Z`, the `Z` or an
/// offset `±hh:mm`; a bare date is midnight UTC).
pub fn parse_time(text: &str) -> Option<u64> {
    let t = text.trim();
    if let Ok(n) = t.parse::<u64>() {
        return Some(n);
    }
    let (date, rest) = t.split_once(['T', ' ']).unwrap_or((t, "00:00:00Z"));
    let mut d = date.split('-');
    let y: i64 = d.next()?.parse().ok()?;
    let m: i64 = d.next()?.parse().ok()?;
    let dd: i64 = d.next()?.parse().ok()?;
    // RFC 3339 §5.6: four-digit years; nothing here may overflow.
    if !(0..=9999).contains(&y) || !(1..=12).contains(&m) || !(1..=31).contains(&dd) {
        return None;
    }
    let (clock, offset) = match rest.find(['Z', '+', '-']) {
        Some(i) => (rest.get(..i)?, rest.get(i..)?),
        None => (rest, "Z"),
    };
    let mut c = clock.split(':');
    let hh: i64 = c.next().unwrap_or("0").parse().ok()?;
    let mm: i64 = c.next().unwrap_or("0").parse().ok()?;
    let ss: i64 = c
        .next()
        .unwrap_or("0")
        .split('.')
        .next()
        .unwrap_or("0")
        .parse()
        .ok()?;
    if !(0..=23).contains(&hh) || !(0..=59).contains(&mm) || !(0..=60).contains(&ss) {
        return None;
    }
    let off = match offset {
        "Z" | "" => 0,
        o => {
            let sign = if o.starts_with('-') { -1 } else { 1 };
            let (oh, om) = o.get(1..)?.split_once(':').unwrap_or((o.get(1..)?, "0"));
            let (oh, om) = (oh.parse::<i64>().ok()?, om.parse::<i64>().ok()?);
            if !(0..=23).contains(&oh) || !(0..=59).contains(&om) {
                return None;
            }
            sign * (oh * 3600 + om * 60)
        }
    };
    // days_from_civil.
    let y2 = if m <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + dd - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    u64::try_from(days * 86_400 + hh * 3600 + mm * 60 + ss - off).ok()
}

/// The entries as CSV (RFC 4180), UTC times.
pub fn csv(entries: &[&Entry]) -> String {
    let field = |s: &str| {
        // OWASP CSV injection: a cell a spreadsheet would run as a formula
        // (host names and option 82 are the client's) is made text.
        let s = if s.starts_with(['=', '+', '-', '@', '\t', '\r']) {
            format!("'{s}")
        } else {
            s.to_owned()
        };
        if s.contains([',', '"', '\n', '\r']) {
            format!("\"{}\"", s.replace('"', "\"\""))
        } else {
            s
        }
    };
    let mut out = String::from(
        "address,mac,client_id,host_name,server,circuit_id,remote_id,start,end,open\r\n",
    );
    for e in entries {
        let _ = write!(
            out,
            "{},{},{},{},{},{},{},{},{},{}\r\n",
            e.address,
            corerouter_model::MacAddr(e.mac),
            field(e.client_id.as_deref().unwrap_or("")),
            field(&e.host_name),
            field(&e.server),
            field(&e.circuit_id),
            field(&e.remote_id),
            utc(e.start),
            utc(e.until),
            if e.closed { "no" } else { "yes" },
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::leases::State;

    fn lease(ip: [u8; 4], mac: u8, expires: u64) -> Lease {
        Lease {
            address: Ipv4Addr::from(ip),
            server: "dhcp1".into(),
            state: State::Bound,
            mac: [2, 0, 0, 0, 0, mac],
            client_id: None,
            host_name: "cpe".into(),
            vendor_class: String::new(),
            expires,
            lease_time: 600,
            last_seen: 0,
            reason: String::new(),
            relay_info: agent::build(b"olt1 0/1/3:12", b"line-77"),
            hw: None,
        }
    }

    #[test]
    fn who_had_the_address_when() {
        let mut h = History::default();
        let a = lease([100, 64, 3, 20], 1, 1600);
        h.open(&a, 1000);
        let mut renewed = a.clone();
        renewed.expires = 2200;
        h.renew(&renewed);
        h.close(a.address, 1900);
        let b = lease([100, 64, 3, 20], 2, 3000);
        h.open(&b, 2500);
        let at = |t| {
            h.query(
                &Query {
                    address: Some(a.address),
                    at: Some(t),
                    ..Query::default()
                },
                10,
            )
            .first()
            .map(|e| e.mac[5])
        };
        assert_eq!(at(1500), Some(1));
        assert_eq!(at(2000), None, "free between the two");
        assert_eq!(at(2600), Some(2));
        let first = h.query(&Query::default(), 10)[1].clone();
        assert_eq!(first.circuit_id, "olt1 0/1/3:12");
        assert_eq!(first.until, 1900);
        assert!(
            h.query(
                &Query {
                    text: Some("LINE-77".into()),
                    ..Query::default()
                },
                10
            )
            .len()
                == 2
        );
    }

    #[test]
    fn journal_compaction_and_settling() {
        let mut h = History::default();
        let mut lines = Vec::new();
        for e in h.open(&lease([10, 0, 0, 1], 1, 500), 100) {
            lines.push(serde_json::to_string(&e).unwrap());
        }
        for e in h.close("10.0.0.1".parse().unwrap(), 300) {
            lines.push(serde_json::to_string(&e).unwrap());
        }
        for e in h.open(&lease([10, 0, 0, 2], 2, 900), 400) {
            lines.push(serde_json::to_string(&e).unwrap());
        }
        lines.push("{torn".into());
        let mut back = History::default();
        assert_eq!(back.replay(lines.iter().map(String::as_str)), 1);
        assert_eq!(back.len(), 2);
        // The daemon was down when .2's lease ended: closed at its end.
        let closed = back.settle(|_, _| false);
        assert_eq!(closed.len(), 1);
        assert_eq!(closed[0].until, 900);
        // A year later, both are past a 100 s retention.
        assert_eq!(back.compact(2000, 100), "");
    }

    #[test]
    fn times_and_csv() {
        assert_eq!(utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(utc(1_792_701_883), "2026-10-22T20:44:43Z");
        assert_eq!(parse_time("2026-10-22T20:44:43Z"), Some(1_792_701_883));
        assert_eq!(parse_time("2026-10-22T17:44:43-03:00"), Some(1_792_701_883));
        assert_eq!(parse_time("1792701883"), Some(1_792_701_883));
        assert_eq!(parse_time("2026-10-22"), Some(1_792_627_200));
        assert!(parse_time("22/10/2026").is_none());
        let mut h = History::default();
        let mut l = lease([10, 0, 0, 1], 1, 700);
        l.host_name = "a,\"b\"".into();
        h.open(&l, 100);
        let text = csv(&h.query(&Query::default(), 10));
        assert!(text.starts_with("address,mac,"));
        assert!(text.contains("\"a,\"\"b\"\"\""), "{text}");
        assert!(text.contains("1970-01-01T00:01:40Z"));
    }

    /// OWASP CSV injection: a host name (client-controlled) that a
    /// spreadsheet would run as a formula is exported as text.
    #[test]
    fn csv_cells_are_never_formulas() {
        let mut h = History::default();
        for (n, name) in ["=1+1", "+cmd", "-2", "@SUM(A1)", "\tx", "\rx"]
            .iter()
            .enumerate()
        {
            let mut l = lease([10, 0, 0, 1 + n as u8], 1, 700);
            l.host_name = (*name).into();
            h.open(&l, 100);
        }
        let text = csv(&h.query(&Query::default(), 10));
        for line in text.lines().skip(1) {
            let host = line.split(',').nth(3).unwrap();
            assert!(
                !host.starts_with(['=', '+', '-', '@', '\t', '\r']),
                "{line}"
            );
        }
    }

    /// Hostile times: no overflow (a panic in debug, a wrong instant in
    /// release).
    #[test]
    fn hostile_times_do_not_overflow() {
        assert_eq!(parse_time("999999999999999-01-01"), None);
        assert_eq!(parse_time("2026-01-01T99999999999999:00"), None);
        assert_eq!(parse_time("2026-01-01T24:00:00Z"), None);
        assert_eq!(parse_time("2026-01-01T10:60:00Z"), None);
        assert_eq!(parse_time("2026-01-01T10:00:00+999999999999:00"), None);
        assert_eq!(parse_time("10000-01-01"), None);
        assert_eq!(parse_time("9999-12-31T23:59:59Z"), Some(253_402_300_799));
        let mut e = Entry::of(&lease([10, 0, 0, 1], 1, 0), u64::MAX);
        e.until = 0;
        // No overflow at the end of time (a hostile journal line).
        let _ = e.covers(u64::MAX);
        assert!(!e.covers(0));
    }

    /// A flood of new bindings at the cap costs O(1) each (not a 500k
    /// memmove plus an index rebuild under the session lock).
    #[test]
    fn opening_at_the_cap_is_cheap() {
        let mut h = History::default();
        for n in 0..MAX_ENTRIES as u32 {
            let [_, _, a, b] = n.to_be_bytes();
            h.open(&lease([10, 1, a, b], 1, 700), u64::from(n));
        }
        let t = std::time::Instant::now();
        for n in 0..2_000u32 {
            let [_, _, a, b] = n.to_be_bytes();
            h.open(&lease([10, 2, a, b], 2, 700), 1_000_000 + u64::from(n));
        }
        assert!(
            t.elapsed() < std::time::Duration::from_secs(2),
            "{:?}",
            t.elapsed()
        );
        assert_eq!(h.len(), MAX_ENTRIES);
        // The open entries still renew and close.
        let l = lease([10, 2, 0, 5], 2, 9_000_000);
        assert_eq!(h.renew(&l).len(), 1);
        assert_eq!(h.close(l.address, 2_000_000).len(), 1);
        // What left memory is on disk only: a compaction now would erase
        // records inside the retention (laundering one's own history by
        // flooding new bindings).
        let year = 365 * 86_400;
        assert!(!h.can_compact(2_000_000, year));
        assert!(h.can_compact(2_000_000 + 2 * year, year));
        assert!(h.can_compact(2_000_000, 0), "history turned off");
    }
}
