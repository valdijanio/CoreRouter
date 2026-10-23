//! The lease table: one record per address the server ever handed out or
//! held back, indexed by address and by client.
//!
//! Records outlive their lease: an expired or released address remembers
//! its last client, so that client gets it again (RFC 2131 §4.3.1 "the
//! client's previous address") while the pool has never-used addresses for
//! the others. A full pool reuses the oldest of them.
//!
//! Every change that must survive a restart becomes a [`Record`], one JSON
//! line in the journal (see the engine's `dhcp_server.rs`): the line holds
//! the whole record, so replaying the journal is "the last line of each
//! address wins", and compacting it is writing one line per live record —
//! Kea's memfile and its LFC.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

/// What an address is doing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum State {
    /// Offered, waiting for the REQUEST (held a short while).
    Offered,
    Bound,
    /// Given back by the client (RELEASE) or by the operator.
    Released,
    Expired,
    /// Someone else answers ARP for it (our probe): not handed out until
    /// `expires` (the lease time, as RouterOS).
    Conflict,
    /// The client found it in use (DECLINE, RFC 2131 §4.3.3): held the
    /// same way.
    Declined,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Offered => "offered",
            Self::Bound => "bound",
            Self::Released => "released",
            Self::Expired => "expired",
            Self::Conflict => "conflict",
            Self::Declined => "declined",
        }
    }

    /// Whether the address may go to another client.
    pub fn free(self) -> bool {
        matches!(self, Self::Released | Self::Expired)
    }

    /// Bound or on offer: counts as used.
    pub fn active(self) -> bool {
        matches!(self, Self::Offered | Self::Bound)
    }
}

/// One address's record. Field names are short: this is also the journal
/// line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lease {
    #[serde(rename = "a")]
    pub address: Ipv4Addr,
    /// The server's name.
    #[serde(rename = "s")]
    pub server: String,
    #[serde(rename = "st")]
    pub state: State,
    /// `chaddr` (MAC).
    #[serde(rename = "m", with = "hex6")]
    pub mac: [u8; 6],
    /// Option 61, when the client sent one.
    #[serde(
        rename = "c",
        default,
        skip_serializing_if = "Option::is_none",
        with = "hexopt"
    )]
    pub client_id: Option<Vec<u8>>,
    /// Host name the client sent (option 81 or 12), cleaned.
    #[serde(rename = "h", default, skip_serializing_if = "String::is_empty")]
    pub host_name: String,
    /// Option 60, printable.
    #[serde(rename = "v", default, skip_serializing_if = "String::is_empty")]
    pub vendor_class: String,
    /// Unix time the state ends (lease end, offer end, conflict hold).
    #[serde(rename = "e")]
    pub expires: u64,
    /// Lease length granted (seconds), for T1/T2 and the DNS TTL.
    #[serde(rename = "t", default)]
    pub lease_time: u32,
    /// Unix time of the client's last message.
    #[serde(rename = "l", default)]
    pub last_seen: u64,
    /// Why a conflict ("ARP reply from …", "declined by the client").
    #[serde(rename = "r", default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
    /// Option 82 as received (G4.2b reads circuit and remote ids from it).
    #[serde(
        rename = "o82",
        default,
        skip_serializing_if = "Option::is_none",
        with = "hexopt"
    )]
    pub relay_info: Option<Vec<u8>>,
    /// `htype` + `chaddr` of a client that is not Ethernet (`htype` 1,
    /// `hlen` 6): its identity without a client id (RFC 2131 §4.2). `None`
    /// for Ethernet (`[1] + mac`) and in lines written before it existed.
    #[serde(
        rename = "hw",
        default,
        skip_serializing_if = "Option::is_none",
        with = "hexopt"
    )]
    pub hw: Option<Vec<u8>>,
}

impl Lease {
    /// RFC 2131 §4.2: the client id, else `htype` + `chaddr` (1 + the MAC
    /// for Ethernet).
    pub fn client_key(&self) -> Vec<u8> {
        match (&self.client_id, &self.hw) {
            (Some(id), _) => id.clone(),
            (None, Some(hw)) => hw.clone(),
            (None, None) => {
                let mut k = Vec::with_capacity(7);
                k.push(1);
                k.extend_from_slice(&self.mac);
                k
            }
        }
    }

    /// Seconds left at `now` (0 once over).
    pub fn left(&self, now: u64) -> u64 {
        self.expires.saturating_sub(now)
    }
}

/// Bytes as plain lowercase hex.
pub fn hex_plain(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Plain hex back to bytes.
pub fn unhex(t: &str) -> Option<Vec<u8>> {
    if !t.len().is_multiple_of(2) || t.len() > 1024 {
        return None;
    }
    (0..t.len())
        .step_by(2)
        .map(|i| t.get(i..i + 2).and_then(|h| u8::from_str_radix(h, 16).ok()))
        .collect()
}

mod hex6 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(m: &[u8; 6], s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(&super::hex_plain(m))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 6], D::Error> {
        let t = String::deserialize(d)?;
        let v = super::unhex(&t).ok_or_else(|| serde::de::Error::custom("bad MAC"))?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("a MAC is 6 bytes"))
    }
}

mod hexopt {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(b) => s.collect_str(&super::hex_plain(b)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        let t = Option::<String>::deserialize(d)?;
        match t {
            None => Ok(None),
            Some(t) => super::unhex(&t)
                .filter(|b| b.len() <= 255)
                .map(Some)
                .ok_or_else(|| serde::de::Error::custom("bad hex")),
        }
    }
}

/// A journal line: a record as it is now, or an address forgotten.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Record {
    Lease(Lease),
    Forget {
        #[serde(rename = "forget")]
        forget: Ipv4Addr,
    },
}

/// Lines a journal may hold on the way in (**estimado**: a /12 of leases
/// plus history; hostile file).
pub const MAX_RECORDS: usize = 1 << 21;

/// The last `cap` of `lines` (all of them when there are fewer), in order.
pub fn newest<'a>(lines: impl Iterator<Item = &'a str>, cap: usize) -> VecDeque<&'a str> {
    let mut keep: VecDeque<&'a str> = VecDeque::new();
    for line in lines {
        if keep.len() >= cap {
            keep.pop_front();
        }
        if cap > 0 {
            keep.push_back(line);
        }
    }
    keep
}

/// The table.
#[derive(Debug, Default, Clone)]
pub struct Leases {
    by_addr: HashMap<Ipv4Addr, Lease>,
    /// Client key → its addresses (on any server).
    by_client: HashMap<Vec<u8>, Vec<Ipv4Addr>>,
    /// The free records (released, expired) by (end, address): the one
    /// idle the longest is the first (a full pool reuses it without
    /// walking the table).
    free: BTreeSet<(u64, u32)>,
    /// MAC → its addresses (`client_mac_limit` counts them per DISCOVER).
    by_mac: HashMap<[u8; 6], Vec<Ipv4Addr>>,
}

impl Leases {
    pub fn len(&self) -> usize {
        self.by_addr.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_addr.is_empty()
    }

    pub fn get(&self, ip: Ipv4Addr) -> Option<&Lease> {
        self.by_addr.get(&ip)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Lease> {
        self.by_addr.values()
    }

    /// The records of client `key` on `server`.
    pub fn of_client<'a>(&'a self, key: &[u8], server: &'a str) -> impl Iterator<Item = &'a Lease> {
        self.by_client
            .get(key)
            .into_iter()
            .flatten()
            .filter_map(|ip| self.by_addr.get(ip))
            .filter(move |l| l.server == server)
    }

    /// The records of hardware address `mac` (any client id, any server).
    pub fn of_mac(&self, mac: [u8; 6]) -> impl Iterator<Item = &Lease> {
        self.by_mac
            .get(&mac)
            .into_iter()
            .flatten()
            .filter_map(|ip| self.by_addr.get(ip))
    }

    /// The free records, the one idle the longest first.
    pub fn free_oldest_first(&self) -> impl Iterator<Item = &Lease> {
        self.free
            .iter()
            .filter_map(|(_, ip)| self.by_addr.get(&Ipv4Addr::from(*ip)))
    }

    /// Insert or replace the record of `l.address`.
    pub fn put(&mut self, l: Lease) {
        let ip = l.address;
        let key = l.client_key();
        if let Some(old) = self.by_addr.get(&ip) {
            let old_key = old.client_key();
            let (old_mac, old_free) = (old.mac, old.state.free().then_some(old.expires));
            if old_key != key {
                self.unindex(&old_key, ip);
            }
            if old_mac != l.mac {
                self.unindex_mac(old_mac, ip);
            }
            if let Some(e) = old_free {
                self.free.remove(&(e, u32::from(ip)));
            }
        }
        let list = self.by_client.entry(key).or_default();
        if !list.contains(&ip) {
            list.push(ip);
        }
        let macs = self.by_mac.entry(l.mac).or_default();
        if !macs.contains(&ip) {
            macs.push(ip);
        }
        if l.state.free() {
            self.free.insert((l.expires, u32::from(ip)));
        }
        self.by_addr.insert(ip, l);
    }

    fn unindex(&mut self, key: &[u8], ip: Ipv4Addr) {
        if let Some(list) = self.by_client.get_mut(key) {
            list.retain(|a| *a != ip);
            if list.is_empty() {
                self.by_client.remove(key);
            }
        }
    }

    fn unindex_mac(&mut self, mac: [u8; 6], ip: Ipv4Addr) {
        if let Some(list) = self.by_mac.get_mut(&mac) {
            list.retain(|a| *a != ip);
            if list.is_empty() {
                self.by_mac.remove(&mac);
            }
        }
    }

    pub fn remove(&mut self, ip: Ipv4Addr) -> Option<Lease> {
        let l = self.by_addr.remove(&ip)?;
        self.unindex(&l.client_key(), ip);
        self.unindex_mac(l.mac, ip);
        if l.state.free() {
            self.free.remove(&(l.expires, u32::from(ip)));
        }
        Some(l)
    }

    pub fn get_mut_with(&mut self, ip: Ipv4Addr, f: impl FnOnce(&mut Lease)) -> Option<Lease> {
        let mut l = self.by_addr.get(&ip)?.clone();
        f(&mut l);
        self.put(l.clone());
        Some(l)
    }

    /// Apply journal lines: the last line of each address wins. Lines that
    /// do not parse are skipped and counted (a torn last line after a
    /// crash, a hostile file). Past [`MAX_RECORDS`] lines only the newest
    /// are read (the last line wins: the oldest are the ones to lose).
    pub fn replay<'a>(&mut self, lines: impl Iterator<Item = &'a str>) -> usize {
        self.replay_capped(lines, MAX_RECORDS)
    }

    pub(crate) fn replay_capped<'a>(
        &mut self,
        lines: impl Iterator<Item = &'a str>,
        cap: usize,
    ) -> usize {
        let mut bad = 0;
        for line in newest(lines, cap) {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            match serde_json::from_str::<Record>(line) {
                Ok(Record::Lease(l)) => self.put(l),
                Ok(Record::Forget { forget }) => {
                    self.remove(forget);
                }
                Err(_) => bad += 1,
            }
        }
        bad
    }

    /// The compacted journal: one line per record worth keeping at `now`
    /// (`keep_free_secs`: how long a free address remembers its client).
    pub fn compact(&self, now: u64, keep_free_secs: u64) -> String {
        let mut keep: Vec<&Lease> = self
            .by_addr
            .values()
            .filter(|l| l.state != State::Offered)
            .filter(|l| !l.state.free() || l.expires.saturating_add(keep_free_secs) > now)
            .collect();
        keep.sort_by_key(|l| u32::from(l.address));
        let mut out = String::with_capacity(keep.len() * 160);
        for l in keep {
            if let Ok(line) = serde_json::to_string(&Record::Lease(l.clone())) {
                out.push_str(&line);
                out.push('\n');
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lease(ip: [u8; 4], mac: u8, state: State) -> Lease {
        Lease {
            address: Ipv4Addr::from(ip),
            server: "dhcp1".into(),
            state,
            mac: [2, 0, 0, 0, 0, mac],
            client_id: None,
            host_name: "pc".into(),
            vendor_class: String::new(),
            expires: 1000,
            lease_time: 600,
            last_seen: 400,
            reason: String::new(),
            relay_info: None,
            hw: None,
        }
    }

    #[test]
    fn journal_lines_round_trip_and_the_last_wins() {
        let a = lease([10, 0, 0, 5], 1, State::Offered);
        let mut b = a.clone();
        b.state = State::Bound;
        b.client_id = Some(vec![1, 2, 0, 0, 0, 0, 1]);
        let lines = [
            serde_json::to_string(&Record::Lease(a)).unwrap(),
            "{torn".to_owned(),
            serde_json::to_string(&Record::Lease(b.clone())).unwrap(),
        ];
        let mut t = Leases::default();
        assert_eq!(t.replay(lines.iter().map(String::as_str)), 1);
        assert_eq!(t.get(b.address), Some(&b));
        assert_eq!(t.of_client(&b.client_key(), "dhcp1").count(), 1);
        let forget = serde_json::to_string(&Record::Forget { forget: b.address }).unwrap();
        t.replay([forget.as_str()].into_iter());
        assert!(t.is_empty());
        assert!(t.by_client.is_empty(), "index cleaned");
    }

    #[test]
    fn compaction_keeps_live_records() {
        let mut t = Leases::default();
        t.put(lease([10, 0, 0, 1], 1, State::Bound));
        t.put(lease([10, 0, 0, 2], 2, State::Offered));
        t.put(lease([10, 0, 0, 3], 3, State::Expired));
        let text = t.compact(1500, 100);
        assert_eq!(text.lines().count(), 1, "{text}");
        let text = t.compact(1500, 1000);
        assert_eq!(text.lines().count(), 2, "an expired one kept for affinity");
        let mut back = Leases::default();
        back.replay(text.lines());
        assert_eq!(back.len(), 2);
    }

    #[test]
    fn a_new_client_takes_over_the_index() {
        let mut t = Leases::default();
        t.put(lease([10, 0, 0, 1], 1, State::Expired));
        let mut other = lease([10, 0, 0, 1], 2, State::Bound);
        other.host_name = "other".into();
        t.put(other.clone());
        assert_eq!(
            t.of_client(&lease([0; 4], 1, State::Bound).client_key(), "dhcp1")
                .count(),
            0
        );
        assert_eq!(t.of_client(&other.client_key(), "dhcp1").count(), 1);
    }
}
