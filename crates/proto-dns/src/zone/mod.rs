//! Authoritative zones (G4.1c): `/ip dns zone` compiled into answers.
//!
//! - [`ZoneData`]: one zone ready to answer (its SOA and records by owner),
//!   built from the config (a primary) or from a transfer (a secondary).
//! - [`ZoneData::lookup`]: RFC 1034 §4.3.2 inside one zone: a delegation on
//!   the way down gives a referral, an exact name its records (or a CNAME,
//!   or NODATA), a missing one a wildcard (RFC 4592) or NXDOMAIN; empty
//!   non-terminals exist (NODATA, never NXDOMAIN).
//! - [`Runtime`]: the forwarder's zone state (a stage state, see
//!   `server::Forwarder::state`): the primaries compiled from the running
//!   config, the secondaries' transferred copies, and a journal of changes
//!   for IXFR (RFC 1995).
//!
//! The `zones` stage of the chain answers from here; transfers and NOTIFY
//! are in [`xfr`], zone files in [`file`]. Pure data and messages: the
//! daemon brings the sockets (`service/dns_zones.rs`).

pub mod file;
pub mod xfr;

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, RwLock};

use corerouter_model::Config;
use corerouter_model::dns_zone::{RecordType as ZType, Zone, ZoneRecord, ZoneType};
use hickory_proto::rr::rdata::{A, AAAA, CNAME, MX, NS, PTR, SOA, SRV, TXT};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecoder, BinEncodable, Restrict};
use ipnet::IpNet;

use crate::message::key_of;
use crate::server::{Forwarder, ServerConfig};

/// Changes kept per zone for IXFR. BIND keeps up to twice the zone size;
/// past either bound the oldest go (RFC 1995 §5: a client too far behind
/// gets the whole zone).
const JOURNAL_DIFFS: usize = 64;
const JOURNAL_MIN_RECORDS: usize = 1000;
/// Records of one transferred zone (a secondary). Like the config limit of
/// all primaries together: bigger zones belong in a dedicated server.
pub const MAX_ZONE_RECORDS: usize = 100_000;

/// A fully qualified name from text (a model name: checked already).
pub(crate) fn fqdn(text: &str) -> Option<Name> {
    let mut n = Name::from_ascii(text).ok()?;
    n.set_fqdn(true);
    Some(n)
}

/// `key`'s parent (`a.b.c` → `b.c`), `None` at the top.
fn parent(key: &str) -> Option<&str> {
    key.split_once('.').map(|(_, p)| p)
}

/// `key` is `zone` or a name under it.
pub(crate) fn within(key: &str, zone: &str) -> bool {
    key == zone
        || (key.len() > zone.len()
            && key.ends_with(zone)
            && key.as_bytes().get(key.len() - zone.len() - 1) == Some(&b'.'))
}

/// RFC 1035 §3.3.14: character-strings of at most 255 bytes (cut on a
/// character boundary).
pub(crate) fn chunks(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for c in text.chars() {
        if cur.len() + c.len_utf8() > 255 {
            out.push(std::mem::take(&mut cur));
        }
        cur.push(c);
    }
    out.push(cur);
    out
}

/// CAA rdata (RFC 8659 §4.1) from flags, tag and value: built as wire bytes
/// and decoded, since hickory's `CAA` has no constructor for any tag.
pub(crate) fn caa(flags: u8, tag: &str, value: &str) -> Option<RData> {
    let mut bytes = vec![flags, u8::try_from(tag.len()).ok()?];
    bytes.extend_from_slice(tag.as_bytes());
    bytes.extend_from_slice(value.as_bytes());
    let len = u16::try_from(bytes.len()).ok()?;
    let mut d = BinDecoder::new(&bytes);
    RData::read(&mut d, RecordType::CAA, Restrict::new(len)).ok()
}

/// The record `r` of zone `z` stands for.
pub fn record_of(z: &Zone, r: &ZoneRecord) -> Option<Record> {
    let owner = fqdn(&z.owner(&r.name))?;
    let data = match r.rtype {
        ZType::A | ZType::Aaaa => match r.address? {
            IpAddr::V4(v4) => RData::A(A(v4)),
            IpAddr::V6(v6) => RData::AAAA(AAAA(v6)),
        },
        ZType::Cname => RData::CNAME(CNAME(fqdn(&r.target)?)),
        ZType::Ns => RData::NS(NS(fqdn(&r.target)?)),
        ZType::Ptr => RData::PTR(PTR(fqdn(&r.target)?)),
        ZType::Mx => RData::MX(MX::new(r.priority, fqdn(&r.target)?)),
        ZType::Srv => RData::SRV(SRV::new(r.priority, r.weight, r.port, fqdn(&r.target)?)),
        ZType::Txt => RData::TXT(TXT::new(chunks(&r.text))),
        ZType::Caa => caa(r.caa_flags, &r.caa_tag, &r.text)?,
    };
    Some(Record::from_rdata(
        owner,
        r.ttl_secs.unwrap_or(z.ttl_secs),
        data,
    ))
}

/// The SOA record of primary zone `z`.
pub fn soa_of(z: &Zone) -> Option<Record> {
    let soa = SOA::new(
        fqdn(&z.mname())?,
        fqdn(&z.rname())?,
        z.serial,
        i32::try_from(z.refresh_secs).ok()?,
        i32::try_from(z.retry_secs).ok()?,
        i32::try_from(z.expire_secs).ok()?,
        z.minimum_secs,
    );
    Some(Record::from_rdata(
        fqdn(&z.name)?,
        z.ttl_secs,
        RData::SOA(soa),
    ))
}

/// What a lookup inside one zone found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Found {
    /// Records of the type asked, and the addresses of the names they point
    /// to inside the zone (RFC 1034 §4.3.2 step 6: additional section).
    Answer {
        records: Vec<Record>,
        additional: Vec<Record>,
    },
    /// An alias: answer it and go on with the target (step 3a).
    Cname { record: Box<Record>, target: Name },
    /// A delegation on the way down (step 3b): the child's NS set and the
    /// glue addresses this zone has for them.
    Referral { ns: Vec<Record>, glue: Vec<Record> },
    /// The name exists, without records of this type (RFC 2308 §2.2).
    NoData,
    /// RFC 2308 §2.1.
    NxDomain,
}

/// One zone, ready to answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneData {
    pub origin: Name,
    /// The origin as a lookup key (lowercase, no final dot).
    pub key: String,
    pub soa: Record,
    pub serial: u32,
    /// SOA MINIMUM: the negative TTL cap (RFC 2308 §4).
    pub minimum: u32,
    /// Owner key → its records (the SOA aside).
    sets: HashMap<String, Vec<Record>>,
    /// Every owner and every name between an owner and the origin (empty
    /// non-terminals exist: RFC 4592 §2.2.2).
    names: HashSet<String>,
    /// Delegations: owners of NS records below the apex.
    cuts: HashSet<String>,
    count: usize,
}

impl ZoneData {
    /// A zone from its SOA (owner = origin) and its other records. Records
    /// outside the zone, of another class, or a second SOA are refused.
    pub fn new(soa: Record, records: Vec<Record>) -> Result<Self, String> {
        let RData::SOA(s) = &soa.data else {
            return Err("the zone has no SOA".into());
        };
        let serial = s.serial;
        let minimum = s.minimum;
        let origin = soa.name.clone();
        let key = key_of(&origin);
        let mut z = Self {
            origin,
            key,
            soa,
            serial,
            minimum,
            sets: HashMap::new(),
            names: HashSet::new(),
            cuts: HashSet::new(),
            count: 0,
        };
        z.names.insert(z.key.clone());
        if records.len() > MAX_ZONE_RECORDS {
            return Err(format!("more than {MAX_ZONE_RECORDS} records"));
        }
        for r in records {
            z.insert(r)?;
        }
        // One order per owner, whatever order the records came in (a
        // transfer, the config), so equal zones compare equal.
        for v in z.sets.values_mut() {
            v.sort_by_cached_key(|r| {
                (u16::from(r.record_type()), r.to_bytes().unwrap_or_default())
            });
        }
        Ok(z)
    }

    /// A zone from all its records, SOA included (a transfer, a file).
    pub fn from_records(records: Vec<Record>) -> Result<Self, String> {
        let mut soa = None;
        let mut rest = Vec::with_capacity(records.len());
        for r in records {
            if r.record_type() == RecordType::SOA {
                if soa.is_some() {
                    return Err("two SOA records".into());
                }
                soa = Some(r);
            } else {
                rest.push(r);
            }
        }
        let soa = soa.ok_or("the zone has no SOA")?;
        Self::new(soa, rest)
    }

    fn insert(&mut self, r: Record) -> Result<(), String> {
        let owner = key_of(&r.name);
        if !within(&owner, &self.key) {
            let shown: String = owner.chars().take(64).collect();
            return Err(format!("{shown} is outside the zone {}", self.key));
        }
        if r.dns_class != DNSClass::IN {
            return Err(format!("{owner}: only class IN"));
        }
        if r.record_type() == RecordType::SOA {
            return Err(format!("{owner}: a second SOA"));
        }
        if r.record_type() == RecordType::NS && owner != self.key {
            self.cuts.insert(owner.clone());
        }
        let mut k = owner.as_str();
        while self.names.insert(k.to_owned()) && k != self.key {
            match parent(k) {
                Some(p) => k = p,
                None => break,
            }
        }
        self.sets.entry(owner).or_default().push(r);
        self.count += 1;
        Ok(())
    }

    /// Records besides the SOA.
    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Every record besides the SOA, the apex first, then by owner.
    pub fn records(&self) -> Vec<&Record> {
        let mut owners: Vec<&String> = self.sets.keys().collect();
        owners.sort_by_key(|k| {
            (
                k.as_str() != self.key,
                k.split('.').rev().collect::<Vec<_>>(),
            )
        });
        owners
            .into_iter()
            .filter_map(|k| self.sets.get(k))
            .flatten()
            .collect()
    }

    /// The SOA's refresh, retry and expire, in seconds (negative values,
    /// which RFC 1035 never meant, count as 0).
    pub fn timers(&self) -> (u32, u32, u32) {
        match &self.soa.data {
            RData::SOA(s) => (
                u32::try_from(s.refresh).unwrap_or(0),
                u32::try_from(s.retry).unwrap_or(0),
                u32::try_from(s.expire).unwrap_or(0),
            ),
            _ => (0, 0, 0),
        }
    }

    /// The SOA as it goes in a negative answer: TTL = min(TTL, MINIMUM)
    /// (RFC 2308 §3).
    pub fn negative_soa(&self) -> Record {
        let mut s = self.soa.clone();
        s.ttl = s.ttl.min(self.minimum);
        s
    }

    fn of_type(&self, key: &str, t: RecordType) -> Vec<Record> {
        self.sets
            .get(key)
            .map(|v| v.iter().filter(|r| r.record_type() == t).cloned().collect())
            .unwrap_or_default()
    }

    /// The A and AAAA this zone has for `target` (additional data, glue).
    fn addresses(&self, target: &Name) -> Vec<Record> {
        let k = key_of(target);
        if !within(&k, &self.key) {
            return Vec::new();
        }
        let mut out = self.of_type(&k, RecordType::A);
        out.extend(self.of_type(&k, RecordType::AAAA));
        out
    }

    fn additional(&self, records: &[Record]) -> Vec<Record> {
        let mut out: Vec<Record> = Vec::new();
        for r in records {
            let target = match &r.data {
                RData::NS(NS(n)) => n,
                RData::MX(mx) => &mx.exchange,
                RData::SRV(srv) => &srv.target,
                _ => continue,
            };
            for a in self.addresses(target) {
                if !out.contains(&a) {
                    out.push(a);
                }
            }
        }
        out
    }

    /// The records at `key` for `qtype`; `owner`: the name to answer with
    /// (the query name, for a wildcard: RFC 4592 §3.3.3).
    fn at(&self, key: &str, owner: Option<&Name>, qtype: RecordType) -> Found {
        let rename = |mut r: Record| {
            if let Some(o) = owner {
                r.name = o.clone();
            }
            r
        };
        let hits: Vec<Record> = self.of_type(key, qtype).into_iter().map(rename).collect();
        if !hits.is_empty() {
            let additional = self.additional(&hits);
            return Found::Answer {
                records: hits,
                additional,
            };
        }
        if qtype != RecordType::CNAME
            && let Some(c) = self.of_type(key, RecordType::CNAME).into_iter().next()
            && let RData::CNAME(CNAME(target)) = &c.data
        {
            let target = target.clone();
            return Found::Cname {
                record: Box::new(rename(c)),
                target,
            };
        }
        Found::NoData
    }

    /// RFC 1034 §4.3.2, steps 3a–3c, inside this zone. `key` is
    /// `key_of(qname)` and lies within the zone.
    pub fn lookup(&self, qname: &Name, key: &str, qtype: RecordType) -> Found {
        // The names from just below the apex down to the query name.
        let mut path: Vec<&str> = Vec::new();
        let mut k = key;
        while k != self.key {
            path.push(k);
            match parent(k) {
                Some(p) => k = p,
                None => return Found::NxDomain,
            }
        }
        // Step 3b: a delegation on the way (DS lives on the parent side
        // of its cut, RFC 4035 §3.1.4.1).
        for cut in path.iter().rev() {
            if self.cuts.contains(*cut) && !(*cut == key && qtype == RecordType::DS) {
                let ns = self.of_type(cut, RecordType::NS);
                let glue = self.additional(&ns);
                return Found::Referral { ns, glue };
            }
        }
        if key == self.key && qtype == RecordType::SOA {
            return Found::Answer {
                records: vec![self.soa.clone()],
                additional: Vec::new(),
            };
        }
        if self.sets.contains_key(key) {
            return self.at(key, None, qtype);
        }
        if self.names.contains(key) {
            // An empty non-terminal: it exists (RFC 4592 §2.2.2, RFC 8020).
            return Found::NoData;
        }
        // Step 3c: the closest encloser's wildcard (RFC 4592 §3.3.1).
        let mut ce = key;
        while !self.names.contains(ce) {
            match parent(ce) {
                Some(p) => ce = p,
                None => return Found::NxDomain,
            }
        }
        let wild = format!("*.{ce}");
        if self.sets.contains_key(&wild) {
            return self.at(&wild, Some(qname), qtype);
        }
        Found::NxDomain
    }

    /// A zone file of this zone (RFC 1035 §5).
    pub fn to_file(&self) -> String {
        file::export(self)
    }
}

/// Primary zone `z` from the config: its SOA and enabled records. Without
/// an NS at the apex, the SOA's MNAME stands in (a zone always has one,
/// RFC 1034 §4.2.1).
pub fn primary(z: &Zone, records: &[&ZoneRecord]) -> Option<ZoneData> {
    let soa = soa_of(z)?;
    let mut recs: Vec<Record> = records
        .iter()
        .filter(|r| !r.disabled)
        .filter_map(|r| record_of(z, r))
        .collect();
    let apex_ns = records
        .iter()
        .any(|r| !r.disabled && r.name == "@" && r.rtype == ZType::Ns);
    if !apex_ns {
        recs.push(Record::from_rdata(
            soa.name.clone(),
            z.ttl_secs,
            RData::NS(NS(fqdn(&z.mname())?)),
        ));
    }
    ZoneData::new(soa, recs).ok()
}

/// What the zone config says beyond the data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZoneConf {
    pub name: String,
    pub ztype: ZoneType,
    pub allow_transfer: Vec<IpNet>,
    pub notify: Vec<IpAddr>,
    pub primaries: Vec<IpAddr>,
    pub refresh_secs: u32,
    pub retry_secs: u32,
    pub expire_secs: u32,
}

impl ZoneConf {
    fn of(z: &Zone) -> Self {
        Self {
            name: z.name.clone(),
            ztype: z.ztype,
            allow_transfer: z.allow_transfer.clone(),
            notify: z.notify.clone(),
            primaries: z.primaries.clone(),
            refresh_secs: z.refresh_secs,
            retry_secs: z.retry_secs,
            expire_secs: z.expire_secs,
        }
    }

    /// RFC 5936 §5: transfers only to the listed networks (none by default).
    pub fn may_transfer(&self, client: IpAddr) -> bool {
        let c = client.to_canonical();
        self.allow_transfer.iter().any(|n| n.contains(&c))
    }
}

/// The enabled zones of one config.
#[derive(Debug, Default)]
pub struct Zones {
    pub primaries: HashMap<String, Arc<ZoneData>>,
    pub conf: HashMap<String, ZoneConf>,
}

impl Zones {
    pub fn build(cfg: &Config) -> Self {
        let mut out = Self::default();
        let dz = &cfg.ip.dns_zones;
        for z in dz.zones.iter().filter(|z| !z.disabled) {
            out.conf.insert(z.name.clone(), ZoneConf::of(z));
            if z.ztype == ZoneType::Primary {
                let recs: Vec<&ZoneRecord> = dz.records_of(&z.name).collect();
                if let Some(data) = primary(z, &recs) {
                    out.primaries.insert(z.name.clone(), Arc::new(data));
                }
            }
        }
        out
    }

    /// The zone `key` falls in: the closest enclosing one.
    pub fn zone_for<'a>(&'a self, key: &'a str) -> Option<&'a ZoneConf> {
        let mut k = key;
        loop {
            if let Some(c) = self.conf.get(k) {
                return Some(c);
            }
            k = parent(k)?;
        }
    }
}

/// One change of a zone, for IXFR (RFC 1995 §4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diff {
    pub from: Record,
    pub to: Record,
    pub removed: Vec<Record>,
    pub added: Vec<Record>,
}

impl Diff {
    fn size(&self) -> usize {
        self.removed.len() + self.added.len() + 2
    }
}

fn serial_of(soa: &Record) -> u32 {
    match &soa.data {
        RData::SOA(s) => s.serial,
        _ => 0,
    }
}

/// What changed from `old` to `new` (records compared byte for byte, TTL
/// included: a new TTL is a removal and an addition).
pub fn diff(old: &ZoneData, new: &ZoneData) -> Diff {
    let wire = |r: &Record| r.to_bytes().unwrap_or_default();
    let before: HashSet<Vec<u8>> = old.records().into_iter().map(wire).collect();
    let after: HashSet<Vec<u8>> = new.records().into_iter().map(wire).collect();
    Diff {
        from: old.soa.clone(),
        to: new.soa.clone(),
        removed: old
            .records()
            .into_iter()
            .filter(|r| !after.contains(&wire(r)))
            .cloned()
            .collect(),
        added: new
            .records()
            .into_iter()
            .filter(|r| !before.contains(&wire(r)))
            .cloned()
            .collect(),
    }
}

/// A primary whose serial changed: its secondaries are told (NOTIFY).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Changed {
    pub zone: String,
    pub serial: u32,
    pub notify: Vec<IpAddr>,
    pub soa: Record,
}

/// The zone state of a [`Forwarder`] (`f.state::<Runtime>()`).
#[derive(Default)]
pub struct Runtime {
    /// The zones of the config generation they were built from.
    current: RwLock<Option<(u64, Arc<Zones>)>>,
    secondaries: RwLock<HashMap<String, Arc<ZoneData>>>,
    journal: Mutex<HashMap<String, VecDeque<Diff>>>,
    changed: Mutex<Vec<Changed>>,
    /// Secondaries a NOTIFY asked to refresh now.
    notified: Mutex<HashSet<String>>,
}

impl Runtime {
    fn record(&self, zone: &str, d: Diff, zone_size: usize) {
        if !crate::zone::serial_moved(&d) {
            return;
        }
        let mut j = self.journal.lock().unwrap_or_else(|e| e.into_inner());
        let q = j.entry(zone.to_owned()).or_default();
        q.push_back(d);
        let max = (2 * zone_size).max(JOURNAL_MIN_RECORDS);
        while q.len() > JOURNAL_DIFFS || q.iter().map(Diff::size).sum::<usize>() > max {
            q.pop_front();
        }
    }

    /// The changes from serial `from` up to the zone's current one, in
    /// order; `None` when the journal does not reach back that far.
    pub fn changes_since(&self, zone: &ZoneData, from: u32) -> Option<Vec<Diff>> {
        let j = self.journal.lock().unwrap_or_else(|e| e.into_inner());
        let q = j.get(&zone.key)?;
        let start = q.iter().position(|d| serial_of(&d.from) == from)?;
        let mut out = Vec::new();
        let mut at = from;
        for d in q.iter().skip(start) {
            if serial_of(&d.from) != at {
                return None;
            }
            at = serial_of(&d.to);
            out.push(d.clone());
        }
        (at == zone.serial).then_some(out)
    }
}

fn serial_moved(d: &Diff) -> bool {
    serial_of(&d.from) != serial_of(&d.to)
}

fn runtime(f: &Forwarder) -> Arc<Runtime> {
    f.state::<Runtime>()
}

/// The zones of `cfg`, rebuilt when the config changed; a rebuild records
/// what changed in each primary (journal, NOTIFY).
pub fn zones(f: &Forwarder, cfg: &ServerConfig) -> Arc<Zones> {
    let rt = runtime(f);
    if let Some((generation, z)) = rt
        .current
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        && *generation == cfg.generation
    {
        return z.clone();
    }
    let mut cur = rt.current.write().unwrap_or_else(|e| e.into_inner());
    if let Some((generation, z)) = cur.as_ref()
        && *generation == cfg.generation
    {
        return z.clone();
    }
    let new = Arc::new(Zones::build(&cfg.config));
    let old = cur.as_ref().map(|(_, z)| z.clone());
    for (name, data) in &new.primaries {
        let prev = old.as_ref().and_then(|o| o.primaries.get(name));
        if prev.is_some_and(|p| p.serial == data.serial && **p == **data) {
            continue;
        }
        if let Some(p) = prev {
            rt.record(name, diff(p, data), data.len());
        }
        if let Some(c) = new.conf.get(name)
            && prev.is_none_or(|p| p.serial != data.serial)
        {
            rt.changed
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(Changed {
                    zone: name.clone(),
                    serial: data.serial,
                    notify: c.notify.clone(),
                    soa: data.soa.clone(),
                });
        }
    }
    *cur = Some((cfg.generation, new.clone()));
    new
}

/// Brings the zones up to the forwarder's config and returns the primaries
/// whose serial moved since the last call (the daemon sends NOTIFY).
pub fn reload(f: &Forwarder) -> Vec<Changed> {
    zones(f, &f.config());
    std::mem::take(&mut *runtime(f).changed.lock().unwrap_or_else(|e| e.into_inner()))
}

/// The zone answering for `key`: `Some(Ok)` a loaded zone, `Some(Err)` a
/// secondary of ours not loaded (yet, or expired: SERVFAIL), `None` not
/// ours.
pub fn find(f: &Forwarder, cfg: &ServerConfig, key: &str) -> Option<Result<Arc<ZoneData>, String>> {
    let zs = zones(f, cfg);
    let conf = zs.zone_for(key)?;
    match conf.ztype {
        ZoneType::Primary => zs.primaries.get(&conf.name).cloned().map(Ok),
        ZoneType::Secondary => Some(
            secondary(f, &conf.name).ok_or_else(|| format!("zone {} is not loaded", conf.name)),
        ),
    }
}

/// A secondary's transferred copy.
pub fn secondary(f: &Forwarder, zone: &str) -> Option<Arc<ZoneData>> {
    runtime(f)
        .secondaries
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .get(zone)
        .cloned()
}

/// A secondary got a new copy (the old one goes to the journal as a diff,
/// so this server can feed IXFR to others too).
pub fn set_secondary(f: &Forwarder, zone: &str, data: ZoneData) {
    let rt = runtime(f);
    let mut map = rt.secondaries.write().unwrap_or_else(|e| e.into_inner());
    if let Some(old) = map.get(zone) {
        rt.record(zone, diff(old, &data), data.len());
    }
    map.insert(zone.to_owned(), Arc::new(data));
}

/// A secondary expired or left the config: it stops answering.
pub fn drop_secondary(f: &Forwarder, zone: &str) {
    let rt = runtime(f);
    rt.secondaries
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .remove(zone);
    rt.journal
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(zone);
}

/// A NOTIFY for secondary `zone` arrived from one of its primaries.
pub fn mark_notified(f: &Forwarder, zone: &str) {
    runtime(f)
        .notified
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(zone.to_owned());
}

/// The secondaries a NOTIFY asked to refresh since the last call.
pub fn take_notified(f: &Forwarder) -> HashSet<String> {
    std::mem::take(
        &mut *runtime(f)
            .notified
            .lock()
            .unwrap_or_else(|e| e.into_inner()),
    )
}

/// The journal of a zone, for IXFR.
pub fn changes_since(f: &Forwarder, zone: &ZoneData, from: u32) -> Option<Vec<Diff>> {
    runtime(f).changes_since(zone, from)
}

/// Problems hickory finds in the zones of `cfg` that the model cannot
/// (names it cannot parse).
pub fn validate(cfg: &Config) -> Vec<corerouter_model::Issue> {
    let mut out = Vec::new();
    if let Some(p) = cfg.ip.dns_zones.problem() {
        out.push(corerouter_model::Issue::new("ip.dns.zone", p));
        return out;
    }
    let dz = &cfg.ip.dns_zones;
    for z in dz.zones.iter().filter(|z| z.ztype == ZoneType::Primary) {
        if soa_of(z).is_none() {
            out.push(corerouter_model::Issue::new(
                "ip.dns.zone",
                format!("zone {}: the SOA cannot be built", z.name),
            ));
        }
        for r in dz.records_of(&z.name) {
            if record_of(z, r).is_none() {
                out.push(corerouter_model::Issue::new(
                    "ip.dns.zone",
                    format!("record {} of {}: cannot be built", r.id, z.name),
                ));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests;
