//! DNSSEC for authoritative zones (G4.1c-2): signing (RFC 4033–4035, NSEC3
//! of RFC 5155 with the parameters of RFC 9276) and the proofs an answer
//! carries for a client that set DO.
//!
//! The cryptography is hickory-proto's (`dnssec-ring`: DNSKEY, RRSIG, DS,
//! the NSEC3 hash), behind this crate's `dnssec` feature, which only the
//! daemon turns on: the engine, the GUI and wasm builds never link ring.
//! Without it a zone is never signed here, and a transferred signed zone is
//! served as plain records. The chain, which RRsets get signed and which
//! records prove what are ours (hickory-server 0.26.3 signs delegation NS
//! and glue, which RFC 4035 §2.2 forbids).
//!
//! - Signed: every authoritative RRset, with the active ZSKs; the DNSKEY
//!   set with the active KSKs. Not signed: the NS of a delegation and
//!   anything below it (glue) (RFC 4035 §2.2).
//! - NSEC3 (RFC 5155 §7.1): one per authoritative owner and per empty
//!   non-terminal, SHA-1, 0 extra iterations, no salt, no opt-out (RFC
//!   9276 §3.1); TTL = min(SOA TTL, MINIMUM) (RFC 9077); NSEC3PARAM at the
//!   apex.
//! - RRSIG inception an hour in the past (clock skew, RFC 6781 §4.4.2),
//!   expiration `validity` later; the daemon re-signs at half of it.

use std::collections::HashMap;

use hickory_proto::rr::{Name, Record, RecordType};

use super::{Found, ZoneData};
use crate::message::key_of;

/// What an answer adds for DNSSEC: RRSIGs next to the answer, proofs in
/// the authority section.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Proof {
    pub answer: Vec<Record>,
    pub authority: Vec<Record>,
}

/// The signatures and the NSEC3 chain of a signed zone.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Signatures {
    /// RRSIGs by owner key and type covered.
    pub rrsigs: HashMap<(String, RecordType), Vec<Record>>,
    /// The NSEC3 chain, sorted by raw owner hash.
    pub nsec3: Vec<(Vec<u8>, Record)>,
    pub salt: Vec<u8>,
    pub iterations: u16,
    /// The earliest signature expiration (Unix time).
    pub expires: u32,
}

impl Signatures {
    pub fn sigs(&self, key: &str, t: RecordType) -> &[Record] {
        self.rrsigs
            .get(&(key.to_owned(), t))
            .map_or(&[], Vec::as_slice)
    }

    /// Every RRSIG and NSEC3 record (for AXFR and zone files).
    pub fn records(&self) -> impl Iterator<Item = &Record> {
        let mut keys: Vec<&(String, RecordType)> = self.rrsigs.keys().collect();
        keys.sort_by_key(|(k, t)| {
            (
                k.split('.').rev().map(str::to_owned).collect::<Vec<_>>(),
                u16::from(*t),
            )
        });
        let sigs = keys
            .into_iter()
            .filter_map(|k| self.rrsigs.get(k))
            .flatten();
        sigs.chain(self.nsec3.iter().map(|(_, r)| r))
    }

    /// The NSEC3 record whose owner hash is `h`, or the one covering it
    /// (owner < h < next, wrapping at the end of the chain).
    fn find(&self, h: &[u8]) -> Option<(bool, &Record)> {
        if self.nsec3.is_empty() {
            return None;
        }
        let i = self.nsec3.partition_point(|(x, _)| x.as_slice() <= h);
        let at = if i == 0 { self.nsec3.len() - 1 } else { i - 1 };
        let (x, r) = self.nsec3.get(at)?;
        Some((x.as_slice() == h, r))
    }
}

/// RFC 4648 §7 base32hex, lowercase, no padding: NSEC3 owner labels
/// (RFC 5155 §3.3, erratum 3544).
pub fn base32hex(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"0123456789abcdefghijklmnopqrstuv";
    let mut out = String::new();
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for b in bytes {
        acc = (acc << 8) | u32::from(*b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let i = usize::try_from((acc >> bits) & 31).unwrap_or(0);
            out.push(char::from(*ALPHABET.get(i).unwrap_or(&b'0')));
        }
    }
    if bits > 0 {
        let i = usize::try_from((acc << (5 - bits)) & 31).unwrap_or(0);
        out.push(char::from(*ALPHABET.get(i).unwrap_or(&b'0')));
    }
    out
}

/// The inverse of [`base32hex`]; `None` for anything else.
pub fn unbase32hex(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for c in text.bytes() {
        let v = match c.to_ascii_lowercase() {
            d @ b'0'..=b'9' => d - b'0',
            l @ b'a'..=b'v' => l - b'a' + 10,
            _ => return None,
        };
        acc = (acc << 5) | u32::from(v);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from((acc >> bits) & 0xff).ok()?);
        }
    }
    Some(out)
}

/// The names from `key` up to (not including) the zone apex.
fn ancestors<'a>(key: &'a str, apex: &'a str) -> impl Iterator<Item = &'a str> + 'a {
    let mut cur = Some(key);
    std::iter::from_fn(move || {
        let k = cur?;
        if k == apex || !super::within(k, apex) {
            return None;
        }
        cur = k.split_once('.').map(|(_, p)| p);
        Some(k)
    })
}

#[cfg(feature = "dnssec")]
mod sign;
#[cfg(feature = "dnssec")]
pub use sign::{GeneratedKey, generate, index, sign};

/// Without the `dnssec` feature: nothing is hashed, so only the RRSIGs.
#[cfg(not(feature = "dnssec"))]
fn hash(_: &Signatures, _: &Name) -> Option<Vec<u8>> {
    None
}

#[cfg(feature = "dnssec")]
fn hash(s: &Signatures, name: &Name) -> Option<Vec<u8>> {
    sign::hash(&s.salt, s.iterations, name)
}

fn name_of(key: &str) -> Option<Name> {
    super::fqdn(key)
}

impl ZoneData {
    /// The RRSIGs of `key`/`t` (none for an unsigned zone).
    pub fn sigs(&self, key: &str, t: RecordType) -> Vec<Record> {
        self.dnssec
            .as_ref()
            .map(|s| s.sigs(key, t).to_vec())
            .unwrap_or_default()
    }
}

/// Pushes `r` (and its RRSIGs) once.
fn add(out: &mut Vec<Record>, s: &Signatures, r: &Record) {
    if out.contains(r) {
        return;
    }
    out.push(r.clone());
    for sig in s.sigs(&key_of(&r.name), RecordType::NSEC3) {
        if !out.contains(sig) {
            out.push(sig.clone());
        }
    }
}

/// The NSEC3 matching `key` (RFC 5155 §7.2.3), if there is one.
fn matching<'a>(s: &'a Signatures, key: &str) -> Option<&'a Record> {
    let h = hash(s, &name_of(key)?)?;
    match s.find(&h)? {
        (true, r) => Some(r),
        _ => None,
    }
}

/// The NSEC3 covering `key` (RFC 5155 §7.2.1).
fn covering<'a>(s: &'a Signatures, key: &str) -> Option<&'a Record> {
    let h = hash(s, &name_of(key)?)?;
    match s.find(&h)? {
        (false, r) => Some(r),
        _ => None,
    }
}

/// RFC 5155 §7.2.1: the closest encloser (the longest ancestor with an
/// NSEC3) and the next closer name (one label longer).
fn closest_encloser<'a>(
    z: &'a ZoneData,
    s: &Signatures,
    key: &'a str,
) -> Option<(String, &'a str)> {
    let mut next = key;
    for k in ancestors(key, &z.key)
        .skip(1)
        .chain(std::iter::once(z.key.as_str()))
    {
        if k == z.key || matching(s, k).is_some() {
            return Some((k.to_owned(), next));
        }
        next = k;
    }
    None
}

/// What an answer from zone `z` adds for a client that set DO (RFC 4035
/// §3.1, RFC 5155 §7.2). `found` is what `z.lookup` gave for
/// `key`/`qtype`.
pub fn authenticate(z: &ZoneData, key: &str, qtype: RecordType, found: &Found) -> Proof {
    let mut p = Proof::default();
    let Some(s) = z.dnssec.as_deref() else {
        return p;
    };
    // An expanded wildcard: the query name has no records of its own.
    let wildcard = !z.has_owner(key);
    match found {
        Found::Answer { records, .. } => {
            let rtype = records.first().map_or(qtype, Record::record_type);
            if wildcard && key != z.key {
                // RFC 4035 §3.1.3.3 / RFC 5155 §7.2.6: the wildcard's
                // signatures, owner rewritten, and the NSEC3 covering the
                // next closer name (no closer match exists).
                if let Some((ce, next)) = closest_encloser(z, s, key) {
                    let owner = records.first().map(|r| r.name.clone());
                    for mut sig in s.sigs(&format!("*.{ce}"), rtype).iter().cloned() {
                        if let Some(o) = &owner {
                            sig.name = o.clone();
                        }
                        p.answer.push(sig);
                    }
                    if let Some(r) = covering(s, next) {
                        add(&mut p.authority, s, r);
                    }
                }
            } else {
                p.answer.extend(s.sigs(key, rtype).iter().cloned());
            }
        }
        Found::Cname { record, .. } => {
            let owner = key_of(&record.name);
            if wildcard {
                if let Some((ce, _)) = closest_encloser(z, s, key) {
                    for mut sig in s
                        .sigs(&format!("*.{ce}"), RecordType::CNAME)
                        .iter()
                        .cloned()
                    {
                        sig.name = record.name.clone();
                        p.answer.push(sig);
                    }
                }
            } else {
                p.answer
                    .extend(s.sigs(&owner, RecordType::CNAME).iter().cloned());
            }
        }
        Found::Referral { ns, .. } => {
            // RFC 5155 §7.2.7: no DS here (unsigned delegation): the NSEC3
            // matching the delegation point, without the DS bit.
            if let Some(cut) = ns.first().map(|r| key_of(&r.name))
                && let Some(r) = matching(s, &cut)
            {
                add(&mut p.authority, s, r);
            }
        }
        Found::NoData => {
            negative_soa(z, s, &mut p);
            match matching(s, key) {
                // RFC 5155 §7.2.3.
                Some(r) => add(&mut p.authority, s, r),
                // §7.2.5: a wildcard matched, without the type: the
                // closest encloser proof and the wildcard's NSEC3.
                None => {
                    if let Some((ce, next)) = closest_encloser(z, s, key) {
                        for r in [
                            matching(s, &ce),
                            covering(s, next),
                            matching(s, &format!("*.{ce}")),
                        ]
                        .into_iter()
                        .flatten()
                        {
                            add(&mut p.authority, s, r);
                        }
                    }
                }
            }
        }
        Found::NxDomain => {
            negative_soa(z, s, &mut p);
            // RFC 5155 §7.2.2: the closest encloser proof and the NSEC3
            // covering the wildcard at the closest encloser.
            if let Some((ce, next)) = closest_encloser(z, s, key) {
                for r in [
                    matching(s, &ce),
                    covering(s, next),
                    covering(s, &format!("*.{ce}")),
                ]
                .into_iter()
                .flatten()
                {
                    add(&mut p.authority, s, r);
                }
            }
        }
    }
    p
}

/// The SOA's RRSIGs, with the TTL the negative SOA goes out with.
fn negative_soa(z: &ZoneData, s: &Signatures, p: &mut Proof) {
    let ttl = z.negative_soa().ttl;
    for mut sig in s.sigs(&z.key, RecordType::SOA).iter().cloned() {
        sig.ttl = ttl;
        p.authority.push(sig);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32hex_round_trips() {
        // RFC 4648 §10 test vectors (lowercase, no padding).
        assert_eq!(base32hex(b""), "");
        assert_eq!(base32hex(b"f"), "co");
        assert_eq!(base32hex(b"foobar"), "cpnmuoj1e8");
        assert_eq!(unbase32hex("cpnmuoj1e8").unwrap(), b"foobar");
        assert_eq!(unbase32hex("CPNMUOJ1E8").unwrap(), b"foobar");
        assert!(unbase32hex("w!").is_none());
    }
}
