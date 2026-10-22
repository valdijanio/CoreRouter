//! Key generation and zone signing with hickory-proto's ring backend
//! (feature `dnssec`).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use base64::Engine as _;
use corerouter_model::dnssec::{DnssecAlgorithm, DnssecKey, KeyRole, KeyState};
use hickory_proto::dnssec::crypto::{EcdsaSigningKey, Ed25519SigningKey};
use hickory_proto::dnssec::rdata::{DNSKEY, DNSSECRData, DS, NSEC3, NSEC3PARAM, RRSIG, SigInput};
use hickory_proto::dnssec::{Algorithm, DigestType, Nsec3HashAlgorithm, SigningKey, TBS};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType, SerialNumber};
use rustls_pki_types::PrivatePkcs8KeyDer;

use super::{Signatures, ancestors, base32hex, unbase32hex};
use crate::message::key_of;
use crate::zone::{ZoneData, within};

/// RRSIG inception this far in the past (clock skew, RFC 6781 §4.4.2).
const SKEW_SECS: u32 = 3600;
/// RFC 9276 §3.1: no extra iterations, no salt.
const ITERATIONS: u16 = 0;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

fn alg(a: DnssecAlgorithm) -> Algorithm {
    match a {
        DnssecAlgorithm::EcdsaP256 => Algorithm::ECDSAP256SHA256,
        DnssecAlgorithm::Ed25519 => Algorithm::ED25519,
    }
}

fn err(e: impl std::fmt::Display) -> String {
    let mut s = e.to_string();
    s.truncate(200);
    s
}

/// The NSEC3 hash of `name` (RFC 5155 §5).
pub(super) fn hash(salt: &[u8], iterations: u16, name: &Name) -> Option<Vec<u8>> {
    Nsec3HashAlgorithm::SHA1
        .hash(salt, name, iterations)
        .ok()
        .map(|d| d.as_ref().to_vec())
}

/// A key just made, as `DnssecState` keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedKey {
    pub private_key: String,
    pub dnskey: String,
    pub ds: String,
    pub key_tag: u16,
}

fn signing_key(a: DnssecAlgorithm, pkcs8: Vec<u8>) -> Result<Box<dyn SigningKey>, String> {
    let der = PrivatePkcs8KeyDer::from(pkcs8);
    Ok(match a {
        DnssecAlgorithm::EcdsaP256 => {
            Box::new(EcdsaSigningKey::from_pkcs8(&der, alg(a)).map_err(err)?)
        }
        DnssecAlgorithm::Ed25519 => Box::new(Ed25519SigningKey::from_pkcs8(&der).map_err(err)?),
    })
}

fn dnskey_of(key: &dyn SigningKey, role: KeyRole) -> Result<DNSKEY, String> {
    let public = key.to_public_key().map_err(err)?;
    // RFC 4034 §2.1.1: zone key bit always; SEP for the KSK (flags 257).
    Ok(DNSKEY::new(true, role == KeyRole::Ksk, false, public))
}

/// A new key for `zone` (RFC 8624 algorithms only), with its DNSKEY and,
/// for a KSK, the SHA-256 DS for the parent (RFC 4509; SHA-1 is MUST NOT
/// since RFC 9905).
pub fn generate(zone: &str, a: DnssecAlgorithm, role: KeyRole) -> Result<GeneratedKey, String> {
    let pkcs8 = match a {
        DnssecAlgorithm::EcdsaP256 => EcdsaSigningKey::generate_pkcs8(alg(a)).map_err(err)?,
        DnssecAlgorithm::Ed25519 => Ed25519SigningKey::generate_pkcs8().map_err(err)?,
    };
    let bytes = pkcs8.secret_pkcs8_der().to_vec();
    let key = signing_key(a, bytes.clone())?;
    let dnskey = dnskey_of(key.as_ref(), role)?;
    let key_tag = dnskey.calculate_key_tag().map_err(err)?;
    let origin = crate::zone::fqdn(zone).ok_or("bad zone name")?;
    let ds = if role == KeyRole::Ksk {
        let digest = dnskey.to_digest(&origin, DigestType::SHA256).map_err(err)?;
        DS::new(
            key_tag,
            alg(a),
            DigestType::SHA256,
            digest.as_ref().to_vec(),
        )
        .to_string()
    } else {
        String::new()
    };
    Ok(GeneratedKey {
        private_key: B64.encode(&bytes),
        dnskey: dnskey.to_string(),
        ds,
        key_tag,
    })
}

struct Key {
    role: KeyRole,
    state: KeyState,
    dnskey: DNSKEY,
    tag: u16,
    signer: Box<dyn SigningKey>,
}

fn load(k: &DnssecKey) -> Result<Key, String> {
    let pkcs8 = B64
        .decode(k.private_key.as_bytes())
        .map_err(|_| format!("key {}: private key is not base64", k.id))?;
    let signer = signing_key(k.algorithm, pkcs8).map_err(|e| format!("key {}: {e}", k.id))?;
    let dnskey = dnskey_of(signer.as_ref(), k.role)?;
    let tag = dnskey.calculate_key_tag().map_err(err)?;
    Ok(Key {
        role: k.role,
        state: k.state,
        dnskey,
        tag,
        signer,
    })
}

struct Window {
    inception: u32,
    expiration: u32,
}

/// RFC 4034 §3: the RRSIG of one RRset (all with the same owner and type,
/// TTL already the same) by one key.
fn rrsig(
    owner: &Name,
    origin: &Name,
    rrset: &[Record],
    k: &Key,
    w: &Window,
) -> Result<Record, String> {
    let first = rrset.first().ok_or("an empty RRset")?;
    let input = SigInput {
        type_covered: first.record_type(),
        algorithm: k.signer.algorithm(),
        // RFC 4034 §3.1.3: the wildcard label does not count (RFC 6840
        // §6.3); `num_labels` leaves it out.
        num_labels: owner.num_labels(),
        original_ttl: first.ttl,
        sig_expiration: SerialNumber::new(w.expiration),
        sig_inception: SerialNumber::new(w.inception),
        key_tag: k.tag,
        signer_name: origin.clone(),
    };
    let tbs = TBS::from_input(owner, DNSClass::IN, &input, rrset.iter()).map_err(err)?;
    let sig = k.signer.sign(&tbs).map_err(err)?;
    Ok(Record::from_rdata(
        owner.clone(),
        first.ttl,
        RData::DNSSEC(DNSSECRData::RRSIG(RRSIG::from_sig(input, sig))),
    ))
}

/// `z` signed with the published/active keys of its zone in `keys`, at
/// `serial`, signatures valid from an hour before `now` for `validity`
/// seconds.
pub fn sign(
    z: &ZoneData,
    keys: &[DnssecKey],
    serial: u32,
    now: u32,
    validity: u32,
) -> Result<ZoneData, String> {
    let loaded = keys
        .iter()
        .filter(|k| k.zone == z.key)
        .map(load)
        .collect::<Result<Vec<Key>, String>>()?;
    let active = |role| -> Vec<&Key> {
        loaded
            .iter()
            .filter(|k| k.role == role && k.state == KeyState::Active)
            .collect()
    };
    let (mut ksks, mut zsks) = (active(KeyRole::Ksk), active(KeyRole::Zsk));
    if ksks.is_empty() && zsks.is_empty() {
        return Err(format!("zone {}: no active DNSSEC key", z.key));
    }
    // A single kind of key signs everything (a CSK, RFC 6781 §3.1).
    if ksks.is_empty() {
        ksks.clone_from(&zsks);
    }
    if zsks.is_empty() {
        zsks.clone_from(&ksks);
    }
    let w = Window {
        inception: now.saturating_sub(SKEW_SECS),
        expiration: now.saturating_add(validity),
    };
    let origin = z.origin.clone();
    let mut soa = z.soa.clone();
    if let RData::SOA(s) = &mut soa.data {
        s.serial = serial;
    }
    // RFC 9077: NSEC3 TTL = min(SOA TTL, MINIMUM).
    let nsec3_ttl = soa.ttl.min(z.minimum);
    let mut recs: Vec<Record> = z
        .records()
        .into_iter()
        .filter(|r| {
            !matches!(
                r.record_type(),
                RecordType::DNSKEY
                    | RecordType::NSEC3PARAM
                    | RecordType::RRSIG
                    | RecordType::NSEC3
                    | RecordType::NSEC
            )
        })
        .cloned()
        .collect();
    for k in &loaded {
        recs.push(Record::from_rdata(
            origin.clone(),
            soa.ttl,
            RData::DNSSEC(DNSSECRData::DNSKEY(k.dnskey.clone())),
        ));
    }
    recs.push(Record::from_rdata(
        origin.clone(),
        0,
        RData::DNSSEC(DNSSECRData::NSEC3PARAM(NSEC3PARAM::new(
            Nsec3HashAlgorithm::SHA1,
            false,
            ITERATIONS,
            Vec::new(),
        ))),
    ));
    let mut out = ZoneData::new(soa.clone(), recs)?;
    let cuts = out.cuts.clone();
    let below_cut = |k: &str| cuts.iter().any(|c| k != c && within(k, c));
    let mut rrsigs: HashMap<(String, RecordType), Vec<Record>> = HashMap::new();
    let soa_sigs = zsks
        .iter()
        .map(|k| rrsig(&origin, &origin, std::slice::from_ref(&soa), k, &w))
        .collect::<Result<Vec<_>, _>>()?;
    rrsigs.insert((out.key.clone(), RecordType::SOA), soa_sigs);
    // Owner → types it has, for the NSEC3 bitmaps.
    let mut types: BTreeMap<String, (BTreeSet<RecordType>, bool)> = BTreeMap::new();
    let owners: Vec<String> = out.sets.keys().cloned().collect();
    for owner in owners {
        if below_cut(&owner) {
            continue;
        }
        let at_cut = cuts.contains(&owner);
        let Some(set) = out.sets.get_mut(&owner) else {
            continue;
        };
        let name = set
            .first()
            .map(|r| r.name.clone())
            .ok_or("an empty owner")?;
        let mut by_type: BTreeMap<u16, Vec<usize>> = BTreeMap::new();
        for (i, r) in set.iter().enumerate() {
            by_type
                .entry(u16::from(r.record_type()))
                .or_default()
                .push(i);
        }
        let entry = types.entry(owner.clone()).or_default();
        for (t, idx) in by_type {
            let t = RecordType::from(t);
            entry.0.insert(t);
            // RFC 4035 §2.2: the NS of a delegation is not signed.
            if at_cut && t != RecordType::DS {
                continue;
            }
            // RFC 2181 §5.2: one TTL per RRset (the smallest).
            let ttl = idx
                .iter()
                .filter_map(|i| set.get(*i).map(|r| r.ttl))
                .min()
                .unwrap_or(0);
            let mut rrset: Vec<Record> = Vec::with_capacity(idx.len());
            for i in &idx {
                if let Some(r) = set.get_mut(*i) {
                    r.ttl = ttl;
                    rrset.push(r.clone());
                }
            }
            let signers = if t == RecordType::DNSKEY {
                &ksks
            } else {
                &zsks
            };
            let sigs = signers
                .iter()
                .map(|k| rrsig(&name, &origin, &rrset, k, &w))
                .collect::<Result<Vec<_>, _>>()?;
            entry.1 = true;
            rrsigs.insert((owner.clone(), t), sigs);
        }
    }
    if let Some(apex) = types.get_mut(&out.key) {
        apex.0.insert(RecordType::SOA);
        apex.1 = true;
    }
    // Empty non-terminals between an owner and the apex (RFC 5155 §7.1).
    let named: Vec<String> = types.keys().cloned().collect();
    for owner in named {
        for k in ancestors(&owner, &out.key).skip(1) {
            types.entry(k.to_owned()).or_default();
        }
    }
    let mut chain: Vec<(Vec<u8>, BTreeSet<RecordType>, bool)> = Vec::with_capacity(types.len());
    for (k, (ts, signed)) in types {
        let n = crate::zone::fqdn(&k).ok_or("bad owner name")?;
        let h = hash(&[], ITERATIONS, &n).ok_or("NSEC3 hash failed")?;
        chain.push((h, ts, signed));
    }
    chain.sort_by(|a, b| a.0.cmp(&b.0));
    let mut nsec3 = Vec::with_capacity(chain.len());
    for (i, (h, ts, signed)) in chain.iter().enumerate() {
        let next = chain
            .get((i + 1) % chain.len())
            .map(|c| c.0.clone())
            .unwrap_or_default();
        let bitmap: Vec<RecordType> = ts
            .iter()
            .copied()
            .chain(signed.then_some(RecordType::RRSIG))
            .collect();
        let owner = Name::from_ascii(format!("{}.{}.", base32hex(h), out.key)).map_err(err)?;
        let rec = Record::from_rdata(
            owner.clone(),
            nsec3_ttl,
            RData::DNSSEC(DNSSECRData::NSEC3(NSEC3::new(
                Nsec3HashAlgorithm::SHA1,
                false,
                ITERATIONS,
                Vec::new(),
                next,
                bitmap,
            ))),
        );
        let sigs = zsks
            .iter()
            .map(|k| rrsig(&owner, &origin, std::slice::from_ref(&rec), k, &w))
            .collect::<Result<Vec<_>, _>>()?;
        rrsigs.insert((key_of(&owner), RecordType::NSEC3), sigs);
        nsec3.push((h.clone(), rec));
    }
    out.dnssec = Some(Arc::new(Signatures {
        rrsigs,
        nsec3,
        salt: Vec::new(),
        iterations: ITERATIONS,
        expires: w.expiration,
    }));
    Ok(out)
}

/// A transferred zone with its signatures sorted out (a secondary of a
/// signed zone): RRSIG and NSEC3 records leave the data and go to the
/// lookup tables, so a DO query gets them like from a zone signed here.
pub fn index(z: ZoneData) -> Result<ZoneData, String> {
    let mut rrsigs: HashMap<(String, RecordType), Vec<Record>> = HashMap::new();
    let mut nsec3 = Vec::new();
    let mut rest = Vec::new();
    let mut expires = u32::MAX;
    let mut params: Option<(Vec<u8>, u16)> = None;
    for r in z.records().into_iter().cloned() {
        match &r.data {
            RData::DNSSEC(DNSSECRData::RRSIG(sig)) => {
                expires = expires.min(sig.input().sig_expiration.get());
                rrsigs
                    .entry((key_of(&r.name), sig.input().type_covered))
                    .or_default()
                    .push(r.clone());
            }
            RData::DNSSEC(DNSSECRData::NSEC3(_)) => {
                let label = r
                    .name
                    .iter()
                    .next()
                    .map(|l| String::from_utf8_lossy(l).into_owned());
                if let Some(h) = label.as_deref().and_then(unbase32hex) {
                    nsec3.push((h, r.clone()));
                }
            }
            RData::DNSSEC(DNSSECRData::NSEC3PARAM(p)) => {
                params = Some((p.salt().to_vec(), p.iterations()));
                rest.push(r.clone());
            }
            _ => rest.push(r.clone()),
        }
    }
    let Some((salt, iterations)) = params.or_else(|| (!rrsigs.is_empty()).then(|| (Vec::new(), 0)))
    else {
        return Ok(z);
    };
    let mut out = ZoneData::new(z.soa.clone(), rest)?;
    nsec3.sort_by(|a, b| a.0.cmp(&b.0));
    out.dnssec = Some(Arc::new(Signatures {
        rrsigs,
        nsec3,
        salt,
        iterations,
        expires,
    }));
    Ok(out)
}

#[cfg(test)]
mod tests;
