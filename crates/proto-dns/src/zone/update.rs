//! RFC 2136 UPDATE (G4.1c-3), as messages: [`read`] checks one (zone,
//! TSIG of RFC 8945, who may, prerequisites, the update section) and turns
//! it into [`DynamicOp`]s; the daemon has the engine apply them (saved
//! before the answer, §3.5) and answers with [`answer`].
//!
//! - §3.1: the zone section is one SOA question of a primary zone of ours
//!   (else FORMERR / NOTAUTH).
//! - TSIG (RFC 8945 §5.2): key, then MAC, then time (300 s fudge, and never
//!   older than the last message of that key: §5.2.3); BADKEY and BADSIG
//!   answered unsigned, BADTIME signed, all with NOTAUTH. HMAC-SHA256/384/
//!   512 only (§6; MD5 and SHA-1 are refused as unknown keys).
//! - Who may (§3.3, RFC 3007): a key in the zone's `update_keys`, from
//!   `allow_update` if set; with no keys, unsigned from `allow_update`;
//!   neither: REFUSED (no update by default, as BIND, Knot and PowerDNS).
//! - Prerequisites (§2.4, §3.2) against what the zone serves now.
//! - The update section (§2.5, prescan §3.4.1): adds, RRset, name and
//!   record deletes; the SOA is ours (ignored; the serial moves by itself,
//!   §3.6).
//!
//! Hostile input: everything is checked before anything changes; at most
//! [`MAX_PER_UPDATE`] changes per message.

use std::collections::HashMap;
use std::net::IpAddr;

use corerouter_model::ItemId;
use corerouter_model::dns_dynamic::{DynamicOp, MAX_PER_UPDATE};
use corerouter_model::dns_zone::{RecordType as ZType, ZoneRecord, ZoneType, relative_name_ok};
use hickory_proto::op::{Message, OpCode, ResponseCode};
use hickory_proto::rr::{DNSClass, RData, Record, RecordType};

use super::{ZoneData, within};
use crate::message::key_of;
use crate::server::Forwarder;

/// RFC 8945 §10: 300 s is the recommended fudge.
pub const FUDGE_SECS: u64 = 300;

/// A checked UPDATE, ready for the engine.
pub struct Update {
    pub zone: String,
    pub ops: Vec<DynamicOp>,
    /// The TSIG key that signed it, if any.
    pub key: Option<String>,
    pub client: IpAddr,
    request: Message,
    #[cfg(feature = "dnssec")]
    signer: Option<(hickory_proto::rr::TSigner, Vec<u8>)>,
}

/// A bare reply to `m` (the zone section echoed, RFC 2136 §3.8).
fn bare(m: &Message, rcode: ResponseCode) -> Message {
    let mut r = Message::response(m.metadata.id, OpCode::Update);
    r.metadata.response_code = rcode;
    r.add_queries(m.queries.clone());
    r
}

fn bytes(m: &Message) -> Vec<u8> {
    m.to_vec().unwrap_or_default()
}

/// The reply for a checked update: `rcode`, signed when the request was.
pub fn answer(u: &Update, rcode: ResponseCode, now: u64) -> Vec<u8> {
    let r = bare(&u.request, rcode);
    #[cfg(feature = "dnssec")]
    if let Some((signer, mac)) = &u.signer {
        return sign::signed(&r, signer.clone(), mac.clone(), None, now);
    }
    let _ = now;
    bytes(&r)
}

/// The engine applied the update (NOERROR), or failed and applied nothing
/// (§3.4.2.7: SERVFAIL).
pub fn finish(u: &Update, applied: bool, now: u64) -> Vec<u8> {
    let rcode = if applied {
        ResponseCode::NoError
    } else {
        ResponseCode::ServFail
    };
    answer(u, rcode, now)
}

/// The record of an update in zone terms (names relative to `zone`).
fn zone_record(zone: &str, r: &Record) -> Result<ZoneRecord, ResponseCode> {
    let key = key_of(&r.name);
    let rel = relative(zone, &key)?;
    let mut z = ZoneRecord::new(ItemId(0), zone, &rel);
    z.ttl_secs = Some(r.ttl);
    let host = |n: &hickory_proto::rr::Name| key_of(n);
    match &r.data {
        RData::A(a) => {
            z.rtype = ZType::A;
            z.address = Some(IpAddr::V4(a.0));
        }
        RData::AAAA(a) => {
            z.rtype = ZType::Aaaa;
            z.address = Some(IpAddr::V6(a.0));
        }
        RData::CNAME(c) => {
            z.rtype = ZType::Cname;
            z.target = host(&c.0);
        }
        RData::NS(n) => {
            z.rtype = ZType::Ns;
            z.target = host(&n.0);
        }
        RData::PTR(p) => {
            z.rtype = ZType::Ptr;
            z.target = host(&p.0);
        }
        RData::MX(mx) => {
            z.rtype = ZType::Mx;
            z.priority = mx.preference;
            z.target = host(&mx.exchange);
        }
        RData::SRV(s) => {
            z.rtype = ZType::Srv;
            z.priority = s.priority;
            z.weight = s.weight;
            z.port = s.port;
            z.target = host(&s.target);
        }
        RData::TXT(t) => {
            z.rtype = ZType::Txt;
            let mut text = String::new();
            for part in t.txt_data.iter() {
                text.push_str(std::str::from_utf8(part).map_err(|_| ResponseCode::Refused)?);
            }
            z.text = text;
        }
        RData::CAA(c) => {
            z.rtype = ZType::Caa;
            z.caa_flags = c.flags();
            z.caa_tag = c.tag.to_ascii_lowercase();
            z.text = String::from_utf8(c.value.clone()).map_err(|_| ResponseCode::Refused)?;
        }
        // A type the zones do not hold (SSHFP, DHCID…): refused, not
        // stored half-way.
        _ => return Err(ResponseCode::Refused),
    }
    if z.problem().is_some() {
        return Err(ResponseCode::Refused);
    }
    Ok(z)
}

fn ztype(t: RecordType) -> Option<ZType> {
    Some(match t {
        RecordType::A => ZType::A,
        RecordType::AAAA => ZType::Aaaa,
        RecordType::CAA => ZType::Caa,
        RecordType::CNAME => ZType::Cname,
        RecordType::MX => ZType::Mx,
        RecordType::NS => ZType::Ns,
        RecordType::PTR => ZType::Ptr,
        RecordType::SRV => ZType::Srv,
        RecordType::TXT => ZType::Txt,
        _ => return None,
    })
}

/// `key` relative to `zone` (`@` its apex); outside it: NOTZONE (§3.2,
/// §3.4.1.3).
fn relative(zone: &str, key: &str) -> Result<String, ResponseCode> {
    if !within(key, zone) {
        return Err(ResponseCode::NotZone);
    }
    if key == zone {
        return Ok("@".into());
    }
    let rel = key
        .strip_suffix(zone)
        .and_then(|r| r.strip_suffix('.'))
        .ok_or(ResponseCode::NotZone)?;
    if relative_name_ok(rel) {
        Ok(rel.to_owned())
    } else {
        Err(ResponseCode::Refused)
    }
}

/// The RRset at `key` of type `t`, as rdata only (§2.4.2 compares values,
/// not TTLs).
fn rdatas(z: &ZoneData, key: &str, t: RecordType) -> Vec<RData> {
    let mut v: Vec<RData> = z.of_type(key, t).into_iter().map(|r| r.data).collect();
    v.sort_by_key(|d| format!("{d}"));
    v
}

/// §3.2: the prerequisite section against the zone as served.
fn prerequisites(z: &ZoneData, m: &Message) -> Result<(), ResponseCode> {
    let mut exact: HashMap<(String, RecordType), Vec<RData>> = HashMap::new();
    for r in &m.answers {
        if r.ttl != 0 {
            return Err(ResponseCode::FormErr);
        }
        let key = key_of(&r.name);
        if !within(&key, &z.key) {
            return Err(ResponseCode::NotZone);
        }
        let t = r.record_type();
        let empty = matches!(r.data, RData::Update0(_));
        match r.dns_class {
            DNSClass::ANY => {
                if !empty {
                    return Err(ResponseCode::FormErr);
                }
                if t == RecordType::ANY {
                    // §2.4.4: name is in use.
                    if !z.has_owner(&key) {
                        return Err(ResponseCode::NXDomain);
                    }
                } else if rdatas(z, &key, t).is_empty() && !(t == RecordType::SOA && key == z.key) {
                    // §2.4.1: RRset exists (value independent).
                    return Err(ResponseCode::NXRRSet);
                }
            }
            DNSClass::NONE => {
                if !empty {
                    return Err(ResponseCode::FormErr);
                }
                if t == RecordType::ANY {
                    // §2.4.5: name is not in use.
                    if z.has_owner(&key) {
                        return Err(ResponseCode::YXDomain);
                    }
                } else if !rdatas(z, &key, t).is_empty() || (t == RecordType::SOA && key == z.key) {
                    // §2.4.3: RRset does not exist.
                    return Err(ResponseCode::YXRRSet);
                }
            }
            DNSClass::IN => {
                // §2.4.2: RRset exists (value dependent), compared whole.
                exact.entry((key, t)).or_default().push(r.data.clone());
            }
            _ => return Err(ResponseCode::FormErr),
        }
    }
    for ((key, t), mut want) in exact {
        want.sort_by_key(|d| format!("{d}"));
        if rdatas(z, &key, t) != want {
            return Err(ResponseCode::NXRRSet);
        }
    }
    Ok(())
}

/// §3.4.1 prescan and §2.5: the update section as changes.
fn changes(zone: &str, m: &Message) -> Result<Vec<DynamicOp>, ResponseCode> {
    if m.authorities.len() > MAX_PER_UPDATE {
        return Err(ResponseCode::Refused);
    }
    let mut ops = Vec::with_capacity(m.authorities.len());
    for r in &m.authorities {
        let key = key_of(&r.name);
        let name = relative(zone, &key)?;
        let t = r.record_type();
        if matches!(t, RecordType::AXFR | RecordType::IXFR | RecordType::OPT) {
            return Err(ResponseCode::FormErr);
        }
        // §3.4.2.2/§3.6: the SOA is the server's (its serial moves itself).
        if t == RecordType::SOA {
            continue;
        }
        match r.dns_class {
            DNSClass::IN => {
                if t == RecordType::ANY {
                    return Err(ResponseCode::FormErr);
                }
                ops.push(DynamicOp::Add(zone_record(zone, r)?));
            }
            DNSClass::ANY => {
                if r.ttl != 0 || !matches!(r.data, RData::Update0(_)) {
                    return Err(ResponseCode::FormErr);
                }
                if t == RecordType::ANY {
                    ops.push(DynamicOp::DeleteName { name });
                } else if let Some(rtype) = ztype(t) {
                    ops.push(DynamicOp::DeleteRrset { name, rtype });
                }
            }
            DNSClass::NONE => {
                if r.ttl != 0 {
                    return Err(ResponseCode::FormErr);
                }
                let mut rec = zone_record(zone, r)?;
                rec.ttl_secs = None;
                ops.push(DynamicOp::DeleteRecord(rec));
            }
            _ => return Err(ResponseCode::FormErr),
        }
    }
    Ok(ops)
}

/// Checks an UPDATE from `client` at `now` (Unix time). `Err`: the reply
/// to send as is.
pub fn read(f: &Forwarder, packet: &[u8], client: IpAddr, now: u64) -> Result<Update, Vec<u8>> {
    let Ok(m) = Message::from_vec(packet) else {
        let id = u16::from_be_bytes([
            packet.first().copied().unwrap_or(0),
            packet.get(1).copied().unwrap_or(0),
        ]);
        return Err(bytes(&Message::error_msg(
            id,
            OpCode::Update,
            ResponseCode::FormErr,
        )));
    };
    // §3.1.1: one SOA question names the zone.
    let Some(q) = m
        .queries
        .first()
        .filter(|q| q.query_type() == RecordType::SOA)
    else {
        return Err(bytes(&bare(&m, ResponseCode::FormErr)));
    };
    if m.queries.len() != 1 || q.query_class() != DNSClass::IN {
        return Err(bytes(&bare(&m, ResponseCode::FormErr)));
    }
    let zone = key_of(q.name());
    let cfg = f.config();
    let zones = super::zones(f, &cfg);
    let Some(conf) = zones.conf.get(&zone).cloned() else {
        return Err(bytes(&bare(&m, ResponseCode::NotAuth)));
    };
    let client = client.to_canonical();
    // RFC 8945 §5.2: the signature first, before anything is believed.
    #[cfg(feature = "dnssec")]
    let signer = sign::verify(f, &m, packet, now, &cfg.config.ip.dns_tsig)?;
    #[cfg(feature = "dnssec")]
    let key = signer.as_ref().map(|(s, _)| key_of(s.signer_name()));
    #[cfg(not(feature = "dnssec"))]
    let key: Option<String> = match m.signature() {
        Some(_) => return Err(bytes(&bare(&m, ResponseCode::NotAuth))),
        None => None,
    };
    let from_ok =
        conf.allow_update.is_empty() || conf.allow_update.iter().any(|n| n.contains(&client));
    let allowed = match &key {
        Some(k) => conf.update_keys.contains(k) && from_ok,
        None => conf.update_keys.is_empty() && !conf.allow_update.is_empty() && from_ok,
    };
    let mut u = Update {
        zone: zone.clone(),
        ops: Vec::new(),
        key,
        client,
        request: m,
        #[cfg(feature = "dnssec")]
        signer,
    };
    // §3.3 / RFC 3007 §2: who may, before any prerequisite is looked at.
    if conf.ztype != ZoneType::Primary || !allowed {
        return Err(answer(&u, ResponseCode::Refused, now));
    }
    let Some(Ok(data)) = super::find(f, &cfg, &zone) else {
        return Err(answer(&u, ResponseCode::ServFail, now));
    };
    if let Err(rcode) = prerequisites(&data, &u.request) {
        return Err(answer(&u, rcode, now));
    }
    match changes(&zone, &u.request) {
        Ok(ops) => u.ops = ops,
        Err(rcode) => return Err(answer(&u, rcode, now)),
    }
    Ok(u)
}

#[cfg(feature = "dnssec")]
mod sign {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use corerouter_model::dns_tsig::{DnsTsig, TsigAlgorithm, base64_decode};
    use hickory_proto::op::{Message, ResponseCode};
    use hickory_proto::rr::rdata::tsig::{TsigAlgorithm as HAlg, TsigError};
    use hickory_proto::rr::{TSigResponseContext, TSigner};

    use super::{FUDGE_SECS, bare, bytes};
    use crate::message::key_of;
    use crate::server::Forwarder;

    /// RFC 8945 §5.2.3: the last Time Signed seen per key (a replayed
    /// message is older).
    #[derive(Default)]
    pub(super) struct Replay(Mutex<HashMap<String, u64>>);

    fn alg(a: TsigAlgorithm) -> HAlg {
        match a {
            TsigAlgorithm::HmacSha256 => HAlg::HmacSha256,
            TsigAlgorithm::HmacSha384 => HAlg::HmacSha384,
            TsigAlgorithm::HmacSha512 => HAlg::HmacSha512,
        }
    }

    /// `m` (the reply), signed for `signer` after the request MAC `mac`.
    pub(super) fn signed(
        m: &Message,
        signer: TSigner,
        mac: Vec<u8>,
        error: Option<TsigError>,
        now: u64,
    ) -> Vec<u8> {
        let raw = bytes(m);
        let ctx = TSigResponseContext::new(m.metadata.id, now, signer, mac, error);
        match ctx.sign(&raw) {
            Ok(tsig) => {
                let mut out = m.clone();
                out.set_signature(tsig);
                bytes(&out)
            }
            Err(_) => raw,
        }
    }

    /// The request's TSIG, checked: `Ok(None)` unsigned, `Ok(Some)` the
    /// signer and the request MAC, `Err` the reply (NOTAUTH + TSIG error).
    pub(super) fn verify(
        f: &Forwarder,
        m: &Message,
        packet: &[u8],
        now: u64,
        keys: &DnsTsig,
    ) -> Result<Option<(TSigner, Vec<u8>)>, Vec<u8>> {
        let Some(sig) = m.signature() else {
            return Ok(None);
        };
        let id = m.metadata.id;
        let name = key_of(&sig.name);
        let notauth = || bare(m, ResponseCode::NotAuth);
        let unknown = || {
            let r = notauth();
            let raw = bytes(&r);
            match TSigResponseContext::unknown_key(id, now, sig.name.clone()).sign(&raw) {
                Ok(t) => {
                    let mut out = r.clone();
                    out.set_signature(t);
                    bytes(&out)
                }
                Err(_) => raw,
            }
        };
        // §5.2.1: an unknown key, or another algorithm than the key's.
        let Some(k) = keys.get(&name) else {
            return Err(unknown());
        };
        if sig.data.algorithm != alg(k.algorithm) {
            return Err(unknown());
        }
        let Some(secret) = base64_decode(&k.secret) else {
            return Err(unknown());
        };
        let Ok(signer) = TSigner::new(
            secret,
            alg(k.algorithm),
            sig.name.clone(),
            u16::try_from(FUDGE_SECS).unwrap_or(300),
        ) else {
            return Err(unknown());
        };
        // §5.2.2: the MAC (hickory refuses truncated MACs).
        let (mac, time, window) = match signer.verify_message_byte(packet, None, true) {
            Ok(v) => v,
            Err(_) => {
                let r = notauth();
                let raw = bytes(&r);
                return Err(
                    match TSigResponseContext::bad_signature(id, now, signer).sign(&raw) {
                        Ok(t) => {
                            let mut out = r.clone();
                            out.set_signature(t);
                            bytes(&out)
                        }
                        Err(_) => raw,
                    },
                );
            }
        };
        // §5.2.3: the time, and never older than the last one of the key.
        let replay = f.state::<Replay>();
        let mut last = replay.0.lock().unwrap_or_else(|e| e.into_inner());
        let older = last.get(&name).is_some_and(|l| time < *l);
        if now < window.start || now > window.end || older {
            return Err(signed(
                &notauth(),
                signer,
                mac,
                Some(TsigError::BadTime),
                now,
            ));
        }
        last.insert(name, time);
        Ok(Some((signer, mac)))
    }
}

#[cfg(test)]
mod tests;
