//! Names that never go upstream: `localhost` is the loopback (RFC 6761
//! §6.3), `invalid` never exists (§6.4), and `resolver.arpa` is the router's
//! own (RFC 9462 §6.1, §6.4, erratum 8278): `_dns.resolver.arpa` SVCB says
//! where its encrypted service is (DDR, G4.1zf), any other type there is
//! NODATA and any other name under it NXDOMAIN. And `ANY`, which RFC 8482
//! §4.2 lets a server answer with one synthesized HINFO instead of
//! everything it knows: a big ANY answer is the classic amplification
//! query.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::rdata::svcb::{Alpn, IpHint, SVCB, SvcParamKey, SvcParamValue};
use hickory_proto::rr::rdata::{A, AAAA, HINFO};
use hickory_proto::rr::{Name, RData, Record, RecordType};

use crate::resolver::Transport;
use crate::server::explain::Note;
use crate::server::{Forwarder, Query, Reply, Stage, Step};

pub(crate) const STAGE: Stage = Stage {
    name: "special",
    order: 25,
    handle,
    after: None,
};

/// RFC 8482 §4.2: the TTL of the synthesized HINFO ("SHOULD be ... 3600").
const ANY_TTL: u32 = 3600;
const LOCAL_TTL: u32 = 86_400;

fn handle(_: &Forwarder, q: &mut Query, _: Option<&mut dyn Transport>) -> Step {
    let k = q.name.key.as_str();
    let owner = q.name.name.clone();
    let k = k.to_owned();
    let k = k.as_str();
    if k == "localhost" || k.ends_with(".localhost") {
        q.note(|| Note::new("special.localhost"));
        let data = match q.qtype {
            RecordType::A => Some(RData::A(A(Ipv4Addr::LOCALHOST))),
            RecordType::AAAA => Some(RData::AAAA(AAAA(Ipv6Addr::LOCALHOST))),
            _ => None,
        };
        let mut r = Reply::code(ResponseCode::NoError);
        r.authoritative = true;
        r.answers = data
            .map(|d| Record::from_rdata(owner, LOCAL_TTL, d))
            .into_iter()
            .collect();
        return Step::Reply(r);
    }
    if k == "invalid" || k.ends_with(".invalid") {
        q.note(|| Note::new("special.invalid"));
        let mut r = Reply::code(ResponseCode::NXDomain);
        r.authoritative = true;
        return Step::Reply(r);
    }
    if k == "resolver.arpa" || k.ends_with(".resolver.arpa") {
        return resolver_arpa(q, owner);
    }
    if q.qtype == RecordType::ANY {
        q.note(|| Note::new("special.any"));
        let mut r = Reply::code(ResponseCode::NoError);
        r.answers = vec![Record::from_rdata(
            owner,
            ANY_TTL,
            RData::HINFO(HINFO::new("RFC8482".into(), String::new())),
        )];
        return Step::Reply(r);
    }
    q.note(|| Note::new("special.none"));
    Step::Next
}

/// RFC 9462 §4: the SVCB TTL of the designation (a client asks again after
/// it; §4.2 suppresses a failed one for as long).
const DDR_TTL: u32 = 300;

/// `resolver.arpa` is answered here, never forwarded (RFC 9462 §6.1, §6.4).
fn resolver_arpa(q: &mut Query, owner: Name) -> Step {
    let k = q.name.key.clone();
    let mut r = Reply::code(ResponseCode::NoError);
    r.authoritative = true;
    // Erratum 8278 (verified): any other name under it does not exist.
    if k != "resolver.arpa" && k != "_dns.resolver.arpa" {
        q.note(|| Note::new("special.resolver-arpa"));
        r.rcode = ResponseCode::NXDomain;
        return Step::Reply(r);
    }
    if k == "_dns.resolver.arpa" && q.qtype == RecordType::SVCB {
        let (answers, additional) = designations(q, &owner);
        q.note(|| Note::new(if answers.is_empty() { "special.ddr-none" } else { "special.ddr" }));
        r.answers = answers;
        r.additional = additional;
    } else {
        q.note(|| Note::new("special.resolver-arpa"));
    }
    // No designation, or another type: NODATA (§4, §6.4).
    Step::Reply(r)
}

/// The router's encrypted services as SVCB ServiceMode records (RFC 9462 §4,
/// RFC 9461): `alpn` always, `port` only off the default (it is mandatory
/// for the client, §4.2), the router's addresses on the networks that may
/// ask as hints and in the additional section (§4: the client then needs no
/// other query; opportunistic discovery, §4.3, takes only the address it
/// asked). Keys in ascending order (RFC 9460 §2.2). The target is the
/// router's identity as a name, the one `/certificate` puts in the SAN of
/// the certificate it makes.
fn designations(q: &Query, owner: &Name) -> (Vec<Record>, Vec<Record>) {
    let cfg = &q.config.config;
    let e = &cfg.ip.dns.encrypted_service;
    if !(e.dot && e.announce_ddr && cfg.ip.dns.allow_remote_requests) {
        return (Vec::new(), Vec::new());
    }
    let host: String = cfg
        .system
        .identity
        .trim()
        .to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' { c } else { '-' })
        .collect();
    let host = host.trim_matches(|c| c == '-' || c == '.');
    let Ok(target) = Name::from_ascii(if host.is_empty() { "router" } else { host }).map(|n| {
        let mut n = n;
        n.set_fqdn(true);
        n
    }) else {
        return (Vec::new(), Vec::new());
    };
    let mine: Vec<IpAddr> = cfg
        .ip
        .addresses
        .iter()
        .filter(|a| !a.disabled && q.config.allowed.iter().any(|n| n.contains(&a.address.addr())))
        .map(|a| a.address.addr())
        .collect();
    let v4: Vec<A> = mine.iter().filter_map(|a| match a { IpAddr::V4(v) => Some(A(*v)), IpAddr::V6(_) => None }).collect();
    let v6: Vec<AAAA> = mine.iter().filter_map(|a| match a { IpAddr::V6(v) => Some(AAAA(*v)), IpAddr::V4(_) => None }).collect();
    let mut params = vec![(SvcParamKey::Alpn, SvcParamValue::Alpn(Alpn(vec!["dot".to_owned()])))];
    if e.dot_port != corerouter_model::dns_encrypted::DEFAULT_DOT_PORT {
        params.push((SvcParamKey::Port, SvcParamValue::Port(e.dot_port)));
    }
    if !v4.is_empty() {
        params.push((SvcParamKey::Ipv4Hint, SvcParamValue::Ipv4Hint(IpHint(v4.clone()))));
    }
    if !v6.is_empty() {
        params.push((SvcParamKey::Ipv6Hint, SvcParamValue::Ipv6Hint(IpHint(v6.clone()))));
    }
    let svcb = SVCB::new(1, target.clone(), params);
    let answers = vec![Record::from_rdata(owner.clone(), DDR_TTL, RData::SVCB(svcb))];
    let additional = v4
        .into_iter()
        .map(RData::A)
        .chain(v6.into_iter().map(RData::AAAA))
        .map(|d| Record::from_rdata(target.clone(), DDR_TTL, d))
        .collect();
    (answers, additional)
}
