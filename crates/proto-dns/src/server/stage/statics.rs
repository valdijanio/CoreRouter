//! `/ip dns static` (RouterOS v7): the router answers these names itself.
//!
//! - Enabled entries are tried top to bottom, `regexp` entries before
//!   `name` entries (RouterOS). A name matches itself, and every name under
//!   it with `match_subdomain`; a regexp is searched in the lowercase name.
//! - The first matching entry that fits the query decides: one of the type
//!   asked (with the other entries of that type for the same name or
//!   regexp: two A entries are two addresses), or a CNAME (followed, through the static entries
//!   again, then the cache and upstream), NXDOMAIN, or FWD (the query goes
//!   to `forward_to`). A matching entry of another type does not answer:
//!   an AAAA query for a name with only an A entry goes upstream
//!   (RouterOS; dnsmasq does the same since 2.86).
//! - A PTR query for an address of an A/AAAA entry gets that entry's name
//!   (RouterOS adds these PTRs to the cache).
//! - `address_list`: the addresses answered for the entry go into that
//!   firewall address list for their TTL + `address_list_extra_time_secs`.

use std::collections::HashMap;
use std::net::IpAddr;

use corerouter_model::Config;
use corerouter_model::dns_static::{StaticEntry, StaticType};
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::rdata::{CNAME, MX, NS, PTR, SRV, TXT};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use regex::{Regex, RegexBuilder};

use crate::server::{Effect, Forwarder, Query, Reply, Stage, Step};
use crate::message::QName;
use crate::resolver::{Transport, Upstreams};

pub(crate) const STAGE: Stage = Stage {
    name: "static",
    order: 40,
    handle,
    after: Some(after),
};

/// Longest chain of static CNAMEs followed (BIND and Unbound stop near 8–16).
const MAX_CNAMES: usize = 8;
/// Compiled size of one regexp (the `regex` crate is linear-time; this
/// bounds its memory).
const REGEX_SIZE: usize = 1 << 20;

/// Compiles an entry's `regexp` (as the forwarder will match it).
pub fn compile(pattern: &str) -> Result<Regex, String> {
    RegexBuilder::new(pattern)
        .case_insensitive(true)
        .size_limit(REGEX_SIZE)
        .build()
        .map_err(|e| {
            let mut s = e.to_string();
            s.truncate(200);
            s
        })
}

/// The entries, ready to match.
#[derive(Default)]
pub(crate) struct Statics {
    regexps: Vec<(Regex, StaticEntry)>,
    names: Vec<StaticEntry>,
    /// Name → positions in `names` (a lookup is a few hash probes, not a
    /// scan of every entry).
    by_name: HashMap<String, Vec<usize>>,
    /// Address → (name, TTL) of the A/AAAA entries, for PTR.
    ptr: HashMap<IpAddr, (String, u32)>,
}

impl Statics {
    pub(crate) fn build(cfg: &Config) -> Self {
        let mut s = Self::default();
        for e in cfg.ip.dns_static.entries.iter().filter(|e| !e.disabled) {
            if e.regexp.is_empty() {
                let mut e = e.clone();
                e.name = e.name.trim_end_matches('.').to_ascii_lowercase();
                if let (StaticType::A | StaticType::Aaaa, Some(ip)) = (e.rtype, e.address) {
                    s.ptr.entry(ip).or_insert((e.name.clone(), e.ttl_secs));
                }
                s.by_name.entry(e.name.clone()).or_default().push(s.names.len());
                s.names.push(e);
            } else if let Ok(re) = compile(&e.regexp) {
                // Validation refuses a bad regexp before commit; one that
                // still fails (an older config) just never matches.
                s.regexps.push((re, e.clone()));
            }
        }
        s
    }

    /// Entries matching `key`, regexps first.
    fn matching<'a>(&'a self, key: &'a str) -> impl Iterator<Item = &'a StaticEntry> + 'a {
        let by_re = self
            .regexps
            .iter()
            .filter(move |(re, _)| re.is_match(key))
            .map(|(_, e)| e);
        // The name itself, then each parent (`a.b.lan` → `b.lan` → `lan`)
        // for entries with match_subdomain; in config order.
        let mut hits: Vec<usize> = self.by_name.get(key).cloned().unwrap_or_default();
        let mut rest = key;
        while let Some((_, parent)) = rest.split_once('.') {
            if let Some(list) = self.by_name.get(parent) {
                hits.extend(
                    list.iter()
                        .filter(|i| self.names.get(**i).is_some_and(|e| e.match_subdomain)),
                );
            }
            rest = parent;
        }
        hits.sort_unstable();
        by_re.chain(hits.into_iter().filter_map(|i| self.names.get(i)))
    }
}

/// Whether an enabled static FWD entry matches `key`: RouterOS (7.17)
/// takes it as an allowlist, the adlist leaves that name alone.
pub(crate) fn forwarded(f: &Forwarder, q: &Query, key: &str) -> bool {
    let statics = f.compiled(&q.config, Statics::build);
    statics.matching(key).any(|e| e.rtype == StaticType::Fwd)
}

fn record_type(t: StaticType) -> Option<RecordType> {
    Some(match t {
        StaticType::A => RecordType::A,
        StaticType::Aaaa => RecordType::AAAA,
        StaticType::Cname => RecordType::CNAME,
        StaticType::Mx => RecordType::MX,
        StaticType::Ns => RecordType::NS,
        StaticType::Srv => RecordType::SRV,
        StaticType::Txt => RecordType::TXT,
        StaticType::Fwd | StaticType::Nxdomain => return None,
    })
}

fn host(text: &str) -> Option<Name> {
    let mut n = Name::from_ascii(text).ok()?;
    n.set_fqdn(true);
    Some(n)
}

/// The record `e` answers for `owner`.
fn record(e: &StaticEntry, owner: &Name) -> Option<Record> {
    let data = match e.rtype {
        StaticType::A | StaticType::Aaaa => match e.address? {
            IpAddr::V4(v4) => RData::A(v4.into()),
            IpAddr::V6(v6) => RData::AAAA(v6.into()),
        },
        StaticType::Cname => RData::CNAME(CNAME(host(&e.cname)?)),
        StaticType::Mx => RData::MX(MX::new(e.mx_preference, host(&e.mx_exchange)?)),
        StaticType::Ns => RData::NS(NS(host(&e.ns)?)),
        StaticType::Srv => RData::SRV(SRV::new(
            e.srv_priority,
            e.srv_weight,
            e.srv_port,
            host(&e.srv_target)?,
        )),
        // RFC 1035 §3.3.14: character-strings of at most 255 bytes.
        StaticType::Txt => RData::TXT(TXT::new(chunks(&e.text))),
        StaticType::Fwd | StaticType::Nxdomain => return None,
    };
    Some(Record::from_rdata(owner.clone(), e.ttl_secs, data))
}

fn chunks(text: &str) -> Vec<String> {
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

fn handle(f: &Forwarder, q: &mut Query, _: Option<&mut dyn Transport>) -> Step {
    let statics = f.compiled(&q.config, Statics::build);
    if statics.names.is_empty() && statics.regexps.is_empty() {
        return Step::Next;
    }
    if q.qtype == RecordType::PTR
        && let Some(step) = ptr(&statics, q)
    {
        return step;
    }
    for _ in 0..MAX_CNAMES {
        let key = q.name.key.clone();
        let wanted = q.qtype;
        let Some(first) = statics.matching(&key).find(|e| {
            record_type(e.rtype) == Some(wanted)
                || matches!(e.rtype, StaticType::Cname | StaticType::Nxdomain | StaticType::Fwd)
        }) else {
            return Step::Next;
        };
        if !first.address_list.is_empty() {
            q.address_list = Some(first.address_list.clone());
        }
        if record_type(first.rtype) == Some(wanted) {
            let owner = q.name.name.clone();
            let mut r = Reply::code(ResponseCode::NoError);
            r.authoritative = true;
            r.answers = statics
                .matching(&key)
                .filter(|e| {
                    e.rtype == first.rtype && e.name == first.name && e.regexp == first.regexp
                })
                .filter_map(|e| record(e, &owner))
                .collect();
            return Step::Reply(r);
        }
        match first.rtype {
            StaticType::Nxdomain => {
                let mut r = Reply::code(ResponseCode::NXDomain);
                r.authoritative = true;
                return Step::Reply(r);
            }
            StaticType::Fwd => {
                // A group (G4.1d) that is gone or disabled: the usual
                // servers answer.
                q.forward_to = if first.forwarder.is_empty() {
                    Some(Upstreams::plain(first.forward_to.clone()))
                } else {
                    Upstreams::group(&q.config.config, &first.forwarder)
                };
                return Step::Next;
            }
            // A CNAME: answer it and go on with its target.
            _ => {
                let Some(rec) = record(first, &q.name.name) else {
                    return Step::Next;
                };
                let Some(target) = host(&first.cname) else {
                    return Step::Next;
                };
                q.prefix.push(rec);
                q.name = QName::from_name(&target);
            }
        }
    }
    // A loop of static CNAMEs.
    Step::Reply(Reply::code(ResponseCode::ServFail))
}

/// RFC 1035 §3.5 / RFC 3596 §2.5: `in-addr.arpa` and `ip6.arpa` names.
fn ptr(statics: &Statics, q: &Query) -> Option<Step> {
    let net = q.name.name.parse_arpa_name().ok()?;
    let full = match net.addr() {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if net.prefix_len() != full {
        return None;
    }
    let (name, ttl) = statics.ptr.get(&net.addr())?;
    let target = host(name)?;
    let mut r = Reply::code(ResponseCode::NoError);
    r.authoritative = true;
    r.answers = vec![Record::from_rdata(
        q.name.name.clone(),
        *ttl,
        RData::PTR(PTR(target)),
    )];
    Some(Step::Reply(r))
}

/// A matched entry's `address_list`: what was answered goes into it.
fn after(_: &Forwarder, q: &mut Query, r: &Reply) {
    let Some(list) = q.address_list.clone() else {
        return;
    };
    let extra = u64::from(q.config.config.ip.dns.address_list_extra_time_secs);
    let ttl = r
        .answers
        .iter()
        .filter(|rec| matches!(rec.record_type(), RecordType::A | RecordType::AAAA))
        .map(|rec| rec.ttl)
        .min()
        .unwrap_or(0);
    for address in r.addresses() {
        q.effects.push(Effect::AddressList {
            list: list.clone(),
            address,
            timeout_secs: u64::from(ttl) + extra,
        });
    }
}
