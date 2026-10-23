//! Names that never go upstream: `localhost` is the loopback (RFC 6761
//! §6.3), `invalid` never exists (§6.4). And `ANY`, which RFC 8482 §4.2
//! lets a server answer with one synthesized HINFO instead of everything it
//! knows: a big ANY answer is the classic amplification query.

use std::net::{Ipv4Addr, Ipv6Addr};

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::rdata::{A, AAAA, HINFO};
use hickory_proto::rr::{RData, Record, RecordType};

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
