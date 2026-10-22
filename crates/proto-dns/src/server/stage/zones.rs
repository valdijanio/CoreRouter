//! Authoritative zones (G4.1c, `/ip dns zone`): a name inside one of our
//! zones is answered from it with AA, after the static entries and before
//! the cache. The lookup is `zone::ZoneData::lookup` (RFC 1034 §4.3.2):
//!
//! - records of the type asked, with the zone's addresses for NS/MX/SRV
//!   targets in the additional section;
//! - a CNAME: answered, and its target looked up again (in our zones, else
//!   on down the chain to the cache and upstream);
//! - NODATA and NXDOMAIN with the SOA in the authority section (RFC 2308
//!   §3);
//! - a delegation below the apex: a referral (no AA) for a query without
//!   RD; with RD the query goes to the delegation's glue addresses, like a
//!   static FWD entry (we forward, we do not iterate);
//! - a secondary not loaded (or expired): SERVFAIL.

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RData;

use crate::message::QName;
use crate::resolver::Transport;
use crate::server::{Forwarder, Query, Reply, Stage, Step};
use crate::zone::{self, Found};

pub(crate) const STAGE: Stage = Stage {
    name: "zones",
    order: 50,
    handle,
    after: None,
};

/// Longest chain of CNAMEs followed inside our zones (as the static stage).
const MAX_CNAMES: usize = 8;

fn handle(f: &Forwarder, q: &mut Query, _: Option<&mut dyn Transport>) -> Step {
    if q.config.config.ip.dns_zones.zones.is_empty() {
        return Step::Next;
    }
    for _ in 0..MAX_CNAMES {
        let Some(found) = zone::find(f, &q.config, &q.name.key) else {
            return Step::Next;
        };
        let Ok(z) = found else {
            return Step::Reply(Reply::code(ResponseCode::ServFail));
        };
        let mut r = Reply::code(ResponseCode::NoError);
        r.authoritative = true;
        match z.lookup(&q.name.name, &q.name.key, q.qtype) {
            Found::Answer {
                records,
                additional,
            } => {
                r.answers = records;
                r.additional = additional;
            }
            Found::Cname { record, target } => {
                q.prefix.push(*record);
                q.name = QName::from_name(&target);
                continue;
            }
            Found::Referral { ns, glue } => {
                let addrs: Vec<_> = glue
                    .iter()
                    .filter_map(|g| match &g.data {
                        RData::A(a) => Some(std::net::IpAddr::V4(a.0)),
                        RData::AAAA(a) => Some(std::net::IpAddr::V6(a.0)),
                        _ => None,
                    })
                    .collect();
                if q.recursion_desired() && !addrs.is_empty() {
                    q.forward_to = Some(crate::resolver::Upstreams::plain(addrs));
                    return Step::Next;
                }
                r.authoritative = false;
                r.authority = ns;
                r.additional = glue;
            }
            Found::NoData => r.authority = vec![z.negative_soa()],
            Found::NxDomain => {
                r.rcode = ResponseCode::NXDomain;
                r.authority = vec![z.negative_soa()];
            }
        }
        return Step::Reply(r);
    }
    // A loop of CNAMEs.
    Step::Reply(Reply::code(ResponseCode::ServFail))
}
