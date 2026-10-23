//! Adlist (G4.1d, `/ip dns adlist`): names on a loaded block list get
//! 0.0.0.0 (A) or :: (AAAA), and an empty answer for other types — the
//! RouterOS reply, and Pi-hole's default ("NULL"): the client fails at
//! once instead of retrying another server, as it would on NXDOMAIN from a
//! single resolver. The lists are loaded by the daemon
//! (`service/dns_adlist.rs`) into the [`Adlists`] state; a query never
//! waits on a download.
//!
//! A name with a static FWD entry is let through (RouterOS 7.17: that is
//! how an allowlist is written). The router's own lookups (NTP, the list
//! downloads) do not come through this chain and are never blocked.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::Ordering;

use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{RData, Record, RecordType};

use crate::adlist::Adlists;
use crate::resolver::Transport;
use crate::server::explain::{Note, Rule};
use crate::server::{Forwarder, Query, Reply, Stage, Step};

pub(crate) const STAGE: Stage = Stage {
    name: "adlist",
    order: 30,
    handle,
    after: None,
};

/// TTL of a blocked answer: short, so a name taken off a list works again
/// soon (AdGuard Home uses 10 s too).
pub const BLOCKED_TTL: u32 = 10;

fn handle(f: &Forwarder, q: &mut Query, _: Option<&mut dyn Transport>) -> Step {
    let lists = f.state::<Adlists>();
    let Some(list) = lists.find(&q.name.key) else {
        q.note(|| match lists.lists().len() {
            0 => Note::new("adlist.off"),
            n => Note::new("adlist.none").arg("count", n),
        });
        return Step::Next;
    };
    let key = q.name.key.clone();
    let line = |why| {
        let b = list.blocking(&key);
        let (line, text) = b.map_or((0, String::new()), |b| (b.line, b.text));
        Note::new(why)
            .arg("list", corerouter_model::types::ItemId(list.id))
            .arg("line", line)
            .arg("text", text)
            .rule(Rule::Adlist(list.id))
    };
    if super::statics::forwarded(f, q, &q.name.key) {
        q.note(|| line("adlist.allowed"));
        return Step::Next;
    }
    q.note(|| line("adlist.blocked"));
    // A simulated client asked nothing: the match-count stays.
    if !q.simulated() {
        list.hits.fetch_add(1, Ordering::Relaxed);
    }
    let owner = q.name.name.clone();
    let data = match q.qtype {
        RecordType::A => Some(RData::A(Ipv4Addr::UNSPECIFIED.into())),
        RecordType::AAAA => Some(RData::AAAA(Ipv6Addr::UNSPECIFIED.into())),
        _ => None,
    };
    let mut r = Reply::code(ResponseCode::NoError);
    r.answers = data
        .map(|d| Record::from_rdata(owner, BLOCKED_TTL, d))
        .into_iter()
        .collect();
    Step::Reply(r)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use corerouter_model::dns_static::{StaticEntry, StaticType};
    use corerouter_model::types::ItemId;
    use hickory_proto::op::ResponseCode;
    use hickory_proto::rr::RecordType;

    use crate::adlist::{Adlists, Loaded, parse};
    use crate::server::tests::{LAN, Up, ask, forwarder, run};

    #[test]
    fn listed_names_get_the_null_address() {
        let f = forwarder(|c| {
            let mut e = StaticEntry::new(ItemId(1));
            e.name = "ok.ads.example".into();
            e.rtype = StaticType::Fwd;
            e.forward_to = vec!["198.51.100.53".parse().unwrap()];
            c.ip.dns_static.entries.push(e);
        });
        let list = Arc::new(Loaded::new(
            7,
            parse("0.0.0.0 ads.example ok.ads.example\n||track.example^\n", 100),
        ));
        f.state::<Adlists>().set(vec![list.clone()]);
        let mut up = Up::new();
        let m = run(&f, &mut up, LAN, &ask("ads.example.", RecordType::A)).unwrap();
        assert_eq!(m.metadata.response_code, ResponseCode::NoError);
        assert_eq!(m.answers[0].data.to_string(), "0.0.0.0");
        assert_eq!(m.answers[0].ttl, super::BLOCKED_TTL);
        let m = run(&f, &mut up, LAN, &ask("ADS.example.", RecordType::AAAA)).unwrap();
        assert_eq!(m.answers[0].data.to_string(), "::");
        let m = run(&f, &mut up, LAN, &ask("ads.example.", RecordType::MX)).unwrap();
        assert!(m.answers.is_empty() && m.metadata.response_code == ResponseCode::NoError);
        let m = run(&f, &mut up, LAN, &ask("x.track.example.", RecordType::A)).unwrap();
        assert_eq!(m.answers[0].data.to_string(), "0.0.0.0", "||domain^ covers subdomains");
        assert!(up.asked.is_empty(), "nothing blocked went upstream");
        // Hosts lines are exact; a static FWD entry is an allowlist.
        let m = run(&f, &mut up, LAN, &ask("cdn.ads.example.", RecordType::A)).unwrap();
        assert_eq!(m.answers[0].data.to_string(), "192.0.2.1");
        let m = run(&f, &mut up, LAN, &ask("ok.ads.example.", RecordType::A)).unwrap();
        assert_eq!(m.answers[0].data.to_string(), "192.0.2.2");
        assert_eq!(list.hits.load(std::sync::atomic::Ordering::Relaxed), 4);
        // Unloaded: answered upstream again.
        f.state::<Adlists>().set(Vec::new());
        let m = run(&f, &mut up, LAN, &ask("ads.example.", RecordType::A)).unwrap();
        assert_eq!(m.answers[0].data.to_string(), "192.0.2.3");
    }
}
