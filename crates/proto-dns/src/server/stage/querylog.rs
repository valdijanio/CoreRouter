//! The query log (G4.1zd, `ip.dns.log`): only an `after` hook, last in the
//! chain, that turns the query into a [`crate::querylog::Entry`] for the
//! daemon (which adds the time to answer and writes it to disk).
//!
//! Off by default; the check is one field of the running config, so a
//! router with the log off pays a branch per query. On, the entry moves
//! the asked name out of the query (no copy: nothing after this stage
//! reads it) and the filters of `ip.dns.log` apply here, before anything
//! is queued: `except_from`, `only_from` and `exclude` cost nothing
//! downstream.
//!
//! Simulated clients (DNS Lookup as a LAN client, G6.8) never reach
//! `after`, so they are not logged; neither are messages refused before
//! the chain (malformed, another opcode or class: the statistics count
//! them).

use crate::querylog::{Entry, by_code};
use crate::resolver::Transport;
use crate::server::{Forwarder, Query, Reply, Stage, Step};

pub(crate) const STAGE: Stage = Stage {
    name: "querylog",
    order: 110,
    handle,
    after: Some(after),
};

fn handle(_: &Forwarder, _: &mut Query, _: Option<&mut dyn Transport>) -> Step {
    Step::Next
}

fn after(_: &Forwarder, q: &mut Query, r: &Reply) {
    let cfg = &q.config.config.ip.dns_log;
    if !cfg.enabled {
        return;
    }
    let client = q.client;
    if cfg.except_from.iter().any(|n| n.contains(&client))
        || (!cfg.only_from.is_empty() && !cfg.only_from.iter().any(|n| n.contains(&client)))
        || cfg.excludes(&q.asked.key)
    {
        return;
    }
    let mut flags = 0;
    if q.tcp {
        flags |= crate::querylog::format::TCP;
    }
    if q.dropped() {
        flags |= crate::querylog::format::DROPPED;
    }
    if q.truncated() {
        flags |= crate::querylog::format::TRUNCATED;
    }
    let rcode = u8::try_from(u16::from(r.rcode) & 0x0f).unwrap_or(0);
    let category = super::statistics::category(q.answered_by, q.source.as_ref());
    // The extended error the reply stands for, as the statistics count it.
    let ede = q.ede.or(match category {
        "refused" => Some(super::statistics::EDE_PROHIBITED),
        "stale" => Some(super::statistics::EDE_STALE),
        "adlist" => Some(super::statistics::EDE_BLOCKED),
        _ => None,
    });
    q.log = Some(Box::new(Entry {
        at_ms: q.now_ms,
        client,
        name: std::mem::take(&mut q.asked.key),
        qtype: u16::from(q.qtype),
        // A drop sent nothing: no rcode (the flag says so).
        rcode: if q.dropped() { 0 } else { rcode },
        flags,
        by: by_code(category),
        ede,
    }));
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use hickory_proto::rr::RecordType;

    use crate::querylog::{BY, format};
    use crate::server::tests::{LAN, Up, ask, forwarder};
    use crate::server::{Forwarder, Start};

    fn done(f: &Forwarder, up: &mut Up, client: [u8; 4], name: &str) -> crate::server::Done {
        let q = ask(name, RecordType::AAAA);
        match f.start(&q, IpAddr::from(client), false, up.now) {
            Start::Done(d) => d,
            Start::Pending(p) => f.finish(*p, up),
        }
    }

    #[test]
    fn off_by_default_nothing_is_built() {
        let f = forwarder(|_| {});
        let mut up = Up::new();
        assert!(done(&f, &mut up, LAN, "www.example.com.").log.is_none());
    }

    #[test]
    fn on_every_answer_and_drop_has_an_entry() {
        let f = forwarder(|c| {
            c.ip.dns_log.enabled = true;
            c.ip.dns.max_queries_per_client = 1;
        });
        let mut up = Up::new();
        up.now = 7;
        let d = done(&f, &mut up, LAN, "WWW.Example.com.");
        let e = d.log.expect("logged");
        assert_eq!(e.name, "www.example.com");
        assert_eq!(e.qtype, 28);
        assert_eq!(e.client, IpAddr::from(LAN));
        assert_eq!(BY.get(usize::from(e.by)), Some(&"upstream"));
        assert_eq!(e.at_ms, 7);
        // Burst of 2, then dropped over UDP: still logged, flagged.
        let _ = done(&f, &mut up, LAN, "www.example.com.");
        let d = done(&f, &mut up, LAN, "www.example.com.");
        assert!(d.reply.is_none());
        let e = d.log.expect("a drop is logged");
        assert_eq!(e.flags & format::DROPPED, format::DROPPED);
        assert_eq!(BY.get(usize::from(e.by)), Some(&"limit"));
        // Outside allowed_from: refused, logged with the EDE.
        let d = done(&f, &mut up, [203, 0, 113, 9], "x.example.");
        let e = d.log.expect("refused is logged");
        assert_eq!((e.rcode, e.ede), (5, Some(18)));
    }

    #[test]
    fn filters_apply_before_anything_is_queued() {
        let f = forwarder(|c| {
            c.ip.dns_log.enabled = true;
            c.ip.dns_log.exclude = vec!["example.org".into()];
            c.ip.dns_log.except_from = vec!["192.0.2.0/24".parse().unwrap()];
        });
        let mut up = Up::new();
        assert!(done(&f, &mut up, LAN, "a.b.example.org.").log.is_none());
        assert!(done(&f, &mut up, LAN, "example.org.").log.is_none());
        assert!(done(&f, &mut up, LAN, "example.com.").log.is_some());
        assert!(done(&f, &mut up, [192, 0, 2, 7], "example.com.").log.is_none());
        let f = forwarder(|c| {
            c.ip.dns_log.enabled = true;
            c.ip.dns_log.only_from = vec!["198.51.100.0/24".parse().unwrap()];
        });
        assert!(done(&f, &mut up, LAN, "example.com.").log.is_none());
    }
}
