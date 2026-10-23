//! "Why this answer" (G6.8, `tool.dns.query explain`): what each stage of
//! the chain decided for one query — passed it on, answered, dropped it, or
//! was not reached because an earlier one answered — and the exact rule
//! (a static entry, an adlist line, a forwarders group, a zone).
//!
//! Only a query asked with `explain` keeps these notes ([`Query::note`]
//! does nothing otherwise): the LAN's queries pay one branch per stage.
//!
//! The text is English with `{name}` places ([`TEXTS`], keyed by id): the
//! terminal prints it; the GUI shows its own wording of the same id
//! (`crates/ui/src/i18n`).

use crate::server::Query;

/// What a stage did with the query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Looked and let it go on.
    Passed,
    Answered,
    /// No reply at all (a flood over UDP).
    Dropped,
    /// An earlier stage answered.
    NotReached,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Answered => "answered",
            Self::Dropped => "dropped",
            Self::NotReached => "not-reached",
        }
    }
}

/// The configuration item behind a decision (the GUI opens its window).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rule {
    /// `/ip dns static` entry.
    Static(u32),
    /// `/ip dns adlist` entry.
    Adlist(u32),
    /// `/ip dns forwarders` group.
    Forwarders(String),
    /// `/ip dns zone`.
    Zone(String),
}

/// One stage's decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub stage: &'static str,
    pub outcome: Outcome,
    /// Id of the text in [`TEXTS`].
    pub why: &'static str,
    pub args: Vec<(&'static str, String)>,
    pub rule: Option<Rule>,
}

impl Decision {
    /// The English text.
    pub fn text(&self) -> String {
        let template = text(self.why).unwrap_or(self.why);
        let mut out = template.to_owned();
        for (k, v) in &self.args {
            out = out.replace(&format!("{{{k}}}"), v);
        }
        out
    }
}

/// What a stage says about itself, before the chain knows the outcome.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Note {
    pub why: &'static str,
    pub args: Vec<(&'static str, String)>,
    pub rule: Option<Rule>,
}

impl Note {
    pub fn new(why: &'static str) -> Self {
        Self {
            why,
            ..Self::default()
        }
    }

    pub fn arg(mut self, k: &'static str, v: impl ToString) -> Self {
        self.args.push((k, v.to_string()));
        self
    }

    pub fn rule(mut self, r: Rule) -> Self {
        self.rule = Some(r);
        self
    }
}

/// Every text a stage can give, by id (sorted).
pub const TEXTS: &[(&str, &str)] = &[
    ("acl.allowed", "{client} is in allowed_from ({net})"),
    ("acl.loopback", "{client} is the router itself"),
    ("acl.refused", "{client} is not in allowed_from: REFUSED"),
    (
        "adlist.allowed",
        "listed in adlist {list} line {line} ({text}), but a static FWD entry lets it through",
    ),
    (
        "adlist.blocked",
        "blocked by adlist {list} line {line}: {text}",
    ),
    ("adlist.none", "on none of the loaded lists ({count})"),
    ("adlist.off", "no adlist loaded"),
    ("cache.hit", "in the cache, {ttl} s left"),
    ("cache.miss", "not in the cache"),
    (
        "limit.off",
        "no per-client limit (max_queries_per_client=0)",
    ),
    ("limit.over", "{client} is over {rate} queries/s: {action}"),
    ("limit.router", "the router itself is not limited"),
    ("limit.within", "{client} is within {rate} queries/s"),
    ("not-reached", "not reached: {stage} answered first"),
    ("special.any", "ANY gets one HINFO (RFC 8482 §4.2)"),
    ("special.invalid", "invalid. never exists (RFC 6761 §6.4)"),
    (
        "special.localhost",
        "localhost is the loopback (RFC 6761 §6.3)",
    ),
    ("special.none", "not a special-use name"),
    (
        "static.answered",
        "static entry {id} ({match}) answers {type}",
    ),
    (
        "static.cname",
        "static entry {id} ({match}) is a CNAME to {target}",
    ),
    (
        "static.fwd",
        "static entry {id} ({match}) sends it to {servers}",
    ),
    (
        "static.fwd-group",
        "static entry {id} ({match}) sends it to forwarders group {group}",
    ),
    (
        "static.fwd-group-gone",
        "static entry {id} ({match}) names forwarders group {group}, which is gone or disabled: the usual servers answer",
    ),
    ("static.none", "no static entry matches"),
    (
        "static.nxdomain",
        "static entry {id} ({match}) says NXDOMAIN",
    ),
    ("static.ptr", "PTR of static entry {id} ({name})"),
    ("upstream.cached", "answered from the cache while it waited"),
    ("upstream.failed", "every server failed: {why}"),
    (
        "upstream.held",
        "failed recently: not asked again for {secs} s (RFC 9520 §3.2)",
    ),
    ("upstream.server", "{server} answered{via}"),
    (
        "upstream.stale",
        "every server failed: served the expired answer (serve-stale, RFC 8767)",
    ),
    ("zones.answered", "zone {zone} answers with authority"),
    (
        "zones.delegated",
        "zone {zone} delegates it: asked of its glue {servers}",
    ),
    ("zones.none", "in none of the router's zones"),
    ("zones.not-loaded", "zone {zone} is not loaded: SERVFAIL"),
    (
        "zones.referral",
        "zone {zone} delegates it: a referral (no recursion asked)",
    ),
];

/// The English template of `id`.
pub fn text(id: &str) -> Option<&'static str> {
    TEXTS
        .binary_search_by(|(k, _)| (*k).cmp(id))
        .ok()
        .and_then(|i| TEXTS.get(i))
        .map(|(_, t)| *t)
}

/// What a static entry matched by: its name or its regexp.
pub fn matched_by(name: &str, regexp: &str) -> String {
    if regexp.is_empty() {
        format!("name={name}")
    } else {
        format!("regexp={}", regexp.chars().take(80).collect::<String>())
    }
}

impl Query {
    /// Whether this query keeps notes (asked with `explain`).
    pub fn explaining(&self) -> bool {
        self.explain.is_some()
    }

    /// The running stage says why it decided what it did (only when
    /// [`Self::explaining`]; `make` is not called otherwise).
    pub fn note(&mut self, make: impl FnOnce() -> Note) {
        if self.explain.is_some() {
            self.pending = Some(make());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn texts_are_sorted_and_unique() {
        for w in TEXTS.windows(2) {
            if let [(a, _), (b, _)] = w {
                assert!(a < b, "{a} before {b}");
            }
        }
        let d = Decision {
            stage: "cache",
            outcome: Outcome::Answered,
            why: "cache.hit",
            args: vec![("ttl", "42".into())],
            rule: None,
        };
        assert_eq!(d.text(), "in the cache, 42 s left");
    }

    use std::net::IpAddr;
    use std::sync::Arc;

    use corerouter_model::dns_forwarders::ForwarderEntry;
    use corerouter_model::dns_static::{StaticEntry, StaticType};
    use corerouter_model::types::ItemId;
    use hickory_proto::rr::RecordType;

    use crate::adlist::{Adlists, Loaded, parse};
    use crate::server::tests::{LAN, Up, ask, forwarder};
    use crate::server::{Done, Forwarder, How, Start};

    /// The chain with `explain`, as `from` (simulated when not the LAN
    /// test client).
    fn why(
        f: &Forwarder,
        up: &mut Up,
        from: [u8; 4],
        name: &str,
        t: RecordType,
        simulated: bool,
    ) -> Done {
        let how = How {
            explain: true,
            simulated,
        };
        match f.start_as(&ask(name, t), IpAddr::from(from), false, up.now, how) {
            Start::Done(d) => d,
            Start::Pending(p) => f.finish(*p, up),
        }
    }

    /// (stage, outcome, text) of each decision.
    fn lines(d: &Done) -> Vec<(&'static str, &'static str, String)> {
        d.explain
            .iter()
            .map(|x| (x.stage, x.outcome.as_str(), x.text()))
            .collect()
    }

    fn stage<'a>(d: &'a Done, name: &str) -> &'a Decision {
        d.explain.iter().find(|x| x.stage == name).unwrap()
    }

    #[test]
    fn upstream_then_cache_every_stage_says_why() {
        let f = forwarder(|_| {});
        let mut up = Up::new();
        let d = why(&f, &mut up, LAN, "www.example.com.", RecordType::A, false);
        assert_eq!(
            lines(&d),
            [
                (
                    "acl",
                    "passed",
                    "192.168.88.10 is in allowed_from (192.168.88.0/24)".to_owned()
                ),
                (
                    "limit",
                    "passed",
                    "192.168.88.10 is within 200 queries/s".to_owned()
                ),
                ("special", "passed", "not a special-use name".to_owned()),
                ("adlist", "passed", "no adlist loaded".to_owned()),
                ("static", "passed", "no static entry matches".to_owned()),
                (
                    "zones",
                    "passed",
                    "in none of the router's zones".to_owned()
                ),
                ("cache", "passed", "not in the cache".to_owned()),
                ("upstream", "answered", "198.51.100.53 answered".to_owned()),
            ],
            "statistics only counts: left out"
        );
        up.now += 10_000;
        let d = why(&f, &mut up, LAN, "www.example.com.", RecordType::A, false);
        assert_eq!(stage(&d, "cache").text(), "in the cache, 290 s left");
        assert_eq!(stage(&d, "cache").outcome, Outcome::Answered);
        assert_eq!(stage(&d, "upstream").outcome, Outcome::NotReached);
    }

    #[test]
    fn static_entries_name_the_rule() {
        let f = forwarder(|c| {
            let mut a = StaticEntry::new(ItemId(3));
            a.name = "nas.lan".into();
            a.rtype = StaticType::A;
            a.address = Some([192, 168, 88, 2].into());
            let mut re = StaticEntry::new(ItemId(4));
            re.regexp = "^blocked[0-9]+\\.example$".into();
            re.rtype = StaticType::Nxdomain;
            let mut fwd = StaticEntry::new(ItemId(5));
            fwd.name = "corp.example".into();
            fwd.match_subdomain = true;
            fwd.rtype = StaticType::Fwd;
            fwd.forwarder = "CORP".into();
            let mut g = ForwarderEntry::new(ItemId(1));
            g.name = "CORP".into();
            g.dns_servers = vec![[10, 9, 9, 9].into()];
            c.ip.dns_forwarders.entries.push(g);
            c.ip.dns_static.entries.extend([a, re, fwd]);
        });
        let mut up = Up::new();
        let d = why(&f, &mut up, LAN, "nas.lan.", RecordType::A, false);
        let s = stage(&d, "static");
        assert_eq!(s.text(), "static entry *3 (name=nas.lan) answers A");
        assert_eq!(
            (s.outcome, s.rule.clone()),
            (Outcome::Answered, Some(Rule::Static(3)))
        );
        assert!(
            d.explain
                .iter()
                .skip_while(|x| x.stage != "static")
                .skip(1)
                .all(|x| x.outcome == Outcome::NotReached)
        );
        let d = why(&f, &mut up, LAN, "blocked7.example.", RecordType::A, false);
        assert_eq!(
            stage(&d, "static").text(),
            "static entry *4 (regexp=^blocked[0-9]+\\.example$) says NXDOMAIN"
        );
        let d = why(&f, &mut up, LAN, "git.corp.example.", RecordType::A, false);
        assert_eq!(
            stage(&d, "static").text(),
            "static entry *5 (name=corp.example) sends it to forwarders group CORP"
        );
        assert_eq!(stage(&d, "static").outcome, Outcome::Passed);
        let u = stage(&d, "upstream");
        assert_eq!(
            u.text(),
            "10.9.9.9 answered (the servers a static entry or zone named)"
        );
        // PTR of the A entry.
        let d = why(
            &f,
            &mut up,
            LAN,
            "2.88.168.192.in-addr.arpa.",
            RecordType::PTR,
            false,
        );
        assert_eq!(stage(&d, "static").rule, Some(Rule::Static(3)));
    }

    #[test]
    fn adlist_gives_the_list_and_the_line() {
        let f = forwarder(|_| {});
        let list = Arc::new(Loaded::new(
            2,
            parse("# list\n0.0.0.0 ads.example\n||track.example^\n", 100),
        ));
        f.state::<Adlists>().set(vec![list.clone()]);
        let mut up = Up::new();
        let d = why(&f, &mut up, LAN, "x.track.example.", RecordType::A, false);
        let a = stage(&d, "adlist");
        assert_eq!(a.text(), "blocked by adlist *2 line 3: ||track.example^");
        assert_eq!(
            (a.outcome, a.rule.clone()),
            (Outcome::Answered, Some(Rule::Adlist(2)))
        );
        let d = why(&f, &mut up, LAN, "other.example.", RecordType::A, false);
        assert_eq!(
            stage(&d, "adlist").text(),
            "on none of the loaded lists (1)"
        );
        // A simulated client does not count as a hit.
        let before = list.hits.load(std::sync::atomic::Ordering::Relaxed);
        why(&f, &mut up, LAN, "ads.example.", RecordType::A, true);
        assert_eq!(list.hits.load(std::sync::atomic::Ordering::Relaxed), before);
    }

    #[test]
    fn special_names_and_the_router_itself() {
        let f = forwarder(|_| {});
        let mut up = Up::new();
        let d = why(
            &f,
            &mut up,
            [127, 0, 0, 1],
            "db.localhost.",
            RecordType::A,
            false,
        );
        assert_eq!(stage(&d, "acl").text(), "127.0.0.1 is the router itself");
        assert_eq!(
            stage(&d, "limit").text(),
            "the router itself is not limited"
        );
        assert_eq!(
            stage(&d, "special").text(),
            "localhost is the loopback (RFC 6761 §6.3)"
        );
        assert_eq!(stage(&d, "special").outcome, Outcome::Answered);
    }

    /// `as_client` outside allowed_from: REFUSED by the ACL, nothing after
    /// it ran, and the statistics never saw it.
    #[test]
    fn a_simulated_outsider_is_refused_and_not_counted() {
        let f = forwarder(|_| {});
        let mut up = Up::new();
        let d = why(
            &f,
            &mut up,
            [203, 0, 113, 9],
            "example.com.",
            RecordType::A,
            true,
        );
        assert_eq!(d.answered_by, "acl");
        let reply = hickory_proto::op::Message::from_vec(d.reply.as_ref().unwrap()).unwrap();
        assert_eq!(
            reply.metadata.response_code,
            hickory_proto::op::ResponseCode::Refused
        );
        assert_eq!(
            lines(&d)[0].2,
            "203.0.113.9 is not in allowed_from: REFUSED"
        );
        assert!(
            d.explain
                .iter()
                .skip(1)
                .all(|x| x.outcome == Outcome::NotReached)
        );
        assert!(up.asked.is_empty());
        let stats = f.state::<crate::server::Statistics>().snapshot(10);
        assert_eq!(
            stats.counters.queries, 0,
            "a simulated query is not counted"
        );
    }

    /// A client over its limit: the real queries emptied the bucket; the
    /// simulated one sees that without taking a token.
    #[test]
    fn the_limit_is_seen_not_spent() {
        let f = forwarder(|c| c.ip.dns.max_queries_per_client = 1);
        let mut up = Up::new();
        assert!(
            why(&f, &mut up, LAN, "a.example.", RecordType::A, true)
                .reply
                .is_some()
        );
        for _ in 0..2 {
            why(&f, &mut up, LAN, "a.example.", RecordType::A, false);
        }
        let d = why(&f, &mut up, LAN, "a.example.", RecordType::A, true);
        assert!(d.reply.is_none(), "dropped over UDP");
        let l = stage(&d, "limit");
        assert_eq!(l.outcome, Outcome::Dropped);
        assert_eq!(l.text(), "192.168.88.10 is over 1 queries/s: dropped (UDP)");
    }

    /// serve-stale (RFC 8767) and the failure hold (RFC 9520).
    #[test]
    fn stale_and_held_failures() {
        let f = forwarder(|_| {});
        let mut up = Up::new();
        why(&f, &mut up, LAN, "www.example.com.", RecordType::A, false);
        up.now += 301_000;
        up.down = true;
        let d = why(&f, &mut up, LAN, "www.example.com.", RecordType::A, false);
        assert_eq!(stage(&d, "upstream").why, "upstream.stale");
        let d = why(&f, &mut up, LAN, "other.example.", RecordType::A, false);
        assert_eq!(stage(&d, "upstream").why, "upstream.failed");
        let d = why(&f, &mut up, LAN, "other.example.", RecordType::A, false);
        let u = stage(&d, "upstream");
        assert_eq!(u.why, "upstream.held", "{}", u.text());
        assert!(u.text().contains("RFC 9520"), "{}", u.text());
    }

    /// Without `explain` nothing is kept (the LAN's queries).
    #[test]
    fn plain_queries_keep_no_notes() {
        let f = forwarder(|_| {});
        let mut up = Up::new();
        let d = match f.start(
            &ask("www.example.com.", RecordType::A),
            IpAddr::from(LAN),
            false,
            up.now,
        ) {
            Start::Done(d) => d,
            Start::Pending(p) => f.finish(*p, &mut up),
        };
        assert!(d.explain.is_empty());
    }
}
