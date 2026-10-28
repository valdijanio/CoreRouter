//! L2 — OSPFv2/OSPFv3 (G3.4).
//!
//! Validates `routing.ospf` (`corerouter_model::ospf`) and renders it for
//! the FRR daemons `ospfd` and `ospf6d` ([`frr`]); `hal-frr` diffs the
//! render against what they run and types only the difference. FRR runs
//! the protocol and the SPF; what is ours is the config model, which
//! interfaces each template takes ([`bind`]), the checks, and reading the
//! daemons' state back.
//!
//! Contract shared by every `proto-*` crate: `validate` inspects the
//! candidate and returns issues; the engine refuses to commit while any exist.

pub mod bind;
pub mod chain;
pub mod diagnose;
pub mod frr;
pub mod impact;
pub mod layout;
pub mod packet;
pub mod pools;
pub mod sample;
pub mod topology;

use std::collections::{BTreeSet, HashMap, HashSet};

use corerouter_model::config::InterfaceKind;
use corerouter_model::ospf::{
    AreaType, AuthType, MAIN_VRF, NetworkType, NssaTranslate, Ospf, OspfTemplate, Version,
};
use corerouter_model::{Config, Issue};
use ipnet::IpNet;

/// RFC 2328 §A.4.1 / §A.4.5: costs and metrics are 16 bits on a link and
/// 24 bits in a summary.
pub const MAX_COST: u32 = 65_535;
pub const MAX_METRIC: u32 = 0x00FF_FFFF;
/// RFC 2328 §D.3: the simple password is 64 bits.
pub const MAX_SIMPLE_KEY: usize = 8;
/// FRR's key-string and RFC 5709's practical limit (the HMAC key is
/// hashed when longer than the block, so length buys nothing past it).
pub const MAX_KEY: usize = 64;
/// RFC 2328 §D.3: an 8-bit key id in v2; RFC 7166 §2: 16 bits in v3.
pub const MAX_KEY_ID_V2: u16 = 255;

/// Names of instances, areas and key chains: they go on FRR's vty
/// (route-map and key chain names), so `[A-Za-z0-9_.-]`, 1..=48.
pub fn name_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 48
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

pub fn validate(cfg: &Config) -> Vec<Issue> {
    let ospf = &cfg.routing.ospf;
    if ospf.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::new();
    instances(cfg, &mut out);
    areas(ospf, &mut out);
    ranges(ospf, &mut out);
    for (i, t) in ospf.templates.iter().enumerate() {
        template(
            cfg,
            t,
            &format!("routing.ospf.templates[{}]", t.id),
            i,
            &mut out,
        );
    }
    keychains(ospf, &mut out);
    neighbors(ospf, &mut out);
    out
}

fn instances(cfg: &Config, out: &mut Vec<Issue>) {
    let ospf = &cfg.routing.ospf;
    let mut per_vrf: HashMap<(Version, &str), &str> = HashMap::new();
    for (key, inst) in &ospf.instances {
        let path = format!("routing.ospf.instances.{key}");
        if inst.name != *key || !name_ok(key) {
            out.push(Issue::new(
                &path,
                "instance name must match its key and be 1..=48 of [A-Za-z0-9_.-]",
            ));
        }
        if let Some(r) = inst.router_id
            && (r.is_unspecified() || r.is_broadcast())
        {
            out.push(Issue::new(
                format!("{path}.router_id"),
                "router-id must not be 0.0.0.0 or 255.255.255.255",
            ));
        }
        if inst.vrf != MAIN_VRF {
            let is_vrf = inst
                .vrf
                .parse()
                .ok()
                .and_then(|n| cfg.interfaces.get(&n))
                .is_some_and(|i| matches!(i.kind, InterfaceKind::Vrf { .. }));
            if !is_vrf {
                out.push(Issue::new(
                    format!("{path}.vrf"),
                    format!("no VRF {} (interface.vrf.add)", inst.vrf),
                ));
            }
        }
        if !inst.disabled
            && let Some(other) = per_vrf.insert((inst.version, inst.vrf.as_str()), key)
        {
            out.push(Issue::new(
                &path,
                format!(
                    "instance {other} already runs OSPFv{} in VRF {}: FRR runs one per VRF",
                    inst.version.number(),
                    inst.vrf
                ),
            ));
        }
        if let Some(c) = &inst.out_filter_chain {
            for p in chain::compile(cfg, c).problems {
                out.push(Issue::new(format!("{path}.out_filter_chain"), p));
            }
        }
        if inst.subscriber_pools && inst.version == Version::V3 {
            out.push(Issue::new(
                format!("{path}.subscriber_pools"),
                "the subscriber pools are IPv4: announce them from the OSPFv2 instance",
            ));
        }
    }
}

fn areas(ospf: &Ospf, out: &mut Vec<Issue>) {
    let mut ids: HashMap<(&str, u32), &str> = HashMap::new();
    for (key, a) in &ospf.areas {
        let path = format!("routing.ospf.areas.{key}");
        if a.name != *key || !name_ok(key) {
            out.push(Issue::new(
                &path,
                "area name must match its key and be 1..=48 of [A-Za-z0-9_.-]",
            ));
        }
        let Some(inst) = ospf.instances.get(&a.instance) else {
            out.push(Issue::new(
                format!("{path}.instance"),
                format!("no OSPF instance {}", a.instance),
            ));
            continue;
        };
        if let Some(other) = ids.insert((a.instance.as_str(), a.area_id.0), key) {
            out.push(Issue::new(
                format!("{path}.area_id"),
                format!(
                    "area {} is already area {other} of instance {}",
                    a.area_id, a.instance
                ),
            ));
        }
        // RFC 2328 §3.6: the backbone cannot be a stub area (RFC 3101 §2.1
        // says the same of an NSSA).
        if a.area_id.is_backbone() && a.kind != AreaType::Default {
            out.push(Issue::new(
                format!("{path}.type"),
                "the backbone (0.0.0.0) cannot be stub or NSSA (RFC 2328 §3.6, RFC 3101 §2.1)",
            ));
        }
        if a.kind == AreaType::Default && (a.no_summaries || a.default_cost.is_some()) {
            out.push(Issue::new(
                &path,
                "no-summaries and default-cost apply to stub and NSSA areas",
            ));
        }
        if a.default_cost.is_some_and(|c| c > MAX_METRIC) {
            out.push(Issue::new(
                format!("{path}.default_cost"),
                "at most 16777215 (24 bits)",
            ));
        }
        if a.nssa_translate != NssaTranslate::Candidate {
            if a.kind != AreaType::Nssa {
                out.push(Issue::new(
                    format!("{path}.nssa_translate"),
                    "applies to NSSA areas",
                ));
            } else if inst.version == Version::V3 {
                out.push(Issue::new(
                    format!("{path}.nssa_translate"),
                    "FRR's ospf6d elects the translator itself (RFC 3101 §3.1 candidate)",
                ));
            }
        }
    }
}

fn ranges(ospf: &Ospf, out: &mut Vec<Issue>) {
    let mut seen: HashSet<(&str, IpNet)> = HashSet::new();
    for r in &ospf.ranges {
        let path = format!("routing.ospf.ranges[{}]", r.id);
        let Some(inst) = ospf.instance_of_area(&r.area) else {
            out.push(Issue::new(
                format!("{path}.area"),
                format!("no OSPF area {}", r.area),
            ));
            continue;
        };
        if matches!(r.prefix, IpNet::V6(_)) != (inst.version == Version::V3) {
            out.push(Issue::new(
                format!("{path}.prefix"),
                format!(
                    "an OSPFv{} area summarizes {} prefixes",
                    inst.version.number(),
                    family(inst.version)
                ),
            ));
        }
        if r.prefix.trunc() != r.prefix {
            out.push(Issue::new(
                format!("{path}.prefix"),
                format!(
                    "{} has host bits; the network is {}",
                    r.prefix,
                    r.prefix.trunc()
                ),
            ));
        }
        if r.cost.is_some_and(|c| c > MAX_METRIC) {
            out.push(Issue::new(
                format!("{path}.cost"),
                "at most 16777215 (24 bits)",
            ));
        }
        if !seen.insert((r.area.as_str(), r.prefix)) {
            out.push(Issue::new(
                &path,
                format!("area {} already has range {}", r.area, r.prefix),
            ));
        }
    }
}

fn family(v: Version) -> &'static str {
    match v {
        Version::V2 => "IPv4",
        Version::V3 => "IPv6",
    }
}

fn template(cfg: &Config, t: &OspfTemplate, path: &str, _pos: usize, out: &mut Vec<Issue>) {
    let ospf = &cfg.routing.ospf;
    let Some(area) = ospf.areas.get(&t.area) else {
        out.push(Issue::new(
            format!("{path}.area"),
            format!("no OSPF area {}", t.area),
        ));
        return;
    };
    let Some(inst) = ospf.instances.get(&area.instance) else {
        return;
    };
    let v = inst.version;
    if t.kind == NetworkType::VirtualLink {
        vlink(ospf, t, area, v, path, out);
    } else if t.interfaces.is_empty() && t.networks.is_empty() {
        out.push(Issue::new(
            path,
            "list interfaces or networks: the template matches nothing",
        ));
    }
    for n in &t.networks {
        if matches!(n, IpNet::V6(_)) != (v == Version::V3) {
            out.push(Issue::new(
                format!("{path}.networks"),
                format!("{n}: OSPFv{} matches {} networks", v.number(), family(v)),
            ));
        }
    }
    for i in &t.interfaces {
        let known = i
            .parse()
            .ok()
            .is_some_and(|n| cfg.interfaces.contains_key(&n))
            || cfg.interface_lists.get(i).is_some();
        if !known {
            out.push(Issue::new(
                format!("{path}.interfaces"),
                format!("no interface or interface list {i}"),
            ));
        }
    }
    if t.cost == Some(0) {
        out.push(Issue::new(
            format!("{path}.cost"),
            "1..=65535 (RFC 2328 §A.4.2)",
        ));
    }
    if t.hello_interval == Some(0) || t.dead_interval == Some(0) {
        out.push(Issue::new(
            path,
            "hello and dead intervals are 1..=65535 seconds",
        ));
    }
    // RFC 2328 §C.3: RouterDeadInterval is "some multiple" of the hello
    // interval; at or under it the adjacency drops between two hellos.
    let hello = t.hello_interval.unwrap_or(10);
    if let Some(d) = t.dead_interval
        && d <= hello
    {
        out.push(Issue::new(
            format!("{path}.dead_interval"),
            format!("dead interval {d}s must be longer than the hello interval {hello}s (4× is usual, RFC 2328 §C.3)"),
        ));
    }
    if t.instance_id.is_some() && v == Version::V2 {
        out.push(Issue::new(
            format!("{path}.instance_id"),
            "instance-id is OSPFv3 only (RFC 5340 §2.4)",
        ));
    }
    if v == Version::V3 && t.kind == NetworkType::Nbma {
        out.push(Issue::new(
            format!("{path}.type"),
            "FRR's ospf6d has no NBMA links",
        ));
    }
    auth(ospf, t, v, path, out);
    if let Some(p) = &t.bfd
        && !name_ok(p)
    {
        out.push(Issue::new(
            format!("{path}.bfd"),
            "a BFD profile name: 1..=48 of [A-Za-z0-9_.-]",
        ));
    }
}

fn vlink(
    ospf: &Ospf,
    t: &OspfTemplate,
    area: &corerouter_model::ospf::OspfArea,
    v: Version,
    path: &str,
    out: &mut Vec<Issue>,
) {
    if v == Version::V3 {
        out.push(Issue::new(
            format!("{path}.type"),
            "FRR's ospf6d has no virtual links",
        ));
        return;
    }
    // RFC 2328 §15: a virtual link belongs to the backbone and crosses a
    // non-backbone, non-stub transit area.
    if !area.area_id.is_backbone() {
        out.push(Issue::new(
            format!("{path}.area"),
            "a virtual link belongs to the backbone (RFC 2328 §15)",
        ));
    }
    if t.vlink_neighbor_id.is_none() {
        out.push(Issue::new(
            format!("{path}.vlink_neighbor_id"),
            "the router id at the far end is required",
        ));
    }
    match t
        .vlink_transit_area
        .as_deref()
        .map(|n| (n, ospf.areas.get(n)))
    {
        None => out.push(Issue::new(
            format!("{path}.vlink_transit_area"),
            "the transit area is required",
        )),
        Some((n, None)) => out.push(Issue::new(
            format!("{path}.vlink_transit_area"),
            format!("no OSPF area {n}"),
        )),
        Some((_, Some(tr))) => {
            if tr.area_id.is_backbone()
                || tr.kind != AreaType::Default
                || tr.instance != area.instance
            {
                out.push(Issue::new(
                    format!("{path}.vlink_transit_area"),
                    "the transit area must be a normal (not stub or NSSA) non-backbone area of the same instance (RFC 2328 §15)",
                ));
            }
        }
    }
}

fn auth(ospf: &Ospf, t: &OspfTemplate, v: Version, path: &str, out: &mut Vec<Issue>) {
    let Some(a) = t.auth else {
        if t.has_key() || t.keychain.is_some() {
            out.push(Issue::new(
                format!("{path}.auth"),
                "a key is set but auth is not (sha256 recommended)",
            ));
        }
        return;
    };
    if v == Version::V3
        && !matches!(
            a,
            AuthType::Sha1 | AuthType::Sha256 | AuthType::Sha384 | AuthType::Sha512
        )
    {
        out.push(Issue::new(
            format!("{path}.auth"),
            "OSPFv3 authenticates with HMAC-SHA only (RFC 7166 §4.3): sha1, sha256, sha384 or sha512",
        ));
    }
    match (&t.keychain, t.has_key()) {
        (Some(_), true) => out.push(Issue::new(path, "set auth_key or keychain, not both")),
        (None, false) => out.push(Issue::new(
            format!("{path}.auth_key"),
            format!("auth {} needs auth_key or keychain", a.name()),
        )),
        (Some(k), false) => {
            if a == AuthType::Simple {
                out.push(Issue::new(
                    format!("{path}.keychain"),
                    "simple takes one auth_key, not a key chain",
                ));
            }
            match ospf.keychains.get(k) {
                None => out.push(Issue::new(
                    format!("{path}.keychain"),
                    format!("no OSPF key chain {k}"),
                )),
                Some(kc) => {
                    if kc.keys.is_empty() {
                        out.push(Issue::new(
                            format!("{path}.keychain"),
                            format!("key chain {k} has no key"),
                        ));
                    }
                    for key in &kc.keys {
                        if key.algorithm == AuthType::Simple
                            || (v == Version::V3 && key.algorithm == AuthType::Md5)
                        {
                            out.push(Issue::new(
                                format!("{path}.keychain"),
                                format!(
                                    "key {} of {k} is {}, which OSPFv{} cannot use here",
                                    key.id,
                                    key.algorithm.name(),
                                    v.number()
                                ),
                            ));
                        }
                        if v == Version::V2 && key.id > MAX_KEY_ID_V2 {
                            out.push(Issue::new(
                                format!("{path}.keychain"),
                                format!(
                                    "key {} of {k}: OSPFv2 key ids are 0..=255 (RFC 2328 §D.3)",
                                    key.id
                                ),
                            ));
                        }
                    }
                }
            }
        }
        (None, true) => {
            if v == Version::V2 && t.auth_id.is_some_and(|i| i > MAX_KEY_ID_V2) {
                out.push(Issue::new(
                    format!("{path}.auth_id"),
                    "OSPFv2 key ids are 0..=255 (RFC 2328 §D.3)",
                ));
            }
        }
    }
}

fn keychains(ospf: &Ospf, out: &mut Vec<Issue>) {
    for (key, kc) in &ospf.keychains {
        let path = format!("routing.ospf.keychains.{key}");
        if kc.name != *key || !name_ok(key) {
            out.push(Issue::new(
                &path,
                "key chain name must match its key and be 1..=48 of [A-Za-z0-9_.-]",
            ));
        }
        let mut ids = BTreeSet::new();
        for k in &kc.keys {
            let kp = format!("{path}.keys[{}]", k.id);
            if !ids.insert(k.id) {
                out.push(Issue::new(&kp, "key id used twice"));
            }
            if k.key_string.is_empty() {
                out.push(Issue::new(&kp, "the key is empty"));
            }
            for (from, until, what) in [
                (k.send_from, k.send_until, "send"),
                (k.accept_from, k.accept_until, "accept"),
            ] {
                if let (Some(f), Some(u)) = (from, until)
                    && f >= u
                {
                    out.push(Issue::new(
                        &kp,
                        format!("the {what} window ends before it starts"),
                    ));
                }
                for t in [from, until].into_iter().flatten() {
                    if !(frr::FRR_FIRST..frr::FRR_END).contains(&t) {
                        out.push(Issue::new(
                            &kp,
                            format!("{what} times must fall in 1993..=2035 (FRR's key chain)"),
                        ));
                    }
                }
            }
        }
    }
}

fn neighbors(ospf: &Ospf, out: &mut Vec<Issue>) {
    let mut seen = HashSet::new();
    for n in &ospf.static_neighbors {
        let path = format!("routing.ospf.static_neighbors[{}]", n.id);
        match ospf.instances.get(&n.instance) {
            None => out.push(Issue::new(
                format!("{path}.instance"),
                format!("no OSPF instance {}", n.instance),
            )),
            Some(i) if i.version == Version::V3 => {
                out.push(Issue::new(
                    format!("{path}.instance"),
                    "static neighbors are for OSPFv2 NBMA links",
                ));
            }
            Some(_) => {}
        }
        if !seen.insert((n.instance.as_str(), n.address)) {
            out.push(Issue::new(
                &path,
                format!("neighbor {} is listed twice", n.address),
            ));
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use corerouter_model::config::{AddressEntry, Interface};
    use corerouter_model::ospf::{OspfArea, OspfInstance, Redistribute};
    use corerouter_model::types::ItemId;

    fn iface(name: &str) -> Interface {
        serde_json::from_value(serde_json::json!({"name": name, "kind": {"type": "ethernet"}}))
            .unwrap()
    }

    /// Two interfaces, a v2 instance, the backbone and a totally stubby
    /// area; ether1 by name with a key, ether2 by network.
    pub(crate) fn sample() -> Config {
        let mut cfg = Config::default();
        for n in ["ether1", "ether2", "ether3"] {
            cfg.interfaces.insert(n.parse().unwrap(), iface(n));
        }
        let mut id = 0;
        for (a, i) in [
            ("10.0.1.1/24", "ether1"),
            ("10.0.2.1/30", "ether2"),
            ("192.168.9.1/24", "ether3"),
        ] {
            id += 1;
            cfg.ip.addresses.push(AddressEntry {
                id: ItemId(id),
                address: a.parse().unwrap(),
                interface: i.parse().unwrap(),
                disabled: false,
                comment: String::new(),
                from_pool: None,
            });
        }
        let o = &mut cfg.routing.ospf;
        o.instances.insert(
            "v2".into(),
            OspfInstance {
                name: "v2".into(),
                version: Version::V2,
                vrf: MAIN_VRF.into(),
                router_id: Some([10, 255, 0, 1].into()),
                redistribute: vec![Redistribute::Connected],
                out_filter_chain: None,
                originate_default: Default::default(),
                subscriber_pools: false,
                disabled: false,
                comment: String::new(),
            },
        );
        for (name, id, kind, ns) in [
            ("backbone", 0, AreaType::Default, false),
            ("edge", 1, AreaType::Stub, true),
        ] {
            o.areas.insert(
                name.into(),
                OspfArea {
                    name: name.into(),
                    instance: "v2".into(),
                    area_id: corerouter_model::ospf::AreaId(id),
                    kind,
                    no_summaries: ns,
                    default_cost: None,
                    nssa_translate: NssaTranslate::Candidate,
                    disabled: false,
                    comment: String::new(),
                },
            );
        }
        let t1 = OspfTemplate {
            id: o.next_id(),
            area: "backbone".into(),
            interfaces: vec!["ether1".into()],
            auth: Some(AuthType::Sha256),
            auth_id: Some(1),
            auth_key: "s3cret".into(),
            ..OspfTemplate::default()
        };
        let t2 = OspfTemplate {
            id: o.next_id(),
            area: "backbone".into(),
            interfaces: vec!["ether1".into()],
            networks: vec!["10.0.2.0/24".parse().unwrap()],
            kind: NetworkType::Ptp,
            passive: true,
            ..OspfTemplate::default()
        };
        o.templates = vec![t1, t2];
        cfg
    }

    #[test]
    fn the_sample_is_valid() {
        assert_eq!(validate(&sample()), Vec::new());
    }

    #[test]
    fn backbone_cannot_be_stub() {
        let mut cfg = sample();
        if let Some(a) = cfg.routing.ospf.areas.get_mut("backbone") {
            a.kind = AreaType::Stub;
        }
        let v = validate(&cfg);
        assert!(
            v.iter().any(|i| i.message.contains("RFC 2328 §3.6")),
            "{v:?}"
        );
    }

    #[test]
    fn auth_rules() {
        let mut cfg = sample();
        cfg.routing.ospf.templates[0].auth = None;
        assert!(
            validate(&cfg)
                .iter()
                .any(|i| i.message.contains("auth is not"))
        );
        let mut cfg = sample();
        cfg.routing.ospf.templates[0].keychain = Some("nope".into());
        assert!(
            validate(&cfg)
                .iter()
                .any(|i| i.message.contains("not both"))
        );
        let mut cfg = sample();
        cfg.routing.ospf.templates[0].auth_key = Default::default();
        cfg.routing.ospf.templates[0].keychain = Some("nope".into());
        assert!(
            validate(&cfg)
                .iter()
                .any(|i| i.message.contains("no OSPF key chain nope"))
        );
    }

    #[test]
    fn dead_must_outlast_hello() {
        let mut cfg = sample();
        cfg.routing.ospf.templates[1].hello_interval = Some(10);
        cfg.routing.ospf.templates[1].dead_interval = Some(10);
        assert!(validate(&cfg).iter().any(|i| i.message.contains("§C.3")));
    }

    #[test]
    fn one_instance_per_version_and_vrf() {
        let mut cfg = sample();
        let mut i = cfg.routing.ospf.instances["v2"].clone();
        i.name = "v2b".into();
        cfg.routing.ospf.instances.insert("v2b".into(), i);
        assert!(
            validate(&cfg)
                .iter()
                .any(|i| i.message.contains("one per VRF"))
        );
    }
}
