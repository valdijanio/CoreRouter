//! L2 — BGP.
//!
//! Validates `routing.bgp` (instances), `routing.bgp_templates` and
//! `routing.bgp_connections` (G3.2a) and renders them to FRR `bgpd`
//! configuration. The platform driver `hal-frr` (G3.1) diffs the render
//! against what `bgpd` runs and types only the difference, then reads the
//! sessions back as JSON.
//!
//! Templates are flattened here: each neighbor is rendered with the values
//! in force (`corerouter_model::bgp`), not as an FRR peer-group. A
//! RouterOS template lists many parents and a connection overrides any
//! value; a peer-group has one parent and some settings cannot be
//! overridden per member. Changing a template then types the changed lines
//! of each neighbor that inherits them, and nothing else.
//!
//! Contract shared by every `proto-*` crate: `validate` inspects the
//! candidate and returns issues; the engine refuses to commit while any exist.

pub mod decision;
pub mod filter;
pub mod rib;
pub mod rpki;
pub mod rtr;

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;
use std::net::IpAddr;

use corerouter_model::address_lists::AddressLists;
use corerouter_model::bgp::{
    Afi, BgpConnection, BgpParams, BgpRedistribute, LocalRole, MaxPrefixAction, NexthopChoice,
    resolve_templates,
};
use corerouter_model::firewall::AddrMatch;
use corerouter_model::sealed::Sealed;
use corerouter_model::{BgpInstance, Config, Issue, Routing};

/// RFC 4271 §4.2: a hold time is 0 or at least 3 seconds.
pub const MIN_HOLD_TIME: u16 = 3;
/// Minutes before a neighbor over its prefix limit is tried again, when
/// the action is `restart` and no time is set.
pub const DEFAULT_RESTART_MINUTES: u16 = 5;
/// Longest TCP MD5 key Linux takes (`TCP_MD5SIG_MAXKEYLEN`, RFC 2385).
pub const MAX_KEY_LEN: usize = 80;

/// Opens a sealed TCP MD5 key; `None`: it cannot be opened here.
pub type Opener<'a> = &'a dyn Fn(&Sealed) -> Option<String>;

pub fn validate(cfg: &Config) -> Vec<Issue> {
    let mut out = Vec::new();
    for (key, inst) in &cfg.routing.bgp {
        let path = format!("routing.bgp.{key}");
        if inst.name != *key {
            out.push(Issue::new(&path, "instance name does not match its key"));
        }
        if inst.asn.is_reserved() {
            out.push(Issue::new(
                format!("{path}.asn"),
                format!("AS {} is reserved (0, 23456, 65535, 4294967295)", inst.asn),
            ));
        }
        if inst.router_id.is_unspecified() || inst.router_id.is_broadcast() {
            out.push(Issue::new(
                format!("{path}.router_id"),
                "router-id must not be 0.0.0.0 or 255.255.255.255",
            ));
        }
    }
    validate_neighbors(cfg, &mut out);
    validate_filter(cfg, &mut out);
    out.extend(rpki::validate(&cfg.routing));
    out
}

/// `/routing filter` (G3.2b): every rule parses, every chain, list and
/// jump it names exists, no jump loop, and each chain fits FRR.
fn validate_filter(cfg: &Config, out: &mut Vec<Issue>) {
    let routing = &cfg.routing;
    let f = &routing.filter;
    for issue in filter::validate_lists(f) {
        out.push(issue);
    }
    let (_, problems) = filter::eval::Policy::build(f);
    for p in problems {
        out.push(Issue::new(
            format!("routing.filter.rules.{}", p.item),
            p.message,
        ));
    }
    let chains = f.chains();
    let resolved = resolve_templates(&routing.bgp_templates);
    for (key, c) in &routing.bgp_connections {
        let Ok(eff) = c.effective(&resolved) else {
            continue;
        };
        for (param, chain) in [
            ("input_filter", &eff.input_filter),
            ("output_filter", &eff.output_filter),
        ] {
            if let Some(chain) = chain
                && !chains.contains(&chain.as_str())
            {
                let hint = filter::parse::did_you_mean(chain, &chains);
                out.push(Issue::new(
                    format!("routing.bgp_connections.{key}.params.{param}"),
                    format!("chain {chain:?} has no rules (routing.filter.rule.add){hint}"),
                ));
            }
        }
    }
    // One chain, one RPKI behavior: its route-map holds the RPKI entries
    // for every connection that uses it.
    let mut modes: HashMap<String, (corerouter_model::rpki::RpkiInvalid, &str)> = HashMap::new();
    for (key, c) in &routing.bgp_connections {
        let Ok(eff) = c.effective(&resolved) else {
            continue;
        };
        if let Some(chain) = eff.input_filter.clone() {
            let mode = eff.rpki_invalid.unwrap_or_default();
            match modes.get(&chain) {
                Some((m, other)) if *m != mode && !rpki::enabled(routing).is_empty() => out.push(Issue::new(
                    format!("routing.bgp_connections.{key}.params.rpki_invalid"),
                    format!("input chain {chain:?} is shared with connection {other:?}, which treats RPKI-invalid routes differently: give them separate chains"),
                )),
                Some(_) => {}
                None => {
                    modes.insert(chain, (mode, key.as_str()));
                }
            }
        }
    }
    let (_, render_problems) = filter_render(routing);
    for p in render_problems {
        out.push(Issue::new(
            format!("routing.filter.rules.{}", p.item),
            p.message,
        ));
    }
}

/// The chains the connections use, with the AS of their instance (one
/// per chain; `None` when connections of instances with different ASes
/// share it, or nothing tells).
fn filter_render(routing: &Routing) -> (String, Vec<filter::eval::Problem>) {
    if routing.filter.rules.is_empty() {
        return (String::new(), Vec::new());
    }
    let resolved = resolve_templates(&routing.bgp_templates);
    let mut used: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut asn: HashMap<String, Option<u32>> = HashMap::new();
    // G3.2c: the input chains whose connections drop RPKI-invalid routes
    // (with a validator, eBGP too: the chain is its policy) get the RPKI
    // entries first (sequences 1..=9).
    let validators = !rpki::enabled(routing).is_empty();
    let mut rpki_in: HashMap<String, bool> = HashMap::new();
    for c in routing.bgp_connections.values() {
        let Ok(eff) = c.effective(&resolved) else {
            continue;
        };
        let inst = routing.bgp.get(&c.instance).map(|i| i.asn.0);
        if let Some(chain) = &eff.input_filter {
            let drops = validators
                && eff.rpki_invalid.unwrap_or_default()
                    == corerouter_model::rpki::RpkiInvalid::Reject;
            *rpki_in.entry(chain.clone()).or_insert(drops) |= drops;
        }
        for chain in [&eff.input_filter, &eff.output_filter]
            .into_iter()
            .flatten()
        {
            used.insert(chain.clone());
            let e = asn.entry(chain.clone()).or_insert(inst);
            if *e != inst {
                *e = None;
            }
        }
    }
    let only = (routing.bgp.len() == 1)
        .then(|| routing.bgp.values().next().map(|i| i.asn.0))
        .flatten();
    filter::frr::render_with(
        &routing.filter,
        &used,
        &|chain| match asn.get(chain) {
            Some(a) => *a,
            None => only,
        },
        &|chain| {
            if rpki_in.get(chain).copied().unwrap_or(false) {
                rpki::route_map_prelude(&filter::frr::route_map(chain))
            } else {
                String::new()
            }
        },
    )
}

fn validate_neighbors(cfg: &Config, out: &mut Vec<Issue>) {
    let routing = &cfg.routing;
    let resolved = resolve_templates(&routing.bgp_templates);
    for (key, t) in &routing.bgp_templates {
        let path = format!("routing.bgp_templates.{key}");
        if t.name != *key {
            out.push(Issue::new(&path, "template name does not match its key"));
        }
        match resolved.get(key) {
            Some(Err(e)) => out.push(Issue::new(format!("{path}.templates"), e.to_string())),
            _ => check_params(&t.params, &path, cfg, out),
        }
    }
    // FRR keys a neighbor by its address inside an instance.
    let mut by_address: HashMap<(&str, IpAddr), &str> = HashMap::new();
    for (key, c) in &routing.bgp_connections {
        let path = format!("routing.bgp_connections.{key}");
        if c.name != *key {
            out.push(Issue::new(&path, "connection name does not match its key"));
        }
        let Some(inst) = routing.bgp.get(&c.instance) else {
            out.push(Issue::new(
                format!("{path}.instance"),
                format!(
                    "BGP instance {:?} does not exist (routing.bgp.instance.set first)",
                    c.instance
                ),
            ));
            continue;
        };
        let addr = c.remote_address;
        if addr.is_unspecified()
            || addr.is_multicast()
            || addr == IpAddr::from([255, 255, 255, 255])
        {
            out.push(Issue::new(
                format!("{path}.remote_address"),
                format!("{addr} cannot be a BGP neighbor"),
            ));
        }
        if let Some(other) = by_address.insert((c.instance.as_str(), addr), key) {
            out.push(Issue::new(
                format!("{path}.remote_address"),
                format!("{addr} is already the neighbor of connection {other:?}"),
            ));
        }
        let eff = match c.effective(&resolved) {
            Ok(e) => e,
            Err(e) => {
                out.push(Issue::new(format!("{path}.templates"), e.to_string()));
                continue;
            }
        };
        check_params(&eff, &format!("{path}.params"), cfg, out);
        match (eff.local_role, eff.remote_as) {
            (None, None) => out.push(Issue::new(
                format!("{path}.params.local_role"),
                "set local_role (ibgp, ebgp…) or remote_as: without them the session kind is unknown",
            )),
            (Some(r), Some(asn)) if r.is_ibgp() && asn != inst.asn => out.push(Issue::new(
                format!("{path}.params.remote_as"),
                format!("an ibgp neighbor is in our AS {}, not AS {asn}", inst.asn),
            )),
            (Some(r), Some(asn)) if !r.is_ibgp() && asn == inst.asn => out.push(Issue::new(
                format!("{path}.params.remote_as"),
                format!("an {} neighbor cannot be in our own AS {asn}", r.name()),
            )),
            _ => {}
        }
    }
}

/// Checks on one set of parameters (a template's own, or a connection's
/// in force).
fn check_params(p: &BgpParams, path: &str, cfg: &Config, out: &mut Vec<Issue>) {
    if let Some(asn) = p.remote_as
        && asn.is_reserved()
    {
        out.push(Issue::new(
            format!("{path}.remote_as"),
            format!("AS {asn} is reserved (0, 23456, 65535, 4294967295; RFC 7607, 6793, 7300)"),
        ));
    }
    if let Some(h) = p.hold_time
        && h != 0
        && h < MIN_HOLD_TIME
    {
        out.push(Issue::new(
            format!("{path}.hold_time"),
            "must be 0 (infinity) or at least 3 seconds (RFC 4271 §4.2)",
        ));
    }
    if let (Some(h), Some(k)) = (p.hold_time, p.keepalive_time)
        && h != 0
        && k >= h
    {
        out.push(Issue::new(
            format!("{path}.keepalive_time"),
            format!("{k} s is not shorter than the hold time {h} s (RFC 4271 §10: a third of it)"),
        ));
    }
    if p.afi.as_ref().is_some_and(Vec::is_empty) {
        out.push(Issue::new(
            format!("{path}.afi"),
            "no address family: the session would carry nothing (ip, ipv6)",
        ));
    }
    if let Some(src) = &p.update_source
        && src.parse::<IpAddr>().is_err()
        && !cfg.interfaces.keys().any(|i| i.as_str() == src)
    {
        out.push(Issue::new(
            format!("{path}.update_source"),
            format!("{src:?} is neither an address nor an interface"),
        ));
    }
}

/// The instance FRR runs in the default VRF; any other name is a BGP
/// `view` of its own (a separate instance with its own sessions and
/// table, not installed in the kernel) until instances get a VRF.
pub const DEFAULT_INSTANCE: &str = "default";

/// The FRR context header of an instance, as `show running-config` prints it.
pub fn frr_header(inst: &BgpInstance) -> String {
    if inst.name == DEFAULT_INSTANCE {
        format!("router bgp {}", inst.asn)
    } else {
        format!("router bgp {} view {}", inst.asn, inst.name)
    }
}

/// Every instance of `routing`, rendered (connections grouped by instance
/// in one pass: O(instances + connections)).
pub fn render_all(routing: &Routing, open: Opener<'_>) -> Result<String, String> {
    render_with_lists(routing, None, open)
}

/// [`render_all`] with the address lists the connections' `output_network`
/// names (G3.9fa); `render_all` alone announces no network.
pub fn render_config(cfg: &Config, open: Opener<'_>) -> Result<String, String> {
    render_with_lists(&cfg.routing, Some(cfg), open)
}

/// G3.9fa: whether the BGP render of `to` differs from that of `from`
/// outside `routing`: a changed address list while some connection or
/// template announces one (`output_network`), or changed static routes
/// while one redistributes them. Without it, adding an entry to the list
/// reached FRR only at the next routing commit (seen in the lab). O(1)
/// when both are shared, as in every commit that leaves them alone.
pub fn networks_changed(from: &Config, to: &Config) -> bool {
    let (a, b) = (
        &from.ip.firewall.address_lists,
        &to.ip.firewall.address_lists,
    );
    let lists = !(AddressLists::ptr_eq(a, b) || a == b);
    let (x, y) = (&from.ip.routes, &to.ip.routes);
    let statics = !(corerouter_model::cow_list::CowList::ptr_eq(x, y) || x == y);
    if !lists && !statics {
        return false;
    }
    let r = &to.routing;
    let params = r
        .bgp_connections
        .values()
        .map(|c| &c.params)
        .chain(r.bgp_templates.values().map(|t| &t.params));
    let mut uses = params.filter(|p| {
        (lists && p.output_network.is_some())
            || (statics
                && p.output_redistribute
                    .as_ref()
                    .is_some_and(|v| v.contains(&BgpRedistribute::Static)))
    });
    uses.next().is_some()
}

/// G3.9fa: the route-map (and prefix-list, same name) that lets
/// `redistribute kernel` take only CoreRouter's static routes. The linux
/// backend installs them itself (`proto static`), so zebra sees them as
/// kernel routes: `redistribute static` (staticd's) finds none.
fn static_map(afi: Afi) -> &'static str {
    match afi {
        Afi::Ip => "CR-BGP-STATIC4",
        Afi::Ipv6 => "CR-BGP-STATIC6",
    }
}

/// The static routes of the main table, by family (what
/// `output_redistribute=static` announces).
fn static_prefixes(cfg: &Config, afi: Afi) -> std::collections::BTreeSet<ipnet::IpNet> {
    cfg.ip
        .routes
        .iter()
        .filter(|r| !r.disabled && r.routing_table.is_main())
        .map(|r| r.dst_address.trunc())
        .filter(|n| {
            matches!(
                (afi, n),
                (Afi::Ip, ipnet::IpNet::V4(_)) | (Afi::Ipv6, ipnet::IpNet::V6(_))
            )
        })
        .collect()
}

/// The prefix-lists and route-maps of [`static_map`], when a connection
/// redistributes static routes.
fn static_maps(cfg: &Config) -> String {
    let wanted = cfg
        .routing
        .bgp_connections
        .values()
        .any(|c| c.params.output_redistribute.is_some())
        || cfg
            .routing
            .bgp_templates
            .values()
            .any(|t| t.params.output_redistribute.is_some());
    let mut s = String::new();
    if !wanted {
        return s;
    }
    for afi in [Afi::Ip, Afi::Ipv6] {
        let nets = static_prefixes(cfg, afi);
        if nets.is_empty() {
            continue;
        }
        let (kw, m) = match afi {
            Afi::Ip => ("ip", "ip"),
            Afi::Ipv6 => ("ipv6", "ipv6"),
        };
        let name = static_map(afi);
        for (i, n) in nets.iter().enumerate() {
            let _ = writeln!(s, "{kw} prefix-list {name} seq {} permit {n}", (i + 1) * 5);
        }
        let _ = writeln!(s, "route-map {name} permit 10");
        let _ = writeln!(s, " match {m} address prefix-list {name}");
        let _ = writeln!(s, "exit");
    }
    s
}

fn render_with_lists(
    routing: &Routing,
    cfg: Option<&Config>,
    open: Opener<'_>,
) -> Result<String, String> {
    let resolved = resolve_templates(&routing.bgp_templates);
    let mut by_inst: BTreeMap<&str, Vec<&BgpConnection>> = BTreeMap::new();
    for c in routing.bgp_connections.values() {
        by_inst.entry(c.instance.as_str()).or_default().push(c);
    }
    let (mut s, _) = filter_render(routing);
    if let Some(cfg) = cfg {
        s.push_str(&static_maps(cfg));
    }
    for inst in routing.bgp.values() {
        let conns = by_inst
            .get(inst.name.as_str())
            .map_or(&[][..], Vec::as_slice);
        let mut eff = Vec::with_capacity(conns.len());
        for c in conns {
            let p = c
                .effective(&resolved)
                .map_err(|e| format!("connection {}: {e}", c.name))?;
            eff.push((*c, p));
        }
        render_instance(
            &mut s,
            inst,
            &eff,
            cfg,
            open,
            !rpki::enabled(routing).is_empty(),
        )?;
    }
    // G3.2c: the `rpki` node and its route-map, after the instances.
    s.push_str(&rpki::render_frr(routing));
    Ok(s)
}

/// One instance alone, without neighbors (the preview of
/// `routing.bgp.instance.set`).
pub fn render_frr(inst: &BgpInstance) -> String {
    let mut s = String::new();
    // No neighbors: no key to open.
    let _ = render_instance(&mut s, inst, &[], None, &|_| None, false);
    s
}

/// One instance as an FRR `router bgp` block, in FRR's own canonical form
/// (what `show running-config` gives back), so a diff against the running
/// config is empty when nothing changed.
///
/// eBGP sessions follow RFC 8212 (FRR's `bgp ebgp-requires-policy`, on by
/// default): no route is accepted or sent without a policy (G3.2b).
fn render_instance(
    s: &mut String,
    inst: &BgpInstance,
    neighbors: &[(&BgpConnection, BgpParams)],
    cfg: Option<&Config>,
    open: Opener<'_>,
    rpki: bool,
) -> Result<(), String> {
    // Writing to a String cannot fail; ignore the fmt::Result.
    let _ = writeln!(s, "{}", frr_header(inst));
    let _ = writeln!(s, " bgp router-id {}", inst.router_id);
    let _ = writeln!(s, " no bgp default ipv4-unicast");
    if inst.disabled {
        let _ = writeln!(s, " bgp shutdown");
    }
    let mut v4 = origination(neighbors, cfg, Afi::Ip);
    let mut v6 = origination(neighbors, cfg, Afi::Ipv6);
    for (c, p) in neighbors {
        neighbor(s, inst, c, p, open)?;
        for afi in p.families() {
            let af = match afi {
                Afi::Ip => &mut v4,
                Afi::Ipv6 => &mut v6,
            };
            neighbor_af(af, c, p, afi);
            // G3.2c: drop RPKI-invalid routes; the Adj-RIB-In is kept so
            // FRR revalidates when the VRPs change (its rpki module needs
            // it) and the received list shows what was dropped.
            // With an input chain the RPKI entries go inside it (G3.2b,
            // `filter_render`), and `keep_received` keeps the routes.
            if rpki
                && p.input_filter.is_none()
                && rpki::drops_invalid_ibgp(role_of(inst, p).is_ibgp(), p)
            {
                let a = c.remote_address;
                if !p.keep_received.unwrap_or(true) {
                    let _ = writeln!(af, "  neighbor {a} soft-reconfiguration inbound");
                }
                let _ = writeln!(af, "  neighbor {a} route-map {} in", rpki::ROUTE_MAP_IN);
            }
        }
    }
    for (name, body) in [("ipv4", v4), ("ipv6", v6)] {
        if !body.is_empty() {
            let _ = writeln!(s, " address-family {name} unicast");
            s.push_str(&body);
            let _ = writeln!(s, " exit-address-family");
        }
    }
    let _ = writeln!(s, "exit");
    Ok(())
}

/// G3.9fa: the `network` and `redistribute` lines of one address family,
/// in the order `bgpd` prints them. FRR originates per instance, not per
/// neighbor: the union of what the instance's connections of that family
/// ask for (RouterOS `output.network` / `output.redistribute`); a
/// connection that should not send some of it says so in its output chain.
/// O(connections + entries of the named lists).
fn origination(
    neighbors: &[(&BgpConnection, BgpParams)],
    cfg: Option<&Config>,
    afi: Afi,
) -> String {
    let lists = cfg.map(|c| &c.ip.firewall.address_lists);
    let mut redist = std::collections::BTreeSet::new();
    let mut names = std::collections::BTreeSet::new();
    for (_, p) in neighbors
        .iter()
        .filter(|(_, p)| p.families().contains(&afi))
    {
        redist.extend(p.output_redistribute.iter().flatten().copied());
        names.extend(p.output_network.as_deref());
    }
    let mut nets = std::collections::BTreeSet::new();
    if let Some(lists) = lists
        && !names.is_empty()
    {
        for e in lists
            .iter()
            .filter(|e| !e.disabled && names.contains(e.list.as_str()))
        {
            // A range is no prefix: left out (the connection check says so).
            if let AddrMatch::Net(n) = e.address
                && matches!(
                    (afi, n),
                    (Afi::Ip, ipnet::IpNet::V4(_)) | (Afi::Ipv6, ipnet::IpNet::V6(_))
                )
            {
                nets.insert(n.trunc());
            }
        }
    }
    let mut s = String::new();
    for n in nets {
        let _ = writeln!(s, "  network {n}");
    }
    for r in redist {
        let line = match (r, afi) {
            (BgpRedistribute::Connected, _) => "redistribute connected".to_owned(),
            // No static route of the family: nothing to announce (and no
            // route-map to name).
            (BgpRedistribute::Static, _)
                if cfg.is_none_or(|c| static_prefixes(c, afi).is_empty()) =>
            {
                continue;
            }
            (BgpRedistribute::Static, _) => {
                format!("redistribute kernel route-map {}", static_map(afi))
            }
            (BgpRedistribute::Ospf, Afi::Ip) => "redistribute ospf".to_owned(),
            (BgpRedistribute::Ospf, Afi::Ipv6) => "redistribute ospf6".to_owned(),
        };
        let _ = writeln!(s, "  {line}");
    }
    s
}

fn role_of(inst: &BgpInstance, p: &BgpParams) -> LocalRole {
    match (p.local_role, p.remote_as) {
        (Some(r), _) => r,
        (None, Some(asn)) if asn == inst.asn => LocalRole::Ibgp,
        _ => LocalRole::Ebgp,
    }
}

/// The session-wide lines of one neighbor.
fn neighbor(
    s: &mut String,
    inst: &BgpInstance,
    c: &BgpConnection,
    p: &BgpParams,
    open: Opener<'_>,
) -> Result<(), String> {
    let a = c.remote_address;
    let role = role_of(inst, p);
    match p.remote_as {
        Some(asn) => {
            let _ = writeln!(s, " neighbor {a} remote-as {asn}");
        }
        None if role.is_ibgp() => {
            let _ = writeln!(s, " neighbor {a} remote-as internal");
        }
        None => {
            let _ = writeln!(s, " neighbor {a} remote-as external");
        }
    }
    // The connection's name: how a session FRR lists finds its connection.
    let _ = writeln!(s, " neighbor {a} description {}", c.name);
    if let Some(r) = role.rfc9234() {
        let _ = writeln!(s, " neighbor {a} local-role {r}");
    }
    if c.disabled {
        let _ = writeln!(s, " neighbor {a} shutdown");
    }
    if p.multihop == Some(true) && !role.is_ibgp() {
        // TTL 255; FRR prints the maximum without the number.
        let _ = writeln!(s, " neighbor {a} ebgp-multihop");
    }
    if let Some(src) = &p.update_source {
        let _ = writeln!(s, " neighbor {a} update-source {src}");
    }
    // G3.6b: the session follows BFD (`bfdd`, with CoreRouter's engine as
    // its data plane).
    if let Some(b) = &p.bfd {
        // G3.9f: `bgpd` 10.7.1 prints both lines; with the second alone
        // every sync typed `no neighbor X bfd`, which turns BFD off (seen
        // in the lab: a silent cut fell back to the hold timer).
        let _ = writeln!(s, " neighbor {a} bfd");
        let _ = writeln!(s, " neighbor {a} bfd profile {b}");
    }
    if p.hold_time.is_some() || p.keepalive_time.is_some() {
        let (k, h) = timers(p);
        let _ = writeln!(s, " neighbor {a} timers {k} {h}");
    }
    if p.has_key()
        && let Some(key) = &p.tcp_md5_key
    {
        let clear = open(key).ok_or_else(|| {
            format!(
                "the TCP MD5 key of connection {} cannot be opened (the secret key file of this \
                 router is missing or another router sealed it): set it again",
                c.name
            )
        })?;
        let _ = writeln!(s, " neighbor {a} password {clear}");
    }
    Ok(())
}

/// (keepalive, hold) in seconds, the unset one derived from the other as
/// RouterOS does (keepalive a third of the hold time, RFC 4271 §10).
pub fn timers(p: &BgpParams) -> (u16, u16) {
    match (p.keepalive_time, p.hold_time) {
        (Some(k), Some(h)) => (k, h),
        (None, Some(h)) => (h / 3, h),
        (Some(k), None) => (k, k.saturating_mul(3)),
        // FRR's own defaults (`frr defaults traditional`).
        (None, None) => (60, 180),
    }
}

/// The lines of one neighbor inside `address-family <afi> unicast`.
fn neighbor_af(s: &mut String, c: &BgpConnection, p: &BgpParams, afi: Afi) {
    let a = c.remote_address;
    let _ = writeln!(s, "  neighbor {a} activate");
    // G3.9fb: RouterOS `local.role=ibgp-rr`, RFC 4456 §6.
    if p.local_role == Some(LocalRole::IbgpRr) {
        let _ = writeln!(s, "  neighbor {a} route-reflector-client");
    }
    match p.nexthop_choice.unwrap_or_default() {
        NexthopChoice::Default => {}
        NexthopChoice::ForceSelf => {
            let _ = writeln!(s, "  neighbor {a} next-hop-self");
        }
        NexthopChoice::Propagate => {
            let _ = writeln!(s, "  neighbor {a} attribute-unchanged next-hop");
        }
    }
    let limit = match afi {
        Afi::Ip => p.max_prefix_ipv4,
        Afi::Ipv6 => p.max_prefix_ipv6,
    };
    if let Some(n) = limit.filter(|n| *n > 0) {
        match p.max_prefix_action.unwrap_or_default() {
            MaxPrefixAction::Shutdown => {
                let _ = writeln!(s, "  neighbor {a} maximum-prefix {n}");
            }
            MaxPrefixAction::Warning => {
                let _ = writeln!(s, "  neighbor {a} maximum-prefix {n} warning-only");
            }
            MaxPrefixAction::Restart => {
                let m = p
                    .max_prefix_restart
                    .unwrap_or(DEFAULT_RESTART_MINUTES)
                    .max(1);
                let _ = writeln!(s, "  neighbor {a} maximum-prefix {n} restart {m}");
            }
        }
    }
    // G3.2b: the chains. Without one an eBGP neighbor gets and sends
    // nothing (RFC 8212, FRR's `bgp ebgp-requires-policy`, on by default).
    if p.keep_received.unwrap_or(true) {
        let _ = writeln!(s, "  neighbor {a} soft-reconfiguration inbound");
    }
    if let Some(chain) = &p.input_filter {
        let _ = writeln!(
            s,
            "  neighbor {a} route-map {} in",
            filter::frr::route_map(chain)
        );
    }
    if let Some(chain) = &p.output_filter {
        let _ = writeln!(
            s,
            "  neighbor {a} route-map {} out",
            filter::frr::route_map(chain)
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_model::Asn;
    use corerouter_model::bgp::BgpTemplate;

    fn inst(asn: u32, rid: [u8; 4]) -> BgpInstance {
        BgpInstance {
            name: "default".into(),
            asn: Asn(asn),
            router_id: rid.into(),
            disabled: false,
            comment: String::new(),
        }
    }

    fn conn(name: &str, addr: &str, params: BgpParams) -> BgpConnection {
        BgpConnection {
            name: name.into(),
            instance: "default".into(),
            remote_address: addr.parse().unwrap(),
            templates: Vec::new(),
            params,
            disabled: false,
            comment: String::new(),
        }
    }

    fn cfg_with(conns: Vec<BgpConnection>) -> Config {
        let mut cfg = Config::default();
        cfg.routing
            .bgp
            .insert("default".into(), inst(65000, [10, 0, 0, 1]));
        for c in conns {
            cfg.routing.bgp_connections.insert(c.name.clone(), c);
        }
        cfg
    }

    #[test]
    fn rejects_reserved_and_bad_router_id() {
        let mut cfg = Config::default();
        cfg.routing
            .bgp
            .insert("default".into(), inst(23456, [0, 0, 0, 0]));
        let issues = validate(&cfg);
        assert_eq!(issues.len(), 2);
    }

    #[test]
    fn renders_frr() {
        let text = render_frr(&inst(65000, [10, 0, 0, 1]));
        assert!(text.starts_with("router bgp 65000\n"));
        assert!(text.contains(" bgp router-id 10.0.0.1\n"));
        let mut other = inst(65000, [10, 0, 0, 1]);
        other.name = "lab".into();
        assert!(render_frr(&other).starts_with("router bgp 65000 view lab\n"));
    }

    #[test]
    fn renders_neighbors_with_inherited_values() {
        let mut cfg = cfg_with(vec![
            BgpConnection {
                templates: vec!["transit".into()],
                ..conn(
                    "up1",
                    "192.0.2.1",
                    BgpParams {
                        remote_as: Some(Asn(64500)),
                        tcp_md5_key: Some("$cr1$box".into()),
                        ..Default::default()
                    },
                )
            },
            conn(
                "rr1",
                "2001:db8::1",
                BgpParams {
                    local_role: Some(LocalRole::Ibgp),
                    afi: Some(vec![Afi::Ip, Afi::Ipv6]),
                    nexthop_choice: Some(NexthopChoice::ForceSelf),
                    ..Default::default()
                },
            ),
        ]);
        cfg.routing.bgp_templates.insert(
            "transit".into(),
            BgpTemplate {
                name: "transit".into(),
                templates: Vec::new(),
                params: BgpParams {
                    local_role: Some(LocalRole::EbgpProvider),
                    hold_time: Some(90),
                    multihop: Some(true),
                    max_prefix_ipv4: Some(1000),
                    max_prefix_action: Some(MaxPrefixAction::Restart),
                    ..Default::default()
                },
                comment: String::new(),
            },
        );
        assert_eq!(validate(&cfg), Vec::new());
        let open = |s: &Sealed| (s.stored() == "$cr1$box").then(|| "s3cret".to_owned());
        let text = render_all(&cfg.routing, &open).unwrap();
        assert_eq!(
            text,
            "router bgp 65000\n bgp router-id 10.0.0.1\n no bgp default ipv4-unicast\n \
             neighbor 2001:db8::1 remote-as internal\n neighbor 2001:db8::1 description rr1\n \
             neighbor 192.0.2.1 remote-as 64500\n neighbor 192.0.2.1 description up1\n \
             neighbor 192.0.2.1 local-role provider\n neighbor 192.0.2.1 ebgp-multihop\n \
             neighbor 192.0.2.1 timers 30 90\n neighbor 192.0.2.1 password s3cret\n \
             address-family ipv4 unicast\n  neighbor 2001:db8::1 activate\n  \
             neighbor 2001:db8::1 next-hop-self\n  neighbor 2001:db8::1 soft-reconfiguration inbound\n  \
             neighbor 192.0.2.1 activate\n  \
             neighbor 192.0.2.1 maximum-prefix 1000 restart 5\n  \
             neighbor 192.0.2.1 soft-reconfiguration inbound\n exit-address-family\n \
             address-family ipv6 unicast\n  neighbor 2001:db8::1 activate\n  \
             neighbor 2001:db8::1 next-hop-self\n  neighbor 2001:db8::1 soft-reconfiguration inbound\n \
             exit-address-family\nexit\n"
        );
        // A key this router cannot open refuses the render, not a
        // neighbor without its key.
        let e = render_all(&cfg.routing, &|_| None).unwrap_err();
        assert!(e.contains("up1") && !e.contains("box"), "{e}");
    }

    /// G3.9fa/G3.9fb: `output_network`, `output_redistribute` and the
    /// `ibgp-rr` role, in the form `bgpd` 10.7.1 prints them (seen on the
    /// lab VM against RouterOS 7.25).
    #[test]
    fn renders_origination_and_reflection() {
        use corerouter_model::firewall::AddressListEntry;
        use corerouter_model::types::ItemId;
        let mut cfg = cfg_with(vec![
            conn(
                "chr",
                "10.39.1.1",
                BgpParams {
                    remote_as: Some(Asn(65001)),
                    afi: Some(vec![Afi::Ip, Afi::Ipv6]),
                    output_network: Some("bgp-out".into()),
                    output_redistribute: Some(vec![BgpRedistribute::Connected]),
                    ..Default::default()
                },
            ),
            conn(
                "client",
                "10.39.4.2",
                BgpParams {
                    local_role: Some(LocalRole::IbgpRr),
                    output_redistribute: Some(vec![
                        BgpRedistribute::Ospf,
                        BgpRedistribute::Connected,
                    ]),
                    ..Default::default()
                },
            ),
        ]);
        for (id, list, a, disabled) in [
            (1, "bgp-out", "100.64.39.0/24", false),
            (2, "bgp-out", "fd39:64::/48", false),
            (3, "bgp-out", "198.18.39.7", false),
            (4, "bgp-out", "198.18.40.0/24", true),
            (5, "other", "203.0.113.0/24", false),
            (6, "bgp-out", "10.1.1.1-10.1.1.9", false),
        ] {
            cfg.ip.firewall.address_lists.push(AddressListEntry {
                id: ItemId(id),
                list: list.parse().unwrap(),
                address: a.parse().unwrap(),
                disabled,
                comment: String::new(),
            });
        }
        assert_eq!(validate(&cfg), Vec::new());
        let text = render_config(&cfg, &|_| None).unwrap();
        let v4 = text.split(" address-family ipv4 unicast\n").nth(1).unwrap();
        let v4 = v4.split(" exit-address-family").next().unwrap();
        assert_eq!(
            v4,
            "  network 100.64.39.0/24\n  network 198.18.39.7/32\n  redistribute connected\n  \
             redistribute ospf\n  neighbor 10.39.1.1 activate\n  \
             neighbor 10.39.1.1 soft-reconfiguration inbound\n  neighbor 10.39.4.2 activate\n  \
             neighbor 10.39.4.2 route-reflector-client\n  \
             neighbor 10.39.4.2 soft-reconfiguration inbound\n"
        );
        // IPv6: only chr has the family, so only its origination.
        let v6 = text.split(" address-family ipv6 unicast\n").nth(1).unwrap();
        assert!(
            v6.starts_with(
                "  network fd39:64::/48\n  redistribute connected\n  neighbor 10.39.1.1 activate\n"
            ),
            "{v6}"
        );
        assert!(!v6.contains("ospf6"), "{v6}");
        assert!(
            text.contains(" neighbor 10.39.4.2 remote-as internal\n"),
            "ibgp-rr is iBGP: {text}"
        );
        // Without the lists (render_all), no network line.
        assert!(
            !render_all(&cfg.routing, &|_| None)
                .unwrap()
                .contains("  network ")
        );
    }

    /// G3.9fa: CoreRouter's static routes are kernel routes to zebra (the
    /// linux backend installs them, `proto static`): `static` becomes
    /// `redistribute kernel` limited to them (seen on FRR 10.7.1: zebra
    /// lists them as "kernel", `redistribute static` announced nothing).
    #[test]
    fn static_redistribution_and_what_triggers_a_sync() {
        let route = |id: u32, dst: &str, disabled: bool| corerouter_model::RouteEntry {
            id: corerouter_model::ItemId(id),
            dst_address: dst.parse().unwrap(),
            gateway: corerouter_model::Gateway::ip("192.0.2.254".parse().unwrap()),
            distance: 1,
            routing_table: corerouter_model::RoutingTable::Main,
            disabled,
            comment: String::new(),
            check_gateway: Default::default(),
            bfd_profile: String::new(),
        };
        let mut cfg = cfg_with(vec![conn(
            "up",
            "192.0.2.1",
            BgpParams {
                remote_as: Some(Asn(64500)),
                output_redistribute: Some(vec![BgpRedistribute::Static]),
                ..Default::default()
            },
        )]);
        let before = cfg.clone();
        cfg.ip.routes.push(route(1, "198.18.98.0/24", false));
        cfg.ip.routes.push(route(2, "198.18.97.7/24", false));
        cfg.ip.routes.push(route(3, "198.18.96.0/24", true));
        let text = render_config(&cfg, &|_| None).unwrap();
        assert!(
            text.starts_with(
                "ip prefix-list CR-BGP-STATIC4 seq 5 permit 198.18.97.0/24\n\
                 ip prefix-list CR-BGP-STATIC4 seq 10 permit 198.18.98.0/24\n\
                 route-map CR-BGP-STATIC4 permit 10\n match ip address prefix-list CR-BGP-STATIC4\nexit\n"
            ),
            "{text}"
        );
        assert!(
            text.contains("  redistribute kernel route-map CR-BGP-STATIC4\n"),
            "{text}"
        );
        assert!(!text.contains("STATIC6"), "no IPv6 static route: {text}");
        // No static route: no redistribute line, no map.
        let empty = render_config(&before, &|_| None).unwrap();
        assert!(
            !empty.contains("redistribute") && !empty.contains("CR-BGP-STATIC"),
            "{empty}"
        );
        // A static route change matters to BGP only while one redistributes them.
        assert!(networks_changed(&before, &cfg));
        assert!(!networks_changed(&cfg, &cfg.clone()));
        let mut other = before.clone();
        other
            .routing
            .bgp_connections
            .values_mut()
            .for_each(|c| c.params.output_redistribute = None);
        let mut other2 = other.clone();
        other2.ip.routes.push(route(1, "198.18.98.0/24", false));
        assert!(!networks_changed(&other, &other2));
    }

    #[test]
    fn validation_catches_operator_mistakes() {
        let mut cfg = cfg_with(vec![
            conn(
                "reserved",
                "192.0.2.1",
                BgpParams {
                    remote_as: Some(Asn(23456)),
                    ..Default::default()
                },
            ),
            conn(
                "nofamily",
                "192.0.2.2",
                BgpParams {
                    remote_as: Some(Asn(64500)),
                    afi: Some(Vec::new()),
                    ..Default::default()
                },
            ),
            conn("nokind", "192.0.2.3", BgpParams::default()),
            conn(
                "wrongas",
                "192.0.2.4",
                BgpParams {
                    local_role: Some(LocalRole::Ibgp),
                    remote_as: Some(Asn(64500)),
                    ..Default::default()
                },
            ),
            conn(
                "timers",
                "192.0.2.5",
                BgpParams {
                    remote_as: Some(Asn(64500)),
                    hold_time: Some(2),
                    ..Default::default()
                },
            ),
            conn(
                "keepalive",
                "192.0.2.6",
                BgpParams {
                    remote_as: Some(Asn(64500)),
                    hold_time: Some(9),
                    keepalive_time: Some(9),
                    update_source: Some("nope0".into()),
                    ..Default::default()
                },
            ),
            BgpConnection {
                templates: vec!["ghost".into()],
                ..conn("ghost", "192.0.2.7", BgpParams::default())
            },
            conn(
                "zdup",
                "192.0.2.6",
                BgpParams {
                    remote_as: Some(Asn(64500)),
                    ..Default::default()
                },
            ),
            BgpConnection {
                instance: "other".into(),
                ..conn("orphan", "192.0.2.9", BgpParams::default())
            },
        ]);
        for (name, parent) in [("a", "b"), ("b", "a")] {
            cfg.routing.bgp_templates.insert(
                name.into(),
                BgpTemplate {
                    name: name.into(),
                    templates: vec![parent.into()],
                    params: BgpParams::default(),
                    comment: String::new(),
                },
            );
        }
        let issues = validate(&cfg);
        let has = |path: &str, text: &str| {
            issues
                .iter()
                .any(|i| i.path.ends_with(path) && i.message.contains(text))
        };
        assert!(has("reserved.params.remote_as", "reserved"), "{issues:?}");
        assert!(has("nofamily.params.afi", "no address family"));
        assert!(has("nokind.params.local_role", "local_role"));
        assert!(has("wrongas.params.remote_as", "ibgp"));
        assert!(has("timers.params.hold_time", "RFC 4271"));
        assert!(has("keepalive.params.keepalive_time", "not shorter"));
        assert!(has("keepalive.params.update_source", "neither"));
        assert!(has("ghost.templates", "does not exist"));
        assert!(has("zdup.remote_address", "already"));
        assert!(has("orphan.instance", "does not exist"));
        assert!(has("bgp_templates.a.templates", "loop"));
        assert!(has("bgp_templates.b.templates", "loop"));
    }

    #[test]
    fn timers_follow_routeros_defaults() {
        let p = |k, h| BgpParams {
            keepalive_time: k,
            hold_time: h,
            ..Default::default()
        };
        assert_eq!(timers(&p(None, Some(90))), (30, 90));
        assert_eq!(timers(&p(Some(10), None)), (10, 30));
        assert_eq!(timers(&p(Some(5), Some(0))), (5, 0));
    }
}
