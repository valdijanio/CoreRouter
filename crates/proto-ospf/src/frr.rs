//! `routing.ospf` as FRR configuration, in the form `ospfd` and `ospf6d`
//! print it back (`show running-config`), so the diff of `hal-frr` is empty
//! when nothing changed. Read from FRR 10.7.1's own writers
//! (`ospfd/ospf_vty.c` `config_write_*`, `ospf6d/ospf6_interface.c`,
//! `lib/keychain_cli.c`).
//!
//! - Interfaces: one `interface X` context each, with the values of the
//!   template that matched ([`crate::bind`]). `ospf6d` does not print a
//!   value equal to its default, so v3 values equal to the default are
//!   left out (v2 prints what was typed).
//! - Keys: every crypto key goes in a key chain named `CR-…` (`ospfd`
//!   since 10.0, RFC 5709; `ospf6d`, RFC 7166): a template's own
//!   `auth_key` becomes chain `CR-T<id>`, a `/routing ospf keychain K` is
//!   `CR-K-K`. The windows are FRR's `send-lifetime`/`accept-lifetime`,
//!   printed in the box's local time: CoreRouter runs in UTC.
//! - BFD: not typed into FRR. CoreRouter runs its own BFD (G3.6, not
//!   FRR's `bfdd`); the link between its sessions and `ospfd` is G3.6b.
//! - Redistribution: one route-map per instance and kind
//!   (`CR-O<version>-<inst>-<kind>`): the subscriber pools first (G4.3ce), then
//!   the `out_filter_chain` compiled by the `/routing filter` compiler
//!   (G3.2b), or a plain permit.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write as _;

use corerouter_model::Config;
use corerouter_model::ospf::{
    AuthType, NetworkType, OriginateDefault, OspfInstance, OspfKey, OspfTemplate, Redistribute,
    Version,
};
use corerouter_model::sealed::Sealed;
use corerouter_model::types::ItemId;
use ipnet::Ipv4Net;

use crate::bind::{Binding, bindings};
use crate::chain::{self, Compiled};
use crate::pools;

/// Opens a sealed key; `None`: it cannot be opened here.
pub type Opener<'a> = &'a dyn Fn(&Sealed) -> Option<String>;

/// ospf6d's defaults (`ospf6d/ospf6_interface.h`): a value equal to one is
/// not printed back.
const V3_HELLO: u16 = 10;
const V3_DEAD: u16 = 40;
const V3_RXMT: u16 = 5;
const V3_PRIORITY: u8 = 1;
const V3_TRANSDELAY: u16 = 1;
const V3_INSTANCE_ID: u8 = 0;

/// The key chain of template `id`'s own key.
pub fn template_chain(id: ItemId) -> String {
    format!("CR-T{:X}", id.0)
}

/// The key chain of `/routing ospf keychain name`.
pub fn keychain_name(name: &str) -> String {
    format!("CR-K-{name}")
}

/// The route-map an instance redistributes `kind` through (`CR-O2-…` goes
/// to ospfd, `CR-O3-…` to ospf6d: `hal-frr` routes them by the prefix).
pub fn route_map(inst: &OspfInstance, kind: Redistribute) -> String {
    format!(
        "CR-O{}-{}-{}",
        inst.version.number(),
        inst.name,
        kind.name()
    )
}

/// The prefix-list of the subscriber pools of a v2 instance.
pub fn pools_list(inst: &str) -> String {
    format!("CR-O2-{inst}-POOLS")
}

/// FRR's router header of an instance.
pub fn header(inst: &OspfInstance) -> String {
    let kw = match inst.version {
        Version::V2 => "router ospf",
        Version::V3 => "router ospf6",
    };
    if inst.vrf == corerouter_model::ospf::MAIN_VRF {
        kw.to_owned()
    } else {
        format!("{kw} vrf {}", inst.vrf)
    }
}

/// Everything OSPF of `cfg`, as FRR text. `Err`: a key that does not open.
pub fn render(cfg: &Config, open: Opener<'_>) -> Result<String, String> {
    let ospf = &cfg.routing.ospf;
    if ospf.instances.is_empty() {
        return Ok(String::new());
    }
    let mut s = String::new();
    let binds = bindings(cfg);
    // Key chains: the named ones every template refers to, and the
    // templates' own keys.
    let mut used_chains: BTreeSet<&str> = BTreeSet::new();
    let mut own_keys: BTreeMap<ItemId, &OspfTemplate> = BTreeMap::new();
    let vlinks: Vec<&OspfTemplate> = ospf
        .templates
        .iter()
        .filter(|t| !t.disabled && t.kind == NetworkType::VirtualLink)
        .collect();
    for t in binds
        .iter()
        .map(|b| b.template)
        .chain(vlinks.iter().copied())
    {
        match (&t.keychain, t.auth) {
            (Some(k), Some(a)) if a.is_crypto() => {
                used_chains.insert(k.as_str());
            }
            (None, Some(a)) if a.is_crypto() && t.has_key() => {
                own_keys.insert(t.id, t);
            }
            _ => {}
        }
    }
    for name in &used_chains {
        if let Some(kc) = ospf.keychains.get(*name) {
            key_chain(&mut s, &keychain_name(name), &kc.keys, open)?;
        }
    }
    for t in own_keys.values() {
        let key = OspfKey {
            id: t.auth_id.unwrap_or(1),
            algorithm: t.auth.unwrap_or(AuthType::DEFAULT),
            key_string: t.auth_key.clone(),
            send_from: None,
            send_until: None,
            accept_from: None,
            accept_until: None,
        };
        key_chain(
            &mut s,
            &template_chain(t.id),
            std::slice::from_ref(&key),
            open,
        )?;
    }
    // Redistribution policy.
    let compiled = chain::compile_used(cfg);
    let pools = pools::cidrs(cfg);
    for inst in ospf.instances.values().filter(|i| !i.disabled) {
        redistribution_maps(&mut s, inst, &pools, &compiled);
    }
    // Interfaces, one context each (both versions share it).
    let mut by_iface: BTreeMap<&str, Vec<&Binding<'_>>> = BTreeMap::new();
    for b in &binds {
        by_iface.entry(b.interface.as_str()).or_default().push(b);
    }
    for (name, bs) in &by_iface {
        let mut body = String::new();
        for b in bs {
            match b.instance.version {
                Version::V2 => iface_v2(&mut body, b, open)?,
                Version::V3 => iface_v3(&mut body, b),
            }
        }
        if !body.is_empty() {
            let _ = writeln!(s, "interface {name}");
            s.push_str(&body);
            let _ = writeln!(s, "exit");
        }
    }
    for inst in ospf.instances.values() {
        router(&mut s, cfg, inst, &pools, &vlinks);
    }
    Ok(s)
}

fn key_chain(s: &mut String, name: &str, keys: &[OspfKey], open: Opener<'_>) -> Result<(), String> {
    let _ = writeln!(s, "key chain {name}");
    let mut keys: Vec<&OspfKey> = keys.iter().collect();
    keys.sort_by_key(|k| k.id);
    for k in keys {
        let text = open(&k.key_string).ok_or_else(|| {
            format!(
                "OSPF key {} of key chain {name} cannot be opened here",
                k.id
            )
        })?;
        let _ = writeln!(s, " key {}", k.id);
        let _ = writeln!(s, "  key-string {text}");
        let _ = writeln!(
            s,
            "  cryptographic-algorithm {}",
            k.algorithm.frr_algorithm()
        );
        if let Some(l) = lifetime(k.send_from, k.send_until) {
            let _ = writeln!(s, "  send-lifetime {l}");
        }
        if let Some(l) = lifetime(k.accept_from, k.accept_until) {
            let _ = writeln!(s, "  accept-lifetime {l}");
        }
        let _ = writeln!(s, " exit");
    }
    let _ = writeln!(s, "exit");
    Ok(())
}

/// The earliest start FRR takes (`(1993-2035)` in `lib/keychain_cli.c`).
pub const FRR_FIRST: u64 = 725_846_400; // 1993-01-01 00:00:00 UTC
/// One past the last second FRR takes (2036-01-01 00:00:00 UTC).
pub const FRR_END: u64 = 2_082_758_400;

/// FRR's lifetime text for a window, as `keychain_cli.c` prints it
/// (`%T %b %e %Y`, `infinite` without an end). `None`: always valid (no
/// line).
pub fn lifetime(from: Option<u64>, until: Option<u64>) -> Option<String> {
    if from.is_none() && until.is_none() {
        return None;
    }
    let start = date(from.unwrap_or(FRR_FIRST));
    Some(match until {
        None => format!("{start} infinite"),
        Some(u) => format!("{start} {}", date(u)),
    })
}

/// `%T %b %e %Y` of a Unix time, in UTC (`%e`: the day padded with a
/// space).
pub fn date(t: u64) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let days = t / 86_400;
    let secs = t % 86_400;
    let (y, m, d) = civil(days);
    let month = MONTHS
        .get(usize::from(m.saturating_sub(1)))
        .copied()
        .unwrap_or("Jan");
    format!(
        "{:02}:{:02}:{:02} {month} {d:>2} {y}",
        secs / 3600,
        (secs / 60) % 60,
        secs % 60
    )
}

/// Year, month (1..=12) and day of `days` since 1970-01-01 (H. Hinnant's
/// `civil_from_days`).
fn civil(days: u64) -> (u64, u8, u8) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + u64::from(m <= 2);
    (
        y,
        u8::try_from(m).unwrap_or(1),
        u8::try_from(d).unwrap_or(1),
    )
}

fn iface_v2(s: &mut String, b: &Binding<'_>, open: Opener<'_>) -> Result<(), String> {
    let t = b.template;
    // A passive interface has no neighbor, so its type only decides what
    // is advertised: ospfd takes a /32 on a point-to-point interface (a
    // loopback in a ptp template) as unnumbered and never advertises it
    // (lab VM, FRR 10.7.1: the LDP session to that loopback never came
    // up). Broadcast advertises the stub network either way.
    let kind = match t.kind {
        NetworkType::Ptp if t.passive => NetworkType::Broadcast,
        k => k,
    };
    // The kernel's own loopback takes no network type ("This is a loopback
    // interface. Can't set network type.", ospfd, lab VM, FRR 10.7.1: met
    // with a prefix SID, G3.4f).
    if let Some(n) = network_v2(kind).filter(|_| !kernel_loopback(b)) {
        let _ = writeln!(s, " ip ospf network {n}");
    }
    match t.auth {
        Some(AuthType::Simple) => {
            let key = open(&t.auth_key).ok_or_else(|| {
                format!(
                    "the OSPF key of interface template {} cannot be opened here",
                    t.id
                )
            })?;
            let _ = writeln!(s, " ip ospf authentication");
            let _ = writeln!(s, " ip ospf authentication-key {key}");
        }
        Some(_) => {
            if let Some(chain) = auth_chain(t) {
                let _ = writeln!(s, " ip ospf authentication key-chain {chain}");
            }
        }
        None => {}
    }
    if let Some(c) = t.cost {
        let _ = writeln!(s, " ip ospf cost {c}");
    }
    if let Some(h) = t.hello_interval {
        let _ = writeln!(s, " ip ospf hello-interval {h}");
    }
    if let Some(d) = t.dead_interval {
        let _ = writeln!(s, " ip ospf dead-interval {d}");
    }
    if let Some(p) = t.priority {
        let _ = writeln!(s, " ip ospf priority {p}");
    }
    if let Some(r) = t.retransmit_interval {
        let _ = writeln!(s, " ip ospf retransmit-interval {r}");
    }
    if let Some(d) = t.transmit_delay {
        let _ = writeln!(s, " ip ospf transmit-delay {d}");
    }
    let _ = writeln!(s, " ip ospf area {}", b.area.area_id);
    if t.mtu_ignore {
        let _ = writeln!(s, " ip ospf mtu-ignore");
    }
    if t.passive {
        let _ = writeln!(s, " ip ospf passive");
    }
    Ok(())
}

fn iface_v3(s: &mut String, b: &Binding<'_>) {
    let t = b.template;
    let _ = writeln!(s, " ipv6 ospf6 area {}", b.area.area_id);
    if let Some(c) = t.cost {
        let _ = writeln!(s, " ipv6 ospf6 cost {c}");
    }
    let differs = |v: Option<u16>, d: u16| v.filter(|v| *v != d);
    if let Some(h) = differs(t.hello_interval, V3_HELLO) {
        let _ = writeln!(s, " ipv6 ospf6 hello-interval {h}");
    }
    if let Some(d) = differs(t.dead_interval, V3_DEAD) {
        let _ = writeln!(s, " ipv6 ospf6 dead-interval {d}");
    }
    if let Some(r) = differs(t.retransmit_interval, V3_RXMT) {
        let _ = writeln!(s, " ipv6 ospf6 retransmit-interval {r}");
    }
    if let Some(p) = t.priority.filter(|p| *p != V3_PRIORITY) {
        let _ = writeln!(s, " ipv6 ospf6 priority {p}");
    }
    if let Some(d) = differs(t.transmit_delay, V3_TRANSDELAY) {
        let _ = writeln!(s, " ipv6 ospf6 transmit-delay {d}");
    }
    if let Some(i) = t.instance_id.filter(|i| *i != V3_INSTANCE_ID) {
        let _ = writeln!(s, " ipv6 ospf6 instance-id {i}");
    }
    if t.passive {
        let _ = writeln!(s, " ipv6 ospf6 passive");
    }
    if t.mtu_ignore {
        let _ = writeln!(s, " ipv6 ospf6 mtu-ignore");
    }
    match t.kind {
        _ if kernel_loopback(b) => {}
        NetworkType::Ptp => {
            let _ = writeln!(s, " ipv6 ospf6 network point-to-point");
        }
        NetworkType::Ptmp => {
            let _ = writeln!(s, " ipv6 ospf6 network point-to-multipoint");
        }
        _ => {}
    }
    if t.auth.is_some_and(AuthType::is_crypto)
        && let Some(chain) = auth_chain(t)
    {
        let _ = writeln!(s, " ipv6 ospf6 authentication keychain {chain}");
    }
}

/// Linux's `lo` (IFF_LOOPBACK): FRR refuses a network type on it.
fn kernel_loopback(b: &Binding<'_>) -> bool {
    b.interface.as_str() == "lo"
}

/// The key chain a crypto template authenticates with.
fn auth_chain(t: &OspfTemplate) -> Option<String> {
    match &t.keychain {
        Some(k) => Some(keychain_name(k)),
        None => t.has_key().then(|| template_chain(t.id)),
    }
}

/// `ip ospf network …` of a type (`broadcast` is the default and written
/// anyway: a /31 on Ethernet would otherwise be guessed by FRR).
fn network_v2(t: NetworkType) -> Option<&'static str> {
    match t {
        NetworkType::Broadcast => Some("broadcast"),
        NetworkType::Ptp => Some("point-to-point"),
        NetworkType::Nbma => Some("non-broadcast"),
        NetworkType::Ptmp => Some("point-to-multipoint"),
        NetworkType::VirtualLink => None,
    }
}

/// The kinds instance `inst` redistributes, with the subscriber pools'
/// kinds (a PPP session's address is a connected route, an IPoE lease a
/// kernel route).
pub fn kinds(inst: &OspfInstance, pools: &[Ipv4Net]) -> BTreeSet<Redistribute> {
    let mut k: BTreeSet<Redistribute> = inst.redistribute.iter().copied().collect();
    if announces_pools(inst, pools) {
        k.insert(Redistribute::Connected);
        k.insert(Redistribute::Kernel);
    }
    k
}

/// Whether instance `inst` announces the subscriber pools.
fn announces_pools(inst: &OspfInstance, pools: &[Ipv4Net]) -> bool {
    inst.subscriber_pools && inst.version == Version::V2 && !pools.is_empty()
}

/// Whether instance `inst` needs a route-map for `kind`.
fn needs_map(inst: &OspfInstance, pools: &[Ipv4Net], kind: Redistribute) -> bool {
    let p = announces_pools(inst, pools)
        && matches!(kind, Redistribute::Connected | Redistribute::Kernel);
    p || (inst.out_filter_chain.is_some() && inst.redistribute.contains(&kind))
}

fn redistribution_maps(
    s: &mut String,
    inst: &OspfInstance,
    pools: &[Ipv4Net],
    compiled: &HashMap<String, Compiled>,
) {
    let cidrs: &[Ipv4Net] = if announces_pools(inst, pools) {
        pools
    } else {
        &[]
    };
    let v6 = inst.version == Version::V3;
    if !cidrs.is_empty() {
        let list = pools_list(&inst.name);
        for (i, c) in cidrs.iter().enumerate() {
            let _ = writeln!(
                s,
                "ip prefix-list {list} seq {} permit {c} le 32",
                (i + 1) * 5
            );
        }
    }
    let chain = inst
        .out_filter_chain
        .as_deref()
        .and_then(|c| compiled.get(c));
    if let Some(c) = chain {
        c.lists_text(s, v6);
    }
    for kind in kinds(inst, pools) {
        if !needs_map(inst, pools, kind) {
            continue;
        }
        let name = route_map(inst, kind);
        let pools_here =
            !cidrs.is_empty() && matches!(kind, Redistribute::Connected | Redistribute::Kernel);
        if pools_here {
            let _ = writeln!(s, "route-map {name} permit 1");
            let _ = writeln!(
                s,
                " match ip address prefix-list {}",
                pools_list(&inst.name)
            );
            let _ = writeln!(s, "exit");
        }
        if inst.redistribute.contains(&kind) {
            match chain {
                Some(c) => c.map_text(&name, s),
                None => {
                    let _ = writeln!(s, "route-map {name} permit {}", chain::END_SEQ);
                    let _ = writeln!(s, "exit");
                }
            }
        }
    }
}

fn router(
    s: &mut String,
    cfg: &Config,
    inst: &OspfInstance,
    pools: &[Ipv4Net],
    vlinks: &[&OspfTemplate],
) {
    let ospf = &cfg.routing.ospf;
    let v2 = inst.version == Version::V2;
    // ospfd keeps a disabled instance with `shutdown`; ospf6d has no such
    // switch, so a disabled v3 instance is not rendered at all.
    if inst.disabled && !v2 {
        return;
    }
    let _ = writeln!(s, "{}", header(inst));
    if let Some(r) = inst.router_id {
        let _ = writeln!(s, " {} router-id {r}", if v2 { "ospf" } else { "ospf6" });
    }
    for kind in kinds(inst, pools) {
        let mut l = format!(" redistribute {}", kind.name());
        if needs_map(inst, pools, kind) {
            let _ = write!(l, " route-map {}", route_map(inst, kind));
        }
        let _ = writeln!(s, "{l}");
    }
    if announces_pools(inst, pools) {
        for c in pools {
            let _ = writeln!(s, " summary-address {c}");
        }
    }
    let areas: Vec<_> = ospf
        .areas
        .values()
        .filter(|a| a.instance == inst.name && !a.disabled)
        .collect();
    if v2 {
        for a in &areas {
            area_v2(s, a, ospf);
        }
        for n in ospf
            .static_neighbors
            .iter()
            .filter(|n| n.instance == inst.name && !n.disabled)
        {
            match n.poll_interval {
                Some(p) => {
                    let _ = writeln!(s, " neighbor {} poll-interval {p}", n.address);
                }
                None => {
                    let _ = writeln!(s, " neighbor {}", n.address);
                }
            }
        }
        for t in vlinks {
            let transit = t
                .vlink_transit_area
                .as_deref()
                .and_then(|n| ospf.areas.get(n));
            let (Some(transit), Some(peer)) = (transit, t.vlink_neighbor_id) else {
                continue;
            };
            if transit.instance != inst.name || transit.disabled {
                continue;
            }
            let _ = writeln!(s, " area {} virtual-link {peer}", transit.area_id);
        }
    } else {
        for a in &areas {
            area_v3(s, a, ospf);
        }
    }
    match inst.originate_default {
        OriginateDefault::Never => {}
        OriginateDefault::IfInstalled => {
            let _ = writeln!(s, " default-information originate");
        }
        OriginateDefault::Always => {
            let _ = writeln!(s, " default-information originate always");
        }
    }
    // G3.4f: Segment Routing (only the instance that runs it).
    for l in crate::sr::router_lines(cfg, inst) {
        let _ = writeln!(s, " {l}");
    }
    if inst.disabled && v2 {
        let _ = writeln!(s, " shutdown");
    }
    let _ = writeln!(s, "exit");
}

fn ranges<'a>(
    ospf: &'a corerouter_model::ospf::Ospf,
    area: &'a str,
) -> impl Iterator<Item = &'a corerouter_model::ospf::OspfAreaRange> + 'a {
    ospf.ranges
        .iter()
        .filter(move |r| r.area == area && !r.disabled)
}

fn area_v2(
    s: &mut String,
    a: &corerouter_model::ospf::OspfArea,
    ospf: &corerouter_model::ospf::Ospf,
) {
    use corerouter_model::ospf::{AreaType, NssaTranslate};
    let id = a.area_id;
    for r in ranges(ospf, &a.name) {
        let mut l = format!(" area {id} range {}", r.prefix);
        if let Some(c) = r.cost {
            let _ = write!(l, " cost {c}");
        }
        if !r.advertise {
            l.push_str(" not-advertise");
        }
        let _ = writeln!(s, "{l}");
    }
    match a.kind {
        AreaType::Default => {}
        AreaType::Stub => {
            let _ = writeln!(
                s,
                " area {id} stub{}",
                if a.no_summaries { " no-summary" } else { "" }
            );
        }
        AreaType::Nssa => {
            let mut l = format!(" area {id} nssa");
            match a.nssa_translate {
                NssaTranslate::Candidate => {}
                NssaTranslate::Yes => l.push_str(" translate-always"),
                NssaTranslate::No => l.push_str(" translate-never"),
            }
            if a.no_summaries {
                l.push_str(" no-summary");
            }
            let _ = writeln!(s, "{l}");
        }
    }
    if a.kind != AreaType::Default
        && let Some(c) = a.default_cost
    {
        let _ = writeln!(s, " area {id} default-cost {c}");
    }
}

fn area_v3(
    s: &mut String,
    a: &corerouter_model::ospf::OspfArea,
    ospf: &corerouter_model::ospf::Ospf,
) {
    use corerouter_model::ospf::AreaType;
    let id = a.area_id;
    for r in ranges(ospf, &a.name) {
        let mut l = format!(" area {id} range {}", r.prefix);
        if !r.advertise {
            l.push_str(" not-advertise");
        } else if let Some(c) = r.cost {
            let _ = write!(l, " cost {c}");
        }
        let _ = writeln!(s, "{l}");
    }
    match a.kind {
        AreaType::Default => {}
        AreaType::Stub => {
            let _ = writeln!(
                s,
                " area {id} stub{}",
                if a.no_summaries { " no-summary" } else { "" }
            );
        }
        AreaType::Nssa => {
            let _ = writeln!(
                s,
                " area {id} nssa{}",
                if a.no_summaries { " no-summary" } else { "" }
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::sample;

    #[test]
    fn dates_print_like_strftime() {
        // 2026-10-01 12:34:56 UTC.
        assert_eq!(date(1_790_858_096), "12:34:56 Oct  1 2026");
        assert_eq!(date(0), "00:00:00 Jan  1 1970");
        assert_eq!(date(FRR_FIRST), "00:00:00 Jan  1 1993");
        assert_eq!(date(FRR_END - 1), "23:59:59 Dec 31 2035");
        // A leap day.
        assert_eq!(date(951_782_400), "00:00:00 Feb 29 2000");
        assert_eq!(lifetime(None, None), None);
        assert_eq!(
            lifetime(Some(0), None).unwrap(),
            "00:00:00 Jan  1 1970 infinite"
        );
    }

    #[test]
    fn renders_interfaces_keys_and_router() {
        let cfg = sample();
        let text = render(&cfg, &|s| Some(s.stored().to_owned())).unwrap();
        assert!(
            text.contains("interface ether1\n ip ospf network broadcast\n"),
            "{text}"
        );
        assert!(
            text.contains(" ip ospf authentication key-chain CR-T1\n"),
            "{text}"
        );
        assert!(text.contains("key chain CR-T1\n key 1\n  key-string s3cret\n  cryptographic-algorithm hmac-sha-256\n exit\nexit\n"), "{text}");
        assert!(text.contains(" ip ospf area 0.0.0.0\n"), "{text}");
        // ether2 is a passive point-to-point (a loopback in a ptp
        // template): broadcast, or ospfd never advertises a /32 there.
        assert!(
            text.contains("interface ether2\n ip ospf network broadcast\n"),
            "{text}"
        );
        let mut cfg = sample();
        for t in &mut cfg.routing.ospf.templates {
            t.passive = false;
        }
        let text = render(&cfg, &|s| Some(s.stored().to_owned())).unwrap();
        assert!(
            text.contains("interface ether2\n ip ospf network point-to-point\n"),
            "{text}"
        );
        assert!(text.contains("router ospf\n ospf router-id 10.255.0.1\n redistribute connected\n area 0.0.0.1 stub no-summary\n"), "{text}");
        // The render parses as the FRR tree hal-frr diffs.
        assert!(!text.contains('\t'));
    }

    #[test]
    fn pools_and_filter_chain_redistribution() {
        use corerouter_model::ip_pool::{IpPool, PoolRange};
        use corerouter_model::ppp::{AddrOrPool, PppProfile};
        use corerouter_model::routing_filter::FilterRule;
        let mut cfg = sample();
        cfg.ip.pools.pools.push(IpPool {
            id: ItemId(1),
            name: "subs".into(),
            ranges: vec![PoolRange::new([100, 64, 0, 1].into(), [100, 64, 3, 254].into()).unwrap()],
            next_pool: None,
            comment: String::new(),
        });
        cfg.ppp.profiles.push(PppProfile {
            name: "p".into(),
            remote_address: Some(AddrOrPool::Pool("subs".into())),
            ..PppProfile::default()
        });
        cfg.routing.filter.rules.push(FilterRule {
            id: ItemId(1),
            chain: "ospf-out".into(),
            rule: "if (dst in 10.0.0.0/8) { set bgp-med 20; accept }".into(),
            disabled: false,
            comment: String::new(),
        });
        if let Some(i) = cfg.routing.ospf.instances.get_mut("v2") {
            i.subscriber_pools = true;
            i.out_filter_chain = Some("ospf-out".into());
        }
        assert_eq!(crate::validate(&cfg), Vec::new());
        let text = render(&cfg, &|s| Some(s.stored().to_owned())).unwrap();
        assert!(
            text.contains("ip prefix-list CR-O2-v2-POOLS seq 5 permit 100.64.0.0/22 le 32\n"),
            "{text}"
        );
        assert!(text.contains(" summary-address 100.64.0.0/22\n"), "{text}");
        assert!(
            text.contains(" redistribute connected route-map CR-O2-v2-connected\n"),
            "{text}"
        );
        assert!(
            text.contains(" redistribute kernel route-map CR-O2-v2-kernel\n"),
            "{text}"
        );
        assert!(text.contains("route-map CR-O2-v2-connected permit 1\n match ip address prefix-list CR-O2-v2-POOLS\n"), "{text}");
        assert!(text.contains(" set metric 20\n"), "{text}");
        assert!(text.contains("ip prefix-list CR-O2-P-"), "{text}");
        assert!(
            !text.contains("CR-P-"),
            "BGP's list names stay in bgpd: {text}"
        );
        // A chain with a BGP-only test is refused before the commit.
        cfg.routing.filter.rules[0].rule = "if (bgp-as-path \"^65000_\") { accept }".into();
        let v = crate::validate(&cfg);
        assert!(v.iter().any(|i| i.message.contains("AS path")), "{v:?}");
    }

    #[test]
    fn a_key_that_does_not_open_fails_the_render() {
        let cfg = sample();
        let e = render(&cfg, &|_| None).unwrap_err();
        assert!(e.contains("cannot be opened"), "{e}");
        assert!(!e.contains("s3cret"));
    }
}
