//! OSPF state read from `ospfd` and `ospf6d` (G3.4b): neighbors
//! (`show ip ospf neighbor json`, `show ipv6 ospf6 neighbor json`),
//! interfaces (`show ip ospf interface json`) and the link-state database
//! (`show ip ospf database router|network|summary|external json`).
//!
//! The JSON is the daemon's (field names from FRR 10.7.1's
//! `ospfd/ospf_vty.c` and `ospf6d/ospf6_neighbor.c`), read leniently: a
//! missing or oddly typed field is `None`, never an error. The LSDB is
//! read as it streams from the socket into the compact
//! `corerouter_model::ospf_state::Lsdb` (one fixed row per LSA, the
//! router links in one flat array), so 10 000 LSAs never sit in memory as
//! a JSON tree; numbers in `docs/ospf.md`.

use std::fmt;
use std::io::Read;
use std::net::Ipv4Addr;

use corerouter_model::ospf_state::{
    Link, Lsa, Lsdb, MaxLsaState, OspfIfState, OspfNeighbor, OspfRoute, OspfStubState,
};
use serde::Deserialize;
use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};

use crate::loose::{self, Dict, List, Loose, Obj, bool_of, text, u32_of, u64_of};

/// Most LSAs kept from one database (a large single area is ~10 000,
/// **estimado**; past this they are counted in `dropped`).
pub const MAX_LSAS: usize = 500_000;
/// Most links of one router LSA (RFC 2328: 16-bit count).
const MAX_LINKS: usize = 65_535;

/// FRR's `timerstring`/`ospf_timeval_dump` durations: `00:01:23`,
/// `1d02h03m`, `5w2d03h`, `12.345s`.
pub fn secs(text: &str) -> Option<u64> {
    let t = text.trim();
    if t.contains(':') {
        let mut total = 0u64;
        for part in t.split(':') {
            total = total
                .checked_mul(60)?
                .checked_add(part.trim().parse::<f64>().ok()? as u64)?;
        }
        return Some(total);
    }
    let mut total = 0u64;
    let mut num = String::new();
    for c in t.chars() {
        if c.is_ascii_digit() || c == '.' {
            num.push(c);
            continue;
        }
        let v = num.parse::<f64>().ok()? as u64;
        num.clear();
        let mult = match c {
            'w' => 604_800,
            'd' => 86_400,
            'h' => 3_600,
            'm' => 60,
            's' => 1,
            _ => return None,
        };
        total = total.checked_add(v.checked_mul(mult)?)?;
    }
    num.is_empty().then_some(total)
}

// G3.4n: the answers are read into the few fields kept (`crate::loose`),
// not into a `serde_json::Value` tree: 4 000 interfaces in 15.2 → see
// docs/ospf.md (**medido**).

#[derive(Deserialize, Default)]
#[serde(default)]
struct NbrsV2<'a> {
    #[serde(borrow)]
    neighbors: Dict<'a, List<NbrV2<'a>>>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct NbrV2<'a> {
    #[serde(borrow)]
    nbr_state: Option<Loose<'a>>,
    #[serde(borrow)]
    role: Option<Loose<'a>>,
    #[serde(borrow)]
    iface_name: Option<Loose<'a>>,
    #[serde(borrow)]
    iface_address: Option<Loose<'a>>,
    #[serde(borrow)]
    area_id: Option<Loose<'a>>,
    #[serde(borrow)]
    area: Option<Loose<'a>>,
    #[serde(borrow)]
    converged: Option<Loose<'a>>,
    #[serde(borrow)]
    nbr_priority: Option<Loose<'a>>,
    #[serde(borrow)]
    up_time_in_msec: Option<Loose<'a>>,
    #[serde(borrow)]
    router_dead_interval_timer_due_msec: Option<Loose<'a>>,
    #[serde(borrow)]
    link_state_retransmission_list_counter: Option<Loose<'a>>,
    #[serde(borrow)]
    link_state_request_list_counter: Option<Loose<'a>>,
    #[serde(borrow)]
    database_summary_list_counter: Option<Loose<'a>>,
}

/// `show ip ospf neighbor json` of instance `instance`.
pub fn neighbors_v2(json: impl AsRef<[u8]>, instance: &str) -> Result<Vec<OspfNeighbor>, String> {
    let top: Obj<NbrsV2<'_>> = loose::parse(json.as_ref(), "ospfd")?;
    let mut out = Vec::new();
    let Some(top) = top.0 else { return Ok(out) };
    for (id, list) in &top.neighbors.0 {
        for m in &list.0 {
            let full = text(&m.nbr_state).unwrap_or_default();
            let (state, role) = match full.split_once('/') {
                Some((a, b)) => (a.to_owned(), b.to_owned()),
                None => (full.clone(), text(&m.role).unwrap_or_default()),
            };
            let iface = text(&m.iface_name).unwrap_or_default();
            out.push(OspfNeighbor {
                instance: instance.to_owned(),
                version: 2,
                router_id: if id == "neighbor" {
                    String::new()
                } else {
                    id.chars().take(128).collect()
                },
                address: text(&m.iface_address).unwrap_or_default(),
                // `eth0:10.0.0.1` in older daemons.
                interface: iface.split(':').next().unwrap_or_default().to_owned(),
                area: text(&m.area_id).or_else(|| text(&m.area)),
                state: text(&m.converged).unwrap_or(state),
                role,
                priority: u32_of(&m.nbr_priority),
                state_secs: u64_of(&m.up_time_in_msec).map(|ms| ms / 1000),
                dead_secs: u64_of(&m.router_dead_interval_timer_due_msec).map(|ms| ms / 1000),
                bfd: None,
                retransmit: u64_of(&m.link_state_retransmission_list_counter).unwrap_or(0),
                request: u64_of(&m.link_state_request_list_counter).unwrap_or(0),
                summary: u64_of(&m.database_summary_list_counter).unwrap_or(0),
            });
        }
    }
    out.sort_by(|a, b| (&a.interface, &a.router_id).cmp(&(&b.interface, &b.router_id)));
    Ok(out)
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct NbrsV3<'a> {
    #[serde(borrow)]
    neighbors: List<NbrV3<'a>>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct NbrV3<'a> {
    #[serde(borrow)]
    neighbor_id: Option<Loose<'a>>,
    #[serde(borrow)]
    link_local_address: Option<Loose<'a>>,
    #[serde(borrow)]
    interface_name: Option<Loose<'a>>,
    #[serde(borrow)]
    area: Option<Loose<'a>>,
    #[serde(borrow)]
    state: Option<Loose<'a>>,
    #[serde(borrow)]
    if_state: Option<Loose<'a>>,
    #[serde(borrow)]
    priority: Option<Loose<'a>>,
    #[serde(borrow)]
    duration: Option<Loose<'a>>,
    #[serde(borrow)]
    dead_time: Option<Loose<'a>>,
}

/// `show ipv6 ospf6 neighbor json`.
pub fn neighbors_v3(json: impl AsRef<[u8]>, instance: &str) -> Result<Vec<OspfNeighbor>, String> {
    let top: Obj<NbrsV3<'_>> = loose::parse(json.as_ref(), "ospf6d")?;
    let Some(top) = top.0 else {
        return Ok(Vec::new());
    };
    let mut out: Vec<OspfNeighbor> = top
        .neighbors
        .0
        .iter()
        .map(|m| OspfNeighbor {
            instance: instance.to_owned(),
            version: 3,
            router_id: text(&m.neighbor_id).unwrap_or_default(),
            address: text(&m.link_local_address).unwrap_or_default(),
            interface: text(&m.interface_name).unwrap_or_default(),
            area: text(&m.area),
            state: text(&m.state).unwrap_or_default(),
            role: text(&m.if_state).unwrap_or_default(),
            priority: u32_of(&m.priority),
            state_secs: text(&m.duration).and_then(|d| secs(&d)),
            dead_secs: text(&m.dead_time).and_then(|d| secs(&d)),
            bfd: None,
            retransmit: 0,
            request: 0,
            summary: 0,
        })
        .collect();
    out.sort_by(|a, b| (&a.interface, &a.router_id).cmp(&(&b.interface, &b.router_id)));
    Ok(out)
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Ifs<'a> {
    #[serde(borrow)]
    interfaces: Dict<'a, Obj<IfV2<'a>>>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct IfV2<'a> {
    #[serde(borrow)]
    ospf_enabled: Option<Loose<'a>>,
    #[serde(borrow)]
    area: Option<Loose<'a>>,
    #[serde(borrow)]
    network_type: Option<Loose<'a>>,
    #[serde(borrow)]
    state: Option<Loose<'a>>,
    #[serde(borrow)]
    ip_address: Option<Loose<'a>>,
    #[serde(borrow)]
    ip_address_prefixlen: Option<Loose<'a>>,
    #[serde(borrow)]
    cost: Option<Loose<'a>>,
    #[serde(borrow)]
    mtu_bytes: Option<Loose<'a>>,
    #[serde(borrow)]
    mtu_mismatch_detect: Option<Loose<'a>>,
    #[serde(borrow)]
    timer_hello_in_msecs: Option<Loose<'a>>,
    #[serde(borrow)]
    timer_dead_secs: Option<Loose<'a>>,
    #[serde(borrow)]
    dr_id: Option<Loose<'a>>,
    #[serde(borrow)]
    bdr_id: Option<Loose<'a>>,
    #[serde(borrow)]
    timer_passive_iface: Option<Loose<'a>>,
    #[serde(borrow)]
    nbr_count: Option<Loose<'a>>,
    #[serde(borrow)]
    nbr_adjacent_count: Option<Loose<'a>>,
}

/// `show ip ospf interface json`.
pub fn interfaces_v2(json: impl AsRef<[u8]>, instance: &str) -> Result<Vec<OspfIfState>, String> {
    let top: Obj<Ifs<'_>> = loose::parse(json.as_ref(), "ospfd")?;
    let Some(top) = top.0 else {
        return Ok(Vec::new());
    };
    let mut out = Vec::with_capacity(top.interfaces.0.len());
    for (name, m) in &top.interfaces.0 {
        let Some(m) = &m.0 else { continue };
        if bool_of(&m.ospf_enabled) == Some(false) {
            continue;
        }
        out.push(OspfIfState {
            instance: instance.to_owned(),
            version: 2,
            interface: name.chars().take(128).collect(),
            area: text(&m.area).map(|a| a.split(' ').next().unwrap_or_default().to_owned()),
            network_type: text(&m.network_type),
            state: text(&m.state),
            address: match (text(&m.ip_address), u64_of(&m.ip_address_prefixlen)) {
                (Some(a), Some(l)) => Some(format!("{a}/{l}")),
                (a, _) => a,
            },
            cost: u32_of(&m.cost),
            mtu: u32_of(&m.mtu_bytes),
            mtu_mismatch_detection: bool_of(&m.mtu_mismatch_detect),
            hello: u64_of(&m.timer_hello_in_msecs).map(|ms| u32::try_from(ms / 1000).unwrap_or(0)),
            dead: u32_of(&m.timer_dead_secs),
            dr: text(&m.dr_id),
            bdr: text(&m.bdr_id),
            passive: bool_of(&m.timer_passive_iface).unwrap_or(false),
            neighbors: u32_of(&m.nbr_count).unwrap_or(0),
            adjacent: u32_of(&m.nbr_adjacent_count).unwrap_or(0),
        });
    }
    Ok(out)
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct OspfTop<'a> {
    #[serde(borrow)]
    areas: Dict<'a, Obj<AreaStub<'a>>>,
    #[serde(borrow)]
    router_is_stub_router: Option<Loose<'a>>,
    // G3.4r: the database's size (ospfd; ospf6d's AS scope).
    #[serde(borrow)]
    lsa_external_counter: Option<Loose<'a>>,
    #[serde(borrow)]
    lsa_asopaque_counter: Option<Loose<'a>>,
    #[serde(borrow)]
    lsa_other_routers_counter: Option<Loose<'a>>,
    #[serde(borrow)]
    number_of_as_scoped_lsa: Option<Loose<'a>>,
    #[serde(borrow)]
    max_lsa: Obj<MaxLsaJson<'a>>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct AreaStub<'a> {
    #[serde(borrow)]
    origin_stub_max_dist_router_lsa: Option<Loose<'a>>,
    #[serde(borrow)]
    indefinite_active_admin: Option<Loose<'a>>,
    #[serde(borrow)]
    active_startup_remainder_msecs: Option<Loose<'a>>,
    #[serde(borrow)]
    lsa_number: Option<Loose<'a>>,
    #[serde(borrow)]
    number_of_area_scoped_lsa: Option<Loose<'a>>,
}

/// G3.4r: the `maxLsa` object of the patched ospfd
/// (`os/patches/frr/0002-…`, `show_ip_ospf_common`).
#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct MaxLsaJson<'a> {
    #[serde(borrow)]
    limit: Option<Loose<'a>>,
    #[serde(borrow)]
    state: Option<Loose<'a>>,
    #[serde(borrow)]
    ignore_entries: Option<Loose<'a>>,
    #[serde(borrow)]
    ignore_count: Option<Loose<'a>>,
    #[serde(borrow)]
    ignore_remaining_msecs: Option<Loose<'a>>,
}

/// G3.4r: the size of the database and the LSDB protection, from the
/// answer the stub router state is read from (the counters, not the
/// LSAs: ~1 KiB and ≤ 0.5 ms of ospfd at any size, **medido**).
fn lsdb_size(top: &OspfTop<'_>, out: &mut OspfStubState) {
    let mut total: Option<u64> = None;
    let mut add = |v: Option<u64>| {
        if let Some(v) = v {
            total = Some(total.unwrap_or(0).saturating_add(v));
        }
    };
    for (_, a) in top.areas.0.iter().take(1_000) {
        if let Some(a) = &a.0 {
            add(u64_of(&a.lsa_number));
            add(u64_of(&a.number_of_area_scoped_lsa));
        }
    }
    add(u64_of(&top.lsa_external_counter));
    add(u64_of(&top.lsa_asopaque_counter));
    add(u64_of(&top.number_of_as_scoped_lsa));
    out.lsas = total;
    out.lsas_other = u64_of(&top.lsa_other_routers_counter);
    out.max_lsa = top.max_lsa.0.as_ref().map(|m| MaxLsaState {
        limit: u64_of(&m.limit).unwrap_or(0),
        state: text(&m.state)
            .map(|s| s.chars().take(16).collect())
            .unwrap_or_default(),
        ignore_entries: u64_of(&m.ignore_entries).unwrap_or(0),
        ignore_count: u64_of(&m.ignore_count).unwrap_or(0),
        ignore_remaining_secs: u64_of(&m.ignore_remaining_msecs).map(|ms| ms.div_ceil(1000)),
    });
}

/// G3.9c: `show ip ospf json`: the areas that originate a stub router-LSA
/// now (`originStubMaxDistRouterLsa`), administratively
/// (`indefiniteActiveAdmin`) or on startup (`activeStartupRemainderMsecs`;
/// FRR 10.7.1 `ospfd/ospf_vty.c`, `show_ip_ospf_area`).
pub fn stub_v2(json: impl AsRef<[u8]>, instance: &str) -> Result<OspfStubState, String> {
    let top: Obj<OspfTop<'_>> = loose::parse(json.as_ref(), "ospfd")?;
    let mut out = OspfStubState {
        instance: instance.to_owned(),
        ..OspfStubState::default()
    };
    let Some(top) = top.0 else { return Ok(out) };
    lsdb_size(&top, &mut out);
    for (id, a) in top.areas.0.iter().take(1_000) {
        let Some(m) = &a.0 else { continue };
        if bool_of(&m.origin_stub_max_dist_router_lsa) != Some(true) {
            continue;
        }
        out.areas.push(id.chars().take(32).collect());
        out.admin |= bool_of(&m.indefinite_active_admin) == Some(true);
        if let Some(ms) = u64_of(&m.active_startup_remainder_msecs) {
            let secs = ms.div_ceil(1000);
            out.startup_remaining_secs =
                Some(out.startup_remaining_secs.map_or(secs, |o| o.max(secs)));
        }
    }
    out.areas.sort();
    Ok(out)
}

/// G3.9c: `show ipv6 ospf6 json`: `routerIsStubRouter` (FRR 10.7.1
/// `ospf6d/ospf6_top.c`); ospf6d has the administrative form only.
pub fn stub_v3(json: impl AsRef<[u8]>, instance: &str) -> Result<OspfStubState, String> {
    let top: Obj<OspfTop<'_>> = loose::parse(json.as_ref(), "ospf6d")?;
    let mut out = OspfStubState {
        instance: instance.to_owned(),
        admin: top
            .0
            .as_ref()
            .is_some_and(|t| bool_of(&t.router_is_stub_router) == Some(true)),
        ..OspfStubState::default()
    };
    if let Some(t) = &top.0 {
        lsdb_size(t, &mut out);
    }
    Ok(out)
}

/// Most routes kept from `show ip ospf route json`.
pub const MAX_ROUTES: usize = 200_000;

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct RouteJson<'a> {
    #[serde(borrow)]
    route_type: Option<Loose<'a>>,
    #[serde(borrow)]
    cost: Option<Loose<'a>>,
    #[serde(borrow, rename = "type2cost")]
    type2cost: Option<Loose<'a>>,
    #[serde(borrow)]
    area: Option<Loose<'a>>,
    #[serde(borrow)]
    nexthops: List<HopJson<'a>, 64>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct HopJson<'a> {
    #[serde(borrow)]
    ip: Option<Loose<'a>>,
    #[serde(borrow)]
    via: Option<Loose<'a>>,
    #[serde(borrow)]
    directly_attached_to: Option<Loose<'a>>,
}

fn route_of(key: &str, m: &RouteJson<'_>, instance: &str) -> OspfRoute {
    let kind = match m.route_type.as_ref().and_then(Loose::str).map(str::trim) {
        Some("N") => "intra-area",
        Some("N IA") => "inter-area",
        Some("N E1") => "ext-1",
        Some("N E2") => "ext-2",
        Some("N N1") => "nssa-1",
        Some("N N2") => "nssa-2",
        _ => "other",
    };
    let nexthops = m
        .nexthops
        .0
        .iter()
        .map(|h| {
            let via = text(&h.ip).filter(|i| !i.trim().is_empty());
            let dev = text(&h.via)
                .or_else(|| text(&h.directly_attached_to))
                .unwrap_or_default();
            (via, dev)
        })
        .collect();
    OspfRoute {
        instance: instance.to_owned(),
        prefix: key.chars().take(64).collect(),
        kind: kind.to_owned(),
        cost: u32_of(&m.cost).unwrap_or(0),
        type2_cost: u32_of(&m.type2cost),
        area: text(&m.area),
        nexthops,
        fast_reroute: None,
    }
}

/// The top object of `show ip ospf route json`, read entry by entry: the
/// network routes (keys with a `/`) become rows as they are read; the
/// router routes (to ABRs/ASBRs) and entries past [`MAX_ROUTES`] are
/// skipped without being built.
struct RoutesSeed<'i> {
    instance: &'i str,
}

impl<'de> DeserializeSeed<'de> for RoutesSeed<'_> {
    type Value = Vec<OspfRoute>;
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<Vec<OspfRoute>, D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for RoutesSeed<'_> {
    type Value = Vec<OspfRoute>;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OSPF routes")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Vec<OspfRoute>, A::Error> {
        let mut out = Vec::new();
        while let Some(k) = map.next_key::<std::borrow::Cow<'de, str>>()? {
            if !k.contains('/') || out.len() >= MAX_ROUTES {
                map.next_value::<IgnoredAny>()?;
                continue;
            }
            if let Obj(Some(m)) = map.next_value::<Obj<RouteJson<'_>>>()? {
                out.push(route_of(&k, &m, self.instance));
            }
        }
        Ok(out)
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<OspfRoute>, A::Error> {
        while seq.next_element::<IgnoredAny>()?.is_some() {}
        Ok(Vec::new())
    }
    fn visit_bool<E>(self, _: bool) -> Result<Vec<OspfRoute>, E> {
        Ok(Vec::new())
    }
    fn visit_i64<E>(self, _: i64) -> Result<Vec<OspfRoute>, E> {
        Ok(Vec::new())
    }
    fn visit_u64<E>(self, _: u64) -> Result<Vec<OspfRoute>, E> {
        Ok(Vec::new())
    }
    fn visit_f64<E>(self, _: f64) -> Result<Vec<OspfRoute>, E> {
        Ok(Vec::new())
    }
    fn visit_str<E>(self, _: &str) -> Result<Vec<OspfRoute>, E> {
        Ok(Vec::new())
    }
    fn visit_unit<E>(self) -> Result<Vec<OspfRoute>, E> {
        Ok(Vec::new())
    }
}

/// `show ip ospf route json`: the network routes (keys with a `/`); the
/// router routes (to ABRs/ASBRs) are left out.
pub fn routes_v2(json: impl AsRef<[u8]>, instance: &str) -> Result<Vec<OspfRoute>, String> {
    let mut de = serde_json::Deserializer::from_slice(json.as_ref());
    let out = RoutesSeed { instance }
        .deserialize(&mut de)
        .and_then(|v| de.end().map(|()| v))
        .map_err(|e| format!("ospfd answered bad JSON: {e}"))?;
    Ok(out)
}

/// [`routes_v2`] as the answer streams from the socket (G3.4n: 200 000
/// routes are ~43 MiB of JSON, which no longer sit in one buffer, nor
/// count against the vty's reply limit).
pub fn read_routes(input: impl Read, instance: &str) -> Result<Vec<OspfRoute>, String> {
    let mut de =
        serde_json::Deserializer::from_reader(std::io::BufReader::with_capacity(64 * 1024, input));
    RoutesSeed { instance }
        .deserialize(&mut de)
        .map_err(|e| format!("ospfd answered bad JSON: {e}"))
}

// ---- the LSDB, streamed ----

fn ip_u32(t: &str) -> Option<u32> {
    t.parse::<Ipv4Addr>().ok().map(u32::from)
}

/// The LSA type of a `…LinkStates` key.
fn kind_of(key: &str) -> Option<u8> {
    Some(match key {
        "routerLinkStates" => 1,
        "networkLinkStates" => 2,
        "summaryLinkStates" => 3,
        "asbrSummaryLinkStates" => 4,
        "asExternalLinkStates" => 5,
        "nssaExternalLinkStates" => 7,
        _ => return None,
    })
}

/// One LSA object, read field by field into the compact row.
struct LsaSeed<'a> {
    db: &'a mut Lsdb,
    kind: u8,
    area: u32,
}

impl<'de> DeserializeSeed<'de> for LsaSeed<'_> {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for LsaSeed<'_> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an LSA")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let mut lsa = Lsa {
            kind: self.kind,
            area: self.area,
            ..Lsa::default()
        };
        let start = self.db.links.len();
        let att_start = self.db.attached.len();
        let mut e2 = false;
        while let Some(k) = map.next_key::<std::borrow::Cow<'de, str>>()? {
            match k.as_ref() {
                "lsaAge" => lsa.age = u16::try_from(map.next_value::<u64>()?).unwrap_or(u16::MAX),
                "linkStateId" => {
                    lsa.id = ip_u32(&map.next_value::<std::borrow::Cow<'de, str>>()?).unwrap_or(0)
                }
                "advertisingRouter" => {
                    lsa.adv = ip_u32(&map.next_value::<std::borrow::Cow<'de, str>>()?).unwrap_or(0)
                }
                "lsaSeqNumber" => {
                    lsa.seq =
                        u32::from_str_radix(&map.next_value::<std::borrow::Cow<'de, str>>()?, 16)
                            .unwrap_or(0)
                }
                "abr" => lsa.flags |= u8::from(map.next_value::<bool>()?),
                "asbr" => lsa.flags |= u8::from(map.next_value::<bool>()?) << 1,
                "vlEndpoint" => lsa.flags |= u8::from(map.next_value::<bool>()?) << 2,
                "networkMask" => {
                    let m = map.next_value::<u64>()?;
                    lsa.plen = u8::try_from(m.min(32)).unwrap_or(32);
                    if self.kind == 2 {
                        lsa.flags = lsa.plen;
                    }
                }
                "metric" | "tos0Metric" => {
                    lsa.metric = u32::try_from(map.next_value::<u64>()?).unwrap_or(0)
                }
                "routerLinks" => map.next_value_seed(LinksSeed(&mut *self.db))?,
                "attchedRouters" | "attachedRouters" => {
                    map.next_value_seed(AttachedSeed(&mut *self.db))?
                }
                "metricType" => {
                    // E1 / E2: E2 marked in the top bit of the metric.
                    let t = map.next_value::<std::borrow::Cow<'de, str>>()?;
                    e2 = t.starts_with("E2");
                }
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        if e2 {
            lsa.metric |= 1 << 31;
        }
        if self.db.lsas.len() >= MAX_LSAS {
            self.db.links.truncate(start);
            self.db.attached.truncate(att_start);
            self.db.dropped += 1;
            return Ok(());
        }
        match self.kind {
            1 => {
                lsa.link_start = u32::try_from(start).unwrap_or(u32::MAX);
                lsa.link_count = u16::try_from(self.db.links.len() - start).unwrap_or(u16::MAX);
            }
            2 => {
                lsa.link_start = u32::try_from(att_start).unwrap_or(u32::MAX);
                lsa.link_count =
                    u16::try_from(self.db.attached.len() - att_start).unwrap_or(u16::MAX);
            }
            _ => {}
        }
        self.db.lsas.push(lsa);
        Ok(())
    }
}

/// `routerLinks: {"link0": {...}, ...}`.
struct LinksSeed<'a>(&'a mut Lsdb);

impl<'de> DeserializeSeed<'de> for LinksSeed<'_> {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for LinksSeed<'_> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("router links")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let mut count = 0usize;
        while map.next_key::<IgnoredAny>()?.is_some() {
            let Obj(l) = map.next_value::<Obj<LinkJson<'de>>>()?;
            count += 1;
            let Some(l) = l.filter(|_| count <= MAX_LINKS) else {
                continue;
            };
            let t = l
                .link_type
                .as_ref()
                .and_then(Loose::str)
                .unwrap_or_default();
            let kind = if t.contains("point-to-point") {
                1
            } else if t.contains("Transit") {
                2
            } else if t.contains("Stub") {
                3
            } else if t.contains("Virtual") {
                4
            } else {
                0
            };
            let addr = |v: &Option<Loose<'_>>| v.as_ref().and_then(Loose::str).and_then(ip_u32);
            let id = addr(&l.neighbor_router_id)
                .or_else(|| addr(&l.designated_router_address))
                .or_else(|| addr(&l.network_address))
                .unwrap_or(0);
            let data = addr(&l.router_interface_address)
                .or_else(|| addr(&l.network_mask))
                .unwrap_or(0);
            let metric = u64_of(&l.tos0_metric)
                .and_then(|m| u16::try_from(m).ok())
                .unwrap_or(0);
            self.0.links.push(Link {
                kind,
                id,
                data,
                metric,
            });
        }
        Ok(())
    }
}

/// One router link: only the fields kept (G3.4n: it was a JSON map per
/// link, every key and value allocated).
#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct LinkJson<'a> {
    #[serde(borrow)]
    link_type: Option<Loose<'a>>,
    #[serde(borrow)]
    neighbor_router_id: Option<Loose<'a>>,
    #[serde(borrow)]
    designated_router_address: Option<Loose<'a>>,
    #[serde(borrow)]
    network_address: Option<Loose<'a>>,
    #[serde(borrow)]
    router_interface_address: Option<Loose<'a>>,
    #[serde(borrow)]
    network_mask: Option<Loose<'a>>,
    #[serde(borrow, rename = "tos0Metric")]
    tos0_metric: Option<Loose<'a>>,
}

/// `attchedRouters: {"10.0.0.1": {"attachedRouterId": "10.0.0.1"}, ...}`
/// (FRR spells the key `attchedRouters`).
struct AttachedSeed<'a>(&'a mut Lsdb);

impl<'de> DeserializeSeed<'de> for AttachedSeed<'_> {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for AttachedSeed<'_> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("attached routers")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        while let Some(k) = map.next_key::<std::borrow::Cow<'de, str>>()? {
            map.next_value::<IgnoredAny>()?;
            if let Some(v) = ip_u32(&k) {
                self.0.attached.push(v);
            }
        }
        Ok(())
    }
}

/// An array of LSAs of one kind and area.
struct ArraySeed<'a> {
    db: &'a mut Lsdb,
    kind: u8,
    area: u32,
}

impl<'de> DeserializeSeed<'de> for ArraySeed<'_> {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_seq(self)
    }
}

impl<'de> Visitor<'de> for ArraySeed<'_> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a list of LSAs")
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        while seq
            .next_element_seed(LsaSeed {
                db: &mut *self.db,
                kind: self.kind,
                area: self.area,
            })?
            .is_some()
        {}
        Ok(())
    }
}

/// `{"areas": {"0.0.0.0": [...]}}` of one kind.
struct AreasSeed<'a> {
    db: &'a mut Lsdb,
    kind: u8,
}

impl<'de> DeserializeSeed<'de> for AreasSeed<'_> {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for AreasSeed<'_> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LSAs by area")
    }
    /// AS-scope LSAs come as a plain array.
    fn visit_seq<A: SeqAccess<'de>>(self, seq: A) -> Result<(), A::Error> {
        ArraySeed {
            db: self.db,
            kind: self.kind,
            area: u32::MAX,
        }
        .visit_seq(seq)
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        while let Some(k) = map.next_key::<std::borrow::Cow<'de, str>>()? {
            if k == "areas" {
                map.next_value_seed(ByArea {
                    db: &mut *self.db,
                    kind: self.kind,
                })?;
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(())
    }
}

struct ByArea<'a> {
    db: &'a mut Lsdb,
    kind: u8,
}

impl<'de> DeserializeSeed<'de> for ByArea<'_> {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for ByArea<'_> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("areas")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        while let Some(k) = map.next_key::<std::borrow::Cow<'de, str>>()? {
            let area = ip_u32(&k).unwrap_or(0);
            map.next_value_seed(ArraySeed {
                db: &mut *self.db,
                kind: self.kind,
                area,
            })?;
        }
        Ok(())
    }
}

/// The top object of `show ip ospf database … json`.
struct Top<'a>(&'a mut Lsdb);

impl<'de> DeserializeSeed<'de> for Top<'_> {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for Top<'_> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an OSPF database")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        while let Some(k) = map.next_key::<std::borrow::Cow<'de, str>>()? {
            match (k.as_ref(), kind_of(&k)) {
                ("routerId", _) => {
                    let r = map.next_value::<std::borrow::Cow<'de, str>>()?;
                    self.0.router_id = ip_u32(&r);
                }
                (_, Some(kind)) => map.next_value_seed(AreasSeed {
                    db: &mut *self.0,
                    kind,
                })?,
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(())
    }
}

/// Read one `show ip ospf database <kind> json` answer into `db`, as it
/// streams.
pub fn read_lsdb(input: impl Read, db: &mut Lsdb) -> Result<(), String> {
    let mut de = serde_json::Deserializer::from_reader(std::io::BufReader::new(input));
    Top(db)
        .deserialize(&mut de)
        .map_err(|e| format!("ospfd answered bad LSDB JSON: {e}"))
}

/// [`read_lsdb`] from a buffer (tests, benches).
pub fn read_lsdb_slice(input: &[u8], db: &mut Lsdb) -> Result<(), String> {
    let mut de = serde_json::Deserializer::from_slice(input);
    Top(db)
        .deserialize(&mut de)
        .map_err(|e| format!("ospfd answered bad LSDB JSON: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const NEIGHBORS: &str = r#"{"neighbors":{"10.0.0.2":[{"nbrState":"Full/DR","nbrPriority":1,"converged":"Full","role":"DR","upTimeInMsec":125000,"routerDeadIntervalTimerDueMsec":33000,"ifaceAddress":"10.0.1.2","ifaceName":"ether1","linkStateRetransmissionListCounter":0,"linkStateRequestListCounter":0,"databaseSummaryListCounter":0}],"10.0.0.3":[{"nbrState":"ExStart/-","converged":"ExStart","role":"DROther","deadTimeMsecs":"inactive","ifaceAddress":"10.0.2.2","ifaceName":"ether2:10.0.2.1"}]}}"#;

    #[test]
    fn neighbors_of_ospfd() {
        let n = neighbors_v2(NEIGHBORS, "v2").unwrap();
        assert_eq!(n.len(), 2);
        assert_eq!(
            (
                n[0].router_id.as_str(),
                n[0].state.as_str(),
                n[0].role.as_str()
            ),
            ("10.0.0.2", "Full", "DR")
        );
        assert_eq!(n[0].state_secs, Some(125));
        assert_eq!(n[1].interface, "ether2");
        assert_eq!(n[1].state, "ExStart");
        assert!(neighbors_v2("{}", "v2").unwrap().is_empty());
        assert!(neighbors_v2("nope", "v2").is_err());
    }

    #[test]
    fn neighbors_of_ospf6d_and_durations() {
        let j = r#"{"neighbors":[{"neighborId":"10.0.0.9","priority":1,"deadTime":"00:00:35","state":"Full","ifState":"PointToPoint","duration":"1d02h03m","interfaceName":"ether3","interfaceState":"PointToPoint"}]}"#;
        let n = neighbors_v3(j, "v3").unwrap();
        assert_eq!(n[0].dead_secs, Some(35));
        assert_eq!(n[0].state_secs, Some(86_400 + 2 * 3600 + 3 * 60));
        assert_eq!(secs("12.5s"), Some(12));
        assert_eq!(secs("x"), None);
    }

    /// G3.9c: the stub router state, in the form FRR 10.7.1 prints it.
    #[test]
    fn stub_router_state_of_ospfd_and_ospf6d() {
        let none = r#"{"routerId":"10.255.39.2","areas":{"0.0.0.0":{"nbrFullAdjacentCounter":1}}}"#;
        let st = stub_v2(none, "v2").unwrap();
        assert!(!st.active(), "{st:?}");
        let both = r#"{"routerId":"10.255.39.2","stubAdvertisement":true,"postStartEnabledSecs":300,
            "areas":{"0.0.0.1":{"originStubMaxDistRouterLsa":true,"activeStartupRemainderMsecs":41200},
                     "0.0.0.0":{"originStubMaxDistRouterLsa":true,"indefiniteActiveAdmin":true,"activeStartupRemainderMsecs":40001}}}"#;
        let st = stub_v2(both, "v2").unwrap();
        assert_eq!(st.areas, ["0.0.0.0", "0.0.0.1"]);
        assert!(st.admin && st.active());
        assert_eq!(st.startup_remaining_secs, Some(42));
        assert!(
            stub_v3(r#"{"routerId":"1.1.1.1","routerIsStubRouter":true}"#, "v3")
                .unwrap()
                .admin
        );
        assert!(
            !stub_v3(r#"{"routerId":"1.1.1.1","routerIsStubRouter":false}"#, "v3")
                .unwrap()
                .active()
        );
        assert!(stub_v2("garbage", "v2").is_err());
    }

    /// G3.4r: the database's size and the LSDB protection, in the form
    /// the patched ospfd prints (taken from the host lab,
    /// `scripts/ospf-stress-lab.sh`), and ospf6d's counters.
    #[test]
    fn lsdb_size_and_max_lsa_of_ospfd_and_ospf6d() {
        let plain = r#"{"routerId":"10.255.0.1","lsaExternalCounter":194881,"lsaAsopaqueCounter":0,
            "areas":{"0.0.0.0":{"lsaNumber":2}}}"#;
        let st = stub_v2(plain, "v2").unwrap();
        assert_eq!((st.lsas, st.lsas_other, st.max_lsa.clone()), (Some(194_883), None, None), "{st:?}");
        let patched = r#"{"routerId":"10.255.0.1","lsaOtherRoutersCounter":0,
            "maxLsa":{"limit":50000,"threshold":80,"warningOnly":false,"ignoreTimeSecs":30,"ignoreCount":2,
                      "resetTimeSecs":60,"state":"ignore","ignoreEntries":1,"ignoreRemainingMsecs":29854},
            "lsaExternalCounter":0,"lsaAsopaqueCounter":0,"areas":{"0.0.0.0":{"lsaNumber":0}}}"#;
        let st = stub_v2(patched, "v2").unwrap();
        let m = st.max_lsa.clone().unwrap();
        assert_eq!((st.lsas, st.lsas_other), (Some(0), Some(0)));
        assert_eq!((m.limit, m.state.as_str(), m.ignore_entries, m.ignore_count, m.ignore_remaining_secs), (50_000, "ignore", 1, 2, Some(30)));
        assert!(m.down());
        let v3 = r#"{"routerId":"1.1.1.1","numberOfAsScopedLsa":7,"areas":{"0.0.0.0":{"numberOfAreaScopedLsa":5}}}"#;
        assert_eq!(stub_v3(v3, "v3").unwrap().lsas, Some(12));
        // Odd types are None, not an error.
        let odd = r#"{"lsaOtherRoutersCounter":"x","maxLsa":{"limit":"y","state":7},"areas":{"0":{"lsaNumber":[]}}}"#;
        let st = stub_v2(odd, "v2").unwrap();
        assert_eq!((st.lsas, st.lsas_other), (None, None));
        assert_eq!(st.max_lsa.unwrap().limit, 0);
    }

    #[test]
    fn routes_of_ospfd() {
        let j = r#"{"10.0.3.0/24":{"routeType":"N","transit":true,"cost":20,"area":"0.0.0.0","nexthops":[{"ip":"10.0.12.2","via":"ether1"}]},
                    "10.0.12.0/30":{"routeType":"N","cost":10,"area":"0.0.0.0","nexthops":[{"ip":" ","directlyAttachedTo":"ether1"}]},
                    "10.0.0.2":{"routeType":"R "},
                    "0.0.0.0/0":{"routeType":"N E2","cost":10,"type2cost":1,"tag":0,"nexthops":[{"ip":"10.0.12.2","via":"ether1"}]}}"#;
        let r = routes_v2(j, "v2").unwrap();
        assert_eq!(r.len(), 3);
        let d = r.iter().find(|r| r.prefix == "0.0.0.0/0").unwrap();
        assert_eq!((d.kind.as_str(), d.type2_cost), ("ext-2", Some(1)));
        let c = r.iter().find(|r| r.prefix == "10.0.12.0/30").unwrap();
        assert_eq!(c.nexthops, vec![(None, "ether1".to_owned())]);
    }

    /// G3.4n: the streamed reader gives what the buffer reader gives, the
    /// cap holds, and odd shapes are skipped, not errors.
    #[test]
    fn routes_stream_like_the_buffer_and_odd_shapes_are_skipped() {
        let j = r#"{"10.0.3.0/24":{"routeType":"N","cost":"20","area":"0.0.0.0","nexthops":[{"ip":"10.0.12.2","via":"ether1"},7]},
                    "10.0.4.0/24":[1,2],"10.0.5.0/24":{"routeType":5,"nexthops":{"x":1}},"10.0.0.2":{"routeType":"R "}}"#;
        let a = routes_v2(j, "v2").unwrap();
        let b = read_routes(j.as_bytes(), "v2").unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 2);
        assert_eq!((a[0].cost, a[0].nexthops.len()), (20, 1));
        assert_eq!((a[1].kind.as_str(), a[1].nexthops.len()), ("other", 0));
        assert!(routes_v2("[1]", "v2").unwrap().is_empty());
        assert!(read_routes(&b"{\"x/1\": "[..], "v2").is_err());
        // A link that is not an object is skipped; the LSA stays.
        let mut db = Lsdb::default();
        read_lsdb_slice(br#"{"routerLinkStates":{"areas":{"0.0.0.0":[{"linkStateId":"1.1.1.1","advertisingRouter":"1.1.1.1","routerLinks":{"link0":5,"link1":{"linkType":"Stub Network","networkAddress":"10.0.0.0","networkMask":"255.0.0.0","tos0Metric":1}}}]}}}"#, &mut db).unwrap();
        assert_eq!((db.lsas.len(), db.links.len()), (1, 1));
        assert_eq!(db.links[0].kind, 3);
    }

    pub(crate) const LSDB: &str = r#"{"routerId":"10.0.0.1","routerLinkStates":{"areas":{"0.0.0.0":[
        {"lsaAge":10,"options":"*|-|-|-|-|-|E|-","lsaFlags":6,"flags":3,"abr":true,"asbr":true,"lsaType":"router-LSA","linkStateId":"10.0.0.1","advertisingRouter":"10.0.0.1","lsaSeqNumber":"80000003","checksum":"1a2b","length":48,"numOfLinks":2,
         "routerLinks":{"link0":{"linkType":"another Router (point-to-point)","neighborRouterId":"10.0.0.2","routerInterfaceAddress":"10.0.12.1","numOfTosMetrics":0,"tos0Metric":10},
                        "link1":{"linkType":"Stub Network","networkAddress":"10.0.12.0","networkMask":"255.255.255.252","numOfTosMetrics":0,"tos0Metric":10}}},
        {"lsaAge":20,"lsaType":"router-LSA","linkStateId":"10.0.0.2","advertisingRouter":"10.0.0.2","lsaSeqNumber":"80000001","numOfLinks":1,
         "routerLinks":{"link0":{"linkType":"another Router (point-to-point)","neighborRouterId":"10.0.0.1","routerInterfaceAddress":"10.0.12.2","tos0Metric":20}}}]}},
      "networkLinkStates":{"areas":{"0.0.0.0":[{"lsaAge":5,"linkStateId":"10.0.3.1","advertisingRouter":"10.0.0.2","lsaSeqNumber":"80000002","networkMask":24,"attchedRouters":{"10.0.0.2":{"attachedRouterId":"10.0.0.2"},"10.0.0.5":{"attachedRouterId":"10.0.0.5"}}}]}},
      "asExternalLinkStates":[{"lsaAge":1,"linkStateId":"0.0.0.0","advertisingRouter":"10.0.0.1","lsaSeqNumber":"80000001","networkMask":0,"metricType":"E2","metric":1}]}"#;

    #[test]
    fn the_lsdb_streams_into_rows() {
        let mut db = Lsdb::default();
        read_lsdb(LSDB.as_bytes(), &mut db).unwrap();
        assert_eq!(db.router_id, Some(u32::from(Ipv4Addr::new(10, 0, 0, 1))));
        assert_eq!(db.lsas.len(), 4);
        let r1 = db.lsas[0];
        assert_eq!(
            (r1.kind, r1.flags & 3, r1.link_count, r1.seq),
            (1, 3, 2, 0x8000_0003)
        );
        assert_eq!(db.links[0].kind, 1);
        assert_eq!(db.links[0].metric, 10);
        assert_eq!(db.links[1].kind, 3);
        let net = db.lsas[2];
        assert_eq!((net.kind, net.plen, net.link_count), (2, 24, 2));
        let ext = db.lsas[3];
        assert_eq!(
            (ext.kind, ext.area, ext.metric & 0xFFFF, ext.metric >> 31),
            (5, u32::MAX, 1, 1)
        );
        let mut bad = Lsdb::default();
        assert!(read_lsdb(&b"{\"routerLinkStates\": 5"[..], &mut bad).is_err());
    }

    mod prop {
        use proptest::prelude::*;

        use super::super::*;
        use super::LSDB;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(500))]

            /// The daemon's JSON cut or changed anywhere: an error or a
            /// table, never a panic, and the links stay inside the table.
            #[test]
            fn damaged_lsdb(cut in 0usize..2000, at in 0usize..2000, v in any::<u8>()) {
                let mut b = LSDB.as_bytes().to_vec();
                b.truncate(cut.max(1));
                if let Some(x) = b.get_mut(at) {
                    *x = v;
                }
                let mut db = Lsdb::default();
                let _ = read_lsdb_slice(&b, &mut db);
                for l in &db.lsas {
                    if l.kind == 1 {
                        prop_assert!(l.link_start as usize + l.link_count as usize <= db.links.len());
                    }
                }
            }

            #[test]
            fn neighbor_json_garbage(s in ".{0,300}") {
                let _ = neighbors_v2(&s, "x");
                let _ = neighbors_v3(&s, "x");
                let _ = interfaces_v2(&s, "x");
                let _ = routes_v2(&s, "x");
                let _ = read_routes(s.as_bytes(), "x");
                let _ = stub_v2(&s, "x");
                let _ = secs(&s);
            }
        }
    }
}
