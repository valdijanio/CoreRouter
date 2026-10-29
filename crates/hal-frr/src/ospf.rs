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
    Link, Lsa, Lsdb, OspfIfState, OspfNeighbor, OspfRoute, OspfStubState,
};
use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};

/// Most LSAs kept from one database (a large single area is ~10 000,
/// **estimado**; past this they are counted in `dropped`).
pub const MAX_LSAS: usize = 500_000;
/// Most links of one router LSA (RFC 2328: 16-bit count).
const MAX_LINKS: usize = 65_535;

fn s(m: &Map<String, Value>, k: &str) -> Option<String> {
    m.get(k)
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
        .map(|v| v.chars().take(128).collect())
}

fn n(m: &Map<String, Value>, k: &str) -> Option<u64> {
    m.get(k).and_then(|v| {
        v.as_u64()
            .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
    })
}

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

/// `show ip ospf neighbor json` of instance `instance`.
pub fn neighbors_v2(json: &str, instance: &str) -> Result<Vec<OspfNeighbor>, String> {
    let v: Value =
        serde_json::from_str(json).map_err(|e| format!("ospfd answered bad JSON: {e}"))?;
    let mut out = Vec::new();
    let Some(Value::Object(by_id)) = v.get("neighbors") else {
        return Ok(out);
    };
    for (id, list) in by_id {
        let Value::Array(list) = list else { continue };
        for nb in list {
            let Value::Object(m) = nb else { continue };
            let full = s(m, "nbrState").unwrap_or_default();
            let (state, role) = match full.split_once('/') {
                Some((a, b)) => (a.to_owned(), b.to_owned()),
                None => (full.clone(), s(m, "role").unwrap_or_default()),
            };
            let iface = s(m, "ifaceName").unwrap_or_default();
            out.push(OspfNeighbor {
                instance: instance.to_owned(),
                version: 2,
                router_id: if id == "neighbor" {
                    String::new()
                } else {
                    id.clone()
                },
                address: s(m, "ifaceAddress").unwrap_or_default(),
                // `eth0:10.0.0.1` in older daemons.
                interface: iface.split(':').next().unwrap_or_default().to_owned(),
                area: s(m, "areaId").or_else(|| s(m, "area")),
                state: s(m, "converged").unwrap_or(state),
                role,
                priority: n(m, "nbrPriority").and_then(|p| u32::try_from(p).ok()),
                state_secs: n(m, "upTimeInMsec").map(|ms| ms / 1000),
                dead_secs: n(m, "routerDeadIntervalTimerDueMsec").map(|ms| ms / 1000),
                bfd: None,
                retransmit: n(m, "linkStateRetransmissionListCounter").unwrap_or(0),
                request: n(m, "linkStateRequestListCounter").unwrap_or(0),
                summary: n(m, "databaseSummaryListCounter").unwrap_or(0),
            });
        }
    }
    out.sort_by(|a, b| (&a.interface, &a.router_id).cmp(&(&b.interface, &b.router_id)));
    Ok(out)
}

/// `show ipv6 ospf6 neighbor json`.
pub fn neighbors_v3(json: &str, instance: &str) -> Result<Vec<OspfNeighbor>, String> {
    let v: Value =
        serde_json::from_str(json).map_err(|e| format!("ospf6d answered bad JSON: {e}"))?;
    let mut out = Vec::new();
    let Some(Value::Array(list)) = v.get("neighbors") else {
        return Ok(out);
    };
    for nb in list {
        let Value::Object(m) = nb else { continue };
        out.push(OspfNeighbor {
            instance: instance.to_owned(),
            version: 3,
            router_id: s(m, "neighborId").unwrap_or_default(),
            address: s(m, "linkLocalAddress").unwrap_or_default(),
            interface: s(m, "interfaceName").unwrap_or_default(),
            area: s(m, "area"),
            state: s(m, "state").unwrap_or_default(),
            role: s(m, "ifState").unwrap_or_default(),
            priority: n(m, "priority").and_then(|p| u32::try_from(p).ok()),
            state_secs: s(m, "duration").and_then(|d| secs(&d)),
            dead_secs: s(m, "deadTime").and_then(|d| secs(&d)),
            bfd: None,
            retransmit: 0,
            request: 0,
            summary: 0,
        });
    }
    out.sort_by(|a, b| (&a.interface, &a.router_id).cmp(&(&b.interface, &b.router_id)));
    Ok(out)
}

/// `show ip ospf interface json`.
pub fn interfaces_v2(json: &str, instance: &str) -> Result<Vec<OspfIfState>, String> {
    let v: Value =
        serde_json::from_str(json).map_err(|e| format!("ospfd answered bad JSON: {e}"))?;
    let mut out = Vec::new();
    let Some(Value::Object(by_name)) = v.get("interfaces") else {
        return Ok(out);
    };
    for (name, i) in by_name {
        let Value::Object(m) = i else { continue };
        if m.get("ospfEnabled").and_then(Value::as_bool) == Some(false) {
            continue;
        }
        out.push(OspfIfState {
            instance: instance.to_owned(),
            version: 2,
            interface: name.clone(),
            area: s(m, "area").map(|a| a.split(' ').next().unwrap_or_default().to_owned()),
            network_type: s(m, "networkType"),
            state: s(m, "state"),
            address: match (s(m, "ipAddress"), n(m, "ipAddressPrefixlen")) {
                (Some(a), Some(l)) => Some(format!("{a}/{l}")),
                (a, _) => a,
            },
            cost: n(m, "cost").and_then(|c| u32::try_from(c).ok()),
            mtu: n(m, "mtuBytes").and_then(|c| u32::try_from(c).ok()),
            mtu_mismatch_detection: m.get("mtuMismatchDetect").and_then(Value::as_bool),
            hello: n(m, "timerHelloInMsecs").map(|ms| u32::try_from(ms / 1000).unwrap_or(0)),
            dead: n(m, "timerDeadSecs").and_then(|c| u32::try_from(c).ok()),
            dr: s(m, "drId"),
            bdr: s(m, "bdrId"),
            passive: m
                .get("timerPassiveIface")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            neighbors: n(m, "nbrCount")
                .and_then(|c| u32::try_from(c).ok())
                .unwrap_or(0),
            adjacent: n(m, "nbrAdjacentCount")
                .and_then(|c| u32::try_from(c).ok())
                .unwrap_or(0),
        });
    }
    Ok(out)
}

/// G3.9c: `show ip ospf json`: the areas that originate a stub router-LSA
/// now (`originStubMaxDistRouterLsa`), administratively
/// (`indefiniteActiveAdmin`) or on startup (`activeStartupRemainderMsecs`;
/// FRR 10.7.1 `ospfd/ospf_vty.c`, `show_ip_ospf_area`).
pub fn stub_v2(json: &str, instance: &str) -> Result<OspfStubState, String> {
    let v: Value =
        serde_json::from_str(json).map_err(|e| format!("ospfd answered bad JSON: {e}"))?;
    let mut out = OspfStubState {
        instance: instance.to_owned(),
        ..OspfStubState::default()
    };
    let Some(Value::Object(areas)) = v.get("areas") else {
        return Ok(out);
    };
    for (id, a) in areas.iter().take(1_000) {
        let Value::Object(m) = a else { continue };
        let flag = |k: &str| m.get(k).and_then(Value::as_bool) == Some(true);
        if !flag("originStubMaxDistRouterLsa") {
            continue;
        }
        out.areas.push(id.chars().take(32).collect());
        out.admin |= flag("indefiniteActiveAdmin");
        if let Some(ms) = n(m, "activeStartupRemainderMsecs") {
            let secs = ms.div_ceil(1000);
            out.startup_remaining_secs = Some(out.startup_remaining_secs.map_or(secs, |o| o.max(secs)));
        }
    }
    out.areas.sort();
    Ok(out)
}

/// G3.9c: `show ipv6 ospf6 json`: `routerIsStubRouter` (FRR 10.7.1
/// `ospf6d/ospf6_top.c`); ospf6d has the administrative form only.
pub fn stub_v3(json: &str, instance: &str) -> Result<OspfStubState, String> {
    let v: Value =
        serde_json::from_str(json).map_err(|e| format!("ospf6d answered bad JSON: {e}"))?;
    Ok(OspfStubState {
        instance: instance.to_owned(),
        admin: v.get("routerIsStubRouter").and_then(Value::as_bool) == Some(true),
        ..OspfStubState::default()
    })
}

/// Most routes kept from `show ip ospf route json`.
pub const MAX_ROUTES: usize = 200_000;

/// `show ip ospf route json`: the network routes (keys with a `/`); the
/// router routes (to ABRs/ASBRs) are left out.
pub fn routes_v2(json: &str, instance: &str) -> Result<Vec<OspfRoute>, String> {
    let v: Value =
        serde_json::from_str(json).map_err(|e| format!("ospfd answered bad JSON: {e}"))?;
    let Value::Object(top) = v else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for (key, r) in &top {
        let Value::Object(m) = r else { continue };
        if !key.contains('/') || out.len() >= MAX_ROUTES {
            continue;
        }
        let kind = match s(m, "routeType").as_deref().map(str::trim) {
            Some("N") => "intra-area",
            Some("N IA") => "inter-area",
            Some("N E1") => "ext-1",
            Some("N E2") => "ext-2",
            Some("N N1") => "nssa-1",
            Some("N N2") => "nssa-2",
            _ => "other",
        };
        let mut nexthops = Vec::new();
        if let Some(Value::Array(hops)) = m.get("nexthops") {
            for h in hops.iter().take(64) {
                let Value::Object(h) = h else { continue };
                let via = s(h, "ip").filter(|i| !i.trim().is_empty());
                let dev = s(h, "via")
                    .or_else(|| s(h, "directlyAttachedTo"))
                    .unwrap_or_default();
                nexthops.push((via, dev));
            }
        }
        out.push(OspfRoute {
            instance: instance.to_owned(),
            prefix: key.chars().take(64).collect(),
            kind: kind.to_owned(),
            cost: n(m, "cost")
                .and_then(|c| u32::try_from(c).ok())
                .unwrap_or(0),
            type2_cost: n(m, "type2cost").and_then(|c| u32::try_from(c).ok()),
            area: s(m, "area"),
            nexthops,
            fast_reroute: None,
        });
    }
    Ok(out)
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
            let l: Map<String, Value> = map.next_value()?;
            count += 1;
            if count > MAX_LINKS {
                continue;
            }
            let t = s(&l, "linkType").unwrap_or_default();
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
            let id = [
                "neighborRouterId",
                "designatedRouterAddress",
                "networkAddress",
            ]
            .iter()
            .find_map(|k| s(&l, k))
            .and_then(|v| ip_u32(&v))
            .unwrap_or(0);
            let data = ["routerInterfaceAddress", "networkMask"]
                .iter()
                .find_map(|k| s(&l, k))
                .and_then(|v| ip_u32(&v))
                .unwrap_or(0);
            let metric = n(&l, "tos0Metric")
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
        assert!(stub_v3(r#"{"routerId":"1.1.1.1","routerIsStubRouter":true}"#, "v3").unwrap().admin);
        assert!(!stub_v3(r#"{"routerId":"1.1.1.1","routerIsStubRouter":false}"#, "v3").unwrap().active());
        assert!(stub_v2("garbage", "v2").is_err());
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
                let _ = secs(&s);
            }
        }
    }
}
