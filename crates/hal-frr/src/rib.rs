//! BGP routes from bgpd's JSON (G3.2c): the routes of one neighbor
//! (`show bgp … neighbors X received-routes | routes | advertised-routes
//! json`) parsed as the answer streams in, into the compact
//! `corerouter_model::bgp_rib::BgpRib` (attributes interned), and every
//! path of one prefix (`show bgp … <prefix> json`) for "Why this route?".
//!
//! The JSON comes from FRR, not from the network, but it is still bounded:
//! routes past [`MAX_ROUTES`] are counted and dropped with a warning, and
//! strings are cut. Field names are FRR 10.x's (checked against 10.7.1 in
//! the VM lab, `tests/frr_rpki_live.rs`).

use std::collections::HashMap;
use std::fmt;
use std::io::Read;
use std::net::IpAddr;

use corerouter_model::bgp_rib::{
    AsSegment, BgpAttrs, BgpPath, BgpPrefix, BgpRib, BgpRoute, Origin, PeerKind, SegmentKind,
};
use ipnet::IpNet;
use serde::Deserialize;
use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, SeqAccess, Visitor};

/// Most routes kept from one answer (a full IPv4 + IPv6 table is ~1.2 M
/// today, **estimado**; this leaves room and bounds memory at ~100 MiB).
pub const MAX_ROUTES: usize = 4_000_000;
/// Longest AS path or community list kept, characters.
const MAX_TEXT: usize = 2_048;

fn cut(s: &str) -> String {
    match s.char_indices().nth(MAX_TEXT) {
        Some((i, _)) => s.get(..i).unwrap_or_default().to_owned(),
        None => s.to_owned(),
    }
}

/// One route as the compact tables print it (received/advertised: one
/// object per prefix; `routes`: an array of paths per prefix). The prefix
/// is the map's key. Only what is kept is read into owned values: the
/// addresses and the origin are parsed from the text as it streams by (no
/// allocation), the AS path is the one string per route (**medido**:
/// 1 M routes in `benches/frr_rib.rs`).
#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct Compact {
    #[serde(deserialize_with = "ip")]
    next_hop: Option<IpAddr>,
    nexthops: Vec<Hop>,
    metric: Option<u32>,
    loc_prf: Option<u32>,
    weight: Option<u32>,
    path: Option<String>,
    #[serde(deserialize_with = "origin")]
    origin: Option<Origin>,
    best: Option<bool>,
    bestpath: Option<bool>,
    #[serde(deserialize_with = "ip")]
    peer_id: Option<IpAddr>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct Hop {
    #[serde(deserialize_with = "ip")]
    ip: Option<IpAddr>,
}

/// A string read without keeping it: `f` turns it into the value.
struct Text<T>(fn(&str) -> Option<T>);

impl<'de, T> Visitor<'de> for Text<T> {
    type Value = Option<T>;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a string")
    }
    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Option<T>, E> {
        Ok((self.0)(v))
    }
    fn visit_unit<E: serde::de::Error>(self) -> Result<Option<T>, E> {
        Ok(None)
    }
}

fn ip<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<IpAddr>, D::Error> {
    d.deserialize_any(Text(|s| s.parse().ok()))
}

fn origin<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Origin>, D::Error> {
    d.deserialize_any(Text(Origin::parse))
}

/// Builds a [`BgpRib`], interning attribute sets.
#[derive(Default)]
pub struct Builder {
    rib: BgpRib,
    seen: HashMap<BgpAttrs, u32>,
    /// Keep only paths from this peer (a `routes` answer is the
    /// neighbor's; the check costs nothing and guards a format change).
    peer: Option<IpAddr>,
    dropped: usize,
}

impl Builder {
    pub fn new(pre_policy: bool, peer: Option<IpAddr>) -> Builder {
        Builder {
            rib: BgpRib {
                pre_policy,
                ..BgpRib::default()
            },
            peer,
            ..Builder::default()
        }
    }

    fn intern(&mut self, a: BgpAttrs) -> u32 {
        if let Some(&i) = self.seen.get(&a) {
            return i;
        }
        let i = u32::try_from(self.rib.attrs.len()).unwrap_or(u32::MAX);
        self.rib.attrs.push(a.clone());
        self.seen.insert(a, i);
        i
    }

    fn push(&mut self, key: &str, c: Compact) {
        if let (Some(want), Some(got)) = (&self.peer, &c.peer_id)
            && want != got
        {
            return;
        }
        let Ok(prefix) = key.parse::<IpNet>() else {
            return;
        };
        if self.rib.routes.len() >= MAX_ROUTES {
            self.dropped += 1;
            return;
        }
        let next_hop = c.next_hop.or_else(|| c.nexthops.first().and_then(|h| h.ip));
        let mut as_path = c.path.unwrap_or_default();
        if as_path.len() > MAX_TEXT {
            as_path = cut(&as_path);
        }
        let attrs = BgpAttrs {
            as_path,
            origin: c.origin.unwrap_or_default(),
            next_hop,
            med: c.metric,
            local_pref: c.loc_prf,
            weight: c.weight.unwrap_or(0),
            communities: Vec::new(),
            large_communities: Vec::new(),
            ext_communities: Vec::new(),
        };
        let best = c.best.unwrap_or(false) || c.bestpath.unwrap_or(false);
        let attrs = self.intern(attrs);
        self.rib.routes.push(BgpRoute {
            prefix: prefix.trunc(),
            attrs,
            flags: if best { BgpRoute::BEST } else { 0 },
        });
    }

    pub fn finish(mut self) -> BgpRib {
        if self.dropped > 0 {
            self.rib.warnings.push(format!(
                "{} route(s) past {MAX_ROUTES} were not kept",
                self.dropped
            ));
        }
        self.rib
    }

    pub fn warn(&mut self, w: String) {
        self.rib.warnings.push(w);
    }

    pub fn routes(&self) -> usize {
        self.rib.routes.len()
    }

    pub fn set_pre_policy(&mut self, pre: bool) {
        self.rib.pre_policy = pre;
    }

    /// Add the routes of another table (its attribute sets interned here).
    pub fn extend(&mut self, other: BgpRib) {
        for r in other.routes {
            let Some(a) = other
                .attrs
                .get(usize::try_from(r.attrs).unwrap_or(usize::MAX))
            else {
                continue;
            };
            let attrs = self.intern(a.clone());
            self.rib.routes.push(BgpRoute { attrs, ..r });
        }
        self.rib.warnings.extend(other.warnings);
    }
}

/// What a table answer said besides its routes.
#[derive(Debug, Default)]
pub struct Parsed {
    /// FRR's `warning` (`Inbound soft reconfiguration not enabled`).
    pub warning: Option<String>,
    pub routes: usize,
}

struct Top<'a> {
    b: &'a mut Builder,
    out: &'a mut Parsed,
}

impl<'de> DeserializeSeed<'de> for Top<'_> {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for Top<'_> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an FRR route table")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        while let Some(k) = map.next_key::<String>()? {
            match k.as_str() {
                "receivedRoutes" | "advertisedRoutes" | "routes" => {
                    let before = self.b.routes();
                    map.next_value_seed(Routes { b: &mut *self.b })?;
                    self.out.routes += self.b.routes() - before;
                }
                "warning" => {
                    let w: String = map.next_value()?;
                    self.out.warning = Some(cut(&w));
                }
                _ => {
                    map.next_value::<IgnoredAny>()?;
                }
            }
        }
        Ok(())
    }
}

struct Routes<'a> {
    b: &'a mut Builder,
}

impl<'de> DeserializeSeed<'de> for Routes<'_> {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for Routes<'_> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("routes by prefix")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        while let Some(key) = map.next_key::<String>()? {
            map.next_value_seed(OneOrMany {
                b: &mut *self.b,
                key: &key,
            })?;
        }
        Ok(())
    }
}

struct OneOrMany<'a> {
    b: &'a mut Builder,
    key: &'a str,
}

impl<'de> DeserializeSeed<'de> for OneOrMany<'_> {
    type Value = ();
    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for OneOrMany<'_> {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a route or a list of paths")
    }
    fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<(), A::Error> {
        let c = Compact::deserialize(serde::de::value::MapAccessDeserializer::new(map))?;
        self.b.push(self.key, c);
        Ok(())
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        while let Some(c) = seq.next_element::<Compact>()? {
            self.b.push(self.key, c);
        }
        Ok(())
    }
}

/// Parse one table answer into `b`, reading `input` as it arrives.
pub fn parse_table(input: impl Read, b: &mut Builder) -> Result<Parsed, String> {
    let mut out = Parsed::default();
    let reader = std::io::BufReader::with_capacity(1 << 20, input);
    let mut de = serde_json::Deserializer::from_reader(reader);
    Top { b, out: &mut out }
        .deserialize(&mut de)
        .map_err(|e| format!("bgpd route table: {e}"))?;
    Ok(out)
}

/// Parse a whole answer held in memory (the benchmark compares it with
/// the streaming [`parse_table`]).
pub fn parse_slice(input: &[u8], b: &mut Builder) -> Result<Parsed, String> {
    let mut out = Parsed::default();
    let mut de = serde_json::Deserializer::from_slice(input);
    Top { b, out: &mut out }
        .deserialize(&mut de)
        .map_err(|e| format!("bgpd route table: {e}"))?;
    Ok(out)
}

/// The prefixes of a table answer (the `filtered-routes` list).
pub fn prefixes_of(input: impl Read) -> Result<Vec<IpNet>, String> {
    let mut b = Builder::new(false, None);
    parse_table(input, &mut b)?;
    Ok(b.finish().routes.into_iter().map(|r| r.prefix).collect())
}

// --- One prefix (`show bgp … <prefix> json`) -------------------------------

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct PrefixJson {
    prefix: Option<String>,
    paths: Vec<PathJson>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct PathJson {
    aspath: Option<AsPathJson>,
    origin: Option<String>,
    metric: Option<u32>,
    loc_prf: Option<u32>,
    weight: Option<u32>,
    valid: bool,
    multipath: bool,
    stale: bool,
    local: bool,
    sourced: bool,
    bestpath: Option<BestJson>,
    community: Option<ListJson>,
    large_community: Option<ListJson>,
    /// G3.9fc: FRR gives only the text, `RT:65001:7 SoO:…`.
    extended_community: Option<TextJson>,
    last_update: Option<EpochJson>,
    nexthops: Vec<HopJson>,
    peer: Option<PeerJson>,
    originator_id: Option<String>,
    cluster_list: Option<ListJson>,
    rpki_validation_state: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct AsPathJson {
    string: String,
    segments: Vec<SegmentJson>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct SegmentJson {
    #[serde(rename = "type")]
    kind: String,
    list: Vec<u32>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct BestJson {
    overall: bool,
    selection_reason: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ListJson {
    list: Vec<serde_json::Value>,
}

impl ListJson {
    fn strings(&self) -> Vec<String> {
        self.list
            .iter()
            .take(256)
            .map(|v| v.as_str().map_or_else(|| v.to_string(), str::to_owned))
            .collect()
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct TextJson {
    string: String,
}

/// FRR's text of the extended communities in RouterOS's words: `RT:65001:7`
/// → `rt:65001:7`; a kind the filter does not know stays as FRR prints it.
fn ext_words(text: &str) -> Vec<String> {
    text.split_whitespace()
        .take(256)
        .map(|w| {
            corerouter_proto_bgp::filter::Ext::from_frr(w)
                .map_or_else(|| w.to_owned(), |e| e.to_string())
        })
        .collect()
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct EpochJson {
    epoch: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct HopJson {
    ip: Option<String>,
    metric: Option<u32>,
    accessible: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct PeerJson {
    peer_id: Option<String>,
    router_id: Option<String>,
    #[serde(rename = "type")]
    kind: Option<String>,
}

fn segment_kind(s: &str) -> SegmentKind {
    match s {
        "as-set" => SegmentKind::Set,
        "as-confed-sequence" => SegmentKind::ConfedSequence,
        "as-confed-set" => SegmentKind::ConfedSet,
        _ => SegmentKind::Sequence,
    }
}

/// Every path of one prefix. `{}` (FRR: not in the table) gives no paths.
pub fn parse_prefix(text: &str) -> Result<BgpPrefix, String> {
    let t = text.trim();
    if t.is_empty() || t.starts_with('%') {
        return Ok(BgpPrefix::default());
    }
    let p: PrefixJson = serde_json::from_str(t).map_err(|e| format!("bgpd prefix detail: {e}"))?;
    let paths = p
        .paths
        .into_iter()
        .take(1_024)
        .map(|j| {
            let peer = j.peer.unwrap_or_default();
            let local = j.local || j.sourced;
            let peer_kind = if local {
                PeerKind::Local
            } else {
                match peer.kind.as_deref() {
                    Some("internal") | Some("confed-internal") => PeerKind::Internal,
                    Some(k) if k.starts_with("confed") => PeerKind::ConfedExternal,
                    _ => PeerKind::External,
                }
            };
            let hop = j.nexthops.first();
            let aspath = j.aspath.unwrap_or_default();
            BgpPath {
                peer: peer.peer_id.unwrap_or_default(),
                peer_router_id: peer.router_id.and_then(|r| r.parse().ok()),
                peer_kind,
                segments: aspath
                    .segments
                    .into_iter()
                    .take(64)
                    .map(|s| AsSegment {
                        kind: segment_kind(&s.kind),
                        asns: s.list.into_iter().take(1_024).collect(),
                    })
                    .collect(),
                as_path: cut(if aspath.string == "Local" {
                    ""
                } else {
                    &aspath.string
                }),
                origin: j
                    .origin
                    .as_deref()
                    .and_then(Origin::parse)
                    .unwrap_or_default(),
                med: j.metric,
                local_pref: j.loc_prf,
                weight: j.weight.unwrap_or(0),
                next_hop: hop.and_then(|h| h.ip.clone()),
                igp_metric: hop.and_then(|h| h.metric),
                next_hop_reachable: hop.and_then(|h| h.accessible).unwrap_or(j.valid),
                valid: j.valid,
                best: j.bestpath.as_ref().is_some_and(|b| b.overall),
                multipath: j.multipath,
                selection_reason: j.bestpath.and_then(|b| b.selection_reason),
                originator_id: j.originator_id.and_then(|o| o.parse().ok()),
                cluster_list_len: j
                    .cluster_list
                    .map_or(0, |c| u32::try_from(c.list.len()).unwrap_or(u32::MAX)),
                communities: j.community.map(|c| c.strings()).unwrap_or_default(),
                large_communities: j.large_community.map(|c| c.strings()).unwrap_or_default(),
                ext_communities: j
                    .extended_community
                    .map(|c| ext_words(&c.string))
                    .unwrap_or_default(),
                last_update: j.last_update.and_then(|l| l.epoch),
                rpki: j.rpki_validation_state,
                stale: j.stale,
            }
        })
        .collect();
    Ok(BgpPrefix {
        prefix: p.prefix.unwrap_or_default(),
        paths,
        default_local_pref: None,
        local_as: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // Answers of FRR 10.7.1 (VM lab, 2026-10-27), trimmed.
    const RECEIVED: &str = r#"{
"bgpTableVersion":4,"bgpLocalRouterId":"198.51.100.1","defaultLocPrf":100,"localAS":65000,"receivedRoutes": {"10.20.1.0/24":{"addrPrefix":"10.20.1.0","prefixLen":24,"network":"10.20.1.0/24","nextHop":"198.51.100.18","metric":0,"locPrf":200,"weight":0,"path":"64502 64502","origin":"IGP","valid":true,"best":true},"10.30.2.0/24":{"addrPrefix":"10.30.2.0","prefixLen":24,"network":"10.30.2.0/24","nextHop":"198.51.100.18","metric":0,"locPrf":100,"weight":0,"path":"64502 64502","origin":"IGP","valid":true,"best":true}}
,"totalPrefixCounter":2,"filteredPrefixCounter":0,"totalPathsCount":0}"#;

    const ROUTES: &str = r#"{
 "vrfId": 0, "vrfName": "default", "tableVersion": 4, "routerId": "198.51.100.1", "defaultLocPrf": 100, "localAS": 65000,
 "routes": { "10.20.1.0/24": [{"valid":true,"bestpath":true,"selectionReason":"Local Pref","pathFrom":"internal","prefix":"10.20.1.0","prefixLen":24,"network":"10.20.1.0/24","version":3,"metric":0,"locPrf":200,"weight":0,"peerId":"198.51.100.18","path":"64502 64502","origin":"IGP","nexthops":[{"ip":"198.51.100.18","hostname":"corerouter-lab","afi":"ipv4","used":true}]}]
,"10.30.2.0/24": [{"valid":true,"bestpath":true,"selectionReason":"First path received","pathFrom":"internal","prefix":"10.30.2.0","prefixLen":24,"network":"10.30.2.0/24","version":2,"metric":0,"locPrf":100,"weight":0,"peerId":"198.51.100.18","path":"64502 64502","origin":"IGP","nexthops":[{"ip":"198.51.100.18","hostname":"corerouter-lab","afi":"ipv4","used":true}]}]
 } , "totalRoutes": 2, "totalPaths": 5,"numRoutes":2
 } "#;

    const PREFIX: &str = r#"{"prefix":"10.20.1.0/24","version":3,"pathCount":2,"paths":[
{"aspath":{"string":"64502 64502","segments":[{"type":"as-sequence","list":[64502,64502]}],"length":2},"origin":"IGP","metric":0,"locPrf":200,"valid":true,"version":3,"bestpath":{"overall":true,"selectionReason":"Local Pref"},"community":{"string":"65000:2 65000:100","list":["65000:2","65000:100"]},"largeCommunity":{"string":"65000:1:2","list":["65000:1:2"]},"lastUpdate":{"epoch":1793134358,"string":"Tue Oct 27 20:52:38 2026"},"nexthops":[{"ip":"198.51.100.18","afi":"ipv4","metric":0,"accessible":true,"used":true}],"peer":{"peerId":"198.51.100.18","routerId":"198.51.100.18","type":"internal"}},
{"aspath":{"string":"64503 64503","segments":[{"type":"as-sequence","list":[64503,64503]}],"length":2},"origin":"IGP","metric":0,"locPrf":100,"valid":true,"version":3,"nexthops":[{"ip":"198.51.100.22","afi":"ipv4","metric":0,"accessible":true,"used":true}],"peer":{"peerId":"198.51.100.22","routerId":"198.51.100.22","type":"internal"}}],
"multiPathCount":1,"flags":{"bestPathExists":true}}"#;

    #[test]
    fn received_routes_stream_into_a_compact_table() {
        let mut b = Builder::new(true, None);
        let p = parse_table(RECEIVED.as_bytes(), &mut b).unwrap();
        assert_eq!((p.routes, p.warning), (2, None));
        let rib = b.finish();
        assert_eq!(rib.routes.len(), 2);
        // Both share one attribute set but local-pref: two sets.
        assert_eq!(rib.attrs.len(), 2);
        let a = rib.attrs_of(&rib.routes[0]).unwrap();
        assert_eq!(
            (a.as_path.as_str(), a.local_pref, a.next_hop),
            ("64502 64502", Some(200), "198.51.100.18".parse().ok())
        );
        assert!(rib.routes[0].best());
    }

    #[test]
    fn accepted_routes_keep_the_neighbor_s_paths() {
        let mut b = Builder::new(false, "198.51.100.18".parse().ok());
        parse_table(ROUTES.as_bytes(), &mut b).unwrap();
        let rib = b.finish();
        assert_eq!(rib.routes.len(), 2);
        assert_eq!(rib.attrs.len(), 2);
        let mut other = Builder::new(false, "198.51.100.99".parse().ok());
        parse_table(ROUTES.as_bytes(), &mut other).unwrap();
        assert_eq!(other.routes(), 0);
    }

    #[test]
    fn no_soft_reconfiguration_and_garbage() {
        let mut b = Builder::new(true, None);
        let p = parse_table(
            r#"{"warning": "Inbound soft reconfiguration not enabled"}"#.as_bytes(),
            &mut b,
        )
        .unwrap();
        assert_eq!(
            p.warning.as_deref(),
            Some("Inbound soft reconfiguration not enabled")
        );
        assert!(parse_table("% Unknown command".as_bytes(), &mut Builder::default()).is_err());
        assert!(
            parse_table(
                r#"{"routes": {"x": 3}}"#.as_bytes(),
                &mut Builder::default()
            )
            .is_err()
        );
        // A route without a usable prefix is skipped, not an error.
        let mut b = Builder::default();
        parse_table(
            r#"{"routes": {"nope": [{"path": "1"}]}}"#.as_bytes(),
            &mut b,
        )
        .unwrap();
        assert_eq!(b.routes(), 0);
    }

    #[test]
    fn prefix_detail() {
        let p = parse_prefix(PREFIX).unwrap();
        assert_eq!(p.paths.len(), 2);
        let best = &p.paths[0];
        assert!(best.best && best.valid);
        assert_eq!(best.selection_reason.as_deref(), Some("Local Pref"));
        assert_eq!(best.peer_kind, PeerKind::Internal);
        assert_eq!(best.segments[0].asns, [64502, 64502]);
        assert_eq!(best.communities, ["65000:2", "65000:100"]);
        assert_eq!(best.large_communities, ["65000:1:2"]);
        assert_eq!(best.igp_metric, Some(0));
        assert_eq!(p.paths[1].local_pref, Some(100));
        assert_eq!(parse_prefix("{}").unwrap().paths.len(), 0);
        assert_eq!(
            parse_prefix("% Network not in table").unwrap().paths.len(),
            0
        );
    }
}
