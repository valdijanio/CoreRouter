//! BGP routes read from bgpd for the `/routing filter` preview (G3.2b).
//!
//! - What a neighbor sent, before the input chain: `show bgp … neighbors X
//!   received-routes json` (needs `soft-reconfiguration inbound`, the
//!   connection's `keep_received`) has every route with its path but no
//!   communities; `received-routes detail` (text) has the communities but
//!   only of the routes the input chain accepted, and `detail json` is
//!   empty objects (FRR 10.7.1, **medido** in the lab VM, 2026-10-27). The
//!   two are merged; a route only the first lists is `partial`.
//! - What this router would send, before the output chain: its best
//!   routes, `show bgp … detail json`.
//!
//! Both are read leniently: a block or field that does not parse is
//! skipped, never an error.

use corerouter_model::bgp_route::BgpRouteEntry;
use corerouter_proto_bgp::filter::{CommunityValue, parse_community};
use ipnet::IpNet;
use serde_json::Value;

/// "65200 {65001,65002} (65100)" → [65200, 65001, 65002, 65100]; "Local"
/// → []. Anything after a comma (", (Received from a RR-client)") is not
/// part of the path.
fn path_of(text: &str) -> Vec<u32> {
    let head = text.split(", ").next().unwrap_or_default();
    head.split(|c: char| !c.is_ascii_digit())
        .filter_map(|t| t.parse().ok())
        .collect()
}

fn communities(words: &str, e: &mut BgpRouteEntry) {
    for w in words.split_whitespace() {
        match parse_community(w) {
            Ok(CommunityValue::Normal(c)) => e.communities.push(c),
            Ok(CommunityValue::Large(l)) => e.large.push((l.0, l.1, l.2)),
            Err(_) => {}
        }
    }
}

fn number_after(line: &str, key: &str) -> Option<u32> {
    let i = line.find(key)?;
    line.get(i + key.len()..)?
        .split(|c: char| !c.is_ascii_digit())
        .next()?
        .parse()
        .ok()
}

/// The routes of `received-routes detail` (text).
pub fn received_text(text: &str) -> Vec<BgpRouteEntry> {
    let lines: Vec<&str> = text.lines().collect();
    let mut out = Vec::new();
    let mut cur: Option<BgpRouteEntry> = None;
    for (i, line) in lines.iter().enumerate() {
        if let Some(rest) = line.strip_prefix("BGP routing table entry for ") {
            if let Some(e) = cur.take() {
                out.push(e);
            }
            let p = rest.split(',').next().unwrap_or_default().trim();
            cur = Some(BgpRouteEntry {
                prefix: p.parse::<IpNet>().ok(),
                ..Default::default()
            });
            continue;
        }
        let Some(e) = cur.as_mut() else { continue };
        let t = line.trim();
        // The path is the line just above "<nexthop> from <peer> (<id>)".
        if lines
            .get(i + 1)
            .is_some_and(|n| n.trim_start().contains(" from ") && n.starts_with("    "))
            && line.starts_with("  ")
        {
            e.as_path = path_of(t);
        } else if let Some(rest) = t.strip_prefix("Large Community: ") {
            communities(rest, e);
        } else if let Some(rest) = t.strip_prefix("Community: ") {
            communities(rest, e);
        } else if t.starts_with("Origin ") {
            e.med = number_after(t, "metric ");
            e.local_pref = number_after(t, "localpref ");
        }
    }
    if let Some(e) = cur {
        out.push(e);
    }
    out.retain(|e| e.prefix.is_some());
    out
}

/// `received-routes json` (every route, path and MED; no communities),
/// completed with the communities of `received-routes detail` (`text`).
pub fn received(json: &str, text: &str) -> Result<Vec<BgpRouteEntry>, String> {
    let v: Value =
        serde_json::from_str(json).map_err(|e| format!("bgpd answered bad JSON: {e}"))?;
    let detail: std::collections::HashMap<IpNet, BgpRouteEntry> = received_text(text)
        .into_iter()
        .filter_map(|e| Some((e.prefix?, e)))
        .collect();
    let Some(routes) = v.get("receivedRoutes").and_then(Value::as_object) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::with_capacity(routes.len());
    for (prefix, r) in routes {
        let Ok(p) = prefix.parse::<IpNet>() else {
            continue;
        };
        if let Some(d) = detail.get(&p) {
            out.push(d.clone());
            continue;
        }
        out.push(BgpRouteEntry {
            prefix: Some(p),
            as_path: r
                .get("path")
                .and_then(Value::as_str)
                .map(path_of)
                .unwrap_or_default(),
            med: r
                .get("metric")
                .and_then(Value::as_u64)
                .and_then(|n| u32::try_from(n).ok()),
            local_pref: r
                .get("locPrf")
                .and_then(Value::as_u64)
                .and_then(|n| u32::try_from(n).ok()),
            partial: true,
            ..Default::default()
        });
    }
    Ok(out)
}

/// The best routes of `show bgp … detail json` (`{"routes": {prefix:
/// [path…]}}`).
pub fn best_json(json: &str) -> Result<Vec<BgpRouteEntry>, String> {
    let v: Value =
        serde_json::from_str(json).map_err(|e| format!("bgpd answered bad JSON: {e}"))?;
    let Some(routes) = v.get("routes").and_then(Value::as_object) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::with_capacity(routes.len());
    for (prefix, paths) in routes {
        let Some(paths) = paths.as_array() else {
            continue;
        };
        let best = paths.iter().find(|p| {
            p.get("bestpath").is_some_and(|b| {
                b.get("overall").and_then(Value::as_bool) == Some(true) || b.as_bool() == Some(true)
            })
        });
        let Some(p) = best else { continue };
        let mut e = BgpRouteEntry {
            prefix: prefix.parse().ok(),
            ..Default::default()
        };
        if let Some(segs) = p.pointer("/aspath/segments").and_then(Value::as_array) {
            for s in segs {
                for a in s
                    .get("list")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    if let Some(n) = a.as_u64().and_then(|n| u32::try_from(n).ok()) {
                        e.as_path.push(n);
                    }
                }
            }
        }
        for key in ["/community/list", "/largeCommunity/list"] {
            for c in p
                .pointer(key)
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                if let Some(s) = c.as_str() {
                    communities(s, &mut e);
                }
            }
        }
        e.med = p
            .get("metric")
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok());
        e.local_pref = p
            .get("locPrf")
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok());
        if e.prefix.is_some() {
            out.push(e);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FRR 10.7.1's answer in the lab (scripts/frr-policy-live.sh).
    const RECEIVED: &str = "BGP table version is 9, local router ID is 198.51.100.33, vrf id 0
Default local pref 100, local AS 65000
BGP routing table entry for 10.66.0.0/16, version 6
Paths: (1 available, best #1, table default)
  Advertised to peers:
  198.51.100.38
  65200
    198.51.100.34 from 198.51.100.34 (198.51.100.34)
      Origin IGP, metric 0, valid, external, best (First path received)
      Community: 65200:666
      Last update: Tue Oct 27 21:15:54 2026
BGP routing table entry for 203.0.113.0/24, version 9
Paths: (1 available, best #1, table default)
  Not advertised to any peer
  65200 64512 {64513,64514}
    198.51.100.34 from 198.51.100.34 (198.51.100.34)
      Origin IGP, metric 7, localpref 120, valid, external, best (First path received)
      Community: 65200:100 65200:200 no-export
      Large Community: 65200:1:2
      Last update: Tue Oct 27 21:15:54 2026

Total number of prefixes 2, total number of paths 0
";

    #[test]
    fn received_routes_text_parses() {
        let r = received_text(RECEIVED);
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].prefix, Some("10.66.0.0/16".parse().unwrap()));
        assert_eq!(r[0].as_path, [65200]);
        assert_eq!(r[0].communities, [65200 << 16 | 666]);
        assert_eq!(r[1].as_path, [65200, 64512, 64513, 64514]);
        assert_eq!(
            r[1].communities,
            [65200 << 16 | 100, 65200 << 16 | 200, 0xFFFF_FF01]
        );
        assert_eq!(r[1].large, [(65200, 1, 2)]);
        assert_eq!((r[1].med, r[1].local_pref), (Some(7), Some(120)));
        assert!(received_text("% Inbound soft reconfiguration not enabled\n").is_empty());
        assert!(
            received_text("BGP routing table entry for nonsense, x\n  1\n    a from b\n")
                .is_empty()
        );
    }

    #[test]
    fn received_json_and_text_merge() {
        let j = r#"{"receivedRoutes": {
          "10.66.0.0/16": {"path":"65200","metric":0},
          "198.18.0.0/15": {"path":"65200 64512","metric":3},
          "bad": {}
        }}"#;
        let r = received(j, RECEIVED).unwrap();
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].communities, [65200 << 16 | 666]);
        assert!(!r[0].partial);
        assert_eq!(
            (r[1].as_path.clone(), r[1].med, r[1].partial),
            (vec![65200, 64512], Some(3), true)
        );
        assert!(received("x", "").is_err());
    }

    #[test]
    fn best_routes_json_parses() {
        let j = r#"{"routes": {
          "10.30.1.0/24": [{"aspath":{"string":"Local","segments":[],"length":0},"metric":0,"locPrf":100,"bestpath":{"overall":true}}],
          "203.0.113.0/24": [
            {"aspath":{"segments":[{"type":"as-sequence","list":[65300]}]},"bestpath":{"overall":false}},
            {"aspath":{"segments":[{"type":"as-sequence","list":[65200]}]},"metric":5,"bestpath":{"overall":true},
             "community":{"list":["65200:100","no-export"]},"largeCommunity":{"list":["65200:1:2"]}}],
          "bad": [{"bestpath":{"overall":true}}]
        }}"#;
        let r = best_json(j).unwrap();
        assert_eq!(r.len(), 2);
        assert!(r[0].as_path.is_empty());
        assert_eq!(r[1].as_path, [65200]);
        assert_eq!(r[1].communities, [65200 << 16 | 100, 0xFFFF_FF01]);
        assert_eq!(r[1].large, [(65200, 1, 2)]);
        assert!(best_json("nope").is_err());
        assert_eq!(best_json("{}").unwrap(), []);
    }
}
