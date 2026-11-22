//! The Segment Routing database of `ospfd` (G3.4f): `show ip ospf database
//! segment-routing json` (FRR 10.7.1 `ospfd/ospf_sr.c`, `show_sr_node` and
//! `show_sr_prefix`): `{"srdbID": rid, "srNodes": [{routerID, srgbSize,
//! srgbLabel, srlbSize, srlbLabel, nodeMsd, extendedPrefix: [{prefix, sid,
//! inputLabel, prefixRoute: [{outputLabel, interface, nexthop}]}],
//! extendedLink: [...]}]}`.
//!
//! Read leniently like the rest of the daemon's JSON: an odd field is
//! skipped; only text that is not JSON is an error.

use std::net::Ipv4Addr;

use corerouter_model::ospf_sr::{SrDb, SrHop, SrNode, SrPrefix};
use ipnet::Ipv4Net;
use serde_json::{Map, Value};

/// Most SR routers kept (an area of 10 000 routers is far past what one
/// OSPF area runs, **estimado**).
pub const MAX_NODES: usize = 10_000;
/// Most prefixes and ways out kept per router.
pub const MAX_PER_NODE: usize = 1_000;
const MAX_HOPS: usize = 16;

fn num(m: &Map<String, Value>, k: &str) -> Option<u32> {
    m.get(k)
        .and_then(Value::as_u64)
        .and_then(|n| u32::try_from(n).ok())
}

fn ip(m: &Map<String, Value>, k: &str) -> Option<u32> {
    m.get(k)
        .and_then(Value::as_str)
        .and_then(|s| s.parse::<Ipv4Addr>().ok())
        .map(u32::from)
}

fn text(m: &Map<String, Value>, k: &str) -> String {
    m.get(k)
        .and_then(Value::as_str)
        .map(|s| s.chars().take(32).collect())
        .unwrap_or_default()
}

pub fn sr_db(json: &str) -> Result<SrDb, String> {
    let v: Value =
        serde_json::from_str(json).map_err(|e| format!("ospfd answered bad JSON: {e}"))?;
    let Value::Object(top) = v else {
        return Ok(SrDb::default());
    };
    let mut db = SrDb {
        router_id: ip(&top, "srdbID"),
        nodes: Vec::new(),
    };
    let nodes = top.get("srNodes").and_then(Value::as_array);
    for n in nodes.into_iter().flatten().take(MAX_NODES) {
        let Value::Object(n) = n else { continue };
        let Some(router_id) = ip(n, "routerID") else {
            continue;
        };
        let prefixes = n
            .get("extendedPrefix")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .take(MAX_PER_NODE)
            .filter_map(Value::as_object)
            .filter_map(prefix)
            .collect();
        let adjacencies = n
            .get("extendedLink")
            .and_then(Value::as_array)
            .map_or(0, |a| u32::try_from(a.len()).unwrap_or(u32::MAX));
        db.nodes.push(SrNode {
            router_id,
            srgb_start: num(n, "srgbLabel").unwrap_or(0),
            srgb_size: num(n, "srgbSize").unwrap_or(0),
            srlb_start: num(n, "srlbLabel").unwrap_or(0),
            srlb_size: num(n, "srlbSize").unwrap_or(0),
            msd: num(n, "nodeMsd").and_then(|m| u8::try_from(m).ok()),
            prefixes,
            adjacencies,
        });
    }
    db.nodes.sort_by_key(|n| n.router_id);
    Ok(db)
}

fn prefix(m: &Map<String, Value>) -> Option<SrPrefix> {
    let net: Ipv4Net = m.get("prefix")?.as_str()?.parse().ok()?;
    let out = m
        .get("prefixRoute")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .take(MAX_HOPS)
        .filter_map(Value::as_object)
        .map(|h| SrHop {
            label: num(h, "outputLabel").unwrap_or(0),
            interface: text(h, "interface"),
            nexthop: ip(h, "nexthop").unwrap_or(0),
        })
        .collect();
    Some(SrPrefix {
        prefix: u32::from(net.addr()),
        plen: net.prefix_len(),
        sid: num(m, "sid")?,
        in_label: num(m, "inputLabel").unwrap_or(0),
        out,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shape `show_sr_node` prints (FRR 10.7.1), two routers.
    pub(crate) const SAMPLE: &str = r#"{
      "srdbID": "10.255.0.1",
      "srNodes": [
        {"routerID": "10.255.0.2", "srgbSize": 8000, "srgbLabel": 16000,
         "srlbSize": 1000, "srlbLabel": 15000,
         "algorithms": [{"0": "SPF"}], "nodeMsd": 8,
         "extendedPrefix": [
           {"prefix": "10.255.0.2/32", "sid": 2, "inputLabel": 16002,
            "prefixRoute": [{"outputLabel": 3, "interface": "ether1", "nexthop": "10.0.12.2"}]}
         ],
         "extendedLink": [{"prefix": "10.0.12.2/32", "sid": 15000}]},
        {"routerID": "10.255.0.1", "srgbSize": 8000, "srgbLabel": 16000,
         "srlbSize": 1000, "srlbLabel": 15000,
         "extendedPrefix": [{"prefix": "10.255.0.1/32", "sid": 1, "inputLabel": 0,
            "prefixRoute": [{"outputLabel": 3, "interface": "lo", "nexthop": "0.0.0.0"}]}]},
        {"routerID": "junk"},
        "junk"
      ]
    }"#;

    #[test]
    fn reads_the_sr_database() {
        let db = sr_db(SAMPLE).unwrap();
        assert_eq!(db.router_id, Some(u32::from(Ipv4Addr::new(10, 255, 0, 1))));
        assert_eq!(db.nodes.len(), 2);
        let r2 = &db.nodes[1];
        assert_eq!(r2.srgb_start, 16_000);
        assert_eq!(r2.srgb_size, 8000);
        assert_eq!(r2.msd, Some(8));
        assert_eq!(r2.adjacencies, 1);
        let p = &r2.prefixes[0];
        assert_eq!((p.sid, p.in_label, p.plen), (2, 16_002, 32));
        assert_eq!(p.out[0].label, 3);
        assert_eq!(p.out[0].interface, "ether1");
        assert!(sr_db("not json").is_err());
        assert_eq!(sr_db("[]").unwrap(), SrDb::default());
    }
}
