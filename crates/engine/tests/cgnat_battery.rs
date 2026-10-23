//! G2.3e — the CGNAT battery at the command level: the planner says what a
//! real pool then does, and every subscriber's slot leads back to it
//! through "who was" (RFC 7422 §2: the mapping must be reversible), for
//! random pool shapes; hostile planner input never panics.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use corerouter_engine::Session;
use proptest::prelude::*;
use serde_json::{Value, json};

const T0: u64 = 1_780_000_000;

fn ok(s: &mut Session, id: &str, p: Value) -> Value {
    s.execute(id, &p).unwrap_or_else(|e| panic!("{id} {p}: {e}"))
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 48, ..ProptestConfig::default() })]

    /// What the planner says fits is what the pool built from its own
    /// parameters holds, and each subscriber comes back from its slot.
    #[test]
    fn the_plan_is_the_pool_and_every_slot_leads_back(
        sub_bits in 2u32..13,
        public in 1u32..64,
        ports in 64u16..4000,
        pick in any::<u32>(),
    ) {
        let mut s = Session::virtual_lab();
        s.tick(T0);
        let subs = 1u32 << sub_bits;
        let plan = ok(&mut s, "tool.ip-calc.cgnat.plan", json!({
            "inside": subs.to_string(), "outside": public.to_string(), "ports_per_subscriber": ports, "preview": 3,
        }));
        let capacity = plan["capacity"].as_u64().unwrap();
        let fits = plan["fits"].as_bool().unwrap();
        prop_assert_eq!(fits, capacity >= u64::from(subs), "{}", plan);
        if !fits {
            prop_assert!(plan.get("pool").is_none());
            return Ok(());
        }
        prop_assert!(plan["public_needed"].as_u64().unwrap() <= u64::from(public));
        let mut pool = plan["pool"].clone();
        pool["name"] = json!("p");
        ok(&mut s, "ip.firewall.cgnat.pool.add", pool);
        s.tick(T0 + 10);
        // The preview's rows are the pool's.
        for row in plan["preview"].as_array().unwrap() {
            let l = ok(&mut s, "ip.firewall.cgnat.lookup", json!({"subscriber": row["subscriber"]}));
            prop_assert_eq!(&l["public"], &row["public"]);
            prop_assert_eq!(&l["first_port"], &row["first_port"]);
        }
        // A random subscriber: lookup, then who was on its slot's ports.
        let i = pick % subs;
        let sub = std::net::Ipv4Addr::from(0x6440_0000u32 + i).to_string();
        let l = ok(&mut s, "ip.firewall.cgnat.lookup", json!({"subscriber": sub}));
        let (first, last) = (l["first_port"].as_u64().unwrap(), l["last_port"].as_u64().unwrap());
        for port in [first, last, (first + last) / 2] {
            let w = ok(&mut s, "ip.firewall.cgnat.who-was", json!({"public": l["public"], "port": port}));
            prop_assert_eq!(w["subscriber"].as_str(), Some(sub.as_str()));
        }
    }

    /// Hostile planner input is a parameter error, never a panic.
    #[test]
    fn hostile_planner_input(inside in ".{0,80}", outside in ".{0,80}", ports in any::<i64>()) {
        let mut s = Session::virtual_lab();
        let _ = s.execute("tool.ip-calc.cgnat.plan", &json!({"inside": inside, "outside": outside, "ports_per_subscriber": ports}));
        let _ = s.execute("tool.ip-calc.cgnat.export", &json!({"inside": inside, "outside": outside, "format": "csv"}));
        let _ = s.execute("ip.firewall.cgnat.who-was", &json!({"public": inside, "port": ports, "time": outside}));
    }
}
