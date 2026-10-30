//! Every command, fed garbage, must return Ok or a typed error — never
//! `Internal` (which would mean a panic was caught by the guard).

use corerouter_engine::{EngineError, Session, cmd};
use serde_json::{Value, json};

fn garbage() -> Vec<Value> {
    vec![
        Value::Null,
        json!(true),
        json!(-1),
        json!(1e308),
        json!(u64::MAX),
        json!(""),
        json!("zz"),
        json!("*FFFFFFFFFF"),
        json!("10.0.0.1/99"),
        json!("x".repeat(10_000)),
        json!("\u{0}\u{7}"),
        json!([]),
        json!({}),
    ]
}

/// G0.30: the sweep grows with every command added, so it is split into
/// `SHARDS` tests that nextest runs side by side (one test over all of them
/// took 10.2 s on the GitHub runner, above the quick-layer ceiling). Shard
/// `i` takes every command whose index is `i` modulo `SHARDS`, split again
/// over the cores; each input still gets a fresh lab.
const SHARDS: usize = 16;

fn sweep_shard(shard: usize) {
    let specs: Vec<_> = cmd::all().skip(shard).step_by(SHARDS).collect();
    assert!(!specs.is_empty(), "shard {shard} has no command");
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get().min(8));
    let chunk = specs.len().div_ceil(threads).max(1);
    let failures: Vec<String> = std::thread::scope(|scope| {
        let parts: Vec<_> = specs
            .chunks(chunk)
            .map(|part| {
                scope.spawn(move || {
                    part.iter()
                        .filter_map(|s| sweep(s).err())
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        parts
            .into_iter()
            .flat_map(|p| {
                p.join()
                    .unwrap_or_else(|_| vec!["a sweep thread panicked".to_owned()])
            })
            .collect()
    });
    assert!(failures.is_empty(), "{failures:#?}");
}

mod no_command_panics_on_garbage {
    macro_rules! shards {
        ($($name:ident = $i:expr),* $(,)?) => {
            $(#[test]
            fn $name() {
                super::sweep_shard($i);
            })*
        };
    }
    shards!(
        shard_00 = 0,
        shard_01 = 1,
        shard_02 = 2,
        shard_03 = 3,
        shard_04 = 4,
        shard_05 = 5,
        shard_06 = 6,
        shard_07 = 7,
        shard_08 = 8,
        shard_09 = 9,
        shard_10 = 10,
        shard_11 = 11,
        shard_12 = 12,
        shard_13 = 13,
        shard_14 = 14,
        shard_15 = 15,
    );

    /// The shards cover every command exactly once.
    #[test]
    fn the_shards_cover_every_command() {
        let total = corerouter_engine::cmd::all().count();
        let covered: usize = (0..super::SHARDS)
            .map(|i| {
                corerouter_engine::cmd::all()
                    .skip(i)
                    .step_by(super::SHARDS)
                    .count()
            })
            .sum();
        assert_eq!(covered, total);
    }
}

/// Every garbage input of one command; `Err` names the one that panicked.
fn sweep(spec: &cmd::CommandSpec) -> Result<(), String> {
    let mut inputs = vec![Value::Null, json!([]), json!(42), json!({"bogus": 1})];
    let keys = cmd::doc_keys(spec.params);
    for g in garbage() {
        let mut obj = serde_json::Map::new();
        for (k, _) in &keys {
            obj.insert((*k).to_owned(), g.clone());
        }
        inputs.push(Value::Object(obj));
        for (k, _) in &keys {
            inputs.push(json!({ *k: g.clone() }));
        }
    }
    for params in inputs {
        let mut s = Session::virtual_lab();
        if let Err(EngineError::Internal(what)) = s.execute(spec.id, &params) {
            return Err(format!("{what} panicked with params {params}"));
        }
    }
    Ok(())
}
