//! The pair with BFD on its two paths (G3.6h), in the in-memory lab: the
//! takeover in ~150 ms instead of the hellos' dead interval, the same
//! majority rule (a fresh witness answer before taking over), false
//! alarms damped, and the random faults of `sim.rs` with BFD on.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use corerouter_proto_ha::lab::{Lab, LabConfig};
use corerouter_proto_ha::msg::Role;
use corerouter_proto_ha::role::Reason;

/// RFC 5880 §6.8.4: detection time = multiplier × interval (50 ms × 3).
const DETECT: u64 = 150;

fn lab(bfd: [Option<u64>; 2]) -> Lab {
    let mut l = Lab::new(LabConfig {
        bfd_ms: bfd,
        ..LabConfig::default()
    });
    l.run_until(10_000, |l| l.active().is_some()).unwrap();
    l.load(20_000);
    l.run_until(60_000, Lab::in_sync).unwrap();
    // The BFD sessions are up on both nodes.
    l.run(100);
    l
}

#[test]
fn bfd_on_both_paths_takes_over_in_about_the_detection_time() {
    let mut l = lab([Some(DETECT), Some(DETECT)]);
    let before = l.table(0);
    l.kill(0);
    let t = l.run_until(5_000, |l| l.active() == Some(1)).unwrap();
    // Detection, one witness round trip (2 × latency), steps of 5 ms.
    assert!(t <= DETECT + 4 * l.cfg.latency_ms + 3 * l.cfg.step_ms, "takeover in {t} ms");
    assert_eq!(l.lost(&before, 1), 0, "every session kept");
    let tr = *l.nodes[1].transitions.last().unwrap();
    assert_eq!((tr.to, tr.reason, tr.stateful), (Role::Active, Reason::PeerDead, true));
    let d = tr.detection.unwrap();
    assert_eq!(d.bfd, [true, true], "found by BFD on both paths");
    assert!(d.witness_at.unwrap() >= d.detected, "a fresh witness answer: {d:?}");
    assert!(d.last_heard <= d.detected && tr.at >= d.detected);
    assert_eq!(l.nodes[1].probes, 1, "one probe");
    eprintln!("BFD {DETECT} ms: takeover {t} ms after the kill, 0 of {} lost, {d:?}", before.len());
    assert_eq!(l.watch.split_brain_ms, 0);
}

#[test]
fn bfd_on_one_path_waits_for_the_other_paths_hellos() {
    let mut l = lab([Some(DETECT), None]);
    l.kill(0);
    let t = l.run_until(5_000, |l| l.active() == Some(1)).unwrap();
    let dead = l.cfg.role[1].dead_ms;
    assert!(t + 300 >= dead, "the access hellos still count ({t} ms)");
    let d = l.nodes[1].transitions.last().unwrap().detection.unwrap();
    assert_eq!(d.bfd, [false, false], "the dead interval found the silence");
}

#[test]
fn without_a_fresh_witness_answer_bfd_does_not_take_over() {
    let mut l = lab([Some(DETECT), Some(DETECT)]);
    // Node 2 is the isolated one: both paths and its witness gone.
    l.set_witness(1, false);
    l.cut_sync();
    l.cut_access();
    l.run(3_000);
    assert_ne!(l.roles()[1], Role::Active, "no fresh answer: no takeover");
    assert_eq!(l.roles()[0], Role::Active, "the healthy node keeps serving");
    assert!(l.nodes[1].probes >= 1, "it asked the witness");
    l.set_witness(1, true);
    l.heal_access();
    l.heal_sync();
    l.run_until(15_000, Lab::in_sync).unwrap();
    assert_eq!(l.roles(), [Role::Active, Role::Standby]);
    assert_eq!(l.watch.split_brain_ms, 0);
}

#[test]
fn bfd_lost_on_one_path_while_the_peer_lives_changes_nothing() {
    let mut l = lab([Some(DETECT), Some(DETECT)]);
    for _ in 0..5 {
        l.bfd_blocked_until[0] = l.now + 500;
        l.run(2_000);
        assert_eq!(l.roles(), [Role::Active, Role::Standby]);
    }
    let b = l.node(1).unwrap().ha().status(l.now).bfd[0];
    // A false alarm costs two penalties: the next loss damps the path's
    // BFD (hellos only).
    assert!(b.losses >= 5 && b.false_alarms == 1 && b.suppressed, "{b:?}");
}

#[test]
fn a_flapping_link_is_damped_after_its_first_false_alarm() {
    let mut l = lab([Some(DETECT), Some(DETECT)]);
    let mut takeovers = 0;
    let mut role = l.active();
    for _ in 0..6 {
        // BFD lost on both paths while the hellos pass: from BFD alone,
        // the peer looks dead.
        l.bfd_blocked_until = [l.now + 400, l.now + 400];
        l.run(1_500);
        if l.active() != role {
            takeovers += 1;
            role = l.active();
        }
        assert!(l.active().is_some());
    }
    assert!(takeovers <= 1, "{takeovers} takeovers: damped after the first false alarm");
    let s = l.node(1).unwrap().ha().status(l.now);
    assert!(s.bfd.iter().all(|b| b.suppressed), "{:?}", s.bfd);
    // Quiet: the penalty decays below reuse and BFD counts again.
    l.run(60_000);
    let s = l.node(1).unwrap().ha().status(l.now);
    assert!(s.bfd.iter().all(|b| !b.suppressed), "{:?}", s.bfd);
    let a = l.active().unwrap();
    l.kill(a);
    let t = l.run_until(5_000, |l| l.active() == Some(1 - a)).unwrap();
    assert!(t <= DETECT + 30, "fast again: {t} ms");
    assert_eq!(l.watch.split_brain_ms, 0);
}

#[test]
fn a_simulated_failure_silences_bfd_too() {
    let mut l = lab([Some(DETECT), Some(DETECT)]);
    l.simulate_failure(0, 5_000).unwrap();
    let t = l.run_until(5_000, |l| l.active() == Some(1)).unwrap();
    assert!(t <= DETECT + 30, "the peer detects it as a crash: {t} ms");
    l.run_until(30_000, Lab::in_sync).unwrap();
    assert_eq!(l.roles(), [Role::Standby, Role::Active]);
}

#[test]
fn random_faults_with_bfd_never_put_two_actives_on_the_same_subscribers() {
    let seeds: u64 = std::env::var("HA_SIM_SEEDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(12);
    for seed in 1..=seeds {
        let mut l = Lab::new(LabConfig {
            seed,
            access_loss: 20_000,
            trace: true,
            bfd_ms: [Some(DETECT), Some(DETECT)],
            ..LabConfig::default()
        });
        l.run(1000);
        l.load(3000);
        for _ in 0..120 {
            match l.rng.below(16) {
                0 => {
                    let i = l.rng.below(2) as usize;
                    l.kill(i);
                }
                1 => {
                    for i in 0..2 {
                        if !l.nodes[i].alive {
                            l.restart(i);
                        }
                    }
                }
                2 => l.cut_sync(),
                3 | 4 => l.heal_sync(),
                5 => l.cut_access(),
                6 | 7 => l.heal_access(),
                8 => {
                    let i = l.rng.below(2) as usize;
                    let ok = l.rng.below(3) > 0;
                    l.set_witness(i, ok);
                }
                9 => {
                    let i = l.rng.below(2) as usize;
                    let force = l.rng.below(2) == 0;
                    let _ = l.switchover(i, force);
                }
                10 => {
                    let i = l.rng.below(2) as usize;
                    let ms = 500 + l.rng.below(3000);
                    let _ = l.simulate_failure(i, ms);
                }
                11 => {
                    let i = l.rng.below(2) as usize;
                    let ok = l.rng.below(3) > 0;
                    l.set_track(i, ok);
                }
                12 | 13 => {
                    let p = l.rng.below(3) as usize;
                    let until = l.now + 100 + l.rng.below(600);
                    match p {
                        0 | 1 => l.bfd_blocked_until[p] = until,
                        _ => l.bfd_blocked_until = [until, until],
                    }
                }
                _ => {}
            }
            let steps = 20 + l.rng.below(200);
            for _ in 0..steps {
                l.churn(4000, 2, 1, 2);
                l.step();
            }
            let tail = l.log.len().saturating_sub(30);
            assert_eq!(l.watch.split_brain_ms, 0, "seed {seed}:\n{}", l.log[tail..].join("\n"));
        }
        for i in 0..2 {
            if !l.nodes[i].alive {
                l.restart(i);
            }
            l.set_witness(i, true);
            l.set_track(i, true);
        }
        l.bfd_blocked_until = [0, 0];
        l.heal_sync();
        l.heal_access();
        assert!(l.run_until(60_000, Lab::in_sync).is_some(), "seed {seed}: roles {:?}", l.roles());
        assert_eq!(l.watch.split_brain_ms, 0, "seed {seed}");
        eprintln!("seed {seed}: {:?}", l.watch);
    }
}
