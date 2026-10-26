//! Two BNGs in memory (`lab`): failover, split-brain attempts, link flaps
//! and resync, up to 100 000 sessions. After every step the lab's watch
//! checks that two nodes never answer the same subscribers
//! (`split_brain_ms`), and each test ends with the pair converged: one
//! active, the standby's replica equal to the active's table.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use corerouter_proto_ha::lab::{Lab, LabConfig};
use corerouter_proto_ha::msg::Role;
use corerouter_proto_ha::role::Reason;

fn booted(sessions: u32) -> Lab {
    let mut l = Lab::new(LabConfig::default());
    let t = l.run_until(10_000, |l| l.active().is_some()).unwrap();
    assert!(
        t < 1000,
        "two nodes that hear each other elect at once ({t} ms)"
    );
    assert_eq!(l.active(), Some(0), "priority 200 wins");
    l.load(sessions);
    let t = l.run_until(60_000, Lab::in_sync).unwrap();
    eprintln!(
        "{sessions} sessions synced in {t} ms, {} bytes on the link",
        l.sync_bytes
    );
    l
}

#[test]
fn a_hundred_thousand_sessions_sync_and_survive_the_active_dying() {
    let mut l = booted(100_000);
    let per_session = l.sync_bytes / 100_000;
    assert!(per_session < 300, "{per_session} B per session");
    // Steady churn: logins, logouts, counters (a busy BNG: 2000 changes/s).
    for _ in 0..400 {
        l.churn(120_000, 5, 3, 2);
        l.step();
    }
    let t = l.run_until(5_000, Lab::in_sync).unwrap();
    assert!(t < 100, "the replica follows within a few steps ({t} ms)");
    let before = l.table(0);
    let killed = l.now;
    l.kill(0);
    let t = l.run_until(5_000, |l| l.active() == Some(1)).unwrap();
    let dead = l.cfg.role[1].dead_ms;
    assert!(
        t <= dead + 2 * l.cfg.step_ms,
        "takeover in {t} ms (dead interval {dead})"
    );
    let tr = l.nodes[1].transitions.last().unwrap();
    assert_eq!(
        (tr.to, tr.reason, tr.stateful),
        (Role::Active, Reason::PeerDead, true)
    );
    assert_eq!(l.lost(&before, 1), 0, "every session kept");
    eprintln!(
        "killed at {killed}, node 2 active {t} ms later, 0 of {} lost",
        before.len()
    );
    // The dead node comes back: standby, with a full copy, no preemption.
    l.restart(0);
    l.run_until(30_000, Lab::in_sync).unwrap();
    assert_eq!(l.active(), Some(1));
    assert_eq!(l.watch.split_brain_ms, 0);
}

#[test]
fn killing_the_active_mid_churn_loses_only_the_changes_in_flight() {
    let mut l = booted(20_000);
    for _ in 0..200 {
        l.churn(25_000, 20, 10, 10);
        l.step();
    }
    // No pause: the last changes may not be acked yet.
    let before = l.table(0);
    let acked_behind = {
        let s = l.nodes[0].publisher.as_ref().unwrap().status();
        s.seq - s.acked
    };
    l.kill(0);
    l.run_until(5_000, |l| l.active() == Some(1)).unwrap();
    let lost = l.lost(&before, 1);
    eprintln!("{lost} sessions differ after the kill ({acked_behind} changes were unacked)");
    assert!(
        lost as u64 <= acked_behind + 40,
        "{lost} lost, {acked_behind} unacked"
    );
}

#[test]
fn a_cut_sync_link_or_access_path_alone_changes_nothing() {
    let mut l = booted(1000);
    l.cut_sync();
    l.run(5_000);
    assert_eq!(
        l.roles(),
        [Role::Active, Role::Standby],
        "the access hellos keep the peer alive"
    );
    l.heal_sync();
    l.run_until(5_000, Lab::in_sync).unwrap();
    l.cut_access();
    l.run(5_000);
    assert_eq!(l.roles(), [Role::Active, Role::Standby]);
    l.heal_access();
    l.run(1000);
    assert_eq!(
        l.nodes[1].transitions.len(),
        1,
        "standby since boot, never more"
    );
    assert_eq!(l.watch.split_brain_ms + l.watch.partitioned_both_ms, 0);
}

#[test]
fn a_full_partition_with_both_on_the_witness_heals_to_one_active() {
    let mut l = booted(1000);
    l.cut_sync();
    l.cut_access();
    l.run(3_000);
    // Neither hears the other and both reach the witness: each serves the
    // half of the access network it still reaches (counted, not a fault).
    assert_eq!(l.roles(), [Role::Active, Role::Active]);
    assert!(l.watch.partitioned_both_ms > 0);
    l.heal_access();
    let t = l.run_until(2_000, |l| l.active().is_some()).unwrap();
    assert!(t <= 400, "split brain resolved in {t} ms");
    assert_eq!(
        l.active(),
        Some(1),
        "the later takeover (higher epoch) stays"
    );
    l.heal_sync();
    l.run_until(10_000, Lab::in_sync).unwrap();
    assert_eq!(l.watch.split_brain_ms, 0);
}

#[test]
fn an_isolated_active_fences_itself_and_the_peer_takes_over() {
    let mut l = booted(5000);
    let before = l.table(0);
    // Node 1 loses everything: the peer on both paths and its witness.
    l.cut_sync();
    l.cut_access();
    l.set_witness(0, false);
    l.run(2_000);
    assert_eq!(l.roles(), [Role::Fenced, Role::Active]);
    assert_eq!(l.lost(&before, 1), 0);
    assert!(
        l.watch.partitioned_both_ms <= 2 * l.cfg.step_ms,
        "{:?}",
        l.watch
    );
    // Back: the fenced node waits recover_hold, sees an active peer, standby.
    l.set_witness(0, true);
    l.heal_access();
    l.heal_sync();
    l.run_until(15_000, Lab::in_sync).unwrap();
    assert_eq!(l.roles(), [Role::Standby, Role::Active]);
    assert_eq!(l.watch.split_brain_ms, 0);
}

#[test]
fn without_the_witness_the_standby_never_takes_over() {
    let mut l = booted(100);
    l.set_witness(1, false);
    l.kill(0);
    l.run(5_000);
    assert_eq!(
        l.roles()[1],
        Role::Fenced,
        "could be isolated itself: no takeover"
    );
    l.set_witness(1, true);
    let t = l.run_until(10_000, |l| l.active() == Some(1)).unwrap();
    assert!(
        t >= l.cfg.role[1].recover_hold_ms - l.cfg.step_ms,
        "after the hold ({t} ms)"
    );
}

#[test]
fn link_flaps_resume_from_the_log_without_snapshots() {
    let mut l = booted(10_000);
    let at_boot = l.nodes[0].publisher.as_ref().unwrap().status().snapshots;
    for flap in 0..20 {
        l.cut_sync();
        for _ in 0..(20 + flap * 3) {
            l.churn(12_000, 4, 2, 4);
            l.step();
        }
        l.heal_sync();
        for _ in 0..20 {
            l.churn(12_000, 4, 2, 4);
            l.step();
        }
    }
    l.run_until(5_000, Lab::in_sync).unwrap();
    let s = l.nodes[0].publisher.as_ref().unwrap().status();
    assert_eq!(s.snapshots, at_boot, "every reconnect resumed from the log");
    assert_eq!(l.roles(), [Role::Active, Role::Standby]);
    assert_eq!(l.nodes[1].replica.status().gaps, 0);
}

#[test]
fn switchover_moves_every_session_with_no_overlap() {
    let mut l = booted(50_000);
    let before = l.table(0);
    l.switchover(0, false).unwrap();
    let t = l.run_until(2_000, |l| l.active() == Some(1)).unwrap();
    assert!(t <= 20, "handover in {t} ms");
    assert_eq!(l.lost(&before, 1), 0);
    l.run_until(30_000, Lab::in_sync).unwrap();
    assert_eq!(l.roles(), [Role::Standby, Role::Active]);
    assert_eq!(l.watch.split_brain_ms + l.watch.partitioned_both_ms, 0);
    // And back, once the peer's hello says it is in sync.
    l.run(400);
    l.switchover(1, false).unwrap();
    l.run_until(2_000, |l| l.active() == Some(0)).unwrap();
    assert_eq!(l.watch.split_brain_ms + l.watch.partitioned_both_ms, 0);
}

#[test]
fn simulated_failure_fails_over_and_comes_back_as_standby() {
    let mut l = booted(10_000);
    let before = l.table(0);
    l.simulate_failure(0, 5_000).unwrap();
    let t = l.run_until(5_000, |l| l.active() == Some(1)).unwrap();
    assert!(t <= l.cfg.role[1].dead_ms + 2 * l.cfg.step_ms, "{t} ms");
    assert_eq!(l.lost(&before, 1), 0);
    l.run_until(20_000, Lab::in_sync).unwrap();
    assert_eq!(l.roles(), [Role::Standby, Role::Active]);
    assert_eq!(l.watch.split_brain_ms, 0);
}

#[test]
fn preemption_takes_the_role_back_when_in_sync() {
    let mut cfg = LabConfig::default();
    cfg.role[0].preempt = true;
    cfg.role[0].preempt_delay_ms = 2_000;
    let mut l = Lab::new(cfg);
    l.run_until(10_000, |l| l.active() == Some(0)).unwrap();
    l.load(5000);
    l.kill(0);
    l.run_until(5_000, |l| l.active() == Some(1)).unwrap();
    l.restart(0);
    l.load(10);
    let t = l.run_until(30_000, |l| l.active() == Some(0)).unwrap();
    assert!(t >= 2_000, "after the preempt delay ({t} ms)");
    l.run_until(30_000, Lab::in_sync).unwrap();
    assert_eq!(l.watch.split_brain_ms, 0);
}

#[test]
fn random_faults_never_put_two_actives_on_the_same_subscribers() {
    let seeds: u64 = std::env::var("HA_SIM_SEEDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(12);
    let first: u64 = std::env::var("HA_SIM_FIRST")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);
    for seed in first..first + seeds {
        let cfg = LabConfig {
            seed,
            access_loss: 20_000,
            trace: true,
            ..LabConfig::default()
        };
        let mut l = Lab::new(cfg);
        l.run(1000);
        l.load(3000);
        for _ in 0..120 {
            match l.rng.below(14) {
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
                _ => {}
            }
            let steps = 20 + l.rng.below(200);
            for _ in 0..steps {
                l.churn(4000, 2, 1, 2);
                l.step();
            }
            let tail = l.log.len().saturating_sub(30);
            assert_eq!(
                l.watch.split_brain_ms,
                0,
                "seed {seed}:\n{}",
                l.log[tail..].join("\n")
            );
        }
        // Everything heals: one active, the other in sync.
        for i in 0..2 {
            if !l.nodes[i].alive {
                l.restart(i);
            }
            l.set_witness(i, true);
            l.set_track(i, true);
        }
        l.heal_sync();
        l.heal_access();
        let t = l.run_until(60_000, Lab::in_sync);
        assert!(
            t.is_some(),
            "seed {seed}: no convergence, roles {:?}",
            l.roles()
        );
        let tail = l.log.len().saturating_sub(30);
        assert_eq!(
            l.watch.split_brain_ms,
            0,
            "seed {seed}:\n{}",
            l.log[tail..].join("\n")
        );
        eprintln!("seed {seed}: {:?}", l.watch);
    }
}
