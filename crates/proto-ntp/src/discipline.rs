//! What to do with a measured clock offset (G4.6b): slew, step, wait or ask.
//!
//! Pure: no clock and no system call. The daemon passes the time, applies
//! [`Discipline::frequency_ppm`] and the steps through the `Hal`, so all of
//! this is tested with a simulated clock.
//!
//! The state machine is RFC 5905 §11.3 Figure 28, without the frequency
//! file: never set (NSET), in sync (SYNC) and spike (SPIK).
//!
//! | State | offset < 128 ms  | offset ≥ 128 ms                     |
//! |-------|------------------|-------------------------------------|
//! | NSET  | slew → SYNC      | step → SYNC                         |
//! | SYNC  | slew             | → SPIK, the clock is left alone     |
//! | SPIK  | slew → SYNC      | hold for 900 s (WATCH), then step   |
//!
//! Above 1000 s (PANICT, Figure 27) nothing happens without the operator's
//! confirmation (RFC 8633 §5.2 lists "requiring manual intervention for
//! large steps"), except when the clock is provably wrong: before
//! [`MIN_VALID_UNIX`], a router without a battery-backed clock after boot.
//! No step ever lands before [`MIN_VALID_UNIX`], confirmed or not (RFC 8633
//! §5.2: prevent steps to a time earlier than the daemon's compile date).
//!
//! # The first step of a boot (G4.6m)
//!
//! RFC 8633 §5.2 allows the panic threshold to be ignored "at startup":
//! ntpd `-g`, chrony `makestep`, systemd-timesyncd and ntpd-rs all set the
//! clock on their first sample. A machine whose battery clock keeps local
//! time (dual boot with Windows) or a flat battery starts hours off, and
//! waited for a person. With [`Discipline::allow_boot_step`] (the daemon
//! calls it once per boot, kept in tmpfs) the first synchronization steps
//! any offset forward and up to [`BOOT_STEP_BACK_NANOS`] backward without
//! asking; the first slew or step spends it, and PANICT holds again. A
//! backward step that large is what a lying server would do to replay old
//! certificates or logs: beyond a day it still asks.
//!
//! # Slew by frequency
//!
//! The clock runs slightly fast or slow for a bounded time, the way ntpd-rs
//! steers it: the kernel only sees frequency changes. The same measurements
//! teach the clock's own drift, in the spirit of the FLL of RFC 5905 §11.3:
//! between two updates, what the offset did beyond what the slew explains
//! is frequency error. Its gain grows with the interval, because a long
//! interval measures frequency better (the noise is divided by it).

/// Above this the offset is stepped, below it slewed. RFC 5905 Figure 27
/// says STEPT = 125 ms; 128 ms is what ntpd, Junos and the gap use.
pub const STEP_NANOS: i64 = 128_000_000;
/// RFC 5905 Figure 27: PANICT = 1000 s.
pub const PANIC_NANOS: i64 = 1_000_000_000_000;
/// RFC 5905 Figure 27: WATCH = 900 s, how long a spike is held.
pub const WATCH_SECS: f64 = 900.0;
/// 2026-01-01 00:00:00 UTC. A clock before it is wrong (this code did not
/// exist), and a step never lands before it (RFC 8633 §5.2).
pub const MIN_VALID_UNIX: i64 = 1_767_225_600;
/// Largest deliberate speed-up on top of the drift. With [`MAX_DRIFT_PPM`]
/// it stays inside the kernel's ±500 ppm (`MAXFREQ_SCALED`, kernel/time/ntp.c).
pub const MAX_SLEW_PPM: f64 = 300.0;
/// Largest drift learned. RFC 5905 §11.3 assumes 15 ppm of tolerance; cheap
/// crystals and virtual machines measure far more.
pub const MAX_DRIFT_PPM: f64 = 200.0;
/// A slew takes at least this long (a small offset runs at a gentle rate).
const MIN_SLEW_SECS: f64 = 16.0;
/// A confirmation holds while the new measurement stays this close to what
/// the operator saw; otherwise they are asked again with the new number.
pub const CONFIRM_TOLERANCE_NANOS: i64 = 60_000_000_000;
/// G4.6m: the first step of a boot goes back without asking only this far
/// (a day: a battery clock in local time is at most 14 h ahead), as ntpd-rs
/// limits its startup step.
pub const BOOT_STEP_BACK_NANOS: i64 = 86_400 * 1_000_000_000;
/// Nanoseconds per second per ppm.
const NANOS_PER_PPM_SEC: f64 = 1000.0;

/// What an update decided (the frequency is [`Discipline::frequency_ppm`]).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Action {
    /// Below the step threshold: the frequency carries it away.
    Slew { offset_nanos: i64, secs: f64 },
    /// Step the clock by this much, now.
    Step { offset_nanos: i64 },
    /// A spike, held for `held_secs` so far (RFC 5905 §11.3 SPIK).
    HoldSpike { offset_nanos: i64, held_secs: f64 },
    /// Above the panic threshold: waits for [`Discipline::update`] with
    /// `confirmed`.
    NeedConfirm { offset_nanos: i64 },
    /// It would put the clock before [`MIN_VALID_UNIX`]: refused for good.
    Refuse { offset_nanos: i64 },
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Phase {
    NeverSet,
    Sync,
    Spike { since: f64 },
}

#[derive(Debug, Clone, Copy, PartialEq)]
struct Slew {
    extra_ppm: f64,
    from: f64,
    until: f64,
}

/// The clock's discipline. Times are seconds on a clock that never steps.
#[derive(Debug, Clone, PartialEq)]
pub struct Discipline {
    phase: Phase,
    drift_ppm: f64,
    slew: Option<Slew>,
    /// The last update inside the slew range: (when, offset).
    last: Option<(f64, i64)>,
    /// What slews corrected since `last`, in nanoseconds.
    applied_nanos: f64,
    /// The offset the operator is being asked about.
    pending: Option<i64>,
    /// G4.6m: this boot's first synchronization may pass PANICT.
    boot_step: bool,
}

impl Default for Discipline {
    fn default() -> Self {
        Self {
            phase: Phase::NeverSet,
            drift_ppm: 0.0,
            slew: None,
            last: None,
            applied_nanos: 0.0,
            pending: None,
            boot_step: false,
        }
    }
}

impl Discipline {
    /// The frequency the clock must run at right now, in ppm.
    pub fn frequency_ppm(&self) -> f64 {
        self.drift_ppm + self.slew.map_or(0.0, |s| s.extra_ppm)
    }

    /// The drift learned so far, in ppm (positive: the clock was slow).
    pub fn drift_ppm(&self) -> f64 {
        self.drift_ppm
    }

    /// The offset waiting for the operator's confirmation.
    pub fn pending_step(&self) -> Option<i64> {
        self.pending
    }

    /// When the running slew ends, if one runs.
    pub fn slew_until(&self) -> Option<f64> {
        self.slew.map(|s| s.until)
    }

    /// Forget everything: the clock could not be changed (a failed step
    /// does not spend the boot's first step).
    pub fn reset(&mut self) {
        *self = Self {
            boot_step: self.boot_step,
            ..Self::default()
        };
    }

    /// G4.6m: this is the boot's first synchronization; it may step past
    /// PANICT (RFC 8633 §5.2, "at startup"). Spent by the first slew or step.
    pub fn allow_boot_step(&mut self) {
        self.boot_step = true;
    }

    /// The boot's first step is still unspent.
    pub fn boot_step_open(&self) -> bool {
        self.boot_step
    }

    /// Ends the slew when its time is up. Call it often: the later it runs,
    /// the more the clock overshoots (the next update measures and corrects
    /// that, since what ran is accounted by the real time).
    pub fn tick(&mut self, now: f64) {
        if self.slew.is_some_and(|s| now >= s.until) {
            self.stop_slew(now);
        }
    }

    fn stop_slew(&mut self, now: f64) {
        if let Some(s) = self.slew.take() {
            let ran = (now - s.from).max(0.0);
            self.applied_nanos += s.extra_ppm * NANOS_PER_PPM_SEC * ran;
        }
    }

    /// One good measurement: `offset_nanos` is the server's clock minus
    /// ours, `now` the steady time and `wall_unix` our wall clock. With
    /// `confirmed`, the operator accepted [`Discipline::pending_step`].
    pub fn update(
        &mut self,
        now: f64,
        wall_unix: i64,
        offset_nanos: i64,
        confirmed: bool,
    ) -> Action {
        self.stop_slew(now);
        let size = offset_nanos.saturating_abs();
        let landing = wall_unix.saturating_add(offset_nanos / 1_000_000_000);
        if landing < MIN_VALID_UNIX {
            return Action::Refuse { offset_nanos };
        }
        // RFC 5905 §11.3: "The process terminates immediately if the offset
        // is greater than the panic threshold"; here it waits for a person.
        if size >= PANIC_NANOS {
            let accepted = self.pending.is_some_and(|p| {
                confirmed
                    && offset_nanos.saturating_sub(p).saturating_abs() <= CONFIRM_TOLERANCE_NANOS
            });
            // RFC 8633 §5.2: the panic threshold may be ignored at startup;
            // forward any amount, backward a day at most (G4.6m).
            let at_boot = self.boot_step && (offset_nanos > 0 || size <= BOOT_STEP_BACK_NANOS);
            if accepted || at_boot || wall_unix < MIN_VALID_UNIX {
                return self.step(offset_nanos);
            }
            self.pending = Some(offset_nanos);
            return Action::NeedConfirm { offset_nanos };
        }
        self.pending = None;
        if size < STEP_NANOS {
            self.learn(now, offset_nanos);
            self.phase = Phase::Sync;
            return self.slew_away(now, offset_nanos);
        }
        match self.phase {
            Phase::NeverSet => self.step(offset_nanos),
            Phase::Sync => {
                self.phase = Phase::Spike { since: now };
                Action::HoldSpike {
                    offset_nanos,
                    held_secs: 0.0,
                }
            }
            Phase::Spike { since } if now - since >= WATCH_SECS => self.step(offset_nanos),
            Phase::Spike { since } => Action::HoldSpike {
                offset_nanos,
                held_secs: now - since,
            },
        }
    }

    fn step(&mut self, offset_nanos: i64) -> Action {
        self.phase = Phase::Sync;
        self.pending = None;
        self.boot_step = false;
        // The step says nothing about the frequency.
        self.last = None;
        self.applied_nanos = 0.0;
        Action::Step { offset_nanos }
    }

    fn learn(&mut self, now: f64, offset_nanos: i64) {
        if let Some((then, before)) = self.last {
            let dt = now - then;
            if dt >= MIN_SLEW_SECS {
                // What the offset should be if the drift were right.
                let expected = before as f64 - self.applied_nanos;
                let error_ppm = (offset_nanos as f64 - expected) / dt / NANOS_PER_PPM_SEC;
                let gain = (dt / 2048.0).clamp(1.0 / 16.0, 0.5);
                self.drift_ppm =
                    (self.drift_ppm + gain * error_ppm).clamp(-MAX_DRIFT_PPM, MAX_DRIFT_PPM);
            }
        }
        self.last = Some((now, offset_nanos));
        self.applied_nanos = 0.0;
    }

    fn slew_away(&mut self, now: f64, offset_nanos: i64) -> Action {
        self.boot_step = false;
        let nanos = offset_nanos as f64;
        let secs = (nanos.abs() / (MAX_SLEW_PPM * NANOS_PER_PPM_SEC)).max(MIN_SLEW_SECS);
        let extra_ppm = nanos / secs / NANOS_PER_PPM_SEC;
        self.slew = Some(Slew {
            extra_ppm,
            from: now,
            until: now + secs,
        });
        Action::Slew { offset_nanos, secs }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// 2026-11-08, a plausible wall clock.
    const WALL: i64 = 1_794_000_000;
    const MS: i64 = 1_000_000;
    const SEC: i64 = 1_000_000_000;

    #[test]
    fn rfc_5905_figure_28_first_sample() {
        // NSET, offset above STEP: step.
        let mut d = Discipline::default();
        assert_eq!(
            d.update(0.0, WALL, 500 * MS, false),
            Action::Step {
                offset_nanos: 500 * MS
            }
        );
        // NSET, offset below STEP: adjust time.
        let mut d = Discipline::default();
        assert!(matches!(
            d.update(0.0, WALL, 5 * MS, false),
            Action::Slew { .. }
        ));
        // The boundary is 128 ms: just under slews, on it steps.
        let mut d = Discipline::default();
        assert!(matches!(
            d.update(0.0, WALL, 128 * MS - 1, false),
            Action::Slew { .. }
        ));
        let mut d = Discipline::default();
        assert!(matches!(
            d.update(0.0, WALL, 128 * MS, false),
            Action::Step { .. }
        ));
        assert!(matches!(
            Discipline::default().update(0.0, WALL, -128 * MS, false),
            Action::Step { .. }
        ));
    }

    /// RFC 5905 Figure 28 SYNC → SPIK: one wild answer does not move a
    /// clock already in sync; it must last WATCH = 900 s.
    #[test]
    fn a_spike_is_held_for_900_seconds_then_stepped() {
        let mut d = Discipline::default();
        d.update(0.0, WALL, MS, false);
        assert!(matches!(
            d.update(64.0, WALL, 400 * MS, false),
            Action::HoldSpike { held_secs, .. } if held_secs == 0.0
        ));
        assert!(matches!(
            d.update(128.0, WALL, 400 * MS, false),
            Action::HoldSpike { held_secs, .. } if held_secs == 64.0
        ));
        assert!(matches!(
            d.update(963.0, WALL, 400 * MS, false),
            Action::HoldSpike { .. }
        ));
        assert_eq!(
            d.update(964.0, WALL, 400 * MS, false),
            Action::Step {
                offset_nanos: 400 * MS
            }
        );
    }

    #[test]
    fn a_spike_that_goes_away_changes_nothing() {
        let mut d = Discipline::default();
        d.update(0.0, WALL, MS, false);
        d.update(64.0, WALL, 400 * MS, false);
        assert!(matches!(
            d.update(128.0, WALL, MS, false),
            Action::Slew { .. }
        ));
        // The next spike starts its own 900 s.
        d.update(192.0, WALL, 400 * MS, false);
        assert!(matches!(
            d.update(1000.0, WALL, 400 * MS, false),
            Action::HoldSpike { .. }
        ));
    }

    #[test]
    fn panic_waits_for_the_operator() {
        let mut d = Discipline::default();
        let off = 5000 * SEC;
        // The boundary: PANICT itself asks; just under steps on a first sample.
        assert_eq!(
            Discipline::default().update(0.0, WALL, PANIC_NANOS - 1, false),
            Action::Step {
                offset_nanos: PANIC_NANOS - 1
            }
        );
        assert!(matches!(
            Discipline::default().update(0.0, WALL, PANIC_NANOS, false),
            Action::NeedConfirm { .. }
        ));
        // A confirmation with nothing pending does not step.
        assert_eq!(
            d.update(0.0, WALL, off, true),
            Action::NeedConfirm { offset_nanos: off }
        );
        assert_eq!(d.pending_step(), Some(off));
        assert_eq!(
            d.update(64.0, WALL, off, false),
            Action::NeedConfirm { offset_nanos: off }
        );
        // Confirmed, and the new sample agrees.
        assert_eq!(
            d.update(128.0, WALL, off + SEC, true),
            Action::Step {
                offset_nanos: off + SEC
            }
        );
        assert_eq!(d.pending_step(), None);
    }

    /// The operator saw one number; a very different one is asked again.
    fn at_boot() -> Discipline {
        let mut d = Discipline::default();
        d.allow_boot_step();
        d
    }

    /// G4.6m, RFC 8633 §5.2 (the panic threshold may be ignored at
    /// startup): forward, any amount, without asking.
    #[test]
    fn the_first_step_of_a_boot_goes_forward_without_limit() {
        // The notebook of the audit: 2 h 50 min behind (battery clock in
        // local time); and a flat battery, a year behind.
        for off in [10_200 * SEC, 365 * 86_400 * SEC] {
            let mut d = at_boot();
            assert_eq!(
                d.update(0.0, WALL, off, false),
                Action::Step { offset_nanos: off }
            );
            assert!(!d.boot_step_open(), "spent");
            assert_eq!(d.pending_step(), None);
        }
    }

    /// G4.6m, RFC 8633 §5.2: backward a day at most without asking.
    #[test]
    fn the_first_step_of_a_boot_goes_back_up_to_a_day() {
        for off in [-10_800 * SEC, -BOOT_STEP_BACK_NANOS] {
            let mut d = at_boot();
            assert_eq!(
                d.update(0.0, WALL, off, false),
                Action::Step { offset_nanos: off }
            );
        }
    }

    /// G4.6m, RFC 8633 §5.2: more than a day back is what a lying server
    /// does to replay the past; it still asks, and the boot's step stays
    /// open for a sample that makes sense.
    #[test]
    fn the_first_step_of_a_boot_asks_beyond_a_day_back() {
        let mut d = at_boot();
        let off = -BOOT_STEP_BACK_NANOS - SEC;
        assert_eq!(
            d.update(0.0, WALL, off, false),
            Action::NeedConfirm { offset_nanos: off }
        );
        assert_eq!(d.pending_step(), Some(off));
        assert!(d.boot_step_open());
        // Nothing lands before the floor either (the earlier rule).
        let mut d = at_boot();
        let past = (MIN_VALID_UNIX - WALL - 10) * SEC;
        assert!(matches!(
            d.update(0.0, WALL, past, false),
            Action::Refuse { .. }
        ));
    }

    /// G4.6m, RFC 8633 §5.2: only the first synchronization of the boot.
    /// After it (a step, or a slew: the clock was right) PANICT holds again.
    #[test]
    fn the_second_step_of_the_same_boot_asks_again() {
        let mut d = at_boot();
        assert!(matches!(
            d.update(0.0, WALL, 10_200 * SEC, false),
            Action::Step { .. }
        ));
        let off = 5_000 * SEC;
        assert_eq!(
            d.update(64.0, WALL, off, false),
            Action::NeedConfirm { offset_nanos: off }
        );
        // A first sample that only slews spends it too.
        let mut d = at_boot();
        assert!(matches!(
            d.update(0.0, WALL, 3 * MS, false),
            Action::Slew { .. }
        ));
        assert!(!d.boot_step_open());
        assert!(matches!(
            d.update(64.0, WALL, off, false),
            Action::NeedConfirm { .. }
        ));
        // A clock that could not be set keeps it (the step did not happen).
        let mut d = at_boot();
        d.reset();
        assert!(d.boot_step_open());
        // Without the boot's step (a daemon restarted in the same boot):
        // PANICT, as before.
        assert!(matches!(
            Discipline::default().update(0.0, WALL, 10_200 * SEC, false),
            Action::NeedConfirm { .. }
        ));
    }

    #[test]
    fn a_confirmation_does_not_cover_another_offset() {
        let mut d = Discipline::default();
        let off = 5000 * SEC;
        d.update(0.0, WALL, off, false);
        let other = off + CONFIRM_TOLERANCE_NANOS + SEC;
        assert_eq!(
            d.update(64.0, WALL, other, true),
            Action::NeedConfirm {
                offset_nanos: other
            }
        );
        assert_eq!(d.pending_step(), Some(other));
        // A pending question goes away with the problem.
        d.update(128.0, WALL, MS, false);
        assert_eq!(d.pending_step(), None);
    }

    /// RFC 8633 §5.2: a clock before the build is wrong, whatever the size
    /// of the offset; and no answer takes the clock back before it.
    #[test]
    fn a_clock_before_the_floor_may_jump_and_nobody_may_go_back_there() {
        let mut d = Discipline::default();
        let off = (WALL - 86_400) * SEC;
        assert_eq!(
            d.update(0.0, 86_400, off, false),
            Action::Step { offset_nanos: off }
        );
        let mut d = Discipline::default();
        let back = -(WALL - 1000) * SEC;
        assert_eq!(
            d.update(0.0, WALL, back, true),
            Action::Refuse { offset_nanos: back }
        );
        // Confirming does not help, and nothing became pending.
        assert_eq!(d.pending_step(), None);
        assert_eq!(
            d.update(64.0, WALL, back, true),
            Action::Refuse { offset_nanos: back }
        );
        // Still before the floor after the answer: refused too.
        let mut d = Discipline::default();
        assert!(matches!(
            d.update(0.0, 86_400, SEC, false),
            Action::Refuse { .. }
        ));
    }

    /// The whole loop on a simulated crystal: the offset stays small, the
    /// drift is learned, the frequency stays inside what the kernel takes.
    #[test]
    fn a_drifting_clock_converges() {
        for true_drift in [-150.0f64, -50.0, 12.0, 80.0, 150.0] {
            let mut sim = Sim::new(true_drift);
            // Bounded noise, reproducible: an LCG instead of a random crate.
            let mut seed = 12345u64;
            let mut poll = 64.0;
            let mut worst_late = 0f64;
            let mut t = 0.0;
            while t < 6.0 * 3600.0 {
                seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                let noise = ((seed >> 40) % 4_000_000) as f64 - 2_000_000.0; // ±2 ms
                let seen = sim.offset + noise;
                let action = sim.d.update(t, WALL, seen as i64, false);
                if let Action::Step { offset_nanos } = action {
                    sim.offset -= offset_nanos as f64;
                }
                assert!(sim.d.frequency_ppm().abs() < 500.0);
                let until = t + poll;
                sim.run_until(&mut t, until);
                if t > 3.0 * 3600.0 {
                    worst_late = worst_late.max(sim.offset.abs());
                }
                poll = f64::min(poll * 2.0, 1024.0);
            }
            assert!(
                (sim.d.drift_ppm() - true_drift).abs() < 15.0,
                "{true_drift} ppm clock, learned {}",
                sim.d.drift_ppm()
            );
            assert!(
                worst_late < 25.0 * MS as f64,
                "{true_drift} ppm: {worst_late} ns"
            );
        }
    }

    /// A clock with drift in `offset` = server − ours; positive drift is a
    /// slow crystal, so the offset grows. Frequency corrects it.
    struct Sim {
        d: Discipline,
        drift: f64,
        offset: f64,
    }

    impl Sim {
        fn new(drift: f64) -> Self {
            Self {
                d: Discipline::default(),
                drift,
                offset: 3.0 * MS as f64,
            }
        }

        fn run_until(&mut self, t: &mut f64, until: f64) {
            while *t < until {
                let next = (*t + 1.0).min(until);
                let dt = next - *t;
                self.offset += (self.drift - self.d.frequency_ppm()) * 1000.0 * dt;
                *t = next;
                self.d.tick(*t);
            }
        }
    }

    #[test]
    fn a_slew_ends_on_time_and_goes_back_to_the_drift() {
        let mut d = Discipline::default();
        d.update(0.0, WALL, 1_600_000, false);
        // 1.6 ms over the minimum 16 s: 100 000 ns/s = 100 ppm.
        assert!((d.frequency_ppm() - 100.0).abs() < 1e-9);
        assert_eq!(d.slew_until(), Some(16.0));
        d.tick(15.0);
        assert!(d.frequency_ppm() != 0.0);
        d.tick(16.0);
        assert_eq!(d.frequency_ppm(), d.drift_ppm());
        assert_eq!(d.slew_until(), None);
        // The largest offset that slews runs at the rate limit.
        let mut d = Discipline::default();
        d.update(0.0, WALL, 128 * MS - 1, false);
        assert!(d.frequency_ppm() <= MAX_SLEW_PPM);
        assert!(d.slew_until().unwrap() > 400.0);
    }

    proptest! {
        /// Hostile samples never panic, never ask the kernel for more than
        /// it takes, and never step toward a time before the floor.
        #[test]
        fn any_offset_is_safe(
            samples in proptest::collection::vec((any::<i64>(), any::<bool>(), 1u32..2000), 1..40),
            wall in 0i64..4_000_000_000,
        ) {
            let mut d = Discipline::default();
            let mut now = 0.0;
            for (offset, confirmed, gap) in samples {
                let action = d.update(now, wall, offset, confirmed);
                prop_assert!(d.frequency_ppm().abs() <= MAX_DRIFT_PPM + MAX_SLEW_PPM + 1e-6);
                if let Action::Step { offset_nanos } = action {
                    prop_assert!(wall.saturating_add(offset_nanos / SEC) >= MIN_VALID_UNIX);
                }
                now += f64::from(gap);
                d.tick(now);
            }
        }
    }
}
