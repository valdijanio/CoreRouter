//! Steps of the wall clock (G0.13).
//!
//! Some times must stay on the wall clock because they leave the process:
//! the end of a DHCP lease is written to its journal as a Unix time and read
//! back after a restart. When NTP *steps* the wall clock (a router without a
//! battery-backed clock boots in 1970 and jumps 56 years at its first
//! answer; a wrong server or an operator steps it back), those times are
//! moved by the step, so each one keeps the time it had left
//! (`Server::clock_step` in `proto-dhcp`).
//!
//! A step is the wall clock moving by a different amount than the
//! monotonic one between two looks ([`Session::wall_step`]), beyond
//! [`STEP_SECS`]: NTP slews smaller errors (at most 500 ppm, RFC 5905
//! §11.3), and both clocks are read in whole seconds. Without a monotonic
//! clock (the virtual lab) nothing is detected, as before.

use crate::Session;

/// The smallest difference taken as a step, in seconds. Both clocks are
/// read in whole seconds (±1 each); a slew moves the wall clock by at most
/// 0.5 ms per second.
pub const STEP_SECS: i64 = 5;

#[derive(Default)]
struct Watch {
    /// (wall, monotonic) at the last look.
    last: Option<(u64, u64)>,
}

impl Session {
    /// How far the wall clock stepped since the last call (positive:
    /// ahead), when that is at least [`STEP_SECS`]. `wall` is the wall
    /// clock now (seconds since the Unix epoch). The DHCP rounds call it.
    pub(crate) fn wall_step(&mut self, wall: u64) -> Option<i64> {
        let mono = self.hal().monotonic_secs()?;
        let w = self.ext_mut::<Watch>()?;
        let (last_wall, last_mono) = w.last.replace((wall, mono))?;
        let step = (i128::from(wall) - i128::from(last_wall))
            - (i128::from(mono) - i128::from(last_mono));
        if step.abs() < i128::from(STEP_SECS) {
            return None;
        }
        let step = i64::try_from(step).ok()?;
        let sign = if step > 0 { "+" } else { "" };
        log::warn!(
            "the wall clock stepped {sign}{step} s (NTP or a manual set): lease and timer \
             times move with it"
        );
        self.log_event(
            &["system", "clock", "warning"],
            "clock",
            format!(
                "O relógio de parede deu um passo de {sign}{step} s (NTP ou ajuste manual); \
                 os prazos dos leases DHCP andaram junto e cada um manteve o tempo que faltava"
            ),
            serde_json::json!({"step_secs": step, "wall": wall, "monotonic": mono}),
        );
        Some(step)
    }
}
