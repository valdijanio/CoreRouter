//! Flap dampening (RFC 5882 §3.2 asks clients to damp a flapping session;
//! Cisco's `bfd dampening` and Junos' `holddown-interval` do it in BFD
//! itself). Each Up → Down adds a penalty that decays exponentially with
//! a half-life; above `suppress` the session is reported down to its
//! clients until the penalty decays below `reuse` (or `max_suppress`
//! passed). BFD itself keeps running: the peer sees it Up.

/// Microseconds; penalties are unitless (1000 per flap, as BGP's RFC 2439).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DampConfig {
    pub half_life_us: u64,
    pub penalty: u32,
    pub suppress: u32,
    pub reuse: u32,
    pub max_suppress_us: u64,
}

impl Default for DampConfig {
    /// Three flaps within ~15 s suppress; quiet for ~30 s releases.
    fn default() -> Self {
        Self {
            half_life_us: 15_000_000,
            penalty: 1000,
            suppress: 2500,
            reuse: 800,
            max_suppress_us: 120_000_000,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Damper {
    penalty: f64,
    at: u64,
    suppressed_since: Option<u64>,
}

impl Damper {
    fn decay(&mut self, cfg: &DampConfig, now: u64) {
        if now > self.at && cfg.half_life_us > 0 {
            let halves = (now - self.at) as f64 / cfg.half_life_us as f64;
            self.penalty *= 0.5f64.powf(halves);
        }
        self.at = self.at.max(now);
        // RFC 2439 §4.2 ceiling: the penalty that decays to `reuse` in
        // exactly `max_suppress`.
        let ceil = f64::from(cfg.reuse)
            * 2f64.powf(cfg.max_suppress_us as f64 / cfg.half_life_us.max(1) as f64);
        self.penalty = self.penalty.min(ceil);
    }

    /// Records a flap; true when the session is (now) suppressed.
    pub fn flap(&mut self, cfg: &DampConfig, now: u64) -> bool {
        self.decay(cfg, now);
        self.penalty += f64::from(cfg.penalty);
        if self.suppressed_since.is_none() && self.penalty >= f64::from(cfg.suppress) {
            self.suppressed_since = Some(now);
        }
        self.suppressed_since.is_some()
    }

    /// Re-evaluates at `now`; true while suppressed.
    pub fn suppressed(&mut self, cfg: &DampConfig, now: u64) -> bool {
        self.decay(cfg, now);
        if let Some(since) = self.suppressed_since
            && (self.penalty < f64::from(cfg.reuse)
                || now.saturating_sub(since) >= cfg.max_suppress_us)
        {
            self.suppressed_since = None;
        }
        self.suppressed_since.is_some()
    }

    pub fn penalty(&self) -> u32 {
        self.penalty as u32
    }

    /// When the suppression ends if nothing else flaps.
    pub fn reuse_at(&self, cfg: &DampConfig) -> Option<u64> {
        let since = self.suppressed_since?;
        let halves = (self.penalty / f64::from(cfg.reuse.max(1))).log2().max(0.0);
        let by_decay = self.at + (halves * cfg.half_life_us as f64) as u64;
        Some(by_decay.min(since + cfg.max_suppress_us))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: u64 = 1_000_000;

    #[test]
    fn third_quick_flap_suppresses_then_quiet_releases() {
        let c = DampConfig::default();
        let mut d = Damper::default();
        assert!(!d.flap(&c, 0));
        assert!(!d.flap(&c, S));
        assert!(d.flap(&c, 2 * S));
        assert!(d.suppressed(&c, 10 * S));
        let at = d.reuse_at(&c).unwrap();
        assert!(at > 20 * S && at < 40 * S, "{at}");
        assert!(!d.suppressed(&c, at + S));
    }

    #[test]
    fn spaced_flaps_never_suppress() {
        let c = DampConfig::default();
        let mut d = Damper::default();
        for i in 0..20 {
            assert!(!d.flap(&c, i * 60 * S));
        }
    }

    #[test]
    fn max_suppress_caps_a_storm() {
        let c = DampConfig::default();
        let mut d = Damper::default();
        for i in 0..1000 {
            d.flap(&c, i * 100_000);
        }
        let end = 1000 * 100_000;
        assert!(d.suppressed(&c, end));
        assert!(!d.suppressed(&c, end + c.max_suppress_us + S));
    }
}
