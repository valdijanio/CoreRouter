//! Bandwidth alerts (G4.5): "receive above 80 % of the link for 5 minutes"
//! goes to the router's log, once, and "back below" when it ends.
//!
//! - Judged on the 1-minute averages of the history (`rrd` tier 1), once a
//!   minute closes: a burst shorter than a minute does not count, and a
//!   minute the router did not see (unknown) breaks the streak.
//! - The capacity is the rule's `capacity_mbps`, else the link's speed
//!   (`Hal::ethernet_monitor`, asked again every [`SPEED_EVERY`] seconds,
//!   never every second). Without either the rule is `unknown`, said by
//!   `system.graph.alert.print`.
//! - `direction: any` takes the busier direction of each minute.
//! - The rules are config (`system.graphing.alerts`); their state is
//!   operational and starts over after a restart (a new streak).

use std::collections::BTreeMap;

use corerouter_model::graphing::{BandwidthAlert, Direction};
use corerouter_model::{IfName, ItemId};
use serde::Serialize;

use super::{GraphDb, INTERFACE};

/// Seconds between two asks for a link's speed.
pub const SPEED_EVERY: u64 = 60;
/// The 1-minute ring.
const MINUTE_TIER: usize = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
    /// Below, or not long enough above.
    #[default]
    Ok,
    Alerting,
    /// No capacity known, or no history of the interface.
    Unknown,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct AlertState {
    pub state: State,
    /// Unix time the alert started.
    pub since: Option<u64>,
    /// Use of the capacity in the last closed minute, %.
    pub last_percent: Option<f64>,
    /// The capacity judged against, Mbit/s, and where it came from.
    pub capacity_mbps: Option<u32>,
    pub capacity_from: Option<&'static str>,
    pub reason: Option<String>,
    /// The rule this state is about (a changed rule starts over).
    #[serde(skip)]
    rule: Option<BandwidthAlert>,
    #[serde(skip)]
    judged: u64,
}

/// Link speeds by interface: (asked at, Mbit/s).
pub type Speeds = BTreeMap<IfName, (u64, Option<u32>)>;

/// One line for the log: (warning, text).
pub type Line = (bool, String);

impl GraphDb {
    /// The state of rule `id`.
    pub fn alert_state(&self, id: ItemId) -> Option<&AlertState> {
        self.alerts.get(&id)
    }

    /// Judge every rule whose interface closed a minute since the last
    /// time. `speeds` has the link speeds the caller knows.
    pub fn judge_alerts(&mut self, rules: &[BandwidthAlert], speeds: &Speeds) -> Vec<Line> {
        let mut log = Vec::new();
        self.alerts.retain(|id, _| rules.iter().any(|r| r.id == *id));
        for rule in rules {
            let key = format!("{INTERFACE}{}", rule.interface);
            let st = self.alerts.entry(rule.id).or_default();
            if st.rule.as_ref() != Some(rule) {
                *st = AlertState {
                    rule: Some(rule.clone()),
                    ..AlertState::default()
                };
            }
            if rule.disabled {
                st.state = State::Ok;
                st.since = None;
                st.reason = Some("disabled".into());
                continue;
            }
            let (capacity, from) = match (rule.capacity_mbps, speeds.get(&rule.interface)) {
                (Some(c), _) => (Some(c), Some("rule")),
                (None, Some((_, Some(s)))) => (Some(*s), Some("link speed")),
                _ => (None, None),
            };
            st.capacity_mbps = capacity;
            st.capacity_from = from;
            let Some(rrd) = self.series.get(&key).map(|k| &k.rrd) else {
                st.state = State::Unknown;
                st.reason = Some("no history of this interface (system.graph.set include=…)".into());
                continue;
            };
            let Some(cap) = capacity.filter(|c| *c > 0) else {
                st.state = State::Unknown;
                st.reason = Some("link speed unknown: set capacity_mbps".into());
                continue;
            };
            let closed = rrd.closed(MINUTE_TIER);
            if closed == 0 || closed == st.judged {
                continue;
            }
            st.judged = closed;
            st.reason = None;
            let bits = f64::from(cap) * 1e6;
            let use_of = |k: u64| -> Option<f64> {
                let (avg, _) = rrd.row(MINUTE_TIER, k)?;
                let rx = avg.first().copied().filter(|v| v.is_finite());
                let tx = avg.get(1).copied().filter(|v| v.is_finite());
                let v = match rule.direction {
                    Direction::Rx => rx?,
                    Direction::Tx => tx?,
                    Direction::Any => rx.into_iter().chain(tx).fold(None, |m: Option<f32>, v| Some(m.map_or(v, |m| m.max(v))))?,
                };
                Some(f64::from(v) * 100.0 / bits)
            };
            let last = use_of(closed);
            st.last_percent = last.map(|p| (p * 10.0).round() / 10.0);
            let threshold = f64::from(rule.percent);
            let minutes = u64::from(rule.minutes.max(1));
            let streak = (0..minutes)
                .all(|back| closed >= back && use_of(closed - back).is_some_and(|p| p > threshold));
            let what = format!(
                "{} {} {}% of {} Mbit/s",
                rule.interface,
                rule.direction.as_str(),
                rule.percent,
                cap
            );
            match st.state {
                State::Alerting if !last.is_some_and(|p| p > threshold) => {
                    st.state = State::Ok;
                    st.since = None;
                    log.push((false, format!("graphing: {what}: back below ({})", pct(last))));
                }
                State::Alerting => {}
                _ if streak => {
                    st.state = State::Alerting;
                    st.since = Some((closed + 1) * 60);
                    log.push((
                        true,
                        format!("graphing: {what}: above for {minutes} min (last minute {})", pct(last)),
                    ));
                }
                _ => st.state = State::Ok,
            }
        }
        log
    }
}

fn pct(p: Option<f64>) -> String {
    p.map_or("unknown".into(), |p| format!("{p:.1}%"))
}
