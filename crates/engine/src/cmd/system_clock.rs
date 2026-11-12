//! `/system clock` (G4.6p): the router's time, and where it came from.
//!
//! RouterOS 7 `/system clock print` shows `time`, `date`, `time-zone-name`,
//! `gmt-offset` and `dst-active`; Cisco `show clock detail` and Junos `show
//! system uptime` add the time source (NTP, the hardware calendar). Both are
//! here, with the board's battery clock (RTC) beside: a Windows machine
//! keeps it in local time, and the difference says so at a glance.
//!
//! The router has no time zone yet: everything is UTC (`time_zone_name:
//! "UTC"`), which is what the kernel and the logs use.

use corerouter_model::ntp::ClockState;
use serde_json::{Value, json};

use super::{CommandSpec, always};
use crate::ntp::ClockSetByNtp;
use crate::{Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[cmd!(query "system.clock.print", "Clock", [], None,
    "{} → {time (HH:MM:SS, UTC), date (YYYY-MM-DD), unix, time_zone_name, gmt_offset, dst_active, source: ntp|rtc|host|not-set|unknown, source_detail, ntp_server, last_sync, hardware_clock: {available, time, date, unix, offset_secs (RTC − system), written: follows-system|left-alone|not-written|none, local_time_offset (when the RTC looks like local time: ±HH:MM), drift_secs (what is left beyond that zone)}}",
    always, print)];

/// 2026-01-01 00:00:00 UTC: earlier is surely wrong (no battery), as in the
/// NTP client's floor (`corerouter_proto_ntp::discipline`).
const FLOOR_UNIX: u64 = 1_767_225_600;

/// Where the time came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Source {
    /// The NTP client moved the system clock in this run.
    Ntp,
    /// The clock the system booted with, from the RTC, not corrected since.
    Rtc,
    /// The virtual lab: the clock of the computer it runs on.
    Host,
    /// Before 2026: a board without battery.
    NotSet,
    /// No clock at all.
    Unknown,
}

impl Source {
    fn as_str(self) -> &'static str {
        match self {
            Self::Ntp => "ntp",
            Self::Rtc => "rtc",
            Self::Host => "host",
            Self::NotSet => "not-set",
            Self::Unknown => "unknown",
        }
    }
}

fn source(now: Option<u64>, real_machine: bool, by_ntp: bool) -> Source {
    match now {
        None => Source::Unknown,
        Some(t) if t < FLOOR_UNIX => Source::NotSet,
        Some(_) if by_ntp => Source::Ntp,
        Some(_) if real_machine => Source::Rtc,
        Some(_) => Source::Host,
    }
}

/// `(date, time)` of a Unix time, UTC.
fn split(unix: u64) -> (String, String) {
    let text = crate::safe_mode::utc(unix);
    let mut parts = text.split(' ');
    let date = parts.next().unwrap_or_default().to_owned();
    let time = parts.next().unwrap_or_default().to_owned();
    (date, time)
}

/// The time zone an RTC in local time would be in, from `offset_secs` (RTC
/// − system): the nearest half hour, when within 12 min of it, and in UTC−12
/// to UTC+14. An RTC in local time reads as UTC shifted by the zone, plus
/// its own drift: the audit's notebook was 2 h 50 min behind (UTC−3 and
/// 10 min of drift), this computer 2 h 55 min. Returns `(±HH:MM, drift)`.
fn local_time_offset(offset_secs: i64) -> Option<(String, i64)> {
    const HALF_HOUR: i64 = 1_800;
    let halves = (offset_secs + offset_secs.signum() * HALF_HOUR / 2) / HALF_HOUR;
    let zone = halves * HALF_HOUR;
    let drift = offset_secs - zone;
    if drift.abs() > 12 * 60 || zone == 0 || !(-12 * 3_600..=14 * 3_600).contains(&zone) {
        return None;
    }
    let sign = if zone < 0 { '−' } else { '+' };
    let m = zone.abs() / 60;
    Some((format!("{sign}{:02}:{:02}", m / 60, m % 60), drift))
}

fn print(s: &mut Session, _p: &Value) -> Result<Value> {
    let now = s.now();
    let real_machine = s.hal_now().is_some();
    let ntp = s.ntp_status();
    let set = s.ext::<ClockSetByNtp>().cloned().unwrap_or_default();
    // Moved by NTP now, or earlier in this run (the client may be off now).
    let by_ntp =
        set.at.is_some() || matches!(ntp.clock, ClockState::Slewing | ClockState::Stepped);
    let src = source(now, real_machine, by_ntp);
    let live = crate::live::is_live(s);
    let rtc = s.hal().hardware_clock().ok();
    let detail = match src {
        Source::Ntp => format!(
            "set by the NTP client{}",
            set.server
                .as_deref()
                .or(ntp.synced_server.as_deref())
                .map_or_else(String::new, |sv| format!(" from {sv}"))
        ),
        Source::Rtc => {
            "the clock the system booted with (the RTC), not corrected since by this router".into()
        }
        Source::Host => "the virtual lab: the clock of the computer it runs on".into(),
        Source::NotSet => {
            "before 2026: never set (a board without battery, and no NTP answer yet)".into()
        }
        Source::Unknown => "this backend has no clock".into(),
    };
    let (date, time) = now.map(split).unwrap_or_default();
    let hardware = match rtc {
        None => json!({"available": false, "time": null, "date": null, "unix": null,
            "offset_secs": null, "written": "none", "local_time_offset": null,
            "drift_secs": null}),
        Some(r) => {
            let offset = now.map(|n| r.saturating_sub(i64::try_from(n).unwrap_or(i64::MAX)));
            let (rdate, rtime) = u64::try_from(r).map(split).unwrap_or_default();
            // G4.6o: the kernel writes the RTC only after the NTP client
            // said "synchronized", and never on the live image.
            let written = if live {
                "left-alone"
            } else if src == Source::Ntp && ntp.status != corerouter_model::ntp::NtpState::Stopped
            {
                "follows-system"
            } else {
                "not-written"
            };
            let zone = offset.and_then(local_time_offset);
            json!({"available": true, "time": rtime, "date": rdate, "unix": r,
                "offset_secs": offset, "written": written,
                "local_time_offset": zone.as_ref().map(|z| z.0.clone()),
                "drift_secs": zone.map(|z| z.1)})
        }
    };
    Ok(json!({
        "time": time,
        "date": date,
        "unix": now,
        "time_zone_name": "UTC",
        "gmt_offset": "+00:00",
        "dst_active": false,
        "source": src.as_str(),
        "source_detail": detail,
        "ntp_server": if src == Source::Ntp { set.server.or(ntp.synced_server) } else { None },
        "last_sync": if src == Source::Ntp { set.at.or(ntp.last_sync) } else { None },
        "hardware_clock": hardware,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_source_follows_what_set_the_clock() {
        let now = Some(1_794_450_000);
        assert_eq!(source(None, true, true), Source::Unknown);
        assert_eq!(source(Some(1_000), true, true), Source::NotSet, "1970 is never NTP's");
        assert_eq!(source(now, true, true), Source::Ntp);
        assert_eq!(source(now, true, false), Source::Rtc);
        assert_eq!(source(now, false, false), Source::Host);
    }

    #[test]
    fn dates_and_times_are_utc() {
        // 2026-11-12 14:02:31 UTC.
        assert_eq!(
            split(1_794_492_151),
            ("2026-11-12".to_owned(), "14:02:31".to_owned())
        );
    }

    /// RTCs in Brazil's local time read as UTC: exact, the audit's notebook
    /// (2 h 50 min) and this computer (2 h 55 min 4 s, **medido**); a
    /// half-hour zone; small drift and the far ends are no zone.
    #[test]
    fn an_rtc_in_local_time_shows_its_zone() {
        let z = |o| local_time_offset(o);
        assert_eq!(z(-3 * 3_600), Some(("−03:00".into(), 0)));
        assert_eq!(z(-10_200), Some(("−03:00".into(), 600)));
        assert_eq!(z(-10_504), Some(("−03:00".into(), 296)));
        assert_eq!(z(5 * 3_600 + 1_800), Some(("+05:30".into(), 0)));
        assert_eq!(z(14 * 3_600), Some(("+14:00".into(), 0)));
        assert_eq!(z(0), None);
        assert_eq!(z(30), None, "drift");
        assert_eq!(z(15 * 60), None, "nearer no zone than any");
        assert_eq!(z(-13 * 3_600), None, "past UTC−12");
    }

    #[test]
    fn the_virtual_lab_says_whose_clock_it_shows() {
        let mut s = Session::virtual_lab();
        s.tick(1_794_492_151);
        let r = s.execute("system.clock.print", &json!({})).unwrap();
        assert_eq!(r["date"], "2026-11-12");
        assert_eq!(r["time"], "14:02:31");
        assert_eq!(r["time_zone_name"], "UTC");
        assert_eq!(r["source"], "host");
        assert_eq!(r["hardware_clock"]["available"], false);
        assert_eq!(r["hardware_clock"]["written"], "none");
        assert!(r["ntp_server"].is_null());
    }

    /// Once the NTP client moved the clock, the source stays NTP, with
    /// the server, after the client is turned off.
    #[test]
    fn ntp_is_remembered_as_the_source() {
        let mut s = Session::virtual_lab();
        s.tick(1_794_492_151);
        s.execute("system.ntp.client.set", &json!({"enabled": true, "servers": ["192.0.2.1"]}))
            .unwrap();
        s.set_ntp_status(corerouter_model::ntp::NtpStatus {
            status: corerouter_model::ntp::NtpState::Synchronized,
            synced_server: Some("192.0.2.1".into()),
            last_sync: Some(1_794_492_100),
            clock: ClockState::Stepped,
            ..Default::default()
        });
        let r = s.execute("system.clock.print", &json!({})).unwrap();
        assert_eq!(r["source"], "ntp");
        assert_eq!(r["ntp_server"], "192.0.2.1");
        assert_eq!(r["last_sync"], 1_794_492_100);
        s.execute("system.ntp.client.set", &json!({"enabled": false})).unwrap();
        let r = s.execute("system.clock.print", &json!({})).unwrap();
        assert_eq!(r["source"], "ntp");
        assert_eq!(r["source_detail"], "set by the NTP client from 192.0.2.1");
    }
}
