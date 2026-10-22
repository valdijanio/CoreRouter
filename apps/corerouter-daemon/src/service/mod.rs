//! Services the daemon runs next to the control channel: DNS resolver, NTP
//! client, remote syslog, Prometheus metrics… One file each,
//! `src/service/<name>.rs`, with a
//! `pub(crate) const SERVICE: Service`; `build.rs` finds them. A service
//! declares its own command-line flags, so a new one does not touch
//! `main.rs` (the hot spot of parallel features).

use std::collections::BTreeMap;

use corerouter_control::Shutdown;
use corerouter_engine::Shared;

/// A command-line flag a service takes.
pub(crate) struct Flag {
    pub name: &'static str,
    /// The value's placeholder in the help (`[<addr>:]<port>`); `None` for a
    /// switch without value.
    pub value: Option<&'static str>,
    /// Help text; continuation lines are indented by `usage`.
    pub help: &'static str,
}

pub(crate) struct Service {
    pub name: &'static str,
    pub flags: &'static [Flag],
    /// Starts the service (threads of its own). `Err` stops the daemon: a
    /// service that can run without something logs it and returns `Ok`.
    pub start: fn(&Ctx) -> Result<(), String>,
}

/// What a service gets at start.
pub(crate) struct Ctx {
    pub session: Shared,
    pub shutdown: Shutdown,
    /// The service flags given on the command line (value, or "" for a switch).
    pub flags: BTreeMap<&'static str, String>,
}

impl Ctx {
    pub(crate) fn flag(&self, name: &str) -> Option<&str> {
        self.flags.get(name).map(String::as_str)
    }
}

include!(concat!(env!("OUT_DIR"), "/services.rs"));

/// The service flag named `name`, if one service declares it.
pub(crate) fn flag(name: &str) -> Option<&'static Flag> {
    ALL.iter().flat_map(|s| s.flags).find(|f| f.name == name)
}

/// Start every service, in order; the first `Err` stops the daemon.
pub(crate) fn start_all(ctx: &Ctx) -> Result<(), String> {
    for s in ALL {
        (s.start)(ctx).map_err(|e| format!("{}: {e}", s.name))?;
    }
    Ok(())
}

/// The services' flags, for `--help`.
pub(crate) fn usage() -> String {
    let mut out = String::new();
    for f in ALL.iter().flat_map(|s| s.flags) {
        let head = match f.value {
            Some(v) => format!("{} {v}", f.name),
            None => f.name.to_owned(),
        };
        let mut lines = f.help.lines();
        let first = lines.next().unwrap_or_default();
        out.push_str(&format!("\n  {head:<20}  {first}"));
        for l in lines {
            out.push_str(&format!("\n{:24}{}", "", l.trim_start()));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn services_are_found_and_flags_are_unique() {
        let names: Vec<&str> = ALL.iter().map(|s| s.name).collect();
        for want in ["dns resolver", "metrics", "ntp client", "remote logging"] {
            assert!(names.contains(&want), "{want} not in {names:?}");
        }
        let mut flags: Vec<&str> = ALL.iter().flat_map(|s| s.flags).map(|f| f.name).collect();
        let n = flags.len();
        flags.sort_unstable();
        flags.dedup();
        assert_eq!(flags.len(), n, "a flag is declared twice");
        assert!(usage().contains("--metrics"));
    }
}
