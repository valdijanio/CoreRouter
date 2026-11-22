//! NTP client status (G4.6). The daemon runs the SNTP client (it owns the
//! sockets) and reports here what it learned; `system.ntp.client.get`
//! shows it. Operational state, never saved.

use corerouter_hal::clock::SystemClock;
use corerouter_model::firewall::AddrMatch;
use corerouter_model::ntp::{ClockState, NtpServerStats, NtpState, NtpStatus};
use corerouter_model::source_set::SourceEntry;
use serde_json::Value;

use crate::Session;

/// G4.6p: the last time the NTP client moved the system clock (a step or
/// a slew), and from whom; kept after the client is turned off, so
/// `system.clock.print` still says where the time came from.
#[derive(Default, Clone)]
pub(crate) struct ClockSetByNtp {
    pub(crate) at: Option<u64>,
    pub(crate) server: Option<String>,
}

/// The operator accepted the pending step; the next round looks at it.
#[derive(Default)]
struct StepConfirmation(bool);

impl Session {
    /// The daemon's NTP client reports a round. A disabled client is always
    /// `stopped`, whatever arrives late from a round already under way.
    pub fn set_ntp_status(&mut self, mut status: NtpStatus) {
        if !self.store().running().system.ntp_client.enabled {
            status = NtpStatus::default();
        }
        if let Some((level, message)) = crate::logging::ntp_event(&self.ntp, &status) {
            self.log_event(&["ntp", level], crate::logging::DAEMON, message, Value::Null);
        }
        if matches!(status.clock, ClockState::Slewing | ClockState::Stepped)
            && let Some(set) = self.ext_mut::<ClockSetByNtp>()
        {
            set.at = status.last_sync.or(set.at);
            set.server = status
                .synced_server
                .clone()
                .or_else(|| set.server.take());
        }
        self.ntp = status;
    }

    /// The backend's system clock, for the daemon's client (G4.6b): it is
    /// used outside the session lock from then on.
    pub fn open_system_clock(&mut self) -> Result<Box<dyn SystemClock>, String> {
        self.hal_mut().system_clock().map_err(|e| e.to_string())
    }

    /// The servers DHCP brought for the NTP client: DHCPv4 option 42 first,
    /// then DHCPv6 option 56 (G4.6n), each from the clients with
    /// `use_peer_ntp`, without repeats. The daemon bounds the total.
    pub fn ntp_peer_servers(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .dhcp_peer_ntp()
            .iter()
            .map(ToString::to_string)
            .collect();
        for name in self.dhcp6_peer_ntp() {
            if !out.contains(&name) {
                out.push(name);
            }
        }
        out
    }

    /// Whether a DHCP client that is on may bring NTP servers (`use_peer_ntp`
    /// on a DHCPv4 or DHCPv6 client), in the candidate config.
    pub(crate) fn ntp_dhcp_may_bring(&self) -> bool {
        let cfg = self.store().candidate();
        cfg.ip
            .dhcp_clients
            .iter()
            .any(|d| d.use_peer_ntp && !d.disabled)
            || cfg
                .ipv6
                .dhcp_clients
                .iter()
                .any(|d| d.use_peer_ntp && !d.disabled)
    }

    /// `system.ntp.client.confirm-step` ran: true once, for the daemon's client.
    pub fn take_ntp_step_confirmation(&mut self) -> bool {
        self.ext_mut::<StepConfirmation>()
            .is_some_and(|c| std::mem::take(&mut c.0))
    }

    pub(crate) fn confirm_ntp_step(&mut self) {
        if let Some(c) = self.ext_mut::<StepConfirmation>() {
            c.0 = true;
        }
    }

    /// The last report; `stopped` while the running config has the client
    /// disabled; `using-local-clock` while it has no good answer and the
    /// server is serving this router's own clock (RouterOS's status).
    pub fn ntp_status(&self) -> NtpStatus {
        let cfg = &self.store().running().system;
        if !cfg.ntp_client.enabled {
            return NtpStatus::default();
        }
        let mut status = self.ntp.clone();
        if status.status != NtpState::Synchronized
            && cfg.ntp_server.enabled
            && cfg.ntp_server.use_local_clock
        {
            status.status = NtpState::UsingLocalClock;
        }
        status
    }

    /// What `allowed` of `/system ntp server` holds right now, and the
    /// address lists in it with nothing in them. The caller sorts it into a
    /// `SourceSet` outside the session lock. A name that is not a list holds
    /// nobody, like a firewall rule that names one: entries may come later.
    pub fn ntp_server_sources(&self) -> (Vec<AddrMatch>, Vec<String>) {
        let cfg = self.store().running();
        let mut out = Vec::new();
        let mut empty = Vec::new();
        for item in &cfg.system.ntp_server.allowed {
            match SourceEntry::parse(item) {
                Ok(SourceEntry::Match(m)) => out.push(m),
                Ok(SourceEntry::List(name)) => {
                    let before = out.len();
                    out.extend(
                        cfg.ip
                            .firewall
                            .address_lists
                            .iter()
                            .filter(|e| !e.disabled && e.list == name)
                            .map(|e| e.address),
                    );
                    out.extend(
                        self.dynamic_addresses
                            .entries()
                            .iter()
                            .filter(|e| e.list == name)
                            .map(|e| e.address),
                    );
                    if out.len() == before {
                        empty.push(name.to_string());
                    }
                }
                Err(_) => {}
            }
        }
        (out, empty)
    }

    /// The daemon's NTP server reports its counters (G4.6c).
    pub fn set_ntp_server_stats(&mut self, stats: NtpServerStats) {
        if let Some(s) = self.ext_mut::<NtpServerStats>() {
            *s = stats;
        }
    }

    /// The last report of the server; empty with no daemon.
    pub fn ntp_server_stats(&self) -> NtpServerStats {
        self.ext::<NtpServerStats>().cloned().unwrap_or_default()
    }
}
