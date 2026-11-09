//! NTP client status (G4.6). The daemon runs the SNTP client (it owns the
//! sockets) and reports here what it learned; `system.ntp.client.get`
//! shows it. Operational state, never saved.

use corerouter_hal::clock::SystemClock;
use corerouter_model::ntp::NtpStatus;
use serde_json::Value;

use crate::Session;

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
        self.ntp = status;
    }

    /// The backend's system clock, for the daemon's client (G4.6b): it is
    /// used outside the session lock from then on.
    pub fn open_system_clock(&mut self) -> Result<Box<dyn SystemClock>, String> {
        self.hal_mut().system_clock().map_err(|e| e.to_string())
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

    /// The last report; `stopped` while the running config has the
    /// client disabled.
    pub fn ntp_status(&self) -> NtpStatus {
        if self.store().running().system.ntp_client.enabled {
            self.ntp.clone()
        } else {
            NtpStatus::default()
        }
    }
}
