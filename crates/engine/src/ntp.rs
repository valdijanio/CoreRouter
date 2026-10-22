//! NTP client status (G4.6). The daemon runs the SNTP client (it owns the
//! sockets) and reports here what it learned; `system.ntp.client.get`
//! shows it. Operational state, never saved.

use corerouter_model::ntp::NtpStatus;
use serde_json::Value;

use crate::Session;

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
