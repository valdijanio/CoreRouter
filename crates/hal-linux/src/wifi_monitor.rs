//! Wi-Fi monitor mode on Linux (G1.30j): a monitor interface on the
//! radio's wiphy (`NL80211_CMD_NEW_INTERFACE`, type monitor, flags
//! `control` and `otherbss`: every network's frames, control frames
//! included), brought up, tuned with `NL80211_CMD_SET_CHANNEL`, and read
//! with an `AF_PACKET` socket (`crate::capture::HostCapture`): each frame
//! comes with the radiotap header mac80211 writes
//! (`net/mac80211/rx.c`, `ieee80211_add_rx_radiotap_header`).
//!
//! Why a second interface and not the station's turned into a monitor:
//! mac80211 lists monitor among the wiphy's software interface types
//! (Linux 6.18.59 `net/mac80211/main.c:1355`), which need no interface
//! combination, so the monitor runs beside the station and the station
//! stays connected. It cannot leave the station's channel then:
//! `cfg80211_set_monitor_channel` answers `-EBUSY` while any non-monitor
//! interface of the wiphy is up (`net/wireless/chan.c:1550`,
//! `cfg80211_has_monitors_only` in `core.h:262`). Choosing the channel
//! needs the station down: the engine asks for an exclusive monitor only on
//! a radio the configuration has disabled, and this checks the station's
//! netdev is down before taking the radio.
//!
//! The monitor is removed when the socket is dropped (`DEL_INTERFACE`); a
//! leftover of a crash (same name) is removed before a new one is made.
//! It never becomes one of the router's interfaces: its link type is
//! `ARPHRD_IEEE80211_RADIOTAP` (803), which `crate::owner` leaves alone.
//!
//! Not `TPACKET_V3`: its ring is shared memory (`mmap`, `unsafe`); a
//! channel carries some thousands of frames a second, one `recvmsg` each
//! (`docs/wifi-sniffer.md` has the numbers).

use std::time::Duration;

use corerouter_hal::capture::{
    CaptureDevice, CaptureError, CaptureSocket, CaptureSpec, FrameBatch, MAX_SNAPLEN_RADIO,
    PacketCapture,
};
use corerouter_hal::ieee80211::center_mhz;
use corerouter_hal::wifi_monitor::{
    MonitorMode, MonitorSocket, MonitorSpec, WifiMonitor, monitor_name,
};
use corerouter_model::IfName;
use rtnetlink::LinkUnspec;

use crate::capture::HostCapture;
use crate::genl::GenlError;
use crate::nl80211::Nl80211;

/// `EBUSY`: another interface of the wiphy is up.
const EBUSY: i32 = 16;

/// Monitors on the host's radios.
#[derive(Debug, Clone, Default)]
pub struct LinuxMonitor;

fn unavailable(what: &str, e: impl std::fmt::Display) -> CaptureError {
    CaptureError::Unavailable(format!("{what}: {e}"))
}

/// Set link `index` up or down.
fn set_up(index: u32, up: bool) -> Result<(), CaptureError> {
    crate::netlink::with_kernel(|k| async move {
        let b = LinkUnspec::new_with_index(index);
        let msg = if up { b.up() } else { b.down() }.build();
        k.handle
            .link()
            .set(msg)
            .execute()
            .await
            .map_err(|e| corerouter_hal::HalError::Io(crate::netlink::readable(&e)))
    })
    .map_err(|e| unavailable("bringing the monitor interface up", e))
}

impl WifiMonitor for LinuxMonitor {
    fn describe(&self) -> String {
        "nl80211 monitor interface, AF_PACKET".into()
    }

    fn open(&self, spec: &MonitorSpec) -> Result<Box<dyn MonitorSocket>, CaptureError> {
        let radio: IfName = spec
            .radio
            .parse()
            .map_err(|e| CaptureError::NoDevice(format!("'{}': {e}", spec.radio)))?;
        let station = crate::netlink::link_detail(radio.as_str())
            .map_err(|e| unavailable("reading the radio", e))?
            .ok_or_else(|| CaptureError::NoDevice(format!("no interface '{radio}' in the kernel")))?
            .link;
        if spec.mode == MonitorMode::Exclusive && station.up {
            return Err(CaptureError::Unavailable(format!(
                "'{radio}' is up: its station holds the radio; disable the interface to give the \
                 sniffer the radio"
            )));
        }
        let mut nl = Nl80211::open()
            .ok_or_else(|| CaptureError::Unavailable("no nl80211 (cfg80211 not loaded)".into()))?;
        let (wiphy, _) = nl
            .interface(station.index)
            .map_err(|e| unavailable("asking nl80211 about the radio", e))?;
        let wiphy = wiphy.ok_or_else(|| {
            CaptureError::Unavailable(format!("'{radio}' is not a Wi-Fi radio (no wiphy)"))
        })?;
        let name = monitor_name(radio.as_str());
        // A monitor left by a crash: remove it first.
        if let Ok(Some(old)) = crate::netlink::link_detail(&name) {
            let _ = nl.del_interface(old.link.index);
        }
        let index = match nl.new_monitor(wiphy, &name) {
            Ok(Some(i)) => i,
            Ok(None) => {
                crate::netlink::link_detail(&name)
                    .ok()
                    .flatten()
                    .ok_or_else(|| {
                        CaptureError::Unavailable(format!("{name} vanished after creation"))
                    })?
                    .link
                    .index
            }
            Err(e) if e.unsupported() => {
                return Err(CaptureError::Unavailable(format!(
                    "the driver of '{radio}' has no monitor mode ({e})"
                )));
            }
            Err(e) => return Err(unavailable("creating the monitor interface", e)),
        };
        // From here on the socket owns the interface: dropping it removes it.
        let mut sock = LinuxMonitorSocket {
            nl,
            index,
            station: station.index,
            name: name.clone(),
            mode: spec.mode,
            width: spec.width_mhz,
            freq: None,
            capture: None,
        };
        set_up(index, true)?;
        if spec.mode == MonitorMode::Exclusive
            && let Some(f) = spec.freq_mhz
        {
            sock.set_channel(f)?;
        }
        let capture = HostCapture.open(&CaptureSpec {
            devices: vec![CaptureDevice { name, vlan: None }],
            snaplen: MAX_SNAPLEN_RADIO,
            sample: 1,
        })?;
        sock.capture = Some(capture);
        Ok(Box::new(sock))
    }
}

struct LinuxMonitorSocket {
    nl: Nl80211,
    index: u32,
    /// The radio's own netdev (the station), for its channel.
    station: u32,
    name: String,
    mode: MonitorMode,
    width: u32,
    /// What it was tuned to (exclusive).
    freq: Option<u32>,
    capture: Option<Box<dyn CaptureSocket>>,
}

impl MonitorSocket for LinuxMonitorSocket {
    fn recv(&mut self, wait: Duration, batch: &mut FrameBatch) -> Result<(), CaptureError> {
        match self.capture.as_mut() {
            Some(c) => c.recv(wait, batch),
            None => Err(CaptureError::Io("the monitor is not open".into())),
        }
    }

    fn set_channel(&mut self, freq_mhz: u32) -> Result<(), CaptureError> {
        if self.mode == MonitorMode::Shared {
            return Err(CaptureError::Unavailable(
                "a monitor beside the station stays on the station's channel".into(),
            ));
        }
        let (width, center) = match center_mhz(freq_mhz, self.width) {
            Some(c) => (self.width, c),
            None => (20, freq_mhz),
        };
        match self.nl.set_channel(self.index, freq_mhz, width, center) {
            Ok(()) => {
                self.freq = Some(freq_mhz);
                Ok(())
            }
            Err(GenlError::Errno(EBUSY)) => Err(CaptureError::Unavailable(
                "the radio's station is up again: the monitor follows its channel".into(),
            )),
            Err(e) => Err(unavailable(
                &format!("tuning to {freq_mhz} MHz ({width} MHz wide)"),
                e,
            )),
        }
    }

    fn channel(&mut self) -> Option<u32> {
        // The monitor's own channel when the kernel reports one; beside a
        // station, the station's.
        let own = self.nl.interface(self.index).ok().and_then(|(_, f)| f);
        let station = || self.nl.interface(self.station).ok().and_then(|(_, f)| f);
        own.or(self.freq).or_else(station)
    }

    fn interface(&self) -> String {
        self.name.clone()
    }
}

impl Drop for LinuxMonitorSocket {
    fn drop(&mut self) {
        self.capture = None;
        if let Err(e) = self.nl.del_interface(self.index) {
            log::warn!("wifi monitor {}: removing it: {e}", self.name);
        }
    }
}
