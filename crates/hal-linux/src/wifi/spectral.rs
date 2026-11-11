//! Spectral scan on Linux (G1.30i): Qualcomm Atheros radios (ath9k, ath10k,
//! ath11k) hand FFT samples through debugfs, `/sys/kernel/debug/ieee80211/
//! <phy>/<driver>/`:
//!
//! - `spectral_scan_ctl` takes the mode (Linux 6.18.59,
//!   `ath9k/common-spectral.c` `write_file_spec_scan_ctl`,
//!   `ath10k/spectral.c`, `ath11k/spectral.c`): `background` samples the
//!   channel in use, ath9k's `chanscan` every channel the radio visits
//!   while it scans, `trigger` starts, `disable` stops;
//! - `spectral_scan0`, `spectral_scan1`… (a relay channel, one file per
//!   CPU: `relay_open("spectral_scan", …)`) carry the samples, in the TLV
//!   format `corerouter_hal::wifi::spectral` reads.
//!
//! The scan runs in a thread of its own (`wifi-spectral-<radio>`) for the
//! seconds asked and leaves its samples in a bounded queue for the engine's
//! tick; nothing here waits on the session. No other driver has the
//! interface: rtw88/rtw89 (Realtek), mt76 (MediaTek) and iwlwifi (Intel)
//! have no spectral scan in the kernel, and `mac80211_hwsim` has none.

use std::path::Path;

/// The drivers whose debugfs has `spectral_scan_ctl`, and the debugfs
/// directory each one makes.
const DRIVERS: [&str; 3] = ["ath9k", "ath10k", "ath11k"];

/// Can the radio of `driver` scan the spectrum: `Ok(dir)` with its debugfs
/// directory, or why not, in words. `ctl` tells whether a directory has
/// the control file.
pub(crate) fn support(
    driver: Option<&str>,
    phy_debugfs: &Path,
    ctl: impl Fn(&Path) -> bool,
) -> Result<std::path::PathBuf, String> {
    let name = driver.unwrap_or("unknown");
    let Some(family) = DRIVERS.iter().find(|d| name.starts_with(*d)) else {
        return Err(format!(
            "this radio ({name}) has no spectral scan: it needs a Qualcomm Atheros chip \
             (ath9k, ath10k, ath11k)"
        ));
    };
    let dir = phy_debugfs.join(family);
    if ctl(&dir.join("spectral_scan_ctl")) {
        Ok(dir)
    } else {
        Err(format!(
            "the {family} driver has no spectral scan here: debugfs is not mounted, or the \
             kernel was built without it ({})",
            match *family {
                "ath9k" => "CONFIG_ATH9K_COMMON_SPECTRAL",
                "ath10k" => "CONFIG_ATH10K_SPECTRAL",
                _ => "CONFIG_ATH11K_SPECTRAL",
            }
        ))
    }
}

/// What to write to `spectral_scan_ctl` before `trigger`.
pub(crate) fn mode(dir: &Path, sweep: bool) -> &'static str {
    if sweep && dir.ends_with("ath9k") {
        "chanscan"
    } else {
        "background"
    }
}

#[cfg(target_os = "linux")]
pub(crate) use run::Run;

#[cfg(target_os = "linux")]
mod run {
    use std::collections::VecDeque;
    use std::io::Read;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex, PoisonError};
    use std::time::{Duration, Instant};

    use corerouter_hal::HalError;
    use corerouter_hal::wifi::spectral::parse_stream;
    use corerouter_hal::wifi::{MAX_SPECTRAL_PENDING, SpectralSample};

    /// How often the relay files are read.
    const READ_EVERY: Duration = Duration::from_millis(50);
    /// Bytes read from a relay file at a time (a relay sub-buffer of
    /// ath10k is 1140 bytes, `relay_open(…, 1140, 2500, …)`).
    const CHUNK: usize = 64 * 1024;
    /// Relay files (CPUs) looked at.
    const MAX_CPUS: usize = 512;

    /// A spectral scan running.
    pub(crate) struct Run {
        stop: Arc<AtomicBool>,
        queue: Arc<Mutex<VecDeque<SpectralSample>>>,
    }

    fn write(ctl: &Path, what: &str) -> Result<(), HalError> {
        std::fs::write(ctl, what)
            .map_err(|e| HalError::Io(format!("{}: {what}: {e}", ctl.display())))
    }

    impl Run {
        /// Start: the mode and `trigger` written here (an error is the
        /// caller's), the reading in the thread.
        pub(crate) fn start(
            radio: &str,
            dir: &Path,
            secs: u32,
            sweep: bool,
        ) -> Result<Self, HalError> {
            let ctl = dir.join("spectral_scan_ctl");
            write(&ctl, super::mode(dir, sweep))?;
            write(&ctl, "trigger")?;
            let stop = Arc::new(AtomicBool::new(false));
            let queue = Arc::new(Mutex::new(VecDeque::new()));
            let (s, q, dir) = (Arc::clone(&stop), Arc::clone(&queue), dir.to_path_buf());
            let until = Instant::now() + Duration::from_secs(u64::from(secs));
            std::thread::Builder::new()
                .name(format!("wifi-spectral-{radio}"))
                .spawn(move || read_loop(&dir, until, &s, &q))
                .map_err(|e| HalError::Io(format!("the spectral scan's thread: {e}")))?;
            Ok(Self { stop, queue })
        }

        /// The samples since the last call, at most `max`.
        pub(crate) fn take(&self, max: usize) -> Vec<SpectralSample> {
            let mut q = self.queue.lock().unwrap_or_else(PoisonError::into_inner);
            let n = max.min(q.len());
            q.drain(..n).collect()
        }

        pub(crate) fn finished(&self) -> bool {
            self.stop.load(Ordering::Relaxed)
        }
    }

    impl Drop for Run {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
        }
    }

    /// The relay files of `dir`, `spectral_scan<cpu>`.
    fn relays(dir: &Path) -> Vec<PathBuf> {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return Vec::new();
        };
        rd.filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .and_then(|n| n.strip_prefix("spectral_scan"))
                    .is_some_and(|cpu| !cpu.is_empty() && cpu.bytes().all(|b| b.is_ascii_digit()))
            })
            .take(MAX_CPUS)
            .collect()
    }

    fn read_loop(
        dir: &Path,
        until: Instant,
        stop: &AtomicBool,
        queue: &Mutex<VecDeque<SpectralSample>>,
    ) {
        let mut files: Vec<(std::fs::File, Vec<u8>)> = relays(dir)
            .into_iter()
            .filter_map(|p| std::fs::File::open(p).ok().map(|f| (f, Vec::new())))
            .collect();
        let mut buf = vec![0u8; CHUNK];
        let mut dropped = 0u64;
        while !stop.load(Ordering::Relaxed) && Instant::now() < until {
            let mut fresh = Vec::new();
            for (f, carry) in &mut files {
                // A relay file reads what is there and then 0.
                while let Ok(n) = f.read(&mut buf) {
                    let Some(got) = buf.get(..n).filter(|g| !g.is_empty()) else {
                        break;
                    };
                    carry.extend_from_slice(got);
                    let used = parse_stream(carry, &mut fresh, MAX_SPECTRAL_PENDING);
                    carry.drain(..used.min(carry.len()));
                    // A TLV is at most a few hundred bytes: more left over
                    // is not a stream any more.
                    if carry.len() > 4096 {
                        carry.clear();
                    }
                }
            }
            if !fresh.is_empty() {
                let mut q = queue.lock().unwrap_or_else(PoisonError::into_inner);
                q.extend(fresh);
                while q.len() > MAX_SPECTRAL_PENDING {
                    q.pop_front();
                    dropped = dropped.saturating_add(1);
                }
            }
            std::thread::sleep(READ_EVERY);
        }
        let _ = write(&dir.join("spectral_scan_ctl"), "disable");
        stop.store(true, Ordering::Relaxed);
        if dropped > 0 {
            log::debug!(
                "wifi spectral {}: {dropped} samples dropped (the engine read too slowly)",
                dir.display()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn which_radios_scan_the_spectrum() {
        let phy = Path::new("/sys/kernel/debug/ieee80211/phy0");
        let yes = |_: &Path| true;
        let no = |_: &Path| false;
        let e = support(Some("rtw89_8852be"), phy, yes).unwrap_err();
        assert!(
            e.contains("rtw89_8852be") && e.contains("Qualcomm Atheros"),
            "{e}"
        );
        assert!(support(Some("mt7921e"), phy, yes).is_err());
        assert!(support(None, phy, yes).unwrap_err().contains("unknown"));
        assert_eq!(
            support(Some("ath10k_pci"), phy, yes).unwrap(),
            phy.join("ath10k")
        );
        let e = support(Some("ath9k"), phy, no).unwrap_err();
        assert!(e.contains("CONFIG_ATH9K_COMMON_SPECTRAL"), "{e}");
        assert_eq!(mode(&phy.join("ath9k"), true), "chanscan");
        assert_eq!(mode(&phy.join("ath10k"), true), "background");
        assert_eq!(mode(&phy.join("ath9k"), false), "background");
    }
}
