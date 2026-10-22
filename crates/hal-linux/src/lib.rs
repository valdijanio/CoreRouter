//! Linux backend.
//!
//! - `apply`: [`plan::plan`] turns the diff `from` → `to` into ordered kernel
//!   operations (pure, tested everywhere); `netlink` runs them over rtnetlink
//!   and undoes the done ones if one fails (G1.2).
//! - discovery and counters: `/sys/class/net` (netlink stats in G1.7).
//! - `features`: probed once, on first use, with a throwaway link per
//!   capability (`netlink::features`), then cached (G1.14).
//!
//! Integration tests run against a real kernel inside a throwaway network
//! namespace, without root: see `tests/netns.rs`.

pub mod plan;

#[cfg(target_os = "linux")]
mod netlink;

#[cfg(target_os = "linux")]
mod linux {
    use std::fs;
    use std::path::Path;
    use std::sync::OnceLock;
    use std::time::{SystemTime, UNIX_EPOCH};

    use corerouter_hal::{Features, Hal, HalError, LinkInfo, LinkState};
    use corerouter_model::{Config, IfName};

    const SYS_NET: &str = "/sys/class/net";
    /// `ARPHRD_LOOPBACK`: the kernel `lo` is never managed (its MTU, 65536,
    /// does not even fit the model).
    const ARPHRD_LOOPBACK: &str = "772";

    #[derive(Debug, Default)]
    pub struct LinuxHal {
        /// Probed on the first `features()` call, not at startup.
        features: OnceLock<Features>,
    }

    impl LinuxHal {
        pub fn new() -> Self {
            Self::default()
        }
    }

    fn read_trim(path: &Path) -> Option<String> {
        fs::read_to_string(path).ok().map(|s| s.trim().to_owned())
    }

    fn read_u64(path: &Path) -> u64 {
        read_trim(path).and_then(|s| s.parse().ok()).unwrap_or(0)
    }

    fn names() -> Result<Vec<(IfName, std::path::PathBuf)>, HalError> {
        let dir = fs::read_dir(SYS_NET).map_err(|e| HalError::Io(format!("{SYS_NET}: {e}")))?;
        let mut out: Vec<_> = dir
            .filter_map(Result::ok)
            .filter(|e| read_trim(&e.path().join("type")).as_deref() != Some(ARPHRD_LOOPBACK))
            .filter_map(|e| {
                let name = e.file_name().to_str()?.parse::<IfName>().ok()?;
                Some((name, e.path()))
            })
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(out)
    }

    impl Hal for LinuxHal {
        fn describe(&self) -> String {
            "linux (rtnetlink apply, sysfs counters)".into()
        }

        fn discover_links(&mut self) -> Result<Vec<LinkInfo>, HalError> {
            Ok(names()?
                .into_iter()
                .map(|(name, p)| LinkInfo {
                    mac: read_trim(&p.join("address")),
                    mtu: read_trim(&p.join("mtu"))
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(1500),
                    name,
                })
                .collect())
        }

        fn apply(&mut self, from: &Config, to: &Config) -> Result<(), HalError> {
            crate::netlink::apply(&crate::plan::plan(from, to)?)
        }

        fn poll(&mut self) -> Vec<LinkState> {
            names()
                .unwrap_or_default()
                .into_iter()
                .map(|(name, p)| {
                    let st = p.join("statistics");
                    LinkState {
                        running: read_trim(&p.join("operstate")).as_deref() == Some("up"),
                        rx_bytes: read_u64(&st.join("rx_bytes")),
                        tx_bytes: read_u64(&st.join("tx_bytes")),
                        rx_packets: read_u64(&st.join("rx_packets")),
                        tx_packets: read_u64(&st.join("tx_packets")),
                        name,
                    }
                })
                .collect()
        }

        fn now_unix(&self) -> Option<u64> {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()
                .map(|d| d.as_secs())
        }

        fn features(&self) -> Features {
            *self.features.get_or_init(crate::netlink::features)
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::LinuxHal;
