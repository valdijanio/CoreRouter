//! Linux backend.
//!
//! Today: read-only discovery from `/sys/class/net` (no root needed).
//! Next (docs/gaps.md G1.2/G1.3): `rtnetlink` for links/addresses/routes and
//! nftables for firewall/NAT, applied as one transaction per commit.

#[cfg(target_os = "linux")]
mod linux {
    use std::fs;
    use std::path::Path;
    use std::time::{SystemTime, UNIX_EPOCH};

    use corerouter_hal::{Hal, HalError, LinkInfo, LinkState};
    use corerouter_model::{Config, IfName};

    const SYS_NET: &str = "/sys/class/net";

    #[derive(Debug, Default)]
    pub struct LinuxHal {
        _private: (),
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
            "linux (sysfs read-only; netlink apply pending G1.2)".into()
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

        fn apply(&mut self, _from: &Config, _to: &Config) -> Result<(), HalError> {
            Err(HalError::Unsupported(
                "netlink apply is not implemented yet (docs/gaps.md G1.2); use --backend virtual"
                    .into(),
            ))
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
    }
}

#[cfg(target_os = "linux")]
pub use linux::LinuxHal;
