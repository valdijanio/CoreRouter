//! WireGuard interfaces (G1.31): what the engine asks the data plane to
//! hold, and what the data plane reports back.
//!
//! The link itself is created and deleted by `Hal::apply` like any other
//! (its kind is `wireguard`); the keys, the port and the peers come after,
//! from [`crate::Hal::wireguard_set`], because they are sealed in the
//! config and only the engine opens them. Linux takes them over generic
//! netlink (`hal-linux`, family `wireguard`); the virtual lab keeps them
//! and makes two of its own interfaces that name each other shake hands.
//!
//! [`WgDevice`] holds private keys: its `Debug` prints neither them nor the
//! preshared keys, so a log line or a panic message never carries one.

use std::collections::BTreeMap;
use std::fmt;
use std::net::SocketAddr;

use corerouter_model::IfName;
use ipnet::IpNet;

/// A Curve25519 key (private, public or preshared), 32 bytes.
pub type Key = [u8; 32];

/// What one WireGuard interface must hold (`wg setconf`, but incremental:
/// the backend changes only what differs, so a live session survives a
/// change to another peer).
#[derive(Clone, PartialEq, Eq, Default)]
pub struct WgDevice {
    pub private_key: Key,
    pub listen_port: u16,
    /// Mark of the encrypted packets (`WGDEVICE_A_FWMARK`): the routing
    /// mark of the VRF they go by (G1.31c), 0 = none (main table).
    pub fwmark: u32,
    /// Enabled peers only, in config order.
    pub peers: Vec<WgPeerSpec>,
}

#[derive(Clone, PartialEq, Eq, Default)]
pub struct WgPeerSpec {
    pub public_key: Key,
    /// All zeros: none.
    pub preshared_key: Key,
    /// Where the first handshake goes; `None`: wait for the peer.
    pub endpoint: Option<SocketAddr>,
    /// Seconds; 0 = off.
    pub persistent_keepalive: u16,
    pub allowed: Vec<IpNet>,
}

impl fmt::Debug for WgDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WgDevice")
            .field("private_key", &"<hidden>")
            .field("listen_port", &self.listen_port)
            .field("fwmark", &self.fwmark)
            .field("peers", &self.peers)
            .finish()
    }
}

impl fmt::Debug for WgPeerSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WgPeerSpec")
            .field("public_key", &short(&self.public_key))
            .field(
                "preshared_key",
                &if self.preshared_key == [0; 32] {
                    "none"
                } else {
                    "<hidden>"
                },
            )
            .field("endpoint", &self.endpoint)
            .field("persistent_keepalive", &self.persistent_keepalive)
            .field("allowed", &self.allowed)
            .finish()
    }
}

/// The first bytes of a public key in hex, to tell peers apart in logs.
pub fn short(k: &Key) -> String {
    k.iter().take(4).map(|b| format!("{b:02x}")).collect()
}

/// What the data plane says about one interface (`wg show`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WgStatus {
    pub listen_port: u16,
    pub public_key: Key,
    pub peers: Vec<WgPeerStatus>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WgPeerStatus {
    pub public_key: Key,
    /// Where its last authenticated packet came from (roaming), or the
    /// configured endpoint before any.
    pub endpoint: Option<SocketAddr>,
    /// Unix seconds of the last handshake; `None`: never.
    pub last_handshake_unix: Option<u64>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

/// The virtual lab's WireGuard: it keeps what it was told and, on every
/// read, makes two of its interfaces whose peers name each other's public
/// key look connected (a handshake now, traffic counted by reads). Anything
/// else never shakes hands: the lab has no Internet to reach a real peer.
#[derive(Debug, Clone, Default)]
pub struct LabWireguard {
    devices: BTreeMap<IfName, (WgDevice, Key)>,
    reads: u64,
}

impl LabWireguard {
    /// `public`: the public key of `dev.private_key` (the engine computed
    /// it; the lab does no Curve25519).
    pub fn set(&mut self, name: &IfName, dev: &WgDevice, public: Key) {
        self.devices.insert(name.clone(), (dev.clone(), public));
    }

    pub fn remove(&mut self, name: &IfName) {
        self.devices.remove(name);
    }

    /// Forget the interfaces `keep` does not name (they left the config).
    pub fn retain(&mut self, keep: impl Fn(&IfName) -> bool) {
        self.devices.retain(|n, _| keep(n));
    }

    pub fn status(&mut self, name: &IfName, now_unix: u64) -> Option<WgStatus> {
        self.reads = self.reads.saturating_add(1);
        let (dev, public) = self.devices.get(name)?;
        let peers = dev
            .peers
            .iter()
            .map(|p| {
                // The other side: a lab interface with this public key that
                // has a peer with ours.
                let mutual = self.devices.iter().any(|(n, (d, k))| {
                    n != name
                        && *k == p.public_key
                        && d.peers.iter().any(|q| q.public_key == *public)
                });
                let bytes = if mutual {
                    self.reads.saturating_mul(1480)
                } else {
                    0
                };
                WgPeerStatus {
                    public_key: p.public_key,
                    endpoint: p.endpoint,
                    last_handshake_unix: mutual.then_some(now_unix.saturating_sub(7)),
                    rx_bytes: bytes,
                    tx_bytes: if p.endpoint.is_some() && !mutual {
                        148
                    } else {
                        bytes
                    },
                }
            })
            .collect();
        Some(WgStatus {
            listen_port: dev.listen_port,
            public_key: *public,
            peers,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> IfName {
        s.parse().unwrap()
    }

    #[test]
    fn debug_hides_the_secret_keys() {
        let dev = WgDevice {
            private_key: [7; 32],
            listen_port: 13231,
            fwmark: 0,
            peers: vec![WgPeerSpec {
                public_key: [1; 32],
                preshared_key: [9; 32],
                ..WgPeerSpec::default()
            }],
        };
        let text = format!("{dev:?}");
        assert!(text.contains("<hidden>"));
        assert!(!text.contains("[7,"), "{text}");
        assert!(!text.contains('9'), "{text}");
        assert!(text.contains("01010101"));
    }

    #[test]
    fn two_lab_interfaces_that_name_each_other_shake_hands() {
        let mut lab = LabWireguard::default();
        let a_pub = [1; 32];
        let b_pub = [2; 32];
        let peer = |k: Key| WgPeerSpec {
            public_key: k,
            endpoint: "127.0.0.1:13231".parse().ok(),
            ..WgPeerSpec::default()
        };
        lab.set(
            &n("wg0"),
            &WgDevice {
                peers: vec![peer(b_pub), peer([3; 32])],
                ..WgDevice::default()
            },
            a_pub,
        );
        let s = lab.status(&n("wg0"), 1000).unwrap();
        assert_eq!(s.peers.first().and_then(|p| p.last_handshake_unix), None);
        lab.set(
            &n("wg1"),
            &WgDevice {
                peers: vec![peer(a_pub)],
                ..WgDevice::default()
            },
            b_pub,
        );
        let s = lab.status(&n("wg0"), 1000).unwrap();
        assert_eq!(
            s.peers.first().and_then(|p| p.last_handshake_unix),
            Some(993)
        );
        assert_eq!(s.peers.get(1).and_then(|p| p.last_handshake_unix), None);
        lab.retain(|i| i.as_str() == "wg1");
        assert!(lab.status(&n("wg0"), 1000).is_none());
    }
}
