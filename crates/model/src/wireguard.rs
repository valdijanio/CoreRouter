//! `/interface wireguard` and `/interface wireguard peers` (G1.31): an
//! encrypted tunnel interface (RouterOS type `wireguard`) and the peers it
//! talks to. A WireGuard interface is an interface
//! (`InterfaceKind::Wireguard`), so `ip address`, routes, firewall rules and
//! interface lists name it like any other; its keys, port and peers live
//! here. Names and defaults follow RouterOS v7.25 (`docs/wireguard.md`).
//!
//! The data plane is the kernel's WireGuard (`drivers/net/wireguard`); the
//! engine opens the sealed keys and hands the HAL what the kernel needs.
//!
//! Keys are the standard 32-byte Curve25519 keys in base64 (44 characters,
//! as `wg genkey` prints them). The private keys (the interface's, and a
//! peer's when the router generated it for the client config) and the
//! preshared keys are [`Sealed`] at rest, like the PPP passwords.

use std::net::IpAddr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::sealed::Sealed;

/// RouterOS `listen-port` default.
pub const DEFAULT_LISTEN_PORT: u16 = 13231;
/// RouterOS `mtu` default: 1500 minus the worst-case overhead (IPv6
/// underlay: 40 + UDP 8 + WireGuard 32 = 80 bytes), as the kernel's own
/// default (`drivers/net/wireguard/device.c`, `ETH_DATA_LEN - overhead`).
pub const DEFAULT_MTU: u16 = 1420;
/// Overhead of WireGuard over IPv4 / IPv6 (whitepaper §5.4.6 + UDP + IP).
pub const OVERHEAD_V4: u16 = 60;
pub const OVERHEAD_V6: u16 = 80;
/// Peers on one interface. The kernel takes 2^20 (`MAX_PEERS_PER_DEVICE`);
/// past this bound one commit already takes seconds (10 000 peers are
/// created in 0.7 s, 50 000 in 11.7 s, **medido**, `docs/wireguard.md`).
pub const MAX_PEERS: usize = 20_000;
/// Allowed addresses of one peer (hostile input; a site rarely has more
/// than a handful).
pub const MAX_ALLOWED: usize = 256;
/// Longest peer name or comment.
pub const MAX_NAME: usize = 64;
/// A key in base64: 32 bytes = 44 characters with one `=`.
pub const KEY_B64_LEN: usize = 44;

fn default_port() -> u16 {
    DEFAULT_LISTEN_PORT
}

fn is_false(b: &bool) -> bool {
    !*b
}

fn is_zero(v: &u16) -> bool {
    *v == 0
}

/// A public key: 32 bytes in standard base64 (`wg pubkey`). Checked by
/// [`WgKey::parse`]; the bytes come from the engine, which decodes it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct WgKey(String);

impl WgKey {
    /// A key as text (`wg pubkey`), trimmed and checked for shape: 44
    /// characters of the standard base64 alphabet, the last one `=`, and the
    /// one before it a character that leaves no stray bits (so a key has one
    /// spelling and two spellings of the same key never pass as two peers).
    pub fn parse(text: &str) -> Option<Self> {
        let t = text.trim();
        if t.len() != KEY_B64_LEN || !t.ends_with('=') {
            return None;
        }
        let body = t.get(..KEY_B64_LEN - 1)?;
        if !body
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
        {
            return None;
        }
        // 43 characters carry 258 bits: the last one holds 4 key bits and
        // 2 that must be zero (RFC 4648 §3.5, canonical encoding).
        let last = body.bytes().last()?;
        let v = b64_value(last)?;
        if v & 0b11 != 0 {
            return None;
        }
        Some(Self(t.to_owned()))
    }

    /// A key the engine computed (it encodes it itself).
    pub fn from_encoded(text: String) -> Self {
        Self(text)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The first and last characters, enough to tell keys apart in a log
    /// line or a table (`Hk3…9xQ=`).
    pub fn short(&self) -> String {
        let head: String = self.0.chars().take(4).collect();
        let tail: String = self.0.chars().skip(KEY_B64_LEN.saturating_sub(4)).collect();
        format!("{head}…{tail}")
    }
}

impl std::fmt::Display for WgKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn b64_value(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// One WireGuard interface: what `interface.wireguard.add` stores.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Wireguard {
    /// UDP port the encrypted packets arrive on (RouterOS `listen-port`).
    #[serde(default = "default_port")]
    pub listen_port: u16,
    /// Sealed at rest; never shown but to group `full`
    /// (`show_sensitive`).
    #[serde(default, skip_serializing_if = "Sealed::is_empty")]
    pub private_key: Sealed,
    /// Derived from the private key by the engine (read-only, as RouterOS).
    #[serde(default, skip_serializing_if = "WgKey::is_empty")]
    pub public_key: WgKey,
    /// `/interface wireguard peers` of this interface, in the order added.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peers: Vec<WgPeer>,
}

impl Wireguard {
    pub fn new(listen_port: u16) -> Self {
        Self {
            listen_port,
            private_key: Sealed::default(),
            public_key: WgKey::default(),
            peers: Vec::new(),
        }
    }

    pub fn peer(&self, name: &str) -> Option<&WgPeer> {
        self.peers.iter().find(|p| p.name == name)
    }
}

/// One peer of a WireGuard interface (RouterOS `/interface wireguard peers`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WgPeer {
    /// Unique on the router (RouterOS 7.15+ names them `peer1`, `peer2`…).
    pub name: String,
    pub public_key: WgKey,
    /// The peer's private key when the router generated it, to hand the
    /// client its config (RouterOS `private-key=auto`); empty when the
    /// operator pasted the peer's public key. Sealed at rest.
    #[serde(default, skip_serializing_if = "Sealed::is_empty")]
    pub private_key: Sealed,
    /// Optional symmetric key mixed into the handshake (whitepaper §5.2:
    /// a hedge against a future break of Curve25519). Sealed at rest.
    #[serde(default, skip_serializing_if = "Sealed::is_empty")]
    pub preshared_key: Sealed,
    /// Where to send the handshake; `None` = wait for the peer (a road
    /// warrior). The kernel follows the peer when it moves (roaming), so
    /// this is only where the first packet goes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_address: Option<IpAddr>,
    /// 0 = none (only with no `endpoint_address`).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub endpoint_port: u16,
    /// What the peer may send from and what is sent to it (cryptokey
    /// routing). It does not add routes, as in RouterOS.
    #[serde(default)]
    pub allowed_address: Vec<IpNet>,
    /// Seconds between keepalives (0 = off; 25 behind NAT).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub persistent_keepalive: u16,
    /// Never start a handshake: only answer (RouterOS 7.15 `responder`).
    #[serde(default, skip_serializing_if = "is_false")]
    pub responder: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub disabled: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub comment: String,
}

impl WgPeer {
    pub fn new(name: String, public_key: WgKey) -> Self {
        Self {
            name,
            public_key,
            private_key: Sealed::default(),
            preshared_key: Sealed::default(),
            endpoint_address: None,
            endpoint_port: 0,
            allowed_address: Vec::new(),
            persistent_keepalive: 0,
            responder: false,
            disabled: false,
            comment: String::new(),
        }
    }

    /// The router may start a handshake with it: it knows where, and the
    /// operator did not make it answer-only.
    pub fn initiates(&self) -> bool {
        self.endpoint_address.is_some() && self.endpoint_port != 0 && !self.responder
    }
}

/// How a peer looks from its last handshake (G1.31), the rule the engine
/// and every client follow. The timers are the protocol's (whitepaper §6.1,
/// `drivers/net/wireguard/messages.h`): a live session is rekeyed every
/// `REKEY_AFTER_TIME` (120 s) and no packet passes with keys older than
/// `REJECT_AFTER_TIME` (180 s).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PeerState {
    /// A handshake within the last 180 s: the tunnel carries traffic.
    Up,
    /// The last handshake is older, and nothing asks for a new one: a peer
    /// without keepalive that has nothing to send (normal).
    Idle,
    /// The router tries (it has an endpoint and a keepalive, or traffic to
    /// send) and gets no answer.
    NoHandshake,
    /// Never a handshake, and the router only waits (no endpoint, or
    /// `responder`): the peer has not called yet.
    Never,
    Disabled,
}

/// `REJECT_AFTER_TIME` (whitepaper §6.1): past it a session carries nothing.
pub const REJECT_AFTER_SECS: u64 = 180;

impl PeerState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Up => "up",
            Self::Idle => "idle",
            Self::NoHandshake => "no-handshake",
            Self::Never => "never",
            Self::Disabled => "disabled",
        }
    }

    /// `age`: seconds since the last handshake (`None`: never). `sending`:
    /// the router has sent bytes to it (the kernel counts the handshake
    /// initiations too).
    pub fn of(peer: &WgPeer, iface_disabled: bool, age: Option<u64>, sending: bool) -> Self {
        if peer.disabled || iface_disabled {
            return Self::Disabled;
        }
        let tries = peer.initiates() && (peer.persistent_keepalive > 0 || sending);
        match age {
            Some(a) if a <= REJECT_AFTER_SECS => Self::Up,
            Some(_) if tries && peer.persistent_keepalive > 0 => Self::NoHandshake,
            Some(_) => Self::Idle,
            None if tries => Self::NoHandshake,
            None => Self::Never,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const K: &str = "YAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";

    #[test]
    fn keys_have_one_spelling() {
        assert!(WgKey::parse(K).is_some());
        assert_eq!(WgKey::parse(&format!("  {K}\n")).map(|k| k.0), Some(K.into()));
        // Wrong length, alphabet, padding, or stray bits in the last char.
        assert!(WgKey::parse(&K[1..]).is_none());
        assert!(WgKey::parse(&K.replace('+', "-")).is_none());
        assert!(WgKey::parse(&K.replace('=', "A")).is_none());
        assert!(WgKey::parse("YAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmn=").is_none());
        assert!(WgKey::parse("").is_none());
        assert_eq!(WgKey::parse(K).map(|k| k.short()), Some("YAnz…Bmk=".into()));
    }

    #[test]
    fn interface_round_trips_with_defaults_left_out() {
        let mut w = Wireguard::new(DEFAULT_LISTEN_PORT);
        let mut p = WgPeer::new("peer1".into(), WgKey::parse(K).unwrap_or_default());
        p.allowed_address.push("10.9.0.2/32".parse().unwrap_or_else(|_| IpNet::default()));
        w.peers.push(p);
        let j = serde_json::to_value(&w).unwrap_or_default();
        assert_eq!(
            j,
            serde_json::json!({"listen_port": 13231, "peers": [
                {"name": "peer1", "public_key": K, "allowed_address": ["10.9.0.2/32"]}
            ]})
        );
        let back: Wireguard = serde_json::from_value(j).unwrap_or_else(|_| Wireguard::new(0));
        assert_eq!(back, w);
    }

    #[test]
    fn state_follows_the_protocol_timers() {
        let key = WgKey::parse(K).unwrap_or_default();
        let mut road = WgPeer::new("road".into(), key.clone());
        assert_eq!(PeerState::of(&road, false, None, false), PeerState::Never);
        assert_eq!(PeerState::of(&road, false, Some(10), true), PeerState::Up);
        assert_eq!(PeerState::of(&road, false, Some(181), false), PeerState::Idle);
        road.disabled = true;
        assert_eq!(PeerState::of(&road, false, Some(1), true), PeerState::Disabled);

        let mut site = WgPeer::new("site".into(), key);
        site.endpoint_address = "198.51.100.7".parse().ok();
        site.endpoint_port = 13231;
        assert_eq!(PeerState::of(&site, false, None, false), PeerState::Never);
        assert_eq!(PeerState::of(&site, false, None, true), PeerState::NoHandshake);
        assert_eq!(PeerState::of(&site, false, Some(500), true), PeerState::Idle);
        site.persistent_keepalive = 25;
        assert_eq!(PeerState::of(&site, false, None, false), PeerState::NoHandshake);
        assert_eq!(PeerState::of(&site, false, Some(180), false), PeerState::Up);
        assert_eq!(PeerState::of(&site, false, Some(181), false), PeerState::NoHandshake);
        assert_eq!(PeerState::of(&site, true, Some(1), false), PeerState::Disabled);
        site.responder = true;
        assert_eq!(PeerState::of(&site, false, None, true), PeerState::Never);
    }
}
