//! WireGuard at run time (G1.31): keys, the push of the running config to
//! the data plane, and the state of each peer.
//!
//! The link is created by `Hal::apply` like any other; its keys, port and
//! peers are sealed in the config, so the engine opens them and hands them
//! to [`Hal::wireguard_set`](corerouter_hal::Hal::wireguard_set):
//!
//! - right after a commit that changed a WireGuard interface
//!   ([`Session::wireguard_after_commit`]), so a command's effect is there
//!   when it returns;
//! - and on the service clock ([`Session::wireguard_service`], the DHCP
//!   clients' clock): what failed is tried again, and every
//!   [`REPAIR_MS`] the backend compares with what the link holds (a link
//!   recreated by a restart, a peer someone removed with `wg`). The backend
//!   sends only the difference, so a push that changes nothing costs one
//!   read of the link.
//!
//! Keys are Curve25519 (`x25519-dalek`, pure Rust: the engine compiles for
//! wasm32). A private key is clamped as `wg genkey` does (RFC 7748 §5), so
//! the base64 we keep is the one `wg` would show.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};

use base64::Engine as _;
pub use corerouter_hal::wireguard::Key;
use corerouter_hal::wireguard::{WgDevice, WgPeerSpec, WgPeerStatus, WgStatus};
use corerouter_model::wireguard::{PeerState, REJECT_AFTER_SECS, WgKey, WgPeer, Wireguard};
use corerouter_model::{Config, IfName, InterfaceKind};

use crate::Session;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// How often the service compares each link with what it should hold.
pub const REPAIR_MS: u64 = 30_000;
/// A name endpoint is asked again at most this often (and after a
/// failure), only while its peer has no fresh handshake (G1.31b).
pub const RESOLVE_AGAIN_MS: u64 = 30_000;
/// A peer the router tries and that has not answered this long is a
/// health warning (G1.31b): past `REJECT_AFTER_TIME` (180 s) and two
/// minutes of retries.
pub const NO_HANDSHAKE_ALERT_SECS: u64 = 300;

/// A fresh private key, clamped (RFC 7748 §5, as `wg genkey`).
pub fn generate_private() -> Result<Key, String> {
    let mut k = [0u8; 32];
    if let Err(e) = crate::auth::random_bytes(&mut k) {
        // The browser lab has no random source; its keys protect nothing
        // (there is no network behind it), but two interfaces still need
        // two keys.
        if !cfg!(target_arch = "wasm32") {
            return Err(e);
        }
        lab_fill(&mut k);
    }
    Ok(clamp(k))
}

fn lab_fill(k: &mut Key) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0x9E37_79B9_7F4A_7C15);
    let mut x = NEXT.fetch_add(0x6A09_E667_F3BC_C909, Ordering::Relaxed);
    for chunk in k.chunks_mut(8) {
        // xorshift64*
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        let v = x.wrapping_mul(0x2545_F491_4F6C_DD1D).to_le_bytes();
        for (d, s) in chunk.iter_mut().zip(v) {
            *d = s;
        }
    }
}

fn clamp(mut k: Key) -> Key {
    if let Some(b) = k.first_mut() {
        *b &= 248;
    }
    if let Some(b) = k.last_mut() {
        *b = (*b & 127) | 64;
    }
    k
}

/// The public key of `private` (Curve25519 scalar times the base point).
pub fn public_of(private: &Key) -> Key {
    let secret = x25519_dalek::StaticSecret::from(*private);
    x25519_dalek::PublicKey::from(&secret).to_bytes()
}

pub fn encode(k: &Key) -> String {
    B64.encode(k)
}

/// The 32 bytes of a key in base64 (`None`: not a key).
pub fn decode(text: &str) -> Option<Key> {
    let k = WgKey::parse(text)?;
    B64.decode(k.as_str()).ok()?.try_into().ok()
}

pub fn wg_key(k: &Key) -> WgKey {
    WgKey::from_encoded(encode(k))
}

/// A private key typed by the operator (base64), clamped.
pub fn parse_private(text: &str) -> Option<Key> {
    decode(text).map(clamp)
}

/// The WireGuard interfaces of `cfg`: (name, disabled, settings).
pub fn interfaces(cfg: &Config) -> impl Iterator<Item = (&IfName, bool, &Wireguard)> {
    cfg.interfaces.iter().filter_map(|(n, i)| match &i.kind {
        InterfaceKind::Wireguard(w) => Some((n, i.disabled, &**w)),
        _ => None,
    })
}

/// Every peer of `cfg` with its interface.
pub fn peers(cfg: &Config) -> impl Iterator<Item = (&IfName, &WgPeer)> {
    interfaces(cfg).flat_map(|(n, _, w)| w.peers.iter().map(move |p| (n, p)))
}

/// The data plane's peers of one interface by public key: a listing looks
/// each configured peer up here, once. A walk of the status per peer was
/// O(peers²): 20 000 peers took 4·10⁸ key compares on every refresh of the
/// window (G1.31a).
pub fn status_by_key(status: Option<&WgStatus>) -> BTreeMap<Key, &WgPeerStatus> {
    status
        .map(|st| st.peers.iter().map(|p| (p.public_key, p)).collect())
        .unwrap_or_default()
}

/// What a listing says of one peer: its state, the seconds since its last
/// handshake, and what the data plane reports (`None`: not running).
pub fn peer_view<'a>(
    peer: &WgPeer,
    iface_disabled: bool,
    by_key: &BTreeMap<Key, &'a WgPeerStatus>,
    now: u64,
) -> (PeerState, Option<u64>, Option<&'a WgPeerStatus>) {
    let st = decode(peer.public_key.as_str()).and_then(|k| by_key.get(&k).copied());
    let age = st
        .and_then(|x| x.last_handshake_unix)
        .map(|t| now.saturating_sub(t));
    let state = PeerState::of(peer, iface_disabled, age, st.is_some_and(|x| x.tx_bytes > 0));
    (state, age, st)
}

/// The run-time state: what each link was last given.
#[derive(Default)]
pub struct WgRuntime {
    pushed: BTreeMap<IfName, Pushed>,
    /// Name endpoints as the resolver last answered, by name.
    resolved: BTreeMap<String, Resolved>,
    /// When each peer (by name) was first seen trying without an answer
    /// and never having had a handshake (Unix seconds).
    trying_since: BTreeMap<String, u64>,
}

/// What the resolver said of a name endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    /// The address in use (kept from an earlier answer when the last one
    /// failed: an old address beats none).
    pub ip: Option<IpAddr>,
    /// Monotonic ms of the last answer (the service's clock).
    pub at_ms: u64,
    /// Unix seconds of the last answer, to show.
    pub at_unix: u64,
    pub error: Option<String>,
}

struct Pushed {
    dev: WgDevice,
    at_ms: u64,
    error: Option<String>,
}

impl WgRuntime {
    /// Why the last push to `name` failed, if it did.
    pub fn error(&self, name: &IfName) -> Option<&str> {
        self.pushed.get(name).and_then(|p| p.error.as_deref())
    }

    /// The resolver's last answer for name endpoint `host`.
    pub fn resolved(&self, host: &str) -> Option<&Resolved> {
        self.resolved.get(host)
    }
}

/// Where the handshake of `p` goes: its address, or what the resolver
/// gave for its name (`None`: no endpoint, or a name not resolved yet).
pub fn endpoint_of(p: &WgPeer, resolved: &BTreeMap<String, Resolved>) -> Option<SocketAddr> {
    let host = p.endpoint_address.as_ref().filter(|_| p.endpoint_port != 0)?;
    let ip = host.ip().or_else(|| resolved.get(host.as_str()).and_then(|r| r.ip))?;
    Some(SocketAddr::new(ip, p.endpoint_port))
}

/// G1.31b, Safe Mode: why going from `before` to `after` would cut a
/// session that comes in through WireGuard interface `wg` from `caller`
/// (the peer whose allowed address holds it): a new key pair or port on
/// the interface, or that peer removed, disabled, rekeyed or no longer
/// holding the caller's address. `None`: the tunnel stays.
pub(crate) fn tunnel_cut(before: &Config, after: &Config, wg: &IfName, caller: IpAddr) -> Option<String> {
    let of = |cfg: &Config| match cfg.interfaces.get(wg).map(|i| &i.kind) {
        Some(InterfaceKind::Wireguard(w)) => Some(w.clone()),
        _ => None,
    };
    let was = of(before)?;
    let Some(now) = of(after) else {
        return Some(format!("would remove {wg}, the WireGuard tunnel this connection comes through"));
    };
    // The peer the caller is behind: the longest allowed prefix holding it.
    let behind = |w: &Wireguard| {
        w.peers
            .iter()
            .filter(|p| !p.disabled)
            .filter_map(|p| p.allowed_address.iter().filter(|n| n.contains(&caller)).map(|n| n.prefix_len()).max().map(|l| (l, p)))
            .max_by_key(|(l, _)| *l)
            .map(|(_, p)| p.clone())
    };
    let peer = behind(&was)?;
    if now.public_key != was.public_key {
        return Some(format!(
            "would give {wg} a new key pair: peer '{}', which this connection comes through, keeps the old public key and the tunnel drops",
            peer.name
        ));
    }
    if now.listen_port != was.listen_port {
        return Some(format!(
            "would move {wg} from UDP {} to {}: peer '{}', which this connection comes through, keeps sending to the old port",
            was.listen_port, now.listen_port, peer.name
        ));
    }
    match behind(&now) {
        None => Some(format!(
            "would remove or disable peer '{}' of {wg}, or take {caller} out of its allowed address: this connection comes through it",
            peer.name
        )),
        Some(p) if p.public_key != peer.public_key => Some(format!(
            "would send {caller} to peer '{}' instead of '{}' of {wg}, which this connection comes through",
            p.name, peer.name
        )),
        Some(_) => None,
    }
}

impl Session {
    /// What WireGuard interface `name` of `cfg` must hold, keys opened.
    /// `Err`: why it cannot be built (a key that does not open).
    fn wireguard_device(&mut self, w: &Wireguard) -> Result<(WgDevice, Key), String> {
        let resolved = self.ext::<WgRuntime>().map(|rt| rt.resolved.clone()).unwrap_or_default();
        let key = crate::sealing::key(self)?;
        let private = key
            .open(&w.private_key)
            .and_then(|t| parse_private(&t))
            .ok_or("its private key cannot be opened (sealed with another router's key?)")?;
        let peers = w
            .peers
            .iter()
            .filter(|p| !p.disabled)
            .filter_map(|p| {
                let public_key = decode(p.public_key.as_str())?;
                let preshared_key = if p.preshared_key.is_empty() {
                    [0; 32]
                } else {
                    key.open(&p.preshared_key).and_then(|t| decode(&t)).unwrap_or([0; 32])
                };
                Some(WgPeerSpec {
                    public_key,
                    preshared_key,
                    endpoint: endpoint_of(p, &resolved),
                    persistent_keepalive: p.persistent_keepalive,
                    allowed: p.allowed_address.clone(),
                })
            })
            .collect();
        let dev = WgDevice {
            private_key: private,
            listen_port: w.listen_port,
            peers,
        };
        Ok((dev, public_of(&private)))
    }

    /// Push every enabled WireGuard interface of the running config whose
    /// wanted state changed, or all when `repair` (and those that failed).
    fn wireguard_push(&mut self, now_ms: u64, repair: bool) {
        let running = self.store().running().clone();
        let wanted: Vec<(IfName, Wireguard)> = interfaces(&running)
            .filter(|(_, off, _)| !off)
            .map(|(n, _, w)| (n.clone(), w.clone()))
            .collect();
        if let Some(rt) = self.ext_mut::<WgRuntime>() {
            rt.pushed.retain(|n, _| wanted.iter().any(|(w, _)| w == n));
        }
        for (name, w) in wanted {
            let built = self.wireguard_device(&w);
            let (dev, public) = match built {
                Ok(d) => d,
                Err(e) => {
                    self.wireguard_note(&name, WgDevice::default(), now_ms, Some(e));
                    continue;
                }
            };
            let due = self.ext::<WgRuntime>().is_none_or(|rt| match rt.pushed.get(&name) {
                None => true,
                Some(p) => {
                    p.dev != dev
                        || p.error.is_some()
                        || (repair && now_ms.saturating_sub(p.at_ms) >= REPAIR_MS)
                }
            });
            if !due {
                continue;
            }
            let r = self.hal_mut().wireguard_set(&name, &dev, &public);
            let err = r.err().map(|e| e.to_string());
            if let Some(e) = &err {
                let first = self.ext::<WgRuntime>().is_none_or(|rt| {
                    rt.pushed.get(&name).and_then(|p| p.error.as_ref()) != Some(e)
                });
                if first {
                    log::warn!("wireguard: {name}: {e}");
                }
            }
            self.wireguard_note(&name, dev, now_ms, err);
        }
    }

    fn wireguard_note(&mut self, name: &IfName, dev: WgDevice, now_ms: u64, error: Option<String>) {
        if let Some(rt) = self.ext_mut::<WgRuntime>() {
            rt.pushed.insert(
                name.clone(),
                Pushed {
                    dev,
                    at_ms: now_ms,
                    error,
                },
            );
        }
    }

    /// After a commit (G1.31): the WireGuard interfaces it changed get their
    /// keys and peers now, not on the next service tick.
    pub(crate) fn wireguard_after_commit(&mut self) {
        let any = self
            .store()
            .running()
            .interfaces
            .values()
            .any(|i| matches!(i.kind, InterfaceKind::Wireguard(_)));
        let had = self.ext::<WgRuntime>().is_some_and(|rt| !rt.pushed.is_empty());
        if any || had {
            let now = self.ext::<WgRuntime>().and_then(|rt| rt.pushed.values().map(|p| p.at_ms).max());
            self.wireguard_push(now.unwrap_or(0), false);
        }
    }

    /// The service clock (G1.31): retry what failed, compare with the
    /// kernel every [`REPAIR_MS`]. `now_ms`: monotonic.
    pub fn wireguard_service(&mut self, now_ms: u64) {
        if interfaces(self.store().running()).next().is_none()
            && self.ext::<WgRuntime>().is_none_or(|rt| rt.pushed.is_empty())
        {
            return;
        }
        self.wireguard_push(now_ms, true);
    }

    /// The name endpoints to ask the resolver now (G1.31b): never
    /// answered, or whose peer has no handshake for `REJECT_AFTER_TIME`
    /// (180 s) and was asked [`RESOLVE_AGAIN_MS`] ago or more — the rule
    /// of OpenWrt's `wireguard_watchdog` and RouterOS (a peer that moved
    /// its name to a new address is found again). A failed answer is
    /// asked again on the same clock.
    pub fn wireguard_names_due(&mut self, now_ms: u64) -> Vec<String> {
        let running = self.store().running().clone();
        let now = self.now().unwrap_or(0);
        let mut due: Vec<String> = Vec::new();
        for (iface, off, w) in interfaces(&running) {
            let named: Vec<&WgPeer> = w
                .peers
                .iter()
                .filter(|p| !p.disabled && p.endpoint_address.as_ref().is_some_and(|h| h.ip().is_none()))
                .collect();
            if off || named.is_empty() {
                continue;
            }
            let status = self.wireguard_status(iface).0;
            let by_key = status_by_key(status.as_ref());
            for p in named {
                let Some(host) = p.endpoint_address.as_ref().map(|h| h.as_str().to_owned()) else {
                    continue;
                };
                let (_, age, _) = peer_view(p, false, &by_key, now);
                let fresh = age.is_some_and(|a| a <= REJECT_AFTER_SECS);
                let last = self.ext::<WgRuntime>().and_then(|rt| rt.resolved.get(&host).cloned());
                let ask = match last {
                    None => true,
                    Some(r) => now_ms.saturating_sub(r.at_ms) >= RESOLVE_AGAIN_MS && (r.error.is_some() || !fresh),
                };
                if ask && !due.contains(&host) {
                    due.push(host);
                }
            }
        }
        due
    }

    /// The resolver's answer for name endpoint `host`: kept (an address
    /// that changed goes to the kernel now), the old address kept when it
    /// failed.
    pub fn wireguard_resolved(&mut self, host: &str, answer: Result<Vec<IpAddr>, String>, now_ms: u64) {
        let at_unix = self.now().unwrap_or(0);
        let Some(rt) = self.ext_mut::<WgRuntime>() else {
            return;
        };
        let old = rt.resolved.get(host).and_then(|r| r.ip);
        let (ip, error) = match answer {
            Ok(ips) => (ips.first().copied().or(old), ips.is_empty().then(|| "no address".to_owned())),
            Err(e) => (old, Some(e)),
        };
        if let Some(e) = &error
            && rt.resolved.get(host).is_none_or(|r| r.error.as_ref() != Some(e))
        {
            log::warn!("wireguard: endpoint {host}: {e}");
        }
        rt.resolved.insert(host.to_owned(), Resolved { ip, at_ms: now_ms, at_unix, error });
        if ip != old {
            self.wireguard_push(now_ms, false);
        }
    }

    /// Peers the router tries and that have not answered for
    /// [`NO_HANDSHAKE_ALERT_SECS`] or more: (peer, interface, seconds, had
    /// a handshake once). Only `no-handshake` peers (an endpoint and a
    /// keepalive, or traffic to send): one that waits or idles is fine.
    pub(crate) fn wireguard_stale(&mut self) -> Vec<(String, String, u64, bool)> {
        let running = self.store().running().clone();
        let now = self.now().unwrap_or(0);
        let mut out = Vec::new();
        let mut trying: BTreeMap<String, u64> = BTreeMap::new();
        let before = self.ext::<WgRuntime>().map(|rt| rt.trying_since.clone()).unwrap_or_default();
        for (iface, off, w) in interfaces(&running) {
            if off || w.peers.is_empty() {
                continue;
            }
            let status = self.wireguard_status(iface).0;
            if status.is_none() {
                continue;
            }
            let by_key = status_by_key(status.as_ref());
            for p in &w.peers {
                let (state, age, _) = peer_view(p, false, &by_key, now);
                if state != PeerState::NoHandshake {
                    continue;
                }
                let secs = match age {
                    Some(a) => a,
                    None => {
                        let since = before.get(&p.name).copied().unwrap_or(now);
                        trying.insert(p.name.clone(), since);
                        now.saturating_sub(since)
                    }
                };
                if secs >= NO_HANDSHAKE_ALERT_SECS {
                    out.push((p.name.clone(), iface.to_string(), secs, age.is_some()));
                }
            }
        }
        if let Some(rt) = self.ext_mut::<WgRuntime>() {
            rt.trying_since = trying;
        }
        out
    }

    /// What the data plane says about `name` (`None`: not running, or the
    /// backend cannot say; the reason in the second field).
    pub(crate) fn wireguard_status(&mut self, name: &IfName) -> (Option<WgStatus>, Option<String>) {
        let now = self.now().unwrap_or(0);
        let pushed_error = self
            .ext::<WgRuntime>()
            .and_then(|rt| rt.error(name).map(str::to_owned));
        match self.hal_mut().wireguard_status(name, now) {
            Ok(s) => (Some(s), pushed_error),
            Err(e) => (None, pushed_error.or_else(|| Some(e.to_string()))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 7748 §6.1: Alice's private and public keys.
    #[test]
    fn public_key_matches_rfc_7748() {
        let hex = |s: &str| -> Key {
            let v: Vec<u8> = (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect();
            v.try_into().unwrap()
        };
        let a = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let a_pub = hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        assert_eq!(public_of(&a), a_pub);
        // Clamping does not change the public key (the scalar is clamped
        // by the function anyway).
        assert_eq!(public_of(&clamp(a)), a_pub);
    }

    #[test]
    fn keys_round_trip_and_generated_ones_are_clamped() {
        let k = generate_private().unwrap();
        assert_eq!(k[0] & 7, 0);
        assert_eq!(k[31] & 0xC0, 0x40);
        let text = encode(&k);
        assert_eq!(text.len(), 44);
        assert_eq!(decode(&text), Some(k));
        assert_eq!(parse_private(&text), Some(k));
        assert_ne!(generate_private().unwrap(), k);
        assert_eq!(decode("not a key"), None);
    }

    #[test]
    fn lab_keys_differ() {
        let mut a = [0; 32];
        let mut b = [0; 32];
        lab_fill(&mut a);
        lab_fill(&mut b);
        assert_ne!(a, b);
    }
}
