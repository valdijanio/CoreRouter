//! The DHCP relay agent (G4.2b, `/ip dhcp-relay`), pure: what the router
//! does to a client's request on the way to the servers and to a server's
//! reply on the way back.
//!
//! - Up (RFC 1542 §4.1.1, RFC 2131 §4.1): `giaddr` set to the relay's
//!   address when zero (left alone when another agent already set it),
//!   `hops` + 1, dropped past [`MAX_HOPS`]; option 82 added (RFC 3046
//!   §2.1) with the circuit id and the remote id, last, when asked and when
//!   it fits (§2.1: without room the request goes without it). A request
//!   that already carries option 82 with `giaddr` 0 came from the client
//!   side: dropped (§2.1: an untrusted circuit; a client could claim
//!   another subscriber's circuit id), or relayed untouched when the relay
//!   trusts a layer-2 agent there (`relay_info_trusted`; a relay does not
//!   add a second one).
//! - Down (RFC 1542 §4.1.2, RFC 3046 §2.2): only replies whose `giaddr` is
//!   this relay's; option 82 removed before the client sees it; to the
//!   client by broadcast when it asked (or for a NAK), else by unicast to
//!   `yiaddr`/`chaddr`.

use std::net::Ipv4Addr;

use corerouter_hal::dhcp_server::ReplyTo;
pub use corerouter_model::dhcp_relay::MAX_HOPS;
use corerouter_model::{Config, IfName};

use crate::server::agent;
use crate::server::request::{BOOTREPLY, BOOTREQUEST, Kind};

const OPTIONS_AT: usize = 240;
const MAGIC: [u8; 4] = [99, 130, 83, 99];
/// A relayed request may grow to this (the minimum every client and
/// server must take, RFC 2131 §2; larger messages are already larger).
const ROOM: usize = 576;

/// One enabled relay, compiled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayPlan {
    pub name: String,
    pub interface: IfName,
    pub servers: Vec<Ipv4Addr>,
    /// `giaddr`.
    pub giaddr: Ipv4Addr,
    pub add_info: bool,
    /// Custom remote id (empty: the client's MAC).
    pub remote_id: Vec<u8>,
    /// Option 82 from the client side (`giaddr` 0) is relayed, not dropped.
    pub trusted: bool,
}

/// Why a message was not relayed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RelayDrop {
    Malformed,
    /// More than [`MAX_HOPS`] agents.
    Hops,
    /// A reply for another relay (its `giaddr` is not ours).
    NotOurs,
    /// A client's request that already carried option 82 (RFC 3046 §2.1:
    /// from an untrusted circuit).
    Untrusted82,
    /// A reply from an address that is not one of the relay's servers.
    NotFromServer,
}

impl RelayDrop {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::Hops => "hops",
            Self::NotOurs => "not-ours",
            Self::Untrusted82 => "untrusted-82",
            Self::NotFromServer => "not-from-server",
        }
    }
}

/// The enabled relays of `cfg`, with their `giaddr` (the configured one,
/// else the interface's first IPv4 address; a relay without either is
/// left out: it cannot work).
pub fn plans(cfg: &Config) -> Vec<RelayPlan> {
    let mine = crate::server::checks::router_addresses(cfg);
    cfg.ip
        .dhcp_relays
        .relays
        .iter()
        .filter(|r| !r.disabled && !r.dhcp_server.is_empty())
        .filter_map(|r| {
            let giaddr = r.local_address.or_else(|| {
                mine.iter()
                    .find(|(_, i)| **i == r.interface)
                    .map(|(n, _)| n.addr())
            })?;
            Some(RelayPlan {
                name: r.name.clone(),
                interface: r.interface.clone(),
                servers: r.dhcp_server.clone(),
                giaddr,
                add_info: r.add_relay_info,
                remote_id: r.relay_info_remote_id.as_bytes().to_vec(),
                trusted: r.relay_info_trusted,
            })
        })
        .collect()
}

/// The options of a message as (code, bytes) in order, pads dropped; and
/// where the fixed part ends. `None` without a cookie or past the limit.
fn options(bytes: &[u8]) -> Option<Vec<(u8, Vec<u8>)>> {
    if bytes.len() > crate::v4::MAX_MESSAGE || bytes.get(236..OPTIONS_AT) != Some(&MAGIC[..]) {
        return None;
    }
    let mut out = Vec::new();
    let mut rest = bytes.get(OPTIONS_AT..).unwrap_or(&[]);
    while let Some((&code, tail)) = rest.split_first() {
        match code {
            0 => rest = tail,
            255 => break,
            _ => {
                let (&len, tail) = tail.split_first()?;
                let data = tail.get(..usize::from(len))?;
                out.push((code, data.to_vec()));
                rest = tail.get(usize::from(len)..).unwrap_or(&[]);
            }
        }
    }
    Some(out)
}

/// `bytes` with its options rewritten: the fixed part, `opts`, the end.
fn rebuild(bytes: &[u8], opts: &[(u8, Vec<u8>)]) -> Option<Vec<u8>> {
    let mut out = bytes.get(..OPTIONS_AT)?.to_vec();
    for (code, data) in opts {
        out.push(*code);
        out.push(u8::try_from(data.len()).ok()?);
        out.extend_from_slice(data);
    }
    out.push(255);
    Some(out)
}

/// A client's request heard on the relay's interface, from Ethernet
/// source `src_mac`: the message to send to every server.
pub fn up(plan: &RelayPlan, payload: &[u8], src_mac: [u8; 6]) -> Result<Vec<u8>, RelayDrop> {
    if payload.first() != Some(&BOOTREQUEST) || payload.len() < OPTIONS_AT {
        return Err(RelayDrop::Malformed);
    }
    let mut opts = options(payload).ok_or(RelayDrop::Malformed)?;
    let hops = payload.get(3).copied().unwrap_or(0);
    if hops >= MAX_HOPS {
        return Err(RelayDrop::Hops);
    }
    let giaddr_was_zero = payload.get(24..28) == Some(&[0, 0, 0, 0][..]);
    let mut out = payload.to_vec();
    if let Some(h) = out.get_mut(3) {
        *h = hops + 1;
    }
    if giaddr_was_zero && let Some(g) = out.get_mut(24..28) {
        g.copy_from_slice(&plan.giaddr.octets());
    }
    let has_82 = opts.iter().any(|(c, _)| *c == 82);
    if giaddr_was_zero && has_82 && !plan.trusted {
        return Err(RelayDrop::Untrusted82);
    }
    if plan.add_info && giaddr_was_zero && !has_82 {
        let mac: Vec<u8> = src_mac.to_vec();
        let remote = if plan.remote_id.is_empty() {
            &mac
        } else {
            &plan.remote_id
        };
        if let Some(info) = agent::build(plan.interface.as_str().as_bytes(), remote) {
            let size: usize = OPTIONS_AT + opts.iter().map(|(_, d)| d.len() + 2).sum::<usize>() + 1;
            // §2.1: no room, no option 82 (the request still goes).
            if size + info.len() + 2 <= ROOM.max(payload.len()) {
                opts.push((82, info));
            }
        }
    }
    let out_fixed = rebuild(&out, &opts).ok_or(RelayDrop::Malformed)?;
    Ok(out_fixed)
}

/// A server's reply: for this relay's client, with option 82 removed, and
/// where it goes on the relay's interface.
pub fn down(plan: &RelayPlan, payload: &[u8]) -> Result<(Vec<u8>, ReplyTo, Kind), RelayDrop> {
    if payload.first() != Some(&BOOTREPLY) || payload.len() < OPTIONS_AT {
        return Err(RelayDrop::Malformed);
    }
    if payload.get(24..28) != Some(&plan.giaddr.octets()[..]) {
        return Err(RelayDrop::NotOurs);
    }
    let opts = options(payload).ok_or(RelayDrop::Malformed)?;
    let kind = opts
        .iter()
        .find(|(c, _)| *c == 53)
        .and_then(|(_, d)| d.first())
        .and_then(|t| Kind::from_code(*t))
        .ok_or(RelayDrop::Malformed)?;
    let kept: Vec<(u8, Vec<u8>)> = opts.into_iter().filter(|(c, _)| *c != 82).collect();
    let out = rebuild(payload, &kept).ok_or(RelayDrop::Malformed)?;
    let ip = |at: usize| match payload.get(at..at + 4) {
        Some([a, b, c, d]) => Ipv4Addr::new(*a, *b, *c, *d),
        _ => Ipv4Addr::UNSPECIFIED,
    };
    let broadcast = payload.get(10).is_some_and(|f| f & 0x80 != 0);
    let (htype, hlen) = (payload.get(1).copied(), payload.get(2).copied());
    let mut mac = [0u8; 6];
    if let Some(c) = payload.get(28..34) {
        mac.copy_from_slice(c);
    }
    let to = if kind == Kind::Nak || broadcast || htype != Some(1) || hlen != Some(6) {
        ReplyTo::Broadcast
    } else if !ip(12).is_unspecified() {
        ReplyTo::Unicast(ip(12))
    } else {
        ReplyTo::Client { ip: ip(16), mac }
    };
    Ok((out, to, kind))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v4::Outgoing;
    use dhcproto::v4::MessageType;
    use proptest::prelude::*;

    fn plan(add_info: bool) -> RelayPlan {
        RelayPlan {
            name: "relay1".into(),
            interface: "vlan20".parse().unwrap(),
            servers: vec!["10.99.0.2".parse().unwrap()],
            giaddr: "10.88.0.1".parse().unwrap(),
            add_info,
            remote_id: Vec::new(),
            trusted: false,
        }
    }

    fn discover() -> Vec<u8> {
        Outgoing {
            kind: MessageType::Discover,
            xid: 1,
            secs: 0,
            mac: [2, 0, 0, 0, 0, 7],
            ciaddr: Ipv4Addr::UNSPECIFIED,
            broadcast: false,
            requested: None,
            server_id: None,
            client_id: &[],
            host_name: None,
            vendor_class: None,
            extra: &[],
        }
        .encode()
        .unwrap()
    }

    #[test]
    fn up_sets_giaddr_hops_and_option_82() {
        let out = up(&plan(true), &discover(), [2, 0, 0, 0, 0, 7]).unwrap();
        assert_eq!(&out[24..28], &[10, 88, 0, 1]);
        assert_eq!(out[3], 1);
        let req = crate::server::request::parse(&out).unwrap();
        let info = req.relay_info.unwrap();
        assert_eq!(agent::get(&info, agent::CIRCUIT_ID).unwrap(), b"vlan20");
        assert_eq!(
            agent::get(&info, agent::REMOTE_ID).unwrap(),
            [2, 0, 0, 0, 0, 7]
        );
        // Last option before the end (RFC 3046 §2.1).
        let opts = options(&out).unwrap();
        assert_eq!(opts.last().unwrap().0, 82);
        // Without add_relay_info: none.
        let plain = up(&plan(false), &discover(), [0; 6]).unwrap();
        assert!(
            crate::server::request::parse(&plain)
                .unwrap()
                .relay_info
                .is_none()
        );
    }

    #[test]
    fn another_agents_giaddr_and_hops() {
        let mut m = discover();
        m[24..28].copy_from_slice(&[10, 1, 1, 1]);
        let out = up(&plan(true), &m, [0; 6]).unwrap();
        assert_eq!(&out[24..28], &[10, 1, 1, 1], "left alone");
        assert!(
            crate::server::request::parse(&out)
                .unwrap()
                .relay_info
                .is_none(),
            "not ours to add"
        );
        m[3] = MAX_HOPS;
        assert_eq!(up(&plan(true), &m, [0; 6]), Err(RelayDrop::Hops));
    }

    #[test]
    fn down_strips_option_82_and_picks_the_destination() {
        let req = up(&plan(true), &discover(), [2, 0, 0, 0, 0, 7]).unwrap();
        // A server's OFFER: our own server answering the relayed request.
        let reply = {
            let r = crate::server::request::parse(&req).unwrap();
            let head = crate::server::reply::Head {
                kind: Kind::Offer,
                ciaddr: Ipv4Addr::UNSPECIFIED,
                yiaddr: "10.88.0.10".parse().unwrap(),
                siaddr: Ipv4Addr::UNSPECIFIED,
                file: None,
            };
            crate::server::reply::encode(
                &r,
                &head,
                &[
                    (54, vec![10, 99, 0, 2]),
                    (82, r.relay_info.clone().unwrap()),
                ],
            )
            .unwrap()
        };
        let (out, to, kind) = down(&plan(true), &reply).unwrap();
        assert_eq!(kind, Kind::Offer);
        assert_eq!(
            to,
            ReplyTo::Client {
                ip: "10.88.0.10".parse().unwrap(),
                mac: [2, 0, 0, 0, 0, 7]
            }
        );
        assert!(
            !options(&out).unwrap().iter().any(|(c, _)| *c == 82),
            "RFC 3046 §2.2"
        );
        let mut other = plan(true);
        other.giaddr = "10.88.1.1".parse().unwrap();
        assert_eq!(down(&other, &reply), Err(RelayDrop::NotOurs));
    }

    /// RFC 3046 §2.1: a client's own option 82 (giaddr 0) is dropped on an
    /// untrusted circuit, relayed untouched on a trusted one.
    #[test]
    fn a_clients_option_82_is_not_relayed() {
        let mut m = discover();
        assert_eq!(m.pop(), Some(255));
        m.extend_from_slice(&[82, 6, 1, 4, b'o', b'l', b't', b'1', 255]);
        assert_eq!(
            up(&plan(true), &m, [2, 0, 0, 0, 0, 7]),
            Err(RelayDrop::Untrusted82)
        );
        assert_eq!(
            up(&plan(false), &m, [2, 0, 0, 0, 0, 7]),
            Err(RelayDrop::Untrusted82)
        );
        let mut trusted = plan(true);
        trusted.trusted = true;
        let out = up(&trusted, &m, [2, 0, 0, 0, 0, 7]).unwrap();
        let info = crate::server::request::parse(&out)
            .unwrap()
            .relay_info
            .unwrap();
        assert_eq!(agent::get(&info, agent::CIRCUIT_ID).unwrap(), b"olt1");
    }

    proptest! {
        #[test]
        fn hostile_messages_never_panic(tail in proptest::collection::vec(any::<u8>(), 0..400), op in 0u8..3) {
            let mut m = discover();
            m.truncate(240);
            m[0] = op;
            m.extend_from_slice(&tail);
            let _ = up(&plan(true), &m, [0; 6]);
            let _ = down(&plan(true), &m);
            let _ = up(&plan(true), &tail, [0; 6]);
        }
    }
}
