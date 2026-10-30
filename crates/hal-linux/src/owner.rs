//! Who owns each kernel link: CoreRouter, or someone else (G1.18).
//!
//! Pure, like `plan.rs`: the netlink dump (`netlink::links`) fills
//! [`KernelLink`]s and [`classify`] decides, so the policy is unit-tested on
//! every platform. A link CoreRouter does not manage is still listed (with
//! its kind and the reason), but `apply` never touches it and the engine
//! refuses commands that would change it.
//!
//! The rule, first match wins:
//! 1. a name the model cannot hold (`IfName`) — external;
//! 2. the kernel loopback (`ARPHRD_LOOPBACK`, `lo`) — the OS's: managed
//!    only when the config has it as a loopback named `lo` (G3.4i,
//!    `os_loopback`), and then only for its addresses (`plan` never
//!    creates, deletes, resizes nor takes it down); external otherwise;
//! 3. a name in `--unmanaged` — external;
//! 4. a link enslaved to an external master (a veth in `docker0`) — external;
//! 5. a name the config claims: managed when the kernel kind fits the claim
//!    (`vlan`/`bridge`/`dummy`/`vrf` for what CoreRouter creates; physical,
//!    `veth` or `dummy` for an `ether` port). A misfit `ether` claim (a
//!    stale seed that took `docker0`) is external; a misfit virtual one is a
//!    *conflict*: listed as unmanaged, and `apply` lets the executor refuse
//!    it with its message (and roll back);
//! 6. a physical port (no `IFLA_INFO_KIND`, `ARPHRD_ETHER`) — managed;
//! 7. a `veth` whose peer is in this same namespace (a cable inside this
//!    router) — managed; with the peer in another namespace (a container's)
//!    — external, unless listed in `--manage`;
//! 8. a `veth`/`dummy` listed in `--manage` — managed;
//! 9. anything else (`bridge`, `vlan`, `ppp`, `tun`, `wireguard`, …) —
//!    external: another program made it.
//!
//! A port also needs an MTU the model can hold (68..=9216); otherwise it is
//! external, so the seed never has to change it.

use std::collections::BTreeMap;

use corerouter_model::os_loopback;
use corerouter_model::{IfName, InterfaceKind};

pub const ARPHRD_ETHER: u16 = 1;
pub const ARPHRD_PPP: u16 = 512;
pub const ARPHRD_LOOPBACK: u16 = 772;

/// Bounds of a `--manage` / `--unmanaged` list (hostile input).
const MAX_PATTERNS: usize = 64;

/// One link as the kernel describes it (`RTM_GETLINK`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KernelLink {
    pub index: u32,
    pub name: String,
    /// `IFLA_INFO_KIND`; `None` for physical NICs (and `lo`).
    pub kind: Option<String>,
    /// `ARPHRD_*` link-layer type.
    pub arphrd: u16,
    /// `IFLA_MASTER` (bridge, VRF, bond).
    pub master: Option<u32>,
    /// `IFLA_LINK_NETNSID` present: the peer (veth) or lower link lives in
    /// another network namespace.
    pub peer_elsewhere: bool,
    pub mtu: u32,
    /// Administratively up (`IFF_UP`).
    pub up: bool,
    /// Operationally up (`IFLA_OPERSTATE` up, or unknown with carrier).
    pub running: bool,
    pub mac: Option<String>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    /// `IFLA_STATS64` error/drop counters (none without the attribute).
    pub errors: Option<corerouter_hal::LinkErrors>,
    /// `IFLA_PARENT_DEV_BUS_NAME`: `pci`, `usb`, `virtio` (G1.29b).
    pub bus: Option<String>,
}

impl KernelLink {
    /// What the link is, in `interface.list` words.
    pub fn label(&self) -> String {
        if self.arphrd == ARPHRD_LOOPBACK {
            return "loopback".into();
        }
        match (&self.kind, self.arphrd) {
            (Some(k), _) => k.clone(),
            (None, ARPHRD_ETHER) => "ether".into(),
            (None, ARPHRD_PPP) => "ppp".into(),
            (None, other) => format!("link type {other}"),
        }
    }

    fn physical(&self) -> bool {
        self.kind.is_none() && self.arphrd == ARPHRD_ETHER
    }

    fn is(&self, kind: &str) -> bool {
        self.kind.as_deref() == Some(kind)
    }

    /// Something an `ether` port of the config may be.
    fn port_like(&self) -> bool {
        self.physical() || self.is("veth") || self.is("dummy")
    }
}

/// Names the operator sets aside or adds (`corerouter-daemon --manage` /
/// `--unmanaged`). A pattern is a name, or a prefix ending in `*`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Policy {
    pub manage: Vec<String>,
    pub unmanaged: Vec<String>,
}

impl Policy {
    /// Parse a comma-separated pattern list (`eth0,lab*`).
    pub fn patterns(list: &str) -> Result<Vec<String>, String> {
        let out: Vec<String> = list
            .split(',')
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .map(str::to_owned)
            .collect();
        if out.len() > MAX_PATTERNS {
            return Err(format!("at most {MAX_PATTERNS} interface patterns"));
        }
        for p in &out {
            let stem = p.strip_suffix('*').unwrap_or(p);
            let ok = stem.len() <= 15
                && !stem.contains('*')
                && stem
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
            if !ok {
                let shown: String = p.chars().take(32).collect();
                return Err(format!(
                    "'{shown}' is not an interface name or prefix* (ASCII letters, digits, \
                     '-', '_', '.'; at most 15)"
                ));
            }
        }
        Ok(out)
    }

    fn hit(list: &[String], name: &str) -> bool {
        list.iter().any(|p| match p.strip_suffix('*') {
            Some(prefix) => name.starts_with(prefix),
            None => p == name,
        })
    }
}

/// The verdict on one link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Owner {
    Managed,
    /// Not CoreRouter's: listed, never applied to.
    External(String),
    /// The config claims the name for another kind of link. Listed as
    /// unmanaged; `apply` leaves the refusal to the executor, which names
    /// both kinds (and rolls back).
    Conflict(String),
}

impl Owner {
    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Managed => None,
            Self::External(r) | Self::Conflict(r) => Some(r),
        }
    }
}

fn claim_fits(claim: &InterfaceKind, link: &KernelLink) -> bool {
    match claim {
        InterfaceKind::Ethernet => link.port_like(),
        InterfaceKind::Vlan { .. } => link.is("vlan"),
        InterfaceKind::Bridge => link.is("bridge"),
        InterfaceKind::Loopback => link.is("dummy"),
        InterfaceKind::Vrf { .. } => link.is("vrf"),
        InterfaceKind::Bonding { .. } => link.is("bond"),
        // The session's netdev is one end of a veth pair (G3.9ga).
        InterfaceKind::PppoeClient(_) => link.is("veth"),
    }
}

/// Rules 1–3 and 5–9 (rule 4 needs the masters' verdicts: [`classify`]).
fn base(link: &KernelLink, claim: Option<&InterfaceKind>, policy: &Policy) -> Owner {
    let ext = |r: String| Owner::External(r);
    if link.name.parse::<IfName>().is_err() {
        return ext("its name is not a valid CoreRouter interface name".into());
    }
    if link.arphrd == ARPHRD_LOOPBACK {
        if link.name == os_loopback::NAME && claim == Some(&InterfaceKind::Loopback) {
            return Owner::Managed;
        }
        return ext(format!(
            "the kernel loopback, kept by the OS (add a loopback named '{}' to put addresses on it)",
            os_loopback::NAME
        ));
    }
    if Policy::hit(&policy.unmanaged, &link.name) {
        return ext("listed in --unmanaged".into());
    }
    let label = link.label();
    if let Some(claim) = claim {
        let why = format!(
            "the configuration has it as {} but the kernel as {label}",
            claim.label()
        );
        return match claim {
            _ if claim_fits(claim, link) => Owner::Managed,
            // A port is never created, so nothing would refuse the ops on
            // it: they are dropped (a stale seed that took `docker0`).
            InterfaceKind::Ethernet => ext(format!("{why} (created outside CoreRouter)")),
            _ => Owner::Conflict(why),
        };
    }
    if !(68..=9216).contains(&link.mtu) {
        return ext(format!("its MTU {} is outside 68..=9216", link.mtu));
    }
    if link.physical() {
        return Owner::Managed;
    }
    let listed = Policy::hit(&policy.manage, &link.name);
    if link.is("veth") {
        return if !link.peer_elsewhere || listed {
            Owner::Managed
        } else {
            ext("a veth whose peer is in another network namespace (a container's)".into())
        };
    }
    if listed && link.is("dummy") {
        return Owner::Managed;
    }
    ext(format!("a {label} created outside CoreRouter"))
}

/// Verdict per link name. `claims` is what the config says each name is
/// (empty before the first apply: the seed then takes only what rules 6–8
/// allow).
pub fn classify(
    links: &[KernelLink],
    claims: &BTreeMap<IfName, InterfaceKind>,
    policy: &Policy,
) -> BTreeMap<u32, Owner> {
    let claim = |l: &KernelLink| {
        l.name
            .parse::<IfName>()
            .ok()
            .and_then(|n| claims.get(&n).cloned())
    };
    // The hidden ends of the PPPoE clients' veth pairs (G3.9ga) are
    // CoreRouter's, but no interface of the config: never seeded as ports.
    let relay_ends: BTreeMap<String, &IfName> = claims
        .iter()
        .filter(|(_, k)| matches!(k, InterfaceKind::PppoeClient(_)))
        .map(|(n, _)| (corerouter_model::pppoe_client::relay_peer(n.as_str()), n))
        .collect();
    let mut out: BTreeMap<u32, Owner> = links
        .iter()
        .map(|l| match relay_ends.get(&l.name) {
            Some(client) if l.is("veth") => (
                l.index,
                Owner::External(format!("the relay end of PPPoE client '{client}'")),
            ),
            _ => (l.index, base(l, claim(l).as_ref(), policy)),
        })
        .collect();
    let names: BTreeMap<u32, &str> = links.iter().map(|l| (l.index, l.name.as_str())).collect();
    // Rule 4, to a fixed point (a bridge in an external VRF…). Each pass
    // turns at least one link external or stops.
    for _ in 0..=links.len() {
        let more: Vec<(u32, Owner)> = links
            .iter()
            .filter(|l| out.get(&l.index) == Some(&Owner::Managed))
            .filter_map(|l| {
                let m = l.master?;
                matches!(out.get(&m), Some(Owner::External(_))).then(|| {
                    let master = names.get(&m).copied().unwrap_or("?");
                    (
                        l.index,
                        Owner::External(format!(
                            "a port of '{master}', which CoreRouter does not manage"
                        )),
                    )
                })
            })
            .collect();
        if more.is_empty() {
            break;
        }
        out.extend(more);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_model::VlanId;

    fn link(index: u32, name: &str, kind: Option<&str>) -> KernelLink {
        KernelLink {
            index,
            name: name.into(),
            kind: kind.map(str::to_owned),
            arphrd: ARPHRD_ETHER,
            mtu: 1500,
            ..KernelLink::default()
        }
    }

    fn n(s: &str) -> IfName {
        s.parse().unwrap()
    }

    fn verdicts(
        links: &[KernelLink],
        claims: &[(&str, InterfaceKind)],
        policy: &Policy,
    ) -> BTreeMap<String, Owner> {
        let claims = claims.iter().map(|(k, v)| (n(k), v.clone())).collect();
        let by = classify(links, &claims, policy);
        links
            .iter()
            .map(|l| (l.name.clone(), by.get(&l.index).cloned().unwrap()))
            .collect()
    }

    fn managed(v: &BTreeMap<String, Owner>, name: &str) -> bool {
        v.get(name) == Some(&Owner::Managed)
    }

    fn reason<'a>(v: &'a BTreeMap<String, Owner>, name: &str) -> &'a str {
        v.get(name).and_then(Owner::reason).unwrap_or("")
    }

    #[test]
    fn labels_follow_the_kernel_kind() {
        let mut lo = link(1, "lo", None);
        lo.arphrd = ARPHRD_LOOPBACK;
        assert_eq!(lo.label(), "loopback");
        assert_eq!(link(2, "eno1", None).label(), "ether");
        let mut ppp = link(3, "ppp0", None);
        ppp.arphrd = ARPHRD_PPP;
        assert_eq!(ppp.label(), "ppp");
        for k in ["veth", "bridge", "vlan", "dummy", "tun", "wireguard", "vrf"] {
            assert_eq!(link(4, "x", Some(k)).label(), k);
        }
        let mut odd = link(5, "x", None);
        odd.arphrd = 65534;
        assert_eq!(odd.label(), "link type 65534");
    }

    #[test]
    fn a_typical_docker_host() {
        let mut lo = link(1, "lo", None);
        lo.arphrd = ARPHRD_LOOPBACK;
        lo.mtu = 65536;
        let mut ppp = link(5, "ppp0", Some("ppp"));
        ppp.arphrd = ARPHRD_PPP;
        let mut cveth = link(6, "veth1a2b3c", Some("veth"));
        cveth.peer_elsewhere = true;
        cveth.master = Some(3);
        let links = [
            lo,
            link(2, "eno1", None),
            link(3, "docker0", Some("bridge")),
            link(4, "br-0123456789ab", Some("bridge")),
            ppp,
            cveth,
            link(7, "virbr0", Some("bridge")),
            link(8, "tun0", Some("tun")),
            link(9, "wg0", Some("wireguard")),
            link(10, "eth0", Some("veth")),
            link(11, "eth1", Some("veth")),
        ];
        let v = verdicts(&links, &[], &Policy::default());
        let ours: Vec<&str> = v
            .iter()
            .filter(|(_, o)| **o == Owner::Managed)
            .map(|(k, _)| k.as_str())
            .collect();
        assert_eq!(ours, ["eno1", "eth0", "eth1"]);
        assert!(reason(&v, "lo").contains("loopback"));
        assert!(reason(&v, "docker0").contains("bridge created outside"));
        assert!(reason(&v, "ppp0").contains("ppp created outside"));
        assert!(reason(&v, "wg0").contains("wireguard"));
        // Rule 7 decides before rule 4 gets a say; either way it is not ours.
        assert!(reason(&v, "veth1a2b3c").contains("another network namespace"));
    }

    #[test]
    fn ports_of_an_external_bridge_are_external() {
        let mut v1 = link(2, "lab1", Some("veth"));
        v1.master = Some(1);
        let mut dummy = link(3, "d0", Some("dummy"));
        dummy.master = Some(1);
        let links = [link(1, "docker0", Some("bridge")), v1, dummy];
        let policy = Policy {
            manage: vec!["lab*".into(), "d0".into()],
            unmanaged: vec![],
        };
        let v = verdicts(&links, &[("lab1", InterfaceKind::Ethernet)], &policy);
        assert!(reason(&v, "lab1").contains("port of 'docker0'"));
        assert!(reason(&v, "d0").contains("port of 'docker0'"));
    }

    #[test]
    fn what_corerouter_created_is_managed_and_conflicts_are_flagged() {
        let mut v10 = link(3, "vlan10", Some("vlan"));
        v10.master = Some(2);
        let links = [
            link(1, "ether1", None),
            link(2, "br1", Some("bridge")),
            v10,
            link(4, "lo1", Some("dummy")),
            link(5, "vrf1", Some("vrf")),
            link(6, "br2", Some("dummy")),
            link(7, "docker0", Some("bridge")),
        ];
        let claims = [
            ("ether1", InterfaceKind::Ethernet),
            ("br1", InterfaceKind::Bridge),
            (
                "vlan10",
                InterfaceKind::Vlan {
                    parent: n("ether1"),
                    vlan_id: VlanId::new(10).unwrap(),
                    service_tag: false,
                },
            ),
            ("lo1", InterfaceKind::Loopback),
            ("vrf1", InterfaceKind::Vrf { table: 1000 }),
            ("br2", InterfaceKind::Bridge),
            // A stale seed from before G1.18 took the host's bridges as ports.
            ("docker0", InterfaceKind::Ethernet),
        ];
        let v = verdicts(&links, &claims, &Policy::default());
        for name in ["ether1", "br1", "vlan10", "lo1", "vrf1"] {
            assert!(managed(&v, name), "{name}: {:?}", v.get(name));
        }
        assert_eq!(
            v.get("br2"),
            Some(&Owner::Conflict(
                "the configuration has it as bridge but the kernel as dummy".into()
            ))
        );
        assert!(matches!(v.get("docker0"), Some(Owner::External(_))));
        assert!(reason(&v, "docker0").contains("as ether but the kernel as bridge"));
    }

    #[test]
    fn unclaimed_virtual_links_are_external_until_listed() {
        let mut far = link(3, "lab9", Some("veth"));
        far.peer_elsewhere = true;
        let links = [
            link(1, "dum0", Some("dummy")),
            link(2, "vl5", Some("vlan")),
            far,
        ];
        let v = verdicts(&links, &[], &Policy::default());
        assert!(v.values().all(|o| matches!(o, Owner::External(_))), "{v:?}");
        let listed = Policy {
            manage: Policy::patterns("dum0, lab*,vl5").unwrap(),
            unmanaged: vec![],
        };
        let v = verdicts(&links, &[], &listed);
        assert!(managed(&v, "dum0"));
        assert!(managed(&v, "lab9"));
        // --manage only adopts port-like links; a vlan stays someone else's.
        assert!(!managed(&v, "vl5"));
    }

    #[test]
    fn unmanaged_list_and_odd_links_win_over_everything() {
        let mut lo = link(1, "lo", None);
        lo.arphrd = ARPHRD_LOOPBACK;
        let mut jumbo = link(4, "eno2", None);
        jumbo.mtu = 9600;
        let links = [
            lo,
            link(2, "eno1", None),
            link(3, "wlp1s0", None),
            jumbo,
            link(5, "bad:name", None),
        ];
        let policy = Policy {
            manage: vec!["lo".into()],
            unmanaged: Policy::patterns("wl*").unwrap(),
        };
        let claims = [
            ("lo", InterfaceKind::Ethernet),
            ("wlp1s0", InterfaceKind::Ethernet),
        ];
        let v = verdicts(&links, &claims, &policy);
        assert!(managed(&v, "eno1"));
        assert!(reason(&v, "lo").contains("loopback"));
        assert_eq!(reason(&v, "wlp1s0"), "listed in --unmanaged");
        assert!(reason(&v, "eno2").contains("MTU 9600"));
        assert!(reason(&v, "bad:name").contains("not a valid"));
    }

    #[test]
    fn patterns_are_bounded_and_validated() {
        assert_eq!(
            Policy::patterns("eth0, ,lab*").unwrap(),
            ["eth0".to_owned(), "lab*".to_owned()]
        );
        for bad in ["a*b", "e th", "x/y", "0123456789abcdef", "**"] {
            assert!(Policy::patterns(bad).is_err(), "{bad}");
        }
        let many = vec!["e"; MAX_PATTERNS + 1].join(",");
        assert!(Policy::patterns(&many).is_err());
    }

    /// G3.4i: the kernel's `lo` is managed when the config has a loopback
    /// named `lo` (its addresses only), and never under another claim.
    #[test]
    fn the_kernel_lo_is_managed_as_a_loopback_named_lo() {
        let mut lo = link(1, "lo", None);
        lo.arphrd = ARPHRD_LOOPBACK;
        lo.mtu = 65536;
        let links = [lo];
        let v = verdicts(
            &links,
            &[("lo", InterfaceKind::Loopback)],
            &Policy::default(),
        );
        assert!(managed(&v, "lo"));
        for kind in [InterfaceKind::Ethernet, InterfaceKind::Bridge] {
            let v = verdicts(&links, &[("lo", kind)], &Policy::default());
            assert!(reason(&v, "lo").contains("kernel loopback"));
        }
        let v = verdicts(&links, &[], &Policy::default());
        assert!(reason(&v, "lo").contains("add a loopback named 'lo'"));
    }

    /// G3.9ga: the client's netdev is ours; the relay end of its veth is
    /// CoreRouter's too, but never seeded as a port of its own.
    #[test]
    fn pppoe_client_veth_and_its_relay_end() {
        let client = corerouter_model::pppoe_client::PppoeClient::new(n("ether1"), "u".into());
        let links = [
            link(2, "ether1", None),
            link(3, "pppoe-out1", Some("veth")),
            link(4, "pppoe-out1-r", Some("veth")),
        ];
        let claims = [
            ("ether1", InterfaceKind::Ethernet),
            ("pppoe-out1", InterfaceKind::PppoeClient(Box::new(client))),
        ];
        let v = verdicts(&links, &claims, &Policy::default());
        assert!(managed(&v, "pppoe-out1"));
        assert!(reason(&v, "pppoe-out1-r").contains("relay end of PPPoE client 'pppoe-out1'"));
        // Without the claim (before the first apply) it is a plain veth.
        let v = verdicts(&links, &[], &Policy::default());
        assert!(managed(&v, "pppoe-out1-r"));
    }
}
