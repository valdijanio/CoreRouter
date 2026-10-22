//! /interface bonding (G1.8) — link aggregation: 802.3ad (LACP),
//! active-backup and the other Linux bonding modes. A bond is an interface
//! (type `bonding`); its slaves are ethernet ports that carry nothing of
//! their own (no address, VLAN, bridge, VRF or DHCP client). `interface.remove`
//! deletes a bond and releases its slaves.

use corerouter_model::bonding::DEFAULT_MII_INTERVAL_MS;
use corerouter_model::{BondMode, Config, HashPolicy, IfName, Interface, InterfaceKind, LacpRate};
use serde_json::{Value, json};

use super::args::{opt_bool, opt_names, opt_parse, opt_str, opt_text, opt_u32, req_parse};
use super::interface::{new_name, refuse_unmanaged};
use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};

/// More slaves than this is a typo: 802.3ad aggregates at most 8 active
/// links on most switches, and the kernel has no use for hundreds.
pub const MAX_SLAVES: usize = 32;
/// Upper bound for `mii_interval` (ms): a minute without noticing a dead
/// link is already useless.
const MAX_MII_INTERVAL_MS: u32 = 60_000;

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(
        "interface.bonding.add",
        "Add Bonding",
        ["Interfaces"],
        None,
        "{name: string, slaves: [string] | string (comma-separated ethernet ports), mode: string (802.3ad | active-backup | balance-rr | balance-xor | broadcast | balance-tlb | balance-alb), primary?: string (a slave; active-backup, balance-tlb/alb), transmit_hash_policy?: string (layer-2 | layer-2-and-3 | layer-3-and-4 | encap-2-and-3 | encap-3-and-4; 802.3ad, balance-xor/tlb), lacp_rate?: string (30secs | 1sec; 802.3ad), mii_interval?: u32 (ms, 0..=60000, 0 = no link monitoring, default 100), min_links?: u32 (up slaves needed for carrier, at most the slave count), mtu?: u32 (68..=9216, default: the first slave's), comment?: string} → {name}",
        always,
        add
    ),
    cmd!(
        "interface.bonding.set",
        "Set Bonding",
        [],
        None,
        "{name: string, slaves?: [string] | string (replaces the slaves), mode?: string, primary?: string (\"\" = none), transmit_hash_policy?: string, lacp_rate?: string, mii_interval?: u32, min_links?: u32, mtu?: u32 (also the slaves'), disabled?: bool, comment?: string} → {name}",
        always,
        set
    ),
    cmd!(query "interface.bonding.list", "Bonding", ["Interfaces"], None,
        "{} → [{name, mode, slaves, primary, transmit_hash_policy, lacp_rate, mii_interval, min_links, mtu, disabled, running, comment}]",
        always, list),
];

/// Bond settings while a command builds them.
struct Settings {
    mode: BondMode,
    primary: Option<IfName>,
    hash: HashPolicy,
    lacp_rate: LacpRate,
    mii_interval_ms: u32,
    min_links: u32,
}

impl Settings {
    fn of(kind: &InterfaceKind) -> Option<Self> {
        match kind {
            InterfaceKind::Bonding {
                mode,
                primary,
                transmit_hash_policy,
                lacp_rate,
                mii_interval_ms,
                min_links,
            } => Some(Self {
                mode: *mode,
                primary: primary.clone(),
                hash: *transmit_hash_policy,
                lacp_rate: *lacp_rate,
                mii_interval_ms: *mii_interval_ms,
                min_links: *min_links,
            }),
            _ => None,
        }
    }

    fn kind(self) -> InterfaceKind {
        InterfaceKind::Bonding {
            mode: self.mode,
            primary: self.primary,
            transmit_hash_policy: self.hash,
            lacp_rate: self.lacp_rate,
            mii_interval_ms: self.mii_interval_ms,
            min_links: self.min_links,
        }
    }

    /// Apply the optional keys of `p` on top of `self`, then check that
    /// every setting means something in the resulting mode.
    fn update(mut self, p: &Value, slaves: &[IfName]) -> Result<Self> {
        if let Some(m) = opt_parse::<BondMode>(p, "mode")? {
            self.mode = m;
        }
        let hash = opt_parse::<HashPolicy>(p, "transmit_hash_policy")?;
        let rate = opt_parse::<LacpRate>(p, "lacp_rate")?;
        if let Some(h) = hash {
            if !self.mode.hashes() {
                return Err(EngineError::bad(
                    "transmit_hash_policy",
                    format!(
                        "mode {} does not hash flows (only 802.3ad, balance-xor, balance-tlb)",
                        self.mode
                    ),
                ));
            }
            self.hash = h;
        }
        if let Some(r) = rate {
            if self.mode != BondMode::Lacp {
                return Err(EngineError::bad(
                    "lacp_rate",
                    format!("mode {} does not run LACP (only 802.3ad)", self.mode),
                ));
            }
            self.lacp_rate = r;
        }
        if let Some(ms) = opt_u32(p, "mii_interval")? {
            if ms > MAX_MII_INTERVAL_MS {
                return Err(EngineError::bad(
                    "mii_interval",
                    format!("must be 0..={MAX_MII_INTERVAL_MS} ms"),
                ));
            }
            self.mii_interval_ms = ms;
        }
        if let Some(n) = opt_u32(p, "min_links")? {
            self.min_links = n;
        }
        match opt_str(p, "primary")?.map(str::trim) {
            None => {}
            Some("" | "none") => self.primary = None,
            Some(_) => self.primary = Some(req_parse(p, "primary")?),
        }
        if let Some(pr) = &self.primary {
            if !self.mode.has_primary() {
                return Err(EngineError::bad(
                    "primary",
                    format!(
                        "mode {} has no primary slave (only active-backup, balance-tlb, balance-alb); clear it with primary: \"\"",
                        self.mode
                    ),
                ));
            }
            if !slaves.contains(pr) {
                return Err(EngineError::bad(
                    "primary",
                    format!("'{pr}' is not one of the slaves"),
                ));
            }
        }
        if usize::try_from(self.min_links).map_or(true, |n| n > slaves.len()) {
            return Err(EngineError::bad(
                "min_links",
                format!(
                    "{} is more than the {} slave(s): the bond would never come up",
                    self.min_links,
                    slaves.len()
                ),
            ));
        }
        Ok(self)
    }
}

fn parse_mtu(mtu: u32) -> Result<u16> {
    u16::try_from(mtu)
        .ok()
        .filter(|m| (68..=9216).contains(m))
        .ok_or_else(|| EngineError::bad("mtu", "must be 68..=9216"))
}

/// Why `port` cannot be a slave of `bond`, if it cannot.
fn slave_problem(cfg: &Config, bond: &IfName, port: &IfName) -> Option<String> {
    let Some(iface) = cfg.interfaces.get(port) else {
        return Some(format!("no interface '{port}' (see interface.list)"));
    };
    if !matches!(iface.kind, InterfaceKind::Ethernet) {
        return Some(format!(
            "'{port}' is a {}; only ethernet ports can be slaves",
            iface.kind.label()
        ));
    }
    if let Some(other) = iface.bond.as_ref().filter(|b| *b != bond) {
        return Some(format!(
            "'{port}' is already a slave of '{other}'; take it out there first (interface.bonding.set)"
        ));
    }
    if let Some(b) = &iface.bridge {
        return Some(format!(
            "'{port}' is a port of bridge '{b}'; remove it there first (interface.bridge.port.remove), then add '{bond}' to the bridge"
        ));
    }
    if let Some(v) = &iface.vrf {
        return Some(format!(
            "'{port}' is in VRF '{v}'; take it out first (ip.vrf.set), then put '{bond}' in the VRF"
        ));
    }
    let addrs: Vec<String> = cfg
        .ip
        .addresses
        .iter()
        .filter(|a| a.interface == *port)
        .map(|a| a.address.to_string())
        .collect();
    if !addrs.is_empty() {
        return Some(format!(
            "'{port}' has address {}; remove it first (ip.address.remove) — addresses go on '{bond}'",
            addrs.join(", ")
        ));
    }
    if cfg.ip.dhcp_clients.iter().any(|c| c.interface == *port) {
        return Some(format!(
            "'{port}' has a DHCP client; remove it first (ip.dhcp-client.remove)"
        ));
    }
    if cfg.ipv6.dhcp_clients.iter().any(|c| c.interface == *port) {
        return Some(format!(
            "'{port}' has a DHCPv6 client; remove it first (ipv6.dhcp-client.remove)"
        ));
    }
    let vlans: Vec<&str> = cfg
        .interfaces
        .values()
        .filter(|i| matches!(&i.kind, InterfaceKind::Vlan { parent, .. } if parent == port))
        .map(|i| i.name.as_str())
        .collect();
    if !vlans.is_empty() {
        return Some(format!(
            "VLAN {} runs on '{port}'; remove it first (interface.remove) and create it on '{bond}'",
            vlans.join(", ")
        ));
    }
    None
}

fn parse_slaves(p: &Value, required: bool) -> Result<Option<Vec<IfName>>> {
    let slaves = opt_names(p, "slaves", MAX_SLAVES)?;
    match &slaves {
        None if required => Err(EngineError::bad("slaves", "missing (at least one port)")),
        Some(v) if v.is_empty() => Err(EngineError::bad(
            "slaves",
            "at least one port (to drop the bond, use interface.remove)",
        )),
        _ => Ok(slaves),
    }
}

/// Check `slaves`, then make them exactly the slaves of `bond`, with its MTU.
fn set_slaves(cfg: &mut Config, bond: &IfName, slaves: &[IfName], mtu: u16) -> Result<()> {
    for port in slaves {
        if let Some(why) = slave_problem(cfg, bond, port) {
            return Err(EngineError::bad("slaves", why));
        }
    }
    for iface in cfg.interfaces.values_mut() {
        if slaves.contains(&iface.name) {
            iface.bond = Some(bond.clone());
            // The kernel gives every slave the bond's MTU when it takes it.
            iface.mtu = mtu;
        } else if iface.bond.as_ref() == Some(bond) {
            iface.bond = None;
        }
    }
    Ok(())
}

/// Slaves of `bond`, in name order.
pub(super) fn slaves_of<'a>(cfg: &'a Config, bond: &IfName) -> Vec<&'a IfName> {
    cfg.interfaces
        .values()
        .filter(|i| i.bond.as_ref() == Some(bond))
        .map(|i| &i.name)
        .collect()
}

fn add(s: &mut Session, p: &Value) -> Result<Value> {
    refuse_unmanaged(s, p, &["name", "slaves"])?;
    let slaves = parse_slaves(p, true)?.unwrap_or_default();
    let mode: BondMode = req_parse(p, "mode")?;
    let comment = opt_text(p, "comment", 256)?.unwrap_or_default();
    let mtu = opt_u32(p, "mtu")?.map(parse_mtu).transpose()?;
    let cfg = s.store_mut().candidate_mut();
    let name = new_name(cfg, p)?;
    let start = Settings {
        mode,
        primary: None,
        hash: HashPolicy::default(),
        lacp_rate: LacpRate::default(),
        mii_interval_ms: DEFAULT_MII_INTERVAL_MS,
        min_links: 0,
    };
    let settings = start.update(p, &slaves)?;
    let mtu = match mtu {
        Some(m) => m,
        None => slaves
            .first()
            .and_then(|f| cfg.interfaces.get(f))
            .map_or(1500, |i| i.mtu),
    };
    let mut bond = Interface::new(name.clone(), settings.kind());
    bond.mtu = mtu;
    bond.comment = comment;
    cfg.interfaces.insert(name.clone(), bond);
    set_slaves(cfg, &name, &slaves, mtu)?;
    Ok(json!({ "name": name }))
}

fn set(s: &mut Session, p: &Value) -> Result<Value> {
    refuse_unmanaged(s, p, &["slaves"])?;
    let new_slaves = parse_slaves(p, false)?;
    let mtu = opt_u32(p, "mtu")?.map(parse_mtu).transpose()?;
    let disabled = opt_bool(p, "disabled")?;
    let comment = opt_text(p, "comment", 256)?;
    let cfg = s.store_mut().candidate_mut();
    let name: IfName = req_parse(p, "name")?;
    let (current, old_mtu) = cfg
        .interfaces
        .get(&name)
        .and_then(|i| Some((Settings::of(&i.kind)?, i.mtu)))
        .ok_or_else(|| {
            EngineError::bad(
                "name",
                format!("no bond '{name}' (see interface.bonding.list)"),
            )
        })?;
    let slaves = match new_slaves {
        Some(v) => v,
        None => slaves_of(cfg, &name).into_iter().cloned().collect(),
    };
    let settings = current.update(p, &slaves)?;
    let mtu = mtu.unwrap_or(old_mtu);
    set_slaves(cfg, &name, &slaves, mtu)?;
    if let Some(bond) = cfg.interfaces.get_mut(&name) {
        bond.kind = settings.kind();
        bond.mtu = mtu;
        if let Some(d) = disabled {
            bond.disabled = d;
        }
        if let Some(c) = comment {
            bond.comment = c;
        }
    }
    Ok(json!({ "name": name }))
}

fn list(s: &mut Session, _: &Value) -> Result<Value> {
    let live = s.hal_mut().poll();
    let cfg = s.store().candidate();
    let rows = cfg
        .interfaces
        .values()
        .filter_map(|b| Some((b, Settings::of(&b.kind)?)))
        .map(|(b, st)| {
            json!({
                "name": b.name,
                "mode": st.mode.label(),
                "slaves": slaves_of(cfg, &b.name),
                "primary": st.primary,
                "transmit_hash_policy": st.hash.label(),
                "lacp_rate": st.lacp_rate.label(),
                "mii_interval": st.mii_interval_ms,
                "min_links": st.min_links,
                "mtu": b.mtu,
                "disabled": b.disabled,
                "running": live.iter().any(|l| l.name == b.name && l.running),
                "comment": b.comment,
            })
        })
        .collect();
    Ok(Value::Array(rows))
}
