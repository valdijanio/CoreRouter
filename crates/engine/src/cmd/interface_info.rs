//! What the "Interface <name>" dialog's Status, Hardware, Traffic and
//! Statistics tabs show (G1.19): read-only queries over the HAL, like
//! RouterOS `/interface ethernet monitor` and `print stats`.
//!
//! A port or driver that cannot say something is not an error: the result
//! has `available: false` with the `reason`, plus whatever is known from
//! the link state. Only an interface that does not exist is an error.

use corerouter_hal::{HalError, LinkState};
use corerouter_model::IfName;
use serde_json::{Map, Value, json};

use super::args::req_parse;
use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(query "interface.ethernet.monitor", "Ethernet Monitor", [], None,
        "{name: string} → {name, available, reason, status (link-ok | no-link), auto_negotiation (done | incomplete | disabled), rate, speed_mbps, full_duplex, autoneg, port, mdix, mdix_ctrl, supported_modes, advertising, link_partner_advertising, rx_flow_control, tx_flow_control, flow_control_autoneg, carrier_changes, link_downs, down_reason, last_link_up_time, last_link_down_time, watching_since, now, configured: {auto_negotiation, speed_mbps, full_duplex, advertise, rx_flow_control, tx_flow_control, offloads}, sfp: null | {module_present, kind, spec, connector, compliance, cable, nominal_rate_mbd, vendor_name, vendor_oui, vendor_part_number, vendor_revision, vendor_serial, manufacturing_date, wavelength_nm, link_length: [{medium, meters}], rx_loss, tx_fault, checksum_ok, dom: [{name, lane, value, unit, limits: {high_alarm, high_warning, low_warning, low_alarm}, level (ok | low-warning | high-warning | low-alarm | high-alarm)}], alerts: [string], notes}, sfp_reason, notes}",
        always, monitor)
    .positional("name"),
    cmd!(query "interface.hardware", "Interface Hardware", [], None,
        "{name: string} → {name, available, reason, mac, perm_mac, min_mtu, max_mtu, bus, bus_address, vendor_id, device_id, subsystem_vendor_id, subsystem_device_id, vendor, model, subsystem, driver, driver_version, firmware, serial, numa_node, rx_queues, tx_queues, combined_channels, combined_channels_max, irqs, ring_rx, ring_rx_max, ring_tx, ring_tx_max, offloads: [{name, feature, active, fixed}], usb: null | {port, speed_mbps, speed, adapter_max_mbps, adapter, port_max_mbps, version, vendor_id, product_id, manufacturer, product, serial, revision, max_power_ma, autosuspend, lpm, over_current, tx_timeouts (NETDEV WATCHDOG), port_power_switch, slow_port (the port caps the adapter), cap_mbps, alert}, notes}",
        always, hardware)
    .positional("name"),
    cmd!(query "interface.stats", "Interface Statistics", [], None,
        "{name: string} → {name, available, reason, groups: [{name (interface | eth-phy | eth-mac | eth-ctrl | rmon | pause), counters: [{name, value}]}], notes}",
        always, stats)
    .positional("name"),
];

/// The interface `name` (config or platform link) and its live state.
fn target(s: &mut Session, p: &Value) -> Result<(IfName, Option<LinkState>)> {
    let name: IfName = req_parse(p, "name")?;
    let live = s.hal_mut().poll();
    s.watch_links(&live);
    let st = live.into_iter().find(|l| l.name == name);
    if st.is_none() && !s.store().candidate().interfaces.contains_key(&name) {
        return Err(EngineError::bad(
            "name",
            format!("no interface '{name}' (see interface.list)"),
        ));
    }
    Ok((name, st))
}

/// `available` / `reason` for a HAL answer.
fn availability<T>(r: &std::result::Result<T, HalError>) -> (bool, Option<String>) {
    match r {
        Ok(_) => (true, None),
        Err(HalError::Unsupported(why) | HalError::Rejected(why) | HalError::Io(why)) => {
            (false, Some(why.clone()))
        }
    }
}

/// RouterOS `rate`: 100 → `100Mbps`, 2500 → `2.5Gbps`, 10000 → `10Gbps`.
pub fn rate(mbps: u32) -> String {
    if mbps >= 1000 && mbps.is_multiple_of(1000) {
        format!("{}Gbps", mbps / 1000)
    } else if mbps >= 1000 {
        format!("{}.{}Gbps", mbps / 1000, (mbps % 1000) / 100)
    } else {
        format!("{mbps}Mbps")
    }
}

fn monitor(s: &mut Session, p: &Value) -> Result<Value> {
    let (name, st) = target(s, p)?;
    let r = s.hal_mut().ethernet_monitor(&name);
    let (available, reason) = availability(&r);
    let m = r.unwrap_or_default();
    let link_ok = if available {
        m.link_ok
    } else {
        st.as_ref().is_some_and(|l| l.running)
    };
    let times = s.links.get(&name).copied();
    let (sfp, sfp_reason) = if available {
        sfp(s, &name)
    } else {
        (Value::Null, reason.clone())
    };
    let auto = match (m.autoneg, link_ok) {
        (Some(false), _) => Some("disabled"),
        (Some(true), true) => Some("done"),
        (Some(true), false) => Some("incomplete"),
        (None, _) => None,
    };
    Ok(json!({
        "name": name,
        "available": available,
        "reason": reason,
        "status": if link_ok { "link-ok" } else { "no-link" },
        "auto_negotiation": auto,
        "rate": m.speed_mbps.map(rate),
        "speed_mbps": m.speed_mbps,
        "full_duplex": m.full_duplex,
        "autoneg": m.autoneg,
        "port": m.port,
        "mdix": m.mdix,
        "mdix_ctrl": m.mdix_ctrl,
        "supported_modes": m.supported,
        "advertising": m.advertising,
        "link_partner_advertising": m.partner_advertising,
        "rx_flow_control": m.rx_flow_control,
        "tx_flow_control": m.tx_flow_control,
        "flow_control_autoneg": m.flow_control_autoneg,
        "carrier_changes": m.carrier_changes,
        // The platform's count when it keeps one, else what the engine saw.
        "link_downs": m.link_downs.or(times.map(|t| t.downs)),
        "down_reason": m.down_reason,
        "last_link_up_time": times.and_then(|t| t.last_up),
        "last_link_down_time": times.and_then(|t| t.last_down),
        "watching_since": s.links.since,
        "now": s.now(),
        "configured": super::ethernet::configured(s, &name),
        "sfp": sfp,
        "sfp_reason": sfp_reason,
        "notes": m.notes,
    }))
}

/// The module in `name`'s cage as JSON, with its alerts spelled out; or
/// why there is none (`null` + reason: a copper port, a driver without
/// module access).
fn sfp(s: &mut Session, name: &IfName) -> (Value, Option<String>) {
    let disabled = s
        .store()
        .running()
        .interfaces
        .get(name)
        .is_some_and(|i| i.disabled);
    match s.read_module(name) {
        Ok(m) => {
            // A disabled port's laser is off on purpose (as in the log).
            let alerts: Vec<String> = m
                .alerts()
                .filter(|r| !(disabled && r.name.starts_with("tx-")))
                .map(|r| {
                    let level = r.level.map_or("", |l| l.label());
                    format!("{} {:.2} {} ({level})", r.key(), r.value, r.unit)
                })
                .collect();
            let mut v = serde_json::to_value(&m).unwrap_or(Value::Null);
            if let Value::Object(o) = &mut v {
                o.insert("alerts".into(), json!(alerts));
            }
            (v, None)
        }
        Err(HalError::Unsupported(why) | HalError::Rejected(why) | HalError::Io(why)) => {
            (Value::Null, Some(why))
        }
    }
}

/// `0x8086` → `"8086"`.
fn hex(id: Option<u16>) -> Value {
    id.map_or(Value::Null, |v| json!(format!("{v:04x}")))
}

fn hardware(s: &mut Session, p: &Value) -> Result<Value> {
    let (name, st) = target(s, p)?;
    let r = s.hal_mut().hardware(&name);
    let (available, reason) = availability(&r);
    let mut hw = r.unwrap_or_default();
    if hw.mac.is_none() {
        hw.mac = st.and_then(|l| l.mac);
    }
    let ids = [
        ("vendor_id", hw.vendor_id),
        ("device_id", hw.device_id),
        ("subsystem_vendor_id", hw.subsystem_vendor_id),
        ("subsystem_device_id", hw.subsystem_device_id),
    ];
    let mut out = match serde_json::to_value(&hw) {
        Ok(Value::Object(m)) => m,
        _ => Map::new(),
    };
    for (key, id) in ids {
        out.insert(key.into(), hex(id));
    }
    out.insert("usb".into(), crate::usb_nic::detail(s, &name, &hw));
    out.insert("name".into(), json!(name));
    out.insert("available".into(), json!(available));
    out.insert("reason".into(), json!(reason));
    Ok(Value::Object(out))
}

fn stats(s: &mut Session, p: &Value) -> Result<Value> {
    let (name, st) = target(s, p)?;
    let r = s.hal_mut().counters(&name);
    let (available, reason) = availability(&r);
    let c = r.unwrap_or_default();
    let groups: Vec<Value> = if c.groups.is_empty() {
        // At least what `interface.list` shows.
        st.map(|l| {
            json!({"name": "interface", "counters": [
                {"name": "rx_bytes", "value": l.rx_bytes},
                {"name": "tx_bytes", "value": l.tx_bytes},
                {"name": "rx_packets", "value": l.rx_packets},
                {"name": "tx_packets", "value": l.tx_packets},
            ]})
        })
        .into_iter()
        .collect()
    } else {
        c.groups
            .iter()
            .map(|g| json!({"name": g.name, "counters": g.counters}))
            .collect()
    };
    Ok(json!({
        "name": name,
        "available": available,
        "reason": reason,
        "groups": groups,
        "notes": c.notes,
    }))
}

#[cfg(test)]
mod tests {
    use super::rate;

    #[test]
    fn rates_read_like_routeros() {
        assert_eq!(rate(10), "10Mbps");
        assert_eq!(rate(100), "100Mbps");
        assert_eq!(rate(1000), "1Gbps");
        assert_eq!(rate(2500), "2.5Gbps");
        assert_eq!(rate(10_000), "10Gbps");
        assert_eq!(rate(25_000), "25Gbps");
    }
}
