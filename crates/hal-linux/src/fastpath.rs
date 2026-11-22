//! The fast path in the kernel (G2.4): table `inet corerouter_fastpath`
//! over nfnetlink (`nfnl`), replaced whole in one batch.
//!
//! `hw_offload`:
//! - `auto`: the flowtable goes with `flags offload`; a refusal (veth,
//!   a card without `TC_SETUP_FT`, mlx5 in legacy mode: EOPNOTSUPP) falls
//!   back to the software flowtable and the state says why;
//! - `yes`: the refusal refuses the change;
//! - `no`: software only.
//!
//! The table is also rebuilt when the firewall changes: deleting a
//! flowtable sends its flows back to the slow path, so connections that
//! a new rule drops stop at once instead of riding the old flow until it
//! ends.

use corerouter_firewall::fastpath::{TABLE, devices, table};
use corerouter_firewall::program::{Family, Table};
use corerouter_hal::HalError;
use corerouter_hal::fastpath::{Eswitch, EswitchMode, FastPathState};
use corerouter_model::config::Config;
use corerouter_model::fastpath::HwOffload;

use crate::nfnl;

/// The empty table: a replace with it deletes ours.
fn none() -> Table {
    Table {
        family: Family::Inet,
        name: TABLE.into(),
        ..Table::default()
    }
}

/// Whether link `name` exists in this namespace now.
fn exists(name: &str) -> bool {
    matches!(crate::netlink::link_detail(name), Ok(Some(_)))
}

/// Install the fast path of `to` (or remove it); `state` becomes what is
/// in the kernel.
pub fn apply(to: &Config, state: &mut FastPathState) -> Result<(), HalError> {
    let fp = &to.ip.fastpath;
    let ports = if fp.enabled {
        devices(fp, to, exists)
    } else {
        Vec::new()
    };
    let want_hw = fp.hw_offload != HwOffload::No;
    let Some(t) = table(fp, &ports, want_hw) else {
        if state.active || fp.enabled {
            nfnl::apply(nfnl::replace(&none(), 1), "fast path")?;
        }
        *state = FastPathState {
            note: fp
                .enabled
                .then(|| "no port of the fast path exists: nothing installed".into()),
            ..FastPathState::default()
        };
        return Ok(());
    };
    match nfnl::apply(nfnl::replace(&t, 1), "fast path") {
        Ok(()) => {
            *state = FastPathState {
                active: true,
                hardware: want_hw,
                devices: ports,
                note: None,
            };
            Ok(())
        }
        Err(e) if want_hw && fp.hw_offload == HwOffload::Auto => {
            let soft = table(fp, &ports, false).unwrap_or_else(none);
            nfnl::apply(nfnl::replace(&soft, 1), "fast path")?;
            *state = FastPathState {
                active: true,
                hardware: false,
                devices: ports,
                note: Some(format!(
                    "hardware offload refused ({}); running in software",
                    short(&e)
                )),
            };
            Ok(())
        }
        Err(e) => Err(match fp.hw_offload {
            HwOffload::Yes => HalError::Rejected(format!(
                "{}; hardware offload is required (hw_offload=yes): use auto to fall back to software",
                short(&e)
            )),
            _ => e,
        }),
    }
}

fn short(e: &HalError) -> String {
    let t = e.to_string();
    t.chars().take(200).collect()
}

// devlink (`DEVLINK_*`): the eSwitch mode.
const DEVLINK_CMD_ESWITCH_GET: u8 = 29;
const DEVLINK_ATTR_BUS_NAME: u16 = 1;
const DEVLINK_ATTR_DEV_NAME: u16 = 2;
const DEVLINK_ATTR_ESWITCH_MODE: u16 = 25;
const DEVLINK_ESWITCH_MODE_SWITCHDEV: u16 = 1;

/// The eSwitch mode of `bus`/`dev`; `Err` is a note (most NICs have none).
fn eswitch_mode(bus: &str, dev: &str) -> Result<EswitchMode, String> {
    use crate::genl::{Genl, Msg, attrs};
    let mut genl = Genl::open().map_err(|e| e.to_string())?;
    let family = genl
        .family("devlink")
        .map_err(|e| format!("no devlink in this kernel ({e})"))?;
    let seq = genl.next_seq();
    let mut m = Msg::new(family, DEVLINK_CMD_ESWITCH_GET, 1, seq);
    m.str(DEVLINK_ATTR_BUS_NAME, bus)
        .str(DEVLINK_ATTR_DEV_NAME, dev);
    let replies = genl
        .call(m.finish(), seq)
        .map_err(|e| format!("the driver has no eSwitch ({e})"))?;
    let Some((_, a)) = replies.first() else {
        return Err("devlink: no answer".into());
    };
    attrs(a)
        .find(|at| at.kind == DEVLINK_ATTR_ESWITCH_MODE)
        .and_then(|at| at.u16())
        .map(|m| {
            if m == DEVLINK_ESWITCH_MODE_SWITCHDEV {
                EswitchMode::Switchdev
            } else {
                EswitchMode::Legacy
            }
        })
        .ok_or_else(|| "devlink: no eSwitch mode in the answer".into())
}

/// What port `name`'s card offers the flowtable: driver, firmware,
/// `hw-tc-offload`, the eSwitch mode and whether it is a representor.
pub fn eswitch(name: &str) -> Result<Eswitch, HalError> {
    let hw = crate::nic::hardware(name)?;
    let mut out = Eswitch {
        driver: hw.driver.clone(),
        firmware: hw.firmware.clone(),
        hw_tc_offload: hw
            .offloads
            .iter()
            .find(|o| o.feature == "hw-tc-offload")
            .map(|o| o.active),
        ..Eswitch::default()
    };
    if let (Some(bus), Some(dev)) = (hw.bus.as_deref(), hw.bus_address.as_deref())
        && bus != "virtual"
    {
        out.devlink = Some(format!("{bus}/{dev}"));
        match eswitch_mode(bus, dev) {
            Ok(m) => out.mode = Some(m),
            Err(e) => out.notes.push(e),
        }
    }
    // A switchdev representor has a port name (`p0`, `pf0vf1`).
    let port = std::fs::read_to_string(format!("/sys/class/net/{name}/phys_port_name"))
        .map(|s| s.trim().to_owned())
        .unwrap_or_default();
    out.representor = !port.is_empty() && out.mode == Some(EswitchMode::Switchdev);
    Ok(out)
}
