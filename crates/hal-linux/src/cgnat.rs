//! CGNAT in the kernel (G2.3): table `ip corerouter_cgnat` over nfnetlink
//! (`nfnl`), no `nft` program.
//!
//! A change that only moves map elements (ports per subscriber, an
//! exception's address, more subscribers in a range) goes as the
//! elements that left and came: the live UDP mappings of the dynamic
//! maps survive and nothing is rebuilt. Anything else replaces the table
//! in one batch. Either way the kernel takes the whole batch or nothing.
//! If the incremental batch is refused (the kernel's table is not what
//! `from` says: someone flushed it), a replace follows.
//!
//! Then the connections of remapped subscribers are killed
//! (`cgnat::remapped`): they still carry the old translation, and "who
//! was" must find the subscriber the formula of the moment names.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use corerouter_firewall::cgnat::{TABLE, remapped, table};
use corerouter_firewall::program::{Element, Set, Type, Value};
use corerouter_hal::HalError;
use corerouter_hal::cgnat::BlockChange;
use corerouter_hal::conntrack::status;
use corerouter_model::ItemId;
use corerouter_model::cgnat::{Cgnat, Mode, Slot};

use crate::nfnl;

/// The port blocks installed in blocks-mode maps (G2.3c), by (pool,
/// subscriber): re-installed after a replace of the table.
pub type Blocks = BTreeMap<(ItemId, Ipv4Addr), Slot>;

/// The map `d_<id>` of a pool, as the encoder needs it.
fn map(pool: ItemId) -> Set {
    Set {
        name: format!("d_{:x}", pool.0),
        key: Type::Addr,
        data: Some(Type::AddrPortRange),
        interval: false,
        dynamic_timeout: None,
        size: None,
        elements: Vec::new(),
    }
}

fn element(sub: Ipv4Addr, slot: Slot) -> Element {
    Element {
        key: Value::Addr(sub),
        key_last: None,
        data: Some(Value::AddrPortRange(
            slot.public,
            slot.first_port,
            slot.last_port,
        )),
    }
}

/// Whether `slot` is still a block of blocks-mode pool `pool` in `c`.
fn still_valid(c: &Cgnat, pool: ItemId, slot: Slot) -> bool {
    c.pools
        .iter()
        .find(|p| p.id == pool && p.mode == Mode::Blocks && !p.disabled)
        .and_then(|p| p.layout().ok())
        .and_then(|l| {
            l.locate(slot.public, slot.first_port)
                .and_then(|(a, b)| l.block(a, b))
        })
        == Some(slot)
}

/// Set or remove blocks: in one batch, the old element of each changed
/// subscriber leaves and the new one comes (an add of an existing key is
/// refused).
pub fn set_blocks(changes: &[BlockChange], blocks: &mut Blocks) -> Result<(), HalError> {
    let mut b = nfnl::Batch::new(1);
    let mut any = false;
    for c in changes {
        let set = map(c.pool);
        if let Some(old) = blocks.get(&(c.pool, c.subscriber)) {
            if Some(*old) == c.slot {
                continue;
            }
            b.elements(TABLE, &set, &[element(c.subscriber, *old)], false);
            any = true;
        }
        if let Some(slot) = c.slot {
            b.elements(TABLE, &set, &[element(c.subscriber, slot)], true);
            any = true;
        }
    }
    if !any {
        return Ok(());
    }
    nfnl::apply(b, "changing CGNAT blocks")?;
    for c in changes {
        match c.slot {
            Some(slot) => {
                blocks.insert((c.pool, c.subscriber), slot);
            }
            None => {
                blocks.remove(&(c.pool, c.subscriber));
            }
        }
    }
    Ok(())
}

/// After the table was rebuilt: the blocks still valid go back in.
fn reinstall(to: &Cgnat, blocks: &mut Blocks) {
    blocks.retain(|(pool, _), slot| still_valid(to, *pool, *slot));
    if blocks.is_empty() {
        return;
    }
    let mut b = nfnl::Batch::new(1);
    let mut by_pool: BTreeMap<ItemId, Vec<Element>> = BTreeMap::new();
    for ((pool, sub), slot) in blocks.iter() {
        by_pool.entry(*pool).or_default().push(element(*sub, *slot));
    }
    for (pool, items) in &by_pool {
        b.elements(TABLE, &map(*pool), items, true);
    }
    if let Err(e) = nfnl::apply(b, "re-installing CGNAT blocks") {
        log::error!("cgnat: {e}; the engine re-sends them at its next allocation");
        blocks.clear();
    }
}

/// Bring the kernel from `from` to `to`.
pub fn apply(from: &Cgnat, to: &Cgnat, blocks: &mut Blocks) -> Result<(), HalError> {
    let (old, new) = (table(from), table(to));
    match (&old, &new) {
        (_, None) => {
            let mut b = nfnl::Batch::new(1);
            b.new_table(TABLE);
            b.del_table(TABLE);
            nfnl::apply(b, "removing the CGNAT table")?;
            blocks.clear();
        }
        (Some(a), Some(b)) => match nfnl::update(a, b, 1) {
            Some(batch) => {
                if let Err(e) = nfnl::apply(batch, "changing the CGNAT maps") {
                    log::warn!("{e}; replacing the CGNAT table instead");
                    nfnl::apply(nfnl::replace(b, 1), "loading the CGNAT table")?;
                    reinstall(to, blocks);
                }
            }
            None => {
                nfnl::apply(nfnl::replace(b, 1), "loading the CGNAT table")?;
                reinstall(to, blocks);
            }
        },
        (None, Some(b)) => {
            nfnl::apply(nfnl::replace(b, 1), "loading the CGNAT table")?;
            reinstall(to, blocks);
        }
    }
    let moved = remapped(from, to);
    if !moved.is_empty() {
        // The live UDP mappings of a remapped subscriber name its old
        // ports, which may now be another subscriber's: forget them all
        // (each is learned again by the next packet).
        if let Some(t) = &new {
            let dynamic: Vec<&str> = t
                .sets
                .iter()
                .filter(|s| s.dynamic_timeout.is_some())
                .map(|s| s.name.as_str())
                .collect();
            if !dynamic.is_empty() {
                let mut b = nfnl::Batch::new(1);
                for name in dynamic {
                    b.flush_set(TABLE, name);
                }
                if let Err(e) = nfnl::apply(b, "forgetting the UDP mappings") {
                    log::warn!("cgnat: {e}");
                }
            }
        }
        kill_remapped(&moved);
    }
    Ok(())
}

/// Kill the connections of subscribers whose mapping changed. A failure
/// is logged, not returned: the new table is in, and those connections
/// end by themselves.
fn kill_remapped(moved: &[std::net::Ipv4Addr]) {
    let conns = match crate::ctnl::dump() {
        Ok(c) => c,
        Err(e) => {
            log::warn!(
                "cgnat: {} subscribers remapped, their connections not killed: {e}",
                moved.len()
            );
            return;
        }
    };
    let victims: Vec<_> = conns
        .into_iter()
        .filter(|c| c.has(status::SRC_NAT))
        .filter(|c| match c.orig.src {
            std::net::IpAddr::V4(a) => moved.binary_search(&a).is_ok(),
            std::net::IpAddr::V6(_) => false,
        })
        .collect();
    match crate::ctnl::delete(&victims) {
        Ok(n) => log::info!(
            "cgnat: {} subscribers remapped; {n} of their connections killed",
            moved.len()
        ),
        Err(e) => log::warn!("cgnat: killing the remapped connections: {e}"),
    }
}
