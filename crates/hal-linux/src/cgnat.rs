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

use corerouter_firewall::cgnat::{TABLE, remapped, table};
use corerouter_hal::HalError;
use corerouter_hal::conntrack::status;
use corerouter_model::cgnat::Cgnat;

use crate::nfnl;

/// Bring the kernel from `from` to `to`.
pub fn apply(from: &Cgnat, to: &Cgnat) -> Result<(), HalError> {
    let (old, new) = (table(from), table(to));
    match (&old, &new) {
        (_, None) => {
            let mut b = nfnl::Batch::new(1);
            b.new_table(TABLE);
            b.del_table(TABLE);
            nfnl::apply(b, "removing the CGNAT table")?;
        }
        (Some(a), Some(b)) => match nfnl::update(a, b, 1) {
            Some(batch) => {
                if let Err(e) = nfnl::apply(batch, "changing the CGNAT maps") {
                    log::warn!("{e}; replacing the CGNAT table instead");
                    nfnl::apply(nfnl::replace(b, 1), "loading the CGNAT table")?;
                }
            }
            None => nfnl::apply(nfnl::replace(b, 1), "loading the CGNAT table")?,
        },
        (None, Some(b)) => nfnl::apply(nfnl::replace(b, 1), "loading the CGNAT table")?,
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
