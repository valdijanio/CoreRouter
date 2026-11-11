//! G1.30: which links are Wi-Fi radios.
//!
//! `RTM_NEWLINK` does not say. A station's netdev is `ARPHRD_ETHER` with no
//! `IFLA_INFO_KIND` (`net/mac80211/iface.c`, `ieee80211_if_setup`), exactly
//! what an Ethernet port looks like, so the link dump alone took a `wlan0`
//! for a port, seeded it as one and put the ports' settings on it. sysfs
//! tells them apart (`DEVTYPE=wlan`, the `phy80211` link), but it shows the
//! namespace that mounted `/sys`, not the one this process is in.
//!
//! nl80211 does: the `NL80211_CMD_GET_INTERFACE` dump lists the wireless
//! netdevs of this network namespace by index, to anybody. It is asked only
//! when the link dump shows a port-like link not seen before (a netdev never
//! turns into a radio, and the kernel does not hand an index out again while
//! the link is there), so the every-second poll pays nothing for it.
//! And only with cfg80211 already in the kernel (see [`radios`]).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use crate::genl::{Genl, GenlError, Msg, attrs, find};
use crate::owner::{ARPHRD_ETHER, KernelLink};

const NL80211_FAMILY: &str = "nl80211";
const NL80211_CMD_GET_INTERFACE: u8 = 5;
const NL80211_ATTR_IFINDEX: u16 = 3;

/// Port-like links already asked about: index → is a radio.
static SEEN: Mutex<BTreeMap<u32, bool>> = Mutex::new(BTreeMap::new());

/// cfg80211 in the kernel: built in, or the module loaded.
const CFG80211: &str = "/sys/module/cfg80211";

/// The indexes of this namespace's wireless netdevs. Without cfg80211 (a
/// module, loaded with the first card's driver) there is none, and the
/// kernel must not be asked: looking a generic netlink family up by name
/// makes it run `modprobe` for it (`genl_ctrl_getfamily`, `request_module`),
/// which loaded cfg80211 and rfkill on every router, 48 ms into the daemon's
/// start (**medido**), for a card that is not there.
fn radios() -> Result<BTreeSet<u32>, GenlError> {
    if !std::path::Path::new(CFG80211).exists() {
        return Ok(BTreeSet::new());
    }
    let mut genl = Genl::open()?;
    let family = match genl.family(NL80211_FAMILY) {
        Ok(f) => f,
        Err(e) if e.unsupported() => return Ok(BTreeSet::new()),
        Err(e) => return Err(e),
    };
    let seq = genl.next_seq();
    let req = Msg::dump(family, NL80211_CMD_GET_INTERFACE, 0, seq).finish();
    Ok(genl
        .call(req, seq)?
        .iter()
        .filter_map(|(_, a)| find(attrs(a), NL80211_ATTR_IFINDEX)?.u32())
        .collect())
}

/// What `seen` says about the candidates, asking `ask` once if one of them
/// is new. A failed question leaves the new ones unknown (not radios, this
/// time) and is asked again at the next dump.
fn resolve(
    seen: &mut BTreeMap<u32, bool>,
    candidates: &BTreeSet<u32>,
    ask: impl FnOnce() -> Option<BTreeSet<u32>>,
) {
    seen.retain(|index, _| candidates.contains(index));
    if candidates.iter().all(|c| seen.contains_key(c)) {
        return;
    }
    if let Some(radios) = ask() {
        for c in candidates {
            seen.entry(*c).or_insert_with(|| radios.contains(c));
        }
    }
}

/// Sets [`KernelLink::wireless`] on the links of a dump.
pub(crate) fn mark(links: &mut [KernelLink]) {
    let candidates: BTreeSet<u32> = links
        .iter()
        .filter(|l| l.kind.is_none() && l.arphrd == ARPHRD_ETHER)
        .map(|l| l.index)
        .collect();
    let mut seen = SEEN
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    resolve(&mut seen, &candidates, || radios().ok());
    for l in links.iter_mut() {
        l.wireless = seen.get(&l.index).copied().unwrap_or(false);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_kernel_is_asked_only_about_a_link_not_seen_before() {
        let mut seen = BTreeMap::new();
        let mut asked = 0;
        let mut step = |seen: &mut BTreeMap<u32, bool>, cand: &[u32], radios: Option<&[u32]>| {
            let cand: BTreeSet<u32> = cand.iter().copied().collect();
            resolve(seen, &cand, || {
                asked += 1;
                radios.map(|r| r.iter().copied().collect())
            });
        };
        // Boot: two ports and a radio.
        step(&mut seen, &[2, 3, 4], Some(&[4]));
        assert_eq!(seen, BTreeMap::from([(2, false), (3, false), (4, true)]));
        // The poll, a thousand times: nothing new, nothing asked.
        for _ in 0..1000 {
            step(&mut seen, &[2, 3, 4], Some(&[]));
        }
        assert_eq!(seen.get(&4), Some(&true));
        // A USB radio is plugged in; a port goes away (forgotten: its index
        // may come back as something else).
        step(&mut seen, &[2, 4, 9], Some(&[4, 9]));
        assert_eq!(seen, BTreeMap::from([(2, false), (4, true), (9, true)]));
        // The question fails: the new link is not judged, and asked again.
        step(&mut seen, &[2, 4, 9, 10], None);
        assert_eq!(seen.get(&10), None);
        step(&mut seen, &[2, 4, 9, 10], Some(&[4, 9, 10]));
        assert_eq!(seen.get(&10), Some(&true));
        drop(step);
        assert_eq!(asked, 4);
    }
}
