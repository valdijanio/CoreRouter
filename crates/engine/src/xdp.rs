//! IP › Firewall › XDP (G2.5a), runtime side: packets per second from the
//! data plane's counters, and the lockout check of a block list that would
//! drop the management connection before the firewall even sees it.

use std::collections::BTreeMap;
use std::net::IpAddr;

use corerouter_hal::xdp::{REASONS, XdpPlan, XdpStatus};
use corerouter_model::firewall::DynamicAddress;
use corerouter_model::{Config, IfName};

/// The last counter sample, kept in the session (`Session::ext_mut`), so a
/// query can turn counters into rates.
#[derive(Debug, Default)]
pub struct XdpRates {
    /// Seconds (session clock) of `counts`.
    at: Option<u64>,
    counts: BTreeMap<(IfName, usize), u64>,
    /// Packets per second by interface and reason, from the last two
    /// samples a second or more apart.
    rates: BTreeMap<(IfName, usize), u64>,
}

impl XdpRates {
    /// Take `status`'s counters at `now` (seconds). Samples less
    /// than a second apart keep the previous rates (the clock counts
    /// seconds); a counter that went down (reset) restarts at 0 pps.
    pub fn sample(&mut self, status: &XdpStatus, now: Option<u64>) {
        let counts: BTreeMap<(IfName, usize), u64> = status
            .ports
            .iter()
            .flat_map(|p| {
                p.counters
                    .iter()
                    .enumerate()
                    .map(move |(r, (pk, _))| ((p.interface.clone(), r), *pk))
            })
            .collect();
        let (Some(now), Some(at)) = (now, self.at) else {
            self.at = now;
            self.counts = counts;
            return;
        };
        let dt = now.saturating_sub(at);
        if dt == 0 {
            return;
        }
        self.rates = counts
            .iter()
            .map(|(k, c)| {
                let before = self.counts.get(k).copied().unwrap_or(*c);
                (k.clone(), c.checked_sub(before).map_or(0, |d| d / dt))
            })
            .collect();
        self.at = Some(now);
        self.counts = counts;
    }

    /// Packets per second of `interface` for reason index `reason`.
    pub fn pps(&self, interface: &IfName, reason: usize) -> u64 {
        self.rates
            .get(&(interface.clone(), reason))
            .copied()
            .unwrap_or(0)
    }

    /// Dropped packets per second of `interface` (every reason but pass).
    pub fn drop_pps(&self, interface: &IfName) -> u64 {
        (1..REASONS.len()).map(|r| self.pps(interface, r)).sum()
    }
}

/// Would the XDP filter of `cfg` drop packets from `peer` arriving on
/// `ingress`? The block list holding it, if so (the allow lists win).
pub fn blocks(
    cfg: &Config,
    dynamic: &[DynamicAddress],
    ingress: Option<&str>,
    peer: IpAddr,
) -> Option<String> {
    let x = &cfg.ip.xdp;
    let on_path = x
        .active()
        .any(|i| ingress.is_none_or(|name| i.interface.as_str() == name));
    if !on_path {
        return None;
    }
    let plan = XdpPlan::of(cfg, dynamic);
    if plan.allow.iter().any(|(n, _)| n.contains(&peer)) {
        return None;
    }
    let (_, list) = plan.block.iter().find(|(n, _)| n.contains(&peer))?;
    Some(
        x.filter
            .block_lists
            .get(*list as usize)
            .map_or_else(|| "a block list".to_owned(), ToString::to_string),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_hal::xdp::XdpPort;
    use corerouter_model::xdp::XdpMode;

    fn status(pass: u64) -> XdpStatus {
        XdpStatus {
            ports: vec![XdpPort {
                interface: "ether1".parse().unwrap(),
                mode: XdpMode::Auto,
                active: Some("native"),
                note: None,
                counters: vec![(pass, 0), (pass / 2, 0), (0, 0), (0, 0), (0, 0)],
            }],
            ..XdpStatus::default()
        }
    }

    #[test]
    fn rates_from_two_samples() {
        let e1: IfName = "ether1".parse().unwrap();
        let mut r = XdpRates::default();
        r.sample(&status(1000), Some(10));
        assert_eq!(r.pps(&e1, 0), 0);
        r.sample(&status(5000), Some(12));
        assert_eq!((r.pps(&e1, 0), r.drop_pps(&e1)), (2000, 1000));
        // Same second: rates kept.
        r.sample(&status(9000), Some(12));
        assert_eq!(r.pps(&e1, 0), 2000);
        // Reset counters: 0, not a huge number.
        r.sample(&status(10), Some(13));
        assert_eq!(r.pps(&e1, 0), 0);
    }
}
