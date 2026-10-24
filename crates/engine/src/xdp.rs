//! IP › Firewall › XDP (G2.5a), runtime side: packets per second from the
//! data plane's counters, and the lockout check of a block list that would
//! drop the management connection before the firewall even sees it.

use std::collections::BTreeMap;
use std::net::IpAddr;

use corerouter_hal::xdp::{DROPS, XdpPlan, XdpStatus};
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
        DROPS.iter().map(|r| self.pps(interface, *r)).sum()
    }
}

/// What the daemon's `xdp-nat` service last reported (G2.5b), for
/// `ip.firewall.xdp.print`.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct XdpNatStatus {
    /// Connections the fast path carries now.
    pub carried: usize,
    pub installed: u64,
    pub removed: u64,
    /// Conntrack timeouts renewed for connections XDP carried.
    pub renewed: u64,
    /// Events the kernel dropped (each one is followed by a table read).
    pub lost: u64,
    pub resyncs: u64,
    pub last_error: Option<String>,
    /// Why the service is idle (fast path off, no XDP attached…).
    pub idle: Option<String>,
}

impl crate::Session {
    /// The CGNAT fast path's link (G2.5b), for the daemon's `xdp-nat`
    /// service.
    pub fn xdp_nat_link(
        &mut self,
    ) -> Result<Box<dyn corerouter_hal::xdp_nat::NatLink>, String> {
        self.hal_mut().xdp_nat_link().map_err(|e| e.to_string())
    }

    /// Keep the service's report.
    pub fn xdp_nat_set_status(&mut self, st: XdpNatStatus) {
        if let Some(slot) = self.ext_mut::<XdpNatStatus>() {
            *slot = st;
        }
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
