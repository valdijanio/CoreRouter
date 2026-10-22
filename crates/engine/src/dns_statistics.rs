//! The LAN forwarder as the engine sees it (G4.1e): its statistics, which
//! the daemon registers with [`Session::set_dns_statistics`] (without a
//! daemon nothing counts and `ip.dns.statistics.print` shows zeros), and
//! the networks `allowed_from` stands for now, DHCP-learned and pool
//! addresses included.

use std::borrow::Cow;
use std::sync::Arc;

use corerouter_model::Config;
use corerouter_proto_dns::server::{Statistics, allowed_networks};
use ipnet::IpNet;

use crate::Session;

#[derive(Default)]
struct DnsStatsRuntime {
    stats: Option<Arc<Statistics>>,
    /// Unix time counting started (registration or the last reset).
    since: Option<u64>,
}

impl Session {
    /// The daemon's forwarder counts into `stats`.
    pub fn set_dns_statistics(&mut self, stats: Arc<Statistics>) {
        let now = self.hal_now();
        if let Some(rt) = self.ext_mut::<DnsStatsRuntime>() {
            rt.stats = Some(stats);
            rt.since = now;
        }
    }

    /// The forwarder's statistics and since when they count.
    pub fn dns_statistics(&self) -> Option<(Arc<Statistics>, Option<u64>)> {
        let rt = self.ext::<DnsStatsRuntime>()?;
        Some((rt.stats.clone()?, rt.since))
    }

    /// Back to zero; false without a forwarder.
    pub(crate) fn dns_statistics_reset(&mut self) -> bool {
        let now = self.hal_now();
        let Some(rt) = self.ext_mut::<DnsStatsRuntime>() else {
            return false;
        };
        let Some(stats) = &rt.stats else {
            return false;
        };
        stats.reset();
        rt.since = now;
        true
    }

    /// What `allowed_from` of `cfg` stands for now: the interface lists'
    /// static addresses, the ones DHCP clients learned (RouterOS flag D)
    /// and the IPv6 addresses taken from a delegated pool, once it has a
    /// prefix. A LAN whose address comes from DHCP or a pool is then
    /// allowed without listing its prefix by hand.
    pub fn dns_allowed_networks(&self, cfg: &Config) -> Vec<IpNet> {
        match self.effective(cfg) {
            Cow::Borrowed(c) => allowed_networks(c),
            Cow::Owned(mut c) => {
                // The pools' addresses that stay are resolved: whole now.
                for a in &mut c.ip.addresses {
                    a.from_pool = None;
                }
                allowed_networks(&c)
            }
        }
    }
}
