//! Jobs of the diagnostic tools. Pure logic over a [`ProbeSocket`] and a
//! [`TaskCtx`]: no sockets, threads or clocks of their own, so they run the
//! same on the host's ICMP and on the simulated network, and in tests.

pub mod mtr;
pub mod mtu;
pub mod ping;
pub mod stats;
pub mod text;

use std::net::IpAddr;
use std::ops::ControlFlow;
use std::time::Duration;

use corerouter_hal::probe::{ProbeSocket, Prober, Reply};

use crate::tasks::TaskCtx;

/// Longest single wait on the socket, so a stop is noticed quickly.
const MAX_WAIT: Duration = Duration::from_millis(100);

/// A ping/MTU target as the operator typed it, and its address once known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub input: String,
    pub addr: Option<IpAddr>,
}

impl Target {
    /// `addr` itself, or the name resolved through `prober` (the address of
    /// `family` if one is required, e.g. by the source address).
    pub fn resolve(&self, prober: &dyn Prober, v6: Option<bool>) -> Result<IpAddr, String> {
        if let Some(a) = self.addr {
            return Ok(a);
        }
        let all = prober.resolve(&self.input).map_err(|e| e.to_string())?;
        all.iter()
            .copied()
            .find(|a| v6.is_none_or(|v6| a.is_ipv6() == v6))
            .ok_or_else(|| {
                let want = if v6 == Some(true) { "IPv6" } else { "IPv4" };
                format!("'{}' has no {want} address", self.input)
            })
    }
}

/// Receive until `until` (job time), handing every reply to `on_reply`
/// (which may end the wait with `Break`). `Ok(false)`: the task was stopped.
pub(crate) fn wait_replies(
    sock: &mut dyn ProbeSocket,
    ctx: &TaskCtx,
    until: Duration,
    mut on_reply: impl FnMut(Reply, Duration) -> ControlFlow<()>,
) -> Result<bool, String> {
    loop {
        if ctx.stopped() {
            return Ok(false);
        }
        let now = ctx.now();
        if now >= until {
            return Ok(true);
        }
        let wait = until.saturating_sub(now).min(MAX_WAIT);
        match sock.recv(wait).map_err(|e| e.to_string())? {
            Some(reply) => {
                if on_reply(reply, ctx.now()).is_break() {
                    return Ok(true);
                }
            }
            // A simulated socket answers at once: wait out the slice here.
            None => {
                let left = until.saturating_sub(ctx.now()).min(wait);
                if !left.is_zero() && !ctx.sleep(left) {
                    return Ok(false);
                }
            }
        }
    }
}

/// Milliseconds with microsecond precision, for JSON.
pub(crate) fn ms(d: Duration) -> f64 {
    (d.as_secs_f64() * 1_000_000.0).round() / 1000.0
}
