//! Answers built outside the session lock (G0.31b).
//!
//! Every command of the daemon runs inside `lock(&shared)`: while one
//! query turns 60 000 routes into JSON, DHCP, PPPoE, the metrics scrape
//! and every other client wait for it. A query whose answer is big takes
//! what it needs under the lock (a copy of the config, which is a few
//! reference counts, `crate::cow`, and `Arc`s of the live state) and hands
//! the rest to [`Session::defer`]: a closure that builds the answer from
//! that copy alone.
//!
//! - [`Session::execute_reply_as`] (the control channel) returns it as
//!   [`Reply::Later`]; the caller drops the lock and then runs it
//!   ([`Reply::finish`]).
//! - Everyone else ([`Session::execute`]: the GUI in-process, the CLI
//!   without a daemon, batches, tests, a command that runs another one)
//!   gets the answer as before: `defer` runs the closure on the spot.
//!
//! Only the command the reply was asked for defers: one it runs inside
//! (a nested `execute`) answers in place, or its caller would get `null`.
//! The closure must not reach back into the session: what it reads is
//! the snapshot it owns (`Send + 'static` makes that a compile error).

use serde_json::Value;

use crate::{Caller, Result, Session};

/// The rest of an answer, built without the session.
pub type Build = Box<dyn FnOnce() -> Result<Value> + Send>;

/// What [`Session::execute_reply_as`] answers.
pub enum Reply {
    /// Built under the lock (every command that does not defer).
    Ready(Value),
    /// Run [`Reply::finish`] after releasing the lock.
    Later(Build),
}

impl Reply {
    /// The answer: built now if it was deferred.
    pub fn finish(self) -> Result<Value> {
        match self {
            Self::Ready(v) => Ok(v),
            Self::Later(build) => build(),
        }
    }
}

impl std::fmt::Debug for Reply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ready(v) => f.debug_tuple("Ready").field(v).finish(),
            Self::Later(_) => f.write_str("Later(..)"),
        }
    }
}

/// Nesting of `execute` and the depth whose command may defer.
#[derive(Default)]
pub(crate) struct OffLock {
    depth: u32,
    accept: Option<u32>,
    pending: Option<Build>,
}

impl Session {
    /// [`Session::execute_as`], with the answer of a query that defers
    /// left to the caller: run [`Reply::finish`] after unlocking.
    pub fn execute_reply_as(&mut self, caller: &Caller, id: &str, params: &Value) -> Result<Reply> {
        let (outer, depth) = match self.ext_mut::<OffLock>() {
            Some(o) => {
                let outer = o.accept.replace(o.depth.saturating_add(1));
                (outer, o.depth)
            }
            None => (None, 0),
        };
        let out = self.execute_as(caller, id, params);
        let pending = self.ext_mut::<OffLock>().and_then(|o| {
            o.accept = outer;
            o.depth = depth;
            o.pending.take()
        });
        let value = out?;
        Ok(match pending {
            Some(build) => Reply::Later(build),
            None => Reply::Ready(value),
        })
    }

    /// Answer the running query with `build`: after the lock is released
    /// when the caller asked for a [`Reply`], else now.
    pub(crate) fn defer(
        &mut self,
        build: impl FnOnce() -> Result<Value> + Send + 'static,
    ) -> Result<Value> {
        match self.ext_mut::<OffLock>() {
            Some(o) if o.accept == Some(o.depth) && o.pending.is_none() => {
                // Outside `execute`'s guard now: a panic while building
                // is an error answer, as it was under the lock.
                o.pending = Some(Box::new(move || crate::guard::run("deferred answer", build)));
                Ok(Value::Null)
            }
            _ => build(),
        }
    }

    /// `execute` entered (`true`) or left: only the outermost command of
    /// a reply defers.
    pub(crate) fn off_lock_nest(&mut self, enter: bool) {
        if let Some(o) = self.ext_mut::<OffLock>() {
            o.depth = if enter {
                o.depth.saturating_add(1)
            } else {
                o.depth.saturating_sub(1)
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn lab() -> Session {
        let mut s = Session::virtual_lab();
        s.execute(
            "ip.address.add",
            &json!({"address": "192.168.88.1/24", "interface": "ether1"}),
        )
        .unwrap();
        s.execute(
            "ip.route.add",
            &json!({"dst_address": "198.51.100.0/24", "gateway": "192.168.88.254"}),
        )
        .unwrap();
        s
    }

    #[test]
    fn a_reply_defers_and_finishes_to_the_same_answer() {
        let mut s = lab();
        let now = s.execute("ip.route.list", &json!({})).unwrap();
        let reply = s
            .execute_reply_as(&Caller::local(), "ip.route.list", &json!({}))
            .unwrap();
        assert!(matches!(reply, Reply::Later(_)), "{reply:?}");
        assert_eq!(reply.finish().unwrap(), now);
        // A command that does not defer answers in place.
        let ready = s
            .execute_reply_as(&Caller::local(), "system.identity.get", &json!({}))
            .unwrap();
        assert!(matches!(ready, Reply::Ready(_)), "{ready:?}");
    }

    #[test]
    fn a_command_run_inside_another_answers_in_place() {
        let mut s = lab();
        let want = s.execute("ip.route.list", &json!({})).unwrap();
        // As if a command asked for as a reply ran `ip.route.list` itself.
        if let Some(o) = s.ext_mut::<OffLock>() {
            o.accept = Some(o.depth + 1);
            o.depth += 1;
        }
        assert_eq!(s.execute("ip.route.list", &json!({})).unwrap(), want);
        assert!(s.ext::<OffLock>().unwrap().pending.is_none());
    }

    #[test]
    #[allow(clippy::panic)]
    fn a_panic_while_building_is_an_error() {
        let mut s = lab();
        if let Some(o) = s.ext_mut::<OffLock>() {
            o.accept = Some(o.depth);
        }
        s.defer(|| panic!("boom")).unwrap();
        let build = s.ext_mut::<OffLock>().unwrap().pending.take().unwrap();
        assert!(Reply::Later(build).finish().is_err());
    }

    #[test]
    fn a_failed_reply_leaves_nothing_behind() {
        let mut s = lab();
        let bad = s.execute_reply_as(&Caller::local(), "ip.route.list", &json!({"family": "ipx"}));
        assert!(bad.is_err());
        let o = s.ext::<OffLock>().unwrap();
        assert!(o.pending.is_none() && o.accept.is_none() && o.depth == 0);
        assert!(s.execute("ip.route.list", &json!({})).unwrap().is_array());
    }
}
