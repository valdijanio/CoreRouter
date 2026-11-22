//! CGNAT mapping history (G2.3): which pool definitions were in force
//! when, so "who was 203.0.113.7:40312 at 14:02 on 3 May?" is answered by
//! the formula of *that* moment, not today's.
//!
//! RFC 7422 §3: a deterministic CGN MUST record every change of the
//! inside and outside ranges, the ports per subscriber, the algorithm and
//! the reserved ports, with the time. Each commit that changes the running
//! pools or exceptions appends one epoch (the whole CGNAT section, a few
//! hundred bytes) to its own journal, `journal-cgnat-history.log`, kept
//! for `ip.firewall.cgnat.set history_days` (a year by default: Marco
//! Civil, Lei 12.965/2014 art. 13). Operational state, never in a revision
//! (the 64 revisions of the config history are far too few for a year).

use std::net::Ipv4Addr;

use corerouter_model::cgnat::{Cgnat, Mode, Slot};
use serde::{Deserialize, Serialize};

use crate::Session;

/// The journal's name (`journal-cgnat-history.log`).
pub const JOURNAL: &str = "cgnat-history";
/// Epochs kept in memory (a commit a minute for two months, **estimado**);
/// the oldest beyond this are dropped from memory, not from the journal
/// until it is compacted.
pub const MAX_EPOCHS: usize = 100_000;
/// A journal line longer than this is skipped (hostile or damaged file).
const MAX_LINE: usize = 1 << 20;

/// The part of the section that decides mappings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Epoch {
    /// Unix time it came into force (0: before the clock was known).
    pub t: u64,
    pub cgnat: Cgnat,
}

fn mapping_part(c: &Cgnat) -> Cgnat {
    Cgnat {
        pools: c.pools.clone(),
        exceptions: c.exceptions.clone(),
        settings: Default::default(),
        next_id: 0,
    }
}

#[derive(Debug, Default)]
pub struct CgnatHistory {
    epochs: Vec<Epoch>,
    loaded: bool,
    error: Option<String>,
}

impl CgnatHistory {
    pub fn epochs(&self) -> &[Epoch] {
        &self.epochs
    }

    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    /// The epoch in force at `t`, and when the next one began.
    pub fn at(&self, t: u64) -> Option<(&Epoch, Option<u64>)> {
        let i = self.epochs.partition_point(|e| e.t <= t).checked_sub(1)?;
        let e = self.epochs.get(i)?;
        Some((e, self.epochs.get(i + 1).map(|n| n.t)))
    }

    /// Replay journal lines; returns how many were unreadable.
    fn replay(&mut self, text: &str) -> usize {
        let mut bad = 0;
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            if line.len() > MAX_LINE {
                bad += 1;
                continue;
            }
            match serde_json::from_str::<Epoch>(line) {
                Ok(e) => self.push(e),
                Err(_) => bad += 1,
            }
        }
        bad
    }

    fn push(&mut self, e: Epoch) {
        if self.epochs.last().is_some_and(|l| l.cgnat == e.cgnat) {
            return;
        }
        // A clock that went back keeps the order: the new epoch starts no
        // earlier than the last one.
        let t = self.epochs.last().map_or(e.t, |l| e.t.max(l.t));
        self.epochs.push(Epoch { t, ..e });
        if self.epochs.len() > MAX_EPOCHS {
            self.epochs.remove(0);
        }
    }

    /// Drop epochs that ended before `cutoff` (the one in force at the
    /// cutoff stays). Whether anything went.
    fn expire(&mut self, cutoff: u64) -> bool {
        let keep_from = self
            .epochs
            .partition_point(|e| e.t <= cutoff)
            .saturating_sub(1);
        if keep_from == 0 {
            return false;
        }
        self.epochs.drain(..keep_from);
        true
    }

    fn text(&self) -> String {
        let mut out = String::new();
        for e in &self.epochs {
            if let Ok(line) = serde_json::to_string(e) {
                out.push_str(&line);
                out.push('\n');
            }
        }
        out
    }
}

/// The answer to "who was": one per pool or exception that held the
/// address and port at that time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WhoWas {
    pub subscriber: Ipv4Addr,
    /// Pool name, or `exception` for a 1:1 mapping.
    pub via: String,
    pub mode: &'static str,
    /// The subscriber's whole slot (an exception has every port).
    pub slot: Slot,
    /// When this mapping came into force and, if it changed since, when it
    /// ended.
    pub since: u64,
    pub until: Option<u64>,
}

/// "Who was" over one epoch's definitions.
pub fn lookup(c: &Cgnat, public: Ipv4Addr, port: u16) -> Result<(Ipv4Addr, String, Mode, Slot), String> {
    if let Some(e) = c.exceptions.iter().find(|e| !e.disabled && e.public == public) {
        return Ok((
            e.subscriber,
            "exception".into(),
            Mode::Deterministic,
            Slot {
                public,
                first_port: 0,
                last_port: u16::MAX,
            },
        ));
    }
    let Some(pool) = c
        .pools
        .iter()
        .filter(|p| !p.disabled)
        .find(|p| p.outside.iter().any(|r| r.contains(public)))
    else {
        return Err(format!("{public} was not a public address of any pool"));
    };
    let layout = pool
        .layout()
        .map_err(|e| format!("pool '{}' could not be laid out: {e}", pool.name))?;
    if pool.mode == Mode::Blocks {
        return Err(format!(
            "pool '{}' hands out blocks on demand: the block log answers (ip.firewall.cgnat.block.history)",
            pool.name
        ));
    }
    let Some(sub) = layout.reverse(public, port) else {
        return Err(format!(
            "port {port} of {public} belonged to no subscriber of pool '{}' (outside its port range or unused)",
            pool.name
        ));
    };
    let slot = layout.forward(sub).ok_or_else(|| "no slot".to_owned())?;
    // A subscriber with a 1:1 exception never used its pool slot.
    if c.exception_of(sub).is_some() {
        return Err(format!(
            "port {port} of {public} is the slot of {sub}, which had a 1:1 exception: nobody used it"
        ));
    }
    Ok((sub, pool.name.clone(), pool.mode, slot))
}

impl Session {
    fn cgnat_history_load(&mut self) {
        if self.ext::<CgnatHistory>().is_some_and(|h| h.loaded) {
            return;
        }
        let text = self.storage_mut().load_journal(JOURNAL);
        if let Some(h) = self.ext_mut::<CgnatHistory>() {
            h.loaded = true;
            match text {
                Ok(Some(t)) => {
                    let bad = h.replay(&t);
                    if bad > 0 {
                        log::warn!("cgnat history: {bad} unreadable journal lines skipped");
                    }
                }
                Ok(None) => {}
                Err(e) => h.error = Some(e.to_string()),
            }
        }
    }

    /// Record the running pools if they changed since the last epoch
    /// (called after every commit, rollback and Safe Mode undo).
    pub(crate) fn cgnat_note(&mut self) {
        let now = self.now().unwrap_or(0);
        let running = mapping_part(&self.store().running().ip.cgnat);
        let empty = running.pools.is_empty() && running.exceptions.is_empty();
        self.cgnat_history_load();
        let retention = u64::from(self.store().running().ip.cgnat.settings.history_days) * 86_400;
        let Some(h) = self.ext_mut::<CgnatHistory>() else {
            return;
        };
        // Nothing configured and nothing recorded: no file appears for a
        // router without CGNAT.
        if h.epochs.last().is_some_and(|l| l.cgnat == running) || (h.epochs.is_empty() && empty) {
            return;
        }
        let epoch = Epoch { t: now, cgnat: running };
        let line = serde_json::to_string(&epoch).unwrap_or_default();
        h.push(epoch);
        let rewrite = retention > 0 && now > retention && h.expire(now - retention);
        let text = rewrite.then(|| h.text());
        let result = match text {
            Some(t) => self.storage_mut().rewrite_journal(JOURNAL, &t),
            None => self.storage_mut().append_journal(JOURNAL, &format!("{line}\n")),
        };
        if let Some(h) = self.ext_mut::<CgnatHistory>() {
            h.error = result.err().map(|e| {
                log::error!("cgnat history not saved: {e}");
                e.to_string()
            });
        }
    }

    /// The mapping history (loaded on first use).
    pub fn cgnat_history(&mut self) -> Option<&CgnatHistory> {
        self.cgnat_history_load();
        self.ext::<CgnatHistory>()
    }

    /// "Who was" `public`:`port` at `at` (now when absent).
    pub fn cgnat_who_was(&mut self, public: Ipv4Addr, port: u16, at: Option<u64>) -> Result<WhoWas, String> {
        self.cgnat_note();
        let now = self.now().unwrap_or(0);
        let t = at.unwrap_or(now);
        let h = self
            .cgnat_history()
            .ok_or_else(|| "the history is not available".to_owned())?;
        let Some((epoch, until)) = h.at(t) else {
            let first = h.epochs().first().map(|e| e.t);
            return Err(match first {
                Some(f) => format!("no CGNAT record before {f} (unix): the history starts there"),
                None => "no CGNAT pool has ever been configured".into(),
            });
        };
        let since = epoch.t;
        // Blocks mode: the block log answers (who held the block then).
        let blocks_pool = epoch
            .cgnat
            .pools
            .iter()
            .find(|p| !p.disabled && p.mode == Mode::Blocks && p.outside.iter().any(|r| r.contains(public)))
            .map(|p| p.name.clone());
        if let Some(name) = blocks_pool {
            let Some(r) = self.cgnat_block_who_was(public, port, t) else {
                return Err(format!(
                    "no block of pool '{name}' held port {port} of {public} at that time"
                ));
            };
            return Ok(WhoWas {
                subscriber: r.subscriber,
                via: r.pool,
                mode: Mode::Blocks.as_str(),
                slot: r.slot,
                since: r.from,
                until: r.until,
            });
        }
        let (subscriber, via, mode, slot) = lookup(&epoch.cgnat, public, port)?;
        Ok(WhoWas {
            subscriber,
            via,
            mode: mode.as_str(),
            slot,
            since,
            until,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch(t: u64, n: u32) -> Epoch {
        let mut c = Cgnat {
            next_id: n,
            ..Default::default()
        };
        c.exceptions.push(corerouter_model::cgnat::Exception {
            id: corerouter_model::ItemId(n),
            subscriber: Ipv4Addr::new(100, 64, 0, 1),
            public: Ipv4Addr::new(203, 0, 113, u8::try_from(n).unwrap()),
            disabled: false,
            comment: String::new(),
        });
        Epoch { t, cgnat: c }
    }

    #[test]
    fn the_epoch_in_force_is_found_and_old_ones_expire() {
        let mut h = CgnatHistory::default();
        h.push(epoch(100, 1));
        h.push(epoch(200, 2));
        h.push(epoch(200, 2)); // same: not a new epoch
        h.push(epoch(150, 3)); // clock went back: starts at 200
        assert_eq!(h.epochs().len(), 3);
        assert!(h.at(99).is_none());
        assert_eq!(h.at(100).map(|(e, u)| (e.t, u)), Some((100, Some(200))));
        assert_eq!(h.at(5000).map(|(e, u)| (e.t, u)), Some((200, None)));
        assert!(h.expire(250));
        assert_eq!(h.epochs().len(), 1);
        let text = h.text();
        let mut back = CgnatHistory::default();
        assert_eq!(back.replay(&format!("{text}garbage\n")), 1);
        assert_eq!(back.epochs(), h.epochs());
    }
}
