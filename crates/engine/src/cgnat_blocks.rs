//! CGNAT port blocks on demand and port alerts (G2.3c).
//!
//! **Blocks mode** (port block allocation, RFC 6888 §5, REQ-13/14): a
//! subscriber gets a block of `ports_per_subscriber` ports (the same
//! geometry as the deterministic formula, `Layout::block`) when its first
//! packet arrives ([`Session::cgnat_block_for`], called by the daemon's
//! queue thread, or by the tick for the lab's pretend subscribers); a
//! second one when the current one is [`GROW_PERCENT`] full, up to
//! `max_blocks`; a block without connections for `block_timeout` is
//! released and held back for [`HOLD_SECS`] before anyone else gets it
//! (RFC 6888 REQ-8). Every block of one subscriber is on the same public
//! address (paired pooling, RFC 6888 REQ-2).
//!
//! Each allocation and release is one line in the router's log (topic
//! `cgnat`, so `/system logging` can send it to a remote syslog) and in
//! the block journal (`journal-cgnat-blocks.log`), which "who was" reads
//! for blocks-mode pools and which rebuilds the active blocks at boot.
//!
//! **Port alerts** (both modes, RFC 7422 §2.2): a subscriber using
//! `alert_percent` of its ports (its slot, or its last allowed block) is
//! logged once per crossing and listed with how many times it happened.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};

use corerouter_hal::cgnat::BlockChange;
use corerouter_hal::conntrack::status;
use corerouter_model::ItemId;
use corerouter_model::cgnat::{Mode, Pool, Slot};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::Session;

/// The journal's name (`journal-cgnat-blocks.log`).
pub const JOURNAL: &str = "cgnat-blocks";
/// RFC 6888 REQ-8: a released port is not handed out again for 120 s.
pub const HOLD_SECS: u64 = 120;
/// A subscriber's current block this full gets it a new one.
pub const GROW_PERCENT: u64 = 80;
/// The usage scan (a conntrack read) runs at most this often.
pub const SCAN_SECS: u64 = 10;
/// Block records kept in memory (a year of a busy CGN, **estimado**);
/// older ones stay in the journal until compacted.
pub const MAX_RECORDS: usize = 1_000_000;
/// Alerts listed at most.
pub const MAX_ALERTS: usize = 10_000;
const MAX_LINE: usize = 4096;

/// One line of the block journal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub t: u64,
    /// `alloc` | `release`.
    pub e: String,
    pub pool: String,
    pub sub: Ipv4Addr,
    pub public: Ipv4Addr,
    pub first: u16,
    pub last: u16,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub why: String,
}

/// One block a subscriber holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    pub pool: ItemId,
    pub pool_name: String,
    pub address: u64,
    pub block: u32,
    pub slot: Slot,
    pub since: u64,
    /// No connection in it since then.
    pub empty_since: Option<u64>,
}

/// A block's life, for "who was".
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Record {
    pub pool: String,
    pub subscriber: Ipv4Addr,
    pub slot: Slot,
    pub from: u64,
    pub until: Option<u64>,
}

/// A subscriber that ran out of ports (or close to it).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Alert {
    pub subscriber: Ipv4Addr,
    pub pool: String,
    pub used: u64,
    pub ports: u64,
    pub percent: u64,
    pub peak: u64,
    /// Times it crossed the threshold.
    pub crossings: u64,
    pub first: u64,
    pub last: u64,
    /// Above the threshold at the last scan.
    pub above: bool,
    /// Above at the scan before (a crossing is "not then, now").
    #[serde(skip)]
    was_above: bool,
}

#[derive(Debug, Default)]
pub struct CgnatRuntime {
    loaded: bool,
    /// Kernel elements re-sent after the load.
    installed: bool,
    /// Per subscriber, its blocks; the last one is the current.
    active: BTreeMap<Ipv4Addr, Vec<Block>>,
    /// Taken blocks: (pool, address, block).
    taken: HashSet<(ItemId, u64, u32)>,
    /// Blocks per public address of each pool (paired allocation).
    per_address: HashMap<ItemId, Vec<u32>>,
    /// Released blocks held back until then.
    hold: Vec<((ItemId, u64, u32), u64)>,
    records: Vec<Record>,
    alerts: BTreeMap<Ipv4Addr, Alert>,
    last_scan: Option<u64>,
    /// The running pools at the last tick: a change releases the blocks
    /// whose geometry left at once, not at the next scan.
    pools_seen: Vec<Pool>,
    /// `insert_failed` of the kernel at the last scan and the growth since
    /// the first: new connections that found no free NAT tuple.
    insert_failed: Option<(u64, u64)>,
    pub error: Option<String>,
}

impl CgnatRuntime {
    pub fn active(&self) -> &BTreeMap<Ipv4Addr, Vec<Block>> {
        &self.active
    }

    pub fn records(&self) -> &[Record] {
        &self.records
    }

    pub fn alerts(&self) -> &BTreeMap<Ipv4Addr, Alert> {
        &self.alerts
    }

    pub fn insert_failed(&self) -> u64 {
        self.insert_failed.map_or(0, |(_, grew)| grew)
    }

    fn replay(&mut self, text: &str, pools: &[Pool]) -> usize {
        let mut bad = 0;
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            if line.len() > MAX_LINE {
                bad += 1;
                continue;
            }
            match serde_json::from_str::<Event>(line) {
                Ok(e) => self.apply(&e, pools),
                Err(_) => bad += 1,
            }
        }
        bad
    }

    /// Fold one event into the state (journal replay and live).
    fn apply(&mut self, e: &Event, pools: &[Pool]) {
        let slot = Slot {
            public: e.public,
            first_port: e.first,
            last_port: e.last,
        };
        match e.e.as_str() {
            "alloc" => {
                self.records.push(Record {
                    pool: e.pool.clone(),
                    subscriber: e.sub,
                    slot,
                    from: e.t,
                    until: None,
                });
                if self.records.len() > MAX_RECORDS {
                    self.records.remove(0);
                }
                // Active only while the pool still lays the block out the
                // same way (a changed pool forgets its blocks).
                let Some(p) = pools.iter().find(|p| p.name == e.pool && p.mode == Mode::Blocks) else {
                    return;
                };
                let Ok(l) = p.layout() else { return };
                let Some((address, block)) = l.locate(e.public, e.first) else {
                    return;
                };
                if l.block(address, block) != Some(slot) {
                    return;
                }
                self.take(p.id, address, block, l.public_addresses());
                self.active.entry(e.sub).or_default().push(Block {
                    pool: p.id,
                    pool_name: p.name.clone(),
                    address,
                    block,
                    slot,
                    since: e.t,
                    empty_since: None,
                });
            }
            "release" => {
                if let Some(r) = self
                    .records
                    .iter_mut()
                    .rev()
                    .find(|r| r.subscriber == e.sub && r.slot == slot && r.until.is_none())
                {
                    r.until = Some(e.t);
                }
                let mut freed = None;
                if let Some(blocks) = self.active.get_mut(&e.sub) {
                    if let Some(i) = blocks.iter().position(|b| b.slot == slot) {
                        let b = blocks.remove(i);
                        freed = Some((b.pool, b.address, b.block));
                    }
                    if blocks.is_empty() {
                        self.active.remove(&e.sub);
                    }
                }
                if let Some(key) = freed {
                    self.untake(key);
                    self.hold.push((key, e.t.saturating_add(HOLD_SECS)));
                }
            }
            _ => {}
        }
    }

    fn take(&mut self, pool: ItemId, address: u64, block: u32, addresses: u64) {
        if self.taken.insert((pool, address, block)) {
            let counts = self
                .per_address
                .entry(pool)
                .or_insert_with(|| vec![0; usize::try_from(addresses).unwrap_or(0)]);
            if let Some(c) = counts.get_mut(usize::try_from(address).unwrap_or(usize::MAX)) {
                *c = c.saturating_add(1);
            }
        }
    }

    fn untake(&mut self, key: (ItemId, u64, u32)) {
        if self.taken.remove(&key)
            && let Some(c) = self
                .per_address
                .get_mut(&key.0)
                .and_then(|v| v.get_mut(usize::try_from(key.1).unwrap_or(usize::MAX)))
        {
            *c = c.saturating_sub(1);
        }
    }

    fn held(&self, key: (ItemId, u64, u32), now: u64) -> bool {
        self.hold.iter().any(|(k, until)| *k == key && *until > now)
    }

    /// A free block for a subscriber of `p`: on `address` if given (its
    /// other blocks' address), else on the public address with the fewest
    /// blocks taken.
    fn free_block(&self, p: &Pool, l: &corerouter_model::cgnat::Layout, address: Option<u64>, now: u64) -> Option<(u64, u32)> {
        let on = |a: u64| {
            (0..l.per_address()).find(|b| {
                let key = (p.id, a, *b);
                !self.taken.contains(&key) && !self.held(key, now)
            })
        };
        if let Some(a) = address {
            return on(a).map(|b| (a, b));
        }
        let counts = self.per_address.get(&p.id);
        let mut order: Vec<u64> = (0..l.public_addresses()).collect();
        order.sort_by_key(|a| {
            counts
                .and_then(|c| c.get(usize::try_from(*a).unwrap_or(usize::MAX)))
                .copied()
                .unwrap_or(0)
        });
        order.into_iter().find_map(|a| on(a).map(|b| (a, b)))
    }

    fn text(&self) -> String {
        // Compaction keeps what is still needed: the records (with their
        // ends) of the retention window.
        let mut out = String::new();
        for r in &self.records {
            let mut ev = Event {
                t: r.from,
                e: "alloc".into(),
                pool: r.pool.clone(),
                sub: r.subscriber,
                public: r.slot.public,
                first: r.slot.first_port,
                last: r.slot.last_port,
                why: String::new(),
            };
            if let Ok(line) = serde_json::to_string(&ev) {
                out.push_str(&line);
                out.push('\n');
            }
            if let Some(u) = r.until {
                ev.t = u;
                ev.e = "release".into();
                if let Ok(line) = serde_json::to_string(&ev) {
                    out.push_str(&line);
                    out.push('\n');
                }
            }
        }
        out
    }
}

/// The public port (or ICMP id) a srcnat connection uses.
fn public_port(c: &corerouter_hal::conntrack::Conn) -> u16 {
    if matches!(c.protocol, 1 | 58) {
        c.reply.src_port
    } else {
        c.reply.dst_port
    }
}

impl Session {
    fn blocks_load(&mut self) {
        if self.ext::<CgnatRuntime>().is_some_and(|r| r.loaded) {
            return;
        }
        let pools = self.store().running().ip.cgnat.pools.clone();
        let text = self.storage_mut().load_journal(JOURNAL);
        if let Some(rt) = self.ext_mut::<CgnatRuntime>() {
            rt.loaded = true;
            match text {
                Ok(Some(t)) => {
                    let bad = rt.replay(&t, &pools);
                    if bad > 0 {
                        log::warn!("cgnat blocks: {bad} unreadable journal lines skipped");
                    }
                }
                Ok(None) => {}
                Err(e) => rt.error = Some(e.to_string()),
            }
        }
    }

    /// The block runtime (loaded on first use).
    pub fn cgnat_blocks(&mut self) -> Option<&CgnatRuntime> {
        self.blocks_load();
        self.ext::<CgnatRuntime>()
    }

    fn block_event(&mut self, e: Event) {
        let line = serde_json::to_string(&e).unwrap_or_default();
        let level = "info";
        let message = format!(
            "{} {} {} {}:{}-{} pool {}{}",
            if e.e == "alloc" { "ALLOC" } else { "RELEASE" },
            e.sub,
            if e.e == "alloc" { "->" } else { "<-" },
            e.public,
            e.first,
            e.last,
            e.pool,
            if e.why.is_empty() { String::new() } else { format!(" ({})", e.why) }
        );
        self.log_event(
            &["cgnat", level],
            "cgnat",
            message,
            json!({"event": e.e, "subscriber": e.sub, "public": e.public, "first_port": e.first, "last_port": e.last, "pool": e.pool}),
        );
        if let Err(err) = self.storage_mut().append_journal(JOURNAL, &format!("{line}\n")) {
            log::error!("cgnat block journal not saved: {err}");
            if let Some(rt) = self.ext_mut::<CgnatRuntime>() {
                rt.error = Some(err.to_string());
            }
        }
    }

    fn push_blocks(&mut self, changes: &[BlockChange]) {
        if changes.is_empty() {
            return;
        }
        if let Err(e) = self.hal_mut().cgnat_blocks(changes) {
            log::warn!("cgnat: the data plane did not take {} block changes: {e}", changes.len());
        }
    }

    /// The block of `subscriber` (allocated now if it has none): what the
    /// queue thread asks for a subscriber's first packet. `Err` when it is
    /// not in a blocks-mode pool or the pool has no free block (the packet
    /// is dropped: RFC 6888 REQ-11).
    pub fn cgnat_block_for(&mut self, subscriber: Ipv4Addr, now: u64) -> Result<Slot, String> {
        self.blocks_load();
        if let Some(b) = self
            .ext::<CgnatRuntime>()
            .and_then(|r| r.active.get(&subscriber))
            .and_then(|v| v.last())
        {
            // Already allocated (two packets raced, or the kernel lost the
            // element): make sure the kernel has it.
            let (pool, slot) = (b.pool, b.slot);
            self.push_blocks(&[BlockChange { pool, subscriber, slot: Some(slot) }]);
            return Ok(slot);
        }
        self.allocate(subscriber, now, "first packet")
    }

    fn allocate(&mut self, subscriber: Ipv4Addr, now: u64, why: &str) -> Result<Slot, String> {
        let cgnat = self.store().running().ip.cgnat.clone();
        if cgnat.exception_of(subscriber).is_some() {
            return Err(format!("{subscriber} has a 1:1 exception"));
        }
        let pool = cgnat
            .pool_of(subscriber)
            .filter(|p| p.mode == Mode::Blocks)
            .ok_or_else(|| format!("{subscriber} is in no blocks-mode pool"))?
            .clone();
        let layout = pool.layout().map_err(|e| e.to_string())?;
        let Some(rt) = self.ext_mut::<CgnatRuntime>() else {
            return Err("no runtime".into());
        };
        rt.hold.retain(|(_, until)| *until > now);
        let mine: Vec<Block> = rt.active.get(&subscriber).cloned().unwrap_or_default();
        if mine.len() >= usize::from(pool.max_blocks) {
            return Err(format!("{subscriber} holds {} blocks, the most allowed", mine.len()));
        }
        let Some((address, block)) = rt.free_block(&pool, &layout, mine.last().map(|b| b.address), now) else {
            return Err(format!("pool '{}' has no free block", pool.name));
        };
        let Some(slot) = layout.block(address, block) else {
            return Err("block out of range".into());
        };
        rt.take(pool.id, address, block, layout.public_addresses());
        rt.active.entry(subscriber).or_default().push(Block {
            pool: pool.id,
            pool_name: pool.name.clone(),
            address,
            block,
            slot,
            since: now,
            empty_since: None,
        });
        rt.records.push(Record {
            pool: pool.name.clone(),
            subscriber,
            slot,
            from: now,
            until: None,
        });
        if rt.records.len() > MAX_RECORDS {
            rt.records.remove(0);
        }
        self.block_event(Event {
            t: now,
            e: "alloc".into(),
            pool: pool.name.clone(),
            sub: subscriber,
            public: slot.public,
            first: slot.first_port,
            last: slot.last_port,
            why: why.into(),
        });
        self.push_blocks(&[BlockChange { pool: pool.id, subscriber, slot: Some(slot) }]);
        Ok(slot)
    }

    fn release(&mut self, subscriber: Ipv4Addr, slot: Slot, now: u64, why: &str) {
        self.release_with(subscriber, slot, now, why, true);
    }

    /// Release a block; `hold`: keep it from anyone else for [`HOLD_SECS`]
    /// (RFC 6888 REQ-8). A block whose geometry left is not held: its
    /// connections are killed instead (as a deterministic remap does).
    fn release_with(&mut self, subscriber: Ipv4Addr, slot: Slot, now: u64, why: &str, hold: bool) {
        let pools = self.store().running().ip.cgnat.pools.clone();
        let Some(rt) = self.ext_mut::<CgnatRuntime>() else { return };
        let Some(b) = rt.active.get(&subscriber).and_then(|v| v.iter().find(|b| b.slot == slot)).cloned() else {
            return;
        };
        let e = Event {
            t: now,
            e: "release".into(),
            pool: b.pool_name.clone(),
            sub: subscriber,
            public: slot.public,
            first: slot.first_port,
            last: slot.last_port,
            why: why.into(),
        };
        rt.apply(&e, &pools);
        if !hold {
            rt.hold.retain(|(k, _)| *k != (b.pool, b.address, b.block));
        }
        let next = rt.active.get(&subscriber).and_then(|v| v.last()).map(|b| b.slot);
        self.block_event(e);
        // The map points to the newest block left, or to nothing.
        self.push_blocks(&[BlockChange { pool: b.pool, subscriber, slot: next }]);
    }

    /// Release every block of pools that changed or left: their geometry
    /// is gone (called by the tick when the running pools differ).
    fn blocks_forget_stale(&mut self, now: u64) {
        let pools = self.store().running().ip.cgnat.pools.clone();
        let stale: Vec<(Ipv4Addr, Slot)> = self
            .ext::<CgnatRuntime>()
            .map(|rt| {
                rt.active
                    .iter()
                    .flat_map(|(sub, v)| v.iter().map(move |b| (*sub, b)))
                    .filter(|(_, b)| {
                        pools
                            .iter()
                            .find(|p| p.id == b.pool && p.mode == Mode::Blocks && !p.disabled)
                            .and_then(|p| p.layout().ok())
                            .and_then(|l| l.block(b.address, b.block))
                            != Some(b.slot)
                    })
                    .map(|(sub, b)| (sub, b.slot))
                    .collect()
            })
            .unwrap_or_default();
        let mut moved: Vec<Ipv4Addr> = Vec::new();
        for (sub, slot) in stale {
            self.release_with(sub, slot, now, "pool changed", false);
            moved.push(sub);
        }
        if !moved.is_empty()
            && let Ok((conns, _)) = self.connections(true)
        {
            let victims: Vec<_> = conns
                .iter()
                .filter(|c| c.has(status::SRC_NAT))
                .filter(|c| matches!(c.orig.src, IpAddr::V4(a) if moved.contains(&a)))
                .cloned()
                .collect();
            if let Err(e) = self.hal_mut().connections_kill(&victims) {
                log::warn!("cgnat: connections of released blocks not killed: {e}");
            }
        }
    }

    /// The periodic work: install the active blocks after a boot, hand
    /// blocks to waiting subscribers, and every [`SCAN_SECS`] read the
    /// connections to grow, release and alert.
    pub(crate) fn cgnat_tick(&mut self, now: u64) {
        let cgnat = &self.store().running().ip.cgnat;
        if cgnat.pools.is_empty() && self.ext::<CgnatRuntime>().is_none_or(|r| r.active.is_empty() && r.alerts.is_empty()) {
            return;
        }
        self.blocks_load();
        if self.ext::<CgnatRuntime>().is_some_and(|r| !r.installed) {
            self.blocks_forget_stale(now);
            let all: Vec<BlockChange> = self
                .ext::<CgnatRuntime>()
                .map(|r| {
                    r.active
                        .iter()
                        .filter_map(|(sub, v)| v.last().map(|b| BlockChange { pool: b.pool, subscriber: *sub, slot: Some(b.slot) }))
                        .collect()
                })
                .unwrap_or_default();
            self.push_blocks(&all);
            if let Some(r) = self.ext_mut::<CgnatRuntime>() {
                r.installed = true;
            }
        }
        let changed = self
            .ext::<CgnatRuntime>()
            .is_some_and(|r| r.pools_seen != self.store().running().ip.cgnat.pools);
        if changed {
            self.blocks_forget_stale(now);
            let pools = self.store().running().ip.cgnat.pools.clone();
            if let Some(r) = self.ext_mut::<CgnatRuntime>() {
                r.pools_seen = pools;
            }
        }
        for w in self.hal_mut().cgnat_waiting() {
            if let Err(e) = self.allocate(w.subscriber, now, "first packet") {
                log::debug!("cgnat: {e}");
            }
        }
        let due = self
            .ext::<CgnatRuntime>()
            .is_some_and(|r| r.last_scan.is_none_or(|t| now.saturating_sub(t) >= SCAN_SECS));
        if due {
            if let Some(r) = self.ext_mut::<CgnatRuntime>() {
                r.last_scan = Some(now);
            }
            self.blocks_forget_stale(now);
            self.cgnat_scan(now);
            self.blocks_compact(now);
        }
    }

    /// Usage per subscriber from the kernel's connections.
    fn cgnat_scan(&mut self, now: u64) {
        let Ok((conns, stats)) = self.connections(false) else {
            return;
        };
        let cgnat = self.store().running().ip.cgnat.clone();
        let pools: Vec<(Pool, corerouter_model::cgnat::Layout)> = cgnat
            .pools
            .iter()
            .filter(|p| !p.disabled)
            .filter_map(|p| p.layout().ok().map(|l| (p.clone(), l)))
            .collect();
        // Distinct public ports per (subscriber, protocol) and per
        // (subscriber, slot).
        let mut ports: HashMap<(Ipv4Addr, u8), HashSet<u16>> = HashMap::new();
        let mut in_slot: HashMap<(Ipv4Addr, Ipv4Addr, u16), HashSet<(u8, u16)>> = HashMap::new();
        for c in conns.iter().filter(|c| c.has(status::SRC_NAT)) {
            let (IpAddr::V4(sub), IpAddr::V4(public)) = (c.orig.src, c.reply.dst) else {
                continue;
            };
            let port = public_port(c);
            ports.entry((sub, c.protocol)).or_default().insert(port);
            if let Some((p, l)) = pools.iter().find(|(p, _)| p.mode == Mode::Blocks && p.inside.iter().any(|r| r.contains(sub)))
                && let Some((a, b)) = l.locate(public, port)
                && let Some(slot) = l.block(a, b)
            {
                let _ = p;
                in_slot.entry((sub, slot.public, slot.first_port)).or_default().insert((c.protocol, port));
            }
        }
        let busiest = |sub: Ipv4Addr| -> u64 {
            [6u8, 17, 1]
                .iter()
                .map(|pr| ports.get(&(sub, *pr)).map_or(0, HashSet::len) as u64)
                .max()
                .unwrap_or(0)
        };
        // Blocks: grow, release, empty tracking.
        let mut grow: Vec<Ipv4Addr> = Vec::new();
        let mut release: Vec<(Ipv4Addr, Slot, &'static str)> = Vec::new();
        if let Some(rt) = self.ext_mut::<CgnatRuntime>() {
            for (sub, blocks) in rt.active.iter_mut() {
                let n = blocks.len();
                for (i, b) in blocks.iter_mut().enumerate() {
                    let Some((p, _)) = pools.iter().find(|(p, _)| p.id == b.pool) else { continue };
                    let used_set = in_slot.get(&(*sub, b.slot.public, b.slot.first_port));
                    let used = [6u8, 17, 1]
                        .iter()
                        .map(|pr| used_set.map_or(0, |s| s.iter().filter(|(p, _)| p == pr).count()))
                        .max()
                        .unwrap_or(0) as u64;
                    if used == 0 {
                        let since = *b.empty_since.get_or_insert(now);
                        if now.saturating_sub(since) >= u64::from(p.block_timeout) {
                            release.push((*sub, b.slot, "idle"));
                        }
                    } else {
                        b.empty_since = None;
                        let size = u64::from(b.slot.ports());
                        if i + 1 == n && used.saturating_mul(100) >= size.saturating_mul(GROW_PERCENT) && n < usize::from(p.max_blocks) {
                            grow.push(*sub);
                        }
                    }
                }
            }
        }
        for (sub, slot, why) in release {
            self.release(sub, slot, now, why);
        }
        for sub in grow {
            if let Err(e) = self.allocate(sub, now, "block full") {
                log::debug!("cgnat: {e}");
            }
        }
        // Alerts: deterministic subscribers against their slot, blocks
        // subscribers at their last allowed block.
        let mut crossed: Vec<Alert> = Vec::new();
        let active = self.ext::<CgnatRuntime>().map(|r| r.active.clone()).unwrap_or_default();
        let subscribers: HashSet<Ipv4Addr> = ports.keys().map(|(s, _)| *s).collect();
        if let Some(rt) = self.ext_mut::<CgnatRuntime>() {
            for a in rt.alerts.values_mut() {
                a.was_above = a.above;
                a.above = false;
            }
            for sub in subscribers {
                let Some((p, _)) = pools.iter().find(|(p, _)| p.inside.iter().any(|r| r.contains(sub))) else { continue };
                if p.alert_percent == 0 {
                    continue;
                }
                let (used, size) = match p.mode {
                    Mode::Deterministic => (busiest(sub), u64::from(p.ports_per_subscriber)),
                    Mode::Blocks => {
                        let mine = active.get(&sub).map_or(0, Vec::len);
                        if mine < usize::from(p.max_blocks) {
                            continue;
                        }
                        (busiest(sub), u64::from(p.ports_per_subscriber) * u64::from(p.max_blocks))
                    }
                };
                let percent = used.saturating_mul(100).checked_div(size).unwrap_or(0);
                if percent < u64::from(p.alert_percent) {
                    continue;
                }
                let entry = rt.alerts.entry(sub).or_insert_with(|| Alert {
                    subscriber: sub,
                    pool: p.name.clone(),
                    used,
                    ports: size,
                    percent,
                    peak: used,
                    crossings: 0,
                    first: now,
                    last: now,
                    above: false,
                    was_above: false,
                });
                let was = entry.was_above;
                entry.used = used;
                entry.ports = size;
                entry.percent = percent;
                entry.peak = entry.peak.max(used);
                entry.last = now;
                entry.above = true;
                if !was {
                    entry.crossings += 1;
                    crossed.push(entry.clone());
                }
            }
            if rt.alerts.len() > MAX_ALERTS {
                let mut by_age: Vec<(u64, Ipv4Addr)> = rt.alerts.values().map(|a| (a.last, a.subscriber)).collect();
                by_age.sort();
                for (_, s) in by_age.into_iter().take(rt.alerts.len() - MAX_ALERTS) {
                    rt.alerts.remove(&s);
                }
            }
            rt.insert_failed = Some(match rt.insert_failed {
                None => (stats.insert_failed, 0),
                Some((base, grew)) => (stats.insert_failed, grew.saturating_add(stats.insert_failed.saturating_sub(base))),
            });
        }
        for a in crossed {
            self.log_event(
                &["cgnat", "warning"],
                "cgnat",
                format!(
                    "ports: {} uses {} of {} ports ({} %) in pool {}",
                    a.subscriber, a.used, a.ports, a.percent, a.pool
                ),
                json!({"subscriber": a.subscriber, "used": a.used, "ports": a.ports, "pool": a.pool}),
            );
        }
    }

    /// Drop block records older than the retention and rewrite the journal
    /// (at most once a day).
    fn blocks_compact(&mut self, now: u64) {
        let days = u64::from(self.store().running().ip.cgnat.settings.history_days);
        let cutoff = now.saturating_sub(days * 86_400);
        let text = self.ext_mut::<CgnatRuntime>().and_then(|rt| {
            let before = rt.records.len();
            rt.records.retain(|r| r.until.is_none_or(|u| u >= cutoff));
            (rt.records.len() != before).then(|| rt.text())
        });
        if let Some(t) = text
            && let Err(e) = self.storage_mut().rewrite_journal(JOURNAL, &t)
        {
            log::error!("cgnat block journal not compacted: {e}");
        }
    }

    /// "Who was" in a blocks-mode pool: the block covering `port` of
    /// `public` at `t`.
    pub fn cgnat_block_who_was(&mut self, public: Ipv4Addr, port: u16, t: u64) -> Option<Record> {
        self.blocks_load();
        self.ext::<CgnatRuntime>().and_then(|rt| {
            rt.records
                .iter()
                .rev()
                .find(|r| r.slot.contains(public, port) && r.from <= t && r.until.is_none_or(|u| t < u))
                .cloned()
        })
    }

    /// Forget the alerts (of one subscriber, or all).
    pub(crate) fn cgnat_alerts_clear(&mut self, subscriber: Option<Ipv4Addr>) -> usize {
        let Some(rt) = self.ext_mut::<CgnatRuntime>() else { return 0 };
        match subscriber {
            Some(s) => usize::from(rt.alerts.remove(&s).is_some()),
            None => {
                let n = rt.alerts.len();
                rt.alerts.clear();
                n
            }
        }
    }
}

impl Session {
    /// The data plane's queue of first packets (the daemon's CGNAT
    /// service serves it outside the session lock).
    pub fn cgnat_queue(&mut self) -> Result<Box<dyn corerouter_hal::cgnat::CgnatQueue>, String> {
        self.hal_mut().cgnat_queue().map_err(|e| e.to_string())
    }

    /// Whether any enabled pool hands out blocks.
    pub fn cgnat_has_blocks(&self) -> bool {
        self.store()
            .running()
            .ip
            .cgnat
            .pools
            .iter()
            .any(|p| !p.disabled && p.mode == Mode::Blocks)
    }
}
