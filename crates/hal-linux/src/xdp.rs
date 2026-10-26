//! IP › Firewall › XDP (G2.5a): loads `dataplane-ebpf`'s object with aya
//! (userspace, no `unsafe` here), attaches it to the configured interfaces
//! and keeps its maps equal to [`XdpPlan`]: settings, block and allow
//! tries. Reads its counters and the dropped sources back.
//!
//! - Nothing is loaded until an interface is configured: a router without
//!   XDP makes no BPF call at all.
//! - `auto` tries native (driver) mode, then generic; `native` fails where
//!   the driver lacks it (the commit is refused, nothing half-applied).
//! - The links belong to the daemon's process (bpf_link): if it dies, the
//!   kernel detaches the filter and traffic flows unfiltered (fail-open),
//!   never through stale maps.
//! - Tries are synced by difference: a block-list edit costs one map call
//!   per changed prefix, not a reload.

use std::collections::BTreeMap;
use std::net::IpAddr;

use aya::Ebpf;
use aya::maps::lpm_trie::{Key, LpmTrie};
use aya::maps::{Array, PerCpuHashMap, PerCpuValues};
use aya::programs::xdp::XdpLinkId;
use aya::programs::{Xdp as XdpProgram, XdpMode as AttachMode};
use corerouter_dataplane_ebpf_common::fastnat::{self, FlowKey, FlowValue};
use corerouter_dataplane_ebpf_common::filter::{Reason, Settings};
use corerouter_dataplane_ebpf_common::maps as m;
use corerouter_dataplane_ebpf_common::nat::Endpoint;
use corerouter_dataplane_ebpf_common::parse::Addr;
use corerouter_hal::HalError;
use corerouter_hal::xdp::{REASONS, XdpPlan, XdpPort, XdpStatus, XdpTop};
use corerouter_model::firewall::DynamicAddress;
use corerouter_model::xdp::XdpMode;
use corerouter_model::{Config, IfName};
use ipnet::IpNet;

#[path = "xdp_pppoe.rs"]
mod pppoe;
#[path = "xdp_shaper.rs"]
mod shaper;
pub use pppoe::{PppoeCounters, session_of as pppoe_session_of};

/// The XDP object, built by `cargo xtask ebpf` (crates/dataplane-ebpf).
static OBJECT: &[u8] =
    aya::include_bytes_aligned!("../../dataplane-ebpf/prebuilt/corerouter-xdp.o");

/// Why loading failed, in words for the operator (`EPERM` is the usual one).
fn why(e: &dyn std::error::Error) -> String {
    let mut text = e.to_string();
    let mut src = e.source();
    while let Some(s) = src {
        text.push_str(": ");
        text.push_str(&s.to_string());
        src = s.source();
    }
    if text.contains("Operation not permitted") || text.contains("EPERM") {
        text.push_str(
            " (loading XDP needs CAP_BPF and CAP_NET_ADMIN: run the daemon as root or \
             `setcap cap_bpf,cap_net_admin,cap_perfmon+ep corerouter-daemon`)",
        );
    }
    // The verifier's reason is at the end of its log: keep the head and
    // the tail.
    let chars: Vec<char> = text.chars().collect();
    if chars.len() <= 3000 {
        return text;
    }
    let head: String = chars.iter().take(500).collect();
    let tail: String = chars.iter().skip(chars.len() - 2500).collect();
    format!("{head} … {tail}")
}

fn rejected(what: &str, e: &dyn std::error::Error) -> HalError {
    HalError::Rejected(format!("XDP: {what}: {}", why(e)))
}

struct Attached {
    mode: XdpMode,
    active: &'static str,
    note: Option<String>,
    ifindex: u32,
    link: XdpLinkId,
}

struct Loaded {
    ebpf: Ebpf,
    links: BTreeMap<IfName, Attached>,
    /// `NAT_FLOWS` was sized for the fast path (G2.5b); a change reloads.
    fast_nat: bool,
    /// The PPPoE maps were sized for sessions (G4.3c); a change reloads.
    pppoe: bool,
    /// The queue maps were sized for queues (G4.9b), and the PCQ map for
    /// PCQ queues; a change reloads.
    queues: bool,
    pcq: bool,
    /// The tc programs' links (G4.9b, G4.3ca).
    tc: shaper::TcLinks,
}

/// The XDP part of [`crate::LinuxHal`] (public for the root tests and
/// benchmarks, which drive it without a whole config).
#[derive(Default)]
pub struct XdpState {
    loaded: Option<Loaded>,
    applied: XdpPlan,
    /// The config of the last sync, for dynamic address-list changes.
    cfg: Option<Config>,
    dynamic: Vec<DynamicAddress>,
    /// The last load failure, for the status.
    error: Option<String>,
    /// The CGNAT fast path's flow map, shared with the daemon's link.
    nat: SharedNat,
    /// PPPoE subscribers (G4.3c, `xdp_pppoe.rs`): on, and the sessions
    /// the maps hold (written again after a reload).
    pppoe: pppoe::PppoeState,
    /// Queues and `bng0` (G4.9b, G4.3ca, `xdp_shaper.rs`).
    shaper: shaper::ShaperState,
}

impl std::fmt::Debug for XdpState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("XdpState")
            .field("loaded", &self.loaded.as_ref().map(|l| l.links.len()))
            .field("applied", &self.applied)
            .field("error", &self.error)
            .finish()
    }
}

impl XdpState {
    /// Make the data plane hold what `cfg` asks for.
    pub fn sync(&mut self, cfg: &Config) -> Result<(), HalError> {
        let plan = XdpPlan::of(cfg, &self.dynamic);
        self.cfg = Some(cfg.clone());
        self.reach(plan)
    }

    /// A dynamic address-list entry came or went: the tries follow, if the
    /// filter is on.
    pub fn dynamic(&mut self, change: corerouter_hal::DynamicChange<'_>) {
        use corerouter_hal::DynamicChange;
        match change {
            DynamicChange::Add(d) => {
                self.dynamic
                    .retain(|x| x.list != d.list || x.address != d.address);
                self.dynamic.push(d.clone());
            }
            DynamicChange::Remove(d) => {
                self.dynamic
                    .retain(|x| x.list != d.list || x.address != d.address);
            }
            DynamicChange::Expired(gone) => {
                self.dynamic.retain(|x| {
                    !gone
                        .iter()
                        .any(|g| g.list == x.list && g.address == x.address)
                });
            }
        }
        let Some(cfg) = self.cfg.clone() else {
            return;
        };
        if let Err(e) = self.reach(XdpPlan::of(&cfg, &self.dynamic)) {
            log::error!("XDP: dynamic address list: {e}");
        }
    }

    fn reach(&mut self, plan: XdpPlan) -> Result<(), HalError> {
        self.reach_with(plan, false)
    }

    /// `strict`: a shaper failure is the caller's error (`shaper_apply`);
    /// otherwise it is only recorded (the shaper never fails a config
    /// apply, an XDP filter change or a PPPoE session).
    fn reach_with(&mut self, plan: XdpPlan, strict: bool) -> Result<(), HalError> {
        let shaping = self.shaper.wanted();
        let sized = |l: &Loaded, st: &Self| {
            l.fast_nat == plan.fast_nat
                && l.pppoe == st.pppoe.maps()
                && l.queues == st.shaper.queues()
                && l.pcq == st.shaper.pcq()
        };
        if plan == self.applied
            && !shaping
            && self.shaper.idle()
            && (plan.is_empty() || self.loaded.as_ref().is_some_and(|l| sized(l, self)))
        {
            return Ok(());
        }
        if plan.is_empty() && !shaping {
            // Dropping the object detaches every link and frees the maps.
            self.loaded = None;
            self.set_nat(None);
            self.applied = plan;
            self.shaper.reloaded();
            return self.shaper.reach(None, false, false);
        }
        // The flow map, the session maps and the queue maps are
        // preallocated: sized only while in use, so a change reloads the
        // object (links come back in this same call).
        let pppoe = self.pppoe.maps();
        if self.loaded.as_ref().is_some_and(|l| !sized(l, self)) {
            self.loaded = None;
            self.set_nat(None);
        }
        if self.loaded.is_none() {
            match load(
                plan.fast_nat,
                pppoe,
                self.shaper.queues(),
                self.shaper.pcq(),
            ) {
                Ok(mut l) => {
                    pppoe::refill(&mut l.ebpf, &self.pppoe)?;
                    shaper::refill_sessions(&mut l.ebpf, &self.shaper, self.pppoe.sessions())?;
                    let map = if l.fast_nat {
                        take_nat(&mut l.ebpf)?
                    } else {
                        None
                    };
                    self.set_nat(map);
                    self.loaded = Some(l);
                    self.error = None;
                    // Fresh maps: everything goes in.
                    self.applied = XdpPlan::default();
                    self.shaper.reloaded();
                }
                Err(e) => {
                    // Only the queues wanted it: that is the shaper's
                    // failure, not the filter's.
                    if plan.is_empty() && !strict {
                        self.shaper.set_error(Some(e.to_string()));
                        return Ok(());
                    }
                    self.error = Some(e.to_string());
                    return Err(e);
                }
            }
        }
        let Some(l) = self.loaded.as_mut() else {
            return Ok(());
        };
        write_settings(&mut l.ebpf, &plan, self.pppoe.word())?;
        pppoe::sync_ports(&mut l.ebpf, &self.pppoe)?;
        sync_trie(
            &mut l.ebpf,
            m::BLOCK_V4,
            m::BLOCK_V6,
            &self.applied.block,
            &plan.block,
        )?;
        sync_trie(
            &mut l.ebpf,
            m::ALLOW_V4,
            m::ALLOW_V6,
            &self.applied.allow,
            &plan.allow,
        )?;
        // The maps are right whatever happens to the links below.
        self.applied.block = plan.block.clone();
        self.applied.allow = plan.allow.clone();
        attach_all(l, &plan.interfaces)?;
        self.applied = plan;
        let on = self.pppoe.maps();
        match self.shaper.reach(self.loaded.as_mut(), self.pppoe.on, on) {
            Err(e) if !strict => {
                log::warn!("shaper: {e}");
                self.shaper.set_error(Some(e.to_string()));
                Ok(())
            }
            Ok(()) => {
                self.shaper.set_error(None);
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    /// Queues (G4.9b): hold `plan`. The object loads for it alone when no
    /// XDP port is configured.
    pub fn shaper_apply(
        &mut self,
        plan: &corerouter_hal::queue::ShaperPlan,
    ) -> Result<(), HalError> {
        if self.shaper.plan == *plan && (plan.is_empty() || self.loaded.is_some()) {
            return Ok(());
        }
        self.shaper.plan = plan.clone();
        let cfg = self.cfg.clone().unwrap_or_default();
        let xdp = XdpPlan::of(&cfg, &self.dynamic);
        self.applied = XdpPlan::default();
        self.reach_with(xdp, true)
    }

    pub fn shaper_status(&mut self) -> corerouter_hal::queue::ShaperStatus {
        self.shaper.status(self.loaded.as_mut())
    }

    pub fn status(&mut self, top: usize) -> XdpStatus {
        let misses = self.nat_misses();
        let Some(l) = self.loaded.as_mut() else {
            return XdpStatus {
                unavailable: self.error.clone(),
                ..XdpStatus::default()
            };
        };
        let counters = read_counters(&mut l.ebpf);
        let ports = l
            .links
            .iter()
            .map(|(name, a)| XdpPort {
                interface: name.clone(),
                mode: a.mode,
                active: Some(a.active),
                note: a.note.clone(),
                counters: REASONS
                    .iter()
                    .enumerate()
                    .map(|(r, _)| counters.get(&(a.ifindex, r)).copied().unwrap_or((0, 0)))
                    .collect(),
            })
            .collect();
        let lists = self
            .cfg
            .as_ref()
            .map(|c| c.ip.xdp.filter.block_lists.clone())
            .unwrap_or_default();
        XdpStatus {
            unavailable: None,
            ports,
            top: if top == 0 {
                Vec::new()
            } else {
                read_top(&mut l.ebpf, top, &lists)
            },
            block_prefixes: self.applied.block.len(),
            fast_nat_flows: lock_nat(&self.nat).count(),
            fast_nat_misses: misses,
            allow_prefixes: self.applied.allow.len(),
        }
    }

    pub fn reset(&mut self) -> Result<(), HalError> {
        let Some(l) = self.loaded.as_mut() else {
            return Ok(());
        };
        let ifindexes: Vec<u32> = l.links.values().map(|a| a.ifindex).collect();
        zero_counters(&mut l.ebpf, &ifindexes)?;
        let map = l
            .ebpf
            .map_mut(m::TOP)
            .ok_or_else(|| HalError::Rejected("XDP: no TOP map".into()))?;
        let mut top = PerCpuHashMap::<_, [u8; 16], m::Top>::try_from(map)
            .map_err(|e| rejected("TOP map", &e))?;
        let keys: Vec<[u8; 16]> = top.keys().filter_map(Result::ok).collect();
        for k in keys {
            let _ = top.remove(&k);
        }
        Ok(())
    }
}

pub use corerouter_hal::xdp_nat::{FlowUse, NatFlow};

/// The fast path's flow map (owned: taken out of the object at load).
type NatMap = aya::maps::HashMap<aya::maps::MapData, FlowKey, FlowValue>;

/// The fast path's flow map, shared by the loader and the daemon's link
/// (`xdp_nat`): `None` while the fast path is off; `generation` changes
/// with every new map (a reload empties it, and the link must refill it).
#[derive(Default)]
pub(crate) struct NatSlot {
    pub generation: u64,
    pub map: Option<NatMap>,
}

pub(crate) type SharedNat = std::sync::Arc<std::sync::Mutex<NatSlot>>;

pub(crate) fn lock_nat(slot: &SharedNat) -> std::sync::MutexGuard<'_, NatSlot> {
    slot.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn take_nat(ebpf: &mut Ebpf) -> Result<Option<NatMap>, HalError> {
    let map = ebpf
        .take_map(m::NAT_FLOWS)
        .ok_or_else(|| HalError::Rejected("XDP: no NAT_FLOWS map".into()))?;
    NatMap::try_from(map)
        .map(Some)
        .map_err(|e| rejected("NAT_FLOWS map", &e))
}

pub(crate) fn flow_key(f: &NatFlow) -> FlowKey {
    fastnat::key(
        f.proto,
        f.src.0.octets(),
        f.dst.0.octets(),
        f.src.1,
        f.dst.1,
    )
}

fn endpoint((a, p): (std::net::Ipv4Addr, u16)) -> Endpoint {
    Endpoint {
        addr: a.octets(),
        port: p,
    }
}

impl NatSlot {
    fn map(&mut self) -> Result<&mut NatMap, HalError> {
        self.map
            .as_mut()
            .ok_or_else(|| HalError::Rejected("XDP: the CGNAT fast path is off".into()))
    }

    pub(crate) fn install(&mut self, flows: &[NatFlow]) -> Result<(), HalError> {
        let map = self.map()?;
        for f in flows {
            map.insert(
                flow_key(f),
                fastnat::value(endpoint(f.new_src), endpoint(f.new_dst)),
                0,
            )
            .map_err(|e| rejected("NAT_FLOWS insert", &e))?;
        }
        Ok(())
    }

    pub(crate) fn remove(&mut self, flows: &[NatFlow]) -> Result<(), HalError> {
        let map = self.map()?;
        for f in flows {
            let _ = map.remove(&flow_key(f));
        }
        Ok(())
    }

    pub(crate) fn used(&mut self, flow: &NatFlow) -> Option<FlowUse> {
        let map = self.map.as_ref()?;
        map.get(&flow_key(flow), 0)
            .ok()
            .map(|[_, _, last_ns, packets]| FlowUse { last_ns, packets })
    }

    pub(crate) fn count(&self) -> usize {
        self.map
            .as_ref()
            .map_or(0, |m| m.keys().filter(Result::is_ok).count())
    }
}

impl XdpState {
    fn set_nat(&self, map: Option<NatMap>) {
        let mut slot = lock_nat(&self.nat);
        slot.generation = slot.generation.wrapping_add(1);
        slot.map = map;
    }

    /// The flow map's slot, for the daemon's link (`xdp_nat`).
    pub(crate) fn nat_slot(&self) -> SharedNat {
        self.nat.clone()
    }

    /// The fast path's link to this map and to conntrack (what the
    /// daemon's service gets through `Hal::xdp_nat_link`).
    pub fn nat_link(&self) -> Result<Box<dyn corerouter_hal::xdp_nat::NatLink>, HalError> {
        Ok(Box::new(crate::xdp_nat::LinuxNatLink::open(
            self.nat_slot(),
        )?))
    }

    /// Put flow directions in the fast path (replacing what a key held).
    pub fn nat_install(&mut self, flows: &[NatFlow]) -> Result<(), HalError> {
        lock_nat(&self.nat).install(flows)
    }

    /// Take flow directions out (one already gone is not an error).
    pub fn nat_remove(&mut self, flows: &[NatFlow]) -> Result<(), HalError> {
        lock_nat(&self.nat).remove(flows)
    }

    /// What the fast path did with `flow` (`None`: not there).
    pub fn nat_use(&mut self, flow: &NatFlow) -> Result<Option<FlowUse>, HalError> {
        Ok(lock_nat(&self.nat).used(flow))
    }

    /// Flow directions in the fast path now.
    pub fn nat_count(&mut self) -> usize {
        lock_nat(&self.nat).count()
    }

    /// Why packets of known flows went to the kernel, by reason (only the
    /// reasons seen), summed over the CPUs.
    pub fn nat_misses(&mut self) -> Vec<(&'static str, u64)> {
        let Some(l) = self.loaded.as_mut().filter(|l| l.fast_nat) else {
            return Vec::new();
        };
        let Some(map) = l.ebpf.map_mut(m::NAT_MISS) else {
            return Vec::new();
        };
        let Ok(arr) = aya::maps::PerCpuArray::<_, u64>::try_from(map) else {
            return Vec::new();
        };
        fastnat::MISS_NAMES
            .iter()
            .enumerate()
            .filter(|(_, name)| !name.is_empty())
            .filter_map(|(i, name)| {
                let total: u64 = arr.get(&(i as u32), 0).ok()?.iter().sum();
                (total > 0).then_some((*name, total))
            })
            .collect()
    }

    /// Run the loaded program on `frame` `repeat` times in the kernel
    /// (`BPF_PROG_TEST_RUN`), with its maps as they are: the XDP action
    /// (1 drop, 2 pass) and the mean time per run. For tests and
    /// benchmarks; needs the filter loaded (an interface configured).
    pub fn test_run(
        &mut self,
        frame: &[u8],
        repeat: u32,
    ) -> Result<(u32, std::time::Duration), HalError> {
        self.test_run_on(frame, repeat, None)
    }

    /// [`XdpState::test_run`] as if the frame arrived on interface
    /// `ingress` (its index): the CGNAT fast path's FIB lookup starts there.
    pub fn test_run_on(
        &mut self,
        frame: &[u8],
        repeat: u32,
        ingress: Option<u32>,
    ) -> Result<(u32, std::time::Duration), HalError> {
        self.test_run_out(frame, repeat, ingress)
            .map(|(action, took, _)| (action, took))
    }

    /// [`XdpState::test_run_on`], with the frame as the program left it
    /// (decapsulated, encapsulated, rewritten) — the PPPoE differential
    /// test compares it byte for byte (G4.3c).
    pub fn test_run_out(
        &mut self,
        frame: &[u8],
        repeat: u32,
        ingress: Option<u32>,
    ) -> Result<(u32, std::time::Duration, Vec<u8>), HalError> {
        use aya::programs::{TestRun, TestRunOptions};
        // `struct xdp_md`: data, data_end, data_meta, ingress_ifindex,
        // rx_queue_index, egress_ifindex.
        let ctx: Option<Vec<u8>> = ingress.map(|i| {
            let len = u32::try_from(frame.len()).unwrap_or(u32::MAX);
            [0u32, len, 0, i, 0, 0]
                .iter()
                .flat_map(|w| w.to_ne_bytes())
                .collect()
        });
        let l = self
            .loaded
            .as_mut()
            .ok_or_else(|| HalError::Rejected("XDP: not loaded".into()))?;
        let prog: &mut XdpProgram = l
            .ebpf
            .program_mut(m::PROGRAM)
            .ok_or_else(|| HalError::Rejected("XDP: program gone".into()))?
            .try_into()
            .map_err(|e| rejected("program type", &e))?;
        let mut out = vec![0u8; frame.len() + 256];
        let r = prog
            .test_run(TestRunOptions {
                data_in: Some(frame),
                data_out: Some(&mut out),
                ctx_in: ctx.as_deref(),
                repeat: repeat.max(1),
                ..TestRunOptions::default()
            })
            .map_err(|e| rejected("test run", &e))?;
        out.truncate(r.data_size_out as usize);
        Ok((r.return_value, r.duration, out))
    }
}

fn load(fast_nat: bool, pppoe: bool, queues: bool, pcq: bool) -> Result<Loaded, HalError> {
    let flows = if fast_nat { m::NAT_FLOWS_MAX } else { 1 };
    let mut loader = aya::EbpfLoader::new();
    loader.map_max_entries(m::NAT_FLOWS, flows);
    if !pppoe {
        for name in m::PPPOE_SIZED.into_iter().chain(m::SUB_SIZED) {
            loader.map_max_entries(name, 1);
        }
        loader.map_max_entries(m::PPPOE_V6, 1);
        loader.map_max_entries(m::PPPOE_RT4, 1);
        loader.map_max_entries(m::PPPOE_RT6, 1);
        loader.map_max_entries(m::PPPOE_POLICER, 2);
    }
    if !queues {
        loader.map_max_entries(m::Q_CONF, 1);
        loader.map_max_entries(m::Q_STATE, 2);
        loader.map_max_entries(m::Q_COUNT, 2);
    }
    if !pcq {
        loader.map_max_entries(m::Q_PCQ, 1);
    }
    let mut ebpf = loader
        .load(OBJECT)
        .map_err(|e| rejected("loading the object", &e))?;
    let prog: &mut XdpProgram = ebpf
        .program_mut(m::PROGRAM)
        .ok_or_else(|| HalError::Rejected(format!("XDP: no program {} in the object", m::PROGRAM)))?
        .try_into()
        .map_err(|e| rejected("program type", &e))?;
    prog.load()
        .map_err(|e| rejected("the kernel refused the program", &e))?;
    Ok(Loaded {
        ebpf,
        links: BTreeMap::new(),
        fast_nat,
        pppoe,
        queues,
        pcq,
        tc: shaper::TcLinks::default(),
    })
}

/// `subscribers`: the PPPoE/IPoE switches (`PppoeState::word`).
fn write_settings(ebpf: &mut Ebpf, plan: &XdpPlan, subscribers: u64) -> Result<(), HalError> {
    let s = Settings {
        drop_malformed: plan.drop_malformed,
        drop_bad_tcp_flags: plan.drop_invalid_tcp_flags,
        block: !plan.block.is_empty(),
        allow: !plan.allow.is_empty(),
        rate_pps: plan.rate_limit,
        burst: plan.rate_burst,
        fast_nat: plan.fast_nat,
    };
    let map = ebpf
        .map_mut(m::SETTINGS)
        .ok_or_else(|| HalError::Rejected("XDP: no SETTINGS map".into()))?;
    let mut arr = Array::<_, u64>::try_from(map).map_err(|e| rejected("SETTINGS map", &e))?;
    for (i, w) in s.to_words().iter().enumerate() {
        arr.set(i as u32, w, 0)
            .map_err(|e| rejected("writing the settings", &e))?;
    }
    arr.set(
        corerouter_dataplane_ebpf_common::pppoe::SETTINGS_SLOT,
        subscribers,
        0,
    )
    .map_err(|e| rejected("writing the settings", &e))
}

/// Make tries `v4`/`v6` go from `from` to `to`: removals, then inserts
/// and changed list indexes.
fn sync_trie(
    ebpf: &mut Ebpf,
    v4: &str,
    v6: &str,
    from: &[(IpNet, u32)],
    to: &[(IpNet, u32)],
) -> Result<(), HalError> {
    let old: BTreeMap<IpNet, u32> = from.iter().copied().collect();
    let new: BTreeMap<IpNet, u32> = to.iter().copied().collect();
    let gone = old.keys().filter(|k| !new.contains_key(k));
    let put = new.iter().filter(|(k, v)| old.get(k) != Some(v));
    let mut t4 = LpmTrie::<_, [u8; 4], u32>::try_from(
        ebpf.map_mut(v4)
            .ok_or_else(|| HalError::Rejected(format!("XDP: no {v4} map")))?,
    )
    .map_err(|e| rejected(v4, &e))?;
    let mut removed6 = Vec::new();
    for n in gone {
        match n {
            IpNet::V4(n) => {
                let _ = t4.remove(&Key::new(u32::from(n.prefix_len()), n.network().octets()));
            }
            IpNet::V6(n) => removed6.push(*n),
        }
    }
    let mut put6 = Vec::new();
    for (n, list) in put {
        match n {
            IpNet::V4(n) => t4
                .insert(
                    &Key::new(u32::from(n.prefix_len()), n.network().octets()),
                    list,
                    0,
                )
                .map_err(|e| rejected(&format!("{v4} insert {n}"), &e))?,
            IpNet::V6(n) => put6.push((*n, *list)),
        }
    }
    let mut t6 = LpmTrie::<_, [u8; 16], u32>::try_from(
        ebpf.map_mut(v6)
            .ok_or_else(|| HalError::Rejected(format!("XDP: no {v6} map")))?,
    )
    .map_err(|e| rejected(v6, &e))?;
    for n in removed6 {
        let _ = t6.remove(&Key::new(u32::from(n.prefix_len()), n.network().octets()));
    }
    for (n, list) in put6 {
        t6.insert(
            &Key::new(u32::from(n.prefix_len()), n.network().octets()),
            list,
            0,
        )
        .map_err(|e| rejected(&format!("{v6} insert {n}"), &e))?;
    }
    Ok(())
}

fn ifindex(name: &IfName) -> Result<u32, HalError> {
    let path = format!("/sys/class/net/{name}/ifindex");
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|t| t.trim().parse().ok())
        .ok_or_else(|| HalError::Rejected(format!("XDP: no interface {name} in the kernel")))
}

/// Attach to every interface of `want` (in its mode), detach from the rest.
fn attach_all(l: &mut Loaded, want: &[(IfName, XdpMode)]) -> Result<(), HalError> {
    let prog: &mut XdpProgram = l
        .ebpf
        .program_mut(m::PROGRAM)
        .ok_or_else(|| HalError::Rejected("XDP: program gone".into()))?
        .try_into()
        .map_err(|e| rejected("program type", &e))?;
    let stale: Vec<IfName> = l
        .links
        .iter()
        .filter(|(name, a)| !want.iter().any(|(n, mode)| n == *name && *mode == a.mode))
        .map(|(n, _)| n.clone())
        .collect();
    for name in stale {
        if let Some(a) = l.links.remove(&name)
            && let Err(e) = prog.detach(a.link)
        {
            log::warn!("XDP: detaching from {name}: {}", why(&e));
        }
    }
    let mut fresh = Vec::new();
    for (name, mode) in want {
        if l.links.contains_key(name) {
            continue;
        }
        let index = ifindex(name)?;
        let try_mode = |prog: &mut XdpProgram, m: AttachMode| prog.attach_to_if_index(index, m);
        let attached = match mode {
            XdpMode::Native => try_mode(prog, AttachMode::Driver)
                .map(|id| (id, "native", None))
                .map_err(|e| rejected(&format!("native mode on {name}"), &e))?,
            XdpMode::Generic => try_mode(prog, AttachMode::Skb)
                .map(|id| (id, "generic", None))
                .map_err(|e| rejected(&format!("generic mode on {name}"), &e))?,
            XdpMode::Auto => match try_mode(prog, AttachMode::Driver) {
                Ok(id) => (id, "native", None),
                Err(native) => {
                    let note = format!("native mode refused ({}); running generic", why(&native));
                    let id = try_mode(prog, AttachMode::Skb)
                        .map_err(|e| rejected(&format!("generic mode on {name}"), &e))?;
                    (id, "generic", Some(note))
                }
            },
        };
        let (link, active, note) = attached;
        l.links.insert(
            name.clone(),
            Attached {
                mode: *mode,
                active,
                note,
                ifindex: index,
                link,
            },
        );
        fresh.push(index);
    }
    // Counters exist before the first packet: exact from the start, no
    // per-CPU insert race in the program.
    if !fresh.is_empty() {
        zero_counters(&mut l.ebpf, &fresh)?;
    }
    Ok(())
}

fn zero_counters(ebpf: &mut Ebpf, ifindexes: &[u32]) -> Result<(), HalError> {
    let cpus = aya::util::nr_cpus().map_err(|(what, e)| rejected(what, &e))?;
    let map = ebpf
        .map_mut(m::COUNTERS)
        .ok_or_else(|| HalError::Rejected("XDP: no COUNTERS map".into()))?;
    let mut c = PerCpuHashMap::<_, u64, m::Counter>::try_from(map)
        .map_err(|e| rejected("COUNTERS map", &e))?;
    for i in ifindexes {
        for r in Reason::ALL {
            let zero = PerCpuValues::try_from(vec![[0u64; 2]; cpus])
                .map_err(|e| rejected("per-CPU values", &e))?;
            c.insert(m::counter_key(*i, r), zero, 0)
                .map_err(|e| rejected("zeroing the counters", &e))?;
        }
    }
    Ok(())
}

/// `(packets, bytes)` by (ifindex, reason index), summed over the CPUs.
fn read_counters(ebpf: &mut Ebpf) -> BTreeMap<(u32, usize), (u64, u64)> {
    let mut out = BTreeMap::new();
    let Some(map) = ebpf.map_mut(m::COUNTERS) else {
        return out;
    };
    let Ok(c) = PerCpuHashMap::<_, u64, m::Counter>::try_from(map) else {
        return out;
    };
    for (key, values) in c.iter().filter_map(Result::ok) {
        let (ifindex, Some(reason)) = m::split_counter_key(key) else {
            continue;
        };
        let sum = values.iter().fold((0u64, 0u64), |(p, b), [vp, vb]| {
            (p.saturating_add(*vp), b.saturating_add(*vb))
        });
        out.insert((ifindex, reason as usize), sum);
    }
    out
}

/// CLOCK_MONOTONIC in nanoseconds: `bpf_ktime_get_ns`'s clock.
fn monotonic_ns() -> u64 {
    let t = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    u64::try_from(t.tv_sec)
        .unwrap_or(0)
        .saturating_mul(1_000_000_000)
        .saturating_add(u64::try_from(t.tv_nsec).unwrap_or(0))
}

fn read_top(ebpf: &mut Ebpf, n: usize, lists: &[corerouter_model::firewall::Name]) -> Vec<XdpTop> {
    let Some(map) = ebpf.map_mut(m::TOP) else {
        return Vec::new();
    };
    let Ok(t) = PerCpuHashMap::<_, [u8; 16], m::Top>::try_from(map) else {
        return Vec::new();
    };
    let now = monotonic_ns();
    let mut rows: Vec<XdpTop> = t
        .iter()
        .filter_map(Result::ok)
        .map(|(key, values)| {
            let (mut packets, mut bytes, mut last, mut tag) = (0u64, 0u64, 0u64, 0u64);
            for [p, b, at, tg] in values.iter() {
                packets = packets.saturating_add(*p);
                bytes = bytes.saturating_add(*b);
                if *at >= last && *p > 0 {
                    last = *at;
                    tag = *tg;
                }
            }
            let (reason, list) = m::split_top_tag(tag);
            let address = match Addr::from_mapped(key) {
                Addr::V4(a) => IpAddr::from(a),
                Addr::V6(a) => IpAddr::from(a),
            };
            XdpTop {
                address,
                packets,
                bytes,
                reason: reason
                    .map(|r| REASONS.get(r as usize).copied().unwrap_or("?"))
                    .unwrap_or("?"),
                list: list.and_then(|i| lists.get(i as usize).cloned()),
                last_secs: now.saturating_sub(last) / 1_000_000_000,
            }
        })
        .collect();
    rows.sort_by(|a, b| b.packets.cmp(&a.packets).then(a.address.cmp(&b.address)));
    rows.truncate(n);
    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The constants the program was built with are the ones the model
    /// validates against.
    #[test]
    fn limits_agree_with_the_model() {
        assert_eq!(
            corerouter_hal::xdp_nat::MAX_CARRIED * 2,
            m::NAT_FLOWS_MAX as usize,
            "two flow directions per carried connection"
        );
        assert_eq!(
            m::MAX_INTERFACES as usize,
            corerouter_model::xdp::MAX_INTERFACES
        );
        assert_eq!(REASONS.len(), Reason::ALL.len());
        for r in Reason::ALL {
            assert_eq!(REASONS[r as usize], r.name());
        }
        assert!(
            u64::from(corerouter_model::xdp::MAX_RATE)
                <= corerouter_dataplane_ebpf_common::bucket::MAX_RATE
        );
        assert!(
            u64::from(corerouter_model::xdp::MAX_BURST)
                <= corerouter_dataplane_ebpf_common::bucket::MAX_BURST
        );
    }

    /// The XDP crates are GPL-2.0-or-later and the object says "GPL" to the
    /// kernel (GPL-only helpers such as bpf_fib_lookup); the rest stays
    /// AGPL (docs/xdp.md § Licença).
    #[test]
    fn the_xdp_crates_and_object_are_gpl() {
        let obj = aya_obj::Object::parse(OBJECT).unwrap();
        assert_eq!(obj.license.to_str().unwrap(), "GPL");
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        for c in ["dataplane-ebpf", "dataplane-ebpf-common", "cgnat-map"] {
            let toml = std::fs::read_to_string(root.join(c).join("Cargo.toml")).unwrap();
            assert!(toml.contains("license = \"GPL-2.0-or-later\""), "{c}");
        }
        let own = std::fs::read_to_string(root.join("hal-linux/Cargo.toml")).unwrap();
        assert!(
            own.contains("license.workspace = true"),
            "hal-linux stays AGPL"
        );
    }

    /// The embedded object parses and has the program and every map.
    #[test]
    fn the_object_has_the_program_and_maps() {
        let obj = aya_obj::Object::parse(OBJECT).unwrap();
        assert!(
            obj.programs.contains_key(m::PROGRAM),
            "{:?}",
            obj.programs.keys()
        );
        for name in [
            m::SETTINGS,
            m::BLOCK_V4,
            m::BLOCK_V6,
            m::ALLOW_V4,
            m::ALLOW_V6,
            m::RATE,
            m::COUNTERS,
            m::TOP,
            m::NAT_FLOWS,
            m::NAT_MISS,
        ] {
            assert!(
                obj.maps.contains_key(name),
                "map {name}: {:?}",
                obj.maps.keys()
            );
        }
    }
}
