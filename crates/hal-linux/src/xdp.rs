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
use corerouter_dataplane_ebpf_common::filter::{Reason, Settings};
use corerouter_dataplane_ebpf_common::maps as m;
use corerouter_dataplane_ebpf_common::parse::Addr;
use corerouter_hal::HalError;
use corerouter_hal::xdp::{REASONS, XdpPlan, XdpPort, XdpStatus, XdpTop};
use corerouter_model::firewall::DynamicAddress;
use corerouter_model::xdp::XdpMode;
use corerouter_model::{Config, IfName};
use ipnet::IpNet;

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
    text.chars().take(2000).collect()
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
        if plan == self.applied && (plan.is_empty() || self.loaded.is_some()) {
            return Ok(());
        }
        if plan.is_empty() {
            // Dropping the object detaches every link and frees the maps.
            self.loaded = None;
            self.applied = plan;
            return Ok(());
        }
        if self.loaded.is_none() {
            match load() {
                Ok(l) => {
                    self.loaded = Some(l);
                    self.error = None;
                    // Fresh maps: everything goes in.
                    self.applied = XdpPlan::default();
                }
                Err(e) => {
                    self.error = Some(e.to_string());
                    return Err(e);
                }
            }
        }
        let Some(l) = self.loaded.as_mut() else {
            return Ok(());
        };
        write_settings(&mut l.ebpf, &plan)?;
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
        Ok(())
    }

    pub fn status(&mut self, top: usize) -> XdpStatus {
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

impl XdpState {
    /// Run the loaded program on `frame` `repeat` times in the kernel
    /// (`BPF_PROG_TEST_RUN`), with its maps as they are: the XDP action
    /// (1 drop, 2 pass) and the mean time per run. For tests and
    /// benchmarks; needs the filter loaded (an interface configured).
    pub fn test_run(
        &mut self,
        frame: &[u8],
        repeat: u32,
    ) -> Result<(u32, std::time::Duration), HalError> {
        use aya::programs::{TestRun, TestRunOptions};
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
                repeat: repeat.max(1),
                ..TestRunOptions::default()
            })
            .map_err(|e| rejected("test run", &e))?;
        Ok((r.return_value, r.duration))
    }
}

fn load() -> Result<Loaded, HalError> {
    let mut ebpf = Ebpf::load(OBJECT).map_err(|e| rejected("loading the object", &e))?;
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
    })
}

fn write_settings(ebpf: &mut Ebpf, plan: &XdpPlan) -> Result<(), HalError> {
    let s = Settings {
        drop_malformed: plan.drop_malformed,
        drop_bad_tcp_flags: plan.drop_invalid_tcp_flags,
        block: !plan.block.is_empty(),
        allow: !plan.allow.is_empty(),
        rate_pps: plan.rate_limit,
        burst: plan.rate_burst,
    };
    let map = ebpf
        .map_mut(m::SETTINGS)
        .ok_or_else(|| HalError::Rejected("XDP: no SETTINGS map".into()))?;
    let mut arr = Array::<_, u64>::try_from(map).map_err(|e| rejected("SETTINGS map", &e))?;
    for (i, w) in s.to_words().iter().enumerate() {
        arr.set(i as u32, w, 0)
            .map_err(|e| rejected("writing the settings", &e))?;
    }
    Ok(())
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
        ] {
            assert!(
                obj.maps.contains_key(name),
                "map {name}: {:?}",
                obj.maps.keys()
            );
        }
    }
}
