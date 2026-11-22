//! The responder's tap in tc (G3.9db): the `lsp_tap` classifier of the
//! XDP object (`crates/dataplane-ebpf`) on the ingress of each MPLS
//! interface copies the candidate frames (`lsp_tap::keep`, the decision
//! of the classic filters) to the `LSP_TAP` ring buffer, read here.
//!
//! Why: the `AF_PACKET` taps, even unbound, made the kernel call
//! `packet_rcv` (a reference on the skb, the filter, the release) for
//! every frame of their protocol on the host: −19% of MPLS switching on one
//! core (G3.9d, **medido**). The classifier runs only on the interfaces it
//! is attached to, a few loads and compares, and the frame is never shared.
//!
//! - **Its own load of the object**, every other map at its smallest (the
//!   XDP filter and the shaper keep theirs, loaded by `xdp.rs`): a few KiB
//!   besides the 1 MiB ring buffer.
//! - **Fail-open:** the links belong to this process; if the daemon dies,
//!   the kernel detaches the program and traffic goes on untouched.
//! - **No root, old kernel, no `CAP_BPF`:** [`EbpfTap::open`] fails and the
//!   responder keeps the `AF_PACKET` taps (`host.rs`).

use std::collections::BTreeMap;
use std::os::fd::{AsFd, BorrowedFd};

use aya::maps::{Array, MapData, PerCpuArray, RingBuf};
use aya::programs::SchedClassifier;
use aya::programs::tc::{self, SchedClassifierLinkId, TcAttachType};
use corerouter_dataplane_ebpf_common::lsp_tap::{self, Settings, Stat};
use corerouter_dataplane_ebpf_common::maps as m;
use corerouter_model::IfName;

/// Records read per wake-up (a flood cannot stall the loop).
const BUDGET: usize = 256;

fn text(what: &str, e: &dyn std::error::Error) -> String {
    let mut t = format!("{what}: {e}");
    let mut src = e.source();
    while let Some(s) = src {
        t.push_str(": ");
        t.push_str(&s.to_string());
        src = s.source();
    }
    t
}

/// The loaded classifier, its ring buffer and where it is attached.
pub(super) struct EbpfTap {
    ebpf: aya::Ebpf,
    ring: RingBuf<MapData>,
    settings: Array<MapData, u64>,
    stats: PerCpuArray<MapData, u64>,
    links: BTreeMap<IfName, SchedClassifierLinkId>,
    big: Option<u32>,
}

impl EbpfTap {
    /// Load the object (maps other than the tap's at their smallest) and
    /// the classifier. `Err`: why not (no `CAP_BPF`, an old kernel…), for
    /// the responder to fall back to packet sockets.
    pub(super) fn open() -> Result<Self, String> {
        let obj =
            aya_obj::Object::parse(crate::xdp::OBJECT).map_err(|e| text("the eBPF object", &e))?;
        let mut loader = aya::EbpfLoader::new();
        let names: Vec<&str> = obj
            .maps
            .iter()
            .filter(|(n, map)| {
                !n.starts_with("LSP_TAP") && map.section_kind() == aya_obj::EbpfSectionKind::Maps
            })
            .map(|(n, _)| n.as_str())
            .collect();
        for n in &names {
            loader.map_max_entries(n, 1);
        }
        let mut ebpf = loader
            .load(crate::xdp::OBJECT)
            .map_err(|e| text("loading the eBPF object", &e))?;
        let p: &mut SchedClassifier = ebpf
            .program_mut(m::LSP_TAP_PROGRAM)
            .ok_or_else(|| format!("no program {} in the object", m::LSP_TAP_PROGRAM))?
            .try_into()
            .map_err(|e| text("program type", &e))?;
        p.load()
            .map_err(|e| text("the kernel refused the LSP tap", &e))?;
        let mut take = |name: &str| {
            ebpf.take_map(name)
                .ok_or_else(|| format!("no map {name} in the object"))
        };
        let ring = RingBuf::try_from(take(m::LSP_TAP)?).map_err(|e| text(m::LSP_TAP, &e))?;
        let settings =
            Array::try_from(take(m::LSP_TAP_SET)?).map_err(|e| text(m::LSP_TAP_SET, &e))?;
        let stats = PerCpuArray::try_from(take(m::LSP_TAP_STATS)?)
            .map_err(|e| text(m::LSP_TAP_STATS, &e))?;
        Ok(Self {
            ebpf,
            ring,
            settings,
            stats,
            links: BTreeMap::new(),
            big: None,
        })
    }

    fn program(&mut self) -> Option<&mut SchedClassifier> {
        self.ebpf
            .program_mut(m::LSP_TAP_PROGRAM)
            .and_then(|p| p.try_into().ok())
    }

    /// Attach to `names` (tc ingress), detach from the others; the ones
    /// it could not attach to, and why.
    pub(super) fn listen(&mut self, names: &[IfName]) -> Vec<(IfName, String)> {
        let stale: Vec<IfName> = self
            .links
            .keys()
            .filter(|n| !names.contains(n))
            .cloned()
            .collect();
        for n in stale {
            if let Some(id) = self.links.remove(&n)
                && let Some(p) = self.program()
                && let Err(e) = p.detach(id)
            {
                log::warn!("LSP tap: detaching from {n}: {e}");
            }
        }
        let mut failed = Vec::new();
        for n in names {
            if self.links.contains_key(n) {
                continue;
            }
            // Before tcx (6.6) the classifier needs the clsact qdisc; it
            // may be there already (the shaper's).
            let _ = tc::qdisc_add_clsact(n.as_str());
            let Some(p) = self.program() else {
                failed.push((n.clone(), "the LSP tap program is gone".to_owned()));
                continue;
            };
            match p.attach(n.as_str(), TcAttachType::Ingress) {
                Ok(id) => {
                    self.links.insert(n.clone(), id);
                }
                Err(e) => failed.push((n.clone(), text("attaching the LSP tap", &e))),
            }
        }
        failed
    }

    /// Also keep MPLS frames longer than `frame_len` (G3.9da).
    pub(super) fn set_big(&mut self, frame_len: Option<u32>) {
        if frame_len == self.big {
            return;
        }
        let word = Settings {
            big: frame_len.unwrap_or(0),
        }
        .to_word();
        if self.settings.set(0, word, 0).is_ok() {
            self.big = frame_len;
        }
    }

    pub(super) fn big(&self) -> Option<u32> {
        self.big
    }

    pub(super) fn fd(&self) -> BorrowedFd<'_> {
        self.ring.as_fd()
    }

    /// The records waiting, at most [`BUDGET`]: `(ifindex, frame)` each.
    pub(super) fn drain(&mut self, mut each: impl FnMut(u32, &[u8])) {
        for _ in 0..BUDGET {
            let Some(item) = self.ring.next() else { break };
            if let Some((ifindex, _len, frame)) = lsp_tap::record(&item) {
                each(ifindex, frame);
            }
        }
    }

    /// Frames copied, and candidates lost to a full ring buffer.
    pub(super) fn stats(&self) -> (u64, u64) {
        let sum = |s: Stat| {
            self.stats
                .get(&(s as u32), 0)
                .map(|v| v.iter().sum::<u64>())
                .unwrap_or(0)
        };
        (sum(Stat::Kept), sum(Stat::Full))
    }
}
