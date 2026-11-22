//! System › Tuning, Interfaces (G1.26b) on Linux: each port's rings,
//! queues and interrupt coalescing over ethtool netlink (`RINGS_*`,
//! `CHANNELS_*`, `COALESCE_*`), its `txqueuelen` and root qdisc over
//! rtnetlink, and its `rp_filter` under `/proc/sys/net/ipv4/conf/<port>`.
//! No `ethtool`, no `tc`.
//!
//! Like the kernel parameters ([`crate::tuning`]), the first change of a
//! setting snapshots the port's own value, so taking it out of the config
//! puts it back; a port's change is all or nothing (the groups written
//! before a failure go back).

use std::collections::BTreeMap;

use corerouter_hal::HalError;
use corerouter_hal::tuning::PortTuning;
use corerouter_model::IfName;
use corerouter_model::tuning::{PORT_PARAMS, QDISCS};
use futures_util::TryStreamExt;
use rtnetlink::LinkUnspec;
use rtnetlink::packet_core::{
    NLM_F_ACK, NLM_F_CREATE, NLM_F_REPLACE, NLM_F_REQUEST, NetlinkMessage, NetlinkPayload,
};
use rtnetlink::packet_route::RouteNetlinkMessage;
use rtnetlink::packet_route::link::LinkAttribute;
use rtnetlink::packet_route::tc::{TcAttribute, TcHandle, TcMessage};

use crate::ethtool::Ethtool;
use crate::tuning::Root;

/// How a key is written: keys of one group go in one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Group {
    Rings,
    Channels,
    Coalesce,
    TxQueueLen,
    Qdisc,
    RpFilter,
    /// IRQ affinity, RPS, XPS (G1.26c): files under `/proc` and `/sys`.
    Cpu,
}

fn group(key: &str) -> Option<Group> {
    Some(match key {
        "rx_ring" | "tx_ring" => Group::Rings,
        "rx_channels" | "tx_channels" | "combined_channels" => Group::Channels,
        "adaptive_rx" | "rx_usecs" | "adaptive_tx" | "tx_usecs" => Group::Coalesce,
        "txqueuelen" => Group::TxQueueLen,
        "qdisc" => Group::Qdisc,
        "rp_filter" => Group::RpFilter,
        "irq_affinity" | "rps" | "xps" => Group::Cpu,
        _ => return None,
    })
}

fn rt<T>(f: impl AsyncFnOnce(&mut rtnetlink::Handle) -> Result<T, String>) -> Result<T, String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .map_err(|e| e.to_string())?;
    runtime.block_on(async {
        let (conn, mut handle, _) = rtnetlink::new_connection().map_err(|e| e.to_string())?;
        let task = tokio::spawn(conn);
        let out = f(&mut handle).await;
        task.abort();
        out
    })
}

/// Index and `txqueuelen` of link `name`.
fn link(name: &str) -> Result<(u32, Option<u32>), String> {
    let name = name.to_owned();
    rt(async move |h| {
        let msg = h
            .link()
            .get()
            .match_name(name.clone())
            .execute()
            .try_next()
            .await
            .map_err(|e| format!("{name}: {e}"))?
            .ok_or_else(|| format!("{name}: no such link"))?;
        let txq = msg.attributes.iter().find_map(|a| match a {
            LinkAttribute::TxQueueLen(q) => Some(*q),
            _ => None,
        });
        Ok((msg.header.index, txq))
    })
}

fn set_txqueuelen(index: u32, len: u32) -> Result<(), String> {
    rt(async move |h| {
        h.link()
            .set(LinkUnspec::new_with_index(index).txqueuelen(len).build())
            .execute()
            .await
            .map_err(|e| format!("txqueuelen {len}: {e}"))
    })
}

/// Kind of the root qdisc of link `index`.
fn root_qdisc(index: u32) -> Result<Option<String>, String> {
    rt(async move |h| {
        let mut dump = h.qdisc().get().execute();
        while let Some(m) = dump.try_next().await.map_err(|e| e.to_string())? {
            if u32::try_from(m.header.index).ok() == Some(index)
                && m.header.parent == TcHandle::ROOT
            {
                return Ok(m.attributes.iter().find_map(|a| match a {
                    TcAttribute::Kind(k) => Some(k.clone()),
                    _ => None,
                }));
            }
        }
        Ok(None)
    })
}

/// `tc qdisc replace dev <index> root <kind>`, with the kind's defaults.
fn set_root_qdisc(index: u32, kind: &str) -> Result<(), String> {
    let kind = kind.to_owned();
    rt(async move |h| {
        let mut tc = TcMessage::with_index(i32::try_from(index).map_err(|e| e.to_string())?);
        tc.header.parent = TcHandle::ROOT;
        tc.header.handle = TcHandle::UNSPEC;
        tc.attributes.push(TcAttribute::Kind(kind.clone()));
        let mut req = NetlinkMessage::from(RouteNetlinkMessage::NewQueueDiscipline(tc));
        req.header.flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;
        let mut replies = h.request(req).map_err(|e| e.to_string())?;
        while let Some(m) = futures_util::StreamExt::next(&mut replies).await {
            if let NetlinkPayload::Error(e) = m.payload
                && let Some(code) = e.code
            {
                return Err(format!(
                    "root qdisc {kind}: {}",
                    std::io::Error::from_raw_os_error(-code.get())
                ));
            }
        }
        Ok(())
    })
}

fn qdisc_code(kind: &str) -> Option<i64> {
    QDISCS.iter().find(|(_, k)| *k == kind).map(|(c, _)| *c)
}

fn qdisc_kind(code: i64) -> Option<&'static str> {
    QDISCS.iter().find(|(c, _)| *c == code).map(|(_, k)| *k)
}

fn rp_filter_path(root: &Root, name: &str) -> std::path::PathBuf {
    root.proc
        .join("sys/net/ipv4/conf")
        .join(name)
        .join("rp_filter")
}

/// Port `name` as it is now.
pub(crate) fn read(name: &IfName, root: &Root) -> PortTuning {
    let mut out = PortTuning::default();
    let mut values: BTreeMap<String, Option<i64>> = PORT_PARAMS
        .iter()
        .filter(|p| !p.ethernet)
        .map(|p| (p.name.to_owned(), None))
        .collect();
    match Ethtool::open(name.as_str()) {
        Ok(mut e) => {
            let (now, max) = e.tuning();
            for (k, v) in now {
                values.insert(k, Some(v));
            }
            out.max = max;
            out.notes.append(&mut e.notes);
        }
        Err(e) => out.notes.push(format!("ethtool netlink: {e}")),
    }
    match link(name.as_str()) {
        Ok((index, txq)) => {
            values.insert("txqueuelen".into(), txq.map(i64::from));
            match root_qdisc(index) {
                Ok(Some(kind)) => match qdisc_code(&kind) {
                    Some(c) => {
                        values.insert("qdisc".into(), Some(c));
                    }
                    None => out.notes.push(format!(
                        "root qdisc {kind}: not one CoreRouter changes (shaping is configured elsewhere)"
                    )),
                },
                Ok(None) => {}
                Err(e) => out.notes.push(format!("qdisc: {e}")),
            }
        }
        Err(e) => out.notes.push(e),
    }
    let rp = std::fs::read_to_string(rp_filter_path(root, name.as_str()))
        .ok()
        .and_then(|t| t.trim().parse().ok());
    values.insert("rp_filter".into(), rp);
    let (cpu, irqs) = crate::cpu_tuning::read_port(root, name.as_str());
    values.extend(cpu);
    out.irqs = irqs;
    out.values = values;
    out
}

fn write(name: &IfName, root: &Root, g: Group, vals: &BTreeMap<String, i64>) -> Result<(), String> {
    match g {
        Group::Rings | Group::Channels | Group::Coalesce => {
            let mut e = Ethtool::open(name.as_str()).map_err(|e| e.to_string())?;
            e.set_tuning(vals).map_err(|e| e.to_string())
        }
        Group::TxQueueLen => {
            let len = vals
                .get("txqueuelen")
                .and_then(|v| u32::try_from(*v).ok())
                .ok_or("txqueuelen out of range")?;
            let (index, _) = link(name.as_str())?;
            set_txqueuelen(index, len)
        }
        Group::Qdisc => {
            let kind = vals
                .get("qdisc")
                .and_then(|v| qdisc_kind(*v))
                .ok_or("unknown qdisc")?;
            let (index, _) = link(name.as_str())?;
            set_root_qdisc(index, kind)
        }
        // Ports::port handles these itself (it keeps the files' originals).
        Group::Cpu => Err("CPU settings go through Ports".into()),
        Group::RpFilter => {
            let v = vals.get("rp_filter").copied().unwrap_or(0);
            std::fs::write(rp_filter_path(root, name.as_str()), format!("{v}\n"))
                .map_err(|e| format!("rp_filter: {e}"))
        }
    }
}

/// The port settings CoreRouter changed, with each port's own values.
#[derive(Debug, Default)]
pub struct Ports {
    orig: BTreeMap<(IfName, String), i64>,
    /// IRQ affinity, RPS and XPS: the files as they were before the
    /// first change (what turning one off puts back).
    files: BTreeMap<(IfName, String), crate::cpu_tuning::Saved>,
}

/// One port's settings, by key.
type Settings = BTreeMap<String, i64>;
type PortMap = BTreeMap<IfName, Settings>;

impl Ports {
    /// Bring every port from `from` to `to`, all or nothing.
    pub fn transition(
        &mut self,
        from: &PortMap,
        to: &PortMap,
        root: &Root,
    ) -> Result<(), HalError> {
        let empty = BTreeMap::new();
        let names: Vec<&IfName> = from.keys().chain(to.keys()).collect();
        // (port, its settings now, what to put back).
        let mut done: Vec<(IfName, Settings, Settings)> = Vec::new();
        let mut seen = Vec::new();
        for name in names {
            if seen.contains(&name) {
                continue;
            }
            seen.push(name);
            let (f, t) = (
                from.get(name).unwrap_or(&empty),
                to.get(name).unwrap_or(&empty),
            );
            if f == t {
                continue;
            }
            match self.port(name, f, t, root) {
                Ok(()) => done.push((name.clone(), t.clone(), f.clone())),
                Err(e) => {
                    for (n, now, back) in done.iter().rev() {
                        if let Err(b) = self.port(n, now, back, root) {
                            log::error!("restoring the settings of '{n}': {b}");
                        }
                    }
                    return Err(e);
                }
            }
        }
        Ok(())
    }

    fn port(
        &mut self,
        name: &IfName,
        from: &BTreeMap<String, i64>,
        to: &BTreeMap<String, i64>,
        root: &Root,
    ) -> Result<(), HalError> {
        let now = read(name, root);
        let cur = |k: &str| now.values.get(k).copied().flatten();
        // The target of each key that changes: the config's value, or the
        // port's own for a key taken out (never known: leave it).
        let mut target: BTreeMap<Group, BTreeMap<String, i64>> = BTreeMap::new();
        for (k, v) in to.iter().filter(|(k, v)| from.get(*k) != Some(*v)) {
            if let Some(g) = group(k) {
                target.entry(g).or_default().insert(k.clone(), *v);
            }
        }
        for k in from.keys().filter(|k| !to.contains_key(*k)) {
            if let (Some(g), Some(o)) = (group(k), self.orig.get(&(name.clone(), k.clone()))) {
                target.entry(g).or_default().insert(k.clone(), *o);
            }
        }
        // IRQ affinity, RPS, XPS first: plain files, with their originals.
        if let Some(vals) = target.remove(&Group::Cpu) {
            let mut done: Vec<(String, Option<crate::cpu_tuning::Saved>)> = Vec::new();
            for (k, v) in &vals {
                if cur(k) == Some(*v) {
                    continue;
                }
                let key = (name.clone(), k.clone());
                let res = if *v != 0 {
                    crate::cpu_tuning::write_port(root, name.as_str(), k, true).map(|saved| {
                        let had = self.files.contains_key(&key);
                        self.files.entry(key.clone()).or_insert(saved);
                        (!had).then_some(())
                    })
                } else {
                    match self.files.remove(&key) {
                        Some(saved) => {
                            crate::cpu_tuning::restore(&saved);
                            Ok(None)
                        }
                        None => crate::cpu_tuning::write_port(root, name.as_str(), k, false)
                            .map(|_| None),
                    }
                };
                match res {
                    Ok(_) => done.push((k.clone(), None)),
                    Err(e) => {
                        for (k, _) in done.iter().rev() {
                            if let Some(saved) = self.files.remove(&(name.clone(), k.clone())) {
                                crate::cpu_tuning::restore(&saved);
                            }
                        }
                        return Err(HalError::Rejected(format!("{name}: {e}")));
                    }
                }
            }
        }
        let mut written: Vec<(Group, BTreeMap<String, i64>)> = Vec::new();
        for (g, vals) in &target {
            let unchanged = vals.iter().all(|(k, v)| cur(k) == Some(*v));
            if unchanged {
                continue;
            }
            for k in vals.keys() {
                if cur(k).is_none() {
                    return self.undo(
                        name,
                        root,
                        written,
                        format!("{name}: {k}: this NIC (driver) does not let CoreRouter change it"),
                    );
                }
            }
            if let Err(e) = write(name, root, *g, vals) {
                return self.undo(name, root, written, format!("{name}: {e}"));
            }
            let back: BTreeMap<String, i64> = vals
                .keys()
                .filter_map(|k| Some((k.clone(), cur(k)?)))
                .collect();
            written.push((*g, back));
        }
        // The driver may round or keep a value without an error.
        let after = read(name, root);
        for vals in target.values() {
            for (k, v) in vals {
                let got = after.values.get(k).copied().flatten();
                if got != Some(*v) {
                    let got = got.map_or_else(|| "nothing".into(), |g| g.to_string());
                    return self.undo(
                        name,
                        root,
                        written,
                        format!("{name}: {k}: the driver kept {got} instead of {v}"),
                    );
                }
            }
        }
        for (_, back) in &written {
            for (k, v) in back {
                let key = (name.clone(), k.clone());
                if to.contains_key(k) {
                    self.orig.entry(key).or_insert(*v);
                } else {
                    self.orig.remove(&key);
                }
            }
        }
        Ok(())
    }

    fn undo(
        &self,
        name: &IfName,
        root: &Root,
        written: Vec<(Group, BTreeMap<String, i64>)>,
        why: String,
    ) -> Result<(), HalError> {
        for (g, back) in written.iter().rev() {
            if let Err(b) = write(name, root, *g, back) {
                log::error!("restoring {name}: {b}");
            }
        }
        Err(HalError::Rejected(why))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_port_key_has_a_group_and_qdisc_codes_round_trip() {
        for p in PORT_PARAMS.iter().filter(|p| !p.ethernet) {
            assert!(group(p.name).is_some(), "{}", p.name);
        }
        for (c, k) in QDISCS {
            assert_eq!(qdisc_code(k), Some(*c));
            assert_eq!(qdisc_kind(*c), Some(*k));
        }
        assert_eq!(qdisc_code("htb"), None);
    }
}
