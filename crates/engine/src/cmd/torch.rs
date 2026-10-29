//! /tool torch and /tool sniffer (G6.4a): an interface's traffic per flow,
//! live, and its frames into a pcap file. Tasks like ping and MTR
//! (`tool.task.poll` / `tool.task.stop`); see `docs/tools.md` §4.4.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::{Arc, PoisonError};
use std::time::Duration;

use base64::Engine as _;
use corerouter_hal::capture::{
    CaptureDevice, CaptureSpec, HEADERS_SNAPLEN, MAX_DEVICES, MAX_SNAPLEN, SharedCapture,
    proto_number,
};
use corerouter_model::{IfName, InterfaceKind};
use ipnet::IpNet;
use serde_json::{Value, json};

use super::args::{opt_bool, opt_str, opt_u32, req_str, req_u32};
use super::CommandSpec;
use crate::tools::sniffer::{self, MIN_LIMIT, PcapFile, SnifferJob};
use crate::tools::torch::{self, Filter, GROUP_FIELDS, Group, MAX_SAMPLE, Sampling, TorchJob};
use crate::{EngineError, Result, Session};

/// Capture files kept at once (each up to its limit).
pub const MAX_FILES: usize = 2;
/// Largest capture file (KiB).
pub const MAX_FILE_KIB: u32 = 65_536;
/// Largest piece one download returns.
pub const MAX_CHUNK: u32 = 4 << 20;

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(query "tool.torch.start", "Torch", ["Tools", "Torch"], None,
        "{interface: string, group?: string|[string] (src, dst, proto, port, vlan, dscp, mac; default src,dst), src_address?: string (IP or prefix, this side of the interface), dst_address?: string (IP or prefix, the far side), port?: int 1..65535 (either port), protocol?: string (tcp, udp, icmp… or a number), vlan_id?: int 0..4095, dscp?: int 0..63, mac_address?: string (this side's MAC), sampling?: string (auto (default: 1:N above 500 kpps) | off | 2..4096), duration?: int 1..86400 (s; default until stopped), interval_ms?: int 200..10000 (default 1000), top?: int 1..256 (rows, default 64), as_lookup?: bool (default true: origin AS of the far side)} → {id, task_id, columns}",
        can_capture, torch_start)
    .alias("torch")
    .positional("interface")
    .task(),
    cmd!(query "tool.sniffer.start", "Packet Sniffer", ["Tools", "Packet Sniffer"], None,
        "{interface: string, src_address?: string (IP or prefix), dst_address?: string (IP or prefix), port?: int 1..65535, protocol?: string, vlan_id?: int 0..4095, mac_address?: string, snaplen?: int 64..9216 (bytes kept per frame, default 128: headers only), file_limit?: int 1..65536 (KiB, default 4096), duration?: int 1..3600 (s, default 60)} → {id, task_id, columns}",
        can_capture, sniffer_start)
    .task(),
    cmd!(query "tool.sniffer.download", "Download Capture", [], None,
        "{id: int, offset?: int, length?: int 1..4194304 (default 4194304)} → {id, file_name, offset, length, total, complete, data}",
        super::always, sniffer_download),
];

/// Why Torch and the sniffer are disabled here, if they are.
fn can_capture(s: &Session) -> std::result::Result<(), String> {
    crate::tasks::can_run(s)?;
    s.hal().packet_capture().map(|_| ())
}

/// Capture files by task id.
#[derive(Default)]
pub(crate) struct SnifferFiles(BTreeMap<u64, PcapFile>);

fn ranged(p: &Value, key: &str, lo: u32, hi: u32) -> Result<Option<u32>> {
    match opt_u32(p, key)? {
        Some(v) if !(lo..=hi).contains(&v) => {
            Err(EngineError::bad(key, format!("must be {lo}..={hi}")))
        }
        v => Ok(v),
    }
}

fn narrow<T: TryFrom<u32>>(key: &str, v: u32) -> Result<T> {
    T::try_from(v).map_err(|_| EngineError::bad(key, "out of range"))
}

/// An address or a prefix (`10.0.0.1` = `10.0.0.1/32`).
fn opt_net(p: &Value, key: &str) -> Result<Option<IpNet>> {
    let Some(s) = opt_str(p, key)? else {
        return Ok(None);
    };
    let s = s.trim();
    if s.is_empty() {
        return Ok(None);
    }
    if let Ok(a) = s.parse::<IpAddr>() {
        return Ok(Some(IpNet::from(a)));
    }
    s.parse::<IpNet>().map(|n| Some(n.trunc())).map_err(|_| {
        let shown: String = s.chars().take(48).collect();
        EngineError::bad(key, format!("'{shown}' is not an IP address or prefix"))
    })
}

fn opt_mac(p: &Value, key: &str) -> Result<Option<[u8; 6]>> {
    let Some(s) = opt_str(p, key)? else {
        return Ok(None);
    };
    let s = s.trim();
    if s.is_empty() {
        return Ok(None);
    }
    let bytes: Vec<u8> = s
        .split([':', '-'])
        .map(|b| u8::from_str_radix(b, 16))
        .collect::<std::result::Result<_, _>>()
        .map_err(|_| EngineError::bad(key, "must be a MAC address like AA:BB:CC:DD:EE:FF"))?;
    <[u8; 6]>::try_from(bytes)
        .map(Some)
        .map_err(|_| EngineError::bad(key, "must be a MAC address like AA:BB:CC:DD:EE:FF"))
}

fn filter(p: &Value) -> Result<Filter> {
    let proto = match opt_str(p, "protocol")?.map(str::trim) {
        None | Some("") => None,
        Some(name) => Some(proto_number(name).ok_or_else(|| {
            let shown: String = name.chars().take(24).collect();
            EngineError::bad("protocol", format!("unknown protocol '{shown}' (tcp, udp, icmp… or 0..255)"))
        })?),
    };
    Ok(Filter {
        src: opt_net(p, "src_address")?,
        dst: opt_net(p, "dst_address")?,
        port: ranged(p, "port", 1, 65_535)?.map(|v| narrow("port", v)).transpose()?,
        proto,
        vlan: ranged(p, "vlan_id", 0, 4095)?.map(|v| narrow("vlan_id", v)).transpose()?,
        dscp: ranged(p, "dscp", 0, 63)?.map(|v| narrow("dscp", v)).transpose()?,
        mac: opt_mac(p, "mac_address")?,
    })
}

fn group(p: &Value) -> Result<Group> {
    let raw: Vec<String> = match p.get("group") {
        None | Some(Value::Null) => vec!["src".into(), "dst".into()],
        Some(Value::String(s)) => s.split(',').map(|x| x.trim().to_owned()).collect(),
        Some(Value::Array(a)) => a
            .iter()
            .map(|v| {
                v.as_str()
                    .map(|x| x.trim().to_owned())
                    .ok_or_else(|| EngineError::bad("group", "must be a list of field names"))
            })
            .collect::<Result<_>>()?,
        Some(_) => return Err(EngineError::bad("group", "must be a list of field names")),
    };
    let mut g = Group::default();
    for f in raw.iter().filter(|f| !f.is_empty()) {
        if !g.set(f) {
            let shown: String = f.chars().take(16).collect();
            return Err(EngineError::bad(
                "group",
                format!("unknown field '{shown}' (one of {})", GROUP_FIELDS.join(", ")),
            ));
        }
    }
    Ok(g)
}

/// The interface to capture and, when VLANs matter, its VLAN interfaces.
fn devices(s: &Session, p: &Value, vlans: bool) -> Result<(IfName, Vec<CaptureDevice>)> {
    let name: IfName = req_str(p, "interface")?
        .trim()
        .parse()
        .map_err(|e| EngineError::bad("interface", format!("{e}")))?;
    let cfg = s.store().running();
    let Some(iface) = cfg.interfaces.get(&name) else {
        return Err(EngineError::bad(
            "interface",
            format!("no interface '{name}' (see interface.list)"),
        ));
    };
    let own_vlan = match &iface.kind {
        InterfaceKind::Vlan { vlan_id, .. } => Some(vlan_id.get()),
        _ => None,
    };
    let mut out = vec![CaptureDevice {
        name: name.to_string(),
        vlan: own_vlan,
    }];
    if vlans && own_vlan.is_none() {
        for (child, i) in &cfg.interfaces {
            if let InterfaceKind::Vlan { parent, vlan_id, .. } = &i.kind
                && parent == &name
                && !i.disabled
                && out.len() < MAX_DEVICES
            {
                out.push(CaptureDevice {
                    name: child.to_string(),
                    vlan: Some(vlan_id.get()),
                });
            }
        }
    }
    Ok((name, out))
}

fn capture(s: &Session) -> Result<SharedCapture> {
    s.hal().packet_capture().map_err(EngineError::Hal)
}

fn torch_start(s: &mut Session, p: &Value) -> Result<Value> {
    let group = group(p)?;
    let filter = filter(p)?;
    let (name, devices) = devices(s, p, group.vlan || filter.vlan.is_some())?;
    let sampling = match opt_str(p, "sampling")?.map(str::trim) {
        None | Some("" | "auto") => Sampling::Auto,
        Some("off" | "1") => Sampling::Off,
        Some(n) => match n.parse::<u32>() {
            Ok(v) if (2..=MAX_SAMPLE).contains(&v) => Sampling::Fixed(v),
            _ => {
                return Err(EngineError::bad(
                    "sampling",
                    format!("must be auto, off or 2..={MAX_SAMPLE}"),
                ));
            }
        },
    };
    let duration = ranged(p, "duration", 1, 86_400)?.map(|d| Duration::from_secs(u64::from(d)));
    let interval = ranged(p, "interval_ms", 200, 10_000)?.unwrap_or(1000);
    let top = ranged(p, "top", 1, 256)?.unwrap_or(64);
    let as_lookup = if opt_bool(p, "as_lookup")?.unwrap_or(true) {
        s.tool_prober().ok()
    } else {
        None
    };
    let capture = capture(s)?;
    let job = TorchJob {
        interface: name.to_string(),
        spec: CaptureSpec {
            devices,
            snaplen: HEADERS_SNAPLEN,
            sample: 1,
        },
        group,
        filter,
        sampling,
        duration,
        interval: Duration::from_millis(u64::from(interval)),
        top: usize::try_from(top).unwrap_or(64),
        as_lookup,
    };
    let id = s.start_task("torch", format!("torch {name}"), move |ctx| {
        torch::run(job, capture, ctx)
    })?;
    Ok(json!({
        "id": id,
        "task_id": id,
        "columns": ["src", "dst", "proto", "src_port", "dst_port", "vlan", "dscp", "mac", "tx_bps", "rx_bps", "tx_pps", "rx_pps"],
    }))
}

fn sniffer_start(s: &mut Session, p: &Value) -> Result<Value> {
    // Frames carry subscribers' data: only accounts that may change the
    // router may record them (Torch shows headers only and stays `read`).
    s.permit(crate::auth::Group::Write)
        .map_err(|reason| EngineError::Denied {
            id: "tool.sniffer.start".into(),
            reason,
        })?;
    let filter = filter(p)?;
    let (name, devices) = devices(s, p, filter.vlan.is_some())?;
    let snaplen = ranged(p, "snaplen", 64, u32::from(MAX_SNAPLEN))?
        .unwrap_or(u32::from(HEADERS_SNAPLEN));
    let limit_kib = ranged(p, "file_limit", 1, MAX_FILE_KIB)?.unwrap_or(4096);
    let limit = usize::try_from(limit_kib)
        .unwrap_or(4096)
        .saturating_mul(1024)
        .max(MIN_LIMIT);
    let duration = ranged(p, "duration", 1, 3600)?.unwrap_or(60);
    let capture = capture(s)?;
    // Room for the file: forget files whose task is gone, then the oldest
    // finished one.
    let kept: Vec<u64> = s
        .ext::<SnifferFiles>()
        .map(|f| f.0.keys().copied().collect())
        .unwrap_or_default();
    let gone: Vec<u64> = kept.iter().copied().filter(|id| !s.task_kept(*id)).collect();
    let mut finished = Vec::new();
    for id in kept.iter().filter(|id| !gone.contains(id)) {
        if !s.task_running(*id, "sniffer").unwrap_or(true) {
            finished.push(*id);
        }
    }
    let Some(files) = s.ext_mut::<SnifferFiles>() else {
        return Err(EngineError::Hal("capture files are unavailable".into()));
    };
    for id in &gone {
        files.0.remove(id);
    }
    for id in finished {
        if files.0.len() < MAX_FILES {
            break;
        }
        files.0.remove(&id);
    }
    if files.0.len() >= MAX_FILES {
        return Err(EngineError::Hal(format!(
            "{MAX_FILES} captures are running already; stop one first (tool.task.stop)"
        )));
    }
    let file: PcapFile = Arc::default();
    let job = SnifferJob {
        interface: name.to_string(),
        spec: CaptureSpec {
            devices,
            snaplen: narrow("snaplen", snaplen)?,
            sample: 1,
        },
        filter,
        limit,
        duration: Duration::from_secs(u64::from(duration)),
        start_unix: s.now(),
        file: Arc::clone(&file),
    };
    let id = s.start_task("sniffer", format!("sniffer {name}"), move |ctx| {
        sniffer::run(job, capture, ctx)
    })?;
    if let Some(files) = s.ext_mut::<SnifferFiles>() {
        files.0.insert(id, file);
    }
    Ok(json!({
        "id": id,
        "task_id": id,
        "columns": ["t", "packets", "bytes", "file_size"],
    }))
}

fn sniffer_download(s: &mut Session, p: &Value) -> Result<Value> {
    let id = u64::from(req_u32(p, "id")?);
    let running = s.task_running(id, "sniffer")?;
    let offset = match p.get("offset") {
        None | Some(Value::Null) => 0,
        Some(v) => v
            .as_u64()
            .ok_or_else(|| EngineError::bad("offset", "must be a non-negative integer"))?,
    };
    let length = ranged(p, "length", 1, MAX_CHUNK)?.unwrap_or(MAX_CHUNK);
    let file = s
        .ext::<SnifferFiles>()
        .and_then(|f| f.0.get(&id).cloned())
        .ok_or_else(|| EngineError::bad("id", format!("task {id} has no capture file")))?;
    let f = file.lock().unwrap_or_else(PoisonError::into_inner);
    let total = f.len() as u64;
    if offset > total {
        return Err(EngineError::bad(
            "offset",
            format!("past the end of the file ({total} bytes)"),
        ));
    }
    let start = usize::try_from(offset).unwrap_or(usize::MAX);
    let end = start.saturating_add(usize::try_from(length).unwrap_or(0)).min(f.len());
    let chunk = f.get(start..end).unwrap_or(&[]);
    Ok(json!({
        "id": id,
        "file_name": format!("sniffer-{id}.pcap"),
        "offset": offset,
        "length": chunk.len(),
        "total": total,
        "complete": !running,
        "data": base64::engine::general_purpose::STANDARD.encode(chunk),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tasks::test_runner;
    use std::thread;

    fn lab() -> Session {
        let mut s = Session::virtual_lab();
        s.set_runner(test_runner::sim());
        s
    }

    fn until_done(s: &mut Session, id: u64) -> Value {
        for _ in 0..800 {
            let p = s
                .execute("tool.task.poll", &json!({"id": id, "max": 256}))
                .unwrap();
            if p["done"] == true {
                return p;
            }
            thread::sleep(Duration::from_millis(10));
        }
        panic!("task {id} did not finish");
    }

    #[test]
    fn torch_on_a_lab_port() {
        let mut s = lab();
        let r = s
            .execute(
                "tool.torch.start",
                &json!({"interface": "ether1", "group": "src,dst,proto", "duration": 2, "interval_ms": 500}),
            )
            .unwrap();
        let id = r["task_id"].as_u64().unwrap();
        let p = until_done(&mut s, id);
        assert_eq!(p["kind"], "torch");
        assert_eq!(p["state"], "done");
        assert!(p["events"].as_array().unwrap().len() >= 3);
        let rows = p["summary"]["rows"].as_array().unwrap();
        assert!(rows.iter().any(|r| r["proto"] == "udp" && r["dst"] == "8.8.8.8"));
        assert!(rows.iter().any(|r| r["asn"].is_number()), "AS on by default");
        assert_eq!(p["summary"]["group"], json!(["src", "dst", "proto"]));
        // Text for the terminal.
        let t = s
            .execute("tool.task.poll", &json!({"id": id, "text": true}))
            .unwrap();
        assert!(t["header"].as_str().unwrap().contains("TX"));
        assert!(t["lines"].as_array().unwrap().iter().any(|l| l.as_str().unwrap().contains("8.8.8.8")));
        // Operational: nothing in the journal.
        assert!(s.journal().is_empty());
    }

    #[test]
    fn torch_by_vlan_takes_the_vlan_interfaces() {
        let mut s = lab();
        s.execute(
            "interface.vlan.add",
            &json!({"name": "vlan100", "parent": "ether1", "vlan_id": 100}),
        )
        .unwrap();
        let p = json!({"interface": "ether1", "group": ["vlan"]});
        let g = group(&p).unwrap();
        let (_, devs) = devices(&s, &p, g.vlan).unwrap();
        assert_eq!(devs.len(), 2);
        assert_eq!(devs[1].vlan, Some(100));
        let (_, devs) = devices(&s, &json!({"interface": "vlan100"}), false).unwrap();
        assert_eq!((devs.len(), devs[0].vlan), (1, Some(100)));
    }

    #[test]
    fn bad_torch_parameters_are_refused() {
        let mut s = lab();
        for p in [
            json!({}),
            json!({"interface": "nope0"}),
            json!({"interface": "ether1", "group": "src,colour"}),
            json!({"interface": "ether1", "group": 3}),
            json!({"interface": "ether1", "src_address": "10.0.0.300"}),
            json!({"interface": "ether1", "port": 0}),
            json!({"interface": "ether1", "protocol": "bogus"}),
            json!({"interface": "ether1", "vlan_id": 4096}),
            json!({"interface": "ether1", "mac_address": "AA:BB"}),
            json!({"interface": "ether1", "sampling": "1000000"}),
            json!({"interface": "ether1", "interval_ms": 50}),
            json!({"interface": "ether1", "top": 0}),
            json!({"interface": "ether1", "extra": 1}),
        ] {
            assert!(s.execute("tool.torch.start", &p).is_err(), "accepted {p}");
        }
        assert!(s.task_list().as_array().unwrap().is_empty());
        let f = filter(&json!({"src_address": "10.1.2.3/8", "protocol": "TCP", "mac_address": "aa-bb-cc-dd-ee-ff"})).unwrap();
        assert_eq!(f.src, Some("10.0.0.0/8".parse().unwrap()));
        assert_eq!(f.proto, Some(6));
        assert_eq!(f.mac, Some([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]));
    }

    #[test]
    fn sniffer_records_and_downloads_in_pieces() {
        let mut s = lab();
        let r = s
            .execute(
                "tool.sniffer.start",
                &json!({"interface": "ether1", "duration": 1, "port": 53}),
            )
            .unwrap();
        let id = r["task_id"].as_u64().unwrap();
        let p = until_done(&mut s, id);
        assert_eq!(p["summary"]["end"], "duration reached");
        let total = p["summary"]["file_size"].as_u64().unwrap();
        let mut file = Vec::new();
        loop {
            let d = s
                .execute(
                    "tool.sniffer.download",
                    &json!({"id": id, "offset": file.len(), "length": 1000}),
                )
                .unwrap();
            assert_eq!(d["complete"], true);
            assert_eq!(d["file_name"], format!("sniffer-{id}.pcap"));
            let chunk = base64::engine::general_purpose::STANDARD
                .decode(d["data"].as_str().unwrap())
                .unwrap();
            if chunk.is_empty() {
                break;
            }
            file.extend_from_slice(&chunk);
        }
        assert_eq!(file.len() as u64, total);
        assert_eq!(&file[0..4], &[0xD4, 0xC3, 0xB2, 0xA1]);
        assert!(s
            .execute("tool.sniffer.download", &json!({"id": id, "offset": total + 1}))
            .is_err());
        // A torch task has no file.
        let t = s
            .execute("tool.torch.start", &json!({"interface": "ether1", "duration": 1}))
            .unwrap();
        let tid = t["task_id"].as_u64().unwrap();
        assert!(s.execute("tool.sniffer.download", &json!({"id": tid})).is_err());
    }

    #[test]
    fn at_most_two_captures_run() {
        let mut s = lab();
        let p = json!({"interface": "ether1", "duration": 60});
        let a = s.execute("tool.sniffer.start", &p).unwrap();
        s.execute("tool.sniffer.start", &p).unwrap();
        let e = s.execute("tool.sniffer.start", &p).unwrap_err();
        assert!(e.to_string().contains("running already"), "{e}");
        // Stopping one makes room (its file goes once a new one needs it).
        let id = a["task_id"].as_u64().unwrap();
        s.execute("tool.task.stop", &json!({"id": id})).unwrap();
        until_done(&mut s, id);
        s.execute("tool.sniffer.start", &p).unwrap();
        assert!(s.execute("tool.sniffer.download", &json!({"id": id})).is_err());
    }

    #[test]
    fn bad_sniffer_parameters_are_refused() {
        let mut s = lab();
        for p in [
            json!({"interface": "ether1", "snaplen": 10}),
            json!({"interface": "ether1", "file_limit": 0}),
            json!({"interface": "ether1", "file_limit": 70_000}),
            json!({"interface": "ether1", "duration": 4000}),
            json!({"interface": "nope0"}),
        ] {
            assert!(s.execute("tool.sniffer.start", &p).is_err(), "accepted {p}");
        }
    }
}
