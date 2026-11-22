//! Tools › Torch and Packet Sniffer (G6.4a): Start runs the task on the
//! lab's simulated traffic, the rows come with the AS pill and the CGNAT
//! chip, the subscriber chip shows once the router names the address, and
//! the sniffer's file is downloaded in pieces into an export.

use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use corerouter_engine::tasks::SimClock;
use corerouter_engine::{Job, Runner};

use super::*;
use crate::sniffer::SnifferPanel;
use crate::torch::{TorchPanel, absorb_identities};

struct Threads;
impl Runner for Threads {
    fn spawn(&self, _name: &str, job: Job) -> Result<(), String> {
        thread::spawn(move || job(&SimClock::default()));
        Ok(())
    }
}

fn open(win: &'static str) -> Harness {
    let mut s = Session::virtual_lab();
    s.set_runner(Arc::new(Threads));
    s.tick(1_000);
    let mut h = Harness::with_session(s);
    h.app.open.clear();
    h.app.open(Win::Panel(win));
    for _ in 0..6 {
        h.idle();
    }
    h
}

fn until(h: &mut Harness, what: &str, mut done: impl FnMut(&mut Harness) -> bool) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while !done(h) {
        assert!(Instant::now() < deadline, "{what}: {:?}", h.app.log());
        thread::sleep(Duration::from_millis(30));
        h.app.cache.refreshed_at = None;
        h.time += 0.3;
        h.idle();
    }
    h.idle();
}

#[test]
fn torch_shows_the_flows_of_an_interface() {
    let mut h = open(crate::torch::WIN);
    assert!(h.has_text("Group by") && h.has_text("Sampling"));
    h.app.panel_mut::<TorchPanel>().unwrap().interface = "ether1".into();
    h.idle();
    h.click(h.text("Start"));
    until(&mut h, "no rows", |h| {
        h.app.panel_mut::<TorchPanel>().unwrap().summary["rows"]
            .as_array()
            .is_some_and(|r| r.len() >= 5)
    });
    assert!(h.has_text("100.64.0.10"), "a subscriber");
    assert!(h.has_text("CGNAT"), "its scope chip");
    assert!(h.has_text("AS64999 SIM-DEST"), "the far side's AS pill");
    assert!(h.has_text("Interface counters"));
    assert!(h.has_text_containing("seen 100"), "everything read");
    let summary = h.app.panel_mut::<TorchPanel>().unwrap().summary.clone();
    assert_eq!(summary["sampling"], 1, "no sampling at lab rates");
    // Stop ends the task.
    h.click(h.text("Stop"));
    until(&mut h, "did not stop", |h| h.app.panel_mut::<TorchPanel>().unwrap().done);
    assert_eq!(h.app.panel_mut::<TorchPanel>().unwrap().state, "stopped");
}

#[test]
fn torch_form_and_identity_chip() {
    let mut p = TorchPanel {
        interface: " ether1 ".into(),
        port: "443".into(),
        sampling: "100".into(),
        ..TorchPanel::default()
    };
    p.group[4] = true;
    assert_eq!(
        p.params(),
        json!({"interface": "ether1", "group": ["src", "dst", "vlan"], "port": 443, "sampling": "100"})
    );
    // `ip.identity.lookup` (G0.25), either shape.
    absorb_identities(&mut p.identities, &json!([{"address": "100.64.0.10", "subscriber": "joao.silva"}]));
    absorb_identities(&mut p.identities, &json!({"100.64.0.11": {"name": "maria"}, "100.64.0.12": null}));
    assert_eq!(p.identities.get("100.64.0.11").map(String::as_str), Some("maria"));
    let row = p.row(&json!({"src": "100.64.0.10", "src_scope": "cgnat", "dst": "8.8.8.8", "asn": 15169, "as_name": "GOOGLE", "vlan": 100, "tx_bps": 2.5e6, "rx_bps": 1200.0, "tx_pps": 300.0, "rx_pps": 20.0}));
    let joined = row.cells.join("|");
    assert!(joined.contains("joao.silva") && joined.contains("CGNAT"), "{joined}");
    assert!(joined.contains("AS15169 GOOGLE"));
    assert!(joined.contains("2.5 Mbps") && joined.contains("1.2 kbps"));
    // Unknown addresses are remembered empty and show no chip.
    let row = p.row(&json!({"src": "100.64.0.12"}));
    assert!(!row.cells.join("|").contains(crate::chip::SEP), "{:?}", row.cells);
}

#[test]
fn sniffer_records_and_downloads_a_pcap() {
    let mut h = open(crate::sniffer::WIN);
    {
        let p = h.app.panel_mut::<SnifferPanel>().unwrap();
        p.interface = "ether1".into();
        p.duration = "1".into();
        p.port = "53".into();
    }
    h.idle();
    assert!(!h.has_text("payloads"), "headers only by default");
    h.click(h.text("Start"));
    until(&mut h, "capture did not end", |h| h.app.panel_mut::<SnifferPanel>().unwrap().done);
    assert!(h.has_text("duration reached"));
    let size = h.app.panel_mut::<SnifferPanel>().unwrap().summary["file_size"].as_u64().unwrap();
    assert!(size > 24, "{size}");
    h.click(h.text("Download .pcap"));
    until(&mut h, "no export", |h| h.app.panel_mut::<SnifferPanel>().unwrap().download.is_none() && !h.app.exports.is_empty());
    let files = h.app.take_exports();
    assert_eq!(files.len(), 1);
    assert!(files[0].file_name.ends_with(".pcap"));
    assert_eq!(files[0].bytes.len() as u64, size);
    assert_eq!(&files[0].bytes[0..4], &[0xD4, 0xC3, 0xB2, 0xA1]);
    // Whole frames: the chip warns.
    h.app.panel_mut::<SnifferPanel>().unwrap().snaplen = "1514".into();
    h.idle();
    assert!(h.has_text("payloads"));
}

#[test]
fn every_explanation_of_both_windows_exists() {
    for key in [
        "torch.interface", "torch.group", "torch.src", "torch.dst", "torch.port", "torch.protocol",
        "torch.sampling", "torch.counters", "sniffer.interface", "sniffer.snaplen",
        "sniffer.file_limit", "sniffer.duration", "menu.torch", "menu.sniffer",
    ] {
        for l in crate::i18n::Lang::ALL {
            let langs = crate::i18n::Langs { labels: l, help: l };
            let found = crate::i18n::explain(langs, key).map(|(lang, _)| lang);
            assert_eq!(found, Some(l), "{key} in {l:?}");
        }
    }
}
