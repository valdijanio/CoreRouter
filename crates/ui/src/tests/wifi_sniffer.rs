//! Interfaces › Wi-Fi Sniffer (G1.30j) on the lab's radio and its air
//! (`lab_wifi_air`): the snooper's table with the networks, their
//! stations and the notes as chips; the capture's live list and its pcap
//! downloaded into an export; the form for a radio in use.

use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use corerouter_engine::tasks::SimClock;
use corerouter_engine::{Job, Runner};
use corerouter_hal::VirtualHal;
use corerouter_hal::lab_wifi::LAB_PASSPHRASE;

use super::*;
use crate::wifi_sniffer::{Tab, WIN, WifiSnifferPanel};

struct Threads;
impl Runner for Threads {
    fn spawn(&self, _name: &str, job: Job) -> Result<(), String> {
        thread::spawn(move || job(&SimClock::default()));
        Ok(())
    }
}

/// A lab with one radio, adopted and off, and the window open.
fn open() -> Harness {
    let mut s = Session::new(Box::new(VirtualHal::new(8).with_wifi(1)));
    s.set_runner(Arc::new(Threads));
    for t in 0..4 {
        s.tick(1_000 + t);
    }
    let mut h = Harness::with_session(s);
    h.app.open.clear();
    h.app.open(Win::Panel(WIN));
    for _ in 0..3 {
        h.app.cache.refreshed_at = None;
        h.idle();
        h.idle();
    }
    h
}

fn panel(h: &mut Harness) -> &mut WifiSnifferPanel {
    h.app.panel_mut::<WifiSnifferPanel>().unwrap()
}

fn until(h: &mut Harness, what: &str, mut done: impl FnMut(&mut Harness) -> bool) {
    let deadline = Instant::now() + Duration::from_secs(20);
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
fn the_snooper_shows_networks_stations_and_notes() {
    let mut h = open();
    assert_eq!(panel(&mut h).radio, "wifi1", "the only radio, picked");
    assert!(h.has_text("exclusive"), "a disabled radio is the sniffer's");
    {
        let p = panel(&mut h);
        p.channel = "44".into();
        p.duration = "30".into();
    }
    h.idle();
    h.click(h.text("Start snooper"));
    until(&mut h, "no table", |h| {
        let p = panel(h);
        p.done
            && p.snoop["networks"]
                .as_array()
                .is_some_and(|n| n.iter().any(|x| x["ssid"] == "CoreRouter-Lab"))
    });
    assert!(h.has_text("CoreRouter-Lab"), "the network");
    assert!(h.has_text("      · 02:5e:10:00:00:13"), "the far printer under it");
    assert!(h.has_text("far, slow"), "its note as a chip");
    assert!(h.has_text("evil twin?"), "the open twin");
    assert!(h.has_text("handshake 4/4"), "the TV's handshake");
    assert!(h.has_text("deauth ×12"), "the TV was thrown out twice in 30 s");
    assert!(h.has_text("44"), "the channel strip");
    // The selected row's notes in full.
    let row = h
        .ctx
        .read_response(table::row_id(crate::wifi_sniffer::TABLE, "02:c0:fe:00:00:01/02:5e:10:00:00:14"))
        .unwrap()
        .rect
        .center();
    h.click(row);
    assert!(h.has_text_containing("class 3 frame"), "the deauth reason in words");
}

#[test]
fn the_capture_lists_frames_and_downloads_the_pcap() {
    let mut h = open();
    {
        let p = panel(&mut h);
        p.tab = Tab::Capture;
        p.channel = "44".into();
        p.duration = "4".into();
        p.mgmt = true;
    }
    h.idle();
    assert!(h.has_text("Handshake only (EAPOL)"));
    h.click(h.text("Start capture"));
    until(&mut h, "no frames", |h| {
        let p = panel(h);
        p.done && p.frames.len() > 10
    });
    assert!(h.has_text("beacon"), "a frame type chip");
    assert!(panel(&mut h).frames.iter().all(|f| f["kind"] == "mgmt"));
    h.click(h.text("Download .pcap"));
    until(&mut h, "no export", |h| !h.app.exports.is_empty());
    let e = h.app.exports.last().unwrap();
    assert!(e.file_name.starts_with("wifi-wifi1-") && e.file_name.ends_with(".pcap"), "{}", e.file_name);
    assert_eq!(&e.bytes[0..4], &[0xD4, 0xC3, 0xB2, 0xA1]);
    assert_eq!(u32::from_le_bytes(e.bytes[20..24].try_into().unwrap()), 127, "radiotap");
}

#[test]
fn an_enabled_radio_keeps_its_station() {
    let mut h = open();
    {
        let mut s = h.session.lock().unwrap();
        s.execute("interface.wifi.country.set", &json!({"country": "BR"})).unwrap();
        s.execute(
            "interface.wifi.set",
            &json!({"name": "wifi1", "ssid": "CoreRouter-Lab", "passphrase": LAB_PASSPHRASE, "disabled": false}),
        )
        .unwrap();
    }
    h.app.cache.refreshed_at = None;
    for _ in 0..4 {
        h.idle();
    }
    assert!(h.has_text("beside the station"));
    let p = panel(&mut h);
    assert!(p.shared());
    p.channel = "1".into();
    p.hop = true;
    // The form leaves the channel out: the monitor follows the station.
    assert_eq!(p.params(Tab::Snooper), json!({"interface": "wifi1", "duration": 300}));
    p.radios[0]["disabled"] = json!(true);
    assert_eq!(
        p.params(Tab::Capture),
        json!({"interface": "wifi1", "hop": true, "channel_time": 200, "duration": 300, "file_limit": 16384})
    );
}
