//! The Networks tab's three views (G1.30i) against the lab's radio and its
//! neighbours: the list with the band filter, the channel groups and the
//! chips of overlap and contention; the channel graph with the survey; the
//! spectrum of a radio that has spectral scan, and the view off, with why,
//! on one that has not.

use super::*;
use crate::wifi::{HEARD, Tab, WIN, WifiPanel};
use crate::wifi_scan::{Band, Mode};
use corerouter_hal::VirtualHal;
use corerouter_hal::lab_wifi::LAB_PASSPHRASE;

/// The lab's radio on its network, a scan done; `spectral`: the radio has
/// spectral scan.
fn joined(spectral: bool) -> (Session, u64) {
    let hal = VirtualHal::new(8).with_wifi(1);
    if !spectral {
        hal.wifi().without_spectral(&"wifi1".parse().unwrap());
    }
    let mut s = Session::new(Box::new(hal));
    for t in 0..4 {
        s.tick(1_000 + t);
    }
    s.execute("interface.wifi.country.set", &json!({"country": "BR"})).unwrap();
    s.execute(
        "interface.wifi.set",
        &json!({"name": "wifi1", "ssid": "CoreRouter-Lab", "passphrase": LAB_PASSPHRASE, "disabled": false}),
    )
    .unwrap();
    let mut ms = 0;
    for _ in 0..8 {
        ms += 100;
        s.wifi_service(ms);
    }
    s.execute("interface.wifi.scan", &json!({"name": "wifi1"})).unwrap();
    for _ in 0..4 {
        ms += 100;
        s.wifi_service(ms);
    }
    (s, ms)
}

fn refresh(h: &mut Harness) {
    h.app.cache.refreshed_at = None;
    h.idle();
    h.idle();
}

/// The window on its Networks tab.
fn networks(s: Session) -> Harness {
    let mut h = Harness::with_session(s);
    h.app.open.clear();
    h.app.open(Win::Panel(WIN));
    refresh(&mut h);
    {
        let p = h.app.panel_mut::<WifiPanel>().unwrap();
        p.tab = Tab::Networks;
        p.radio = "wifi1".into();
    }
    refresh(&mut h);
    refresh(&mut h);
    h
}

fn panel(h: &mut Harness) -> &mut WifiPanel {
    h.app.panel_mut::<WifiPanel>().unwrap()
}

#[test]
fn the_list_filters_by_band_groups_by_channel_and_says_who_shares_the_air() {
    let (s, _) = joined(true);
    let mut h = networks(s);
    assert!(h.has_text("yours"), "the network the radio is on");
    assert!(h.has_text("80 MHz") && h.has_text("160 MHz"), "the width chips");
    assert!(h.has_text("overlaps ch 1, 6, 11"), "Apto-301 on ch 4");
    assert!(h.has_text("shares airtime ×1"), "ours, covered by the 80 MHz neighbour");
    assert!(h.has_text_containing("clients"), "the BSS Load");
    assert!(h.has_text("Least busy channel"));
    assert!(h.has_text("2.4 GHz ch 11"), "the suggestion");
    // The band pills, with their counts.
    assert!(h.has_text("All 11") && h.has_text("2.4 GHz 5") && h.has_text("5 GHz 5") && h.has_text("6 GHz 1"));
    h.click(h.text("2.4 GHz 5"));
    refresh(&mut h);
    assert_eq!(panel(&mut h).scan.band, Band::G2);
    assert!(h.has_text("Cafe") && !h.has_text("Lab-WPA3"), "5 GHz left out");
    // Grouped by channel: a header per channel.
    panel(&mut h).scan.group = true;
    refresh(&mut h);
    assert!(h.has_text_containing("2.4 GHz ch 6 · 2 networks"), "CoreRouter-Lab and Loja");
    // A header is not a network: Connect… says so.
    let header = h
        .ctx
        .read_response(table::row_id(HEARD, "section-2ghz-6"))
        .expect("the header row")
        .rect
        .center();
    h.click(header);
    refresh(&mut h);
    assert_eq!(panel(&mut h).heard_table.selection(&[]).len(), 0);
}

#[test]
fn the_channel_graph_draws_each_band_and_the_survey() {
    let (s, _) = joined(true);
    let mut h = networks(s);
    h.click(h.text("Channels"));
    refresh(&mut h);
    refresh(&mut h);
    assert_eq!(panel(&mut h).scan.mode, Mode::Channels);
    assert!(panel(&mut h).scan.survey.is_some(), "frequency-scan asked for");
    assert!(h.has_text("counted on every channel"), "the lab counts every channel");
    // The curves are labelled by SSID, ours marked.
    assert!(h.has_text("CoreRouter-Lab · yours"));
    assert!(h.has_text("Lab-6E") && h.has_text("Vizinho_2G"));
    assert!(h.has_text("2.4 GHz") && h.has_text("6 GHz"), "a graph per band");
    // The busy share over the channels the survey counted.
    assert!(h.has_text_containing("%"));
}

#[test]
fn the_spectrum_runs_on_a_radio_that_has_it() {
    let (s, ms) = joined(true);
    let mut h = networks(s);
    h.click(h.text("Spectrum"));
    refresh(&mut h);
    assert_eq!(panel(&mut h).scan.mode, Mode::Spectrum);
    assert!(h.has_text("No samples yet: Start listens for the seconds set."));
    h.click(h.text("Start"));
    {
        let mut s = lock(&h.session);
        let mut t = ms;
        for _ in 0..50 {
            t += 250;
            s.wifi_service(t);
        }
    }
    refresh(&mut h);
    refresh(&mut h);
    let rows = panel(&mut h).scan.rows.len();
    assert!(rows >= 40, "{rows} rows of the waterfall");
    assert!(h.has_text("Waterfall") && h.has_text("Channel usage"));
    assert!(h.has_text_containing("scanning ·"), "the running chip");
    assert!(h.has_text("Sources"), "the sources line is on screen");
    assert!(h.has_text_containing("carrier 5232"), "the lab's carrier at 5232 MHz: {:?}", panel(&mut h).scan.spectral.as_ref().map(|d| d["interference"].clone()));
    assert!(h.has_text("Stop"));
    // Only the new rows come with each refresh.
    let seq = panel(&mut h).scan.last_seq;
    {
        let mut s = lock(&h.session);
        s.wifi_service(ms + 50 * 250 + 250);
    }
    refresh(&mut h);
    assert_eq!(panel(&mut h).scan.last_seq, seq + 1);
    h.click(h.text("Stop"));
    refresh(&mut h);
    assert!(h.has_text("stopped"));
}

#[test]
fn the_spectrum_is_off_with_why_on_a_radio_without_it() {
    let (s, _) = joined(false);
    let mut h = networks(s);
    let why = panel(&mut h).scan.spectral.as_ref().and_then(|d| d["why_not"].as_str().map(str::to_owned)).unwrap();
    assert!(why.contains("Qualcomm Atheros"), "{why}");
    h.click(h.text("Spectrum"));
    refresh(&mut h);
    assert_eq!(panel(&mut h).scan.mode, Mode::List, "the view is off");
}

#[test]
fn every_explanation_and_label_of_the_views() {
    for key in crate::wifi_scan::help_keys() {
        for lang in [crate::i18n::Lang::Pt, crate::i18n::Lang::En] {
            let langs = crate::i18n::Langs { labels: lang, help: lang };
            let (got, _) = crate::i18n::explain(langs, key).unwrap_or_else(|| panic!("{key}"));
            assert_eq!(got, lang, "{key} in {lang:?}");
        }
    }
    let same = ["SSID", "BSSID", "Wi-Fi", "Bluetooth", "5 GHz", "6 GHz", "Auto"];
    for label in crate::wifi_scan::labels() {
        let pt = crate::i18n::tr_in("wifi_scan", crate::i18n::Lang::Pt, label);
        assert!(same.contains(&label) || pt != label, "{label} has no Portuguese");
    }
}

/// `secs` of the UI's clock, a frame a second (the tab drawn all along).
fn wait(h: &mut Harness, secs: u32) {
    for _ in 0..secs {
        h.time += 1.0;
        h.idle();
    }
    refresh(h);
}

/// Times command `id` went out (the app's log).
fn sent(h: &Harness, id: &str) -> usize {
    h.app.log().iter().filter(|l| l.command == id).count()
}

#[test]
fn a_label_that_does_not_fit_above_goes_inside_the_block() {
    use crate::wifi_scan::label_rect;
    use egui::{Rect, pos2, vec2};
    // The axis goes to −20 dBm: networks at −21 and −15 dBm have their top
    // at (or above) the plot's top, where a label above would be cut.
    let plot = Rect::from_min_max(pos2(50.0, 10.0), pos2(650.0, 210.0));
    let y = |dbm: f32| plot.bottom() - ((dbm + 100.0) / 80.0).clamp(0.0, 1.0) * plot.height();
    let size = vec2(60.0, 12.0);
    let mut placed = Vec::new();
    for (x, dbm) in [(300.0, -21.0), (310.0, -15.0), (649.0, -15.0), (330.0, -60.0)] {
        let r = label_rect(plot, x, y(dbm), size, &placed);
        assert!(plot.contains_rect(r), "{dbm} dBm at {x}: {r:?} outside {plot:?}");
        assert!(!placed.iter().any(|p: &Rect| p.intersects(r)), "{dbm} dBm covers another: {r:?} {placed:?}");
        placed.push(r);
    }
    // A weak one keeps its label above the block.
    let r = label_rect(plot, 100.0, y(-70.0), size, &[]);
    assert!(r.bottom() <= y(-70.0));
}

#[test]
fn auto_scans_again_and_stops_when_the_tab_is_left() {
    let (s, _) = joined(true);
    let mut h = networks(s);
    assert!(h.has_text("Auto"));
    assert!(!panel(&mut h).scan.auto, "off at first");
    let before = sent(&h, "interface.wifi.scan");
    panel(&mut h).scan.auto = true;
    panel(&mut h).scan.auto_secs = 10;
    refresh(&mut h);
    assert_eq!(sent(&h, "interface.wifi.scan"), before + 1, "a scan at once");
    // The radio is a station on a network: 30 s at least, and the warning.
    assert_eq!(panel(&mut h).scan.auto_interval(true), 30);
    assert!(h.has_text("leaves the channel"));
    wait(&mut h, 15);
    assert_eq!(sent(&h, "interface.wifi.scan"), before + 1, "not before 30 s");
    wait(&mut h, 16);
    assert_eq!(sent(&h, "interface.wifi.scan"), before + 2);
    // Another tab for a while: Auto is off when the tab comes back.
    panel(&mut h).tab = Tab::Radios;
    refresh(&mut h);
    h.time += 5.0;
    refresh(&mut h);
    panel(&mut h).tab = Tab::Networks;
    refresh(&mut h);
    assert!(!panel(&mut h).scan.auto);
    h.time += 60.0;
    refresh(&mut h);
    assert_eq!(sent(&h, "interface.wifi.scan"), before + 2);
}

#[test]
fn auto_starts_the_spectral_scan_again_when_it_ends() {
    let (s, ms) = joined(true);
    let mut h = networks(s);
    h.click(h.text("Spectrum"));
    refresh(&mut h);
    {
        let p = panel(&mut h);
        p.scan.duration = 2;
        p.scan.auto = true;
    }
    refresh(&mut h);
    h.click(h.text("Start"));
    assert_eq!(sent(&h, "interface.wifi.spectral-scan"), 1);
    // Past its 2 s: the data says it ended, and Auto starts it again.
    {
        let mut s = lock(&h.session);
        let mut t = ms;
        for _ in 0..12 {
            t += 250;
            s.wifi_service(t);
        }
    }
    wait(&mut h, 3);
    assert_eq!(sent(&h, "interface.wifi.spectral-scan"), 2, "{:?}", panel(&mut h).scan.spectral.as_ref().map(|d| d["running"].clone()));
    // Stop by hand turns Auto off.
    h.click(h.text("Stop"));
    assert!(!panel(&mut h).scan.auto);
}
