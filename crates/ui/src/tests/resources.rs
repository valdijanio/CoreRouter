//! System › Resources (G4.8a), a panel: the tabs on the lab's readings,
//! the health chip of the top bar and the optional CPU/memory readout.

use super::*;
use crate::resources::{ResourcesPanel, Tab, WIN, chip_id};

fn refresh(h: &mut Harness) {
    for _ in 0..3 {
        h.app.cache.refreshed_at = None;
        h.idle();
    }
}

fn open() -> Harness {
    let mut h = Harness::new();
    h.app.open.clear();
    h.app.open(Win::Panel(WIN));
    refresh(&mut h);
    h
}

fn tab(h: &mut Harness, t: Tab) {
    h.app.panel_mut::<ResourcesPanel>().unwrap().tab = t;
    refresh(h);
}

#[test]
fn overview_has_cards_links_and_checks() {
    let mut h = open();
    for text in ["Overview", "Processes", "OS Log", "CPU", "Memory", "Disk", "Temperature", "Interfaces", "Health checks"] {
        assert!(h.has_text(text), "{text}");
    }
    assert!(h.has_text("ether1"));
    assert!(h.has_text("10 G"), "link chip with the speed");
    assert!(h.has_text("NIC errors"));
    assert!(h.has_text_containing("ether4 com erros subindo"), "the reason, in Portuguese");
    assert!(h.has_text_containing("1 warning"), "header chip: only the bad cable (NTP off is the default)");
    assert!(h.has_text_containing("16 cores"));
    assert!(h.has_text_containing("crit 100 °C"));
    let p = h.app.panel_mut::<ResourcesPanel>().unwrap();
    assert!(p.print.as_ref().unwrap()["cpu_load"].is_number());
}

#[test]
fn every_tab_shows_its_part() {
    let mut h = open();
    tab(&mut h, Tab::Cpu);
    assert!(h.has_text("CPU0") && h.has_text("CPU15"));
    assert!(h.has_text("Load per core"));
    tab(&mut h, Tab::Memory);
    assert!(h.has_text("Available") && h.has_text("Memory pressure"));
    assert!(h.has_text("bgpd"), "largest processes");
    tab(&mut h, Tab::Disk);
    assert!(h.has_text("/dev/vda1"));
    assert!(h.has_text("Written since boot"));
    tab(&mut h, Tab::Network);
    assert!(h.has_text("ether8"));
    tab(&mut h, Tab::Sensors);
    assert!(h.has_text("coretemp") && h.has_text("Package"));
    tab(&mut h, Tab::Processes);
    assert!(h.has_text("corerouter-daemon"));
    h.app.panel_mut::<ResourcesPanel>().unwrap().sort = "memory";
    refresh(&mut h);
    let p = h.app.panel_mut::<ResourcesPanel>().unwrap();
    assert_eq!(p.procs.as_ref().unwrap()[0]["name"], "bgpd", "the router sorts by memory");
    tab(&mut h, Tab::OsLog);
    assert!(h.has_text_containing("G4.8b"));
}

#[test]
fn the_top_bar_chip_opens_the_window() {
    let mut h = Harness::new();
    h.app.open.clear();
    refresh(&mut h);
    let at = h.ctx.read_response(chip_id()).map(|r| r.rect.center());
    h.click(at.expect("the chip is in the top bar"));
    refresh(&mut h);
    assert!(h.app.open.contains(&Win::Panel(WIN)));
}

#[test]
fn the_readout_is_off_by_default_and_a_preference() {
    let mut h = Harness::new();
    h.app.open.clear();
    refresh(&mut h);
    assert!(!h.has_text_containing("MEM "), "off by default");
    assert!(h.app.prefs().contains(r#""readout":false"#));
    h.app.apply_prefs(r#"{"resources":{"readout":true}}"#);
    refresh(&mut h);
    assert!(h.has_text_containing("MEM "));
    assert!(h.has_text_containing("CPU "));
    assert!(h.app.prefs().contains(r#""readout":true"#));
}

/// G1.6qe: the Threads tab lists each thread of the router's processes,
/// the busiest first, and says when one fills a core.
#[test]
fn the_threads_tab_shows_the_daemon_threads() {
    let mut h = open();
    assert!(h.has_text("Threads"));
    tab(&mut h, Tab::Threads);
    for text in ["pppoe-ctl", "radius-aaa", "dns-lookup-0", "corerouter-daemon", "CPU (1 core)", "TID"] {
        assert!(h.has_text(text), "{text}");
    }
    let p = h.app.panel_mut::<ResourcesPanel>().unwrap();
    let rows = p.threads.as_ref().unwrap().as_array().unwrap();
    assert_eq!(rows[0]["tasks"][0]["name"], "pppoe-ctl", "the engine sorts the threads");
    let hot = rows[0]["tasks"][0]["cpu"].as_f64().unwrap();
    if hot >= 90.0 {
        assert!(h.has_text_containing("pppoe-ctl: "), "the chip names the hot thread");
    } else {
        assert!(h.has_text("No thread fills a core"));
    }
}
