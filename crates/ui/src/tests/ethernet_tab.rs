//! G1.20: the Ethernet and SFP tabs of "Interface <name>" over the
//! in-process lab — edit the link and send it with OK, read the SFP+
//! module of ether8, run a cable test (tasks on test threads).

use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use corerouter_engine::{Clock, Job, Runner};

use super::*;

struct Threads;
struct Wall(Instant);

impl Clock for Wall {
    fn elapsed(&self) -> Duration {
        self.0.elapsed()
    }
    fn sleep(&self, d: Duration) {
        thread::sleep(d);
    }
}

impl Runner for Threads {
    fn spawn(&self, _name: &str, job: Job) -> Result<(), String> {
        thread::spawn(move || job(&Wall(Instant::now())));
        Ok(())
    }
}

fn lab() -> Harness {
    let mut s = Session::virtual_lab();
    s.set_runner(Arc::new(Threads));
    s.tick(1_000);
    Harness::with_session(s)
}

impl Harness {
    /// Frames and real time until `done` holds (task threads).
    fn wait_for(&mut self, what: &str, mut done: impl FnMut(&Self) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !done(self) {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            thread::sleep(Duration::from_millis(20));
            self.time += 0.3;
            self.idle();
        }
        self.idle();
    }

    fn ethernet_of(&self, name: &str) -> corerouter_model::EthernetSettings {
        lock(&self.session)
            .store()
            .running()
            .interfaces
            .values()
            .find(|i| i.name.as_str() == name)
            .unwrap()
            .ethernet
            .clone()
    }
}

#[test]
fn ethernet_tab_edits_the_link_and_ok_sends_it() {
    let mut h = lab();
    h.app.open_props("ether2");
    h.wait(1.2);
    h.tab("Ethernet");
    assert!(h.has_text("Auto Negotiation"));
    assert!(h.has_text("Advertise"));
    assert!(h.has_text("Offloads"));
    assert!(h.has_text("Cable Test"));
    // Stop advertising gigabit: the box is the mode's label.
    h.click(h.text("1000baseT/Full"));
    h.click(h.text("GRO"));
    h.click(h.text("OK"));
    h.wait(0.5);
    let e = h.ethernet_of("ether2");
    let adv = e.advertise.unwrap();
    assert!(!adv.contains(&"1000baseT/Full".to_owned()), "{adv:?}");
    assert!(adv.contains(&"100baseT/Full".to_owned()));
    assert_eq!(e.offloads.get("rx-gro"), Some(&false));
    assert!(h.app.dialogs.is_empty(), "OK closed the window");
    let m = lock(&h.session)
        .execute("interface.ethernet.monitor", &json!({"name": "ether2"}))
        .unwrap();
    assert_eq!(m["rate"], "100Mbps");
}

#[test]
fn ethernet_tab_shows_the_engine_refusal() {
    let mut h = lab();
    h.app.open_props("ether3");
    h.wait(1.2);
    h.tab("Ethernet");
    // Force gigabit copper: the router refuses (it needs auto-negotiation).
    if let Some(v) = h.app.nic.get_mut("ether3") {
        let f = v.eth.form.as_mut().unwrap();
        f.autoneg = false;
        f.forced = "1000baseT/Full".into();
    }
    h.click(h.text("Apply"));
    h.wait(0.5);
    assert!(
        h.has_text_containing("needs auto-negotiation"),
        "the engine's reason is shown"
    );
    assert!(!h.app.dialogs.is_empty(), "the window stays open");
    assert_eq!(h.ethernet_of("ether3"), Default::default());
}

#[test]
fn sfp_tab_reads_the_module_and_copper_ports_say_why_not() {
    let mut h = lab();
    h.app.open_props("ether8");
    h.wait(1.2);
    h.tab("SFP");
    for t in [
        "SFP/SFP+/SFP28",
        "CoreRouter Lab",
        "CR-SFP10G-SR",
        "LC",
        "850 nm",
        "Diagnostics (DOM)",
        "rx-power",
        "-3.10 dBm",
    ] {
        assert!(h.has_text(t), "{t}");
    }
    h.key(egui::Key::Escape, egui::Modifiers::NONE);
    h.app.open_props("ether1");
    h.wait(1.2);
    h.tab("SFP");
    assert!(h.has_text_containing("No SFP: 'ether1' is a copper port"));
}

#[test]
fn cable_test_button_runs_the_task() {
    let mut h = lab();
    h.app.open_props("ether7");
    h.wait(1.2);
    h.tab("Ethernet");
    h.click(h.text("Cable Test"));
    h.wait_for("the cable test", |h| h.has_text_containing("cable-pairs:"));
    assert!(h.has_text("short"));
    assert!(h.has_text("23.5 m"));
    assert!(h.has_text_containing("cable-pairs: ok,ok,short:23.5,ok"));
}
