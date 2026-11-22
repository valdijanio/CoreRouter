//! System › Install to disk (G1.6y): disks and what each asks, the network
//! test, the management choice, the confirmation, the screen after the reboot.

use super::*;
use corerouter_engine::install::{self, Disk, Holds, MediumInfo};

const WIN: Win = Win::Panel(crate::install_to_disk::WIN);

fn disk(name: &str, holds: Holds, serial: &str) -> Disk {
    Disk {
        name: name.into(),
        bytes: 240_000_000_000,
        model: "Kingston SA400".into(),
        serial: serial.into(),
        bus: "SATA".into(),
        removable: false,
        holds,
        detail: holds.as_str().into(),
        config_keepable: holds == Holds::CoreRouter,
        refused: None,
    }
}

fn lab() -> Session {
    let mut s = Session::virtual_lab();
    corerouter_engine::live::set(&mut s);
    install::set_support(&mut s, Ok(()));
    let mut stick = disk("sdb", Holds::Data, "S9");
    stick.refused = Some("the installer medium".into());
    install::set_scan(
        &mut s,
        Some(MediumInfo {
            device: "sdb".into(),
            version: "0.1.0-dev.9".into(),
            commit: "c".into(),
            channel: "dev".into(),
            signed_by: "ec2b".into(),
            min_disk: 1 << 30,
        }),
        vec![disk("sda", Holds::Empty, "S1"), disk("nvme0n1", Holds::Data, "S2"), disk("vda", Holds::CoreRouter, "S3"), stick],
    );
    install::set_network(
        &mut s,
        json!({
            "connected_port": "ether1",
            "problems": [],
            "firmware": ["regulatory.db"],
            "ports": [{
                "name": "ether1", "mac": "52:54:00:00:00:01", "driver": "igc", "link": true,
                "speed_mbps": 1000, "address": "192.0.2.42/24", "dhcp_status": "bound",
                "gateway": "192.0.2.1", "gateway_ok": true, "dns": ["192.0.2.1"], "dns_ok": true,
                "firmware": ["rtl_nic/rtl8125b-2.fw"], "connected": true,
            }, {
                "name": "ether2", "mac": "52:54:00:00:00:02", "driver": "igc", "link": false,
                "speed_mbps": null, "address": null, "dhcp_status": "searching", "gateway": null,
                "gateway_ok": null, "dns": [], "dns_ok": null, "firmware": [], "connected": false,
            }],
        }),
    );
    s
}

fn open(s: Session) -> Harness {
    let mut h = Harness::with_session(s);
    h.app.open.clear();
    h.app.open(WIN);
    refresh(&mut h);
    h
}

fn refresh(h: &mut Harness) {
    h.app.cache.refreshed_at = None;
    for _ in 0..6 {
        h.idle();
    }
}

fn job(h: &mut Harness) -> Option<install::Job> {
    install::take_job(&mut corerouter_engine::lock(&h.session))
}

#[test]
fn it_shows_disks_network_and_the_suggested_port() {
    let h = open(lab());
    for t in [
        "Install to disk", "0.1.0-dev.9", "signed", "sda", "nvme0n1", "vda", "empty", "data", "CoreRouter", "not offered",
        "Network test", "ether1", "192.0.2.42/24", "Gateway 192.0.2.1", "DNS answers", "you", "This GUI comes in through ether1",
        "Management after install", "suggested", "Keep DHCP", "Fix current address 192.0.2.42/24", "Install…",
    ] {
        assert!(h.has_text_containing(t), "{t}");
    }
    assert!(h.has_text_containing("rtl_nic/rtl8125b-2.fw"));
    assert!(!h.has_text_containing("regulatory.db"), "not a port's problem");
}

#[test]
fn a_router_that_is_installed_says_so() {
    let h = open(Session::virtual_lab());
    assert!(h.has_text_containing("this router is installed"));
    assert!(!h.has_text_containing("Network test"));
}

#[test]
fn an_empty_disk_asks_its_name_and_installs_with_the_chosen_management() {
    let mut h = open(lab());
    h.click(h.text("sda"));
    refresh(&mut h);
    h.click(h.text("Install…"));
    refresh(&mut h);
    assert!(h.has_text("Disk is empty"));
    assert!(!h.has_text_containing("Code on the console"));
    h.app
        .with_panel_as::<crate::install_to_disk::InstallPanel, _>(|p, app| p.confirm_for_test(app, "sda", ""))
        .unwrap();
    refresh(&mut h);
    let j = job(&mut h).expect("queued");
    assert_eq!(j.disk, "sda");
    let m = j.mgmt.unwrap();
    assert_eq!((m.port.as_str(), m.address), ("ether1", None));
}

#[test]
fn a_disk_with_data_asks_the_console_code_and_shows_a_wrong_one() {
    let mut h = open(lab());
    h.click(h.text("nvme0n1"));
    refresh(&mut h);
    h.click(h.text("Install…"));
    refresh(&mut h);
    assert!(h.has_text("Disk has data"));
    assert!(h.has_text_containing("Code on the console"));
    assert!(h.has_text_containing("Press the power button 3 times"));
    h.app
        .with_panel_as::<crate::install_to_disk::InstallPanel, _>(|p, app| p.confirm_for_test(app, "nvme0n1", "WRONG0"))
        .unwrap();
    refresh(&mut h);
    assert!(h.has_text_containing("wrong code"), "the error stays in the dialog");
    assert!(job(&mut h).is_none());
}

#[test]
fn a_corerouter_disk_offers_to_keep_its_configuration() {
    let mut h = open(lab());
    h.click(h.text("vda"));
    refresh(&mut h);
    h.click(h.text("Install…"));
    refresh(&mut h);
    for t in ["CoreRouter installed", "Keep configuration", "Code on the console", "Reinstall"] {
        assert!(h.has_text_containing(t), "{t}");
    }
}

#[test]
fn problems_of_the_network_only_warn() {
    let mut s = lab();
    install::set_network(&mut s, json!({"connected_port": null, "ports": [], "problems": ["no port has a link"], "firmware": []}));
    let h = open(s);
    assert!(h.has_text_containing("no port has a link"));
    assert!(h.has_text_containing("Install anyway…"));
}

#[test]
fn the_top_bar_says_live_and_opens_the_window_once() {
    let mut h = Harness::with_session(lab());
    h.app.open.clear();
    h.app.cache.info = json!({"name": "corerouter", "version": "0.1.0", "boot": "live"});
    for _ in 0..3 {
        h.idle();
    }
    assert!(h.has_text("live: not installed"));
    assert!(h.app.open.contains(&WIN));
    h.app.open.clear();
    for _ in 0..3 {
        h.idle();
    }
    assert!(!h.app.open.contains(&WIN), "only once: closing it stays closed");
    h.app.cache.info = json!({"name": "corerouter", "version": "0.1.0", "boot": "installed"});
    for _ in 0..3 {
        h.idle();
    }
    assert!(!h.has_text("live: not installed"));
}

/// The window asks for the password that lasts; the dialog would cover it.
#[test]
fn a_live_image_does_not_open_the_first_login_dialog_by_itself() {
    let mut h = Harness::with_session(lab());
    h.app.cache.whoami = json!({"user": "admin", "no_password": ["admin"]});
    h.app.cache.info = json!({"name": "corerouter", "version": "0.1.0", "boot": "live"});
    for _ in 0..3 {
        h.idle();
    }
    assert!(!h.app.password_dialog_open());
    h.app.open_password_dialog();
    for _ in 0..3 {
        h.idle();
    }
    assert!(h.app.password_dialog_open(), "the top bar's button still opens it");
    h.app.password_not_now();
    h.app.cache.info = json!({"name": "corerouter", "version": "0.1.0", "boot": "installed"});
    for _ in 0..3 {
        h.idle();
    }
    assert!(h.app.password_dialog_open(), "once installed it asks as on any router");
}
