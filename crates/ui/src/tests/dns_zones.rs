//! IP › DNS › Zones (G4.1c), a panel: zones, records and the zone file.

use super::*;
use crate::dns_zones::{RECORD_TABLE, WIN, WIN_FILE, WIN_RECORDS, ZONE_TABLE, ZonesPanel, record_row, zone_row};

fn lab() -> Session {
    let mut s = Session::virtual_lab();
    s.execute("ip.dns.zone.add", &json!({"name": "example.com"}))
        .unwrap();
    s.execute(
        "ip.dns.zone.record.add",
        &json!({"zone": "example.com", "name": "www", "address": "192.0.2.80"}),
    )
    .unwrap();
    s.execute(
        "ip.dns.zone.add",
        &json!({"name": "sec.example", "type": "secondary", "primaries": "192.0.2.53"}),
    )
    .unwrap();
    s
}

fn open(s: Session, win: &'static str) -> Harness {
    let mut h = Harness::with_session(s);
    h.app.open.clear();
    h.app.open(Win::Panel(win));
    refresh(&mut h);
    h
}

fn refresh(h: &mut Harness) {
    h.app.cache.refreshed_at = None;
    for _ in 0..3 {
        h.idle();
    }
}

#[test]
fn zones_window_lists_zones_and_opens_records() {
    let mut h = open(lab(), WIN);
    assert!(h.has_text("DNS Zones"));
    assert!(h.has_text("example.com"));
    assert!(h.has_text("secondary"));
    assert!(h.has_text("config only (no daemon)"));
    let p = h.app.panel_mut::<ZonesPanel>().unwrap();
    assert_eq!(p.zones.len(), 2);
    assert_eq!(p.zone, "example.com", "the records window follows the first zone");
    // Records of the zone.
    h.app.open(Win::Panel(WIN_RECORDS));
    refresh(&mut h);
    assert!(h.has_text("DNS Zone Records"));
    assert!(h.has_text("192.0.2.80"));
    let _ = (ZONE_TABLE, RECORD_TABLE);
}

#[test]
fn a_new_record_by_dialog_reaches_the_engine() {
    let mut h = open(lab(), WIN_RECORDS);
    let add = h
        .ctx
        .read_response(table::tool_id(RECORD_TABLE, table::Icon::Add))
        .unwrap()
        .rect
        .center();
    h.click(add);
    refresh(&mut h);
    assert!(h.has_text("New Record in example.com"));
    {
        let p = h.app.panel_mut::<ZonesPanel>().unwrap();
        let d = p.dialogs.last_mut().unwrap();
        let crate::dns_zones::Dialog::NewRecord(f) = &mut d.dialog else {
            panic!("a new record dialog")
        };
        f.name = "mail".into();
        f.address = "192.0.2.25".into();
    }
    h.idle();
    h.click(h.text("OK"));
    refresh(&mut h);
    let rows = lock(&h.session)
        .execute("ip.dns.zone.record.print", &json!({"name": "mail"}))
        .unwrap();
    assert_eq!(rows[0]["address"], "192.0.2.25", "{:?}", h.app.log());
    assert!(h.app.panel_mut::<ZonesPanel>().unwrap().dialogs.is_empty());
}

#[test]
fn the_zone_file_window_reads_and_loads() {
    let mut h = open(lab(), WIN);
    {
        let p = h.app.panel_mut::<ZonesPanel>().unwrap();
        p.file.zone = "example.com".into();
    }
    h.app.open(Win::Panel(WIN_FILE));
    refresh(&mut h);
    h.click(h.text("Reload"));
    refresh(&mut h);
    let text = h.app.panel_mut::<ZonesPanel>().unwrap().file.text.clone();
    assert!(text.contains("www 3600 IN A 192.0.2.80"), "{text}");
    h.app.panel_mut::<ZonesPanel>().unwrap().file.text =
        format!("{text}ftp 300 IN A 192.0.2.21\n");
    h.idle();
    h.click(h.text("Load into Zone"));
    refresh(&mut h);
    let msg = h.app.panel_mut::<ZonesPanel>().unwrap().file.message.clone();
    assert!(
        msg.as_ref().is_some_and(|m| m.as_ref().is_ok_and(|t| t.starts_with("Loaded: 3 records"))),
        "{msg:?}"
    );
    let rows = lock(&h.session)
        .execute("ip.dns.zone.record.print", &json!({"name": "ftp"}))
        .unwrap();
    assert_eq!(rows[0]["ttl_secs"], 300);
}

#[test]
fn rows_say_what_they_are() {
    let z = json!({"id": "*2", "name": "sec.example", "type": "secondary", "serial": 0,
        "records": 7, "status": "loaded", "loaded_serial": 42, "flags": ""});
    let r = zone_row(&z);
    assert_eq!(r.cells[3], "42", "a secondary shows the serial it loaded");
    assert_eq!(r.cells[5], "loaded, serial 42");
    let rec = json!({"id": "*1", "zone": "example.com", "name": "www", "type": "A",
        "data": "192.0.2.80", "ttl": 3600, "flags": ""});
    assert_eq!(record_row(&rec).cells[4], "(3600)", "the zone's TTL in parentheses");
}
