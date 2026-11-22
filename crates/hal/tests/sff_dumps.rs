//! G1.20 — the SFF decoder against EEPROM dumps of real modules, published
//! with `ethtool -m` output (sources in each `tests/sff/*.hex` header).
//! Identity and thresholds must match the published decode exactly; live
//! readings are checked against the bytes of the dump itself.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use corerouter_hal::sff::{self, DiagPage, Level, SfpModule};

/// The bytes of a fixture: `0xNNNN: aa bb …` lines, in order.
fn dump(name: &str) -> Vec<u8> {
    let path = format!("{}/tests/sff/{name}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    let mut out = Vec::new();
    for line in text.lines().filter(|l| l.starts_with("0x")) {
        let (at, hex) = line.split_once(':').unwrap();
        let at = usize::from_str_radix(at.trim_start_matches("0x"), 16).unwrap();
        assert_eq!(at, out.len(), "{name}: gap before {at:#x}");
        out.extend(
            hex.split_whitespace()
                .map(|b| u8::from_str_radix(b, 16).unwrap()),
        );
    }
    out
}

fn reading(m: &SfpModule, key: &str) -> (f64, Option<sff::Limits>, Option<Level>) {
    let r = m
        .dom
        .iter()
        .find(|r| r.key() == key)
        .unwrap_or_else(|| panic!("no {key} in {:?}", m.dom));
    (r.value, r.limits, r.level)
}

fn close(a: f64, b: f64, tol: f64) -> bool {
    (a - b).abs() <= tol
}

fn mw_to_dbm(mw: f64) -> f64 {
    10.0 * mw.log10()
}

#[test]
fn finisar_sfp_with_internal_calibration() {
    let d = dump("finisar_ftlf8524p2bnv.hex");
    let (a0, a2) = (&d[..256], &d[256..384]);
    assert_eq!(sff::diag_page(a0), DiagPage::A2);
    let m = sff::decode(a0, Some(a2));
    assert_eq!(m.kind.as_deref(), Some("SFP/SFP+/SFP28"));
    assert_eq!(m.connector.as_deref(), Some("LC"));
    assert!(
        m.compliance.contains(&"1000BASE-SX".to_owned()),
        "{:?}",
        m.compliance
    );
    assert_eq!(m.vendor_name.as_deref(), Some("FINISAR CORP."));
    assert_eq!(m.vendor_oui.as_deref(), Some("00:90:65"));
    assert_eq!(m.vendor_part_number.as_deref(), Some("FTLF8524P2BNV"));
    assert_eq!(m.vendor_revision.as_deref(), Some("A"));
    assert_eq!(m.vendor_serial.as_deref(), Some("PFA48HS"));
    assert_eq!(m.manufacturing_date.as_deref(), Some("2009-03-06"));
    assert_eq!(m.wavelength_nm, Some(850.0));
    assert_eq!(m.nominal_rate_mbd, Some(4200));
    assert_eq!(m.checksum_ok, Some(true));
    assert_eq!(m.rx_loss, Some(false));
    assert!(!m.cable);
    let lengths: Vec<(&str, u32)> = m.link_length.iter().map(|l| (l.medium, l.meters)).collect();
    assert_eq!(lengths, [("om1", 70), ("om2", 150)]);

    // Published thresholds (ethtool -m): 95/-25/90/-20 C, 3.9/2.7/3.7/2.9 V,
    // 17/1/14/2 mA, TX 0.6310/0.0670/0.6310/0.0790 mW, RX 1.2590/0.0100/0.7940/0.0158 mW.
    let (t, lim, level) = reading(&m, "temperature");
    assert!(close(t, 29.23, 0.01), "{t}");
    assert_eq!(level, Some(Level::Ok));
    let lim = lim.unwrap();
    assert_eq!(
        (
            lim.high_alarm,
            lim.low_alarm,
            lim.high_warning,
            lim.low_warning
        ),
        (95.0, -25.0, 90.0, -20.0)
    );
    let (v, lim, _) = reading(&m, "supply-voltage");
    assert!(close(v, 3.3016, 1e-4), "{v}");
    let lim = lim.unwrap();
    assert!(close(lim.high_alarm, 3.9, 1e-4) && close(lim.low_alarm, 2.7, 1e-4));
    let (i, lim, _) = reading(&m, "tx-bias-current");
    assert!(close(i, 6.902, 1e-3), "{i}");
    let lim = lim.unwrap();
    assert!(close(lim.high_alarm, 17.0, 1e-3) && close(lim.low_warning, 2.0, 1e-3));
    let (tx, lim, _) = reading(&m, "tx-power");
    assert!(close(tx, mw_to_dbm(0.3996), 0.01), "{tx}");
    let lim = lim.unwrap();
    assert!(close(lim.high_alarm, mw_to_dbm(0.6310), 0.01));
    assert!(close(lim.low_alarm, mw_to_dbm(0.0670), 0.01));
    let (rx, lim, level) = reading(&m, "rx-power");
    assert!(close(rx, mw_to_dbm(0.4404), 0.01), "{rx}");
    assert_eq!(level, Some(Level::Ok));
    let lim = lim.unwrap();
    assert!(close(lim.high_alarm, mw_to_dbm(1.2590), 0.01));
    assert!(close(lim.low_warning, mw_to_dbm(0.0158), 0.01));
    assert_eq!(m.alerts().count(), 0);
}

#[test]
fn passive_dac_has_no_laser_and_no_dom() {
    let d = dump("sfp_dac_3m.hex");
    let a0 = &d[..256];
    assert_eq!(sff::diag_page(a0), DiagPage::None);
    let m = sff::decode(a0, None);
    assert!(m.cable);
    assert_eq!(m.connector.as_deref(), Some("copper-pigtail"));
    assert_eq!(m.vendor_name.as_deref(), Some("OEM"));
    assert_eq!(m.vendor_oui.as_deref(), Some("00:40:20"));
    assert_eq!(m.vendor_part_number.as_deref(), Some("SFP-H10GB-CU3M"));
    assert_eq!(m.vendor_revision.as_deref(), Some("R"));
    assert_eq!(m.vendor_serial.as_deref(), Some("CSC210403850189"));
    assert_eq!(m.manufacturing_date.as_deref(), Some("2021-04-26"));
    assert_eq!(m.nominal_rate_mbd, Some(10_300));
    assert_eq!(m.wavelength_nm, None, "a DAC has no wavelength");
    assert!(m.compliance.contains(&"passive copper cable".to_owned()));
    let lengths: Vec<(&str, u32)> = m.link_length.iter().map(|l| (l.medium, l.meters)).collect();
    assert_eq!(lengths, [("cable", 3)]);
    assert_eq!(m.checksum_ok, Some(true));
    assert!(m.dom.is_empty());
    assert!(m.notes.iter().any(|n| n.contains("no diagnostics")));
}

#[test]
fn qsfp28_aoc_with_threshold_page() {
    let d = dump("qsfp28_aoc_3m.hex");
    // Legacy ethtool layout: lower, page 00h, 01h, 02h, 03h (128 B each).
    let (page0, page3) = (&d[..256], &d[512..640]);
    assert_eq!(sff::diag_page(page0), DiagPage::Page3);
    let m = sff::decode(page0, Some(page3));
    assert_eq!(m.kind.as_deref(), Some("QSFP28"));
    assert_eq!(m.spec.as_deref(), Some("SFF-8636"));
    assert_eq!(m.connector.as_deref(), Some("no-separable-connector"));
    assert_eq!(m.vendor_name.as_deref(), Some("CISCO-PROLINE"));
    assert_eq!(m.vendor_part_number.as_deref(), Some("QSFP-100G-AOC-3M"));
    assert_eq!(m.vendor_revision.as_deref(), Some("D1"));
    assert_eq!(m.manufacturing_date.as_deref(), Some("2025-08-11"));
    assert_eq!(m.wavelength_nm, Some(850.0));
    // Byte 140 = 0xFF, byte 222 = 103 × 250 MBd (the 25.78 GBd of a 100G
    // lane); the published text, from another ethtool, says 25500.
    assert_eq!(m.nominal_rate_mbd, Some(25_750));
    assert!(
        m.compliance.iter().any(|c| c.contains("100G AOC")),
        "{:?}",
        m.compliance
    );
    let lengths: Vec<(&str, u32)> = m.link_length.iter().map(|l| (l.medium, l.meters)).collect();
    assert_eq!(lengths, [("cable", 3)]);
    // Published: 51.01 C, 3.2688 V, RX 2.3192/2.3952/2.4352/2.0848 mW.
    let (t, lim, _) = reading(&m, "temperature");
    assert!(close(t, 51.01, 0.01), "{t}");
    let lim = lim.unwrap();
    assert_eq!(
        (
            lim.high_alarm,
            lim.low_alarm,
            lim.high_warning,
            lim.low_warning
        ),
        (90.0, -20.0, 80.0, -10.0)
    );
    let (v, lim, _) = reading(&m, "supply-voltage");
    assert!(close(v, 3.2688, 1e-4), "{v}");
    assert!(close(lim.unwrap().high_alarm, 3.62, 1e-4));
    for (lane, mw) in [(1, 2.3192), (2, 2.3952), (3, 2.4352), (4, 2.0848)] {
        let (rx, lim, level) = reading(&m, &format!("rx-power lane {lane}"));
        assert!(close(rx, mw_to_dbm(mw), 0.01), "lane {lane}: {rx}");
        assert_eq!(level, Some(Level::Ok));
        let lim = lim.unwrap();
        assert!(close(lim.high_alarm, mw_to_dbm(6.5), 0.01));
        assert!(close(lim.low_alarm, mw_to_dbm(0.05), 0.01));
    }
    let (_, lim, _) = reading(&m, "tx-bias-current lane 1");
    let lim = lim.unwrap();
    assert!(close(lim.high_alarm, 14.0, 1e-3) && close(lim.low_warning, 1.5, 1e-3));
    assert_eq!(m.alerts().count(), 0);
}

#[test]
fn qsfp28_lr4_without_threshold_page() {
    let d = dump("qsfp28_mellanox_lr4.hex");
    let m = sff::decode(&d, None);
    assert_eq!(m.kind.as_deref(), Some("QSFP28"));
    assert_eq!(m.connector.as_deref(), Some("LC"));
    assert_eq!(m.vendor_oui.as_deref(), Some("00:02:c9"));
    assert_eq!(m.vendor_serial.as_deref(), Some("MT1639DM00026"));
    assert!(
        m.compliance.iter().any(|c| c.contains("100GBASE-LR4")),
        "{:?}",
        m.compliance
    );
    assert!(close(m.wavelength_nm.unwrap(), 1302.35, 0.01));
    assert_eq!(m.checksum_ok, Some(true));
    // Published: 42.16 C, 3.2523 V. No page 03h: readings without limits
    // (the old ethtool bug decoded garbage thresholds past byte 256).
    let (t, lim, level) = reading(&m, "temperature");
    assert!(close(t, 42.16, 0.01), "{t}");
    assert_eq!((lim, level), (None, None));
    let (v, _, _) = reading(&m, "supply-voltage");
    assert!(close(v, 3.2523, 1e-4));
}
