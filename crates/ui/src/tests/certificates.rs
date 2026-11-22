//! System › Certificates (G1.6zs): the list, the Add and Import modals
//! through their previews, and www-ssl picking a certificate.

use super::*;
use crate::certificates::{CertificatesPanel, WIN};

fn refresh(h: &mut Harness) {
    h.app.cache.refreshed_at = None;
    for _ in 0..6 {
        h.idle();
    }
}

fn lab() -> Session {
    let mut s = Session::virtual_lab();
    s.tick(1_794_441_600); // the daemon's clock: 2026-11-12
    s.execute("ip.address.add", &json!({"address": "192.168.88.1/24", "interface": "ether2"})).unwrap();
    s
}

fn open(s: Session) -> Harness {
    let mut h = Harness::with_session(s);
    h.app.open.clear();
    h.app.open(Win::Panel(WIN));
    refresh(&mut h);
    h
}

fn set(h: &mut Harness, k: &'static str, v: &str) {
    let p = h.app.panel_mut::<CertificatesPanel>().unwrap();
    p.modal.as_mut().unwrap().1.values.insert(k, v.to_owned());
    h.time += 1.0;
    refresh(h);
}

#[test]
fn it_lists_certificates_with_state_names_and_use() {
    let mut s = lab();
    s.execute("certificate.add", &json!({"name": "web", "subject_alt_name": "router.lan, 192.168.88.1"})).unwrap();
    s.execute("ip.service.www-ssl.set", &json!({"certificate": "web"})).unwrap();
    let mut h = open(s);
    for text in ["web", "valid", "self-signed", "generated", "DNS:router.lan, IP:192.168.88.1", "ecdsa-p256", "2029-02-14 (825 d)", "www-ssl"] {
        assert!(h.has_text_containing(text), "{text}");
    }
    h.click(h.text("web"));
    refresh(&mut h);
    assert!(h.has_text_containing("SHA256:"), "the fingerprint of the selection");
    assert!(h.has_text_containing("browsers, iOS, macOS and Windows"), "the warnings of the selection");
}

#[test]
fn add_goes_through_the_preview_and_makes_the_certificate() {
    let mut h = open(lab());
    assert!(h.has_text_containing("No certificates."), "the empty table says what to do");
    h.app.with_panel_as::<CertificatesPanel, _>(|p, app| {
        p.modal = Some((crate::certificates::Which::Add, crate::list_modal::Modal::open(app, None, Default::default())));
    });
    refresh(&mut h);
    assert!(h.has_text_containing("New Certificate"));
    set(&mut h, "name", "has space");
    assert!(h.has_text_containing("letters, digits"), "the name error under the field");
    set(&mut h, "name", "dns-lan");
    set(&mut h, "days_valid", "900");
    assert!(h.has_text_containing("Apple devices refuse it"), "the warning of the preview");
    set(&mut h, "days_valid", "");
    assert!(h.has_text_containing("/certificate add name=dns-lan"), "the command it runs");
    assert!(h.has_text_containing("IP:192.168.88.1"), "the names it computes");
    h.click(h.text("OK"));
    refresh(&mut h);
    let rows = lock(&h.session).execute("certificate.print", &json!({})).unwrap();
    assert_eq!(rows[0]["name"], "dns-lan");
    assert!(h.app.panel_mut::<CertificatesPanel>().unwrap().modal.is_none());
}

#[test]
fn import_checks_the_pem_and_the_key() {
    let mut h = open(lab());
    let (cert, key) = corerouter_engine::x509::generate(&corerouter_engine::x509::NewCert {
        common_name: "dns.example.net".into(),
        subject_alt_names: vec!["DNS:dns.example.net".into()],
        key_type: "ecdsa-p256".into(),
        days_valid: 90,
        now: 1_794_441_600,
    })
    .unwrap();
    h.app.with_panel_as::<CertificatesPanel, _>(|p, app| {
        p.modal = Some((crate::certificates::Which::Import, crate::list_modal::Modal::open(app, None, Default::default())));
    });
    refresh(&mut h);
    set(&mut h, "name", "le");
    set(&mut h, "certificate", "not a pem");
    assert!(h.has_text_containing("no '-----BEGIN CERTIFICATE-----' block"));
    set(&mut h, "certificate", &cert);
    set(&mut h, "private_key", &key);
    assert!(h.has_text_containing("the key belongs to this certificate"));
    assert!(h.has_text_containing("dns.example.net"));
    // The command's preview hides the key (it shows in its own field only).
    let line = h
        .shapes
        .iter()
        .find_map(|c| match &c.shape {
            egui::Shape::Text(t) if t.galley.text().starts_with("/certificate import") => Some(t.galley.text().to_owned()),
            _ => None,
        })
        .unwrap();
    assert!(line.contains("private-key=\"•••\"") && !line.contains("PRIVATE KEY"), "{line}");
    h.click(h.text("OK"));
    refresh(&mut h);
    let rows = lock(&h.session).execute("certificate.print", &json!({})).unwrap();
    assert_eq!(rows[0]["origin"], "imported");
}

/// A long command (a PEM chain wraps into dozens of lines) scrolls inside
/// the preview: OK stays above the status bar. The certificate's length
/// varies by a byte or two with its random key, and the import test above
/// used to fail when the wrap gave the modal one or two more lines.
#[test]
fn a_long_chain_keeps_ok_on_screen() {
    let mut h = open(lab());
    let (cert, key) = corerouter_engine::x509::generate(&corerouter_engine::x509::NewCert {
        common_name: "dns.example.net".into(),
        subject_alt_names: vec!["DNS:dns.example.net".into()],
        key_type: "ecdsa-p256".into(),
        days_valid: 90,
        now: 1_794_441_600,
    })
    .unwrap();
    h.app.with_panel_as::<CertificatesPanel, _>(|p, app| {
        p.modal = Some((crate::certificates::Which::Import, crate::list_modal::Modal::open(app, None, Default::default())));
    });
    refresh(&mut h);
    set(&mut h, "name", "chain");
    set(&mut h, "certificate", &[cert.as_str(); 4].join("\n"));
    set(&mut h, "private_key", &key);
    assert!(h.has_text_containing("/certificate import"), "the preview came back");
    let ok = h.text("OK");
    let bar = h.text("ready");
    assert!(ok.y + 12.0 < bar.y, "OK at {ok:?}, the status bar at {bar:?}");
}

#[test]
fn www_ssl_offers_the_certificates_with_a_key() {
    let mut s = lab();
    s.execute("certificate.add", &json!({"name": "web"})).unwrap();
    let mut h = Harness::with_session(s);
    h.app.open.clear();
    h.app.open(Win::Panel(crate::ip_services::WIN));
    refresh(&mut h);
    h.app.with_panel_as::<crate::ip_services::ServicesPanel, _>(|p, app| p.act_for_test(app, crate::list::Act::Edit("www-ssl".into())));
    refresh(&mut h);
    assert!(h.has_text_containing("Certificate"));
    assert_eq!(h.app.panel_mut::<crate::ip_services::ServicesPanel>().unwrap().certificates, ["none", "web"]);
    h.app
        .panel_mut::<crate::ip_services::ServicesPanel>()
        .unwrap()
        .modal
        .as_mut()
        .unwrap()
        .values
        .insert("certificate", "web".to_owned());
    h.time += 1.0;
    refresh(&mut h);
    assert!(h.has_text_containing("certificate=web"), "the preview of the command");
    h.click(h.text("OK"));
    refresh(&mut h);
    assert_eq!(lock(&h.session).store().candidate().system.web.www_ssl.certificate, "web");
}

#[test]
fn every_explanation_exists_in_both_languages() {
    for key in [
        "menu.certificates",
        "certificates.certificate",
        "certificates.common_name",
        "certificates.days_valid",
        "certificates.expires",
        "certificates.import",
        "certificates.key_type",
        "certificates.name",
        "certificates.private_key",
        "certificates.state",
        "certificates.subject_alt_name",
        "certificates.used_by",
        "ip_services.certificate",
    ] {
        for lang in [crate::i18n::Lang::En, crate::i18n::Lang::Pt] {
            let langs = crate::i18n::Langs { labels: lang, help: lang };
            let (got, _) = crate::i18n::explain(langs, key).unwrap();
            assert_eq!(got, lang, "{key}");
        }
    }
}
