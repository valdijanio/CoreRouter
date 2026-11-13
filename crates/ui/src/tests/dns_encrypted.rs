//! IP › DNS › Encrypted Service (G4.1zf): the form goes through
//! `ip.dns.encrypted-service.set` (and makes the certificate), the state and
//! the engine's checks show, and DNS Statistics' "DoT / DoH in" follows.

use super::*;
use crate::dns_encrypted::{EncryptedPanel, WIN};

fn refresh(h: &mut Harness) {
    h.app.cache.refreshed_at = None;
    for _ in 0..6 {
        h.idle();
    }
}

fn lab() -> Session {
    let mut s = Session::virtual_lab();
    s.tick(1_794_441_600);
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

#[test]
fn apply_turns_dot_on_with_a_certificate_and_shows_the_checks() {
    let mut h = open(lab());
    assert!(h.has_text("DNS over TLS"));
    assert!(h.has_text_containing("(made at the first Apply)"));
    h.app.panel_mut::<EncryptedPanel>().unwrap().form.dot = true;
    h.idle();
    h.click(h.text("Apply"));
    refresh(&mut h);
    let e = lock(&h.session).store().candidate().ip.dns.encrypted_service.clone();
    assert!(e.dot);
    assert_eq!(e.certificate, "dns-server");
    assert!(h.has_text_containing("made /certificate dns-server"), "the note of set");
    assert!(h.has_text_containing("allow_remote_requests is off"), "the engine's check");
    assert!(h.has_text("stopped"), "no daemon in the lab");
    assert_eq!(h.app.panel_mut::<EncryptedPanel>().unwrap().certificates, ["dns-server"]);
}

#[test]
fn doh_shows_its_url_once_on() {
    let mut s = lab();
    s.execute("ip.dns.encrypted-service.set", &json!({"doh": true, "doh_port": 8443})).unwrap();
    let mut h = open(s);
    assert!(h.has_text("DNS over HTTPS"));
    assert!(h.has_text_containing("/dns-query{?dns}"), "the URL to give clients");
    assert!(h.has_text("Copy"));
}

#[test]
fn statistics_say_dot_is_off_until_it_is_on() {
    let mut s = lab();
    s.execute("ip.dns.set", &json!({"allow_remote_requests": true})).unwrap();
    let mut h = Harness::with_session(s);
    h.app.open.clear();
    h.app.open(Win::Panel(crate::dns_statistics::WIN));
    refresh(&mut h);
    assert!(h.has_text("DoT / DoH in"));
    assert!(h.has_text("off"));
    lock(&h.session).execute("ip.dns.encrypted-service.set", &json!({"dot": true})).unwrap();
    refresh(&mut h);
    assert!(h.has_text_containing("0 (0 sessions)"));
}

#[test]
fn every_explanation_exists_in_both_languages() {
    for key in [
        "menu.dns-encrypted",
        "dns_encrypted.accepted",
        "dns_encrypted.announce_ddr",
        "dns_encrypted.certificate",
        "dns_encrypted.dot",
        "dns_encrypted.doh",
        "dns_encrypted.doh_errors",
        "dns_encrypted.doh_path",
        "dns_encrypted.doh_port",
        "dns_encrypted.doh_queries",
        "dns_encrypted.dot_port",
        "dns_encrypted.fingerprint",
        "dns_encrypted.handshake_failures",
        "dns_encrypted.handshakes",
        "dns_encrypted.http2",
        "dns_encrypted.idle_timeout_secs",
        "dns_encrypted.last_error",
        "dns_encrypted.max_sessions",
        "dns_encrypted.over_limit",
        "dns_encrypted.queries",
        "dns_encrypted.refused",
        "dns_encrypted.resumed",
        "dns_encrypted.sessions",
        "dns_encrypted.status",
        "dns_encrypted.url",
    ] {
        for lang in [crate::i18n::Lang::En, crate::i18n::Lang::Pt] {
            let langs = crate::i18n::Langs { labels: lang, help: lang };
            let (got, _) = crate::i18n::explain(langs, key).unwrap();
            assert_eq!(got, lang, "{key}");
        }
    }
}
