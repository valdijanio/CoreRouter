//! The Log window (G4.6d), a panel: the router's own log with time,
//! topics, origin and message; Legível/Técnico, filters, pause, clear.

use super::*;
use crate::system_log::{LogPanel, WIN, short_time};
use corerouter_model::ntp::{NtpState, NtpStatus};

fn refresh(h: &mut Harness) {
    h.app.cache.refreshed_at = None;
    for _ in 0..3 {
        h.idle();
    }
}

fn open(s: Session) -> Harness {
    let mut h = Harness::with_session(s);
    h.app.open.clear();
    h.app.open(Win::Panel(WIN));
    refresh(&mut h);
    h
}

/// A lab with a change from the GUI, a failed command and an NTP error.
fn lab() -> Session {
    let mut s = Session::virtual_lab();
    s.tick(1_792_674_309); // 2026-10-22 13:05:09 UTC
    s.execute("system.identity.set", &json!({"name": "edge1"}))
        .unwrap();
    s.execute(
        "system.ntp.client.set",
        &json!({"enabled": true, "servers": ["pool.ntp.org"]}),
    )
    .unwrap();
    s.set_ntp_status(NtpStatus {
        status: NtpState::Waiting,
        last_error: Some("pool.ntp.org: failed to lookup address information".into()),
        ..NtpStatus::default()
    });
    s.execute("ip.address.add", &json!({"address": "bad", "interface": "ether1"}))
        .unwrap_err();
    s
}

#[test]
fn log_window_shows_readable_lines_with_time_origin_and_colour() {
    let mut h = open(lab());
    assert!(h.has_text("Hora") && h.has_text("Origem") && h.has_text("Mensagem"));
    assert!(h.has_text("Nome do roteador alterado para «edge1»"));
    assert!(h.has_text("NTP Client ligado: servidores pool.ntp.org, poll 6–10"));
    assert!(h.has_text("13:05:09"), "today: time only");
    assert!(h.has_text("system,info"));
    let warn = "NTP: não foi possível resolver pool.ntp.org";
    assert!(h.has_text(warn));
    let visuals = h.ctx.global_style().visuals.clone();
    assert_eq!(h.text_color(warn), visuals.warn_fg_color);
    let failed = h
        .app
        .panel_mut::<LogPanel>()
        .unwrap()
        .lines
        .iter()
        .find(|l| l.level == "error")
        .unwrap()
        .message
        .clone();
    assert_eq!(h.text_color(&failed), visuals.error_fg_color);

    // A change made through the GUI shows who and from where.
    h.app.run("system.identity.set", json!({"name": "edge2"}));
    refresh(&mut h);
    assert!(h.has_text("Nome do roteador alterado para «edge2»"));
    assert!(h.has_text("local · GUI"));
}

#[test]
fn technical_view_adds_command_params_and_revision() {
    let mut h = open(lab());
    assert!(!h.has_text_containing("#1 system.identity.set"));
    h.click(h.text("Técnico"));
    assert!(h.app.panel_mut::<LogPanel>().unwrap().technical);
    let line = h
        .app
        .panel_mut::<LogPanel>()
        .unwrap()
        .lines
        .first()
        .unwrap()
        .technical();
    assert!(
        line.starts_with(r#"#1 system.identity.set {"name":"edge1"} → "#),
        "{line}"
    );
    assert!(line.contains("(revisão "), "{line}");
    assert!(h.has_text(&line));
}

#[test]
fn filters_narrow_the_lines_and_clear_empties() {
    let mut h = open(lab());
    let all = h.app.panel_mut::<LogPanel>().unwrap().shown().len();
    assert!(all >= 4, "{all}");
    h.click(h.text("Só avisos e erros"));
    let p = h.app.panel_mut::<LogPanel>().unwrap();
    assert!(p.only_problems);
    assert_eq!(p.shown().len(), 2, "the NTP warning and the failed command");
    p.only_problems = false;
    p.topic = "ntp".into();
    assert_eq!(p.shown().len(), 2, "NTP Client set and its error");
    p.topic.clear();
    p.find = "EDGE1".into();
    assert_eq!(p.shown().len(), 1);
    p.find.clear();
    h.idle();
    assert!(h.has_text(&format!("{all} de {all} linhas")));

    // Pause stops following; Clear asks the router.
    h.click(h.text("Pausar"));
    assert!(h.app.panel_mut::<LogPanel>().unwrap().paused);
    h.click(h.text("Limpar"));
    refresh(&mut h);
    let p = h.app.panel_mut::<LogPanel>().unwrap();
    let msgs: Vec<&str> = p.lines.iter().map(|l| l.message.as_str()).collect();
    assert_eq!(msgs, ["Log apagado"]);
}

#[test]
fn a_restarted_router_starts_the_window_over() {
    let mut h = open(lab());
    assert!(!h.app.panel_mut::<LogPanel>().unwrap().lines.is_empty());
    // Same window, new session: the numbering starts again.
    let mut fresh = Session::virtual_lab();
    fresh
        .execute("system.identity.set", &json!({"name": "after"}))
        .unwrap();
    *lock(&h.session) = fresh;
    refresh(&mut h);
    refresh(&mut h);
    let p = h.app.panel_mut::<LogPanel>().unwrap();
    let msgs: Vec<&str> = p.lines.iter().map(|l| l.message.as_str()).collect();
    assert_eq!(msgs, ["Nome do roteador alterado para «after»"]);
}

#[test]
fn times_show_the_date_only_on_other_days() {
    let today = 1_792_674_309 / 86_400;
    assert_eq!(short_time(1_792_674_309, today), "13:05:09");
    assert_eq!(short_time(1_792_674_309 - 86_400, today), "2026-10-21 13:05:09");
    assert_eq!(short_time(0, today), "—");
}
