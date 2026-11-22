//! G3.5b: Tools › LSP Ping over the in-process lab (its simulated LSPs,
//! answered by the real responder), with the engine's tasks on threads.

use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use corerouter_engine::tasks::SimClock;
use corerouter_engine::{Job, Runner};

use super::*;
use crate::lsp_ping::LspPingPanel;

struct Threads;

impl Runner for Threads {
    fn spawn(&self, name: &str, job: Job) -> Result<(), String> {
        thread::Builder::new()
            .name(name.into())
            .spawn(move || job(&SimClock::default()))
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

fn lab() -> Harness {
    let mut s = Session::virtual_lab();
    s.set_runner(Arc::new(Threads));
    let mut h = Harness::with_session(s);
    h.app.open.clear();
    crate::lsp_ping::open_with(&mut h.app, "10.255.0.4", false);
    for _ in 0..6 {
        h.idle();
    }
    h
}

/// Start the form as it is, and draw until the task is done.
fn run(h: &mut Harness) {
    h.app
        .with_panel_as::<LspPingPanel, _>(|p, app| {
            p.interval = "100".into();
            p.count = "3".into();
            p.start(app);
        })
        .unwrap();
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(10) {
        h.app.cache.refreshed_at = None;
        h.idle();
        if h.app.panel_mut::<LspPingPanel>().is_some_and(|p| p.done) {
            for _ in 0..3 {
                h.idle();
            }
            return;
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("the task did not finish");
}

#[test]
fn ping_shows_each_reply_with_its_code_and_the_path() {
    let mut h = lab();
    run(&mut h);
    let p = h.app.panel_mut::<LspPingPanel>().unwrap();
    assert_eq!(p.events.len(), 3, "{:?}", p.events);
    assert_eq!(p.summary["stats"]["received"], 3);
    assert!(p.events.iter().all(|e| e["detail"].as_str().unwrap().contains("egress for the FEC")));
    for t in ["MPLS 1401", "via 10.1.1.2 on ether1", "! 3", "Return Code"] {
        assert!(h.has_text(t), "{t}");
    }
}

#[test]
fn traceroute_lists_the_hops_and_where_it_ends() {
    let mut h = lab();
    h.app.panel_mut::<LspPingPanel>().unwrap().trace = true;
    run(&mut h);
    for t in ["MPLS 1402", "implicit-null", "reached the egress at hop 3", "Hop", "Labels"] {
        assert!(h.has_text(t), "{t}");
    }
    let p = h.app.panel_mut::<LspPingPanel>().unwrap();
    assert!(p.events[1]["detail"].as_str().unwrap().starts_with("label switched"), "{:?}", p.events);
    // A broken LSP: the hop and the reason.
    h.app.panel_mut::<LspPingPanel>().unwrap().fec = "10.255.9.9".into();
    run(&mut h);
    assert!(h.has_text("stopped at hop 2: no label entry at stack-depth 1"));
}

#[test]
fn the_form_sends_what_was_typed() {
    let mut p = LspPingPanel::default();
    p.fec = " 10.255.0.3 ".into();
    p.size = "200".into();
    p.ttl = "x".into();
    let (cmd, params) = p.params();
    assert_eq!(cmd, "tool.mpls.ping.start");
    assert_eq!(params["fec"], "10.255.0.3");
    assert_eq!(params["size"], 200);
    // Not a number: as typed, the engine says why.
    assert_eq!(params["ttl"], "x");
    assert!(params.get("max_hops").is_none());
    p.trace = true;
    let (cmd, params) = p.params();
    assert_eq!(cmd, "tool.mpls.traceroute.start");
    assert_eq!(params["max_hops"], 30);
    assert!(params.get("count").is_none());
}

#[test]
fn the_forwarding_table_opens_it_on_a_fec() {
    let mut h = lab();
    h.app.open.clear();
    crate::lsp_ping::open_with(&mut h.app, "10.255.0.2/32", true);
    let p = h.app.panel_mut::<LspPingPanel>().unwrap();
    assert_eq!((p.fec.as_str(), p.trace), ("10.255.0.2/32", true));
    assert!(h.app.open.contains(&Win::Panel(crate::lsp_ping::WIN)));
}

#[test]
fn every_label_explains_itself_in_both_languages() {
    for key in LspPingPanel::help_keys().into_iter().chain(["mpls.lsp_ping_responder", "mpls.lsp_ping_rate"]) {
        for lang in crate::i18n::Lang::ALL {
            let langs = crate::i18n::Langs { labels: lang, help: lang };
            assert_eq!(crate::i18n::explain(langs, key).map(|(l, _)| l), Some(lang), "{key}");
        }
    }
}
