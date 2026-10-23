//! System › Tuning (G1.26a): Summary, Kernel and Profiles over the lab.

use super::*;
use crate::i18n::{self, Lang, Langs};
use crate::tuning::{Tab, TuningPanel, WIN, cpu_ranges, params};

fn open(tab: Tab) -> Harness {
    let mut h = Harness::with_session(Session::virtual_lab());
    h.app.open.clear();
    h.app.open(Win::Panel(WIN));
    h.app.with_panel_as::<TuningPanel, _>(|p, _| p.tab = tab);
    refresh(&mut h);
    h
}

fn refresh(h: &mut Harness) {
    h.app.cache.refreshed_at = None;
    for _ in 0..4 {
        h.idle();
    }
}

fn panel(h: &mut Harness) -> &mut TuningPanel {
    h.app.panel_mut::<TuningPanel>().unwrap()
}

#[test]
fn every_parameter_is_explained_in_both_languages() {
    for p in corerouter_model::tuning::PARAMS {
        let key = format!("tuning.{}", p.name);
        for l in [Lang::En, Lang::Pt] {
            let got = i18n::explain(Langs { labels: l, help: l }, &key);
            assert_eq!(got.map(|(l, _)| l), Some(l), "{key} in {l:?}");
        }
    }
}

#[test]
fn summary_shows_the_machine_and_the_diagnosis() {
    let mut h = open(Tab::Summary);
    assert!(h.has_text("Hardware"));
    assert!(h.has_text("16 × Virtual CPU (lab)"));
    assert!(h.has_text_containing("0: 0–7 16.0 GiB"));
    assert!(h.has_text("32.0 GiB"));
    // The lab's conntrack is 91 % full: said in the explanations' language.
    assert!(
        h.has_text("A tabela do conntrack está 91% cheia (240000 de 262144): conexões novas são descartadas quando ela enche."),
        "Portuguese finding"
    );
    assert!(h.has_text("warning") || h.has_text("critical"));
    assert!(h.has_text_containing("parameters differ from this profile."));

    // "Set" on the finding raises nf_conntrack_max to the balanced value.
    h.click(h.text("Set net.netfilter.nf_conntrack_max = 6684672"));
    refresh(&mut h);
    let set = lock(&h.session)
        .store()
        .running()
        .system
        .tuning
        .sysctl
        .get("net.netfilter.nf_conntrack_max")
        .copied();
    assert_eq!(set, Some(6_684_672), "{:?}", h.app.log());
    assert!(!h.has_text_containing("conntrack está"), "the finding is gone");
}

#[test]
fn kernel_tab_lists_edits_and_explains() {
    let mut h = open(Tab::Kernel);
    assert!(h.has_text("Packet receive (4)"));
    assert!(h.has_text("net.core.netdev_budget"));
    assert!(h.has_text("obsolete"), "chip on route.max_size v4");
    assert!(h.has_text("differs"), "current differs from the recommendation");

    // Select a row: the editor sets the value through the engine.
    h.click(h.text("net.core.netdev_budget"));
    h.idle();
    assert_eq!(panel(&mut h).selected.as_deref(), Some("net.core.netdev_budget"));
    panel(&mut h).edit = "900".into();
    h.idle();
    h.click(h.text("Set"));
    refresh(&mut h);
    let rows = params(panel(&mut h).print.as_ref().unwrap());
    let b = rows.iter().find(|p| p.name == "net.core.netdev_budget").unwrap();
    assert_eq!((b.configured, b.current), (Some(900), Some(900)));

    // Out of range: the engine's refusal shows.
    panel(&mut h).edit = "5".into();
    h.idle();
    h.click(h.text("Set"));
    refresh(&mut h);
    let err = panel(&mut h).error.clone().unwrap_or_default();
    assert!(err.contains("50..=100000"), "{err}");

    // Unset puts the kernel's value back.
    h.click(h.text("Unset"));
    refresh(&mut h);
    let rows = params(panel(&mut h).print.as_ref().unwrap());
    let b = rows.iter().find(|p| p.name == "net.core.netdev_budget").unwrap();
    assert_eq!((b.configured, b.current), (None, Some(300)));

    // ⓘ: explanation in Portuguese, the value recommended here and the
    // command, with English labels.
    let p = rows.iter().find(|p| p.name == "net.core.netdev_budget").unwrap().clone();
    panel(&mut h).help = Some(crate::tuning::explanation(&p, &p.why));
    h.idle();
    h.idle();
    assert!(h.has_text("O que faz"));
    assert!(h.has_text("Recomendado aqui"));
    assert!(h.has_text("Comando equivalente"));
    assert!(h.has_text_containing("/system tuning set name=net.core.netdev_budget value=600"));
    assert!(h.has_text("Close"));
}

#[test]
fn find_filters_and_portuguese_labels() {
    let mut h = open(Tab::Kernel);
    panel(&mut h).find = "gc_thresh".into();
    h.idle();
    h.idle();
    assert!(h.has_text("net.ipv4.neigh.default.gc_thresh3"));
    assert!(!h.has_text("net.core.netdev_budget"));
    panel(&mut h).find = "rmem".into();
    h.idle();
    h.idle();
    assert!(h.has_text("control plane"), "chip on the TCP section");
    h.app.lang.labels = Lang::Pt;
    h.idle();
    h.idle();
    assert!(h.has_text("Parâmetro"));
    panel(&mut h).find = "gc_thresh".into();
    h.idle();
    h.idle();
    assert!(h.has_text("Tabelas de vizinhos (6)"));
    assert!(h.has_text("Resumo"));
}

#[test]
fn apply_with_safe_mode_enters_it_and_applies_the_profile() {
    let mut h = open(Tab::Summary);
    h.click(h.text("Apply with Safe Mode"));
    refresh(&mut h);
    let s = lock(&h.session);
    assert!(s.in_safe_mode(), "{:?}", h.app.log());
    assert_eq!(
        s.store().running().system.tuning.sysctl.get("net.core.netdev_budget"),
        Some(&600)
    );
    drop(s);
    assert!(h.has_text_containing(": 0 parameters differ from this profile."));
}

#[test]
fn profiles_tab_compares_the_four() {
    let mut h = open(Tab::Profiles);
    for label in ["Conservative", "Balanced", "High throughput", "Low latency"] {
        assert!(h.has_text(label), "{label}");
    }
    assert!(h.has_text("7440 s"), "throughput's established timeout");
    // Show differences: the engine's list in a modal.
    panel(&mut h).tab = Tab::Summary;
    refresh(&mut h);
    h.click(h.text("Show differences"));
    refresh(&mut h);
    assert!(panel(&mut h).diff.is_some());
    assert!(h.has_text("Recommended"));
}

#[test]
fn numbers_read_well() {
    use crate::tuning::grouped;
    assert_eq!(grouped(7440), "7440");
    assert_eq!(grouped(6_684_672), "6 684 672");
    assert_eq!(grouped(-123_456), "-123 456");
    assert_eq!(grouped(i64::MIN), "-9 223 372 036 854 775 808");
    assert_eq!(cpu_ranges(&[0, 1, 2, 3, 8, 10, 11]), "0–3,8,10–11");
    assert_eq!(cpu_ranges(&[]), "");
}
