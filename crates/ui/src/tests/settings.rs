//! Settings (G0.15): the languages of the labels and of the explanations.

use super::*;
use crate::help::HelpView;
use crate::i18n::{Lang, Langs};
use crate::settings::{SettingsPanel, WIN};

fn open() -> Harness {
    let mut h = Harness::with_session(Session::virtual_lab());
    h.app.open.clear();
    h.app.open(Win::Panel(WIN));
    h.idle();
    h.idle();
    h
}

#[test]
fn settings_window_defaults_to_english_labels_and_portuguese_help() {
    let mut h = open();
    assert_eq!(h.app.lang, Langs::default());
    assert!(h.has_text("Labels"));
    assert!(h.has_text("Explanations"));
    assert!(h.has_text("English"));
    assert!(h.has_text("Português"));

    // ⓘ: the explanation comes in Portuguese while the labels stay English.
    h.app.panel_mut::<SettingsPanel>().unwrap().help =
        Some(HelpView::new("settings.labels_lang", "Labels"));
    h.idle();
    h.idle();
    assert!(h.has_text("O que faz"), "Portuguese explanation");
    assert!(h.has_text("Close"), "English button");
}

#[test]
fn portuguese_labels_translate_the_new_windows_only() {
    let mut h = open();
    h.app.lang.labels = Lang::Pt;
    h.app.lang.help = Lang::En;
    h.app.open(Win::Interfaces);
    h.idle();
    h.idle();
    assert!(h.has_text("Configurações"), "window title and menu");
    assert!(h.has_text("Rótulos"));
    assert!(h.has_text("Interfaces"), "untranslated labels stay English");

    h.app.panel_mut::<SettingsPanel>().unwrap().help =
        Some(HelpView::new("settings.help_lang", "Explicações"));
    h.idle();
    h.idle();
    assert!(h.has_text("What it does"), "English explanation");
    assert!(h.has_text("Fechar"));
    assert!(h.app.prefs().contains(r#""labels_lang":"pt""#));
}

#[test]
fn picking_a_language_in_the_window_changes_it() {
    let mut h = open();
    h.click(h.text("English"));
    h.idle();
    // The popup is painted last: its "Português" is the topmost one.
    h.click(h.text("Português"));
    h.idle();
    assert_eq!(h.app.lang.labels, Lang::Pt, "{:?}", h.app.lang);
    h.idle();
    assert!(h.has_text("Idioma"));
    assert!(h.has_text("Guardado neste computador, não no roteador."));
}
