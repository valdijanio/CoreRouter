//! Languages of the GUI (G0.15): one for the **labels** (menus, columns,
//! buttons) and one for the **explanations** (help text, ⓘ modals), chosen
//! apart in Settings. Default: labels in English, as the rest of the app,
//! and explanations in Portuguese.
//!
//! - [`tr`]: a label. The English text is the key and the fallback, so code
//!   reads as English and a missing translation shows English, never a key.
//! - [`explain`]: the explanation of a parameter or topic by a stable key
//!   (`settings.labels_lang`, `tuning.net.core.netdev_max_backlog`), simple
//!   Markdown (`markdown.rs` draws it). Missing in the chosen language, it
//!   falls back to the other chosen one and then to English.
//!
//! Catalogs: one file per language (`en.rs`, `pt.rs`), sorted by key, so a
//! lookup is a binary search and a new entry has one obvious place.
//! A preference of the window, not of the router: stored with the theme
//! (`prefs.rs`).

mod en;
mod pt;

/// A language the GUI speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Lang {
    #[default]
    En,
    Pt,
}

impl Lang {
    pub const ALL: [Lang; 2] = [Lang::En, Lang::Pt];

    /// Stored in the preferences.
    pub fn code(self) -> &'static str {
        match self {
            Lang::En => "en",
            Lang::Pt => "pt",
        }
    }

    pub fn from_code(code: &str) -> Option<Lang> {
        Self::ALL.into_iter().find(|l| l.code() == code)
    }

    /// Its own name, as a language picker shows it.
    pub fn name(self) -> &'static str {
        match self {
            Lang::En => "English",
            Lang::Pt => "Português",
        }
    }

    /// Label translations: (English, this language), sorted by English.
    fn labels(self) -> &'static [(&'static str, &'static str)] {
        match self {
            Lang::En => &[],
            Lang::Pt => pt::LABELS,
        }
    }

    /// Explanations: (key, Markdown), sorted by key.
    fn help(self) -> &'static [(&'static str, &'static str)] {
        match self {
            Lang::En => en::HELP,
            Lang::Pt => pt::HELP,
        }
    }
}

/// The two choices of Settings › Language.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Langs {
    pub labels: Lang,
    pub help: Lang,
}

impl Default for Langs {
    fn default() -> Self {
        Self {
            labels: Lang::En,
            help: Lang::Pt,
        }
    }
}

fn lookup(
    table: &'static [(&'static str, &'static str)],
    key: &str,
) -> Option<&'static str> {
    table
        .binary_search_by(|(k, _)| (*k).cmp(key))
        .ok()
        .and_then(|i| table.get(i))
        .map(|(_, text)| *text)
}

/// Label `en` in `lang`; English when there is no translation.
pub fn tr(lang: Lang, en: &'static str) -> &'static str {
    lookup(lang.labels(), en).unwrap_or(en)
}

/// The explanation `key`: in `langs.help`, else `langs.labels`, else
/// English; with the language it came in. `None`: nobody wrote it.
pub fn explain(langs: Langs, key: &str) -> Option<(Lang, &'static str)> {
    [langs.help, langs.labels, Lang::En]
        .into_iter()
        .find_map(|l| lookup(l.help(), key).map(|text| (l, text)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sorted_unique(name: &str, table: &[(&str, &str)]) {
        for w in table.windows(2) {
            if let [(a, _), (b, _)] = w {
                assert!(a < b, "{name}: {a:?} must come before {b:?} (sorted, once)");
            }
        }
    }

    #[test]
    fn catalogs_are_sorted_and_unique() {
        for l in Lang::ALL {
            sorted_unique(&format!("{l:?} labels"), l.labels());
            sorted_unique(&format!("{l:?} help"), l.help());
        }
    }

    #[test]
    fn every_explanation_exists_in_both_languages() {
        let en: Vec<_> = en::HELP.iter().map(|(k, _)| *k).collect();
        let pt: Vec<_> = pt::HELP.iter().map(|(k, _)| *k).collect();
        assert_eq!(en, pt, "every explanation key in en.rs and pt.rs");
        for (k, text) in en::HELP.iter().chain(pt::HELP) {
            assert!(!text.trim().is_empty(), "{k}: empty");
        }
    }

    #[test]
    fn labels_fall_back_to_english() {
        assert_eq!(tr(Lang::Pt, "Settings"), "Configurações");
        assert_eq!(tr(Lang::En, "Settings"), "Settings");
        assert_eq!(tr(Lang::Pt, "No such label, ever"), "No such label, ever");
    }

    #[test]
    fn explanations_fall_back_without_panic() {
        let pt = Langs::default();
        let (l, text) = explain(pt, "settings.labels_lang").unwrap();
        assert_eq!(l, Lang::Pt);
        assert!(text.contains("rótulos"), "{text}");
        let en = Langs {
            labels: Lang::En,
            help: Lang::En,
        };
        assert_eq!(explain(en, "settings.labels_lang").unwrap().0, Lang::En);
        assert_eq!(explain(pt, "no.such.key"), None);
        assert_eq!(explain(pt, ""), None);
    }

    #[test]
    fn every_portuguese_label_is_used_somewhere() {
        // A translation nobody asks for is a typo of its English key.
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut code = String::new();
        let mut dirs = vec![src];
        while let Some(d) = dirs.pop() {
            for e in std::fs::read_dir(d).unwrap() {
                let p = e.unwrap().path();
                if p.is_dir() {
                    if !p.ends_with("i18n") {
                        dirs.push(p);
                    }
                } else if p.extension().is_some_and(|x| x == "rs") {
                    code.push_str(&std::fs::read_to_string(p).unwrap());
                }
            }
        }
        for (en, _) in pt::LABELS {
            assert!(
                code.contains(&format!("{en:?}")),
                "pt.rs translates {en:?}, which no code asks for"
            );
        }
    }
}
