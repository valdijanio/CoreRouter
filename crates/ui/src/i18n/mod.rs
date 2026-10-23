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
//! Catalogs: one file per language (`en.rs`, `pt.rs`), and a feature with
//! many texts gets its own pair (`tuning_en.rs`, `tuning_pt.rs`), so
//! parallel features do not edit the same list. Each table is sorted by
//! key: a lookup is a binary search per table.
//! - [`template`]: the GUI's own wording of a text the engine sends in
//!   English with arguments (`why.<id>`: why a value is recommended),
//!   `{name}` places filled by [`fill`].
//!
//! A preference of the window, not of the router: stored with the theme
//! (`prefs.rs`).

mod dns_lookup_pt;
mod bandwidth_en;
mod bandwidth_pt;
mod cgnat_en;
mod cgnat_pt;
mod connections_en;
mod connections_pt;
mod en;
mod graphs_en;
mod graphs_pt;
mod list_pt;
mod menu_en;
mod menu_pt;
mod pt;
mod routes_pt;
mod torch_en;
mod torch_pt;
mod traceroute_en;
mod traceroute_pt;
mod tuning_en;
mod tuning_pt;
mod traffic_flow_en;
mod traffic_flow_pt;

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
    fn labels(self) -> &'static [Table] {
        match self {
            Lang::En => &[],
            Lang::Pt => &[
                pt::LABELS,
                tuning_pt::LABELS,
                menu_pt::LABELS,
                routes_pt::LABELS,
                connections_pt::LABELS,
                cgnat_pt::LABELS,
                dns_lookup_pt::LABELS,
                list_pt::LABELS,
                torch_pt::LABELS,
                bandwidth_pt::LABELS,
                traffic_flow_pt::LABELS,
                graphs_pt::LABELS,
            ],
        }
    }

    /// Explanations: (key, Markdown), sorted by key.
    fn help(self) -> &'static [Table] {
        match self {
            Lang::En => &[
                en::HELP,
                tuning_en::HELP,
                menu_en::HELP,
                connections_en::HELP,
                cgnat_en::HELP,
                traffic_flow_en::HELP,
                graphs_en::HELP,
                torch_en::HELP,
                bandwidth_en::HELP,
                traceroute_en::HELP,
            ],
            Lang::Pt => &[
                pt::HELP,
                tuning_pt::HELP,
                menu_pt::HELP,
                connections_pt::HELP,
                cgnat_pt::HELP,
                traffic_flow_pt::HELP,
                graphs_pt::HELP,
                torch_pt::HELP,
                bandwidth_pt::HELP,
                traceroute_pt::HELP,
            ],
        }
    }

    /// Wordings of the engine's English texts: (key, template).
    fn templates(self) -> &'static [Table] {
        match self {
            Lang::En => &[],
            Lang::Pt => &[tuning_pt::TEMPLATES, routes_pt::TEMPLATES, dns_lookup_pt::TEMPLATES],
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

/// A catalog: (key, text), sorted by key.
type Table = &'static [(&'static str, &'static str)];

fn lookup(tables: &'static [Table], key: &str) -> Option<&'static str> {
    tables.iter().find_map(|table| {
        table
            .binary_search_by(|(k, _)| (*k).cmp(key))
            .ok()
            .and_then(|i| table.get(i))
            .map(|(_, text)| *text)
    })
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

/// The engine's English text `english` (template `key`, arguments
/// `args`) in `lang`: the catalog's template filled, else `english`.
pub fn template(lang: Lang, key: &str, args: &[(&str, &str)], english: &str) -> String {
    lookup(lang.templates(), key).map_or_else(|| english.to_owned(), |t| fill(t, args))
}

/// Put `args` into the `{name}` places of `template`.
pub fn fill(template: &str, args: &[(&str, &str)]) -> String {
    let mut out = template.to_owned();
    for (k, v) in args {
        out = out.replace(&format!("{{{k}}}"), v);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(tables: &[Table]) -> Vec<&'static str> {
        let mut k: Vec<&str> = tables.iter().flat_map(|t| t.iter().map(|(k, _)| *k)).collect();
        k.sort_unstable();
        k
    }

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
            for (what, tables) in [("labels", l.labels()), ("help", l.help()), ("templates", l.templates())] {
                for t in tables {
                    sorted_unique(&format!("{l:?} {what}"), t);
                }
                // Across tables a key may repeat (two features both say "of"), as long
                // as the text is the same: lookup takes the first, so only a different
                // text would make one window show the other's word. Parallel PRs kept
                // colliding on identical entries ("changed", "of", 2026-10-23).
                let mut all: Vec<(&str, &str)> = tables.iter().flat_map(|t| t.iter().copied()).collect();
                all.sort_unstable();
                for w in all.windows(2) {
                    if let [(a, ta), (b, tb)] = w {
                        assert!(
                            a != b || ta == tb,
                            "{l:?} {what}: {a:?} has two different texts across tables: {ta:?} and {tb:?}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn every_explanation_exists_in_both_languages() {
        assert_eq!(
            keys(Lang::En.help()),
            keys(Lang::Pt.help()),
            "every explanation key in English and in Portuguese"
        );
        for l in Lang::ALL {
            for (k, text) in l.help().iter().flat_map(|t| t.iter()) {
                assert!(!text.trim().is_empty(), "{k}: empty");
            }
        }
    }

    #[test]
    fn templates_fill_and_fall_back() {
        let args = [("gbps", "20")];
        assert_eq!(
            template(Lang::Pt, "why.backlog", &args, "english"),
            "Dimensionado para 20 Gb/s de portas: uma rajada espera no backlog em vez de ser descartada."
        );
        assert_eq!(template(Lang::En, "why.backlog", &args, "english"), "english");
        assert_eq!(template(Lang::Pt, "why.nope", &args, "english"), "english");
    }

    /// `{name}` places of a template, sorted.
    fn places(t: &str) -> Vec<&str> {
        let mut out: Vec<&str> = t
            .split('{')
            .skip(1)
            .filter_map(|p| p.split_once('}').map(|(n, _)| n))
            .collect();
        out.sort_unstable();
        out
    }

    #[test]
    fn every_engine_text_has_a_portuguese_template_with_the_same_places() {
        use corerouter_engine::route_detail::CHOICES;
        use corerouter_engine::route_table::REASONS;
        use corerouter_engine::tuning::{FINDINGS, WHY};
        let groups = [("why", WHY), ("finding", FINDINGS), ("route", REASONS), ("choice", CHOICES)];
        let mut ids = Vec::new();
        for (prefix, texts) in groups {
            for (id, en) in texts {
                let key = format!("{prefix}.{id}");
                let pt = lookup(Lang::Pt.templates(), &key)
                    .unwrap_or_else(|| panic!("no Portuguese template {key}"));
                assert_eq!(places(en), places(pt), "{key}");
                ids.push(key);
            }
        }
        for (id, en) in corerouter_engine::dns_upstreams::TEXTS {
            let key = format!("dnsbench.{id}");
            let pt = lookup(Lang::Pt.templates(), &key)
                .unwrap_or_else(|| panic!("dns_lookup_pt.rs lacks {key}"));
            assert_eq!(places(en), places(pt), "{key}");
            ids.push(key);
        }
        for (id, en) in corerouter_engine::dns_lookup::WHY_TEXTS {
            let key = format!("dnswhy.{id}");
            let pt = lookup(Lang::Pt.templates(), &key)
                .unwrap_or_else(|| panic!("dns_lookup_pt.rs lacks {key}"));
            assert_eq!(places(en), places(pt), "{key}");
            ids.push(key);
        }
        for (k, _) in Lang::Pt.templates().iter().flat_map(|t| t.iter()) {
            assert!(ids.iter().any(|i| i == k), "{k}: the engine has no such text");
        }
    }

    /// Glyphs the GUI's default fonts lack: they would show as boxes
    /// (found on the G1.26 screenshots).
    const MISSING_GLYPHS: [char; 5] = ['→', '⚠', 'ⓘ', '▸', '▾'];

    #[test]
    fn catalogs_use_only_glyphs_the_font_has() {
        for l in Lang::ALL {
            for t in l.help().iter().chain(l.labels()).chain(l.templates()) {
                for (k, text) in t.iter() {
                    for g in MISSING_GLYPHS {
                        assert!(!text.contains(g), "{l:?} {k}: {g} shows as a box");
                    }
                }
            }
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
        for (en, _) in Lang::Pt.labels().iter().flat_map(|t| t.iter()) {
            assert!(
                code.contains(&format!("{en:?}")),
                "pt.rs translates {en:?}, which no code asks for"
            );
        }
    }
}
