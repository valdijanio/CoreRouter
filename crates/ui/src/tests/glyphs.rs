//! G0.15c: every text the GUI can draw uses glyphs its fonts have. A glyph
//! the fonts lack shows as a box ("→", "⚠", "ⓘ", "▸" were, on the G1.26
//! screenshots), so the test asks egui's own fonts instead of a list.
//!
//! What it reads: every string and char literal of `crates/ui/src` outside
//! tests (the `i18n` catalogs are literals too), plus the engine's text
//! tables the GUI shows translated.

use std::path::{Path, PathBuf};

/// The fonts the GUI draws with: egui's defaults (`apps/corerouter-gui`
/// installs no text font of its own) and the icon font of `icons.rs`.
fn fonts() -> egui::Context {
    let ctx = egui::Context::default();
    crate::icons::install(&ctx);
    for _ in 0..2 {
        ctx.run_ui(egui::RawInput::default(), |_| {})
            .drop_without_applying_deltas();
    }
    ctx
}

/// Glyphs only the monospace font (Hack) has, in a file that draws them only
/// in monospace: the terminal's wrap mark.
const MONO_ONLY: &[(&str, char)] = &[("src/terminal.rs", '\u{21b3}')];

/// The characters of `text` (in source file `file`) the GUI fonts lack.
/// Text is drawn in the proportional family (whose fonts the monospace one
/// also falls back to); private-use code points are the icon font's.
fn missing(ctx: &egui::Context, file: &str, text: &str) -> Vec<char> {
    let prop = egui::FontId::proportional(14.0);
    let mono = egui::FontId::monospace(14.0);
    let icons = crate::icons::font(14.0);
    ctx.fonts_mut(|f| {
        text.chars()
            .filter(|c| !c.is_control())
            .filter(|&c| {
                if ('\u{e000}'..='\u{f8ff}').contains(&c) {
                    return !f.has_glyph(&icons, c);
                }
                let mono_ok = MONO_ONLY.contains(&(file, c)) && f.has_glyph(&mono, c);
                !f.has_glyph(&prop, c) && !mono_ok
            })
            .collect()
    })
}

/// A string or char literal and the line it starts on.
#[derive(Debug, PartialEq)]
struct Literal {
    line: usize,
    text: String,
}

/// The literals of Rust source `src`, outside comments and outside items
/// under `#[cfg(test)]`. A small lexer, enough for this crate: plain, raw
/// and byte strings, char literals (not lifetimes), `\u{…}` escapes.
fn literals(src: &str) -> Vec<Literal> {
    let chars: Vec<char> = src.chars().collect();
    let at = |i: usize| chars.get(i).copied().unwrap_or('\0');
    let mut out = Vec::new();
    let (mut i, mut line) = (0, 1);
    // Brace depth, and the depth at which a `#[cfg(test)]` item opened.
    let (mut depth, mut skip_from): (usize, Option<usize>) = (0, None);
    let mut test_attr = false;
    let mut code = String::new();
    while i < chars.len() {
        let c = at(i);
        if c == '\n' {
            line += 1;
        }
        if c == '/' && at(i + 1) == '/' {
            while i < chars.len() && at(i) != '\n' {
                i += 1;
            }
            continue;
        }
        if c == '/' && at(i + 1) == '*' {
            i += 2;
            while i < chars.len() && !(at(i) == '*' && at(i + 1) == '/') {
                line += usize::from(at(i) == '\n');
                i += 1;
            }
            i += 2;
            continue;
        }
        // Raw strings: r"…", r#"…"#, br"…".
        let raw_start = if c == 'r' { Some(i + 1) } else if c == 'b' && at(i + 1) == 'r' { Some(i + 2) } else { None };
        let ident_before = i > 0 && (at(i - 1).is_alphanumeric() || at(i - 1) == '_');
        if let (Some(mut j), false) = (raw_start, ident_before) {
            let mut hashes = 0;
            while at(j) == '#' {
                hashes += 1;
                j += 1;
            }
            if at(j) == '"' {
                let start_line = line;
                let mut text = String::new();
                j += 1;
                loop {
                    if j >= chars.len() {
                        break;
                    }
                    if at(j) == '"' && (1..=hashes).all(|h| at(j + h) == '#') {
                        j += 1 + hashes;
                        break;
                    }
                    line += usize::from(at(j) == '\n');
                    text.push(at(j));
                    j += 1;
                }
                if skip_from.is_none() {
                    out.push(Literal { line: start_line, text });
                }
                i = j;
                continue;
            }
        }
        if c == '"' {
            let start_line = line;
            let mut text = String::new();
            let mut j = i + 1;
            while j < chars.len() && at(j) != '"' {
                if at(j) == '\\' {
                    let (ch, len) = escape(&chars, j);
                    line += chars.iter().skip(j).take(len).filter(|c| **c == '\n').count();
                    text.extend(ch);
                    j += len;
                    continue;
                }
                line += usize::from(at(j) == '\n');
                text.push(at(j));
                j += 1;
            }
            if skip_from.is_none() {
                out.push(Literal { line: start_line, text });
            }
            i = j + 1;
            continue;
        }
        if c == '\'' {
            // 'x' or '\…' is a char; 'a (a lifetime or label) is not.
            let (ch, len) = if at(i + 1) == '\\' { escape(&chars, i + 1) } else { (Some(at(i + 1)), 1) };
            if at(i + 1 + len) == '\'' {
                if skip_from.is_none() {
                    out.push(Literal { line, text: ch.into_iter().collect() });
                }
                i += len + 2;
                continue;
            }
        }
        code.push(c);
        if code.ends_with("#[cfg(test)]") {
            test_attr = true;
        }
        match c {
            '{' => {
                if test_attr && skip_from.is_none() {
                    skip_from = Some(depth);
                }
                test_attr = false;
                depth += 1;
            }
            '}' => {
                depth = depth.saturating_sub(1);
                if skip_from == Some(depth) {
                    skip_from = None;
                }
            }
            ';' => test_attr = false,
            _ => {}
        }
        i += 1;
    }
    out
}

/// The character an escape at `chars[i]` (a backslash) stands for, and the
/// escape's length. A line continuation stands for nothing.
fn escape(chars: &[char], i: usize) -> (Option<char>, usize) {
    let at = |k: usize| chars.get(k).copied().unwrap_or('\0');
    match at(i + 1) {
        'u' if at(i + 2) == '{' => {
            let hex: String = chars.iter().skip(i + 3).take_while(|c| **c != '}').collect();
            let ch = u32::from_str_radix(&hex, 16).ok().and_then(char::from_u32);
            (ch, hex.len() + 4)
        }
        'x' => (None, 4),
        '\n' => {
            let blanks = chars.iter().skip(i + 2).take_while(|c| c.is_whitespace()).count();
            (None, blanks + 2)
        }
        c => (Some(c), 2),
    }
}

/// `crates/ui/src` without `src/tests/`.
fn ui_sources() -> Vec<PathBuf> {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut out = Vec::new();
    let mut dirs = vec![src.clone()];
    while let Some(d) = dirs.pop() {
        for e in std::fs::read_dir(&d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                if p != src.join("tests") {
                    dirs.push(p);
                }
            } else if p.extension().is_some_and(|x| x == "rs") {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

#[test]
fn literals_skip_comments_tests_and_lifetimes() {
    let src = r##"
// "→ in a comment"
/* "→" */
fn f<'a>(x: &'a str) -> char { let _ = r#"raw "→""#; '\u{25b8}' }
const S: &str = "a \"→\" \
    b";
#[cfg(test)]
mod tests { fn t() { let _ = "→"; } }
#[cfg(test)]
use x::y;
fn g() { "after" }
"##;
    let got: Vec<(usize, String)> = literals(src).into_iter().map(|l| (l.line, l.text)).collect();
    assert_eq!(
        got,
        [
            (4, r#"raw "→""#.to_owned()),
            (4, "▸".to_owned()),
            (5, "a \"→\" b".to_owned()),
            (11, "after".to_owned()),
        ]
    );
}

#[test]
fn catalogs_use_only_glyphs_the_font_has() {
    let ctx = fonts();
    // The fonts do lack these (what G0.15c found): the test must see them.
    for g in ['→', '⚠', 'ⓘ', '▸', '▾'] {
        assert_eq!(missing(&ctx, "", &g.to_string()), [g], "the fonts have {g} now: update the comment");
    }
    for (file, c) in MONO_ONLY {
        assert!(ctx.fonts_mut(|f| f.has_glyph(&egui::FontId::monospace(14.0), *c)), "{file}: monospace lacks {c}");
    }
    let mut bad = Vec::new();
    for path in ui_sources() {
        let src = std::fs::read_to_string(&path).unwrap();
        let name = path.strip_prefix(env!("CARGO_MANIFEST_DIR")).unwrap_or(&path).display().to_string();
        for lit in literals(&src) {
            // The bounds of the private-use range (`table.rs`, `chip.rs`
            // test whether a cell starts with an icon) are never drawn.
            if lit.text == "\u{e000}" || lit.text == "\u{f8ff}" {
                continue;
            }
            let m = missing(&ctx, &name, &lit.text);
            if !m.is_empty() {
                bad.push(format!("{name}:{}: {m:?}", lit.line));
            }
        }
    }
    use corerouter_engine::{dns_lookup, dns_upstreams, route_detail, route_table, tuning};
    let engine = [
        ("tuning::WHY", tuning::WHY),
        ("tuning::FINDINGS", tuning::FINDINGS),
        ("route_table::REASONS", route_table::REASONS),
        ("route_detail::CHOICES", route_detail::CHOICES),
        ("dns_upstreams::TEXTS", dns_upstreams::TEXTS),
        ("dns_lookup::WHY_TEXTS", dns_lookup::WHY_TEXTS),
    ];
    for (table, texts) in engine {
        for (id, text) in texts {
            let m = missing(&ctx, "", text);
            if !m.is_empty() {
                bad.push(format!("engine {table} {id}: {m:?}"));
            }
        }
    }
    assert!(bad.is_empty(), "glyphs the GUI fonts lack (they show as a box):\n{}", bad.join("\n"));
}

