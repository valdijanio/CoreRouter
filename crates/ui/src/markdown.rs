//! The little Markdown the explanations use (G0.15, `i18n`): `## heading`,
//! `- bullet`, paragraphs split by a blank line, `` `code` `` and
//! `**bold**`. Anything else is plain text, so a stray `*` or `` ` `` shows
//! as it is: the catalogs are ours, but a renderer must not panic on any
//! input.

use egui::text::LayoutJob;
use egui::{FontId, RichText, TextFormat, TextStyle, Ui};

/// A block of the text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Block {
    Heading(String),
    Paragraph(String),
    Bullet(String),
}

/// Split `text` into blocks: consecutive plain lines are one paragraph.
pub(crate) fn blocks(text: &str) -> Vec<Block> {
    let mut out = Vec::new();
    let mut para = String::new();
    let flush = |para: &mut String, out: &mut Vec<Block>| {
        if !para.is_empty() {
            out.push(Block::Paragraph(std::mem::take(para)));
        }
    };
    for line in text.lines().map(str::trim) {
        if line.is_empty() {
            flush(&mut para, &mut out);
        } else if let Some(h) = line.strip_prefix("## ") {
            flush(&mut para, &mut out);
            out.push(Block::Heading(h.trim().to_owned()));
        } else if let Some(b) = line.strip_prefix("- ") {
            flush(&mut para, &mut out);
            out.push(Block::Bullet(b.trim().to_owned()));
        } else {
            if !para.is_empty() {
                para.push(' ');
            }
            para.push_str(line);
        }
    }
    flush(&mut para, &mut out);
    out
}

/// Inline spans: (text, code, bold).
pub(crate) fn spans(text: &str) -> Vec<(String, bool, bool)> {
    let mut out: Vec<(String, bool, bool)> = Vec::new();
    let mut rest = text;
    let mut bold = false;
    while !rest.is_empty() {
        let tick = rest.find('`');
        let star = rest.find("**");
        match (tick, star) {
            (Some(t), s) if s.is_none_or(|s| t < s) => {
                let after = rest.get(t + 1..).unwrap_or("");
                match after.find('`') {
                    Some(end) => {
                        push(&mut out, rest.get(..t).unwrap_or(""), false, bold);
                        push(&mut out, after.get(..end).unwrap_or(""), true, bold);
                        rest = after.get(end + 1..).unwrap_or("");
                    }
                    None => {
                        push(&mut out, rest, false, bold);
                        rest = "";
                    }
                }
            }
            (_, Some(s)) => {
                push(&mut out, rest.get(..s).unwrap_or(""), false, bold);
                bold = !bold;
                rest = rest.get(s + 2..).unwrap_or("");
            }
            _ => {
                push(&mut out, rest, false, bold);
                rest = "";
            }
        }
    }
    out
}

fn push(out: &mut Vec<(String, bool, bool)>, text: &str, code: bool, bold: bool) {
    if !text.is_empty() {
        out.push((text.to_owned(), code, bold));
    }
}

fn inline(ui: &mut Ui, text: &str) {
    let v = ui.visuals();
    let body = TextStyle::Body.resolve(ui.style());
    let mono = FontId::monospace(body.size * 0.95);
    let mut job = LayoutJob::default();
    for (t, code, bold) in spans(text) {
        let mut f = TextFormat {
            font_id: if code { mono.clone() } else { body.clone() },
            color: if bold {
                v.strong_text_color()
            } else {
                v.text_color()
            },
            ..TextFormat::default()
        };
        if code {
            f.background = v.code_bg_color;
        }
        job.append(&t, 0.0, f);
    }
    job.wrap.max_width = ui.available_width();
    ui.label(job);
}

/// Draw `text`.
pub(crate) fn show(ui: &mut Ui, text: &str) {
    for (i, b) in blocks(text).iter().enumerate() {
        match b {
            Block::Heading(h) => {
                if i > 0 {
                    ui.add_space(6.0);
                }
                ui.label(RichText::new(h).strong().size(
                    TextStyle::Body.resolve(ui.style()).size * 1.1,
                ));
            }
            Block::Paragraph(p) => inline(ui, p),
            Block::Bullet(b) => {
                ui.horizontal_wrapped(|ui| {
                    ui.label("•");
                    inline(ui, b);
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_and_spans() {
        let b = blocks("## What\nline one\nline two\n\n- a **b**\n- `c`\ntail");
        assert_eq!(
            b,
            [
                Block::Heading("What".into()),
                Block::Paragraph("line one line two".into()),
                Block::Bullet("a **b**".into()),
                Block::Bullet("`c`".into()),
                Block::Paragraph("tail".into()),
            ]
        );
        assert_eq!(
            spans("set `x = 1` **now** ok"),
            [
                ("set ".into(), false, false),
                ("x = 1".into(), true, false),
                (" ".into(), false, false),
                ("now".into(), false, true),
                (" ok".into(), false, false),
            ]
        );
    }

    #[test]
    fn stray_marks_do_not_panic() {
        for t in ["`", "**", "a ` b", "***", "``", "é`ç**ã", "- ", "## ", "\n\n\n"] {
            let joined: String = blocks(t)
                .iter()
                .flat_map(|b| match b {
                    Block::Heading(s) | Block::Paragraph(s) | Block::Bullet(s) => spans(s),
                })
                .map(|(s, ..)| s)
                .collect();
            assert!(joined.len() <= t.len(), "{t:?}");
        }
    }
}
