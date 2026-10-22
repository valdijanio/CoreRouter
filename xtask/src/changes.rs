//! `cargo xtask docs [fold [--date AAAA-MM-DD]]` — per-PR change files.
//!
//! Every PR writes its own `docs/changes/<id>[-slug].md` instead of editing
//! the shared `docs/log.md`, `docs/gaps-history.md` and the Status column of
//! `docs/gaps.md`: a file only one PR touches never conflicts. The merge queue
//! (`scripts/land.sh`) folds them into those documents one PR at a time, right
//! before the merge, so the fold never conflicts either. Format in
//! `docs/changes/README.md`.
//!
//! `docs` (a `cargo xtask ci` step) only checks the files; `docs fold` applies
//! and deletes them.

use std::path::Path;

use crate::Outcome;

const DIR: &str = "docs/changes";
const GAPS: &str = "docs/gaps.md";
const LOG: &str = "docs/log.md";
const HISTORY: &str = "docs/gaps-history.md";
const PERF: &str = "docs/perf.md";
/// Upper bound for one change file: a log entry, not a document.
const MAX_BYTES: usize = 64 * 1024;

#[derive(Debug, PartialEq)]
pub struct Change {
    pub id: String,
    /// New text of the Status column of the `id` row in `docs/gaps.md`.
    pub status: Option<String>,
    /// One line for `docs/gaps-history.md`.
    pub history: Option<String>,
    /// The `docs/log.md` entry, without the `- date — id:` prefix.
    pub log: Vec<String>,
    /// New `docs/gaps.md` rows (`| G4.7d | … |`).
    pub rows: Vec<String>,
    /// Text after a `## perf` line, for the end of `docs/perf.md`.
    pub perf: Vec<String>,
}

/// `G4.7c` → (4, 7, "c"); `G2` → (2, 0, ""). `None` for anything else.
fn gap_key(id: &str) -> Option<(u32, u32, String)> {
    let rest = id.strip_prefix('G')?;
    let (phase, minor) = match rest.split_once('.') {
        Some((p, m)) => (p, m),
        None => (rest, "0"),
    };
    let phase = phase.parse().ok()?;
    let digits = minor.trim_end_matches(|c: char| c.is_ascii_lowercase());
    let suffix = minor.get(digits.len()..)?.to_owned();
    if suffix.len() > 2 {
        return None;
    }
    Some((phase, digits.parse().ok()?, suffix))
}

/// A gap id (`G4.7c`) or a lowercase tag for work without one (`processo`, `docs`).
fn valid_id(id: &str) -> bool {
    gap_key(id).is_some()
        || (!id.is_empty()
            && id.len() <= 32
            && id.chars().all(|c| c.is_ascii_lowercase() || c == '-'))
}

/// Id of a `docs/gaps.md` table row (`| G1.2 | …`).
fn row_id(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("| ")?;
    let (id, _) = rest.split_once(" |")?;
    gap_key(id).map(|_| id)
}

pub fn parse(file: &str, text: &str) -> Result<Change, String> {
    if text.len() > MAX_BYTES {
        return Err(format!("{file}: larger than {MAX_BYTES} bytes"));
    }
    let mut lines = text.lines();
    let (mut id, mut status, mut history) = (None, None, None);
    for line in lines.by_ref() {
        if line.trim().is_empty() {
            break;
        }
        let Some((key, value)) = line.split_once(':') else {
            return Err(format!(
                "{file}: header line without 'key: value': {line:.60}"
            ));
        };
        let value = value.trim().to_owned();
        let slot = match key.trim() {
            "id" => &mut id,
            "status" => &mut status,
            "history" => &mut history,
            other => {
                return Err(format!(
                    "{file}: unknown header '{other:.20}' (id, status, history)"
                ));
            }
        };
        if value.is_empty() || slot.replace(value).is_some() {
            return Err(format!("{file}: '{}' empty or repeated", key.trim()));
        }
    }
    let id: String = id.ok_or_else(|| format!("{file}: missing 'id:'"))?;
    if !valid_id(&id) {
        return Err(format!(
            "{file}: id '{id:.32}' is neither a gap id (G4.7c) nor a lowercase tag (processo)"
        ));
    }
    let stem = file.trim_end_matches(".md");
    if stem != id && !stem.starts_with(&format!("{id}-")) {
        return Err(format!(
            "{file}: the file name must be '{id}.md' or '{id}-<slug>.md'"
        ));
    }
    if status.is_some() && gap_key(&id).is_none() {
        return Err(format!("{file}: 'status:' needs a gap id, not '{id}'"));
    }
    let (mut log, mut rows, mut perf) = (Vec::new(), Vec::new(), Vec::new());
    let mut in_perf = false;
    for line in lines {
        if line.trim() == "## perf" {
            in_perf = true;
        } else if in_perf {
            perf.push(line.trim_end().to_owned());
        } else if line.starts_with("| G") {
            row_id(line).ok_or_else(|| format!("{file}: bad gap row: {line:.60}"))?;
            rows.push(line.to_owned());
        } else {
            log.push(line.trim_end().to_owned());
        }
    }
    while log.last().is_some_and(String::is_empty) {
        log.pop();
    }
    while log.first().is_some_and(String::is_empty) {
        log.remove(0);
    }
    if log.is_empty() {
        return Err(format!("{file}: no log text after the header"));
    }
    trim_blank(&mut perf);
    if in_perf && perf.is_empty() {
        return Err(format!("{file}: '## perf' without text"));
    }
    Ok(Change {
        id,
        status,
        history,
        log,
        rows,
        perf,
    })
}

/// Replace the Status (last) column of the `id` row.
pub fn apply_status(gaps: &str, id: &str, status: &str) -> Result<String, String> {
    let mut found = false;
    let mut out = String::with_capacity(gaps.len() + status.len());
    for line in gaps.lines() {
        if row_id(line) == Some(id) {
            let body = line.trim_end().trim_end_matches('|').trim_end();
            let (head, _) = body
                .rsplit_once(" | ")
                .ok_or_else(|| format!("{GAPS}: row {id} has no Status column"))?;
            out.push_str(&format!("{head} | {status} |"));
            found = true;
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    if found {
        Ok(out)
    } else {
        Err(format!("{GAPS}: no row for {id}"))
    }
}

/// Insert a new row after the last row of the same phase with a smaller id.
pub fn insert_row(gaps: &str, row: &str) -> Result<String, String> {
    let id = row_id(row).ok_or_else(|| format!("bad gap row: {row:.60}"))?;
    let key = gap_key(id).ok_or_else(|| format!("bad gap id: {id}"))?;
    let lines: Vec<&str> = gaps.lines().collect();
    let mut after = None;
    for (i, line) in lines.iter().enumerate() {
        let Some(other) = row_id(line).and_then(gap_key) else {
            continue;
        };
        if other == key {
            return Err(format!("{GAPS}: {id} already exists"));
        }
        if other.0 == key.0 && other < key {
            after = Some(i);
        }
    }
    let at = after.ok_or_else(|| {
        format!(
            "{GAPS}: no G{}.x row to put {id} after; add it by hand",
            key.0
        )
    })?;
    let mut out = String::with_capacity(gaps.len() + row.len() + 1);
    for (i, line) in lines.iter().enumerate() {
        out.push_str(line);
        out.push('\n');
        if i == at {
            out.push_str(row);
            out.push('\n');
        }
    }
    Ok(out)
}

/// `- 2026-10-22 — G4.7c: …` with continuation lines indented.
pub fn log_entry(date: &str, c: &Change) -> String {
    let mut out = String::new();
    for (i, line) in c.log.iter().enumerate() {
        if i == 0 {
            out.push_str(&format!("- {date} — {}: {line}\n", c.id));
        } else if line.is_empty() {
            out.push('\n');
        } else {
            out.push_str(&format!("  {line}\n"));
        }
    }
    out
}

/// Is `c`'s log entry already in `log` (any date)?
fn is_folded(log: &str, c: &Change) -> bool {
    c.log
        .first()
        .is_some_and(|first| log.contains(&format!(" — {}: {first}\n", c.id)))
}

/// Append `entry` after a blank line.
fn append(doc: &str, entry: &str, blank: bool) -> String {
    let mut out = doc.trim_end().to_owned();
    out.push('\n');
    if blank {
        out.push('\n');
    }
    out.push_str(entry);
    if !out.ends_with('\n') {
        out.push('\n');
    }
    out
}

fn trim_blank(lines: &mut Vec<String>) {
    while lines.last().is_some_and(String::is_empty) {
        lines.pop();
    }
    while lines.first().is_some_and(String::is_empty) {
        lines.remove(0);
    }
}

/// The documents a fold writes.
#[derive(Debug, Clone, PartialEq)]
pub struct Docs {
    pub gaps: String,
    pub log: String,
    pub history: String,
    pub perf: String,
}

/// Fold the changes, in file name order, into the documents.
pub fn fold(date: &str, changes: &[Change], docs: &Docs) -> Result<Docs, String> {
    let Docs {
        mut gaps,
        mut log,
        mut history,
        mut perf,
    } = docs.clone();
    for c in changes {
        // Already folded: a branch made from another PR's branch still
        // carries that PR's change file after its squash reached the main
        // (the file never existed there, so the merge keeps it). Drop it.
        if is_folded(&log, c) {
            continue;
        }
        for row in &c.rows {
            gaps = insert_row(&gaps, row)?;
        }
        if let Some(s) = &c.status {
            gaps = apply_status(&gaps, &c.id, s)?;
        }
        log = append(&log, &log_entry(date, c), true);
        if let Some(h) = &c.history {
            history = append(&history, &format!("- {date} — {h}\n"), false);
        }
        if !c.perf.is_empty() {
            perf = append(&perf, &(c.perf.join("\n") + "\n"), true);
        }
    }
    Ok(Docs {
        gaps,
        log,
        history,
        perf,
    })
}

fn read(root: &Path, rel: &str) -> Result<String, String> {
    std::fs::read_to_string(root.join(rel)).map_err(|e| format!("{rel}: {e}"))
}

/// Change files in name order, as (file name, parsed).
fn load(root: &Path) -> Result<Vec<(String, Change)>, String> {
    let dir = root.join(DIR);
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("{DIR}: {e}")),
    };
    let mut names: Vec<String> = Vec::new();
    for entry in entries {
        let name = entry.map_err(|e| format!("{DIR}: {e}"))?.file_name();
        let name = name.to_string_lossy().into_owned();
        if name.ends_with(".md") && name != "README.md" {
            names.push(name);
        }
    }
    names.sort();
    names
        .into_iter()
        .map(|n| {
            let text = read(root, &format!("{DIR}/{n}"))?;
            parse(&n, &text).map(|c| (n, c))
        })
        .collect()
}

fn today() -> String {
    std::process::Command::new("date")
        .arg("+%F")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .filter(|d| d.len() == 10)
        .unwrap_or_else(|| "0000-00-00".into())
}

/// The `docs` step of `cargo xtask ci`: every change file parses and folds.
pub fn check(root: &Path) -> Outcome {
    match dry_fold(root, &today()) {
        Ok(_) => Outcome::Ok,
        Err(e) => Outcome::Fail(e),
    }
}

fn dry_fold(root: &Path, date: &str) -> Result<(Vec<String>, Docs), String> {
    let loaded = load(root)?;
    let (names, changes): (Vec<String>, Vec<Change>) = loaded.into_iter().unzip();
    let docs = Docs {
        gaps: read(root, GAPS)?,
        log: read(root, LOG)?,
        history: read(root, HISTORY)?,
        perf: read(root, PERF)?,
    };
    Ok((names, fold(date, &changes, &docs)?))
}

/// `cargo xtask docs pending`: what the change files not folded yet say. The
/// merge queue folds periodically (like towncrier at release time), so
/// `docs/gaps.md` can lag: read this too before picking a gap.
fn pending(root: &Path) -> Outcome {
    let loaded = match load(root) {
        Ok(l) => l,
        Err(e) => return Outcome::Fail(e),
    };
    if loaded.is_empty() {
        println!("nothing pending in {DIR}: docs/gaps.md is current");
        return Outcome::Ok;
    }
    println!("{} change file(s) not folded yet ({DIR}):", loaded.len());
    for (name, c) in &loaded {
        let first = c.log.first().map_or("", String::as_str);
        println!("- {name}: {}", first.chars().take(100).collect::<String>());
        if let Some(st) = &c.status {
            println!("    status {}: {st}", c.id);
        }
        for row in &c.rows {
            println!("    new gap {}", row.chars().take(100).collect::<String>());
        }
    }
    Outcome::Ok
}

/// `cargo xtask docs [pending | fold [--date AAAA-MM-DD]]`.
pub fn main(root: &Path, args: &[String]) -> Outcome {
    let date = match args {
        [] => return check(root),
        [p] if p == "pending" => return pending(root),
        [f] if f == "fold" => today(),
        [f, d, date] if f == "fold" && d == "--date" && date.len() == 10 => date.clone(),
        _ => {
            return Outcome::Fail(
                "usage: cargo xtask docs [pending | fold [--date AAAA-MM-DD]]".into(),
            );
        }
    };
    let (names, docs) = match dry_fold(root, &date) {
        Ok(v) => v,
        Err(e) => return Outcome::Fail(e),
    };
    if names.is_empty() {
        eprintln!("nothing to fold in {DIR}");
        return Outcome::Ok;
    }
    let write = |rel: &str, text: &str| {
        std::fs::write(root.join(rel), text).map_err(|e| format!("{rel}: {e}"))
    };
    let result = write(GAPS, &docs.gaps)
        .and_then(|()| write(LOG, &docs.log))
        .and_then(|()| write(HISTORY, &docs.history))
        .and_then(|()| write(PERF, &docs.perf))
        .and_then(|()| {
            names.iter().try_for_each(|n| {
                std::fs::remove_file(root.join(DIR).join(n)).map_err(|e| format!("{DIR}/{n}: {e}"))
            })
        });
    match result {
        Ok(()) => {
            eprintln!("folded {}: {}", names.len(), names.join(", "));
            Outcome::Ok
        }
        Err(e) => Outcome::Fail(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GAPS_MD: &str = "\
| Id | Tarefa | Status |
|---|---|---|
| G4.7 | Cliente | feito |
| G4.7b | DHCPv6 | aberto |
| G4.8 | Outro | aberto |
| G5.1 | CRDP | feito |
";

    fn change(text: &str) -> Change {
        parse("G4.7b.md", text).unwrap()
    }

    #[test]
    fn parses_header_log_and_rows() {
        let c = change(
            "id: G4.7b\nstatus: feito (`x`)\nhistory: G4.7b feito\n\nLinha um.\n  Linha dois.\n\n| G4.7c | Resiliência | aberto |\n",
        );
        assert_eq!(c.id, "G4.7b");
        assert_eq!(c.status.as_deref(), Some("feito (`x`)"));
        assert_eq!(c.history.as_deref(), Some("G4.7b feito"));
        assert_eq!(c.log, ["Linha um.", "  Linha dois."]);
        assert_eq!(c.rows, ["| G4.7c | Resiliência | aberto |"]);
    }

    #[test]
    fn rejects_bad_files() {
        let bad = [
            ("G4.7b.md", "status: feito\n\nx"),
            ("G4.7b.md", "id: G4.7b\n\n"),
            ("G4.7b.md", "id: G4.7b\nfoo: bar\n\nx"),
            ("G4.7b.md", "id: G4.7b\nid: G4.7b\n\nx"),
            ("other.md", "id: G4.7b\n\nx"),
            ("processo.md", "id: processo\nstatus: feito\n\nx"),
            ("G4.7b.md", "id: G4.7b\n\nx\n| G4.7c broken\n"),
            ("Bad.md", "id: Bad\n\nx"),
        ];
        for (file, text) in bad {
            assert!(parse(file, text).is_err(), "{file}: {text:?}");
        }
        assert!(parse("processo-ci.md", "id: processo\n\nCI mais rápido.").is_ok());
        assert!(parse("G4.7b-part2.md", "id: G4.7b\n\nx").is_ok());
    }

    #[test]
    fn gap_ids_order_naturally() {
        assert!(gap_key("G4.7").unwrap() < gap_key("G4.7b").unwrap());
        assert!(gap_key("G4.7c").unwrap() < gap_key("G4.10").unwrap());
        assert!(gap_key("G4.x").is_none());
        assert!(gap_key("processo").is_none());
    }

    #[test]
    fn status_replaces_only_the_last_column() {
        let out = apply_status(GAPS_MD, "G4.7b", "feito (`stream/x`)").unwrap();
        assert!(out.contains("| G4.7b | DHCPv6 | feito (`stream/x`) |\n"));
        assert!(out.contains("| G4.8 | Outro | aberto |\n"));
        assert!(apply_status(GAPS_MD, "G9.9", "x").is_err());
    }

    #[test]
    fn rows_go_after_their_predecessor() {
        let out = insert_row(GAPS_MD, "| G4.7c | Novo | aberto |").unwrap();
        assert!(out.contains("| G4.7b | DHCPv6 | aberto |\n| G4.7c | Novo | aberto |\n| G4.8 |"));
        assert!(insert_row(GAPS_MD, "| G4.7b | Dup | aberto |").is_err());
        assert!(insert_row(GAPS_MD, "| G7.1 | Fase nova | aberto |").is_err());
    }

    fn docs(log: &str, history: &str) -> Docs {
        Docs {
            gaps: GAPS_MD.into(),
            log: log.into(),
            history: history.into(),
            perf: "# perf\n".into(),
        }
    }

    #[test]
    fn fold_skips_a_change_already_in_the_log() {
        let c = change("id: G4.7b\nstatus: feito\nhistory: G4.7b feito\n\nEntrou.\n");
        let before = docs("# log\n\n- 2026-10-21 — G4.7b: Entrou.\n", "# h\n");
        assert_eq!(fold("2026-10-22", &[c], &before).unwrap(), before);
    }

    #[test]
    fn fold_appends_log_history_and_perf() {
        let c = change(
            "id: G4.7b\nstatus: feito\nhistory: G4.7b feito\n\nEntrou.\nComo testar.\n\n## perf\n\n| codec | 1 µs |\n",
        );
        assert_eq!(c.log, ["Entrou.", "Como testar."]);
        let out = fold(
            "2026-10-22",
            &[c],
            &docs("# log\n\n- antiga\n", "# h\n- velha\n"),
        )
        .unwrap();
        assert!(out.gaps.contains("| G4.7b | DHCPv6 | feito |"));
        assert_eq!(
            out.log,
            "# log\n\n- antiga\n\n- 2026-10-22 — G4.7b: Entrou.\n  Como testar.\n"
        );
        assert_eq!(out.history, "# h\n- velha\n- 2026-10-22 — G4.7b feito\n");
        assert_eq!(out.perf, "# perf\n\n| codec | 1 µs |\n");
    }

    #[test]
    fn empty_perf_section_is_an_error() {
        assert!(parse("G4.7b.md", "id: G4.7b\n\nx\n## perf\n\n").is_err());
    }
}
