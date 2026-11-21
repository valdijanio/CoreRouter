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
//!
//! G0.34: a new gap that is still open and small (at most
//! [`SMALL_GAP_HOURS`]) is refused unless its Status says what it waits for
//! (`aberto (depende: …)`): work that small is done in the PR that found it.
//! Ideas nobody asked for go under `## ideias`, folded into `docs/ideias.md`,
//! outside the gap list.

use std::path::Path;

use crate::Outcome;

const DIR: &str = "docs/changes";
const GAPS: &str = "docs/gaps.md";
const LOG: &str = "docs/log.md";
const HISTORY: &str = "docs/gaps-history.md";
const PERF: &str = "docs/perf.md";
const IDEAS: &str = "docs/ideias.md";
/// A new open gap estimated at this or less needs `depende:` in its Status.
pub const SMALL_GAP_HOURS: f64 = 4.0;
/// Upper bound for one change file: a log entry, not a document.
const MAX_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq)]
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
    /// Text under a `## perf` line, for the end of `docs/perf.md`.
    pub perf: Vec<String>,
    /// Text under a `## ideias` line, for the end of `docs/ideias.md`.
    pub ideas: Vec<String>,
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
        || (id.len() <= 32
            && id.starts_with(|c: char| c.is_ascii_lowercase())
            && id
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'))
}

/// Hours of an estimate cell: `4 h`, `1 d` (8 h), `2–4 h` (the upper
/// bound), `12 h (**estimado**)`. `None` when it is not a number of hours or
/// days (`—`, `?`).
fn estimate_hours(cell: &str) -> Option<f64> {
    let number = |s: &str| -> Option<(f64, usize)> {
        let len = s
            .find(|c: char| !(c.is_ascii_digit() || c == '.' || c == ','))
            .unwrap_or(s.len());
        let n = s.get(..len)?.replace(',', ".").parse().ok()?;
        Some((n, len))
    };
    let cell = cell.trim();
    let (mut n, len) = number(cell)?;
    let mut rest = cell.get(len..)?.trim_start();
    if let Some(upper) = rest.strip_prefix(['–', '-']) {
        let (m, len) = number(upper.trim_start())?;
        n = m;
        rest = upper.trim_start().get(len..)?.trim_start();
    }
    match rest.chars().next()? {
        'h' => Some(n),
        'd' => Some(n * 8.0),
        _ => None,
    }
}

/// G0.34: a new row that is open, estimated at [`SMALL_GAP_HOURS`] or less
/// and does not say what it waits for. Rows without the Est. and Status
/// columns (`| G… | … |` in short form) are not judged.
fn small_open_gap(row: &str) -> Option<String> {
    let body = row.trim_end().trim_end_matches('|').trim_end();
    let mut cells = body.rsplitn(3, " | ");
    let status = cells.next()?.trim();
    let estimate = cells.next()?.trim();
    let id = row_id(row)?;
    if !status.to_lowercase().starts_with("aberto") || status.contains("depende:") {
        return None;
    }
    let hours = estimate_hours(estimate)?;
    (hours <= SMALL_GAP_HOURS).then(|| {
        format!(
            "new gap {id} is open and estimated at {estimate}: a gap of {SMALL_GAP_HOURS} h or less is done in the PR that found it (CLAUDE.md, \"Gap nova ou feita na hora\"); if it cannot be, its Status says why: 'aberto (depende: hardware | root | G… | decisão do usuário | …)'"
        )
    })
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
    let (mut log, mut rows, mut perf, mut ideas) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    // Where the lines go: the log, then the `## perf` / `## ideias` sections
    // (each at most once, in any order, up to the end of the file).
    let (mut section, mut seen_perf, mut seen_ideas) = (None::<bool>, false, false);
    for line in lines {
        match line.trim() {
            heading @ ("## perf" | "## ideias") => {
                let is_perf = heading == "## perf";
                let seen = if is_perf {
                    &mut seen_perf
                } else {
                    &mut seen_ideas
                };
                if std::mem::replace(seen, true) {
                    return Err(format!("{file}: '{heading}' repeated"));
                }
                section = Some(is_perf);
            }
            _ => match section {
                Some(true) => perf.push(line.trim_end().to_owned()),
                Some(false) => ideas.push(line.trim_end().to_owned()),
                None if line.starts_with("| G") => {
                    row_id(line).ok_or_else(|| format!("{file}: bad gap row: {line:.60}"))?;
                    if let Some(e) = small_open_gap(line) {
                        return Err(format!("{file}: {e}"));
                    }
                    rows.push(line.to_owned());
                }
                None => log.push(line.trim_end().to_owned()),
            },
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
    if seen_perf && perf.is_empty() {
        return Err(format!("{file}: '## perf' without text"));
    }
    trim_blank(&mut ideas);
    if seen_ideas && ideas.is_empty() {
        return Err(format!("{file}: '## ideias' without text"));
    }
    if let Some(bad) = ideas
        .iter()
        .find(|l| !(l.is_empty() || l.starts_with("- ") || l.starts_with("  ")))
    {
        return Err(format!(
            "{file}: '## ideias' takes '- ' items (continuation indented): {bad:.60}"
        ));
    }
    Ok(Change {
        id,
        status,
        history,
        log,
        rows,
        perf,
        ideas,
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
    pub ideas: String,
}

/// Fold the changes, in file name order, into the documents.
pub fn fold(date: &str, changes: &[Change], docs: &Docs) -> Result<Docs, String> {
    let Docs {
        mut gaps,
        mut log,
        mut history,
        mut perf,
        mut ideas,
    } = docs.clone();
    // Already folded: a branch made from another PR's branch still
    // carries that PR's change file after its squash reached the main
    // (the file never existed there, so the merge keeps it). Drop it.
    let changes: Vec<&Change> = changes.iter().filter(|c| !is_folded(&log, c)).collect();
    // New rows first: a file may set the status of a gap another file
    // (sorted after it, `docs-…` after `G0.24`) creates.
    for row in changes.iter().flat_map(|c| &c.rows) {
        gaps = insert_row(&gaps, row)?;
    }
    for c in changes {
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
        if !c.ideas.is_empty() {
            let block = format!("### {date} — {}\n\n{}\n", c.id, c.ideas.join("\n"));
            ideas = append(&ideas, &block, true);
        }
    }
    Ok(Docs {
        gaps,
        log,
        history,
        perf,
        ideas,
    })
}

/// Status cell (last column) of a gap row.
fn status_of(row: &str) -> &str {
    let body = row.trim_end().trim_end_matches('|').trim_end();
    body.rsplit_once(" | ").map_or("", |(_, s)| s.trim())
}

fn is_open(status: &str) -> bool {
    status.to_lowercase().starts_with("aberto")
}

/// G0.34: how the gap list moves with these changes: gaps closed (a
/// `status:` that starts with `feito`), new rows and, of them, the open
/// ones; `open_now` is the open rows of `gaps` before the fold.
pub fn balance(changes: &[Change], gaps: &str) -> String {
    let closed = changes
        .iter()
        .filter(|c| {
            c.status
                .as_deref()
                .is_some_and(|s| s.to_lowercase().starts_with("feito"))
        })
        .count();
    let rows: Vec<&String> = changes.iter().flat_map(|c| &c.rows).collect();
    let opened = rows.iter().filter(|r| is_open(status_of(r))).count();
    let open_now = gaps
        .lines()
        .filter(|l| row_id(l).is_some() && is_open(status_of(l)))
        .count();
    let after = (open_now + opened).saturating_sub(closed);
    let delta = after as i64 - open_now as i64;
    format!(
        "saldo: {closed} gap(s) fechada(s), {} nova(s) ({opened} aberta(s), {} já feita(s)); abertas {open_now} → {after} ({delta:+})",
        rows.len(),
        rows.len() - opened
    )
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

/// The change file names, the documents after the fold and the
/// [`balance`] line.
fn dry_fold(root: &Path, date: &str) -> Result<(Vec<String>, Docs, String), String> {
    let loaded = load(root)?;
    let (names, changes): (Vec<String>, Vec<Change>) = loaded.into_iter().unzip();
    let docs = Docs {
        gaps: read(root, GAPS)?,
        log: read(root, LOG)?,
        history: read(root, HISTORY)?,
        perf: read(root, PERF)?,
        ideas: read(root, IDEAS)?,
    };
    let line = balance(&changes, &docs.gaps);
    Ok((names, fold(date, &changes, &docs)?, line))
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
    let changes: Vec<Change> = loaded.iter().map(|(_, c)| c.clone()).collect();
    match read(root, GAPS) {
        Ok(gaps) => println!("{}", balance(&changes, &gaps)),
        Err(e) => return Outcome::Fail(e),
    }
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
    let (names, docs, line) = match dry_fold(root, &date) {
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
        .and_then(|()| write(IDEAS, &docs.ideas))
        .and_then(|()| {
            names.iter().try_for_each(|n| {
                std::fs::remove_file(root.join(DIR).join(n)).map_err(|e| format!("{DIR}/{n}: {e}"))
            })
        });
    match result {
        Ok(()) => {
            eprintln!("folded {}: {}", names.len(), names.join(", "));
            eprintln!("{line}");
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
            ideas: "# ideias\n".into(),
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

    #[test]
    fn estimates_read_hours_and_days() {
        assert_eq!(estimate_hours("4 h"), Some(4.0));
        assert_eq!(estimate_hours("12 h (**estimado**)"), Some(12.0));
        assert_eq!(estimate_hours("1 d"), Some(8.0));
        assert_eq!(estimate_hours("2–4 h"), Some(4.0));
        assert_eq!(estimate_hours("1,5 h"), Some(1.5));
        assert_eq!(estimate_hours("—"), None);
        assert_eq!(estimate_hours("Resiliência"), None);
    }

    /// G0.34: a small open gap is done in the PR that found it, or says
    /// what it waits for.
    #[test]
    fn a_small_open_gap_needs_a_reason() {
        let file = |row: &str| format!("id: G4.7b\n\nEntrou.\n\n{row}\n");
        let small = "| G4.7c | Resto | engine | Critério | 3 h | aberto |";
        let err = parse("G4.7b.md", &file(small)).unwrap_err();
        assert!(err.contains("G4.7c") && err.contains("depende:"), "{err}");
        for ok in [
            "| G4.7c | Resto | engine | Critério | 3 h | aberto (depende: root na VM) |",
            "| G4.7c | Resto | engine | Critério | 3 h | feito: entrou neste PR |",
            "| G4.7c | Maior | engine | Critério | 6 h | aberto |",
            "| G4.7c | Maior | engine | Critério | 1 d | aberto |",
            "| G4.7c | Sem estimativa | engine | Critério | — | aberto |",
            "| G4.7c | Resiliência | aberto |",
        ] {
            assert!(parse("G4.7b.md", &file(ok)).is_ok(), "{ok}");
        }
    }

    #[test]
    fn ideas_fold_into_their_own_document() {
        let c = change(
            "id: G4.7b\n\nEntrou.\n\n## ideias\n\n- **Uma ideia**: como o Junos faz.\n  Mais texto.\n\n## perf\n\n| codec | 1 µs |\n",
        );
        assert_eq!(c.log, ["Entrou."]);
        assert_eq!(
            c.ideas,
            ["- **Uma ideia**: como o Junos faz.", "  Mais texto."]
        );
        assert_eq!(c.perf, ["| codec | 1 µs |"]);
        let out = fold("2026-11-21", &[c], &docs("# log\n", "# h\n")).unwrap();
        assert_eq!(
            out.ideas,
            "# ideias\n\n### 2026-11-21 — G4.7b\n\n- **Uma ideia**: como o Junos faz.\n  Mais texto.\n"
        );
        for bad in [
            "id: G4.7b\n\nx\n## ideias\n\n",
            "id: G4.7b\n\nx\n## ideias\n- a\n## ideias\n- b\n",
            "id: G4.7b\n\nx\n## ideias\nsolta\n",
        ] {
            assert!(parse("G4.7b.md", bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn balance_counts_closed_and_new_gaps() {
        let a = change(
            "id: G4.7b\nstatus: feito (`x`)\n\nEntrou.\n\n| G4.7c | Resto | e | c | 6 h | aberto |\n| G4.7d | Feita | e | c | 1 h | feito |\n",
        );
        assert_eq!(
            balance(&[a], GAPS_MD),
            "saldo: 1 gap(s) fechada(s), 2 nova(s) (1 aberta(s), 1 já feita(s)); abertas 2 → 2 (+0)"
        );
    }
}
