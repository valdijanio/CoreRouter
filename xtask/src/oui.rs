//! `cargo xtask oui <oui.csv> --date YYYY-MM-DD` (G1.27d): the vendor
//! table built into CoreRouter (`crates/model/data/oui.bin`) from the IEEE
//! MA-L public listing, `https://standards-oui.ieee.org/oui/oui.csv`.
//!
//! Tooling depends on no workspace crate (`layers`): the model's own
//! example `oui_build` does the work with the model's codec. Download the
//! listing by hand (or let a router fetch its own: `ip.arp.vendors.update`),
//! run this, and record the date and the SHA-256 it prints in
//! `docs/third-party.md`.

use std::path::Path;
use std::process::Command;

use crate::Outcome;

pub fn main(root: &Path, args: &[String]) -> Outcome {
    let mut csv = None;
    let mut date = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--date" => date = it.next().cloned(),
            other => csv = Some(other.to_owned()),
        }
    }
    let (Some(csv), Some(date)) = (csv, date) else {
        return Outcome::Fail("usage: cargo xtask oui <oui.csv> --date YYYY-MM-DD".into());
    };
    let csv = std::fs::canonicalize(&csv).map_or(csv, |p| p.display().to_string());
    let out = root.join("crates/model/data/oui.bin");
    let status = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
        .args([
            "run",
            "-q",
            "-p",
            "corerouter-model",
            "--example",
            "oui_build",
            "--",
        ])
        .arg(&csv)
        .arg(&date)
        .arg(&out)
        .current_dir(root)
        .status();
    match status {
        Ok(s) if s.success() => Outcome::Ok,
        Ok(s) => Outcome::Fail(format!("oui_build: {s}")),
        Err(e) => Outcome::Fail(format!("cargo run: {e}")),
    }
}
