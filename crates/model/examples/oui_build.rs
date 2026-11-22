//! Build the vendor table built into CoreRouter (`crates/model/data/oui.bin`)
//! from the IEEE MA-L listing (G1.27d). Run through `cargo xtask oui`:
//! `oui_build <oui.csv> <date> <out>`. Prints what to record in
//! `docs/third-party.md`.

// A build tool, run by hand: a bad argument may stop it.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use sha2::{Digest, Sha256};

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [csv, date, out] = args.as_slice() else {
        eprintln!("usage: oui_build <oui.csv> <YYYY-MM-DD> <out>");
        return std::process::ExitCode::from(2);
    };
    let bytes = match std::fs::read(csv) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{csv}: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let sha: [u8; 32] = Sha256::digest(&bytes).into();
    let (entries, skipped) =
        match corerouter_model::oui::parse_csv(&String::from_utf8_lossy(&bytes)) {
            Ok(x) => x,
            Err(e) => {
                eprintln!("{csv}: {e}");
                return std::process::ExitCode::FAILURE;
            }
        };
    let size = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    let table = corerouter_model::oui::build(&entries, date, sha, size);
    if let Err(e) = corerouter_model::oui::Table::new(&table) {
        eprintln!("the table built is invalid: {e}");
        return std::process::ExitCode::FAILURE;
    }
    if let Err(e) = std::fs::write(out, &table) {
        eprintln!("{out}: {e}");
        return std::process::ExitCode::FAILURE;
    }
    let hex: String = sha.iter().map(|b| format!("{b:02x}")).collect();
    println!(
        "{out}: {} assignments ({skipped} lines skipped), {} bytes\nsource: {} bytes, sha256 {hex}, date {date}",
        entries.len(),
        table.len(),
        bytes.len()
    );
    std::process::ExitCode::SUCCESS
}
