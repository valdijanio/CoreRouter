//! Vendor table updates (G1.27d): `ip.arp.vendors.update` asks, this
//! thread downloads the IEEE MA-L listing
//! (`https://standards-oui.ieee.org/oui/oui.csv`, TLS checked), parses it
//! (`corerouter_model::oui`: every field bounded, hostile input), builds
//! the compact table and hands it to the engine in one swap. All of it
//! with no lock held; the session lock only to ask and to install.
//!
//! With `--config-dir` the table is kept as `oui.bin` there (written to a
//! temporary file, then renamed: never half a table) and loaded again at
//! start, so a downloaded table outlives a restart and wins over the one
//! built into the program.

use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use corerouter_engine::lock;
use corerouter_model::oui::{self, MAX_CSV};
use serde_json::json;
use sha2::{Digest, Sha256};

const URL: &str = "https://standards-oui.ieee.org/oui/oui.csv";
const TIMEOUT: Duration = Duration::from_secs(120);
const TICK: Duration = Duration::from_secs(1);
const FILE: &str = "oui.bin";

pub(crate) const SERVICE: super::Service = super::Service {
    name: "oui",
    flags: &[],
    topic: "arp",
    enable: "ip.arp.vendors.update (on demand)",
    depends: &[],
    start,
};

fn start(ctx: &super::Ctx) -> Result<super::Run, String> {
    let session = ctx.session.clone();
    let dir = ctx.config_dir.clone();
    Ok(Box::new(move |health: &super::Health| {
        lock(&session).vendors_updater(true);
        if let Some(path) = dir.as_ref().map(|d| d.join(FILE))
            && path.exists()
        {
            match std::fs::read(&path).map_err(|e| e.to_string()).and_then(|b| lock(&session).vendors_install(b)) {
                Ok(m) => health.event(format!("vendor table of {} ({} entries) from {}", m.date, m.entries, path.display())),
                Err(e) => health.error(format!("{}: {e} (the built-in table stays)", path.display())),
            }
        }
        while health.sleep(TICK) {
            health.beat();
            if !lock(&session).vendors_take_request() {
                continue;
            }
            let resolve = |host: &str| super::dns::resolve(&session, host);
            match update(&resolve, dir.as_ref()) {
                Ok(bytes) => {
                    let mut s = lock(&session);
                    match s.vendors_install(bytes) {
                        Ok(m) => {
                            let text = format!("vendor table updated: {} entries of {} (sha256 {})", m.entries, m.date, m.sha256_hex());
                            health.event(&text);
                            s.log_event(&["arp", "info"], "oui", text, json!({"entries": m.entries, "date": m.date}));
                        }
                        Err(e) => s.vendors_failed(e),
                    }
                }
                Err(e) => {
                    health.error(&e);
                    let mut s = lock(&session);
                    s.log_event(&["arp", "warning"], "oui", format!("vendor table not updated: {e}"), json!({}));
                    s.vendors_failed(e);
                }
            }
        }
        lock(&session).vendors_updater(false);
        Ok(())
    }))
}

/// Download, check, build and keep the table; its bytes.
fn update(
    resolve: &dyn Fn(&str) -> Result<Vec<std::net::IpAddr>, String>,
    dir: Option<&PathBuf>,
) -> Result<Vec<u8>, String> {
    let csv = super::https::get(URL, true, MAX_CSV, TIMEOUT, resolve)?;
    table_of(&csv, &today(), dir)
}

/// The table of a downloaded `oui.csv`, kept in `dir` when given.
fn table_of(csv: &[u8], date: &str, dir: Option<&PathBuf>) -> Result<Vec<u8>, String> {
    let sha: [u8; 32] = Sha256::digest(csv).into();
    let (entries, _skipped) = oui::parse_csv(&String::from_utf8_lossy(csv))?;
    let size = u32::try_from(csv.len()).unwrap_or(u32::MAX);
    let table = oui::build(&entries, date, sha, size);
    oui::Table::new(&table)?;
    if let Some(dir) = dir {
        let tmp = dir.join(format!("{FILE}.new"));
        std::fs::write(&tmp, &table).map_err(|e| format!("{}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, dir.join(FILE)).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    Ok(table)
}

/// The UTC date, `YYYY-MM-DD` (Howard Hinnant's civil-from-days).
fn today() -> String {
    let secs = SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    civil(i64::try_from(secs / 86_400).unwrap_or(0))
}

fn civil(days: i64) -> String {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_are_civil() {
        assert_eq!(civil(0), "1970-01-01");
        assert_eq!(civil(20_753), "2026-10-27");
        assert_eq!(civil(11_016), "2000-02-29");
    }

    #[test]
    fn a_listing_becomes_a_kept_table() {
        let dir = std::env::temp_dir().join(format!("cr-oui-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let csv = b"Registry,Assignment,Organization Name,Organization Address\nMA-L,005056,\"VMware, Inc.\",x\n";
        let t = table_of(csv, "2026-10-27", Some(&dir)).unwrap();
        let kept = std::fs::read(dir.join(FILE)).unwrap();
        assert_eq!(t, kept);
        assert!(!dir.join("oui.bin.new").exists());
        let table = oui::Table::new(&kept).unwrap();
        assert_eq!(table.vendor([0, 0x50, 0x56, 0, 0, 0]), Some("VMware, Inc."));
        assert!(table_of(b"<html>not it</html>", "d", None).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
