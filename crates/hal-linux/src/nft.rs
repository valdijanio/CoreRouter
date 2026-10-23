//! nftables through the `nft` program (G2.1).
//!
//! Why `nft -f -` and not netlink from Rust: the kernel's nftables API is a
//! bytecode VM fed by netlink batches; the Rust crates that speak it either
//! wrap libnftnl over FFI (C + `unsafe`) or cover only part of the
//! expressions we render (sets with intervals and timeouts, `ct status`,
//! NAT ranges). `nft` is the kernel project's reference user space: it
//! compiles our text and sends it as **one netlink batch**, which the kernel
//! commits atomically or rejects whole. So "replace our table" is atomic
//! without a line of `unsafe`. The text we hand it is built only from
//! validated values (see `corerouter_firewall::nft`), never from free input.
//!
//! Only table `inet corerouter` is ever named: rules of other owners
//! (Docker, libvirt, the distribution's firewall) are not read or touched.

use std::io::{Read, Write as _};
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use corerouter_hal::HalError;
use corerouter_model::firewall::{AddrMatch, DynamicAddress, Family, Name};
use serde_json::Value;

use corerouter_firewall::TABLE;

/// Where `nft` lives: `$COREROUTER_NFT`, else the first of the usual paths.
fn nft_bin() -> PathBuf {
    if let Some(p) = std::env::var_os("COREROUTER_NFT") {
        return PathBuf::from(p);
    }
    for p in ["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft", "/bin/nft"] {
        let path = PathBuf::from(p);
        if path.exists() {
            return path;
        }
    }
    PathBuf::from("nft")
}

/// Whether `nft` can be run at all (tests skip without it).
pub fn available() -> bool {
    Command::new(nft_bin())
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn first_lines(s: &str) -> String {
    let lines: Vec<&str> = s.lines().take(6).collect();
    let text = lines.join(" | ");
    text.chars().take(600).collect()
}

/// How long one `nft` may take before it is killed: a 65 536-entry
/// ruleset loads in about a second (**estimado**); a kernel netlink stall
/// must not hold the commit, and the engine with it, forever.
pub const DEADLINE: Duration = Duration::from_secs(30);

/// Run `cmd` with `input` on its stdin, collecting stdout and stderr,
/// killing it after `deadline`. The pipes are served by their own threads,
/// so a child that neither reads nor exits cannot block us either.
pub(crate) fn run_bounded(
    mut cmd: Command,
    input: Vec<u8>,
    deadline: Duration,
) -> Result<Output, HalError> {
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            HalError::Unsupported(format!(
                "cannot run nft ({e}); install nftables or set COREROUTER_NFT"
            ))
        })?;
    let writer = child.stdin.take().map(|mut stdin| {
        std::thread::spawn(move || {
            // A child that exits early closes the pipe: EPIPE, not our error.
            let _ = stdin.write_all(&input);
        })
    });
    let reader = |pipe: Option<Box<dyn Read + Send>>| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(mut p) = pipe {
                let _ = p.read_to_end(&mut buf);
            }
            buf
        })
    };
    let stdout = reader(
        child
            .stdout
            .take()
            .map(|p| Box::new(p) as Box<dyn Read + Send>),
    );
    let stderr = reader(
        child
            .stderr
            .take()
            .map(|p| Box::new(p) as Box<dyn Read + Send>),
    );
    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if start.elapsed() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(HalError::Io(format!(
                    "nft did not finish in {} s and was killed (nothing changed)",
                    deadline.as_secs()
                )));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(2)),
            Err(e) => return Err(HalError::Io(format!("nft: {e}"))),
        }
    };
    if let Some(w) = writer {
        let _ = w.join();
    }
    Ok(Output {
        status,
        stdout: stdout.join().unwrap_or_default(),
        stderr: stderr.join().unwrap_or_default(),
    })
}

/// Run `nft -f -` with `script` as one transaction.
pub fn run(script: &str) -> Result<(), HalError> {
    let mut cmd = Command::new(nft_bin());
    cmd.args(["-f", "-"]);
    let out = run_bounded(cmd, script.as_bytes().to_vec(), DEADLINE)?;
    if out.status.success() {
        Ok(())
    } else {
        Err(HalError::Rejected(format!(
            "nftables refused the ruleset (nothing changed): {}",
            first_lines(&String::from_utf8_lossy(&out.stderr))
        )))
    }
}

/// `nft -j list table inet corerouter`, or `None` if the table is absent.
pub fn list_json() -> Option<Value> {
    let mut cmd = Command::new(nft_bin());
    cmd.args(["-j", "list", "table", "inet", TABLE]);
    let out = run_bounded(cmd, Vec::new(), DEADLINE).ok()?;
    if !out.status.success() {
        return None;
    }
    serde_json::from_slice(&out.stdout).ok()
}

fn elem_addr(v: &Value) -> Option<AddrMatch> {
    match v {
        Value::String(s) => s.parse().ok(),
        Value::Object(o) => {
            if let Some(p) = o.get("prefix") {
                let addr = p.get("addr")?.as_str()?;
                let len = p.get("len")?.as_u64()?;
                format!("{addr}/{len}").parse().ok()
            } else if let Some(Value::Array(r)) = o.get("range") {
                let a = r.first()?.as_str()?;
                let b = r.get(1)?.as_str()?;
                format!("{a}-{b}").parse().ok()
            } else {
                None
            }
        }
        _ => None,
    }
}

/// The dynamic entries of our address-list sets, kept across a table
/// replace (`apply` re-adds them): entries with a timeout in the `al*`
/// sets (added by `address-list.add timeout=…`), with the time left, and
/// every entry of the `ad*` sets (added by `add-*-to-address-list` rules,
/// with or without a timeout).
pub fn dynamic() -> Vec<DynamicAddress> {
    let Some(json) = list_json() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let items = json
        .get("nftables")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for item in items {
        let Some(set) = item.get("set") else { continue };
        let Some(name) = set.get("name").and_then(Value::as_str) else {
            continue;
        };
        let (rest, by_rule) = match name.get(..4) {
            Some("al4_" | "al6_") => (name.get(4..), false),
            Some("ad4_" | "ad6_") => (name.get(4..), true),
            _ => continue,
        };
        let Some(list) = rest.and_then(|l| l.parse::<Name>().ok()) else {
            continue;
        };
        let elems = set
            .get("elem")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for e in elems {
            let (val, left) = match e.get("elem") {
                Some(inner) => (
                    inner.get("val").cloned().unwrap_or(Value::Null),
                    inner.get("expires").and_then(Value::as_u64),
                ),
                None => (e.clone(), None),
            };
            if left.is_none() && !by_rule {
                continue;
            }
            let Some(address) = elem_addr(&val) else {
                continue;
            };
            out.push(DynamicAddress {
                list: list.clone(),
                address,
                timeout_secs: left.map_or(0, |l| l.max(1)),
                added_by_rule: by_rule,
            });
        }
    }
    out
}

fn set_name(d: &DynamicAddress) -> (String, &'static str) {
    match d.address.family() {
        Family::Ipv6 => (format!("al6_{}", d.list), "ipv6_addr"),
        _ => (format!("al4_{}", d.list), "ipv4_addr"),
    }
}

/// Add one dynamic entry (creating our table and the set if needed).
pub fn add_dynamic(d: &DynamicAddress) -> Result<(), HalError> {
    let (set, ty) = set_name(d);
    run(&format!(
        "add table inet {TABLE}\n\
         add set inet {TABLE} {set} {{ type {ty}; flags interval, timeout; auto-merge; }}\n\
         add element inet {TABLE} {set} {{ {} timeout {}s }}\n",
        d.address,
        d.timeout_secs.max(1)
    ))
}

pub fn remove_dynamic(d: &DynamicAddress) -> Result<(), HalError> {
    let (set, _) = set_name(d);
    run(&format!(
        "delete element inet {TABLE} {set} {{ {} }}\n",
        d.address
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stuck `nft` (here `sleep`, which never reads its stdin either) is
    /// killed at the deadline instead of holding the commit forever.
    #[test]
    fn a_hung_nft_is_killed_at_the_deadline() {
        let mut cmd = Command::new("sleep");
        cmd.arg("30");
        let start = Instant::now();
        let err = run_bounded(cmd, vec![b'x'; 1 << 20], Duration::from_millis(200)).unwrap_err();
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "{:?}",
            start.elapsed()
        );
        assert!(err.to_string().contains("killed"), "{err}");
    }

    #[test]
    fn output_and_status_are_collected() {
        let out = run_bounded(Command::new("cat"), b"table inet x\n".to_vec(), DEADLINE).unwrap();
        assert!(out.status.success());
        assert_eq!(out.stdout, b"table inet x\n");
    }
}
