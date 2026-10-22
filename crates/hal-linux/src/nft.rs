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

use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};

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

/// Run `nft -f -` with `script` as one transaction.
pub fn run(script: &str) -> Result<(), HalError> {
    let mut child = Command::new(nft_bin())
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            HalError::Unsupported(format!(
                "cannot run nft ({e}); install nftables or set COREROUTER_NFT"
            ))
        })?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(script.as_bytes())
            .map_err(|e| HalError::Io(format!("nft stdin: {e}")))?;
    }
    let out = child
        .wait_with_output()
        .map_err(|e| HalError::Io(format!("nft: {e}")))?;
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
    let out = Command::new(nft_bin())
        .args(["-j", "list", "table", "inet", TABLE])
        .stderr(Stdio::null())
        .output()
        .ok()?;
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

/// Entries with a timeout in our address-list sets, with the time left:
/// they are kept across a table replace (`apply` re-adds them).
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
        let Some(list) = name
            .strip_prefix("al4_")
            .or_else(|| name.strip_prefix("al6_"))
            .and_then(|l| l.parse::<Name>().ok())
        else {
            continue;
        };
        let elems = set
            .get("elem")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for e in elems {
            let Some(inner) = e.get("elem") else { continue };
            let Some(left) = inner.get("expires").and_then(Value::as_u64) else {
                continue;
            };
            let Some(address) = inner.get("val").and_then(elem_addr) else {
                continue;
            };
            out.push(DynamicAddress {
                list: list.clone(),
                address,
                timeout_secs: left.max(1),
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
