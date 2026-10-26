//! `cargo xtask bng-lab` (G4.3g): the mass PPPoE lab. BNG Blaster against
//! a release daemon, in throwaway namespaces (the stages are in
//! `apps/corerouter-daemon/tests/bng_lab.rs`).
//!
//! - without root: `unshare --user --map-root-user --net`, the slow path
//!   (no XDP, so no policer), BNG Blaster's client only;
//! - `--root`: `sudo ip netns add crbng`, XDP on the ports (the policer),
//!   and `pppd` with the kernel PPPoE plugin as a second client. Nothing
//!   outside the namespace is touched; it is deleted at the end.
//!
//! `--only ha` (G4.3h) runs the redundant pair instead
//! (`apps/corerouter-daemon/tests/bng_lab_ha.rs`; `--scales` then sets its
//! sizes).
//!
//! Options: `--root`, `--scales 1000,10000,100000`, `--radius <n>`,
//! `--only capture,scale,radius,shaping,workers,wave,qinq,pppd`, `--shaping <n>`, `--wave <n>`, `--qinq <n>` (QinQ lines), `--radius-cap <n/s>`, `--out <dir>` (default
//! `<target>/bng-lab`). BNG Blaster comes from `$BNGBLASTER` or the PATH.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::Outcome;

const NS: &str = "crbng";

const INSTALL: &str = "BNG Blaster not found ($BNGBLASTER or bngblaster in the PATH). \
    Install the release for this distribution from https://github.com/rtbrick/bngblaster/releases \
    (sudo apt install ./bngblaster-<v>-ubuntu-24.04_amd64.deb), or unpack it without root \
    (dpkg-deb -x <deb> <dir>) and point BNGBLASTER at <dir>/usr/bin/bngblaster";

pub fn main(root: &Path, args: &[String]) -> Outcome {
    let mut as_root = false;
    let mut env: Vec<(&str, String)> = Vec::new();
    let mut out = None;
    let mut blaster_arg = None;
    let mut target = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut value = |k: &'static str| -> Result<(), String> {
            let v = it.next().ok_or_else(|| format!("{a} needs a value"))?;
            env.push((k, v.clone()));
            Ok(())
        };
        let r = match a.as_str() {
            "--root" => {
                as_root = true;
                Ok(())
            }
            "--scales" => value("BNG_LAB_SCALES"),
            "--radius" => value("BNG_LAB_RADIUS"),
            "--only" => value("BNG_LAB_ONLY"),
            "--hold" => value("BNG_LAB_HOLD"),
            "--wave" => value("BNG_LAB_WAVE"),
            "--shaping" => value("BNG_LAB_SHAPING"),
            "--qinq" => value("BNG_LAB_QINQ"),
            "--radius-cap" => value("BNG_LAB_RADIUS_CAP"),
            "--blaster" => match it.next() {
                Some(v) => {
                    blaster_arg = Some(PathBuf::from(v));
                    Ok(())
                }
                None => Err("--blaster needs a path".into()),
            },
            "--target-dir" => match it.next() {
                Some(v) => {
                    target = Some(PathBuf::from(v));
                    Ok(())
                }
                None => Err("--target-dir needs a directory".into()),
            },
            "--out" => match it.next() {
                Some(v) => {
                    out = Some(PathBuf::from(v));
                    Ok(())
                }
                None => Err("--out needs a directory".into()),
            },
            other => Err(format!(
                "unknown option {other}; cargo xtask bng-lab [--root] [--scales 1000,10000] \
                 [--radius 100] [--only capture,scale,radius,shaping,workers,wave,pppd] [--hold 30] [--shaping 1000] [--wave 100000] [--radius-cap 3000] [--out dir] [--blaster path] [--target-dir dir]"
            )),
        };
        if let Err(e) = r {
            return Outcome::Fail(e);
        }
    }
    let target = target
        .map(|t| if t.is_absolute() { t } else { root.join(t) })
        .unwrap_or_else(|| target_dir(root));
    let Some(blaster) = blaster_arg.filter(|p| p.exists()).or_else(blaster) else {
        return Outcome::Fail(INSTALL.into());
    };
    // G4.3h: the pair is its own binary (two daemons, another topology).
    let ha = env.iter().any(|(k, v)| *k == "BNG_LAB_ONLY" && v == "ha");
    if ha {
        for (k, _) in env.iter_mut() {
            if *k == "BNG_LAB_SCALES" {
                *k = "BNG_LAB_HA_SCALES";
            }
        }
    }
    let name = if ha { "bng_lab_ha" } else { "bng_lab" };
    let exe = match lab_binary(root, &target, name) {
        Ok(e) => e,
        Err(e) => return Outcome::Fail(e),
    };
    let out = out.unwrap_or_else(|| target.join("bng-lab"));
    let _ = std::fs::create_dir_all(&out);
    eprintln!(
        "bng-lab: {} with {}, results in {}",
        exe.display(),
        blaster.display(),
        out.display()
    );
    let mut vars: Vec<String> = vec![
        "COREROUTER_BNG_LAB=1".into(),
        format!("BNGBLASTER={}", blaster.display()),
        format!("BNG_LAB_OUT={}", out.display()),
    ];
    if as_root {
        vars.push("BNG_LAB_ROOT=1".into());
    }
    vars.extend(env.iter().map(|(k, v)| format!("{k}={v}")));
    let test = [
        exe.to_string_lossy().into_owned(),
        name.into(),
        "--exact".into(),
        "--nocapture".into(),
        "--test-threads=1".into(),
    ];
    let status = if as_root {
        // `sudo` asks the user for the password (never -n here: the lab is
        // run by hand). The namespace is the only thing created.
        let sudo = |a: &[&str]| Command::new("sudo").args(a).status();
        let _ = sudo(&["ip", "netns", "del", NS]);
        match sudo(&["ip", "netns", "add", NS]) {
            Ok(s) if s.success() => {}
            Ok(s) => return Outcome::Fail(format!("sudo ip netns add {NS}: {s}")),
            Err(e) => return Outcome::Fail(format!("sudo: {e}")),
        }
        let st = Command::new("sudo")
            .args(["ip", "netns", "exec", NS, "env"])
            .args(&vars)
            .args(test)
            .status();
        let _ = sudo(&["ip", "netns", "del", NS]);
        // The files are root's: give them back.
        let me = format!(
            "{}:{}",
            id("-u").unwrap_or_default(),
            id("-g").unwrap_or_default()
        );
        let _ = Command::new("sudo")
            .args(["chown", "-R", &me])
            .arg(&out)
            .status();
        st
    } else {
        if let Err(why) = crate::netns_probe() {
            return Outcome::Fail(why);
        }
        Command::new("unshare")
            .args(crate::UNSHARE)
            .arg("env")
            .args(&vars)
            .args(test)
            .status()
    };
    let summary = out.join("summary.md");
    if let Ok(t) = std::fs::read_to_string(&summary) {
        eprintln!("\n{t}");
    }
    match status {
        Ok(s) if s.success() => Outcome::Ok,
        Ok(s) => Outcome::Fail(format!(
            "the lab: {s} (see {} and the logs next to it)",
            summary.display()
        )),
        Err(e) => Outcome::Fail(format!("could not start the lab: {e}")),
    }
}

fn id(flag: &str) -> Option<String> {
    let o = Command::new("id").arg(flag).output().ok()?;
    Some(String::from_utf8_lossy(&o.stdout).trim().to_owned())
}

fn blaster() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("BNGBLASTER") {
        let p = PathBuf::from(p);
        return p.exists().then_some(p);
    }
    let path = std::env::var_os("PATH").unwrap_or_default();
    std::env::split_paths(&path)
        .chain(["/usr/sbin".into(), "/usr/local/sbin".into()])
        .map(|d| d.join("bngblaster"))
        .find(|p| p.exists())
}

fn target_dir(root: &Path) -> PathBuf {
    std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .map(|p| if p.is_absolute() { p } else { root.join(p) })
        .unwrap_or_else(|| root.join("target"))
}

/// The lab's test binary, built in release (the daemon it starts too).
fn lab_binary(root: &Path, target: &Path, name: &str) -> Result<PathBuf, String> {
    let out = crate::cargo()
        .env("CARGO_TARGET_DIR", target)
        .args([
            "test",
            "--release",
            "-p",
            "corerouter-daemon",
            "--test",
            name,
            "--no-run",
            "--message-format=json-render-diagnostics",
        ])
        .current_dir(root)
        .stderr(std::process::Stdio::inherit())
        .output()
        .map_err(|e| format!("cargo test --no-run: {e}"))?;
    if !out.status.success() {
        return Err(format!("cargo test --release --no-run: {}", out.status));
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|m| {
            m.pointer("/target/name")
                .and_then(serde_json::Value::as_str)
                == Some(name)
        })
        .find_map(|m| m.get("executable")?.as_str().map(PathBuf::from))
        .ok_or_else(|| format!("{name} test binary not found"))
}
