//! `cargo xtask os push --to HOST:PORT` (G1.6e): the fast test cycle of the
//! image. Builds only the update package (`os build --only crpkg`), sends it
//! to a running router over the control channel (`corerouter-cli upload`,
//! `system.package.upload.*`), and waits for the router to reboot into the
//! new slot and confirm it. The VM is never recreated: `/config`, the
//! password and the certificate stay. Prints the time of each step.
//!
//! `--to 127.0.0.1:PORT` is a local control port (a GUI's `--control`
//! managing the router, or a forwarded daemon port): the local token, no
//! password. Any other address is TLS with `--user` (password from
//! `$COREROUTER_PASSWORD` or a prompt).

use std::path::Path;
use std::process::Command;
use std::time::Instant;

struct Args {
    to: String,
    user: Option<String>,
    fingerprint: Option<String>,
    build: bool,
    wait: bool,
    params: Vec<(String, String)>,
}

fn parse(args: &[String]) -> Result<Args, String> {
    let mut a = Args {
        to: String::new(),
        user: None,
        fingerprint: None,
        build: true,
        wait: true,
        params: Vec::new(),
    };
    let mut it = args.iter();
    while let Some(x) = it.next() {
        let mut val = |what: &str| it.next().cloned().ok_or(format!("{x} needs {what}"));
        match x.as_str() {
            "--to" => a.to = val("HOST:PORT")?,
            "--user" => a.user = Some(val("a user")?),
            "--fingerprint" => a.fingerprint = Some(val("SHA256:...")?),
            "--no-build" => a.build = false,
            "--no-wait" => a.wait = false,
            "--confirm" => a
                .params
                .push(("confirm".into(), format!("\"{}\"", val("auto|manual")?))),
            "--timeout" => a.params.push(("timeout".into(), val("seconds")?)),
            other => return Err(format!("os push: unknown argument '{other}'")),
        }
    }
    if a.to.is_empty() {
        return Err(
            "os push needs --to HOST:PORT (e.g. 127.0.0.1:7990, a GUI's --control port)".into(),
        );
    }
    Ok(a)
}

pub fn push(root: &Path, images: &Path, args: &[String]) -> Result<(), String> {
    let a = parse(args)?;
    let t0 = Instant::now();
    let mut steps: Vec<(&str, f64)> = Vec::new();
    if a.build {
        let t = Instant::now();
        super::build(root, &["--only".into(), "crpkg".into()])?;
        steps.push(("build (--only crpkg)", t.elapsed().as_secs_f64()));
    }
    let crpkg = images.join("corerouter.crpkg");
    if !crpkg.exists() {
        return Err(format!(
            "{} missing: run cargo xtask os build",
            crpkg.display()
        ));
    }
    let t = Instant::now();
    let st = Command::new(crate::cargo_bin())
        .args(["build", "-q", "--release", "-p", "corerouter-cli"])
        .current_dir(root)
        .status()
        .map_err(|e| format!("cargo: {e}"))?;
    if !st.success() {
        return Err("cargo build -p corerouter-cli failed".into());
    }
    steps.push(("corerouter-cli", t.elapsed().as_secs_f64()));
    // The release CLI sits next to this xtask's debug directory.
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let cli = exe
        .parent()
        .and_then(Path::parent)
        .map(|t| t.join("release/corerouter-cli"))
        .filter(|p| p.exists())
        .ok_or("corerouter-cli: release binary not found next to the xtask")?;
    let params = format!(
        "{{{}}}",
        a.params
            .iter()
            .map(|(k, v)| format!("\"{k}\":{v}"))
            .collect::<Vec<_>>()
            .join(",")
    );
    let mut cmd = Command::new(&cli);
    cmd.args(["--connect", &a.to]);
    if let Some(u) = &a.user {
        cmd.args(["--user", u]);
    }
    if let Some(f) = &a.fingerprint {
        cmd.args(["--fingerprint", f]);
    }
    cmd.arg("upload").arg(&crpkg).arg(&params);
    if a.wait {
        cmd.arg("--wait");
    }
    let t = Instant::now();
    let out = cmd
        .stderr(std::process::Stdio::inherit())
        .output()
        .map_err(|e| format!("{}: {e}", cli.display()))?;
    let text = String::from_utf8_lossy(&out.stdout);
    if !out.status.success() {
        return Err(format!("upload to {} failed", a.to));
    }
    let v: serde_json::Value = serde_json::from_str(&text).unwrap_or_default();
    let null = serde_json::Value::Null;
    let tm = v.get("times").unwrap_or(&null);
    let secs = |k: &str| tm.get(k).and_then(serde_json::Value::as_f64);
    if let Some(s) = secs("send_s") {
        steps.push(("send", s));
    }
    if let (Some(d), Some(s)) = (secs("done_s"), secs("send_s")) {
        steps.push(("finish write + read-back", d - s));
    }
    if let Some(s) = secs("reboot_to_answer_s") {
        steps.push(("reboot → answering from the new slot", s));
    }
    if let (Some(c), Some(b)) = (secs("reboot_to_confirmed_s"), secs("reboot_to_answer_s")) {
        steps.push(("→ confirmed", c - b));
    }
    if !a.wait {
        steps.push(("upload (no wait)", t.elapsed().as_secs_f64()));
    }
    let r = v.get("result").unwrap_or(&null);
    let txt = |o: &serde_json::Value, k: &str| {
        o.get(k)
            .and_then(serde_json::Value::as_str)
            .unwrap_or("?")
            .to_owned()
    };
    eprintln!(
        "\npushed {} to {}: slot {}, {:.1} MiB at {:.0} MiB/s",
        txt(r, "version"),
        a.to,
        txt(r, "slot"),
        secs("bytes").unwrap_or(0.0) / 1048576.0,
        secs("mib_per_s").unwrap_or(0.0)
    );
    for (what, s) in &steps {
        eprintln!("  {what:<38} {s:>7.1} s");
    }
    eprintln!("  {:<38} {:>7.1} s", "total", t0.elapsed().as_secs_f64());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arguments() {
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        let a = parse(&s(&[
            "--to",
            "127.0.0.1:7990",
            "--no-build",
            "--confirm",
            "manual",
            "--timeout",
            "60",
        ]))
        .unwrap();
        assert_eq!(a.to, "127.0.0.1:7990");
        assert!(!a.build && a.wait);
        assert_eq!(
            a.params,
            [
                ("confirm".into(), "\"manual\"".into()),
                ("timeout".into(), "60".into())
            ]
        );
        assert!(parse(&s(&[])).is_err());
        assert!(parse(&s(&["--to"])).is_err());
        assert!(parse(&s(&["--to", "x", "--bogus"])).is_err());
    }
}
