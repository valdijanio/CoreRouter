//! G1.6e: a package sent over the control channel (`system.package.upload.*`)
//! to a daemon's virtual lab (`--backend virtual --config-dir`: the A/B code
//! of the image on sparse files). Success boots the trial slot; a tampered
//! package and an interrupted upload change nothing.
#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use base64::Engine as _;
use corerouter_control::Client;
use corerouter_sysupdate::package::{self, Blob, Manifest, Rootfs};
use corerouter_sysupdate::verity;
use serde_json::{Value, json};

const DAEMON: &str = env!("CARGO_BIN_EXE_corerouter-daemon");

struct Daemon {
    child: Child,
    control: String,
    token_file: PathBuf,
    dir: PathBuf,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
        let _ = std::fs::remove_file(&self.token_file);
    }
}

fn exec(d: &Daemon, command: &str, params: Value) -> Result<Value, String> {
    let token = std::fs::read_to_string(&d.token_file).map_err(|e| e.to_string())?;
    let mut c = Client::connect(&d.control, Duration::from_millis(500))?;
    c.set_token(Some(token.trim().to_owned()));
    c.call(
        "engine.execute",
        json!({"command": command, "params": params}),
    )
}

fn wait_for(what: &str, within: Duration, mut ok: impl FnMut() -> bool) {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if ok() {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("timed out ({within:?}) waiting for {what}");
}

fn lab(name: &str) -> Daemon {
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let dir = std::env::temp_dir().join(format!("cr-upload-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let token_file = dir.with_extension("token");
    let child = Command::new(DAEMON)
        .args(["--control", &port.to_string()])
        .arg("--token-file")
        .arg(&token_file)
        .arg("--config-dir")
        .arg(dir.join("config"))
        .arg("--no-discovery")
        .env("RUST_LOG", "info")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let d = Daemon {
        child,
        control: format!("127.0.0.1:{port}"),
        token_file,
        dir,
    };
    wait_for("the lab image", Duration::from_secs(30), || {
        exec(&d, "system.package.print", json!({}))
            .is_ok_and(|p| p["supported"] == true && p["running"] == "a")
    });
    d
}

/// A package signed with the lab's own key (what the lab trusts).
fn package(config: &Path, version: &str) -> Vec<u8> {
    let key = std::fs::read(config.join("lab-image/lab-key.pk8")).unwrap();
    let kernel: Vec<u8> = (0..700_000u32).map(|i| (i % 251) as u8).collect();
    let data: Vec<u8> = (0..600 * 4096u32).map(|i| (i % 241) as u8 ^ 0x33).collect();
    let salt = [9, 8, 7];
    let tree = verity::tree(&data, &salt, 1).unwrap();
    let mut rootfs = data;
    rootfs.extend_from_slice(&tree.bytes);
    let m = Manifest {
        format: 1,
        version: version.into(),
        build: 1_900_000_000,
        commit: "upload".into(),
        channel: "stable".into(),
        kernel_version: "virtual".into(),
        config_format: 1,
        kernel: Blob {
            size: kernel.len() as u64,
            sha256: package::sha256_hex(&kernel),
        },
        rootfs: Rootfs {
            size: rootfs.len() as u64,
            sha256: package::sha256_hex(&rootfs),
            data_blocks: tree.data_blocks,
            hash_blocks: tree.hash_blocks,
            salt: verity::hex(&salt),
            root_hash: verity::hex(&tree.root),
        },
    };
    let mut out = package::sign(&m, &key).unwrap();
    out.extend_from_slice(&kernel);
    out.extend_from_slice(&rootfs);
    out
}

/// Sends `bytes` (all of them, or up to chunk `stop`), resending busy
/// chunks; then waits for the job's result.
fn upload(d: &Daemon, bytes: &[u8], params: Value, stop: Option<usize>) -> Value {
    let mut start = params;
    start["size"] = json!(bytes.len());
    let s = exec(d, "system.package.upload.start", start).unwrap();
    let job = s["upload"].as_u64().unwrap();
    let mut sent = 0u64;
    for (i, c) in bytes.chunks(256 << 10).enumerate() {
        if stop == Some(i) {
            exec(d, "system.package.upload.abort", json!({"upload": job})).unwrap();
            break;
        }
        let data = base64::engine::general_purpose::STANDARD.encode(c);
        loop {
            match exec(
                d,
                "system.package.upload.chunk",
                json!({"upload": job, "offset": sent, "data": data}),
            ) {
                Ok(r) if r["busy"] == true => thread::sleep(Duration::from_millis(5)),
                Ok(_) => break,
                Err(e) if e.contains("no upload") => return result(d, job),
                Err(e) => panic!("chunk {i}: {e}"),
            }
        }
        sent += c.len() as u64;
    }
    result(d, job)
}

fn result(d: &Daemon, job: u64) -> Value {
    let mut out = Value::Null;
    wait_for("the upload job", Duration::from_secs(30), || {
        let p = exec(d, "system.package.print", json!({})).unwrap();
        if p["result"]["id"].as_u64() == Some(job) {
            out = p["result"].clone();
            return true;
        }
        false
    });
    out
}

#[test]
fn upload_over_the_control_channel() {
    let d = lab("ok");
    let pkg = package(&d.dir.join("config"), "9.1");
    // Only checked: nothing written.
    let r = upload(&d, &pkg, json!({"check": true}), None);
    assert_eq!(r["ok"], true, "{r}");
    assert_eq!(r["result"]["intact"], true);
    assert_eq!(r["result"]["signature"], "ok");
    // Tampered on the way: refused, slot B never activated.
    let mut bad = pkg.clone();
    let at = bad.len() - 10_000;
    bad[at] ^= 0x40;
    let r = upload(&d, &bad, json!({}), None);
    assert_eq!(r["ok"], false);
    assert!(
        r["error"].as_str().unwrap().contains("signed hashes"),
        "{r}"
    );
    // Interrupted in the middle.
    let r = upload(&d, &pkg, json!({}), Some(3));
    assert_eq!(r["ok"], false);
    assert!(r["error"].as_str().unwrap().contains("aborted"), "{r}");
    let p = exec(&d, "system.package.print", json!({})).unwrap();
    assert_eq!(p["trial"], Value::Null);
    assert_eq!(p["running"], "a");
    assert_eq!(p["slots"][1]["next"], false);
    // Whole: written, the lab reboots into the trial of slot B.
    let r = upload(&d, &pkg, json!({"confirm": "manual"}), None);
    assert_eq!(r["ok"], true, "{r}");
    assert_eq!(r["result"]["slot"], "b");
    wait_for("the trial boot of B", Duration::from_secs(10), || {
        let p = exec(&d, "system.package.print", json!({})).unwrap();
        p["running"] == "b" && p["trial"]["slot"] == "b"
    });
    exec(&d, "system.package.confirm", json!({})).unwrap();
    wait_for("B confirmed", Duration::from_secs(10), || {
        let p = exec(&d, "system.package.print", json!({})).unwrap();
        p["trial"].is_null() && p["primary"] == "b" && p["slots"][1]["version"] == "9.1"
    });
}

/// Serves `body` (or a 404 for any other path) to `conns` connections.
fn serve(body: Vec<u8>, conns: usize) -> u16 {
    use std::io::{BufRead, BufReader, Write};
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    thread::spawn(move || {
        for s in l.incoming().take(conns) {
            let mut s = s.unwrap();
            let mut first = String::new();
            let mut r = BufReader::new(s.try_clone().unwrap());
            r.read_line(&mut first).unwrap();
            loop {
                let mut h = String::new();
                if r.read_line(&mut h).unwrap() == 0 || h == "\r\n" {
                    break;
                }
            }
            if first.contains(" /b.crpkg ") {
                let _ = write!(
                    s,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = s.write_all(&body);
            } else {
                let _ = s.write_all(
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
            }
        }
    });
    port
}

fn download(d: &Daemon, params: Value) -> Value {
    let job = exec(d, "system.package.download", params).unwrap()["job"]
        .as_u64()
        .unwrap();
    result(d, job)
}

#[test]
fn download_over_http() {
    let d = lab("download");
    let pkg = package(&d.dir.join("config"), "9.2");
    let mut bad = pkg.clone();
    let at = bad.len() - 5000;
    bad[at] ^= 1;
    let good = serve(pkg, 3);
    let tampered = serve(bad, 1);
    let r = download(
        &d,
        json!({"url": format!("http://127.0.0.1:{good}/missing.crpkg")}),
    );
    assert!(r["error"].as_str().unwrap().contains("404"), "{r}");
    let r = download(
        &d,
        json!({"url": format!("http://127.0.0.1:{tampered}/b.crpkg")}),
    );
    assert!(
        r["error"].as_str().unwrap().contains("signed hashes"),
        "{r}"
    );
    let r = download(
        &d,
        json!({"url": format!("http://127.0.0.1:{good}/b.crpkg"), "check": true}),
    );
    assert_eq!(
        (r["ok"].as_bool(), r["result"]["intact"].as_bool()),
        (Some(true), Some(true)),
        "{r}"
    );
    let r = download(
        &d,
        json!({"url": format!("http://127.0.0.1:{good}/b.crpkg"), "confirm": "manual"}),
    );
    assert_eq!(r["ok"], true, "{r}");
    assert_eq!(r["result"]["slot"], "b");
    wait_for("the trial boot of B", Duration::from_secs(10), || {
        let p = exec(&d, "system.package.print", json!({})).unwrap();
        p["running"] == "b" && p["trial"]["slot"] == "b" && p["trial"]["version"] == "9.2"
    });
}
