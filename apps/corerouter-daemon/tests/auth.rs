//! G0.3 end to end on the real daemon: first admin printed once, TLS
//! endpoint with login, certificate kept across restarts, local token on
//! loopback, `--reset-admin-password`.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use corerouter_control::dial::{Expect, RefuseNew};
use corerouter_control::{Client, KnownHosts, Login, Target, UNAUTHORIZED, dial};
use serde_json::{Value, json};

const DAEMON: &str = env!("CARGO_BIN_EXE_corerouter-daemon");

struct Daemon {
    child: Child,
    control: String,
    tls: String,
    token_file: PathBuf,
    /// Lines of stderr as they arrive.
    lines: mpsc::Receiver<String>,
    seen: Vec<String>,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Daemon {
    /// Wait for a stderr line containing `needle`; returns it.
    fn line(&mut self, needle: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(20);
        if let Some(l) = self.seen.iter().find(|l| l.contains(needle)) {
            return l.clone();
        }
        while Instant::now() < deadline {
            if let Ok(l) = self.lines.recv_timeout(Duration::from_millis(100)) {
                self.seen.push(l.clone());
                if l.contains(needle) {
                    return l;
                }
            }
        }
        panic!(
            "no '{needle}' in the daemon output:\n{}",
            self.seen.join("\n")
        );
    }

    fn token(&self) -> String {
        std::fs::read_to_string(&self.token_file)
            .unwrap()
            .trim()
            .to_owned()
    }

    fn password(&mut self) -> String {
        self.line("  password: ")
            .split("password: ")
            .nth(1)
            .unwrap()
            .trim()
            .to_owned()
    }

    fn fingerprint(&mut self) -> String {
        self.line("TLS certificate fingerprint: ")
            .split("fingerprint: ")
            .nth(1)
            .unwrap()
            .trim()
            .to_owned()
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn start(dir: &Path, extra: &[&str]) -> Daemon {
    let (control, tls) = (free_port(), free_port());
    let token_file = dir.join("local.token");
    let mut child = Command::new(DAEMON)
        .args(["--control", &control.to_string(), "--no-discovery"])
        .args(["--listen", &format!("127.0.0.1:{tls}")])
        .arg("--config-dir")
        .arg(dir)
        .arg("--token-file")
        .arg(&token_file)
        .args(extra)
        .env("RUST_LOG", "info")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let (tx, rx) = mpsc::channel();
    let err = child.stderr.take().unwrap();
    thread::spawn(move || {
        for l in BufReader::new(err).lines().map_while(Result::ok) {
            if tx.send(l).is_err() {
                return;
            }
        }
    });
    let mut d = Daemon {
        child,
        control: format!("127.0.0.1:{control}"),
        tls: format!("tls://127.0.0.1:{tls}"),
        token_file,
        lines: rx,
        seen: Vec::new(),
    };
    d.line("control channel over TLS");
    d
}

fn login(d: &Daemon, user: &str, password: &str, fp: &str) -> Result<Client, String> {
    dial(
        &Target::parse(&d.tls).unwrap(),
        Duration::from_secs(2),
        &Login::Password {
            user: user.into(),
            password: password.into(),
        },
        &mut KnownHosts::in_memory(),
        &mut Expect(fp.to_owned()),
    )
}

fn exec(c: &mut Client, command: &str, params: Value) -> Result<Value, String> {
    c.call(
        "engine.execute",
        json!({"command": command, "params": params}),
    )
}

#[test]
fn admin_tls_login_local_token_and_reset() {
    let dir = std::env::temp_dir().join(format!("cr-auth-daemon-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    let mut d = start(&dir, &[]);
    let password = d.password();
    assert!(password.len() >= 16, "{password}");
    let fp = d.fingerprint();
    let key = std::fs::metadata(dir.join("tls-key.pem")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(key.permissions().mode() & 0o777, 0o600);
        let t = std::fs::metadata(&d.token_file).unwrap();
        assert_eq!(t.permissions().mode() & 0o777, 0o600);
    }
    let _ = key;

    // TLS + login as admin; create a read-only user.
    let mut admin = login(&d, "admin", &password, &fp).unwrap();
    assert_eq!(
        admin.call("auth.whoami", Value::Null).unwrap()["group"],
        "full"
    );
    exec(
        &mut admin,
        "user.add",
        json!({"name": "noc", "group": "read", "password": "noc-password"}),
    )
    .unwrap();
    assert_eq!(
        login(&d, "admin", "wrong-password", &fp).err().unwrap(),
        format!("{}: invalid user or password", d.tls)
    );
    let mut noc = login(&d, "noc", "noc-password", &fp).unwrap();
    let e = exec(&mut noc, "system.identity.set", json!({"name": "x"})).unwrap_err();
    assert!(e.contains("needs group write"), "{e}");

    // The TLS endpoint does not take the local token.
    let mut c =
        Client::connect_tls(&d.tls["tls://".len()..], Duration::from_secs(2), Some(&fp)).unwrap();
    c.set_token(Some(d.token()));
    assert!(
        c.call("engine.list", Value::Null)
            .unwrap_err()
            .starts_with(UNAUTHORIZED)
    );

    // Loopback: nothing without the token, everything with it.
    let mut plain = Client::connect(&d.control, Duration::from_secs(2)).unwrap();
    assert!(
        plain
            .call("engine.list", Value::Null)
            .unwrap_err()
            .starts_with(UNAUTHORIZED)
    );
    plain.set_token(Some(d.token()));
    exec(
        &mut plain,
        "system.identity.set",
        json!({"name": "edge-auth"}),
    )
    .unwrap();
    // The password is nowhere in the journal or the log.
    let journal = plain
        .call("state.inspect", json!({"path": "journal"}))
        .unwrap();
    assert!(!journal.to_string().contains("noc-password"));
    drop((admin, noc, plain, c));
    let _ = d.child.kill();
    let _ = d.child.wait();
    let log = d.seen.join("\n");
    assert_eq!(log.matches(&password).count(), 1, "printed exactly once");
    assert!(!log.contains("noc-password"));

    // Restart: same certificate, users kept, no new admin password.
    let mut d = start(&dir, &[]);
    assert_eq!(d.fingerprint(), fp);
    assert!(!d.seen.iter().any(|l| l.contains("  password: ")));
    assert!(login(&d, "noc", "noc-password", &fp).is_ok());
    // A client that never saw this router refuses to send anything.
    let e = dial(
        &Target::parse(&d.tls).unwrap(),
        Duration::from_secs(2),
        &Login::Nothing,
        &mut KnownHosts::in_memory(),
        &mut RefuseNew,
    )
    .err()
    .unwrap();
    assert!(e.contains("not trusted"), "{e}");
    drop(d);

    // --reset-admin-password: the old one stops working.
    let mut d = start(&dir, &["--reset-admin-password"]);
    let new = d.password();
    assert_ne!(new, password);
    assert!(login(&d, "admin", &password, &fp).is_err());
    if let Err(e) = login(&d, "admin", &new, &fp) {
        panic!("{e}\n{}", d.seen.join("\n"));
    }
    drop(d);
    let _ = std::fs::remove_dir_all(&dir);
}
