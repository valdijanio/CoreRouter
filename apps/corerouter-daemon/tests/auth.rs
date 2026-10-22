//! G0.3 end to end on the real daemon: first admin without a password
//! (G0.3b), TLS endpoint with login, certificate kept across restarts,
//! local token on loopback, `--reset-admin-password`.
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
    start_on(dir, "127.0.0.1", extra)
}

fn start_on(dir: &Path, listen: &str, extra: &[&str]) -> Daemon {
    let (control, tls) = (free_port(), free_port());
    let token_file = dir.join("local.token");
    let mut child = Command::new(DAEMON)
        .args(["--control", &control.to_string(), "--no-discovery"])
        .args(["--listen", &format!("{listen}:{tls}")])
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

const ADMIN_PW: &str = "first-real-password";

#[test]
fn admin_tls_login_local_token_and_reset() {
    let dir = std::env::temp_dir().join(format!("cr-auth-daemon-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    let mut d = start(&dir, &[]);
    d.line("created user 'admin' (group full) without a password");
    let fp = d.fingerprint();
    assert!(
        !d.seen.iter().any(|l| l.contains("  password: ")),
        "no random password is printed any more"
    );
    let key = std::fs::metadata(dir.join("tls-key.pem")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(key.permissions().mode() & 0o777, 0o600);
        let t = std::fs::metadata(&d.token_file).unwrap();
        assert_eq!(t.permissions().mode() & 0o777, 0o600);
    }
    let _ = key;

    // First login, from this machine, with an empty password; the router
    // says admin has none. Setting one keeps this session.
    assert!(login(&d, "admin", "not-the-password", &fp).is_err());
    let mut admin = login(&d, "admin", "", &fp).unwrap();
    let me = admin.call("auth.whoami", Value::Null).unwrap();
    assert_eq!(me["group"], "full");
    assert_eq!(me["no_password"], json!(["admin"]));
    exec(
        &mut admin,
        "user.set",
        json!({"name": "admin", "password": ADMIN_PW}),
    )
    .unwrap();
    let me = admin.call("auth.whoami", Value::Null).unwrap();
    assert_eq!(me["no_password"], json!([]), "{me}");
    assert!(
        login(&d, "admin", "", &fp).is_err(),
        "empty no longer works"
    );
    let list = exec(&mut admin, "user.list", json!({})).unwrap();
    assert_eq!(list[0]["no_password"], false);

    // Create a read-only user.
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
    assert!(
        noc.call("auth.whoami", Value::Null)
            .unwrap()
            .get("no_password")
            .is_none(),
        "only group full is told"
    );

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
    // The passwords are nowhere in the journal or the log.
    let journal = plain
        .call("state.inspect", json!({"path": "journal"}))
        .unwrap();
    assert!(!journal.to_string().contains("noc-password"));
    assert!(!journal.to_string().contains(ADMIN_PW));
    drop((admin, noc, plain, c));
    let _ = d.child.kill();
    let _ = d.child.wait();
    let log = d.seen.join("\n");
    assert!(!log.contains("noc-password") && !log.contains(ADMIN_PW));

    // Restart: same certificate, users and passwords kept, admin not reset.
    let mut d = start(&dir, &[]);
    assert_eq!(d.fingerprint(), fp);
    assert!(!d.seen.iter().any(|l| l.contains("without a password")));
    assert!(login(&d, "noc", "noc-password", &fp).is_ok());
    assert!(login(&d, "admin", ADMIN_PW, &fp).is_ok());
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

    // --reset-admin-password: admin has no password again.
    let mut d = start(&dir, &["--reset-admin-password"]);
    d.line("user 'admin' has no password again");
    assert!(login(&d, "admin", ADMIN_PW, &fp).is_err());
    if let Err(e) = login(&d, "admin", "", &fp) {
        panic!("{e}\n{}", d.seen.join("\n"));
    }
    assert!(login(&d, "noc", "noc-password", &fp).is_ok(), "others kept");
    drop(d);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn network_listener_warns_while_admin_has_no_password() {
    let dir = std::env::temp_dir().join(format!("cr-auth-open-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mut d = start_on(&dir, "0.0.0.0", &[]);
    d.line("every network login is refused until a password is set");
    // Reached through loopback it is still this machine: the empty login
    // works (the refusal from other addresses is tested in control::auth).
    let fp = d.fingerprint();
    let port = d.tls.rsplit(':').next().unwrap().to_owned();
    let local = Target::parse(&format!("tls://127.0.0.1:{port}")).unwrap();
    let c = dial(
        &local,
        Duration::from_secs(2),
        &Login::Password {
            user: "admin".into(),
            password: String::new(),
        },
        &mut KnownHosts::in_memory(),
        &mut Expect(fp),
    );
    assert!(c.is_ok(), "{:?}", c.err());
    drop(d);
    let _ = std::fs::remove_dir_all(&dir);
}
