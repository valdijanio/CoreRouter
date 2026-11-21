//! G0.11: two operating-system users on the local socket, as root in the
//! lab VM only (a second uid needs root, or `newuidmap` in a namespace).
//! The router runs as root; a client running as `nobody` (65534) is
//! refused by the directory mode, and, with the modes loosened on purpose,
//! by `SO_PEERCRED`, before any request.
//!
//! ```sh
//! cargo xtask vm-lab run -- env COREROUTER_UNIX_ROOT=1 \
//!     cargo test -p corerouter-control --test unix_socket_root
//! ```
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use corerouter_control::{Client, Gate, SharedHost, Shutdown, unix};
use corerouter_engine::{Session, shared};
use serde_json::Value;

const NOBODY: u32 = 65534;
/// Set in the child: the socket to try, as `nobody`.
const CHILD: &str = "COREROUTER_UNIX_ROOT_CHILD";

fn enabled() -> bool {
    let on = std::env::var_os("COREROUTER_UNIX_ROOT").is_some_and(|v| v == "1");
    if !on {
        eprintln!("skipped: lab VM only, set COREROUTER_UNIX_ROOT=1");
    }
    on && unix::my_uid() == 0
}

/// What `nobody` gets from the socket: "connect: …" or the first reply.
fn as_nobody(base: &Path, path: &Path) -> String {
    // A copy nobody may run (the build directory may be root's only).
    let exe = base.join("child-test");
    if !exe.exists() {
        std::fs::copy(std::env::current_exe().unwrap(), &exe).unwrap();
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let out = Command::new(&exe)
        .args(["--exact", "child_tries_the_socket", "--nocapture"])
        .env(CHILD, path)
        .uid(NOBODY)
        .gid(NOBODY)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.lines()
        .find_map(|l| l.strip_prefix("CHILD: "))
        .unwrap_or_else(|| {
            panic!(
                "child said nothing: {text} {}",
                String::from_utf8_lossy(&out.stderr)
            )
        })
        .to_owned()
}

/// Runs only in the child (as `nobody`): one ping on the socket.
#[test]
fn child_tries_the_socket() {
    let Some(path) = std::env::var_os(CHILD).map(PathBuf::from) else {
        return;
    };
    let said = match UnixStream::connect(&path) {
        Err(e) => format!("connect: {:?}", e.kind()),
        Ok(mut s) => {
            let _ = s.write_all(b"{\"id\":1,\"method\":\"auth.whoami\"}\n");
            let mut line = String::new();
            let _ = BufReader::new(&s).read_line(&mut line);
            line.trim().to_owned()
        }
    };
    println!("CHILD: {said}");
}

#[test]
fn another_uid_is_refused_and_root_is_local() {
    if !enabled() {
        return;
    }
    let base = std::env::temp_dir().join(format!("cr-unix-root-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();
    std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o755)).unwrap();
    let dir = base.join("run");
    let path = dir.join("control-7979.sock");
    let session = shared(Session::virtual_lab());
    let l = unix::bind_at(&path).unwrap();
    let stop = Shutdown::default();
    unix::spawn_until(l, SharedHost(session), Gate::default(), stop.clone()).unwrap();

    // Root (the router's own user here) is local without a token.
    let mut c = Client::connect_unix(&path).unwrap();
    let me = c.call("auth.whoami", Value::Null).unwrap();
    assert_eq!(me["group"], "full", "{me}");

    // nobody: the private directory keeps it out.
    let said = as_nobody(&base, &path);
    assert_eq!(said, "connect: PermissionDenied", "{said}");

    // Modes loosened on purpose: SO_PEERCRED still refuses it, with why.
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
    let said = as_nobody(&base, &path);
    assert!(
        said.contains("only for the operating-system user that runs the router"),
        "{said}"
    );
    assert!(!said.contains("\"ok\":true"), "{said}");
    // And the router keeps serving its own user.
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(c.call("ping", Value::Null).unwrap()["pong"], true);
    stop.close();
    let _ = std::fs::remove_dir_all(&base);
}
