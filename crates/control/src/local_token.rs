//! The local token: how the CLI and the MCP server on the router's own
//! machine get in without a password (G0.3).
//!
//! Whoever serves a control port (`corerouter-daemon`, `corerouter-gui
//! --control`) writes a fresh random token to `control-<port>.token` in
//! [`runtime_dir`] at start-up, readable only by its operating-system user
//! (directory 0700, file 0600 on unix; under the user's own profile on
//! Windows), and removes it on a clean shutdown. A client connecting to
//! `127.0.0.1:<port>` reads that file and sends the token with every
//! request. Another user of the same machine cannot read it, so it cannot
//! act as the router's admin over loopback: it has to log in like anyone
//! else. The file is the credential, as an SSH agent socket is.
//!
//! [`runtime_dir`] is `$COREROUTER_RUNTIME_DIR`, else
//! `$XDG_RUNTIME_DIR/corerouter`, else `~/.corerouter/run` (on Windows
//! `%LOCALAPPDATA%\corerouter\run`). A daemon run by root as a service
//! therefore keeps it under `/root`, and only root's CLI finds it.

use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;

/// Longest token file read (a token is 64 hex characters).
const MAX_FILE: u64 = 256;

/// Where token files live, or `None` when no base directory is known.
pub fn runtime_dir() -> Option<PathBuf> {
    if let Some(d) = std::env::var_os("COREROUTER_RUNTIME_DIR").filter(|d| !d.is_empty()) {
        return Some(PathBuf::from(d));
    }
    if let Some(d) = std::env::var_os("XDG_RUNTIME_DIR").filter(|d| !d.is_empty()) {
        return Some(PathBuf::from(d).join("corerouter"));
    }
    if let Some(h) = std::env::var_os("HOME").filter(|d| !d.is_empty()) {
        return Some(PathBuf::from(h).join(".corerouter").join("run"));
    }
    std::env::var_os("LOCALAPPDATA")
        .filter(|d| !d.is_empty())
        .map(|d| PathBuf::from(d).join("corerouter").join("run"))
}

/// The token file of the control port `port`.
pub fn path(port: u16) -> Option<PathBuf> {
    runtime_dir().map(|d| d.join(format!("control-{port}.token")))
}

/// Write `token` for `port` (replacing an old file); returns the path.
pub fn create(port: u16, token: &str) -> io::Result<PathBuf> {
    let file = path(port)
        .ok_or_else(|| io::Error::other("no runtime directory (set COREROUTER_RUNTIME_DIR)"))?;
    let dir = file
        .parent()
        .ok_or_else(|| io::Error::other("token path has no directory"))?;
    create_private_dir(dir)?;
    let tmp = file.with_extension("token.tmp");
    let _ = fs::remove_file(&tmp);
    {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(token.as_bytes())?;
        f.write_all(b"\n")?;
        f.sync_all()?;
    }
    fs::rename(&tmp, &file)?;
    Ok(file)
}

fn create_private_dir(dir: &std::path::Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
        // An existing directory others can enter would leak the token.
        let mode = fs::metadata(dir)?.permissions().mode();
        if mode & 0o077 != 0 {
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(dir)
    }
}

/// The token for `port`, if this user can read one.
pub fn read(port: u16) -> Option<String> {
    let file = path(port)?;
    let mut text = String::new();
    fs::File::open(file)
        .ok()?
        .take(MAX_FILE)
        .read_to_string(&mut text)
        .ok()?;
    let t = text.trim();
    (!t.is_empty() && t.bytes().all(|b| b.is_ascii_hexdigit())).then(|| t.to_owned())
}

/// Remove the file of `port` if it still holds `token` (a newer daemon on
/// the same port may have replaced it).
pub fn remove(port: u16, token: &str) {
    if read(port).as_deref() == Some(token)
        && let Some(f) = path(port)
    {
        let _ = fs::remove_file(f);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn written_private_read_back_and_removed() {
        // The environment cannot be changed here (`set_var` needs `unsafe`):
        // this uses the runtime directory of whoever runs the tests.
        let Some(base) = runtime_dir() else { return };
        assert!(path(7).unwrap().starts_with(base));
        let port = 40_000 + (std::process::id() % 20_000) as u16;
        let token = "ab".repeat(32);
        let file = create(port, &token).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&file).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
            let dmode = fs::metadata(file.parent().unwrap())
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(dmode & 0o077, 0);
        }
        assert_eq!(read(port).as_deref(), Some(token.as_str()));
        remove(port, "other");
        assert!(file.exists());
        remove(port, &token);
        assert!(!file.exists() && read(port).is_none());
    }
}
