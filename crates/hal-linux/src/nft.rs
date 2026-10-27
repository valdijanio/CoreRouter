//! The `nft` program, for tests and benchmarks only (G2.8).
//!
//! The router never runs it: every table CoreRouter owns (the firewall,
//! the CGNAT, the fast path, the packet trace) goes to the kernel over
//! nfnetlink (`nfnl`, `firewall`) and is read back the same way
//! (`nft_read`), so the system image needs neither `nft` nor nftables
//! built with JSON. The tests load our text with `nft -f` to compare what
//! the kernel holds, and the benchmarks measure `nft` against netlink.

use std::io::{Read, Write as _};
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use corerouter_hal::HalError;

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
