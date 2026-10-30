//! G1.6n in `boot-test`: a card plugged into the running router gets the
//! next `etherN`, and the same one when it is plugged in again. QEMU's
//! monitor adds a virtio card behind a PCIe root port (what a hot-plug
//! PCIe slot or a card added to a running VM is), takes it out and puts it
//! back; the console line of `corerouter-init` says which name it got.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

/// The root port the test plugs into, and the backend of the card.
pub(super) const QEMU_ARGS: [&str; 4] = [
    "-device",
    "pcie-root-port,id=hp0,bus=pcie.0,chassis=9,slot=9",
    "-netdev",
    "user,id=n1,restrict=on",
];

const MAC: &str = "52:54:00:c0:ff:ee";

/// Reads the console until a line passes the test, at most the duration.
pub(super) type WaitLine<'a> =
    dyn FnMut(&dyn Fn(&str) -> bool, Duration) -> Result<(), String> + 'a;

/// One HMP command on the monitor socket; its output, up to the next
/// prompt.
fn hmp(sock: &Path, cmd: &str) -> Result<String, String> {
    let mut s = UnixStream::connect(sock).map_err(|e| format!("{}: {e}", sock.display()))?;
    s.set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;
    let until_prompt = |s: &mut UnixStream| -> Result<String, String> {
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        while !out.ends_with(b"(qemu) ") {
            let n = s.read(&mut buf).map_err(|e| format!("monitor: {e}"))?;
            if n == 0 {
                return Err("monitor closed".into());
            }
            out.extend_from_slice(buf.get(..n).unwrap_or_default());
            if out.len() > 1 << 20 {
                return Err("monitor: answer too long".into());
            }
        }
        Ok(String::from_utf8_lossy(&out).into_owned())
    };
    until_prompt(&mut s)?;
    s.write_all(format!("{cmd}\n").as_bytes())
        .map_err(|e| format!("monitor: {e}"))?;
    until_prompt(&mut s)
}

/// The console line PID 1 writes when it names the card.
fn named(line: &str, name: &str) -> bool {
    line.contains("port names:") && line.contains(&format!("→{name} ({MAC})"))
}

/// Plug, unplug, plug again. `wait_line` reads the console until a line
/// matches (or fails at its deadline).
pub(super) fn check(sock: &Path, wait_line: &mut WaitLine<'_>) -> Result<String, String> {
    let t = Instant::now();
    hmp(
        sock,
        &format!("device_add virtio-net-pci,bus=hp0,id=hot0,netdev=n1,mac={MAC}"),
    )?;
    wait_line(&|l| named(l, "ether2"), Duration::from_secs(20))
        .map_err(|e| format!("card plugged in after boot: not named ether2: {e}"))?;
    let first = t.elapsed();
    hmp(sock, "device_del hot0")?;
    // PCIe hot-unplug waits for the guest (the attention button: ~5 s).
    let gone = Instant::now();
    while hmp(sock, "info pci")?.contains("\"hot0\"") {
        if gone.elapsed() > Duration::from_secs(20) {
            return Err("the guest did not release the hot-plugged card in 20 s".into());
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    let t2 = Instant::now();
    hmp(
        sock,
        &format!("device_add virtio-net-pci,bus=hp0,id=hot1,netdev=n1,mac={MAC}"),
    )?;
    wait_line(&|l| named(l, "ether2"), Duration::from_secs(20))
        .map_err(|e| format!("card plugged in again: not named ether2 again: {e}"))?;
    Ok(format!(
        "new card → ether2 in {} ms; unplugged and plugged in again → ether2 in {} ms",
        first.as_millis(),
        t2.elapsed().as_millis()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn console_line() {
        let l = "corerouter-init: port names: ether1→ether1 (52:54:00:12:34:56), eth0→ether2 (52:54:00:c0:ff:ee)";
        assert!(named(l, "ether2"));
        assert!(!named(l, "ether3"));
        assert!(!named("eth0→ether2 (52:54:00:c0:ff:ee)", "ether2"));
    }
}
