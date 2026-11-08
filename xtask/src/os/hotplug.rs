//! G1.6n in `boot-test`: a card plugged into the running router gets the
//! next `etherN`, and the same one when it is plugged in again. QEMU's
//! monitor adds a virtio card behind a PCIe root port (what a hot-plug
//! PCIe slot or a card added to a running VM is), takes it out and puts it
//! back; the console line of `corerouter-init` says which name it got.
//!
//! G1.6j: the drivers built as modules load themselves. An `i82551` (e100)
//! is in the machine from the start, and a `pcnet` (pcnet32) is plugged in
//! later, so both of the init's paths run: the scan at boot and the kernel's
//! device messages. The `i82551` also proves the firmware path: its revision
//! (0x0f) makes e100 refuse to open the port without `e100/d102e_ucode.bin`
//! (the only QEMU card that reads a file from `/lib/firmware`; `web_check`
//! brings it up).

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

/// The root port the test plugs into, and the backend of the card.
pub(super) const QEMU_ARGS: [&str; 12] = [
    "-device",
    "pcie-root-port,id=hp0,bus=pcie.0,chassis=9,slot=9",
    "-netdev",
    "user,id=n1,restrict=on",
    "-device",
    "pcie-root-port,id=hp1,bus=pcie.0,chassis=10,slot=10",
    "-netdev",
    "user,id=n3,restrict=on",
    // After the virtio card in bus order (the kernel's `ip=` and ether1 stay
    // on that one): this one's driver is a module.
    "-netdev",
    "user,id=n2,restrict=on",
    "-device",
    "i82551,netdev=n2,mac=52:54:00:e1:00:01,bus=pcie.0,addr=0x10",
];

const MAC: &str = "52:54:00:c0:ff:ee";
const PCNET_MAC: &str = "52:54:00:9c:4e:01";

/// The console line of the driver that the card present at boot asks for.
pub(super) fn boot_driver(line: &str) -> bool {
    line.contains("corerouter-init") && line.contains("driver e100 loaded")
}

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
fn named(line: &str, name: &str, mac: &str) -> bool {
    line.contains("port names:") && line.contains(&format!("→{name} ({mac})"))
}

/// Plug, unplug, plug again. `wait_line` reads the console until a line
/// matches (or fails at its deadline).
pub(super) fn check(sock: &Path, wait_line: &mut WaitLine<'_>) -> Result<String, String> {
    let t = Instant::now();
    hmp(
        sock,
        &format!("device_add virtio-net-pci,bus=hp0,id=hot0,netdev=n1,mac={MAC}"),
    )?;
    wait_line(&|l| named(l, "ether3", MAC), Duration::from_secs(20))
        .map_err(|e| format!("card plugged in after boot: not named ether3: {e}"))?;
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
    wait_line(&|l| named(l, "ether3", MAC), Duration::from_secs(20))
        .map_err(|e| format!("card plugged in again: not named ether3 again: {e}"))?;
    let again = t2.elapsed();
    // A card whose driver nobody loaded yet.
    let t3 = Instant::now();
    hmp(
        sock,
        &format!("device_add pcnet,bus=hp1,id=hot2,netdev=n3,mac={PCNET_MAC}"),
    )?;
    wait_line(
        &|l| l.contains("driver pcnet32 loaded"),
        Duration::from_secs(20),
    )
    .map_err(|e| format!("card plugged in with no driver loaded: pcnet32 did not load: {e}"))?;
    wait_line(&|l| named(l, "ether4", PCNET_MAC), Duration::from_secs(20))
        .map_err(|e| format!("card whose driver just loaded: not named ether4: {e}"))?;
    Ok(format!(
        "new card → ether3 in {} ms; unplugged and plugged in again → ether3 in {} ms; \
         card with its driver in a module → loaded and ether4 in {} ms",
        first.as_millis(),
        again.as_millis(),
        t3.elapsed().as_millis()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn console_line() {
        let l = "corerouter-init: port names: ether1→ether1 (52:54:00:12:34:56), eth0→ether2 (52:54:00:c0:ff:ee)";
        assert!(named(l, "ether2", MAC));
        assert!(!named(l, "ether3", MAC));
        assert!(!named(l, "ether2", PCNET_MAC));
        assert!(!named("eth0→ether2 (52:54:00:c0:ff:ee)", "ether2", MAC));
        assert!(boot_driver("corerouter-init: driver e100 loaded in 3 ms"));
        assert!(!boot_driver(
            "corerouter-init: driver pcnet32 loaded in 3 ms"
        ));
        assert!(!boot_driver("driver e100 loaded"));
    }
}
