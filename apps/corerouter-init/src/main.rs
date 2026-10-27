//! `corerouter-init`: PID 1 of the CoreRouter image (G1.6a, `docs/os-image.md`).
//!
//! It does the few things a router appliance needs and nothing else:
//! mounts the API filesystems and the tmpfs dirs over the read-only
//! squashfs root, mounts `/config` (the writable partition), brings `lo` up,
//! starts `corerouter-daemon` and restarts it with backoff, reaps orphans,
//! reports when the control channel first answers (boot time, idle memory)
//! and shuts down cleanly on the signals busybox `reboot`/`poweroff`/`halt`
//! send. No shell unless the kernel command line asks for one on a terminal
//! (`corerouter.shell=ttyS0`).

#[cfg(target_os = "linux")]
mod ctl;
#[cfg(target_os = "linux")]
mod pid1;
mod plan;

#[cfg(target_os = "linux")]
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("run") {
        std::process::exit(ctl::main(args.get(1..).unwrap_or(&[])));
    }
    pid1::main();
}

#[cfg(not(target_os = "linux"))]
fn main() {
    use std::io::Write;
    let _ = writeln!(
        std::io::stderr(),
        "corerouter-init runs only as PID 1 of the Linux image"
    );
    std::process::exit(2);
}
