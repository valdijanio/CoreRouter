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
//!
//! G1.6c: it also starts FRR's daemons when the image has them, applies
//! the installer's management address on the first boot, runs the console
//! setup when no port has an address (`setup`), and is the installer when
//! the installer ISO's kernel boots it (`corerouter.mode=install`).

#[cfg(target_os = "linux")]
mod console;
#[cfg(target_os = "linux")]
mod ctl;
#[cfg(target_os = "linux")]
mod install;
#[cfg(target_os = "linux")]
mod links;
#[cfg(target_os = "linux")]
mod pid1;
mod plan;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod ports;
#[cfg(target_os = "linux")]
mod setup;

#[cfg(target_os = "linux")]
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("run") => std::process::exit(ctl::main(args.get(1..).unwrap_or(&[]))),
        Some("setup") => std::process::exit(setup::main(args.get(1..).unwrap_or(&[]))),
        _ => {}
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
