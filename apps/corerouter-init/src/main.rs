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
//!
//! G1.6y: the ISO boots live (`corerouter.mode=live`, `live`): the image from
//! RAM, so the GUI and the browser can install it over the network.
//!
//! G1.6zn: the installed image too, when asked (`to_ram`), and a system disk
//! that goes away is one clear line (`disk_watch`).

#[cfg(target_os = "linux")]
mod comm;
#[cfg(target_os = "linux")]
mod console;
#[cfg(target_os = "linux")]
mod ctl;
#[cfg(target_os = "linux")]
mod disk_watch;
#[cfg(target_os = "linux")]
mod grow;
#[cfg(target_os = "linux")]
mod install;
#[cfg(target_os = "linux")]
mod links;
#[cfg(target_os = "linux")]
mod live;
#[cfg(target_os = "linux")]
mod modules;
#[cfg(target_os = "linux")]
mod pid1;
mod plan;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod ports;
#[cfg(target_os = "linux")]
mod setup;
mod setup_wifi;
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod style;
#[cfg(target_os = "linux")]
mod to_ram;
#[cfg(target_os = "linux")]
mod wifi_names;

#[cfg(target_os = "linux")]
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    // G1.6zq: not `exe` in the process list (PID 1 runs these through
    // `/proc/self/exe`).
    if let Some(name) = args.first().and_then(|m| comm::of_mode(m)) {
        let _ = comm::set(name);
    }
    match args.first().map(String::as_str) {
        Some("run") => std::process::exit(ctl::main(args.get(1..).unwrap_or(&[]))),
        Some("setup") => std::process::exit(setup::main(args.get(1..).unwrap_or(&[]))),
        // G1.6y: `i` on the live image's console.
        Some("install-here") => {
            let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
            install::run(&plan::BootOptions::parse(&cmdline), cmdline.trim())
        }
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
