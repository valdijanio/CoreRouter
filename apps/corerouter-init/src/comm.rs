//! G1.6zr: the name a helper process shows (`/proc/<pid>/comm`). PID 1 runs
//! its console setup and the live image's installer as `/proc/self/exe
//! <mode>`, and the kernel names such a process after the file it ran:
//! `exe`, which `system.resource.process.print` showed with no way to tell
//! what it was. Each mode names itself first thing, while it has one
//! thread (threads it starts later inherit the name).

use std::io::Write;

/// The name of a mode of `corerouter-init` (at most 15 bytes, the
/// kernel's `TASK_COMM_LEN` less the NUL), `None` for PID 1 itself.
pub fn of_mode(mode: &str) -> Option<&'static str> {
    match mode {
        "setup" => Some("cr-setup"),
        "install-here" => Some("cr-install"),
        "run" => Some("cr-ctl"),
        _ => None,
    }
}

/// Name the calling thread (the whole process while it has one thread).
/// No `unsafe` `prctl(PR_SET_NAME)`: the kernel's file does the same.
pub fn set(name: &str) -> std::io::Result<()> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .open("/proc/thread-self/comm")?;
    f.write_all(name.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_helper_mode_has_a_name_that_fits_the_kernels_comm() {
        for mode in ["setup", "install-here", "run"] {
            let name = of_mode(mode).unwrap();
            assert!(
                name.len() <= 15 && name.starts_with("cr-"),
                "{mode}: {name}"
            );
        }
        assert_eq!(of_mode("anything else"), None, "PID 1 keeps its name");
    }

    #[test]
    fn the_name_reaches_proc() {
        std::thread::spawn(|| {
            set("cr-setup").unwrap();
            let comm = std::fs::read_to_string("/proc/thread-self/comm").unwrap();
            assert_eq!(comm.trim_end(), "cr-setup");
        })
        .join()
        .unwrap();
    }
}
