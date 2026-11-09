//! G1.6za: the kernel modules of the ISO's kernel, a payload of their own
//! (`LIVEMODS.IMG`, in the signed index). After the build this checks what the
//! kernel's `same_magic` will check at load time (`kernel/module/version.c`),
//! so a mix-up stops the build, not a card on somebody's ISO.

use std::path::Path;

/// What makes the ISO's kernel another release than the image's:
/// `CONFIG_LOCALVERSION` in `installer.fragment`.
pub(super) const SUFFIX: &str = "-live";

/// The `vermagic=` value of a module's bytes (`.modinfo` is a list of
/// `key=value\0`).
fn vermagic(ko: &[u8]) -> Option<&str> {
    ko.split(|&b| b == 0)
        .find_map(|s| s.strip_prefix(b"vermagic="))
        .and_then(|v| std::str::from_utf8(v).ok())
}

/// A module of the release `release`? The magic is the release, a space and
/// the build's flags.
fn built_for(ko: &[u8], release: &str) -> bool {
    vermagic(ko).and_then(|m| m.split(' ').next()) == Some(release)
}

/// The staged tree of the payload: `<installer>/live-modules/lib/modules`.
/// Every module is of the ISO's kernel, the drivers the boot test uses are
/// there, the index is, and no link points back at the build machine.
/// Returns how many modules and their size.
pub(super) fn verify(
    installer: &Path,
    version: &str,
    required: &[&str],
) -> Result<(usize, u64), String> {
    let release = format!("{version}{SUFFIX}");
    let top = installer.join("live-modules/lib/modules").join(&release);
    let mut kos = Vec::new();
    super::firmware::ko_files(&top, &mut kos);
    if kos.is_empty() {
        return Err(format!("{}: no modules", top.display()));
    }
    let mut size = 0;
    for ko in &kos {
        let b = std::fs::read(ko).map_err(|e| format!("{}: {e}", ko.display()))?;
        size += b.len() as u64;
        if !built_for(&b, &release) {
            return Err(format!(
                "{}: vermagic {:?}, the ISO's kernel is {release}",
                ko.display(),
                vermagic(&b)
            ));
        }
    }
    for want in required {
        let file = format!("{want}.ko");
        if !kos
            .iter()
            .any(|k| k.file_name().is_some_and(|n| *n == *file))
        {
            return Err(format!(
                "{}: no {file} (the ISO's kernel built it in?)",
                top.display()
            ));
        }
    }
    for f in ["modules.dep", "modules.alias"] {
        if !top.join(f).is_file() {
            return Err(format!("{}: no {f}", top.display()));
        }
    }
    for l in ["build", "source"] {
        if top.join(l).symlink_metadata().is_ok() {
            return Err(format!(
                "{}: {l} points at the build machine",
                top.display()
            ));
        }
    }
    Ok((kos.len(), size))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_module_of_another_release_is_told_apart() {
        let ko =
            b"\x7fELF\0license=GPL\0vermagic=6.18.59-live SMP preempt mod_unload \0name=e100\0";
        assert!(built_for(ko, "6.18.59-live"));
        // The image's kernel: the same version, the magic differs.
        assert!(!built_for(ko, "6.18.59"));
        assert!(!built_for(b"no magic here", "6.18.59-live"));
        assert!(!built_for(b"vermagic=\xff\xfe\0", "6.18.59-live"));
        assert!(!built_for(b"", ""));
    }

    #[test]
    fn the_tree_is_checked() {
        let d = std::env::temp_dir().join(format!("cr-livemods-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let top = d.join("live-modules/lib/modules/6.18.59-live");
        std::fs::create_dir_all(top.join("kernel")).unwrap();
        assert!(verify(&d, "6.18.59", &["e100"]).is_err());
        let good = b"vermagic=6.18.59-live SMP \0".as_slice();
        std::fs::write(top.join("kernel/e100.ko"), good).unwrap();
        assert!(
            verify(&d, "6.18.59", &["e100"])
                .unwrap_err()
                .contains("modules.dep")
        );
        std::fs::write(top.join("modules.dep"), "").unwrap();
        std::fs::write(top.join("modules.alias"), "").unwrap();
        assert_eq!(verify(&d, "6.18.59", &["e100"]).unwrap().0, 1);
        assert!(
            verify(&d, "6.18.59", &["pcnet32"])
                .unwrap_err()
                .contains("pcnet32")
        );
        std::fs::write(top.join("build"), "").unwrap();
        assert!(
            verify(&d, "6.18.59", &["e100"])
                .unwrap_err()
                .contains("build")
        );
        std::fs::remove_file(top.join("build")).unwrap();
        // The installed kernel's module in the payload.
        std::fs::write(top.join("kernel/bad.ko"), b"vermagic=6.18.59 SMP \0").unwrap();
        assert!(
            verify(&d, "6.18.59", &["e100"])
                .unwrap_err()
                .contains("vermagic")
        );
        let _ = std::fs::remove_dir_all(&d);
    }
}
