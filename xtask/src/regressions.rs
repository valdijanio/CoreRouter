//! G0.30: the saved proptest failures keep running. Proptest replays every
//! seed of `proptest-regressions/<path>.txt` before its new cases, with any
//! `PROPTEST_CASES` (the quick layer's 32 included), but it finds the file
//! from the test's source path: the crate's `src/foo/bar.rs` reads
//! `proptest-regressions/foo/bar.txt`, `tests/it/x.rs` reads
//! `tests/proptest-regressions/x.txt`. A test file moved or renamed
//! (`tests/it`, G0.29) leaves its seeds behind and they silently stop
//! running; this finds those orphans.

use std::path::{Path, PathBuf};

/// Every `proptest-regressions/**/*.txt` under `crates/*` and `apps/*` that
/// no source file maps to, relative to `root`.
pub fn orphans(root: &Path) -> Vec<String> {
    let mut files = Vec::new();
    for top in ["crates", "apps"] {
        let Ok(dirs) = std::fs::read_dir(root.join(top)) else {
            continue;
        };
        for dir in dirs.flatten() {
            find_regressions(&dir.path(), 0, &mut files);
        }
    }
    files.sort();
    files
        .into_iter()
        .filter(|f| !has_source(f))
        .map(|f| f.strip_prefix(root).unwrap_or(&f).display().to_string())
        .collect()
}

/// The `.txt` files inside `proptest-regressions` directories below `dir`
/// (not into `target*`, a few levels deep).
fn find_regressions(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if !p.is_dir() {
            continue;
        }
        let name = e.file_name();
        let name = name.to_string_lossy();
        if name == "proptest-regressions" {
            collect_txt(&p, out);
        } else if depth < 3 && !name.starts_with("target") && !name.starts_with('.') {
            find_regressions(&p, depth + 1, out);
        }
    }
}

fn collect_txt(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            collect_txt(&p, out);
        } else if p.extension().is_some_and(|x| x == "txt") {
            out.push(p);
        }
    }
}

/// Is there a source `<base>/<root>/<rel>.rs` for `<base>/proptest-regressions/<rel>.txt`,
/// `<root>` being a directory with `lib.rs` or `main.rs` (proptest's rule)?
fn has_source(file: &Path) -> bool {
    let Some(regdir) = file
        .ancestors()
        .find(|a| a.file_name().is_some_and(|n| n == "proptest-regressions"))
    else {
        return false;
    };
    let (Some(base), Ok(rel)) = (regdir.parent(), file.strip_prefix(regdir)) else {
        return false;
    };
    let rel = rel.with_extension("rs");
    let Ok(roots) = std::fs::read_dir(base) else {
        return false;
    };
    roots.flatten().map(|e| e.path()).any(|src| {
        (src.join("lib.rs").is_file() || src.join("main.rs").is_file())
            && std::fs::read_to_string(src.join(&rel)).is_ok_and(|t| t.contains("proptest"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_repository_has_no_orphan() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        assert_eq!(orphans(&root), Vec::<String>::new());
    }

    #[test]
    fn a_moved_test_leaves_its_seeds_orphaned() {
        let tmp = std::env::temp_dir().join(format!("cr-regressions-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let krate = tmp.join("crates/x");
        for d in [
            "src/a",
            "tests/it",
            "proptest-regressions/a",
            "tests/proptest-regressions",
        ] {
            std::fs::create_dir_all(krate.join(d)).unwrap();
        }
        std::fs::write(krate.join("src/lib.rs"), "").unwrap();
        std::fs::write(krate.join("src/a/b.rs"), "proptest! {}").unwrap();
        std::fs::write(krate.join("tests/it/main.rs"), "mod p;").unwrap();
        std::fs::write(krate.join("tests/it/p.rs"), "use proptest::prelude::*;").unwrap();
        for f in [
            "proptest-regressions/a/b.txt",
            "proptest-regressions/gone.txt",
            "tests/proptest-regressions/p.txt",
            "tests/proptest-regressions/moved.txt",
        ] {
            std::fs::write(krate.join(f), "cc 00").unwrap();
        }
        assert_eq!(
            orphans(&tmp),
            vec![
                "crates/x/proptest-regressions/gone.txt".to_owned(),
                "crates/x/tests/proptest-regressions/moved.txt".to_owned(),
            ]
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
