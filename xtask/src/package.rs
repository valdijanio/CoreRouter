//! `cargo xtask package gui` (G0.28): the manager as a `.deb`, installed
//! once and opened from the menu like WinBox. One package, `corerouter-gui`,
//! with the GUI and the CLI in `/usr/bin`, the `.desktop` entry (also the
//! handler of `corerouter://` links) and the icon in every hicolor size.
//!
//! The `.deb` is written here (ar + ustar + gzip, `flate2` in Rust) instead
//! of with `cargo-deb` or `dpkg-deb --build`: no tool to install, files owned
//! by root without `fakeroot`, and the same bytes for the same commit (every
//! mtime is the commit's time). `dpkg-deb`, when present, only checks the
//! result. Decision and numbers in `docs/architecture.md` ("Pacotes da GUI").

mod icon;

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use md5::Digest as _;

use crate::Outcome;

const USAGE: &str = "\
usage: cargo xtask package gui [--out <dir>] [--no-build] [--version <v>]
       cargo xtask package notes [--since <git ref>]

  gui: builds corerouter-gui and corerouter-cli (profile `dist`: release
  without symbols) and writes corerouter-gui_<version>_<arch>.deb.
  --out <dir>      where the .deb goes (default <target>/package)
  --no-build       package the binaries already in <target>/dist
  --version <v>    a release (the tag without the `v`: 0.2.0, 0.2.0-rc.1);
                   must be the workspace version, plus an optional
                   pre-release. Default: <workspace>+<commits>.g<commit>
  notes: the release notes, from the docs/log.md entries the log at
  <since> (the previous tag) does not have; all of them without --since.";

/// GitHub refuses a release body above 125 000 characters; the notes stop
/// before that and point at the full log.
const NOTES_MAX: usize = 100_000;
/// One entry of the notes: its first characters (the log entry has the
/// details).
const NOTE_ENTRY_MAX: usize = 300;

const NAME: &str = "corerouter-gui";
const BINARIES: &[&str] = &["corerouter-gui", "corerouter-cli"];

/// Shared libraries the binaries are linked against (`ldd`) and the Debian
/// package of each. A new one fails the packaging until it is added here.
const NEEDED: &[(&str, &str)] = &[
    ("libc.so.6", "libc6"),
    ("libm.so.6", "libc6"),
    ("libdl.so.2", "libc6"),
    ("libpthread.so.0", "libc6"),
    ("librt.so.1", "libc6"),
    ("ld-linux-x86-64.so.2", "libc6"),
    ("ld-linux-aarch64.so.1", "libc6"),
    ("linux-vdso.so.1", ""),
    ("libgcc_s.so.1", "libgcc-s1"),
];

/// What winit and wgpu load at run time with `dlopen` (not in `ldd`): the
/// keyboard map, a display server (Wayland or X11) and a GPU API (Vulkan,
/// else OpenGL through EGL). The window cannot open without one of each.
const RUNTIME_DEPENDS: &[&str] = &[
    "libxkbcommon0",
    "libwayland-client0 | libx11-6",
    "libvulkan1 | libegl1",
];

/// The rest of what they open (names found in the binary): the other GPU
/// API and its drivers, EGL on Wayland, and the X11 extras (cursor, input).
const RECOMMENDS: &[&str] = &[
    "libvulkan1",
    "mesa-vulkan-drivers | vulkan-icd",
    "libegl1",
    "libwayland-egl1",
    "libx11-6",
    "libx11-xcb1",
    "libxcursor1",
    "libxi6",
    "libxkbcommon-x11-0",
];

/// Remembered passwords go to the Secret Service (D-Bus).
const SUGGESTS: &[&str] = &["gnome-keyring | kwalletmanager | keepassxc"];

const DESKTOP: &str = "\
[Desktop Entry]
Type=Application
Name=CoreRouter
GenericName=Router Manager
GenericName[pt_BR]=Gerenciador de roteadores
Comment=Manage CoreRouter routers, local or remote over TLS
Comment[pt_BR]=Gerencie roteadores CoreRouter, locais ou remotos por TLS
Exec=corerouter-gui %u
Icon=corerouter-gui
Terminal=false
Categories=Network;RemoteAccess;
Keywords=router;network;firewall;bgp;ospf;roteador;rede;
MimeType=x-scheme-handler/corerouter;
StartupNotify=true
StartupWMClass=corerouter-gui
";

const DESCRIPTION: &str = "\
Description: CoreRouter manager (GUI and CLI)
 Graphical manager for CoreRouter routers, like WinBox: the connect screen
 lists the routers heard on the network (CRDP) and the saved ones, logs in
 to local routers with the local token and to remote ones over TLS (the
 certificate confirmed on first use), and keeps passwords in the system
 keyring. corerouter:// links open it already connecting.
 .
 Also ships corerouter-cli, the command-line client (commands, terminal,
 MCP server for AI agents).";

/// One file of the package.
struct Entry {
    /// Path inside the package, without the leading `/`.
    path: String,
    data: Vec<u8>,
    mode: u32,
}

/// A `.deb` to write.
struct Deb {
    control: String,
    files: Vec<Entry>,
    /// mtime of every member (the commit's time: same input, same bytes).
    mtime: u64,
}

pub fn main(root: &Path, args: &[String]) -> Outcome {
    let mut args = args.iter();
    match args.next().map(String::as_str) {
        Some("gui") => {}
        Some("notes") => return notes_main(root, args),
        _ => return Outcome::Fail(USAGE.into()),
    }
    let mut out_dir = None;
    let mut build = true;
    let mut release = None;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--out" => match args.next() {
                Some(d) => out_dir = Some(PathBuf::from(d)),
                None => return Outcome::Fail(USAGE.into()),
            },
            "--no-build" => build = false,
            "--version" => match args.next() {
                Some(v) => match release_version(v, env!("CARGO_PKG_VERSION")) {
                    Ok(v) => release = Some(v),
                    Err(e) => return Outcome::Fail(e),
                },
                None => return Outcome::Fail(USAGE.into()),
            },
            _ => return Outcome::Fail(format!("unknown argument '{a}'\n{USAGE}")),
        }
    }
    match package_gui(root, out_dir, build, release) {
        Ok(path) => {
            eprintln!(
                "\nwrote {}\ninstall: sudo apt install {}",
                path.display(),
                path.display()
            );
            Outcome::Ok
        }
        Err(e) => Outcome::Fail(e),
    }
}

fn package_gui(
    root: &Path,
    out_dir: Option<PathBuf>,
    build: bool,
    release: Option<String>,
) -> Result<PathBuf, String> {
    let target = crate::bng_lab::target_dir(root);
    if build {
        let mut cmd = crate::cargo();
        cmd.args(["build", "--profile", "dist"]);
        for b in BINARIES {
            cmd.args(["-p", b]);
        }
        match crate::run(cmd, root) {
            Outcome::Ok => {}
            Outcome::Fail(why) | Outcome::Skip(why) => {
                return Err(format!("cargo build --profile dist: {why}"));
            }
        }
    }
    let arch = deb_arch(std::env::consts::ARCH)?;
    let bins: Vec<(String, Vec<u8>)> = BINARIES
        .iter()
        .map(|b| {
            let p = target.join("dist").join(b);
            std::fs::read(&p)
                .map(|d| ((*b).to_owned(), d))
                .map_err(|e| format!("{}: {e} (build with --profile dist)", p.display()))
        })
        .collect::<Result<_, _>>()?;
    let mut depends = linked_packages(&target)?;
    if let Some(glibc) = bins.iter().filter_map(|(_, d)| max_glibc(d)).max() {
        let v = format!("libc6 (>= {}.{})", glibc.0, glibc.1);
        depends.retain(|d| d != "libc6");
        depends.insert(0, v);
    }
    depends.extend(RUNTIME_DEPENDS.iter().map(|s| (*s).to_owned()));

    let version = match release {
        Some(v) => v,
        None => version(root)?,
    };
    let mtime = commit_time(root);
    let mut files: Vec<Entry> = bins
        .into_iter()
        .map(|(name, data)| Entry {
            path: format!("usr/bin/{name}"),
            data,
            mode: 0o755,
        })
        .collect();
    files.push(Entry {
        path: format!("usr/share/applications/{NAME}.desktop"),
        data: DESKTOP.as_bytes().to_vec(),
        mode: 0o644,
    });
    for &size in icon::SIZES {
        files.push(Entry {
            path: format!("usr/share/icons/hicolor/{size}x{size}/apps/{NAME}.png"),
            data: icon::png(size)?,
            mode: 0o644,
        });
    }
    files.push(Entry {
        path: format!("usr/share/icons/hicolor/scalable/apps/{NAME}.svg"),
        data: icon::svg().into_bytes(),
        mode: 0o644,
    });
    files.push(Entry {
        path: format!("usr/share/doc/{NAME}/copyright"),
        data: copyright().into_bytes(),
        mode: 0o644,
    });
    files.push(Entry {
        path: format!("usr/share/doc/{NAME}/changelog.gz"),
        data: gzip(changelog(&version, mtime).as_bytes())?,
        mode: 0o644,
    });
    let installed_kib: u64 = files
        .iter()
        .map(|f| (f.data.len() as u64).div_ceil(1024))
        .sum();
    let control = format!(
        "Package: {NAME}\nVersion: {version}\nArchitecture: {arch}\n\
         Maintainer: CoreRouter <corerouter@users.noreply.github.com>\n\
         Installed-Size: {installed_kib}\nDepends: {}\nRecommends: {}\nSuggests: {}\n\
         Section: net\nPriority: optional\nHomepage: {}\n{DESCRIPTION}\n",
        depends.join(", "),
        RECOMMENDS.join(", "),
        SUGGESTS.join(", "),
        env!("CARGO_PKG_REPOSITORY"),
    );
    let deb = Deb {
        control,
        files,
        mtime,
    };
    let out_dir = out_dir.unwrap_or_else(|| target.join("package"));
    std::fs::create_dir_all(&out_dir).map_err(|e| format!("{}: {e}", out_dir.display()))?;
    let path = out_dir.join(format!("{NAME}_{version}_{arch}.deb"));
    std::fs::write(&path, deb.bytes()?).map_err(|e| format!("{}: {e}", path.display()))?;
    check_with_dpkg(&path)?;
    Ok(path)
}

/// Debian's name of the architecture the binaries were built for.
fn deb_arch(rust: &str) -> Result<&'static str, String> {
    Ok(match rust {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "arm" => "armhf",
        "riscv64" => "riscv64",
        other => return Err(format!("no Debian architecture known for '{other}'")),
    })
}

/// `0.1.0+1234.gabc1234`: the workspace version, then the number of commits
/// (grows on the main, so an upgrade sorts after) and the commit itself.
fn version(root: &Path) -> Result<String, String> {
    let count = git(root, &["rev-list", "--count", "HEAD"])?;
    let commit = git(root, &["rev-parse", "--short=7", "HEAD"])?;
    let v = format!("{}+{count}.g{commit}", env!("CARGO_PKG_VERSION"));
    if !v
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '~'))
    {
        return Err(format!("bad package version '{v}'"));
    }
    Ok(v)
}

/// The Debian version of a release: the tag without the `v` (`0.2.0`), a
/// pre-release after `-` becoming `~` (`0.2.0-rc.1` → `0.2.0~rc.1`, which
/// sorts before `0.2.0`). The base must be the workspace version, so the
/// package and the binaries (`server.info`, the GUI's bar) say the same.
fn release_version(tag: &str, workspace: &str) -> Result<String, String> {
    let shown: String = tag.chars().take(40).collect();
    let v = tag.strip_prefix('v').unwrap_or(tag);
    let (base, pre) = match v.split_once('-') {
        Some((b, p)) => (b, Some(p)),
        None => (v, None),
    };
    if base != workspace {
        return Err(format!(
            "release version '{shown}' is not the workspace version {workspace}: \
             bump [workspace.package] version in Cargo.toml first (or tag v{workspace})"
        ));
    }
    match pre {
        None => Ok(base.to_owned()),
        Some(p)
            if !p.is_empty()
                && p.len() <= 30
                && p.chars().all(|c| c.is_ascii_alphanumeric() || c == '.') =>
        {
            Ok(format!("{base}~{p}"))
        }
        Some(_) => Err(format!(
            "bad pre-release in '{shown}': letters, digits and dots after the '-' (0.2.0-rc.1)"
        )),
    }
}

fn notes_main(root: &Path, mut args: std::slice::Iter<'_, String>) -> Outcome {
    let mut since = None;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--since" => match args.next() {
                Some(r) if !r.is_empty() => since = Some(r.clone()),
                Some(_) => {}
                None => return Outcome::Fail(USAGE.into()),
            },
            _ => return Outcome::Fail(format!("unknown argument '{a}'\n{USAGE}")),
        }
    }
    let new = match std::fs::read_to_string(root.join("docs/log.md")) {
        Ok(t) => t,
        Err(e) => return Outcome::Fail(format!("docs/log.md: {e}")),
    };
    let old = match &since {
        Some(r) => match git(root, &["show", &format!("{r}:docs/log.md")]) {
            Ok(t) => t,
            Err(e) => return Outcome::Fail(e),
        },
        None => String::new(),
    };
    print!("{}", release_notes(&old, &new));
    Outcome::Ok
}

/// The entries of `docs/log.md` (`- AAAA-MM-DD — id: …` plus its indented
/// continuation lines), each joined into one line without the `- `.
fn log_entries(log: &str) -> Vec<String> {
    let mut entries: Vec<String> = Vec::new();
    let mut open = false;
    for line in log.lines() {
        if let Some(rest) = line.strip_prefix("- ") {
            entries.push(rest.trim().to_owned());
            open = true;
        } else if line.trim().is_empty() || !line.starts_with(char::is_whitespace) {
            open = false;
        } else if open && let Some(last) = entries.last_mut() {
            last.push(' ');
            last.push_str(line.trim());
        }
    }
    entries
}

/// One bullet per entry of `new` that `old` does not have, in the log's
/// order, each cut at [`NOTE_ENTRY_MAX`] characters and the whole at
/// [`NOTES_MAX`].
fn release_notes(old: &str, new: &str) -> String {
    let seen: std::collections::HashSet<String> = log_entries(old).into_iter().collect();
    let fresh: Vec<String> = log_entries(new)
        .into_iter()
        .filter(|e| !seen.contains(e))
        .collect();
    if fresh.is_empty() {
        return "Nenhuma entrada nova em docs/log.md.\n".into();
    }
    let mut out = String::new();
    for (i, e) in fresh.iter().enumerate() {
        let line = match e.char_indices().nth(NOTE_ENTRY_MAX) {
            Some((cut, _)) => format!("- {}…\n", e[..cut].trim_end()),
            None => format!("- {e}\n"),
        };
        if out.len() + line.len() > NOTES_MAX {
            out.push_str(&format!(
                "- … e mais {} entradas (docs/log.md)\n",
                fresh.len() - i
            ));
            break;
        }
        out.push_str(&line);
    }
    out
}

fn commit_time(root: &Path) -> u64 {
    std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .or_else(|| git(root, &["log", "-1", "--format=%ct"]).ok())
        .and_then(|t| t.parse().ok())
        .unwrap_or(0)
}

fn git(root: &Path, args: &[&str]) -> Result<String, String> {
    let out = Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .map_err(|e| format!("git: {e}"))?;
    if !out.status.success() {
        return Err(format!("git {}: {}", args.join(" "), out.status));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

/// The packages behind each library `ldd` lists for the binaries.
fn linked_packages(target: &Path) -> Result<Vec<String>, String> {
    let mut packages: Vec<String> = Vec::new();
    for b in BINARIES {
        let p = target.join("dist").join(b);
        let out = Command::new("ldd")
            .arg(&p)
            .output()
            .map_err(|e| format!("ldd (checks the libraries): {e}"))?;
        for lib in ldd_libraries(&String::from_utf8_lossy(&out.stdout)) {
            let pkg = NEEDED
                .iter()
                .find(|(l, _)| *l == lib)
                .map(|(_, p)| *p)
                .ok_or_else(|| {
                    format!(
                        "{b} links {lib}, which has no package in xtask/src/package.rs \
                         NEEDED: add it (and to Depends)"
                    )
                })?;
            if !pkg.is_empty() && !packages.iter().any(|p| p == pkg) {
                packages.push(pkg.to_owned());
            }
        }
    }
    Ok(packages)
}

/// Library names in `ldd` output (`\tlibm.so.6 => /lib/…`, `\t/lib64/ld-…`).
fn ldd_libraries(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|l| l.split_whitespace().next())
        .filter(|w| w.contains(".so"))
        .map(|w| w.rsplit('/').next().unwrap_or(w).to_owned())
        .collect()
}

/// Newest `GLIBC_x.y` symbol version the binary asks for.
fn max_glibc(bin: &[u8]) -> Option<(u32, u32)> {
    const TAG: &[u8] = b"GLIBC_";
    let mut best = None;
    let mut i = 0;
    while let Some(pos) = bin
        .get(i..)
        .and_then(|rest| rest.windows(TAG.len()).position(|w| w == TAG))
    {
        let start = i + pos + TAG.len();
        let digits: Vec<u8> = bin
            .get(start..)
            .unwrap_or_default()
            .iter()
            .take(12)
            .take_while(|b| b.is_ascii_digit() || **b == b'.')
            .copied()
            .collect();
        let text = String::from_utf8_lossy(&digits);
        let mut parts = text.split('.').map(|p| p.parse::<u32>().ok());
        if let (Some(Some(major)), Some(Some(minor))) = (parts.next(), parts.next()) {
            best = best.max(Some((major, minor)));
        }
        i = start;
    }
    best
}

fn copyright() -> String {
    format!(
        "Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\n\
         Upstream-Name: CoreRouter\nSource: {}\n\n\
         Files: *\nCopyright: CoreRouter contributors\nLicense: {}\n \
         On Debian systems the full text of the GNU Affero General Public License\n \
         is not in /usr/share/common-licenses; see <https://www.gnu.org/licenses/agpl-3.0.html>.\n",
        env!("CARGO_PKG_REPOSITORY"),
        env!("CARGO_PKG_LICENSE"),
    )
}

fn changelog(version: &str, mtime: u64) -> String {
    format!(
        "{NAME} ({version}) unstable; urgency=medium\n\n  * Built from git by \
         `cargo xtask package gui`.\n\n -- CoreRouter <corerouter@users.noreply.github.com>  \
         {}\n",
        rfc2822(mtime)
    )
}

/// `Thu, 01 Jan 1970 00:00:00 +0000` for a Unix time (UTC).
fn rfc2822(t: u64) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let days = t / 86_400;
    let secs = t % 86_400;
    // Civil date from days since 1970-01-01 (H. Hinnant's algorithm).
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{}, {d:02} {} {y} {:02}:{:02}:{:02} +0000",
        DAYS.get((days % 7) as usize).unwrap_or(&"Thu"),
        MONTHS.get((m - 1) as usize).unwrap_or(&"Jan"),
        secs / 3600,
        secs % 3600 / 60,
        secs % 60
    )
}

impl Deb {
    fn bytes(&self) -> Result<Vec<u8>, String> {
        let md5sums: String = self
            .files
            .iter()
            .map(|f| {
                let hex: String = md5::Md5::digest(&f.data)
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                format!("{hex}  {}\n", f.path)
            })
            .collect();
        let mut control = Tar::default();
        control.file("control", self.control.as_bytes(), 0o644, self.mtime)?;
        control.file("md5sums", md5sums.as_bytes(), 0o644, self.mtime)?;
        let mut data = Tar::default();
        // `./` first, as dpkg-deb writes it.
        data.dir("", self.mtime)?;
        let mut dirs: Vec<String> = Vec::new();
        for f in &self.files {
            // Every parent directory first, once, in order.
            let parts: Vec<&str> = f.path.split('/').collect();
            let mut parent = String::new();
            for part in parts.iter().take(parts.len().saturating_sub(1)) {
                parent.push_str(part);
                parent.push('/');
                if !dirs.contains(&parent) {
                    data.dir(&parent, self.mtime)?;
                    dirs.push(parent.clone());
                }
            }
            data.file(&f.path, &f.data, f.mode, self.mtime)?;
        }
        let mut ar = b"!<arch>\n".to_vec();
        ar_member(&mut ar, "debian-binary", b"2.0\n", self.mtime)?;
        ar_member(
            &mut ar,
            "control.tar.gz",
            &gzip(&control.finish())?,
            self.mtime,
        )?;
        ar_member(&mut ar, "data.tar.gz", &gzip(&data.finish())?, self.mtime)?;
        Ok(ar)
    }
}

/// One member of an `ar` archive (the common format dpkg reads).
fn ar_member(out: &mut Vec<u8>, name: &str, data: &[u8], mtime: u64) -> Result<(), String> {
    let header = format!(
        "{name:<16}{mtime:<12}{:<6}{:<6}{:<8}{:<10}`\n",
        0,
        0,
        "100644",
        data.len()
    );
    if header.len() != 60 {
        return Err(format!("ar header for '{name}' is {} bytes", header.len()));
    }
    out.extend_from_slice(header.as_bytes());
    out.extend_from_slice(data);
    if data.len() % 2 == 1 {
        out.push(b'\n');
    }
    Ok(())
}

fn gzip(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut enc = flate2::GzBuilder::new()
        .mtime(0)
        .write(Vec::new(), flate2::Compression::best());
    enc.write_all(data).map_err(|e| format!("gzip: {e}"))?;
    enc.finish().map_err(|e| format!("gzip: {e}"))
}

/// A ustar archive, every entry owned by root.
#[derive(Default)]
struct Tar(Vec<u8>);

impl Tar {
    fn dir(&mut self, path: &str, mtime: u64) -> Result<(), String> {
        self.entry(path, &[], 0o755, b'5', mtime)
    }

    fn file(&mut self, path: &str, data: &[u8], mode: u32, mtime: u64) -> Result<(), String> {
        self.entry(path, data, mode, b'0', mtime)
    }

    fn entry(
        &mut self,
        path: &str,
        data: &[u8],
        mode: u32,
        kind: u8,
        mtime: u64,
    ) -> Result<(), String> {
        let name = format!("./{path}");
        if name.len() > 100 {
            return Err(format!("tar: path longer than 100 bytes: {name}"));
        }
        let mut h = [0u8; 512];
        let put = |h: &mut [u8; 512], at: usize, bytes: &[u8]| {
            if let Some(dst) = h.get_mut(at..at + bytes.len()) {
                dst.copy_from_slice(bytes);
            }
        };
        put(&mut h, 0, name.as_bytes());
        put(&mut h, 100, format!("{mode:07o}\0").as_bytes());
        put(&mut h, 108, b"0000000\0");
        put(&mut h, 116, b"0000000\0");
        put(&mut h, 124, format!("{:011o}\0", data.len()).as_bytes());
        put(&mut h, 136, format!("{mtime:011o}\0").as_bytes());
        put(&mut h, 148, b"        ");
        put(&mut h, 156, &[kind]);
        put(&mut h, 257, b"ustar\0");
        put(&mut h, 263, b"00");
        put(&mut h, 265, b"root");
        put(&mut h, 297, b"root");
        let sum: u32 = h.iter().map(|&b| u32::from(b)).sum();
        put(&mut h, 148, format!("{sum:06o}\0 ").as_bytes());
        self.0.extend_from_slice(&h);
        self.0.extend_from_slice(data);
        let pad = (512 - data.len() % 512) % 512;
        self.0.extend(std::iter::repeat_n(0u8, pad));
        Ok(())
    }

    fn finish(mut self) -> Vec<u8> {
        self.0.extend([0u8; 1024]);
        self.0
    }
}

/// `dpkg-deb --info` and `--contents` read the package back, when dpkg is
/// installed (skipped elsewhere: the archive is checked by the unit tests).
fn check_with_dpkg(path: &Path) -> Result<(), String> {
    for flag in ["--info", "--contents"] {
        match Command::new("dpkg-deb").arg(flag).arg(path).output() {
            Ok(o) if o.status.success() => {
                if flag == "--contents" {
                    eprint!("{}", String::from_utf8_lossy(&o.stdout));
                }
            }
            Ok(o) => {
                return Err(format!(
                    "dpkg-deb {flag} refused the package: {}",
                    String::from_utf8_lossy(&o.stderr).trim()
                ));
            }
            Err(_) => {
                eprintln!("skip: no dpkg-deb to read the package back");
                return Ok(());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Deb {
        Deb {
            control: "Package: corerouter-gui\nVersion: 0.1.0+1.gabc1234\nArchitecture: amd64\n\
                      Maintainer: CoreRouter <corerouter@users.noreply.github.com>\n\
                      Description: test\n test package\n"
                .into(),
            files: vec![
                Entry {
                    path: "usr/bin/corerouter-gui".into(),
                    data: b"#!/bin/sh\necho gui\n".to_vec(),
                    mode: 0o755,
                },
                Entry {
                    path: format!("usr/share/applications/{NAME}.desktop"),
                    data: DESKTOP.as_bytes().to_vec(),
                    mode: 0o644,
                },
            ],
            mtime: 1_761_609_600,
        }
    }

    #[test]
    fn deb_is_an_ar_with_the_three_members_and_reproducible() {
        let bytes = sample().bytes().unwrap();
        assert!(bytes.starts_with(b"!<arch>\ndebian-binary   "));
        // 8-byte magic + 60-byte header, then the member.
        assert_eq!(&bytes[66..68], b"`\n");
        assert_eq!(&bytes[68..72], b"2.0\n");
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("control.tar.gz") && text.contains("data.tar.gz"));
        assert_eq!(bytes, sample().bytes().unwrap(), "same input, same bytes");
    }

    #[test]
    fn dpkg_reads_the_package_and_installs_it_into_a_scratch_root() {
        let dir = std::env::temp_dir().join(format!("xtask-deb-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let deb = dir.join("t.deb");
        std::fs::write(&deb, sample().bytes().unwrap()).unwrap();
        if Command::new("dpkg-deb").arg("--version").output().is_err() {
            eprintln!("skip: no dpkg-deb");
            return;
        }
        let out = Command::new("dpkg-deb")
            .arg("--contents")
            .arg(&deb)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let listing = String::from_utf8_lossy(&out.stdout);
        assert!(listing.contains("-rwxr-xr-x root/root"), "{listing}");
        assert!(listing.contains("./usr/share/applications/corerouter-gui.desktop"));
        let field = Command::new("dpkg-deb")
            .args(["--field"])
            .arg(&deb)
            .arg("Version")
            .output()
            .unwrap();
        assert_eq!(
            String::from_utf8_lossy(&field.stdout).trim(),
            "0.1.0+1.gabc1234"
        );
        // Install and remove under a scratch root, without root (G0.28).
        let inst = dir.join("root");
        let admin = inst.join("var/lib/dpkg");
        std::fs::create_dir_all(admin.join("info")).unwrap();
        std::fs::create_dir_all(admin.join("updates")).unwrap();
        std::fs::write(admin.join("status"), "").unwrap();
        let dpkg = |args: &[&str]| {
            Command::new("dpkg")
                .arg("--force-not-root")
                .arg("--force-bad-path")
                .arg(format!("--root={}", inst.display()))
                .arg(format!("--admindir={}", admin.display()))
                .arg("--log=/dev/null")
                .args(args)
                .output()
                .unwrap()
        };
        let i = dpkg(&["--install", deb.to_str().unwrap()]);
        assert!(i.status.success(), "{}", String::from_utf8_lossy(&i.stderr));
        assert!(inst.join("usr/bin/corerouter-gui").exists());
        let r = dpkg(&["--purge", NAME]);
        assert!(r.status.success(), "{}", String::from_utf8_lossy(&r.stderr));
        assert!(!inst.join("usr/bin/corerouter-gui").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn desktop_entry_handles_corerouter_links() {
        assert!(DESKTOP.contains("Exec=corerouter-gui %u\n"));
        assert!(DESKTOP.contains("MimeType=x-scheme-handler/corerouter;\n"));
        // StartupWMClass and the icon match the GUI's app id (native.rs).
        assert!(DESKTOP.contains("StartupWMClass=corerouter-gui\n"));
        if Command::new("desktop-file-validate")
            .arg("--help")
            .output()
            .is_err()
        {
            eprintln!("skip: no desktop-file-validate");
            return;
        }
        let path =
            std::env::temp_dir().join(format!("corerouter-gui-{}.desktop", std::process::id()));
        std::fs::write(&path, DESKTOP).unwrap();
        let v = Command::new("desktop-file-validate")
            .arg(&path)
            .output()
            .unwrap();
        let _ = std::fs::remove_file(&path);
        assert!(v.status.success(), "{}", String::from_utf8_lossy(&v.stdout));
    }

    #[test]
    fn helpers() {
        assert_eq!(
            ldd_libraries(
                "\tlinux-vdso.so.1 (0x1)\n\tlibm.so.6 => /lib/x86_64-linux-gnu/libm.so.6 (0x2)\n\
                 \t/lib64/ld-linux-x86-64.so.2 (0x3)\n"
            ),
            ["linux-vdso.so.1", "libm.so.6", "ld-linux-x86-64.so.2"]
        );
        assert_eq!(
            max_glibc(b"x GLIBC_2.17\0GLIBC_2.34\0GLIBC_2.3.4\0"),
            Some((2, 34))
        );
        assert_eq!(max_glibc(b"none"), None);
        assert_eq!(rfc2822(0), "Thu, 01 Jan 1970 00:00:00 +0000");
        assert_eq!(rfc2822(1_761_609_600), "Tue, 28 Oct 2025 00:00:00 +0000");
        assert_eq!(deb_arch("x86_64").unwrap(), "amd64");
        assert!(deb_arch("mips").is_err());
    }

    #[test]
    fn release_version_is_the_tag_on_the_workspace_version() {
        assert_eq!(release_version("v0.2.0", "0.2.0").unwrap(), "0.2.0");
        assert_eq!(release_version("0.2.0", "0.2.0").unwrap(), "0.2.0");
        assert_eq!(
            release_version("v0.2.0-rc.1", "0.2.0").unwrap(),
            "0.2.0~rc.1"
        );
        let e = release_version("v0.3.0", "0.2.0").unwrap_err();
        assert!(e.contains("bump"), "{e}");
        assert!(release_version("v0.2.0-", "0.2.0").is_err());
        assert!(release_version("v0.2.0-rc_1", "0.2.0").is_err());
        assert!(release_version("v0.2.0-rc 1;rm", "0.2.0").is_err());
    }

    #[test]
    fn notes_list_the_log_entries_the_previous_tag_lacks() {
        let old = "# log\n\nNot an entry.\n\n- 2026-10-21 — G0.1: first\n  line two\n";
        let new = format!(
            "{old}\n- 2026-10-22 — G0.2: second\n  continues\n\n- 2026-10-23 — G0.3: {}\n",
            "x".repeat(400)
        );
        let notes = release_notes(old, &new);
        let lines: Vec<&str> = notes.lines().collect();
        assert_eq!(lines.len(), 2, "{notes}");
        assert_eq!(lines[0], "- 2026-10-22 — G0.2: second continues");
        assert!(lines[1].ends_with('…') && lines[1].chars().count() == 2 + NOTE_ENTRY_MAX + 1);
        assert!(release_notes(&new, &new).starts_with("Nenhuma"));
        assert_eq!(
            release_notes("", old),
            "- 2026-10-21 — G0.1: first line two\n"
        );

        let many: String = (0..2000)
            .map(|i| format!("- 2026-10-21 — G{i}: {}\n", "y".repeat(200)))
            .collect();
        let notes = release_notes("", &many);
        assert!(notes.len() <= NOTES_MAX + 100, "{}", notes.len());
        assert!(notes.trim_end().ends_with("entradas (docs/log.md)"));
    }
}
