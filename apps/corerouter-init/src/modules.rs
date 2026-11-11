//! G1.6j: the drivers built as modules load themselves. The image
//! has no udev: PID 1 reads the kernel's module index (`modules.alias`,
//! `modules.dep`), looks at the PCI and USB devices that have no driver yet
//! (and the auxiliary ones a driver makes while it probes)
//! and loads what matches, once at boot (after `/` is mounted, so a driver
//! that asks for its firmware while probing finds it: `ice`) and again when
//! the kernel announces a new device (a card plugged in with the router
//! running). A card that is not in the machine costs nothing: its driver
//! stays on the disk.
//!
//! Only modules under `kernel/drivers/net/` and `kernel/drivers/gpu/drm/`
//! are candidates, and the files come from the root under dm-verity. A driver
//! that fails to load, or one whose probe hangs, must not stop the router:
//! everything runs in its own thread and PID 1 waits a bounded time
//! ([`BOOT_WAIT`]) for the network drivers only; a port that shows up later
//! is named by the hot-plug pass (`spawn_hotplug_names`).
//!
//! G1.6zd: the screen's driver (`i915`) is a module for the same reason as
//! `ice`: it asks for its firmware (GuC, HuC, DMC) while probing. It loads
//! after the network drivers and the boot does not wait for it: until it
//! takes the screen, the console is on the firmware's framebuffer
//! (`simpledrm`, G1.6zc).
//!
//! G1.30: the Wi-Fi cards' drivers (`kernel/drivers/net/wireless/`) have a
//! pass of their own, after the boot's: a radio is not one of the ports the
//! boot names, and its driver's probe (firmware, calibration) must not be in
//! the boot's wait. The stack (cfg80211, mac80211, rfkill) is a module too
//! and comes with the first driver that needs it: cfg80211 then reads the
//! regulatory database from `/`, which the built-in one could not.

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};

const MODULES: &str = "/lib/modules";
/// Only these drivers load by themselves (`modules.dep` paths): the ports'
/// and the screen's.
const NET_DRIVERS: &str = "kernel/drivers/net/";
const SCREEN_DRIVERS: &str = "kernel/drivers/gpu/drm/";
/// Inside [`NET_DRIVERS`]: the radios, which are not the boot's ports.
const WIFI_DRIVERS: &str = "kernel/drivers/net/wireless/";
/// Modules no device asks for and their driver needs: loaded with it.
/// `iwlwifi` is the bus half of Intel's driver; it finds out from the
/// firmware which half talks to it (`iwlmvm` up to Wi-Fi 6E, `iwlmld` for
/// Wi-Fi 7) and asks the kernel to run `/sbin/modprobe` for that one
/// (`iwl-drv.c`, `request_module_nowait`), which nothing here answers for
/// sure. With both already in, whichever the firmware names starts the card
/// (`iwl_opmode_register`).
const COMPANIONS: [(&str, &[&str]); 1] = [("iwlwifi", &["iwlmvm", "iwlmld"])];
/// The kernel's simulated radios (`corerouter.hwsim=N`): a test's.
const HWSIM: &str = "mac80211_hwsim";
/// Where a radio shows up, one entry each (`phy0`).
const RADIOS: &str = "/sys/class/ieee80211";
/// `modules.alias` of every network driver is ~1 MiB.
const MAX_INDEX: u64 = 16 << 20;
/// The kernel's `MODALIAS` values are far shorter (USB: ~70 bytes).
const MAX_MODALIAS: usize = 256;
/// More devices than any machine has: the scan's bound.
const MAX_DEVICES: usize = 4096;
/// How long the boot waits for the drivers before it goes on naming the
/// ports. `ice` takes seconds per function, loading its firmware.
const BOOT_WAIT: Duration = Duration::from_secs(20);
const BUSES: [(&str, &str); 3] = [
    ("pci", "/sys/bus/pci/devices"),
    ("usb", "/sys/bus/usb/devices"),
    // `mlx4_en` binds here: `mlx4_core` makes the device while it probes. The
    // bus has no `modalias` file, so these arrive as device messages only.
    ("auxiliary", "/sys/bus/auxiliary/devices"),
];

/// `*`, `?` and `[a-z]`, what `modules.alias` uses: the single pass with a
/// restart at the last `*` (`O(pattern × text)` at worst, both bounded).
fn glob(pattern: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while let Some(&c) = text.get(t) {
        let (matched, next) = match pattern.get(p) {
            Some(b'*') => {
                star = Some((p + 1, t));
                p += 1;
                continue;
            }
            Some(b'?') => (true, p + 1),
            Some(b'[') => match class(pattern.get(p + 1..).unwrap_or_default(), c) {
                Some((hit, len)) => (hit, p + 1 + len),
                None => (c == b'[', p + 1),
            },
            Some(&l) => (l == c, p + 1),
            None => (false, p),
        };
        if matched {
            p = next;
            t += 1;
        } else if let Some((sp, st)) = star {
            star = Some((sp, st + 1));
            p = sp;
            t = st + 1;
        } else {
            return false;
        }
    }
    pattern
        .get(p..)
        .unwrap_or_default()
        .iter()
        .all(|&c| c == b'*')
}

/// The class after a `[`: whether `c` is in it and how many bytes it takes,
/// `]` included. `None`: no closing `]`.
fn class(rest: &[u8], c: u8) -> Option<(bool, usize)> {
    let end = rest.iter().position(|&b| b == b']')?;
    let body = rest.get(..end)?;
    let mut hit = false;
    let mut i = 0;
    while let Some(&a) = body.get(i) {
        if let (Some(b'-'), Some(&b)) = (body.get(i + 1), body.get(i + 2)) {
            hit |= (a..=b).contains(&c);
            i += 3;
        } else {
            hit |= a == c;
            i += 1;
        }
    }
    Some((hit, end + 1))
}

/// `kernel/.../e1000-e.ko` → `e1000_e`, how `modules.alias` names it.
fn module_name(path: &str) -> Option<String> {
    let file = path.rsplit('/').next()?;
    let stem = file.split(".ko").next()?;
    (!stem.is_empty()).then(|| stem.replace('-', "_"))
}

/// Which of the candidates a pass loads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pass {
    /// The network drivers: the boot waits for them, the ports' names
    /// depend on what they find.
    Ports,
    /// The Wi-Fi cards' drivers (G1.30): after the boot's, nothing waits.
    Wifi,
    /// The screen's driver: nothing waits for it.
    Screen,
    /// A device that arrived with the router running: whatever it asks for.
    Any,
}

/// What the module index says about the drivers that load by themselves.
#[derive(Debug, Default)]
pub struct Index {
    /// `(bus, pattern, module)`.
    aliases: Vec<(String, String, String)>,
    /// A module's files in load order: what it needs, then itself.
    chains: HashMap<String, Vec<String>>,
}

impl Index {
    /// The two index files' text. Lines that do not parse are skipped: the
    /// files come from the image's own build.
    pub fn parse(dep: &str, alias: &str) -> Self {
        let mut chains = HashMap::new();
        for line in dep.lines() {
            let Some((path, needs)) = line.split_once(':') else {
                continue;
            };
            if !path.starts_with(NET_DRIVERS) && !path.starts_with(SCREEN_DRIVERS) {
                continue;
            }
            let Some(name) = module_name(path) else {
                continue;
            };
            // depmod lists the closest need first: load from the right.
            let mut chain: Vec<String> = needs
                .split_ascii_whitespace()
                .rev()
                .map(str::to_owned)
                .collect();
            chain.push(path.to_owned());
            chains.insert(name, chain);
        }
        let mut aliases = Vec::new();
        for line in alias.lines() {
            let mut w = line.split_ascii_whitespace();
            let (Some("alias"), Some(pattern), Some(module)) = (w.next(), w.next(), w.next())
            else {
                continue;
            };
            let module = module.replace('-', "_");
            let Some((bus, _)) = pattern.split_once(':') else {
                continue;
            };
            if chains.contains_key(&module) && BUSES.iter().any(|(b, _)| *b == bus) {
                aliases.push((bus.to_owned(), pattern.to_owned(), module));
            }
        }
        Self { aliases, chains }
    }

    fn is_empty(&self) -> bool {
        self.aliases.is_empty()
    }

    /// The modules a device asks for, each once, in the index's order.
    pub fn matches(&self, modalias: &str) -> Vec<&str> {
        let Some((bus, _)) = modalias.split_once(':') else {
            return Vec::new();
        };
        let mut out: Vec<&str> = Vec::new();
        for (b, pattern, module) in &self.aliases {
            if b == bus
                && glob(pattern.as_bytes(), modalias.as_bytes())
                && !out.contains(&module.as_str())
            {
                out.push(module);
            }
        }
        out
    }

    fn chain(&self, module: &str) -> &[String] {
        self.chains.get(module).map_or(&[], Vec::as_slice)
    }

    /// Is `module` one of the pass's? Its own file is the chain's last.
    fn in_pass(&self, module: &str, pass: Pass) -> bool {
        let file = self.chain(module).last().map_or("", String::as_str);
        let wifi = file.starts_with(WIFI_DRIVERS);
        let net = file.starts_with(NET_DRIVERS);
        match pass {
            Pass::Ports => net && !wifi,
            Pass::Wifi => wifi,
            Pass::Screen => !net,
            Pass::Any => true,
        }
    }
}

fn read_limited(path: &Path, limit: u64) -> String {
    let mut s = String::new();
    if let Ok(f) = File::open(path) {
        let _ = f.take(limit).read_to_string(&mut s);
    }
    s
}

/// This kernel's directory under `/lib/modules`.
fn kernel_dir() -> PathBuf {
    let uts = rustix::system::uname();
    Path::new(MODULES).join(uts.release().to_string_lossy().as_ref())
}

/// The `modalias` of every device of the buses with no driver yet.
fn unbound_devices() -> Vec<String> {
    let mut out = Vec::new();
    for (_, dir) in BUSES {
        let Ok(rd) = fs::read_dir(dir) else {
            continue;
        };
        for e in rd.flatten().take(MAX_DEVICES) {
            let dev = e.path();
            if dev.join("driver").exists() {
                continue;
            }
            let alias = read_limited(&dev.join("modalias"), MAX_MODALIAS as u64);
            let alias = alias.trim();
            if !alias.is_empty() {
                out.push(alias.to_owned());
            }
        }
    }
    out
}

/// One file of a module's chain; `true` when the kernel took it now (a
/// module already in the kernel is not news).
fn insert(dir: &Path, rel: &str, params: &CStr) -> std::io::Result<bool> {
    let file = File::open(dir.join(rel))?;
    match rustix::system::finit_module(&file, params, 0) {
        Ok(()) => Ok(true),
        Err(rustix::io::Errno::EXIST) => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// Loads a module with what it needs; the line to log, when something
/// happened. In the kernel, the driver's probe of every device it finds
/// runs inside this call.
fn load(index: &Index, dir: &Path, module: &str) -> Option<String> {
    load_with(index, dir, module, c"")
}

/// [`load`], the module itself with `params` (what it needs: with none).
fn load_with(index: &Index, dir: &Path, module: &str, params: &CStr) -> Option<String> {
    let t = Instant::now();
    let mut loaded = false;
    let chain = index.chain(module);
    for (i, rel) in chain.iter().enumerate() {
        let own = i + 1 == chain.len();
        match insert(dir, rel, if own { params } else { c"" }) {
            Ok(now) => loaded |= now,
            Err(e) => return Some(format!("driver {module}: {rel}: {e}")),
        }
    }
    loaded.then(|| format!("driver {module} loaded in {} ms", t.elapsed().as_millis()))
}

/// The modules of `pass` the devices in `aliases` ask for, each once, in
/// the devices' order.
fn wanted<'a>(index: &'a Index, aliases: &[String], pass: Pass) -> Vec<&'a str> {
    let mut out: Vec<&str> = Vec::new();
    let mut push = |module: &'a str| {
        if !out.contains(&module) {
            out.push(module);
        }
    };
    for alias in aliases {
        for module in index.matches(alias) {
            if !index.in_pass(module, pass) {
                continue;
            }
            push(module);
            let with = COMPANIONS.iter().find(|(m, _)| *m == module);
            for companion in with.into_iter().flat_map(|(_, c)| c.iter()) {
                // Only what this kernel has: the index knows.
                if !index.chain(companion).is_empty() {
                    push(companion);
                }
            }
        }
    }
    out
}

/// `corerouter.hwsim=N`: the simulated radios, for a test of the image in a
/// machine with no Wi-Fi card (QEMU emulates none). The line says how many
/// radios the kernel has afterwards.
fn load_hwsim(index: &Index, dir: &Path, radios: u8, log: impl Fn(&str)) {
    if index.chain(HWSIM).is_empty() {
        log("wifi: corerouter.hwsim: this kernel has no mac80211_hwsim");
        return;
    }
    let Ok(params) = CString::new(format!("radios={radios}")) else {
        return;
    };
    if let Some(line) = load_with(index, dir, HWSIM, &params) {
        log(&line);
    }
    let found = fs::read_dir(RADIOS).map_or(0, |d| d.flatten().take(MAX_DEVICES).count());
    log(&format!(
        "wifi: {found} test radios (corerouter.hwsim={radios})"
    ));
}

/// Loads the modules of `pass` the devices in `aliases` ask for, one line
/// per module. One after the other: a machine loads a handful, and the slow
/// part (a probe) is the kernel's, in the thread that is not PID 1's.
fn load_for(index: &Index, dir: &Path, aliases: &[String], pass: Pass, mut log: impl FnMut(&str)) {
    for module in wanted(index, aliases, pass) {
        if let Some(line) = load(index, dir, module) {
            log(&line);
        }
    }
}

/// The value of `MODALIAS` in an `add` message of the kernel's uevent
/// socket (`add@/devices/...\0ACTION=add\0...\0MODALIAS=pci:...\0`).
fn uevent_modalias(msg: &[u8]) -> Option<&str> {
    let mut parts = msg.split(|&b| b == 0);
    if !parts.next()?.starts_with(b"add@") {
        return None;
    }
    let v = parts.find_map(|p| p.strip_prefix(b"MODALIAS="))?;
    let v = std::str::from_utf8(v).ok()?;
    (!v.is_empty() && v.len() <= MAX_MODALIAS && v.bytes().all(|b| b.is_ascii_graphic()))
        .then_some(v)
}

/// The kernel's device messages. A sleeping socket: no polling, one wake
/// per device event (rare on a router).
struct DeviceEvents(netlink_sys::Socket);

impl DeviceEvents {
    fn open() -> std::io::Result<Self> {
        use netlink_sys::{Socket, SocketAddr as NlAddr, protocols::NETLINK_KOBJECT_UEVENT};
        /// The kernel's group; 2 is udev's own, which nobody sends here.
        const KERNEL_GROUP: u32 = 1;
        let mut sock = Socket::new(NETLINK_KOBJECT_UEVENT)?;
        sock.bind(&NlAddr::new(0, KERNEL_GROUP))?;
        Ok(Self(sock))
    }

    /// Waits for a message; its length. Anything not from the kernel
    /// (port 0) comes back as length 0.
    fn wait(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut out: &mut [u8] = buf;
        let (n, from) = self.0.recv_from(&mut out, 0)?;
        Ok(if from.port_number() == 0 { n } else { 0 })
    }
}

fn hotplug_loop(events: &DeviceEvents, index: &Index, dir: &Path, log: &dyn Fn(&str)) {
    const ENOBUFS: i32 = 105;
    let mut buf = vec![0u8; 16 << 10];
    loop {
        match events.wait(&mut buf) {
            Ok(n) => {
                let alias = buf.get(..n).and_then(uevent_modalias).map(str::to_owned);
                if let Some(alias) = alias {
                    load_for(index, dir, &[alias], Pass::Any, log);
                }
            }
            // Lost messages: the devices themselves say what is missing.
            Err(e) if e.raw_os_error() == Some(ENOBUFS) => {
                load_for(index, dir, &unbound_devices(), Pass::Any, log);
            }
            Err(_) => std::thread::sleep(Duration::from_secs(1)),
        }
    }
}

/// Loads the drivers of what is in the machine and keeps listening for what
/// is plugged in later, in its own thread. Returns when the boot's network
/// drivers are in, or at [`BOOT_WAIT`] with the loading still going; the
/// Wi-Fi cards' drivers and the screen's load after that, with the boot
/// already going on. `hwsim`: that many simulated radios (a test's).
pub fn start(log: fn(&str), hwsim: Option<u8>) {
    let dir = kernel_dir();
    let index = Index::parse(
        &read_limited(&dir.join("modules.dep"), MAX_INDEX),
        &read_limited(&dir.join("modules.alias"), MAX_INDEX),
    );
    if index.is_empty() {
        return;
    }
    // Before the scan: a device that arrives during it is not lost.
    let events = DeviceEvents::open();
    let (done, boot) = mpsc::sync_channel::<()>(1);
    let spawned = std::thread::Builder::new()
        .name("drivers".into())
        .spawn(move || {
            let t = Instant::now();
            let devices = unbound_devices();
            load_for(&index, &dir, &devices, Pass::Ports, log);
            log(&format!(
                "drivers: {} devices without a driver looked at in {} ms",
                devices.len(),
                t.elapsed().as_millis()
            ));
            let _ = done.send(());
            load_for(&index, &dir, &devices, Pass::Wifi, log);
            if let Some(radios) = hwsim {
                load_hwsim(&index, &dir, radios, log);
            }
            load_for(&index, &dir, &devices, Pass::Screen, log);
            match events {
                Ok(events) => hotplug_loop(&events, &index, &dir, &log),
                Err(e) => log(&format!(
                    "drivers: no device messages ({e}); a card plugged in after boot needs a reboot if its driver is not loaded"
                )),
            }
        });
    match spawned {
        Ok(_) => {
            if boot.recv_timeout(BOOT_WAIT).is_err() {
                log(
                    "drivers: still loading; the boot goes on, the ports get their names when they appear",
                );
            }
        }
        Err(e) => log(&format!("drivers: thread: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEP: &str = "\
kernel/drivers/net/ethernet/intel/ice/ice.ko: kernel/drivers/net/aux.ko kernel/lib/base.ko
kernel/drivers/net/ethernet/intel/e100.ko:
kernel/drivers/net/usb/ax-88179.ko.zst: kernel/drivers/net/usb/usbnet.ko
kernel/net/netfilter/xt_mark.ko:
kernel/drivers/gpu/drm/i915/i915.ko: kernel/drivers/gpu/drm/ttm/ttm.ko kernel/drivers/gpu/drm/drm_buddy.ko
kernel/drivers/gpu/drm/ttm/ttm.ko:
kernel/drivers/gpu/drm/drm_buddy.ko:
kernel/drivers/net/wireless/intel/iwlwifi/iwlwifi.ko: kernel/net/wireless/cfg80211.ko kernel/net/rfkill/rfkill.ko
kernel/drivers/net/wireless/intel/iwlwifi/mvm/iwlmvm.ko: kernel/drivers/net/wireless/intel/iwlwifi/iwlwifi.ko kernel/net/mac80211/mac80211.ko kernel/lib/crypto/libarc4.ko kernel/net/wireless/cfg80211.ko kernel/net/rfkill/rfkill.ko
kernel/drivers/net/wireless/intel/iwlwifi/mld/iwlmld.ko: kernel/drivers/net/wireless/intel/iwlwifi/iwlwifi.ko kernel/net/mac80211/mac80211.ko kernel/lib/crypto/libarc4.ko kernel/net/wireless/cfg80211.ko kernel/net/rfkill/rfkill.ko
kernel/drivers/net/wireless/mediatek/mt76/mt7925/mt7925e.ko: kernel/drivers/net/wireless/mediatek/mt76/mt76.ko kernel/net/mac80211/mac80211.ko kernel/net/wireless/cfg80211.ko kernel/net/rfkill/rfkill.ko
kernel/drivers/net/wireless/mediatek/mt76/mt76.ko: kernel/net/mac80211/mac80211.ko kernel/net/wireless/cfg80211.ko kernel/net/rfkill/rfkill.ko
kernel/drivers/net/wireless/virtual/mac80211_hwsim.ko: kernel/net/mac80211/mac80211.ko kernel/net/wireless/cfg80211.ko kernel/net/rfkill/rfkill.ko
";
    const ALIAS: &str = "\
# Aliases extracted from modules themselves.
alias pci:v00008086d00001592sv*sd*bc*sc*i* ice
alias pci:v00008086d00001229sv*sd*bc02sc00i* e100
alias usb:v0B95p1790d*dc*dsc*dp*ic*isc*ip*in* ax_88179
alias pci:v00001234d*sv*sd*bc*sc*i* xt_mark
alias pci:v00008086d0000A7A0sv*sd*bc03sc*i* i915
alias pci:v00008086d000051F0sv*sd*bc*sc*i* iwlwifi
alias pci:v000014C3d00000717sv*sd*bc*sc*i* mt7925e
alias cpu:type:x86,ven*fam*mod*:feature:*0073* ice
broken line
";

    #[test]
    fn glob_as_the_kernel_writes_them() {
        for (p, t, want) in [
            ("pci:v*d*", "pci:v8086d1592", true),
            ("pci:v8086d1592", "pci:v8086d1592", true),
            ("pci:v8086d1592", "pci:v8086d1593", false),
            ("abc", "abcd", false),
            ("abcd", "abc", false),
            ("a*", "a", true),
            ("*", "", true),
            ("", "", true),
            ("", "x", false),
            ("a?c", "abc", true),
            ("a?c", "ac", false),
            ("*a*b*c", "xxaxxbxxc", true),
            ("*a*b*c", "xxaxxbxx", false),
            ("d0[0-2]*", "d01ff", true),
            ("d0[0-2]*", "d03ff", false),
            ("d[135]x", "d3x", true),
            ("d[135]x", "d2x", false),
            // A class that never closes is a literal, not a crash.
            ("d[0-2", "d[0-2", true),
        ] {
            assert_eq!(glob(p.as_bytes(), t.as_bytes()), want, "{p} ~ {t}");
        }
    }

    #[test]
    fn only_port_and_screen_drivers_on_the_buses() {
        let i = Index::parse(DEP, ALIAS);
        assert_eq!(
            i.matches("pci:v00008086d00001592sv00008086sd00000001bc02sc00i00"),
            ["ice"]
        );
        assert_eq!(
            i.matches("pci:v00008086d00001229sv00000000sd00000000bc02sc00i00"),
            ["e100"]
        );
        // Same id with another class: not what the pattern says.
        assert!(
            i.matches("pci:v00008086d00001229sv00000000sd00000000bc03sc00i00")
                .is_empty()
        );
        assert_eq!(
            i.matches("usb:v0B95p1790d0100dc00dsc00dp00icFFisc00ip00in00"),
            ["ax_88179"]
        );
        assert_eq!(
            i.matches("pci:v00008086d0000A7A0sv000017AAsd00003B60bc03sc00i00"),
            ["i915"]
        );
        // Not a port's nor a screen's driver, whatever the alias says.
        assert!(i.matches("pci:v00001234d00000001sv0sd0bc0sc0i0").is_empty());
        // Other buses never load anything.
        assert!(
            i.matches("cpu:type:x86,ven0000fam0006mod0055:feature:,0073")
                .is_empty()
        );
        assert!(i.matches("no colon").is_empty());
    }

    #[test]
    fn a_chain_ends_in_the_module_with_its_needs_first() {
        let i = Index::parse(DEP, ALIAS);
        assert_eq!(
            i.chain("ice"),
            [
                "kernel/lib/base.ko",
                "kernel/drivers/net/aux.ko",
                "kernel/drivers/net/ethernet/intel/ice/ice.ko"
            ]
        );
        assert_eq!(
            i.chain("e100"),
            ["kernel/drivers/net/ethernet/intel/e100.ko"]
        );
        assert!(i.chain("nothing").is_empty());
    }

    /// G1.6zd: the boot waits for the ports' drivers only; the screen's
    /// loads in its own pass, with what it needs first.
    #[test]
    fn the_screen_driver_is_not_in_the_boot_wait() {
        let i = Index::parse(DEP, ALIAS);
        let devices = [
            "pci:v00008086d0000A7A0sv000017AAsd00003B60bc03sc00i00".to_owned(),
            "pci:v00008086d00001592sv00008086sd00000001bc02sc00i00".to_owned(),
            "pci:v00008086d00001229sv00000000sd00000000bc02sc00i00".to_owned(),
        ];
        assert_eq!(wanted(&i, &devices, Pass::Ports), ["ice", "e100"]);
        assert_eq!(wanted(&i, &devices, Pass::Screen), ["i915"]);
        assert_eq!(wanted(&i, &devices, Pass::Any), ["i915", "ice", "e100"]);
        assert_eq!(
            i.chain("i915"),
            [
                "kernel/drivers/gpu/drm/drm_buddy.ko",
                "kernel/drivers/gpu/drm/ttm/ttm.ko",
                "kernel/drivers/gpu/drm/i915/i915.ko"
            ]
        );
        // The helpers have no device of their own: nothing asks for them.
        assert!(wanted(&i, &["pci:v1d2".to_owned()], Pass::Any).is_empty());
    }

    /// G1.30: a radio's driver is not one of the boot's (nothing names a
    /// port after it), it brings the stack with it, and Intel's comes with
    /// both of its halves, which no device asks for.
    #[test]
    fn the_wifi_drivers_load_after_the_boot_with_their_halves() {
        let i = Index::parse(DEP, ALIAS);
        let devices = [
            "pci:v00008086d000051F0sv00008086sd00000090bc02sc80i00".to_owned(),
            "pci:v000014C3d00000717sv000014C3sd00000717bc02sc80i00".to_owned(),
            "pci:v00008086d00001229sv00000000sd00000000bc02sc00i00".to_owned(),
        ];
        assert_eq!(wanted(&i, &devices, Pass::Ports), ["e100"]);
        assert_eq!(
            wanted(&i, &devices, Pass::Wifi),
            ["iwlwifi", "iwlmvm", "iwlmld", "mt7925e"]
        );
        assert!(wanted(&i, &devices, Pass::Screen).is_empty());
        // A USB radio plugged in later, or a rescan: the same, once.
        assert_eq!(
            wanted(&i, &devices, Pass::Any),
            ["iwlwifi", "iwlmvm", "iwlmld", "mt7925e", "e100"]
        );
        // The stack first, from outside the drivers' directories.
        assert_eq!(
            i.chain("mt7925e"),
            [
                "kernel/net/rfkill/rfkill.ko",
                "kernel/net/wireless/cfg80211.ko",
                "kernel/net/mac80211/mac80211.ko",
                "kernel/drivers/net/wireless/mediatek/mt76/mt76.ko",
                "kernel/drivers/net/wireless/mediatek/mt76/mt7925/mt7925e.ko"
            ]
        );
        // The simulated radios: in the index, asked for by no device.
        assert_eq!(i.chain(HWSIM).len(), 4);
        assert!(i.aliases.iter().all(|(_, _, m)| m != HWSIM));
        // A kernel without one of the halves (the live image's has none).
        let dep = "kernel/drivers/net/wireless/intel/iwlwifi/iwlwifi.ko:\n";
        let i = Index::parse(dep, ALIAS);
        assert_eq!(wanted(&i, &devices, Pass::Wifi), ["iwlwifi"]);
    }

    #[test]
    fn a_device_asks_for_a_module_once() {
        let alias = "alias pci:v1d* e100\nalias pci:v1d2* e100\n";
        let i = Index::parse(DEP, alias);
        assert_eq!(i.matches("pci:v1d2"), ["e100"]);
    }

    #[test]
    fn module_names() {
        assert_eq!(
            module_name("kernel/a/e1000-e.ko").as_deref(),
            Some("e1000_e")
        );
        assert_eq!(module_name("kernel/a/x.ko.zst").as_deref(), Some("x"));
        assert_eq!(module_name("kernel/a/.ko"), None);
    }

    #[test]
    fn uevent_messages() {
        let add = b"add@/devices/pci0000:00/0000:00:02.0\0ACTION=add\0SUBSYSTEM=pci\0MODALIAS=pci:v8086d1592\0SEQNUM=1\0";
        assert_eq!(uevent_modalias(add), Some("pci:v8086d1592"));
        let bind = b"bind@/devices/x\0ACTION=bind\0MODALIAS=pci:v1\0";
        assert_eq!(uevent_modalias(bind), None);
        assert_eq!(uevent_modalias(b"add@/devices/x\0ACTION=add\0"), None);
        assert_eq!(uevent_modalias(b""), None);
        assert_eq!(uevent_modalias(b"add@/x\0MODALIAS=\0"), None);
        assert_eq!(uevent_modalias(b"add@/x\0MODALIAS=has space\0"), None);
        assert_eq!(uevent_modalias(b"add@/x\0MODALIAS=\xff\xfe\0"), None);
        let long = [b"add@/x\0MODALIAS=".as_slice(), &[b'a'; 300], b"\0"].concat();
        assert_eq!(uevent_modalias(&long), None);
    }

    /// Hostile index and messages: nothing here may panic (the init is
    /// PID 1). The cost is what the boot pays: every device against every
    /// alias, the worst case of the wide driver set.
    #[test]
    fn garbage_and_scale() {
        for junk in [
            "\0\0\0",
            ":::",
            "alias",
            "alias a",
            "alias a b c d",
            "x.ko:",
            ":y",
            "\u{fffd}",
        ] {
            let i = Index::parse(junk, junk);
            assert!(i.matches(junk).is_empty());
            assert_eq!(uevent_modalias(junk.as_bytes()), None);
        }
        let mut dep = String::new();
        let mut alias = String::new();
        for m in 0..200 {
            dep.push_str(&format!("kernel/drivers/net/m{m}.ko:\n"));
            for d in 0..50 {
                alias.push_str(&format!("alias pci:v00008086d{d:08X}sv*sd*bc*sc*i* m{m}\n"));
            }
        }
        let i = Index::parse(&dep, &alias);
        let t = Instant::now();
        for d in 0..100 {
            assert!(
                i.matches(&format!("pci:v00001AF4d{d:08X}sv0sd0bc02sc00i00"))
                    .is_empty()
            );
        }
        // ~1 ms in a release build; generous for a shared CI machine.
        assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
    }

    /// `mlx4_core` makes the device `mlx4_en` binds to while it probes: the
    /// port of a ConnectX-3 depends on this message.
    #[test]
    fn a_driver_of_the_auxiliary_bus() {
        let dep = "kernel/drivers/net/ethernet/mellanox/mlx4/mlx4_en.ko: kernel/drivers/net/ethernet/mellanox/mlx4/mlx4_core.ko
                   kernel/drivers/net/ethernet/mellanox/mlx4/mlx4_core.ko:
";
        let i = Index::parse(
            dep,
            "alias auxiliary:mlx4_core.eth mlx4_en
",
        );
        let add = b"add@/devices/pci0000:00/0000:00:03.0/mlx4_core.eth.0 ACTION=add SUBSYSTEM=auxiliary MODALIAS=auxiliary:mlx4_core.eth ";
        let alias = uevent_modalias(add).unwrap();
        assert_eq!(i.matches(alias), ["mlx4_en"]);
        assert_eq!(i.chain("mlx4_en").len(), 2);
    }
}
