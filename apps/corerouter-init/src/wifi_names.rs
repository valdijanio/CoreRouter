//! G1.30: a Wi-Fi radio's name. The kernel calls a radio's netdev
//! `wlan<N>` in the order the drivers probe, which a firmware that loads a
//! little later changes; the configuration names an interface, so the radio
//! gets `wifi<N>` (RouterOS v7's name) once and keeps it, by its MAC, as a
//! port keeps its `etherN` (`ports.rs`). A map of its own
//! (`/config/.wifi-names`): the ports' map and its rules (a card replaced in
//! the same slot takes the old name) are about Ethernet.
//!
//! Named from the thread that names the ports plugged in after boot, on the
//! kernel's link messages: a radio always shows up after the boot's own
//! naming (its driver loads in the pass after the ports').

use std::fs;
use std::path::Path;

/// The map file, on the configuration partition.
pub const MAP_FILE: &str = "/config/.wifi-names";
/// Longest map read (it is on a writable partition).
const MAX_MAP: u64 = 16 << 10;
/// Most radios named.
const MAX_RADIOS: usize = 64;
const SYS_NET: &str = "/sys/class/net";

/// `wlan<N>`: a name the kernel gave, which this module may change.
pub fn is_kernel_name(name: &str) -> bool {
    name.strip_prefix("wlan")
        .is_some_and(|n| !n.is_empty() && n.len() <= 3 && n.bytes().all(|b| b.is_ascii_digit()))
}

/// `wifi<N>`, N from 1.
fn number(name: &str) -> Option<u32> {
    let d = name.strip_prefix("wifi")?;
    (!d.is_empty() && d.len() <= 3 && !d.starts_with('0') && d.bytes().all(|b| b.is_ascii_digit()))
        .then(|| d.parse().ok())
        .flatten()
}

fn valid_mac(m: &str) -> bool {
    m.len() == 17
        && m.split(':')
            .all(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// The map: `<name> <mac>` per line; anything else is skipped.
pub fn parse_map(text: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for line in text.lines() {
        let mut f = line.split_ascii_whitespace();
        let (Some(name), Some(mac)) = (f.next(), f.next()) else {
            continue;
        };
        let mac = mac.to_ascii_lowercase();
        if number(name).is_some()
            && valid_mac(&mac)
            && out.len() < MAX_RADIOS
            && !out.iter().any(|(n, m)| n == name || *m == mac)
        {
            out.push((name.to_owned(), mac));
        }
    }
    out
}

pub fn render_map(known: &[(String, String)]) -> String {
    let mut s = String::from(
        "# CoreRouter Wi-Fi radio names (G1.30): <name> <MAC>. Remove this file to renumber the radios from wifi1 on the next boot.\n",
    );
    for (name, mac) in known {
        s.push_str(&format!("{name} {mac}\n"));
    }
    s
}

/// Pairs of texts: `(name, MAC)` in the map and of a radio found,
/// `(kernel name, new name)` of a rename.
pub type Pairs = Vec<(String, String)>;

/// What to rename, `(kernel name, new name)`, and the map afterwards.
/// `found`: `(netdev name, MAC)` of every radio, whatever it is called now.
pub fn assign(found: &[(String, String)], known: &[(String, String)]) -> (Pairs, Pairs) {
    let mut map = known.to_vec();
    let mut renames = Vec::new();
    let mut found: Vec<&(String, String)> = found.iter().take(MAX_RADIOS).collect();
    // The same order every boot, whatever order the drivers probed in.
    found.sort_by(|a, b| a.1.cmp(&b.1));
    for (now, mac) in found {
        if !is_kernel_name(now) {
            // Already named (by this module or by somebody).
            continue;
        }
        let name = match map.iter().find(|(_, m)| m == mac) {
            Some((n, _)) => n.clone(),
            None => {
                let taken = |n: &str| {
                    map.iter().any(|(k, _)| k == n) || renames.iter().any(|(_, to)| to == n)
                };
                let Some(free) = (1..=MAX_RADIOS as u32)
                    .map(|i| format!("wifi{i}"))
                    .find(|n| !taken(n))
                else {
                    continue;
                };
                map.push((free.clone(), mac.clone()));
                free
            }
        };
        renames.push((now.clone(), name));
    }
    (renames, map)
}

fn read(path: &Path) -> String {
    fs::read_to_string(path)
        .map(|s| s.trim().to_owned())
        .unwrap_or_default()
}

/// The radios' netdevs: `(name, MAC)`.
fn radios() -> Vec<(String, String)> {
    let Ok(dir) = fs::read_dir(SYS_NET) else {
        return Vec::new();
    };
    dir.flatten()
        .filter(|e| e.path().join("phy80211").exists())
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            let mac = read(&e.path().join("address")).to_ascii_lowercase();
            valid_mac(&mac).then_some((name, mac))
        })
        .take(MAX_RADIOS)
        .collect()
}

/// Is a radio still under the kernel's name? Cheap: asked at every link
/// message.
pub fn pending() -> bool {
    radios().iter().any(|(n, _)| is_kernel_name(n))
}

/// Names the radios that still carry the kernel's name; one log line per
/// rename. `write`: how the map is saved.
pub fn pass(log: impl Fn(&str), write: impl Fn(&Path, &str) -> std::io::Result<()>) {
    let map = Path::new(MAP_FILE);
    let known = {
        use std::io::Read;
        let mut s = String::new();
        if let Ok(f) = fs::File::open(map) {
            let _ = f.take(MAX_MAP).read_to_string(&mut s);
        }
        parse_map(&s)
    };
    let (renames, new_map) = assign(&radios(), &known);
    let mut done = Vec::new();
    for (from, to) in &renames {
        match crate::links::rename(from, to) {
            Ok(()) => done.push(format!("{from}→{to}")),
            Err(e) => log(&format!("wifi names: {from}→{to}: {e}")),
        }
    }
    if !done.is_empty() {
        log(&format!("wifi names: {}", done.join(", ")));
    }
    if new_map != known
        && let Err(e) = write(map, &render_map(&new_map))
    {
        log(&format!(
            "wifi names: {}: {e} (the names hold until the next boot)",
            map.display()
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(name: &str, mac: &str) -> (String, String) {
        (name.to_owned(), mac.to_owned())
    }

    #[test]
    fn a_radio_gets_its_name_once_and_keeps_it() {
        // First boot: two radios, named by MAC order, whatever the kernel
        // called them.
        let found = [
            r("wlan1", "4c:79:6e:00:00:01"),
            r("wlan0", "9c:6b:00:00:00:02"),
        ];
        let (renames, map) = assign(&found, &[]);
        assert_eq!(renames, [r("wlan1", "wifi1"), r("wlan0", "wifi2")]);
        assert_eq!(
            map,
            [
                r("wifi1", "4c:79:6e:00:00:01"),
                r("wifi2", "9c:6b:00:00:00:02")
            ]
        );
        // Next boot the drivers probe the other way round: same names.
        let found = [
            r("wlan0", "4c:79:6e:00:00:01"),
            r("wlan1", "9c:6b:00:00:00:02"),
        ];
        let (renames, again) = assign(&found, &map);
        assert_eq!(renames, [r("wlan0", "wifi1"), r("wlan1", "wifi2")]);
        assert_eq!(again, map);
        // Named already: nothing to do, and the map is not rewritten.
        let found = [
            r("wifi1", "4c:79:6e:00:00:01"),
            r("wifi2", "9c:6b:00:00:00:02"),
        ];
        assert_eq!(assign(&found, &map), (vec![], map.clone()));
        // The first radio is pulled out and another plugged in: the new one
        // does not take the absent one's name (its configuration waits).
        let found = [
            r("wifi2", "9c:6b:00:00:00:02"),
            r("wlan0", "02:11:22:33:44:55"),
        ];
        let (renames, map3) = assign(&found, &map);
        assert_eq!(renames, [r("wlan0", "wifi3")]);
        assert_eq!(map3.len(), 3);
        // A name somebody chose is left alone.
        let (renames, _) = assign(&[r("uplink", "02:11:22:33:44:66")], &map);
        assert!(renames.is_empty());
    }

    #[test]
    fn the_map_file_is_hostile_input() {
        let text = "# comment\nwifi1 4C:79:6E:00:00:01\nwifi1 02:00:00:00:00:09\nwifi2 4c:79:6e:00:00:01\n\
                    ether1 02:00:00:00:00:03\nwifi0 02:00:00:00:00:04\nwifi03 02:00:00:00:00:05\n\
                    wifi9 not-a-mac\nwifi4\n\0\0\nwifi7 02:00:00:00:00:07 extra words\n";
        let map = parse_map(text);
        assert_eq!(
            map,
            [
                r("wifi1", "4c:79:6e:00:00:01"),
                r("wifi7", "02:00:00:00:00:07")
            ]
        );
        assert_eq!(parse_map(&render_map(&map)), map);
        let many: String = (1..200)
            .map(|i| format!("wifi{i} 02:00:00:00:{:02x}:{:02x}\n", i / 256, i % 256))
            .collect();
        assert_eq!(parse_map(&many).len(), MAX_RADIOS);
        for n in ["wlan0", "wlan12"] {
            assert!(is_kernel_name(n), "{n}");
        }
        for n in ["wlan", "wlan1234", "wlanx", "wifi1", "wlp3s0", ""] {
            assert!(!is_kernel_name(n), "{n}");
        }
        // More radios than names: the rest keep the kernel's name.
        let found: Vec<(String, String)> = (0..70)
            .map(|i| r(&format!("wlan{i}"), &format!("02:00:00:00:00:{i:02x}")))
            .collect();
        let (renames, map) = assign(&found, &[]);
        assert_eq!((renames.len(), map.len()), (MAX_RADIOS, MAX_RADIOS));
    }
}
