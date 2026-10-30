//! Port names (G1.6m): the kernel calls the Ethernet ports `eth0`, `eth1`…
//! in probe order; the rest of CoreRouter (GUI, documents, RouterOS habits)
//! calls them `ether1`, `ether2`…. PID 1 renames them before the daemon
//! starts, so the daemon, the console setup and `corerouter.mgmt=` all see
//! the same names.
//!
//! What decides a name, kept apart from the syscalls (`pid1`) so it is
//! tested on any host:
//!
//! - the ports are numbered in bus order (the PCI path of the device, then
//!   `dev_port` for a card with several ports on one function, then the
//!   MAC), not in probe order, which changes between boots when drivers
//!   probe in parallel (the VyOS and RouterOS forum reports);
//! - a name, once given, sticks to the card's MAC (`/config/.port-names`),
//!   like VyOS' `hw-id`: a card added later gets the next free number and
//!   never shifts the others;
//! - a card replaced in the same slot (its MAC is gone, a new MAC sits at
//!   the same bus path) takes the old card's name, like Junos' slot/port
//!   names: the configuration on that port keeps working;
//! - the name of a card that is gone stays reserved (its configuration
//!   still points at it) until the map file is removed.

/// The map file, on the configuration partition.
pub const MAP_FILE: &str = "/config/.port-names";
/// Longest map file read (hostile input: it is on a writable partition).
pub const MAX_MAP: u64 = 64 << 10;
/// Most ports named (a 1U box has tens; a bound on the map).
pub const MAX_PORTS: usize = 1024;

/// A physical Ethernet port as `/sys/class/net` shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    /// The kernel's name (`eth0`).
    pub kernel: String,
    pub mac: String,
    /// The device's sysfs path (`/sys/devices/pci0000:00/0000:00:02.0/virtio1`).
    pub path: String,
    pub dev_port: u32,
}

/// One line of the map: a name and the card it belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Known {
    pub name: String,
    pub mac: String,
    pub path: String,
}

/// A kernel name that names a port this module may rename (`eth<N>`): a
/// name someone chose (`wan`, `ether7`) is left alone.
pub fn is_kernel_name(name: &str) -> bool {
    name.strip_prefix("eth")
        .is_some_and(|n| !n.is_empty() && n.len() <= 4 && n.bytes().all(|b| b.is_ascii_digit()))
}

fn valid_mac(m: &str) -> bool {
    m.len() == 17
        && m.split(':')
            .all(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn valid_name(n: &str) -> bool {
    n.strip_prefix("ether").is_some_and(|d| {
        !d.is_empty()
            && d.len() <= 4
            && d.bytes().all(|b| b.is_ascii_digit())
            && !d.starts_with('0')
    }) || is_kernel_name(n)
}

/// The map file: `<name> <mac> <path>` per line; anything else is skipped
/// (and counted, for the log).
pub fn parse_map(text: &str) -> (Vec<Known>, usize) {
    let mut out: Vec<Known> = Vec::new();
    let mut bad = 0;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut f = line.split_ascii_whitespace();
        let (Some(name), Some(mac), path) = (f.next(), f.next(), f.next().unwrap_or("")) else {
            bad += 1;
            continue;
        };
        let mac = mac.to_ascii_lowercase();
        if !valid_name(name)
            || !valid_mac(&mac)
            || path.len() > 256
            || out.iter().any(|k| k.name == name || k.mac == mac)
            || out.len() >= MAX_PORTS
        {
            bad += 1;
            continue;
        }
        out.push(Known {
            name: name.to_owned(),
            mac,
            path: path.to_owned(),
        });
    }
    (out, bad)
}

pub fn render_map(known: &[Known]) -> String {
    let mut s = String::from(
        "# CoreRouter port names (G1.6m): <name> <MAC> <bus path>. Remove this file to renumber every port from ether1 on the next boot.\n",
    );
    for k in known {
        s.push_str(&format!("{} {} {}\n", k.name, k.mac, k.path));
    }
    s
}

/// Bus order: PCI path, port on the function, MAC.
pub fn bus_order(found: &mut [Found]) {
    found.sort_by(|a, b| {
        (a.path.as_str(), a.dev_port, a.mac.as_str()).cmp(&(
            b.path.as_str(),
            b.dev_port,
            b.mac.as_str(),
        ))
    });
}

/// The ports a hot-plug pass names (G1.6n): the ones still under the
/// kernel's name and the ones that already carry a name from the map. The
/// named ones go in so `assign` sees them present (a new card in a slot is
/// not taken for the replacement of a card that is still there); a port
/// under a name someone chose (`wan`) is not ours to touch.
pub fn hotplug_set(all: Vec<Found>, known: &[Known]) -> Vec<Found> {
    all.into_iter()
        .filter(|f| is_kernel_name(&f.kernel) || known.iter().any(|k| k.name == f.kernel))
        .collect()
}

/// What to do at boot.
#[derive(Debug, PartialEq, Eq)]
pub struct Plan {
    /// `(kernel name, new name)`, in bus order; links that already have
    /// their name are left out.
    pub renames: Vec<(String, String)>,
    /// Every port's name this boot, by kernel name (for `corerouter.mgmt=`
    /// written with a kernel name).
    pub names: Vec<(String, String)>,
    /// The map to write.
    pub map: Vec<Known>,
    /// Lines for the console log (a replaced card, a new one).
    pub notes: Vec<String>,
}

/// The names of `found` given the map `known`. With `keep_kernel` (a
/// configuration from before G1.6m exists and no map yet), every port keeps
/// the kernel's name and the map records them: renaming would leave the
/// configuration pointing at names that are gone (a lockout).
pub fn assign(found: &[Found], known: &[Known], keep_kernel: bool) -> Plan {
    let mut found: Vec<Found> = found.iter().take(MAX_PORTS).cloned().collect();
    bus_order(&mut found);
    let mut map: Vec<Known> = known.to_vec();
    let mut notes = Vec::new();
    let mut got: Vec<Option<String>> = vec![None; found.len()];
    let present = |mac: &str| found.iter().any(|f| f.mac == mac);
    // 1. The card's own name.
    for (f, g) in found.iter().zip(got.iter_mut()) {
        if let Some(k) = map.iter_mut().find(|k| k.mac == f.mac) {
            k.path.clone_from(&f.path);
            *g = Some(k.name.clone());
        }
    }
    // 2. A new card in the slot of one that is gone.
    for (f, g) in found.iter().zip(got.iter_mut()) {
        if g.is_some() || f.path.is_empty() {
            continue;
        }
        let slot = map
            .iter_mut()
            .find(|k| k.path == f.path && !present(&k.mac));
        if let Some(k) = slot {
            notes.push(format!(
                "{}: card {} replaced by {} in the same slot: it keeps the name",
                k.name, k.mac, f.mac
            ));
            k.mac.clone_from(&f.mac);
            *g = Some(k.name.clone());
        }
    }
    // 3. New cards: the kernel's name (keep_kernel), else the first free
    // etherN.
    for (f, g) in found.iter().zip(got.iter_mut()) {
        if g.is_some() {
            continue;
        }
        let name = if keep_kernel && !map.iter().any(|k| k.name == f.kernel) {
            f.kernel.clone()
        } else {
            let Some(n) = (1..=MAX_PORTS)
                .map(|n| format!("ether{n}"))
                .find(|n| !map.iter().any(|k| &k.name == n))
            else {
                continue;
            };
            n
        };
        if !known.is_empty() {
            notes.push(format!("{name}: new card {} ({})", f.mac, f.path));
        }
        map.push(Known {
            name: name.clone(),
            mac: f.mac.clone(),
            path: f.path.clone(),
        });
        *g = Some(name);
    }
    let names: Vec<(String, String)> = found
        .iter()
        .zip(&got)
        .filter_map(|(f, g)| Some((f.kernel.clone(), g.clone()?)))
        .collect();
    let renames = names.iter().filter(|(k, n)| k != n).cloned().collect();
    Plan {
        renames,
        names,
        map,
        notes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f(kernel: &str, mac: &str, path: &str) -> Found {
        Found {
            kernel: kernel.into(),
            mac: mac.into(),
            path: path.into(),
            dev_port: 0,
        }
    }
    const A: &str = "52:54:00:00:00:0a";
    const B: &str = "52:54:00:00:00:0b";
    const C: &str = "52:54:00:00:00:0c";
    const D: &str = "52:54:00:00:00:0d";
    const P1: &str = "/sys/devices/pci0000:00/0000:00:01.0/virtio1";
    const P2: &str = "/sys/devices/pci0000:00/0000:00:02.0/virtio2";
    const P3: &str = "/sys/devices/pci0000:00/0000:00:03.0/virtio0";

    #[test]
    fn first_boot_numbers_in_bus_order_not_probe_order() {
        // The kernel probed the third slot first.
        let p = assign(
            &[f("eth0", C, P3), f("eth1", A, P1), f("eth2", B, P2)],
            &[],
            false,
        );
        assert_eq!(
            p.names,
            vec![
                ("eth1".into(), "ether1".into()),
                ("eth2".into(), "ether2".into()),
                ("eth0".into(), "ether3".into())
            ]
        );
        assert_eq!(p.renames.len(), 3);
        assert!(p.notes.is_empty());
        let (back, bad) = parse_map(&render_map(&p.map));
        assert_eq!((back, bad), (p.map, 0));
    }

    #[test]
    fn names_follow_the_mac_and_a_new_card_takes_the_next_number() {
        let (known, _) = parse_map(&format!("ether1 {A} {P1}\nether2 {B} {P2}\n"));
        // A new card probes first, in a slot before the others.
        let p = assign(
            &[
                f("eth0", D, "/sys/devices/pci0000:00/0000:00:00.5/virtio9"),
                f("eth1", A, P1),
                f("eth2", B, P2),
            ],
            &known,
            false,
        );
        assert!(p.names.contains(&("eth1".into(), "ether1".into())));
        assert!(p.names.contains(&("eth2".into(), "ether2".into())));
        assert!(p.names.contains(&("eth0".into(), "ether3".into())));
        assert_eq!(p.notes.len(), 1, "{:?}", p.notes);
    }

    #[test]
    fn a_card_replaced_in_its_slot_keeps_the_name_a_missing_one_stays_reserved() {
        let (known, _) = parse_map(&format!("ether1 {A} {P1}\nether2 {B} {P2}\n"));
        // B's card swapped for D in the same slot; A's card removed.
        let p = assign(&[f("eth0", D, P2), f("eth1", C, P3)], &known, false);
        assert_eq!(
            p.names,
            vec![
                ("eth0".into(), "ether2".into()),
                ("eth1".into(), "ether3".into())
            ]
        );
        assert!(p.map.iter().any(|k| k.name == "ether1" && k.mac == A));
        assert!(p.map.iter().any(|k| k.name == "ether2" && k.mac == D));
        assert!(p.notes.iter().any(|n| n.contains("replaced")));
    }

    #[test]
    fn a_configuration_from_before_keeps_the_kernel_names() {
        let p = assign(&[f("eth0", A, P1), f("eth1", B, P2)], &[], true);
        assert!(p.renames.is_empty());
        assert_eq!(p.map.len(), 2);
        assert_eq!(p.map[0].name, "eth0");
        // A card added later is ether-numbered.
        let p2 = assign(
            &[f("eth0", A, P1), f("eth1", B, P2), f("eth2", C, P3)],
            &p.map,
            false,
        );
        assert_eq!(p2.renames, vec![("eth2".into(), "ether1".into())]);
    }

    #[test]
    fn hostile_map_lines_are_skipped() {
        let text = format!(
            "ether1 {A} {P1}\nether1 {B} x\nether0 {C} x\nwan {D} x\nether2 zz:zz x\nether3\nether4 {A} y\nether5 {} {}\n",
            D,
            "p".repeat(300)
        );
        let (k, bad) = parse_map(&text);
        assert_eq!(k.len(), 1);
        assert_eq!(bad, 7);
        let (_, bad) = parse_map(&"x\n".repeat(5000));
        assert_eq!(bad, 5000);
    }

    #[test]
    fn kernel_names() {
        assert!(is_kernel_name("eth0") && is_kernel_name("eth12"));
        for n in ["eth", "ether1", "eth0.5", "wlan0", "eth12345"] {
            assert!(!is_kernel_name(n), "{n}");
        }
    }

    #[test]
    fn a_card_plugged_in_after_boot_takes_the_next_number_and_keeps_it() {
        // G1.6n: ether1 and ether2 were named at boot; a USB adapter shows up
        // as eth0 with the router running.
        let usb = "/sys/devices/pci0000:00/0000:00:04.0/usb4/4-2/4-2:1.0";
        let (known, _) = parse_map(&format!("ether1 {A} {P1}\nether2 {B} {P2}\n"));
        let all = vec![
            f("ether1", A, P1),
            f("ether2", B, P2),
            f("eth0", D, usb),
            f("wan", C, P3),
        ];
        let set = hotplug_set(all, &known);
        assert_eq!(set.len(), 3, "a name someone chose is left alone");
        let p = assign(&set, &known, false);
        assert_eq!(p.renames, vec![("eth0".into(), "ether3".into())]);
        // Unplugged and plugged in again (another port, the kernel calls it
        // eth1 now): the same name.
        let set = hotplug_set(
            vec![
                f("ether1", A, P1),
                f("ether2", B, P2),
                f(
                    "eth1",
                    D,
                    "/sys/devices/pci0000:00/0000:00:04.0/usb3/3-1/3-1:1.0",
                ),
            ],
            &p.map,
        );
        let p2 = assign(&set, &p.map, false);
        assert_eq!(p2.renames, vec![("eth1".into(), "ether3".into())]);
    }

    #[test]
    fn a_card_in_a_free_slot_does_not_take_a_present_cards_name() {
        // ether2 is present under its name: a new card at the same path (a
        // second port of a USB adapter, say) is new, not a replacement.
        let (known, _) = parse_map(&format!("ether1 {A} {P1}\nether2 {B} {P2}\n"));
        let set = hotplug_set(
            vec![f("ether1", A, P1), f("ether2", B, P2), f("eth0", C, P2)],
            &known,
        );
        let p = assign(&set, &known, false);
        assert_eq!(p.renames, vec![("eth0".into(), "ether3".into())]);
    }
}
