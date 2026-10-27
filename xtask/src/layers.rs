//! `cargo xtask layers`: the dependency rules of docs/architecture.md, as code.
//!
//! 1. Every workspace crate has a layer in `LAYERS` (new crate = classify it here).
//! 2. A crate depends only on strictly lower layers (sideways only via `SIDEWAYS_ALLOWED`).
//! 3. UI libraries (`UI_CRATES`) only from layer `UI_MIN_LAYER` up.
//! 4. Platform crates (`PLATFORM_CRATES`) only from the apps (`APP_LAYER`),
//!    or from the platform crate that drives them (`PLATFORM_ALLOWED`).
//! 5. Tooling (`xtask`) depends on no workspace crate.

use std::fmt;

pub const LAYERS: &[(&str, u8)] = &[
    ("corerouter-model", 0),
    ("corerouter-buildinfo", 0),
    // G2.5b: the CGNAT port arithmetic (no_std), under the model and the XDP
    // fast path alike.
    ("corerouter-cgnat-map", 0),
    ("corerouter-hal", 1),
    ("corerouter-hal-linux", 1),
    // Pure (no I/O, wasm-safe): firewall validation + nftables render, needed by
    // hal-linux (L1) and the engine, so it cannot be an L2 proto-* crate.
    ("corerouter-firewall", 1),
    // G2.5: what the XDP programs and their loader share (no_std, pure). The
    // programs themselves (`crates/dataplane-ebpf`) build for BPF outside
    // the workspace (`cargo xtask ebpf`), so cargo metadata never lists them.
    ("corerouter-dataplane-ebpf-common", 1),
    ("corerouter-proto-bgp", 2),
    ("corerouter-proto-ospf", 2),
    ("corerouter-proto-mpls", 2),
    ("corerouter-proto-cgnat", 2),
    ("corerouter-proto-dns", 2),
    ("corerouter-proto-dhcp", 2),
    ("corerouter-proto-discovery", 2),
    ("corerouter-proto-lldp", 2),
    ("corerouter-proto-mndp", 2),
    ("corerouter-proto-ntp", 2),
    ("corerouter-proto-iperf", 2),
    ("corerouter-proto-syslog", 2),
    ("corerouter-proto-flow", 2),
    // G4.3a: PPPoE/PPP codecs and the sans-IO BNG machines (pure, wasm-safe).
    ("corerouter-proto-pppoe", 2),
    // G4.3b: RADIUS codec, client and CoA/DM server (sans-IO).
    ("corerouter-proto-radius", 2),
    // G4.3h: BNG high availability: sync protocol, role machine, fencing (sans-IO).
    ("corerouter-proto-ha", 2),
    // G3.1: the FRR driver renders with the proto-* crates (L2), so it sits
    // beside them; as a platform crate only the apps use it.
    ("corerouter-hal-frr", 2),
    ("corerouter-engine", 3),
    ("corerouter-control", 4),
    ("corerouter-mcp", 4),
    ("corerouter-storage-fs", 4),
    ("corerouter-discovery", 4),
    ("corerouter-shell", 4),
    ("corerouter-ui", 5),
    ("corerouter-daemon", 6),
    // G1.6a: PID 1 of the OS image (mounts, /config, supervises the daemon).
    ("corerouter-init", 6),
    ("corerouter-gui", 6),
    ("corerouter-cli", 6),
    ("xtask", 7),
];

/// Allowed same-layer edges, each with its reason.
pub const SIDEWAYS_ALLOWED: &[(&str, &str)] = &[
    // The model's CGNAT Layout runs the shared port arithmetic (G2.5b).
    ("corerouter-model", "corerouter-cgnat-map"),
    // MCP's Remote backend speaks the control protocol.
    ("corerouter-mcp", "corerouter-control"),
    // Platform backends implement the L1 traits.
    ("corerouter-hal-linux", "corerouter-hal"),
    // The lab backend records the ruleset it would load (G2.1).
    ("corerouter-hal", "corerouter-firewall"),
    // hal-linux applies the ruleset corerouter-firewall renders (G2.1).
    ("corerouter-hal-linux", "corerouter-firewall"),
    // hal-linux loads the XDP programs and reads their maps (G2.5).
    ("corerouter-hal-linux", "corerouter-dataplane-ebpf-common"),
    // The PPP authenticator reuses the RADIUS MS-CHAP/MPPE arithmetic and
    // the `Mikrotik-Rate-Limit` type of the session descriptor (G4.3a).
    ("corerouter-proto-pppoe", "corerouter-proto-radius"),
    // The FRR driver renders the routing protocols' config (G3.1).
    ("corerouter-hal-frr", "corerouter-proto-bgp"),
];

pub const UI_CRATES: &[&str] = &[
    "egui",
    "eframe",
    "winit",
    "wgpu",
    "egui-wgpu",
    "egui-winit",
    "egui_glow",
    "egui_extras",
    "egui_kittest",
    "rfd",
];
pub const UI_MIN_LAYER: u8 = 5;

pub const PLATFORM_CRATES: &[&str] = &[
    "corerouter-hal-linux",
    "corerouter-hal-frr",
    "corerouter-dataplane-ebpf",
    "corerouter-dataplane-ebpf-common",
];

/// Platform crates a platform crate below the apps may use: the loader and
/// the programs it loads (G2.5).
pub const PLATFORM_ALLOWED: &[(&str, &str)] =
    &[("corerouter-hal-linux", "corerouter-dataplane-ebpf-common")];
pub const APP_LAYER: u8 = 6;
pub const TOOLING_LAYER: u8 = 7;

#[derive(Debug, Clone)]
pub struct Pkg {
    pub name: String,
    pub deps: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Violation {
    Unclassified(String),
    Upward {
        from: String,
        to: String,
        from_layer: u8,
        to_layer: u8,
    },
    Sideways {
        from: String,
        to: String,
        layer: u8,
    },
    UiDep {
        from: String,
        dep: String,
        layer: u8,
    },
    PlatformDep {
        from: String,
        dep: String,
        layer: u8,
    },
    ToolingDep {
        from: String,
        dep: String,
    },
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unclassified(p) => write!(
                f,
                "{p}: crate has no layer; add it to LAYERS in xtask/src/layers.rs"
            ),
            Self::Upward {
                from,
                to,
                from_layer,
                to_layer,
            } => write!(
                f,
                "{from} (L{from_layer}) depends on {to} (L{to_layer}): dependencies must point down"
            ),
            Self::Sideways { from, to, layer } => write!(
                f,
                "{from} -> {to} is sideways within L{layer}; move shared code down or allowlist it"
            ),
            Self::UiDep { from, dep, layer } => write!(
                f,
                "{from} (L{layer}) depends on UI crate {dep}: only L{UI_MIN_LAYER}+ may"
            ),
            Self::PlatformDep { from, dep, layer } => write!(
                f,
                "{from} (L{layer}) depends on platform crate {dep}: only apps (L{APP_LAYER}) may"
            ),
            Self::ToolingDep { from, dep } => {
                write!(
                    f,
                    "{from} is tooling and must not depend on workspace crate {dep}"
                )
            }
        }
    }
}

pub fn layer_of(name: &str) -> Option<u8> {
    LAYERS.iter().find(|(n, _)| *n == name).map(|(_, l)| *l)
}

/// Pure rule check over `cargo metadata` packages (workspace members only).
pub fn check(pkgs: &[Pkg]) -> Vec<Violation> {
    let mut out = Vec::new();
    let is_ws = |n: &str| pkgs.iter().any(|p| p.name == n);
    for p in pkgs {
        let Some(layer) = layer_of(&p.name) else {
            out.push(Violation::Unclassified(p.name.clone()));
            continue;
        };
        for dep in &p.deps {
            // A crate's dev-dependency on itself (to turn on a feature for
            // its own tests) is no edge.
            if *dep == p.name {
                continue;
            }
            if UI_CRATES.contains(&dep.as_str()) && layer < UI_MIN_LAYER {
                out.push(Violation::UiDep {
                    from: p.name.clone(),
                    dep: dep.clone(),
                    layer,
                });
            }
            if PLATFORM_CRATES.contains(&dep.as_str())
                && layer < APP_LAYER
                && !PLATFORM_ALLOWED.contains(&(p.name.as_str(), dep.as_str()))
            {
                out.push(Violation::PlatformDep {
                    from: p.name.clone(),
                    dep: dep.clone(),
                    layer,
                });
            }
            if !is_ws(dep) {
                continue;
            }
            if layer == TOOLING_LAYER {
                out.push(Violation::ToolingDep {
                    from: p.name.clone(),
                    dep: dep.clone(),
                });
                continue;
            }
            let Some(to_layer) = layer_of(dep) else {
                continue; // reported as Unclassified on its own package
            };
            if to_layer > layer {
                out.push(Violation::Upward {
                    from: p.name.clone(),
                    to: dep.clone(),
                    from_layer: layer,
                    to_layer,
                });
            } else if to_layer == layer
                && !SIDEWAYS_ALLOWED.contains(&(p.name.as_str(), dep.as_str()))
            {
                out.push(Violation::Sideways {
                    from: p.name.clone(),
                    to: dep.clone(),
                    layer,
                });
            }
        }
    }
    out
}

/// Parse `cargo metadata --no-deps --format-version 1` (all dependency kinds count).
pub fn parse_metadata(json: &serde_json::Value) -> Vec<Pkg> {
    json.get("packages")
        .and_then(|p| p.as_array())
        .into_iter()
        .flatten()
        .filter_map(|p| {
            let name = p.get("name")?.as_str()?.to_owned();
            let deps = p
                .get("dependencies")
                .and_then(|d| d.as_array())
                .into_iter()
                .flatten()
                .filter_map(|d| d.get("name")?.as_str().map(str::to_owned))
                .collect();
            Some(Pkg { name, deps })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg(name: &str, deps: &[&str]) -> Pkg {
        Pkg {
            name: name.into(),
            deps: deps.iter().map(|d| (*d).to_owned()).collect(),
        }
    }

    fn ws(extra: Pkg) -> Vec<Pkg> {
        let mut v: Vec<Pkg> = LAYERS.iter().map(|(n, _)| pkg(n, &[])).collect();
        v.retain(|p| p.name != extra.name);
        v.push(extra);
        v
    }

    #[test]
    fn clean_graph_passes() {
        let v = ws(pkg(
            "corerouter-engine",
            &["corerouter-model", "corerouter-hal", "serde"],
        ));
        assert!(check(&v).is_empty());
    }

    #[test]
    fn upward_is_flagged() {
        let v = ws(pkg("corerouter-model", &["corerouter-engine"]));
        assert!(matches!(check(&v)[..], [Violation::Upward { .. }]));
    }

    #[test]
    fn sideways_is_flagged_unless_allowed() {
        let v = ws(pkg("corerouter-proto-bgp", &["corerouter-proto-ospf"]));
        assert!(matches!(check(&v)[..], [Violation::Sideways { .. }]));
        let v = ws(pkg(
            "corerouter-mcp",
            &["corerouter-control", "corerouter-engine"],
        ));
        assert!(check(&v).is_empty());
    }

    #[test]
    fn egui_below_ui_is_flagged() {
        let v = ws(pkg("corerouter-engine", &["egui"]));
        assert!(matches!(check(&v)[..], [Violation::UiDep { .. }]));
        let v = ws(pkg("corerouter-model", &["eframe"]));
        assert!(matches!(check(&v)[..], [Violation::UiDep { .. }]));
        let v = ws(pkg("corerouter-ui", &["egui", "corerouter-engine"]));
        assert!(check(&v).is_empty());
    }

    #[test]
    fn platform_crate_only_from_apps() {
        let v = ws(pkg("corerouter-engine", &["corerouter-hal-linux"]));
        assert!(matches!(check(&v)[..], [Violation::PlatformDep { .. }]));
        let v = ws(pkg("corerouter-daemon", &["corerouter-hal-linux"]));
        assert!(check(&v).is_empty());
    }

    #[test]
    fn unclassified_and_tooling() {
        let mut v = ws(pkg("xtask", &["corerouter-model"]));
        v.push(pkg("corerouter-new", &[]));
        let found = check(&v);
        assert!(found.contains(&Violation::Unclassified("corerouter-new".into())));
        assert!(
            found
                .iter()
                .any(|x| matches!(x, Violation::ToolingDep { .. }))
        );
    }
}
