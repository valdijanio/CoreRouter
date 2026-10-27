//! G0.26: third-party tools of the VM lab, declared here and reviewed like
//! code (`cargo xtask vm-lab tools`, `docs/vm-lab.md`). Each `.deb` is
//! pinned to its official URL and SHA-256; apt packages come from Ubuntu's
//! signed archive. The user runs `tools` once per new entry (the app's
//! classifier stops agents from installing downloaded programs); agents
//! run `tools --check`.

/// Where a tool comes from.
pub enum Source {
    /// From the Ubuntu archive of the VM (any version).
    Apt,
    /// A `.deb` from the project's release page, checked against `sha256`.
    Deb {
        url: &'static str,
        sha256: &'static str,
    },
}

pub struct Tool {
    /// The dpkg package name.
    pub package: &'static str,
    /// Required version prefix (`""`: any).
    pub version: &'static str,
    pub source: Source,
    /// What it is for, printed by `tools`.
    pub why: &'static str,
}

pub const TOOLS: &[Tool] = &[
    Tool {
        package: "bngblaster",
        version: "1.0.1",
        source: Source::Deb {
            url: "https://github.com/rtbrick/bngblaster/releases/download/1.0.1/bngblaster-1.0.1-ubuntu-24.04_amd64.deb",
            // Same as GitHub's release digest for the asset.
            sha256: "c51461c288db093e7112cb2c2a67755efe007822c99138701bb1f11c4f5a0faa",
        },
        why: "BNG lab: PPPoE/IPoE subscribers in mass (G4.3g)",
    },
    Tool {
        package: "ppp",
        version: "",
        source: Source::Apt,
        why: "pppd, the reference PPPoE client",
    },
    Tool {
        package: "pppoe",
        version: "",
        source: Source::Apt,
        why: "rp-pppoe (pppoe-server, pppoe-discovery)",
    },
    Tool {
        package: "tcpdump",
        version: "",
        source: Source::Apt,
        why: "captures",
    },
    Tool {
        package: "iperf3",
        version: "",
        source: Source::Apt,
        why: "throughput against the bandwidth test (G6.4)",
    },
    Tool {
        package: "ethtool",
        version: "",
        source: Source::Apt,
        why: "NIC offloads and channels",
    },
    // G3.1: FRR from the project's own repository (Ubuntu's 8.4 predates
    // mgmtd). Hashes from deb.frrouting.org's `Packages` for noble, whose
    // `InRelease` checks against the FRR signing key A90FC36D…AB194DBF.
    Tool {
        package: "libyang3",
        version: "3.13.6",
        source: Source::Deb {
            url: "https://deb.frrouting.org/frr/pool/frr-stable/liby/libyang3/libyang3_3.13.6-1~ubuntu24.04u1_amd64.deb",
            sha256: "03ffcf092652aa41a5f474de2a24902fc21502e2fe1c70ff22c15f7859ad166f",
        },
        why: "YANG library FRR 10 links against",
    },
    Tool {
        package: "frr",
        version: "10.7.1",
        source: Source::Deb {
            url: "https://deb.frrouting.org/frr/pool/frr-stable/f/frr/frr_10.7.1-0~ubuntu24.04.1_amd64.deb",
            sha256: "05d17ad3abe56df9090f6637dfad9cd3fd84987df34ee2cd6e8d6928c730ec4b",
        },
        why: "FRRouting: bgpd/ospfd/zebra/mgmtd driven by hal-frr (G3.1)",
    },
    Tool {
        package: "frr-pythontools",
        version: "10.7.1",
        source: Source::Deb {
            url: "https://deb.frrouting.org/frr/pool/frr-stable/f/frr/frr-pythontools_10.7.1-0~ubuntu24.04.1_all.deb",
            sha256: "c17efa8c84c7f63e63d8352dd90e50fd9c694625a1cf10f8e7261208dd529626",
        },
        why: "frr-reload.py, the baseline hal-frr is measured against (G3.1)",
    },
    // G3.2c: bgpd's RPKI module (`bgpd -M rpki`), with rtrlib from Ubuntu's
    // archive. Hash from the same `Packages` (its SHA-256 matches the
    // signed `InRelease`).
    Tool {
        package: "librtr0t64",
        version: "",
        source: Source::Apt,
        why: "rtrlib, the RPKI-to-Router client bgpd's rpki module links against (G3.2c)",
    },
    Tool {
        package: "frr-rpki-rtrlib",
        version: "10.7.1",
        source: Source::Deb {
            url: "https://deb.frrouting.org/frr/pool/frr-stable/f/frr/frr-rpki-rtrlib_10.7.1-0~ubuntu24.04.1_amd64.deb",
            sha256: "126a1cda9bed1a6f6a7dfca5826dc20ad809326bb372364d7482d9b1ed7cc568",
        },
        why: "bgpd_rpki: origin validation in FRR (G3.2c)",
    },
];

impl Tool {
    /// The `.deb` file name (from its URL).
    pub fn file(&self) -> Option<&'static str> {
        match self.source {
            Source::Deb { url, .. } => url.rsplit('/').next(),
            Source::Apt => None,
        }
    }
}

/// One line per package from `dpkg-query -W -f '${Package} ${db:Status-Status} ${Version}\n'`
/// (a package dpkg never heard of is simply absent).
pub fn missing<'a>(tools: &'a [Tool], dpkg: &str) -> Vec<(&'a Tool, Option<String>)> {
    tools
        .iter()
        .filter_map(|t| {
            let have = dpkg.lines().find_map(|l| {
                let mut f = l.split_whitespace();
                (f.next() == Some(t.package))
                    .then(|| (f.next().unwrap_or(""), f.next().unwrap_or("")))
            });
            match have {
                Some(("installed", v)) if v.starts_with(t.version) => None,
                Some(("installed", v)) => Some((t, Some(v.to_owned()))),
                _ => Some((t, None)),
            }
        })
        .collect()
}

/// The `dpkg-query` line that `missing` reads.
pub fn query(tools: &[Tool]) -> String {
    let names: Vec<&str> = tools.iter().map(|t| t.package).collect();
    format!(
        "dpkg-query -W -f '${{Package}} ${{db:Status-Status}} ${{Version}}\\n' {} 2>/dev/null; true",
        names.join(" ")
    )
}

/// The root script that installs `targets` (package names, or paths of
/// `.deb`s already copied into the VM), checking each `(sha256, path)`
/// first. No `.deb`, no `sha256sum`: fed nothing, it fails ("no properly
/// formatted checksum lines found", **measured** with iperf3 alone).
pub fn install_script(checks: &[(String, String)], targets: &[String]) -> String {
    let mut s = String::from("set -e\nexport DEBIAN_FRONTEND=noninteractive\n");
    if !checks.is_empty() {
        s.push_str("sha256sum -c --quiet - <<'SUMS'\n");
        for (sha, path) in checks {
            s.push_str(&format!("{sha}  {path}\n"));
        }
        s.push_str("SUMS\n");
    }
    s.push_str("apt-get update -q >/dev/null\n");
    s.push_str(&format!(
        "apt-get install -y -q --no-install-recommends {}\n",
        targets.join(" ")
    ));
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_deb_is_pinned_to_https_and_a_sha256() {
        for t in TOOLS {
            if let Source::Deb { url, sha256 } = t.source {
                assert!(url.starts_with("https://"), "{}", t.package);
                assert!(
                    t.file().is_some_and(|f| f.ends_with(".deb")),
                    "{}",
                    t.package
                );
                assert_eq!(sha256.len(), 64, "{}", t.package);
                assert!(
                    sha256
                        .bytes()
                        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
                );
                assert!(
                    !t.version.is_empty(),
                    "{}: a .deb names its version",
                    t.package
                );
            }
        }
    }

    #[test]
    fn apt_only_installs_skip_the_checksum() {
        let s = install_script(&[], &["iperf3".into()]);
        assert!(!s.contains("sha256sum"), "{s}");
        assert!(s.contains("apt-get install -y -q --no-install-recommends iperf3\n"));
    }

    #[test]
    fn debs_are_checked_before_install() {
        let deb = "/srv/lab/tools/bngblaster-1.0.1-ubuntu-24.04_amd64.deb";
        let s = install_script(
            &[("ab".repeat(32), deb.into())],
            &[deb.into(), "iperf3".into()],
        );
        let check = s.find("sha256sum -c").unwrap();
        let line = s
            .find(&format!("{}  {deb}\nSUMS\n", "ab".repeat(32)))
            .unwrap();
        let install = s.find("apt-get install").unwrap();
        assert!(check < line && line < install, "{s}");
        assert!(s.contains(&format!("--no-install-recommends {deb} iperf3\n")));
    }

    #[test]
    fn missing_reads_dpkg_query() {
        let dpkg = "bngblaster installed 1.0.1\nppp installed 2.4.9-1+1.1ubuntu3\n\
                    pppoe config-files 3.15-1\ntcpdump installed 4.99.4-3ubuntu4\n\
                    ethtool installed 1:6.7-1build1\n\
                    libyang3 installed 3.13.6-1~ubuntu24.04u1\n\
                    frr installed 10.7.1-0~ubuntu24.04.1\n";
        let names: Vec<&str> = missing(TOOLS, dpkg)
            .iter()
            .map(|(t, _)| t.package)
            .collect();
        assert_eq!(
            names,
            [
                "pppoe",
                "iperf3",
                "frr-pythontools",
                "librtr0t64",
                "frr-rpki-rtrlib"
            ]
        );
        let old = missing(TOOLS, "bngblaster installed 0.9.30\n");
        let (t, have) = old.first().unwrap();
        assert_eq!((t.package, have.as_deref()), ("bngblaster", Some("0.9.30")));
    }
}
