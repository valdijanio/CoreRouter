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
    fn missing_reads_dpkg_query() {
        let dpkg = "bngblaster installed 1.0.1\nppp installed 2.4.9-1+1.1ubuntu3\n\
                    pppoe config-files 3.15-1\ntcpdump installed 4.99.4-3ubuntu4\n\
                    ethtool installed 1:6.7-1build1\n";
        let names: Vec<&str> = missing(TOOLS, dpkg)
            .iter()
            .map(|(t, _)| t.package)
            .collect();
        assert_eq!(names, ["pppoe", "iperf3"]);
        let old = missing(TOOLS, "bngblaster installed 0.9.30\n");
        let (t, have) = old.first().unwrap();
        assert_eq!((t.package, have.as_deref()), ("bngblaster", Some("0.9.30")));
    }
}
