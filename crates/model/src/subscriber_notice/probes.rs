//! The captive-portal probes of each OS (G4.10): the plain-HTTP request a
//! system makes when it joins a network, and what it expects back when the
//! internet works. Anything else makes the OS show "Sign in to network" and
//! open its portal browser, which is what the notice wants: the probe is
//! plain HTTP, so the router answers it with no certificate at all.
//!
//! Data, not code: a system that changes its probe changes one row. Hosts
//! and paths checked on 2026-10-26 (`docs/subscriber-notices.md`).

/// How a probe is answered when the subscriber must see the page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    /// `302 Found` to the portal page. Android counts 200–399 as a
    /// portal and 4xx/5xx as "no internet" (no page), so a probe never
    /// gets 511.
    Redirect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Probe {
    /// The OS family, as the Test result and the log show it.
    pub os: &'static str,
    /// The `Host` of the request (lower case, no port).
    pub host: &'static str,
    /// The path the OS asks for (`*`: any path on that host).
    pub path: &'static str,
    /// What the OS gets from the real server ("internet ok").
    pub expects: &'static str,
    pub answer: Answer,
}

const fn p(os: &'static str, host: &'static str, path: &'static str, expects: &'static str) -> Probe {
    Probe {
        os,
        host,
        path,
        expects,
        answer: Answer::Redirect,
    }
}

/// Every probe the router knows, most common first.
pub const PROBES: &[Probe] = &[
    // AOSP NetworkMonitor: the HTTP probe and its fallbacks.
    p("android", "connectivitycheck.gstatic.com", "/generate_204", "204"),
    p("android", "www.google.com", "/gen_204", "204"),
    p("android", "play.googleapis.com", "/generate_204", "204"),
    p("android", "connectivitycheck.android.com", "/generate_204", "204"),
    p("chromeos", "clients3.google.com", "/generate_204", "204"),
    p("chromeos", "clients1.google.com", "/generate_204", "204"),
    p("samsung", "connectivitycheck.samsung.com", "/generate_204", "204"),
    p("xiaomi", "connect.rom.miui.com", "/generate_204", "204"),
    p("huawei", "connectivitycheck.platform.hicloud.com", "/generate_204", "204"),
    // Apple CaptiveNetworkSupport (iOS, iPadOS, macOS).
    p("apple", "captive.apple.com", "*", "200 Success"),
    p("apple", "www.apple.com", "/library/test/success.html", "200 Success"),
    // Windows NCSI (active probe; the DNS check is never touched).
    p("windows", "www.msftconnecttest.com", "*", "200 Microsoft Connect Test"),
    p("windows", "ipv6.msftconnecttest.com", "*", "200 Microsoft Connect Test"),
    p("windows", "www.msftncsi.com", "/ncsi.txt", "200 Microsoft NCSI"),
    p("firefox", "detectportal.firefox.com", "*", "200 success"),
    // NetworkManager (each distribution's connectivity URI).
    p("linux", "fedoraproject.org", "/static/hotspot.txt", "200 OK"),
    p("linux", "connectivity-check.ubuntu.com", "*", "204"),
    p("linux", "ping.archlinux.org", "/nm-check.txt", "200 NetworkManager is online"),
    p("linux", "nmcheck.gnome.org", "/check_network_status.txt", "200 NetworkManager is online"),
    p("linux", "networkcheck.kde.org", "*", "200 OK"),
    p("linux", "network-test.debian.org", "/nm", "200 NetworkManager is online"),
];

/// The probe a request is, if any (`host` without the port, any case).
pub fn probe_of(host: &str, path: &str) -> Option<&'static Probe> {
    let host = host.split(':').next().unwrap_or(host);
    PROBES.iter().find(|p| {
        p.host.eq_ignore_ascii_case(host)
            && (p.path == "*" || path.split('?').next().is_some_and(|x| x == p.path))
    })
}

/// The probe host names, once each (what the router resolves to keep the
/// probe addresses).
pub fn hosts() -> Vec<&'static str> {
    let mut h: Vec<&'static str> = PROBES.iter().map(|p| p.host).collect();
    h.sort_unstable();
    h.dedup();
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_probes_are_found() {
        assert_eq!(probe_of("connectivitycheck.gstatic.com", "/generate_204").map(|p| p.os), Some("android"));
        assert_eq!(probe_of("Captive.Apple.com:80", "/hotspot-detect.html").map(|p| p.os), Some("apple"));
        assert_eq!(probe_of("www.msftconnecttest.com", "/connecttest.txt").map(|p| p.os), Some("windows"));
        assert_eq!(probe_of("detectportal.firefox.com", "/canonical.html").map(|p| p.os), Some("firefox"));
        assert_eq!(probe_of("nmcheck.gnome.org", "/check_network_status.txt?x=1").map(|p| p.os), Some("linux"));
        // A Google page that is not the probe is ordinary HTTP.
        assert_eq!(probe_of("www.google.com", "/search"), None);
        assert_eq!(probe_of("example.com", "/generate_204"), None);
    }

    #[test]
    fn hosts_are_unique_and_lower_case() {
        let h = hosts();
        assert!(h.len() >= 18);
        assert!(h.iter().all(|x| x.bytes().all(|b| !b.is_ascii_uppercase())));
    }
}
