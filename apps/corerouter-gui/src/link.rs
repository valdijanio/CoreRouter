//! `corerouter://[user@]host[:port]` links (G0.28): the desktop opens the GUI
//! with one when a link is clicked (`x-scheme-handler/corerouter` in the
//! `.desktop` file). The link only says where to connect: it goes through
//! the same path as the Connect button, so a router seen for the first time
//! still asks about its certificate. The text comes from any web page or
//! document, so it is hostile: a strict whitelist, bounded, no
//! percent-encoding, never a password.

use corerouter_control::DEFAULT_TLS_PORT;

pub const SCHEME: &str = "corerouter:";

/// Longest link taken (a host name is at most 253 bytes).
const MAX_LINK: usize = 300;
/// Longest login name in a link.
const MAX_USER: usize = 64;

/// Where a link points.
#[derive(Debug, PartialEq, Eq)]
pub struct Link {
    /// As `--connect` takes it: `tls://host:port`, or `host:port` for a
    /// loopback port given in the link (the control channel, local token).
    pub address: String,
    pub user: Option<String>,
}

/// Is this argument a link (and not an option)?
pub fn is_link(arg: &str) -> bool {
    arg.get(..SCHEME.len())
        .is_some_and(|s| s.eq_ignore_ascii_case(SCHEME))
}

/// Parse `corerouter://[user@]host[:port][/]`. Without a port it is the
/// router's TLS port (8729). Errors quote at most 64 characters.
pub fn parse(text: &str) -> Result<Link, String> {
    let shown: String = text.chars().take(64).collect();
    let bad = |why: &str| format!("bad corerouter:// link '{shown}': {why}");
    if text.len() > MAX_LINK {
        return Err(bad("too long"));
    }
    let rest = text
        .get(..SCHEME.len())
        .filter(|s| s.eq_ignore_ascii_case(SCHEME))
        .and_then(|_| text.get(SCHEME.len()..))
        .and_then(|r| r.strip_prefix("//"))
        .ok_or_else(|| bad("expected corerouter://host[:port]"))?;
    // Browsers may add a trailing slash; nothing else after the authority.
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    if rest.contains(['/', '?', '#', '%', '\\']) {
        return Err(bad("only [user@]host[:port], no path, query or encoding"));
    }
    let (user, hostport) = match rest.rsplit_once('@') {
        Some((u, h)) => (Some(u), h),
        None => (None, rest),
    };
    if let Some(u) = user {
        if u.contains(':') {
            return Err(bad("a link never carries a password"));
        }
        if u.is_empty()
            || u.len() > MAX_USER
            || !u
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        {
            return Err(bad("the login name takes letters, digits, '.', '_', '-'"));
        }
    }
    let (host, port) = split_port(hostport).ok_or_else(|| bad("bad port"))?;
    if !valid_host(host) {
        return Err(bad("bad host"));
    }
    let loopback = {
        let bare = host.trim_start_matches('[').trim_end_matches(']');
        bare.eq_ignore_ascii_case("localhost")
            || bare
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    };
    let address = match port {
        // A loopback port named in the link: the local control channel.
        Some(p) if loopback => format!("{host}:{p}"),
        Some(p) => format!("tls://{host}:{p}"),
        None => format!("tls://{host}:{DEFAULT_TLS_PORT}"),
    };
    Ok(Link {
        address,
        user: user.map(str::to_owned),
    })
}

/// `host`, `host:port`, `[v6]` or `[v6]:port`; `None` for a bad port.
fn split_port(text: &str) -> Option<(&str, Option<u16>)> {
    let port = |p: &str| -> Option<u16> {
        // `u16::from_str` takes a leading '+'.
        if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        p.parse().ok().filter(|&n| n != 0)
    };
    if text.starts_with('[') {
        let end = text.find(']')?;
        let (host, after) = text.split_at(end + 1);
        return match after.strip_prefix(':') {
            Some(p) => Some((host, Some(port(p)?))),
            None if after.is_empty() => Some((host, None)),
            None => None,
        };
    }
    match text.rsplit_once(':') {
        Some((host, p)) => Some((host, Some(port(p)?))),
        None => Some((text, None)),
    }
}

/// A DNS name (letters, digits, '-', '.'; no label starting with '-'), an
/// IPv4 address or a bracketed IPv6 address (no zone).
fn valid_host(host: &str) -> bool {
    if let Some(v6) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        return v6.parse::<std::net::Ipv6Addr>().is_ok();
    }
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(text: &str) -> (String, Option<String>) {
        let l = parse(text).unwrap();
        (l.address, l.user)
    }

    #[test]
    fn links_become_connect_addresses() {
        assert_eq!(ok("corerouter://10.0.0.1").0, "tls://10.0.0.1:8729");
        assert_eq!(ok("corerouter://10.0.0.1:9000/").0, "tls://10.0.0.1:9000");
        assert_eq!(ok("CoreRouter://router.lan").0, "tls://router.lan:8729");
        assert_eq!(
            ok("corerouter://[2001:db8::1]:8729").0,
            "tls://[2001:db8::1]:8729"
        );
        assert_eq!(ok("corerouter://[::1]").0, "tls://[::1]:8729");
        // A loopback port: the control channel with the local token.
        assert_eq!(ok("corerouter://127.0.0.1:7979").0, "127.0.0.1:7979");
        assert_eq!(ok("corerouter://localhost").0, "tls://localhost:8729");
        assert_eq!(
            ok("corerouter://noc@10.0.0.1"),
            ("tls://10.0.0.1:8729".into(), Some("noc".into()))
        );
        // Every result is something `--connect` takes.
        for l in [
            "corerouter://a.b",
            "corerouter://[::1]:1",
            "corerouter://x@h:65535",
        ] {
            let addr = parse(l).unwrap().address;
            assert!(corerouter_control::Target::parse(&addr).is_ok(), "{addr}");
        }
    }

    #[test]
    fn hostile_links_are_refused() {
        for bad in [
            "corerouter:10.0.0.1",
            "http://10.0.0.1",
            "corerouter://",
            "corerouter://admin:secret@10.0.0.1",
            "corerouter://10.0.0.1:0",
            "corerouter://10.0.0.1:65536",
            "corerouter://10.0.0.1:+80",
            "corerouter://10.0.0.1:",
            "corerouter://10.0.0.1/x",
            "corerouter://10.0.0.1?cmd=reboot",
            "corerouter://10.0.0.1#x",
            "corerouter://10%2e0.0.1",
            "corerouter://-oProxyCommand=x",
            "corerouter://a..b",
            "corerouter://h ost",
            "corerouter://h;rm",
            "corerouter://[fe80::1%25eth0]",
            "corerouter://[zz]:1",
            "corerouter://[::1]x",
            "corerouter://@h",
            "corerouter://us er@h",
            "corerouter://h\n",
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
        let long = format!("corerouter://{}", "a".repeat(400));
        let err = parse(&long).unwrap_err();
        assert!(err.len() < 160, "error quotes a bounded prefix: {err}");
        assert!(is_link("CORERouter://x") && !is_link("--connect") && !is_link("core"));
    }
}
