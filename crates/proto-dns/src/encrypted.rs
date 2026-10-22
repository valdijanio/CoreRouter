//! Encrypted upstream servers (G4.1d): DNS over HTTPS (RFC 8484) and DNS
//! over TLS (RFC 7858). Here only what has no socket: the server address
//! as the operator writes it, and the query as it goes on the wire. The
//! daemon brings TLS and HTTP (`service/dns_secure.rs`).
//!
//! Addresses:
//! - `https://dns.example/dns-query`, `https://1.1.1.1/dns-query`,
//!   `https://[2606:4700:4700::1111]:443/dns-query` (DoH, POST);
//! - `tls://dns.example`, `tls://1.1.1.1:853#one.one.one.one` (DoT; the
//!   name after `#` is the one the certificate must carry, RFC 8310 §6.6,
//!   Unbound's `ip@853#name`; default: the host).

use std::net::IpAddr;

use hickory_proto::op::{Edns, Message, Query};
use hickory_proto::rr::rdata::opt::EdnsOption;
use hickory_proto::rr::{Name, RecordType};

/// RFC 7858 §3.1: DoT's port.
pub const DOT_PORT: u16 = 853;
pub const HTTPS_PORT: u16 = 443;
/// RFC 8467 §4.1: queries padded to a multiple of this.
pub const PAD_BLOCK: usize = 128;
/// RFC 7830 §4: the EDNS(0) Padding option.
const PADDING: u16 = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Proto {
    /// RFC 8484.
    Https,
    /// RFC 7858.
    Tls,
}

/// One encrypted server.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SecureServer {
    pub proto: Proto,
    /// Lowercase name or address literal (without brackets).
    pub host: String,
    pub port: u16,
    /// DoH: the path (with any query); DoT: empty.
    pub path: String,
    /// The name the certificate must carry (the host unless `#name`).
    pub auth_name: String,
    /// Check the certificate (RFC 8310 strict); off: encrypted, any
    /// certificate (still never plain text).
    pub verify: bool,
}

impl SecureServer {
    pub fn parse(url: &str, verify: bool) -> Result<Self, String> {
        let shown: String = url.chars().take(64).collect();
        if let Some(why) = corerouter_model::dns::secure_url_problem(url) {
            return Err(why);
        }
        let (proto, rest) = if let Some(r) = url.strip_prefix("https://") {
            (Proto::Https, r)
        } else if let Some(r) = url.strip_prefix("tls://") {
            (Proto::Tls, r)
        } else {
            return Err(format!("'{shown}' is not https:// or tls://"));
        };
        let (rest, auth) = match (proto, rest.split_once('#')) {
            (Proto::Tls, Some((r, name))) => (r, Some(name.to_ascii_lowercase())),
            (Proto::Https, Some((r, _))) => (r, None),
            (_, None) => (rest, None),
        };
        let (authority, path) = match (proto, rest.find(['/', '?'])) {
            (Proto::Https, Some(i)) => (
                rest.get(..i).unwrap_or_default(),
                rest.get(i..).unwrap_or_default(),
            ),
            (Proto::Https, None) => (rest, "/dns-query"),
            (Proto::Tls, Some(i)) if rest.get(i..) == Some("/") => {
                (rest.get(..i).unwrap_or_default(), "")
            }
            (Proto::Tls, Some(_)) => return Err(format!("'{shown}': tls:// takes no path")),
            (Proto::Tls, None) => (rest, ""),
        };
        let default = match proto {
            Proto::Https => HTTPS_PORT,
            Proto::Tls => DOT_PORT,
        };
        let (host, port) =
            split_host(authority, default).ok_or_else(|| format!("'{shown}': bad host or port"))?;
        if host.is_empty() || host.contains('@') || !host_ok(&host) {
            return Err(format!("'{shown}': bad host"));
        }
        let auth_name = auth.unwrap_or_else(|| host.clone());
        if !host_ok(&auth_name) {
            return Err(format!("'{shown}': bad name after #"));
        }
        let path = if proto == Proto::Https && !path.starts_with('/') {
            format!("/{path}")
        } else {
            path.to_owned()
        };
        Ok(Self {
            proto,
            host,
            port,
            path,
            auth_name,
            verify,
        })
    }

    /// The host as an address, if it is one.
    pub fn ip(&self) -> Option<IpAddr> {
        self.host.parse().ok()
    }

    /// As written back (for errors and status).
    pub fn url(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        match self.proto {
            Proto::Https if self.port == HTTPS_PORT => format!("https://{host}{}", self.path),
            Proto::Https => format!("https://{host}:{}{}", self.port, self.path),
            Proto::Tls => {
                let port = if self.port == DOT_PORT {
                    String::new()
                } else {
                    format!(":{}", self.port)
                };
                let name = if self.auth_name == self.host {
                    String::new()
                } else {
                    format!("#{}", self.auth_name)
                };
                format!("tls://{host}{port}{name}")
            }
        }
    }
}

fn split_host(authority: &str, default: u16) -> Option<(String, u16)> {
    if let Some(v6) = authority.strip_prefix('[') {
        let (h, after) = v6.split_once(']')?;
        let port = match after.strip_prefix(':') {
            Some(p) => p.parse().ok()?,
            None if after.is_empty() => default,
            None => return None,
        };
        return Some((h.to_ascii_lowercase(), port));
    }
    match authority.rsplit_once(':') {
        // A bare IPv6 address has colons and no port.
        Some(_) if authority.parse::<IpAddr>().is_ok() => {
            Some((authority.to_ascii_lowercase(), default))
        }
        Some((h, p)) => Some((h.to_ascii_lowercase(), p.parse().ok()?)),
        None => Some((authority.to_ascii_lowercase(), default)),
    }
}

fn host_ok(h: &str) -> bool {
    h.parse::<IpAddr>().is_ok()
        || (h.len() <= 253
            && h.split('.').all(|l| {
                (1..=63).contains(&l.len())
                    && l.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            }))
}

/// A query for an encrypted server: id 0 (RFC 8484 §4.1: the HTTP
/// exchange already pairs question and answer, and 0 keeps HTTP caches
/// useful), RD set, EDNS(0) with the Padding option so the message is a
/// multiple of 128 bytes (RFC 8467 §4.1: the length tells nothing).
pub fn query(name: &Name, rtype: RecordType, payload: u16) -> Result<Vec<u8>, String> {
    let build = |pad: usize| -> Result<Vec<u8>, String> {
        let mut m = Message::query();
        m.metadata.id = 0;
        m.metadata.recursion_desired = true;
        m.add_query(Query::query(name.clone(), rtype));
        let mut edns = Edns::new();
        edns.set_max_payload(payload.max(512));
        edns.options_mut()
            .insert(EdnsOption::Unknown(PADDING, vec![0; pad]));
        m.set_edns(edns);
        m.to_vec().map_err(|e| e.to_string())
    };
    let bare = build(0)?.len();
    build((PAD_BLOCK - bare % PAD_BLOCK) % PAD_BLOCK)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn addresses() {
        let s = SecureServer::parse("https://Cloudflare-DNS.com/dns-query", true).unwrap();
        assert_eq!(
            (s.proto, s.host.as_str(), s.port, s.path.as_str()),
            (Proto::Https, "cloudflare-dns.com", 443, "/dns-query")
        );
        assert_eq!(s.auth_name, "cloudflare-dns.com");
        let s = SecureServer::parse("https://[2606:4700:4700::1111]:8443/q?x=1", false).unwrap();
        assert_eq!(
            (s.host.as_str(), s.port, s.path.as_str()),
            ("2606:4700:4700::1111", 8443, "/q?x=1")
        );
        assert_eq!(s.ip(), "2606:4700:4700::1111".parse().ok());
        assert_eq!(s.url(), "https://[2606:4700:4700::1111]:8443/q?x=1");
        let s = SecureServer::parse("https://dns.example", true).unwrap();
        assert_eq!(s.path, "/dns-query", "RFC 8484 §6 example path by default");
        let s = SecureServer::parse("tls://1.1.1.1#one.one.one.one", true).unwrap();
        assert_eq!(
            (s.proto, s.port, s.auth_name.as_str()),
            (Proto::Tls, 853, "one.one.one.one")
        );
        assert_eq!(s.url(), "tls://1.1.1.1#one.one.one.one");
        assert_eq!(
            SecureServer::parse("tls://dns.example:8853", true)
                .unwrap()
                .port,
            8853
        );
        for bad in [
            "http://dns.example/",
            "tls://dns.example/path",
            "https:///x",
            "https://user@h/",
            "tls://h:99999",
            "tls://h#bad name",
            "https://bad_host!/",
            "",
        ] {
            assert!(SecureServer::parse(bad, true).is_err(), "{bad}");
        }
    }

    #[test]
    fn queries_are_padded_with_id_zero() {
        for name in ["a.example.", "a-much-longer-name.for.padding.example.com."] {
            let q = query(&Name::from_ascii(name).unwrap(), RecordType::AAAA, 1232).unwrap();
            assert_eq!(q.len() % PAD_BLOCK, 0, "{name}: {}", q.len());
            let m = Message::from_vec(&q).unwrap();
            assert_eq!(m.metadata.id, 0);
            assert!(m.metadata.recursion_desired);
        }
    }

    proptest! {
        #[test]
        fn any_address_is_safe(s in "\\PC{0,80}") {
            if let Ok(srv) = SecureServer::parse(&s, true) {
                prop_assert!(SecureServer::parse(&srv.url(), true).is_ok());
            }
        }
    }
}
