//! Connect to a router the way every client should (G0.3): plain TCP only
//! to loopback, TLS to anything else, the certificate pinned on first use,
//! then the login (local token or user + password).

use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use crate::client::Client;
use crate::known_hosts::KnownHosts;
use crate::local_token;

/// Where a router is: `HOST:PORT` or `tls://HOST:PORT`. TLS is forced for
/// any host that is not loopback (no plain text over a network).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub host: String,
    pub port: u16,
    pub tls: bool,
}

impl Target {
    pub fn parse(text: &str) -> Result<Self, String> {
        let bad = || {
            format!(
                "expected HOST:PORT or tls://HOST:PORT, got '{}'",
                text.chars().take(64).collect::<String>()
            )
        };
        let (explicit_tls, rest) = match text.strip_prefix("tls://") {
            Some(r) => (true, r),
            None => (false, text),
        };
        let (host, port) = rest.rsplit_once(':').ok_or_else(bad)?;
        let port: u16 = port.parse().map_err(|_| bad())?;
        if host.is_empty() || host.chars().any(|c| c.is_whitespace() || c == '/') {
            return Err(bad());
        }
        let mut t = Self {
            host: host.to_owned(),
            port,
            tls: explicit_tls,
        };
        t.tls |= !t.is_loopback();
        Ok(t)
    }

    pub fn is_loopback(&self) -> bool {
        let bare = self.host.trim_start_matches('[').trim_end_matches(']');
        let bare = bare.split('%').next().unwrap_or(bare);
        bare.eq_ignore_ascii_case("localhost")
            || bare.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
    }

    /// `HOST:PORT`, the socket address and the known-hosts key.
    pub fn addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.tls {
            write!(f, "tls://{}", self.addr())
        } else {
            f.write_str(&self.addr())
        }
    }
}

/// How to log in once connected.
#[derive(Clone)]
pub enum Login {
    /// The local token file of a loopback port, if this user can read it;
    /// otherwise stay logged out (calls fail with `unauthorized`).
    Auto,
    Password {
        user: String,
        password: String,
    },
    Token(String),
    /// Do not log in (`ping`, `server.info`).
    Nothing,
}

impl fmt::Debug for Login {
    /// Never prints a password or a token.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Auto => f.write_str("Auto"),
            Self::Password { user, .. } => write!(f, "Password {{ user: {user:?}, .. }}"),
            Self::Token(_) => f.write_str("Token(..)"),
            Self::Nothing => f.write_str("Nothing"),
        }
    }
}

/// Decides about a certificate seen for the first time.
pub trait Trust {
    /// `true` to remember `fingerprint` for `target` and go on.
    fn first_use(&mut self, target: &Target, fingerprint: &str) -> bool;
}

/// Never trusts a new certificate (non-interactive clients: the host must
/// already be in known_hosts).
pub struct RefuseNew;

impl Trust for RefuseNew {
    fn first_use(&mut self, _: &Target, _: &str) -> bool {
        false
    }
}

/// Trusts exactly this fingerprint (given on the command line).
pub struct Expect(pub String);

impl Trust for Expect {
    fn first_use(&mut self, _: &Target, fingerprint: &str) -> bool {
        self.0.eq_ignore_ascii_case(fingerprint)
    }
}

/// Why there is no local token for `port`, for error messages.
pub fn local_token_hint(port: u16) -> String {
    match local_token::path(port) {
        Some(p) => format!(
            "no local token readable at {} (run as the operating-system user that runs \
             the router, or log in with a user and password)",
            p.display()
        ),
        None => "no runtime directory for the local token (set COREROUTER_RUNTIME_DIR, \
                 or log in with a user and password)"
            .into(),
    }
}

/// Connect, check the certificate (TLS), and log in.
pub fn dial(
    target: &Target,
    timeout: Duration,
    login: &Login,
    known: &mut KnownHosts,
    trust: &mut dyn Trust,
) -> Result<Client, String> {
    let addr = target.addr();
    let mut client = if target.tls {
        let expected = known.get(&addr).map(str::to_owned);
        let c = Client::connect_tls(&addr, timeout, expected.as_deref())
            .map_err(|e| format!("{target}: {e}"))?;
        if expected.is_none() {
            let fp = c.fingerprint().unwrap_or_default().to_owned();
            if !trust.first_use(target, &fp) {
                return Err(format!(
                    "{target}: certificate {fp} is not trusted (first connection); \
                     nothing was sent"
                ));
            }
            match known.remember(&addr, &fp) {
                Ok(()) => log::info!("{target}: remembered certificate {fp}"),
                Err(e) => log::warn!("{target}: certificate accepted but not saved: {e}"),
            }
        }
        c
    } else if target.host.eq_ignore_ascii_case("localhost") {
        // `localhost` usually resolves to `::1` first, where the router does
        // not listen ([`crate::bind_loopback`]) and any local user could.
        Client::connect(&format!("{}:{}", Ipv4Addr::LOCALHOST, target.port), timeout)?
    } else {
        Client::connect(&addr, timeout)?
    };
    match login {
        Login::Auto if !target.tls => {
            // The token file belongs to the port on 127.0.0.1, the only
            // address the router binds in the clear: never hand it to
            // whatever answers elsewhere (`[::1]`, `127.0.0.2`).
            let ours = client
                .peer()
                .is_some_and(|p| p.ip() == IpAddr::V4(Ipv4Addr::LOCALHOST));
            match local_token::read(target.port) {
                Some(t) if ours => client.set_token(Some(t)),
                Some(_) => log::warn!(
                    "{target}: not {}:{}, where the router listens; the local token \
                     is not sent",
                    Ipv4Addr::LOCALHOST,
                    target.port
                ),
                None => log::debug!("{}", local_token_hint(target.port)),
            }
        }
        Login::Auto | Login::Nothing => {}
        Login::Password { user, password } => {
            client
                .login(user, password)
                .map_err(|e| format!("{target}: {e}"))?;
        }
        Login::Token(t) => client.set_token(Some(t.clone())),
    }
    Ok(client)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets() {
        let t = Target::parse("127.0.0.1:7979").unwrap();
        assert!(!t.tls && t.is_loopback());
        assert_eq!(t.to_string(), "127.0.0.1:7979");
        let t = Target::parse("tls://localhost:8729").unwrap();
        assert!(t.tls);
        assert_eq!(t.addr(), "localhost:8729");
        // A network address is always TLS.
        for remote in ["10.0.0.1:8729", "[fe80::1%2]:8729", "router.lan:8729"] {
            assert!(Target::parse(remote).unwrap().tls, "{remote}");
        }
        assert!(!Target::parse("[::1]:7979").unwrap().tls);
        for bad in ["", "host", ":1", "h:x", "h:70000", "a b:1", "tls://"] {
            assert!(Target::parse(bad).is_err(), "{bad}");
        }
        let l = Login::Password {
            user: "u".into(),
            password: "hunter22".into(),
        };
        assert!(!format!("{l:?}").contains("hunter22"));
    }

    /// Audit (control finding 5): whatever listens on `[::1]:P` (any local
    /// user can bind it; the router binds only 127.0.0.1) never gets the
    /// local token of port P, neither as `[::1]:P` nor as `localhost:P`.
    #[test]
    fn the_local_token_goes_only_to_127_0_0_1() {
        use std::io::{BufRead, BufReader, Write};
        use std::net::TcpListener;
        use std::sync::mpsc;
        let Ok(fake) = TcpListener::bind("[::1]:0") else {
            return; // no IPv6 loopback here
        };
        let port = fake.local_addr().unwrap().port();
        let token = "cd".repeat(32);
        let Ok(file) = local_token::create(port, &token) else {
            return; // no runtime directory
        };
        let (tx, rx) = mpsc::channel::<String>();
        std::thread::spawn(move || {
            for conn in fake.incoming() {
                let Ok(mut conn) = conn else { break };
                let mut line = String::new();
                let _ = BufReader::new(&conn).read_line(&mut line);
                let _ = conn.write_all(b"{\"id\":1,\"ok\":true,\"result\":{\"pong\":true}}\n");
                let _ = tx.send(line);
            }
        });
        let t = Duration::from_secs(2);
        for target in [format!("[::1]:{port}"), format!("localhost:{port}")] {
            let target = Target::parse(&target).unwrap();
            if let Ok(mut c) = dial(
                &target,
                t,
                &Login::Auto,
                &mut KnownHosts::load(std::path::Path::new("/nonexistent/kh")),
                &mut RefuseNew,
            ) {
                let _ = c.call("ping", serde_json::Value::Null);
            }
        }
        let _ = std::fs::remove_file(file);
        let seen: Vec<String> = rx.try_iter().collect();
        assert!(
            !seen.is_empty(),
            "the [::1] test listener was never reached"
        );
        for line in seen {
            assert!(!line.contains(&token), "token sent to [::1]: {line}");
        }
    }
}
