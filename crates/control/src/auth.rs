//! Login and session tokens of the control channel (G0.3).
//!
//! Every request except `ping`, `server.info` and `auth.login` carries a
//! `"token"` next to `id`/`method`/`params` (never in a URL). A token is
//! either:
//!
//! - a **session token** from `auth.login {user, password}`: 32 random
//!   bytes, kept here only as its SHA-256, ended by `auth.logout`, by
//!   [`Limits::idle`] without use, by [`Limits::lifetime`], or when the
//!   account is disabled, removed or gets a new password;
//! - the **local token** ([`crate::local_token`]): written at start-up to a
//!   file only the operating-system user running the router can read; it
//!   acts as [`Principal::Local`] (group full). It is how the CLI and the
//!   MCP server on the same machine work without a password.
//!
//! **No password yet (G0.3b, RouterOS 7 style).** The first `admin` has no
//! password. It logs in with an empty one, but only from loopback; and
//! while any enabled account of group `full` has no password, every login
//! from a non-loopback address is refused with [`NO_PASSWORD_REMOTE`], so a
//! fresh router cannot be taken over from the network. The local token is
//! not affected.
//!
//! Tokens are compared in constant time. Failed logins are counted per
//! source address and per user name: after [`Limits::free_failures`] each
//! new attempt waits longer ([`Limits::base_delay`] doubling up to
//! [`Limits::max_delay`]), and an address with [`Limits::block_after`]
//! failures in [`Limits::window`] is refused outright until the window
//! passes. Every failure gives the same message, [`INVALID_LOGIN`], and an
//! unknown user costs the same Argon2 time as a wrong password.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use corerouter_engine::auth::{MAX_PASSWORD, burn_verification, verify_password};
use corerouter_engine::{Caller, Principal};
use ring::digest::{SHA256, digest};
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::{Value, json};

use crate::dispatch::Host;

/// Prefix of every authentication error, so clients can tell "log in
/// again" apart from a refused command.
pub const UNAUTHORIZED: &str = "unauthorized";
/// The one answer to a failed login, whatever the cause.
pub const INVALID_LOGIN: &str = "invalid user or password";
/// The answer to a network login while an account of group `full` has no
/// password (G0.3b). Clients stop retrying on it.
pub const NO_PASSWORD_REMOTE: &str = "login from the network is refused while an account of \
     group full has no password: set the admin password first (on the router itself, \
     e.g. `corerouter-cli shell` or the GUI at 127.0.0.1, or user.set)";
/// Most tokens held at once (the oldest session token goes first).
pub const MAX_TOKENS: usize = 256;
/// Most tracked sources of failed logins.
const MAX_TRACKED: usize = 4096;

#[derive(Debug, Clone)]
pub struct Limits {
    /// A session token unused this long ends.
    pub idle: Duration,
    /// A session token ends this long after the login, used or not.
    pub lifetime: Duration,
    /// Failures without delay (typos).
    pub free_failures: u32,
    pub base_delay: Duration,
    pub max_delay: Duration,
    /// Failures from one address that block it for the rest of the window.
    pub block_after: u32,
    /// How long failures are remembered.
    pub window: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            idle: Duration::from_secs(30 * 60),
            lifetime: Duration::from_secs(12 * 3600),
            free_failures: 3,
            base_delay: Duration::from_millis(250),
            max_delay: Duration::from_secs(8),
            block_after: 20,
            window: Duration::from_secs(15 * 60),
        }
    }
}

struct Token {
    digest: [u8; 32],
    principal: Principal,
    /// Entry in the session's `user.active.list` (session tokens only).
    login: Option<u64>,
    created: Instant,
    used: Instant,
}

#[derive(Default)]
struct Failures {
    count: u32,
    last: Option<Instant>,
}

struct Inner {
    tokens: Mutex<Vec<Token>>,
    failures: Mutex<HashMap<String, Failures>>,
    limits: Limits,
}

/// Shared by every connection of a router (TCP, TLS and WebSocket).
#[derive(Clone)]
pub struct Gate(Arc<Inner>);

impl Default for Gate {
    fn default() -> Self {
        Self::new(Limits::default())
    }
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn sha256(token: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(digest(&SHA256, token.as_bytes()).as_ref());
    out
}

/// Equal-length comparison that looks at every byte.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// `n` random bytes from the operating system, as lowercase hex.
pub fn random_hex(n: usize) -> Result<String, String> {
    let mut buf = vec![0u8; n];
    SystemRandom::new()
        .fill(&mut buf)
        .map_err(|_| "no random source".to_owned())?;
    Ok(buf.iter().map(|b| format!("{b:02x}")).collect())
}

/// A fresh token (256 bits).
pub fn new_token() -> Result<String, String> {
    random_hex(32)
}

fn unauthorized(why: &str) -> String {
    format!("{UNAUTHORIZED}: {why}")
}

/// `{user, password}`, nothing else. Errors never echo the password.
fn login_params(p: &Value) -> Result<(&str, &str), String> {
    const USAGE: &str = "auth.login needs {user: string, password: string}";
    let o = p.as_object().ok_or(USAGE)?;
    if o.keys().any(|k| k != "user" && k != "password") {
        return Err(USAGE.into());
    }
    let user = o.get("user").and_then(Value::as_str).ok_or(USAGE)?;
    let password = o.get("password").and_then(Value::as_str).ok_or(USAGE)?;
    Ok((user, password))
}

impl Gate {
    pub fn new(limits: Limits) -> Self {
        Self(Arc::new(Inner {
            tokens: Mutex::new(Vec::new()),
            failures: Mutex::new(HashMap::new()),
            limits,
        }))
    }

    /// Accept `token` as [`Principal::Local`] until the process ends.
    pub fn add_local_token(&self, token: &str) {
        let now = Instant::now();
        lock(&self.0.tokens).push(Token {
            digest: sha256(token),
            principal: Principal::Local,
            login: None,
            created: now,
            used: now,
        });
    }

    /// `auth.login`: check the password (outside the session lock) and
    /// hand out a session token.
    pub fn login(
        &self,
        host: &mut dyn Host,
        caller: &Caller,
        peer: Option<IpAddr>,
        params: &Value,
    ) -> Result<Value, String> {
        let (user, password) = login_params(params)?;
        let loopback = peer.is_some_and(|p| p.is_loopback());
        if !loopback {
            let missing = host
                .with_session(&mut |s| Ok(Value::from(s.admins_without_password())))
                .ok()
                .and_then(|v| v.as_array().map(Vec::len))
                .unwrap_or(0);
            if missing > 0 {
                log::warn!(
                    "control: network login for {:?} from {} refused: an account of group \
                     full has no password",
                    user.chars().take(64).collect::<String>(),
                    peer.map(|p| p.to_string()).unwrap_or_else(|| "?".into()),
                );
                return Err(NO_PASSWORD_REMOTE.into());
            }
        }
        let keys = [
            format!("ip {}", peer.map(|p| p.to_string()).unwrap_or_default()),
            format!("user {}", user.chars().take(64).collect::<String>()),
        ];
        let delay = self.delay_for(&keys)?;
        if !delay.is_zero() {
            thread::sleep(delay);
        }
        let stored = if user.len() > 64 || password.len() > MAX_PASSWORD {
            Value::Null
        } else {
            let user = user.to_owned();
            host.with_session(&mut |s| {
                Ok(match s.password_hash(&user) {
                    Some(h) => Value::from(h),
                    None => Value::Bool(s.has_no_password(&user)),
                })
            })
            .unwrap_or(Value::Null)
        };
        let ok = match &stored {
            Value::String(h) => verify_password(h, password),
            // An account without a password: the empty one, from loopback.
            Value::Bool(true) if loopback => password.is_empty(),
            _ => {
                burn_verification(password);
                false
            }
        };
        if !ok {
            self.failed(&keys);
            log::warn!(
                "control: failed login for {:?} from {} ({})",
                user.chars().take(64).collect::<String>(),
                peer.map(|p| p.to_string()).unwrap_or_else(|| "?".into()),
                caller.name
            );
            return Err(INVALID_LOGIN.into());
        }
        self.succeeded(&keys);
        let token = new_token()?;
        let name = user.to_owned();
        let via = caller.name.clone();
        let login = host
            .with_session(&mut |s| Ok(Value::from(s.login_begin(&name, &via))))?
            .as_u64();
        let group = host
            .with_session(&mut |s| {
                Ok(s.group_of(&Principal::User(name.clone()))
                    .map_or(Value::Null, |g| Value::from(g.as_str())))
            })
            .unwrap_or(Value::Null);
        let now = Instant::now();
        let dropped = {
            let mut tokens = lock(&self.0.tokens);
            let dropped = self.expire(&mut tokens, now);
            if tokens.len() >= MAX_TOKENS
                && let Some(i) = tokens.iter().position(|t| t.login.is_some())
            {
                tokens.remove(i);
            }
            tokens.push(Token {
                digest: sha256(&token),
                principal: Principal::User(name.clone()),
                login,
                created: now,
                used: now,
            });
            dropped
        };
        end_logins(host, &dropped);
        log::info!("control: '{name}' logged in ({})", caller.name);
        Ok(json!({
            "token": token,
            "user": name,
            "group": group,
            "idle_timeout_secs": self.0.limits.idle.as_secs(),
            "no_password": stored == Value::Bool(true),
        }))
    }

    /// The principal a request with `token` acts as.
    pub fn principal(&self, host: &mut dyn Host, token: Option<&str>) -> Result<Principal, String> {
        let token = token.ok_or_else(|| {
            unauthorized(
                "log in first: auth.login {user, password}, or send the local token \
                 (see docs/control-protocol.md)",
            )
        })?;
        let wanted = sha256(token);
        let now = Instant::now();
        let (found, dropped) = {
            let mut tokens = lock(&self.0.tokens);
            let dropped = self.expire(&mut tokens, now);
            let mut found = None;
            for (i, t) in tokens.iter().enumerate() {
                if ct_eq(&t.digest, &wanted) {
                    found = Some(i);
                }
            }
            let found = found.and_then(|i| {
                let t = tokens.get_mut(i)?;
                t.used = now;
                Some((i, t.principal.clone(), t.login))
            });
            (found, dropped)
        };
        end_logins(host, &dropped);
        let Some((_, principal, login)) = found else {
            return Err(unauthorized("invalid or expired token; log in again"));
        };
        if let Some(id) = login {
            let alive = host
                .with_session(&mut |s| Ok(Value::Bool(s.login_touch(id))))
                .is_ok_and(|v| v == Value::Bool(true));
            if !alive {
                lock(&self.0.tokens).retain(|t| t.login != Some(id));
                return Err(unauthorized(
                    "this session was ended (password changed, user disabled or removed); \
                     log in again",
                ));
            }
        }
        Ok(principal)
    }

    /// `auth.logout`: forget the session token.
    pub fn logout(&self, host: &mut dyn Host, token: Option<&str>) -> Result<Value, String> {
        let Some(token) = token else {
            return Ok(json!({}));
        };
        let wanted = sha256(token);
        let mut ended = Vec::new();
        lock(&self.0.tokens).retain(|t| {
            let hit = t.login.is_some() && ct_eq(&t.digest, &wanted);
            if hit {
                ended.extend(t.login);
            }
            !hit
        });
        end_logins(host, &ended);
        Ok(json!({}))
    }

    /// Drop expired session tokens; their login ids, to end in the session.
    fn expire(&self, tokens: &mut Vec<Token>, now: Instant) -> Vec<u64> {
        let l = &self.0.limits;
        let mut ended = Vec::new();
        tokens.retain(|t| {
            let live = t.login.is_none()
                || (now.duration_since(t.used) < l.idle
                    && now.duration_since(t.created) < l.lifetime);
            if !live {
                ended.extend(t.login);
            }
            live
        });
        ended
    }

    /// How long this attempt waits, or why it is refused.
    fn delay_for(&self, keys: &[String]) -> Result<Duration, String> {
        let l = &self.0.limits;
        let now = Instant::now();
        let mut map = lock(&self.0.failures);
        let mut worst = 0u32;
        for (i, key) in keys.iter().enumerate() {
            let Some(f) = map.get_mut(key) else { continue };
            if f.last.is_some_and(|t| now.duration_since(t) >= l.window) {
                *f = Failures::default();
            }
            if i == 0 && f.count >= l.block_after {
                return Err(format!(
                    "too many failed logins from this address; try again in {} minutes",
                    l.window.as_secs().div_ceil(60)
                ));
            }
            worst = worst.max(f.count);
        }
        let Some(extra) = worst.checked_sub(l.free_failures) else {
            return Ok(Duration::ZERO);
        };
        let factor = 1u32.checked_shl(extra.min(16)).unwrap_or(u32::MAX);
        Ok(l.base_delay.saturating_mul(factor).min(l.max_delay))
    }

    fn failed(&self, keys: &[String]) {
        let now = Instant::now();
        let window = self.0.limits.window;
        let mut map = lock(&self.0.failures);
        if map.len() >= MAX_TRACKED {
            map.retain(|_, f| f.last.is_some_and(|t| now.duration_since(t) < window));
        }
        if map.len() >= MAX_TRACKED {
            // Still full of fresh entries: forget the user-name keys first
            // (cheap to forge), keep the per-address ones.
            map.retain(|k, _| k.starts_with("ip "));
        }
        for key in keys {
            let f = map.entry(key.clone()).or_default();
            f.count = f.count.saturating_add(1);
            f.last = Some(now);
        }
    }

    fn succeeded(&self, keys: &[String]) {
        let mut map = lock(&self.0.failures);
        for key in keys {
            map.remove(key);
        }
    }

    pub fn limits(&self) -> &Limits {
        &self.0.limits
    }
}

fn end_logins(host: &mut dyn Host, ids: &[u64]) {
    if ids.is_empty() {
        return;
    }
    let _ = host.with_session(&mut |s| {
        for id in ids {
            s.login_end(*id);
        }
        Ok(Value::Null)
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_engine::Session;

    fn lab() -> Session {
        let mut s = Session::virtual_lab();
        s.execute(
            "user.add",
            &json!({"name": "admin", "group": "full", "password": "right-password"}),
        )
        .unwrap();
        s
    }

    fn quick() -> Limits {
        Limits {
            base_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(4),
            block_after: 6,
            ..Limits::default()
        }
    }

    fn try_login(gate: &Gate, s: &mut Session, user: &str, pw: &str) -> Result<Value, String> {
        let caller = Caller::new(1, "tcp 10.0.0.9:1");
        gate.login(
            s,
            &caller,
            Some("10.0.0.9".parse().unwrap()),
            &json!({"user": user, "password": pw}),
        )
    }

    #[test]
    fn right_and_wrong_logins() {
        let gate = Gate::new(quick());
        let mut s = lab();
        let ok = try_login(&gate, &mut s, "admin", "right-password").unwrap();
        assert_eq!(ok["group"], "full");
        let token = ok["token"].as_str().unwrap();
        assert_eq!(token.len(), 64);
        assert_eq!(
            gate.principal(&mut s, Some(token)).unwrap(),
            Principal::User("admin".into())
        );
        assert_eq!(s.logins().len(), 1);
        for (u, p) in [("admin", "wrong"), ("ghost", "right-password"), ("", "")] {
            assert_eq!(try_login(&gate, &mut s, u, p).unwrap_err(), INVALID_LOGIN);
        }
        let e = gate
            .principal(&mut s, Some("0".repeat(64).as_str()))
            .unwrap_err();
        assert!(e.starts_with(UNAUTHORIZED), "{e}");
        assert!(
            gate.principal(&mut s, None)
                .unwrap_err()
                .starts_with(UNAUTHORIZED)
        );
        gate.logout(&mut s, Some(token)).unwrap();
        assert!(gate.principal(&mut s, Some(token)).is_err());
        assert!(s.logins().is_empty());
        let bad = gate.login(
            &mut s,
            &Caller::new(1, "x"),
            None,
            &json!({"user": "admin", "password": "right-password", "extra": 1}),
        );
        assert!(!bad.unwrap_err().contains("right-password"));
    }

    #[test]
    fn brute_force_is_slowed_then_blocked() {
        let gate = Gate::new(quick());
        let mut s = lab();
        for _ in 0..6 {
            assert_eq!(
                try_login(&gate, &mut s, "admin", "nope").unwrap_err(),
                INVALID_LOGIN
            );
        }
        // Blocked: even the right password is refused from that address.
        let e = try_login(&gate, &mut s, "admin", "right-password").unwrap_err();
        assert!(e.contains("too many failed logins"), "{e}");
        // Another address gets in (and its success clears the user's count).
        let other = gate.login(
            &mut s,
            &Caller::new(2, "tcp 10.0.0.10:1"),
            Some("10.0.0.10".parse().unwrap()),
            &json!({"user": "admin", "password": "right-password"}),
        );
        assert!(other.is_ok());
        let d = Gate::new(Limits::default());
        d.failed(&["ip a".into(), "user b".into()]);
        assert_eq!(d.delay_for(&["ip a".into()]).unwrap(), Duration::ZERO);
        for _ in 0..4 {
            d.failed(&["ip a".into()]);
        }
        assert_eq!(
            d.delay_for(&["ip a".into()]).unwrap(),
            Duration::from_secs(1),
            "5 failures: 2 past the free ones, 250 ms doubled twice"
        );
    }

    #[test]
    fn tokens_expire_and_end_with_the_account() {
        let gate = Gate::new(Limits {
            idle: Duration::from_millis(50),
            ..quick()
        });
        let mut s = lab();
        let t = try_login(&gate, &mut s, "admin", "right-password").unwrap()["token"]
            .as_str()
            .unwrap()
            .to_owned();
        thread::sleep(Duration::from_millis(80));
        let e = gate.principal(&mut s, Some(&t)).unwrap_err();
        assert!(e.contains("expired"), "{e}");
        assert!(
            s.logins().is_empty(),
            "the expired login left the active list"
        );

        let gate = Gate::new(quick());
        let t = try_login(&gate, &mut s, "admin", "right-password").unwrap()["token"]
            .as_str()
            .unwrap()
            .to_owned();
        s.execute(
            "user.set",
            &json!({"name": "admin", "password": "a-new-password"}),
        )
        .unwrap();
        let e = gate.principal(&mut s, Some(&t)).unwrap_err();
        assert!(e.contains("ended"), "{e}");
    }

    #[test]
    fn no_password_admin_logs_in_from_loopback_only() {
        let gate = Gate::new(quick());
        let mut s = Session::virtual_lab();
        assert!(s.bootstrap_admin(false).is_some());
        s.execute(
            "user.add",
            &json!({"name": "noc", "group": "read", "password": "right-password"}),
        )
        .unwrap();
        let at = |gate: &Gate, s: &mut Session, ip: &str, user: &str, pw: &str| {
            gate.login(
                s,
                &Caller::new(1, format!("tcp {ip}:1")),
                Some(ip.parse().unwrap()),
                &json!({"user": user, "password": pw}),
            )
        };
        let ok = at(&gate, &mut s, "127.0.0.1", "admin", "").unwrap();
        assert_eq!(ok["no_password"], true);
        assert_eq!(ok["group"], "full");
        let ok = at(&gate, &mut s, "::1", "admin", "").unwrap();
        assert_eq!(ok["no_password"], true);
        assert_eq!(
            at(&gate, &mut s, "127.0.0.1", "admin", "anything").unwrap_err(),
            INVALID_LOGIN
        );
        // From the network: refused for everyone while admin has none,
        // before any password check (no failure counted).
        for (u, p) in [("admin", ""), ("noc", "right-password"), ("ghost", "x")] {
            assert_eq!(
                at(&gate, &mut s, "10.0.0.9", u, p).unwrap_err(),
                NO_PASSWORD_REMOTE
            );
        }
        // A read account with a password still logs in locally.
        let noc = at(&gate, &mut s, "127.0.0.1", "noc", "right-password").unwrap();
        assert_eq!(noc["no_password"], false);
        // Once admin has a password, the network is open, and the empty
        // password no longer works anywhere.
        s.execute(
            "user.set",
            &json!({"name": "admin", "password": "a-real-password"}),
        )
        .unwrap();
        assert!(at(&gate, &mut s, "10.0.0.9", "admin", "a-real-password").is_ok());
        assert!(at(&gate, &mut s, "10.0.0.9", "noc", "right-password").is_ok());
        assert_eq!(
            at(&gate, &mut s, "127.0.0.1", "admin", "").unwrap_err(),
            INVALID_LOGIN
        );
        // --reset-admin-password closes the network again.
        s.bootstrap_admin(true);
        assert_eq!(
            at(&gate, &mut s, "10.0.0.9", "admin", "a-real-password").unwrap_err(),
            NO_PASSWORD_REMOTE
        );
        // Unknown peer (no address): treated as the network.
        let e = gate
            .login(
                &mut s,
                &Caller::new(1, "x"),
                None,
                &json!({"user": "admin", "password": ""}),
            )
            .unwrap_err();
        assert_eq!(e, NO_PASSWORD_REMOTE);
    }

    #[test]
    fn local_token_is_full_and_never_expires() {
        let gate = Gate::new(Limits {
            idle: Duration::ZERO,
            ..quick()
        });
        let mut s = lab();
        let t = new_token().unwrap();
        gate.add_local_token(&t);
        assert_eq!(gate.principal(&mut s, Some(&t)).unwrap(), Principal::Local);
        // auth.logout does not end it.
        gate.logout(&mut s, Some(&t)).unwrap();
        assert_eq!(gate.principal(&mut s, Some(&t)).unwrap(), Principal::Local);
        assert!(ct_eq(b"abc", b"abc") && !ct_eq(b"abc", b"abd") && !ct_eq(b"a", b"ab"));
    }

    mod prop {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(64))]

            /// Any params shape: never a panic, never a token, never an echo.
            #[test]
            fn login_params_are_hostile(raw in "\\PC{0,200}", pw in "[a-z]{12,20}") {
                let gate = Gate::new(quick());
                let mut s = lab();
                let caller = Caller::new(1, "x");
                let candidates = [
                    serde_json::from_str::<Value>(&raw).unwrap_or(Value::Null),
                    json!({"user": raw, "password": pw}),
                    json!({"user": "admin", "password": raw}),
                    json!({"user": 1, "password": pw}),
                    json!([raw]),
                ];
                for p in candidates {
                    if let Err(e) = gate.login(&mut s, &caller, None, &p) {
                        prop_assert!(!e.contains(&pw));
                    } else {
                        prop_assert_eq!(&p["password"], &json!("right-password"));
                    }
                }
            }
        }
    }
}
