//! Web access (G1.6o): `ip.service.www-ssl.*` and `ip.service.www.*`, the
//! RouterOS WebFig model. `www-ssl` serves the GUI built for the browser
//! (`--web-files`, the `trunk build` output) and the control channel over
//! WebSocket on one TLS port, with the router's own certificate (the one of
//! `--listen`); every request still needs a login, as on the TLS control
//! port. `www` is plain HTTP that only answers `301` to `https://<host>/`:
//! a password never travels in clear text.
//!
//! The body follows the running config: a change closes the listener and
//! opens the new one, so `ip.service.www-ssl.set port=8443` works without a
//! restart (connections already open stay up: changing the service never
//! cuts the operator who changed it). A bind that fails (a port in use, or
//! 443 without `CAP_NET_BIND_SERVICE`) is retried every tick and reported
//! once, in the log and in `last_error`.
//!
//! `--web-factory-on` (the router image passes it): a config made at this
//! start (none saved yet) gets `www-ssl` on, so a new router answers at
//! `https://<address>/` out of the box while an updated one keeps what it
//! had.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use corerouter_control::tls::ServerIdentity;
use corerouter_control::{Allow, Endpoint, Gate, SharedHost, Shutdown, WsPolicy, spawn_ws_until};
use corerouter_engine::{Shared, lock};
use corerouter_model::service::Listen;
use corerouter_model::web::{WebListener, WebListenerStatus, WebService, WebState, WebStatus};
use serde_json::json;

pub(crate) const SERVICE: super::Service = super::Service {
    name: "web",
    flags: &[
        super::Flag {
            name: "--web-files",
            value: Some("<dir>"),
            help: "the web GUI (`trunk build` -> dist/) that ip.service www-ssl serves\nat https://<router>/; without it that port only speaks WebSocket",
        },
        super::Flag {
            name: "--web-factory-on",
            value: None,
            help: "a config made at this start (none saved yet) gets ip.service www-ssl\nenabled=yes (the router image's factory default)",
        },
    ],
    topic: "system",
    enable: "ip.service.www-ssl.set enabled=yes",
    depends: &[],
    start,
};

/// How often the body looks at the running config.
const TICK: Duration = Duration::from_secs(1);
/// How often the redirect listener looks for a connection (and its stop).
const ACCEPT_POLL: Duration = Duration::from_millis(50);
/// Redirect connections answered at once; more are dropped.
const MAX_REDIRECTS: usize = 16;
/// Longest request head the redirect reads, and the time it gets.
const MAX_HEAD: usize = 8 * 1024;
const REDIRECT_TIME: Duration = Duration::from_secs(5);

/// What the body needs, from `start`.
#[derive(Clone)]
struct Env {
    session: Shared,
    gate: Gate,
    tls: Option<ServerIdentity>,
    config_dir: Option<PathBuf>,
    files: Option<PathBuf>,
}

fn start(ctx: &super::Ctx) -> Result<super::Run, String> {
    // A missing GUI must not stop the router (the daemon is its network):
    // the port then only speaks WebSocket, and the row says why.
    let files = ctx.flag("--web-files").map(PathBuf::from).filter(|dir| {
        let ok = dir.join("index.html").is_file();
        if !ok {
            log::error!(
                "--web-files {}: no index.html; https:// serves no GUI (only the WebSocket)",
                dir.display()
            );
        }
        ok
    });
    if ctx.flag("--web-factory-on").is_some() {
        factory_default(&ctx.session);
    }
    let env = Env {
        session: ctx.session.clone(),
        gate: ctx.remote_gate.clone(),
        tls: ctx.tls.clone(),
        config_dir: ctx.config_dir.clone(),
        files,
    };
    Ok(Box::new(move |health: &super::Health| {
        run(&env, health);
        Ok(())
    }))
}

/// `www-ssl` on for a config that was never saved (a new router).
fn factory_default(session: &Shared) {
    let mut s = lock(session);
    if s.storage_status().loaded_from.is_some() {
        return;
    }
    match s.execute("ip.service.www-ssl.set", &json!({"enabled": true})) {
        Ok(_) => log::info!("new config: web access on (ip.service www-ssl, port 443)"),
        Err(e) => log::warn!("new config: web access not turned on: {e}"),
    }
}

/// An open listener of one row.
struct Open {
    at: SocketAddr,
    refused: Arc<AtomicU64>,
    stop: Stop,
}

enum Stop {
    Ws(Shutdown),
    Redirect(Arc<AtomicBool>),
}

impl Open {
    fn close(self) {
        match self.stop {
            Stop::Ws(s) => s.close(),
            Stop::Redirect(flag) => flag.store(true, Ordering::Release),
        }
    }
}

fn counter(l: &WebListener) -> (Arc<AtomicU64>, Option<Allow>) {
    let refused = Arc::new(AtomicU64::new(0));
    if l.available_from.is_empty() {
        return (refused, None);
    }
    let (cfg, count) = (l.clone(), refused.clone());
    let allow: Allow = Arc::new(move |ip| {
        let ok = cfg.allows(ip);
        if !ok {
            count.fetch_add(1, Ordering::Relaxed);
        }
        ok
    });
    (refused, Some(allow))
}

/// The router's certificate: the daemon's, or the one in the config dir
/// (made there if missing), or one for this run only.
fn identity(env: &Env) -> Result<ServerIdentity, String> {
    if let Some(id) = &env.tls {
        return Ok(id.clone());
    }
    match &env.config_dir {
        Some(dir) => corerouter_control::tls::load_or_create(dir).map(|(id, _)| id),
        None => {
            let (cert, key) = corerouter_control::tls::generate()?;
            corerouter_control::tls::identity_from_pem(cert.as_bytes(), key.as_bytes())
        }
    }
}

fn open_ssl(env: &Env, l: &WebListener, id: &ServerIdentity) -> Result<Open, String> {
    let addr = SocketAddr::new(l.address, l.port);
    let listener = TcpListener::bind(addr).map_err(|e| bind_error(addr, &e))?;
    let at = listener.local_addr().unwrap_or(addr);
    let (refused, allow) = counter(l);
    let mut endpoint = Endpoint::tls(listener, id.config.clone());
    if let Some(a) = allow {
        endpoint = endpoint.with_allow(a);
    }
    let stop = Shutdown::default();
    let policy = WsPolicy {
        origins: Vec::new(),
        web_root: env.files.clone(),
        same_host: true,
    };
    spawn_ws_until(
        endpoint,
        SharedHost(env.session.clone()),
        policy,
        env.gate.clone(),
        stop.clone(),
    )
    .map_err(|e| format!("cannot start the www-ssl thread: {e}"))?;
    match &env.files {
        Some(dir) => log::info!("web GUI at https://{at}/ (files in {})", dir.display()),
        None => log::info!("WebSocket over TLS at wss://{at}/ws (no GUI files)"),
    }
    Ok(Open {
        at,
        refused,
        stop: Stop::Ws(stop),
    })
}

fn open_redirect(health: &super::Health, l: &WebListener, ssl_port: u16) -> Result<Open, String> {
    let addr = SocketAddr::new(l.address, l.port);
    let listener = TcpListener::bind(addr).map_err(|e| bind_error(addr, &e))?;
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("{addr}: {e}"))?;
    let at = listener.local_addr().unwrap_or(addr);
    let (refused, allow) = counter(l);
    let stop = Arc::new(AtomicBool::new(false));
    let (flag, h) = (stop.clone(), health.clone());
    health
        .spawn("www-redirect", move || {
            redirect_loop(&listener, allow.as_ref(), ssl_port, &flag, &h);
        })
        .map_err(|e| format!("cannot start the www thread: {e}"))?;
    log::info!("http://{at}/ redirects to https:// (port {ssl_port})");
    Ok(Open {
        at,
        refused,
        stop: Stop::Redirect(stop),
    })
}

fn bind_error(addr: SocketAddr, e: &std::io::Error) -> String {
    if e.kind() == std::io::ErrorKind::PermissionDenied {
        format!("cannot listen on {addr}: {e} (a port below 1024 needs CAP_NET_BIND_SERVICE)")
    } else {
        format!("cannot listen on {addr}: {e}")
    }
}

fn run(env: &Env, health: &super::Health) {
    let mut cfg: Option<WebService> = None;
    let (mut ssl, mut plain): (Option<Open>, Option<Open>) = (None, None);
    let mut status = WebStatus {
        gui_files: env.files.is_some(),
        ..WebStatus::default()
    };
    let mut id: Option<ServerIdentity> = None;
    while !health.stopping() {
        health.beat();
        let now = lock(&env.session).store().running().system.web.clone();
        health.disabled(
            (!now.www_ssl.enabled && !now.www.enabled).then_some("ip.service www-ssl and www enabled=no"),
        );
        let changed = cfg.as_ref() != Some(&now);
        if changed {
            if let Some(o) = ssl.take() {
                o.close();
            }
            if let Some(o) = plain.take() {
                o.close();
            }
            status.www_ssl = WebListenerStatus::default();
            status.www = WebListenerStatus::default();
        }
        if now.www_ssl.enabled && ssl.is_none() {
            let opened = match &id {
                Some(i) => Ok(i.clone()),
                None => identity(env).inspect(|i| id = Some(i.clone())),
            }
            .and_then(|i| retry(changed, || open_ssl(env, &now.www_ssl, &i)));
            ssl = note(opened, &mut status.www_ssl, "www-ssl");
        }
        if now.www.enabled && plain.is_none() {
            let opened = retry(changed, || open_redirect(health, &now.www, now.www_ssl.port));
            plain = note(opened, &mut status.www, "www");
        }
        for (open, st) in [(&ssl, &mut status.www_ssl), (&plain, &mut status.www)] {
            if let Some(o) = open {
                st.refused = o.refused.load(Ordering::Relaxed);
            }
        }
        let at: Vec<Listen> = [(&ssl, "https"), (&plain, "http")]
            .into_iter()
            .filter_map(|(o, kind)| o.as_ref().map(|o| Listen::new(kind, o.at)))
            .collect();
        health.listen(at);
        match status.www_ssl.last_error.as_ref().or(status.www.last_error.as_ref()) {
            Some(e) => health.error(e),
            None => health.clear_error(),
        }
        publish(&env.session, &status);
        cfg = Some(now);
        health.sleep(TICK);
    }
    for o in [ssl, plain].into_iter().flatten() {
        o.close();
    }
    publish(
        &env.session,
        &WebStatus {
            gui_files: env.files.is_some(),
            ..WebStatus::default()
        },
    );
}

/// Right after a change the old listener of the same port may still be
/// closing: one more try a moment later before reporting an error.
fn retry(changed: bool, mut f: impl FnMut() -> Result<Open, String>) -> Result<Open, String> {
    match f() {
        Err(_) if changed => {
            thread::sleep(Duration::from_millis(200));
            f()
        }
        r => r,
    }
}

fn note(opened: Result<Open, String>, st: &mut WebListenerStatus, row: &str) -> Option<Open> {
    match opened {
        Ok(o) => {
            st.status = WebState::Listening;
            st.listening = Some(o.at.to_string());
            st.last_error = None;
            Some(o)
        }
        Err(e) => {
            if st.last_error.as_ref() != Some(&e) {
                log::error!("ip.service {row}: {e}");
            }
            st.status = WebState::Error;
            st.listening = None;
            st.last_error = Some(e);
            None
        }
    }
}

fn publish(session: &Shared, status: &WebStatus) {
    let mut s = lock(session);
    if s.ext::<WebStatus>() != Some(status)
        && let Some(st) = s.ext_mut::<WebStatus>()
    {
        *st = status.clone();
    }
}

fn redirect_loop(
    listener: &TcpListener,
    allow: Option<&Allow>,
    ssl_port: u16,
    stop: &AtomicBool,
    health: &super::Health,
) {
    let active = Arc::new(AtomicUsize::new(0));
    while !stop.load(Ordering::Acquire) && !health.stopping() {
        let (stream, peer) = match listener.accept() {
            Ok(c) => c,
            Err(e) => {
                if e.kind() != std::io::ErrorKind::WouldBlock {
                    log::debug!("www: accept failed: {e}");
                }
                thread::sleep(ACCEPT_POLL);
                continue;
            }
        };
        if allow.is_some_and(|a| !a(peer.ip())) {
            continue;
        }
        if active.fetch_add(1, Ordering::AcqRel) >= MAX_REDIRECTS {
            active.fetch_sub(1, Ordering::AcqRel);
            log::debug!("www: {peer} dropped, {MAX_REDIRECTS} redirects in progress");
            continue;
        }
        let count = active.clone();
        let spawned = thread::Builder::new()
            .name("www-conn".into())
            .spawn(move || {
                if let Err(e) = redirect(stream, ssl_port) {
                    log::debug!("www: {peer}: {e}");
                }
                count.fetch_sub(1, Ordering::AcqRel);
            });
        if let Err(e) = spawned {
            active.fetch_sub(1, Ordering::AcqRel);
            log::warn!("www: cannot spawn a connection thread: {e}");
        }
    }
}

/// Read the request head (bounded in size and time) and answer `301` to
/// the same host over HTTPS.
fn redirect(mut stream: TcpStream, ssl_port: u16) -> std::io::Result<()> {
    stream.set_nonblocking(false)?;
    let until = Instant::now() + REDIRECT_TIME;
    stream.set_write_timeout(Some(REDIRECT_TIME))?;
    let mut head = Vec::with_capacity(1024);
    let mut buf = [0u8; 1024];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
        let left = until.saturating_duration_since(Instant::now());
        if left.is_zero() || head.len() >= MAX_HEAD {
            return Ok(());
        }
        stream.set_read_timeout(Some(left))?;
        let n = stream.read(&mut buf)?;
        if n == 0 {
            return Ok(());
        }
        head.extend_from_slice(buf.get(..n).unwrap_or_default());
    }
    let local = stream.local_addr()?.ip();
    let host = host_header(&head).unwrap_or_else(|| ip_host(local));
    let location = location(&host, ssl_port);
    let reply = format!(
        "HTTP/1.1 301 Moved Permanently\r\nLocation: {location}\r\n\
         Content-Length: 0\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(reply.as_bytes())?;
    stream.flush()
}

fn location(host: &str, port: u16) -> String {
    if port == 443 {
        format!("https://{host}/")
    } else {
        format!("https://{host}:{port}/")
    }
}

fn ip_host(ip: IpAddr) -> String {
    match ip.to_canonical() {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => format!("[{v6}]"),
    }
}

/// The host part of the `Host` header, if it is a plain name or address
/// (the browser's own; anything odd falls back to the local address, so
/// nothing a client sends ends up in another header).
fn host_header(head: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(head).ok()?;
    let value = text.split("\r\n").skip(1).find_map(|line| {
        let (k, v) = line.split_once(':')?;
        k.trim().eq_ignore_ascii_case("host").then(|| v.trim())
    })?;
    if value.is_empty()
        || value.len() > 255
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']'))
    {
        return None;
    }
    if let Some(rest) = value.strip_prefix('[') {
        let (inner, _) = rest.split_once(']')?;
        return inner.parse::<std::net::Ipv6Addr>().ok().map(|_| format!("[{inner}]"));
    }
    let name = match value.split_once(':') {
        Some((name, port)) if port.bytes().all(|b| b.is_ascii_digit()) => name,
        Some(_) => return None,
        None => value,
    };
    (!name.is_empty() && !name.contains(['[', ']'])).then(|| name.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_header_keeps_only_a_clean_host() {
        let h = |s: &str| host_header(format!("GET / HTTP/1.1\r\n{s}\r\n\r\n").as_bytes());
        assert_eq!(h("Host: 192.0.2.1").as_deref(), Some("192.0.2.1"));
        assert_eq!(h("host: router.lan:80").as_deref(), Some("router.lan"));
        assert_eq!(h("Host: [2001:db8::1]:80").as_deref(), Some("[2001:db8::1]"));
        assert_eq!(h("Host: evil\r\nX: y").as_deref(), Some("evil"));
        assert_eq!(h("Host: a b"), None);
        assert_eq!(h("Host: a/b"), None);
        assert_eq!(h("Host: [nope]"), None);
        assert_eq!(h("Host: a:b"), None);
        assert_eq!(h("X: y"), None);
        assert_eq!(location("192.0.2.1", 443), "https://192.0.2.1/");
        assert_eq!(location("[::1]", 8443), "https://[::1]:8443/");
        assert_eq!(ip_host("::ffff:10.0.0.1".parse().unwrap()), "10.0.0.1");
    }

    #[test]
    fn redirect_answers_301_to_https() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let t = thread::spawn(move || {
            let (s, _) = l.accept().unwrap();
            redirect(s, 8443).unwrap();
        });
        let mut c = TcpStream::connect(addr).unwrap();
        c.write_all(b"GET /x HTTP/1.1\r\nHost: router.lan\r\n\r\n").unwrap();
        let mut out = String::new();
        c.read_to_string(&mut out).unwrap();
        t.join().unwrap();
        assert!(out.starts_with("HTTP/1.1 301"), "{out}");
        assert!(out.contains("Location: https://router.lan:8443/\r\n"), "{out}");
    }
}
