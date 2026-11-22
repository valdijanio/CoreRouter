//! Subscriber notices (G4.10c): the portal the router serves itself, the
//! round that keeps the notice state, the names it resolves and the
//! webhook. Design: `docs/subscriber-notices.md`.
//!
//! Threads, each named:
//! - `notice` (the service body): every [`TICK`], under the session lock,
//!   `notice_tick` and a fresh [`Snapshot`] (who is under which profile,
//!   the pages); every [`RESOLVE`] the walled garden's and the OS probes'
//!   names through the router's resolver, outside the lock;
//! - `notice-http`: accepts on the portal's port (IPv4 and IPv6) and hands
//!   each connection to `notice-w<N>` over a bounded queue (full: the
//!   connection is closed at once, "busy");
//! - `notice-hook`: POSTs the webhook events, bounded, with retries.
//!
//! A worker never takes the session lock for a probe (it reads the
//! snapshot); only a page view does, once, to mark it seen.
//!
//! Every request is hostile: the head is read with a deadline and at most
//! [`MAX_HEAD`] bytes, only `GET`/`HEAD` are answered, nothing of it is
//! echoed back unescaped.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError, sync_channel};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::thread;
use std::time::{Duration, Instant};

use corerouter_engine::subscriber_notice::{Event, Snapshot, page_vars};
use corerouter_engine::{Shared, lock};
use corerouter_model::service::Listen;
use corerouter_model::subscriber_notice::probes::{self, Probe};
use corerouter_model::subscriber_notice::{GARDEN_LIST, Mode, PROBE_LIST, render};

/// How often the round runs.
const TICK: Duration = Duration::from_secs(2);
/// How often the names are resolved again (their TTL is ignored: a CDN's
/// is seconds; the entries live [`RESOLVED_TTL`]).
const RESOLVE: Duration = Duration::from_secs(300);
const RESOLVED_TTL: u64 = 900;
/// Request head read at most, and how long a client may take to send it.
const MAX_HEAD: usize = 8 * 1024;
const READ_DEADLINE: Duration = Duration::from_secs(5);
/// Workers and the connections waiting for one (**estimado**: a page is
/// a few KB from memory; 4 workers answer thousands of probes a second).
const WORKERS: usize = 4;
const QUEUE: usize = 256;
/// Webhook events waiting, attempts, and the request deadline.
const HOOK_QUEUE: usize = 1024;
const HOOK_TRIES: u32 = 3;
const HOOK_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) const SERVICE: super::Service = super::Service {
    name: "subscriber-notice",
    flags: &[],
    topic: "firewall",
    enable: "ip.subscriber-notice.profile.add",
    depends: &[],
    start,
};

fn start(ctx: &super::Ctx) -> Result<super::Run, String> {
    let session = ctx.session.clone();
    Ok(Box::new(move |health: &super::Health| {
        run(&session, health);
        Ok(())
    }))
}

type Shot = Arc<RwLock<Arc<Snapshot>>>;

fn read(s: &Shot) -> Arc<Snapshot> {
    s.read().unwrap_or_else(PoisonError::into_inner).clone()
}

fn run(session: &Shared, health: &super::Health) {
    let shot: Shot = Arc::new(RwLock::new(Arc::new(Snapshot::default())));
    let (hook_tx, hook_rx) = sync_channel::<(String, Event)>(HOOK_QUEUE);
    {
        let session = session.clone();
        let h = health.clone();
        let _ = health.spawn("notice-hook", move || hook(&session, &hook_rx, &h));
    }
    // The port the acceptors serve; a change makes the old ones stop.
    let port_now = Arc::new(AtomicU16::new(0));
    let (conn_tx, conn_rx) = sync_channel::<TcpStream>(QUEUE);
    let conn_rx = Arc::new(Mutex::new(conn_rx));
    for i in 0..WORKERS {
        let rx = conn_rx.clone();
        let shot = shot.clone();
        let session = session.clone();
        let h = health.clone();
        if let Err(e) = health.spawn(&format!("notice-w{i}"), move || work(&rx, &shot, &session, &h)) {
            health.error(format!("portal worker: {e}"));
        }
    }
    let mut last_resolve: Option<Instant> = None;
    let mut built: Option<(u32, (usize, u32))> = None;
    loop {
        health.beat();
        let (snap, events) = {
            let mut s = lock(session);
            s.notice_tick();
            let events = s.notice_take_events(HOOK_QUEUE);
            // Rebuilt only when the members may have changed (100 000:
            // ~26 ms under the lock, **medido** in G4.10b).
            let stamp = s.notice_stamp();
            let snap = (built != Some(stamp)).then(|| s.notice_snapshot());
            built = Some(stamp);
            (snap, events)
        };
        if let Some(snap) = snap {
            *shot.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(snap);
        }
        let current = read(&shot);
        let on = current.on;
        let port = current.settings.port;
        let url = current.settings.webhook_url.clone();
        for e in events {
            if url.is_empty() {
                break;
            }
            if let Err(TrySendError::Full(_)) = hook_tx.try_send((url.clone(), e)) {
                log::warn!("subscriber-notice: webhook queue full, event dropped");
            }
        }
        let serving = port_now.load(Ordering::Acquire);
        if on && serving != port {
            match listen(port, &port_now, &conn_tx, health) {
                Ok(l) => {
                    health.listen(l);
                    health.clear_error();
                }
                Err(e) => health.error(format!("portal port {port}: {e}")),
            }
        } else if !on && serving != 0 {
            port_now.store(0, Ordering::Release);
            health.listen(Vec::new());
        }
        if on && last_resolve.is_none_or(|t| t.elapsed() >= RESOLVE) {
            resolve_names(session);
            last_resolve = Some(Instant::now());
        }
        health.disabled((!on).then_some("ip.subscriber-notice.profile.add"));
        if !health.sleep(TICK) {
            return;
        }
    }
}

/// The walled garden's and the probes' names, resolved through the router's
/// resolver (outside the session lock), into `sn-garden` / `sn-probe`.
fn resolve_names(session: &Shared) {
    let garden: Vec<String> = lock(session)
        .store()
        .running()
        .ip
        .subscriber_notice
        .walled_garden
        .iter()
        .filter(|g| !g.disabled && !g.dst_host.is_empty())
        .map(|g| g.dst_host.clone())
        .collect();
    let mut found: Vec<(&str, String, Vec<IpAddr>)> = Vec::new();
    for h in garden {
        if let Ok(ips) = super::dns::resolve(session, &h) {
            found.push((GARDEN_LIST, h, ips));
        }
    }
    for h in probes::hosts() {
        if let Ok(ips) = super::dns::resolve(session, h) {
            found.push((PROBE_LIST, h.to_owned(), ips));
        }
    }
    let mut s = lock(session);
    for (list, host, ips) in found {
        s.notice_resolved(list, &host, &ips, RESOLVED_TTL);
    }
}

/// Bind the portal on IPv4 and IPv6 and start their acceptors (the ones
/// of an older port stop on their own).
fn listen(port: u16, port_now: &Arc<AtomicU16>, tx: &SyncSender<TcpStream>, health: &super::Health) -> Result<Vec<Listen>, String> {
    let mut bound = Vec::new();
    for addr in [SocketAddr::from(([0, 0, 0, 0], port)), SocketAddr::from((Ipv6Addr::UNSPECIFIED, port))] {
        match bind(addr) {
            Ok(l) => bound.push((addr, l)),
            Err(e) if !bound.is_empty() => log::debug!("subscriber-notice: {addr}: {e}"),
            Err(e) => return Err(e),
        }
    }
    port_now.store(port, Ordering::Release);
    let mut out = Vec::new();
    for (addr, l) in bound {
        out.push(Listen::new("http", addr));
        let tx = tx.clone();
        let h = health.clone();
        let now = port_now.clone();
        health
            .spawn("notice-http", move || accept(&l, port, &now, &tx, &h))
            .map_err(|e| e.to_string())?;
    }
    Ok(out)
}

/// A listener on `addr`; the IPv6 one takes only IPv6 (the IPv4 one is
/// separate, so neither fails on a host without the other family).
fn bind(addr: SocketAddr) -> Result<TcpListener, String> {
    let domain = if addr.is_ipv4() { socket2::Domain::IPV4 } else { socket2::Domain::IPV6 };
    let s = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP)).map_err(|e| e.to_string())?;
    if addr.is_ipv6() {
        s.set_only_v6(true).map_err(|e| e.to_string())?;
    }
    s.set_reuse_address(true).map_err(|e| e.to_string())?;
    s.bind(&addr.into()).map_err(|e| format!("{addr}: {e}"))?;
    s.listen(1024).map_err(|e| e.to_string())?;
    Ok(s.into())
}

fn accept(l: &TcpListener, port: u16, port_now: &AtomicU16, tx: &SyncSender<TcpStream>, health: &super::Health) {
    let _ = l.set_nonblocking(true);
    while !health.stopping() && port_now.load(Ordering::Acquire) == port {
        match l.accept() {
            Ok((c, _)) => {
                let _ = c.set_nonblocking(false);
                // Every worker busy and the queue full: closed at once (the
                // client retries), never an unbounded backlog.
                let _ = tx.try_send(c);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(e) => {
                log::debug!("subscriber-notice: accept: {e}");
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

fn work(rx: &Mutex<Receiver<TcpStream>>, shot: &Shot, session: &Shared, health: &super::Health) {
    while !health.stopping() {
        let next = rx.lock().unwrap_or_else(PoisonError::into_inner).recv_timeout(Duration::from_millis(200));
        let Ok(mut c) = next else { continue };
        let snap = read(shot);
        if let Err(e) = serve(&mut c, &snap, session) {
            log::debug!("subscriber-notice: {e}");
        }
    }
}

/// One request (no keep-alive: a probe is one request).
fn serve(c: &mut TcpStream, snap: &Snapshot, session: &Shared) -> Result<(), String> {
    let _ = c.set_read_timeout(Some(READ_DEADLINE));
    let _ = c.set_write_timeout(Some(READ_DEADLINE));
    let peer = c.peer_addr().map_err(|e| e.to_string())?.ip();
    let peer = unmap(peer);
    let local = c.local_addr().map(|a| unmap(a.ip())).ok();
    let head = read_head(c)?;
    let req = Request::parse(&head).ok_or("malformed request")?;
    let resp = answer(
        &req,
        peer,
        local,
        snap,
        &|via, ua| {
            lock(session).notice_mark_seen(peer, via, ua);
        },
        &|ip, profile| page_vars(&lock(session), ip, profile),
    );
    let head_only = req.method == "HEAD";
    c.write_all(&resp.bytes(head_only)).map_err(|e| e.to_string())
}

fn unmap(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}

fn read_head(c: &mut TcpStream) -> Result<Vec<u8>, String> {
    let start = Instant::now();
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") && !buf.windows(2).any(|w| w == b"\n\n") {
        if buf.len() >= MAX_HEAD || start.elapsed() >= READ_DEADLINE {
            return Err("request head too long or too slow".into());
        }
        let n = c.read(&mut chunk).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(chunk.get(..n).unwrap_or_default());
    }
    Ok(buf)
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Request {
    pub method: String,
    pub path: String,
    pub host: String,
    pub user_agent: String,
}

impl Request {
    pub(crate) fn parse(head: &[u8]) -> Option<Self> {
        let text = std::str::from_utf8(head).ok()?;
        let mut lines = text.split('\n').map(|l| l.trim_end_matches('\r'));
        let first = lines.next()?;
        let mut parts = first.split(' ');
        let method = parts.next()?.to_owned();
        let mut path = parts.next()?.to_owned();
        if !parts.next()?.starts_with("HTTP/1.") {
            return None;
        }
        // An absolute URI (a proxy-style request) carries the host.
        let mut host = String::new();
        if let Some(rest) = path.strip_prefix("http://") {
            let (h, p) = rest.split_once('/').map_or((rest, "/".to_owned()), |(h, p)| (h, format!("/{p}")));
            host = h.to_owned();
            path = p;
        }
        let mut user_agent = String::new();
        for l in lines.take(64) {
            let Some((k, v)) = l.split_once(':') else { continue };
            match k.trim().to_ascii_lowercase().as_str() {
                "host" if host.is_empty() => v.trim().clone_into(&mut host),
                "user-agent" => user_agent = v.trim().chars().take(160).collect(),
                _ => {}
            }
        }
        host = host.split(':').next().unwrap_or_default().to_ascii_lowercase();
        if host.len() > 253 || path.len() > 2048 || !path.starts_with('/') {
            return None;
        }
        Some(Self { method, path, host, user_agent })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Response {
    pub status: u16,
    pub reason: &'static str,
    pub content_type: &'static str,
    pub location: Option<String>,
    pub body: Vec<u8>,
}

impl Response {
    fn new(status: u16, reason: &'static str, content_type: &'static str, body: impl Into<Vec<u8>>) -> Self {
        Self { status, reason, content_type, location: None, body: body.into() }
    }

    fn bytes(&self, head_only: bool) -> Vec<u8> {
        let mut h = format!(
            "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n",
            self.status,
            self.reason,
            self.content_type,
            self.body.len()
        );
        if let Some(l) = &self.location {
            h.push_str(&format!("Location: {l}\r\n"));
        }
        h.push_str("\r\n");
        let mut out = h.into_bytes();
        if !head_only {
            out.extend_from_slice(&self.body);
        }
        out
    }
}

/// What an OS gets from its real server ("internet ok"): the answer to a
/// probe of someone not (or no longer) under a notice, so the OS clears its
/// portal state at once.
pub(crate) fn success(p: &Probe) -> Response {
    let text = |t: &'static str| Response::new(200, "OK", "text/plain", t);
    match p.expects {
        "204" => Response::new(204, "No Content", "text/plain", Vec::new()),
        "200 Success" => Response::new(200, "OK", "text/html", "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>"),
        "200 Microsoft Connect Test" => text("Microsoft Connect Test"),
        "200 Microsoft NCSI" => text("Microsoft NCSI"),
        "200 success" if p.host == "detectportal.firefox.com" => text("success\n"),
        "200 OK" => text("OK\n"),
        "200 NetworkManager is online" => text("NetworkManager is online\n"),
        _ => Response::new(204, "No Content", "text/plain", Vec::new()),
    }
}

/// The portal's own address as the redirect names it.
fn portal_base(snap: &Snapshot, local: Option<IpAddr>) -> String {
    let host = if !snap.settings.portal_host.is_empty() {
        snap.settings.portal_host.clone()
    } else {
        match snap.settings.portal_address.or(local) {
            Some(IpAddr::V6(a)) => format!("[{a}]"),
            Some(a) => a.to_string(),
            None => "router".into(),
        }
    };
    format!("http://{host}:{}", snap.settings.port)
}

/// The answer to `req` from `peer`. `seen` records a page view, `vars` the
/// page's variables (both take the session lock: a page view, not a probe).
pub(crate) fn answer(
    req: &Request,
    peer: IpAddr,
    local: Option<IpAddr>,
    snap: &Snapshot,
    seen: &dyn Fn(&str, &str),
    vars: &dyn Fn(IpAddr, &str) -> BTreeMap<String, String>,
) -> Response {
    if req.method != "GET" && req.method != "HEAD" {
        return Response::new(405, "Method Not Allowed", "text/plain", "GET only\n");
    }
    let probe = probes::probe_of(&req.host, &req.path);
    let Some(p) = snap.profile_of(peer) else {
        return match probe {
            Some(pb) => success(pb),
            None => Response::new(200, "OK", "text/html; charset=utf-8", OK_PAGE),
        };
    };
    if req.path.starts_with("/captive-portal/api") {
        // RFC 8908 §5: `captive` is required; the API proper is https
        // (G4.10g), this answers the same JSON for tests and proxies.
        let body = serde_json::json!({
            "captive": true,
            "user-portal-url": format!("{}/", portal_base(snap, local)),
        })
        .to_string();
        return Response::new(200, "OK", "application/captive+json", body);
    }
    let base = portal_base(snap, local);
    let ours = req.host.is_empty()
        || req.host == snap.settings.portal_host
        || local.is_some_and(|l| req.host.trim_matches(['[', ']']) == l.to_string());
    if let Some(pb) = probe
        && !ours
    {
        // The OS's probe: a redirect is what every OS reads as a portal
        // (Android: 200–399 is a portal, 4xx/5xx "no internet").
        let mut r = Response::new(302, "Found", "text/html; charset=utf-8", format!("<a href=\"{base}/?via={}\">Aviso</a>", pb.os));
        r.location = Some(format!("{base}/?via={}", pb.os));
        return r;
    }
    let via = req.path.split_once("via=").map_or("browser", |(_, v)| v.split('&').next().unwrap_or("browser"));
    let via = probes::PROBES.iter().find(|p| p.os == via).map_or("browser", |p| p.os);
    let page = snap.page_of(p);
    let v = vars(peer, p.name.as_str());
    let lookup = |k: &str| v.get(k).cloned();
    if req.path.starts_with("/seen") {
        seen("continue", &req.user_agent);
        return Response::new(200, "OK", "text/html; charset=utf-8", OK_PAGE);
    }
    let cont = (p.mode != Mode::Block).then(|| format!("{base}/seen"));
    let html = render(&page, &lookup, cont.as_deref());
    seen(via, &req.user_agent);
    if ours {
        Response::new(200, "OK", "text/html; charset=utf-8", html)
    } else {
        // Any other plain-HTTP site: 511 with the page (RFC 6585 §6).
        Response::new(511, "Network Authentication Required", "text/html; charset=utf-8", html)
    }
}

const OK_PAGE: &str = "<!doctype html><html lang=\"pt-BR\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Acesso liberado</title></head>\
<body style=\"font-family:system-ui,sans-serif;max-width:30rem;margin:2rem auto;padding:0 1rem\">\
<h1>Acesso liberado</h1><p>Pode navegar normalmente.</p></body></html>";

/// The webhook: one POST per event, `HOOK_TRIES` attempts.
fn hook(session: &Shared, rx: &Receiver<(String, Event)>, health: &super::Health) {
    while !health.stopping() {
        let Ok((url, e)) = rx.recv_timeout(Duration::from_millis(500)) else { continue };
        let body = serde_json::to_vec(&e).unwrap_or_default();
        let mut last = String::new();
        for attempt in 0..HOOK_TRIES {
            match post(session, &url, &body) {
                Ok(()) => {
                    last.clear();
                    break;
                }
                Err(err) => last = err,
            }
            if !health.sleep(Duration::from_secs(1 << attempt)) {
                return;
            }
        }
        if !last.is_empty() {
            log::warn!("subscriber-notice: webhook {url}: {last}");
        }
    }
}

fn post(session: &Shared, url: &str, body: &[u8]) -> Result<(), String> {
    let u = super::https::Url::parse(url)?;
    let deadline = Instant::now() + HOOK_TIMEOUT;
    let ip = match u.host.parse::<IpAddr>() {
        Ok(ip) => ip,
        Err(_) => *super::dns::resolve(session, &u.host)?.first().ok_or("no address")?,
    };
    let mut s = super::https::connect(SocketAddr::new(ip, u.port), u.tls, &u.host, true, deadline)?;
    let r = super::https::exchange(&mut s, "POST", &u, &[("Content-Type", "application/json")], body, 4096, deadline)?;
    if (200..300).contains(&r.status) { Ok(()) } else { Err(format!("HTTP {}", r.status)) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_engine::Session;
    use serde_json::json;

    fn snap(mode: &str) -> Snapshot {
        let mut s = Session::virtual_lab();
        for (id, p) in [
            ("ip.subscriber-notice.profile.add", json!({"name": "atraso", "mode": mode, "address_list": "bloqueados"})),
            ("ip.firewall.address-list.add", json!({"list": "bloqueados", "address": "100.64.0.10"})),
            ("ip.firewall.address-list.add", json!({"list": "bloqueados", "address": "100.64.8.0/24"})),
        ] {
            s.execute(id, &p).unwrap();
        }
        s.notice_snapshot()
    }

    fn req(host: &str, path: &str) -> Request {
        let head = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: test/1\r\n\r\n");
        Request::parse(head.as_bytes()).unwrap()
    }

    const SUB: &str = "100.64.0.10";
    const ROUTER: &str = "100.64.0.1";

    fn ask(snap: &Snapshot, host: &str, path: &str, from: &str) -> (Response, Vec<String>) {
        let seen = Mutex::new(Vec::new());
        let r = answer(
            &req(host, path),
            from.parse().unwrap(),
            Some(ROUTER.parse().unwrap()),
            snap,
            &|via, _| seen.lock().unwrap().push(via.to_owned()),
            &|_, _| BTreeMap::from([("valor".to_owned(), "R$ 99,90".to_owned())]),
        );
        (r, seen.into_inner().unwrap())
    }

    #[test]
    fn every_known_probe_of_a_member_is_redirected_to_the_portal() {
        let s = snap("block");
        for p in probes::PROBES {
            let path = if p.path == "*" { "/hotspot-detect.html" } else { p.path };
            let (r, seen) = ask(&s, p.host, path, SUB);
            assert_eq!(r.status, 302, "{} {}", p.host, p.path);
            assert_eq!(r.location.as_deref(), Some(format!("http://{ROUTER}:8880/?via={}", p.os).as_str()));
            assert!(seen.is_empty(), "a probe is not a view");
        }
        // A member of a prefix entry, too.
        assert_eq!(ask(&s, "captive.apple.com", "/", "100.64.8.77").0.status, 302);
    }

    #[test]
    fn the_portal_shows_the_page_and_logs_the_view() {
        let s = snap("block");
        let (r, seen) = ask(&s, ROUTER, "/?via=android", SUB);
        assert_eq!(r.status, 200);
        let body = String::from_utf8(r.body).unwrap();
        assert!(body.contains("R$ 99,90"), "{body}");
        assert!(!body.contains("/seen"), "a block page has no continue link");
        assert_eq!(seen, ["android"]);
        // Any other plain-HTTP site: 511 with the page (RFC 6585 §6).
        let (r, seen) = ask(&s, "example.com", "/news", SUB);
        assert_eq!(r.status, 511);
        assert_eq!(seen, ["browser"]);
        let bytes = String::from_utf8(r.bytes(false)).unwrap();
        assert!(bytes.contains("Cache-Control: no-store"), "{bytes}");
        // A notice page has the continue link, and following it is a view.
        let n = snap("notice");
        let (r, _) = ask(&n, ROUTER, "/", SUB);
        assert!(String::from_utf8(r.body).unwrap().contains(&format!("http://{ROUTER}:8880/seen")));
        let (r, seen) = ask(&n, ROUTER, "/seen", SUB);
        assert_eq!((r.status, seen), (200, vec!["continue".to_owned()]));
    }

    #[test]
    fn a_non_member_gets_what_its_os_expects() {
        let s = snap("block");
        let (r, _) = ask(&s, "connectivitycheck.gstatic.com", "/generate_204", "100.64.0.99");
        assert_eq!(r.status, 204);
        let (r, _) = ask(&s, "captive.apple.com", "/hotspot-detect.html", "100.64.0.99");
        assert!(String::from_utf8(r.body).unwrap().contains("<TITLE>Success</TITLE>"));
        let (r, _) = ask(&s, "www.msftconnecttest.com", "/connecttest.txt", "100.64.0.99");
        assert_eq!(r.body, b"Microsoft Connect Test");
        let (r, _) = ask(&s, "nmcheck.gnome.org", "/check_network_status.txt", "100.64.0.99");
        assert_eq!(r.body, b"NetworkManager is online\n");
        let (r, seen) = ask(&s, ROUTER, "/", "100.64.0.99");
        assert_eq!(r.status, 200);
        assert!(seen.is_empty());
    }

    #[test]
    fn the_capport_api_and_hostile_requests() {
        let s = snap("block");
        let (r, _) = ask(&s, ROUTER, "/captive-portal/api", SUB);
        assert_eq!(r.content_type, "application/captive+json");
        let v: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
        assert_eq!(v["captive"], true);
        for bad in [
            &b"\xff\xfe"[..],
            b"GET\r\n\r\n",
            b"GET / FTP/1.0\r\n\r\n",
            b"GET relative HTTP/1.1\r\n\r\n",
        ] {
            assert!(Request::parse(bad).is_none(), "{bad:?}");
        }
        let long = format!("GET /{} HTTP/1.1\r\nHost: x\r\n\r\n", "a".repeat(3000));
        assert!(Request::parse(long.as_bytes()).is_none());
        // An absolute URI carries the host; the port is dropped.
        let r = Request::parse(b"GET http://Captive.Apple.com:80/x HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!((r.host.as_str(), r.path.as_str()), ("captive.apple.com", "/x"));
        let post = Request::parse(b"POST / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
        let r = answer(&post, SUB.parse().unwrap(), None, &s, &|_, _| {}, &|_, _| BTreeMap::new());
        assert_eq!(r.status, 405);
        // The page escapes what the ISP's system put in a variable.
        let (r, _) = (
            answer(&req(ROUTER, "/"), SUB.parse().unwrap(), Some(ROUTER.parse().unwrap()), &s, &|_, _| {}, &|_, _| {
                BTreeMap::from([("login".to_owned(), "<script>x</script>".to_owned())])
            }),
            (),
        );
        assert!(!String::from_utf8(r.body).unwrap().contains("<script>"));
    }

    #[test]
    fn members_answer_from_the_snapshot() {
        let mut s = Session::virtual_lab();
        s.execute("ip.subscriber-notice.profile.add", &json!({"name": "atraso", "mode": "block", "address_list": "bloqueados"})).unwrap();
        let steps: Vec<serde_json::Value> = (0..10_000u32)
            .map(|i| json!({"command": "ip.firewall.address-list.add", "params": {"list": "bloqueados", "address": std::net::Ipv4Addr::from(0x6440_0000 + i).to_string()}}))
            .collect();
        s.batch(&serde_json::Value::Array(steps), true).unwrap();
        let t = Instant::now();
        let snap = s.notice_snapshot();
        let built = t.elapsed();
        assert_eq!(snap.members(), 10_000);
        let t = Instant::now();
        for i in 0..10_000u32 {
            let ip = IpAddr::V4(std::net::Ipv4Addr::from(0x6440_0000 + i));
            assert!(snap.profile_of(ip).is_some());
        }
        eprintln!("snapshot of 10 000: {built:?}; 10 000 lookups: {:?}", t.elapsed());
    }
}
