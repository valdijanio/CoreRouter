//! `--connect HOST:PORT`: the UI as a client of a `corerouter-daemon`, over
//! the control channel, on a worker thread so a slow or dead router never
//! stalls a frame.
//!
//! The worker owns the `Client`. Requests run in order; a request that finds
//! no connection fails at once (it is never queued for "later", which could
//! apply a change the operator already saw fail). Lost connections are
//! retried every `RETRY`.
//!
//! G0.3: the worker connects through a [`Dialer`] — plain with the local
//! token on loopback, TLS pinned to the certificate the operator accepted
//! elsewhere — and logs in again by itself when the session token expires.
//! A refused login stops the retries (they would only feed the router's
//! brute-force limit) and is shown as the link's reason.

use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use corerouter_control::dial::RefuseNew;
use corerouter_control::{Client, KnownHosts, Login, Target, UNAUTHORIZED, dial};
use corerouter_ui::{Backend, Link, Reply, RequestId};
use serde_json::Value;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const RETRY: Duration = Duration::from_secs(2);
/// Longest the worker sleeps while connected and idle.
const IDLE: Duration = Duration::from_secs(60);

/// How to reach one router again and again: its address, the login, and
/// (TLS) the one certificate fingerprint accepted for it.
#[derive(Clone)]
pub struct Dialer {
    pub target: Target,
    login: Login,
    fingerprint: Option<String>,
    /// The worker's current session token, shared with the `--control`
    /// proxy so it acts as the same logged-in user.
    token: Arc<Mutex<Option<String>>>,
}

impl Dialer {
    pub fn new(target: Target, login: Login, fingerprint: Option<String>) -> Self {
        Self {
            target,
            login,
            fingerprint,
            token: Arc::new(Mutex::new(None)),
        }
    }

    fn known(&self) -> KnownHosts {
        let mut k = KnownHosts::in_memory();
        if let Some(fp) = &self.fingerprint {
            let _ = k.remember(&self.target.addr(), fp);
        }
        k
    }

    /// Connect and log in (the worker).
    pub fn dial(&self) -> Result<Client, String> {
        let c = dial(
            &self.target,
            CONNECT_TIMEOUT,
            &self.login,
            &mut self.known(),
            &mut RefuseNew,
        )?;
        self.keep_token(&c);
        Ok(c)
    }

    /// Connect with the worker's session (the `--control` proxy), or the
    /// local token when there is no login.
    pub fn dial_shared(&self) -> Result<Client, String> {
        let token = self
            .token
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let login = match token {
            Some(t) => Login::Token(t),
            // No session yet: log in on our own.
            None => return self.dial(),
        };
        dial(
            &self.target,
            CONNECT_TIMEOUT,
            &login,
            &mut self.known(),
            &mut RefuseNew,
        )
    }

    fn keep_token(&self, c: &Client) {
        if matches!(self.login, Login::Password { .. }) {
            *self.token.lock().unwrap_or_else(PoisonError::into_inner) =
                c.token().map(str::to_owned);
        }
    }

    /// Log in again on `c` (the session token expired).
    fn relogin(&self, c: &mut Client) -> Result<(), String> {
        let Login::Password { user, password } = &self.login else {
            return Err("no password to log in again with".into());
        };
        c.login(user, password)?;
        self.keep_token(c);
        Ok(())
    }

    fn can_relogin(&self) -> bool {
        matches!(self.login, Login::Password { .. })
    }
}

struct Request {
    id: RequestId,
    method: String,
    params: Value,
}

enum Event {
    Reply(Reply),
    Link(Link),
}

pub struct Remote {
    requests: Sender<Request>,
    events: Receiver<Event>,
    next: RequestId,
    link: Link,
    target: String,
    /// Replies made up here because the worker is gone.
    orphans: Vec<Reply>,
}

impl Remote {
    /// Start the worker on a connection already made (and logged in) by
    /// the connect screen, or connecting in the background when `None`.
    pub fn spawn(dialer: Dialer, first: Option<Client>) -> std::io::Result<Self> {
        let (req_tx, req_rx) = mpsc::channel();
        let (ev_tx, ev_rx) = mpsc::channel();
        let target = dialer.target.to_string();
        if let Some(c) = &first {
            dialer.keep_token(c);
        }
        thread::Builder::new()
            .name("gui-remote".into())
            .spawn(move || worker(&dialer, first, &req_rx, &ev_tx))?;
        Ok(Self {
            requests: req_tx,
            events: ev_rx,
            next: 0,
            link: Link::Connecting {
                target: target.clone(),
            },
            target,
            orphans: Vec::new(),
        })
    }
}

impl Backend for Remote {
    fn submit(&mut self, method: &str, params: Value) -> RequestId {
        self.next = self.next.wrapping_add(1);
        let req = Request {
            id: self.next,
            method: method.to_owned(),
            params: corerouter_ui::backend::tag_via(method, params),
        };
        if self.requests.send(req).is_err() {
            self.orphans
                .push((self.next, Err("the connection worker stopped".into())));
        }
        self.next
    }

    fn poll(&mut self) -> Vec<Reply> {
        let mut out = std::mem::take(&mut self.orphans);
        loop {
            match self.events.try_recv() {
                Ok(Event::Reply(r)) => out.push(r),
                Ok(Event::Link(l)) => self.link = l,
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.link = Link::Disconnected {
                        target: self.target.clone(),
                        reason: "the connection worker stopped".into(),
                    };
                    break;
                }
            }
        }
        out
    }

    fn link(&self) -> Link {
        self.link.clone()
    }
}

/// A login the router refused: retrying cannot help.
fn refused(e: &str) -> bool {
    e.contains(corerouter_control::auth::INVALID_LOGIN)
        || e.contains(corerouter_control::auth::NO_PASSWORD_REMOTE)
        || e.contains("too many failed logins")
        || e.contains("CHANGED")
        || e.contains("not trusted")
}

/// Runs until the UI drops its `Remote`.
fn worker(
    dialer: &Dialer,
    first: Option<Client>,
    requests: &Receiver<Request>,
    events: &Sender<Event>,
) {
    let target = dialer.target.to_string();
    let connected = first.is_some();
    let mut client: Option<Client> = first;
    let mut reason = String::new();
    // Set when the router refused the login: no more retries.
    let mut fatal: Option<String> = None;
    let mut retry_at = Instant::now();
    let link = |l: Link| events.send(Event::Link(l)).is_ok();
    if connected
        && !link(Link::Connected {
            target: target.clone(),
        })
    {
        return;
    }
    loop {
        if client.is_none() && fatal.is_none() && Instant::now() >= retry_at {
            if !link(Link::Connecting {
                target: target.clone(),
            }) {
                return;
            }
            let next = match dialer.dial() {
                Ok(c) => {
                    client = Some(c);
                    log::info!("connected to {target}");
                    Link::Connected {
                        target: target.clone(),
                    }
                }
                Err(e) => {
                    if refused(&e) {
                        fatal = Some(e.clone());
                    }
                    reason = e;
                    retry_at = Instant::now() + RETRY;
                    Link::Disconnected {
                        target: target.clone(),
                        reason: reason.clone(),
                    }
                }
            };
            if !link(next) {
                return;
            }
        }
        let wait = match (&client, &fatal) {
            (Some(_), _) | (None, Some(_)) => IDLE,
            (None, None) => retry_at.saturating_duration_since(Instant::now()),
        };
        let req = match requests.recv_timeout(wait) {
            Ok(r) => r,
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => return,
        };
        let result = match client.as_mut() {
            None => Err(format!("not connected to {target}: {reason}")),
            Some(c) => match c.request(&req.method, req.params.clone()) {
                // The session token expired: log in again, once, and retry.
                Ok(Err(e)) if e.starts_with(UNAUTHORIZED) && dialer.can_relogin() => {
                    match dialer.relogin(c) {
                        Ok(()) => c
                            .request(&req.method, req.params)
                            .unwrap_or_else(|e| Err(format!("connection to {target} lost: {e}"))),
                        Err(again) => {
                            if refused(&again) {
                                fatal = Some(again.clone());
                                client = None;
                                reason = again.clone();
                                if !link(Link::Disconnected {
                                    target: target.clone(),
                                    reason: again.clone(),
                                }) {
                                    return;
                                }
                            }
                            Err(again)
                        }
                    }
                }
                Ok(answer) => answer,
                Err(e) => {
                    log::warn!("connection to {target} lost: {e}");
                    client = None;
                    reason = e.clone();
                    // Reconnect on the next turn, without waiting.
                    retry_at = Instant::now();
                    if !link(Link::Disconnected {
                        target: target.clone(),
                        reason: e.clone(),
                    }) {
                        return;
                    }
                    Err(format!("connection to {target} lost: {e}"))
                }
            },
        };
        if events.send(Event::Reply((req.id, result))).is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_control::{Endpoint, Gate, Limits, SharedHost, bind_loopback, spawn};
    use corerouter_engine::{Session, shared};
    use serde_json::json;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;

    /// Poll until `n` replies are in (or 10 s pass).
    fn wait(b: &mut Remote, n: usize) -> Vec<Reply> {
        let mut out = Vec::new();
        let until = Instant::now() + Duration::from_secs(10);
        while out.len() < n && Instant::now() < until {
            out.extend(b.poll());
            thread::sleep(Duration::from_millis(5));
        }
        out
    }

    /// A router with user `op` (write); session tokens idle out after `idle`.
    fn router(idle: Duration) -> String {
        let mut s = Session::virtual_lab();
        s.execute(
            "user.add",
            &json!({"name": "op", "group": "write", "password": "op-password"}),
        )
        .unwrap();
        let listener = bind_loopback(0).unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let gate = Gate::new(Limits {
            idle,
            ..Limits::default()
        });
        spawn(Endpoint::loopback(listener), SharedHost(shared(s)), gate).unwrap();
        addr
    }

    fn dialer(addr: &str, password: &str) -> Dialer {
        Dialer::new(
            Target::parse(addr).unwrap(),
            Login::Password {
                user: "op".into(),
                password: password.into(),
            },
            None,
        )
    }

    #[test]
    fn talks_to_a_real_control_server() {
        let addr = router(Duration::from_secs(600));
        let mut b = Remote::spawn(dialer(&addr, "op-password"), None).unwrap();
        let set = b.submit(
            "engine.execute",
            json!({"command": "system.identity.set", "params": {"name": "remote"}}),
        );
        let bad = b.submit("engine.execute", json!({"command": "nope"}));
        let inspect = b.submit("state.inspect", json!({}));
        let replies = wait(&mut b, 3);
        let get = |id| &replies.iter().find(|(i, _)| *i == id).unwrap().1;
        assert_eq!(get(set).as_ref().unwrap()["name"], "remote");
        assert!(get(bad).as_ref().unwrap_err().contains("nope"));
        assert_eq!(get(inspect).as_ref().unwrap()["identity"], "remote");
        assert_eq!(b.link(), Link::Connected { target: addr });
    }

    #[test]
    fn logs_in_again_when_the_token_expires_and_stops_on_a_bad_password() {
        let addr = router(Duration::from_millis(100));
        let d = dialer(&addr, "op-password");
        let mut b = Remote::spawn(d.clone(), None).unwrap();
        let first = b.submit("auth.whoami", Value::Null);
        assert_eq!(wait(&mut b, 1)[0].0, first);
        thread::sleep(Duration::from_millis(250));
        let later = b.submit("auth.whoami", Value::Null);
        let r = wait(&mut b, 1);
        assert_eq!(r[0].0, later);
        assert_eq!(r[0].1.as_ref().unwrap()["user"], "op");
        // The proxy reuses the same session.
        let mut proxy = d.dial_shared().unwrap();
        assert_eq!(
            proxy.call("auth.whoami", Value::Null).unwrap()["user"],
            "op"
        );

        let mut bad = Remote::spawn(dialer(&addr, "wrong-password"), None).unwrap();
        let id = bad.submit("ping", Value::Null);
        let r = wait(&mut bad, 1);
        assert_eq!(r[0].0, id);
        thread::sleep(Duration::from_millis(100));
        bad.poll();
        match bad.link() {
            Link::Disconnected { reason, .. } => {
                assert!(reason.contains("invalid user or password"), "{reason}");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn no_router_fails_fast_and_says_why() {
        // Bind and drop: a loopback port with nobody listening.
        let addr = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .to_string();
        let mut b = Remote::spawn(dialer(&addr, "x"), None).unwrap();
        let id = b.submit("ping", Value::Null);
        let replies = wait(&mut b, 1);
        assert_eq!(replies.len(), 1);
        assert_eq!(replies[0].0, id);
        assert!(replies[0].1.is_err());
        assert!(
            matches!(b.link(), Link::Disconnected { .. }),
            "{:?}",
            b.link()
        );
    }

    #[test]
    fn a_dropped_connection_fails_the_request_and_reconnects() {
        // A router that answers one request per connection, then hangs up.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        thread::spawn(move || {
            for conn in listener.incoming().take(2) {
                let mut s = conn.unwrap();
                let mut line = String::new();
                BufReader::new(s.try_clone().unwrap())
                    .read_line(&mut line)
                    .unwrap();
                let req: Value = serde_json::from_str(&line).unwrap();
                writeln!(s, "{}", json!({"id": req["id"], "ok": true, "result": 1})).unwrap();
            }
        });
        let d = Dialer::new(Target::parse(&addr).unwrap(), Login::Nothing, None);
        let mut b = Remote::spawn(d, None).unwrap();
        let first = b.submit("ping", Value::Null);
        let lost = b.submit("ping", Value::Null);
        let again = b.submit("ping", Value::Null);
        let replies = wait(&mut b, 3);
        let get = |id| &replies.iter().find(|(i, _)| *i == id).unwrap().1;
        assert_eq!(get(first).as_ref().unwrap(), &json!(1));
        assert!(get(lost).as_ref().unwrap_err().contains("lost"));
        // The next request reconnects first.
        assert_eq!(get(again).as_ref().unwrap(), &json!(1));
    }
}
