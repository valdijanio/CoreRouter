//! `--connect HOST:PORT`: the UI as a client of a `corerouter-daemon`, over
//! the control channel, on a worker thread so a slow or dead router never
//! stalls a frame.
//!
//! The worker owns the `Client`. Requests run in order; a request that finds
//! no connection fails at once (it is never queued for "later", which could
//! apply a change the operator already saw fail). Lost connections are
//! retried every `RETRY`.

use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread;
use std::time::{Duration, Instant};

use corerouter_control::Client;
use corerouter_ui::{Backend, Link, Reply, RequestId};
use serde_json::Value;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const RETRY: Duration = Duration::from_secs(2);
/// Longest the worker sleeps while connected and idle.
const IDLE: Duration = Duration::from_secs(60);

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
    /// Start the worker; connecting happens in the background.
    pub fn spawn(target: &str) -> std::io::Result<Self> {
        let (req_tx, req_rx) = mpsc::channel();
        let (ev_tx, ev_rx) = mpsc::channel();
        let addr = target.to_owned();
        thread::Builder::new()
            .name("gui-remote".into())
            .spawn(move || worker(&addr, &req_rx, &ev_tx))?;
        Ok(Self {
            requests: req_tx,
            events: ev_rx,
            next: 0,
            link: Link::Connecting {
                target: target.to_owned(),
            },
            target: target.to_owned(),
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
            params,
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

/// Runs until the UI drops its `Remote`.
fn worker(addr: &str, requests: &Receiver<Request>, events: &Sender<Event>) {
    let target = addr.to_owned();
    let mut client: Option<Client> = None;
    let mut reason = String::new();
    let mut retry_at = Instant::now();
    let link = |l: Link| events.send(Event::Link(l)).is_ok();
    loop {
        if client.is_none() && Instant::now() >= retry_at {
            if !link(Link::Connecting {
                target: target.clone(),
            }) {
                return;
            }
            let next = match Client::connect(addr, CONNECT_TIMEOUT) {
                Ok(c) => {
                    client = Some(c);
                    log::info!("connected to {addr}");
                    Link::Connected {
                        target: target.clone(),
                    }
                }
                Err(e) => {
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
        let wait = match client {
            Some(_) => IDLE,
            None => retry_at.saturating_duration_since(Instant::now()),
        };
        let req = match requests.recv_timeout(wait) {
            Ok(r) => r,
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => return,
        };
        let result = match client.as_mut() {
            None => Err(format!("not connected to {addr}: {reason}")),
            Some(c) => match c.request(&req.method, req.params) {
                Ok(answer) => answer,
                Err(e) => {
                    log::warn!("connection to {addr} lost: {e}");
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
                    Err(format!("connection to {addr} lost: {e}"))
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
    use corerouter_control::{SharedHost, bind_loopback, spawn};
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

    #[test]
    fn talks_to_a_real_control_server() {
        let listener = bind_loopback(0).unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        spawn(listener, SharedHost(shared(Session::virtual_lab()))).unwrap();

        let mut b = Remote::spawn(&addr).unwrap();
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
    fn no_router_fails_fast_and_says_why() {
        // Bind and drop: a loopback port with nobody listening.
        let addr = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .to_string();
        let mut b = Remote::spawn(&addr).unwrap();
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
        let mut b = Remote::spawn(&addr).unwrap();
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
