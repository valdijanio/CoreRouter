//! audit-e2e: the `Remote` backend outlives the router process. Against the
//! real daemon, an MCP server whose daemon restarted answered every later
//! tool call with "send: Broken pipe" until it was restarted itself. Now it
//! redials on the next call; a request whose reply was lost is reported as
//! "may or may not have run", never silently sent twice.
//!
//! A fake router on loopback stands in for the daemon so each case can
//! close the connection exactly where it needs to.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use corerouter_control::dial::RefuseNew;
use corerouter_control::{KnownHosts, Login, Target};
use corerouter_mcp::{Backend, Remote};
use serde_json::{Value, json};

/// What a fake connection does after the login checks
/// (`server.info`, `auth.whoami`).
#[derive(Clone, Copy)]
enum Then {
    /// Answer this many requests, then close.
    AnswerThenClose(usize),
    /// Read one request, then close without answering.
    DropRequest,
}

/// Serves one connection per entry of `plan`; each reply carries the
/// connection number. Every request line is sent to the returned channel.
fn fake_router(plan: Vec<Then>) -> (String, mpsc::Receiver<(usize, Value)>) {
    let l = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = l.local_addr().unwrap().to_string();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        for (n, then) in plan.into_iter().enumerate() {
            let (s, _) = l.accept().unwrap();
            serve(s, n + 1, then, &tx);
        }
    });
    (addr, rx)
}

fn serve(s: TcpStream, conn: usize, then: Then, tx: &mpsc::Sender<(usize, Value)>) {
    let mut w = s.try_clone().unwrap();
    let mut lines = BufReader::new(s).lines();
    let mut answered = 0;
    while let Some(Ok(line)) = lines.next() {
        let req: Value = serde_json::from_str(&line).unwrap();
        let method = req["method"].as_str().unwrap_or_default().to_owned();
        let login = matches!(method.as_str(), "server.info" | "auth.whoami");
        if !login {
            tx.send((conn, req.clone())).unwrap();
        }
        if !login && matches!(then, Then::DropRequest) {
            return;
        }
        let result = match method.as_str() {
            "server.info" => json!({"has_ui": false}),
            "auth.whoami" => json!({"user": "local"}),
            _ => json!({"conn": conn}),
        };
        let reply = json!({"id": req["id"], "ok": true, "result": result});
        w.write_all(format!("{reply}\n").as_bytes()).unwrap();
        if !login {
            answered += 1;
            if matches!(then, Then::AnswerThenClose(n) if answered >= n) {
                return;
            }
        }
    }
}

fn remote(addr: &str) -> Remote {
    Remote::dial(
        &Target::parse(addr).unwrap(),
        &Login::Token("t".into()),
        &mut KnownHosts::load(std::path::Path::new("/nonexistent/known_hosts")),
        &mut RefuseNew,
    )
    .unwrap()
}

fn run(r: &mut Remote) -> Result<Value, String> {
    r.call("engine.execute", json!({"command": "interface.list"}))
}

#[test]
fn a_restarted_router_is_redialled_on_the_next_call() {
    let (addr, seen) = fake_router(vec![Then::AnswerThenClose(1), Then::AnswerThenClose(9)]);
    let mut r = remote(&addr);
    assert_eq!(run(&mut r).unwrap()["conn"], 1);
    // The router went away between two calls (restart, upgrade).
    thread::sleep(Duration::from_millis(100));
    assert_eq!(run(&mut r).unwrap()["conn"], 2);
    assert_eq!(run(&mut r).unwrap()["conn"], 2);
    // Each request reached a router exactly once.
    let got: Vec<usize> = seen.try_iter().map(|(c, _)| c).collect();
    assert_eq!(got, [1, 2, 2]);
}

#[test]
fn a_lost_reply_is_not_sent_again() {
    let (addr, seen) = fake_router(vec![Then::DropRequest, Then::AnswerThenClose(9)]);
    let mut r = remote(&addr);
    let e = run(&mut r).unwrap_err();
    assert!(e.contains("may or may not have run"), "{e}");
    assert_eq!(seen.try_iter().count(), 1, "sent twice");
    assert_eq!(run(&mut r).unwrap()["conn"], 2);
}

#[test]
fn an_unreachable_router_is_a_clear_error_and_the_next_call_retries() {
    let (addr, _seen) = fake_router(vec![Then::AnswerThenClose(1)]);
    let mut r = remote(&addr);
    run(&mut r).unwrap();
    thread::sleep(Duration::from_millis(100));
    // Nothing listens any more (the fake router served its one connection
    // and the listener is gone with its thread).
    let e = run(&mut r).unwrap_err();
    assert!(e.contains("unreachable"), "{e}");
    let e = run(&mut r).unwrap_err();
    assert!(e.contains("unreachable"), "{e}");
}
