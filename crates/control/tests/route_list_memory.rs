//! G0.31h: `ip.route.list` of a large table over the control channel
//! without the memory of the answer. Before, the rows became a
//! `serde_json::Value` tree (~9 KiB per row at its peak), then a string of
//! the whole line: 274 → 720 MiB of RSS for 60 000 routes on the host,
//! and the 2 GiB image's daemon was killed by the OOM killer on the second
//! call. Now the rows are written into the socket one at a time.
//!
//! Own binary: it reads and resets this process's peak RSS
//! (`/proc/self/clear_refs`), which other tests in the process would move.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use corerouter_control::{Endpoint, Gate, Limits, SharedHost, bind_loopback, spawn};
use corerouter_engine::{Session, shared};
use serde_json::{Value, json};

/// Routes in the table: twice the "large" bound, an answer of ~11 MB.
const N: usize = 20_000;

/// `VmHWM` / `VmRSS` of this process, in bytes.
fn status(key: &str) -> u64 {
    let s = std::fs::read_to_string("/proc/self/status").unwrap();
    let line = s.lines().find(|l| l.starts_with(key)).unwrap();
    let kb: u64 = line
        .split_whitespace()
        .nth(1)
        .and_then(|v| v.parse().ok())
        .unwrap();
    kb * 1024
}

/// Send one request and read the answer to its `\n`, keeping only its
/// first bytes and its length.
fn call(addr: &str, line: &str) -> (Vec<u8>, usize) {
    let mut c = TcpStream::connect(addr).unwrap();
    c.set_read_timeout(Some(Duration::from_secs(60))).unwrap();
    c.write_all(line.as_bytes()).unwrap();
    let mut head = Vec::new();
    let mut len = 0;
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = c.read(&mut buf).unwrap();
        assert!(n > 0, "connection closed after {len} bytes");
        if head.len() < 256 {
            head.extend_from_slice(&buf[..n.min(256)]);
        }
        len += n;
        if buf[..n].last() == Some(&b'\n') {
            return (head, len);
        }
    }
}

#[test]
fn a_large_route_list_streams_without_its_size_in_memory() {
    let mut s = Session::virtual_lab();
    s.execute(
        "ip.address.add",
        &json!({"address": "192.0.2.1/24", "interface": "ether1"}),
    )
    .unwrap();
    let steps: Vec<Value> = (0..N)
        .map(|i| {
            json!({"command": "ip.route.add", "params": {
                "dst_address": format!("10.{}.{}.0/24", i / 256, i % 256),
                "gateway": "192.0.2.254",
                "comment": "a comment of some length per route",
            }})
        })
        .collect();
    s.batch(&Value::Array(steps), true).unwrap();
    // The table's lines are built (and cached) before the measure.
    s.execute("ip.route.page", &json!({"limit": 1})).unwrap();
    let gate = Gate::new(Limits::default());
    let token = corerouter_control::auth::new_token().unwrap();
    gate.add_local_token(&token);
    let listener = bind_loopback(0).unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    spawn(Endpoint::loopback(listener), SharedHost(shared(s)), gate).unwrap();
    let line = format!(
        "{}\n",
        json!({"id": 1, "method": "engine.execute", "token": token,
               "params": {"command": "ip.route.list", "params": {}}})
    );
    // One call first: the threads, buffers and allocator arenas a
    // connection needs are there before the peak is reset.
    let (_, size) = call(&addr, &line);
    assert!(size > N * 400, "answer of {size} bytes");

    std::fs::write("/proc/self/clear_refs", "5").unwrap();
    let before = status("VmRSS:");
    // Two connections at once: one is written, the other is either
    // written after it or told the router is busy.
    let answers: Vec<(Vec<u8>, usize)> = std::thread::scope(|sc| {
        let a = sc.spawn(|| call(&addr, &line));
        let b = sc.spawn(|| call(&addr, &line));
        vec![a.join().unwrap(), b.join().unwrap()]
    });
    let peak = status("VmHWM:").saturating_sub(before);
    let mut written = 0;
    for (head, len) in &answers {
        let head = String::from_utf8_lossy(head);
        if head.starts_with(r#"{"id":1,"ok":true,"result":[{"#) {
            assert_eq!(*len, size);
            written += 1;
        } else {
            assert!(head.contains("busy"), "{head}");
        }
    }
    assert!(written >= 1);
    eprintln!(
        "route_list_memory: {N} routes, answer {:.1} MB, peak RSS +{:.1} MB ({written} written)",
        size as f64 / 1e6,
        peak as f64 / 1e6
    );
    // The criterion of the gap: below twice the answer. Streamed, it is a
    // small fraction of it (the row being written and a 64 KiB buffer).
    assert!(
        peak < size as u64 / 2,
        "peak RSS grew {peak} bytes for an answer of {size}"
    );
}
