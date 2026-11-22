//! A test RPKI validator (G3.2c): serves a fixed list of VRPs over RTR
//! (RFC 8210, `corerouter_proto_bgp::rtr::Server`) so the lab needs no
//! Routinator, StayRTR or internet. One thread per router.
//!
//! ```sh
//! cargo run -p corerouter-hal-frr --example rtr_server -- 127.0.0.1:3323 vrps.txt
//! ```
//!
//! `vrps.txt`: one VRP per line, `prefix max_length asn` (`#` comments).

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;

use corerouter_proto_bgp::rpki::Vrp;
use corerouter_proto_bgp::rtr::{Server, pdu_len};

fn parse(text: &str) -> Result<Vec<Vrp>, String> {
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        let bad = || format!("line {}: {line:?}: want `prefix max_length asn`", n + 1);
        let mut w = line.split_whitespace();
        let (Some(p), Some(m), Some(a)) = (w.next(), w.next(), w.next()) else {
            return Err(bad());
        };
        let net: ipnet::IpNet = p.parse().map_err(|_| bad())?;
        let vrp = Vrp::new(
            net.network(),
            net.prefix_len(),
            m.parse().map_err(|_| bad())?,
            a.trim_start_matches("AS").parse().map_err(|_| bad())?,
        )
        .ok_or_else(bad)?;
        out.push(vrp);
    }
    Ok(out)
}

fn main() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let (Some(listen), Some(file)) = (args.next(), args.next()) else {
        return Err("usage: rtr_server <addr:port> <vrps.txt>".into());
    };
    let text = std::fs::read_to_string(&file).map_err(|e| format!("{file}: {e}"))?;
    let vrps = parse(&text)?;
    let server = Arc::new(Server::new(7, vrps));
    let l = TcpListener::bind(&listen).map_err(|e| format!("{listen}: {e}"))?;
    eprintln!("rtr_server: {} VRPs on {listen}", server.vrps().len());
    for conn in l.incoming() {
        let Ok(mut s) = conn else { continue };
        let server = Arc::clone(&server);
        std::thread::spawn(move || {
            let peer = s.peer_addr().map(|p| p.to_string()).unwrap_or_default();
            eprintln!("rtr_server: router {peer}");
            let mut pending = Vec::new();
            let mut b = [0u8; 4096];
            loop {
                let n = match s.read(&mut b) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => n,
                };
                pending.extend_from_slice(b.get(..n).unwrap_or_default());
                loop {
                    let len = match pdu_len(&pending) {
                        Ok(Some(len)) if pending.len() >= len => len,
                        Ok(_) => break,
                        Err(_) => return,
                    };
                    let q: Vec<u8> = pending.drain(..len).collect();
                    let (a, close) = match server.answer(&q) {
                        Ok(a) => (a, false),
                        Err(a) => (a, true),
                    };
                    if s.write_all(&a).is_err() || close {
                        return;
                    }
                }
            }
        });
    }
    Ok(())
}
