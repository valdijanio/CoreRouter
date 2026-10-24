//! Fuzz oracles (docs/fuzzing.md): bytes in, `Err` saying what broke.
//! The same functions run as proptests in `cargo xtask ci`
//! (`tests/fuzz.rs`) and under libFuzzer (`fuzz/fuzz_targets/radius.rs`).
#![doc(hidden)]

use std::net::SocketAddr;

use crate::client::{Client, ClientConfig, ServerConfig, SocketKey};
use crate::dict::Dictionary;
use crate::dynauth::{DynAuthClient, DynAuthConfig, DynAuthServer, Incoming};
use crate::packet::{AttrList, Builder, Packet, PushAttr, attr};
use crate::testserver::TestServer;
use crate::{crypto, juniper, rate_limit};

const SECRET: &[u8] = b"fuzz";

fn peer() -> SocketAddr {
    SocketAddr::from(([192, 0, 2, 1], 1812))
}

/// One datagram through every receive path: the codec and its
/// iterators, the dictionary, the crypto checks, the client (with requests
/// outstanding so identifiers match), the CoA/DM server and the test
/// server. Nothing may panic, and a packet that parses must re-encode to
/// the same attribute bytes.
pub fn packet(data: &[u8]) -> Result<(), String> {
    if let Ok(p) = Packet::parse(data) {
        if p.len() > crate::packet::MAX_PACKET_LEN || p.len() > data.len() {
            return Err(format!("parsed length {} out of range", p.len()));
        }
        let walked: usize = p.attributes().map(|a| a.value.len() + 2).sum();
        if walked + crate::packet::HEADER_LEN != p.len() {
            return Err("attribute walk does not cover the packet".into());
        }
        let _ = p.vsas().count();
        for e in p.extended() {
            let _ = p.long_extended(e.typ, e.ext);
        }
        let dict = Dictionary::builtin();
        let _ = dict.decode_packet(&p);
        let list = AttrList::from_packet(&p, &[]);
        if list.as_bytes() != p.as_bytes().get(crate::packet::HEADER_LEN..).unwrap_or(&[]) {
            return Err("re-encoded attributes differ".into());
        }
        let mut b = Builder::with_authenticator(p.code(), p.identifier(), p.authenticator());
        b.extend(&list).map_err(|e| format!("re-encode: {e}"))?;
        if b.into_unsigned() != p.as_bytes() {
            return Err("re-encoded packet differs".into());
        }
        let auth = p.authenticator();
        let _ = crypto::verify_response(&p, &auth, SECRET);
        let _ = crypto::verify_computed_request(&p, SECRET);
        let _ = crypto::check_message_authenticator(&p, &auth, SECRET);
        let _ = crypto::verify_chap(&p, b"pw");
        if let Some(v) = p.attr(attr::USER_PASSWORD) {
            let _ = crypto::unhide_user_password(v, SECRET, &auth);
        }
        if let Some(v) = p.attr(attr::TUNNEL_PASSWORD) {
            let _ = crypto::salt_decrypt(v.get(1..).unwrap_or(&[]), SECRET, &auth);
        }
    }

    let server = peer();
    let mut c = Client::new(
        ClientConfig::default(),
        vec![ServerConfig::auth(server, SECRET)],
        [1; 32],
    );
    for _ in 0..4 {
        let mut l = AttrList::new();
        let _ = l.push_text(attr::USER_NAME, "u");
        c.access(l, Some(b"pw"), 0).map_err(|e| e.to_string())?;
    }
    let mut buf = Vec::new();
    while c.poll_transmit(&mut buf).is_some() {}
    let key = SocketKey {
        server: 0,
        socket: 0,
    };
    let _ = c.handle_input(key, server, data, 1);
    c.handle_timeout(100_000);
    c.check_invariants()?;

    let mut d = DynAuthServer::new(DynAuthConfig {
        clients: vec![DynAuthClient {
            addr: server.ip(),
            secret: SECRET.to_vec(),
        }],
        ..DynAuthConfig::default()
    });
    if let Ok(Incoming::Request(r)) = d.handle(server, data, 0, 0) {
        let _ = r.selector.matches(&Default::default());
        let _ = d.respond(&r, crate::dynauth::Outcome::Ack, &AttrList::new(), 0);
    }

    let mut t = TestServer::new(SECRET, 1);
    t.script.allow_missing_message_authenticator = true;
    t.add_user("u", "pw", AttrList::new());
    if let Some(r) = t.handle(server, data, 0) {
        Packet::parse(&r.bytes).map_err(|e| format!("test server reply: {e}"))?;
    }
    Ok(())
}

/// Text inputs: the rate-limit, the Juniper service syntax and the
/// dictionary loader. A rate-limit that parses must format and parse back
/// to itself.
pub fn text(data: &[u8]) -> Result<(), String> {
    let s = String::from_utf8_lossy(data);
    if let Ok(r) = s.parse::<rate_limit::RateLimit>() {
        let back: rate_limit::RateLimit = r
            .to_string()
            .parse()
            .map_err(|e| format!("formatted rate-limit {r} does not parse: {e}"))?;
        if back != r {
            return Err(format!("rate-limit {s:?} does not round-trip"));
        }
    }
    let _ = juniper::parse_service(&s);
    let mut d = Dictionary::builtin();
    let _ = d.load(&s);
    Ok(())
}
