//! Fuzz oracles: hostile bytes into every decoder never panic, and what
//! decodes encodes back to the same message. `tests/fuzz.rs` runs them as
//! proptests; `crates/proto-ha/fuzz` runs them under libFuzzer.

use crate::hello::{self, HelloFrame};
use crate::msg::{FrameReader, Msg};
use crate::record::SessionRecord;
use crate::sync::{Replica, SyncConfig};

/// A byte stream into the deframer and, message by message, into a
/// replica: no panic, and every decoded message re-encodes and decodes to
/// itself.
pub fn stream(data: &[u8]) {
    let mut fr = FrameReader::new();
    let mut replica = Replica::new(SyncConfig::default());
    let mut out = Vec::new();
    // Split the input at a point it chooses, like a socket would.
    let cut = data.first().map_or(0, |b| usize::from(*b)).min(data.len());
    let (a, b) = data.split_at(cut);
    for part in [a, b] {
        fr.push(part);
        while let Ok(Some(m)) = fr.next_msg() {
            round_trip(&m);
            replica.handle(0, &m, &mut out);
            replica.poll(1000, &mut out);
        }
    }
}

fn round_trip(m: &Msg) {
    let mut b = Vec::new();
    if m.encode(&mut b).is_ok() {
        let mut fr = FrameReader::new();
        fr.push(&b);
        let back = fr.next_msg();
        assert_eq!(
            back.as_ref().ok().and_then(Option::as_ref),
            Some(m),
            "re-encode"
        );
    }
}

/// A frame payload of a given kind straight into the decoder.
pub fn message(kind: u8, payload: &[u8]) {
    if let Ok(m) = Msg::decode(kind, payload) {
        round_trip(&m);
    }
}

/// A session record: no panic; what decodes encodes to an equal record.
pub fn record(data: &[u8]) {
    if let Ok(r) = SessionRecord::decode(data)
        && let Ok(b) = r.to_bytes()
    {
        assert_eq!(SessionRecord::decode(&b).ok(), Some(r), "record re-encode");
    }
}

/// An access hello under a fixed key: forged ones never pass.
pub fn access_hello(data: &[u8]) {
    let key = hello::derive("hello", b"fuzz");
    if let Ok(h) = HelloFrame::decode(&key, data) {
        let mut b = Vec::new();
        h.encode(&key, &mut b);
        assert_eq!(
            b.as_slice(),
            data.get(..b.len()).unwrap_or(&[]),
            "only a real tag passes"
        );
    }
}
