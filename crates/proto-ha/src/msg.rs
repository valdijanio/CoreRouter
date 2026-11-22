//! The messages two BNGs of a pair exchange over the sync stream (TLS on
//! the control channel), versioned and length-framed:
//!
//! ```text
//! magic "CRHA" (4) | version (1) | kind (1) | reserved (2) | length (4, LE) | payload
//! ```
//!
//! In a Hello frame the reserved bytes are its [`Hello::features`]: what
//! else the sender understands. An older reader ignores them, and a message
//! of a newer feature goes only to a peer that announced it.
//!
//! Payload integers are little-endian. A newer minor version may append
//! fields at the end of a message; an older reader ignores what it does not
//! know only inside a [`crate::record::SessionRecord`] (TLV), never in the
//! framing: a frame of an unknown `version` or `kind` closes the stream and
//! the peers fall back to what both speak (the Hello carries the version).

use std::sync::Arc;

use crate::wire::{self, Error, Reader, Result, put_bytes8, put_bytes16, put_u32, put_u64};

pub const MAGIC: [u8; 4] = *b"CRHA";
pub const VERSION: u8 = 1;
pub const HEADER: usize = 12;
/// Largest payload of one frame (a snapshot chunk; **estimado**: 1 MiB
/// holds ≈ 5000 session records of ≈ 200 B).
pub const MAX_FRAME: usize = 1 << 20;
/// Session keys are short (the PPPoE key is 17 bytes).
pub const MAX_KEY: usize = 32;
/// One session record, encoded.
pub const MAX_VALUE: usize = 8192;
/// Operations in one delta and records in one chunk.
pub const MAX_OPS: usize = 16_384;
/// The body of one [`Msg::Forward`] or [`Msg::ForwardReply`] (a RADIUS
/// CoA/DM, ≤ 4096 B, as the daemon serializes it).
pub const MAX_FORWARD: usize = 64 << 10;
/// [`Hello::features`]: the sender takes [`Msg::Forward`] (G4.3hb).
pub const FEATURE_FORWARD: u16 = 1;
/// Config sections compared for drift.
pub const MAX_SECTIONS: usize = 32;

/// A role of a node in the pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Role {
    /// Just started: listening for the peer before claiming anything.
    Init,
    /// Holds the replica, answers no subscriber.
    Standby,
    /// Answers PADI, owns the sessions and the virtual MAC.
    Active,
    /// Cannot prove it is not isolated (or a tracked port is down, or a
    /// failure is being simulated): answers nothing, takes nothing over.
    Fenced,
    /// Yielding the active role to the peer (switchover in progress).
    Yielding,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Init => "init",
            Role::Standby => "standby",
            Role::Active => "active",
            Role::Fenced => "fenced",
            Role::Yielding => "yielding",
        }
    }

    fn code(self) -> u8 {
        match self {
            Role::Init => 0,
            Role::Standby => 1,
            Role::Active => 2,
            Role::Fenced => 3,
            Role::Yielding => 4,
        }
    }

    fn from_code(c: u8) -> Result<Role> {
        Ok(match c {
            0 => Role::Init,
            1 => Role::Standby,
            2 => Role::Active,
            3 => Role::Fenced,
            4 => Role::Yielding,
            _ => return Err(Error::BadValue("role")),
        })
    }
}

/// A session key: opaque bytes (the owner's map key), at most
/// [`MAX_KEY`]. Inline, so the tables allocate nothing per key.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Key {
    len: u8,
    b: [u8; MAX_KEY],
}

impl Key {
    pub fn new(bytes: &[u8]) -> Option<Key> {
        let mut b = [0u8; MAX_KEY];
        b.get_mut(..bytes.len())?.copy_from_slice(bytes);
        Some(Key {
            len: u8::try_from(bytes.len()).ok()?,
            b,
        })
    }

    /// The first [`MAX_KEY`] bytes of `bytes` (for keys built from fixed
    /// fields, which always fit).
    pub fn truncated(bytes: &[u8]) -> Key {
        let n = bytes.len().min(MAX_KEY);
        let mut b = [0u8; MAX_KEY];
        for (d, s) in b.iter_mut().zip(bytes) {
            *d = *s;
        }
        Key {
            len: u8::try_from(n).unwrap_or(0),
            b,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.b.get(..usize::from(self.len)).unwrap_or(&[])
    }
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for b in self.as_bytes() {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// A session's traffic counters, from the router's view (rx = from the
/// subscriber). Absolute values: applying the same update twice is harmless.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Counters {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
}

/// One change of the replicated table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    /// The session record is new or changed (whole: idempotent).
    Upsert {
        key: Key,
        value: Arc<[u8]>,
    },
    Remove {
        key: Key,
    },
    /// Counters only: the frequent change, 1 + key + 32 bytes.
    Counters {
        key: Key,
        c: Counters,
    },
}

impl Op {
    pub fn key(&self) -> &Key {
        match self {
            Op::Upsert { key, .. } | Op::Remove { key } | Op::Counters { key, .. } => key,
        }
    }

    /// Bytes on the wire.
    pub fn wire_len(&self) -> usize {
        1 + 1
            + self.key().as_bytes().len()
            + match self {
                Op::Upsert { value, .. } => 2 + value.len(),
                Op::Remove { .. } => 0,
                Op::Counters { .. } => 32,
            }
    }
}

/// A config section and the hash of its contents, for drift detection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    pub name: Box<str>,
    pub hash: u64,
}

/// The first message on a sync stream, both ways.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    pub version: u8,
    pub node_id: u64,
    pub epoch: u64,
    pub role: Role,
    pub priority: u8,
    pub hot_standby: bool,
    /// The replication stream this node publishes (active) or last applied
    /// (standby), and the last sequence number of it.
    pub stream: u64,
    pub applied: u64,
    pub sessions: u32,
    /// Hashes of the config sections the pair must agree on.
    pub sections: Vec<Section>,
    /// `FEATURE_*` bits, in the frame header's reserved bytes.
    pub features: u16,
}

/// Liveness and role, every hello interval, both ways.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Heartbeat {
    pub node_id: u64,
    /// See `role::PeerView::{incarnation, hears}`.
    pub incarnation: u64,
    pub hears: u64,
    pub view_seq: u64,
    pub acked: u64,
    pub epoch: u64,
    pub role: Role,
    pub priority: u8,
    /// The sender reaches its witness.
    pub witness: bool,
    /// The sender's replica is complete for the current stream.
    pub in_sync: bool,
    /// The sender could serve (see `role::PeerView::eligible`).
    pub eligible: bool,
    pub stream: u64,
    /// Publisher: last sequence number assigned. Replica: last applied.
    pub seq: u64,
    pub sessions: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub key: Key,
    pub value: Arc<[u8]>,
    pub counters: Counters,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Msg {
    Hello(Hello),
    Heartbeat(Heartbeat),
    /// A full copy follows: `total` records, then the deltas after `base`.
    SnapshotBegin {
        stream: u64,
        base: u64,
        total: u32,
    },
    SnapshotChunk {
        stream: u64,
        records: Vec<Record>,
    },
    SnapshotEnd {
        stream: u64,
        base: u64,
        count: u32,
    },
    /// Operations `first`, `first + 1`, … of `stream`.
    Delta {
        stream: u64,
        first: u64,
        ops: Vec<Op>,
    },
    /// The replica applied everything up to `seq`.
    Ack {
        stream: u64,
        seq: u64,
    },
    /// The replica missed something: resend from `from` (or a snapshot).
    Resync {
        stream: u64,
        from: u64,
    },
    /// The active yields (switchover): the peer takes over with a higher
    /// epoch than `epoch`.
    Handover {
        epoch: u64,
    },
    /// The standby asks the active to yield (preemption).
    HandoverRequest {
        epoch: u64,
    },
    /// First message both ways: a fresh random nonce (`node::Node`
    /// authenticates the peer before anything else is accepted).
    Challenge {
        nonce: [u8; 32],
    },
    /// The answer to the peer's challenge: HMAC under the pair's link key.
    Proof {
        node_id: u64,
        mac: [u8; 32],
    },
    /// A request for the peer's services, opaque to the pair (G4.3hb: a
    /// RADIUS CoA/Disconnect the server sent to the node that no longer
    /// holds the session). Only to a peer with [`FEATURE_FORWARD`].
    Forward {
        id: u64,
        body: Vec<u8>,
    },
    /// The answer to [`Msg::Forward`] `id`.
    ForwardReply {
        id: u64,
        body: Vec<u8>,
    },
}

mod kind {
    pub const HELLO: u8 = 1;
    pub const HEARTBEAT: u8 = 2;
    pub const SNAPSHOT_BEGIN: u8 = 3;
    pub const SNAPSHOT_CHUNK: u8 = 4;
    pub const SNAPSHOT_END: u8 = 5;
    pub const DELTA: u8 = 6;
    pub const ACK: u8 = 7;
    pub const RESYNC: u8 = 8;
    pub const HANDOVER: u8 = 9;
    pub const HANDOVER_REQUEST: u8 = 10;
    pub const CHALLENGE: u8 = 11;
    pub const PROOF: u8 = 12;
    pub const FORWARD: u8 = 13;
    pub const FORWARD_REPLY: u8 = 14;
}

mod op {
    pub const UPSERT: u8 = 1;
    pub const REMOVE: u8 = 2;
    pub const COUNTERS: u8 = 3;
}

fn put_key(out: &mut Vec<u8>, k: &Key) {
    out.push(k.len);
    out.extend_from_slice(k.as_bytes());
}

fn get_key(r: &mut Reader<'_>) -> Result<Key> {
    let b = r.bytes8()?;
    Key::new(b).ok_or(Error::TooLong {
        what: "key",
        len: b.len(),
        max: MAX_KEY,
    })
}

fn put_counters(out: &mut Vec<u8>, c: &Counters) {
    put_u64(out, c.rx_bytes);
    put_u64(out, c.tx_bytes);
    put_u64(out, c.rx_packets);
    put_u64(out, c.tx_packets);
}

fn get_counters(r: &mut Reader<'_>) -> Result<Counters> {
    Ok(Counters {
        rx_bytes: r.u64()?,
        tx_bytes: r.u64()?,
        rx_packets: r.u64()?,
        tx_packets: r.u64()?,
    })
}

fn count(n: usize, what: &'static str) -> Result<u32> {
    if n > MAX_OPS {
        return Err(Error::TooLong {
            what,
            len: n,
            max: MAX_OPS,
        });
    }
    Ok(u32::try_from(n).unwrap_or(u32::MAX))
}

fn get_count(r: &mut Reader<'_>, what: &'static str) -> Result<usize> {
    let n = usize::try_from(r.u32()?).unwrap_or(usize::MAX);
    if n > MAX_OPS {
        return Err(Error::TooLong {
            what,
            len: n,
            max: MAX_OPS,
        });
    }
    Ok(n)
}

impl Msg {
    fn kind(&self) -> u8 {
        match self {
            Msg::Hello(_) => kind::HELLO,
            Msg::Heartbeat(_) => kind::HEARTBEAT,
            Msg::SnapshotBegin { .. } => kind::SNAPSHOT_BEGIN,
            Msg::SnapshotChunk { .. } => kind::SNAPSHOT_CHUNK,
            Msg::SnapshotEnd { .. } => kind::SNAPSHOT_END,
            Msg::Delta { .. } => kind::DELTA,
            Msg::Ack { .. } => kind::ACK,
            Msg::Resync { .. } => kind::RESYNC,
            Msg::Handover { .. } => kind::HANDOVER,
            Msg::HandoverRequest { .. } => kind::HANDOVER_REQUEST,
            Msg::Challenge { .. } => kind::CHALLENGE,
            Msg::Proof { .. } => kind::PROOF,
            Msg::Forward { .. } => kind::FORWARD,
            Msg::ForwardReply { .. } => kind::FORWARD_REPLY,
        }
    }

    /// Appends one frame to `out`. On error (`out` is left as it was) the
    /// message breaks a limit the reader would refuse.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let start = out.len();
        out.extend_from_slice(&MAGIC);
        out.push(VERSION);
        out.push(self.kind());
        let flags = match self {
            Msg::Hello(h) => h.features,
            _ => 0,
        };
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&[0, 0, 0, 0]);
        let r = self.payload(out);
        let len = out.len() - start - HEADER;
        if let Err(e) = r {
            out.truncate(start);
            return Err(e);
        }
        if len > MAX_FRAME {
            out.truncate(start);
            return Err(Error::TooLong {
                what: "frame",
                len,
                max: MAX_FRAME,
            });
        }
        let l = u32::try_from(len).unwrap_or(u32::MAX).to_le_bytes();
        if let Some(dst) = out.get_mut(start + 8..start + 12) {
            dst.copy_from_slice(&l);
        }
        Ok(())
    }

    fn payload(&self, out: &mut Vec<u8>) -> Result<()> {
        match self {
            Msg::Hello(h) => {
                out.push(h.version);
                put_u64(out, h.node_id);
                put_u64(out, h.epoch);
                out.push(h.role.code());
                out.push(h.priority);
                out.push(u8::from(h.hot_standby));
                put_u64(out, h.stream);
                put_u64(out, h.applied);
                put_u32(out, h.sessions);
                if h.sections.len() > MAX_SECTIONS {
                    return Err(Error::TooLong {
                        what: "sections",
                        len: h.sections.len(),
                        max: MAX_SECTIONS,
                    });
                }
                out.push(u8::try_from(h.sections.len()).unwrap_or(0));
                for s in &h.sections {
                    put_bytes8(out, "section name", s.name.as_bytes())?;
                    put_u64(out, s.hash);
                }
            }
            Msg::Heartbeat(h) => {
                put_u64(out, h.node_id);
                put_u64(out, h.incarnation);
                put_u64(out, h.hears);
                put_u64(out, h.view_seq);
                put_u64(out, h.acked);
                put_u64(out, h.epoch);
                out.push(h.role.code());
                out.push(h.priority);
                out.push(u8::from(h.witness));
                out.push(u8::from(h.in_sync));
                out.push(u8::from(h.eligible));
                put_u64(out, h.stream);
                put_u64(out, h.seq);
                put_u32(out, h.sessions);
            }
            Msg::SnapshotBegin {
                stream,
                base,
                total,
            } => {
                put_u64(out, *stream);
                put_u64(out, *base);
                put_u32(out, *total);
            }
            Msg::SnapshotChunk { stream, records } => {
                put_u64(out, *stream);
                put_u32(out, count(records.len(), "records")?);
                for rec in records {
                    put_key(out, &rec.key);
                    put_bytes16(out, "value", &rec.value, MAX_VALUE)?;
                    put_counters(out, &rec.counters);
                }
            }
            Msg::SnapshotEnd {
                stream,
                base,
                count,
            } => {
                put_u64(out, *stream);
                put_u64(out, *base);
                put_u32(out, *count);
            }
            Msg::Delta { stream, first, ops } => {
                put_u64(out, *stream);
                put_u64(out, *first);
                put_u32(out, count(ops.len(), "ops")?);
                for o in ops {
                    match o {
                        Op::Upsert { key, value } => {
                            out.push(op::UPSERT);
                            put_key(out, key);
                            put_bytes16(out, "value", value, MAX_VALUE)?;
                        }
                        Op::Remove { key } => {
                            out.push(op::REMOVE);
                            put_key(out, key);
                        }
                        Op::Counters { key, c } => {
                            out.push(op::COUNTERS);
                            put_key(out, key);
                            put_counters(out, c);
                        }
                    }
                }
            }
            Msg::Ack { stream, seq } => {
                put_u64(out, *stream);
                put_u64(out, *seq);
            }
            Msg::Resync { stream, from } => {
                put_u64(out, *stream);
                put_u64(out, *from);
            }
            Msg::Handover { epoch } | Msg::HandoverRequest { epoch } => put_u64(out, *epoch),
            Msg::Challenge { nonce } => out.extend_from_slice(nonce),
            Msg::Proof { node_id, mac } => {
                put_u64(out, *node_id);
                out.extend_from_slice(mac);
            }
            Msg::Forward { id, body } | Msg::ForwardReply { id, body } => {
                put_u64(out, *id);
                if body.len() > MAX_FORWARD {
                    return Err(Error::TooLong {
                        what: "forward",
                        len: body.len(),
                        max: MAX_FORWARD,
                    });
                }
                out.extend_from_slice(body);
            }
        }
        Ok(())
    }

    /// Reads one frame's payload (`kind` from its header).
    pub fn decode(kind: u8, payload: &[u8]) -> Result<Msg> {
        Self::decode_flagged(kind, 0, payload)
    }

    /// [`Msg::decode`] with the header's reserved bytes (a Hello's
    /// features).
    pub fn decode_flagged(kind: u8, flags: u16, payload: &[u8]) -> Result<Msg> {
        let mut r = Reader::new(payload);
        let m = match kind {
            kind::HELLO => {
                let version = r.u8()?;
                let node_id = r.u64()?;
                let epoch = r.u64()?;
                let role = Role::from_code(r.u8()?)?;
                let priority = r.u8()?;
                let hot_standby = r.bool()?;
                let stream = r.u64()?;
                let applied = r.u64()?;
                let sessions = r.u32()?;
                let n = usize::from(r.u8()?);
                if n > MAX_SECTIONS {
                    return Err(Error::TooLong {
                        what: "sections",
                        len: n,
                        max: MAX_SECTIONS,
                    });
                }
                let mut sections = Vec::with_capacity(n);
                for _ in 0..n {
                    let name = std::str::from_utf8(r.bytes8()?)
                        .map_err(|_| Error::BadValue("section name"))?;
                    sections.push(Section {
                        name: name.into(),
                        hash: r.u64()?,
                    });
                }
                Msg::Hello(Hello {
                    version,
                    node_id,
                    epoch,
                    role,
                    priority,
                    hot_standby,
                    stream,
                    applied,
                    sessions,
                    sections,
                    features: flags,
                })
            }
            kind::HEARTBEAT => Msg::Heartbeat(Heartbeat {
                node_id: r.u64()?,
                incarnation: r.u64()?,
                hears: r.u64()?,
                view_seq: r.u64()?,
                acked: r.u64()?,
                epoch: r.u64()?,
                role: Role::from_code(r.u8()?)?,
                priority: r.u8()?,
                witness: r.bool()?,
                in_sync: r.bool()?,
                eligible: r.bool()?,
                stream: r.u64()?,
                seq: r.u64()?,
                sessions: r.u32()?,
            }),
            kind::SNAPSHOT_BEGIN => Msg::SnapshotBegin {
                stream: r.u64()?,
                base: r.u64()?,
                total: r.u32()?,
            },
            kind::SNAPSHOT_CHUNK => {
                let stream = r.u64()?;
                let n = get_count(&mut r, "records")?;
                // Each record is at least 1 + 2 + 32 bytes: a count the
                // payload cannot hold allocates nothing.
                let mut records = Vec::with_capacity(n.min(r.remaining() / 35));
                for _ in 0..n {
                    let key = get_key(&mut r)?;
                    let value = r.bytes16("value", MAX_VALUE)?.into();
                    let counters = get_counters(&mut r)?;
                    records.push(Record {
                        key,
                        value,
                        counters,
                    });
                }
                Msg::SnapshotChunk { stream, records }
            }
            kind::SNAPSHOT_END => Msg::SnapshotEnd {
                stream: r.u64()?,
                base: r.u64()?,
                count: r.u32()?,
            },
            kind::DELTA => {
                let stream = r.u64()?;
                let first = r.u64()?;
                let n = get_count(&mut r, "ops")?;
                let mut ops = Vec::with_capacity(n.min(r.remaining() / 2));
                for _ in 0..n {
                    let code = r.u8()?;
                    let key = get_key(&mut r)?;
                    ops.push(match code {
                        op::UPSERT => Op::Upsert {
                            key,
                            value: r.bytes16("value", MAX_VALUE)?.into(),
                        },
                        op::REMOVE => Op::Remove { key },
                        op::COUNTERS => Op::Counters {
                            key,
                            c: get_counters(&mut r)?,
                        },
                        _ => return Err(Error::BadValue("op")),
                    });
                }
                if first.checked_add(ops.len() as u64).is_none() {
                    return Err(Error::BadValue("sequence"));
                }
                Msg::Delta { stream, first, ops }
            }
            kind::ACK => Msg::Ack {
                stream: r.u64()?,
                seq: r.u64()?,
            },
            kind::RESYNC => Msg::Resync {
                stream: r.u64()?,
                from: r.u64()?,
            },
            kind::HANDOVER => Msg::Handover { epoch: r.u64()? },
            kind::HANDOVER_REQUEST => Msg::HandoverRequest { epoch: r.u64()? },
            kind::CHALLENGE => Msg::Challenge { nonce: r.array()? },
            kind::PROOF => Msg::Proof {
                node_id: r.u64()?,
                mac: r.array()?,
            },
            kind::FORWARD | kind::FORWARD_REPLY => {
                let id = r.u64()?;
                let n = r.remaining();
                if n > MAX_FORWARD {
                    return Err(Error::TooLong {
                        what: "forward",
                        len: n,
                        max: MAX_FORWARD,
                    });
                }
                let body = r.take(n)?.to_vec();
                if kind == kind::FORWARD {
                    Msg::Forward { id, body }
                } else {
                    Msg::ForwardReply { id, body }
                }
            }
            k => return Err(Error::UnknownKind(k)),
        };
        r.end()?;
        Ok(m)
    }
}

/// Splits a byte stream into messages. Bounded: it never buffers more than
/// one frame (header + [`MAX_FRAME`]); a bad header is an error and the
/// caller closes the stream.
#[derive(Default)]
pub struct FrameReader {
    buf: Vec<u8>,
    start: usize,
}

impl FrameReader {
    pub fn new() -> Self {
        Self::default()
    }

    /// Bytes buffered and not yet returned as messages.
    pub fn pending(&self) -> usize {
        self.buf.len() - self.start
    }

    /// Feeds bytes read from the stream.
    pub fn push(&mut self, data: &[u8]) {
        if self.start > 0 && (self.start >= self.buf.len() / 2 || self.buf.len() > 4 * MAX_FRAME) {
            self.buf.drain(..self.start);
            self.start = 0;
        }
        self.buf.extend_from_slice(data);
    }

    /// The next whole message, `Ok(None)` if more bytes are needed.
    pub fn next_msg(&mut self) -> Result<Option<Msg>> {
        let avail = self.buf.get(self.start..).unwrap_or(&[]);
        let Some(h) = avail.get(..HEADER) else {
            return Ok(None);
        };
        let mut r = Reader::new(h);
        if r.array::<4>()? != MAGIC || r.u8()? != VERSION {
            return Err(Error::BadMagic);
        }
        let kind = r.u8()?;
        let flags = r.u16()?;
        let len = usize::try_from(r.u32()?).unwrap_or(usize::MAX);
        if len > MAX_FRAME {
            return Err(Error::TooLong {
                what: "frame",
                len,
                max: MAX_FRAME,
            });
        }
        let Some(payload) = avail.get(HEADER..HEADER + len) else {
            return Ok(None);
        };
        let m = Msg::decode_flagged(kind, flags, payload)?;
        self.start += HEADER + len;
        if self.start == self.buf.len() {
            self.buf.clear();
            self.start = 0;
        }
        Ok(Some(m))
    }
}

/// Encodes `msgs` one after the other (a convenience for tests and the lab).
pub fn encode_all(msgs: &[Msg], out: &mut Vec<u8>) -> wire::Result<()> {
    for m in msgs {
        m.encode(out)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u32) -> Key {
        Key::new(&n.to_le_bytes()).unwrap()
    }

    pub(crate) fn samples() -> Vec<Msg> {
        vec![
            Msg::Hello(Hello {
                version: VERSION,
                node_id: 7,
                epoch: 3,
                role: Role::Standby,
                priority: 100,
                hot_standby: true,
                stream: 99,
                applied: 12,
                sessions: 2,
                sections: vec![Section {
                    name: "ppp.profile".into(),
                    hash: 0xdead,
                }],
                features: FEATURE_FORWARD,
            }),
            Msg::Heartbeat(Heartbeat {
                node_id: 7,
                incarnation: 70,
                hears: 80,
                view_seq: 3,
                acked: 2,
                epoch: 4,
                role: Role::Active,
                priority: 200,
                witness: true,
                in_sync: false,
                eligible: true,
                stream: 1,
                seq: 2,
                sessions: 3,
            }),
            Msg::SnapshotBegin {
                stream: 1,
                base: 10,
                total: 2,
            },
            Msg::SnapshotChunk {
                stream: 1,
                records: vec![Record {
                    key: key(1),
                    value: Arc::from(&b"abc"[..]),
                    counters: Counters {
                        rx_bytes: 1,
                        tx_bytes: 2,
                        rx_packets: 3,
                        tx_packets: 4,
                    },
                }],
            },
            Msg::SnapshotEnd {
                stream: 1,
                base: 10,
                count: 1,
            },
            Msg::Delta {
                stream: 1,
                first: 11,
                ops: vec![
                    Op::Upsert {
                        key: key(2),
                        value: Arc::from(&b"x"[..]),
                    },
                    Op::Remove { key: key(1) },
                    Op::Counters {
                        key: key(2),
                        c: Counters::default(),
                    },
                ],
            },
            Msg::Ack { stream: 1, seq: 13 },
            Msg::Resync { stream: 1, from: 5 },
            Msg::Handover { epoch: 4 },
            Msg::HandoverRequest { epoch: 4 },
            Msg::Challenge { nonce: [7; 32] },
            Msg::Proof {
                node_id: 9,
                mac: [3; 32],
            },
            Msg::Forward {
                id: 5,
                body: b"{\"kind\":\"coa\"}".to_vec(),
            },
            Msg::ForwardReply {
                id: 5,
                body: Vec::new(),
            },
        ]
    }

    /// G4.3hb: an older reader (it ignored the reserved bytes) reads a
    /// Hello with features as it was; a Forward is never sent to it.
    #[test]
    fn hello_features_ride_in_the_reserved_bytes() {
        let Some(Msg::Hello(h)) = samples().into_iter().next() else {
            panic!("the first sample is a Hello");
        };
        let mut b = Vec::new();
        Msg::Hello(h.clone()).encode(&mut b).unwrap();
        assert_eq!(&b[6..8], &FEATURE_FORWARD.to_le_bytes());
        let payload = &b[HEADER..];
        let Ok(Msg::Hello(old)) = Msg::decode(kind::HELLO, payload) else {
            panic!("decodes without the header");
        };
        assert_eq!(old.features, 0);
        assert_eq!(
            Hello {
                features: FEATURE_FORWARD,
                ..old
            },
            h
        );
        let big = Msg::Forward {
            id: 1,
            body: vec![0; MAX_FORWARD + 1],
        };
        assert!(big.encode(&mut Vec::new()).is_err());
    }

    #[test]
    fn every_message_round_trips_through_a_byte_at_a_time_stream() {
        let msgs = samples();
        let mut bytes = Vec::new();
        encode_all(&msgs, &mut bytes).unwrap();
        let mut fr = FrameReader::new();
        let mut back = Vec::new();
        for b in bytes {
            fr.push(&[b]);
            while let Some(m) = fr.next_msg().unwrap() {
                back.push(m);
            }
        }
        assert_eq!(back, msgs);
        assert_eq!(fr.pending(), 0);
    }

    #[test]
    fn hostile_headers_are_refused_without_buffering() {
        let mut fr = FrameReader::new();
        fr.push(b"HTTP/1.1 200 OK\r\n");
        assert_eq!(fr.next_msg(), Err(Error::BadMagic));
        let mut fr = FrameReader::new();
        let mut h = MAGIC.to_vec();
        h.extend_from_slice(&[VERSION, kind::ACK, 0, 0]);
        h.extend_from_slice(&u32::MAX.to_le_bytes());
        fr.push(&h);
        assert!(matches!(fr.next_msg(), Err(Error::TooLong { .. })));
        // A count bigger than the payload allocates nothing and fails.
        let mut p = Vec::new();
        put_u64(&mut p, 1);
        put_u32(&mut p, MAX_OPS as u32);
        assert!(Msg::decode(kind::SNAPSHOT_CHUNK, &p).is_err());
        assert_eq!(Msg::decode(99, &[]), Err(Error::UnknownKind(99)));
        // Trailing bytes are an error, not ignored.
        let mut p = Vec::new();
        put_u64(&mut p, 1);
        put_u64(&mut p, 2);
        p.push(0);
        assert_eq!(Msg::decode(kind::ACK, &p), Err(Error::Trailing(1)));
    }

    #[test]
    fn oversized_messages_are_refused_on_encode() {
        let big = Msg::Delta {
            stream: 1,
            first: 1,
            ops: vec![Op::Remove { key: key(1) }; MAX_OPS + 1],
        };
        let mut out = vec![1, 2, 3];
        assert!(big.encode(&mut out).is_err());
        assert_eq!(out, [1, 2, 3], "nothing half-written");
        let huge = Msg::SnapshotChunk {
            stream: 1,
            records: vec![
                Record {
                    key: key(1),
                    value: Arc::from(vec![0u8; MAX_VALUE + 1]),
                    counters: Counters::default(),
                };
                1
            ],
        };
        assert!(huge.encode(&mut out).is_err());
        assert!(Key::new(&[0; MAX_KEY + 1]).is_none());
    }

    #[test]
    fn a_sequence_that_would_wrap_is_refused() {
        let m = Msg::Delta {
            stream: 1,
            first: u64::MAX,
            ops: vec![Op::Remove { key: key(1) }],
        };
        let mut b = Vec::new();
        m.encode(&mut b).unwrap();
        let mut fr = FrameReader::new();
        fr.push(&b);
        assert_eq!(fr.next_msg(), Err(Error::BadValue("sequence")));
    }
}
