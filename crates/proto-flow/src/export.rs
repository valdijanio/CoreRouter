//! The exporting side: records in, messages out (one datagram each over
//! UDP, back to back over TCP).
//!
//! - IPFIX (RFC 7011): 16-byte header (§3.1); the sequence number counts
//!   the data records sent before this message in this observation domain
//!   (§3.1, template records do not count); template set id 2, options
//!   template set id 3 (§3.3.2); no padding (§3.3.1 allows, never requires).
//! - NetFlow v9 (RFC 3954): 20-byte header (§5.1) whose count is every
//!   record of the packet, templates included, and whose sequence number
//!   counts packets (§5.1); template FlowSet id 0, options template id 1
//!   (§5.2, §6.1); each FlowSet padded to 32 bits (§5.3).
//! - Over UDP the templates are sent again every `refresh_ms` and every
//!   `refresh_packets` messages (RFC 7011 §8.4, RFC 3954 §9; RouterOS
//!   `v9-template-timeout` and `v9-template-refresh`), so a collector that
//!   restarted learns them back. Over a stream they go once per connection
//!   (RFC 7011 §8.1), and again when they change.

use crate::record::{Meta, Record};
use crate::template::{self, Row, Template, Version};

/// The smallest message size accepted: every template fits in one message.
pub const MIN_MESSAGE: usize = 512;
/// The default: under a 1500-byte MTU after IPv6 and UDP headers, with room
/// for a tunnel (RFC 7011 §10.3.3: avoid fragmentation).
pub const DEFAULT_MESSAGE: usize = 1400;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub version: Version,
    /// IPFIX observation domain id, v9 source id.
    pub domain: u32,
    /// Largest message in bytes (clamped to [`MIN_MESSAGE`]..=65535).
    pub max_size: usize,
    /// Templates again after this many ms (0: never by time).
    pub refresh_ms: u64,
    /// … and after this many messages (0: never by count).
    pub refresh_packets: u32,
    /// TCP/SCTP: templates once per connection, no refresh.
    pub stream: bool,
    /// Unix ms the v9 sysUpTime counts from.
    pub boot_ms: u64,
    /// NAT events with the destination (template `NAT44`) or without
    /// (`NAT44_SRC`, the default of `/ip traffic-flow`).
    pub nat_destination: bool,
    /// `natEvent` 1/2 instead of 4/5 for the NAT44 session events
    /// ([`crate::NatEventType::legacy_code`]).
    pub legacy_nat: bool,
}

/// What an exporter sent, for the statistics.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counters {
    pub messages: u64,
    pub bytes: u64,
    pub data_records: u64,
    /// Times the templates went out.
    pub template_sends: u64,
}

#[derive(Debug, Clone)]
pub struct Exporter {
    cfg: Config,
    templates: Vec<Template>,
    /// Per template, its record's bytes when no field is variable: sized
    /// without walking the fields for each record.
    fixed: Vec<Option<usize>>,
    meta: Meta,
    seq: u32,
    last_templates: Option<u64>,
    since_templates: u32,
    counters: Counters,
}

/// One message being filled.
struct Msg {
    buf: Vec<u8>,
    /// Start of the open set and its id.
    set: Option<(usize, u16)>,
    /// v9 count (every record), IPFIX data records.
    records: u16,
    data: u32,
}

impl Exporter {
    pub fn new(mut cfg: Config) -> Self {
        cfg.max_size = cfg.max_size.clamp(MIN_MESSAGE, 65535);
        Self {
            fixed: template::all(cfg.version)
                .iter()
                .map(|t| {
                    t.fields
                        .iter()
                        .all(|f| f.len != crate::ie::VARIABLE)
                        .then(|| t.record_len())
                })
                .collect(),
            templates: template::all(cfg.version),
            cfg,
            meta: Meta::default(),
            seq: 0,
            last_templates: None,
            since_templates: 0,
            counters: Counters::default(),
        }
    }

    pub fn config(&self) -> &Config {
        &self.cfg
    }

    pub fn counters(&self) -> Counters {
        self.counters
    }

    /// New sampling rate or interface names: sent with the templates, now.
    pub fn set_meta(&mut self, meta: Meta) {
        if meta != self.meta {
            self.meta = meta;
            self.last_templates = None;
        }
    }

    /// A new stream connection: it needs the templates again.
    pub fn reset_stream(&mut self) {
        self.last_templates = None;
    }

    fn templates_due(&self, now_ms: u64) -> bool {
        let Some(last) = self.last_templates else {
            return true;
        };
        if self.cfg.stream {
            return false;
        }
        (self.cfg.refresh_ms > 0 && now_ms.saturating_sub(last) >= self.cfg.refresh_ms)
            || (self.cfg.refresh_packets > 0 && self.since_templates >= self.cfg.refresh_packets)
    }

    fn header_len(&self) -> usize {
        match self.cfg.version {
            Version::Ipfix => 16,
            Version::V9 => 20,
        }
    }

    fn open(&self) -> Msg {
        let mut buf = Vec::with_capacity(self.cfg.max_size);
        buf.resize(self.header_len(), 0);
        Msg {
            buf,
            set: None,
            records: 0,
            data: 0,
        }
    }

    fn pad(&self, m: &mut Msg) {
        if self.cfg.version == Version::V9 {
            while !m.buf.len().is_multiple_of(4) {
                m.buf.push(0);
            }
        }
    }

    fn close_set(&self, m: &mut Msg) {
        if let Some((start, _)) = m.set.take() {
            self.pad(m);
            let len = u16::try_from(m.buf.len() - start).unwrap_or(u16::MAX);
            if let Some(slot) = m.buf.get_mut(start + 2..start + 4) {
                slot.copy_from_slice(&len.to_be_bytes());
            }
        }
    }

    fn open_set(&self, m: &mut Msg, id: u16) {
        self.close_set(m);
        m.set = Some((m.buf.len(), id));
        m.buf.extend_from_slice(&id.to_be_bytes());
        m.buf.extend_from_slice(&[0, 0]);
    }

    /// Template and options template sets, then the options records.
    fn put_templates(&mut self, m: &mut Msg, now_ms: u64, out: &mut Vec<Vec<u8>>) {
        self.put_template_sets(m);
        self.last_templates = Some(now_ms);
        self.since_templates = 0;
        self.counters.template_sends += 1;
        let meta = std::mem::take(&mut self.meta);
        let interval = meta.sampling_interval.max(1);
        self.add(
            m,
            Row::Sampling {
                domain: self.cfg.domain,
                interval,
            },
            now_ms,
            out,
        );
        for (index, name) in &meta.interfaces {
            self.add(
                m,
                Row::Interface {
                    index: *index,
                    name,
                },
                now_ms,
                out,
            );
        }
        self.meta = meta;
    }

    /// The template and options template sets.
    fn put_template_sets(&self, m: &mut Msg) {
        let v9 = self.cfg.version == Version::V9;
        let (data_set, opt_set) = if v9 { (0, 1) } else { (2, 3) };
        self.open_set(m, data_set);
        for t in self.templates.iter().filter(|t| t.scope == 0) {
            m.buf.extend_from_slice(&t.id.to_be_bytes());
            m.buf
                .extend_from_slice(&u16::try_from(t.fields.len()).unwrap_or(0).to_be_bytes());
            put_fields(&mut m.buf, &t.fields);
            m.records = m.records.saturating_add(1);
        }
        self.open_set(m, opt_set);
        for t in self.templates.iter().filter(|t| t.scope > 0) {
            let scope = usize::from(t.scope).min(t.fields.len());
            let (sc, rest) = t.fields.split_at(scope);
            m.buf.extend_from_slice(&t.id.to_be_bytes());
            if v9 {
                // RFC 3954 §6.1: lengths in bytes of the scope and option specs.
                let len = |n: usize| u16::try_from(n * 4).unwrap_or(0).to_be_bytes();
                m.buf.extend_from_slice(&len(sc.len()));
                m.buf.extend_from_slice(&len(rest.len()));
            } else {
                let n = u16::try_from(t.fields.len()).unwrap_or(0);
                m.buf.extend_from_slice(&n.to_be_bytes());
                m.buf.extend_from_slice(&t.scope.to_be_bytes());
            }
            put_fields(&mut m.buf, &t.fields);
            m.records = m.records.saturating_add(1);
        }
        self.close_set(m);
    }

    /// Append one data record, finishing the message first when it would
    /// not fit.
    fn add(&mut self, m: &mut Msg, row: Row<'_>, now_ms: u64, out: &mut Vec<Vec<u8>>) {
        let tid = match row {
            Row::Nat(_) if !self.cfg.nat_destination => template::NAT44_SRC,
            _ => row.template(),
        };
        let Some(slot) = self.templates.iter().position(|t| t.id == tid) else {
            return;
        };
        let len = match (self.fixed.get(slot).copied().flatten(), self.templates.get(slot)) {
            (Some(n), _) => n,
            (None, Some(t)) => t.row_len(row),
            (None, None) => return,
        };
        let same = matches!(m.set, Some((_, id)) if id == tid);
        let need = len + if same { 0 } else { 4 } + 3;
        if m.buf.len() + need > self.cfg.max_size && m.records > 0 {
            let full = std::mem::replace(m, self.open());
            out.push(self.finish(full, now_ms));
            if self.templates_due(now_ms) {
                self.put_templates(m, now_ms, out);
            }
        }
        if !matches!(m.set, Some((_, id)) if id == tid) {
            self.open_set(m, tid);
        }
        let how = template::Put {
            boot_ms: self.cfg.boot_ms,
            legacy_nat: self.cfg.legacy_nat,
        };
        if let Some(t) = self.templates.get(slot) {
            for field in &t.fields {
                template::put(&mut m.buf, *field, row, how);
            }
        }
        m.records = m.records.saturating_add(1);
        m.data = m.data.saturating_add(1);
    }

    fn finish(&mut self, mut m: Msg, now_ms: u64) -> Vec<u8> {
        self.close_set(&mut m);
        let secs = u32::try_from(now_ms / 1000).unwrap_or(u32::MAX);
        let len = u16::try_from(m.buf.len()).unwrap_or(u16::MAX);
        let mut h = Vec::with_capacity(20);
        h.extend_from_slice(&self.cfg.version.number().to_be_bytes());
        match self.cfg.version {
            Version::Ipfix => {
                h.extend_from_slice(&len.to_be_bytes());
                h.extend_from_slice(&secs.to_be_bytes());
                h.extend_from_slice(&self.seq.to_be_bytes());
                self.seq = self.seq.wrapping_add(m.data);
            }
            Version::V9 => {
                h.extend_from_slice(&m.records.to_be_bytes());
                let up = u32::try_from(now_ms.saturating_sub(self.cfg.boot_ms) & 0xffff_ffff)
                    .unwrap_or(0);
                h.extend_from_slice(&up.to_be_bytes());
                h.extend_from_slice(&secs.to_be_bytes());
                h.extend_from_slice(&self.seq.to_be_bytes());
                self.seq = self.seq.wrapping_add(1);
            }
        }
        h.extend_from_slice(&self.cfg.domain.to_be_bytes());
        if let Some(slot) = m.buf.get_mut(..h.len()) {
            slot.copy_from_slice(&h);
        }
        self.since_templates = self.since_templates.saturating_add(1);
        self.counters.messages += 1;
        self.counters.bytes += m.buf.len() as u64;
        self.counters.data_records += u64::from(m.data);
        m.buf
    }

    /// Encode `records` into messages appended to `out`. With no records
    /// it still sends the templates when they are due (a quiet exporter
    /// keeps its collector's templates fresh).
    pub fn encode(&mut self, now_ms: u64, records: &[Record], out: &mut Vec<Vec<u8>>) {
        self.encode_iter(now_ms, records, out);
    }

    /// [`Self::encode`] over any records (a collector's share of a batch,
    /// without copying it).
    pub fn encode_iter<'a>(
        &mut self,
        now_ms: u64,
        records: impl IntoIterator<Item = &'a Record>,
        out: &mut Vec<Vec<u8>>,
    ) {
        let mut m = self.open();
        if self.templates_due(now_ms) {
            self.put_templates(&mut m, now_ms, out);
        }
        for r in records {
            let row = match r {
                Record::Flow(f) => Row::Flow(f),
                Record::Nat(n) => Row::Nat(n),
                Record::PortBlock(b) => Row::Block(b),
                Record::NatLimit(l) => Row::Limit(l),
            };
            self.add(&mut m, row, now_ms, out);
        }
        if m.records > 0 {
            out.push(self.finish(m, now_ms));
        }
    }
}

impl Exporter {
    /// A message with the template and options template sets only, no
    /// data records (IPFIX): what a stream sender puts first on a new
    /// connection, before the messages that waited for it (RFC 7011 §8.1:
    /// templates before the data that uses them). Its sequence number is
    /// left for the sender to set ([`set_sequence`]): with no data records
    /// it takes the one of the message after it, so the collector sees no
    /// gap. Changes nothing in the exporter.
    pub fn templates_only(&self, now_ms: u64) -> Vec<u8> {
        let mut e = self.clone();
        e.meta = Meta::default();
        let mut m = e.open();
        e.put_template_sets(&mut m);
        let mut msg = e.finish(m, now_ms);
        // The options records of `put_templates` are not here: the header
        // counts no data.
        set_sequence(&mut msg, 0);
        msg
    }
}

/// Overwrite the sequence number of an IPFIX message (RFC 7011 §3.1,
/// bytes 8–11).
pub fn set_sequence(msg: &mut [u8], seq: u32) {
    if let Some(slot) = msg.get_mut(8..12) {
        slot.copy_from_slice(&seq.to_be_bytes());
    }
}

/// The sequence number of an IPFIX message.
pub fn sequence(msg: &[u8]) -> Option<u32> {
    Some(u32::from_be_bytes(msg.get(8..12)?.try_into().ok()?))
}

fn put_fields(buf: &mut Vec<u8>, fields: &[crate::ie::Field]) {
    for f in fields {
        buf.extend_from_slice(&f.id.to_be_bytes());
        buf.extend_from_slice(&f.len.to_be_bytes());
    }
}
