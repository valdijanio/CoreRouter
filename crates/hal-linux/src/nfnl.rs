//! nf_tables over nfnetlink, without the `nft` program (G2.3b).
//!
//! The kernel's nftables API is a batch of netlink messages between
//! `NFNL_MSG_BATCH_BEGIN` and `NFNL_MSG_BATCH_END`: the kernel commits the
//! whole batch or none of it, so replacing a table (create, delete,
//! recreate, fill) is one transaction, as `nft -f` makes it. The encoder
//! is pure (bytes in a `Vec`, tested against what `nft --debug=netlink,mnl`
//! sends); the socket half is Linux-only and safe (`netlink-sys`).
//!
//! What we encode is a `corerouter_firewall::program::Table`: the same
//! description "View generated rules" prints, so the text is what the
//! kernel holds. Attribute numbers are the UAPI's
//! (`include/uapi/linux/netfilter/nf_tables.h`); every integer attribute
//! is big-endian, element and register data are packet-order bytes.

use corerouter_firewall::program::{
    Base, Chain, Dir, Element, Expr, FAMILY_IPV4, NatKind, Rule, Set, Table,
};

const NLA_HDR: usize = 4;
const NLA_F_NESTED: u16 = 1 << 15;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_ACK: u16 = 0x4;
const NLM_F_CREATE: u16 = 0x400;
const NLM_F_APPEND: u16 = 0x800;

pub const NFNL_SUBSYS_NFTABLES: u16 = 10;
const NFNL_MSG_BATCH_BEGIN: u16 = 16;
const NFNL_MSG_BATCH_END: u16 = 17;

// enum nf_tables_msg_types
const NFT_MSG_NEWTABLE: u16 = 0;
const NFT_MSG_DELTABLE: u16 = 2;
const NFT_MSG_NEWCHAIN: u16 = 3;
const NFT_MSG_NEWRULE: u16 = 6;
const NFT_MSG_NEWSET: u16 = 9;
const NFT_MSG_NEWSETELEM: u16 = 12;
const NFT_MSG_DELSETELEM: u16 = 14;

const NFTA_TABLE_NAME: u16 = 1;
const NFTA_CHAIN_TABLE: u16 = 1;
const NFTA_CHAIN_NAME: u16 = 3;
const NFTA_CHAIN_HOOK: u16 = 4;
const NFTA_CHAIN_POLICY: u16 = 5;
const NFTA_CHAIN_TYPE: u16 = 7;
const NFTA_HOOK_HOOKNUM: u16 = 1;
const NFTA_HOOK_PRIORITY: u16 = 2;
const NFTA_RULE_TABLE: u16 = 1;
const NFTA_RULE_CHAIN: u16 = 2;
const NFTA_RULE_EXPRESSIONS: u16 = 4;
const NFTA_LIST_ELEM: u16 = 1;
const NFTA_EXPR_NAME: u16 = 1;
const NFTA_EXPR_DATA: u16 = 2;
const NFTA_SET_TABLE: u16 = 1;
const NFTA_SET_NAME: u16 = 2;
const NFTA_SET_FLAGS: u16 = 3;
const NFTA_SET_KEY_TYPE: u16 = 4;
const NFTA_SET_KEY_LEN: u16 = 5;
const NFTA_SET_DATA_TYPE: u16 = 6;
const NFTA_SET_DATA_LEN: u16 = 7;
const NFTA_SET_DESC: u16 = 9;
const NFTA_SET_DESC_SIZE: u16 = 1;
const NFTA_SET_ID: u16 = 10;
const NFTA_SET_TIMEOUT: u16 = 11;
const NFTA_SET_USERDATA: u16 = 13;
const NFTA_SET_ELEM_LIST_TABLE: u16 = 1;
const NFTA_SET_ELEM_LIST_SET: u16 = 2;
const NFTA_SET_ELEM_LIST_ELEMENTS: u16 = 3;
const NFTA_SET_ELEM_KEY: u16 = 1;
const NFTA_SET_ELEM_DATA: u16 = 2;
const NFTA_SET_ELEM_FLAGS: u16 = 3;
const NFT_SET_ELEM_INTERVAL_END: u32 = 1;
const NFTA_DATA_VALUE: u16 = 1;
const NFTA_DATA_VERDICT: u16 = 2;
const NFTA_VERDICT_CODE: u16 = 1;
const NF_ACCEPT: u32 = 1;
const NF_DROP: u32 = 0;

// Expression attributes.
const NFTA_PAYLOAD_DREG: u16 = 1;
const NFTA_PAYLOAD_BASE: u16 = 2;
const NFTA_PAYLOAD_OFFSET: u16 = 3;
const NFTA_PAYLOAD_LEN: u16 = 4;
const NFTA_META_DREG: u16 = 1;
const NFTA_META_KEY: u16 = 2;
const NFTA_CMP_SREG: u16 = 1;
const NFTA_CMP_OP: u16 = 2;
const NFTA_CMP_DATA: u16 = 3;
const NFTA_BITWISE_SREG: u16 = 1;
const NFTA_BITWISE_DREG: u16 = 2;
const NFTA_BITWISE_LEN: u16 = 3;
const NFTA_BITWISE_MASK: u16 = 4;
const NFTA_BITWISE_XOR: u16 = 5;
const NFTA_CT_DREG: u16 = 1;
const NFTA_CT_KEY: u16 = 2;
const NFTA_CT_DIRECTION: u16 = 3;
const NFTA_LOOKUP_SET: u16 = 1;
const NFTA_LOOKUP_SREG: u16 = 2;
const NFTA_LOOKUP_DREG: u16 = 3;
const NFTA_LOOKUP_FLAGS: u16 = 5;
const NFT_LOOKUP_F_INV: u32 = 1;
const NFTA_QUEUE_NUM: u16 = 1;
const NFTA_QUEUE_TOTAL: u16 = 2;
const NFTA_QUEUE_FLAGS: u16 = 3;
const NFTA_NAT_TYPE: u16 = 1;
const NFTA_NAT_FAMILY: u16 = 2;
const NFTA_NAT_REG_ADDR_MIN: u16 = 3;
const NFTA_NAT_REG_ADDR_MAX: u16 = 4;
const NFTA_NAT_REG_PROTO_MIN: u16 = 5;
const NFTA_NAT_REG_PROTO_MAX: u16 = 6;
const NFTA_DYNSET_SET_NAME: u16 = 1;
const NFTA_DYNSET_OP: u16 = 3;
const NFTA_DYNSET_SREG_KEY: u16 = 4;
const NFTA_DYNSET_SREG_DATA: u16 = 5;
const NFT_DYNSET_OP_UPDATE: u32 = 1;
const NFTA_IMMEDIATE_DREG: u16 = 1;
const NFTA_IMMEDIATE_DATA: u16 = 2;

/// nft's private set metadata (`NFTNL_UDATA_SET_*`) so `nft list` prints
/// our sets as it prints its own: key byte order big-endian, data byte
/// order, and "data is an interval" for the ranged maps.
const UDATA_KEY_BIG_ENDIAN: [u8; 6] = [0, 4, 2, 0, 0, 0];
const UDATA_DATA_INTERVAL: [u8; 6] = [6, 4, 1, 0, 0, 0];

/// One attribute's worth of bytes per netlink message is bounded by its
/// 16-bit length: elements go in messages of at most this many.
pub const ELEMENTS_PER_MESSAGE: usize = 512;

/// A batch being built.
#[derive(Debug)]
pub struct Batch {
    buf: Vec<u8>,
    /// Start of the message being written.
    msg: usize,
    /// Start offsets of the nests still open.
    open: Vec<usize>,
    seq: u32,
    /// Sequence numbers of the messages that want an answer.
    first: u32,
    set_ids: u32,
}

impl Batch {
    pub fn new(seq: u32) -> Self {
        let mut b = Self {
            buf: Vec::with_capacity(4096),
            msg: 0,
            open: Vec::new(),
            seq,
            first: seq.wrapping_add(1),
            set_ids: 0,
        };
        b.header(NFNL_MSG_BATCH_BEGIN, NLM_F_REQUEST, 0, NFNL_SUBSYS_NFTABLES);
        b.close_msg();
        b
    }

    fn header(&mut self, kind: u16, flags: u16, family: u8, res_id: u16) {
        self.msg = self.buf.len();
        self.buf.extend_from_slice(&0u32.to_ne_bytes());
        self.buf.extend_from_slice(&kind.to_ne_bytes());
        self.buf.extend_from_slice(&flags.to_ne_bytes());
        self.buf.extend_from_slice(&self.seq.to_ne_bytes());
        self.buf.extend_from_slice(&0u32.to_ne_bytes());
        // nfgenmsg: family, version 0, res_id (big-endian).
        self.buf.push(family);
        self.buf.push(0);
        self.buf.extend_from_slice(&res_id.to_be_bytes());
    }

    fn close_msg(&mut self) {
        while !self.open.is_empty() {
            self.end();
        }
        let len = u32::try_from(self.buf.len() - self.msg).unwrap_or(u32::MAX);
        if let Some(slot) = self.buf.get_mut(self.msg..self.msg + 4) {
            slot.copy_from_slice(&len.to_ne_bytes());
        }
        self.seq = self.seq.wrapping_add(1);
    }

    /// Start an nf_tables message of type `msg`.
    fn begin_msg(&mut self, msg: u16, flags: u16) {
        let kind = (NFNL_SUBSYS_NFTABLES << 8) | msg;
        self.header(kind, NLM_F_REQUEST | NLM_F_ACK | flags, FAMILY_IPV4, 0);
    }

    fn put(&mut self, kind: u16, data: &[u8]) {
        let len = u16::try_from(NLA_HDR + data.len()).unwrap_or(u16::MAX);
        self.buf.extend_from_slice(&len.to_ne_bytes());
        self.buf.extend_from_slice(&kind.to_ne_bytes());
        self.buf.extend_from_slice(data);
        self.buf.resize(self.buf.len().div_ceil(4) * 4, 0);
    }

    fn be32(&mut self, kind: u16, v: u32) {
        self.put(kind, &v.to_be_bytes());
    }

    fn be64(&mut self, kind: u16, v: u64) {
        self.put(kind, &v.to_be_bytes());
    }

    fn str(&mut self, kind: u16, s: &str) {
        let mut d = s.as_bytes().to_vec();
        d.push(0);
        self.put(kind, &d);
    }

    fn begin(&mut self, kind: u16) {
        self.open.push(self.buf.len());
        self.put(kind | NLA_F_NESTED, &[]);
    }

    fn end(&mut self) {
        if let Some(start) = self.open.pop() {
            let len = u16::try_from(self.buf.len().saturating_sub(start)).unwrap_or(u16::MAX);
            if let Some(slot) = self.buf.get_mut(start..start + 2) {
                slot.copy_from_slice(&len.to_ne_bytes());
            }
        }
    }

    /// `NFTA_DATA_VALUE` inside attribute `kind`.
    fn value(&mut self, kind: u16, bytes: &[u8]) {
        self.begin(kind);
        self.put(NFTA_DATA_VALUE, bytes);
        self.end();
    }

    pub fn new_table(&mut self, name: &str) {
        self.begin_msg(NFT_MSG_NEWTABLE, NLM_F_CREATE);
        self.str(NFTA_TABLE_NAME, name);
        self.close_msg();
    }

    pub fn del_table(&mut self, name: &str) {
        self.begin_msg(NFT_MSG_DELTABLE, 0);
        self.str(NFTA_TABLE_NAME, name);
        self.close_msg();
    }

    pub fn new_chain(&mut self, table: &str, c: &Chain) {
        self.begin_msg(NFT_MSG_NEWCHAIN, NLM_F_CREATE);
        self.str(NFTA_CHAIN_TABLE, table);
        self.str(NFTA_CHAIN_NAME, &c.name);
        self.begin(NFTA_CHAIN_HOOK);
        self.be32(NFTA_HOOK_HOOKNUM, c.hook.number());
        self.put(NFTA_HOOK_PRIORITY, &c.priority.to_be_bytes());
        self.end();
        self.be32(NFTA_CHAIN_POLICY, NF_ACCEPT);
        self.str(NFTA_CHAIN_TYPE, c.kind.name());
        self.close_msg();
    }

    pub fn new_set(&mut self, table: &str, s: &Set) {
        self.set_ids = self.set_ids.wrapping_add(1);
        self.begin_msg(NFT_MSG_NEWSET, NLM_F_CREATE);
        self.str(NFTA_SET_TABLE, table);
        self.str(NFTA_SET_NAME, &s.name);
        self.be32(NFTA_SET_FLAGS, s.flags());
        self.be32(NFTA_SET_KEY_TYPE, s.key.nft_id());
        self.be32(NFTA_SET_KEY_LEN, s.key.len());
        if let Some(d) = s.data {
            self.be32(NFTA_SET_DATA_TYPE, d.nft_id());
            self.be32(NFTA_SET_DATA_LEN, d.len());
        }
        if let Some(t) = s.dynamic_timeout {
            self.be64(NFTA_SET_TIMEOUT, u64::from(t) * 1000);
        }
        self.be32(NFTA_SET_ID, self.set_ids);
        if let Some(n) = s.size {
            self.begin(NFTA_SET_DESC);
            self.be32(NFTA_SET_DESC_SIZE, n);
            self.end();
        }
        let mut udata = UDATA_KEY_BIG_ENDIAN.to_vec();
        if s.data == Some(corerouter_firewall::program::Type::AddrPortRange) {
            udata.extend_from_slice(&UDATA_DATA_INTERVAL);
        }
        self.put(NFTA_SET_USERDATA, &udata);
        self.close_msg();
    }

    /// Elements `items` of set `set`, added (`add`) or deleted, in
    /// messages of at most [`ELEMENTS_PER_MESSAGE`].
    pub fn elements(&mut self, table: &str, s: &Set, items: &[Element], add: bool) {
        // Interval sets go as start/end pairs (rbtree encoding).
        let pairs: Vec<(Vec<u8>, Option<Vec<u8>>, u32)> = if s.interval {
            let one = Set {
                elements: items.to_vec(),
                ..s.clone()
            };
            one.interval_elements()
                .into_iter()
                .map(|(k, end)| (k, None, if end { NFT_SET_ELEM_INTERVAL_END } else { 0 }))
                .collect()
        } else {
            items
                .iter()
                .map(|e| (e.key.bytes(), e.data.map(|d| d.bytes()), 0))
                .collect()
        };
        for chunk in pairs.chunks(ELEMENTS_PER_MESSAGE) {
            let msg = if add {
                NFT_MSG_NEWSETELEM
            } else {
                NFT_MSG_DELSETELEM
            };
            self.begin_msg(msg, if add { NLM_F_CREATE } else { 0 });
            self.str(NFTA_SET_ELEM_LIST_TABLE, table);
            self.str(NFTA_SET_ELEM_LIST_SET, &s.name);
            self.begin(NFTA_SET_ELEM_LIST_ELEMENTS);
            for (key, data, flags) in chunk {
                self.begin(NFTA_LIST_ELEM);
                if *flags != 0 {
                    self.be32(NFTA_SET_ELEM_FLAGS, *flags);
                }
                self.value(NFTA_SET_ELEM_KEY, key);
                if let Some(d) = data {
                    self.value(NFTA_SET_ELEM_DATA, d);
                }
                self.end();
            }
            self.close_msg();
        }
    }

    /// Empty set `set` (a `DELSETELEM` without elements).
    pub fn flush_set(&mut self, table: &str, set: &str) {
        self.begin_msg(NFT_MSG_DELSETELEM, 0);
        self.str(NFTA_SET_ELEM_LIST_TABLE, table);
        self.str(NFTA_SET_ELEM_LIST_SET, set);
        self.close_msg();
    }

    pub fn new_rule(&mut self, table: &str, r: &Rule) {
        self.begin_msg(NFT_MSG_NEWRULE, NLM_F_CREATE | NLM_F_APPEND);
        self.str(NFTA_RULE_TABLE, table);
        self.str(NFTA_RULE_CHAIN, &r.chain);
        self.begin(NFTA_RULE_EXPRESSIONS);
        for e in &r.exprs {
            self.expr(e);
        }
        self.end();
        self.close_msg();
    }

    fn expr(&mut self, e: &Expr) {
        self.begin(NFTA_LIST_ELEM);
        let name = match e {
            Expr::Payload { .. } => "payload",
            Expr::Meta { .. } => "meta",
            Expr::Cmp { .. } => "cmp",
            Expr::And { .. } => "bitwise",
            Expr::Ct { .. } => "ct",
            Expr::Lookup { .. } => "lookup",
            Expr::Nat { .. } => "nat",
            Expr::Update { .. } => "dynset",
            Expr::Counter => "counter",
            Expr::Drop => "immediate",
            Expr::Queue { .. } => "queue",
        };
        self.str(NFTA_EXPR_NAME, name);
        self.begin(NFTA_EXPR_DATA);
        match e {
            Expr::Payload {
                base,
                offset,
                len,
                dreg,
            } => {
                self.be32(NFTA_PAYLOAD_DREG, *dreg);
                self.be32(
                    NFTA_PAYLOAD_BASE,
                    match base {
                        Base::Network => 1,
                        Base::Transport => 2,
                    },
                );
                self.be32(NFTA_PAYLOAD_OFFSET, *offset);
                self.be32(NFTA_PAYLOAD_LEN, *len);
            }
            Expr::Meta { key, dreg } => {
                self.be32(NFTA_META_DREG, *dreg);
                self.be32(NFTA_META_KEY, key.number());
            }
            Expr::Cmp { sreg, eq, data } => {
                self.be32(NFTA_CMP_SREG, *sreg);
                self.be32(NFTA_CMP_OP, if *eq { 0 } else { 1 });
                self.value(NFTA_CMP_DATA, data);
            }
            Expr::And { sreg, dreg, mask } => {
                self.be32(NFTA_BITWISE_SREG, *sreg);
                self.be32(NFTA_BITWISE_DREG, *dreg);
                self.be32(NFTA_BITWISE_LEN, u32::try_from(mask.len()).unwrap_or(4));
                self.value(NFTA_BITWISE_MASK, mask);
                self.value(NFTA_BITWISE_XOR, &vec![0; mask.len()]);
            }
            Expr::Ct { key, dir, dreg } => {
                self.be32(NFTA_CT_DREG, *dreg);
                self.be32(NFTA_CT_KEY, key.number());
                if let Some(d) = dir {
                    self.put(NFTA_CT_DIRECTION, &[if *d == Dir::Reply { 1 } else { 0 }]);
                }
            }
            Expr::Lookup {
                set,
                sreg,
                dreg,
                inv,
            } => {
                self.str(NFTA_LOOKUP_SET, set);
                self.be32(NFTA_LOOKUP_SREG, *sreg);
                if let Some(d) = dreg {
                    self.be32(NFTA_LOOKUP_DREG, *d);
                }
                if *inv {
                    self.be32(NFTA_LOOKUP_FLAGS, NFT_LOOKUP_F_INV);
                }
            }
            Expr::Queue { num } => {
                // u16 attributes go as 2 big-endian bytes, padded.
                self.put(NFTA_QUEUE_NUM, &num.to_be_bytes());
                self.put(NFTA_QUEUE_TOTAL, &1u16.to_be_bytes());
                self.put(NFTA_QUEUE_FLAGS, &0u16.to_be_bytes());
            }
            Expr::Nat {
                kind,
                addr_min,
                addr_max,
                proto_min,
                proto_max,
            } => {
                self.be32(NFTA_NAT_TYPE, if *kind == NatKind::Snat { 0 } else { 1 });
                self.be32(NFTA_NAT_FAMILY, u32::from(FAMILY_IPV4));
                self.be32(NFTA_NAT_REG_ADDR_MIN, *addr_min);
                if let Some(r) = addr_max {
                    self.be32(NFTA_NAT_REG_ADDR_MAX, *r);
                }
                if let Some(r) = proto_min {
                    self.be32(NFTA_NAT_REG_PROTO_MIN, *r);
                }
                if let Some(r) = proto_max {
                    self.be32(NFTA_NAT_REG_PROTO_MAX, *r);
                }
            }
            Expr::Update {
                set,
                sreg_key,
                sreg_data,
            } => {
                self.str(NFTA_DYNSET_SET_NAME, set);
                self.be32(NFTA_DYNSET_OP, NFT_DYNSET_OP_UPDATE);
                self.be32(NFTA_DYNSET_SREG_KEY, *sreg_key);
                self.be32(NFTA_DYNSET_SREG_DATA, *sreg_data);
            }
            Expr::Counter => {}
            Expr::Drop => {
                self.be32(NFTA_IMMEDIATE_DREG, 0);
                self.begin(NFTA_IMMEDIATE_DATA);
                self.begin(NFTA_DATA_VERDICT);
                self.be32(NFTA_VERDICT_CODE, NF_DROP);
                self.end();
                self.end();
            }
        }
        self.end();
        self.end();
    }

    /// Close the batch: its bytes and the sequence numbers that answer.
    pub fn finish(mut self) -> (Vec<u8>, std::ops::Range<u32>) {
        let last = self.seq;
        self.header(NFNL_MSG_BATCH_END, NLM_F_REQUEST, 0, NFNL_SUBSYS_NFTABLES);
        self.close_msg();
        (self.buf, self.first..last)
    }
}

/// The batch that replaces table `t` whole: create it (so the delete
/// never fails), delete it, create it again with everything in it.
pub fn replace(t: &Table, seq: u32) -> Batch {
    let mut b = Batch::new(seq);
    b.new_table(&t.name);
    b.del_table(&t.name);
    if t.sets.is_empty() && t.chains.is_empty() {
        return b;
    }
    b.new_table(&t.name);
    for s in &t.sets {
        b.new_set(&t.name, s);
        b.elements(&t.name, s, &s.elements, true);
    }
    for c in &t.chains {
        b.new_chain(&t.name, c);
    }
    for r in &t.rules {
        b.new_rule(&t.name, r);
    }
    b
}

/// Elements of `old` that leave and of `new` that come (a key whose data
/// changed is in both: an add of an existing key is refused). Elements
/// come in the formula's order, so most of a change lines up position by
/// position (one subscriber more, other ports for everyone) and costs no
/// hashing; only what is left after the first misaligned key is hashed.
pub fn diff(old: &[Element], new: &[Element]) -> (Vec<Element>, Vec<Element>) {
    let mut gone = Vec::new();
    let mut came = Vec::new();
    let mut i = 0;
    while let (Some(a), Some(b)) = (old.get(i), new.get(i)) {
        if a.key != b.key {
            break;
        }
        if a.data != b.data {
            gone.push(a.clone());
            came.push(b.clone());
        }
        i += 1;
    }
    let (old, new) = (old.get(i..).unwrap_or(&[]), new.get(i..).unwrap_or(&[]));
    if old.is_empty() || new.is_empty() {
        gone.extend_from_slice(old);
        came.extend_from_slice(new);
        return (gone, came);
    }
    let mut was: std::collections::HashMap<_, (usize, _)> = old
        .iter()
        .enumerate()
        .map(|(i, e)| (e.key, (i, e.data)))
        .collect();
    let mut kept = vec![false; old.len()];
    for e in new {
        match was.remove(&e.key) {
            Some((i, data)) if data == e.data => {
                if let Some(k) = kept.get_mut(i) {
                    *k = true;
                }
            }
            _ => came.push(e.clone()),
        }
    }
    gone.extend(
        old.iter()
            .zip(&kept)
            .filter(|(_, k)| !**k)
            .map(|(e, _)| e.clone()),
    );
    (gone, came)
}

/// The batch that turns `from` into `to` when only elements differ (same
/// [`Table::skeleton`]): the elements that left, then the new ones. Live
/// dynamic sets (UDP mappings) are untouched, unlike a replace.
pub fn update(from: &Table, to: &Table, seq: u32) -> Option<Batch> {
    if !from.same_skeleton(to) {
        return None;
    }
    let mut b = Batch::new(seq);
    for (old, new) in from.sets.iter().zip(&to.sets) {
        if old.elements == new.elements {
            continue;
        }
        if old.interval {
            // Interval sets are small (public ranges): rewrite them.
            b.elements(&to.name, old, &old.elements, false);
            b.elements(&to.name, new, &new.elements, true);
            continue;
        }
        let (gone, came) = diff(&old.elements, &new.elements);
        b.elements(&to.name, old, &gone, false);
        b.elements(&to.name, new, &came, true);
    }
    Some(b)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use corerouter_firewall::program::Value;

    fn e(k: u8, d: u8) -> Element {
        Element {
            key: Value::Addr([10, 0, 0, k].into()),
            key_last: None,
            data: Some(Value::Addr([1, 1, 1, d].into())),
        }
    }

    #[test]
    fn diffs_line_up_or_fall_back_to_a_hash() {
        // One more at the end.
        let (g, c) = diff(&[e(1, 1), e(2, 2)], &[e(1, 1), e(2, 2), e(3, 3)]);
        assert_eq!((g, c), (vec![], vec![e(3, 3)]));
        // Same keys, one new data.
        let (g, c) = diff(&[e(1, 1), e(2, 2)], &[e(1, 1), e(2, 9)]);
        assert_eq!((g, c), (vec![e(2, 2)], vec![e(2, 9)]));
        // One gone from the middle: the rest is matched by key.
        let (g, c) = diff(
            &[e(1, 1), e(2, 2), e(3, 3), e(4, 4)],
            &[e(1, 1), e(3, 3), e(4, 5)],
        );
        assert_eq!((g, c), (vec![e(2, 2), e(4, 4)], vec![e(4, 5)]));
        let (g, c) = diff(&[e(1, 1)], &[]);
        assert_eq!((g, c), (vec![e(1, 1)], vec![]));
    }

    /// Every message of a batch is framed: lengths add up, the end
    /// message closes it, each set's elements stay under the 16-bit
    /// attribute length.
    #[test]
    fn batches_are_framed() {
        let mut c = corerouter_model::cgnat::Cgnat::default();
        c.pools.push(
            serde_json::from_value(serde_json::json!({
                "id": "*1", "name": "p", "inside": ["100.64.0.0/20"], "outside": ["203.0.113.0/26"],
            }))
            .unwrap(),
        );
        let t = corerouter_firewall::cgnat::table(&c).unwrap();
        let (bytes, seqs) = replace(&t, 100).finish();
        let mut at = 0;
        let mut kinds = Vec::new();
        while at < bytes.len() {
            let len = u32::from_ne_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
            let kind = u16::from_ne_bytes(bytes[at + 4..at + 6].try_into().unwrap());
            assert!((20..=65_535 + 20).contains(&len), "message of {len} bytes");
            kinds.push(kind);
            at += len.div_ceil(4) * 4;
        }
        assert_eq!(at, bytes.len());
        assert_eq!(kinds.first(), Some(&NFNL_MSG_BATCH_BEGIN));
        assert_eq!(kinds.last(), Some(&NFNL_MSG_BATCH_END));
        assert_eq!(seqs.len(), kinds.len() - 2);
        // 4096 subscribers: 8 element messages for the formula's map.
        let elems = kinds
            .iter()
            .filter(|k| **k == (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWSETELEM)
            .count();
        assert_eq!(elems, 8 + 1);
    }
}

#[cfg(target_os = "linux")]
pub use io::apply;

#[cfg(target_os = "linux")]
mod io {
    use std::os::fd::AsFd;
    use std::time::{Duration, Instant};

    use corerouter_hal::HalError;
    use netlink_sys::{Socket, protocols::NETLINK_NETFILTER};
    use nix::poll::{PollFd, PollFlags, PollTimeout, poll};

    use super::Batch;

    /// A batch slower than this is a stuck kernel: give up (the kernel
    /// commits the batch whole or not at all, so nothing is half-done).
    const DEADLINE: Duration = Duration::from_secs(30);

    fn io(e: impl std::fmt::Display) -> HalError {
        HalError::Io(format!("nftables netlink: {e}"))
    }

    /// Send `batch` and wait for every answer; the first error refuses it.
    pub fn apply(batch: Batch, what: &str) -> Result<(), HalError> {
        let (bytes, seqs) = batch.finish();
        let mut sock = Socket::new(NETLINK_NETFILTER).map_err(io)?;
        sock.bind_auto().map_err(io)?;
        // The whole batch is one message to the kernel: the send buffer
        // must hold it (as nft does, SO_SNDBUFFORCE; we are CAP_NET_ADMIN).
        // As root of the real router SO_SNDBUFFORCE lifts the limit; in a
        // user namespace (tests) it is refused and SO_SNDBUF goes up to
        // twice `net.core.wmem_max` (8 MiB by default: some 150 000
        // subscribers in one batch), as `nft` does.
        let want = bytes.len().saturating_add(65_536);
        use nix::sys::socket::{setsockopt, sockopt};
        if setsockopt(&sock.as_fd(), sockopt::SndBufForce, &want).is_err() {
            let _ = setsockopt(&sock.as_fd(), sockopt::SndBuf, &want);
        }
        if setsockopt(&sock.as_fd(), sockopt::RcvBufForce, &(1usize << 20)).is_err() {
            let _ = setsockopt(&sock.as_fd(), sockopt::RcvBuf, &(1usize << 20));
        }
        sock.send(&bytes, 0).map_err(|e| {
            if e.raw_os_error() == Some(90) {
                HalError::Rejected(format!(
                    "{what}: the batch ({} KiB) does not fit the netlink send buffer; nothing changed",
                    bytes.len() / 1024
                ))
            } else {
                io(e)
            }
        })?;
        let mut pending: std::collections::BTreeSet<u32> = seqs.clone().collect();
        let start = Instant::now();
        let mut buf = vec![0u8; 1 << 16];
        let mut first_error: Option<(u32, i32)> = None;
        while !pending.is_empty() {
            let left = DEADLINE.saturating_sub(start.elapsed());
            if left.is_zero() {
                return Err(HalError::Io(format!(
                    "{what}: the kernel did not answer in {} s",
                    DEADLINE.as_secs()
                )));
            }
            let ms = u16::try_from(left.as_millis().min(1000)).unwrap_or(1000);
            let mut fds = [PollFd::new(sock.as_fd(), PollFlags::POLLIN)];
            if poll(&mut fds, PollTimeout::from(ms)).map_err(io)? == 0 {
                continue;
            }
            let n = sock.recv(&mut &mut buf[..], 0).map_err(io)?;
            for (seq, code) in acks(buf.get(..n).unwrap_or(&[])) {
                pending.remove(&seq);
                if code != 0 && first_error.is_none() {
                    first_error = Some((seq, code));
                }
            }
            // After an error the kernel aborts the batch: the remaining
            // messages may not all answer.
            if first_error.is_some() && pending.iter().all(|s| *s > first_error.map_or(0, |e| e.0))
            {
                break;
            }
        }
        match first_error {
            None => Ok(()),
            Some((seq, errno)) => Err(HalError::Rejected(format!(
                "{what}: the kernel refused message {} of the batch ({}); nothing changed",
                seq.wrapping_sub(seqs.start),
                std::io::Error::from_raw_os_error(errno)
            ))),
        }
    }

    /// (seq, errno) of every NLMSG_ERROR in `buf` (0: an ACK).
    pub(super) fn acks(buf: &[u8]) -> Vec<(u32, i32)> {
        let mut out = Vec::new();
        let mut rest = buf;
        while let Some(hdr) = rest.get(..16) {
            let word = |at: usize| {
                hdr.get(at..at + 4)
                    .and_then(|b| b.try_into().ok())
                    .map(u32::from_ne_bytes)
            };
            let (Some(len), Some(seq)) = (word(0), word(8)) else {
                break;
            };
            let kind = hdr
                .get(4..6)
                .and_then(|b| b.try_into().ok())
                .map(u16::from_ne_bytes);
            let len = usize::try_from(len).unwrap_or(0);
            if len < 16 {
                break;
            }
            if kind == Some(2) {
                let code = rest
                    .get(16..20)
                    .and_then(|b| b.try_into().ok())
                    .map_or(0, i32::from_ne_bytes);
                out.push((seq, code.saturating_neg()));
            }
            rest = rest.get(len.div_ceil(4) * 4..).unwrap_or(&[]);
        }
        out
    }
}
