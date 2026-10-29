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
    AnonSet, Base, Chain, Dir, Element, Expr, FAMILY_IPV4, Family, Flowtable, FwSet, Hook,
    KernelElement, NatKind, Rule, SET_ANONYMOUS, SET_CONSTANT, SET_INTERVAL, Set, Table,
};

const NLA_HDR: usize = 4;
const NLA_F_NESTED: u16 = 1 << 15;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_ACK: u16 = 0x4;
const NLM_F_ECHO: u16 = 0x8;
const NLM_F_CREATE: u16 = 0x400;
const NLM_F_APPEND: u16 = 0x800;

pub const NFNL_SUBSYS_NFTABLES: u16 = 10;
const NFNL_MSG_BATCH_BEGIN: u16 = 16;
const NFNL_MSG_BATCH_END: u16 = 17;
/// `NFNL_BATCH_GENID`: the batch applies only while the ruleset is still
/// at this generation (0: any), else the kernel answers `ERESTART`.
const NFNL_BATCH_GENID: u16 = 1;
/// Where the generation id sits in the batch: after the begin message's
/// netlink header (16), `nfgenmsg` (4) and the attribute header (4).
const GENID_AT: usize = 24;

// enum nf_tables_msg_types
const NFT_MSG_NEWTABLE: u16 = 0;
const NFT_MSG_DELTABLE: u16 = 2;
const NFT_MSG_NEWCHAIN: u16 = 3;
const NFT_MSG_DELCHAIN: u16 = 5;
const NFT_MSG_NEWRULE: u16 = 6;
const NFT_MSG_DELRULE: u16 = 8;
const NFT_MSG_NEWSET: u16 = 9;
const NFT_MSG_DELSET: u16 = 11;
const NFT_MSG_NEWSETELEM: u16 = 12;
const NFT_MSG_DELSETELEM: u16 = 14;
const NFT_MSG_NEWGEN: u16 = 15;
const NFT_MSG_NEWFLOWTABLE: u16 = 22;

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
const NFTA_RULE_HANDLE: u16 = 3;
const NFTA_RULE_EXPRESSIONS: u16 = 4;
const NFTA_RULE_POSITION: u16 = 6;
const NFTA_RULE_USERDATA: u16 = 7;
/// libnftnl's rule comment TLV (`NFTNL_UDATA_RULE_COMMENT`).
const UDATA_RULE_COMMENT: u8 = 0;
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
const NFTA_SET_ELEM_TIMEOUT: u16 = 4;
const NFTA_SET_ELEM_LIST_SET_ID: u16 = 4;
const NFT_SET_ELEM_INTERVAL_END: u32 = 1;
const NFTA_DATA_VALUE: u16 = 1;
const NFTA_DATA_VERDICT: u16 = 2;
const NFTA_VERDICT_CODE: u16 = 1;
const NFTA_VERDICT_CHAIN: u16 = 2;
const NF_ACCEPT: u32 = 1;
const NF_DROP: u32 = 0;
/// `NFT_JUMP` (-3) and `NFT_RETURN` (-5) as the kernel's u32.
const NFT_JUMP: u32 = 0xffff_fffd;
const NFT_RETURN: u32 = 0xffff_fffb;

// Flowtables (`NFTA_FLOWTABLE_*`, `NFTA_FLOWTABLE_HOOK_*`).
const NFTA_FLOWTABLE_TABLE: u16 = 1;
const NFTA_FLOWTABLE_NAME: u16 = 2;
const NFTA_FLOWTABLE_HOOK: u16 = 3;
const NFTA_FLOWTABLE_FLAGS: u16 = 7;
const NFTA_FLOWTABLE_HOOK_NUM: u16 = 1;
const NFTA_FLOWTABLE_HOOK_PRIORITY: u16 = 2;
const NFTA_FLOWTABLE_HOOK_DEVS: u16 = 3;
const NFTA_DEVICE_NAME: u16 = 1;
/// `NF_NETDEV_INGRESS`.
const NF_NETDEV_INGRESS: u32 = 0;
const NFTA_FLOW_TABLE_NAME: u16 = 1;

// Expression attributes.
const NFTA_PAYLOAD_DREG: u16 = 1;
const NFTA_PAYLOAD_BASE: u16 = 2;
const NFTA_PAYLOAD_OFFSET: u16 = 3;
const NFTA_PAYLOAD_LEN: u16 = 4;
const NFTA_META_DREG: u16 = 1;
const NFTA_META_KEY: u16 = 2;
const NFTA_META_SREG: u16 = 3;
const NFTA_LIMIT_RATE: u16 = 1;
const NFTA_LIMIT_UNIT: u16 = 2;
const NFTA_LIMIT_BURST: u16 = 3;
const NFTA_LIMIT_TYPE: u16 = 4;
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
const NFTA_LOOKUP_SET_ID: u16 = 4;
const NFTA_LOOKUP_FLAGS: u16 = 5;
const NFTA_RANGE_SREG: u16 = 1;
const NFTA_RANGE_OP: u16 = 2;
const NFTA_RANGE_FROM_DATA: u16 = 3;
const NFTA_RANGE_TO_DATA: u16 = 4;
const NFTA_REJECT_TYPE: u16 = 1;
const NFTA_REJECT_ICMP_CODE: u16 = 2;
const NFTA_LOG_PREFIX: u16 = 2;
const NFTA_CT_SREG: u16 = 4;
const NFTA_MASQ_FLAGS: u16 = 1;
const NFTA_MASQ_REG_PROTO_MIN: u16 = 2;
const NFTA_MASQ_REG_PROTO_MAX: u16 = 3;
const NFTA_REDIR_REG_PROTO_MIN: u16 = 1;
const NFTA_REDIR_REG_PROTO_MAX: u16 = 2;
const NFTA_REDIR_FLAGS: u16 = 3;
const NFTA_NAT_FLAGS: u16 = 7;
const NFTA_FIB_DREG: u16 = 1;
const NFTA_FIB_RESULT: u16 = 2;
const NFTA_FIB_FLAGS: u16 = 3;
const NFTA_DYNSET_SET_ID: u16 = 2;
const NFTA_DYNSET_TIMEOUT: u16 = 6;
const NFT_DYNSET_OP_ADD: u32 = 0;
const NFT_LOOKUP_F_INV: u32 = 1;
const NFTA_QUEUE_NUM: u16 = 1;
/// `NFT_QUEUE_FLAG_BYPASS`: no listener, the packet goes on.
const NFT_QUEUE_FLAG_BYPASS: u16 = 0x01;
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
    /// `NFPROTO_*` of every nf_tables message (the table's family).
    family: u8,
    /// Ids and names of the anonymous sets of the rule being written, in
    /// order.
    anon_ids: std::collections::VecDeque<(u32, String)>,
    /// Name anonymous sets `__set<n>` from this number on, instead of
    /// letting the kernel number them (`__set%d`): the kernel finds a free
    /// number by scanning every set of the table, O(sets) per set, which
    /// made 10 000 rules take 4 s (G2.8, **medido**).
    anon_next: Option<u32>,
    /// Ids of the named firewall sets created in this batch (nft names
    /// them by id as well in the rules that follow).
    named_ids: std::collections::BTreeMap<String, u32>,
    /// New rules ask the kernel to echo them back (with their handles).
    echo: bool,
    /// Sequence numbers of the new rules that asked for an echo.
    echoed: Vec<u32>,
    /// The tables the batch writes (see [`Self::str`]).
    touched: std::collections::BTreeSet<String>,
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
            family: FAMILY_IPV4,
            anon_ids: std::collections::VecDeque::new(),
            anon_next: None,
            named_ids: std::collections::BTreeMap::new(),
            echo: false,
            echoed: Vec::new(),
            touched: std::collections::BTreeSet::new(),
        };
        // The generation id (patched in by `apply`) makes the batch apply
        // only on the ruleset we last saw (G0.31f).
        b.header(NFNL_MSG_BATCH_BEGIN, NLM_F_REQUEST, 0, NFNL_SUBSYS_NFTABLES);
        b.be32(NFNL_BATCH_GENID, 0);
        b.close_msg();
        b
    }

    /// New rules from here on are echoed back with their kernel handles
    /// (`NLM_F_ECHO`), in the order they were written.
    pub fn echo_rules(&mut self, on: bool) {
        self.echo = on;
    }

    /// How many rules asked for an echo.
    pub fn echoed(&self) -> usize {
        self.echoed.len()
    }

    /// The number the next anonymous set would take (see
    /// [`Self::name_anon_sets_from`]).
    pub fn next_anon_set(&self) -> Option<u32> {
        self.anon_next
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

    /// Start an nf_tables message of type `msg`. Only the last message of
    /// the batch asks for an ACK ([`Self::finish`]): the kernel reports any
    /// error anyway, and one ACK per message of a batch of thousands
    /// overflowed the socket's receive buffer (`ENOBUFS`, G2.8).
    ///
    /// The first message asks for an echo: the kernel reads the flag of
    /// the message after `BATCH_BEGIN` to decide whether to tell us the
    /// generation the commit made (`NFT_MSG_NEWGEN`, G0.31f).
    fn begin_msg(&mut self, msg: u16, flags: u16) {
        let kind = (NFNL_SUBSYS_NFTABLES << 8) | msg;
        let echo = if self.seq == self.first {
            NLM_F_ECHO
        } else {
            0
        };
        self.header(kind, NLM_F_REQUEST | flags | echo, self.family, 0);
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
        // Attribute 1 at the top of every nf_tables message we write is
        // its table (`NFTA_TABLE_NAME`, `NFTA_CHAIN_TABLE`,
        // `NFTA_RULE_TABLE`, `NFTA_SET_TABLE`, `NFTA_SET_ELEM_LIST_TABLE`,
        // `NFTA_FLOWTABLE_TABLE`).
        if kind == 1 && self.open.is_empty() && !self.touched.contains(s) {
            self.touched.insert(s.to_owned());
        }
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

    /// The family of the messages that follow (`ip` by default).
    pub fn family(&mut self, f: Family) {
        self.family = f.number();
    }

    pub fn new_flowtable(&mut self, table: &str, f: &Flowtable) {
        self.begin_msg(NFT_MSG_NEWFLOWTABLE, NLM_F_CREATE);
        self.str(NFTA_FLOWTABLE_TABLE, table);
        self.str(NFTA_FLOWTABLE_NAME, &f.name);
        self.begin(NFTA_FLOWTABLE_HOOK);
        self.be32(NFTA_FLOWTABLE_HOOK_NUM, NF_NETDEV_INGRESS);
        self.put(NFTA_FLOWTABLE_HOOK_PRIORITY, &0i32.to_be_bytes());
        self.begin(NFTA_FLOWTABLE_HOOK_DEVS);
        for d in &f.devices {
            self.str(NFTA_DEVICE_NAME, d);
        }
        self.end();
        self.end();
        if f.flags() != 0 {
            self.be32(NFTA_FLOWTABLE_FLAGS, f.flags());
        }
        self.close_msg();
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
        if c.hook == Hook::Regular {
            self.close_msg();
            return;
        }
        // nft's order: policy, type, hook.
        self.be32(NFTA_CHAIN_POLICY, NF_ACCEPT);
        self.str(NFTA_CHAIN_TYPE, c.kind.name());
        self.begin(NFTA_CHAIN_HOOK);
        self.be32(NFTA_HOOK_HOOKNUM, c.hook.number());
        self.put(NFTA_HOOK_PRIORITY, &c.priority.to_be_bytes());
        self.end();
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
        self.insert_rule(table, r, Place::End);
    }

    /// Rule `r` at `place` (G2.8): its anonymous sets first (they live in
    /// the same transaction), then the rule with its comment.
    pub fn insert_rule(&mut self, table: &str, r: &Rule, place: Place) {
        self.anon_ids.clear();
        for e in &r.exprs {
            if let Expr::LookupAnon { set, .. } = e {
                let named = self.anon_set(table, set);
                self.anon_ids.push_back(named);
            }
        }
        let mut flags = match place {
            Place::End | Place::After(_) => NLM_F_CREATE | NLM_F_APPEND,
            Place::Start => NLM_F_CREATE,
        };
        if self.echo {
            flags |= NLM_F_ECHO;
            self.echoed.push(self.seq);
        }
        self.begin_msg(NFT_MSG_NEWRULE, flags);
        self.str(NFTA_RULE_TABLE, table);
        self.str(NFTA_RULE_CHAIN, &r.chain);
        if let Place::After(handle) = place {
            self.be64(NFTA_RULE_POSITION, handle);
        }
        self.begin(NFTA_RULE_EXPRESSIONS);
        for e in &r.exprs {
            self.expr(e);
        }
        self.end();
        if let Some(c) = &r.comment {
            self.put(NFTA_RULE_USERDATA, &comment_udata(c));
        }
        self.close_msg();
    }

    /// Name the anonymous sets that follow `__set<first>`, `__set<first+1>`…
    /// (`first` above any number the table already uses).
    pub fn name_anon_sets_from(&mut self, first: u32) {
        self.anon_next = Some(first);
    }

    /// An anonymous set and its elements; its transaction id and name.
    fn anon_set(&mut self, table: &str, a: &AnonSet) -> (u32, String) {
        self.set_ids = self.set_ids.wrapping_add(1);
        let id = self.set_ids;
        let name = match self.anon_next {
            Some(n) => {
                self.anon_next = Some(n.wrapping_add(1));
                format!("__set{n}")
            }
            None => ANON_SET_NAME.to_owned(),
        };
        let mut flags = SET_ANONYMOUS | SET_CONSTANT;
        if a.interval {
            flags |= SET_INTERVAL;
        }
        self.begin_msg(NFT_MSG_NEWSET, NLM_F_CREATE);
        self.str(NFTA_SET_TABLE, table);
        self.str(NFTA_SET_NAME, &name);
        self.be32(NFTA_SET_FLAGS, flags);
        self.be32(NFTA_SET_KEY_TYPE, a.key.nft_id());
        self.be32(NFTA_SET_KEY_LEN, a.key.len());
        self.be32(NFTA_SET_ID, id);
        self.begin(NFTA_SET_DESC);
        self.be32(
            NFTA_SET_DESC_SIZE,
            u32::try_from(a.elements.len()).unwrap_or(u32::MAX),
        );
        self.end();
        self.put(NFTA_SET_USERDATA, &a.udata);
        self.close_msg();
        let items: Vec<KernelElement> = a
            .elements
            .iter()
            .map(|(key, end)| KernelElement {
                key: key.clone(),
                end: *end,
                timeout_ms: None,
            })
            .collect();
        self.kernel_elements(table, &name, Some(id), &items, true);
        (id, name)
    }

    /// Named set `s` of the firewall (G2.8), without its elements.
    pub fn new_fw_set(&mut self, table: &str, s: &FwSet) -> u32 {
        self.set_ids = self.set_ids.wrapping_add(1);
        self.begin_msg(NFT_MSG_NEWSET, NLM_F_CREATE);
        self.str(NFTA_SET_TABLE, table);
        self.str(NFTA_SET_NAME, &s.name);
        self.be32(NFTA_SET_FLAGS, s.flags());
        self.be32(NFTA_SET_KEY_TYPE, s.key.nft_id());
        self.be32(NFTA_SET_KEY_LEN, s.key.len());
        self.be32(NFTA_SET_ID, self.set_ids);
        if let Some(n) = s.size {
            self.begin(NFTA_SET_DESC);
            self.be32(NFTA_SET_DESC_SIZE, n);
            self.end();
        }
        let mut udata = corerouter_firewall::bytecode::udata_byteorder(s.key.big_endian()).to_vec();
        if s.auto_merge {
            udata.extend_from_slice(&corerouter_firewall::bytecode::udata_merge());
        }
        self.put(NFTA_SET_USERDATA, &udata);
        self.close_msg();
        self.named_ids.insert(s.name.clone(), self.set_ids);
        self.set_ids
    }

    /// Elements of set `set` as the kernel holds them, added or deleted,
    /// in messages of at most [`ELEMENTS_PER_MESSAGE`].
    pub fn kernel_elements(
        &mut self,
        table: &str,
        set: &str,
        set_id: Option<u32>,
        items: &[KernelElement],
        add: bool,
    ) {
        for chunk in items.chunks(ELEMENTS_PER_MESSAGE) {
            let msg = if add {
                NFT_MSG_NEWSETELEM
            } else {
                NFT_MSG_DELSETELEM
            };
            self.begin_msg(msg, if add { NLM_F_CREATE } else { 0 });
            self.str(NFTA_SET_ELEM_LIST_TABLE, table);
            self.str(NFTA_SET_ELEM_LIST_SET, set);
            if let Some(id) = set_id {
                self.be32(NFTA_SET_ELEM_LIST_SET_ID, id);
            }
            self.begin(NFTA_SET_ELEM_LIST_ELEMENTS);
            for (i, e) in chunk.iter().enumerate() {
                // libnftnl numbers the elements of a message from 1 (the
                // kernel reads any type).
                self.begin(u16::try_from(i + 1).unwrap_or(NFTA_LIST_ELEM));
                // nft's order: flags, timeout, key.
                if e.end {
                    self.be32(NFTA_SET_ELEM_FLAGS, NFT_SET_ELEM_INTERVAL_END);
                }
                if let (Some(t), true) = (e.timeout_ms, add) {
                    self.be64(NFTA_SET_ELEM_TIMEOUT, t);
                }
                self.value(NFTA_SET_ELEM_KEY, &e.key);
                self.end();
            }
            self.close_msg();
        }
    }

    /// Delete the rule `handle` of `chain` or, without a handle, every
    /// rule of the chain.
    pub fn del_rule(&mut self, table: &str, chain: &str, handle: Option<u64>) {
        self.begin_msg(NFT_MSG_DELRULE, 0);
        self.str(NFTA_RULE_TABLE, table);
        self.str(NFTA_RULE_CHAIN, chain);
        if let Some(h) = handle {
            self.be64(NFTA_RULE_HANDLE, h);
        }
        self.close_msg();
    }

    pub fn del_chain(&mut self, table: &str, chain: &str) {
        self.begin_msg(NFT_MSG_DELCHAIN, 0);
        self.str(NFTA_CHAIN_TABLE, table);
        self.str(NFTA_CHAIN_NAME, chain);
        self.close_msg();
    }

    pub fn del_set(&mut self, table: &str, set: &str) {
        self.begin_msg(NFT_MSG_DELSET, 0);
        self.str(NFTA_SET_TABLE, table);
        self.str(NFTA_SET_NAME, set);
        self.close_msg();
    }

    /// The number of messages written so far (batch begin included).
    pub fn messages(&self) -> u32 {
        self.seq.wrapping_sub(self.first).wrapping_add(1)
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
            Expr::FlowAdd { .. } => "flow_offload",
            Expr::Immediate { .. } => "immediate",
            Expr::MetaSet { .. } => "meta",
            Expr::Limit { .. } => "limit",
            Expr::Bitwise { .. } => "bitwise",
            Expr::Order { .. } => "cmp",
            Expr::Range { .. } => "range",
            Expr::LookupAnon { .. } => "lookup",
            Expr::Accept | Expr::Return | Expr::Jump { .. } => "immediate",
            Expr::Reject { .. } => "reject",
            Expr::Log { .. } => "log",
            Expr::Notrack => "notrack",
            Expr::CtSet { .. } => "ct",
            Expr::Masq { .. } => "masq",
            Expr::Redir { .. } => "redir",
            Expr::NatRange { .. } => "nat",
            Expr::Fib { .. } => "fib",
            Expr::DynsetAdd { .. } => "dynset",
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
                // nft's order: key, register.
                self.be32(NFTA_META_KEY, key.number());
                self.be32(NFTA_META_DREG, *dreg);
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
                // nft's order: key, register.
                self.be32(NFTA_CT_KEY, key.number());
                self.be32(NFTA_CT_DREG, *dreg);
                if let Some(d) = dir {
                    self.put(NFTA_CT_DIRECTION, &[if *d == Dir::Reply { 1 } else { 0 }]);
                }
            }
            Expr::Lookup {
                set,
                sreg,
                dreg,
                inv,
            } if self.named_ids.contains_key(set) => {
                // A firewall set of this batch: nft's order and its id.
                self.be32(NFTA_LOOKUP_SREG, *sreg);
                self.str(NFTA_LOOKUP_SET, set);
                if let Some(id) = self.named_ids.get(set).copied() {
                    self.be32(NFTA_LOOKUP_SET_ID, id);
                }
                if let Some(d) = dreg {
                    self.be32(NFTA_LOOKUP_DREG, *d);
                }
                if *inv {
                    self.be32(NFTA_LOOKUP_FLAGS, NFT_LOOKUP_F_INV);
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
            Expr::Queue { num, total, bypass } => {
                // u16 attributes go as 2 big-endian bytes, padded.
                self.put(NFTA_QUEUE_NUM, &num.to_be_bytes());
                self.put(NFTA_QUEUE_TOTAL, &(*total).max(1).to_be_bytes());
                let flags = if *bypass { NFT_QUEUE_FLAG_BYPASS } else { 0 };
                self.put(NFTA_QUEUE_FLAGS, &flags.to_be_bytes());
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
            Expr::FlowAdd { table } => self.str(NFTA_FLOW_TABLE_NAME, table),
            Expr::Immediate { dreg, data } => {
                self.be32(NFTA_IMMEDIATE_DREG, *dreg);
                self.value(NFTA_IMMEDIATE_DATA, data);
            }
            Expr::MetaSet { key, sreg } => {
                self.be32(NFTA_META_KEY, key.number());
                self.be32(NFTA_META_SREG, *sreg);
            }
            Expr::Limit {
                rate,
                unit_secs,
                burst,
            } => {
                self.be64(NFTA_LIMIT_RATE, *rate);
                self.be64(NFTA_LIMIT_UNIT, *unit_secs);
                self.be32(NFTA_LIMIT_BURST, *burst);
                self.be32(NFTA_LIMIT_TYPE, 0); // NFT_LIMIT_PKTS
            }
            Expr::Drop => self.verdict(NF_DROP, None),
            Expr::Accept => self.verdict(NF_ACCEPT, None),
            Expr::Return => self.verdict(NFT_RETURN, None),
            Expr::Jump { chain } => self.verdict(NFT_JUMP, Some(chain)),
            Expr::Bitwise {
                sreg,
                dreg,
                mask,
                xor,
            } => {
                self.be32(NFTA_BITWISE_SREG, *sreg);
                self.be32(NFTA_BITWISE_DREG, *dreg);
                self.be32(NFTA_BITWISE_LEN, u32::try_from(mask.len()).unwrap_or(4));
                self.value(NFTA_BITWISE_MASK, mask);
                self.value(NFTA_BITWISE_XOR, xor);
            }
            Expr::Order { sreg, op, data } => {
                self.be32(NFTA_CMP_SREG, *sreg);
                self.be32(NFTA_CMP_OP, op.number());
                self.value(NFTA_CMP_DATA, data);
            }
            Expr::Range { sreg, eq, from, to } => {
                self.be32(NFTA_RANGE_SREG, *sreg);
                self.be32(NFTA_RANGE_OP, if *eq { 0 } else { 1 });
                self.value(NFTA_RANGE_FROM_DATA, from);
                self.value(NFTA_RANGE_TO_DATA, to);
            }
            Expr::LookupAnon { sreg, inv, .. } => {
                let (id, name) = self
                    .anon_ids
                    .pop_front()
                    .unwrap_or_else(|| (0, ANON_SET_NAME.to_owned()));
                self.be32(NFTA_LOOKUP_SREG, *sreg);
                self.str(NFTA_LOOKUP_SET, &name);
                self.be32(NFTA_LOOKUP_SET_ID, id);
                if *inv {
                    self.be32(NFTA_LOOKUP_FLAGS, NFT_LOOKUP_F_INV);
                }
            }
            Expr::Reject { kind, code } => {
                self.be32(NFTA_REJECT_TYPE, *kind);
                self.put(NFTA_REJECT_ICMP_CODE, &[*code]);
            }
            Expr::Log { prefix } => {
                if let Some(p) = prefix {
                    self.str(NFTA_LOG_PREFIX, p);
                }
            }
            Expr::Notrack => {}
            Expr::CtSet { key, sreg } => {
                self.be32(NFTA_CT_KEY, key.number());
                self.be32(NFTA_CT_SREG, *sreg);
            }
            Expr::Masq {
                proto_min,
                proto_max,
                flags,
            } => {
                if *flags != 0 {
                    self.be32(NFTA_MASQ_FLAGS, *flags);
                }
                if let Some(r) = proto_min {
                    self.be32(NFTA_MASQ_REG_PROTO_MIN, *r);
                }
                if let Some(r) = proto_max {
                    self.be32(NFTA_MASQ_REG_PROTO_MAX, *r);
                }
            }
            Expr::Redir {
                proto_min,
                proto_max,
                flags,
            } => {
                if let Some(r) = proto_min {
                    self.be32(NFTA_REDIR_REG_PROTO_MIN, *r);
                }
                if let Some(r) = proto_max {
                    self.be32(NFTA_REDIR_REG_PROTO_MAX, *r);
                }
                if *flags != 0 {
                    self.be32(NFTA_REDIR_FLAGS, *flags);
                }
            }
            Expr::NatRange {
                kind,
                family,
                addr_min,
                addr_max,
                proto_min,
                proto_max,
                flags,
            } => {
                self.be32(NFTA_NAT_TYPE, if *kind == NatKind::Snat { 0 } else { 1 });
                self.be32(NFTA_NAT_FAMILY, u32::from(*family));
                for (attr, reg) in [
                    (NFTA_NAT_REG_ADDR_MIN, addr_min),
                    (NFTA_NAT_REG_ADDR_MAX, addr_max),
                    (NFTA_NAT_REG_PROTO_MIN, proto_min),
                    (NFTA_NAT_REG_PROTO_MAX, proto_max),
                ] {
                    if let Some(r) = reg {
                        self.be32(attr, *r);
                    }
                }
                if *flags != 0 {
                    self.be32(NFTA_NAT_FLAGS, *flags);
                }
            }
            Expr::Fib {
                flags,
                result,
                dreg,
            } => {
                self.be32(NFTA_FIB_DREG, *dreg);
                self.be32(NFTA_FIB_RESULT, *result);
                self.be32(NFTA_FIB_FLAGS, *flags);
            }
            Expr::DynsetAdd {
                set,
                sreg_key,
                timeout_ms,
            } => {
                // nft's order.
                self.be32(NFTA_DYNSET_SREG_KEY, *sreg_key);
                self.be32(NFTA_DYNSET_OP, NFT_DYNSET_OP_ADD);
                if let Some(t) = timeout_ms {
                    self.be64(NFTA_DYNSET_TIMEOUT, *t);
                }
                self.str(NFTA_DYNSET_SET_NAME, set);
                if let Some(id) = self.named_ids.get(set).copied() {
                    self.be32(NFTA_DYNSET_SET_ID, id);
                }
            }
        }
        self.end();
        self.end();
    }

    /// `immediate reg 0 <verdict> [-> chain]`.
    fn verdict(&mut self, code: u32, chain: Option<&str>) {
        self.be32(NFTA_IMMEDIATE_DREG, 0);
        self.begin(NFTA_IMMEDIATE_DATA);
        self.begin(NFTA_DATA_VERDICT);
        self.be32(NFTA_VERDICT_CODE, code);
        if let Some(c) = chain {
            self.str(NFTA_VERDICT_CHAIN, c);
        }
        self.end();
        self.end();
    }

    /// Close the batch: its bytes and the sequence numbers that answer.
    pub fn finish(self) -> (Vec<u8>, std::ops::Range<u32>) {
        let (bytes, seqs, _) = self.finish_echo();
        (bytes, seqs)
    }

    /// The tables this batch writes.
    pub fn tables(&self) -> &std::collections::BTreeSet<String> {
        &self.touched
    }

    /// [`Self::finish`], and the sequence numbers of the rules that asked
    /// for an echo.
    pub fn finish_echo(mut self) -> (Vec<u8>, std::ops::Range<u32>, Vec<u32>) {
        let last = self.seq;
        if last != self.first
            && let Some(f) = self.buf.get_mut(self.msg + 6..self.msg + 8)
        {
            let old = <[u8; 2]>::try_from(&f[..]).map_or(0, u16::from_ne_bytes);
            f.copy_from_slice(&(old | NLM_F_ACK).to_ne_bytes());
        }
        self.header(NFNL_MSG_BATCH_END, NLM_F_REQUEST, 0, NFNL_SUBSYS_NFTABLES);
        self.close_msg();
        (self.buf, self.first..last, self.echoed)
    }
}

/// Where a new rule goes in its chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Place {
    End,
    Start,
    /// Right after the rule with this handle.
    After(u64),
}

/// The name of an anonymous set in a batch (the kernel numbers it).
pub const ANON_SET_NAME: &str = "__set%d";

/// A rule comment as libnftnl stores it: type, length (with the NUL),
/// the text and a NUL. At most 127 bytes of text.
pub fn comment_udata(c: &str) -> Vec<u8> {
    let text: Vec<u8> = c.bytes().take(127).collect();
    let mut out = vec![
        UDATA_RULE_COMMENT,
        u8::try_from(text.len() + 1).unwrap_or(128),
    ];
    out.extend(text);
    out.push(0);
    out
}

/// The batch that replaces table `t` whole: create it (so the delete
/// never fails), delete it, create it again with everything in it.
pub fn replace(t: &Table, seq: u32) -> Batch {
    let mut b = Batch::new(seq);
    b.family(t.family);
    // The table is new: its anonymous sets start from zero.
    b.name_anon_sets_from(0);
    b.new_table(&t.name);
    b.del_table(&t.name);
    if t.sets.is_empty() && t.fw_sets.is_empty() && t.chains.is_empty() && t.flowtables.is_empty() {
        return b;
    }
    b.new_table(&t.name);
    for f in &t.flowtables {
        b.new_flowtable(&t.name, f);
    }
    for s in &t.sets {
        b.new_set(&t.name, s);
        b.elements(&t.name, s, &s.elements, true);
    }
    for s in &t.fw_sets {
        let id = b.new_fw_set(&t.name, s);
        b.kernel_elements(&t.name, &s.name, Some(id), &s.encoded(), true);
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
    b.family(to.family);
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

    /// G2.8: byte for byte what `nft --debug=mnl` sends for the same
    /// table (`tests/fixtures/nft_mnl_g28.txt`): chains, sets with
    /// timeouts and intervals, anonymous sets, rules with comments.
    #[test]
    fn firewall_messages_match_nft_byte_for_byte() {
        use corerouter_firewall::bytecode as bc;
        use corerouter_firewall::program::{
            ChainType, FwSet, Hook, KeyKind, MetaKey, NatKind, Rule as PRule,
        };
        use corerouter_model::firewall::{AddrMatch, ConnState, Flags, Neg, PortSet};
        let fixture = include_str!("../tests/fixtures/nft_mnl_g28.txt");
        let want: Vec<(u16, String)> = fixture
            .lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
            .map(|l| {
                let (t, h) = l.split_once(' ').unwrap();
                (t.parse().unwrap(), h.to_owned())
            })
            .collect();
        let t = "corerouter";
        let chain = |name: &str, kind, hook, priority| Chain {
            name: name.into(),
            kind,
            hook,
            priority,
            priority_text: String::new(),
        };
        let a = |s: &str| s.parse::<AddrMatch>().unwrap();
        let rule = |chain: &str, exprs: Vec<Expr>, c: &str| PRule {
            chain: chain.into(),
            exprs,
            text: String::new(),
            nft: None,
            comment: Some(c.into()),
        };
        let set = |name: &str, key, interval, timeout, dynamic, size, merge| FwSet {
            name: name.into(),
            key,
            interval,
            timeout,
            dynamic,
            size,
            auto_merge: merge,
            elements: Vec::new(),
        };
        let mut b = Batch::new(0);
        b.family(Family::Inet);
        b.new_chain(t, &chain("c", ChainType::Filter, Hook::Regular, 0));
        b.new_chain(t, &chain("filter_input", ChainType::Filter, Hook::Input, 0));
        b.new_chain(
            t,
            &chain("nat_srcnat", ChainType::Nat, Hook::Postrouting, 100),
        );
        let mut s = set("s", KeyKind::Ipv4, true, true, false, None, true);
        let (one, ten) = (a("1.2.3.4"), a("10.0.0.0/8"));
        s.elements = bc::interval_elements(&[&one], &[(&ten, 60)]);
        let id = b.new_fw_set(t, &s);
        b.kernel_elements(t, "s", Some(id), &s.encoded(), true);
        b.new_fw_set(
            t,
            &set("d6", KeyKind::Ipv6, false, true, true, Some(65536), false),
        );
        let mut il = set("il", KeyKind::IfName, false, false, false, None, false);
        il.elements = vec![corerouter_firewall::program::FwElement {
            key: bc::ifname_bytes("a"),
            last: None,
            timeout_ms: None,
        }];
        let id = b.new_fw_set(t, &il);
        b.kernel_elements(t, "il", Some(id), &il.encoded(), true);
        let ports = PortSet(vec!["22".parse().unwrap(), "1000-2000".parse().unwrap()]);
        let ps = bc::port_set(&ports);
        let id = b.new_fw_set(t, &ps);
        b.kernel_elements(t, &ps.name, Some(id), &ps.encoded(), true);
        b.new_fw_set(t, &set("s6", KeyKind::Ipv6, true, true, false, None, true));
        let mut e = bc::port_exprs(false, false, &ports);
        e.extend([
            Expr::Counter,
            Expr::Log {
                prefix: Some("ab".into()),
            },
        ]);
        b.new_rule(t, &rule("c", e, "x"));
        // The one anonymous set we still send (subscriber notices).
        let mut e = bc::l4proto_set(&[6, 17]);
        e.extend(bc::port_exprs(
            false,
            false,
            &PortSet(vec!["53".parse().unwrap()]),
        ));
        e.push(Expr::Return);
        let mut r = rule("c", e, "");
        r.comment = None;
        b.new_rule(t, &r);
        let mut e = bc::ct_state_exprs(&Neg {
            not: false,
            value: Flags(vec![ConnState::Established, ConnState::Related]),
        });
        e.extend([Expr::Counter, Expr::Accept]);
        b.new_rule(t, &rule("filter_input", e, "cr:*2"));
        let mut e = bc::meta_cmp(MetaKey::NfProto, true, vec![bc::NFPROTO_IPV4]);
        e.extend(bc::addr_exprs(true, true, &a("10.0.0.0/8")));
        e.extend(bc::meta_cmp(MetaKey::L4Proto, true, vec![6]));
        e.extend(bc::ports_merged(1, 2));
        e.extend([Expr::Counter, Expr::Jump { chain: "c".into() }]);
        b.new_rule(t, &rule("filter_input", e, "cr:*3"));
        let mut e = bc::meta_cmp(MetaKey::NfProto, true, vec![bc::NFPROTO_IPV6]);
        e.extend(bc::addr_set_exprs(true, true, false, "s6"));
        e.push(Expr::Counter);
        let mut load = bc::addr_set_exprs(true, true, false, "d6");
        load.pop();
        e.extend(load);
        e.push(Expr::DynsetAdd {
            set: "d6".into(),
            sreg_key: 1,
            timeout_ms: Some(60_000),
        });
        b.new_rule(t, &rule("filter_input", e, "cr:*4"));
        let mut e = bc::meta_cmp(MetaKey::L4Proto, true, vec![6]);
        e.extend([
            Expr::Counter,
            Expr::Reject {
                kind: bc::REJECT_TCP_RST,
                code: 0,
            },
        ]);
        b.new_rule(t, &rule("filter_input", e, "cr:*5"));
        let mut e = bc::meta_cmp(MetaKey::NfProto, true, vec![bc::NFPROTO_IPV4]);
        e.extend(bc::meta_cmp(MetaKey::L4Proto, true, vec![17]));
        e.push(Expr::Counter);
        e.extend(bc::nat_exprs(
            NatKind::Snat,
            "198.51.100.10".parse().unwrap(),
            "198.51.100.12".parse().unwrap(),
            Some("10000-20000".parse().unwrap()),
        ));
        b.new_rule(t, &rule("nat_srcnat", e, "cr:*F"));
        let mut e = bc::meta_cmp(MetaKey::L4Proto, true, vec![6]);
        e.push(Expr::Counter);
        e.extend(bc::masq_exprs(Some("1000".parse().unwrap())));
        b.new_rule(t, &rule("nat_srcnat", e, "cr:*E"));
        let (bytes, _) = b.finish();
        let mut got = Vec::new();
        let mut at = 0;
        while at < bytes.len() {
            let len = u32::from_ne_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
            let kind = u16::from_ne_bytes(bytes[at + 4..at + 6].try_into().unwrap());
            if [2563, 2566, 2569, 2572].contains(&kind) {
                let body: String = bytes[at + 20..at + len]
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                got.push((kind, body));
            }
            at += len.div_ceil(4) * 4;
        }
        assert_eq!(got.len(), want.len());
        for (i, (g, w)) in got.iter().zip(&want).enumerate() {
            assert_eq!(g, w, "message {i}");
        }
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
pub use io::{Committed, apply, apply_checked, epoch, stamp};

#[cfg(target_os = "linux")]
mod io {
    use std::collections::BTreeMap;
    use std::os::fd::AsFd;
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    use corerouter_hal::HalError;
    use netlink_sys::{Socket, protocols::NETLINK_NETFILTER};
    use nix::poll::{PollFd, PollFlags, PollTimeout, poll};

    use super::{Batch, GENID_AT, NFNL_SUBSYS_NFTABLES, NFT_MSG_NEWGEN, NFT_MSG_NEWRULE};
    use crate::nft_read::{ReadRule, parse_rule};

    /// A batch slower than this is a stuck kernel: give up (the kernel
    /// commits the batch whole or not at all, so nothing is half-done).
    const DEADLINE: Duration = Duration::from_secs(30);

    /// `ERESTART`: the ruleset is no longer at the batch's generation.
    const ERESTART: i32 = 85;

    /// What this process knows of the netns' nftables generation (G0.31f).
    /// Every batch we send carries the generation our previous one made:
    /// the kernel refuses it (`ERESTART`, nothing applied) if anyone else
    /// committed in between, and then `epoch` moves on. So while `epoch`
    /// stays the same, every commit since was ours, and what we believe
    /// we loaded is what the kernel holds.
    struct Generation {
        last: Option<u32>,
        epoch: u64,
        /// Batches of ours applied, by table they wrote.
        writes: BTreeMap<String, u64>,
        /// The socket every batch goes through, kept open: closing a
        /// netfilter socket (`NETLINK_URELEASE`) makes the kernel wait for
        /// the release of what the last commit deleted (`flush_work` of
        /// nf_tables' destroy work, an RCU grace period: 10–25 ms after
        /// any rule went, **medido**), with its commit lock held.
        sock: Option<Socket>,
    }

    static GENERATION: Mutex<Generation> = Mutex::new(Generation {
        last: None,
        epoch: 0,
        writes: BTreeMap::new(),
        sock: None,
    });

    /// Moves on whenever an nftables commit that is not ours may have
    /// happened (or we could not tell).
    pub fn epoch() -> u64 {
        GENERATION.lock().unwrap_or_else(|e| e.into_inner()).epoch
    }

    /// [`epoch`] and how many of our batches wrote `table`: while both
    /// stay the same, nobody changed that table.
    pub fn stamp(table: &str) -> (u64, u64) {
        let g = GENERATION.lock().unwrap_or_else(|e| e.into_inner());
        (g.epoch, g.writes.get(table).copied().unwrap_or(0))
    }

    /// What a commit echoed back.
    #[derive(Debug, Default)]
    pub struct Committed {
        /// The rules that asked for it ([`Batch::echo_rules`]), in order.
        pub rules: Vec<ReadRule>,
    }

    fn io(e: impl std::fmt::Display) -> HalError {
        HalError::Io(format!("nftables netlink: {e}"))
    }

    /// Send `batch` and wait for every answer; the first error refuses it.
    pub fn apply(batch: Batch, what: &str) -> Result<(), HalError> {
        apply_checked(batch, what, None).map(|_| ())
    }

    /// [`apply`], and with `Some(epoch)` only if no one else committed
    /// since `epoch` was read: `Ok(None)` when someone did (nothing was
    /// sent, or the kernel refused it whole).
    pub fn apply_checked(
        batch: Batch,
        what: &str,
        unchanged_since: Option<u64>,
    ) -> Result<Option<Committed>, HalError> {
        let tables = batch.tables().clone();
        let (mut bytes, seqs, echoed) = batch.finish_echo();
        // Nothing in it: the kernel would commit nothing (and not answer).
        if seqs.is_empty() {
            return Ok(Some(Committed::default()));
        }
        let mut guard = GENERATION.lock().unwrap_or_else(|e| e.into_inner());
        let Generation {
            last,
            epoch,
            writes,
            sock: slot,
        } = &mut *guard;
        let checked = match (unchanged_since, *last) {
            (Some(e), Some(l)) if e == *epoch => Some(l),
            (Some(_), _) => return Ok(None),
            (None, l) => l,
        };
        let sock = match slot {
            Some(s) => s,
            None => {
                let mut s = Socket::new(NETLINK_NETFILTER).map_err(io)?;
                s.bind_auto().map_err(io)?;
                slot.insert(s)
            }
        };
        // What an earlier batch left unread (answers after an error).
        drain(sock);
        // The whole batch is one message to the kernel: the send buffer
        // must hold it (as nft does, SO_SNDBUFFORCE; we are CAP_NET_ADMIN).
        // As root of the real router SO_SNDBUFFORCE lifts the limit; in a
        // user namespace (tests) it is refused and SO_SNDBUF goes up to
        // twice `net.core.wmem_max` (8 MiB by default: some 150 000
        // subscribers in one batch), as `nft` does. Echoed rules come
        // back in the receive buffer (the callers bound how many).
        let want = bytes.len().saturating_add(65_536);
        use nix::sys::socket::{setsockopt, sockopt};
        if setsockopt(&sock.as_fd(), sockopt::SndBufForce, &want).is_err() {
            let _ = setsockopt(&sock.as_fd(), sockopt::SndBuf, &want);
        }
        if setsockopt(&sock.as_fd(), sockopt::RcvBufForce, &(4usize << 20)).is_err() {
            let _ = setsockopt(&sock.as_fd(), sockopt::RcvBuf, &(4usize << 20));
        }
        let mut genid = checked;
        loop {
            if let Some(at) = bytes.get_mut(GENID_AT..GENID_AT + 4) {
                at.copy_from_slice(&genid.unwrap_or(0).to_be_bytes());
            }
            let outcome = match exchange(sock, &bytes, &seqs, &echoed, what) {
                Ok(o) => o,
                Err(e) => {
                    // A socket that failed may hold half an answer: the
                    // next batch opens another (a refused batch is fine).
                    if matches!(e, HalError::Io(_)) {
                        *slot = None;
                    }
                    return Err(e);
                }
            };
            match outcome {
                Outcome::Done(c, made) => {
                    // Proven contiguous only when the kernel checked the
                    // generation we knew.
                    if genid.is_none() || made.is_none() {
                        *epoch = epoch.wrapping_add(1);
                    }
                    *last = made;
                    for t in tables {
                        let n = writes.entry(t).or_insert(0);
                        *n = n.wrapping_add(1);
                    }
                    return Ok(Some(c));
                }
                Outcome::Restart => {
                    *epoch = epoch.wrapping_add(1);
                    *last = None;
                    if unchanged_since.is_some() || genid.is_none() {
                        return Ok(None);
                    }
                    // Someone else committed: send it again unchecked.
                    genid = None;
                }
            }
        }
    }

    /// Read and drop whatever is queued on `sock`, without waiting.
    fn drain(sock: &mut Socket) {
        let mut buf = vec![0u8; 1 << 16];
        loop {
            let mut fds = [PollFd::new(sock.as_fd(), PollFlags::POLLIN)];
            if !matches!(poll(&mut fds, PollTimeout::ZERO), Ok(n) if n > 0) {
                return;
            }
            // ENOBUFS (an overrun) is reported once, then reading goes on.
            if let Err(e) = sock.recv(&mut &mut buf[..], 0)
                && e.raw_os_error() != Some(105)
            {
                return;
            }
        }
    }

    enum Outcome {
        /// Applied: what was echoed and the generation it made.
        Done(Committed, Option<u32>),
        /// Refused whole: the ruleset moved past the batch's generation.
        Restart,
    }

    fn exchange(
        sock: &mut Socket,
        bytes: &[u8],
        seqs: &std::ops::Range<u32>,
        echoed: &[u32],
        what: &str,
    ) -> Result<Outcome, HalError> {
        sock.send(bytes, 0).map_err(|e| {
            if e.raw_os_error() == Some(90) {
                HalError::Rejected(format!(
                    "{what}: the batch ({} KiB) does not fit the netlink send buffer; nothing changed",
                    bytes.len() / 1024
                ))
            } else {
                io(e)
            }
        })?;
        // Only the last message answers on success (see `begin_msg`); a
        // refused generation answers on the begin message.
        let begin = seqs.start.wrapping_sub(1);
        let last = seqs.clone().last();
        let mut done = false;
        let start = Instant::now();
        let mut buf = vec![0u8; 1 << 16];
        let mut first_error: Option<(u32, i32)> = None;
        let mut committed = Committed::default();
        let mut made = None;
        loop {
            let left = DEADLINE.saturating_sub(start.elapsed());
            if left.is_zero() {
                return Err(HalError::Io(format!(
                    "{what}: the kernel did not answer in {} s",
                    DEADLINE.as_secs()
                )));
            }
            // After the last ACK, only what is already queued is read.
            let ms = if done {
                0
            } else {
                u16::try_from(left.as_millis().min(1000)).unwrap_or(1000)
            };
            let mut fds = [PollFd::new(sock.as_fd(), PollFlags::POLLIN)];
            if poll(&mut fds, PollTimeout::from(ms)).map_err(io)? == 0 {
                if done {
                    break;
                }
                continue;
            }
            let n = sock.recv(&mut &mut buf[..], 0).map_err(io)?;
            for m in messages(buf.get(..n).unwrap_or(&[])) {
                match m {
                    Msg::Ack(seq, code) => {
                        if code == ERESTART && seq == begin {
                            return Ok(Outcome::Restart);
                        }
                        if code != 0 && first_error.is_none() {
                            first_error = Some((seq, code));
                        }
                        if Some(seq) == last {
                            done = true;
                        }
                    }
                    Msg::Nft(kind, seq, body) => match kind {
                        NFT_MSG_NEWGEN => made = gen_id(body),
                        // `echoed` is in ascending order.
                        NFT_MSG_NEWRULE if echoed.binary_search(&seq).is_ok() => {
                            committed.rules.extend(parse_rule(body));
                        }
                        _ => {}
                    },
                }
            }
            // After an error the kernel aborts the batch: the remaining
            // messages may not all answer.
            if first_error.is_some_and(|(s, _)| last.is_none_or(|l| l > s)) {
                break;
            }
        }
        match first_error {
            None => Ok(Outcome::Done(committed, made)),
            Some((seq, errno)) => Err(HalError::Rejected(format!(
                "{what}: the kernel refused message {} of the batch ({}); nothing changed",
                seq.wrapping_sub(seqs.start),
                std::io::Error::from_raw_os_error(errno)
            ))),
        }
    }

    /// The generation a batch's commit made, from the `NFT_MSG_NEWGEN` the
    /// kernel echoes (`NFTA_GEN_ID`).
    fn gen_id(body: &[u8]) -> Option<u32> {
        crate::genl::attrs(body)
            .find(|a| a.kind == 1)
            .and_then(|a| Some(u32::from_be_bytes(a.data.get(..4)?.try_into().ok()?)))
    }

    enum Msg<'a> {
        /// `NLMSG_ERROR`: (seq, errno; 0 is an ACK).
        Ack(u32, i32),
        /// An nf_tables message: its type, seq and body (after `nfgenmsg`).
        Nft(u16, u32, &'a [u8]),
    }

    fn messages(buf: &[u8]) -> Vec<Msg<'_>> {
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
                .map_or(0, u16::from_ne_bytes);
            let len = usize::try_from(len).unwrap_or(0);
            if len < 16 {
                break;
            }
            let m = rest.get(..len).unwrap_or(rest);
            if kind == 2 {
                let code = m
                    .get(16..20)
                    .and_then(|b| b.try_into().ok())
                    .map_or(0, i32::from_ne_bytes);
                out.push(Msg::Ack(seq, code.saturating_neg()));
            } else if kind >> 8 == NFNL_SUBSYS_NFTABLES {
                out.push(Msg::Nft(kind & 0xff, seq, m.get(20..).unwrap_or(&[])));
            }
            rest = rest.get(len.div_ceil(4) * 4..).unwrap_or(&[]);
        }
        out
    }
}
