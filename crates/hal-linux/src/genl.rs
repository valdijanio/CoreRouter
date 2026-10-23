//! Minimal generic netlink client (G1.19): enough to ask the `ethtool` and
//! `devlink` families for a port's state, synchronously and without
//! `unsafe` (the socket is `netlink-sys`'s).
//!
//! The codec is pure and bounded: [`attrs`] walks attributes over a byte
//! slice and stops at the first malformed one, so a hostile or truncated
//! reply yields fewer attributes, never a panic or an out-of-bounds read.
//! [`Msg`] builds a request.

/// Netlink attribute header length, and the alignment of everything.
const NLA_HDR: usize = 4;
const ALIGN: usize = 4;
/// `NLA_F_NESTED` / `NLA_F_NET_BYTEORDER`: flags in the type field.
const NLA_TYPE_MASK: u16 = 0x3FFF;
const NLA_F_NESTED: u16 = 1 << 15;

/// Netlink message header (`nlmsghdr`) + generic header (`genlmsghdr`).
pub(crate) const NLMSG_HDR: usize = 16;
pub(crate) const GENL_HDR: usize = 4;

pub(crate) const NLMSG_ERROR: u16 = 2;
pub(crate) const NLMSG_DONE: u16 = 3;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_ACK: u16 = 4;

fn align(n: usize) -> usize {
    n.div_ceil(ALIGN).saturating_mul(ALIGN)
}

/// One attribute: its type (flags stripped) and payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Attr<'a> {
    pub kind: u16,
    pub data: &'a [u8],
}

impl<'a> Attr<'a> {
    pub fn u8(&self) -> Option<u8> {
        self.data.first().copied()
    }

    pub fn u16(&self) -> Option<u16> {
        Some(u16::from_ne_bytes(self.data.get(..2)?.try_into().ok()?))
    }

    pub fn u32(&self) -> Option<u32> {
        Some(u32::from_ne_bytes(self.data.get(..4)?.try_into().ok()?))
    }

    pub fn u64(&self) -> Option<u64> {
        Some(u64::from_ne_bytes(self.data.get(..8)?.try_into().ok()?))
    }

    /// A NUL-terminated string, bounded and lossy (hostile bytes).
    pub fn str(&self) -> Option<String> {
        let end = self
            .data
            .iter()
            .position(|b| *b == 0)
            .unwrap_or(self.data.len());
        let raw = self.data.get(..end.min(256))?;
        Some(String::from_utf8_lossy(raw).into_owned())
    }

    /// The attributes nested inside this one.
    pub fn nested(&self) -> Attrs<'a> {
        attrs(self.data)
    }
}

/// Iterator over the attributes of `buf`.
#[derive(Debug, Clone)]
pub(crate) struct Attrs<'a> {
    rest: &'a [u8],
}

pub(crate) fn attrs(buf: &[u8]) -> Attrs<'_> {
    Attrs { rest: buf }
}

impl<'a> Iterator for Attrs<'a> {
    type Item = Attr<'a>;

    fn next(&mut self) -> Option<Attr<'a>> {
        let hdr = self.rest.get(..NLA_HDR)?;
        let len = usize::from(u16::from_ne_bytes([*hdr.first()?, *hdr.get(1)?]));
        let kind = u16::from_ne_bytes([*hdr.get(2)?, *hdr.get(3)?]) & NLA_TYPE_MASK;
        let data = match self.rest.get(NLA_HDR..len) {
            Some(d) if len >= NLA_HDR => d,
            _ => {
                self.rest = &[];
                return None;
            }
        };
        self.rest = self.rest.get(align(len)..).unwrap_or(&[]);
        Some(Attr { kind, data })
    }
}

/// First attribute of `kind` in `it`.
pub(crate) fn find<'a>(mut it: Attrs<'a>, kind: u16) -> Option<Attr<'a>> {
    it.find(|a| a.kind == kind)
}

/// One message of a reply buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reply<'a> {
    /// A family message: its generic command and attributes.
    Data {
        cmd: u8,
        attrs: &'a [u8],
    },
    /// `NLMSG_ERROR` with code 0: the request's ACK.
    Ack,
    /// `NLMSG_ERROR` with a negative errno (stored positive).
    Error(i32),
    Done,
}

/// The messages in one `recv` buffer, for request `seq` (others skipped).
pub(crate) fn replies(buf: &[u8], seq: u32) -> Vec<Reply<'_>> {
    let mut out = Vec::new();
    let mut rest = buf;
    while let Some(hdr) = rest.get(..NLMSG_HDR) {
        let word = |at: usize| -> Option<u32> {
            Some(u32::from_ne_bytes(hdr.get(at..at + 4)?.try_into().ok()?))
        };
        let kind = hdr
            .get(4..6)
            .and_then(|b| b.try_into().ok())
            .map(u16::from_ne_bytes);
        let (Some(len), Some(kind), Some(msg_seq)) = (word(0), kind, word(8)) else {
            break;
        };
        let len = usize::try_from(len).unwrap_or(0);
        let Some(body) = rest.get(NLMSG_HDR..len).filter(|_| len >= NLMSG_HDR) else {
            break;
        };
        rest = rest.get(align(len)..).unwrap_or(&[]);
        if msg_seq != seq {
            continue;
        }
        let reply = match kind {
            NLMSG_DONE => Reply::Done,
            NLMSG_ERROR => {
                let code = body
                    .get(..4)
                    .and_then(|b| b.try_into().ok())
                    .map_or(0, i32::from_ne_bytes);
                if code == 0 {
                    Reply::Ack
                } else {
                    Reply::Error(code.saturating_neg())
                }
            }
            _ => match (body.first(), body.get(GENL_HDR..)) {
                (Some(cmd), Some(attrs)) => Reply::Data { cmd: *cmd, attrs },
                _ => continue,
            },
        };
        out.push(reply);
    }
    out
}

/// A request being built: netlink + generic headers, then attributes.
#[derive(Debug, Clone)]
pub(crate) struct Msg {
    buf: Vec<u8>,
    /// Start offsets of the nests still open.
    open: Vec<usize>,
}

impl Msg {
    pub fn new(family: u16, cmd: u8, version: u8, seq: u32) -> Self {
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(&0u32.to_ne_bytes()); // length, set by `finish`
        buf.extend_from_slice(&family.to_ne_bytes());
        buf.extend_from_slice(&(NLM_F_REQUEST | NLM_F_ACK).to_ne_bytes());
        buf.extend_from_slice(&seq.to_ne_bytes());
        buf.extend_from_slice(&0u32.to_ne_bytes()); // port id: the kernel's
        buf.extend_from_slice(&[cmd, version, 0, 0]);
        Self {
            buf,
            open: Vec::new(),
        }
    }

    fn put(&mut self, kind: u16, data: &[u8]) -> &mut Self {
        let len = u16::try_from(NLA_HDR + data.len()).unwrap_or(u16::MAX);
        self.buf.extend_from_slice(&len.to_ne_bytes());
        self.buf.extend_from_slice(&kind.to_ne_bytes());
        self.buf.extend_from_slice(data);
        self.buf.resize(align(self.buf.len()), 0);
        self
    }

    pub fn u8(&mut self, kind: u16, v: u8) -> &mut Self {
        self.put(kind, &[v])
    }

    pub fn u32(&mut self, kind: u16, v: u32) -> &mut Self {
        self.put(kind, &v.to_ne_bytes())
    }

    pub fn flag(&mut self, kind: u16) -> &mut Self {
        self.put(kind, &[])
    }

    pub fn str(&mut self, kind: u16, s: &str) -> &mut Self {
        let mut data = s.as_bytes().to_vec();
        data.push(0);
        self.put(kind, &data)
    }

    pub fn begin(&mut self, kind: u16) -> &mut Self {
        self.open.push(self.buf.len());
        self.put(kind | NLA_F_NESTED, &[])
    }

    pub fn end(&mut self) -> &mut Self {
        if let Some(start) = self.open.pop() {
            let len = u16::try_from(self.buf.len().saturating_sub(start)).unwrap_or(u16::MAX);
            if let Some(slot) = self.buf.get_mut(start..start + 2) {
                slot.copy_from_slice(&len.to_ne_bytes());
            }
        }
        self
    }

    pub fn finish(mut self) -> Vec<u8> {
        while !self.open.is_empty() {
            self.end();
        }
        let len = u32::try_from(self.buf.len()).unwrap_or(u32::MAX);
        if let Some(slot) = self.buf.get_mut(..4) {
            slot.copy_from_slice(&len.to_ne_bytes());
        }
        self.buf
    }
}

#[cfg(target_os = "linux")]
pub(crate) use io::Genl;

#[cfg(target_os = "linux")]
mod io {
    use std::os::fd::AsFd;
    use std::time::{Duration, Instant};

    use netlink_sys::{Socket, protocols::NETLINK_GENERIC};
    use nix::poll::{PollFd, PollFlags, PollTimeout, poll};

    use super::{Msg, Reply, attrs, find, replies};

    const GENL_ID_CTRL: u16 = 16;
    const CTRL_CMD_GETFAMILY: u8 = 3;
    const CTRL_ATTR_FAMILY_ID: u16 = 1;
    const CTRL_ATTR_FAMILY_NAME: u16 = 2;
    const CTRL_ATTR_MCAST_GROUPS: u16 = 7;
    const CTRL_ATTR_MCAST_GRP_NAME: u16 = 1;
    const CTRL_ATTR_MCAST_GRP_ID: u16 = 2;
    /// A reply slower than this is a stuck driver: give up on it.
    const TIMEOUT_MS: u16 = 1000;
    /// Bound on the messages of one reply (dumps are not used).
    const MAX_REPLIES: usize = 64;

    /// One generic netlink socket of the current network namespace.
    pub(crate) struct Genl {
        sock: Socket,
        seq: u32,
    }

    /// Why a request failed: a kernel errno, or the socket.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) enum GenlError {
        Errno(i32),
        Io(String),
    }

    impl GenlError {
        /// The driver or kernel has no such operation.
        pub fn unsupported(&self) -> bool {
            matches!(self, GenlError::Errno(95 | 22 | 2))
        }
    }

    impl std::fmt::Display for GenlError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                GenlError::Errno(95) => f.write_str("not supported by the driver"),
                GenlError::Errno(e) => {
                    write!(f, "{}", std::io::Error::from_raw_os_error(*e))
                }
                GenlError::Io(e) => f.write_str(e),
            }
        }
    }

    impl Genl {
        pub fn open() -> Result<Self, GenlError> {
            let mut sock = Socket::new(NETLINK_GENERIC)
                .map_err(|e| GenlError::Io(format!("generic netlink socket: {e}")))?;
            sock.bind_auto()
                .map_err(|e| GenlError::Io(format!("generic netlink bind: {e}")))?;
            Ok(Self { sock, seq: 0 })
        }

        /// Id of family `name` (`ethtool`, `devlink`).
        pub fn family(&mut self, name: &str) -> Result<u16, GenlError> {
            Ok(self.family_and_group(name, "")?.0)
        }

        /// Id of family `name` and of its multicast group `group` (`None`
        /// when it has no such group, or `group` is empty).
        pub fn family_and_group(
            &mut self,
            name: &str,
            group: &str,
        ) -> Result<(u16, Option<u32>), GenlError> {
            let seq = self.next_seq();
            let mut m = Msg::new(GENL_ID_CTRL, CTRL_CMD_GETFAMILY, 1, seq);
            m.str(CTRL_ATTR_FAMILY_NAME, name);
            let data = self.call(m.finish(), seq)?;
            let id = data
                .iter()
                .find_map(|(_, a)| find(attrs(a), CTRL_ATTR_FAMILY_ID)?.u16())
                .ok_or_else(|| GenlError::Io(format!("no id for family {name}")))?;
            let gid = data.iter().find_map(|(_, a)| {
                find(attrs(a), CTRL_ATTR_MCAST_GROUPS)?
                    .nested()
                    .find_map(|g| {
                        let n = find(g.nested(), CTRL_ATTR_MCAST_GRP_NAME)?.str()?;
                        (!group.is_empty() && n == group)
                            .then(|| find(g.nested(), CTRL_ATTR_MCAST_GRP_ID)?.u32())
                            .flatten()
                    })
            });
            Ok((id, gid))
        }

        /// Receive the multicast messages of `group` from now on.
        pub fn join(&mut self, group: u32) -> Result<(), GenlError> {
            self.sock
                .add_membership(group)
                .map_err(|e| GenlError::Io(format!("netlink join group {group}: {e}")))
        }

        /// Notifications (sequence 0) that arrive within `timeout_ms`; an
        /// empty list when none did.
        pub fn notifications(&mut self, timeout_ms: u16) -> Result<Vec<(u8, Vec<u8>)>, GenlError> {
            let mut fds = [PollFd::new(self.sock.as_fd(), PollFlags::POLLIN)];
            let ready = poll(&mut fds, PollTimeout::from(timeout_ms))
                .map_err(|e| GenlError::Io(format!("netlink poll: {e}")))?;
            if ready == 0 {
                return Ok(Vec::new());
            }
            let (buf, _) = self
                .sock
                .recv_from_full()
                .map_err(|e| GenlError::Io(format!("netlink recv: {e}")))?;
            Ok(replies(&buf, 0)
                .into_iter()
                .filter_map(|r| match r {
                    Reply::Data { cmd, attrs } => Some((cmd, attrs.to_vec())),
                    _ => None,
                })
                .take(MAX_REPLIES)
                .collect())
        }

        pub fn next_seq(&mut self) -> u32 {
            self.seq = self.seq.wrapping_add(1);
            self.seq
        }

        /// Send `req` and collect the data messages until the ACK.
        pub fn call(&mut self, req: Vec<u8>, seq: u32) -> Result<Vec<(u8, Vec<u8>)>, GenlError> {
            self.sock
                .send(&req, 0)
                .map_err(|e| GenlError::Io(format!("netlink send: {e}")))?;
            let mut out = Vec::new();
            // One deadline for the whole answer: unrelated notifications
            // (a socket that joined a multicast group) kept re-arming a
            // per-poll timeout forever.
            let start = Instant::now();
            let deadline = start
                .checked_add(Duration::from_millis(u64::from(TIMEOUT_MS)))
                .unwrap_or(start);
            loop {
                let left = deadline.saturating_duration_since(Instant::now());
                let left_ms = u16::try_from(left.as_millis()).unwrap_or(TIMEOUT_MS);
                let mut fds = [PollFd::new(self.sock.as_fd(), PollFlags::POLLIN)];
                let ready = if left_ms == 0 {
                    0
                } else {
                    poll(&mut fds, PollTimeout::from(left_ms))
                        .map_err(|e| GenlError::Io(format!("netlink poll: {e}")))?
                };
                if ready == 0 {
                    return Err(GenlError::Io("no answer from the kernel in 1 s".into()));
                }
                let (buf, _) = self
                    .sock
                    .recv_from_full()
                    .map_err(|e| GenlError::Io(format!("netlink recv: {e}")))?;
                for r in replies(&buf, seq) {
                    match r {
                        Reply::Data { cmd, attrs } => {
                            if out.len() >= MAX_REPLIES {
                                return Err(GenlError::Io("reply too long".into()));
                            }
                            out.push((cmd, attrs.to_vec()));
                        }
                        Reply::Ack | Reply::Done => return Ok(out),
                        Reply::Error(e) => return Err(GenlError::Errno(e)),
                    }
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub(crate) use io::GenlError;

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn builds_and_reads_back_nested_attributes() {
        let mut m = Msg::new(20, 4, 1, 7);
        m.begin(1).str(2, "eth0").u32(3, 0).end().flag(9);
        let buf = m.finish();
        assert_eq!(buf.len() % 4, 0);
        let len = u32::from_ne_bytes(buf[..4].try_into().unwrap()) as usize;
        assert_eq!(len, buf.len());
        let body = &buf[NLMSG_HDR + GENL_HDR..];
        let top: Vec<Attr> = attrs(body).collect();
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].kind, 1, "NLA_F_NESTED is stripped");
        let inner: Vec<Attr> = top[0].nested().collect();
        assert_eq!(inner[0].str().as_deref(), Some("eth0"));
        assert_eq!(inner[1].u32(), Some(0));
        assert_eq!(top[1].kind, 9);
        assert!(top[1].data.is_empty());
    }

    fn nlmsg(kind: u16, seq: u32, body: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&((NLMSG_HDR + body.len()) as u32).to_ne_bytes());
        b.extend_from_slice(&kind.to_ne_bytes());
        b.extend_from_slice(&0u16.to_ne_bytes());
        b.extend_from_slice(&seq.to_ne_bytes());
        b.extend_from_slice(&0u32.to_ne_bytes());
        b.extend_from_slice(body);
        b.resize(align(b.len()), 0);
        b
    }

    #[test]
    fn splits_replies_and_errors() {
        let mut buf = nlmsg(30, 5, &[4, 1, 0, 0, 8, 0, 5, 0, 1, 0, 0, 0]);
        buf.extend(nlmsg(30, 4, &[4, 1, 0, 0])); // another request: skipped
        buf.extend(nlmsg(NLMSG_ERROR, 5, &(-95i32).to_ne_bytes()));
        let r = replies(&buf, 5);
        assert_eq!(r.len(), 2);
        match r[0] {
            Reply::Data { cmd, attrs: a } => {
                assert_eq!(cmd, 4);
                assert_eq!(find(attrs(a), 5).and_then(|x| x.u32()), Some(1));
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(r[1], Reply::Error(95));
        let ack = nlmsg(NLMSG_ERROR, 1, &0i32.to_ne_bytes());
        assert_eq!(replies(&ack, 1), [Reply::Ack]);
    }

    #[test]
    fn short_values_are_none() {
        let a = Attr {
            kind: 1,
            data: &[1, 2],
        };
        assert_eq!(a.u8(), Some(1));
        assert_eq!(a.u16(), Some(u16::from_ne_bytes([1, 2])));
        assert_eq!(a.u32(), None);
        assert_eq!(a.u64(), None);
    }

    proptest! {
        /// Hostile bytes: walking them never panics, never loops forever,
        /// and every attribute found lies inside the buffer.
        #[test]
        fn hostile_attributes_are_bounded(buf in proptest::collection::vec(any::<u8>(), 0..512)) {
            let mut n = 0usize;
            for a in attrs(&buf) {
                n += 1;
                prop_assert!(a.data.len() <= buf.len());
                let _ = (a.u8(), a.u16(), a.u32(), a.u64(), a.str());
                for b in a.nested() {
                    prop_assert!(b.data.len() <= a.data.len());
                }
            }
            prop_assert!(n <= buf.len() / NLA_HDR + 1);
            let _ = replies(&buf, 0);
            let _ = replies(&buf, 1);
        }

        /// What `Msg` writes, `attrs` reads back.
        #[test]
        fn round_trip(vals in proptest::collection::vec((1u16..0x3FFF, any::<u32>()), 0..32),
                      name in "[a-z0-9]{0,15}") {
            let mut m = Msg::new(1, 1, 1, 1);
            m.str(1, &name);
            m.begin(2);
            for (k, v) in &vals {
                m.u32(*k, *v);
            }
            m.end();
            let buf = m.finish();
            let body = &buf[NLMSG_HDR + GENL_HDR..];
            let top: Vec<Attr> = attrs(body).collect();
            prop_assert_eq!(top[0].str(), Some(name));
            let inner: Vec<(u16, u32)> =
                top[1].nested().map(|a| (a.kind, a.u32().unwrap())).collect();
            prop_assert_eq!(inner, vals);
        }
    }
}
