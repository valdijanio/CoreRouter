//! Replies, as bytes, through `dhcproto` (RFC 2131 Table 3).
//!
//! `dhcproto` asserts on a `chaddr` over 16 bytes and a `file` over 128:
//! both are bounded here before it sees them. It writes options in code
//! order and splits long ones (RFC 3396). Option 82 is written here, last
//! (RFC 3046 §2.2): `dhcproto` 0.15 writes a raw option 82 twice (its
//! "82 last" filter and its lookup disagree on the key).

use std::net::Ipv4Addr;

use dhcproto::v4::{
    DhcpOption, Flags, HType, Message, MessageType, Opcode, OptionCode, UnknownOption,
};
use dhcproto::{Encodable, Encoder};

use super::request::{Kind, Request};

/// The header of a reply.
#[derive(Debug, Clone)]
pub struct Head {
    pub kind: Kind,
    pub ciaddr: Ipv4Addr,
    pub yiaddr: Ipv4Addr,
    pub siaddr: Ipv4Addr,
    /// The `file` field (PXE), at most 127 bytes.
    pub file: Option<String>,
}

fn message_type(k: Kind) -> MessageType {
    match k {
        Kind::Discover => MessageType::Discover,
        Kind::Offer => MessageType::Offer,
        Kind::Request => MessageType::Request,
        Kind::Decline => MessageType::Decline,
        Kind::Ack => MessageType::Ack,
        Kind::Nak => MessageType::Nak,
        Kind::Release => MessageType::Release,
        Kind::Inform => MessageType::Inform,
    }
}

/// Encode a reply to `req`: the header fields Table 3 copies from the
/// request (`xid`, `flags`, `giaddr`, `chaddr`), then `head`, then
/// `options` (code, bytes), which must not hold 53.
pub fn encode(req: &Request, head: &Head, options: &[(u8, Vec<u8>)]) -> Option<Vec<u8>> {
    let chaddr = req.chaddr.get(..req.chaddr.len().min(16)).unwrap_or(&[]);
    let mut m = Message::new_with_id(
        req.xid,
        head.ciaddr,
        head.yiaddr,
        head.siaddr,
        req.giaddr,
        chaddr,
    );
    m.set_opcode(Opcode::BootReply)
        .set_htype(HType::from(req.htype))
        .set_hops(0)
        .set_secs(0);
    // RFC 2131 §4.3.2: a NAK through a relay MUST set the broadcast bit.
    let bcast = req.broadcast || (head.kind == Kind::Nak && !req.giaddr.is_unspecified());
    m.set_flags(if bcast {
        Flags::default().set_broadcast()
    } else {
        Flags::default()
    });
    if let Some(f) = head
        .file
        .as_deref()
        .filter(|f| !f.is_empty() && f.len() < 128)
    {
        m.set_fname(f.as_bytes());
    }
    let opts = m.opts_mut();
    opts.insert(DhcpOption::MessageType(message_type(head.kind)));
    let mut relay: Option<&[u8]> = None;
    for (code, data) in options {
        if *code == 82 {
            relay = Some(data);
            continue;
        }
        if matches!(code, 0 | 53 | 255) || data.len() > 1024 {
            continue;
        }
        opts.insert(DhcpOption::Unknown(UnknownOption::new(
            OptionCode::from(*code),
            data.clone(),
        )));
    }
    let mut buf = Vec::with_capacity(400);
    m.encode(&mut Encoder::new(&mut buf)).ok()?;
    if let Some(data) = relay.filter(|d| !d.is_empty() && d.len() <= 1024) {
        // Before the end marker, split in 255-byte pieces (RFC 3396).
        if buf.last() != Some(&255) {
            return None;
        }
        buf.pop();
        for piece in data.chunks(255) {
            buf.push(82);
            buf.push(u8::try_from(piece.len()).ok()?);
            buf.extend_from_slice(piece);
        }
        buf.push(255);
    }
    Some(buf)
}
