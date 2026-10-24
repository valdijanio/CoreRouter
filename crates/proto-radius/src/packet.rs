//! RADIUS wire format: header, attributes, Vendor-Specific and the extended
//! attributes of RFC 6929.
//!
//! [`Packet::parse`] validates the header and the framing of every attribute
//! once; after that the view and its iterators only borrow the input (no
//! allocation on decode). [`Builder`] writes a packet; the authenticators are
//! filled by [`crate::crypto`].

use thiserror::Error;

/// RFC 2865 §3: Code (1) + Identifier (1) + Length (2) + Authenticator (16).
pub const HEADER_LEN: usize = 20;
/// RFC 2865 §3: "The maximum length is 4096."
pub const MAX_PACKET_LEN: usize = 4096;
/// RFC 2865 §5: Length is one octet and counts Type and Length.
pub const MAX_VALUE_LEN: usize = 253;
/// RFC 2865 §5.26: Vendor-Id (4) of a Vendor-Specific attribute.
pub const VENDOR_ID_LEN: usize = 4;

/// Attribute types used by this crate (RFC 2865, 2866, 2869, 3162, 4372,
/// 4818, 5176, 6911, 6929). The full table, with names and data types, is
/// [`crate::dict`].
pub mod attr {
    pub const USER_NAME: u8 = 1;
    pub const USER_PASSWORD: u8 = 2;
    pub const CHAP_PASSWORD: u8 = 3;
    pub const NAS_IP_ADDRESS: u8 = 4;
    pub const NAS_PORT: u8 = 5;
    pub const SERVICE_TYPE: u8 = 6;
    pub const FRAMED_PROTOCOL: u8 = 7;
    pub const FRAMED_IP_ADDRESS: u8 = 8;
    pub const FRAMED_IP_NETMASK: u8 = 9;
    pub const FILTER_ID: u8 = 11;
    pub const FRAMED_MTU: u8 = 12;
    pub const REPLY_MESSAGE: u8 = 18;
    pub const FRAMED_ROUTE: u8 = 22;
    pub const STATE: u8 = 24;
    pub const CLASS: u8 = 25;
    pub const VENDOR_SPECIFIC: u8 = 26;
    pub const SESSION_TIMEOUT: u8 = 27;
    pub const IDLE_TIMEOUT: u8 = 28;
    pub const CALLED_STATION_ID: u8 = 30;
    pub const CALLING_STATION_ID: u8 = 31;
    pub const NAS_IDENTIFIER: u8 = 32;
    pub const PROXY_STATE: u8 = 33;
    pub const ACCT_STATUS_TYPE: u8 = 40;
    pub const ACCT_DELAY_TIME: u8 = 41;
    pub const ACCT_INPUT_OCTETS: u8 = 42;
    pub const ACCT_OUTPUT_OCTETS: u8 = 43;
    pub const ACCT_SESSION_ID: u8 = 44;
    pub const ACCT_AUTHENTIC: u8 = 45;
    pub const ACCT_SESSION_TIME: u8 = 46;
    pub const ACCT_INPUT_PACKETS: u8 = 47;
    pub const ACCT_OUTPUT_PACKETS: u8 = 48;
    pub const ACCT_TERMINATE_CAUSE: u8 = 49;
    pub const ACCT_MULTI_SESSION_ID: u8 = 50;
    pub const ACCT_INPUT_GIGAWORDS: u8 = 52;
    pub const ACCT_OUTPUT_GIGAWORDS: u8 = 53;
    pub const EVENT_TIMESTAMP: u8 = 55;
    pub const CHAP_CHALLENGE: u8 = 60;
    pub const NAS_PORT_TYPE: u8 = 61;
    pub const TUNNEL_PASSWORD: u8 = 69;
    pub const EAP_MESSAGE: u8 = 79;
    pub const MESSAGE_AUTHENTICATOR: u8 = 80;
    pub const ACCT_INTERIM_INTERVAL: u8 = 85;
    pub const NAS_PORT_ID: u8 = 87;
    pub const FRAMED_POOL: u8 = 88;
    pub const CHARGEABLE_USER_IDENTITY: u8 = 89;
    pub const NAS_IPV6_ADDRESS: u8 = 95;
    pub const FRAMED_INTERFACE_ID: u8 = 96;
    pub const FRAMED_IPV6_PREFIX: u8 = 97;
    pub const ERROR_CAUSE: u8 = 101;
    pub const DELEGATED_IPV6_PREFIX: u8 = 123;
    pub const FRAMED_IPV6_ADDRESS: u8 = 168;
    /// RFC 6929 §2.1: Extended-Type-1..4 (241–244).
    pub const EXTENDED_1: u8 = 241;
    pub const EXTENDED_4: u8 = 244;
    /// RFC 6929 §2.2: Long-Extended-Type-1..2 (245–246).
    pub const LONG_EXTENDED_1: u8 = 245;
    pub const LONG_EXTENDED_2: u8 = 246;
}

/// RFC 2865 §3, RFC 2866 §3, RFC 5997 §3, RFC 5176 §2.3 (codes from the
/// IANA registry of RFC 3575).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Code {
    AccessRequest,
    AccessAccept,
    AccessReject,
    AccountingRequest,
    AccountingResponse,
    AccessChallenge,
    StatusServer,
    DisconnectRequest,
    DisconnectAck,
    DisconnectNak,
    CoaRequest,
    CoaAck,
    CoaNak,
}

impl Code {
    pub const fn to_u8(self) -> u8 {
        match self {
            Self::AccessRequest => 1,
            Self::AccessAccept => 2,
            Self::AccessReject => 3,
            Self::AccountingRequest => 4,
            Self::AccountingResponse => 5,
            Self::AccessChallenge => 11,
            Self::StatusServer => 12,
            Self::DisconnectRequest => 40,
            Self::DisconnectAck => 41,
            Self::DisconnectNak => 42,
            Self::CoaRequest => 43,
            Self::CoaAck => 44,
            Self::CoaNak => 45,
        }
    }

    /// RFC 2865 §3: "Packets received with an invalid Code field MUST be
    /// silently discarded" — unknown codes (13 Status-Client, which RFC 5997
    /// §3 says is not used, included) give `None`.
    pub const fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => Self::AccessRequest,
            2 => Self::AccessAccept,
            3 => Self::AccessReject,
            4 => Self::AccountingRequest,
            5 => Self::AccountingResponse,
            11 => Self::AccessChallenge,
            12 => Self::StatusServer,
            40 => Self::DisconnectRequest,
            41 => Self::DisconnectAck,
            42 => Self::DisconnectNak,
            43 => Self::CoaRequest,
            44 => Self::CoaAck,
            45 => Self::CoaNak,
            _ => return None,
        })
    }

    /// Requests carry a Request Authenticator; the rest answer one.
    pub const fn is_request(self) -> bool {
        matches!(
            self,
            Self::AccessRequest
                | Self::AccountingRequest
                | Self::StatusServer
                | Self::DisconnectRequest
                | Self::CoaRequest
        )
    }

    /// Requests whose authenticator is an MD5 over the packet (RFC 2866 §3,
    /// RFC 5176 §2.3), not 16 random octets (RFC 2865 §3, RFC 5997 §3).
    pub const fn has_computed_request_authenticator(self) -> bool {
        matches!(
            self,
            Self::AccountingRequest | Self::DisconnectRequest | Self::CoaRequest
        )
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::AccessRequest => "Access-Request",
            Self::AccessAccept => "Access-Accept",
            Self::AccessReject => "Access-Reject",
            Self::AccountingRequest => "Accounting-Request",
            Self::AccountingResponse => "Accounting-Response",
            Self::AccessChallenge => "Access-Challenge",
            Self::StatusServer => "Status-Server",
            Self::DisconnectRequest => "Disconnect-Request",
            Self::DisconnectAck => "Disconnect-ACK",
            Self::DisconnectNak => "Disconnect-NAK",
            Self::CoaRequest => "CoA-Request",
            Self::CoaAck => "CoA-ACK",
            Self::CoaNak => "CoA-NAK",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DecodeError {
    #[error("packet shorter than the 20-byte header ({0} bytes)")]
    TooShort(usize),
    /// RFC 2865 §3: Length below 20 or above 4096.
    #[error("Length field {0} outside 20..=4096")]
    BadLength(u16),
    /// RFC 2865 §3: "If the packet is shorter than the Length field
    /// indicates, it MUST be silently discarded."
    #[error("Length field {length} but only {got} bytes received")]
    Truncated { length: u16, got: usize },
    #[error("unknown code {0}")]
    UnknownCode(u8),
    /// RFC 2865 §5: Length below 2 or past the end of the packet.
    #[error("attribute at offset {offset} has a bad length")]
    BadAttribute { offset: usize },
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EncodeError {
    #[error("attribute value of {0} bytes is longer than 253")]
    ValueTooLong(usize),
    #[error("packet would exceed 4096 bytes")]
    PacketTooLong,
    #[error("User-Password longer than 128 bytes")]
    PasswordTooLong,
    #[error("Message-Authenticator added twice")]
    DuplicateMessageAuthenticator,
    #[error("salt must have its most significant bit set")]
    BadSalt,
    #[error("type {0} is not an extended attribute type")]
    NotExtended(u8),
    #[error("vendor id {0} uses the high octet (RFC 2865 §5.26 says it is zero)")]
    BadVendor(u32),
}

/// A validated packet borrowed from the receive buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Packet<'a> {
    bytes: &'a [u8],
    code: Code,
}

impl<'a> Packet<'a> {
    /// Validate header and attribute framing. Octets after Length are
    /// padding and are ignored (RFC 2865 §3).
    pub fn parse(buf: &'a [u8]) -> Result<Self, DecodeError> {
        let (head, _) = buf
            .split_first_chunk::<HEADER_LEN>()
            .ok_or(DecodeError::TooShort(buf.len()))?;
        let [code, _, l0, l1, ..] = *head;
        let length = u16::from_be_bytes([l0, l1]);
        if usize::from(length) < HEADER_LEN || usize::from(length) > MAX_PACKET_LEN {
            return Err(DecodeError::BadLength(length));
        }
        let bytes = buf
            .get(..usize::from(length))
            .ok_or(DecodeError::Truncated {
                length,
                got: buf.len(),
            })?;
        let code = Code::from_u8(code).ok_or(DecodeError::UnknownCode(code))?;
        let mut at = HEADER_LEN;
        while at < bytes.len() {
            let len = bytes.get(at + 1).copied().map_or(0, usize::from);
            if len < 2 || at + len > bytes.len() {
                return Err(DecodeError::BadAttribute { offset: at });
            }
            at += len;
        }
        Ok(Self { bytes, code })
    }

    pub fn code(&self) -> Code {
        self.code
    }

    pub fn identifier(&self) -> u8 {
        self.bytes.get(1).copied().unwrap_or(0)
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.len() <= HEADER_LEN
    }

    pub fn authenticator(&self) -> [u8; 16] {
        let mut a = [0u8; 16];
        if let Some(src) = self.bytes.get(4..HEADER_LEN) {
            a.copy_from_slice(src);
        }
        a
    }

    /// The packet as received, without padding.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    pub fn attributes(&self) -> Attrs<'a> {
        Attrs {
            rest: self.bytes.get(HEADER_LEN..).unwrap_or(&[]),
            offset: HEADER_LEN,
        }
    }

    /// First attribute of type `typ`.
    pub fn attr(&self, typ: u8) -> Option<&'a [u8]> {
        self.attributes().find(|a| a.typ == typ).map(|a| a.value)
    }

    pub fn count(&self, typ: u8) -> usize {
        self.attributes().filter(|a| a.typ == typ).count()
    }

    pub fn attr_u32(&self, typ: u8) -> Option<u32> {
        self.attr(typ).and_then(be_u32)
    }

    /// Every vendor sub-attribute (RFC 2865 §5.26 recommended format, which
    /// RFC 4679 §3 uses with several sub-attributes per attribute).
    pub fn vsas(&self) -> impl Iterator<Item = Vsa<'a>> + 'a {
        self.attributes()
            .filter(|a| a.typ == attr::VENDOR_SPECIFIC)
            .flat_map(|a| VendorSpecific::parse(a.value).into_iter().flatten())
    }

    /// First sub-attribute `vtype` of vendor `vendor`.
    pub fn vsa(&self, vendor: u32, vtype: u8) -> Option<&'a [u8]> {
        self.vsas()
            .find(|v| v.vendor == vendor && v.typ == vtype)
            .map(|v| v.value)
    }

    /// Every RFC 6929 extended attribute (241–246), one item per fragment.
    pub fn extended(&self) -> impl Iterator<Item = Extended<'a>> + 'a {
        self.attributes().filter_map(Extended::parse)
    }

    /// The value of a Long-Extended attribute, reassembled from its
    /// fragments (RFC 6929 §2.2: "More" flag). Borrowed when it is a single
    /// fragment; `None` when absent or when the chain is malformed (a
    /// fragment with M set not followed by the same type, §2.2.1).
    pub fn long_extended(&self, typ: u8, ext: u8) -> Option<std::borrow::Cow<'a, [u8]>> {
        let mut it = self
            .attributes()
            .skip_while(|a| !(a.typ == typ && a.value.first() == Some(&ext)));
        let first = Extended::parse(it.next()?)?;
        if !first.more {
            return Some(std::borrow::Cow::Borrowed(first.value));
        }
        let mut out = first.value.to_vec();
        for a in it {
            let frag = Extended::parse(a)?;
            if frag.typ != typ || frag.ext != ext {
                return None;
            }
            out.extend_from_slice(frag.value);
            if !frag.more {
                return Some(std::borrow::Cow::Owned(out));
            }
        }
        None
    }
}

/// Big-endian u32 of a 4-byte value (RFC 8044 §3.1 `integer`).
pub fn be_u32(v: &[u8]) -> Option<u32> {
    let b: [u8; 4] = v.try_into().ok()?;
    Some(u32::from_be_bytes(b))
}

/// One top-level attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Attr<'a> {
    pub typ: u8,
    pub value: &'a [u8],
    /// Offset of the Type octet in the packet (used to zero the
    /// Message-Authenticator value when it is checked).
    pub offset: usize,
}

/// Iterator over validated attributes.
#[derive(Debug, Clone)]
pub struct Attrs<'a> {
    rest: &'a [u8],
    offset: usize,
}

impl<'a> Iterator for Attrs<'a> {
    type Item = Attr<'a>;

    fn next(&mut self) -> Option<Attr<'a>> {
        let [typ, len, ..] = *self.rest else {
            return None;
        };
        let len = usize::from(len);
        let value = self.rest.get(2..len)?;
        let at = self.offset;
        self.rest = self.rest.get(len..)?;
        self.offset += len;
        Some(Attr {
            typ,
            value,
            offset: at,
        })
    }
}

/// RFC 2865 §5.26 Vendor-Specific, split into sub-attributes.
#[derive(Debug, Clone)]
pub struct VendorSpecific<'a> {
    vendor: u32,
    rest: &'a [u8],
}

impl<'a> VendorSpecific<'a> {
    /// `None` when shorter than the Vendor-Id. Sub-attributes are read
    /// lazily; a malformed one stops the iteration (it is not the
    /// "recommended format", RFC 2865 §5.26).
    pub fn parse(value: &'a [u8]) -> Option<Self> {
        let (id, rest) = value.split_first_chunk::<VENDOR_ID_LEN>()?;
        Some(Self {
            vendor: u32::from_be_bytes(*id),
            rest,
        })
    }

    pub fn vendor(&self) -> u32 {
        self.vendor
    }

    /// True when every sub-attribute is well formed (type, length ≥ 2).
    pub fn is_well_formed(&self) -> bool {
        let mut r = self.rest;
        while !r.is_empty() {
            let len = r.get(1).copied().map_or(0, usize::from);
            if len < 2 || len > r.len() {
                return false;
            }
            r = r.get(len..).unwrap_or(&[]);
        }
        true
    }
}

impl<'a> Iterator for VendorSpecific<'a> {
    type Item = Vsa<'a>;

    fn next(&mut self) -> Option<Vsa<'a>> {
        let [typ, len, ..] = *self.rest else {
            return None;
        };
        let len = usize::from(len);
        if len < 2 {
            self.rest = &[];
            return None;
        }
        let Some(value) = self.rest.get(2..len) else {
            self.rest = &[];
            return None;
        };
        self.rest = self.rest.get(len..).unwrap_or(&[]);
        Some(Vsa {
            vendor: self.vendor,
            typ,
            value,
        })
    }
}

/// One vendor sub-attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Vsa<'a> {
    pub vendor: u32,
    pub typ: u8,
    pub value: &'a [u8],
}

/// RFC 6929 §2.1/§2.2: an extended attribute (or one fragment of a long
/// one).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Extended<'a> {
    pub typ: u8,
    pub ext: u8,
    /// Long-Extended "More" flag (RFC 6929 §2.2).
    pub more: bool,
    pub value: &'a [u8],
}

impl<'a> Extended<'a> {
    /// `None` for other types and for an extended attribute too short to
    /// hold its Extended-Type (RFC 6929 §2.8: an "invalid attribute").
    pub fn parse(a: Attr<'a>) -> Option<Self> {
        match a.typ {
            attr::EXTENDED_1..=attr::EXTENDED_4 => {
                let (&ext, value) = a.value.split_first()?;
                Some(Self {
                    typ: a.typ,
                    ext,
                    more: false,
                    value,
                })
            }
            attr::LONG_EXTENDED_1 | attr::LONG_EXTENDED_2 => {
                let ([ext, flags], value) =
                    a.value.split_first_chunk::<2>().map(|(h, v)| (*h, v))?;
                Some(Self {
                    typ: a.typ,
                    ext,
                    more: flags & 0x80 != 0,
                    value,
                })
            }
            _ => None,
        }
    }
}

/// Anything attributes can be appended to: [`Builder`] and [`AttrList`].
pub trait PushAttr {
    /// The encoded attributes so far.
    fn buf_mut(&mut self) -> &mut Vec<u8>;
    /// Bytes still available for attributes.
    fn room(&self) -> usize;

    /// One attribute (RFC 2865 §5: value up to 253 bytes).
    fn push(&mut self, typ: u8, value: &[u8]) -> Result<&mut Self, EncodeError> {
        if value.len() > MAX_VALUE_LEN {
            return Err(EncodeError::ValueTooLong(value.len()));
        }
        if value.len() + 2 > self.room() {
            return Err(EncodeError::PacketTooLong);
        }
        let b = self.buf_mut();
        b.push(typ);
        b.push((value.len() + 2) as u8);
        b.extend_from_slice(value);
        Ok(self)
    }

    fn push_u32(&mut self, typ: u8, v: u32) -> Result<&mut Self, EncodeError> {
        self.push(typ, &v.to_be_bytes())
    }

    fn push_ipv4(&mut self, typ: u8, v: std::net::Ipv4Addr) -> Result<&mut Self, EncodeError> {
        self.push(typ, &v.octets())
    }

    fn push_text(&mut self, typ: u8, v: &str) -> Result<&mut Self, EncodeError> {
        self.push(typ, v.as_bytes())
    }

    /// RFC 8044 §3.10 `ipv6prefix`: reserved octet, prefix length, then
    /// only the octets the prefix needs (RFC 3162 §2.3); bits past the
    /// length are zeroed.
    fn push_ipv6_prefix(
        &mut self,
        typ: u8,
        addr: std::net::Ipv6Addr,
        len: u8,
    ) -> Result<&mut Self, EncodeError> {
        let len = len.min(128);
        let bits = u128::from(addr) & u128::MAX.checked_shl(128 - u32::from(len)).unwrap_or(0);
        let octets = bits.to_be_bytes();
        let n = usize::from(len).div_ceil(8);
        let mut v = [0u8; 18];
        v[1] = len;
        let (dst, src) = (v.get_mut(2..2 + n), octets.get(..n));
        if let (Some(dst), Some(src)) = (dst, src) {
            dst.copy_from_slice(src);
        }
        self.push(typ, v.get(..2 + n).unwrap_or(&[]))
    }

    /// One Vendor-Specific attribute with one sub-attribute (RFC 2865
    /// §5.26 recommended format).
    fn push_vsa(&mut self, vendor: u32, vtype: u8, value: &[u8]) -> Result<&mut Self, EncodeError> {
        if vendor > 0x00FF_FFFF {
            return Err(EncodeError::BadVendor(vendor));
        }
        let inner = value.len() + 2;
        if VENDOR_ID_LEN + inner > MAX_VALUE_LEN {
            return Err(EncodeError::ValueTooLong(value.len()));
        }
        if VENDOR_ID_LEN + inner + 2 > self.room() {
            return Err(EncodeError::PacketTooLong);
        }
        let b = self.buf_mut();
        b.push(attr::VENDOR_SPECIFIC);
        b.push((VENDOR_ID_LEN + inner + 2) as u8);
        b.extend_from_slice(&vendor.to_be_bytes());
        b.push(vtype);
        b.push(inner as u8);
        b.extend_from_slice(value);
        Ok(self)
    }

    /// RFC 6929 §2.1: Extended-Type-1..4 (value up to 252 bytes).
    fn push_extended(&mut self, typ: u8, ext: u8, value: &[u8]) -> Result<&mut Self, EncodeError> {
        if !(attr::EXTENDED_1..=attr::EXTENDED_4).contains(&typ) {
            return Err(EncodeError::NotExtended(typ));
        }
        if value.len() + 1 > MAX_VALUE_LEN {
            return Err(EncodeError::ValueTooLong(value.len()));
        }
        if value.len() + 3 > self.room() {
            return Err(EncodeError::PacketTooLong);
        }
        let b = self.buf_mut();
        b.push(typ);
        b.push((value.len() + 3) as u8);
        b.push(ext);
        b.extend_from_slice(value);
        Ok(self)
    }

    /// RFC 6929 §2.2: Long-Extended-Type, split into 251-byte fragments
    /// with the More flag set on every one but the last (§2.2.1).
    fn push_long_extended(
        &mut self,
        typ: u8,
        ext: u8,
        value: &[u8],
    ) -> Result<&mut Self, EncodeError> {
        const FRAG: usize = MAX_VALUE_LEN - 2;
        if typ != attr::LONG_EXTENDED_1 && typ != attr::LONG_EXTENDED_2 {
            return Err(EncodeError::NotExtended(typ));
        }
        let frags = value.len().div_ceil(FRAG).max(1);
        if value.len() + frags * 4 > self.room() {
            return Err(EncodeError::PacketTooLong);
        }
        let b = self.buf_mut();
        let mut chunks = value.chunks(FRAG).peekable();
        if chunks.peek().is_none() {
            b.extend_from_slice(&[typ, 4, ext, 0]);
        }
        while let Some(c) = chunks.next() {
            let more = if chunks.peek().is_some() { 0x80 } else { 0 };
            b.extend_from_slice(&[typ, (c.len() + 4) as u8, ext, more]);
            b.extend_from_slice(c);
        }
        Ok(self)
    }
}

/// An encoded attribute list kept apart from any header (a client keeps one
/// per request and re-frames it on every transmission).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AttrList {
    bytes: Vec<u8>,
}

impl AttrList {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Iterate like a packet's attributes.
    pub fn iter(&self) -> Attrs<'_> {
        Attrs {
            rest: &self.bytes,
            offset: 0,
        }
    }

    /// Copy the attributes of a received packet, except the types in
    /// `skip` (Message-Authenticator, say, which is recomputed).
    pub fn from_packet(p: &Packet<'_>, skip: &[u8]) -> Self {
        let mut bytes = Vec::with_capacity(p.len());
        for a in p.attributes().filter(|a| !skip.contains(&a.typ)) {
            bytes.push(a.typ);
            bytes.push((a.value.len() + 2) as u8);
            bytes.extend_from_slice(a.value);
        }
        Self { bytes }
    }
}

impl PushAttr for AttrList {
    fn buf_mut(&mut self) -> &mut Vec<u8> {
        &mut self.bytes
    }

    fn room(&self) -> usize {
        (MAX_PACKET_LEN - HEADER_LEN).saturating_sub(self.bytes.len())
    }
}

/// Packet writer. Attributes are appended in order; the authenticator and
/// Message-Authenticator are filled by the `crate::crypto::sign_*`
/// functions, which also fix the Length field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Builder {
    buf: Vec<u8>,
    /// Offset of the Message-Authenticator attribute, when added.
    ma: Option<usize>,
}

impl Builder {
    pub fn new(code: Code, identifier: u8) -> Self {
        Self::with_authenticator(code, identifier, [0; 16])
    }

    pub fn with_authenticator(code: Code, identifier: u8, authenticator: [u8; 16]) -> Self {
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(&[code.to_u8(), identifier, 0, HEADER_LEN as u8]);
        buf.extend_from_slice(&authenticator);
        Self { buf, ma: None }
    }

    /// Add a zeroed Message-Authenticator (RFC 2869 §5.14). It is filled
    /// when the packet is signed. Blast-RADIUS (CVE-2024-3596) mitigations
    /// put it first, so call this before any other attribute.
    pub fn message_authenticator(&mut self) -> Result<&mut Self, EncodeError> {
        if self.ma.is_some() {
            return Err(EncodeError::DuplicateMessageAuthenticator);
        }
        let at = self.buf.len();
        self.push(attr::MESSAGE_AUTHENTICATOR, &[0; 16])?;
        self.ma = Some(at);
        Ok(self)
    }

    /// Append already encoded attributes (from an [`AttrList`]).
    pub fn extend(&mut self, list: &AttrList) -> Result<&mut Self, EncodeError> {
        if list.len() > self.room() {
            return Err(EncodeError::PacketTooLong);
        }
        self.buf.extend_from_slice(list.as_bytes());
        Ok(self)
    }

    pub fn code(&self) -> Option<Code> {
        self.buf.first().copied().and_then(Code::from_u8)
    }

    pub fn authenticator(&self) -> [u8; 16] {
        let mut a = [0u8; 16];
        if let Some(src) = self.buf.get(4..HEADER_LEN) {
            a.copy_from_slice(src);
        }
        a
    }

    pub fn set_authenticator(&mut self, a: [u8; 16]) {
        if let Some(dst) = self.buf.get_mut(4..HEADER_LEN) {
            dst.copy_from_slice(&a);
        }
    }

    pub(crate) fn ma_offset(&self) -> Option<usize> {
        self.ma
    }

    /// Fix the Length field; the bytes as they are now.
    pub(crate) fn bytes_mut(&mut self) -> &mut Vec<u8> {
        let len = (self.buf.len() as u16).to_be_bytes();
        if let Some(dst) = self.buf.get_mut(2..4) {
            dst.copy_from_slice(&len);
        }
        &mut self.buf
    }

    /// The packet without signing (tests, and codes whose authenticator the
    /// caller already set).
    pub fn into_unsigned(mut self) -> Vec<u8> {
        self.bytes_mut();
        self.buf
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.len() <= HEADER_LEN
    }
}

impl PushAttr for Builder {
    fn buf_mut(&mut self) -> &mut Vec<u8> {
        &mut self.buf
    }

    fn room(&self) -> usize {
        MAX_PACKET_LEN.saturating_sub(self.buf.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_checks_follow_rfc_2865_section_3() {
        assert_eq!(Packet::parse(&[1; 19]), Err(DecodeError::TooShort(19)));
        let mut p = vec![1, 0, 0, 19];
        p.resize(20, 0);
        assert_eq!(Packet::parse(&p), Err(DecodeError::BadLength(19)));
        p[3] = 30;
        assert_eq!(
            Packet::parse(&p),
            Err(DecodeError::Truncated {
                length: 30,
                got: 20
            })
        );
        p[3] = 20;
        p[0] = 13; // Status-Client is reserved (RFC 5997 §3)
        assert_eq!(Packet::parse(&p), Err(DecodeError::UnknownCode(13)));
        p[0] = 1;
        // Padding after Length is ignored.
        p.extend_from_slice(&[0xAA; 7]);
        assert_eq!(Packet::parse(&p).unwrap().len(), 20);
    }

    #[test]
    fn attribute_lengths_are_checked() {
        let mut b = Builder::new(Code::AccessRequest, 1);
        b.push(attr::USER_NAME, b"bob").unwrap();
        let mut bytes = b.into_unsigned();
        assert!(Packet::parse(&bytes).is_ok());
        bytes[21] = 1; // length below 2
        assert_eq!(
            Packet::parse(&bytes),
            Err(DecodeError::BadAttribute { offset: 20 })
        );
        bytes[21] = 6; // past the end
        assert_eq!(
            Packet::parse(&bytes),
            Err(DecodeError::BadAttribute { offset: 20 })
        );
    }

    #[test]
    fn values_and_packets_have_limits() {
        let mut b = Builder::new(Code::AccessRequest, 1);
        assert_eq!(
            b.push(1, &[0; 254]).unwrap_err(),
            EncodeError::ValueTooLong(254)
        );
        for _ in 0..15 {
            b.push(25, &[0; 253]).unwrap();
        }
        assert_eq!(
            b.push(25, &[0; 253]).unwrap_err(),
            EncodeError::PacketTooLong
        );
        assert!(b.len() <= MAX_PACKET_LEN);
    }

    #[test]
    fn vsa_with_several_sub_attributes_rfc_4679() {
        // RFC 4679 §3: one attribute 26 carrying Agent-Circuit-Id and
        // Agent-Remote-Id.
        let mut v = 3561u32.to_be_bytes().to_vec();
        v.extend_from_slice(&[1, 6, b'o', b'l', b't', b'1', 2, 4, b'r', b'1']);
        let mut b = Builder::new(Code::AccessRequest, 0);
        b.push(attr::VENDOR_SPECIFIC, &v).unwrap();
        let bytes = b.into_unsigned();
        let p = Packet::parse(&bytes).unwrap();
        let subs: Vec<_> = p.vsas().collect();
        assert_eq!(subs.len(), 2);
        assert_eq!(p.vsa(3561, 1), Some(&b"olt1"[..]));
        assert_eq!(p.vsa(3561, 2), Some(&b"r1"[..]));
    }

    #[test]
    fn long_extended_fragments_and_reassembles() {
        let value: Vec<u8> = (0..600u32).map(|i| i as u8).collect();
        let mut b = Builder::new(Code::AccessAccept, 0);
        b.push_long_extended(attr::LONG_EXTENDED_1, 7, &value)
            .unwrap();
        b.push_extended(attr::EXTENDED_1, 3, b"x").unwrap();
        let bytes = b.into_unsigned();
        let p = Packet::parse(&bytes).unwrap();
        assert_eq!(
            p.extended()
                .filter(|e| e.typ == attr::LONG_EXTENDED_1)
                .count(),
            3
        );
        assert_eq!(
            p.long_extended(attr::LONG_EXTENDED_1, 7).unwrap().as_ref(),
            &value[..]
        );
        let short = p.extended().find(|e| e.typ == attr::EXTENDED_1).unwrap();
        assert_eq!((short.ext, short.value), (3, &b"x"[..]));
    }

    #[test]
    fn ipv6_prefix_writes_only_the_needed_octets() {
        let mut l = AttrList::new();
        l.push_ipv6_prefix(97, "2001:db8:ffff::1".parse().unwrap(), 36)
            .unwrap();
        // RFC 3162 §2.3: reserved, length, then ceil(36/8) = 5 octets with
        // the bits past 36 zeroed.
        assert_eq!(l.as_bytes(), &[97, 9, 0, 36, 0x20, 0x01, 0x0d, 0xb8, 0xf0]);
    }
}
