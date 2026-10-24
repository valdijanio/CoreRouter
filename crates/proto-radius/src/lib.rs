//! L2 — RADIUS for the BNG (G4.3b).
//!
//! Pure Rust and sans-IO: no sockets and no clock. The caller moves the bytes
//! and passes the time; every module is tested with the RFC's own examples.
//!
//! - [`packet`]: the wire format (RFC 2865 §3/§5, RFC 6929 extended
//!   attributes), a zero-copy [`packet::Packet`] view whose iterators never
//!   allocate, and a [`packet::Builder`].
//! - [`crypto`]: authenticators (RFC 2865 §3, RFC 2866 §3, RFC 5176 §2.3),
//!   Message-Authenticator (RFC 2869 §5.14, RFC 5176 §3.4), User-Password
//!   hiding (RFC 2865 §5.2), salt encryption (RFC 2868 §3.5, RFC 2548
//!   §2.4.2) and CHAP (RFC 1994 §4.1).
//! - [`mschap`]: MS-CHAPv1/v2 (RFC 2433, RFC 2759) and the MPPE keys
//!   (RFC 3079), for the attributes of RFC 2548.
//! - [`dict`]: a typed dictionary, extendable with FreeRADIUS-format text,
//!   shipping the standard attributes, Microsoft (311), DSL Forum (3561,
//!   RFC 4679), MikroTik (14988), Juniper/ERX (4874, parse only), Ascend
//!   (529) and Redback (2352).
//! - [`rate_limit`]: `Mikrotik-Rate-Limit` (also the PPP profile `rate-limit`).
//! - [`acct`]: Accounting-Request contents (RFC 2866, RFC 2869 §5.1–§5.3) and
//!   interim scheduling with jitter.
//! - [`client`]: the NAS side — Access/Accounting/Status-Server requests,
//!   retransmission with backoff and jitter (RFC 5080 §2.2.1), failover,
//!   256 identifiers per socket and more sockets under load, Blast-RADIUS
//!   protection (Message-Authenticator required by default).
//! - [`dynauth`]: the NAS's Dynamic Authorization Server (RFC 5176 CoA and
//!   Disconnect): allow-list with per-client secret, replay window,
//!   duplicate cache, session selection; the caller applies the change
//!   atomically and answers ACK or NAK with the Error-Cause it decides.
//! - [`juniper`]: the `ERX-Service-Activate` syntax (parse only).
//! - [`testserver`]: a RADIUS server for tests and labs (users, attributes,
//!   scripted delays and drops), sans-IO like the rest.
//!
//! Input is hostile: [`packet::Packet::parse`] checks every length before
//! any field is read, and nothing here panics (`indexing_slicing` is denied
//! by the workspace).

pub mod acct;
pub mod client;
pub mod crypto;
pub mod dict;
pub mod dynauth;
pub mod fuzz;
pub mod juniper;
pub mod mschap;
pub mod packet;
pub mod rate_limit;
pub mod testserver;

pub use packet::{Attr, Builder, Code, DecodeError, EncodeError, Packet};

/// RFC 2865 §3: authentication (IANA port 1812).
pub const AUTH_PORT: u16 = 1812;
/// RFC 2866 §3: accounting (IANA port 1813).
pub const ACCT_PORT: u16 = 1813;
/// RFC 5176 §2.3: CoA and Disconnect-Request destination port.
pub const DYNAUTH_PORT: u16 = 3799;
/// MikroTik `/radius incoming port` default (not the RFC port).
pub const MIKROTIK_INCOMING_PORT: u16 = 1700;
