// SPDX-License-Identifier: GPL-2.0-or-later
//! What the XDP programs (`crates/dataplane-ebpf`, built for
//! `bpfel-unknown-none`) and their loader (`hal-linux`, userspace) share.
//!
//! - [`packet`]: read-only access to a frame. The eBPF program implements
//!   [`packet::Packet`] over `data..data_end` (bounds-checked loads the
//!   verifier accepts); the host implements it over `&[u8]`.
//! - [`parse`]: Ethernet (up to two VLAN tags), IPv4, IPv6, TCP/UDP/ICMP
//!   headers, and what is malformed about them.
//! - [`filter`]: the decision of the G2.5a filter (allow list, block lists,
//!   per-source rate limit, malformed and invalid TCP flags) over a
//!   [`filter::Lookups`] the program backs with maps and the tests with
//!   plain collections.
//! - [`bucket`]: the per-source token bucket.
//! - [`fastnat`]: the CGNAT fast path (G2.5b): flows conntrack already
//!   NATed, translated and forwarded in XDP.
//! - [`nat`]: the CGNAT fast path's rewrite, with checksums updated
//!   incrementally (RFC 1624).
//! - [`pppoe`]: the PPPoE subscriber data plane (G4.3c): session map,
//!   upstream check and decapsulation, downstream encapsulation.
//! - [`policer`]: the per-subscriber policer, RouterOS burst semantics.
//! - [`maps`]: map names, sizes and value layouts (plain integers and
//!   arrays, so the loader needs no `unsafe impl Pod`).
//!
//! The same functions run in the kernel and in the tests: generic over
//! [`packet::Packet`] and [`filter::Lookups`], monomorphized in the
//! program. They never panic (no indexing, no unchecked division): a panic
//! path would not even link for BPF.

#![no_std]
#![forbid(unsafe_code)]

pub mod bucket;
pub mod fastnat;
pub mod filter;
pub mod maps;
pub mod nat;
pub mod packet;
pub mod parse;
pub mod policer;
pub mod pppoe;
#[cfg(feature = "testing")]
pub mod testing;
