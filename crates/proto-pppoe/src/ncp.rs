//! NCP options: IPCP (RFC 1332 §3, DNS/NBNS from RFC 1877 §1) and IPv6CP
//! (RFC 5072 §4). The NCPs use LCP's packet format with codes 1–7 only
//! (RFC 1332 §2, RFC 5072 §3).

use crate::ppp::{Opt, put_opt};
use crate::wire::WireError;
use std::net::Ipv4Addr;

/// IPCP option types.
pub mod ipcp {
    /// RFC 1332 §3.1 (deprecated; always rejected).
    pub const IP_ADDRESSES: u8 = 1;
    /// RFC 1332 §3.2 (Van Jacobson; rejected: the XDP data plane does not
    /// decompress).
    pub const IP_COMPRESSION: u8 = 2;
    /// RFC 1332 §3.3.
    pub const IP_ADDRESS: u8 = 3;
    /// RFC 1877 §1.1.
    pub const PRIMARY_DNS: u8 = 129;
    /// RFC 1877 §1.2.
    pub const PRIMARY_NBNS: u8 = 130;
    /// RFC 1877 §1.3.
    pub const SECONDARY_DNS: u8 = 131;
    /// RFC 1877 §1.4.
    pub const SECONDARY_NBNS: u8 = 132;
}

/// IPv6CP option types (RFC 5072 §4).
pub mod ipv6cp {
    pub const INTERFACE_IDENTIFIER: u8 = 1;
    /// RFC 5072 §4.2 (rejected).
    pub const IPV6_COMPRESSION: u8 = 2;
}

/// Highest code the NCPs use (Code-Reject); 8–11 are LCP-only.
pub const NCP_MAX_CODE: u8 = 7;

/// A typed IPCP option.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpcpOpt<'a> {
    IpAddress(Ipv4Addr),
    PrimaryDns(Ipv4Addr),
    SecondaryDns(Ipv4Addr),
    PrimaryNbns(Ipv4Addr),
    SecondaryNbns(Ipv4Addr),
    Compression(&'a [u8]),
    IpAddresses(&'a [u8]),
    Unknown(Opt<'a>),
}

fn addr(o: &Opt<'_>) -> Result<Ipv4Addr, WireError> {
    let b: [u8; 4] = o.data.try_into().map_err(|_| WireError::BadOption {
        kind: o.kind,
        len: o.data.len() + 2,
    })?;
    Ok(Ipv4Addr::from(b))
}

impl<'a> IpcpOpt<'a> {
    pub fn parse(o: Opt<'a>) -> Result<IpcpOpt<'a>, WireError> {
        Ok(match o.kind {
            ipcp::IP_ADDRESS => IpcpOpt::IpAddress(addr(&o)?),
            ipcp::PRIMARY_DNS => IpcpOpt::PrimaryDns(addr(&o)?),
            ipcp::SECONDARY_DNS => IpcpOpt::SecondaryDns(addr(&o)?),
            ipcp::PRIMARY_NBNS => IpcpOpt::PrimaryNbns(addr(&o)?),
            ipcp::SECONDARY_NBNS => IpcpOpt::SecondaryNbns(addr(&o)?),
            ipcp::IP_COMPRESSION => IpcpOpt::Compression(o.data),
            ipcp::IP_ADDRESSES => IpcpOpt::IpAddresses(o.data),
            _ => IpcpOpt::Unknown(o),
        })
    }

    pub fn put(&self, out: &mut Vec<u8>) -> Result<(), WireError> {
        match *self {
            IpcpOpt::IpAddress(a) => put_opt(out, ipcp::IP_ADDRESS, &a.octets()),
            IpcpOpt::PrimaryDns(a) => put_opt(out, ipcp::PRIMARY_DNS, &a.octets()),
            IpcpOpt::SecondaryDns(a) => put_opt(out, ipcp::SECONDARY_DNS, &a.octets()),
            IpcpOpt::PrimaryNbns(a) => put_opt(out, ipcp::PRIMARY_NBNS, &a.octets()),
            IpcpOpt::SecondaryNbns(a) => put_opt(out, ipcp::SECONDARY_NBNS, &a.octets()),
            IpcpOpt::Compression(d) => put_opt(out, ipcp::IP_COMPRESSION, d),
            IpcpOpt::IpAddresses(d) => put_opt(out, ipcp::IP_ADDRESSES, d),
            IpcpOpt::Unknown(o) => put_opt(out, o.kind, o.data),
        }
    }
}

/// A typed IPv6CP option.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ipv6cpOpt<'a> {
    /// RFC 5072 §4.1: 64-bit interface identifier.
    InterfaceId([u8; 8]),
    Compression(&'a [u8]),
    Unknown(Opt<'a>),
}

impl<'a> Ipv6cpOpt<'a> {
    pub fn parse(o: Opt<'a>) -> Result<Ipv6cpOpt<'a>, WireError> {
        Ok(match o.kind {
            ipv6cp::INTERFACE_IDENTIFIER => {
                Ipv6cpOpt::InterfaceId(o.data.try_into().map_err(|_| WireError::BadOption {
                    kind: o.kind,
                    len: o.data.len() + 2,
                })?)
            }
            ipv6cp::IPV6_COMPRESSION => Ipv6cpOpt::Compression(o.data),
            _ => Ipv6cpOpt::Unknown(o),
        })
    }

    pub fn put(&self, out: &mut Vec<u8>) -> Result<(), WireError> {
        match *self {
            Ipv6cpOpt::InterfaceId(i) => put_opt(out, ipv6cp::INTERFACE_IDENTIFIER, &i),
            Ipv6cpOpt::Compression(d) => put_opt(out, ipv6cp::IPV6_COMPRESSION, d),
            Ipv6cpOpt::Unknown(o) => put_opt(out, o.kind, o.data),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ppp::options;

    #[test]
    fn rfc1332_rfc1877_round_trip() {
        let a = Ipv4Addr::new(100, 64, 0, 9);
        for o in [
            IpcpOpt::IpAddress(a),
            IpcpOpt::PrimaryDns(a),
            IpcpOpt::SecondaryDns(a),
            IpcpOpt::PrimaryNbns(a),
            IpcpOpt::SecondaryNbns(a),
            IpcpOpt::Compression(&[0, 0x2d, 15, 1]),
            IpcpOpt::IpAddresses(&[1, 2, 3, 4, 5, 6, 7, 8]),
        ] {
            let mut b = Vec::new();
            o.put(&mut b).unwrap();
            assert_eq!(
                IpcpOpt::parse(options(&b).next().unwrap().unwrap()).unwrap(),
                o
            );
        }
    }

    #[test]
    fn rfc1332_3_3_address_is_four_octets() {
        assert!(
            IpcpOpt::parse(Opt {
                kind: ipcp::IP_ADDRESS,
                data: &[1, 2, 3]
            })
            .is_err()
        );
    }

    #[test]
    fn rfc5072_4_1_interface_id_is_eight_octets() {
        let o = Ipv6cpOpt::InterfaceId([1, 2, 3, 4, 5, 6, 7, 8]);
        let mut b = Vec::new();
        o.put(&mut b).unwrap();
        assert_eq!(b.len(), 10);
        assert_eq!(
            Ipv6cpOpt::parse(options(&b).next().unwrap().unwrap()).unwrap(),
            o
        );
        assert!(
            Ipv6cpOpt::parse(Opt {
                kind: 1,
                data: &[0; 7]
            })
            .is_err()
        );
    }
}
