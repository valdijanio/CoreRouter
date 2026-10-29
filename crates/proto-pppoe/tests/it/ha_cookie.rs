//! G4.3h: the two BNGs of a redundant pair accept each other's AC-Cookie
//! (a PADR in flight at a switchover still lands on the new active), and
//! only with the pair's key: a server of its own still refuses it.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use corerouter_proto_pppoe::discovery::{self, Code, DiscoveryWriter, tag};
use corerouter_proto_pppoe::eth::Vlans;
use corerouter_proto_pppoe::server::{Server, ServerConfig, ServerOutput};
use corerouter_proto_pppoe::wire::Mac;

const VMAC: Mac = Mac([0x02, 0x43, 0x52, 0x48, 0x41, 0x01]);
const HOST: Mac = Mac([0x02, 0x11, 0, 0, 0, 1]);

fn server(key: Option<[u8; 32]>, seed: u8) -> Server {
    let c = ServerConfig {
        ac_mac: VMAC,
        cookie_secret: key,
        ..ServerConfig::default()
    };
    Server::new(c, [seed; 32], 0)
}

/// PADI on port `ifindex` of `s`; the PADR its PADO asks for.
fn padr_via(s: &mut Server, ifindex: u32) -> Vec<u8> {
    let mut b = Vec::new();
    let mut w = DiscoveryWriter::begin(&mut b, Mac::BROADCAST, HOST, Vlans::NONE, Code::Padi, 0);
    w.tag(tag::SERVICE_NAME, b"");
    w.tag(tag::HOST_UNIQ, b"hu");
    w.finish().unwrap();
    let mut out = ServerOutput::new();
    s.handle_frame(0, ifindex, &b, &mut out);
    let (_, f) = out.frames().next().expect("PADO");
    let pado = discovery::parse(f).unwrap();
    assert_eq!(pado.code, Code::Pado);
    let mut r = Vec::new();
    let mut w = DiscoveryWriter::begin(&mut r, VMAC, HOST, Vlans::NONE, Code::Padr, 0);
    w.tag(tag::SERVICE_NAME, b"");
    w.tag(tag::HOST_UNIQ, b"hu");
    w.tag(tag::AC_COOKIE, pado.tags.ac_cookie.unwrap());
    w.finish().unwrap();
    r
}

fn pads(s: &mut Server, ifindex: u32, padr: &[u8]) -> bool {
    let mut out = ServerOutput::new();
    s.handle_frame(100, ifindex, padr, &mut out);
    out.frames()
        .filter_map(|(_, f)| discovery::parse(f).ok())
        .any(|d| d.code == Code::Pads && d.session_id != 0)
}

#[test]
fn the_pair_accepts_each_others_cookie_on_another_port() {
    let key = Some([7; 32]);
    let mut a = server(key, 1);
    let mut b = server(key, 2);
    let padr = padr_via(&mut a, 4);
    assert!(pads(&mut b, 9, &padr), "the other node, its own port index");
    assert_eq!(b.active(), 1);
    // A server of its own (another key, or none) does not.
    let mut c = server(Some([8; 32]), 3);
    assert!(!pads(&mut c, 4, &padr));
    let mut d = server(None, 1);
    assert!(!pads(&mut d, 4, &padr));
    // Without a pair, the port stays bound.
    let mut e = server(None, 5);
    let own = padr_via(&mut e, 4);
    assert!(!pads(&mut e, 5, &own), "another port of the same server");
    assert!(pads(&mut e, 4, &own));
}
