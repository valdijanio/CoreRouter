//! G3.4zb: a TCP listener inside a VRF (RouterOS `/ip service … vrf=`,
//! Junos `mgmt_junos`, IOS-XE `Mgmt-intf`). Not a service: the helper the
//! management listeners (`web`, `metrics`) and the TLS control port
//! (`--listen-vrf`) bind with.
//!
//! The socket is bound to the VRF's device (`SO_BINDTODEVICE`) before
//! `bind()`, as the kernel's `Documentation/networking/vrf.rst` asks of a
//! server in a VRF: it takes only the connections that arrive on the
//! VRF's ports, and its replies follow the VRF's table (the `l3mdev` rule),
//! never the main table OSPF and BGP feed. Several sockets may listen on the
//! same port, each in its own VRF. `main` is the unbound socket of before.
//! An address that belongs to the VRF is accepted by `bind()` only once the
//! device is set (its local route is in the VRF's table).

use std::io;
use std::net::{SocketAddr, TcpListener};
use std::time::Duration;

use corerouter_control::Shutdown;
use corerouter_model::RoutingTable;

/// Connections waiting to be accepted (`listen(2)` backlog; std's default).
const BACKLOG: i32 = 128;
/// How often a listener whose VRF is not in the kernel yet tries again.
const RETRY: Duration = Duration::from_secs(2);

/// The command-line listeners (`--listen`, `--ws-listen` with
/// `--listen-vrf`): `then` gets the socket. In main a failure is the
/// caller's (the daemon stops at boot, as before). In a VRF the daemon
/// must not stop: the VRF is the config's (`ip.vrf.add`), so on a first
/// boot it does not exist yet, and a router whose control port died with
/// it would be lost. Then it says so and tries every [`RETRY`] in a thread
/// of its own until the VRF appears (or the daemon stops); the loopback
/// control port and the console stay the way back meanwhile.
pub(crate) fn bind_or_wait(
    addr: SocketAddr,
    vrf: &RoutingTable,
    what: &'static str,
    shutdown: Shutdown,
    then: impl FnOnce(TcpListener) -> Result<(), String> + Send + 'static,
) -> Result<(), String> {
    let first = match bind(addr, vrf) {
        Ok(l) => return then(l),
        Err(e) if vrf.is_main() => return Err(format!("cannot open {what} {addr}: {e}")),
        Err(e) => e,
    };
    log::error!("{what} {addr} in VRF {vrf}: {first}; trying again every {} s", RETRY.as_secs());
    let vrf = vrf.clone();
    std::thread::Builder::new()
        .name("listen-vrf-wait".into())
        .spawn(move || {
            while !shutdown.is_closed() {
                std::thread::sleep(RETRY);
                if let Ok(l) = bind(addr, &vrf) {
                    match then(l) {
                        Ok(()) => log::info!("{what} {addr} in VRF {vrf}: listening now"),
                        Err(e) => log::error!("{what} {addr} in VRF {vrf}: {e}"),
                    }
                    return;
                }
            }
        })
        .map(|_| ())
        .map_err(|e| format!("cannot start the {what} retry thread: {e}"))
}

/// A listener on `addr`, in `vrf`.
pub(crate) fn bind(addr: SocketAddr, vrf: &RoutingTable) -> io::Result<TcpListener> {
    match vrf {
        RoutingTable::Main => TcpListener::bind(addr),
        RoutingTable::Vrf(name) => bind_in(addr, name.as_str()),
    }
}

#[cfg(target_os = "linux")]
fn bind_in(addr: SocketAddr, device: &str) -> io::Result<TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};
    let s = Socket::new(Domain::for_address(addr), Type::STREAM.cloexec(), Some(Protocol::TCP))?;
    // As std's TcpListener::bind: a restarted listener takes its port back
    // while old connections linger in TIME_WAIT.
    s.set_reuse_address(true)?;
    s.bind_device(Some(device.as_bytes())).map_err(|e| {
        io::Error::new(e.kind(), format!("cannot bind to VRF {device}: {e} (does the VRF exist in the kernel?)"))
    })?;
    s.bind(&addr.into())?;
    s.listen(BACKLOG)?;
    Ok(s.into())
}

#[cfg(not(target_os = "linux"))]
fn bind_in(_addr: SocketAddr, device: &str) -> io::Result<TcpListener> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        format!("VRF {device}: listening in a VRF needs Linux (SO_BINDTODEVICE on an l3mdev)"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn main_is_the_plain_listener_and_a_missing_vrf_says_so() {
        let l = bind("127.0.0.1:0".parse().unwrap(), &RoutingTable::Main).unwrap();
        assert!(l.local_addr().unwrap().port() > 0);
        let e = bind("127.0.0.1:0".parse().unwrap(), &"nosuchvrf9".parse().unwrap()).unwrap_err();
        assert!(e.to_string().contains("nosuchvrf9"), "{e}");
    }
}
