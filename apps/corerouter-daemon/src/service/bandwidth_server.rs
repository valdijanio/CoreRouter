//! `/tool bandwidth-server` (G6.4b): the router answers iperf3 tests on
//! `tool.bandwidth-server.set` port (5201), under the supervisor. At
//! start it also hands the session the iperf3 client that
//! `tool.bandwidth-test.start` uses (`iperf::IperfClient`).
//!
//! Off until `enabled=yes` with an allow list. One test at a time (others
//! get iperf3's "server busy"); clients outside `allowed_addresses` are
//! denied before reading anything. Every second the loop re-reads the
//! config: a change of port rebinds, `enabled=no` closes the port. Each
//! test, refused client and failure goes to the status
//! (`tool.bandwidth-server.get`) and the log (topic `tool`).

use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use corerouter_engine::bandwidth::ServerStatus;
use corerouter_engine::{Shared, lock};
use corerouter_model::bandwidth::BandwidthServer;
use corerouter_model::service::Listen;
use corerouter_proto_iperf::Limits;
use serde_json::json;

use super::iperf::{self, IperfClient, Served};

const TICK: Duration = Duration::from_millis(200);

pub(crate) const SERVICE: super::Service = super::Service {
    name: "bandwidth-server",
    flags: &[],
    topic: "tool",
    enable: "tool.bandwidth-server.set enabled=yes allowed_addresses=…",
    depends: &[],
    start,
};

fn start(ctx: &super::Ctx) -> Result<super::Run, String> {
    let session = ctx.session.clone();
    lock(&session).set_bandwidth_backend(Arc::new(IperfClient {
        session: session.clone(),
    }));
    Ok(Box::new(move |health: &super::Health| {
        run(&session, health);
        Ok(())
    }))
}

fn limits(c: &BandwidthServer) -> Limits {
    Limits {
        max_duration: c.max_duration,
        max_streams: c.max_streams,
        max_rate: (c.max_rate > 0).then_some(c.max_rate),
    }
}

/// Listen on `port`, both families when the host allows it.
fn bind(port: u16) -> Result<TcpListener, String> {
    let l = TcpListener::bind(SocketAddr::from(([0u16; 8], port)))
        .or_else(|_| TcpListener::bind(SocketAddr::from(([0u8; 4], port))))
        .map_err(|e| format!("cannot listen on TCP {port}: {e}"))?;
    l.set_nonblocking(true)
        .map_err(|e| format!("cannot listen on TCP {port}: {e}"))?;
    Ok(l)
}

fn log(session: &Shared, level: &str, message: String, data: serde_json::Value) {
    lock(session).log_event(
        &["tool", level],
        corerouter_engine::logging::DAEMON,
        message,
        data,
    );
}

fn served_json(s: &Served) -> serde_json::Value {
    json!({
        "client": s.client,
        "protocol": s.proto,
        "direction": s.direction,
        "streams": s.streams,
        "secs": (s.secs * 10.0).round() / 10.0,
        "bytes": s.bytes,
    })
}

fn run(session: &Shared, health: &super::Health) {
    let mut status = ServerStatus {
        state: "stopped".into(),
        ..ServerStatus::default()
    };
    let mut bound: Option<(BandwidthServer, TcpListener)> = None;
    loop {
        health.beat();
        let cfg = lock(session).store().running().system.bandwidth_server.clone();
        let rebind = match &bound {
            Some((c, _)) => c.port != cfg.port || !cfg.enabled,
            None => cfg.enabled,
        };
        if rebind {
            bound = None;
            status.listening = None;
            status.state = "stopped".into();
            if cfg.enabled {
                match bind(cfg.port) {
                    Ok(l) => {
                        status.state = "listening".into();
                        status.listening = Some(format!("tcp/udp {}", cfg.port));
                        status.last_error = None;
                        health.clear_error();
                        health.event(format!("listening on {}", cfg.port));
                        bound = Some((cfg.clone(), l));
                    }
                    Err(e) => {
                        status.state = "failed".into();
                        status.last_error = Some(e.clone());
                        health.error(&e);
                    }
                }
            }
            lock(session).set_bandwidth_server_status(status.clone());
        }
        if let Some((c, _)) = &mut bound {
            *c = cfg.clone();
        }
        health.listen(if bound.is_some() {
            let at = SocketAddr::from(([0u16; 8], cfg.port));
            vec![Listen::new("tcp", at), Listen::new("udp", at)]
        } else {
            Vec::new()
        });
        health.disabled((!cfg.enabled).then_some("tool.bandwidth-server.set enabled=no"));
        if let Some((c, l)) = &bound {
            accept_one(session, health, c, l, &mut status);
        }
        if !health.sleep(TICK) {
            return;
        }
    }
}

fn accept_one(
    session: &Shared,
    health: &super::Health,
    cfg: &BandwidthServer,
    listener: &TcpListener,
    status: &mut ServerStatus,
) {
    let Ok((conn, peer)) = listener.accept() else {
        return;
    };
    let ip = peer.ip().to_canonical();
    if !cfg.allows(ip) {
        iperf::deny(conn);
        status.refused += 1;
        lock(session).set_bandwidth_server_status(status.clone());
        log(
            session,
            "warning",
            format!("Bandwidth server: teste de {ip} recusado (fora de allowed_addresses)"),
            json!({"client": ip.to_string()}),
        );
        return;
    }
    status.state = "testing".into();
    let alive = || {
        health.beat();
        !health.stopping()
    };
    let mut busy = |other: TcpStream| {
        iperf::deny(other);
    };
    let mut started = |s: &Served| {
        let mut st = status.clone();
        st.current = Some(served_json(s));
        lock(session).set_bandwidth_server_status(st);
    };
    let result = iperf::serve(listener, conn, &limits(cfg), &alive, &mut busy, &mut started);
    status.state = "listening".into();
    status.current = None;
    match result {
        Ok(s) => {
            status.tests_served += 1;
            status.last = Some(served_json(&s));
            log(
                session,
                "info",
                format!(
                    "Bandwidth server: teste {} {} de {} terminou ({} streams, {:.1} s, {} bytes)",
                    s.proto, s.direction, s.client, s.streams, s.secs, s.bytes
                ),
                served_json(&s),
            );
        }
        Err(e) => {
            status.last_error = Some(e.clone());
            log(
                session,
                "warning",
                format!("Bandwidth server: teste de {ip} falhou: {e}"),
                json!({"client": ip.to_string(), "error": e}),
            );
        }
    }
    lock(session).set_bandwidth_server_status(status.clone());
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_engine::bandwidth::{BandwidthBackend, TestRequest};
    use corerouter_engine::{Session, shared};
    use corerouter_proto_iperf::{Direction, Params, Proto};
    use std::thread;
    use std::time::Instant;

    fn free_port() -> u16 {
        TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
    }

    #[test]
    fn enabled_by_config_serves_and_refuses_outsiders() {
        let session = shared(Session::virtual_lab());
        let port = free_port();
        lock(&session)
            .execute(
                "tool.bandwidth-server.set",
                &json!({"enabled": true, "port": port, "allowed_addresses": ["10.0.0.0/8"]}),
            )
            .unwrap();
        let health = super::super::Health::new(corerouter_control::Shutdown::default());
        let h2 = health.clone();
        let s2 = session.clone();
        thread::spawn(move || run(&s2, &h2));
        let client = IperfClient { session: session.clone() };
        let req = TestRequest {
            host: "127.0.0.1".into(),
            addr: Some("127.0.0.1".parse().unwrap()),
            port,
            params: Params { proto: Proto::Tcp, direction: Direction::Send, time: 1, bandwidth: 50_000_000, ..Params::default() },
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        // Not allowed yet (127.0.0.1 is outside 10/8): denied as busy.
        let e = loop {
            match client.run(&req, &|d| { thread::sleep(d); true }, &mut |_| {}) {
                Err(e) if e.contains("busy") => break e,
                other => {
                    assert!(Instant::now() < deadline, "{other:?}");
                    thread::sleep(Duration::from_millis(100));
                }
            }
        };
        assert!(e.contains("busy"));
        assert_eq!(lock(&session).execute("tool.bandwidth-server.get", &json!({})).unwrap()["status"]["refused"], 1);
        lock(&session)
            .execute("tool.bandwidth-server.set", &json!({"allowed_addresses": ["127.0.0.0/8"]}))
            .unwrap();
        thread::sleep(Duration::from_millis(400));
        let o = client.run(&req, &|d| { thread::sleep(d); true }, &mut |_| {}).unwrap();
        assert!(o.upload.unwrap().received > 0);
        let deadline = Instant::now() + Duration::from_secs(5);
        let g = loop {
            let g = lock(&session).execute("tool.bandwidth-server.get", &json!({})).unwrap();
            if g["status"]["tests_served"] == 1 || Instant::now() > deadline {
                break g;
            }
            thread::sleep(Duration::from_millis(50));
        };
        assert_eq!(g["status"]["tests_served"], 1, "{g}");
        assert_eq!(g["status"]["last"]["client"], "127.0.0.1");
        // Off closes the port.
        lock(&session).execute("tool.bandwidth-server.set", &json!({"enabled": false})).unwrap();
        thread::sleep(Duration::from_millis(500));
        assert!(TcpStream::connect(("127.0.0.1", port)).is_err());
        health.stop();
    }
}
