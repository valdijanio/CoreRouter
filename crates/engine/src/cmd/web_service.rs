//! `/ip service www-ssl` and `www` (G1.6o): the GUI in a browser and the
//! control channel over WebSocket, like RouterOS WebFig. `www-ssl` is
//! HTTPS + WSS with the router's own certificate; `www` is plain HTTP that
//! only redirects to `www-ssl` (a login never travels in clear text). The
//! daemon follows the running config, so a commit opens, moves or closes a
//! listener without a restart.

use corerouter_model::web::{WebListener, WebListenerStatus, WebService, WebStatus};
use serde_json::{Value, json};

use super::args::{opt_bool, opt_parse, opt_u32};
use super::metrics_service::available_from;
use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(
        "ip.service.www-ssl.set",
        "Web Access (HTTPS)",
        [],
        None,
        "{enabled?: bool, address?: ip, port?: int 1..65535, available_from?: [prefix]} → {enabled, address, port, available_from, warning?}",
        always,
        set_ssl
    ),
    cmd!(query "ip.service.www-ssl.get", "Web Access (HTTPS)", [], None,
        "{} → {enabled, address, port, available_from, status: stopped|listening|error, listening, last_error, refused, gui_files}",
        always, get_ssl),
    cmd!(
        "ip.service.www.set",
        "Web Access (HTTP redirect)",
        [],
        None,
        "{enabled?: bool, address?: ip, port?: int 1..65535, available_from?: [prefix]} → {enabled, address, port, available_from, warning?}",
        always,
        set_plain
    ),
    cmd!(query "ip.service.www.get", "Web Access (HTTP redirect)", [], None,
        "{} → {enabled, address, port, available_from, status: stopped|listening|error, listening, last_error, refused}",
        always, get_plain),
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Row {
    Ssl,
    Plain,
}

fn row(w: &mut WebService, r: Row) -> &mut WebListener {
    match r {
        Row::Ssl => &mut w.www_ssl,
        Row::Plain => &mut w.www,
    }
}

fn settings_json(c: &WebListener) -> Value {
    json!({
        "enabled": c.enabled,
        "address": c.address,
        "port": c.port,
        "available_from": c.available_from,
    })
}

fn set(s: &mut Session, p: &Value, r: Row) -> Result<Value> {
    let enabled = opt_bool(p, "enabled")?;
    let address = opt_parse::<std::net::IpAddr>(p, "address")?;
    let port = opt_u32(p, "port")?
        .map(|v| {
            u16::try_from(v)
                .ok()
                .filter(|v| *v != 0)
                .ok_or_else(|| EngineError::bad("port", "must be 1..=65535 (443 for HTTPS, 80 for HTTP)"))
        })
        .transpose()?;
    let from = available_from(p)?;
    let mut web = s.store().candidate().system.web.clone();
    let c = row(&mut web, r);
    if let Some(e) = enabled {
        c.enabled = e;
    }
    if let Some(a) = address {
        if a.is_multicast() {
            return Err(EngineError::bad("address", "a multicast address cannot be listened on"));
        }
        c.address = a;
    }
    if let Some(port) = port {
        c.port = port;
    }
    if let Some(list) = from {
        c.available_from = list;
    }
    let mut out = settings_json(c);
    let other = match r {
        Row::Ssl => &web.www,
        Row::Plain => &web.www_ssl,
    };
    let (ssl, plain) = (&web.www_ssl, &web.www);
    let clash = ssl.enabled
        && plain.enabled
        && ssl.port == plain.port
        && (ssl.address == plain.address
            || ssl.address.is_unspecified()
            || plain.address.is_unspecified());
    if clash {
        return Err(EngineError::bad(
            "port",
            format!("www-ssl and www cannot both listen on port {}", ssl.port),
        ));
    }
    let warning = match r {
        Row::Plain if plain.enabled && !other.enabled => {
            Some("www only redirects to www-ssl, which is disabled: browsers will find nothing there")
        }
        _ => None,
    };
    if let (Some(w), Some(o)) = (warning, out.as_object_mut()) {
        o.insert("warning".into(), json!(w));
    }
    s.store_mut().candidate_mut().system.web = web;
    Ok(out)
}

fn get(s: &mut Session, r: Row) -> Result<Value> {
    let mut cfg = s.store().candidate().system.web.clone();
    let mut out = settings_json(row(&mut cfg, r));
    let mut running = s.store().running().system.web.clone();
    let on = row(&mut running, r).enabled;
    let all = s.ext::<WebStatus>().cloned().unwrap_or_default();
    let status = match (on, r) {
        (false, _) => WebListenerStatus::default(),
        (true, Row::Ssl) => all.www_ssl,
        (true, Row::Plain) => all.www,
    };
    let status = serde_json::to_value(status).unwrap_or(Value::Null);
    if let (Some(o), Value::Object(st)) = (out.as_object_mut(), status) {
        o.extend(st);
        if r == Row::Ssl {
            o.insert("gui_files".into(), json!(all.gui_files));
        }
    }
    Ok(out)
}

fn set_ssl(s: &mut Session, p: &Value) -> Result<Value> {
    set(s, p, Row::Ssl)
}

fn set_plain(s: &mut Session, p: &Value) -> Result<Value> {
    set(s, p, Row::Plain)
}

fn get_ssl(s: &mut Session, _: &Value) -> Result<Value> {
    get(s, Row::Ssl)
}

fn get_plain(s: &mut Session, _: &Value) -> Result<Value> {
    get(s, Row::Plain)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::Session;
    use corerouter_model::web::{WebState, WebStatus};

    #[test]
    fn set_changes_only_what_is_given() {
        let mut s = Session::virtual_lab();
        let r = s
            .execute(
                "ip.service.www-ssl.set",
                &json!({"enabled": true, "port": 8443, "available_from": "192.0.2.0/24"}),
            )
            .unwrap();
        assert_eq!(r["address"], "::");
        assert_eq!(r["available_from"], json!(["192.0.2.0/24"]));
        let g = s.execute("ip.service.www-ssl.get", &json!({})).unwrap();
        assert_eq!(g["enabled"], true);
        assert_eq!(g["port"], 8443);
        assert_eq!(g["status"], "stopped", "no daemon in the lab");
        assert_eq!(g["gui_files"], false);
        let g = s.execute("ip.service.www.get", &json!({})).unwrap();
        assert_eq!((g["enabled"].as_bool(), g["port"].as_u64()), (Some(false), Some(80)));
    }

    #[test]
    fn redirect_without_https_warns_and_same_port_is_refused() {
        let mut s = Session::virtual_lab();
        let r = s.execute("ip.service.www.set", &json!({"enabled": true})).unwrap();
        assert!(r["warning"].as_str().unwrap().contains("www-ssl"));
        s.execute("ip.service.www-ssl.set", &json!({"enabled": true})).unwrap();
        let r = s.execute("ip.service.www.set", &json!({"port": 8080})).unwrap();
        assert!(r.get("warning").is_none());
        let e = s
            .execute("ip.service.www-ssl.set", &json!({"port": 8080}))
            .unwrap_err()
            .to_string();
        assert!(e.contains("both listen on port 8080"), "{e}");
        assert_eq!(s.store().running().system.web.www_ssl.port, 443);
    }

    #[test]
    fn bad_values_are_refused_and_nothing_changes() {
        let mut s = Session::virtual_lab();
        for (p, key) in [
            (json!({"port": 0}), "port"),
            (json!({"port": 70000}), "port"),
            (json!({"address": "nope"}), "address"),
            (json!({"address": "ff02::1"}), "address"),
            (json!({"available_from": ["10.0.0.0/33"]}), "available_from"),
            (json!({"available_from": vec!["10.0.0.1"; 65]}), "available_from"),
            (json!({"enabled": "yes"}), "enabled"),
        ] {
            for id in ["ip.service.www-ssl.set", "ip.service.www.set"] {
                let e = s.execute(id, &p).unwrap_err().to_string();
                assert!(e.contains(key), "{id} {p}: {e}");
            }
        }
        assert!(s.store().candidate().system.web.is_default());
    }

    #[test]
    fn rollback_restores_the_previous_service() {
        let mut s = Session::virtual_lab();
        s.execute("ip.service.www-ssl.set", &json!({"enabled": true})).unwrap();
        let rev = s.store().current_revision();
        s.execute("ip.service.www-ssl.set", &json!({"enabled": false, "port": 4443}))
            .unwrap();
        s.execute("config.rollback", &json!({"revision": rev})).unwrap();
        let w = &s.store().running().system.web.www_ssl;
        assert!(w.enabled);
        assert_eq!(w.port, 443);
    }

    #[test]
    fn status_comes_from_the_daemon_only_while_enabled() {
        let mut s = Session::virtual_lab();
        if let Some(st) = s.ext_mut::<WebStatus>() {
            st.www_ssl.status = WebState::Listening;
            st.www_ssl.listening = Some("[::]:443".into());
            st.gui_files = true;
        }
        let g = s.execute("ip.service.www-ssl.get", &json!({})).unwrap();
        assert_eq!(g["status"], "stopped", "disabled in the running config");
        assert_eq!(g["gui_files"], true);
        s.execute("ip.service.www-ssl.set", &json!({"enabled": true})).unwrap();
        let g = s.execute("ip.service.www-ssl.get", &json!({})).unwrap();
        assert_eq!(g["status"], "listening");
        assert_eq!(g["listening"], "[::]:443");
    }
}
