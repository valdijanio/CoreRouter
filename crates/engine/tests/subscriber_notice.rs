//! G4.10: subscriber notices — profiles, walled garden, pages, the "Block
//! (com página)" actions, who is under a profile, seen / timeout, the view
//! log, the webhook events and "test as client".
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use corerouter_engine::{EngineError, Session};
use serde_json::{Value, json};

fn ok(s: &mut Session, id: &str, p: Value) -> Value {
    s.execute(id, &p)
        .unwrap_or_else(|e| panic!("{id} {p}: {e}"))
}

fn fails(s: &mut Session, id: &str, p: Value, needle: &str) {
    match s.execute(id, &p) {
        Ok(v) => panic!("{id} {p} should fail, gave {v}"),
        Err(e) => assert!(
            e.to_string().contains(needle),
            "{id}: '{e}' lacks '{needle}'"
        ),
    }
}

fn lab() -> Session {
    let mut s = Session::virtual_lab();
    s.tick(1_800_000_000);
    ok(
        &mut s,
        "ip.address.add",
        json!({"address": "100.64.0.1/16", "interface": "ether2"}),
    );
    s
}

#[test]
fn profiles_add_set_remove_and_validation() {
    let mut s = lab();
    let id = ok(
        &mut s,
        "ip.subscriber-notice.profile.add",
        json!({"name": "atraso", "mode": "block", "address_list": "bloqueados"}),
    )["id"]
        .clone();
    let rows = ok(&mut s, "ip.subscriber-notice.profile.print", json!({}));
    assert_eq!(rows[0]["mode"], "block");
    assert_eq!(
        rows[0]["intercept"], "http",
        "a block catches every HTTP request"
    );
    assert_eq!(rows[0]["interval"], "1d");
    assert!(rows[0]["behaviour"].as_str().unwrap().contains("refused"));
    ok(
        &mut s,
        "ip.subscriber-notice.profile.add",
        json!({"name": "aviso", "mode": "notice", "address_list": "aviso", "interval": "6h"}),
    );
    let rows = ok(&mut s, "ip.subscriber-notice.profile.print", json!({}));
    assert_eq!(
        rows[1]["intercept"], "probes",
        "a notice keeps the internet"
    );
    assert_eq!(rows[1]["behaviour"], "page every 6h");

    fails(
        &mut s,
        "ip.subscriber-notice.profile.add",
        json!({"name": "x", "address_list": "l"}),
        "mode",
    );
    fails(
        &mut s,
        "ip.subscriber-notice.profile.add",
        json!({"name": "x", "mode": "drop", "address_list": "l"}),
        "block, notice or throttle",
    );
    fails(
        &mut s,
        "ip.subscriber-notice.profile.add",
        json!({"name": "x", "mode": "block", "address_list": "sn-x"}),
        "router's",
    );
    fails(
        &mut s,
        "ip.subscriber-notice.profile.add",
        json!({"name": "x", "mode": "block", "address_list": "bloqueados"}),
        "same address list",
    );
    fails(
        &mut s,
        "ip.subscriber-notice.profile.add",
        json!({"name": "atraso", "mode": "block", "address_list": "z"}),
        "exists",
    );
    fails(
        &mut s,
        "ip.subscriber-notice.profile.add",
        json!({"name": "x", "mode": "throttle", "address_list": "z"}),
        "rate_limit",
    );
    fails(
        &mut s,
        "ip.subscriber-notice.profile.add",
        json!({"name": "x", "mode": "throttle", "address_list": "z", "rate_limit": "fast"}),
        "rate_limit",
    );
    fails(
        &mut s,
        "ip.subscriber-notice.profile.add",
        json!({"name": "x", "mode": "block", "address_list": "z", "page": "nope"}),
        "no page",
    );
    fails(
        &mut s,
        "ip.subscriber-notice.profile.add",
        json!({"name": "x", "mode": "block", "address_list": "z", "colour": 1}),
        "colour",
    );
    ok(
        &mut s,
        "ip.subscriber-notice.profile.add",
        json!({"name": "lento", "mode": "throttle", "address_list": "lento", "rate_limit": "1M/1M"}),
    );

    ok(
        &mut s,
        "ip.subscriber-notice.profile.set",
        json!({"id": id, "mode": "notice"}),
    );
    let rows = ok(&mut s, "ip.subscriber-notice.profile.print", json!({}));
    assert_eq!(rows[0]["mode"], "notice");
    assert_eq!(rows[0]["intercept"], "http", "set keeps the intercept");
    fails(
        &mut s,
        "ip.subscriber-notice.profile.set",
        json!({"id": "aviso", "address_list": "bloqueados"}),
        "same address list",
    );
    fails(
        &mut s,
        "ip.subscriber-notice.profile.set",
        json!({"id": "*99"}),
        "no profile",
    );

    // Rollback brings the removed profile back, with its id.
    let rev = s.store().current_revision();
    ok(
        &mut s,
        "ip.subscriber-notice.profile.remove",
        json!({"id": "atraso"}),
    );
    assert_eq!(
        ok(&mut s, "ip.subscriber-notice.profile.print", json!({}))
            .as_array()
            .unwrap()
            .len(),
        2
    );
    ok(&mut s, "config.rollback", json!({"revision": rev}));
    let rows = ok(&mut s, "ip.subscriber-notice.profile.print", json!({}));
    assert_eq!(rows[0]["id"], id);
}

#[test]
fn walled_garden_and_pages() {
    let mut s = lab();
    let g = ok(
        &mut s,
        "ip.subscriber-notice.walled-garden.add",
        json!({"dst_host": "PIX.Banco.com.br.", "comment": "pix"}),
    )["id"]
        .clone();
    ok(
        &mut s,
        "ip.subscriber-notice.walled-garden.add",
        json!({"dst_address": "203.0.113.7"}),
    );
    let rows = ok(
        &mut s,
        "ip.subscriber-notice.walled-garden.print",
        json!({}),
    );
    assert_eq!(rows[0]["dst_host"], "pix.banco.com.br");
    assert_eq!(rows[1]["dst_address"], "203.0.113.7/32");
    fails(
        &mut s,
        "ip.subscriber-notice.walled-garden.add",
        json!({"dst_host": "pix.banco.com.br"}),
        "already",
    );
    fails(
        &mut s,
        "ip.subscriber-notice.walled-garden.add",
        json!({}),
        "needs dst_host",
    );
    fails(
        &mut s,
        "ip.subscriber-notice.walled-garden.add",
        json!({"dst_host": "a b"}),
        "domain",
    );
    fails(
        &mut s,
        "ip.subscriber-notice.walled-garden.add",
        json!({"dst_host": "x.com", "dst_address": "1.2.3.4"}),
        "not both",
    );
    ok(
        &mut s,
        "ip.subscriber-notice.walled-garden.set",
        json!({"id": g, "disabled": true}),
    );
    ok(
        &mut s,
        "ip.subscriber-notice.walled-garden.remove",
        json!({"id": g}),
    );

    // The built-in page is listed and previews with sample values.
    assert_eq!(
        ok(&mut s, "ip.subscriber-notice.page.print", json!({})),
        json!([]),
        "the built-in page is not a row"
    );
    let pv = ok(&mut s, "ip.subscriber-notice.page.preview", json!({}));
    assert!(pv["html"].as_str().unwrap().contains("R$ 99,90"));
    ok(
        &mut s,
        "ip.subscriber-notice.page.add",
        json!({"name": "provedor", "title": "Provedor X", "text": "Olá {login}", "color": "#ff6600"}),
    );
    fails(
        &mut s,
        "ip.subscriber-notice.page.add",
        json!({"name": "p2", "text": "{senha}"}),
        "unknown variable",
    );
    fails(
        &mut s,
        "ip.subscriber-notice.page.add",
        json!({"name": "p2", "color": "red"}),
        "color",
    );
    fails(
        &mut s,
        "ip.subscriber-notice.page.add",
        json!({"name": "default"}),
        "exists",
    );
    // An unsaved edit previews, and says what is wrong with it.
    let pv = ok(
        &mut s,
        "ip.subscriber-notice.page.preview",
        json!({"page": "provedor", "text": "Oi {plano} {xx}"}),
    );
    assert!(pv["html"].as_str().unwrap().contains("Fibra 300M"));
    assert!(pv["problem"].as_str().unwrap().contains("{xx}"));
    ok(
        &mut s,
        "ip.subscriber-notice.profile.add",
        json!({"name": "atraso", "mode": "block", "address_list": "bloqueados", "page": "provedor"}),
    );
    fails(
        &mut s,
        "ip.subscriber-notice.page.remove",
        json!({"id": "provedor"}),
        "shows page",
    );
    // Renaming the page follows in the profile.
    ok(
        &mut s,
        "ip.subscriber-notice.page.set",
        json!({"id": "provedor", "name": "provedor2"}),
    );
    assert_eq!(
        ok(&mut s, "ip.subscriber-notice.profile.print", json!({}))[0]["page"],
        "provedor2"
    );

    ok(
        &mut s,
        "ip.subscriber-notice.settings.set",
        json!({"port": 8081, "webhook_url": "https://erp.example/hook"}),
    );
    fails(
        &mut s,
        "ip.subscriber-notice.settings.set",
        json!({"capport_url": "http://portal.example/api"}),
        "https only",
    );
    fails(
        &mut s,
        "ip.subscriber-notice.settings.set",
        json!({"capport_url": "https://100.64.0.1/api"}),
        "not an address",
    );
    fails(
        &mut s,
        "ip.subscriber-notice.settings.set",
        json!({"port": 0}),
        "1..65535",
    );
    ok(
        &mut s,
        "ip.subscriber-notice.settings.set",
        json!({"capport_url": "https://aviso.provedor.com.br/api"}),
    );
    let st = ok(&mut s, "ip.subscriber-notice.settings.get", json!({}));
    assert_eq!(st["port"], 8081);
    assert!(st["probes"].as_u64().unwrap() >= 18);
}

#[test]
fn members_seen_log_and_events() {
    let mut s = lab();
    ok(
        &mut s,
        "ip.subscriber-notice.profile.add",
        json!({"name": "atraso", "mode": "block", "address_list": "bloqueados"}),
    );
    ok(
        &mut s,
        "ip.subscriber-notice.profile.add",
        json!({"name": "aviso", "mode": "notice", "address_list": "aviso", "interval": "1h", "timeout": "10m"}),
    );
    ok(
        &mut s,
        "ip.firewall.address-list.add",
        json!({"list": "bloqueados", "address": "100.64.0.10", "comment": "cliente 10"}),
    );
    ok(
        &mut s,
        "ip.firewall.address-list.add",
        json!({"list": "aviso", "address": "100.64.0.20"}),
    );
    ok(
        &mut s,
        "ip.firewall.address-list.add",
        json!({"list": "aviso", "address": "100.64.0.21", "timeout": 3600}),
    );
    s.notice_tick();
    let act = ok(&mut s, "ip.subscriber-notice.active.list", json!({}));
    assert_eq!(act["total"], 3);
    let r10 = act["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["address"] == "100.64.0.10")
        .unwrap();
    assert_eq!(r10["source"], "static");
    assert_eq!(r10["seen"], false);
    assert_eq!(r10["since_secs_ago"], 0);

    let r21 = act["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["address"] == "100.64.0.21")
        .unwrap();
    assert_eq!(r21["source"], "dynamic");
    assert_eq!(
        ok(
            &mut s,
            "ip.subscriber-notice.active.list",
            json!({"find": "cliente"})
        )["total"],
        1
    );
    // The webhook gets one event per entry.
    let ev = s.notice_take_events(100);
    assert_eq!(ev.len(), 3);
    assert!(ev.iter().all(|e| e.event == "entered"));

    // A notice member sees the page: it joins the seen list for the interval.
    let r = ok(
        &mut s,
        "ip.subscriber-notice.seen",
        json!({"address": "100.64.0.20", "via": "android", "user_agent": "Dalvik/2.1"}),
    );
    assert_eq!(r["mode"], "notice");
    let seen = ok(
        &mut s,
        "ip.firewall.address-list.list",
        json!({"list": "sn-seen-aviso"}),
    );
    assert_eq!(seen.as_array().map(Vec::len).unwrap_or(0), 1, "{seen}");
    fails(
        &mut s,
        "ip.subscriber-notice.seen",
        json!({"address": "100.64.0.99"}),
        "no notice profile",
    );
    let log = ok(&mut s, "ip.subscriber-notice.log", json!({}));
    assert_eq!(log[0]["via"], "android");

    // The other notice member does not look within the timeout: it ends.
    s.tick(1_800_000_000 + 601);
    s.notice_tick();
    let log = ok(
        &mut s,
        "ip.subscriber-notice.log",
        json!({"address": "100.64.0.21"}),
    );
    assert_eq!(log[0]["via"], "timeout");
    // Blocked members never time out.
    assert_eq!(
        ok(
            &mut s,
            "ip.subscriber-notice.log",
            json!({"address": "100.64.0.10"})
        )
        .as_array()
        .unwrap()
        .len(),
        0
    );

    // Leaving the list: forgotten, with a "left" event.
    let id = ok(
        &mut s,
        "ip.firewall.address-list.list",
        json!({"list": "bloqueados"}),
    )[0]["id"]
        .clone();
    ok(&mut s, "ip.firewall.address-list.remove", json!({"id": id}));
    s.notice_tick();
    let ev = s.notice_take_events(100);
    assert!(
        ev.iter()
            .any(|e| e.event == "left" && e.address.to_string() == "100.64.0.10"),
        "{ev:?}"
    );
}

#[test]
fn variables_and_test_as_client() {
    let mut s = lab();
    ok(
        &mut s,
        "ip.subscriber-notice.profile.add",
        json!({"name": "atraso", "mode": "block", "address_list": "bloqueados"}),
    );
    ok(
        &mut s,
        "ip.firewall.address-list.add",
        json!({"list": "bloqueados", "address": "100.64.0.0/24"}),
    );
    ok(
        &mut s,
        "ip.subscriber-notice.vars.set",
        json!({"address": "100.64.0.10", "vars": {"valor": "R$ 120,00", "link_pix": "https://pix.example/abc"}}),
    );
    fails(
        &mut s,
        "ip.subscriber-notice.vars.set",
        json!({"address": "100.64.0.10", "vars": {"senha": "x"}}),
        "unknown variable",
    );
    fails(
        &mut s,
        "ip.subscriber-notice.vars.set",
        json!({"address": "100.64.0.10", "vars": {"valor": 1}}),
        "a string",
    );
    let pv = ok(
        &mut s,
        "ip.subscriber-notice.page.preview",
        json!({"address": "100.64.0.10"}),
    );
    let html = pv["html"].as_str().unwrap();
    assert!(
        html.contains("R$ 120,00") && html.contains("https://pix.example/abc"),
        "{html}"
    );

    // Inside the /24: blocked, HTTPS refused, every probe redirected, and
    // the empty walled garden warned.
    let t = ok(
        &mut s,
        "ip.subscriber-notice.test",
        json!({"address": "100.64.0.10"}),
    );
    assert_eq!(t["profile"], "atraso");
    assert_eq!(t["https"], "refused");
    assert_eq!(t["portal"], true);
    assert!(
        t["probes"]
            .as_array()
            .unwrap()
            .iter()
            .all(|p| p["answer"] == "redirect")
    );
    assert!(
        t["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|w| w.as_str().unwrap().contains("walled garden is empty"))
    );
    let out = ok(
        &mut s,
        "ip.subscriber-notice.test",
        json!({"address": "100.64.1.10"}),
    );
    assert!(out.get("profile").is_none() || out["profile"].is_null());
    assert_eq!(out["https"], "passes");

    // An input rule that drops the subscribers takes the portal away: said.
    ok(
        &mut s,
        "ip.firewall.filter.add",
        json!({"chain": "input", "src_address": "100.64.0.0/16", "action": "drop"}),
    );
    let t = ok(
        &mut s,
        "ip.subscriber-notice.test",
        json!({"address": "100.64.0.10"}),
    );
    assert!(
        t["warnings"].as_array().unwrap().iter().any(|w| w
            .as_str()
            .unwrap()
            .contains("drops the subscriber's connection to the portal")),
        "{t}"
    );
}

#[test]
fn lease_and_secret_block_with_page() {
    let mut s = lab();
    ok(
        &mut s,
        "ip.subscriber-notice.profile.add",
        json!({"name": "atraso", "mode": "block", "address_list": "bloqueados"}),
    );
    ok(
        &mut s,
        "ip.subscriber-notice.profile.add",
        json!({"name": "aviso", "mode": "notice", "address_list": "aviso"}),
    );
    ok(
        &mut s,
        "ip.dhcp-server.lease.add",
        json!({"address": "100.64.0.50", "mac_address": "02:00:00:00:00:50", "address_lists": ["clientes"]}),
    );
    let r = ok(
        &mut s,
        "ip.dhcp-server.lease.notice",
        json!({"address": "100.64.0.50", "profile": "atraso"}),
    );
    assert_eq!(r["address_lists"], json!(["clientes", "bloqueados"]));
    // Another profile replaces it; the other lists stay.
    let r = ok(
        &mut s,
        "ip.dhcp-server.lease.notice",
        json!({"address": "100.64.0.50", "profile": "aviso"}),
    );
    assert_eq!(r["address_lists"], json!(["clientes", "aviso"]));
    s.notice_tick();
    let act = ok(
        &mut s,
        "ip.subscriber-notice.active.list",
        json!({"profile": "aviso"}),
    );
    assert_eq!(
        act["total"], 1,
        "the lease's address is in the list at once"
    );
    let r = ok(
        &mut s,
        "ip.dhcp-server.lease.notice",
        json!({"address": "100.64.0.50"}),
    );
    assert_eq!(r["address_lists"], json!(["clientes"]));
    s.notice_tick();
    assert_eq!(
        ok(&mut s, "ip.subscriber-notice.active.list", json!({}))["total"],
        0,
        "released"
    );
    fails(
        &mut s,
        "ip.dhcp-server.lease.notice",
        json!({"address": "100.64.0.51", "profile": "atraso"}),
        "no static lease",
    );
    fails(
        &mut s,
        "ip.dhcp-server.lease.notice",
        json!({"address": "100.64.0.50", "profile": "nope"}),
        "no notice profile",
    );

    let r = ok(
        &mut s,
        "ppp.secret.notice",
        json!({"name": "joao", "profile": "atraso"}),
    );
    assert!(r["warnings"][0].as_str().unwrap().contains("RADIUS"));
    assert_eq!(s.store().running().ip.subscriber_notice.logins.len(), 1);
    ok(
        &mut s,
        "ppp.secret.notice",
        json!({"name": "joao", "profile": "aviso"}),
    );
    assert_eq!(
        s.store().running().ip.subscriber_notice.logins.len(),
        1,
        "one profile per login"
    );
    assert_eq!(
        ok(&mut s, "ip.subscriber-notice.login.print", json!({})),
        json!([{"name": "joao", "profile": "aviso"}])
    );
    ok(&mut s, "ppp.secret.notice", json!({"name": "joao"}));
    assert!(s.store().running().ip.subscriber_notice.logins.is_empty());
    fails(
        &mut s,
        "ip.subscriber-notice.login.add",
        json!({"name": "joao"}),
        "profile",
    );
    ok(
        &mut s,
        "ip.subscriber-notice.login.add",
        json!({"name": "joao", "profile": "atraso"}),
    );
    ok(
        &mut s,
        "ip.subscriber-notice.login.remove",
        json!({"name": "joao"}),
    );
    // Removing a profile frees its logins.
    ok(
        &mut s,
        "ppp.secret.notice",
        json!({"name": "ana", "profile": "aviso"}),
    );
    ok(
        &mut s,
        "ip.subscriber-notice.profile.remove",
        json!({"id": "aviso"}),
    );
    assert!(s.store().running().ip.subscriber_notice.logins.is_empty());
    assert!(matches!(
        s.execute(
            "ip.subscriber-notice.walled-garden.remove",
            &json!({"id": "*1"})
        ),
        Err(EngineError::Disabled { .. })
    ));
}

#[test]
fn throttle_members_get_a_dynamic_queue_and_lose_it_on_leaving() {
    let mut s = lab();
    ok(
        &mut s,
        "ip.subscriber-notice.profile.add",
        json!({"name": "lento", "mode": "throttle", "address_list": "reduzidos", "rate_limit": "1M/1M"}),
    );
    let id = ok(
        &mut s,
        "ip.firewall.address-list.add",
        json!({"list": "reduzidos", "address": "100.64.0.30"}),
    )["id"]
        .clone();
    let q = ok(&mut s, "queue.simple.list", json!({"origin": "notice"}));
    assert_eq!(q["total"], 1, "{q}");
    assert_eq!(q["rows"][0]["name"], "notice<lento>");
    assert_eq!(q["rows"][0]["target"], "100.64.0.30");
    ok(&mut s, "ip.firewall.address-list.remove", json!({"id": id}));
    assert_eq!(
        ok(&mut s, "queue.simple.list", json!({"origin": "notice"}))["total"],
        0
    );
}

#[test]
fn the_generated_ruleset_has_the_notice_chains() {
    let mut s = lab();
    ok(
        &mut s,
        "ip.subscriber-notice.profile.add",
        json!({"name": "atraso", "mode": "block", "address_list": "bloqueados"}),
    );
    let script = corerouter_firewall::script(s.store().running(), &[]);
    assert!(script.contains("chain notice_dstnat"), "{script}");
    assert!(
        script.contains("set al4_bloqueados"),
        "the profile's list has its set even when empty: {script}"
    );
    assert!(script.contains("set al4_sn-garden"), "{script}");
    ok(
        &mut s,
        "ip.subscriber-notice.settings.set",
        json!({"portal_address": "100.64.0.1"}),
    );
    let script = corerouter_firewall::script(s.store().running(), &[]);
    assert!(script.contains("dnat ip to 100.64.0.1:8880"), "{script}");
    fails(
        &mut s,
        "ip.subscriber-notice.settings.set",
        json!({"portal_address": "x"}),
        "address",
    );
}

#[test]
fn previews_for_the_modals() {
    let mut s = lab();
    let p = ok(
        &mut s,
        "ip.subscriber-notice.profile.preview",
        json!({"name": "atraso", "mode": "", "address_list": "bloqueados"}),
    );
    assert_eq!(p["checks"][0]["param"], "mode", "{p}");
    let p = ok(
        &mut s,
        "ip.subscriber-notice.profile.preview",
        json!({"name": "atraso", "mode": "block", "address_list": "bloqueados"}),
    );
    assert_eq!(p["checks"][0]["level"], "ok", "{p}");
    assert!(
        p["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["check"] == "garden")
    );
    assert_eq!(
        p["commands"][0]["command"],
        "ip.subscriber-notice.profile.add"
    );
    assert!(
        p["computed"][0]["value"]
            .as_str()
            .unwrap()
            .contains("refused")
    );
    let p = ok(
        &mut s,
        "ip.subscriber-notice.profile.preview",
        json!({"name": "x", "mode": "block", "address_list": "sn-x"}),
    );
    assert_eq!(p["checks"][0]["level"], "error");
    ok(
        &mut s,
        "ip.subscriber-notice.profile.add",
        json!({"name": "atraso", "mode": "block", "address_list": "bloqueados"}),
    );
    let p = ok(
        &mut s,
        "ip.subscriber-notice.profile.preview",
        json!({"id": "atraso", "mode": "notice", "intercept": "http"}),
    );
    assert_eq!(
        p["commands"][0]["command"],
        "ip.subscriber-notice.profile.set"
    );
    assert!(
        p["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["check"] == "intercept"),
        "{p}"
    );
    let g = ok(
        &mut s,
        "ip.subscriber-notice.walled-garden.preview",
        json!({"dst_host": "pix.banco.com.br"}),
    );
    assert!(
        g["computed"][0]["value"]
            .as_str()
            .unwrap()
            .contains("router's DNS")
    );
    let g = ok(
        &mut s,
        "ip.subscriber-notice.walled-garden.preview",
        json!({"dst_host": "a b"}),
    );
    assert_eq!(g["checks"][0]["param"], "dst_host");
    let pv = ok(&mut s, "ip.subscriber-notice.page.preview", json!({}));
    assert_eq!(pv["title"], "Aviso do seu provedor");
    assert!(pv["paragraphs"][0].as_str().unwrap().contains("joao.silva"));
}
