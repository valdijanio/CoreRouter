//! The terminal against a real engine session, answering its requests the
//! way the control channel does (`engine.execute`, `engine.batch`,
//! `engine.list`, `state.inspect` as one connection).

use std::collections::BTreeMap;

use corerouter_engine::{Caller, Principal, Session, cmd};
use corerouter_shell::parse::{self, Parsed};
use corerouter_shell::{Reply, Request, Shell, doc};
use serde_json::{Value, json};

struct Router {
    session: Session,
    caller: Caller,
    files: BTreeMap<String, String>,
    calls: Vec<String>,
}

impl Router {
    fn new() -> Self {
        Self {
            session: Session::virtual_lab(),
            caller: Caller::new(7, "test 127.0.0.1:1").with_principal(Principal::Local),
            files: BTreeMap::new(),
            calls: Vec::new(),
        }
    }

    fn answer(&mut self, r: &Request) -> Reply {
        let err = |e: corerouter_engine::EngineError| e.to_string();
        match r {
            Request::ReadFile { path } => self
                .files
                .get(path)
                .map(|t| Value::String(t.clone()))
                .ok_or_else(|| format!("{path}: no such file")),
            Request::WriteFile { path, content } => {
                self.files.insert(path.clone(), content.clone());
                Ok(Value::Null)
            }
            Request::Sleep { .. } => Ok(Value::Null),
            Request::Call { method, params } => {
                self.calls.push(method.clone());
                let s = &mut self.session;
                match method.as_str() {
                    "server.info" => Ok(json!({"name": "corerouter", "version": "test"})),
                    "auth.whoami" => Ok(corerouter_engine::auth::whoami(
                        s,
                        &self.caller.principal,
                        &self.caller.name,
                    )),
                    "engine.list" => Ok(s.list()),
                    "engine.execute" => {
                        let id = params["command"].as_str().unwrap_or("");
                        s.execute_as(&self.caller, id, &params["params"])
                            .map_err(err)
                    }
                    "engine.batch" => s
                        .batch_as(&self.caller, &params["steps"], params["atomic"] != false)
                        .map_err(err),
                    "state.inspect" => s
                        .inspect_as(&self.caller, params["path"].as_str())
                        .map_err(err),
                    other => Err(format!("unknown method {other}")),
                }
            }
        }
    }
}

struct Term {
    shell: Shell,
    router: Router,
}

impl Term {
    fn new() -> Self {
        let mut t = Self {
            shell: Shell::new("admin"),
            router: Router::new(),
        };
        let job = t.shell.connect();
        let r = &mut t.router;
        let out = t.shell.run_with(job, |q| r.answer(q));
        assert!(!out.failed, "{}", out.text());
        t
    }

    fn run(&mut self, line: &str) -> String {
        let job = self.shell.submit(line);
        let r = &mut self.router;
        self.shell.run_with(job, |q| r.answer(q)).text()
    }

    fn ok(&mut self, line: &str) -> String {
        let job = self.shell.submit(line);
        let r = &mut self.router;
        let out = self.shell.run_with(job, |q| r.answer(q));
        assert!(!out.failed, "{line}: {}", out.text());
        out.text()
    }

    fn fails(&mut self, line: &str) -> String {
        let job = self.shell.submit(line);
        let r = &mut self.router;
        let out = self.shell.run_with(job, |q| r.answer(q));
        assert!(out.failed, "{line} should fail: {}", out.text());
        out.text()
    }

    fn complete(&self, line: &str) -> Vec<String> {
        self.shell
            .complete(line, line.len())
            .candidates
            .into_iter()
            .map(|c| c.display)
            .collect()
    }

    fn export(&mut self) -> String {
        self.ok("/export file=x");
        self.router.files.get("x").cloned().unwrap_or_default()
    }
}

/// Every command of the registry is reachable by its RouterOS path, and the
/// terminal reads the same parameter keys as the engine.
#[test]
fn every_command_is_reachable() {
    let t = Term::new();
    let reg = t.shell.registry();
    for spec in cmd::all() {
        let (path, c) = reg
            .by_id(spec.id)
            .unwrap_or_else(|| panic!("{} missing from the tree", spec.id));
        let line = format!("/{} {}", path.join(" "), c.verb);
        let got = parse::parse(reg, &[], &line).unwrap_or_else(|e| panic!("{line}: {e:?}"));
        let id = match got {
            Parsed::Command { id, .. } | Parsed::Print { id, .. } => id,
            other => panic!("{line}: {other:?}"),
        };
        assert_eq!(id, spec.id, "{line}");
        let help = parse::parse(reg, &[], &format!("{line} ?")).unwrap();
        assert_eq!(
            help,
            Parsed::Help {
                path: path.to_vec(),
                id: Some(spec.id.to_owned())
            }
        );
        let ours: Vec<(String, bool)> = doc::params(spec.params)
            .into_iter()
            .map(|p| (p.key, p.required))
            .collect();
        let engine: Vec<(String, bool)> = cmd::doc_keys(spec.params)
            .into_iter()
            .map(|(k, r)| (k.to_owned(), r))
            .collect();
        assert_eq!(ours, engine, "{}", spec.id);
        // And `?` on its menu lists it.
        let menu = t.shell.help(path, None);
        assert!(
            menu.iter().any(|l| l.text().contains(&c.verb)),
            "{} not in the help of its menu",
            spec.id
        );
    }
    // No menu and command share a name (the tree would hide one).
    for (path, c) in reg.commands() {
        let menu = reg.menu(path).unwrap();
        assert!(
            !menu.children.contains_key(&c.verb),
            "{} hides a menu",
            c.id
        );
    }
}

#[test]
fn add_print_where_and_remove_by_number() {
    let mut t = Term::new();
    t.ok("/interface vlan add name=vlan10 parent=ether1 vlan-id=10");
    t.ok("/ip address add address=10.0.0.1/24 interface=vlan10 comment=\"uplink A\"");
    t.ok("/ip address add address=10.0.1.1/24 interface=ether2 disabled=yes");
    t.ok("/ip addr");
    assert_eq!(t.shell.prompt_text(), "[admin@CoreRouter] /ip/address> ");
    let table = t.ok("pr");
    let lines: Vec<&str> = table.lines().collect();
    // G4.7a: DHCP leases list here too, flagged D.
    assert_eq!(lines[0], "Flags: X - disabled, I - invalid, D - dynamic");
    assert!(lines[1].contains("ADDRESS") && lines[1].contains("INTERFACE"));
    assert!(lines[2].contains(";;; uplink A"), "{table}");
    assert!(lines[3].starts_with(" 0   10.0.0.1/24"), "{table}");
    assert!(lines[4].starts_with(" 1 X 10.0.1.1/24"), "{table}");

    let w = t.ok("print where interface=vlan10");
    assert!(w.contains("10.0.0.1/24") && !w.contains("10.0.1.1"), "{w}");
    assert_eq!(t.ok("print count-only where !disabled").trim(), "1");
    assert_eq!(t.ok("print count-only interface=ether2").trim(), "1");
    let d = t.ok("print detail");
    assert!(
        d.contains("address=10.0.0.1/24") && d.contains("network=10.0.0.0/24"),
        "{d}"
    );
    let j: Value = serde_json::from_str(&t.ok("print as-json proplist=address")).unwrap();
    assert_eq!(
        j,
        json!([{"address": "10.0.0.1/24"}, {"address": "10.0.1.1/24"}])
    );

    // Numbers refer to the last print (filtered): item 0 is 10.0.1.1 now.
    t.ok("print where disabled");
    t.ok("remove 0");
    let left = t.ok("print");
    assert!(
        left.contains("10.0.0.1/24") && !left.contains("10.0.1.1"),
        "{left}"
    );
    assert!(t.fails("remove 5").contains("no such item 5"));

    // `set` by name and by number, `..`, and an interface property.
    t.ok("..");
    t.ok("..");
    assert_eq!(t.shell.prompt_text(), "[admin@CoreRouter] > ");
    t.ok("/interface set vlan10 mtu=1400");
    t.ok("/interface print where name=vlan10");
    t.ok("/interface set 0 comment=\"VLAN 10\"");
    let row = t.ok("/interface print detail where name=vlan10");
    assert!(
        row.contains("mtu=1400") && row.contains(";;; VLAN 10"),
        "{row}"
    );
}

#[test]
fn ids_batches_and_routes() {
    let mut t = Term::new();
    t.ok("/ip address add address=10.0.0.1/24 interface=ether1");
    t.ok("/ip route add dst-address=0.0.0.0/0 gateway=10.0.0.254");
    t.ok("/ip route add dst-address=10.9.0.0/16 gateway=10.0.0.253 distance=5");
    let routes = t.ok("/ip route print");
    assert!(
        routes.starts_with("Flags: X - disabled, A - active"),
        "{routes}"
    );
    assert!(routes.contains(" ADC "), "connected route flags: {routes}");
    // Two items at once run as one atomic batch.
    t.ok("/ip route print where static");
    t.ok("/ip route set 0,1 comment=bulk");
    assert_eq!(
        t.ok("/ip route print count-only where comment=bulk").trim(),
        "2"
    );
    let ids: Value = serde_json::from_str(&t.ok("/ip route print as-json where static")).unwrap();
    let id = ids[0]["id"].as_str().unwrap().to_owned();
    t.ok(&format!("/ip route remove {id}"));
    assert_eq!(t.ok("/ip route print count-only where static").trim(), "1");
    // A connected route has no id: the engine says why.
    t.ok("/ip route print where connected");
    let e = t.fails("/ip route remove 0");
    assert!(e.contains("cannot be used with remove"), "{e}");
}

#[test]
fn engine_errors_come_through_as_they_are() {
    let mut t = Term::new();
    // Unknown key: the engine's "did you mean", in its own words.
    let e = t.fails("/ip address add address=10.0.0.1/24 interface=ether1 comentt=x");
    assert!(e.contains("comentt") && e.contains("did you mean"), "{e}");
    let e = t.fails("/ip address add address=10.0.0.1/24 interface=nope");
    assert!(e.contains("no interface 'nope'"), "{e}");
    let e = t.fails("/ip address add address=10.0.0.1/24");
    assert!(e.contains("interface") && e.contains("required"), "{e}");
    let e = t.fails("/ip adress print");
    assert!(
        e.contains("did you mean 'address'") && e.contains("column 5"),
        "{e}"
    );
    // A verb the engine has no command for is not improvised: the menu
    // says what it has.
    let e = t.fails("/ip address set 0 comment=x");
    assert!(
        e.contains("bad command name 'set'") && e.contains("here: ") && e.contains("add"),
        "{e}"
    );
    // A disabled command answers with the engine's reason.
    let e = t.fails("/config commit");
    assert!(e.contains("no pending changes"), "{e}");
    // A script stops at the first error.
    let out = t.run("/system identity set name=a; /bogus; /system identity set name=b");
    assert!(out.contains("bad command name"), "{out}");
    assert!(t.shell.prompt_text().contains("@a]"));
}

#[test]
fn print_of_a_one_object_menu_and_query_results() {
    let mut t = Term::new();
    t.ok("/system identity set name=edge-1");
    assert_eq!(t.ok("/system identity print").trim(), "name: edge-1");
    assert!(t.shell.prompt_text().starts_with("[admin@edge-1]"));
    let d = t.ok("/ip neighbor discovery print");
    assert!(d.contains("interval-secs:"), "{d}");
    t.ok("/config mode set mode=transactional");
    t.ok("/system identity set name=edge-2");
    let diff = t.ok("/config diff");
    assert!(diff.contains("OP") && diff.contains("change"), "{diff}");
    t.ok("/config commit comment=\"from the terminal\"");
    let h = t.ok("/config history");
    assert!(h.contains("from the terminal"), "{h}");
}

#[test]
fn completion_offers_menus_commands_params_and_values() {
    let mut t = Term::new();
    t.ok("/interface vlan add name=vlan10 parent=ether1 vlan-id=10");
    assert_eq!(t.complete("/i"), ["interface", "ip", "ipv6", "import"]);
    assert_eq!(t.complete("/ip/ad"), ["address"]);
    assert!(t.complete("/ip address ").contains(&"add".to_owned()));
    assert_eq!(t.complete("/ip address a"), ["add"]);
    assert_eq!(t.complete("/ip address add i"), ["interface="]);
    let ifs = t.complete("/ip address add interface=");
    assert!(
        ifs.contains(&"ether1".to_owned()) && ifs.contains(&"vlan10".to_owned()),
        "{ifs:?}"
    );
    assert_eq!(t.complete("/ip address add interface=vl"), ["vlan10"]);
    assert_eq!(t.complete("/ip address add disabled="), ["yes", "no"]);
    let types = t.complete("/interface print type=");
    assert!(
        types.contains(&"ether".to_owned()) && types.contains(&"vlan".to_owned()),
        "{types:?}"
    );
    assert_eq!(
        t.complete("/ip neighbor print protocol="),
        ["crdp", "lldp", "mndp"]
    );
    assert_eq!(t.complete("/config mode set mode=t"), ["transactional"]);
    // Items of `set`: the names the menu lists.
    assert!(t.complete("/interface set ").contains(&"vlan10".to_owned()));
    // Lists complete after the last comma, without repeats.
    let vrf = t.complete("/ip vrf add interfaces=ether1,eth");
    assert!(
        vrf.contains(&"ether2".to_owned()) && !vrf.contains(&"ether1".to_owned()),
        "{vrf:?}"
    );
    // print options and `where` properties.
    assert!(
        t.complete("/ip address print d")
            .contains(&"detail".to_owned())
    );
    assert!(
        t.complete("/ip address print where ")
            .contains(&"interface".to_owned())
    );
    assert_eq!(
        t.complete("/ip address print where address=1.1.1.1 "),
        ["and", "or"]
    );
    // The relative menu counts.
    t.ok("/ip address");
    assert_eq!(t.complete("re"), ["remove"]);
    assert_eq!(t.complete(".."), [".."]);
    // Insertion point: after `=` for values.
    let c = t.shell.complete("/ip address add interface=vl", 29);
    assert_eq!(c.start, "/ip address add interface=".len());
    assert_eq!(c.common_prefix(), "vlan10 ");
}

#[test]
fn highlight_colors_known_and_unknown_words() {
    use corerouter_shell::Style;
    let t = Term::new();
    let line = "/ip address add address=10.0.0.1/24 interface=ether1";
    let spans = t.shell.highlight(line);
    assert_eq!(
        spans.iter().map(|s| s.text.as_str()).collect::<String>(),
        line
    );
    let style_of = |w: &str| spans.iter().find(|s| s.text.contains(w)).map(|s| s.style);
    assert_eq!(
        spans.iter().find(|s| s.text == "add").map(|s| s.style),
        Some(Style::Verb)
    );
    assert_eq!(style_of("address="), Some(Style::Key));
    assert_eq!(style_of("ether1"), Some(Style::Value));
    let bad = t.shell.highlight("/ip bogus print");
    assert!(
        bad.iter()
            .any(|s| s.style == Style::Error && s.text.contains("bogus"))
    );
}

#[test]
fn ctrl_x_toggles_safe_mode() {
    let mut t = Term::new();
    let toggle = |t: &mut Term| {
        let job = t.shell.toggle_safe_mode();
        let r = &mut t.router;
        t.shell.run_with(job, |q| r.answer(q)).text()
    };
    assert!(toggle(&mut t).contains("[Safe Mode taken]"));
    assert!(t.shell.prompt_text().contains("<SAFE>"));
    assert!(t.router.session.in_safe_mode());
    t.ok("/system identity set name=risky");
    assert!(toggle(&mut t).contains("[Safe Mode released]"));
    assert!(!t.shell.prompt_text().contains("<SAFE>"));
    assert!(!t.router.session.in_safe_mode());
    // Kept: leaving with Ctrl+X confirms.
    assert!(t.shell.prompt_text().contains("@risky]"));

    // `<SAFE>` takes the place of `>`.
    toggle(&mut t);
    t.ok("/ip address");
    assert_eq!(t.shell.prompt_text(), "[admin@risky] /ip/address<SAFE> ");
    // `/quit` keeps the changes...
    t.ok("/system identity set name=kept");
    let job = t.shell.submit("/quit");
    let r = &mut t.router;
    let out = t.shell.run_with(job, |q| r.answer(q));
    assert!(out.quit && !t.router.session.in_safe_mode());
    assert_eq!(t.router.session.inspect(None).unwrap()["identity"], "kept");
    // ...Ctrl+D undoes them.
    toggle(&mut t);
    t.ok("/system identity set name=undone");
    let job = t.shell.hang_up();
    let r = &mut t.router;
    let out = t.shell.run_with(job, |q| r.answer(q));
    assert!(out.quit && out.text().contains("undone"), "{}", out.text());
    assert_eq!(t.router.session.inspect(None).unwrap()["identity"], "kept");

    // Held by another connection: the engine says who.
    t.router
        .session
        .execute_as(
            &Caller::new(99, "other 10.0.0.9:2").with_principal(Principal::Local),
            "config.safe-mode.enter",
            &json!({}),
        )
        .unwrap();
    t.ok("/system identity print");
    let out = toggle(&mut t);
    assert!(out.contains("other 10.0.0.9:2"), "{out}");
}

/// A configuration touching every exportable menu.
fn build(t: &mut Term) {
    for line in [
        "/system identity set name=\"edge 1\"",
        "/interface bridge add name=br1 comment=\"LAN bridge\"",
        "/interface bridge port add bridge=br1 interface=ether3",
        "/interface bridge port add bridge=br1 interface=ether4",
        "/interface vlan add name=vlan20 parent=br1 vlan-id=20",
        "/interface vlan add name=vlan30 parent=vlan20 vlan-id=30 mtu=1400",
        "/interface loopback add name=lo0",
        "/interface set vlan30 disabled=yes",
        "/interface set ether2 mtu=9000 comment=\"to \\\"core\\\"\"",
        "/ip vrf add name=cust interfaces=ether5,lo0 comment=customer",
        "/ip address add address=10.0.0.1/24 interface=ether1",
        "/ip address add address=192.168.20.1/24 interface=vlan20 comment=users",
        "/ip address add address=172.16.0.1/30 interface=ether5 disabled=yes",
        "/ip route add dst-address=0.0.0.0/0 gateway=10.0.0.254",
        "/ip route add dst-address=10.50.0.0/16 gateway=172.16.0.2 routing-table=cust distance=20",
        "/ip route add dst-address=10.60.0.0/16 gateway=ether1 disabled=yes comment=\"spare\"",
        "/routing bgp instance set asn=65001 router-id=10.0.0.1",
        "/ip neighbor discovery set interfaces=ether1,br1 interval-secs=15",
    ] {
        t.ok(line);
    }
}

#[test]
fn export_import_round_trip() {
    let mut a = Term::new();
    build(&mut a);
    let script = a.export();
    assert!(!script.contains("password"));
    // Dependencies first: the bridge before its VLAN, the VLAN before the
    // VLAN on it, the VRF before routes in its table.
    let pos = |needle: &str| {
        script
            .find(needle)
            .unwrap_or_else(|| panic!("{needle} missing from:\n{script}"))
    };
    assert!(pos("add name=br1") < pos("name=vlan20"), "{script}");
    assert!(pos("name=vlan20") < pos("name=vlan30"), "{script}");
    assert!(pos("add name=cust") < pos("routing-table=cust"), "{script}");
    assert!(pos("name=lo0") < pos("add name=cust"), "{script}");
    // Deterministic.
    assert_eq!(a.export(), script);

    let mut b = Term::new();
    b.router.files.insert("cfg.rsc".into(), script.clone());
    let out = b.ok("/import file=cfg.rsc");
    assert!(out.contains("one atomic batch"), "{out}");
    assert_eq!(b.export(), script);
    let running = |t: &Term| {
        let mut v = t.router.session.inspect(Some("running")).unwrap();
        v.as_object_mut().unwrap().remove("routing");
        v
    };
    assert_eq!(running(&b)["interfaces"], running(&a)["interfaces"]);
    assert_eq!(
        running(&b)["ip"]["addresses"],
        running(&a)["ip"]["addresses"]
    );
    assert_eq!(
        b.router.session.inspect(Some("routing.bgp")).unwrap(),
        a.router.session.inspect(Some("routing.bgp")).unwrap()
    );

    // Export of one menu is its slice of the whole.
    let addr = a.ok("/ip address export");
    assert!(
        addr.contains("/ip address") && !addr.contains("/interface"),
        "{addr}"
    );

    // Pasting the script is the same atomic batch.
    let mut c = Term::new();
    let out = c.ok(&script);
    assert!(out.contains("one atomic batch"), "{out}");
    assert_eq!(c.export(), script);
}

/// G2.1: firewall rules (order, sections, negation, lists) and interface
/// lists survive `/export` → `/import`; the default lists LAN/WAN are set,
/// not added again.
#[test]
fn firewall_export_import_round_trip() {
    let mut a = Term::new();
    for (id, p) in [
        (
            "interface.list.set",
            json!({"name": "LAN", "comment": "inside"}),
        ),
        ("interface.list.add", json!({"name": "DMZ"})),
        (
            "interface.list.member.add",
            json!({"list": "LAN", "interface": "ether2"}),
        ),
        (
            "interface.list.member.add",
            json!({"list": "DMZ", "interface": "ether3"}),
        ),
        (
            "ip.firewall.filter.add",
            json!({"section": "Router protection"}),
        ),
        (
            "ip.firewall.filter.add",
            json!({"connection_state": "established,related"}),
        ),
        (
            "ip.firewall.filter.add",
            json!({"protocol": "tcp", "dst_port": "22,8291", "src_address_list": "!mgmt", "action": "drop", "comment": "ssh"}),
        ),
        (
            "ip.firewall.filter.add",
            json!({"in_interface_list": "!LAN", "action": "drop", "disabled": true}),
        ),
        (
            "ip.firewall.filter.add",
            json!({"action": "jump", "jump_target": "guard"}),
        ),
        (
            "ip.firewall.filter.add",
            json!({"chain": "guard", "protocol": "tcp", "action": "reject", "reject_with": "tcp-reset"}),
        ),
        (
            "ip.firewall.nat.add",
            json!({"chain": "srcnat", "action": "masquerade", "out_interface_list": "DMZ"}),
        ),
        (
            "ip.firewall.mangle.add",
            json!({"chain": "prerouting", "action": "mark-connection", "new_connection_mark": "web", "passthrough": false}),
        ),
        (
            "ip.firewall.address-list.add",
            json!({"list": "mgmt", "address": "10.0.0.0/24"}),
        ),
        (
            "ip.firewall.address-list.add",
            json!({"list": "tmp", "address": "192.0.2.1", "timeout": "1h"}),
        ),
    ] {
        a.router
            .session
            .execute(id, &p)
            .unwrap_or_else(|e| panic!("{id}: {e}"));
    }
    let script = a.export();
    assert!(
        !script.contains("add name=LAN"),
        "default list is set, not added:\n{script}"
    );
    assert!(
        !script.contains("192.0.2.1"),
        "dynamic entry is not exported:\n{script}"
    );
    let mut b = Term::new();
    b.router.files.insert("fw.rsc".into(), script.clone());
    b.ok("/import file=fw.rsc");
    // Ids may differ (tables are imported in another order); content may not.
    let fw = |t: &Term, path: &str| {
        let mut v = t.router.session.inspect(Some(path)).unwrap();
        for item in v.as_array_mut().into_iter().flatten() {
            if let Some(o) = item.as_object_mut() {
                o.remove("id");
            }
        }
        v
    };
    for table in ["filter", "nat", "mangle", "address_lists"] {
        let path = format!("running.ip.firewall.{table}");
        assert_eq!(fw(&b, &path), fw(&a, &path), "{table}:\n{script}");
    }
    assert_eq!(
        fw(&b, "running.interface_lists.lists"),
        fw(&a, "running.interface_lists.lists")
    );
    assert_eq!(b.export(), script);
    // Typed in the terminal, custom chains and negations work too.
    b.ok("/ip firewall filter add chain=guard2 src-address=!10.0.0.0/8 action=drop");
}

/// The zone matrix exports as its cells (`/ip firewall zone set from=… to=…
/// action=…`), and the filter rules it generates are not exported again:
/// on import the matrix regenerates them, so they are not duplicated nor
/// turned into loose rules (before: "# set: from is not exported", and the
/// generated rules came out as ordinary `/ip firewall filter add` lines).
/// An empty zone matrix is nothing to export: no line, no note (it came out
/// as "# set: from is not exported").
#[test]
fn empty_zone_matrix_exports_nothing() {
    let mut t = Term::new();
    let script = t.export();
    assert!(!script.contains("ip firewall zone"), "{script}");
    assert!(
        !script.contains("is not exported\n/ip neighbor"),
        "{script}"
    );
}

#[test]
fn zone_matrix_export_import_round_trip() {
    let mut a = Term::new();
    for (id, p) in [
        (
            "interface.list.member.add",
            json!({"list": "LAN", "interface": "ether2"}),
        ),
        (
            "interface.list.member.add",
            json!({"list": "WAN", "interface": "ether1"}),
        ),
        (
            "ip.firewall.filter.add",
            json!({"protocol": "tcp", "dst_port": "22", "action": "drop", "comment": "manual"}),
        ),
        (
            "ip.firewall.zone.set",
            json!({"from": "LAN", "to": "WAN", "action": "allow"}),
        ),
        (
            "ip.firewall.zone.set",
            json!({"from": "WAN", "to": "router", "action": "block"}),
        ),
    ] {
        a.router
            .session
            .execute(id, &p)
            .unwrap_or_else(|e| panic!("{id}: {e}"));
    }
    let script = a.export();
    assert!(
        script.contains("set from=LAN to=WAN action=allow"),
        "{script}"
    );
    assert!(
        script.contains("set from=WAN to=router action=block"),
        "{script}"
    );
    assert!(!script.contains("is not exported"), "{script}");
    assert!(
        !script.contains("zona "),
        "generated rules are not exported:\n{script}"
    );
    assert!(script.contains("comment=manual"), "{script}");
    let mut b = Term::new();
    b.router.files.insert("z.rsc".into(), script.clone());
    b.ok("/import file=z.rsc");
    let rules = |t: &Term| {
        let v = t
            .router
            .session
            .inspect(Some("running.ip.firewall.filter"))
            .unwrap();
        v.as_array().map_or(0, Vec::len)
    };
    assert_eq!(rules(&b), rules(&a), "{script}");
    assert_eq!(b.export(), script);
}

/// audit-e2e: a bond is listed both in `/interface` (type `bonding`) and in
/// `/interface bonding`, which has its own `print`. The `/interface` row
/// came out as "# add name=bond1: slaves is not exported" (as if a secret
/// had been held back) next to the real `/interface bonding add`; now the
/// sub-menu with a `print` exports it once, and `/interface set` keeps
/// what only the interface knows (disabled).
#[test]
fn bond_exports_once_without_a_note() {
    let mut a = Term::new();
    a.ok("/interface bonding add name=bond1 slaves=ether3,ether4 mode=802.3ad comment=uplink");
    a.ok("/interface set bond1 disabled=yes");
    a.ok("/ip address add address=10.9.0.1/24 interface=bond1");
    let script = a.export();
    assert!(!script.contains("is not exported"), "{script}");
    assert_eq!(script.matches("add name=bond1").count(), 1, "{script}");
    let mut b = Term::new();
    b.router.files.insert("cfg.rsc".into(), script.clone());
    b.ok("/import file=cfg.rsc");
    assert_eq!(b.export(), script);
    let running = |t: &Term| t.router.session.inspect(Some("running")).unwrap();
    assert_eq!(running(&b)["interfaces"], running(&a)["interfaces"]);
    assert_eq!(
        running(&b)["ip"]["addresses"],
        running(&a)["ip"]["addresses"]
    );
}

#[test]
fn import_is_atomic_and_says_where_it_failed() {
    let mut t = Term::new();
    let before = t.export();
    t.router.files.insert(
        "bad.rsc".into(),
        "/interface bridge\nadd name=br9\n/ip address\nadd address=10.0.0.1/24 interface=nope\n"
            .into(),
    );
    let e = t.fails("/import file=bad.rsc");
    assert!(
        e.contains("nothing was applied") && e.contains("no interface 'nope'"),
        "{e}"
    );
    assert_eq!(t.export(), before);
    t.router.files.insert(
        "syntax.rsc".into(),
        "/interface bridge\nadd name=br9\n/ip adress\n".into(),
    );
    let e = t.fails("/import file=syntax.rsc");
    assert!(e.contains("line 3"), "{e}");
    assert_eq!(t.export(), before);
    let e = t.fails("/import file=missing.rsc");
    assert!(e.contains("no such file"), "{e}");
    t.router
        .files
        .insert("num.rsc".into(), "/ip address\nremove 0\n".into());
    assert!(
        t.fails("/import file=num.rsc")
            .contains("numbers refer to the last print")
    );
    t.router
        .files
        .insert("print.rsc".into(), "/ip address print\n".into());
    assert!(
        t.fails("/import file=print.rsc")
            .contains("only configuration commands")
    );
}

/// Audit #9: a router with more than 256 config commands could not import
/// its own `/export` (one atomic batch, at most 256 steps).
#[test]
fn a_big_export_imports_back() {
    let mut a = Term::new();
    let mut script = String::from("/ip firewall address-list\n");
    for i in 0..300u32 {
        script.push_str(&format!(
            "add address=10.0.{}.{} list=blocked\n",
            i / 256,
            i % 256
        ));
    }
    a.router.files.insert("big.rsc".into(), script);
    a.ok("/import file=big.rsc");
    let exported = a.export();
    let mut b = Term::new();
    b.router.files.insert("cfg.rsc".into(), exported);
    b.ok("/import file=cfg.rsc");
    let lists = &b.router.session.store().running().ip.firewall.address_lists;
    assert_eq!(lists.len(), 300);
}

/// Audit #15: a script whose last line ended in `\` lost that command.
#[test]
fn a_script_ending_in_a_continuation_is_refused() {
    let t = Term::new();
    let err = t
        .shell
        .script_steps("/system identity\nset name=a \\")
        .unwrap_err();
    assert!(err.contains("line 2") && err.contains("continu"), "{err}");
    // Continued lines that do end still work.
    let steps = t
        .shell
        .script_steps("/system identity\nset \\\nname=a\n")
        .unwrap();
    assert_eq!(steps.len(), 1);
}

#[test]
fn help_shows_menus_commands_and_params() {
    let mut t = Term::new();
    let m = t.ok("/ip ?");
    assert!(
        m.contains("address") && m.contains("route") && m.contains("export"),
        "{m}"
    );
    let c = t.ok("/ip address add ?");
    assert!(
        c.contains("address") && c.contains("required") && c.contains("cidr"),
        "{c}"
    );
    let p = t.ok("/ip address print ?");
    assert!(p.contains("where") && p.contains("properties"), "{p}");
    let off = t.ok("/config commit ?");
    assert!(off.contains("unavailable now: no pending changes"), "{off}");
}

/// A command costs few round trips: no `engine.list` and no read per menu
/// after each line (the control channel pays latency per request).
#[test]
fn a_command_costs_three_requests_and_a_print_one() {
    let mut t = Term::new();
    t.router.calls.clear();
    t.ok("/system identity set name=x");
    assert_eq!(
        t.router.calls,
        ["engine.execute", "state.inspect", "engine.batch"]
    );
    t.router.calls.clear();
    t.ok("/ip address print");
    assert_eq!(t.router.calls, ["engine.execute"]);
    t.router.calls.clear();
    t.ok("/config diff");
    assert_eq!(t.router.calls, ["engine.execute"], "queries do not refresh");
    // The completion values were refreshed by that one batch.
    t.ok("/interface bridge add name=brz");
    assert!(t.complete("/interface set br").contains(&"brz".to_owned()));
}

#[test]
fn quit_and_hostile_lines() {
    let mut t = Term::new();
    let job = t.shell.submit("/quit");
    let r = &mut t.router;
    assert!(t.shell.run_with(job, |q| r.answer(q)).quit);
    t.fails(&"a".repeat(20_000));
    t.fails("/ip address add comment=\"open");
    t.fails(&format!("/ip address add {}", "x ".repeat(600)));
    assert!(t.run("").is_empty());
    assert!(t.run("# a comment").is_empty());
}

/// G1.26: `/system tuning` and `/system tuning interface` (G1.26b) export
/// what the config sets as `set` lines,
/// and an import puts them back.
#[test]
fn tuning_exports_as_set_lines() {
    let mut a = Term::new();
    a.ok("/system tuning set name=net.core.netdev_budget value=600");
    a.ok("/system tuning interface set name=ether2 key=rx_ring value=4096");
    let script = a.export();
    assert!(
        script.contains("/system tuning interface\nset name=ether2 key=rx_ring value=4096"),
        "{script}"
    );
    assert!(!script.contains("is not exported"), "{script}");
    assert!(
        script.contains("/system tuning\nset name=net.core.netdev_budget value=600"),
        "{script}"
    );
    let mut b = Term::new();
    b.router.files.insert("t.rsc".into(), script.clone());
    b.ok("/import file=t.rsc");
    assert_eq!(b.export(), script);
}

mod hostile {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// Any text, at any cursor position: no panic, and colors cover
        /// the line exactly.
        #[test]
        fn never_panics(line in ".{0,120}", cursor in 0usize..200) {
            let mut t = Term::new();
            t.run(&line);
            let _ = t.shell.complete(&line, cursor);
            let spans = t.shell.highlight(&line);
            prop_assert_eq!(spans.iter().map(|s| s.text.as_str()).collect::<String>(), line.clone());
            let _ = t.shell.script_steps(&line);
        }

        /// Lines built from the terminal's own vocabulary, which reach deep
        /// into the parser and the engine.
        #[test]
        fn vocabulary_never_panics(words in proptest::collection::vec(prop_oneof![
            Just("/"), Just("/ip"), Just("address"), Just("add"), Just("print"), Just("where"),
            Just("remove"), Just("set"), Just("0"), Just("*1"), Just("0,1"), Just(".."),
            Just("interface=ether1"), Just("address=10.0.0.1/24"), Just("disabled=yes"),
            Just("!disabled"), Just("mtu>1"), Just("and"), Just("or"), Just("?"), Just("detail"),
            Just("/interface"), Just("vlan"), Just("name=v1"), Just("vlan-id=7"), Just("parent=ether1"),
            Just("export"), Just("\""), Just(";"), Just("=")
        ], 0..10)) {
            let mut t = Term::new();
            let line = words.join(" ");
            t.run(&line);
            for i in 0..=line.len() {
                let _ = t.shell.complete(&line, i);
            }
            t.shell.highlight(&line);
        }
    }
}

/// G0.3b: right after the login, an admin without a password is asked for
/// one; an empty line is "not now"; the answer goes through `user.set`.
#[test]
fn first_login_asks_for_the_admin_password() {
    let first = || {
        let mut router = Router::new();
        router.session.bootstrap_admin(false);
        router.caller =
            Caller::new(7, "test 127.0.0.1:1").with_principal(Principal::User("admin".into()));
        let mut shell = Shell::new("admin");
        let job = shell.connect();
        let r = &mut router;
        let out = shell.run_with(job, |q| r.answer(q)).text();
        assert!(out.contains("User admin has no password"), "{out}");
        assert!(shell.asking_password());
        assert_eq!(shell.prompt_text(), "New password for admin: ");
        Term { shell, router }
    };
    // Not now: back to the normal prompt, nothing changed.
    let mut t = first();
    let out = t.run("");
    assert!(out.contains("Not now"), "{out}");
    assert!(!t.shell.asking_password());
    assert!(t.shell.prompt_text().starts_with("[admin@"));
    assert!(t.router.session.has_no_password("admin"));

    // Too short, then two different entries, then a good one.
    let mut t = first();
    t.run("short");
    assert_eq!(t.shell.prompt_text(), "Repeat new password: ");
    let out = t.run("short");
    assert!(out.contains("at least"), "{out}");
    assert!(t.shell.asking_password());
    t.run("first-password");
    let out = t.run("other-password");
    assert!(out.contains("differ"), "{out}");
    t.run("first-password");
    let out = t.run("first-password");
    assert!(out.contains("Password set for admin"), "{out}");
    assert!(!t.shell.asking_password());
    let h = t.router.session.password_hash("admin").unwrap();
    assert!(corerouter_engine::auth::verify_password(
        &h,
        "first-password"
    ));
    // The password reached the engine only as the masked journal entry.
    assert!(!t.ok("/config history").contains("first-password"));

    // A router where every admin has a password: no question.
    let t = Term::new();
    assert!(!t.shell.asking_password());
}

/// G4.7a: `/ip dhcp-client` from the registry, RouterOS style, and the
/// dynamic address it brings, flagged D.
#[test]
fn dhcp_client_add_print_and_dynamic_address() {
    let mut t = Term::new();
    t.ok("/ip dhcp-client add interface=ether1 add-default-route=special-classless use-peer-ntp=no allowed-servers=192.0.2.1,100.64.1.1 extra-options=77:'wan',224:0x01");
    t.router.session.dhcp_service(0);
    t.router.session.dhcp_service(1_000);
    let table = t.ok("/ip dhcp-client print");
    let lines: Vec<&str> = table.lines().collect();
    assert_eq!(lines[0], "Flags: X - disabled, I - invalid", "{table}");
    assert!(
        lines[1].contains("INTERFACE") && lines[1].contains("STATUS"),
        "{table}"
    );
    assert!(
        lines[2].contains("ether1") && lines[2].contains("bound"),
        "{table}"
    );
    let d = t.ok("/ip dhcp-client print detail");
    assert!(d.contains("add-default-route=special-classless"), "{d}");
    assert!(d.contains("gateway=100.64.1.1"), "{d}");
    assert!(d.contains("extra-options=\"77:'wan',224:0x01\""), "{d}");
    t.ok("/ip dhcp-client set 0 disabled=yes");
    let off = t.ok("/ip dhcp-client print");
    assert!(off.contains(" 0 X ") && off.contains("stopped"), "{off}");
    t.ok("/ip dhcp-client set 0 disabled=no");
    t.router.session.dhcp_service(2_000);
    t.router.session.dhcp_service(3_000);
    let a = t.ok("/ip address print");
    assert!(a.contains("D - dynamic"), "{a}");
    assert!(a.contains(" D 100.64.1."), "{a}");
    let e = t.fails("/ip dhcp-client add interface=ether1");
    assert!(e.contains("already has DHCP client"), "{e}");
    t.ok("/ip dhcp-client renew 0");
}

/// G4.7b: `/ipv6 dhcp-client`, `/ipv6 pool`, `/ipv6 settings` from the
/// registry, and a LAN address numbered from the delegated prefix.
#[test]
fn dhcpv6_client_pool_and_settings() {
    let mut t = Term::new();
    t.ok("/ipv6 dhcp-client add interface=ether1 request=address,prefix pool-name=pd prefix-hint=::/56");
    t.ok("/ip address add address=::1/64 interface=ether2 from-pool=pd");
    t.router.session.dhcp_service(0);
    t.router.session.dhcp_service(1_500);
    let table = t.ok("/ipv6 dhcp-client print");
    assert!(
        table.contains("ether1") && table.contains("bound"),
        "{table}"
    );
    let d = t.ok("/ipv6 dhcp-client print detail");
    assert!(d.contains("prefix=2001:db8:1:100::/56"), "{d}");
    assert!(d.contains("request=address,prefix"), "{d}");
    let p = t.ok("/ipv6 pool print");
    assert!(p.contains("pd") && p.contains("2001:db8:1:100::/56"), "{p}");
    let a = t.ok("/ip address print");
    assert!(a.contains("2001:db8:1:100::1/64"), "{a}");
    let s = t.ok("/ipv6 settings print");
    assert!(s.contains("auto"), "{s}");
    t.ok("/ipv6 settings set accept-router-advertisements=no");
    let e = t.fails("/ipv6 dhcp-client add interface=ether2 request=prefix");
    assert!(e.contains("pool"), "{e}");
}

/// G0.8b: on a narrow terminal `/export` wraps as RouterOS does (` \` and a
/// four-space indent, between arguments) and pasting it back rebuilds the
/// same config; `/export terse` is one line per item with its menu.
#[test]
fn wrapped_and_terse_export_round_trip() {
    let mut a = Term::new();
    build(&mut a);
    a.ok("/ip dhcp-client add interface=ether1 add-default-route=no use-peer-dns=no use-peer-ntp=no comment=\"uplink to the ISP\" fallback-address=192.168.88.2/24");
    a.shell.set_width(Some(48));
    let screen = a.ok("/export");
    assert!(screen.contains(" \\\n    "), "{screen}");
    for l in screen.lines().filter(|l| !l.starts_with('#')) {
        assert!(l.chars().count() <= 48, "{l:?} in:\n{screen}");
    }
    // A quoted value is never cut.
    assert!(screen.contains("comment=\"uplink to the ISP\""), "{screen}");

    let mut b = Term::new();
    let out = b.ok(&screen);
    assert!(out.contains("one atomic batch"), "{out}");
    b.shell.set_width(Some(48));
    assert_eq!(b.ok("/export"), screen);
    // A file does not depend on the window: always 80 columns.
    assert_eq!(b.export(), a.export());

    let terse = a.ok("/export terse");
    for l in terse.lines() {
        assert!(l.starts_with('/') || l.starts_with('#'), "{l:?}");
        assert!(!l.ends_with('\\'), "{l:?}");
    }
    assert!(
        terse.contains("/ip dhcp-client add interface=ether1 "),
        "{terse}"
    );
    let mut c = Term::new();
    c.ok(&terse);
    assert_eq!(c.export(), a.export());
}

/// G4.1b: `/ip dns` and `/ip dns static` survive `/export` → `/import`,
/// typed in the terminal the RouterOS way.
#[test]
fn dns_export_import_round_trip() {
    let mut a = Term::new();
    for line in [
        "/ip dns set servers=1.1.1.1,9.9.9.9 allow-remote-requests=yes allowed-from=LAN,10.0.0.0/8 server-selection=sequential serve-stale-secs=3600",
        "/ip dns static add name=nas.lan address=192.168.88.10 comment=\"file server\"",
        "/ip dns static add name=www.lan type=CNAME cname=nas.lan",
        "/ip dns static add regexp=\"^ads[0-9]*\\\\.example$\" type=NXDOMAIN",
        "/ip dns static add name=corp.example type=FWD forward-to=10.0.0.53 match-subdomain=yes address-list=vpn",
        "/ip dns static add name=_sip._udp.lan type=SRV srv-target=pbx.lan srv-port=5060 disabled=yes",
        "/ip dns static add name=t.lan type=TXT text=\"v=spf1 -all\" ttl-secs=300",
    ] {
        a.ok(line);
    }
    let printed = a.ok("/ip dns static print");
    assert!(
        printed.contains("nas.lan") && printed.contains("CNAME"),
        "{printed}"
    );
    let script = a.export();
    assert!(script.contains("/ip dns static"), "{script}");
    assert!(script.contains("allowed-from=LAN,10.0.0.0/8"), "{script}");
    let mut b = Term::new();
    b.router.files.insert("cfg.rsc".into(), script.clone());
    b.ok("/import file=cfg.rsc");
    assert_eq!(b.export(), script);
    let dns = |t: &Term, p: &str| t.router.session.inspect(Some(p)).unwrap();
    assert_eq!(
        dns(&b, "running.ip.dns_static"),
        dns(&a, "running.ip.dns_static")
    );
    assert_eq!(dns(&b, "running.ip.dns"), dns(&a, "running.ip.dns"));
    // The cache is not configuration.
    assert!(!script.contains("/ip dns cache"), "{script}");
    a.ok("/ip dns cache flush");
}

/// G4.1c: `/ip dns zone` and its records survive `/export` → `/import`
/// (zones before their records; the serial kept as exported).
#[test]
fn dns_zone_export_import_round_trip() {
    let mut a = Term::new();
    for line in [
        "/ip dns zone add name=example.com allow-transfer=192.0.2.0/24 notify=192.0.2.2 admin=noc@example.com",
        "/ip dns zone add name=partner.example type=secondary primaries=192.0.2.53",
        "/ip dns zone record add zone=example.com name=www address=192.0.2.80",
        "/ip dns zone record add zone=example.com type=MX target=mail.example.com priority=10",
        "/ip dns zone record add zone=example.com name=t type=TXT text=\"v=spf1 -all\" ttl-secs=300",
    ] {
        a.ok(line);
    }
    let printed = a.ok("/ip dns zone record print");
    assert!(
        printed.contains("www") && printed.contains("MX"),
        "{printed}"
    );
    let script = a.export();
    assert!(script.contains("/ip dns zone"), "{script}");
    let zones = script.find("/ip dns zone\n").unwrap_or(usize::MAX);
    let records = script.find("/ip dns zone record").unwrap_or(0);
    assert!(zones < records, "zones first: {script}");
    let mut b = Term::new();
    b.router.files.insert("cfg.rsc".into(), script.clone());
    b.ok("/import file=cfg.rsc");
    assert_eq!(b.export(), script);
    let get = |t: &Term| {
        t.router
            .session
            .inspect(Some("running.ip.dns_zones"))
            .unwrap()
    };
    assert_eq!(get(&b)["records"], get(&a)["records"]);
    assert_eq!(get(&b)["zones"][0]["serial"], get(&a)["zones"][0]["serial"]);
}
