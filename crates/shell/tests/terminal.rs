//! The terminal against a real engine session, answering its requests the
//! way the control channel does (`engine.execute`, `engine.batch`,
//! `engine.list`, `state.inspect` as one connection).

use std::collections::BTreeMap;

use corerouter_engine::{Caller, Session, cmd};
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
            caller: Caller::new(7, "test 127.0.0.1:1"),
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
    assert_eq!(lines[0], "Flags: X - disabled");
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
    assert_eq!(t.complete("/i"), ["interface", "ip", "import"]);
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
            &Caller::new(99, "other 10.0.0.9:2"),
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
