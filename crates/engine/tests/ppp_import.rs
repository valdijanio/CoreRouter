//! G4.3n: `ppp.secret.import` of a RouterOS export, and the passwords kept
//! out of everything but the sealed config.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use corerouter_engine::storage::MemoryStorage;
use corerouter_engine::{Caller, EngineError, Principal, Session, Slot};
use corerouter_hal::VirtualHal;
use serde_json::{Value, json};

const EXPORT: &str = r#"# 2026-10-26 by RouterOS 7.20.2
/ip pool
add name=clientes ranges=100.64.0.0/22
/ppp profile
add local-address=100.64.255.254 name=plano-100M only-one=yes rate-limit=50M/100M \
    use-encryption=yes
add name=plano-orfao remote-address=pool-que-nao-existe
/ppp secret
add name=joao@isp password=Pw-j0ao-9Xk profile=plano-100M service=pppoe \
    remote-address=100.64.9.9 caller-id=AA:BB:CC:00:00:01 comment="Jo\C3\A3o"
add name=maria password=Pw-m4ria-7Qz profile=VELHO service=pppoe
add name=pedro profile=plano-100M
add name=ana password=Pw-an4-3Lm last-logged-out=2026-10-01 profile=default \
    caller-id=10.0.0.9 service=l2tp
"#;

const PASSWORDS: [&str; 3] = ["Pw-j0ao-9Xk", "Pw-m4ria-7Qz", "Pw-an4-3Lm"];

fn boot(storage: &MemoryStorage) -> Session {
    Session::with_storage(Box::new(VirtualHal::default()), Box::new(storage.clone()))
}

fn import(s: &mut Session, extra: Value) -> Result<Value, EngineError> {
    let mut p = json!({"text": EXPORT, "profile_map": {"VELHO": "default"}});
    if let (Some(o), Some(e)) = (p.as_object_mut(), extra.as_object()) {
        o.extend(e.clone());
    }
    s.execute("ppp.secret.import", &p)
}

fn open(s: &mut Session, name: &str) -> String {
    let key = corerouter_engine::sealing::key(s).unwrap();
    let x = s.store().candidate().ppp.secret(name).cloned().unwrap();
    key.open(&x.password).unwrap()
}

#[test]
fn preview_then_import() {
    let mut s = Session::virtual_lab();
    // Without the map: VELHO is missing, and the report says so.
    let r = s
        .execute(
            "ppp.secret.import",
            &json!({"text": EXPORT, "dry_run": true}),
        )
        .unwrap();
    assert_eq!(r["total"], 4, "{r}");
    assert_eq!(r["missing_profiles"], json!(["VELHO"]), "{r}");
    assert_eq!(
        r["profiles"],
        json!([
            {"name": "VELHO", "count": 1, "here": false, "in_file": false, "target": ""},
            {"name": "default", "count": 1, "here": true, "in_file": false, "target": "default"},
            {"name": "plano-100M", "count": 2, "here": false, "in_file": true, "target": "plano-100M"},
        ]),
        "{r}"
    );
    assert_eq!(r["without_password"]["names"], json!(["pedro"]), "{r}");
    assert_eq!(r["with_password"], 3);
    assert_eq!(r["profiles_created"], json!(["plano-100M"]));
    assert_eq!(r["unsupported"]["last-logged-out"], 1, "{r}");
    assert_eq!(r["unsupported"]["profile use-encryption"], 1, "{r}");
    assert!(r["warnings"].to_string().contains("not a MAC"), "{r}");
    assert!(r["reminder"].as_str().unwrap().contains("delete"), "{r}");
    assert!(s.store().candidate().ppp.secrets.is_empty(), "dry run");
    assert!(s.store().candidate().ppp.profiles.is_empty(), "dry run");
    // Applying it with the error left: nothing at all.
    let e = s
        .execute("ppp.secret.import", &json!({"text": EXPORT}))
        .unwrap_err();
    assert!(e.to_string().contains("nothing imported"), "{e}");
    assert!(s.store().running().ppp.secrets.is_empty());
    // Mapped: in, one revision.
    let rev = s.store().current_revision();
    let r = import(&mut s, json!({})).unwrap();
    assert_eq!(r["added"], 4, "{r}");
    assert_eq!(s.store().current_revision(), rev + 1);
    assert_eq!(open(&mut s, "joao@isp"), "Pw-j0ao-9Xk");
    let ppp = &s.store().running().ppp;
    assert_eq!(ppp.secret("maria").unwrap().profile, "default");
    assert_eq!(ppp.secret("joao@isp").unwrap().comment, "João");
    assert!(ppp.secret("ana").unwrap().caller_id.is_none());
    assert!(ppp.profile("plano-100M").unwrap().only_one == corerouter_model::ppp::Tri::Yes);
    assert!(
        ppp.profile("plano-orfao").is_none(),
        "only the profiles used"
    );
}

#[test]
fn conflicts_skip_replace_rename() {
    let with_maria = || {
        let mut s = Session::virtual_lab();
        s.execute(
            "ppp.secret.add",
            &json!({"name": "maria", "password": "old", "comment": "here"}),
        )
        .unwrap();
        s
    };
    let mut s = with_maria();
    let r = import(&mut s, json!({"dry_run": true})).unwrap();
    assert_eq!(r["conflicts"], json!({"count": 1, "names": ["maria"]}));
    let mut skip = with_maria();
    let r = import(&mut skip, json!({})).unwrap();
    assert_eq!(
        (r["added"].as_u64(), r["skipped"].as_u64()),
        (Some(3), Some(1))
    );
    assert_eq!(open(&mut skip, "maria"), "old");
    let mut replace = with_maria();
    import(&mut replace, json!({"on_conflict": "replace"})).unwrap();
    let id = s.store().running().ppp.secret("maria").unwrap().id;
    assert_eq!(
        replace.store().running().ppp.secret("maria").unwrap().id,
        id,
        "keeps its id"
    );
    assert_eq!(open(&mut replace, "maria"), "Pw-m4ria-7Qz");
    assert_eq!(replace.store().running().ppp.secrets.len(), 4);
    let mut rename = with_maria();
    let r = import(&mut rename, json!({"on_conflict": "rename"})).unwrap();
    assert_eq!(r["renamed"], json!([{"from": "maria", "to": "maria-2"}]));
    assert_eq!(open(&mut rename, "maria-2"), "Pw-m4ria-7Qz");
    assert_eq!(open(&mut rename, "maria"), "old");
}

#[test]
fn one_transaction_rolled_back_and_safe_mode() {
    let mut s = Session::virtual_lab();
    s.execute("config.mode.set", &json!({"mode": "transactional"}))
        .unwrap();
    import(&mut s, json!({})).unwrap();
    assert_eq!(s.store().candidate().ppp.secrets.len(), 4);
    assert!(s.store().running().ppp.secrets.is_empty());
    s.execute("config.discard", &json!({})).unwrap();
    assert!(s.store().candidate().ppp.secrets.is_empty());
    s.execute("config.mode.set", &json!({"mode": "immediate"}))
        .unwrap();
    s.execute("config.safe-mode.enter", &json!({})).unwrap();
    import(&mut s, json!({})).unwrap();
    assert_eq!(s.store().running().ppp.secrets.len(), 4);
    s.execute("config.safe-mode.cancel", &json!({})).unwrap();
    assert!(
        s.store().running().ppp.secrets.is_empty(),
        "Safe Mode undoes the import"
    );
}

#[test]
fn passwords_never_leave_the_sealed_config() {
    let storage = MemoryStorage::default();
    let mut s = boot(&storage);
    s.execute("config.mode.set", &json!({"mode": "transactional"}))
        .unwrap();
    import(&mut s, json!({})).unwrap();
    let pending = s.execute("config.diff", &json!({})).unwrap().to_string();
    s.execute("config.commit", &json!({})).unwrap();
    s.execute(
        "ppp.secret.set",
        &json!({"id": "maria", "password": "Pw-n3w-1Ab"}),
    )
    .unwrap();
    s.execute("config.commit", &json!({})).unwrap();
    let journal = s.inspect(Some("journal")).unwrap().to_string();
    assert!(
        journal.contains("ppp.secret.import") && journal.contains("bytes)"),
        "{journal}"
    );
    let mut outputs = vec![
        pending,
        journal,
        s.execute("config.history", &json!({})).unwrap().to_string(),
        s.execute("ppp.secret.list", &json!({}))
            .unwrap()
            .to_string(),
        s.execute("log.print", &json!({})).unwrap().to_string(),
        s.inspect(None).unwrap().to_string(),
        s.inspect(Some("ppp")).unwrap().to_string(),
        s.inspect(Some("running")).unwrap().to_string(),
        format!("{:?}", s.store().running()),
        storage.get(Slot::Current).unwrap_or_default(),
        storage.get(Slot::Previous).unwrap_or_default(),
    ];
    // Undo: the previous revision loaded back is the same boxes.
    let rev = s.store().current_revision();
    s.execute("config.rollback", &json!({"revision": rev - 1}))
        .unwrap();
    outputs.push(s.execute("config.diff", &json!({})).unwrap().to_string());
    for n in 0..=rev {
        outputs.push(storage.revision(n).unwrap_or_default());
    }
    for text in &outputs {
        for pw in PASSWORDS.iter().chain(&["Pw-n3w-1Ab"]) {
            assert!(
                !text.contains(pw),
                "{pw} leaks in: {}",
                &text[..text.len().min(400)]
            );
        }
    }
    // A user below group full does not even see the boxes.
    s.execute("config.discard", &json!({})).unwrap();
    s.execute(
        "user.add",
        &json!({"name": "noc", "group": "write", "password": "correct horse"}),
    )
    .unwrap();
    let noc = Caller::new(9, "test").with_principal(Principal::User("noc".into()));
    let e = s
        .execute_as(&noc, "ppp.secret.list", &json!({"show_sensitive": true}))
        .unwrap_err();
    assert!(matches!(e, EngineError::Denied { .. }), "{e}");
    let ppp = s.inspect_as(&noc, Some("ppp")).unwrap().to_string();
    assert!(!ppp.contains("$cr1$"), "{ppp}");
    // The next boot opens them with the stored key.
    let mut again = boot(&storage);
    assert_eq!(open(&mut again, "maria"), "Pw-n3w-1Ab");
}

#[test]
fn clear_passwords_from_before_are_sealed_at_boot() {
    let storage = MemoryStorage::default();
    let mut s = boot(&storage);
    s.execute("ppp.secret.add", &json!({"name": "velho", "password": "x"}))
        .unwrap();
    let boxed = s
        .store()
        .running()
        .ppp
        .secret("velho")
        .unwrap()
        .password
        .stored()
        .to_owned();
    // A config written before G4.3n: the password in clear.
    let old = storage
        .get(Slot::Current)
        .unwrap()
        .replace(&boxed, "Cl34r-0ld");
    storage.put(Slot::Current, Some(old));
    let mut s = boot(&storage);
    let pw = &s.store().running().ppp.secret("velho").unwrap().password;
    assert!(pw.is_sealed());
    assert_eq!(open(&mut s, "velho"), "Cl34r-0ld");
    assert!(!storage.get(Slot::Current).unwrap().contains("Cl34r-0ld"));
}

#[test]
fn hostile_text_is_refused_without_echo() {
    let mut s = Session::virtual_lab();
    for t in [
        "/ppp secret\nadd name=a password=\"Pw-unterminated".to_owned(),
        "/ppp secret\nadd name=a password=Pw-\\zz".to_owned(),
        format!("/ppp secret\nadd name=a password={}", "P".repeat(200)),
        "x".repeat(corerouter_engine::rsc::MAX_TEXT + 1),
    ] {
        let e = s
            .execute("ppp.secret.import", &json!({"text": t}))
            .unwrap_err();
        let msg = e.to_string();
        assert!(!msg.contains("Pw-") && !msg.contains("PPPP"), "{msg}");
        let j = s.inspect(Some("journal")).unwrap().to_string();
        assert!(!j.contains("Pw-") && !j.contains("PPPP"), "{j}");
    }
}

/// A RouterOS export of `n` subscribers, as RouterOS v7 writes them.
fn export_of(n: usize) -> String {
    let mut text =
        String::from("/ppp profile\nadd name=plano-100M rate-limit=50M/100M\n/ppp secret\n");
    for i in 0..n {
        text.push_str(&format!(
            "add caller-id=AA:BB:{:02X}:{:02X}:{:02X}:01 comment=\"Cliente {i:06}\" name=cliente{i:06}@isp \\\n    password=Pw{i:08x}Zq profile=plano-100M remote-address=100.{}.{}.{} service=pppoe\n",
            (i >> 16) & 0xff, (i >> 8) & 0xff, i & 0xff, 64 + (i >> 16), (i >> 8) & 0xff, i & 0xff
        ));
    }
    text
}

/// 100 000 subscribers (`cargo test --release -p corerouter-engine --test
/// ppp_import -- --ignored --nocapture`): parse rate, dry run and import
/// times, the config's size sealed and in clear, peak memory; then a
/// commit of the 40 000 that fit in what a commit may save.
#[test]
#[ignore]
fn hundred_thousand_secrets() {
    use std::time::Instant;
    let n = 100_000;
    let text = export_of(n);
    let mb = text.len() as f64 / 1e6;
    let rss = || {
        std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("VmHWM"))
                    .map(str::to_owned)
            })
            .unwrap_or_default()
    };
    let t = Instant::now();
    let parsed = corerouter_engine::rsc::parse(&text, |m| m.starts_with("ppp")).unwrap();
    let parse = t.elapsed();
    assert_eq!(parsed.items.len(), n + 1);
    drop(parsed);
    let mut s = Session::virtual_lab();
    let t = Instant::now();
    let r = s
        .execute("ppp.secret.import", &json!({"text": text, "dry_run": true}))
        .unwrap();
    let dry = t.elapsed();
    assert_eq!(r["with_password"], n);
    s.execute("config.mode.set", &json!({"mode": "transactional"}))
        .unwrap();
    let t = Instant::now();
    let r = s
        .execute("ppp.secret.import", &json!({"text": text}))
        .unwrap();
    let apply = t.elapsed();
    assert_eq!(r["added"], n);
    let size = |c: &corerouter_model::Config| {
        corerouter_model::persist::encode_config(c).unwrap().len() as f64 / 1e6
    };
    let sealed = size(s.store().candidate());
    let key = corerouter_engine::sealing::key(&mut s).unwrap();
    let mut clear = s.store().candidate().clone();
    let t = Instant::now();
    for x in clear.ppp.secrets.iter_mut() {
        x.password = key.open(&x.password).unwrap().into();
    }
    let open = t.elapsed() / n as u32;
    let refused = s.execute("config.commit", &json!({})).is_err();
    println!(
        "{n} secrets, {mb:.1} MB of export: parse {parse:?} ({:.0} lines/s, {:.0} MB/s), dry run {dry:?}, import {apply:?}, \
         config {sealed:.1} MB sealed / {:.1} MB in clear (commit refused over the save budget: {refused}), open one password {open:?}; {}",
        n as f64 / parse.as_secs_f64(),
        mb / parse.as_secs_f64(),
        size(&clear),
        rss()
    );
    let n = 40_000;
    let text = export_of(n);
    let mut s = Session::virtual_lab();
    let t = Instant::now();
    let r = s
        .execute("ppp.secret.import", &json!({"text": text}))
        .unwrap();
    assert_eq!(r["added"], n);
    println!(
        "{n} secrets imported and committed (one revision) in {:?}; {}",
        t.elapsed(),
        rss()
    );
}
