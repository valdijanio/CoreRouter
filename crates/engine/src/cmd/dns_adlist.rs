//! /ip dns adlist (G4.1d): block lists for the LAN forwarder (RouterOS v7).
//! The config holds where each list comes from; the daemon downloads it
//! and keeps the names (`crate::dns_adlist`), and the forwarder answers a
//! listed name with 0.0.0.0 / :: (`proto-dns`, `server/stage/adlist.rs`).

use corerouter_model::ItemId;
use corerouter_model::dns_adlist::{
    AdlistEntry, MAX_FILE_LEN, MAX_LISTS, MAX_URL_LEN, file_problem, url_problem,
};
use serde_json::{Value, json};

use super::args::{opt_bool, opt_parse, opt_str, opt_text, req_parse};
use super::{CommandSpec, always};
use crate::dns_adlist::AdlistStatus;
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(
        "ip.dns.adlist.add",
        "Add Adlist",
        ["IP", "DNS"],
        None,
        "{url?: string (http:// or https:// list: hosts file, one domain per line, or ||domain^), file?: string (a file in the daemon's --adlist-dir, instead of url), ssl_verify?: bool (check the HTTPS certificate; default yes), disabled?: bool, comment?: string} → {id}",
        always,
        add
    ),
    cmd!(
        "ip.dns.adlist.set",
        "Set Adlist",
        [],
        None,
        "{id: *hex, url?: string, file?: string, ssl_verify?: bool, disabled?: bool, comment?: string} → {id} (\"\" clears url or file)",
        has_lists,
        set
    ),
    cmd!(
        "ip.dns.adlist.remove",
        "Remove Adlist",
        [],
        None,
        "{id: *hex} → {id}",
        has_lists,
        remove
    ),
    cmd!(
        "ip.dns.adlist.reload",
        "Reload Adlists",
        [],
        None,
        "{id?: *hex (absent: every list)} → {reloading}",
        can_reload,
        reload
    ),
    cmd!(query "ip.dns.adlist.print", "DNS Adlist", ["IP", "DNS"], None,
        "{} → [{id, url?, file?, ssl_verify?, disabled?, comment?, state: waiting|loading|loaded|failed|off, name_count, match_count, skipped, loaded_secs_ago, error, flags (X disabled)}]",
        always, print),
];

fn has_lists(s: &Session) -> std::result::Result<(), String> {
    if s.store().candidate().ip.dns_adlist.entries.is_empty() {
        Err("there are no adlists".into())
    } else {
        Ok(())
    }
}

fn can_reload(s: &Session) -> std::result::Result<(), String> {
    has_lists(s)?;
    if s.adlist_backend().is_none() {
        return Err("adlists are loaded by the router daemon; this session has none".into());
    }
    Ok(())
}

fn position(s: &Session, id: ItemId, key: &str) -> Result<usize> {
    s.store()
        .candidate()
        .ip
        .dns_adlist
        .entries
        .iter()
        .position(|e| e.id == id)
        .ok_or_else(|| EngineError::bad(key, format!("no adlist {id}")))
}

/// Applies the fields given in `p` to `e`.
fn apply(e: &mut AdlistEntry, p: &Value) -> Result<()> {
    if let Some(v) = opt_str(p, "url")? {
        let v = v.trim();
        if v.len() > MAX_URL_LEN {
            return Err(EngineError::bad("url", format!("at most {MAX_URL_LEN} characters")));
        }
        if !v.is_empty()
            && let Some(why) = url_problem(v)
        {
            return Err(EngineError::bad("url", why));
        }
        v.clone_into(&mut e.url);
    }
    if let Some(v) = opt_str(p, "file")? {
        let v = v.trim();
        if v.len() > MAX_FILE_LEN {
            return Err(EngineError::bad("file", format!("at most {MAX_FILE_LEN} characters")));
        }
        if !v.is_empty()
            && let Some(why) = file_problem(v)
        {
            return Err(EngineError::bad("file", why));
        }
        v.clone_into(&mut e.file);
    }
    if let Some(v) = opt_bool(p, "ssl_verify")? {
        e.ssl_verify = v;
    }
    if let Some(v) = opt_bool(p, "disabled")? {
        e.disabled = v;
    }
    if let Some(v) = opt_text(p, "comment", 256)? {
        e.comment = v;
    }
    if let Some(why) = e.problem() {
        let key = if why.starts_with("file") { "file" } else { "url" };
        return Err(EngineError::bad(key, why));
    }
    Ok(())
}

fn add(s: &mut Session, p: &Value) -> Result<Value> {
    if s.store().candidate().ip.dns_adlist.entries.len() >= MAX_LISTS {
        return Err(EngineError::bad("url", format!("at most {MAX_LISTS} adlists")));
    }
    let mut e = AdlistEntry::new(ItemId(0));
    apply(&mut e, p)?;
    let lists = &s.store().candidate().ip.dns_adlist.entries;
    if let Some(same) = lists.iter().find(|x| x.source() == e.source()) {
        return Err(EngineError::bad(
            if e.url.is_empty() { "file" } else { "url" },
            format!("adlist {} already loads this list", same.id),
        ));
    }
    let st = &mut s.store_mut().candidate_mut().ip.dns_adlist;
    e.id = st.next_id();
    let id = e.id;
    st.entries.push(e);
    Ok(json!({ "id": id }))
}

fn set(s: &mut Session, p: &Value) -> Result<Value> {
    let id: ItemId = req_parse(p, "id")?;
    let i = position(s, id, "id")?;
    let Some(mut e) = s.store().candidate().ip.dns_adlist.entries.get(i).cloned() else {
        return Err(EngineError::bad("id", format!("no adlist {id}")));
    };
    apply(&mut e, p)?;
    if let Some(slot) = s.store_mut().candidate_mut().ip.dns_adlist.entries.get_mut(i) {
        *slot = e;
    }
    Ok(json!({ "id": id }))
}

fn remove(s: &mut Session, p: &Value) -> Result<Value> {
    let id: ItemId = req_parse(p, "id")?;
    let i = position(s, id, "id")?;
    s.store_mut().candidate_mut().ip.dns_adlist.entries.remove(i);
    Ok(json!({ "id": id }))
}

fn reload(s: &mut Session, p: &Value) -> Result<Value> {
    let id: Option<ItemId> = opt_parse(p, "id")?;
    if let Some(id) = id {
        position(s, id, "id")?;
    }
    let n = match id {
        Some(_) => 1,
        None => s.store().running().ip.dns_adlist.entries.len(),
    };
    if let Some(b) = s.adlist_backend() {
        b.reload(id);
    }
    Ok(json!({ "reloading": n }))
}

fn print(s: &mut Session, _: &Value) -> Result<Value> {
    let status: Vec<AdlistStatus> = s.adlist_backend().map(|b| b.status()).unwrap_or_default();
    let rows: Vec<Value> = s
        .store()
        .candidate()
        .ip
        .dns_adlist
        .entries
        .iter()
        .filter_map(|e| {
            let mut v = serde_json::to_value(e).ok()?;
            let st = status
                .iter()
                .find(|x| x.id == Some(e.id))
                .cloned()
                .unwrap_or(AdlistStatus {
                    state: if e.disabled { "off" } else { "waiting" },
                    ..AdlistStatus::default()
                });
            let o = v.as_object_mut()?;
            if let Some(extra) = serde_json::to_value(st).ok()?.as_object() {
                for (k, x) in extra {
                    o.insert(k.clone(), x.clone());
                }
            }
            o.insert("ssl_verify".into(), json!(e.ssl_verify));
            o.insert("flags".into(), json!(if e.disabled { "X" } else { "" }));
            Some(v)
        })
        .collect();
    Ok(Value::Array(rows))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    const URL: &str = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts";

    #[test]
    fn add_set_print_remove() {
        let mut s = Session::virtual_lab();
        let a = s
            .execute("ip.dns.adlist.add", &json!({"url": URL, "comment": "ads"}))
            .unwrap();
        let b = s
            .execute("ip.dns.adlist.add", &json!({"file": "local.txt", "ssl_verify": false}))
            .unwrap();
        let rows = s.execute("ip.dns.adlist.print", &json!({})).unwrap();
        assert_eq!(rows[0]["url"], URL);
        assert_eq!(rows[0]["ssl_verify"], true);
        assert_eq!(rows[0]["state"], "waiting", "no daemon: nothing loads");
        assert_eq!(rows[0]["name_count"], 0);
        assert_eq!(rows[1]["file"], "local.txt");
        assert_eq!(rows[1]["ssl_verify"], false);
        s.execute(
            "ip.dns.adlist.set",
            &json!({"id": b["id"], "file": "", "url": "http://lists.example/ads.txt", "disabled": true}),
        )
        .unwrap();
        let rows = s.execute("ip.dns.adlist.print", &json!({})).unwrap();
        assert_eq!(rows[1]["url"], "http://lists.example/ads.txt");
        assert!(rows[1].get("file").is_none());
        assert_eq!((rows[1]["flags"].as_str(), rows[1]["state"].as_str()), (Some("X"), Some("off")));
        s.execute("ip.dns.adlist.remove", &json!({"id": a["id"]})).unwrap();
        assert_eq!(s.store().candidate().ip.dns_adlist.entries.len(), 1);
    }

    #[test]
    fn bad_lists_are_refused() {
        let mut s = Session::virtual_lab();
        s.execute("ip.dns.adlist.add", &json!({"url": URL})).unwrap();
        for p in [
            json!({}),
            json!({"url": "ftp://lists.example/x"}),
            json!({"url": "https://user@lists.example/x"}),
            json!({"url": URL, "file": "a.txt"}),
            json!({"file": "../../etc/shadow"}),
            json!({"file": ".hidden"}),
            json!({"url": format!("https://x/{}", "a".repeat(2000))}),
            json!({"url": URL}),
            json!({"url": "https://ok.example/x", "ssl_verify": "maybe"}),
        ] {
            let err = s.execute("ip.dns.adlist.add", &p).unwrap_err();
            assert!(matches!(err, EngineError::BadParam { .. }), "{p}: {err}");
        }
        assert_eq!(s.store().candidate().ip.dns_adlist.entries.len(), 1);
        let err = s
            .execute("ip.dns.adlist.set", &json!({"id": "*1", "url": ""}))
            .unwrap_err();
        assert!(err.to_string().contains("needs a url or a file"), "{err}");
    }

    #[test]
    fn rollback_drops_the_list() {
        let mut s = Session::virtual_lab();
        s.execute("config.mode.set", &json!({"mode": "transactional"}))
            .unwrap();
        s.execute("ip.dns.adlist.add", &json!({"url": URL})).unwrap();
        s.execute("config.discard", &json!({})).unwrap();
        assert!(s.store().candidate().ip.dns_adlist.entries.is_empty());
    }

    #[derive(Default)]
    struct Fake(Mutex<Vec<Option<ItemId>>>);

    impl crate::dns_adlist::AdlistBackend for Fake {
        fn status(&self) -> Vec<AdlistStatus> {
            vec![AdlistStatus {
                id: Some(ItemId(1)),
                state: "loaded",
                name_count: 120_000,
                match_count: 7,
                ..AdlistStatus::default()
            }]
        }
        fn reload(&self, id: Option<ItemId>) {
            self.0.lock().unwrap().push(id);
        }
    }

    #[test]
    fn counts_and_reload_come_from_the_loader() {
        let mut s = Session::virtual_lab();
        s.execute("ip.dns.adlist.add", &json!({"url": URL})).unwrap();
        let err = s.execute("ip.dns.adlist.reload", &json!({})).unwrap_err();
        assert!(err.to_string().contains("daemon"), "{err}");
        let fake = Arc::new(Fake::default());
        s.set_adlist_backend(fake.clone());
        let rows = s.execute("ip.dns.adlist.print", &json!({})).unwrap();
        assert_eq!((rows[0]["name_count"].as_u64(), rows[0]["match_count"].as_u64()), (Some(120_000), Some(7)));
        assert_eq!(rows[0]["state"], "loaded");
        s.execute("ip.dns.adlist.reload", &json!({"id": "*1"})).unwrap();
        s.execute("ip.dns.adlist.reload", &json!({})).unwrap();
        assert!(s.execute("ip.dns.adlist.reload", &json!({"id": "*9"})).is_err());
        assert_eq!(*fake.0.lock().unwrap(), vec![Some(ItemId(1)), None]);
    }
}
