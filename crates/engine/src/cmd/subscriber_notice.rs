//! /ip subscriber-notice (G4.10): block and notice pages for subscribers
//! (profiles, walled garden, pages, who is under a profile now, the view
//! log, "test as client"), and the "Block (com página)" actions of a DHCP
//! lease and a PPP secret. Design: `docs/subscriber-notices.md`.

use std::collections::BTreeMap;
use std::net::IpAddr;

use corerouter_firewall::eval::{self, Packet};
use corerouter_model::ItemId;
use corerouter_model::firewall::{AddrMatch, ConnState, Name, Protocol, Table};
use corerouter_model::subscriber_notice::{
    GardenEntry, Intercept, Login, MAX_FIELD, MAX_GARDEN, MAX_LOGINS, MAX_PAGES, MAX_PROFILES,
    MAX_TEXT, Mode, Page, Profile, SubscriberNotices, VARS, host_problem, probes, render,
};
use serde_json::{Value, json};

use super::args::{opt_bool, opt_parse, opt_str, opt_text, opt_u32, req_parse, req_str};
use super::dhcp_server::opt_secs;
use super::{CommandSpec, always};
use crate::subscriber_notice::{MAX_VAR_LEN, Member};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(query "ip.subscriber-notice.settings.get", "Subscriber Notice Settings", [], None,
        "{} → {port, portal_host, capport_url, webhook_url, probes: int (OS probe hosts known)}",
        always, settings_print),
    cmd!("ip.subscriber-notice.settings.set", "Set Subscriber Notice Settings", [], None,
        "{port?: int 1..65535 (the portal on the router; default 8880), portal_host?: string (name in the redirect, aviso.provedor.com.br; empty: the router's address on the subscriber's side), capport_url?: string (RFC 8908 API, https:// with a valid certificate; announced by DHCP option 114 and RA option 37; empty: not announced), webhook_url?: string (http(s):// POSTed a JSON event when a subscriber enters or leaves a profile's list; empty: off)} → {port}",
        always, settings_set),
    cmd!("ip.subscriber-notice.profile.add", "Add Notice Profile", ["IP", "Subscriber Notices"], None,
        "{name: string, mode: block|notice|throttle, address_list: string (the firewall list whose members get it; RADIUS Mikrotik-Address-List, PPP profiles and DHCP leases fill it), page?: string (a page's name; empty: the built-in one), intercept?: probes|http (what port 80 goes to the page; default http for block, probes for notice and throttle), interval?: duration (notice/throttle: page again after; default 1d), timeout?: duration (notice/throttle: stop if not seen within; 0 never; default 1h), rate_limit?: string (throttle: rx/tx, 1M/1M), kill_connections?: bool (block: end open connections on entry; default yes), webhook?: bool (default yes), disabled?: bool, comment?: string} → {id}",
        always, profile_add),
    cmd!("ip.subscriber-notice.profile.set", "Set Notice Profile", [], None,
        "{id: *hex | name, name?: string, mode?: block|notice|throttle, address_list?: string, page?: string, intercept?: probes|http, interval?: duration, timeout?: duration, rate_limit?: string, kill_connections?: bool, webhook?: bool, disabled?: bool, comment?: string} → {id}",
        has_profiles, profile_set),
    cmd!("ip.subscriber-notice.profile.remove", "Remove Notice Profile", [], None,
        "{id: *hex | name} → {id}",
        has_profiles, profile_remove),
    cmd!(query "ip.subscriber-notice.profile.print", "Notice Profiles", [], None,
        "{} → [{id, name, mode, address_list, page?, intercept, interval, interval_secs, timeout, timeout_secs, rate_limit?, kill_connections, webhook, disabled, comment?, behaviour, members}]",
        always, profile_print),
    cmd!("ip.subscriber-notice.walled-garden.add", "Add Walled Garden", [], None,
        "{dst_host?: string (a domain the router resolves: the ISP's site, the bank's PIX page), dst_address?: prefix (allowed as is), disabled?: bool, comment?: string} → {id}",
        always, garden_add),
    cmd!("ip.subscriber-notice.walled-garden.set", "Set Walled Garden", [], None,
        "{id: *hex, dst_host?: string, dst_address?: prefix, disabled?: bool, comment?: string} → {id} (\"\" clears dst_host or dst_address)",
        has_garden, garden_set),
    cmd!("ip.subscriber-notice.walled-garden.remove", "Remove Walled Garden", [], None,
        "{id: *hex} → {id}",
        has_garden, garden_remove),
    cmd!(query "ip.subscriber-notice.walled-garden.print", "Walled Garden", [], None,
        "{} → [{id, dst_host?, dst_address?, disabled, comment?, addresses: int (resolved now)}]",
        always, garden_print),
    cmd!("ip.subscriber-notice.page.add", "Add Notice Page", [], None,
        "{name: string, title?: string, text?: string (blank lines split paragraphs; {login} {plano} {valor} {vencimento} {link_pix} {endereco} {perfil} are filled), color?: string (#rrggbb), logo_url?: string, button_text?: string, button_url?: string ({link_pix} is typical), continue_text?: string (notice pages: the link that marks it seen), comment?: string} → {id}",
        always, page_add),
    cmd!("ip.subscriber-notice.page.set", "Set Notice Page", [], None,
        "{id: *hex | name, name?: string, title?: string, text?: string, color?: string, logo_url?: string, button_text?: string, button_url?: string, continue_text?: string, comment?: string} → {id}",
        has_pages, page_set),
    cmd!("ip.subscriber-notice.page.remove", "Remove Notice Page", [], None,
        "{id: *hex | name (not one a profile uses)} → {id}",
        has_pages, page_remove),
    cmd!(query "ip.subscriber-notice.page.print", "Notice Pages", [], None,
        "{} → [{id, name, title, text, color, logo_url?, button_text?, button_url?, continue_text?, comment?, used_by: [string]} (the built-in page is not listed: page.preview without a page shows it)]",
        always, page_print),
    cmd!(query "ip.subscriber-notice.page.preview", "Preview Notice Page", [], None,
        "{page?: string (a page's name; default: the built-in one), title?: string, text?: string, color?: string, logo_url?: string, button_text?: string, button_url?: string, continue_text?: string (unsaved edits over the page), address?: ip (fill with this subscriber's variables; default: sample values)} → {html, problem?}",
        always, page_preview),
    cmd!(query "ip.subscriber-notice.active.list", "Notice Active", [], None,
        "{profile?: string, find?: string (in the address, login or comment), limit?: int 1..100000 (default 10000)} → {total, rows: [{address, profile, mode, source (static|dynamic), comment?, login?, since?, since_secs_ago?, seen, seen_secs_ago?}]}",
        always, active_list),
    cmd!(query "ip.subscriber-notice.log", "Notice Log", [], None,
        "{address?: ip, profile?: string, limit?: int 1..10000 (default 500, newest first)} → [{at, address, profile, via (android|apple|windows|firefox|linux|…|browser|timeout), login?, user_agent?}]",
        always, log_print),
    cmd!("ip.subscriber-notice.seen", "Mark Notice Seen", [], None,
        "{address: ip, via?: string (the probe's OS or browser), user_agent?: string} → {profile, mode, until?} (the portal calls it when the page is viewed; notice/throttle: it passes for the profile's interval)",
        always, seen),
    cmd!("ip.subscriber-notice.vars.set", "Set Notice Variables", [], None,
        "{address: ip, vars: {login?: string, plano?: string, valor?: string, vencimento?: string, link_pix?: string} (the ISP system's values for the page; {} clears)} → {address, vars}",
        always, vars_set),
    cmd!(query "ip.subscriber-notice.vars.print", "Notice Variables", [], None,
        "{address: ip} → {address, vars}",
        always, vars_print),
    cmd!(query "ip.subscriber-notice.test", "Test as Client", [], None,
        "{address: ip (a subscriber's)} → {address, profile?, mode?, source?, seen, dns, portal (port 80 goes to the page now), https (refused|passes), probes: [{os, host, path, answer (redirect|passes)}], walled_garden: int, warnings: [string]}",
        always, test),
    cmd!("ip.subscriber-notice.login.add", "Add Notice Login", [], None,
        "{name: string (a PPP login, local or RADIUS), profile: string (a notice profile)} → {name, profile, warnings} (its session's address joins the profile's list while it is up)",
        always, login_add),
    cmd!("ip.subscriber-notice.login.remove", "Remove Notice Login", [], None,
        "{name: string} → {name}",
        has_logins, login_remove),
    cmd!(query "ip.subscriber-notice.login.print", "Notice Logins", [], None,
        "{} → [{name, profile}]",
        always, login_print),
    cmd!("ip.dhcp-server.lease.notice", "Block (com página)", [], None,
        "{address: ipv4 (a static lease), profile?: string (a notice profile; empty: none) } → {id, address, address_lists}",
        always, lease_notice),
    cmd!("ppp.secret.notice", "Block (com página)", [], None,
        "{name: string (a PPP login, local or RADIUS), profile?: string (a notice profile; empty: none)} → {name, profile?, warnings}",
        always, secret_notice),
];

fn cfg(s: &Session) -> &SubscriberNotices {
    &s.store().candidate().ip.subscriber_notice
}

fn has_profiles(s: &Session) -> std::result::Result<(), String> {
    if cfg(s).profiles.is_empty() { Err("there are no notice profiles".into()) } else { Ok(()) }
}

fn has_garden(s: &Session) -> std::result::Result<(), String> {
    if cfg(s).walled_garden.is_empty() { Err("the walled garden is empty".into()) } else { Ok(()) }
}

fn has_logins(s: &Session) -> std::result::Result<(), String> {
    if cfg(s).logins.is_empty() { Err("no login is sent to a notice profile".into()) } else { Ok(()) }
}

fn has_pages(s: &Session) -> std::result::Result<(), String> {
    if cfg(s).pages.is_empty() { Err("there are no pages (the built-in one is not editable: add one)".into()) } else { Ok(()) }
}

/// Write `next` if it is consistent (the whole section is checked: a
/// profile's page, duplicate lists).
fn commit(s: &mut Session, next: SubscriberNotices, key: &str) -> Result<()> {
    if let Some(why) = next.problem() {
        return Err(EngineError::bad(key, why));
    }
    s.store_mut().candidate_mut().ip.subscriber_notice = next;
    Ok(())
}

fn name_param(p: &Value, key: &str) -> Result<Option<Name>> {
    opt_str(p, key)?
        .map(|t| t.trim().parse::<Name>().map_err(|e| EngineError::bad(key, e.to_string())))
        .transpose()
}

fn find_by(p: &Value, items: impl Iterator<Item = (ItemId, String)>, what: &str) -> Result<usize> {
    let raw = req_str(p, "id")?.trim();
    let by_id = raw.starts_with('*').then(|| raw.parse::<ItemId>().ok()).flatten();
    let mut items = items;
    items
        .position(|(id, name)| by_id.map_or(name == raw, |b| b == id))
        .ok_or_else(|| EngineError::bad("id", format!("no {what} '{}'", raw.chars().take(64).collect::<String>())))
}

fn ip_param(p: &Value) -> Result<IpAddr> {
    req_parse::<IpAddr>(p, "address")
}

fn settings_print(s: &mut Session, _: &Value) -> Result<Value> {
    let st = &cfg(s).settings;
    Ok(json!({
        "port": st.port, "portal_host": st.portal_host, "capport_url": st.capport_url,
        "webhook_url": st.webhook_url, "probes": probes::hosts().len(),
    }))
}

fn url_ok(u: &str, https_only: bool) -> bool {
    let rest = u.strip_prefix("https://").or_else(|| if https_only { None } else { u.strip_prefix("http://") });
    rest.is_some_and(|r| {
        let host = r.split(['/', '?', '#']).next().unwrap_or_default();
        !host.is_empty() && !host.contains('@')
    }) && u.bytes().all(|b| b > b' ' && b != 0x7f)
}

fn settings_set(s: &mut Session, p: &Value) -> Result<Value> {
    let mut next = cfg(s).clone();
    let st = &mut next.settings;
    if let Some(port) = opt_u32(p, "port")? {
        st.port = u16::try_from(port).ok().filter(|v| *v > 0).ok_or_else(|| EngineError::bad("port", "1..65535"))?;
    }
    if let Some(h) = opt_text(p, "portal_host", 253)? {
        let h = h.trim();
        if !h.is_empty() && host_problem(h).is_some() && h.parse::<IpAddr>().is_err() {
            return Err(EngineError::bad("portal_host", "a domain name or an address"));
        }
        h.clone_into(&mut st.portal_host);
    }
    if let Some(u) = opt_text(p, "capport_url", 255)? {
        let u = u.trim();
        // RFC 8908 §4: the API URI MUST be https (and the client checks the
        // certificate against the name); RFC 8910 §2: no IP literal.
        if !u.is_empty() {
            if !url_ok(u, true) {
                return Err(EngineError::bad("capport_url", "https://name/path (RFC 8908 §4: the API is https only)"));
            }
            let host = u.trim_start_matches("https://").split(['/', ':', '?']).next().unwrap_or_default();
            if host.parse::<IpAddr>().is_ok() || host.starts_with('[') {
                return Err(EngineError::bad("capport_url", "a name, not an address (RFC 8910 §2; the certificate is for a name)"));
            }
        }
        u.clone_into(&mut st.capport_url);
    }
    if let Some(u) = opt_text(p, "webhook_url", 512)? {
        let u = u.trim();
        if !u.is_empty() && !url_ok(u, false) {
            return Err(EngineError::bad("webhook_url", "http:// or https:// with a host"));
        }
        u.clone_into(&mut st.webhook_url);
    }
    let port = st.port;
    commit(s, next, "port")?;
    Ok(json!({"port": port}))
}

fn opt_mode(p: &Value) -> Result<Option<Mode>> {
    opt_str(p, "mode")?
        .map(|t| Mode::parse(t).ok_or_else(|| EngineError::bad("mode", "block, notice or throttle")))
        .transpose()
}

fn apply_profile(pr: &mut Profile, p: &Value, sn: &SubscriberNotices, adding: bool) -> Result<()> {
    if let Some(n) = name_param(p, "name")? {
        pr.name = n;
    }
    let mode = opt_mode(p)?;
    if let Some(m) = mode {
        pr.mode = m;
    }
    let intercept = opt_str(p, "intercept")?
        .map(|t| Intercept::parse(t).ok_or_else(|| EngineError::bad("intercept", "probes or http")))
        .transpose()?;
    match (intercept, mode, adding) {
        (Some(i), _, _) => pr.intercept = i,
        (None, Some(m), true) => pr.intercept = Intercept::default_for(m),
        _ => {}
    }
    if let Some(l) = name_param(p, "address_list")? {
        pr.address_list = l;
    }
    if let Some(pg) = opt_text(p, "page", 63)? {
        let pg = pg.trim();
        if !pg.is_empty() && !sn.pages.iter().any(|x| x.name == pg) {
            return Err(EngineError::bad("page", format!("no page '{pg}' (add it first, or leave empty for the built-in one)")));
        }
        pg.clone_into(&mut pr.page);
    }
    if let Some(v) = opt_secs(p, "interval")? {
        if v == 0 {
            return Err(EngineError::bad("interval", "more than 0"));
        }
        pr.interval_secs = u64::from(v);
    }
    if let Some(v) = opt_secs(p, "timeout")? {
        pr.timeout_secs = u64::from(v);
    }
    if let Some(r) = super::ppp_common::opt_rate_limit(p)? {
        pr.rate_limit = r.unwrap_or_default();
    }
    if let Some(b) = opt_bool(p, "kill_connections")? {
        pr.kill_connections = b;
    }
    if let Some(b) = opt_bool(p, "webhook")? {
        pr.webhook = b;
    }
    if let Some(b) = opt_bool(p, "disabled")? {
        pr.disabled = b;
    }
    if let Some(c) = opt_text(p, "comment", 256)? {
        pr.comment = c;
    }
    Ok(())
}

fn profile_add(s: &mut Session, p: &Value) -> Result<Value> {
    let mut next = cfg(s).clone();
    if next.profiles.len() >= MAX_PROFILES {
        return Err(EngineError::bad("name", format!("at most {MAX_PROFILES} profiles")));
    }
    let name = name_param(p, "name")?.ok_or_else(|| EngineError::bad("name", "is required"))?;
    let mode = opt_mode(p)?.ok_or_else(|| EngineError::bad("mode", "is required (block, notice or throttle)"))?;
    let list = name_param(p, "address_list")?.ok_or_else(|| EngineError::bad("address_list", "is required"))?;
    if next.profile(name.as_str()).is_some() {
        return Err(EngineError::bad("name", format!("profile {name} exists")));
    }
    let mut pr = Profile::new(ItemId(0), name, mode, list);
    apply_profile(&mut pr, p, &next, true)?;
    pr.id = next.next_id();
    let id = pr.id;
    next.profiles.push(pr);
    commit(s, next, "address_list")?;
    Ok(json!({"id": id}))
}

fn profile_index(s: &Session, p: &Value) -> Result<usize> {
    find_by(p, cfg(s).profiles.iter().map(|x| (x.id, x.name.to_string())), "profile")
}

fn profile_set(s: &mut Session, p: &Value) -> Result<Value> {
    let i = profile_index(s, p)?;
    let mut next = cfg(s).clone();
    let sn = next.clone();
    let Some(pr) = next.profiles.get_mut(i) else { return Err(EngineError::bad("id", "gone")) };
    let old = pr.name.clone();
    apply_profile(pr, p, &sn, false)?;
    let (id, new) = (pr.id, pr.name.clone());
    if old != new {
        for l in &mut next.logins {
            if l.profile == old {
                l.profile = new.clone();
            }
        }
    }
    commit(s, next, "name")?;
    Ok(json!({"id": id}))
}

fn profile_remove(s: &mut Session, p: &Value) -> Result<Value> {
    let i = profile_index(s, p)?;
    let mut next = cfg(s).clone();
    let pr = next.profiles.remove(i);
    // Logins sent to it go back to normal.
    next.logins.retain(|l| l.profile != pr.name);
    commit(s, next, "id")?;
    Ok(json!({"id": pr.id}))
}

fn profile_print(s: &mut Session, _: &Value) -> Result<Value> {
    let members = s.notice_members();
    let rows: Vec<Value> = cfg(s)
        .profiles
        .iter()
        .map(|pr| {
            let n = members.iter().filter(|m| m.profile == pr.name.as_str()).count();
            json!({
                "id": pr.id, "name": pr.name, "mode": pr.mode.as_str(), "address_list": pr.address_list,
                "page": (!pr.page.is_empty()).then_some(&pr.page), "intercept": pr.intercept.as_str(),
                "interval": corerouter_model::subscriber_notice::duration(pr.interval_secs), "interval_secs": pr.interval_secs,
                "timeout": corerouter_model::subscriber_notice::duration(pr.timeout_secs), "timeout_secs": pr.timeout_secs,
                "rate_limit": (!pr.rate_limit.is_empty()).then_some(&pr.rate_limit),
                "kill_connections": pr.kill_connections, "webhook": pr.webhook, "disabled": pr.disabled,
                "comment": (!pr.comment.is_empty()).then_some(&pr.comment),
                "behaviour": pr.behaviour(), "members": n,
            })
        })
        .collect();
    Ok(Value::Array(rows))
}

fn apply_garden(g: &mut GardenEntry, p: &Value) -> Result<()> {
    if let Some(h) = opt_text(p, "dst_host", 253)? {
        let h = h.trim().trim_end_matches('.').to_ascii_lowercase();
        if !h.is_empty()
            && let Some(why) = host_problem(&h)
        {
            return Err(EngineError::bad("dst_host", why));
        }
        g.dst_host = h;
    }
    match opt_str(p, "dst_address")? {
        Some(t) if t.trim().is_empty() => g.dst_address = None,
        Some(t) => {
            let t = t.trim();
            let net = t
                .parse::<ipnet::IpNet>()
                .or_else(|_| t.parse::<IpAddr>().map(ipnet::IpNet::from))
                .map_err(|_| EngineError::bad("dst_address", "an address or prefix"))?;
            g.dst_address = Some(net.trunc());
        }
        None => {}
    }
    if let Some(b) = opt_bool(p, "disabled")? {
        g.disabled = b;
    }
    if let Some(c) = opt_text(p, "comment", 256)? {
        g.comment = c;
    }
    match (g.dst_host.is_empty(), g.dst_address.is_none()) {
        (true, true) => Err(EngineError::bad("dst_host", "needs dst_host or dst_address")),
        (false, false) => Err(EngineError::bad("dst_host", "dst_host or dst_address, not both")),
        _ => Ok(()),
    }
}

fn garden_add(s: &mut Session, p: &Value) -> Result<Value> {
    let mut next = cfg(s).clone();
    if next.walled_garden.len() >= MAX_GARDEN {
        return Err(EngineError::bad("dst_host", format!("at most {MAX_GARDEN} entries")));
    }
    let mut g = GardenEntry { id: ItemId(0), dst_host: String::new(), dst_address: None, disabled: false, comment: String::new() };
    apply_garden(&mut g, p)?;
    if next.walled_garden.iter().any(|x| x.dst_host == g.dst_host && x.dst_address == g.dst_address) {
        return Err(EngineError::bad("dst_host", "already in the walled garden"));
    }
    g.id = next.next_id();
    let id = g.id;
    next.walled_garden.push(g);
    commit(s, next, "dst_host")?;
    Ok(json!({"id": id}))
}

fn garden_index(s: &Session, p: &Value) -> Result<usize> {
    let id: ItemId = req_parse(p, "id")?;
    cfg(s).walled_garden.iter().position(|g| g.id == id).ok_or_else(|| EngineError::bad("id", format!("no entry {id}")))
}

fn garden_set(s: &mut Session, p: &Value) -> Result<Value> {
    let i = garden_index(s, p)?;
    let mut next = cfg(s).clone();
    let Some(g) = next.walled_garden.get_mut(i) else { return Err(EngineError::bad("id", "gone")) };
    apply_garden(g, p)?;
    let id = g.id;
    commit(s, next, "dst_host")?;
    Ok(json!({"id": id}))
}

fn garden_remove(s: &mut Session, p: &Value) -> Result<Value> {
    let i = garden_index(s, p)?;
    let mut next = cfg(s).clone();
    let g = next.walled_garden.remove(i);
    commit(s, next, "id")?;
    Ok(json!({"id": g.id}))
}

/// How many addresses the router resolved for the walled garden now.
fn garden_resolved(s: &Session) -> usize {
    let Ok(list) = corerouter_model::subscriber_notice::GARDEN_LIST.parse::<Name>() else { return 0 };
    s.dynamic_addresses.entries().iter().filter(|e| e.list == list).count()
}

fn garden_print(s: &mut Session, _: &Value) -> Result<Value> {
    let resolved: Vec<(String, usize)> = {
        let Ok(list) = corerouter_model::subscriber_notice::GARDEN_LIST.parse::<Name>() else { return Ok(json!([])) };
        let mut by: BTreeMap<String, usize> = BTreeMap::new();
        for e in s.dynamic_addresses.entries().iter().filter(|e| e.list == list) {
            *by.entry(e.comment.clone()).or_default() += 1;
        }
        by.into_iter().collect()
    };
    let rows: Vec<Value> = cfg(s)
        .walled_garden
        .iter()
        .map(|g| {
            let n = if g.dst_host.is_empty() {
                usize::from(!g.disabled)
            } else {
                resolved.iter().find(|(c, _)| *c == g.dst_host).map_or(0, |(_, n)| *n)
            };
            json!({
                "id": g.id, "dst_host": (!g.dst_host.is_empty()).then_some(&g.dst_host),
                "dst_address": g.dst_address.map(|n| n.to_string()), "disabled": g.disabled,
                "comment": (!g.comment.is_empty()).then_some(&g.comment), "addresses": n,
            })
        })
        .collect();
    Ok(Value::Array(rows))
}

fn apply_page(pg: &mut Page, p: &Value) -> Result<()> {
    if let Some(n) = opt_text(p, "name", 63)? {
        n.trim().clone_into(&mut pg.name);
    }
    if let Some(t) = opt_str(p, "text")? {
        if t.len() > MAX_TEXT {
            return Err(EngineError::bad("text", format!("at most {MAX_TEXT} bytes")));
        }
        // Newlines are the paragraphs; other controls never reach the page.
        pg.text = t.chars().filter(|c| *c == '\n' || !c.is_control()).collect();
    }
    for (key, slot) in [
        ("title", &mut pg.title),
        ("color", &mut pg.color),
        ("logo_url", &mut pg.logo_url),
        ("button_text", &mut pg.button_text),
        ("button_url", &mut pg.button_url),
        ("continue_text", &mut pg.continue_text),
        ("comment", &mut pg.comment),
    ] {
        if let Some(v) = opt_text(p, key, MAX_FIELD)? {
            *slot = v.trim().to_owned();
        }
    }
    if let Some(why) = pg.problem() {
        let key = why.split(':').next().filter(|k| ["name", "text", "title", "color", "logo_url"].contains(k)).unwrap_or("text").to_owned();
        return Err(EngineError::bad(&key, why));
    }
    Ok(())
}

fn page_add(s: &mut Session, p: &Value) -> Result<Value> {
    let mut next = cfg(s).clone();
    if next.pages.len() >= MAX_PAGES {
        return Err(EngineError::bad("name", format!("at most {MAX_PAGES} pages")));
    }
    req_str(p, "name")?;
    let mut pg = Page::builtin();
    apply_page(&mut pg, p)?;
    if pg.name == "default" || next.pages.iter().any(|x| x.name == pg.name) {
        return Err(EngineError::bad("name", format!("page {} exists", pg.name)));
    }
    pg.id = next.next_id();
    let id = pg.id;
    next.pages.push(pg);
    commit(s, next, "name")?;
    Ok(json!({"id": id}))
}

fn page_index(s: &Session, p: &Value) -> Result<usize> {
    find_by(p, cfg(s).pages.iter().map(|x| (x.id, x.name.clone())), "page")
}

fn page_set(s: &mut Session, p: &Value) -> Result<Value> {
    let i = page_index(s, p)?;
    let mut next = cfg(s).clone();
    let Some(pg) = next.pages.get_mut(i) else { return Err(EngineError::bad("id", "gone")) };
    let old = pg.name.clone();
    apply_page(pg, p)?;
    let (id, new) = (pg.id, pg.name.clone());
    if old != new {
        for pr in &mut next.profiles {
            if pr.page == old {
                pr.page.clone_from(&new);
            }
        }
    }
    commit(s, next, "name")?;
    Ok(json!({"id": id}))
}

fn page_remove(s: &mut Session, p: &Value) -> Result<Value> {
    let i = page_index(s, p)?;
    let mut next = cfg(s).clone();
    let pg = next.pages.remove(i);
    if let Some(pr) = next.profiles.iter().find(|x| x.page == pg.name) {
        return Err(EngineError::bad("id", format!("profile {} shows page {}", pr.name, pg.name)));
    }
    commit(s, next, "id")?;
    Ok(json!({"id": pg.id}))
}

fn page_print(s: &mut Session, _: &Value) -> Result<Value> {
    let sn = cfg(s);
    let rows: Vec<Value> = sn
        .pages
        .iter()
        .map(|pg| {
            let used: Vec<&str> = sn.profiles.iter().filter(|pr| pr.page == pg.name).map(|pr| pr.name.as_str()).collect();
            let mut v = serde_json::to_value(pg).unwrap_or_else(|_| json!({}));
            if let Some(o) = v.as_object_mut() {
                o.insert("used_by".into(), json!(used));
            }
            v
        })
        .collect();
    Ok(Value::Array(rows))
}

/// What the preview fills in without a subscriber.
fn sample(k: &str) -> Option<String> {
    Some(
        match k {
            "login" => "joao.silva",
            "plano" => "Fibra 300M",
            "valor" => "R$ 99,90",
            "vencimento" => "10/10/2026",
            "link_pix" => "https://pix.example/cobranca",
            "endereco" => "100.64.0.10",
            "perfil" => "atraso",
            _ => return None,
        }
        .to_owned(),
    )
}

/// The page variables of `ip` for its profile: the ISP's values over what
/// the router knows (login, address, profile).
pub(crate) fn vars_of(s: &Session, ip: IpAddr, profile: &str) -> BTreeMap<String, String> {
    let mut v = BTreeMap::new();
    v.insert("endereco".to_owned(), ip.to_string());
    v.insert("perfil".to_owned(), profile.to_owned());
    if let IpAddr::V4(a) = ip
        && let Some(sess) = s.ppp_active().into_iter().find(|x| x.address == Some(a))
    {
        v.insert("login".to_owned(), sess.name.clone());
        v.insert("plano".to_owned(), sess.profile.clone());
    }
    v.extend(s.notice_vars(ip));
    v
}

fn page_preview(s: &mut Session, p: &Value) -> Result<Value> {
    let sn = cfg(s).clone();
    let mut pg = match opt_str(p, "page")?.map(str::trim) {
        None | Some("" | "default") => Page::builtin(),
        Some(n) => sn.pages.iter().find(|x| x.name == n).cloned().ok_or_else(|| EngineError::bad("page", format!("no page '{n}'")))?,
    };
    let mut edit = p.clone();
    if let Some(o) = edit.as_object_mut() {
        o.remove("page");
        o.remove("address");
        o.remove("name");
    }
    // An edit that does not hold yet still previews; the problem says why.
    let problem = apply_page(&mut pg, &edit).err().map(|e| e.to_string());
    let address: Option<IpAddr> = opt_parse(p, "address")?;
    let vars = match address {
        Some(ip) => vars_of(s, ip, "preview"),
        None => BTreeMap::new(),
    };
    let lookup = |k: &str| vars.get(k).cloned().or_else(|| if address.is_none() { sample(k) } else { None });
    let html = render(&pg, &lookup, Some("#"));
    Ok(json!({"html": html, "problem": problem}))
}

fn single(a: &AddrMatch) -> Option<IpAddr> {
    match a {
        AddrMatch::Net(n) if n.prefix_len() == n.max_prefix_len() => Some(n.addr()),
        _ => None,
    }
}

fn active_list(s: &mut Session, p: &Value) -> Result<Value> {
    let profile = opt_text(p, "profile", 63)?;
    let find = opt_text(p, "find", 128)?.map(|f| f.to_lowercase());
    let limit = opt_u32(p, "limit")?.unwrap_or(10_000).clamp(1, 100_000) as usize;
    let now = s.now();
    let sn = s.store().running().ip.subscriber_notice.clone();
    let logins: BTreeMap<std::net::Ipv4Addr, String> =
        s.ppp_active().into_iter().filter_map(|a| Some((a.address?, a.name))).collect();
    let mut members: Vec<Member> = s.notice_members();
    if let Some(pr) = &profile {
        members.retain(|m| &m.profile == pr);
    }
    let mut rows = Vec::new();
    let mut total = 0usize;
    for m in members {
        let ip = single(&m.address);
        let login = match ip {
            Some(IpAddr::V4(a)) => logins.get(&a).cloned().unwrap_or_default(),
            _ => String::new(),
        };
        if let Some(f) = &find
            && !(m.address.to_string().contains(f.as_str()) || login.to_lowercase().contains(f.as_str()) || m.comment.to_lowercase().contains(f.as_str()))
        {
            continue;
        }
        total += 1;
        if rows.len() >= limit {
            continue;
        }
        let pr = sn.profile(&m.profile);
        let since = ip.and_then(|ip| s.notice_since(&pr.map(|x| x.name.clone())?, ip));
        let seen = match (pr, ip) {
            (Some(pr), Some(ip)) => s.notice_seen_at(pr, ip),
            _ => None,
        };
        rows.push(json!({
            "address": m.address.to_string(), "profile": m.profile, "mode": m.mode, "source": m.source,
            "comment": (!m.comment.is_empty()).then_some(&m.comment), "login": (!login.is_empty()).then_some(&login),
            "since": since, "since_secs_ago": since.zip(now).map(|(a, n)| n.saturating_sub(a)),
            "seen": seen.is_some(), "seen_secs_ago": seen.zip(now).map(|(a, n)| n.saturating_sub(a)),
        }));
    }
    Ok(json!({"total": total, "rows": rows}))
}

fn log_print(s: &mut Session, p: &Value) -> Result<Value> {
    let address: Option<IpAddr> = opt_parse(p, "address")?;
    let profile = opt_text(p, "profile", 63)?;
    let limit = opt_u32(p, "limit")?.unwrap_or(500).clamp(1, 10_000) as usize;
    let rows: Vec<Value> = s
        .notice_log()
        .into_iter()
        .rev()
        .filter(|v| address.is_none_or(|a| a == v.address))
        .filter(|v| profile.as_ref().is_none_or(|pr| *pr == v.profile))
        .take(limit)
        .filter_map(|v| serde_json::to_value(v).ok())
        .collect();
    Ok(Value::Array(rows))
}

fn seen(s: &mut Session, p: &Value) -> Result<Value> {
    let ip = ip_param(p)?;
    let via = opt_text(p, "via", 32)?.unwrap_or_else(|| "browser".into());
    let ua = opt_str(p, "user_agent")?.unwrap_or_default().chars().take(512).collect::<String>();
    let pr = s
        .notice_mark_seen(ip, via.trim(), &ua)
        .ok_or_else(|| EngineError::bad("address", format!("{ip} is under no notice profile")))?;
    let until = (pr.mode != Mode::Block).then(|| s.now().map(|n| n.saturating_add(pr.interval_secs))).flatten();
    Ok(json!({"profile": pr.name, "mode": pr.mode.as_str(), "until": until}))
}

fn vars_set(s: &mut Session, p: &Value) -> Result<Value> {
    let ip = ip_param(p)?;
    let Some(Value::Object(o)) = p.get("vars") else {
        return Err(EngineError::bad("vars", "an object, {\"valor\": \"R$ 99,90\"}"));
    };
    let mut vars = BTreeMap::new();
    for (k, v) in o {
        if !VARS.contains(&k.as_str()) || matches!(k.as_str(), "endereco" | "perfil") {
            return Err(EngineError::bad("vars", format!("unknown variable '{}' (set: login, plano, valor, vencimento, link_pix)", k.chars().take(32).collect::<String>())));
        }
        let Value::String(t) = v else {
            return Err(EngineError::bad("vars", format!("{k}: a string")));
        };
        if t.len() > MAX_VAR_LEN || t.chars().any(char::is_control) {
            return Err(EngineError::bad("vars", format!("{k}: at most {MAX_VAR_LEN} bytes, no control characters")));
        }
        vars.insert(k.clone(), t.clone());
    }
    s.notice_set_vars(ip, vars.clone()).map_err(|e| EngineError::bad("address", e))?;
    Ok(json!({"address": ip, "vars": vars}))
}

fn vars_print(s: &mut Session, p: &Value) -> Result<Value> {
    let ip = ip_param(p)?;
    Ok(json!({"address": ip, "vars": s.notice_vars(ip)}))
}

fn test(s: &mut Session, p: &Value) -> Result<Value> {
    let ip = ip_param(p)?;
    let sn = s.store().running().ip.subscriber_notice.clone();
    let mut warnings: Vec<String> = Vec::new();
    let garden = garden_resolved(s) + sn.walled_garden.iter().filter(|g| !g.disabled && g.dst_address.is_some()).count();
    let Some((pr, source)) = s.notice_profile_of(ip) else {
        if sn.active().next().is_none() {
            warnings.push("no enabled notice profile".into());
        }
        return Ok(json!({
            "address": ip, "seen": false, "dns": true, "portal": false, "https": "passes",
            "probes": probe_rows(false), "walled_garden": garden, "warnings": warnings,
        }));
    };
    let seen = pr.mode != Mode::Block && s.notice_seen_at(&pr, ip).is_some();
    let caught = !seen;
    if pr.mode == Mode::Block && garden == 0 {
        warnings.push("the walled garden is empty: a blocked subscriber reaches only the portal (add the ISP's site and the payment pages)".into());
    }
    if pr.intercept == Intercept::Probes && caught {
        let probe_list: Option<Name> = corerouter_model::subscriber_notice::PROBE_LIST.parse().ok();
        let resolved = probe_list.is_some_and(|l| s.dynamic_addresses.entries().iter().any(|e| e.list == l));
        if !resolved {
            warnings.push("the probe hosts are not resolved yet (the daemon's notice service resolves them through the router's DNS)".into());
        }
    }
    // The portal answers on the router: an input rule that drops the
    // subscriber's SYN to the port takes the page away.
    let dynamic: Vec<_> = {
        let now = s.now();
        s.dynamic_addresses.entries().iter().map(|e| e.data_plane(now)).collect()
    };
    let cfg = s.store().running();
    let router = cfg.ip.addresses.iter().find(|a| a.address.contains(&ip)).map(|a| a.address.addr());
    let syn = Packet {
        src: ip,
        dst: router.unwrap_or(ip),
        protocol: Protocol(6),
        src_port: Some(40_000),
        dst_port: Some(sn.settings.port),
        icmp: None,
        in_interface: None,
        out_interface: None,
        state: ConnState::New,
    };
    let out = eval::walk(cfg, &dynamic, Table::Filter, "input", &syn);
    if out.verdict.blocks() {
        warnings.push(format!(
            "filter input rule {} {} the subscriber's connection to the portal (port {}): allow it above that rule",
            out.rule.map(|r| r.to_string()).unwrap_or_default(),
            if out.verdict == eval::Verdict::Drop { "drops" } else { "rejects" },
            sn.settings.port
        ));
    }
    if pr.mode == Mode::Throttle && pr.rate_limit.is_empty() {
        warnings.push("throttle without rate_limit".into());
    }
    if IpAddr::is_ipv6(&ip) && sn.settings.capport_url.is_empty() {
        // Nothing to warn: IPv6 probes are caught the same way.
    }
    Ok(json!({
        "address": ip, "profile": pr.name, "mode": pr.mode.as_str(), "source": source, "seen": seen, "dns": true,
        "portal": caught && (pr.intercept == Intercept::Http || pr.mode == Mode::Block),
        "https": if pr.mode == Mode::Block { "refused" } else { "passes" },
        "probes": probe_rows(caught), "walled_garden": garden, "warnings": warnings,
    }))
}

fn probe_rows(caught: bool) -> Vec<Value> {
    probes::PROBES
        .iter()
        .map(|pb| json!({"os": pb.os, "host": pb.host, "path": pb.path, "expects": pb.expects, "answer": if caught { "redirect" } else { "passes" }}))
        .collect()
}

fn opt_profile(s: &Session, p: &Value) -> Result<Option<Profile>> {
    match opt_str(p, "profile")?.map(str::trim) {
        None | Some("" | "none") => Ok(None),
        Some(n) => s
            .store()
            .candidate()
            .ip
            .subscriber_notice
            .profile(n)
            .cloned()
            .map(Some)
            .ok_or_else(|| EngineError::bad("profile", format!("no notice profile '{}'", n.chars().take(63).collect::<String>()))),
    }
}

fn lease_notice(s: &mut Session, p: &Value) -> Result<Value> {
    let ip: std::net::Ipv4Addr = req_parse(p, "address")?;
    let pr = opt_profile(s, p)?;
    let lists: Vec<Name> = s.store().candidate().ip.subscriber_notice.profiles.iter().map(|x| x.address_list.clone()).collect();
    let dhcp = &s.store().candidate().ip.dhcp_server;
    let Some(i) = dhcp.leases.iter().position(|l| l.address == ip) else {
        return Err(EngineError::bad("address", format!("no static lease {ip} (make the dynamic one static first)")));
    };
    let dhcp = &mut s.store_mut().candidate_mut().ip.dhcp_server;
    let Some(l) = dhcp.leases.get_mut(i) else { return Err(EngineError::bad("address", "gone")) };
    l.address_lists.retain(|n| !lists.contains(n));
    if let Some(pr) = &pr {
        l.address_lists.push(pr.address_list.clone());
    }
    let out = json!({"id": l.id, "address": ip, "address_lists": l.address_lists});
    Ok(out)
}

fn secret_notice(s: &mut Session, p: &Value) -> Result<Value> {
    let name = opt_text(p, "name", 128)?.ok_or_else(|| EngineError::bad("name", "is required"))?;
    let name = name.trim().to_owned();
    if name.is_empty() {
        return Err(EngineError::bad("name", "is required"));
    }
    let pr = opt_profile(s, p)?;
    let mut warnings = Vec::new();
    if s.store().candidate().ppp.secrets.by_name(&name).is_none() {
        warnings.push(format!("no local secret '{name}': it applies when a session of that login comes up (RADIUS)"));
    }
    let mut next = cfg(s).clone();
    next.logins.retain(|l| l.login != name);
    if let Some(pr) = &pr {
        if next.logins.len() >= MAX_LOGINS {
            return Err(EngineError::bad("name", format!("at most {MAX_LOGINS} logins")));
        }
        next.logins.push(Login { login: name.clone(), profile: pr.name.clone() });
    }
    commit(s, next, "profile")?;
    Ok(json!({"name": name, "profile": pr.map(|x| x.name), "warnings": warnings}))
}

fn login_add(s: &mut Session, p: &Value) -> Result<Value> {
    if opt_str(p, "profile")?.is_none_or(|t| t.trim().is_empty()) {
        return Err(EngineError::bad("profile", "is required"));
    }
    secret_notice(s, p)
}

fn login_remove(s: &mut Session, p: &Value) -> Result<Value> {
    let name = req_str(p, "name")?.trim().to_owned();
    if !cfg(s).logins.iter().any(|l| l.login == name) {
        return Err(EngineError::bad("name", format!("login '{}' is under no notice profile", name.chars().take(64).collect::<String>())));
    }
    let mut next = cfg(s).clone();
    next.logins.retain(|l| l.login != name);
    commit(s, next, "name")?;
    Ok(json!({"name": name}))
}

fn login_print(s: &mut Session, _: &Value) -> Result<Value> {
    Ok(Value::Array(cfg(s).logins.iter().map(|l| json!({"name": l.login, "profile": l.profile})).collect()))
}
