//! `ppp.secret.import` (G4.3n): the subscribers of a RouterOS export, with
//! their passwords, in one command.
//!
//! The text is `/ppp secret export show-sensitive` (or a whole `/export
//! show-sensitive`) from RouterOS v7, or our own `/export show-sensitive`.
//! RouterOS leaves the passwords out of an export without
//! `show-sensitive`, silently: the preview counts the secrets without one.
//! Read by `crate::rsc` (hostile text: bounded, errors never quote it).
//!
//! One command is one change: in immediate mode one revision, in
//! transactional mode one more pending change, and under Safe Mode it is
//! undone with the rest. `dry_run` answers the same report and changes
//! nothing. The text is masked in the journal (`auth::mask_params`), the
//! passwords are sealed (`crate::sealing`) and the report has none.
//!
//! Profiles: a secret's profile is looked up through `profile_map` first
//! (RouterOS name → ours), then by its own name; one the file defines
//! (`/ppp profile add`) and we lack is created from it (`create_profiles`,
//! default yes); any other is reported missing and stops the import.

use std::collections::{BTreeMap, HashMap, HashSet};

use corerouter_model::MacAddr;
use corerouter_model::framed_route::{FramedRoute, overlaps};
use corerouter_model::ppp::{DEFAULT_PROFILE, MAX_NAME, MAX_SECRETS, PppSecret};
use serde_json::{Map, Value, json};

use super::args::{opt_bool, opt_str, req_str};
use super::{CommandSpec, always};
use crate::rsc::{self, Item, Target, Verb};
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[cmd!(
    "ppp.secret.import", "Import PPP Secrets", [], None,
    "{text: string (a RouterOS export: /ppp secret export show-sensitive, or a whole /export show-sensitive; at most 32 MiB, 16 MiB over the control channel; masked in the journal), profile_map?: {<routeros profile>: string} (a RouterOS profile and the one of ours its secrets get), on_conflict?: skip|replace|rename (a name that exists here; default skip; rename adds -2, -3…), create_profiles?: bool (create the profiles the file defines and we lack; default true), dry_run?: bool (only the report)} → {dry_run, total (secrets in the file), profiles: [{name (as in the file), count (secrets that use it), here (we have it), in_file (the file defines it), target (where its secrets go, empty: missing)}], with_password, without_password: {count, names}, profiles_in_file, profiles_created, missing_profiles, conflicts: {count, names}, added, replaced, renamed: [{from, to}], skipped, duplicates, set_unknown, unsupported: {<field>: count}, errors: [{line, name?, param?, message}], warnings, ignored_lines, reminder}",
    always, import
)];

/// Most names, errors and warnings listed in the report (counts are exact).
const MAX_LISTED: usize = 100;

const REMINDER: &str = "the export file holds every subscriber's password in clear: delete it (and its copies) now";

/// RouterOS `/ppp secret` fields → `ppp.secret.add` parameters.
const SECRET_FIELDS: &[(&str, &str)] = &[
    ("name", "name"),
    ("service", "service"),
    ("profile", "profile"),
    ("local-address", "local_address"),
    ("remote-address", "remote_address"),
    ("caller-id", "caller_id"),
    ("limit-bytes-in", "limit_bytes_in"),
    ("limit-bytes-out", "limit_bytes_out"),
    ("comment", "comment"),
    ("disabled", "disabled"),
    ("routes", "routes"),
];

/// RouterOS `/ppp profile` fields → `ppp.profile.add` parameters.
const PROFILE_FIELDS: &[(&str, &str)] = &[
    ("name", "name"),
    ("local-address", "local_address"),
    ("remote-address", "remote_address"),
    ("dns-server", "dns_server"),
    ("rate-limit", "rate_limit"),
    ("address-list", "address_list"),
    ("only-one", "only_one"),
    ("change-tcp-mss", "change_tcp_mss"),
    ("idle-timeout", "idle_timeout"),
    ("session-timeout", "session_timeout"),
    ("comment", "comment"),
    ("use-ipv6", "use_ipv6"),
    ("remote-ipv6-prefix-pool", "remote_ipv6_prefix_pool"),
    ("dhcpv6-pd-pool", "dhcpv6_pd_pool"),
    ("dhcpv6-lease-time", "dhcpv6_lease_time"),
    ("dns-server-ipv6", "dns_server_ipv6"),
];

/// Values RouterOS writes for its built-in profiles' defaults and that
/// mean "not set" here.
fn unset(v: &str) -> bool {
    v.is_empty() || v == "none"
}

/// Does `ppp.secret.add` take `key` (`routes` arrives with G4.3cd)?
fn add_takes(key: &str) -> bool {
    super::find("ppp.secret.add")
        .is_some_and(|c| super::doc_keys(c.params).iter().any(|(k, _)| *k == key))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OnConflict {
    Skip,
    Replace,
    Rename,
}

/// One secret of the file, its `set` lines merged in.
struct Entry {
    line: usize,
    item: Item,
}

#[derive(Default)]
struct Report {
    errors: Vec<Value>,
    errors_total: usize,
    warnings: Vec<String>,
    warnings_total: usize,
    unsupported: BTreeMap<String, usize>,
}

impl Report {
    fn error(&mut self, line: usize, name: Option<&str>, e: &EngineError) {
        self.errors_total += 1;
        if self.errors.len() >= MAX_LISTED {
            return;
        }
        let mut v = json!({"line": line});
        if let Some(o) = v.as_object_mut() {
            if let Some(n) = name {
                o.insert("name".into(), json!(clip(n)));
            }
            match e {
                EngineError::BadParam { param, reason } => {
                    o.insert("param".into(), json!(param));
                    o.insert("message".into(), json!(reason));
                }
                other => {
                    o.insert("message".into(), json!(other.to_string()));
                }
            }
        }
        self.errors.push(v);
    }

    fn warn(&mut self, w: String) {
        self.warnings_total += 1;
        if self.warnings.len() < MAX_LISTED {
            self.warnings.push(w);
        }
    }
}

fn clip(s: &str) -> String {
    s.chars().take(MAX_NAME).collect()
}

fn listed<'a>(names: impl Iterator<Item = &'a str>) -> Value {
    Value::from(names.take(MAX_LISTED).map(clip).collect::<Vec<_>>())
}

/// `yes`/`no` (and `true`/`false`) as RouterOS writes them.
fn bool_of(v: &str) -> Option<bool> {
    match v {
        "yes" | "true" => Some(true),
        "no" | "false" => Some(false),
        _ => None,
    }
}

/// The `ppp.profile.add` parameters of a profile of the file.
fn profile_params(item: &Item, report: &mut Report) -> Value {
    let mut o = Map::new();
    for (k, v) in &item.args {
        match PROFILE_FIELDS.iter().find(|(rk, _)| rk == k) {
            Some((_, ours)) => {
                if !unset(v) || *ours == "name" {
                    o.insert((*ours).into(), Value::from(v.as_str()));
                }
            }
            None => *report.unsupported.entry(format!("profile {}", clip(k))).or_default() += 1,
        }
    }
    Value::Object(o)
}

/// The `ppp.secret.add` parameters of a secret of the file (without the
/// password: sealed apart), `profile` already mapped.
fn secret_params(e: &Entry, profile: &str, routes: bool, report: &mut Report) -> Value {
    let mut o = Map::new();
    let name = e.item.get("name").unwrap_or_default();
    for (k, v) in &e.item.args {
        let Some((_, ours)) = SECRET_FIELDS.iter().find(|(rk, _)| rk == k) else {
            if k != "password" {
                *report.unsupported.entry(clip(k)).or_default() += 1;
            }
            continue;
        };
        let value = match *ours {
            "profile" => continue,
            "routes" if !routes => {
                *report.unsupported.entry("routes".into()).or_default() += 1;
                continue;
            }
            "disabled" => match bool_of(v) {
                Some(b) => Value::from(b),
                None => Value::from(v.as_str()),
            },
            "limit_bytes_in" | "limit_bytes_out" => match v.parse::<u64>() {
                Ok(n) => Value::from(n),
                Err(_) => Value::from(v.as_str()),
            },
            "caller_id" if !v.is_empty() && v.parse::<MacAddr>().is_err() => {
                report.warn(format!(
                    "secret {}: caller-id is not a MAC (only PPPoE's caller-id is kept here): dropped",
                    clip(name)
                ));
                continue;
            }
            "local_address" | "remote_address" | "routes" if v.is_empty() => continue,
            _ => Value::from(v.as_str()),
        };
        o.insert((*ours).into(), value);
    }
    o.insert("profile".into(), Value::from(profile));
    Value::Object(o)
}

/// G4.3cd's checks of `ppp.secret.add` for an imported secret: its routes
/// against the config (`check_routes`) and against the other secrets of
/// the file, and its fixed address outside anyone else's routed block.
/// `file_name`: its name in the file (before a rename).
fn routes_ok(
    s: &Session,
    x: &PppSecret,
    file_name: &str,
    file_routes: &[(ipnet::IpNet, &str)],
    report: &mut Report,
) -> Result<()> {
    if !x.routes.is_empty() {
        for w in super::ppp_secret::check_routes(s, x)? {
            report.warn(format!("secret {}: {w}", clip(&x.name)));
        }
        for r in &x.routes {
            if let Some((n, other)) = file_routes.iter().find(|(n, o)| *o != file_name && overlaps(n, &r.dst)) {
                return Err(EngineError::bad(
                    "routes",
                    format!("{} overlaps {n}, routed to secret {} in the file", r.dst, clip(other)),
                ));
            }
        }
    }
    if let Some(ip) = x.remote_address {
        let host = ipnet::IpNet::from(std::net::IpAddr::V4(ip));
        let cand = s.store().candidate();
        if let Some((n, o)) = cand.ppp.secrets.route_owners(&host).into_iter().find(|(_, o)| o.id != x.id) {
            return Err(EngineError::bad("remote_address", format!("{ip} is inside {n}, routed to secret {}", clip(&o.name))));
        }
        if let Some((n, other)) = file_routes.iter().find(|(n, o)| *o != file_name && n.contains(&host)) {
            return Err(EngineError::bad(
                "remote_address",
                format!("{ip} is inside {n}, routed to secret {} in the file", clip(other)),
            ));
        }
    }
    Ok(())
}

/// A free name: `name-2`, `name-3`…
fn renamed(name: &str, taken: &dyn Fn(&str) -> bool) -> Option<String> {
    (2..10_000).map(|i| format!("{name}-{i}")).find(|n| n.len() <= MAX_NAME && !taken(n))
}

fn import(s: &mut Session, p: &Value) -> Result<Value> {
    let text = req_str(p, "text")?;
    let dry_run = opt_bool(p, "dry_run")?.unwrap_or(false);
    let create = opt_bool(p, "create_profiles")?.unwrap_or(true);
    let on_conflict = match opt_str(p, "on_conflict")?.unwrap_or("skip") {
        "skip" => OnConflict::Skip,
        "replace" => OnConflict::Replace,
        "rename" => OnConflict::Rename,
        _ => return Err(EngineError::bad("on_conflict", "skip, replace or rename")),
    };
    let mut map: HashMap<String, String> = HashMap::new();
    match p.get("profile_map") {
        None | Some(Value::Null) => {}
        Some(Value::Object(o)) => {
            if o.len() > corerouter_model::ppp::MAX_PROFILES {
                return Err(EngineError::bad("profile_map", "too many entries"));
            }
            for (k, v) in o {
                let to = v
                    .as_str()
                    .ok_or_else(|| EngineError::bad("profile_map", "values are profile names"))?;
                map.insert(k.clone(), to.trim().to_owned());
            }
        }
        Some(_) => return Err(EngineError::bad("profile_map", "an object {routeros: ours}")),
    }
    // A dry run puts back what it made (the profiles it checked).
    let before = dry_run.then(|| s.store().candidate().clone());
    let script = rsc::parse(text, |m| m == "ppp secret" || m == "ppp profile")
        .map_err(|e| EngineError::bad("text", e.to_string()))?;
    let mut report = Report::default();

    // The file's profiles (`add`, then its `set [ find name=… ]` merged).
    let mut file_profiles: Vec<Item> = Vec::new();
    let mut entries: Vec<Entry> = Vec::new();
    let mut by_name: HashMap<String, usize> = HashMap::new();
    let mut duplicates = 0usize;
    let mut set_unknown = 0usize;
    for item in script.items {
        match (item.menu.as_str(), &item.verb, &item.target) {
            ("ppp profile", Verb::Add, _) => file_profiles.push(item),
            ("ppp profile", Verb::Set, Some(Target::Name(n))) => {
                match file_profiles.iter_mut().find(|f| f.get("name") == Some(n.as_str())) {
                    Some(f) => f.args.extend(item.args),
                    // A built-in's settings (`set [ find default=yes ]`)
                    // or one of a profile defined elsewhere: ours stay.
                    None => set_unknown += 1,
                }
            }
            ("ppp profile", _, _) => set_unknown += 1,
            (_, Verb::Add, _) => {
                let Some(name) = item.get("name").map(str::to_owned) else {
                    report.error(item.line, None, &EngineError::bad("name", "is required"));
                    continue;
                };
                if by_name.contains_key(&name) {
                    duplicates += 1;
                    report.warn(format!("secret {} appears twice in the file: the first is kept", clip(&name)));
                    continue;
                }
                by_name.insert(name, entries.len());
                entries.push(Entry { line: item.line, item });
            }
            (_, Verb::Set, Some(Target::Name(n))) => match by_name.get(n).and_then(|&i| entries.get_mut(i)) {
                Some(e) => e.item.args.extend(item.args),
                None => set_unknown += 1,
            },
            (_, Verb::Set, _) => set_unknown += 1,
        }
    }
    if entries.len() > MAX_SECRETS {
        return Err(EngineError::bad("text", format!("more than {MAX_SECRETS} secrets")));
    }

    // Profiles: mapped, ours, from the file, or missing.
    let ours = |s: &Session, n: &str| s.store().candidate().ppp.profile(n).is_some();
    for (from, to) in &map {
        let from_file = file_profiles.iter().any(|f| f.get("name") == Some(to.as_str()));
        if !ours(s, to) && !(create && from_file) {
            report.error(0, None, &EngineError::bad(
                "profile_map",
                format!("{} → {}: no profile '{}' here (ppp.profile.add)", clip(from), clip(to), clip(to)),
            ));
        }
    }
    let target_of = |n: &str| map.get(n).cloned().unwrap_or_else(|| n.to_owned());
    let mut needed: Vec<String> = Vec::new();
    let mut seen = HashSet::new();
    for e in &entries {
        let t = target_of(e.item.get("profile").filter(|p| !p.is_empty()).unwrap_or(DEFAULT_PROFILE));
        if seen.insert(t.clone()) {
            needed.push(t);
        }
    }
    // Each profile the file's secrets name, for the mapping (by name).
    let mut used: BTreeMap<String, usize> = BTreeMap::new();
    for e in &entries {
        let p = e.item.get("profile").filter(|p| !p.is_empty()).unwrap_or(DEFAULT_PROFILE);
        *used.entry(p.to_owned()).or_default() += 1;
    }
    let existed: HashSet<&str> = used.keys().filter(|n| ours(s, n)).map(String::as_str).collect();
    let mut missing = Vec::new();
    let mut created = Vec::new();
    let mut profiles_ok: HashSet<String> = HashSet::new();
    for t in needed {
        if ours(s, &t) {
            profiles_ok.insert(t);
            continue;
        }
        match file_profiles.iter().find(|f| f.get("name") == Some(t.as_str())) {
            Some(f) if create => {
                let params = profile_params(f, &mut report);
                match super::ppp_profile::add(s, &params) {
                    Ok(_) => {
                        created.push(t.clone());
                        profiles_ok.insert(t);
                    }
                    Err(e) => report.error(f.line, Some(&t), &e),
                }
            }
            _ => missing.push(t),
        }
    }

    // Secrets.
    let key = crate::sealing::key(s).map_err(EngineError::Internal)?;
    let routes = add_takes("routes");
    let (mut added, mut replaced, mut skipped) = (0usize, 0usize, 0usize);
    let mut renames: Vec<Value> = Vec::new();
    let mut conflicts: Vec<&str> = Vec::new();
    let mut conflicts_total = 0usize;
    let mut no_password: Vec<&str> = Vec::new();
    let mut no_password_total = 0usize;
    let mut replacements: HashMap<String, PppSecret> = HashMap::new();
    let mut fresh: Vec<PppSecret> = Vec::new();
    let mut new_names: HashSet<String> = HashSet::new();
    // Fixed addresses handed out twice (the per-secret check of `add` is
    // a walk of the list: quadratic for 100 000 imports).
    let mut fixed: HashMap<std::net::Ipv4Addr, String> = s
        .store()
        .candidate()
        .ppp
        .secrets
        .iter()
        .filter_map(|x| x.remote_address.map(|ip| (ip, x.name.clone())))
        .collect();
    // G4.3cd: the blocks the file routes, each with its secret, to check
    // the file against itself (`add` checks against the config only). A
    // few per thousand subscribers: the walk per secret stays short.
    let file_routes: Vec<(ipnet::IpNet, &str)> = if routes {
        entries
            .iter()
            .filter_map(|e| Some((e.item.get("name")?, e.item.get("routes")?)))
            .filter_map(|(n, r)| Some((n, FramedRoute::parse_list(r).ok()?)))
            .flat_map(|(n, rs)| rs.into_iter().map(move |r| (r.dst, n)))
            .collect()
    } else {
        Vec::new()
    };
    for e in &entries {
        let name = e.item.get("name").unwrap_or_default();
        let profile = target_of(e.item.get("profile").filter(|p| !p.is_empty()).unwrap_or(DEFAULT_PROFILE));
        if !profiles_ok.contains(&profile) {
            continue;
        }
        let params = secret_params(e, &profile, routes, &mut report);
        let mut x = PppSecret {
            profile: DEFAULT_PROFILE.into(),
            ..PppSecret::default()
        };
        if let Err(err) = super::ppp_secret::apply(s, &mut x, &params) {
            report.error(e.line, Some(name), &err);
            continue;
        }
        let password = match super::ppp_secret::password_of(&json!({"password": e.item.get("password")})) {
            Ok(pw) => pw.unwrap_or_default().to_owned(),
            Err(err) => {
                report.error(e.line, Some(name), &err);
                continue;
            }
        };
        if password.is_empty() && x.service != corerouter_model::ppp::PppService::Ipoe {
            no_password_total += 1;
            if no_password.len() < MAX_LISTED {
                no_password.push(name);
            }
        }
        x.password = key.seal(&password).map_err(EngineError::Internal)?;
        let exists = s.store().candidate().ppp.secret(&x.name).is_some();
        if exists {
            conflicts_total += 1;
            if conflicts.len() < MAX_LISTED {
                conflicts.push(name);
            }
            match on_conflict {
                OnConflict::Skip => {
                    skipped += 1;
                    continue;
                }
                OnConflict::Replace => {}
                OnConflict::Rename => {
                    let cand = s.store().candidate();
                    let taken = |n: &str| {
                        cand.ppp.secret(n).is_some() || by_name.contains_key(n) || new_names.contains(n)
                    };
                    let Some(n) = renamed(&x.name, &taken) else {
                        report.error(e.line, Some(name), &EngineError::bad("name", "no free name to rename it to"));
                        continue;
                    };
                    renames.push(json!({"from": clip(&x.name), "to": n}));
                    x.name = n;
                }
            }
        }
        if exists && on_conflict == OnConflict::Replace {
            // Checked as the secret it replaces (its own routes are no clash).
            x.id = s.store().candidate().ppp.secret(&x.name).map_or(x.id, |o| o.id);
        }
        if let Err(err) = routes_ok(s, &x, name, &file_routes, &mut report) {
            report.error(e.line, Some(name), &err);
            continue;
        }
        if let Some(ip) = x.remote_address {
            match fixed.get(&ip) {
                Some(other) if *other != x.name => report.warn(format!(
                    "remote_address {ip} of secret {} is also the address of secret {}",
                    clip(&x.name),
                    clip(other)
                )),
                _ => {
                    fixed.insert(ip, x.name.clone());
                }
            }
        }
        if exists && on_conflict == OnConflict::Replace {
            replaced += 1;
            replacements.insert(x.name.clone(), x);
        } else {
            added += 1;
            new_names.insert(x.name.clone());
            fresh.push(x);
        }
    }
    if !missing.is_empty() {
        report.error(0, None, &EngineError::bad(
            "profile_map",
            format!(
                "profiles missing here: {} (map them with profile_map, or create them first)",
                missing.iter().take(20).map(|m| clip(m)).collect::<Vec<_>>().join(", ")
            ),
        ));
    }
    let total = s.store().candidate().ppp.secrets.len() + fresh.len();
    if total > MAX_SECRETS {
        report.error(0, None, &EngineError::bad("text", format!("at most {MAX_SECRETS} secrets (use RADIUS)")));
    }

    let profiles: Vec<Value> = used
        .iter()
        .take(MAX_LISTED * 10)
        .map(|(name, n)| {
            let t = target_of(name);
            json!({
                "name": clip(name),
                "count": n,
                "here": existed.contains(name.as_str()),
                "in_file": file_profiles.iter().any(|f| f.get("name") == Some(name.as_str())),
                "target": if profiles_ok.contains(&t) { clip(&t) } else { String::new() },
            })
        })
        .collect();
    let out = json!({
        "dry_run": dry_run,
        "total": entries.len(),
        "profiles": profiles,
        "with_password": entries.len().saturating_sub(no_password_total),
        "without_password": {"count": no_password_total, "names": listed(no_password.into_iter())},
        "profiles_in_file": listed(file_profiles.iter().filter_map(|f| f.get("name"))),
        "profiles_created": created,
        "missing_profiles": missing,
        "conflicts": {"count": conflicts_total, "names": listed(conflicts.into_iter())},
        "on_conflict": match on_conflict { OnConflict::Skip => "skip", OnConflict::Replace => "replace", OnConflict::Rename => "rename" },
        "added": added,
        "replaced": replaced,
        "renamed": renames,
        "skipped": skipped,
        "duplicates": duplicates,
        "set_unknown": set_unknown,
        "unsupported": report.unsupported,
        "errors": report.errors,
        "errors_total": report.errors_total,
        "warnings": report.warnings,
        "warnings_total": report.warnings_total,
        "ignored_lines": script.ignored + script.other_menus,
        "reminder": REMINDER,
    });
    if let Some(before) = before {
        s.store_mut().set_candidate(before);
        return Ok(out);
    }
    if report.errors_total > 0 {
        let first = report
            .errors
            .first()
            .and_then(|e| e.get("message"))
            .and_then(Value::as_str)
            .unwrap_or("");
        return Err(EngineError::bad(
            "text",
            format!(
                "{} error(s), nothing imported (dry_run=yes lists them); first: {first}",
                report.errors_total
            ),
        ));
    }
    let ppp = &mut s.store_mut().candidate_mut().ppp;
    // In place, keeping the indexes (G4.3gb): only the touched blocks of
    // the list are copied.
    for (name, mut new) in replacements {
        let Some(old) = ppp.secrets.by_name(&name).map(|o| o.id) else {
            continue;
        };
        if let Some(i) = ppp.secrets.position(old) {
            new.id = old;
            ppp.secrets.update(i, |x| *x = new);
        }
    }
    for mut x in fresh {
        x.id = ppp.next_id();
        ppp.secrets.push(x);
    }
    Ok(out)
}
