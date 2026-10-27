//! Ready-made firewall (G2.1b): the safe initial configuration and the
//! templates. Each one writes ordinary rules through the same `add` the
//! rule commands use (same validation, same errors), with a comment in
//! Portuguese saying what the rule is for; afterwards they are normal rules
//! the operator edits, moves or removes. One command = one commit, so the
//! lockout check sees the whole template at once.

use corerouter_model::cow_list::CowList;
use corerouter_model::firewall::{Action, AddrMatch, FirewallRule, Limit, Name, PortSet, Table, Timeout};
use corerouter_model::{Config, IfName, ItemId};
use serde_json::{Map, Value, json};

use super::args::{opt_bool, opt_names, opt_parse, opt_text, req_parse};
use super::firewall::{add, al_add};
use super::interface_list::member_add;
use super::{CommandSpec, always};
use crate::lockout::take_force;
use crate::{EngineError, Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(
        "ip.firewall.defaults.apply",
        "Safe Defaults",
        ["IP", "Firewall"],
        None,
        "{lan?: [interface] (added to list LAN), wan?: [interface] (added to list WAN), replace?: bool (remove the rules of an earlier apply, comment defconf…, first), force?: bool} → {rules: [*hex], lan: [interface], wan: [interface]}",
        always,
        defaults_apply
    ),
    cmd!(
        "ip.firewall.template.port-forward",
        "Port Forward",
        ["IP", "Firewall"],
        None,
        "{dst_port: ports (outside), to_addresses: ip (the inside host), to_ports?: port | port-port, protocol?: tcp | udp (default tcp), dst_address?: ip (public address; default any), in_interface_list?: name (default WAN), comment?: string, force?: bool} → {nat: *hex, filter: *hex}",
        always,
        port_forward
    ),
    cmd!(
        "ip.firewall.template.block-address",
        "Block Address",
        ["IP", "Firewall"],
        None,
        "{address: ip | cidr | ip-ip, list?: name (default blocked), timeout?: duration (absent = until removed), comment?: string, force?: bool} → {entry: *hex, rules: [*hex] (drop rules created; empty if they existed)}",
        always,
        block_address
    ),
    cmd!(
        "ip.firewall.template.brute-force",
        "Brute Force Protection",
        ["IP", "Firewall"],
        None,
        "{dst_port?: ports (default 22,8729), protocol?: tcp | udp (default tcp), name?: name (prefix of the lists, default bruteforce), attempts?: 1..10 new connections allowed per stage window (default 3), stage_timeout?: duration (default 1m), block_timeout?: duration (default 10d), force?: bool} → {rules: [*hex], blacklist: name}",
        always,
        brute_force
    ),
    cmd!(
        "ip.firewall.template.ping-limit",
        "Limit Ping",
        ["IP", "Firewall"],
        None,
        "{limit?: count/time[,burst] (default 5/1s,5), force?: bool} → {rules: [*hex]}",
        always,
        ping_limit
    ),
    cmd!(
        "ip.firewall.template.lan-management",
        "Management From LAN Only",
        ["IP", "Firewall"],
        None,
        "{dst_port?: ports (default 22,8729 and the port of your connection), list?: name (interface list, default LAN), force?: bool} → {rules: [*hex]}",
        always,
        lan_management
    ),
    cmd!(
        "ip.firewall.template.raw-bogons",
        "Drop Bogons Before Conntrack",
        ["IP", "Firewall"],
        None,
        "{wan?: name (interface list the attacks come in on, default WAN), list?: name (address list of reserved sources, default bogons), private?: bool (also RFC 1918, 100.64.0.0/10 and fc00::/7; default false: an upstream on private space would be cut), replace?: bool (remove the rules and entries of an earlier run first), force?: bool} → {rules: [*hex], entries: count, list: name}",
        always,
        raw_bogons
    ),
];

/// Comment prefix of the raw template's rules and entries.
pub const RAWDEF: &str = "rawdef";

/// Sources that never come from the internet (RFC 6890, RFC 5737,
/// RFC 3849, RFC 4291 §2.5; multicast is never a source, RFC 1112 §4).
const BOGONS: &[&str] = &[
    "0.0.0.0/8",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "::/128",
    "::1/128",
    "::ffff:0:0/96",
    "100::/64",
    "2001:db8::/32",
    "fec0::/10",
    "ff00::/8",
];

/// Private space (RFC 1918, RFC 6598, RFC 4193): only with `private`.
const PRIVATE: &[&str] = &[
    "10.0.0.0/8",
    "100.64.0.0/10",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "fc00::/7",
];

/// Comment prefix of the safe defaults (as RouterOS' `defconf:`).
pub const DEFCONF: &str = "defconf";

/// A name written in this file (always valid).
fn fixed(name: &str) -> Result<Name> {
    name.parse()
        .map_err(|e: corerouter_model::ParseError| EngineError::Internal(e.to_string()))
}

/// One rule's parameters: chain, action and RouterOS-style matchers.
fn spec(chain: &str, action: &str, pairs: &[(&str, &str)], comment: &str) -> Value {
    let mut p = Map::new();
    p.insert("chain".into(), json!(chain));
    p.insert("action".into(), json!(action));
    for (k, v) in pairs {
        p.insert((*k).to_owned(), json!(v));
    }
    p.insert("comment".into(), json!(comment));
    Value::Object(p)
}

fn section(title: &str) -> Value {
    json!({ "section": title })
}

fn id_of(v: &Value) -> Result<ItemId> {
    v.get("id")
        .cloned()
        .and_then(|id| serde_json::from_value(id).ok())
        .ok_or_else(|| EngineError::Internal("add returned no id".into()))
}

/// Add each of `rules` above `anchor` (in order), or at the end.
fn insert(
    s: &mut Session,
    table: Table,
    anchor: Option<ItemId>,
    rules: Vec<Value>,
) -> Result<Vec<ItemId>> {
    let mut ids = Vec::with_capacity(rules.len());
    for mut p in rules {
        if let (Some(a), Some(obj)) = (anchor, p.as_object_mut()) {
            obj.insert("place_before".into(), json!(a));
        }
        ids.push(id_of(&add(s, table, &p)?)?);
    }
    Ok(ids)
}

/// The rule to insert above for position `idx`: above the section headers
/// right over it, and never inside the zone matrix's block (above its
/// header instead). `None` = the end.
fn anchor_at(rules: &CowList<FirewallRule>, mut idx: usize) -> Option<ItemId> {
    while idx > 0 && rules.get(idx - 1).is_some_and(|r| r.section && !r.zone) {
        idx -= 1;
    }
    if rules.get(idx).is_some_and(|r| r.zone)
        && let Some(first) = rules.iter().position(|r| r.zone)
    {
        idx = first;
    }
    rules.get(idx).map(|r| r.id)
}

/// Above the first rule of `chain` (so the new rules decide first).
fn top_of(cfg: &Config, table: Table, chain: &str) -> Option<ItemId> {
    let rules = cfg.ip.firewall.rules(table);
    let idx = rules
        .iter()
        .position(|r| !r.section && r.chain.as_str() == chain)
        .unwrap_or(rules.len());
    anchor_at(rules, idx)
}

/// Above the first enabled drop/reject of `chain` (an accept must come
/// before what would block it), else at the end.
fn before_blocks(cfg: &Config, table: Table, chain: &str) -> Option<ItemId> {
    let rules = cfg.ip.firewall.rules(table);
    let idx = rules
        .iter()
        .position(|r| {
            !r.section
                && !r.disabled
                && r.chain.as_str() == chain
                && matches!(r.action, Action::Drop | Action::Reject { .. })
        })
        .unwrap_or(rules.len());
    anchor_at(rules, idx)
}

fn list_members(cfg: &Config, list: &str) -> Vec<IfName> {
    cfg.interface_lists.interfaces_of(list).cloned().collect()
}

/// Put `ifaces` in list `list` (those already there are skipped).
fn join_list(s: &mut Session, list: &str, ifaces: &[IfName]) -> Result<()> {
    for i in ifaces {
        if list_members(s.store().candidate(), list).contains(i) {
            continue;
        }
        member_add(s, &json!({ "list": list, "interface": i }))?;
    }
    Ok(())
}

fn defconf(text: &str) -> String {
    format!("{DEFCONF}: {text}")
}

fn defaults_apply(s: &mut Session, p: &Value) -> Result<Value> {
    take_force(s, p)?;
    let lan = opt_names(p, "lan", 64)?.unwrap_or_default();
    let wan = opt_names(p, "wan", 64)?.unwrap_or_default();
    let replace = opt_bool(p, "replace")?.unwrap_or(false);

    let earlier: Vec<(Table, ItemId)> = Table::ALL
        .iter()
        .flat_map(|t| {
            let t = *t;
            s.store()
                .candidate()
                .ip
                .firewall
                .rules(t)
                .iter()
                .filter(|r| r.comment.starts_with(DEFCONF) && !r.zone)
                .map(move |r| (t, r.id))
                .collect::<Vec<_>>()
        })
        .collect();
    if !earlier.is_empty() {
        if !replace {
            let ids: Vec<String> = earlier.iter().map(|(_, id)| id.to_string()).collect();
            return Err(EngineError::bad(
                "replace",
                format!(
                    "the safe defaults are already here (rules {}); replace=true removes \
                     them and applies the defaults again",
                    ids.join(", ")
                ),
            ));
        }
        let cfg = s.store_mut().candidate_mut();
        for (t, id) in &earlier {
            cfg.ip.firewall.rules_mut(*t).retain(|r| r.id != *id);
        }
    }

    for (list, ifaces) in [("LAN", &lan), ("WAN", &wan)] {
        if s.store().candidate().interface_lists.get(list).is_none() {
            return Err(EngineError::bad(
                if list == "LAN" { "lan" } else { "wan" },
                format!(
                    "the interface list {list} does not exist (interface.list.add name={list})"
                ),
            ));
        }
        join_list(s, list, ifaces)?;
    }
    let cfg = s.store().candidate();
    if list_members(cfg, "LAN").is_empty() {
        return Err(EngineError::bad(
            "lan",
            "the LAN list is empty, and the defaults drop what reaches the router from outside \
             LAN: name your LAN interfaces (lan: [\"ether2\"]) or add them in Interface List",
        ));
    }

    let est = "established,related,untracked";
    let filter = vec![
        section(&defconf("configuração inicial segura (edite à vontade)")),
        spec(
            "input",
            "accept",
            &[("connection_state", est)],
            &defconf("aceita respostas e conexões já aceitas"),
        ),
        spec(
            "input",
            "drop",
            &[("connection_state", "invalid")],
            &defconf("descarta pacotes inválidos"),
        ),
        spec(
            "input",
            "accept",
            &[("protocol", "icmp")],
            &defconf("aceita ICMP (ping e avisos de rede)"),
        ),
        spec(
            "input",
            "accept",
            &[("protocol", "icmpv6")],
            &defconf("aceita ICMPv6 (sem ele o IPv6 não funciona)"),
        ),
        spec(
            "input",
            "accept",
            &[("in_interface", "lo")],
            &defconf("aceita o tráfego do próprio roteador (127.0.0.1, ::1)"),
        ),
        spec(
            "input",
            "drop",
            &[("in_interface_list", "!LAN")],
            &defconf("descarta o resto que não vem da LAN"),
        ),
        spec(
            "forward",
            "accept",
            &[("connection_state", est)],
            &defconf("aceita respostas e conexões já aceitas"),
        ),
        spec(
            "forward",
            "drop",
            &[("connection_state", "invalid")],
            &defconf("descarta pacotes inválidos"),
        ),
        spec(
            "forward",
            "accept",
            &[("protocol", "icmpv6")],
            &defconf("aceita ICMPv6 em trânsito (descoberta de MTU)"),
        ),
        spec(
            "forward",
            "drop",
            &[
                ("connection_state", "new"),
                ("connection_nat_state", "!dstnat"),
                ("in_interface_list", "WAN"),
            ],
            &defconf("descarta conexões novas vindas da WAN que não foram redirecionadas"),
        ),
    ];
    let anchor = anchor_at(&cfg.ip.firewall.filter, 0);
    let mut ids = insert(s, Table::Filter, anchor, filter)?;
    let mut masq = spec(
        "srcnat",
        "masquerade",
        &[("out_interface_list", "WAN")],
        &defconf("mascara (NAT) a saída IPv4 pela WAN"),
    );
    if let Some(o) = masq.as_object_mut() {
        o.insert("family".into(), json!("ipv4"));
    }
    ids.extend(insert(s, Table::Nat, None, vec![masq])?);
    let cfg = s.store().candidate();
    Ok(json!({
        "rules": ids,
        "lan": list_members(cfg, "LAN"),
        "wan": list_members(cfg, "WAN"),
    }))
}

fn port_forward(s: &mut Session, p: &Value) -> Result<Value> {
    take_force(s, p)?;
    let dst_port: PortSet = req_parse(p, "dst_port")?;
    let to: corerouter_model::firewall::NatTarget = req_parse(p, "to_addresses")?;
    let to_ports: Option<corerouter_model::firewall::PortRange> = opt_parse(p, "to_ports")?;
    let protocol = opt_text(p, "protocol", 8)?.unwrap_or_else(|| "tcp".into());
    if protocol != "tcp" && protocol != "udp" {
        return Err(EngineError::bad("protocol", "tcp or udp"));
    }
    let dst_address: Option<corerouter_model::firewall::AddrMatch> = opt_parse(p, "dst_address")?;
    let list: Name = opt_parse(p, "in_interface_list")?.map_or_else(|| fixed("WAN"), Ok)?;
    let comment = opt_text(p, "comment", 200)?.unwrap_or_default();

    let ports = dst_port.to_string();
    let inside_ports = to_ports.map_or_else(|| ports.clone(), |r| r.to_string());
    let target = match to_ports {
        Some(r) => format!("{to}:{r}"),
        None => to.to_string(),
    };
    let what = format!("redirecionar {protocol}/{ports} -> {target}");
    let note = |text: &str| {
        if comment.is_empty() {
            text.to_owned()
        } else {
            format!("{text} ({comment})")
        }
    };
    let mut nat_pairs: Vec<(&str, String)> = vec![
        ("in_interface_list", list.to_string()),
        ("protocol", protocol.clone()),
        ("dst_port", ports.clone()),
        ("to_addresses", to.to_string()),
    ];
    if let Some(r) = to_ports {
        nat_pairs.push(("to_ports", r.to_string()));
    }
    if let Some(a) = dst_address {
        nat_pairs.push(("dst_address", a.to_string()));
    }
    let pairs: Vec<(&str, &str)> = nat_pairs.iter().map(|(k, v)| (*k, v.as_str())).collect();
    let nat = insert(
        s,
        Table::Nat,
        None,
        vec![spec("dstnat", "dst-nat", &pairs, &note(&what))],
    )?;
    let to_text = to.to_string();
    let anchor = before_blocks(s.store().candidate(), Table::Filter, "forward");
    let filter = insert(
        s,
        Table::Filter,
        anchor,
        vec![spec(
            "forward",
            "accept",
            &[
                ("in_interface_list", list.as_str()),
                ("connection_nat_state", "dstnat"),
                ("protocol", &protocol),
                ("dst_address", &to_text),
                ("dst_port", &inside_ports),
            ],
            &note(&format!("deixa passar o {what}")),
        )],
    )?;
    Ok(json!({ "nat": nat.first(), "filter": filter.first() }))
}

/// A drop of everything from list `list` in `chain` exists already.
fn has_drop(cfg: &Config, chain: &str, list: &Name) -> bool {
    cfg.ip.firewall.filter.iter().any(|r| {
        !r.section
            && !r.disabled
            && r.chain.as_str() == chain
            && r.action == Action::Drop
            && r.matchers
                == corerouter_model::firewall::Matchers {
                    src_address_list: Some(corerouter_model::firewall::Neg::is(list.clone())),
                    ..Default::default()
                }
    })
}

fn block_address(s: &mut Session, p: &Value) -> Result<Value> {
    take_force(s, p)?;
    let address: corerouter_model::firewall::AddrMatch = req_parse(p, "address")?;
    let list: Name = opt_parse(p, "list")?.map_or_else(|| fixed("blocked"), Ok)?;
    let timeout: Option<Timeout> = opt_parse(p, "timeout")?;
    let comment = opt_text(p, "comment", 256)?.unwrap_or_default();

    let mut rules = Vec::new();
    for chain in ["input", "forward"] {
        if has_drop(s.store().candidate(), chain, &list) {
            continue;
        }
        let anchor = top_of(s.store().candidate(), Table::Filter, chain);
        let what = if chain == "input" {
            "o roteador"
        } else {
            "a rede"
        };
        rules.extend(insert(
            s,
            Table::Filter,
            anchor,
            vec![spec(
                chain,
                "drop",
                &[("src_address_list", list.as_str())],
                &format!("bloqueio: descarta o que vem da lista {list} para {what}"),
            )],
        )?);
    }
    let mut entry = json!({ "list": list, "address": address, "comment": comment });
    if let (Some(t), Some(o)) = (timeout, entry.as_object_mut()) {
        o.insert("timeout".into(), json!(t.secs()));
        // A dynamic entry reaches the data plane now, before the rules are
        // committed: check both together first.
        let before = s.dynamic_now();
        let mut after = before.clone();
        after.push(corerouter_model::firewall::DynamicAddress {
            list: list.clone(),
            address,
            timeout_secs: u64::from(t.secs()),
            added_by_rule: false,
        });
        s.check_lockout(s.store().running(), s.store().candidate(), &before, &after)?;
    }
    let added = al_add(s, &entry)?;
    Ok(json!({ "entry": added.get("id"), "rules": rules }))
}

fn brute_force(s: &mut Session, p: &Value) -> Result<Value> {
    take_force(s, p)?;
    let ports: PortSet = opt_parse(p, "dst_port")?.unwrap_or_else(default_ports);
    let protocol = opt_text(p, "protocol", 8)?.unwrap_or_else(|| "tcp".into());
    if protocol != "tcp" && protocol != "udp" {
        return Err(EngineError::bad("protocol", "tcp or udp"));
    }
    let prefix = opt_text(p, "name", 40)?.unwrap_or_else(|| "bruteforce".into());
    let attempts = match p.get("attempts") {
        None | Some(Value::Null) => 3,
        Some(v) => v
            .as_u64()
            .filter(|n| (1..=10).contains(n))
            .ok_or_else(|| EngineError::bad("attempts", "a whole number 1..=10"))?,
    };
    let stage: Timeout = opt_parse(p, "stage_timeout")?.unwrap_or(Timeout(60));
    let block: Timeout = opt_parse(p, "block_timeout")?.unwrap_or(Timeout(10 * 86_400));
    let name = |suffix: &str| -> Result<Name> {
        format!("{prefix}_{suffix}")
            .parse()
            .map_err(|e: corerouter_model::ParseError| EngineError::bad("name", e.to_string()))
    };
    let blacklist = name("blacklist")?;
    let ports_text = ports.to_string();
    let base: Vec<(&str, &str)> = vec![("protocol", &protocol), ("dst_port", &ports_text)];
    let with = |extra: &[(&'static str, String)]| -> Vec<(String, String)> {
        base.iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .chain(extra.iter().map(|(k, v)| ((*k).to_owned(), v.clone())))
            .collect()
    };
    let rule =
        |action: &str, pairs: Vec<(String, String)>, extra: &[(&str, String)], comment: String| {
            let mut v = spec(
                "input",
                action,
                &pairs
                    .iter()
                    .map(|(k, v)| (k.as_str(), v.as_str()))
                    .collect::<Vec<_>>(),
                &comment,
            );
            if let Some(o) = v.as_object_mut() {
                for (k, x) in extra {
                    o.insert((*k).to_owned(), json!(x));
                }
            }
            v
        };
    let mut rules = vec![
        section(&format!(
            "Proteção contra força bruta ({protocol}/{ports_text})"
        )),
        rule(
            "drop",
            with(&[("src_address_list", blacklist.to_string())]),
            &[],
            format!("descarta quem está na lista {blacklist}"),
        ),
    ];
    // Highest stage first, so one new connection climbs one stage only.
    for k in (1..=attempts).rev() {
        let (target, timeout) = if k == attempts {
            (blacklist.clone(), block)
        } else {
            (name(&format!("stage{}", k + 1))?, stage)
        };
        rules.push(rule(
            "add-src-to-address-list",
            with(&[
                ("connection_state", "new".into()),
                ("src_address_list", name(&format!("stage{k}"))?.to_string()),
            ]),
            &[
                ("address_list", target.to_string()),
                ("address_list_timeout", timeout.to_string()),
            ],
            format!(
                "tentativa {} em {stage}: vai para {target} por {timeout}",
                k + 1
            ),
        ));
    }
    rules.push(rule(
        "add-src-to-address-list",
        with(&[("connection_state", "new".into())]),
        &[
            ("address_list", name("stage1")?.to_string()),
            ("address_list_timeout", stage.to_string()),
        ],
        format!(
            "primeira tentativa: vai para {} por {stage}",
            name("stage1")?
        ),
    ));
    let anchor = top_of(s.store().candidate(), Table::Filter, "input");
    let ids = insert(s, Table::Filter, anchor, rules)?;
    Ok(json!({ "rules": ids, "blacklist": blacklist }))
}

fn ping_limit(s: &mut Session, p: &Value) -> Result<Value> {
    take_force(s, p)?;
    let limit: Limit = opt_parse(p, "limit")?.unwrap_or(Limit {
        count: 5,
        period: corerouter_model::firewall::LimitPeriod::Second,
        burst: 5,
    });
    let l = limit.to_string();
    let rules = vec![
        section(&format!("Limitar ping ({l})")),
        spec(
            "input",
            "accept",
            &[("protocol", "icmp"), ("icmp_options", "8:0"), ("limit", &l)],
            &format!("aceita até {l} pedidos de ping"),
        ),
        spec(
            "input",
            "drop",
            &[("protocol", "icmp"), ("icmp_options", "8:0")],
            "descarta o excesso de pings",
        ),
        spec(
            "input",
            "accept",
            &[
                ("protocol", "icmpv6"),
                ("icmp_options", "128:0"),
                ("limit", &l),
            ],
            &format!("aceita até {l} pedidos de ping IPv6"),
        ),
        spec(
            "input",
            "drop",
            &[("protocol", "icmpv6"), ("icmp_options", "128:0")],
            "descarta o excesso de pings IPv6",
        ),
    ];
    let anchor = top_of(s.store().candidate(), Table::Filter, "input");
    let ids = insert(s, Table::Filter, anchor, rules)?;
    Ok(json!({ "rules": ids }))
}

/// SSH and the control channel over TLS.
fn default_ports() -> PortSet {
    PortSet(vec![
        corerouter_model::firewall::PortRange {
            first: 22,
            last: 22,
        },
        corerouter_model::firewall::PortRange {
            first: 8729,
            last: 8729,
        },
    ])
}

fn lan_management(s: &mut Session, p: &Value) -> Result<Value> {
    take_force(s, p)?;
    let list: Name = opt_parse(p, "list")?.map_or_else(|| fixed("LAN"), Ok)?;
    let ports: PortSet = match opt_parse(p, "dst_port")? {
        Some(ps) => ps,
        None => {
            let mut ps = default_ports();
            // The port this operator is using now is management too.
            if let Some(link) = s.caller().link
                && !ps.contains(link.local.port())
            {
                let port = link.local.port();
                ps.0.push(corerouter_model::firewall::PortRange {
                    first: port,
                    last: port,
                });
            }
            ps
        }
    };
    let cfg = s.store().candidate();
    if cfg.interface_lists.get(list.as_str()).is_none() {
        return Err(EngineError::bad(
            "list",
            format!("no interface list '{list}' (see interface.list.list)"),
        ));
    }
    if list_members(cfg, list.as_str()).is_empty() {
        return Err(EngineError::bad(
            "list",
            format!(
                "the {list} list is empty: management would be closed to everyone; add \
                 your LAN interfaces to it first (Interfaces › Interface List)"
            ),
        ));
    }
    let ports_text = ports.to_string();
    let base = [("protocol", "tcp"), ("dst_port", ports_text.as_str())];
    fn with<'a>(base: &[(&'a str, &'a str)], extra: (&'a str, &'a str)) -> Vec<(&'a str, &'a str)> {
        let mut v = base.to_vec();
        v.push(extra);
        v
    }
    let rules = vec![
        section(&format!("Gerência só da {list} (tcp/{ports_text})")),
        spec(
            "input",
            "accept",
            &with(&base, ("in_interface", "lo")),
            "aceita a gerência local (127.0.0.1, ::1)",
        ),
        spec(
            "input",
            "accept",
            &with(&base, ("in_interface_list", list.as_str())),
            &format!("aceita a gerência vinda da {list}"),
        ),
        spec(
            "input",
            "drop",
            &base,
            &format!("descarta a gerência vinda de fora da {list}"),
        ),
    ];
    let anchor = top_of(cfg, Table::Filter, "input");
    let ids = insert(s, Table::Filter, anchor, rules)?;
    Ok(json!({ "rules": ids }))
}

/// Raw table template: drop reserved sources and port 0 from the WAN in
/// `prerouting`, before connection tracking spends an entry on them (the
/// MikroTik manual's DDoS advice: drop in raw, it costs less).
fn raw_bogons(s: &mut Session, p: &Value) -> Result<Value> {
    take_force(s, p)?;
    let wan: Name = opt_parse(p, "wan")?.unwrap_or(fixed("WAN")?);
    let list: Name = opt_parse(p, "list")?.unwrap_or(fixed("bogons")?);
    let private = opt_bool(p, "private")?.unwrap_or(false);
    let replace = opt_bool(p, "replace")?.unwrap_or(false);
    let cfg = s.store().candidate();
    if cfg.interface_lists.get(wan.as_str()).is_none() {
        return Err(EngineError::bad(
            "wan",
            format!("the interface list {wan} does not exist (interface.list.add name={wan})"),
        ));
    }
    if list_members(cfg, wan.as_str()).is_empty() {
        return Err(EngineError::bad(
            "wan",
            format!(
                "the {wan} list is empty: the rules would match nothing; add the WAN \
                 interfaces in Interface List first"
            ),
        ));
    }
    let tagged = |c: &str| c.starts_with(RAWDEF);
    let earlier: Vec<ItemId> = cfg
        .ip
        .firewall
        .raw
        .iter()
        .filter(|r| tagged(&r.comment))
        .map(|r| r.id)
        .collect();
    if !earlier.is_empty() {
        if !replace {
            let ids: Vec<String> = earlier.iter().map(ItemId::to_string).collect();
            return Err(EngineError::bad(
                "replace",
                format!(
                    "the raw template is already here (rules {}); replace=true removes it and \
                     applies it again",
                    ids.join(", ")
                ),
            ));
        }
        let fw = &mut s.store_mut().candidate_mut().ip.firewall;
        fw.raw.retain(|r| !tagged(&r.comment));
        let stale: Vec<usize> = fw
            .address_lists
            .iter()
            .enumerate()
            .filter(|(_, e)| e.list == list && tagged(&e.comment))
            .map(|(i, _)| i)
            .collect();
        for i in stale.into_iter().rev() {
            fw.address_lists.remove(i);
        }
    }
    let mut entries = 0usize;
    let sources = BOGONS
        .iter()
        .map(|a| (*a, "reservado"))
        .chain(PRIVATE.iter().filter(|_| private).map(|a| (*a, "privado")));
    for (address, kind) in sources {
        let parsed: AddrMatch = address
            .parse()
            .map_err(|e: corerouter_model::ParseError| EngineError::Internal(e.to_string()))?;
        if s.store().candidate().ip.firewall.address_lists.holders(&list, &parsed) > 0 {
            continue;
        }
        al_add(
            s,
            &json!({ "list": list, "address": address, "comment": format!("{RAWDEF}: {kind}") }),
        )?;
        entries += 1;
    }
    let wan_s = wan.to_string();
    let l = list.to_string();
    let rules = vec![
        section(&format!(
            "{RAWDEF}: bogons e ataques, descartados antes do conntrack"
        )),
        spec(
            "prerouting",
            "drop",
            &[("in_interface_list", &wan_s), ("src_address_list", &l)],
            &format!("{RAWDEF}: origem reservada não vem da internet (RFC 6890)"),
        ),
        spec(
            "prerouting",
            "drop",
            &[
                ("in_interface_list", &wan_s),
                ("protocol", "tcp"),
                ("dst_port", "0"),
            ],
            &format!("{RAWDEF}: porta TCP 0 não existe (varredura ou ataque)"),
        ),
        spec(
            "prerouting",
            "drop",
            &[
                ("in_interface_list", &wan_s),
                ("protocol", "udp"),
                ("dst_port", "0"),
            ],
            &format!("{RAWDEF}: porta UDP 0 não existe (varredura ou ataque)"),
        ),
    ];
    let anchor = top_of(s.store().candidate(), Table::Raw, "prerouting");
    let ids = insert(s, Table::Raw, anchor, rules)?;
    Ok(json!({ "rules": ids, "entries": entries, "list": list }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_ports_are_ssh_and_tls() {
        assert_eq!(default_ports().to_string(), "22,8729");
    }
}
