//! A rule in plain Portuguese, generated from its matchers and action, for
//! the GUI's "Descrição" column (G2.1b): "Descarta pacotes para o roteador,
//! que não entram pela lista LAN."

use corerouter_model::firewall::{
    Action, ConnState, Family, FirewallRule, Flags, IcmpOptions, NatState, Neg, PortSet, Protocol,
    RejectWith, Table,
};

fn quoted(s: impl std::fmt::Display) -> String {
    format!("\u{201c}{s}\u{201d}")
}

fn verb(a: &Action) -> String {
    match a {
        Action::Accept => "Aceita".into(),
        Action::Drop => "Descarta".into(),
        Action::Reject { reject_with } => format!(
            "Rejeita ({})",
            match reject_with {
                RejectWith::IcmpNoRoute => "responde \u{201c}sem rota\u{201d}",
                RejectWith::IcmpAdminProhibited => "responde \u{201c}proibido\u{201d}",
                RejectWith::IcmpAddressUnreachable =>
                    "responde \u{201c}endereço inalcançável\u{201d}",
                RejectWith::IcmpPortUnreachable => "responde \u{201c}porta inalcançável\u{201d}",
                RejectWith::TcpReset => "responde com TCP reset",
            }
        ),
        Action::Jump { jump_target } => format!("Manda para a chain {}", quoted(jump_target)),
        Action::Return => "Volta para a chain que chamou".into(),
        Action::Log { log_prefix } if log_prefix.is_empty() => "Registra no log".into(),
        Action::Log { log_prefix } => format!("Registra no log (prefixo {})", quoted(log_prefix)),
        Action::Passthrough => "Só conta".into(),
        Action::Masquerade { to_ports } => match to_ports {
            None => "Mascara com o endereço da interface de saída".into(),
            Some(p) => format!("Mascara com o endereço da interface de saída, portas {p},"),
        },
        Action::SrcNat {
            to_addresses,
            to_ports,
        } => match to_ports {
            None => format!("Troca a origem para {to_addresses}"),
            Some(p) => format!("Troca a origem para {to_addresses} porta {p}"),
        },
        Action::DstNat {
            to_addresses,
            to_ports,
        } => match to_ports {
            None => format!("Redireciona para {to_addresses}"),
            Some(p) => format!("Redireciona para {to_addresses} porta {p}"),
        },
        Action::MarkConnection {
            new_connection_mark: n,
            ..
        } => format!("Marca a conexão como {}", quoted(n)),
        Action::MarkPacket {
            new_packet_mark: n, ..
        } => format!("Marca o pacote como {}", quoted(n)),
        Action::MarkRouting {
            new_routing_mark: n,
            ..
        } => format!("Marca o roteamento como {}", quoted(n)),
        Action::AddSrcToAddressList {
            address_list,
            address_list_timeout,
        } => format!(
            "Põe na lista {}{} a origem dos",
            quoted(address_list),
            address_list_timeout
                .map(|t| format!(" por {t}"))
                .unwrap_or_default()
        ),
        Action::AddDstToAddressList {
            address_list,
            address_list_timeout,
        } => format!(
            "Põe na lista {}{} o destino dos",
            quoted(address_list),
            address_list_timeout
                .map(|t| format!(" por {t}"))
                .unwrap_or_default()
        ),
    }
}

fn direction(table: Table, chain: &str) -> String {
    match (table, chain) {
        (Table::Filter | Table::Mangle, "input") => "para o roteador".into(),
        (Table::Filter | Table::Mangle, "forward") => "que atravessam o roteador".into(),
        (Table::Filter | Table::Mangle, "output") => "que o roteador envia".into(),
        (Table::Nat, "dstnat") | (Table::Mangle, "prerouting") => {
            "que chegam (antes do roteamento)".into()
        }
        (Table::Nat, "srcnat") | (Table::Mangle, "postrouting") => {
            "que saem (depois do roteamento)".into()
        }
        (_, c) => format!("da chain {}", quoted(c)),
    }
}

fn protocol(p: &Neg<Protocol>, icmp: Option<IcmpOptions>) -> String {
    let name = match p.value.name() {
        Some("icmpv6") => "ICMPv6".to_owned(),
        Some(n) => n.to_uppercase(),
        None => format!("de protocolo {}", p.value.0),
    };
    let mut s = if p.not {
        format!("que não são {name}")
    } else {
        name
    };
    if let Some(i) = icmp {
        s.push_str(&format!(" tipo {}", i.kind));
        if let Some(c) = i.code {
            s.push_str(&format!(" código {c}"));
        }
        let what = match (p.value, i.kind, i.code) {
            (Protocol::ICMP, 8, _) | (Protocol::ICMPV6, 128, _) => Some("pedido de ping"),
            (Protocol::ICMP, 0, _) | (Protocol::ICMPV6, 129, _) => Some("resposta de ping"),
            _ => None,
        };
        if let Some(w) = what {
            s.push_str(&format!(" ({w})"));
        }
    }
    s
}

fn ports(n: &Neg<PortSet>, from: bool) -> String {
    let many = n.value.0.len() > 1 || n.value.0.iter().any(|r| r.first != r.last);
    let (one, more) = if from {
        ("da porta", "das portas")
    } else {
        ("para a porta", "para as portas")
    };
    let base = if many { more } else { one };
    if n.not {
        format!(
            "{} fora de {}",
            if from { "de portas" } else { "para portas" },
            n.value
        )
    } else {
        format!("{base} {}", n.value)
    }
}

fn states(n: &Neg<Flags<ConnState>>) -> String {
    let names: Vec<&str> = n
        .value
        .0
        .iter()
        .map(|s| match s {
            ConnState::Established => "estabelecidas",
            ConnState::Related => "relacionadas",
            ConnState::New => "novas",
            ConnState::Invalid => "inválidas",
            ConnState::Untracked => "não rastreadas",
        })
        .collect();
    let list = or_list(&names);
    if n.not {
        format!("de conexões que não são {list}")
    } else {
        format!("de conexões {list}")
    }
}

fn nat_states(n: &Neg<Flags<NatState>>) -> String {
    let names: Vec<&str> = n
        .value
        .0
        .iter()
        .map(|s| match s {
            NatState::Srcnat => "de origem",
            NatState::Dstnat => "de destino",
        })
        .collect();
    let list = or_list(&names);
    if n.not {
        format!("de conexões sem NAT {list}")
    } else {
        format!("de conexões com NAT {list}")
    }
}

/// "a, b ou c".
fn or_list(items: &[&str]) -> String {
    match items {
        [] => String::new(),
        [one] => (*one).to_owned(),
        [init @ .., last] => format!("{} ou {last}", init.join(", ")),
    }
}

fn not(n: bool) -> &'static str {
    if n { "não " } else { "" }
}

/// The rule in one Portuguese sentence; a section header is its title.
pub fn describe(table: Table, r: &FirewallRule) -> String {
    if r.section {
        return r.comment.clone();
    }
    let m = &r.matchers;
    let mut object = String::from("pacotes");
    if let Some(p) = &m.protocol {
        object.push(' ');
        object.push_str(&protocol(p, m.icmp_options));
    }
    match r.family {
        Family::Both => {}
        Family::Ipv4 => object.push_str(" IPv4"),
        Family::Ipv6 => object.push_str(" IPv6"),
    }
    object.push(' ');
    object.push_str(&direction(table, r.chain.as_str()));

    let mut conds: Vec<String> = Vec::new();
    if let Some(a) = &m.src_address {
        conds.push(format!("{}vindos de {}", not(a.not), a.value));
    }
    if let Some(l) = &m.src_address_list {
        conds.push(format!(
            "{}vindos da lista {}",
            not(l.not),
            quoted(&l.value)
        ));
    }
    if let Some(a) = &m.dst_address {
        conds.push(format!("{}destinados a {}", not(a.not), a.value));
    }
    if let Some(l) = &m.dst_address_list {
        conds.push(format!(
            "{}destinados à lista {}",
            not(l.not),
            quoted(&l.value)
        ));
    }
    if let Some(p) = &m.src_port {
        conds.push(ports(p, true));
    }
    if let Some(p) = &m.dst_port {
        conds.push(ports(p, false));
    }
    if let Some(i) = &m.in_interface {
        conds.push(format!("que {}entram pela {}", not(i.not), i.value));
    }
    if let Some(l) = &m.in_interface_list {
        conds.push(format!("que {}entram pela lista {}", not(l.not), l.value));
    }
    if let Some(i) = &m.out_interface {
        conds.push(format!("que {}saem pela {}", not(i.not), i.value));
    }
    if let Some(l) = &m.out_interface_list {
        conds.push(format!("que {}saem pela lista {}", not(l.not), l.value));
    }
    if let Some(s) = &m.connection_state {
        conds.push(states(s));
    }
    if let Some(s) = &m.connection_nat_state {
        conds.push(nat_states(s));
    }
    for (what, mark) in [
        ("de conexão", &m.connection_mark),
        ("de pacote", &m.packet_mark),
        ("de roteamento", &m.routing_mark),
    ] {
        if let Some(n) = mark {
            let with = if n.not { "sem" } else { "com" };
            conds.push(format!("{with} marca {what} {}", quoted(&n.value)));
        }
    }
    if let Some(l) = &m.limit {
        let per = match l.period {
            corerouter_model::firewall::LimitPeriod::Second => "segundo",
            corerouter_model::firewall::LimitPeriod::Minute => "minuto",
            corerouter_model::firewall::LimitPeriod::Hour => "hora",
            corerouter_model::firewall::LimitPeriod::Day => "dia",
        };
        conds.push(format!("até {} por {per} (rajada de {})", l.count, l.burst));
    }
    let mut out = format!("{} {object}", verb(&r.action));
    for c in conds {
        out.push_str(", ");
        out.push_str(&c);
    }
    if r.action.continues() && !matches!(r.action, Action::Passthrough) {
        out.push_str(" — e segue para a próxima regra");
    }
    out.push('.');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sample::sample;

    fn text(table: Table, id: u32) -> String {
        let cfg = sample();
        let r = cfg
            .ip
            .firewall
            .rules(table)
            .iter()
            .find(|r| r.id.0 == id)
            .unwrap()
            .clone();
        describe(table, &r)
    }

    #[test]
    fn rules_read_as_portuguese() {
        assert_eq!(
            text(Table::Filter, 2),
            "Aceita pacotes para o roteador, de conexões estabelecidas, relacionadas ou não rastreadas."
        );
        assert_eq!(
            text(Table::Filter, 10),
            "Descarta pacotes para o roteador, que não entram pela lista LAN."
        );
        assert_eq!(
            text(Table::Filter, 4),
            "Aceita pacotes ICMP tipo 8 código 0 (pedido de ping) para o roteador."
        );
        assert_eq!(
            text(Table::Nat, 16),
            "Redireciona para 10.0.0.20 porta 80 pacotes TCP que chegam (antes do roteamento), \
             para a porta 8080, que entram pela ether1."
        );
        assert_eq!(
            text(Table::Filter, 21),
            "Põe na lista \u{201c}blocked\u{201d} por 1m a origem dos pacotes TCP para o roteador, \
             para a porta 22, de conexões novas — e segue para a próxima regra."
        );
        assert!(text(Table::Filter, 22).contains("até 5 por segundo (rajada de 10)"));
        assert_eq!(text(Table::Filter, 1), "Router protection");
    }

    #[test]
    fn every_sample_rule_has_a_sentence() {
        let cfg = sample();
        for t in Table::ALL {
            for r in cfg.ip.firewall.rules(t) {
                let d = describe(t, r);
                assert!(d.len() > 5 && !d.contains("  "), "{d}");
            }
        }
    }
}
