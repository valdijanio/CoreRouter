//! IP › Firewall, the easy part (G2.1b): the assistants (safe defaults and
//! the templates, each a window that runs one `ip.firewall.defaults.apply`
//! / `ip.firewall.template.*` command) and the Zones tab (the zone matrix,
//! `ip.firewall.zone.*`). The engine writes ordinary, visible rules; these
//! windows only collect parameters and explain, in Portuguese, what will
//! be created.

use egui::{Color32, Grid, RichText, Ui};
use serde_json::{Map, Value, json};

use crate::CoreRouterUi;
use crate::avail::Avail;
use crate::dialog::{Footer, Form};
use crate::firewall::{Feed, action_color};
use crate::value_text;

/// The assistants, in menu order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Wizard {
    Defaults,
    PortForward,
    Block,
    BruteForce,
    PingLimit,
    LanManagement,
}

/// One field: parameter, label, hint.
type Field = (&'static str, &'static str, &'static str);

impl Wizard {
    pub(crate) const ALL: [Wizard; 6] = [
        Wizard::Defaults,
        Wizard::PortForward,
        Wizard::Block,
        Wizard::BruteForce,
        Wizard::PingLimit,
        Wizard::LanManagement,
    ];

    pub(crate) fn label(self) -> &'static str {
        match self {
            Wizard::Defaults => "Safe Defaults",
            Wizard::PortForward => "Port Forward",
            Wizard::Block => "Block Address",
            Wizard::BruteForce => "Brute Force Protection",
            Wizard::PingLimit => "Limit Ping",
            Wizard::LanManagement => "Management From LAN Only",
        }
    }

    pub(crate) fn cmd(self) -> &'static str {
        match self {
            Wizard::Defaults => "ip.firewall.defaults.apply",
            Wizard::PortForward => "ip.firewall.template.port-forward",
            Wizard::Block => "ip.firewall.template.block-address",
            Wizard::BruteForce => "ip.firewall.template.brute-force",
            Wizard::PingLimit => "ip.firewall.template.ping-limit",
            Wizard::LanManagement => "ip.firewall.template.lan-management",
        }
    }

    /// The table whose list shows the result (refreshed after).
    pub(crate) fn feed(self) -> Feed {
        match self {
            Wizard::PortForward => Feed::Nat,
            _ => Feed::Filter,
        }
    }

    fn explain(self) -> &'static str {
        match self {
            Wizard::Defaults => {
                "Cria a configuração inicial segura, no estilo do RouterOS: o roteador aceita \
                 respostas de conexões já aceitas, ICMP, o próprio tráfego local e tudo que vem \
                 da LAN, e descarta o resto; em trânsito, o que vem da WAN só passa se for \
                 resposta ou se foi redirecionado (dst-nat); a saída IPv4 pela WAN é mascarada \
                 (NAT). As regras vão para o topo com o comentário \u{201c}defconf:\u{201d} e \
                 são editáveis como qualquer outra. As interfaces abaixo entram nas listas LAN \
                 e WAN."
            }
            Wizard::PortForward => {
                "Redireciona conexões que chegam pela WAN numa porta para um host da rede \
                 interna (dst-nat) e cria a regra de forward que as deixa passar, acima das \
                 regras que bloqueiam."
            }
            Wizard::Block => {
                "Põe o endereço (ou a rede) numa address-list e garante as regras que descartam \
                 o que vem dela, para o roteador e para a rede. Com prazo, a entrada some \
                 sozinha; sem prazo, fica até você removê-la."
            }
            Wizard::BruteForce => {
                "Cada conexão nova à porta sobe um estágio (listas com prazo curto); quem \
                 passa do número de tentativas dentro do prazo vai para a lista negra e é \
                 descartado pelo tempo de bloqueio. O próprio kernel preenche as listas."
            }
            Wizard::PingLimit => {
                "Aceita pedidos de ping (IPv4 e IPv6) até o limite e descarta o excesso, para \
                 o roteador não servir de alvo de inundação."
            }
            Wizard::LanManagement => {
                "Aceita as portas de gerência só vindas da lista escolhida (e do próprio \
                 roteador) e descarta o resto. Sem portas, valem 22, 8729 e a porta desta \
                 conexão. Se você está fora dessa lista, o roteador avisa antes de aplicar."
            }
        }
    }

    fn fields(self) -> &'static [Field] {
        match self {
            Wizard::Defaults => &[
                ("lan", "LAN Interfaces", "ether2,ether3"),
                ("wan", "WAN Interfaces", "ether1"),
            ],
            Wizard::PortForward => &[
                ("protocol", "Protocol", "tcp"),
                ("dst_port", "Outside Port", "8080"),
                ("to_addresses", "To Address", "192.168.88.10"),
                ("to_ports", "To Port", "same as outside"),
                ("dst_address", "Public Address", "any"),
                ("in_interface_list", "From List", "WAN"),
                ("comment", "Comment", ""),
            ],
            Wizard::Block => &[
                ("address", "Address", "IP, IP/prefix or IP-IP"),
                ("list", "List", "blocked"),
                ("timeout", "Timeout", "none (until removed), 1h, 1d"),
                ("comment", "Comment", ""),
            ],
            Wizard::BruteForce => &[
                ("dst_port", "Port", "22,8729"),
                ("protocol", "Protocol", "tcp"),
                ("attempts", "Attempts", "3"),
                ("stage_timeout", "Within", "1m"),
                ("block_timeout", "Block For", "10d"),
                ("name", "List Prefix", "bruteforce"),
            ],
            Wizard::PingLimit => &[("limit", "Limit", "5/1s,5")],
            Wizard::LanManagement => &[
                ("dst_port", "Ports", "22,8729 + this connection's"),
                ("list", "Allowed List", "LAN"),
            ],
        }
    }

    /// A blank form for this assistant.
    pub(crate) fn form(self) -> WizardForm {
        WizardForm {
            fields: self
                .fields()
                .iter()
                .map(|(k, _, _)| (*k, String::new()))
                .collect(),
            replace: false,
        }
    }
}

/// What an assistant's window holds.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct WizardForm {
    pub fields: Vec<(&'static str, String)>,
    /// Safe Defaults: remove an earlier apply first.
    pub replace: bool,
}

impl WizardForm {
    /// The command's parameters: filled fields only (numbers as numbers).
    pub(crate) fn params(&self) -> Value {
        let mut p = Map::new();
        for (k, v) in &self.fields {
            let v = v.trim();
            if v.is_empty() {
                continue;
            }
            let value = match (*k, v.parse::<u64>()) {
                ("attempts", Ok(n)) => json!(n),
                _ => json!(v),
            };
            p.insert((*k).to_owned(), value);
        }
        if self.replace {
            p.insert("replace".into(), json!(true));
        }
        Value::Object(p)
    }
}

/// The body of an assistant's window.
pub(crate) fn body<B>(
    ui: &mut Ui,
    f: &Form,
    kind: Wizard,
    form: &mut WizardForm,
    can: &Avail,
) -> Footer<B> {
    ui.set_max_width(420.0);
    ui.label(RichText::new(kind.explain()));
    ui.add_space(6.0);
    Grid::new(("wizard", kind.label()))
        .num_columns(2)
        .spacing([12.0, 6.0])
        .show(ui, |ui| {
            for (param, label, hint) in kind.fields() {
                if let Some((_, v)) = form.fields.iter_mut().find(|(k, _)| k == param) {
                    f.text(ui, label, param, v, hint);
                }
            }
            if kind == Wizard::Defaults {
                ui.label("Replace");
                ui.checkbox(
                    &mut form.replace,
                    "remove the rules of an earlier apply first",
                );
                ui.end_row();
            }
        });
    Footer::edit(false, can.check(kind.cmd()))
}

/// The cell text of the zone matrix.
const NONE: &str = "—";
const ALLOW: &str = "allow";
const BLOCK: &str = "block";

fn cell_color(action: &str, dark: bool) -> Option<Color32> {
    match action {
        ALLOW => action_color("accept", dark),
        BLOCK => action_color("drop", dark),
        _ => None,
    }
}

impl CoreRouterUi {
    /// The Zones tab: the matrix from (rows) → to (columns).
    pub(crate) fn zones_tab(&mut self, ui: &mut Ui) {
        let data = self
            .fw
            .rows(Feed::Zones)
            .first()
            .cloned()
            .unwrap_or(Value::Null);
        let zones: Vec<String> = data
            .get("zones")
            .and_then(Value::as_array)
            .map(|a| a.iter().map(value_text).collect())
            .unwrap_or_default();
        let cells: Vec<(String, String, String)> = data
            .get("cells")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .map(|c| {
                        let t = |k: &str| c.get(k).map(value_text).unwrap_or_default();
                        (t("from"), t("to"), t("action"))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let generated = data
            .get("rules")
            .and_then(Value::as_array)
            .map_or(0, Vec::len);
        let can = self.can();
        let set = can.check("ip.firewall.zone.set");
        ui.label(
            "Modo simples: cada célula diz o que acontece com conexões novas de uma zona \
             (linha) para outra (coluna). Zonas são as listas de interfaces e o próprio \
             roteador. A matriz gera uma seção de regras no topo de Filter Rules, marcadas \
             com Z: elas só mudam por aqui (editar uma à mão é recusado); \u{201c}Detach\u{201d} \
             as transforma em regras comuns e esvazia a matriz.",
        );
        ui.add_space(6.0);
        let dark = ui.visuals().dark_mode;
        let mut change: Option<(String, String, &'static str)> = None;
        Grid::new("zone-matrix")
            .striped(true)
            .spacing([10.0, 6.0])
            .show(ui, |ui| {
                ui.weak("from \\ to");
                for to in &zones {
                    ui.strong(to);
                }
                ui.end_row();
                for from in &zones {
                    ui.strong(from);
                    for to in &zones {
                        if from == to {
                            ui.weak("·");
                            continue;
                        }
                        let now = cells.iter().find(|(f, t, _)| f == from && t == to).map_or(
                            NONE,
                            |(_, _, a)| match a.as_str() {
                                ALLOW => ALLOW,
                                BLOCK => BLOCK,
                                _ => NONE,
                            },
                        );
                        let text = match cell_color(now, dark) {
                            Some(c) => RichText::new(now).color(c).strong(),
                            None => RichText::new(now),
                        };
                        ui.add_enabled_ui(set.is_ok(), |ui| {
                            egui::ComboBox::from_id_salt(("zone-cell", from, to))
                                .selected_text(text)
                                .width(80.0)
                                .show_ui(ui, |ui| {
                                    for choice in [NONE, ALLOW, BLOCK] {
                                        if ui.selectable_label(now == choice, choice).clicked()
                                            && now != choice
                                        {
                                            change = Some((from.clone(), to.clone(), choice));
                                        }
                                    }
                                });
                        });
                    }
                    ui.end_row();
                }
            });
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.weak(format!(
                "{} cell(s), {generated} generated rule(s)",
                cells.len()
            ));
            if crate::table::action(ui, "Clear", can.check("ip.firewall.zone.clear")) {
                self.run("ip.firewall.zone.clear", json!({}));
            }
            if crate::table::action(ui, "Detach", can.check("ip.firewall.zone.detach")) {
                self.run("ip.firewall.zone.detach", json!({}));
            }
        });
        if let Some((from, to, choice)) = change {
            let action = if choice == NONE { "none" } else { choice };
            self.run(
                "ip.firewall.zone.set",
                json!({ "from": from, "to": to, "action": action }),
            );
        }
    }
}
