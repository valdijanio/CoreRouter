//! Messages of the OS log the router knows (G4.8b): for each, what it
//! means in plain Portuguese and where to go about it — a window of the
//! GUI and the command behind it. Data, not code: a new message is one
//! more entry in [`KNOWN`] (and a line in the table test).
//!
//! A line matches an entry when its lower-cased message has every word of
//! `all` and, if `any` is not empty, one of `any`; the first entry that
//! matches wins (put the narrow ones first).

use corerouter_hal::oslog::{OsLine, OsSource};
use serde_json::{Value, json};

/// Where an explanation sends the operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Action {
    /// Button text; `{device}` is the line's device.
    pub label: &'static str,
    /// GUI window id (`tuning`, `graphs`, `interfaces`, `services`,
    /// `resources`, `firewall`).
    pub window: &'static str,
    /// The command that window runs (for the terminal and MCP).
    pub command: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Known {
    pub id: &'static str,
    /// Only lines of this source; `None`: any.
    pub source: Option<OsSource>,
    pub all: &'static [&'static str],
    pub any: &'static [&'static str],
    /// Short, for the row's chip and the detail's title.
    pub title: &'static str,
    /// "O que significa": what happened, the usual causes, what to do.
    pub meaning: &'static str,
    pub actions: &'static [Action],
    /// Worth a line in the router's log (`system,error`) when it first
    /// shows up: it costs traffic or hardware now.
    pub alert: bool,
}

const TUNING_PORT: Action = Action {
    label: "Abrir Tuning › {device}",
    window: "tuning",
    command: "system.tuning.interface.print",
};
const GRAPH: Action = Action {
    label: "Ver no gráfico",
    window: "graphs",
    command: "system.graph.print",
};
const INTERFACES: Action = Action {
    label: "Abrir Interfaces › {device}",
    window: "interfaces",
    command: "interface.list",
};
const RESOURCES: Action = Action {
    label: "Abrir Resources",
    window: "resources",
    command: "system.resource.print",
};
const SERVICES: Action = Action {
    label: "Abrir Services",
    window: "services",
    command: "system.service.print",
};
const TUNING: Action = Action {
    label: "Abrir Tuning",
    window: "tuning",
    command: "system.tuning.print",
};
const FIREWALL: Action = Action {
    label: "Abrir Firewall",
    window: "firewall",
    command: "ip.firewall.filter.list",
};
const K: Option<OsSource> = Some(OsSource::Kernel);

pub const KNOWN: &[Known] = &[
    Known {
        id: "nic-ring-full",
        source: K,
        all: &[],
        any: &["rx_missed", "rx_fifo", "rx_no_buffer", "ring full", "no rx buffer", "rx_over"],
        title: "Anel de recepção da placa cheio",
        meaning: "A placa recebeu quadros mais depressa do que o sistema os tirou do anel (ring) de \
                  recepção e descartou os que não couberam: é perda de pacote na entrada. As \
                  causas comuns são o anel pequeno, todas as filas e interrupções num núcleo só, \
                  ou a CPU ocupada. Aumente o rx ring da porta e espalhe as filas e IRQs pelos \
                  núcleos em System › Tuning; confira no gráfico se coincide com pico de tráfego.",
        actions: &[TUNING_PORT, GRAPH],
        alert: true,
    },
    Known {
        id: "nic-tx-timeout",
        source: K,
        all: &[],
        any: &["transmit queue", "tx unit hang", "hardware unit hang", "tx timeout", "tx hang"],
        title: "Placa parou de transmitir",
        meaning: "Uma fila de transmissão da placa ficou parada além do prazo e o driver a \
                  reiniciou: o tráfego da porta para por um instante. Costuma ser driver ou \
                  firmware com defeito, economia de energia (EEE, ASPM) ou a placa sobrecarregada. \
                  Se repetir, atualize o driver/firmware, desligue o EEE e veja os contadores da \
                  porta.",
        actions: &[INTERFACES, TUNING_PORT],
        alert: true,
    },
    Known {
        id: "lacp-no-partner",
        source: K,
        all: &["802.3ad"],
        any: &["no 802.3ad response", "no active aggregator"],
        title: "Bonding LACP sem resposta do outro lado",
        meaning: "O bonding em modo 802.3ad (LACP) não recebeu resposta do equipamento do outro \
                  lado: as portas não formam o agregado e ficam como reserva. Confira se o switch \
                  tem LACP ligado nas mesmas portas, o mesmo modo (active/passive) e a mesma \
                  velocidade.",
        actions: &[INTERFACES],
        alert: false,
    },
    Known {
        id: "link-flap",
        source: K,
        all: &[],
        any: &["link is down", "link is up", "nic link is down", "nic link is up", "link down", "link up"],
        title: "Link da porta caiu ou subiu",
        meaning: "A porta perdeu ou recuperou o sinal do outro lado. Uma vez é normal (cabo \
                  tirado, equipamento reiniciado); várias vezes em poucos minutos é \"flap\": \
                  cabo, conector ou SFP com defeito, autonegociação ruim ou o equipamento do \
                  outro lado reiniciando. Veja quantas vezes repetiu e os erros da interface.",
        actions: &[INTERFACES, GRAPH],
        alert: false,
    },
    Known {
        id: "conntrack-full",
        source: K,
        all: &[],
        any: &["nf_conntrack: table full", "table full, dropping packet"],
        title: "Tabela de conexões (conntrack) cheia",
        meaning: "A tabela onde o kernel guarda as conexões em andamento (usada pelo NAT, CGNAT e \
                  firewall com estado) encheu, e cada conexão nova está sendo descartada: os \
                  assinantes não conseguem abrir conexões. Aumente nf_conntrack_max (e os \
                  buckets) em System › Tuning, reduza os timeouts, e veja se não é um ataque \
                  enchendo a tabela.",
        actions: &[TUNING, GRAPH],
        alert: true,
    },
    Known {
        id: "neighbour-overflow",
        source: K,
        all: &[],
        any: &["neighbor table overflow", "neighbour table overflow"],
        title: "Tabela ARP/vizinhos cheia",
        meaning: "A tabela de vizinhos (ARP no IPv4, ND no IPv6) passou do limite gc_thresh3 e o \
                  kernel não aprende vizinhos novos: hosts deixam de ser alcançados. Comum em \
                  rede grande sem roteamento (muitos hosts na mesma sub-rede). Aumente \
                  net.ipv4.neigh.default.gc_thresh1/2/3 em System › Tuning.",
        actions: &[TUNING],
        alert: true,
    },
    Known {
        id: "syn-flood",
        source: K,
        all: &["syn flooding"],
        any: &[],
        title: "Possível ataque SYN flood",
        meaning: "Chegaram mais pedidos de conexão TCP (SYN) a uma porta do roteador do que ele \
                  aceita, e o kernel passou a responder com SYN cookies. Pode ser ataque ou um \
                  serviço do roteador exposto sem necessidade. Restrinja quem alcança essa porta \
                  no firewall (ou no XDP, para volume alto).",
        actions: &[FIREWALL],
        alert: false,
    },
    Known {
        id: "martian",
        source: K,
        all: &["martian"],
        any: &[],
        title: "Pacote com endereço impossível (martian)",
        meaning: "Chegou um pacote cuja origem ou destino não faz sentido na interface onde \
                  chegou (endereço privado vindo da internet, origem que a rota não leva de \
                  volta): o rp_filter o descartou. Muitos indicam rota assimétrica ou spoofing; \
                  ajuste o rp_filter da porta em System › Tuning se a rota assimétrica for de \
                  propósito.",
        actions: &[TUNING],
        alert: false,
    },
    Known {
        id: "oom-kill",
        source: None,
        all: &[],
        any: &["out of memory", "oom-kill", "invoked oom-killer", "killed by the oom killer"],
        title: "Memória acabou: o kernel matou um processo",
        meaning: "A memória livre acabou e o kernel escolheu um processo para matar (OOM \
                  killer), em geral o que mais usava: se foi um serviço do roteador, ele cai até \
                  o supervisor o reiniciar. Veja quanto cada serviço usa em Resources, limite \
                  caches grandes (DNS, histórico) ou ponha mais memória.",
        actions: &[RESOURCES, SERVICES],
        alert: true,
    },
    Known {
        id: "disk-io-error",
        source: K,
        all: &[],
        any: &["i/o error", "ext4-fs error", "medium error", "timeout, aborting", "remounting filesystem read-only", "uncorrectable error"],
        title: "Erro de leitura ou escrita no disco",
        meaning: "O disco não conseguiu ler ou gravar um bloco. Pode ser o disco (ou cartão, \
                  pendrive) no fim da vida, cabo ou conector solto, ou falta de energia. Se o \
                  sistema de arquivos passou a somente leitura, a configuração deixa de ser \
                  salva. Faça backup da configuração já e troque o disco.",
        actions: &[RESOURCES],
        alert: true,
    },
    Known {
        id: "mce",
        source: K,
        all: &[],
        any: &["machine check", "hardware error", "corrected error", "mce: cpu"],
        title: "Erro de hardware (Machine Check)",
        meaning: "A CPU ou a memória relataram um erro de hardware. Corrigido (corrected) o \
                  sistema segue, mas a repetição avisa que um pente de memória ou a CPU está \
                  falhando; não corrigido derruba o sistema. Anote o banco/DIMM da mensagem, \
                  rode um teste de memória e confira temperatura e fonte.",
        actions: &[RESOURCES],
        alert: true,
    },
    Known {
        id: "thermal",
        source: K,
        all: &[],
        any: &["temperature above threshold", "clock throttled", "critical temperature", "thermal shutdown", "overheat", "cpu throttl"],
        title: "CPU quente: o relógio foi reduzido",
        meaning: "A CPU passou da temperatura segura e baixou a frequência para esfriar (thermal \
                  throttling): o roteador encaminha menos pacotes até esfriar. Limpe o \
                  dissipador, confira as ventoinhas e a ventilação do rack.",
        actions: &[RESOURCES, GRAPH],
        alert: true,
    },
    Known {
        id: "lockup",
        source: K,
        all: &[],
        any: &["soft lockup", "hard lockup", "self-detected stall", "blocked for more than"],
        title: "CPU ou tarefa travada",
        meaning: "Um núcleo ficou preso sem ceder a vez (lockup), ou uma tarefa esperou mais de \
                  dois minutos por disco ou rede (hung task). Pode ser driver com defeito, disco \
                  lento ou o núcleo afogado em interrupções. Veja a carga por núcleo em \
                  Resources e as interrupções em Tuning.",
        actions: &[RESOURCES, TUNING],
        alert: true,
    },
    Known {
        id: "segfault",
        source: None,
        all: &[],
        any: &["segfault at", "general protection fault", "trap invalid opcode"],
        title: "Programa caiu (falha de segmentação)",
        meaning: "Um programa acessou memória que não podia e o kernel o encerrou. Se é um \
                  serviço do roteador, o supervisor o reinicia (veja em Services); se repete, é \
                  defeito do programa — guarde a linha para o relatório.",
        actions: &[SERVICES],
        alert: false,
    },
    Known {
        id: "login-failed",
        source: Some(OsSource::Auth),
        all: &[],
        any: &["failed password", "invalid user", "authentication failure", "password check failed"],
        title: "Login recusado",
        meaning: "Alguém tentou entrar no sistema com senha ou usuário errados. Muitas tentativas \
                  vindas de fora são robôs testando senhas: deixe o SSH só para a rede de \
                  gerência e bloqueie quem insiste numa address list do firewall.",
        actions: &[FIREWALL],
        alert: false,
    },
    Known {
        id: "suppressed",
        source: K,
        all: &["callbacks suppressed"],
        any: &[],
        title: "O kernel resumiu mensagens repetidas",
        meaning: "O kernel tem um limite de mensagens por segundo; acima dele, deixa de escrever \
                  as repetidas e diz quantas pulou. O que importa é a mensagem logo antes desta, \
                  que estava repetindo.",
        actions: &[],
        alert: false,
    },
];

/// The entry `line` matches, if any.
pub fn known(line: &OsLine) -> Option<&'static Known> {
    let msg = line.message.to_lowercase();
    KNOWN.iter().find(|k| {
        k.source.is_none_or(|s| s == line.source)
            && k.all.iter().all(|w| msg.contains(w))
            && (k.any.is_empty() || k.any.iter().any(|w| msg.contains(w)))
    })
}

/// What `log.os.print` says about a known line.
pub fn known_json(k: &Known, line: &OsLine) -> Value {
    let device = if line.device.is_empty() {
        "porta"
    } else {
        line.device.as_str()
    };
    json!({
        "id": k.id,
        "title": k.title,
        "meaning": k.meaning,
        "alert": k.alert,
        "actions": k.actions.iter().map(|a| json!({
            "label": a.label.replace("{device}", device),
            "window": a.window,
            "command": a.command,
            "device": line.device,
        })).collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn l(source: OsSource, msg: &str) -> OsLine {
        let (unit, device, pid) = corerouter_hal::oslog::kernel_origin(msg);
        OsLine {
            time_us: 0,
            severity: 4,
            source,
            unit,
            device,
            pid,
            message: msg.into(),
            boot: String::new(),
        }
    }

    /// Real lines (from kernels and the fixtures) and the entry each must hit.
    #[test]
    fn catalogue_table() {
        use OsSource::{Auth, Kernel, Services};
        let cases: &[(OsSource, &str, Option<&str>)] = &[
            (Kernel, "r8169 0000:03:00.0 ether2: rx_missed 1 (ring full, frame dropped)", Some("nic-ring-full")),
            (Kernel, "ixgbe 0000:01:00.0 eth4: rx_no_buffer_count 1022", Some("nic-ring-full")),
            (Kernel, "NETDEV WATCHDOG: eth0 (r8169): transmit queue 0 timed out 5000 ms", Some("nic-tx-timeout")),
            (Kernel, "e1000e 0000:00:19.0 eno1: Detected Hardware Unit Hang:", Some("nic-tx-timeout")),
            (Kernel, "b1bond: Warning: No 802.3ad response from the link partner for any adapters in the bond", Some("lacp-no-partner")),
            (Kernel, "r8169 0000:02:00.0 ether1: Link is Down", Some("link-flap")),
            (Kernel, "r8169 0000:02:00.0 eno1: Link is Up - 1Gbps/Full - flow control rx/tx", Some("link-flap")),
            (Kernel, "igb 0000:03:00.0 eth1: igb: eth1 NIC Link is Up 1000 Mbps Full Duplex", Some("link-flap")),
            (Kernel, "nf_conntrack: nf_conntrack: table full, dropping packet", Some("conntrack-full")),
            (Kernel, "neighbour: arp_cache: neighbor table overflow!", Some("neighbour-overflow")),
            (Kernel, "TCP: request_sock_TCP: Possible SYN flooding on port 0.0.0.0:443. Sending cookies.", Some("syn-flood")),
            (Kernel, "IPv4: martian source 10.0.0.1 from 192.0.2.1, on dev ether1", Some("martian")),
            (Kernel, "Out of memory: Killed process 2211 (unbound) total-vm:812344kB", Some("oom-kill")),
            (Kernel, "unbound invoked oom-killer: gfp_mask=0x140cca(GFP_HIGHUSER_MOVABLE|__GFP_COMP), order=0", Some("oom-kill")),
            (Services, "unbound.service: A process of this unit has been killed by the OOM killer.", Some("oom-kill")),
            (Kernel, "I/O error, dev sda, sector 123456 op 0x1:(WRITE) flags 0x800 phys_seg 1 prio class 2", Some("disk-io-error")),
            (Kernel, "EXT4-fs error (device sda1): ext4_find_entry:1455: inode #2: comm ls: reading directory lblock 0", Some("disk-io-error")),
            (Kernel, "nvme nvme0: I/O 18 QID 3 timeout, aborting", Some("disk-io-error")),
            (Kernel, "mce: [Hardware Error]: Machine check events logged", Some("mce")),
            (Kernel, "EDAC MC0: 1 CE memory read error on CPU_SrcID#0_Ha#0_Chan#1_DIMM#0 (corrected error)", Some("mce")),
            (Kernel, "CPU3: Core temperature above threshold, cpu clock throttled (total events = 1)", Some("thermal")),
            (Kernel, "watchdog: BUG: soft lockup - CPU#2 stuck for 22s! [ksoftirqd/2:22]", Some("lockup")),
            (Kernel, "INFO: task jbd2/sda1-8:312 blocked for more than 120 seconds.", Some("lockup")),
            (Kernel, "dnsmasq[4242]: segfault at 0 ip 00005581c3a1b2c4 sp 00007ffd0a321178 error 4", Some("segfault")),
            (Auth, "Failed password for invalid user admin from 203.0.113.77 port 41234 ssh2", Some("login-failed")),
            (Auth, "password check failed for user (admin)", Some("login-failed")),
            (Kernel, "kauditd_printk_skb: 5 callbacks suppressed", Some("suppressed")),
            // Look alike, mean nothing.
            (Kernel, "OOM killer enabled.", None),
            (Kernel, "MCE: In-kernel MCE decoding enabled.", None),
            (Kernel, "ACPI: thermal: Thermal Zone [TZ01] (76 C)", None),
            (Kernel, "thermal_sys: Registered thermal governor 'step_wise'", None),
            (Services, "Failed password for x", None),
            (Kernel, "usb 7-1.2: reset high-speed USB device number 4 using xhci_hcd", None),
        ];
        for (src, msg, want) in cases {
            assert_eq!(known(&l(*src, msg)).map(|k| k.id), *want, "{msg}");
        }
        // Every entry is reached by the table.
        for k in KNOWN {
            assert!(cases.iter().any(|(_, _, w)| *w == Some(k.id)), "{} has no case", k.id);
        }
    }

    #[test]
    fn entries_are_well_formed() {
        let mut ids = std::collections::BTreeSet::new();
        for k in KNOWN {
            assert!(ids.insert(k.id), "duplicate {}", k.id);
            assert!(!k.all.is_empty() || !k.any.is_empty(), "{} matches everything", k.id);
            for w in k.all.iter().chain(k.any) {
                assert_eq!(*w, w.to_lowercase(), "{}: '{w}' must be lower case", k.id);
            }
            assert!(k.meaning.len() > 80 && !k.title.is_empty());
            for a in k.actions {
                assert!(!a.window.is_empty() && crate::cmd::find(a.command).is_some() || a.window == "resources",
                    "{}: command {} does not exist", k.id, a.command);
            }
        }
    }

    #[test]
    fn action_names_the_device() {
        let line = l(OsSource::Kernel, "r8169 0000:03:00.0 ether2: rx_missed 1");
        let k = known(&line).unwrap();
        let v = known_json(k, &line);
        assert_eq!(v["actions"][0]["label"], "Abrir Tuning › ether2");
        assert_eq!(v["actions"][0]["window"], "tuning");
        assert_eq!(v["actions"][1]["label"], "Ver no gráfico");
    }
}
