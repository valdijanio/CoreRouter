//! Health checks of System › Resources (G4.8a): rules over the readings
//! (`crate::system_resource`) and the state other features keep (NTP,
//! services, CGNAT), each with a severity, the reason and what to do, in
//! Portuguese for people and with stable English keys for scripts and the
//! MCP (`cpu`, `memory.pressure`…).
//!
//! The rules are a pure function of [`Inputs`] ([`evaluate`]), tested by a
//! table. The thresholds follow what operators use elsewhere: Juniper's
//! `show system alarms`, Cockpit's health overview, the PSI guidance of
//! the kernel (`Documentation/accounting/psi.rst`: sustained `full`
//! pressure is thrashing).
//!
//! Alerts ([`Session::health_alerts`]): a check that turns warning or
//! error, or back to ok, writes one line to the router's log (topics
//! `system` + level, origin `health`) — the path of the G4.5 bandwidth
//! alerts, so the logging rules send it to syslog or ClickHouse. A state
//! must hold for two readings in a row before it is logged (a value on the
//! threshold does not flap the log).

use std::collections::BTreeMap;

use corerouter_model::ntp::{NtpState, NtpStatus};
use corerouter_model::service::{ServiceState, ServiceTable};
use serde::Serialize;

use crate::Session;
use crate::cgnat_blocks::CgnatRuntime;
use crate::system_resource::{Level, ResourceMonitor, memory_used, percent, sensor_level};

/// Severity of a check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// No data to judge (no daemon, no sensor).
    Unknown,
    Ok,
    Warning,
    Error,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Ok => "ok",
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }
}

impl From<Level> for Severity {
    fn from(l: Level) -> Self {
        match l {
            Level::Ok => Self::Ok,
            Level::Warning => Self::Warning,
            Level::Error => Self::Error,
        }
    }
}

/// One check's verdict.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Check {
    /// Stable id (`cpu`, `disk`, `nic.errors`…).
    pub key: &'static str,
    /// Short English name (the GUI's label).
    pub name: &'static str,
    pub severity: Severity,
    /// The measured value, for people (`92 %`, `ether4: 17/s`).
    pub value: Option<String>,
    /// Why, in Portuguese.
    pub reason: String,
    /// What to do, in Portuguese (`None` when ok).
    pub action: Option<String>,
}

// Thresholds (warning, error).
pub const CPU: (f32, f32) = (80.0, 95.0);
/// PSI memory `some` avg60, % (tasks waited for memory this share of time).
pub const PSI_SOME: (f32, f32) = (10.0, 40.0);
/// PSI memory `full` avg60, %: everyone stalled — thrashing.
pub const PSI_FULL_ERROR: f32 = 5.0;
pub const MEM_USED: (f32, f32) = (90.0, 97.0);
pub const SWAP_USED: (f32, f32) = (50.0, 90.0);
/// Pages swapped in per second that mean the working set does not fit.
pub const SWAP_IN_RATE: f64 = 100.0;
/// Free space below this %.
pub const DISK_FREE: (f32, f32) = (15.0, 5.0);
pub const CONNTRACK: (f32, f32) = (80.0, 95.0);
/// Drops per second on one link.
pub const DROPS: (f64, f64) = (100.0, 10_000.0);
/// Errors per second on one link (any is a warning: cables and optics).
pub const ERRORS_ERROR: f64 = 100.0;
/// OOM kills this recent (s) are reported.
pub const OOM_WINDOW: u64 = 3600;
/// RSS: one CPU taking this share of the receive softirqs, with at least
/// [`RSS_MIN_CPUS`] CPUs and [`RSS_MIN_RATE`] softirqs a second.
pub const RSS_SHARE: f64 = 50.0;
pub const RSS_MIN_CPUS: usize = 4;
pub const RSS_MIN_RATE: f64 = 2000.0;
/// History points (5 s apart) the CPU check averages: 5 min.
pub const CPU_POINTS: usize = 60;
/// At least this many points before the CPU check judges (1 min).
pub const CPU_MIN_POINTS: usize = 12;

/// Receive buffers of the daemon's burst-prone sockets (RADIUS, the PPPoE
/// access ports), as the services opened them: name → (bytes the kernel
/// gave, bytes asked for). Short = `net.core.rmem_max` capped it and the
/// daemon has no CAP_NET_ADMIN to pass it (G4.3g).
#[derive(Debug, Default)]
pub struct SocketBuffers {
    pub sockets: BTreeMap<String, (usize, usize)>,
}

/// The first ECMP warning: its prefix with the paths, and the fix.
pub type EcmpFirst = (String, Option<String>);

/// What the rules look at, gathered from the session.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Inputs {
    /// Average CPU load of the history window, and how many points.
    pub cpu_avg: Option<(f32, usize)>,
    pub psi_some60: Option<f32>,
    pub psi_full60: Option<f32>,
    pub mem_used: Option<f32>,
    /// Swap in use, % (`None`: no swap).
    pub swap_used: Option<f32>,
    pub swap_in_rate: Option<f64>,
    /// (mount, free %).
    pub disks: Vec<(String, f32)>,
    /// (sensor, °C, crit, level).
    pub temps: Vec<(String, f64, Option<f64>, Level)>,
    /// (interface, errors/s, drops/s).
    pub nics: Vec<(String, f64, f64)>,
    pub conntrack: Option<(u64, u64)>,
    /// CGNAT: subscribers above their pool's alert percent, and new
    /// connections that found no free port since the start.
    pub cgnat: Option<(usize, u64)>,
    /// OOM kills seen in the last [`OOM_WINDOW`] seconds.
    pub oom_recent: Option<u64>,
    /// NTP client enabled and its state.
    pub ntp: Option<(bool, NtpState)>,
    /// Something configured depends on the clock (RADIUS servers in use):
    /// a disabled NTP client is then a warning, not the factory default.
    pub ntp_needed: bool,
    /// Supervised services by state (`None`: no supervisor — lab).
    pub services: Option<Vec<(String, ServiceState)>>,
    /// (busiest CPU, its share of NET_RX %, CPUs, NET_RX/s).
    pub rss: Option<(usize, f64, usize, f64)>,
    /// (socket, bytes given, bytes asked) of [`SocketBuffers`] (`None`:
    /// no service reported one).
    pub sockbuf: Option<Vec<(String, usize, usize)>>,
    /// ECMP groups of the routing table (G1.27j): warnings (origins mixed
    /// or the default route), infos, and the first warning's prefix with
    /// its paths and the fix. `None`: not looked at.
    pub ecmp: Option<(usize, usize, Option<EcmpFirst>)>,
    /// Enabled accounts of group full without a password (G0.3d): the
    /// router takes an empty password from the network for them.
    pub no_password: Vec<String>,
    /// The running slot of the A/B image and whether its root is the
    /// dm-verity device of its signed root hash (G1.6qb). `None`: not on
    /// the image (lab, browser, the package service has not reported).
    pub root_verity: Option<(String, bool)>,
    /// Whether any reading exists at all.
    pub readings: bool,
}

fn level<T: PartialOrd>(v: T, warn: T, err: T, higher_is_worse: bool) -> Severity {
    let (w, e) = if higher_is_worse {
        (v >= warn, v >= err)
    } else {
        (v <= warn, v <= err)
    };
    if e {
        Severity::Error
    } else if w {
        Severity::Warning
    } else {
        Severity::Ok
    }
}

fn pct(v: f32) -> String {
    format!("{v:.0} %")
}

/// Every check, in a fixed order.
pub fn evaluate(i: &Inputs) -> Vec<Check> {
    let mut out = Vec::new();
    let mut push = |key, name, severity, value: Option<String>, reason: String, action: Option<&str>| {
        out.push(Check {
            key,
            name,
            severity,
            value,
            reason,
            action: if matches!(severity, Severity::Warning | Severity::Error) {
                action.map(str::to_owned)
            } else {
                None
            },
        });
    };
    let no_data = || "sem leitura da máquina".to_owned();

    // CPU sustained.
    match i.cpu_avg {
        Some((avg, n)) if n >= CPU_MIN_POINTS => {
            let s = level(avg, CPU.0, CPU.1, true);
            let reason = match s {
                Severity::Ok => format!("CPU média de {} nos últimos {} min", pct(avg), n * 5 / 60),
                _ => format!("CPU alta por {} min (média {})", n * 5 / 60, pct(avg)),
            };
            push("cpu", "CPU", s, Some(pct(avg)), reason,
                Some("Veja a aba Processes (quem consome) e a aba CPU (softirq concentrado numa CPU indica RSS/IRQ mal distribuídos)."));
        }
        Some((avg, _)) => push("cpu", "CPU", Severity::Unknown, Some(pct(avg)),
            "menos de 1 min de histórico para julgar".into(), None),
        None => push("cpu", "CPU", Severity::Unknown, None, no_data(), None),
    }

    // Memory pressure (PSI), falling back on the share in use.
    match (i.psi_some60, i.psi_full60, i.mem_used) {
        (Some(some), full, used) => {
            let mut s = level(some, PSI_SOME.0, PSI_SOME.1, true);
            if full.is_some_and(|f| f >= PSI_FULL_ERROR) {
                s = Severity::Error;
            }
            let reason = match s {
                Severity::Ok => format!("pressão de memória baixa (PSI some {some:.1} %)"),
                _ => format!(
                    "processos esperando memória {some:.1} % do tempo no último minuto{}",
                    full.filter(|f| *f > 0.0).map(|f| format!(", todos parados {f:.1} %")).unwrap_or_default()
                ),
            };
            push("memory.pressure", "Memory pressure", s,
                Some(used.map_or_else(|| format!("PSI {some:.1} %"), |u| format!("{} em uso, PSI {some:.1} %", pct(u)))),
                reason, Some("Veja quem usa memória na aba Processes; tabelas grandes (BGP full table, conntrack, cache DNS) pedem mais RAM."));
        }
        (None, _, Some(used)) => {
            let s = level(used, MEM_USED.0, MEM_USED.1, true);
            push("memory.pressure", "Memory pressure", s, Some(pct(used)),
                format!("{} da memória em uso (este kernel não tem PSI)", pct(used)),
                Some("Veja quem usa memória na aba Processes."));
        }
        _ => push("memory.pressure", "Memory pressure", Severity::Unknown, None, no_data(), None),
    }

    // Swap.
    match i.swap_used {
        None if i.readings => push("swap", "Swap", Severity::Ok, None, "sem swap configurado".into(), None),
        None => push("swap", "Swap", Severity::Unknown, None, no_data(), None),
        Some(used) => {
            let mut s = level(used, SWAP_USED.0, SWAP_USED.1, true);
            let thrash = i.swap_in_rate.is_some_and(|r| r >= SWAP_IN_RATE);
            if thrash && s < Severity::Warning {
                s = Severity::Warning;
            }
            let reason = if thrash {
                format!("lendo do swap ({:.0} páginas/s): a memória não basta", i.swap_in_rate.unwrap_or(0.0))
            } else {
                format!("{} do swap em uso", pct(used))
            };
            push("swap", "Swap", s, Some(pct(used)), reason,
                Some("Um roteador não deve viver no swap: libere memória ou acrescente RAM."));
        }
    }

    // Disk.
    match i.disks.iter().min_by(|a, b| a.1.total_cmp(&b.1)) {
        None => push("disk", "Disk", Severity::Unknown, None, "nenhum disco com dados".into(), None),
        Some((mount, free)) => {
            let s = level(*free, DISK_FREE.0, DISK_FREE.1, false);
            push("disk", "Disk", s, Some(format!("{mount}: {} livre", pct(*free))),
                format!("{mount} com {} livre", pct(*free)),
                Some("Apague logs e capturas antigos, ou reduza o histórico de gráficos (system.graph.set) e de logs em disco."));
        }
    }

    // Temperature.
    match i.temps.iter().max_by(|a, b| a.3.cmp(&b.3).then(a.1.total_cmp(&b.1))) {
        None => push("temperature", "Temperature", Severity::Unknown, None, "nenhum sensor de temperatura".into(), None),
        Some((name, t, crit, lvl)) => {
            let reason = match crit {
                Some(c) => format!("{name} a {t:.0} °C (crítico em {c:.0} °C)"),
                None => format!("{name} a {t:.0} °C"),
            };
            push("temperature", "Temperature", (*lvl).into(), Some(format!("{t:.0} °C")), reason,
                Some("Confira ventilação, ventoinhas e poeira; perto do crítico o hardware reduz o clock ou desliga."));
        }
    }

    // NIC errors and drops.
    let worst = i
        .nics
        .iter()
        .map(|(n, e, d)| {
            let s = if *e >= ERRORS_ERROR || *d >= DROPS.1 {
                Severity::Error
            } else if *e > 0.0 || *d >= DROPS.0 {
                Severity::Warning
            } else {
                Severity::Ok
            };
            (s, n, *e, *d)
        })
        .max_by(|a, b| a.0.cmp(&b.0).then(a.2.total_cmp(&b.2)).then(a.3.total_cmp(&b.3)));
    match worst {
        None => push("nic.errors", "NIC errors", Severity::Unknown, None, "sem taxas de interface ainda".into(), None),
        Some((Severity::Ok, ..)) => push("nic.errors", "NIC errors", Severity::Ok, None, "nenhum erro ou descarte subindo".into(), None),
        Some((s, n, e, d)) => push("nic.errors", "NIC errors", s, Some(format!("{n}: {e:.1} erros/s, {d:.0} descartes/s")),
            if e > 0.0 { format!("{n} com erros subindo ({e:.1}/s)") } else { format!("{n} descartando {d:.0} pacotes/s") },
            Some("Erros: cabo, conector, óptica ou duplex. Descartes: fila cheia (anel, netdev_max_backlog) ou CPU sem fôlego — veja System › Tuning.")),
    }

    // Conntrack.
    match i.conntrack {
        Some((count, max)) if max > 0 => {
            let p = percent(count, max).unwrap_or(0.0);
            push("conntrack", "Conntrack", level(p, CONNTRACK.0, CONNTRACK.1, true),
                Some(format!("{count}/{max}")), format!("tabela de conexões {} cheia", pct(p)),
                Some("Cheia, conexões novas são descartadas: aumente nf_conntrack_max (System › Tuning) ou reduza os timeouts."));
        }
        _ => push("conntrack", "Conntrack", Severity::Unknown, None, "sem conntrack neste sistema".into(), None),
    }

    // CGNAT ports.
    match i.cgnat {
        None => push("cgnat.ports", "CGNAT ports", Severity::Ok, None, "sem CGNAT por blocos".into(), None),
        Some((above, failed)) => {
            let s = if failed > 0 { Severity::Error } else if above > 0 { Severity::Warning } else { Severity::Ok };
            let reason = match s {
                Severity::Error => format!("{failed} conexões novas sem porta livre no NAT"),
                Severity::Warning => format!("{above} assinante(s) acima do alerta de portas do pool"),
                _ => "portas dos pools com folga".into(),
            };
            push("cgnat.ports", "CGNAT ports", s, Some(format!("{above} acima, {failed} falhas")), reason,
                Some("Veja IP › Firewall › CGNAT: mais portas por assinante, mais blocos ou mais endereços públicos."));
        }
    }

    // OOM kills.
    match i.oom_recent {
        None => push("oom", "OOM kills", Severity::Unknown, None, no_data(), None),
        Some(0) => push("oom", "OOM kills", Severity::Ok, None, "nenhum processo morto por falta de memória na última hora".into(), None),
        Some(n) => push("oom", "OOM kills", Severity::Error, Some(n.to_string()),
            format!("{n} processo(s) morto(s) por falta de memória na última hora"),
            Some("O kernel matou processos para liberar memória: veja o OS Log e quem cresce na aba Processes.")),
    }

    // NTP.
    match i.ntp {
        // G4.6i: off is the RouterOS factory default, so a new router must not
        // be born with a warning; it matters once RADIUS depends on the clock.
        Some((false, _)) if i.ntp_needed => push("ntp", "NTP", Severity::Warning, Some("disabled".into()),
            "cliente NTP desligado, mas há servidores RADIUS configurados: o horário errado quebra Event-Timestamp e a contabilidade".into(),
            Some("Ligue o cliente NTP: system.ntp.client.set enabled=yes servers=…")),
        Some((false, _)) => push("ntp", "NTP", Severity::Ok, Some("disabled".into()),
            "cliente NTP desligado (padrão de fábrica); ligue em System › NTP Client se logs e certificados precisarem do horário certo".into(),
            None),
        Some((true, NtpState::Synchronized)) => push("ntp", "NTP", Severity::Ok, Some("synchronized".into()), "relógio sincronizado".into(), None),
        Some((true, NtpState::Waiting)) => push("ntp", "NTP", Severity::Warning, Some("waiting".into()),
            "cliente NTP sem resposta dos servidores".into(),
            Some("Confira os servidores e se a porta UDP 123 sai (System › NTP Client mostra o último erro).")),
        Some((true, NtpState::Stopped)) | None => push("ntp", "NTP", Severity::Unknown, None, "sem daemon rodando o cliente NTP".into(), None),
    }

    // Accounts without a password (G0.3d): logins from any network with an
    // empty password are accepted, as on a RouterOS CHR; the operator's
    // choice, so a warning, never an error.
    if i.no_password.is_empty() {
        push("auth.no_password", "Admin password", Severity::Ok, None,
            "todas as contas do grupo full têm senha".into(), None);
    } else {
        let names = i.no_password.iter().map(|n| n.chars().take(64).collect::<String>()).collect::<Vec<_>>().join(", ");
        push("auth.no_password", "Admin password", Severity::Warning, Some(names.clone()),
            format!("conta(s) {names} do grupo full sem senha: qualquer um que alcance o roteador pela rede entra com a senha vazia e o controla"),
            Some("Defina a senha: botão \"Set password\" na barra da GUI, `/user set admin password=…` no terminal ou user.set."));
    }

    // The root file system checked block by block against the signed root
    // hash (G1.6qb). The first boot of a qcow2/OVA or of a disk written with
    // dd goes through the built-in fallback `root=PARTUUID=`, without
    // verity, and writes the slot's boot entry: the next boot is verified.
    // A VM of the 2026-10-29 test ran a whole day like that unnoticed.
    match &i.root_verity {
        None => push("root.verity", "Root verity", Severity::Unknown, None,
            "fora da imagem A/B (laboratório, ou o serviço de pacotes não respondeu)".into(), None),
        Some((slot, true)) => push("root.verity", "Root verity", Severity::Ok, Some(format!("slot {slot}")),
            format!("o slot {slot} roda pela raiz dm-verity, conferida contra o hash assinado"), None),
        Some((slot, false)) => push("root.verity", "Root verity", Severity::Warning, Some(format!("slot {slot}")),
            format!("o slot {slot} rodando não está em dm-verity: a raiz não é conferida contra o hash assinado (primeiro boot de qcow2/OVA ou de disco gravado com dd pelo caminho reserva, ou NVRAM apagada)"),
            Some("Reinicie uma vez (`/system reboot confirm=yes` no terminal, ou system.reboot): este boot já gravou a entrada de boot do slot e o próximo sobe pela raiz verificada. Se o aviso voltar, confira em System › Packages a entrada de boot e a linha de comando do slot.")),
    }

    // Supervised services.
    match &i.services {
        None => push("services", "Services", Severity::Unknown, None, "sem supervisor de serviços (laboratório)".into(), None),
        Some(rows) => {
            let failed: Vec<&str> = rows.iter().filter(|r| r.1 == ServiceState::Failed).map(|r| r.0.as_str()).collect();
            let down: Vec<&str> = rows.iter().filter(|r| matches!(r.1, ServiceState::Restarting | ServiceState::Stopped)).map(|r| r.0.as_str()).collect();
            let (s, reason) = if !failed.is_empty() {
                (Severity::Error, format!("serviço(s) em falha: {}", failed.join(", ")))
            } else if !down.is_empty() {
                (Severity::Warning, format!("serviço(s) parado(s) ou reiniciando: {}", down.join(", ")))
            } else {
                (Severity::Ok, format!("{} serviços rodando", rows.len()))
            };
            push("services", "Services", s, None, reason,
                Some("Abra System › Services: o último erro de cada serviço diz por que caiu."));
        }
    }

    // RSS / IRQ distribution.
    match i.rss {
        Some((cpu, share, cpus, rate)) if cpus >= RSS_MIN_CPUS && rate >= RSS_MIN_RATE => {
            let s = if share >= RSS_SHARE { Severity::Warning } else { Severity::Ok };
            push("rss", "RSS balance", s, Some(format!("CPU{cpu}: {share:.0} %")),
                match s {
                    Severity::Ok => format!("recepção espalhada entre as CPUs (a mais carregada: CPU{cpu}, {share:.0} %)"),
                    _ => format!("CPU{cpu} recebe {share:.0} % dos softirqs de rede de {cpus} CPUs"),
                },
                Some("Distribua: mais filas na placa (RSS), RPS/XPS e afinidade das IRQs em System › Tuning › Interface."));
        }
        Some(_) => push("rss", "RSS balance", Severity::Ok, None, "pouco tráfego ou poucas CPUs para julgar".into(), None),
        None => push("rss", "RSS balance", Severity::Unknown, None, no_data(), None),
    }

    // Receive buffers of the sockets that take bursts.
    match &i.sockbuf {
        None => push("sockbuf", "Socket buffers", Severity::Unknown, None,
            "nenhum serviço com rajada aberto (RADIUS, PPPoE)".into(), None),
        Some(v) => {
            let short: Vec<String> = v
                .iter()
                .filter(|(_, got, want)| got < want)
                .map(|(n, got, want)| format!("{n} {} de {} KiB", got / 1024, want / 1024))
                .collect();
            if short.is_empty() {
                push("sockbuf", "Socket buffers", Severity::Ok, None,
                    format!("{} socket(s) com o buffer de recepção pedido", v.len()), None);
            } else {
                push("sockbuf", "Socket buffers", Severity::Warning, Some(short.join(", ")),
                    format!("buffer de recepção menor que o pedido: {}", short.join(", ")),
                    Some("Suba net.core.rmem_max (System › Tuning, recomendação sockbuf) ou rode o daemon com CAP_NET_ADMIN. Uma rajada depois de uma queda (respostas do RADIUS, PADIs de milhares de CPEs) transborda o buffer e vira retransmissão."));
            }
        }
    }

    // ECMP in the routing table (G1.27j): mixed uplinks split traffic per
    // connection between public addresses without anyone asking for it.
    match &i.ecmp {
        None => push("routes.ecmp", "Route ECMP", Severity::Unknown, None, "tabela de rotas não consultada".into(), None),
        Some((0, 0, _)) => push("routes.ecmp", "Route ECMP", Severity::Ok, None, "nenhuma rota dividindo o tráfego (ECMP)".into(), None),
        Some((0, info, _)) => push("routes.ecmp", "Route ECMP", Severity::Ok, Some(format!("{info} grupo(s)")),
            format!("{info} grupo(s) ECMP de uma origem só (ex.: dois gateways estáticos), em geral intencional"), None),
        Some((warn, info, first)) => {
            let (text, fix) = first.clone().unwrap_or_default();
            let action = match fix {
                Some(f) => format!("Torne uma das saídas reserva subindo a distância: {f} (IP › Routes mostra o grupo). Se a divisão por conexão é intencional (balanceamento), o aviso pode ficar."),
                None => "Suba a distância de uma das rotas para ela virar reserva (IP › Routes mostra o grupo).".into(),
            };
            out.push(Check {
                key: "routes.ecmp",
                name: "Route ECMP",
                severity: Severity::Warning,
                value: Some(format!("{warn} aviso(s), {info} info")),
                reason: format!("{warn} grupo(s) ECMP dividindo o tráfego por conexão entre saídas com IPs diferentes (origens misturadas ou rota padrão), como {text}"),
                action: Some(action),
            });
        }
    }
    out
}

/// (running slot, on dm-verity) from the package service's status, or
/// `None` off the image (and in its lab, which has no real root).
fn root_verity(st: &serde_json::Value) -> Option<(String, bool)> {
    use serde_json::Value;
    let on = |v: &Value, k: &str| v.get(k).and_then(Value::as_bool) == Some(true);
    if !on(st, "supported") || on(st, "lab") {
        return None;
    }
    let slot = st.get("slots")?.as_array()?.iter().find(|s| on(s, "running"))?;
    Some((slot.get("slot")?.as_str()?.to_owned(), on(slot, "verity")))
}

/// The worst severity of `checks` (unknown counts as ok).
pub fn overall(checks: &[Check]) -> Severity {
    checks
        .iter()
        .map(|c| c.severity)
        .filter(|s| *s != Severity::Unknown)
        .max()
        .unwrap_or(Severity::Ok)
}

/// What the alert part remembers.
#[derive(Debug, Default)]
pub struct HealthAlerts {
    /// Logged severity per check.
    logged: BTreeMap<&'static str, Severity>,
    /// A new severity seen once, waiting for a second reading.
    pending: BTreeMap<&'static str, Severity>,
    /// (uptime s, oom_kill count) of each rise.
    oom_rises: Vec<(u64, u64)>,
    oom_last: Option<u64>,
}

impl Session {
    /// The rules' inputs now.
    pub(crate) fn health_inputs(&mut self) -> Inputs {
        let mut i = Inputs::default();
        // OOM bookkeeping first (needs `&mut`).
        let reading = self.ext::<ResourceMonitor>().and_then(|m| m.last.as_ref()).map(|l| (l.uptime_ms / 1000, l.oom_kills));
        if let (Some((t, Some(kills))), Some(a)) = (reading, self.ext_mut::<HealthAlerts>()) {
            if let Some(prev) = a.oom_last
                && kills > prev
            {
                a.oom_rises.push((t, kills - prev));
            }
            a.oom_last = Some(kills);
            a.oom_rises.retain(|(at, _)| t.saturating_sub(*at) < OOM_WINDOW && *at <= t);
            i.oom_recent = Some(a.oom_rises.iter().map(|r| r.1).sum());
        }
        if let Some(m) = self.ext::<ResourceMonitor>()
            && let Some(l) = &m.last
        {
            i.readings = true;
            let recent = m.recent(CPU_POINTS);
            let cpus: Vec<f32> = recent.iter().filter_map(|p| p.cpu).collect();
            if !cpus.is_empty() {
                i.cpu_avg = Some((cpus.iter().sum::<f32>() / cpus.len() as f32, cpus.len()));
            } else if let Some(c) = m.cpu() {
                i.cpu_avg = Some((c.load, 1));
            }
            i.psi_some60 = l.pressure.memory.map(|p| p.some60);
            i.psi_full60 = l.pressure.memory.and_then(|p| p.full60);
            i.mem_used = memory_used(l);
            i.swap_used = (l.memory.swap_total > 0)
                .then(|| percent(l.memory.swap_total.saturating_sub(l.memory.swap_free), l.memory.swap_total))
                .flatten();
            i.swap_in_rate = m.rate(|s| s.swap_in);
            i.disks = l
                .disks
                .iter()
                .filter_map(|d| Some((d.mount.clone(), percent(d.available, d.total)?)))
                .collect();
            i.temps = l
                .sensors
                .iter()
                .filter(|s| s.kind == corerouter_hal::system_resource::SensorKind::Temperature)
                .map(|s| (format!("{} {}", s.chip, s.label), s.value, s.crit, sensor_level(s)))
                .collect();
            if m.pair().is_some() {
                i.nics = l
                    .net
                    .iter()
                    .filter(|d| d.name != "lo")
                    .filter_map(|d| {
                        let find = |s: &corerouter_hal::system_resource::Sample| s.net.iter().find(|y| y.name == d.name).cloned();
                        let e = m.rate(|s| find(s).map(|y| y.rx_errors.saturating_add(y.tx_errors)))?;
                        let dr = m.rate(|s| find(s).map(|y| y.rx_dropped.saturating_add(y.tx_dropped)))?;
                        Some((d.name.clone(), e, dr))
                    })
                    .collect();
                let rates: Vec<f64> = (0..l.irqs.len())
                    .map(|c| m.rate(|s| s.irqs.get(c).map(|x| x.net_rx)).unwrap_or(0.0))
                    .collect();
                let total: f64 = rates.iter().sum();
                if let Some((cpu, top)) = rates.iter().enumerate().max_by(|a, b| a.1.total_cmp(b.1)) {
                    i.rss = Some((cpu, if total > 0.0 { top * 100.0 / total } else { 0.0 }, rates.len(), total));
                }
            }
            i.conntrack = l.conntrack.zip(l.conntrack_max);
        }
        if self.cgnat_has_blocks() {
            i.cgnat = self.ext::<CgnatRuntime>().map(|c| (c.alerts().values().filter(|a| a.above).count(), c.insert_failed()));
        }
        let ntp = &self.store().running().system.ntp_client;
        let enabled = ntp.enabled;
        i.ntp_needed = self.store().running().radius.servers.iter().any(|r| !r.service.is_empty());
        i.ntp = Some((enabled, self.ext::<NtpStatus>().map(|s| s.status).unwrap_or_default()));
        i.sockbuf = self
            .ext::<SocketBuffers>()
            .filter(|b| !b.sockets.is_empty())
            .map(|b| b.sockets.iter().map(|(n, (g, w))| (n.clone(), *g, *w)).collect());
        let (_, routes, _) = self.cached_routes();
        i.ecmp = Some((routes.ecmp_warning, routes.ecmp_info, routes.ecmp_first.clone()));
        i.services = self
            .ext::<ServiceTable>()
            .filter(|t| t.supervised)
            .map(|t| t.rows.iter().map(|r| (r.name.clone(), r.state)).collect());
        i.no_password = self.admins_without_password();
        i.root_verity = self
            .ext::<crate::package::Packages>()
            .and_then(|p| p.status.as_ref())
            .and_then(root_verity);
        i
    }

    /// Judge the checks and log what changed (two readings in a row).
    pub fn health_alerts(&mut self) -> Vec<Check> {
        let inputs = self.health_inputs();
        let checks = evaluate(&inputs);
        let mut lines = Vec::new();
        if let Some(a) = self.ext_mut::<HealthAlerts>() {
            for c in &checks {
                if c.severity == Severity::Unknown {
                    continue;
                }
                let logged = a.logged.get(c.key).copied().unwrap_or(Severity::Ok);
                if c.severity == logged {
                    a.pending.remove(c.key);
                    continue;
                }
                if a.pending.get(c.key) != Some(&c.severity) {
                    a.pending.insert(c.key, c.severity);
                    continue;
                }
                a.pending.remove(c.key);
                a.logged.insert(c.key, c.severity);
                let text = match c.severity {
                    Severity::Ok => format!("Saúde: {} normalizado ({})", c.name, c.reason),
                    _ => format!("Saúde: {} — {}", c.name, c.reason),
                };
                lines.push((c.severity, text, c.key));
            }
        }
        for (sev, text, key) in lines {
            let level = match sev {
                Severity::Error => "error",
                Severity::Warning => "warning",
                _ => "info",
            };
            self.log_event(&["system", level], "health", text, serde_json::json!({"check": key, "severity": sev.as_str()}));
        }
        checks
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sev(checks: &[Check], key: &str) -> Severity {
        checks.iter().find(|c| c.key == key).map(|c| c.severity).unwrap()
    }

    /// One row: what to change in healthy inputs, the check and the
    /// severity it must give.
    type Case = (&'static str, fn(&mut Inputs), &'static str, Severity);

    fn healthy() -> Inputs {
        Inputs {
            readings: true,
            cpu_avg: Some((20.0, 60)),
            psi_some60: Some(0.5),
            psi_full60: Some(0.0),
            mem_used: Some(40.0),
            swap_used: None,
            swap_in_rate: Some(0.0),
            disks: vec![("/".into(), 60.0)],
            temps: vec![("k10temp Tctl".into(), 55.0, Some(100.0), Level::Ok)],
            nics: vec![("ether1".into(), 0.0, 0.0)],
            conntrack: Some((1000, 262_144)),
            cgnat: None,
            oom_recent: Some(0),
            ntp: Some((true, NtpState::Synchronized)),
            ntp_needed: false,
            services: Some(vec![("dns-resolver".into(), ServiceState::Running)]),
            rss: Some((0, 20.0, 8, 50_000.0)),
            sockbuf: Some(vec![("radius".into(), 4 << 20, 4 << 20)]),
            ecmp: Some((0, 0, None)),
            no_password: Vec::new(),
            root_verity: Some(("a".into(), true)),
        }
    }

    #[test]
    fn healthy_is_all_ok() {
        let checks = evaluate(&healthy());
        assert_eq!(checks.len(), 16);
        for c in &checks {
            assert_eq!(c.severity, Severity::Ok, "{c:?}");
            assert!(c.action.is_none());
        }
        assert_eq!(overall(&checks), Severity::Ok);
    }

    #[test]
    fn every_rule_by_table() {
        let cases: &[Case] = &[
            ("cpu 85", |i| i.cpu_avg = Some((85.0, 60)), "cpu", Severity::Warning),
            ("rmem_max caps the RADIUS socket", |i| i.sockbuf = Some(vec![("radius".into(), 212_992, 4 << 20)]), "sockbuf", Severity::Warning),
            ("no burst socket open", |i| i.sockbuf = None, "sockbuf", Severity::Unknown),
            ("cpu 97", |i| i.cpu_avg = Some((97.0, 60)), "cpu", Severity::Error),
            ("cpu too little history", |i| i.cpu_avg = Some((99.0, 3)), "cpu", Severity::Unknown),
            ("psi some 15", |i| i.psi_some60 = Some(15.0), "memory.pressure", Severity::Warning),
            ("psi some 50", |i| i.psi_some60 = Some(50.0), "memory.pressure", Severity::Error),
            ("psi full 6", |i| i.psi_full60 = Some(6.0), "memory.pressure", Severity::Error),
            ("no psi, 92 % used", |i| { i.psi_some60 = None; i.mem_used = Some(92.0) }, "memory.pressure", Severity::Warning),
            ("no psi, 98 % used", |i| { i.psi_some60 = None; i.mem_used = Some(98.0) }, "memory.pressure", Severity::Error),
            ("swap 60", |i| i.swap_used = Some(60.0), "swap", Severity::Warning),
            ("swap 95", |i| i.swap_used = Some(95.0), "swap", Severity::Error),
            ("swap thrash", |i| { i.swap_used = Some(5.0); i.swap_in_rate = Some(500.0) }, "swap", Severity::Warning),
            ("disk 10 % free", |i| i.disks.push(("/var".into(), 10.0)), "disk", Severity::Warning),
            ("disk 3 % free", |i| i.disks = vec![("/".into(), 3.0)], "disk", Severity::Error),
            ("no disk", |i| i.disks.clear(), "disk", Severity::Unknown),
            ("temp near crit", |i| i.temps.push(("nvme".into(), 92.0, Some(100.0), Level::Warning)), "temperature", Severity::Warning),
            ("temp at crit", |i| i.temps = vec![("acpitz".into(), 99.0, Some(100.0), Level::Error)], "temperature", Severity::Error),
            ("nic errors", |i| i.nics.push(("ether4".into(), 2.0, 15.0)), "nic.errors", Severity::Warning),
            ("nic many errors", |i| i.nics.push(("ether4".into(), 500.0, 0.0)), "nic.errors", Severity::Error),
            ("nic drops", |i| i.nics.push(("ether2".into(), 0.0, 200.0)), "nic.errors", Severity::Warning),
            ("nic flood of drops", |i| i.nics.push(("ether2".into(), 0.0, 20_000.0)), "nic.errors", Severity::Error),
            ("nic few drops", |i| i.nics.push(("ether2".into(), 0.0, 5.0)), "nic.errors", Severity::Ok),
            ("conntrack 85", |i| i.conntrack = Some((85, 100)), "conntrack", Severity::Warning),
            ("conntrack 99", |i| i.conntrack = Some((99, 100)), "conntrack", Severity::Error),
            ("cgnat above", |i| i.cgnat = Some((3, 0)), "cgnat.ports", Severity::Warning),
            ("cgnat failures", |i| i.cgnat = Some((0, 12)), "cgnat.ports", Severity::Error),
            ("oom", |i| i.oom_recent = Some(1), "oom", Severity::Error),
            ("ntp off, nothing needs it", |i| i.ntp = Some((false, NtpState::Stopped)), "ntp", Severity::Ok),
            ("ntp off, radius needs it", |i| { i.ntp = Some((false, NtpState::Stopped)); i.ntp_needed = true }, "ntp", Severity::Warning),
            ("ntp waiting", |i| i.ntp = Some((true, NtpState::Waiting)), "ntp", Severity::Warning),
            ("ntp no daemon", |i| i.ntp = Some((true, NtpState::Stopped)), "ntp", Severity::Unknown),
            ("service restarting", |i| i.services = Some(vec![("dns".into(), ServiceState::Restarting)]), "services", Severity::Warning),
            ("service failed", |i| i.services = Some(vec![("a".into(), ServiceState::Running), ("dns".into(), ServiceState::Failed)]), "services", Severity::Error),
            ("rss on one cpu", |i| i.rss = Some((0, 80.0, 8, 50_000.0)), "rss", Severity::Warning),
            ("rss idle link", |i| i.rss = Some((0, 100.0, 8, 10.0)), "rss", Severity::Ok),
            ("rss two cpus", |i| i.rss = Some((0, 100.0, 2, 50_000.0)), "rss", Severity::Ok),
            ("ecmp of one origin", |i| i.ecmp = Some((0, 2, None)), "routes.ecmp", Severity::Ok),
            ("ecmp static + dhcp", |i| i.ecmp = Some((1, 0, Some(("x".into(), Some("ip.dhcp-client.set".into()))))), "routes.ecmp", Severity::Warning),
            ("routes not read", |i| i.ecmp = None, "routes.ecmp", Severity::Unknown),
            ("admin without a password", |i| i.no_password = vec!["admin".into()], "auth.no_password", Severity::Warning),
            ("root without dm-verity", |i| i.root_verity = Some(("b".into(), false)), "root.verity", Severity::Warning),
            ("not the A/B image", |i| i.root_verity = None, "root.verity", Severity::Unknown),
        ];
        for (what, change, key, want) in cases {
            let mut i = healthy();
            change(&mut i);
            let checks = evaluate(&i);
            assert_eq!(sev(&checks, key), *want, "{what}");
            let c = checks.iter().find(|c| c.key == *key).unwrap();
            assert!(!c.reason.is_empty(), "{what}: a reason");
            if matches!(want, Severity::Warning | Severity::Error) {
                assert!(c.action.is_some(), "{what}: an action");
            }
            // Only that check moved.
            for other in checks.iter().filter(|c| c.key != *key) {
                assert!(matches!(other.severity, Severity::Ok), "{what} moved {}", other.key);
            }
        }
    }

    #[test]
    fn new_router_has_no_ntp_warning() {
        let mut s = Session::virtual_lab();
        s.health_alerts();
        let log = s.execute("log.print", &serde_json::json!({})).unwrap().to_string();
        assert!(!log.contains("Saúde: NTP"), "{log}");
    }

    #[test]
    fn admin_without_password_warns_until_set() {
        let mut s = Session::virtual_lab();
        assert!(s.bootstrap_admin(false).is_some());
        let warn = |s: &mut Session| {
            let checks = evaluate(&s.health_inputs());
            checks.iter().find(|c| c.key == "auth.no_password").map(|c| c.severity)
        };
        assert_eq!(warn(&mut s), Some(Severity::Warning));
        s.execute("user.set", &serde_json::json!({"name": "admin", "password": "a-real-password"})).unwrap();
        assert_eq!(warn(&mut s), Some(Severity::Ok));
    }

    #[test]
    fn nothing_known_is_unknown_not_ok() {
        let checks = evaluate(&Inputs::default());
        assert_eq!(sev(&checks, "cpu"), Severity::Unknown);
        assert_eq!(sev(&checks, "temperature"), Severity::Unknown);
        assert_eq!(overall(&checks), Severity::Ok, "unknown alone is not a warning");
    }

    #[test]
    fn alerts_need_two_readings_and_log_once() {
        use corerouter_hal::system_resource::{LabSampler, ResourceSampler, Want};
        let mut s = Session::virtual_lab();
        let mut lab = LabSampler::new();
        let mut warnings = 0;
        for i in 0..6u64 {
            s.resource_ingest(lab.sample(Want { processes: false, now_ms: Some(i * 5000) }));
            s.health_alerts();
            let log = s.execute("log.print", &serde_json::json!({})).unwrap().to_string();
            warnings = log.matches("Saúde: NIC errors").count();
            if i < 2 {
                // First reading has no rates; the second is the first warning.
                assert_eq!(warnings, 0, "reading {i}");
            }
        }
        assert_eq!(warnings, 1, "logged once, not on every reading");
    }
}
