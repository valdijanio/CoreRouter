//! IP › DNS › Statistics (G4.1e, G4.1h, G4.1za, G4.1zb): what the LAN
//! forwarder did, in five tabs.
//!
//! - **Overview**: cards (queries per second now and the period's peak,
//!   cache hits and SERVFAIL over the period, the time to answer, the
//!   queries in flight against `max_concurrent_queries`), the `dns` graph
//!   series (queries per second, cache hits) over 1 h, 24 h or 7 d, who
//!   answered, the response codes, the transport and the warnings the
//!   engine raised.
//! - **Names**: the names asked most (all clients together) and the
//!   domains whose names fail (NXDOMAIN, SERVFAIL) with how many different
//!   names failed; the random-subdomain warnings under them.
//! - **Clients**: live, in memory only: queries per second, NXDOMAIN
//!   share, queries over the per-client limit, refused, when last seen.
//!   Never the names a client asked (LGPD).
//! - **Upstreams**: one row per server (how it is asked, answers per
//!   second, round trips, timeouts, SERVFAIL, truncated answers, up, slow
//!   or down and for how long) and the round trips by range, the ends
//!   included.
//! - **Cache**: entries and bytes against the budget, evictions, expiries,
//!   stale answers served, and the types cached and asked.
//!
//! Opened by the Statistics button of the DNS window and by the menu.
//! Reads `ip.dns.statistics.print` and `system.graph.query` (series
//! `dns`), acts with `ip.dns.statistics.reset`; nothing is computed here
//! but percentages of what the router sent.

use std::cell::Cell;

use egui::{Grid, Id, RichText, Ui};
use egui_plot::{Line, Plot, PlotPoints};
use serde_json::{Value, json};

use crate::backend::RequestId;
use crate::chip::{self, AMBER, Kind, RED, chip, neutral_tone};
use crate::dhcp_client::text;
use crate::firewall::duration;
use crate::graphs::{self, Range};
use crate::help::{self, HelpView};
use crate::i18n::{self, Lang, tr_in};
use crate::panel::{Panel, PanelState, PanelThen, Query, WinDef};
use crate::table::{self, Menu, Row, TableState, action, col, num};
use crate::{CoreRouterUi, Win};

const NAME: &str = "dns-statistics";
pub(crate) const WIN: &str = "dns-statistics";
const CLIENTS_TABLE: &str = "dns-statistics-clients";
const NAMES_TABLE: &str = "dns-statistics-names";
const DOMAINS_TABLE: &str = "dns-statistics-domains";
const UPSTREAMS_TABLE: &str = "dns-statistics-upstreams";
const PRINT: &str = "ip.dns.statistics.print";
const RESET: &str = "ip.dns.statistics.reset";
const GRAPH: &str = "system.graph.query";
const SCOPE: &str = "dns_statistics";
/// Clients asked for (the table scrolls).
const TOP: u32 = 20;
/// Record types listed; the rest are summed as "others".
const TYPES: usize = 8;
/// The periods of the graph and of the cards that read it.
const PERIODS: [(Range, &str); 3] = [(Range::Hour, "1h"), (Range::Day, "24h"), (Range::Week, "7d")];

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[WinDef {
        id: WIN,
        group: "IP",
        title: "DNS Statistics",
        size: [920.0, 800.0],
        escape: true,
    }],
    new: || Box::new(DnsStatsPanel::default()),
};

const CLIENT_COLUMNS: [table::Column; 8] = [
    col("Client").help("dns_statistics.client"),
    num("Queries/s").help("dns_statistics.client_rate"),
    num("Queries").help("dns_statistics.client_queries"),
    num("%").help("dns_statistics.client_share"),
    num("NXDOMAIN %").help("dns_statistics.client_nxdomain"),
    num("Limited").help("dns_statistics.client_limited"),
    num("Refused").help("dns_statistics.client_refused"),
    num("Last seen").help("dns_statistics.client_seen"),
];
const NAME_COLUMNS: [table::Column; 4] = [
    col("Name").help("dns_statistics.name"),
    num("Queries").help("dns_statistics.name_queries"),
    num("%").help("dns_statistics.name_share"),
    num("Queries/s").help("dns_statistics.name_rate"),
];
const DOMAIN_COLUMNS: [table::Column; 5] = [
    col("Domain").help("dns_statistics.domain"),
    num("NXDOMAIN").help("dns_statistics.domain_nxdomain"),
    num("SERVFAIL").help("dns_statistics.domain_servfail"),
    num("Failures/s").help("dns_statistics.domain_rate"),
    num("Names").help("dns_statistics.domain_names"),
];
const UPSTREAM_COLUMNS: [table::Column; 9] = [
    col("Server").help("dns_statistics.server"),
    col("Via").help("dns_statistics.via"),
    num("Answers/s").help("dns_statistics.answers_per_sec"),
    num("p50 ms").help("dns_statistics.rtt_p50"),
    num("p95 ms").help("dns_statistics.rtt_p95"),
    num("Timeout %").help("dns_statistics.timeouts"),
    num("SERVFAIL %").help("dns_statistics.upstream_servfail"),
    num("Truncated").help("dns_statistics.tc_tcp"),
    col("State").help("dns_statistics.state"),
];

/// The tabs (docs/ui-style.md: parts of a window are its tabs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Tab {
    #[default]
    Overview,
    Names,
    Clients,
    Upstreams,
    Cache,
}

impl Tab {
    const ALL: [Tab; 5] = [Tab::Overview, Tab::Names, Tab::Clients, Tab::Upstreams, Tab::Cache];

    fn label(self) -> &'static str {
        match self {
            Tab::Overview => "Overview",
            Tab::Names => "Names",
            Tab::Clients => "Clients",
            Tab::Upstreams => "Upstreams",
            Tab::Cache => "Cache",
        }
    }

    fn help(self) -> &'static str {
        match self {
            Tab::Overview => "dns_statistics.tab_overview",
            Tab::Names => "dns_statistics.tab_names",
            Tab::Clients => "dns_statistics.tab_clients",
            Tab::Upstreams => "dns_statistics.tab_upstreams",
            Tab::Cache => "dns_statistics.tab_cache",
        }
    }
}

/// Who answered, grouped as an operator reads it: (label, help key, the
/// `answered` keys summed).
const ANSWERED: [(&str, &str, &[&str]); 5] = [
    ("Cache", "dns_statistics.by_cache", &["cache"]),
    ("Upstream", "dns_statistics.by_upstream", &["upstream"]),
    ("Stale", "dns_statistics.by_stale", &["stale"]),
    ("Static / Adlist", "dns_statistics.by_static", &["static", "adlist", "zones", "special"]),
    ("Refused / Limit", "dns_statistics.by_refused", &["refused", "limit", "busy", "malformed", "none", "parse", "other"]),
];

/// Response codes listed first, in this order (the rest after them).
const RCODES: [(&str, &str); 7] = [
    ("noerror", "NOERROR"),
    ("nxdomain", "NXDOMAIN"),
    ("servfail", "SERVFAIL"),
    ("refused", "REFUSED"),
    ("formerr", "FORMERR"),
    ("notimp", "NOTIMP"),
    ("dropped", "Dropped"),
];

/// The transport rows: (label, help key, field of `transport`).
const TRANSPORT: [(&str, &str, &str); 6] = [
    ("UDP IPv4", "dns_statistics.udp4", "udp4"),
    ("UDP IPv6", "dns_statistics.udp6", "udp6"),
    ("TCP IPv4", "dns_statistics.tcp4", "tcp4"),
    ("TCP IPv6", "dns_statistics.tcp6", "tcp6"),
    ("Truncated (TC)", "dns_statistics.truncated", "truncated"),
    ("Socket drops", "dns_statistics.socket_drops", "socket_drops"),
];

/// Every explanation the window opens (a test checks both languages).
#[cfg(test)]
pub(crate) const HELP_KEYS: &[&str] = &[
    "dns_statistics.answered",
    "dns_statistics.answers_per_sec",
    "dns_statistics.by_cache",
    "dns_statistics.by_refused",
    "dns_statistics.by_stale",
    "dns_statistics.by_static",
    "dns_statistics.by_upstream",
    "dns_statistics.cache_entries",
    "dns_statistics.cache_hits",
    "dns_statistics.cache_used",
    "dns_statistics.client",
    "dns_statistics.client_limited",
    "dns_statistics.client_nxdomain",
    "dns_statistics.client_queries",
    "dns_statistics.client_rate",
    "dns_statistics.client_refused",
    "dns_statistics.client_seen",
    "dns_statistics.client_share",
    "dns_statistics.clients",
    "dns_statistics.domain",
    "dns_statistics.domain_names",
    "dns_statistics.domain_nxdomain",
    "dns_statistics.domain_rate",
    "dns_statistics.domain_servfail",
    "dns_statistics.failing_domains",
    "dns_statistics.encrypted_in",
    "dns_statistics.evicted",
    "dns_statistics.expired",
    "dns_statistics.in_flight",
    "dns_statistics.latency",
    "dns_statistics.malformed",
    "dns_statistics.name",
    "dns_statistics.name_queries",
    "dns_statistics.name_rate",
    "dns_statistics.name_share",
    "dns_statistics.names",
    "dns_statistics.period",
    "dns_statistics.queries_per_sec",
    "dns_statistics.rcodes",
    "dns_statistics.reset",
    "dns_statistics.rtt_histogram",
    "dns_statistics.rtt_p50",
    "dns_statistics.rtt_p95",
    "dns_statistics.server",
    "dns_statistics.servfail",
    "dns_statistics.socket_drops",
    "dns_statistics.stale_served",
    "dns_statistics.state",
    "dns_statistics.tab_cache",
    "dns_statistics.tab_clients",
    "dns_statistics.tab_names",
    "dns_statistics.tab_overview",
    "dns_statistics.tab_upstreams",
    "dns_statistics.tc_tcp",
    "dns_statistics.tcp4",
    "dns_statistics.tcp6",
    "dns_statistics.timeouts",
    "dns_statistics.transport",
    "dns_statistics.truncated",
    "dns_statistics.types_asked",
    "dns_statistics.types_cached",
    "dns_statistics.udp4",
    "dns_statistics.udp6",
    "dns_statistics.upstream_servfail",
    "dns_statistics.warnings",
];

/// The warnings the engine raises, by key (their text has a template).
#[cfg(test)]
pub(crate) const WARNINGS: [&str; 7] = [
    "upstream_down",
    "upstream_timeouts",
    "servfail_high",
    "limit_reached",
    "cache_evicting",
    "socket_drops",
    "random_subdomain",
];

/// The warnings the Names tab shows under its tables.
const NAME_WARNINGS: [&str; 1] = ["random_subdomain"];

#[derive(Default)]
pub(crate) struct DnsStatsPanel {
    /// `ip.dns.statistics.print`.
    pub(crate) stats: Option<Value>,
    /// `system.graph.query` of the `dns` series over [`Self::period`].
    pub(crate) graph: Option<Value>,
    pub(crate) error: Option<String>,
    pub(crate) tab: Tab,
    pub(crate) period: Range,
    /// The period the graph was last asked for, and refreshes counted.
    asked: Cell<Option<Range>>,
    tick: Cell<u32>,
    clients_table: TableState,
    names_table: TableState,
    domains_table: TableState,
    upstreams_table: TableState,
    help: Option<HelpView>,
}

struct Reset;

fn n(v: &Value, k: &str) -> u64 {
    v.get(k).and_then(Value::as_u64).unwrap_or(0)
}

fn f(v: &Value, k: &str) -> Option<f64> {
    v.get(k).and_then(Value::as_f64)
}

/// `part` of `whole` as a whole percentage ("–" when nothing counted).
fn percent(part: u64, whole: u64) -> String {
    (part * 100)
        .checked_div(whole)
        .map_or_else(|| "–".into(), |p| p.to_string())
}

/// A number with one decimal at most ("–" when absent).
fn one(v: Option<f64>) -> String {
    match v {
        Some(x) if x >= 100.0 => format!("{x:.0}"),
        Some(x) => {
            let s = format!("{x:.1}");
            s.strip_suffix(".0").map_or(s.clone(), str::to_owned)
        }
        None => "–".into(),
    }
}

/// Milliseconds: `<0.1`, `0.4`, `23`, `1 600`.
fn ms(v: Option<f64>) -> String {
    match v {
        Some(x) if x < 0.1 => "<0.1".into(),
        Some(x) if x < 10.0 => format!("{x:.1}"),
        Some(x) => format!("{x:.0}"),
        None => "–".into(),
    }
}

/// A count Space-Saving may have inflated: `≤n` when up to `error` of it
/// belongs to keys this one replaced.
fn bounded(r: &Value, k: &str) -> String {
    if n(r, "error") > 0 {
        format!("≤{}", n(r, k))
    } else {
        n(r, k).to_string()
    }
}

fn row(key: String, cells: Vec<String>) -> Row {
    Row {
        key,
        cells,
        dimmed: false,
        section: false,
        tint: None,
    }
}

pub(crate) fn client_row(r: &Value, total: u64) -> Row {
    let seen = r.get("seen_secs").and_then(Value::as_u64);
    let mut out = row(
        text(r, "address"),
        vec![
            text(r, "address"),
            one(f(r, "queries_per_sec")),
            bounded(r, "queries"),
            percent(n(r, "queries"), total),
            one(f(r, "nxdomain_percent")),
            n(r, "limited").to_string(),
            n(r, "refused").to_string(),
            seen.map_or_else(|| "–".into(), duration),
        ],
    );
    // Quiet for a minute: greyed out (still in the table until replaced).
    out.dimmed = seen.is_some_and(|s| s >= 60);
    out
}

pub(crate) fn name_row(r: &Value, total: u64) -> Row {
    row(
        text(r, "name"),
        vec![text(r, "name"), bounded(r, "queries"), percent(n(r, "queries"), total), one(f(r, "queries_per_sec"))],
    )
}

pub(crate) fn domain_row(r: &Value) -> Row {
    let name = text(r, "domain");
    let cell = if r.get("random").and_then(Value::as_bool) == Some(true) {
        chip::cell(&name, &[("random names", Kind::Amber)])
    } else {
        name.clone()
    };
    let fails = if n(r, "error") > 0 { "≤" } else { "" };
    row(
        name,
        vec![
            cell,
            format!("{fails}{}", n(r, "nxdomain")),
            format!("{fails}{}", n(r, "servfail")),
            one(f(r, "failures_per_sec")),
            format!("≈{}", n(r, "names")),
        ],
    )
}

/// `up 5 min`, `down 30 s` as a chip in the State cell.
fn state_cell(r: &Value) -> String {
    let state = r.get("state").and_then(Value::as_str).unwrap_or("up");
    let kind = match state {
        "down" => Kind::Red,
        "slow" => Kind::Amber,
        _ => Kind::Green,
    };
    let label = match r.get("state_secs").and_then(Value::as_u64) {
        Some(secs) => format!("{state} {}", duration(secs)),
        None => state.to_owned(),
    };
    chip::cell("", &[(label.as_str(), kind)])
}

pub(crate) fn upstream_row(r: &Value) -> Row {
    let down = r.get("state").and_then(Value::as_str) == Some("down");
    let pct = |k: &str| one(f(r, k));
    Row {
        key: text(r, "server"),
        cells: vec![
            text(r, "server"),
            r.get("via").and_then(Value::as_str).unwrap_or("udp").to_uppercase(),
            one(f(r, "answers_per_sec")),
            ms(f(r, "rtt_p50_ms")),
            ms(f(r, "rtt_p95_ms")),
            pct("timeouts_percent"),
            pct("servfail_percent"),
            n(r, "truncated").to_string(),
            state_cell(r),
        ],
        dimmed: down,
        section: false,
        tint: None,
    }
}

/// `{key: count}` as (key, count), largest first.
fn counts(v: &Value) -> Vec<(String, u64)> {
    let mut out: Vec<(String, u64)> = v
        .as_object()
        .map(|o| {
            o.iter()
                .map(|(k, c)| (k.clone(), c.as_u64().unwrap_or(0)))
                .collect()
        })
        .unwrap_or_default();
    out.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    out
}

/// A warning's text in the explanations' language (template
/// `dns_statistics.warn.<key>`; the engine's English otherwise).
pub(crate) fn warning_text(lang: Lang, w: &Value) -> String {
    let key = text(w, "key");
    let args: Vec<(String, String)> = w
        .get("args")
        .and_then(Value::as_object)
        .map(|o| {
            o.iter()
                .map(|(k, v)| (k.clone(), v.as_str().map_or_else(|| v.to_string(), str::to_owned)))
                .collect()
        })
        .unwrap_or_default();
    let args: Vec<(&str, &str)> = args.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    i18n::template(lang, &format!("dns_statistics.warn.{key}"), &args, &text(w, "text"))
}

impl PanelState for DnsStatsPanel {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        if !app.open.contains(&Win::Panel(WIN)) || !app.has_command(PRINT) {
            return Vec::new();
        }
        let mut out = vec![Query {
            key: "print",
            command: PRINT,
            params: json!({"top": TOP}),
        }];
        let n = self.tick.get();
        self.tick.set(n.wrapping_add(1));
        let fresh = self.asked.get() == Some(self.period);
        if self.tab == Tab::Overview && app.has_command(GRAPH) && (!fresh || n.is_multiple_of(self.period.every())) {
            self.asked.set(Some(self.period));
            out.push(Query {
                key: "graph",
                command: GRAPH,
                params: json!({"series": "dns", "range": self.period.param(),
                    "fields": ["queries", "cache_hit", "servfail"]}),
            });
        }
        out
    }

    fn arrived(&mut self, _: &mut CoreRouterUi, key: &'static str, _: RequestId, value: Value) {
        if !value.is_object() {
            return;
        }
        match key {
            "print" => self.stats = Some(value),
            "graph" => self.graph = Some(value),
            _ => {}
        }
    }

    fn window(&mut self, app: &mut CoreRouterUi, _: &'static str, ui: &mut Ui) {
        self.draw(app, ui);
    }

    fn dialogs(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, _area: egui::Rect) {
        help::modal(ctx, app.lang, &mut self.help);
    }

    fn reply(&mut self, app: &mut CoreRouterUi, then: PanelThen, result: &Result<Value, String>) {
        if then.downcast::<Reset>().is_ok() {
            self.error = result.as_ref().err().cloned();
            app.cache.refreshed_at = None;
            self.asked.set(None);
        }
    }

    fn escape(&mut self, _: &'static str) -> bool {
        self.clients_table.escape()
            || self.names_table.escape()
            || self.domains_table.escape()
            || self.upstreams_table.escape()
    }

    fn tables(&self) -> Vec<(&'static str, &TableState)> {
        vec![
            (CLIENTS_TABLE, &self.clients_table),
            (NAMES_TABLE, &self.names_table),
            (DOMAINS_TABLE, &self.domains_table),
            (UPSTREAMS_TABLE, &self.upstreams_table),
        ]
    }

    fn tables_mut(&mut self) -> Vec<(&'static str, &mut TableState)> {
        vec![
            (CLIENTS_TABLE, &mut self.clients_table),
            (NAMES_TABLE, &mut self.names_table),
            (DOMAINS_TABLE, &mut self.domains_table),
            (UPSTREAMS_TABLE, &mut self.upstreams_table),
        ]
    }
}

/// A label with its ⓘ (explanation `key`).
fn label(ui: &mut Ui, help: &mut Option<HelpView>, l: Lang, key: &'static str, text: &'static str) {
    ui.horizontal(|ui| {
        ui.label(tr_in(SCOPE, l, text));
        info(ui, help, l, key, text);
    });
}

/// A heading with its ⓘ.
fn heading(ui: &mut Ui, help: &mut Option<HelpView>, l: Lang, key: &'static str, text: &'static str) {
    ui.horizontal(|ui| {
        ui.strong(tr_in(SCOPE, l, text));
        info(ui, help, l, key, text);
    });
}

fn info(ui: &mut Ui, help: &mut Option<HelpView>, l: Lang, key: &'static str, text: &'static str) {
    if help::info_button(ui, Id::unique(("dns-stats-help", key)), tr_in(SCOPE, l, text)).clicked() {
        *help = Some(HelpView::new(key, tr_in(SCOPE, l, text)));
    }
}

impl DnsStatsPanel {
    fn draw(&mut self, app: &mut CoreRouterUi, ui: &mut Ui) {
        let l = app.lang.labels;
        let s = self.stats.clone().unwrap_or(Value::Null);
        ui.horizontal(|ui| {
            for t in Tab::ALL {
                ui.selectable_value(&mut self.tab, t, tr_in(SCOPE, l, t.label()));
                info(ui, &mut self.help, l, t.help(), t.label());
                ui.add_space(6.0);
            }
        });
        ui.separator();
        let reset = self.top_bar(app, ui, &s);
        if let Some(e) = &self.error {
            ui.colored_label(ui.visuals().error_fg_color, e.as_str());
        }
        ui.separator();
        egui::ScrollArea::vertical()
            .id_salt(("dns-stats-tab", self.tab.label()))
            .auto_shrink([false, false])
            .show(ui, |ui| match self.tab {
                Tab::Overview => self.overview(app, ui, &s),
                Tab::Names => self.names(app, ui, &s),
                Tab::Clients => self.clients(app, ui, &s),
                Tab::Upstreams => self.upstreams(app, ui, &s),
                Tab::Cache => self.cache(app, ui, &s),
            });
        if reset {
            app.run_then(RESET, json!({}), crate::panel::then(NAME, Reset));
        }
    }

    /// State chip, "counting for", the period (Overview) and Reset.
    fn top_bar(&mut self, app: &CoreRouterUi, ui: &mut Ui, s: &Value) -> bool {
        let l = app.lang.labels;
        let can = app.can();
        let mut reset = false;
        ui.horizontal_wrapped(|ui| {
            state_chip(ui, l, s);
            match s.get("elapsed_secs").and_then(Value::as_u64) {
                Some(secs) => ui.weak(format!("{} {}", tr_in(SCOPE, l, "counting for"), duration(secs))),
                None => ui.weak(tr_in(SCOPE, l, "counting since the daemon started or the last reset")),
            };
            ui.separator();
            ui.label(RichText::new(format!("{} {}", n(s, "queries"), tr_in(SCOPE, l, "queries"))).strong());
            if self.tab == Tab::Overview {
                ui.separator();
                ui.label(tr_in(SCOPE, l, "Period"));
                info(ui, &mut self.help, l, "dns_statistics.period", "Period");
                for (r, text) in PERIODS {
                    ui.selectable_value(&mut self.period, r, text);
                }
            }
            ui.separator();
            reset = action(ui, tr_in(SCOPE, l, "Reset Statistics"), can.check(RESET));
            info(ui, &mut self.help, l, "dns_statistics.reset", "Reset Statistics");
        });
        reset
    }

    /// The period's stats of graph field `field` (`avg`, `max`, `max_at`).
    fn graph_stat(&self, field: &str, k: &str) -> Option<f64> {
        let g = self.graph.as_ref()?;
        g.get("series")?.get(0)?.get("stats")?.get(field)?.get(k)?.as_f64()
    }

    fn overview(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, s: &Value) {
        let l = app.lang.labels;
        let now = s.get("now").cloned().unwrap_or(Value::Null);
        let period = PERIODS.iter().find(|(r, _)| *r == self.period).map_or("1h", |(_, t)| *t);
        // The cards.
        let peak = self.graph_stat("queries", "max");
        let peak_at = self.graph_stat("queries", "max_at");
        let hit = self.graph_stat("cache_hit", "avg").or_else(|| f(&now, "cache_hit_percent"));
        let servfail = self.graph_stat("servfail", "avg").or_else(|| f(&now, "servfail_percent"));
        let latency = |k: &str, reset: &str| f(&now, k).or_else(|| s.get("latency").and_then(|x| f(x, reset)));
        let (p50, p99) = (latency("latency_p50_ms", "p50_ms"), latency("latency_p99_ms", "p99_ms"));
        let top_ede = s.get("ede").and_then(|e| e.get(0)).map(|e| format!("EDE {} {}", n(e, "code"), text(e, "name")));
        let help = &mut self.help;
        ui.horizontal_wrapped(|ui| {
            card(ui, help, l, ("dns_statistics.queries_per_sec", "Queries/s"), one(f(&now, "queries_per_sec")), match (peak, peak_at) {
                (Some(p), Some(at)) => format!("{} {} {} {}", tr_in(SCOPE, l, "peak"), one(Some(p)), tr_in(SCOPE, l, "at"), graphs::time_label(at, self.period)),
                _ => format!("{} {period}", tr_in(SCOPE, l, "no peak yet in")),
            });
            card(ui, help, l, ("dns_statistics.cache_hits", "Cache hits"), format!("{} %", one(hit)), format!("{} {period}", tr_in(SCOPE, l, "average,")));
            card(ui, help, l, ("dns_statistics.latency", "Latency p50 / p99"), format!("{} / {} ms", ms(p50), ms(p99)), tr_in(SCOPE, l, "to the client, last minute").to_owned());
            card(ui, help, l, ("dns_statistics.servfail", "SERVFAIL"), format!("{} %", one(servfail)), top_ede.unwrap_or_else(|| tr_in(SCOPE, l, "no extended error").to_owned()));
            card(ui, help, l, ("dns_statistics.in_flight", "In flight"), format!("{} / {}", n(s, "in_flight"), n(s, "max_concurrent_queries")), format!("{} {} · {} {}", tr_in(SCOPE, l, "peak"), n(s, "in_flight_peak"), tr_in(SCOPE, l, "limit hit"), n(s, "limit_hits")));
        });
        ui.add_space(4.0);
        self.chart(app, ui);
        ui.add_space(4.0);
        let help = &mut self.help;
        let total = n(s, "queries");
        let answered = s.get("answered").cloned().unwrap_or(Value::Null);
        ui.horizontal_top(|ui| {
            ui.group(|ui| {
                ui.vertical(|ui| {
                    heading(ui, help, l, "dns_statistics.answered", "Answered by");
                    Grid::new("dns-stats-answered").num_columns(3).show(ui, |ui| {
                        for (text, key, keys) in ANSWERED {
                            let c: u64 = keys.iter().map(|k| n(&answered, k)).sum();
                            label(ui, help, l, key, text);
                            ui.label(c.to_string());
                            ui.weak(format!("{} %", percent(c, total)));
                            ui.end_row();
                        }
                    });
                });
            });
            ui.group(|ui| {
                ui.vertical(|ui| {
                    heading(ui, help, l, "dns_statistics.rcodes", "Response codes");
                    let rcodes = s.get("rcodes").cloned().unwrap_or(Value::Null);
                    Grid::new("dns-stats-rcodes").num_columns(2).show(ui, |ui| {
                        for (key, text) in RCODES {
                            ui.label(text);
                            ui.label(n(&rcodes, key).to_string());
                            ui.end_row();
                        }
                        for (code, c) in counts(&rcodes) {
                            if c > 0 && !RCODES.iter().any(|(k, _)| *k == code) {
                                ui.label(code.to_uppercase());
                                ui.label(c.to_string());
                                ui.end_row();
                            }
                        }
                        label(ui, help, l, "dns_statistics.malformed", "of them malformed");
                        ui.label(n(s, "malformed").to_string());
                        ui.end_row();
                    });
                });
            });
            ui.group(|ui| {
                ui.vertical(|ui| {
                    heading(ui, help, l, "dns_statistics.transport", "Transport");
                    let t = s.get("transport").cloned().unwrap_or(Value::Null);
                    Grid::new("dns-stats-transport").num_columns(2).show(ui, |ui| {
                        for (text, key, field) in TRANSPORT {
                            label(ui, help, l, key, text);
                            ui.label(n(&t, field).to_string());
                            ui.end_row();
                        }
                        label(ui, help, l, "dns_statistics.encrypted_in", "DoT / DoH in");
                        ui.weak(tr_in(SCOPE, l, "not served"));
                        ui.end_row();
                    });
                });
            });
        });
        self.warnings(app, ui, s, None);
    }

    /// A table of rows `key` of the reply, with its heading and "shown /
    /// tracked"; the help of a clicked column opens.
    #[allow(clippy::too_many_arguments)]
    fn list(
        &mut self,
        app: &mut CoreRouterUi,
        ui: &mut Ui,
        s: &Value,
        (key, tracked): (&str, &str),
        (help, title): (&'static str, &'static str),
        (id, height, columns): (&'static str, f32, &[table::Column]),
        make: impl Fn(&Value) -> Row,
    ) {
        let l = app.lang.labels;
        let rows: Vec<Row> = s
            .get(key)
            .and_then(Value::as_array)
            .map(|a| a.iter().map(&make).collect())
            .unwrap_or_default();
        ui.horizontal(|ui| {
            heading(ui, &mut self.help, l, help, title);
            ui.weak(format!("{} / {}", rows.len(), n(s, tracked)));
        });
        let state = match id {
            NAMES_TABLE => &mut self.names_table,
            DOMAINS_TABLE => &mut self.domains_table,
            _ => &mut self.clients_table,
        };
        let out = table::show(ui, id, height, state, columns, &rows, |ui, menu| {
            refresh_menu(app, ui, &menu);
        });
        if let Some(key) = out.help {
            let title = columns.iter().find(|c| c.help == key).map_or("", |c| c.title);
            self.help = Some(HelpView::new(key, tr_in(SCOPE, l, title)));
        }
    }

    fn names(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, s: &Value) {
        let l = app.lang.labels;
        let total = n(s, "queries");
        self.list(app, ui, s, ("names", "names_tracked"), ("dns_statistics.names", "Top names"),
            (NAMES_TABLE, 230.0, &NAME_COLUMNS), |r| name_row(r, total));
        ui.add_space(6.0);
        self.list(app, ui, s, ("failing_domains", "domains_tracked"),
            ("dns_statistics.failing_domains", "Failing domains (NXDOMAIN / SERVFAIL)"),
            (DOMAINS_TABLE, 190.0, &DOMAIN_COLUMNS), domain_row);
        ui.weak(tr_in(SCOPE, l, "Counted for all clients together: no name is kept with the client that asked it."));
        ui.add_space(4.0);
        self.warnings(app, ui, s, Some(&NAME_WARNINGS));
    }

    fn clients(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, s: &Value) {
        let l = app.lang.labels;
        let total = n(s, "queries");
        ui.horizontal_wrapped(|ui| {
            chip(ui, tr_in(SCOPE, l, "live"), chip::GREEN.tone(ui.visuals()));
            ui.weak(tr_in(SCOPE, l, "In memory only, never written; the names a client asks are not kept (LGPD). IPv6 clients count per /56."));
        });
        self.list(app, ui, s, ("clients", "clients_tracked"), ("dns_statistics.clients", "Clients"),
            (CLIENTS_TABLE, 0.0, &CLIENT_COLUMNS), |r| client_row(r, total));
    }

    /// Queries per second and cache hits over the period, side by side.
    fn chart(&self, app: &CoreRouterUi, ui: &mut Ui) {
        let l = app.lang.labels;
        let Some(data) = self.graph.as_ref() else {
            ui.weak(tr_in(SCOPE, l, "No history yet: the graph starts with the forwarder (System › Graphing keeps it)."));
            return;
        };
        let Some(series) = data.get("series").and_then(|v| v.get(0)) else {
            return;
        };
        let range = self.period;
        let (x0, x1) = graphs::span(data);
        let w = (ui.available_width() - 12.0) / 2.0;
        ui.horizontal(|ui| {
            for (i, (field, title, unit)) in [("queries", "Queries/s", "/s"), ("cache_hit", "Cache hits", "%")].into_iter().enumerate() {
                let color = chip::palette_tone(ui.visuals(), i * 3).ink;
                let name = tr_in(SCOPE, l, title);
                let mut plot = Plot::new(("dns-stats-chart", field))
                    .width(w.max(160.0))
                    .height(110.0)
                    .include_y(0.0)
                    .include_x(x0)
                    .include_x(x1)
                    .y_axis_formatter(move |m, _| graphs::rate(m.value, unit))
                    .x_axis_formatter(move |m, _| graphs::time_label(m.value, range))
                    .label_formatter(move |h| graphs::hover(h, unit))
                    .allow_scroll(false)
                    .legend(egui_plot::Legend::default().position(egui_plot::Corner::LeftTop));
                if field == "cache_hit" {
                    plot = plot.include_y(100.0);
                }
                plot.show(ui, |p| {
                    for run in graphs::runs(series, data, field) {
                        p.line(Line::new(name, PlotPoints::from(run)).color(color).width(1.5));
                    }
                });
            }
        });
    }

    /// The engine's warnings, one line each (none: a quiet line); only
    /// the keys in `only` when given.
    fn warnings(&mut self, app: &CoreRouterUi, ui: &mut Ui, s: &Value, only: Option<&[&str]>) {
        let l = app.lang.labels;
        let mut list = s.get("warnings").and_then(Value::as_array).cloned().unwrap_or_default();
        if let Some(keys) = only {
            list.retain(|w| keys.contains(&text(w, "key").as_str()));
        }
        ui.horizontal(|ui| {
            heading(ui, &mut self.help, l, "dns_statistics.warnings", "Warnings");
            if list.is_empty() {
                ui.weak(tr_in(SCOPE, l, "none in the last minute"));
            }
        });
        let v = ui.visuals().clone();
        for w in &list {
            ui.horizontal_wrapped(|ui| {
                let (tone, word) = match w.get("severity").and_then(Value::as_str) {
                    Some("error") => (RED.tone(&v), "error"),
                    _ => (AMBER.tone(&v), "warning"),
                };
                chip(ui, tr_in(SCOPE, l, word), tone);
                ui.label(warning_text(app.lang.help, w));
            });
        }
    }

    fn upstreams(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, s: &Value) {
        let l = app.lang.labels;
        let rows: Vec<Row> = s
            .get("upstreams")
            .and_then(Value::as_array)
            .map(|a| a.iter().map(upstream_row).collect())
            .unwrap_or_default();
        if rows.is_empty() {
            ui.weak(tr_in(SCOPE, l, "No upstream server asked yet (IP › DNS › Servers, or a DHCP client with use_peer_dns)."));
        }
        let out = table::show(ui, UPSTREAMS_TABLE, 190.0, &mut self.upstreams_table, &UPSTREAM_COLUMNS, &rows, |ui, menu| {
            refresh_menu(app, ui, &menu);
        });
        if let Some(key) = out.help {
            let title = UPSTREAM_COLUMNS.iter().find(|c| c.help == key).map_or("", |c| c.title);
            self.help = Some(HelpView::new(key, tr_in(SCOPE, l, title)));
        }
        ui.add_space(6.0);
        // The selected server's round trips, else every server's.
        let picked = self.upstreams_table.selection(&rows).into_vec().into_iter().next();
        let (who, ranges): (String, Vec<(String, u64)>) = match picked.as_ref().and_then(|k| {
            s.get("upstreams")?.as_array()?.iter().find(|r| text(r, "server") == *k)
        }) {
            Some(r) => (
                text(r, "server"),
                r.get("rtt_ranges")
                    .and_then(Value::as_array)
                    .map(|a| {
                        RANGE_NAMES.iter().zip(a).map(|(name, c)| ((*name).to_owned(), c.as_u64().unwrap_or(0))).collect()
                    })
                    .unwrap_or_default(),
            ),
            None => (
                tr_in(SCOPE, l, "all servers").to_owned(),
                s.get("rtt_ranges")
                    .and_then(Value::as_array)
                    .map(|a| a.iter().map(|r| (text(r, "range"), n(r, "replies"))).collect())
                    .unwrap_or_default(),
            ),
        };
        ui.horizontal(|ui| {
            heading(ui, &mut self.help, l, "dns_statistics.rtt_histogram", "Round trips by range (ms)");
            ui.weak(who);
        });
        histogram(ui, &ranges);
    }

    fn cache(&mut self, app: &CoreRouterUi, ui: &mut Ui, s: &Value) {
        let l = app.lang.labels;
        let help = &mut self.help;
        let c = s.get("cache").cloned().unwrap_or(Value::Null);
        if c.is_null() {
            ui.weak(tr_in(SCOPE, l, "No daemon: the virtual lab has no cache to show."));
        }
        let used = n(&c, "used_bytes");
        let max = n(&c, "max_bytes");
        Grid::new("dns-stats-cache").num_columns(2).spacing([16.0, 6.0]).show(ui, |ui| {
            label(ui, help, l, "dns_statistics.cache_entries", "Entries");
            ui.label(RichText::new(n(&c, "entries").to_string()).strong());
            ui.end_row();
            label(ui, help, l, "dns_statistics.cache_used", "Used / Max");
            ui.horizontal(|ui| {
                let frac = if max > 0 { used as f32 / max as f32 } else { 0.0 };
                ui.add(egui::ProgressBar::new(frac.clamp(0.0, 1.0)).desired_width(160.0));
                ui.label(format!("{} / {}", graphs::bytes(used as f64), graphs::bytes(max as f64)));
            });
            ui.end_row();
            label(ui, help, l, "dns_statistics.evicted", "Evictions");
            let ev = n(&c, "evicted");
            if ev > 0 {
                ui.colored_label(ui.visuals().warn_fg_color, ev.to_string());
            } else {
                ui.label("0");
            }
            ui.end_row();
            label(ui, help, l, "dns_statistics.expired", "Expired");
            ui.label(n(&c, "expired").to_string());
            ui.end_row();
            label(ui, help, l, "dns_statistics.stale_served", "Stale served");
            ui.label(n(&c, "stale_served").to_string());
            ui.end_row();
        });
        ui.add_space(8.0);
        let cached: Vec<(String, u64)> = c
            .get("types")
            .and_then(Value::as_array)
            .map(|a| a.iter().map(|t| (text(t, "type"), n(t, "entries"))).collect())
            .unwrap_or_default();
        let asked: Vec<(String, u64)> = s
            .get("types")
            .and_then(Value::as_array)
            .map(|a| a.iter().map(|t| (text(t, "type"), n(t, "queries"))).collect())
            .unwrap_or_default();
        ui.horizontal_top(|ui| {
            for (title, key, list) in [
                ("Cached by type", "dns_statistics.types_cached", &cached),
                ("Asked by type", "dns_statistics.types_asked", &asked),
            ] {
                ui.group(|ui| {
                    ui.vertical(|ui| {
                        heading(ui, help, l, key, title);
                        let mut shown: Vec<(String, u64)> = list.iter().take(TYPES).cloned().collect();
                        let rest: u64 = list.iter().skip(TYPES).map(|(_, c)| c).sum();
                        if rest > 0 {
                            shown.push((tr_in(SCOPE, l, "others").to_owned(), rest));
                        }
                        if shown.is_empty() {
                            ui.weak("–");
                        }
                        histogram(ui, &shown);
                    });
                });
            }
        });
    }
}

/// The six ranges of the round-trip histogram (as the router names them).
const RANGE_NAMES: [&str; 6] = ["<1", "1-10", "10-100", "100-500", "500-1600", ">1600"];

/// One bar per row, every row shown (the ends too, even at zero).
fn histogram(ui: &mut Ui, rows: &[(String, u64)]) {
    let most = rows.iter().map(|(_, c)| *c).max().unwrap_or(0).max(1);
    let total: u64 = rows.iter().map(|(_, c)| c).sum();
    let ink = chip::palette_tone(ui.visuals(), 0).ink;
    Grid::new(ui.next_auto_id()).num_columns(3).spacing([10.0, 3.0]).show(ui, |ui| {
        for (name, c) in rows {
            ui.label(name);
            let (rect, _) = ui.allocate_exact_size(egui::vec2(220.0, 12.0), egui::Sense::hover());
            ui.painter().rect_filled(rect, 2.0, ui.visuals().faint_bg_color);
            let mut bar = rect;
            bar.set_width(rect.width() * (*c as f32 / most as f32));
            ui.painter().rect_filled(bar, 2.0, ink);
            ui.label(format!("{c}  ({} %)", percent(*c, total)));
            ui.end_row();
        }
    });
}

/// A card: title with its ⓘ, a large value and a line under it.
fn card(ui: &mut Ui, help: &mut Option<HelpView>, l: Lang, (key, title): (&'static str, &'static str), value: String, sub: String) {
    ui.group(|ui| {
        ui.set_min_width(138.0);
        ui.vertical(|ui| {
            label(ui, help, l, key, title);
            ui.label(RichText::new(value).size(20.0).strong());
            ui.weak(sub);
        });
    });
}

fn refresh_menu(app: &mut CoreRouterUi, ui: &mut Ui, menu: &Menu<'_>) {
    if let Menu::Empty | Menu::Rows(_) = menu
        && ui.button("Refresh").clicked()
    {
        app.cache.refreshed_at = None;
    }
}

/// Why nothing may be counting, as a chip (docs/ui-style.md); `counting`
/// when the forwarder answers.
fn state_chip(ui: &mut Ui, l: Lang, s: &Value) {
    let v = ui.visuals().clone();
    if s.get("resolver").and_then(Value::as_str) == Some("simulated") {
        chip(ui, "lab", neutral_tone(&v))
            .on_hover_text(tr_in(SCOPE, l, "No daemon: the virtual lab does not answer DNS, nothing is counted"));
    } else if s.get("allow_remote_requests").and_then(Value::as_bool) == Some(false) {
        chip(ui, tr_in(SCOPE, l, "forwarder off"), AMBER.tone(&v))
            .on_hover_text(tr_in(SCOPE, l, "Allow Remote Requests is off: the LAN is not answered"));
    } else if s.is_object() {
        chip(ui, tr_in(SCOPE, l, "counting"), chip::GREEN.tone(&v));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rows() {
        let c = json!({"address": "192.168.88.10", "queries": 30, "queries_per_sec": 2.5, "nxdomain_percent": 10.0,
            "limited": 1, "refused": 2, "error": 0, "seen_secs": 5});
        assert_eq!(client_row(&c, 120).cells, ["192.168.88.10", "2.5", "30", "25", "10", "1", "2", "5s"]);
        let c = json!({"address": "2001:db8:1:ab00::/56", "queries": 7, "refused": 0, "error": 6, "seen_secs": 90});
        let r = client_row(&c, 0);
        assert_eq!(r.cells[2..4], ["≤7", "–"]);
        assert!(r.dimmed, "quiet for a minute");
        let d = json!({"domain": "victim.com.br", "nxdomain": 900, "servfail": 3, "failures_per_sec": 41.0,
            "names": 880, "error": 0, "random": true});
        let r = domain_row(&d);
        assert_eq!(chip::split(&r.cells[0]), ("victim.com.br", vec![(Kind::Amber, "random names")]));
        assert_eq!(r.cells[1..], ["900", "3", "41", "≈880"]);
        let nm = json!({"name": "www.example.com", "queries": 50, "queries_per_sec": 0.4, "error": 2});
        assert_eq!(name_row(&nm, 200).cells, ["www.example.com", "≤50", "25", "0.4"]);
        let u = json!({"server": "1.1.1.1", "via": "dot", "answers_per_sec": 12.5, "rtt_p50_ms": 0.04,
            "rtt_p95_ms": 23.4, "timeouts_percent": 0.0, "servfail_percent": null, "truncated": 2,
            "state": "down", "state_secs": 30});
        let r = upstream_row(&u);
        assert_eq!(r.cells[..8], ["1.1.1.1", "DOT", "12.5", "<0.1", "23", "0", "–", "2"]);
        assert_eq!(chip::split(&r.cells[8]).1, [(Kind::Red, "down 30s")]);
        assert!(r.dimmed);
        let got = counts(&json!({"noerror": 3, "nxdomain": 9, "refused": 3}));
        assert_eq!(got[0], ("nxdomain".to_owned(), 9));
        assert_eq!(got[1].0, "noerror", "ties by name");
        assert_eq!((ms(Some(1600.0)), one(Some(33.33)), one(Some(250.0))), ("1600".into(), "33.3".into(), "250".into()));
    }

    #[test]
    fn ranges_match_the_router() {
        assert_eq!(RANGE_NAMES, corerouter_proto_dns::histogram::RANGES.map(|(n, _)| n));
    }
}
