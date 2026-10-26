//! PPP (G4.3d), RouterOS' `/ppp` window: one window, the WinBox tabs
//! (parts of a window are tabs, `docs/ui-style.md`):
//!
//! - **Interface:** the PPPoE service at a glance (running, the data plane
//!   in use, sessions and the Discovery counters) and the servers;
//! - **PPPoE Servers**, **Secrets**, **Profiles:** the list pattern (G0.24)
//!   with the add/edit modal fed by the engine's `*.preview` (a change that
//!   ends sessions asks first: "drops N sessions", Safe Mode offered);
//! - **Active Connections:** one row per subscriber with its identity chip,
//!   rate-limit chip and counters, and the blocks routed to it with the
//!   chip of where each came from (G4.3cd); Disconnect, Torch and **Why?**;
//! - **AAA:** `/ppp aaa`; **RADIUS:** a way to the RADIUS window;
//! - **History:** the last logins, failures and ends, with the reason.
//!
//! **Why?** answers "por que esse cliente não sobe": the stages a user or a
//! MAC reaches (PADI → PADR → LCP → Auth → NCP → up), how many attempts,
//! and the last reason in Portuguese with what to do. The engine and the
//! daemon's `pppoe` service decide; the window only shows and sends.

use std::collections::BTreeMap;

use egui::{Grid, Id, TextEdit, Ui};
use serde_json::{Map, Value, json};

use crate::backend::RequestId;
use crate::chip::{self, Kind};
use crate::dhcp_client::{flag, text};
use crate::dialog::{self, Buttons, Footer, Head, Press, Status};
use crate::help::{self, HelpView};
use crate::i18n::{Lang, tr_in};
use crate::interfaces::{cascade, dialog_id};
use crate::list::{self, Act, Cmds, Item, Tools};
use crate::list_modal::{self, Applied, Field, Input, Modal, Spec};
use crate::panel::{Panel, PanelState, PanelThen, Query, WinDef};
use crate::table::{self, Icon, Menu, Row, TableState, col, comment, num};
use crate::{CoreRouterUi, Win, icons};

pub(crate) const NAME: &str = "ppp";
pub(crate) const WIN: &str = "ppp";
const SCOPE: &str = "ppp";
const SERVERS: &str = "ppp-servers";
const SERVICES: &str = "ppp-services";
/// Height of the Service Names table under the servers (G4.3k).
const SERVICES_H: f32 = 210.0;
const SECRETS: &str = "ppp-secrets";
const PROFILES: &str = "ppp-profiles";
const ACTIVE: &str = "ppp-active";
const HISTORY: &str = "ppp-history";
const AAA_SET: &str = "ppp.aaa.set";
/// Rows asked of the long lists at a time (the find narrows on the router).
const PAGE: u32 = 5000;

pub(crate) const PANEL: Panel = Panel {
    name: NAME,
    windows: &[WinDef { id: WIN, group: "PPP", title: "PPP", size: [1120.0, 480.0], escape: true }],
    new: || Box::<PppPanel>::default(),
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum Tab {
    Interface,
    Servers,
    Secrets,
    Profiles,
    #[default]
    Active,
    Aaa,
    /// G4.3h: the active/standby pair (`ppp_redundancy.rs`).
    Redundancy,
    Radius,
    History,
}

const TABS: [(Tab, &str, &str); 9] = [
    (Tab::Interface, "Interface", "interface"),
    (Tab::Servers, "PPPoE Servers", "servers"),
    (Tab::Secrets, "Secrets", "secrets"),
    (Tab::Profiles, "Profiles", "profiles"),
    (Tab::Active, "Active Connections", "active"),
    (Tab::Aaa, "AAA", "aaa"),
    (Tab::Redundancy, "Redundancy", "redundancy"),
    (Tab::Radius, "RADIUS", "radius"),
    (Tab::History, "History", "history"),
];

const SERVER_CMDS: Cmds = Cmds {
    add: "interface.pppoe-server.server.add",
    remove: "interface.pppoe-server.server.remove",
    set: Some("interface.pppoe-server.server.set"),
    what: "servers",
};
const SERVICE_CMDS: Cmds = Cmds {
    add: "interface.pppoe-server.server.service.add",
    remove: "interface.pppoe-server.server.service.remove",
    set: Some("interface.pppoe-server.server.service.set"),
    what: "service names",
};
const SECRET_CMDS: Cmds = Cmds { add: "ppp.secret.add", remove: "ppp.secret.remove", set: Some("ppp.secret.set"), what: "secrets" };
const PROFILE_CMDS: Cmds = Cmds { add: "ppp.profile.add", remove: "ppp.profile.remove", set: Some("ppp.profile.set"), what: "profiles" };

const SERVER_COLUMNS: [table::Column; 11] = [
    col("Name").help("ppp.server.name"),
    col("Interface").help("ppp.server.interface"),
    col("Service").help("ppp.server.service_name"),
    num("MTU/MRU").help("ppp.server.max_mtu"),
    col("Authentication").help("ppp.server.authentication"),
    num("Keepalive").help("ppp.server.keepalive_timeout"),
    col("VLANs").help("ppp.server.pppoe_over_vlan_range"),
    col("Profile").help("ppp.server.default_profile"),
    col("New Sessions").help("ppp.server.admission"),
    num("Sessions").help("ppp.server.sessions"),
    comment(),
];
const SERVICE_COLUMNS: [table::Column; 7] = [
    col("Service Name").help("ppp.service.name"),
    col("Profile").help("ppp.service.profile"),
    col("Action").help("ppp.service.action"),
    num("PADO Delay").help("ppp.service.pado_delay"),
    num("Max Sessions").help("ppp.service.max_sessions"),
    num("PADI Limit").help("ppp.service.padi_limit"),
    num("Sessions").help("ppp.service.sessions"),
];
const SECRET_COLUMNS: [table::Column; 9] = [
    col("Name").help("ppp.secret.name"),
    col("Service").help("ppp.secret.service"),
    col("Profile").help("ppp.secret.profile"),
    col("Remote Address").help("ppp.secret.remote_address"),
    col("Routes").help("ppp.secret.routes"),
    col("Caller ID").help("ppp.secret.caller_id"),
    col("Limits").help("ppp.secret.limit_bytes"),
    col("State").help("ppp.secret.state"),
    comment(),
];
const PROFILE_COLUMNS: [table::Column; 10] = [
    col("Name").help("ppp.profile.name"),
    col("Local Address").help("ppp.profile.local_address"),
    col("Remote Address").help("ppp.profile.remote_address"),
    col("DNS").help("ppp.profile.dns_server"),
    col("Rate Limit").help("ppp.profile.rate_limit"),
    col("Address List").help("ppp.profile.address_list"),
    col("Only One").help("ppp.profile.only_one"),
    col("IPv6").help("ppp.profile.ipv6"),
    num("Secrets").help("ppp.profile.secrets"),
    comment(),
];
pub(crate) const ACTIVE_COLUMNS: [table::Column; 16] = [
    col("Name").help("ppp.active.name"),
    col("Service").help("ppp.active.service"),
    col("Caller ID").help("ppp.active.caller_id"),
    col("Address").help("ppp.active.address"),
    col("IPv6 Prefix").help("ppp.active.ipv6_prefix"),
    col("Delegated Prefix").help("ppp.active.delegated_prefix"),
    col("Routes").help("ppp.active.routes"),
    num("Uptime").help("ppp.active.uptime"),
    col("Rate Limit").help("ppp.active.rate_limit"),
    num("Queue").help("ppp.active.queue"),
    num("Drops").help("ppp.active.drops"),
    num("Rx").help("ppp.active.rx"),
    num("Tx").help("ppp.active.tx"),
    col("Traffic").help("ppp.active.traffic"),
    col("VLAN").help("ppp.active.vlan"),
    col("Circuit ID").help("ppp.active.circuit_id"),
];
const HISTORY_COLUMNS: [table::Column; 8] = [
    col("When").help("ppp.history.at"),
    col("Name").help("ppp.active.name"),
    col("Caller ID").help("ppp.active.caller_id"),
    col("Event").help("ppp.history.event"),
    col("Stage").help("ppp.why.stage"),
    col("Reason").help("ppp.history.reason"),
    col("Address").help("ppp.active.address"),
    num("Uptime").help("ppp.active.uptime"),
];

const SERVER_FIELDS: &[Field] = &[
    Field { param: "interface", label: "Interface", help: "ppp.server.interface", input: Input::Choice, edit: true },
    Field { param: "name", label: "Name", help: "ppp.server.name", input: Input::Text("pppoe-<interface>"), edit: true },
    Field { param: "max_mtu", label: "Max MTU", help: "ppp.server.max_mtu", input: Input::Text("1480"), edit: true },
    Field { param: "max_mru", label: "Max MRU", help: "ppp.server.max_mru", input: Input::Text("1480"), edit: true },
    Field { param: "mrru", label: "MRRU", help: "ppp.server.mrru", input: Input::Text("disabled"), edit: true },
    Field { param: "authentication", label: "Authentication", help: "ppp.server.authentication", input: Input::Text("mschap2,mschap1,chap,pap"), edit: true },
    Field { param: "keepalive_timeout", label: "Keepalive Timeout", help: "ppp.server.keepalive_timeout", input: Input::Text("10"), edit: true },
    Field { param: "one_session_per_host", label: "One Session Per Host", help: "ppp.server.one_session_per_host", input: Input::Check, edit: true },
    Field { param: "max_sessions", label: "Max Sessions", help: "ppp.server.max_sessions", input: Input::Text("0 (no limit)"), edit: true },
    Field { param: "default_profile", label: "Default Profile", help: "ppp.server.default_profile", input: Input::Choice, edit: true },
    Field { param: "pppoe_over_vlan_range", label: "PPPoE over VLAN Range", help: "ppp.server.pppoe_over_vlan_range", input: Input::Text("100-115,120"), edit: true },
    Field { param: "accept_untagged", label: "Accept Untagged", help: "ppp.server.accept_untagged", input: Input::Check, edit: true },
    Field { param: "vlan_mode", label: "VLAN Mode", help: "ppp.server.vlan_mode", input: Input::Choice, edit: true },
    Field { param: "outer_vlan_range", label: "Outer VLAN Range", help: "ppp.server.outer_vlan_range", input: Input::Text("100-199 (stacked)"), edit: true },
    Field { param: "inner_vlan_range", label: "Inner VLAN Range", help: "ppp.server.inner_vlan_range", input: Input::Text("any"), edit: true },
    Field { param: "outer_tpid", label: "Outer TPID", help: "ppp.server.outer_tpid", input: Input::Choice, edit: true },
    Field { param: "max_sessions_per_vlan", label: "Max Sessions per VLAN", help: "ppp.server.max_sessions_per_vlan", input: Input::Text("0 (no limit; 1 = 1:1)"), edit: true },
    Field { param: "max_payload", label: "Max Payload (RFC 4638)", help: "ppp.server.max_payload", input: Input::Text("none (1492)"), edit: true },
    Field { param: "pado_delay", label: "PADO Delay (ms)", help: "ppp.server.pado_delay", input: Input::Text("0"), edit: true },
    Field { param: "pado_delay_by_load", label: "PADO Delay by Load", help: "ppp.server.pado_delay_by_load", input: Input::Text("5000:100,20000:300"), edit: true },
    Field { param: "ac_cookie", label: "AC-Cookie", help: "ppp.server.ac_cookie", input: Input::Check, edit: true },
    Field { param: "padi_limit", label: "PADI Limit (/s)", help: "ppp.server.padi_limit", input: Input::Text("2000"), edit: true },
    Field { param: "mac_padi_limit", label: "PADI Limit per MAC (/s)", help: "ppp.server.mac_padi_limit", input: Input::Text("1"), edit: true },
    Field { param: "new_session_rate", label: "New Sessions (/s)", help: "ppp.server.new_session_rate", input: Input::Text("2000"), edit: true },
    Field { param: "disabled", label: "Disabled", help: "ppp.server.disabled", input: Input::Check, edit: true },
    Field { param: "comment", label: "Comment", help: "", input: Input::Text(""), edit: true },
];
const SERVER_SPEC: Spec = Spec {
    panel: NAME,
    parent: Win::Panel(WIN),
    new_title: "New PPPoE Server",
    edit_title: "PPPoE Server",
    help: "ppp.servers",
    fields: SERVER_FIELDS,
    preview: "interface.pppoe-server.server.preview",
};

/// A row of the Service-Name table (G4.3k).
const SERVICE_FIELDS: &[Field] = &[
    Field { param: "server", label: "Server", help: "ppp.service.server", input: Input::Choice, edit: false },
    Field { param: "name", label: "Service Name", help: "ppp.service.name", input: Input::Text("internet, empty or any"), edit: true },
    Field { param: "profile", label: "Profile", help: "ppp.service.profile", input: Input::Choice, edit: true },
    Field { param: "action", label: "Action", help: "ppp.service.action", input: Input::Choice, edit: true },
    Field { param: "pado_delay", label: "PADO Delay (ms)", help: "ppp.service.pado_delay", input: Input::Text("0"), edit: true },
    Field { param: "max_sessions", label: "Max Sessions", help: "ppp.service.max_sessions", input: Input::Text("0 (no limit)"), edit: true },
    Field { param: "padi_limit", label: "PADI Limit (/s)", help: "ppp.service.padi_limit", input: Input::Text("0 (no limit)"), edit: true },
];
const SERVICE_SPEC: Spec = Spec {
    panel: NAME,
    parent: Win::Panel(WIN),
    new_title: "New Service Name",
    edit_title: "Service Name",
    help: "ppp.services",
    fields: SERVICE_FIELDS,
    preview: "interface.pppoe-server.server.service.preview",
};

const SECRET_FIELDS: &[Field] = &[
    Field { param: "name", label: "Name", help: "ppp.secret.name", input: Input::Text("joao@isp"), edit: true },
    Field { param: "password", label: "Password", help: "ppp.secret.password", input: Input::Secret("write-only; empty keeps it"), edit: true },
    Field { param: "service", label: "Service", help: "ppp.secret.service", input: Input::Choice, edit: true },
    Field { param: "profile", label: "Profile", help: "ppp.secret.profile", input: Input::Choice, edit: true },
    Field { param: "remote_address", label: "Remote Address", help: "ppp.secret.remote_address", input: Input::Text("(from the profile's pool)"), edit: true },
    Field { param: "local_address", label: "Local Address", help: "ppp.secret.local_address", input: Input::Text("(from the profile)"), edit: true },
    Field { param: "routes", label: "Routes", help: "ppp.secret.routes", input: Input::Text("203.0.113.8/29, 2001:db8:100::/48"), edit: true },
    Field { param: "caller_id", label: "Caller ID", help: "ppp.secret.caller_id", input: Input::Text("AA:BB:CC:DD:EE:FF"), edit: true },
    Field { param: "limit_bytes_in", label: "Limit Bytes In", help: "ppp.secret.limit_bytes", input: Input::Text("0"), edit: true },
    Field { param: "limit_bytes_out", label: "Limit Bytes Out", help: "ppp.secret.limit_bytes", input: Input::Text("0"), edit: true },
    Field { param: "disabled", label: "Disabled", help: "ppp.secret.disabled", input: Input::Check, edit: true },
    Field { param: "comment", label: "Comment", help: "", input: Input::Text(""), edit: true },
];
const SECRET_SPEC: Spec = Spec {
    panel: NAME,
    parent: Win::Panel(WIN),
    new_title: "New PPP Secret",
    edit_title: "PPP Secret",
    help: "ppp.secrets",
    fields: SECRET_FIELDS,
    preview: "ppp.secret.preview",
};

const PROFILE_FIELDS: &[Field] = &[
    Field { param: "name", label: "Name", help: "ppp.profile.name", input: Input::Text("plano-100M"), edit: true },
    Field { param: "local_address", label: "Local Address", help: "ppp.profile.local_address", input: Input::Text("10.0.0.1 or a pool"), edit: true },
    Field { param: "remote_address", label: "Remote Address", help: "ppp.profile.remote_address", input: Input::Text("a pool (ip.pool)"), edit: true },
    Field { param: "dns_server", label: "DNS Server", help: "ppp.profile.dns_server", input: Input::Text("1.1.1.1,8.8.8.8"), edit: true },
    Field { param: "rate_limit", label: "Rate Limit (rx/tx)", help: "ppp.profile.rate_limit", input: Input::Text("50M/100M"), edit: true },
    Field { param: "download_mode", label: "Download Mode", help: "ppp.profile.download_mode", input: Input::Choice, edit: true },
    Field { param: "queue_type", label: "Queue Type", help: "ppp.profile.queue_type", input: Input::Choice, edit: true },
    Field { param: "address_list", label: "Address List", help: "ppp.profile.address_list", input: Input::Text("assinantes"), edit: true },
    Field { param: "only_one", label: "Only One", help: "ppp.profile.only_one", input: Input::Choice, edit: true },
    Field { param: "change_tcp_mss", label: "Change TCP MSS", help: "ppp.profile.change_tcp_mss", input: Input::Choice, edit: true },
    Field { param: "idle_timeout", label: "Idle Timeout", help: "ppp.profile.idle_timeout", input: Input::Text("(none)"), edit: true },
    Field { param: "session_timeout", label: "Session Timeout", help: "ppp.profile.session_timeout", input: Input::Text("(none)"), edit: true },
    Field { param: "use_ipv6", label: "Use IPv6", help: "ppp.profile.use_ipv6", input: Input::Choice, edit: true },
    Field { param: "remote_ipv6_prefix_pool", label: "Remote IPv6 Prefix Pool", help: "ppp.profile.remote_ipv6_prefix_pool", input: Input::Text("an /ipv6 pool of /64"), edit: true },
    Field { param: "dhcpv6_pd_pool", label: "DHCPv6 PD Pool", help: "ppp.profile.dhcpv6_pd_pool", input: Input::Text("an /ipv6 pool of /48–/64"), edit: true },
    Field { param: "dhcpv6_lease_time", label: "DHCPv6 Lease Time", help: "ppp.profile.dhcpv6_lease_time", input: Input::Text("1d"), edit: true },
    Field { param: "dns_server_ipv6", label: "IPv6 DNS Server", help: "ppp.profile.dns_server_ipv6", input: Input::Text("2001:db8::53"), edit: true },
    Field { param: "on_up", label: "On Up", help: "ppp.profile.on_up", input: Input::Text("[{\"command\":…,\"params\":{…}}]"), edit: true },
    Field { param: "on_down", label: "On Down", help: "ppp.profile.on_down", input: Input::Text("[{\"command\":…,\"params\":{…}}]"), edit: true },
    Field { param: "comment", label: "Comment", help: "", input: Input::Text(""), edit: true },
];
const PROFILE_SPEC: Spec = Spec {
    panel: NAME,
    parent: Win::Panel(WIN),
    new_title: "New PPP Profile",
    edit_title: "PPP Profile",
    help: "ppp.profiles",
    fields: PROFILE_FIELDS,
    preview: "ppp.profile.preview",
};

/// `/ppp aaa`, as typed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct AaaForm {
    pub use_radius: bool,
    pub accounting: bool,
    pub interim_update: String,
    pub interim_jitter: String,
    pub use_circuit_id_in_nas_port_id: bool,
    pub enable_ipv6_accounting: bool,
}

impl AaaForm {
    fn of(v: &Value) -> Self {
        Self {
            use_radius: flag(v, "use_radius"),
            accounting: flag(v, "accounting"),
            interim_update: text(v, "interim_update"),
            interim_jitter: text(v, "interim_jitter"),
            use_circuit_id_in_nas_port_id: flag(v, "use_circuit_id_in_nas_port_id"),
            enable_ipv6_accounting: flag(v, "enable_ipv6_accounting"),
        }
    }

    pub(crate) fn set_params(&self, base: &Self) -> Option<Value> {
        let mut p = Map::new();
        for (k, now, was) in [
            ("use_radius", self.use_radius, base.use_radius),
            ("accounting", self.accounting, base.accounting),
            ("use_circuit_id_in_nas_port_id", self.use_circuit_id_in_nas_port_id, base.use_circuit_id_in_nas_port_id),
            ("enable_ipv6_accounting", self.enable_ipv6_accounting, base.enable_ipv6_accounting),
        ] {
            if now != was {
                p.insert(k.into(), json!(now));
            }
        }
        for (k, now, was) in [("interim_update", &self.interim_update, &base.interim_update), ("interim_jitter", &self.interim_jitter, &base.interim_jitter)] {
            if now.trim() != was.trim() {
                let v = now.trim().parse::<u64>().map_or_else(|_| json!(now.trim()), |x| json!(x));
                p.insert(k.into(), v);
            }
        }
        (!p.is_empty()).then_some(Value::Object(p))
    }
}

/// The Why? dialog: a user or a MAC, and the router's answer.
pub(crate) struct WhyDialog {
    pub id: u64,
    pub name: String,
    pub mac: String,
    /// What was asked (sent with every refresh while open).
    pub asked: Option<Value>,
    pub answer: Option<Value>,
    pub status: Status,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WhyButton {
    Find,
}

/// A toolbar change the router refused because it ends sessions: shown to
/// the operator, sent again with `force` on yes.
pub(crate) struct Drops {
    pub id: u64,
    pub steps: Vec<Value>,
    pub message: String,
    pub status: Status,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DropsButton {
    Force,
    SafeMode,
}

/// Replies: an Apply of AAA, a toolbar change (its steps, to ask again).
struct Saved(AaaForm);
struct Done(Vec<Value>);

#[derive(Default)]
pub(crate) struct PppPanel {
    pub(crate) tab: Tab,
    pub(crate) servers: Vec<Value>,
    pub(crate) secrets: Vec<Value>,
    pub(crate) secret_count: Value,
    pub(crate) profiles: Vec<Value>,
    /// `queue.type.list`, for the profile modal's Queue Type (G4.9c).
    queue_types: Vec<Value>,
    pub(crate) active: Value,
    pub(crate) monitor: Value,
    pub(crate) history: Vec<Value>,
    pub(crate) aaa: Value,
    pub(crate) form: AaaForm,
    base: AaaForm,
    waiting: usize,
    pub(crate) error: Option<String>,
    servers_table: TableState,
    /// G4.3k: the Service-Name table of `svc_server` (a server's id: the
    /// one selected, else the first).
    pub(crate) services: Vec<Value>,
    pub(crate) svc_server: Option<String>,
    services_table: TableState,
    pub(crate) svc_modal: Option<Modal>,
    secrets_table: TableState,
    profiles_table: TableState,
    active_table: TableState,
    history_table: TableState,
    /// `ppp.history` filter: up, down or failed (empty: all).
    pub(crate) event: String,
    pub(crate) modal: Option<(Tab, Modal)>,
    pub(crate) why: Option<WhyDialog>,
    pub(crate) drops: Option<Drops>,
    /// Secrets › Import from MikroTik (G4.3n).
    pub(crate) import: Option<crate::ppp_import::ImportDialog>,
    pub(crate) help: Option<HelpView>,
    /// Rx/Tx bits per second of each session since the window opened (the
    /// sparkline of Active Connections), at most [`TRAFFIC_POINTS`].
    pub(crate) traffic: BTreeMap<String, std::collections::VecDeque<(f64, f64)>>,
    /// A login to select once Active Connections has it (the identity chip
    /// of another window was clicked).
    pub(crate) reveal: Option<String>,
    pub(crate) redundancy: crate::ppp_redundancy::RedundancyTab,
}

/// Points of the per-session sparkline (one per refresh, ~2 minutes).
const TRAFFIC_POINTS: usize = 120;

fn showing(app: &CoreRouterUi) -> bool {
    app.open.contains(&Win::Panel(WIN))
}

fn n(v: &Value, k: &str) -> u64 {
    v.get(k).and_then(Value::as_u64).unwrap_or(0)
}

/// Bytes the RouterOS way: 1.5 MiB, 812 KiB.
pub(crate) fn bytes(b: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = b as f64;
    let mut u = 0;
    while v >= 1024.0 && u + 1 < UNITS.len() {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 { format!("{b} B") } else { format!("{v:.1} {}", UNITS.get(u).copied().unwrap_or("B")) }
}

/// A rate limit chip: the rx/tx part, the rest in the tooltip of the cell.
/// The profile's IPv6 in one cell: `use_ipv6` (unless default) and the
/// pools, `/64 wan6 · PD pd6`.
fn profile_v6(r: &Value) -> String {
    let mut parts: Vec<String> = Vec::new();
    let use6 = text(r, "use_ipv6");
    if !use6.is_empty() && use6 != "default" {
        parts.push(use6);
    }
    let p64 = text(r, "remote_ipv6_prefix_pool");
    if !p64.is_empty() {
        parts.push(format!("/64 {p64}"));
    }
    let pd = text(r, "dhcpv6_pd_pool");
    if !pd.is_empty() {
        parts.push(format!("PD {pd}"));
    }
    parts.join(" · ")
}

/// The delegated prefix, with a selo when the CPE's DHCPv6 holds it
/// (`bound`) or only reserved for the session (`reserved`).
fn delegated_cell(r: &Value) -> String {
    let pd = text(r, "delegated_prefix");
    if pd.is_empty() {
        return String::new();
    }
    let chips: &[(&str, Kind)] = if flag(r, "delegated_bound") { &[("bound", Kind::Green)] } else { &[("reserved", Kind::Neutral)] };
    chip::cell(&pd, chips)
}

/// G4.3cd: the colour of a route's origin chip (the same in the table and
/// in Why?): RADIUS attributes in blue shades, the secret neutral.
pub(crate) fn origin_kind(origin: &str) -> Kind {
    match origin {
        "secret" => Kind::Neutral,
        "framed-route" => Kind::Blue,
        other => Kind::Hashed(chip::name_hue(other)),
    }
}

/// The RADIUS attribute (or the menu) a route came from, as the operator
/// knows it.
pub(crate) fn origin_label(origin: &str) -> &str {
    match origin {
        "framed-route" => "Framed-Route",
        "framed-ipv6-route" => "Framed-IPv6-Route",
        "framed-ipv6-prefix" => "Framed-IPv6-Prefix",
        "secret" => "secret",
        other => other,
    }
}

/// G4.3cd: the blocks routed to a session, each a chip of its block and a
/// chip of where it came from; routes refused add a red count (Why? says
/// why).
fn routes_cell(r: &Value) -> String {
    let routes: Vec<(String, String)> = r
        .get("routes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|x| {
            let route = text(x, "route");
            let block = route.split_whitespace().next().unwrap_or_default().to_owned();
            (block, text(x, "origin"))
        })
        .collect();
    let refused = r.get("refused_routes").and_then(Value::as_array).map_or(0, Vec::len);
    let refused_text = format!("{refused} refused");
    let mut chips: Vec<(&str, Kind)> = Vec::new();
    for (block, origin) in &routes {
        chips.push((block.as_str(), Kind::Neutral));
        chips.push((origin_label(origin), origin_kind(origin)));
    }
    if refused > 0 {
        chips.push((refused_text.as_str(), Kind::Red));
    }
    if chips.is_empty() { String::new() } else { chip::cell("", &chips) }
}

fn rate_chip(rate: &str) -> String {
    if rate.is_empty() {
        return "–".into();
    }
    let short = rate.split_whitespace().next().unwrap_or(rate);
    chip::cell("", &[(short, Kind::Hashed(chip::name_hue(short)))])
}

pub(crate) fn stage_kind(stage: &str, failed: bool) -> Kind {
    match (stage, failed) {
        ("up", _) => Kind::Green,
        (_, true) => Kind::Red,
        _ => Kind::Amber,
    }
}

fn event_kind(event: &str) -> Kind {
    match event {
        "up" => Kind::Green,
        "failed" => Kind::Red,
        _ => Kind::Neutral,
    }
}

/// A label with its ⓘ; the explanation key is `ppp.<key>`.
fn label(ui: &mut Ui, help: &mut Option<HelpView>, l: Lang, key: &str, text: &'static str) {
    ui.horizontal(|ui| {
        ui.label(tr_in(SCOPE, l, text));
        if help::info_button(ui, Id::unique(("ppp-help", key)), tr_in(SCOPE, l, text)).clicked() {
            *help = Some(HelpView::new(format!("ppp.{key}"), tr_in(SCOPE, l, text)));
        }
    });
}

fn info(ui: &mut Ui, help: &mut Option<HelpView>, l: Lang, key: &'static str, title: &'static str) {
    if help::info_button(ui, Id::unique(("ppp-info", key)), tr_in(SCOPE, l, title)).clicked() {
        *help = Some(HelpView::new(key, tr_in(SCOPE, l, title)));
    }
}

fn rows_of(v: &Value) -> Vec<Value> {
    v.get("rows").and_then(Value::as_array).cloned().unwrap_or_default()
}

impl PppPanel {
    pub(crate) fn server_row(r: &Value) -> Row {
        let disabled = flag(r, "disabled");
        let vlans = text(r, "pppoe_over_vlan_range");
        let auth: Vec<String> = r
            .get("authentication")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).map(str::to_owned).collect())
            .unwrap_or_default();
        let auth_chips: Vec<(&str, Kind)> = auth
            .iter()
            .map(|a| (a.as_str(), if a == "pap" { Kind::Amber } else { Kind::Neutral }))
            .collect();
        let iface = text(r, "interface");
        let warn = r.get("warnings").and_then(Value::as_array).map_or(0, Vec::len);
        let mut name_chips: Vec<(&str, Kind)> = Vec::new();
        let warn_text = format!("{warn} warn");
        if disabled {
            name_chips.push(("disabled", Kind::Neutral));
        } else if warn > 0 {
            name_chips.push((warn_text.as_str(), Kind::Amber));
        }
        Row {
            key: text(r, "id"),
            cells: vec![
                chip::cell(&text(r, "name"), &name_chips),
                chip::cell("", &[(iface.as_str(), Kind::Hashed(chip::name_hue(&iface)))]),
                {
                    let s = text(r, "service_name");
                    if s.is_empty() { "(any)".into() } else { s }
                },
                format!("{}/{}", text(r, "max_mtu"), text(r, "max_mru")),
                chip::cell("", &auth_chips),
                text(r, "keepalive_timeout"),
                Self::vlans_cell(r, vlans),
                text(r, "default_profile"),
                Self::admission_cell(r),
                n(r, "sessions").to_string(),
                text(r, "comment"),
            ],
            dimmed: disabled,
            section: false,
            tint: None,
        }
    }

    /// A row of the Service-Name table: `empty` and `any` as selos, the
    /// action as a coloured selo (drop red: those CPEs get no answer).
    pub(crate) fn service_row(r: &Value) -> Row {
        let name = text(r, "name");
        let name_cell = match (flag(r, "special"), name.as_str()) {
            (true, "empty") => chip::cell("", &[("empty name", Kind::Neutral)]),
            (true, _) => chip::cell("", &[("other names", Kind::Neutral)]),
            _ => name,
        };
        let profile = text(r, "profile");
        let action = text(r, "action");
        let delay = n(r, "pado_delay");
        let delay_text = format!("delay {delay} ms");
        let action_chip = match action.as_str() {
            "drop" => ("drop", Kind::Red),
            "delay" => (delay_text.as_str(), Kind::Amber),
            _ => ("terminate", Kind::Green),
        };
        let dash = |k: &str| match n(r, k) {
            0 => "–".to_owned(),
            v => v.to_string(),
        };
        Row {
            key: text(r, "id"),
            cells: vec![
                name_cell,
                if profile.is_empty() { "–".into() } else { chip::cell("", &[(profile.as_str(), Kind::Hashed(chip::name_hue(&profile)))]) },
                chip::cell("", &[action_chip]),
                dash("pado_delay"),
                dash("max_sessions"),
                dash("padi_limit"),
                n(r, "sessions").to_string(),
            ],
            dimmed: action == "drop",
            section: false,
            tint: None,
        }
    }

    /// The Service Name modal: a new row of `server`, or `row` edited.
    pub(crate) fn open_service(&mut self, app: &mut CoreRouterUi, server: &str, row: Option<&Value>) {
        if self.modal.is_some() {
            return;
        }
        if let Some(m) = &mut self.svc_modal {
            m.status.bring_to_front();
            return;
        }
        let m = match row {
            None => {
                let mut v = BTreeMap::new();
                v.insert("server", server.to_owned());
                v.insert("action", "terminate".to_owned());
                Modal::open(app, None, v)
            }
            Some(r) => {
                let mut v = Self::values(SERVICE_FIELDS, r);
                // Zero is "none": an empty field reads better.
                for f in ["pado_delay", "max_sessions", "padi_limit"] {
                    if v.get(f).is_some_and(|x| x == "0") {
                        v.insert(f, String::new());
                    }
                }
                Modal::open(app, Some((text(r, "id"), text(r, "name"))), v)
            }
        };
        self.svc_modal = Some(m);
    }

    /// The Service-Name table of the server picked above (G4.3k): the list
    /// pattern, its own modal.
    fn services_section(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, l: Lang) {
        let Some(server) = self.svc_server.as_ref().and_then(|id| self.servers.iter().find(|r| text(r, "id") == *id)).cloned() else {
            return;
        };
        let data = self.services.clone();
        let rows: Vec<Row> = data.iter().map(Self::service_row).collect();
        let sel = self.services_table.selection(&rows);
        let picked: Vec<Item> = sel
            .as_slice()
            .iter()
            .filter_map(|k| data.iter().find(|t| text(t, "id") == *k))
            .map(|t| {
                let mut i = Item::of(t, "id", "");
                if flag(t, "special") {
                    i.fixed = Some(tr_in(SCOPE, l, "the empty and other-names rows always exist: change their action").to_owned());
                }
                i
            })
            .collect();
        let mut tools = Tools::new(&app.can(), &SERVICE_CMDS, &picked);
        // A row is not switched on or off: its action (drop) says it.
        let no = || Err(tr_in(SCOPE, l, "a row has an action instead (drop)").to_owned());
        tools.enable = no();
        tools.disable = no();
        tools.comment = no();
        let mut act = None;
        let mut help = self.help.take();
        ui.separator();
        ui.horizontal(|ui| {
            ui.strong(tr_in(SCOPE, l, "Service Names"));
            info(ui, &mut help, l, "ppp.services", "Service Names");
            let srv = text(&server, "name");
            let v = ui.visuals().clone();
            chip::chip(ui, &srv, chip::palette_tone(&v, chip::name_hue(&srv)));
            act = list::toolbar(ui, SERVICES, &tools, &sel, l);
        });
        let new_label = tr_in(SCOPE, l, SERVICE_SPEC.new_title);
        let out = table::show(ui, SERVICES, 4.0, &mut self.services_table, &SERVICE_COLUMNS, &rows, |ui, menu| match menu {
            Menu::Rows(sel) => {
                if let Some(a) = list::row_menu(ui, &tools, sel, false, l) {
                    act = Some(a);
                }
            }
            Menu::Empty => {
                if table::action(ui, &format!("{new_label}…"), tools.add.clone()) {
                    act = Some(Act::Add);
                }
            }
        });
        if let Some(key) = out.help {
            let title = SERVICE_COLUMNS.iter().find(|c| c.help == key).map_or("", |c| c.title);
            help = Some(HelpView::new(key, tr_in(SCOPE, l, title)));
        }
        self.help = help;
        if act.is_none() {
            act = list::from_shortcut(out.shortcut, &tools, &sel);
        }
        if let Some(k) = out.opened {
            act = Some(Act::Edit(k));
        }
        let step = |command: &str, params: Value| json!({"command": command, "params": params});
        let steps: Vec<Value> = match act {
            Some(Act::Add) => {
                self.open_service(app, &text(&server, "name"), None);
                return;
            }
            Some(Act::Edit(k)) => {
                let r = data.iter().find(|t| text(t, "id") == k).cloned();
                self.open_service(app, &text(&server, "name"), r.as_ref());
                return;
            }
            Some(Act::Remove(ids)) => ids.iter().map(|id| step(SERVICE_CMDS.remove, json!({"id": id}))).collect(),
            Some(Act::Copy(ids)) => {
                let picked: Vec<&Row> = rows.iter().filter(|r| ids.contains(&r.key)).collect();
                ui.ctx().copy_text(list::copy_rows(&picked));
                return;
            }
            _ => Vec::new(),
        };
        if !steps.is_empty() {
            app.run_steps(steps.clone(), crate::panel::then(NAME, Done(steps)));
        }
    }

    /// The VLANs a server serves: `untagged`, the 802.1Q range, or QinQ
    /// `S 100-103 × C any` with a selo (G4.3l).
    fn vlans_cell(r: &Value, single: String) -> String {
        if text(r, "vlan_mode") == "stacked" {
            let tpid = text(r, "outer_tpid");
            let label = format!("S {} × C {}", text(r, "outer_vlan_range"), text(r, "inner_vlan_range"));
            let chips: Vec<(&str, Kind)> = if tpid == "0x8100" { vec![("QinQ 0x8100", Kind::Amber)] } else { vec![("QinQ", Kind::Blue)] };
            return chip::cell(&label, &chips);
        }
        if single.is_empty() { "untagged".into() } else { single }
    }

    /// `new_session_rate`: the fixed rate, off, or `auto` with the rate now
    /// and why (amber when the RADIUS server is what holds it down).
    fn admission_cell(r: &Value) -> String {
        match text(r, "new_session_rate").as_str() {
            "auto" => {
                let reason = text(r, "admission_reason");
                let now = n(r, "admission_rate");
                let label = if now > 0 { format!("auto {now}/s") } else { "auto".into() };
                let kind = if reason.starts_with("RADIUS") { Kind::Amber } else { Kind::Neutral };
                if reason.is_empty() {
                    label
                } else {
                    chip::cell(&label, &[(reason.as_str(), kind)])
                }
            }
            "0" => "off".into(),
            rate => format!("{rate}/s"),
        }
    }

    pub(crate) fn secret_row(r: &Value) -> Row {
        let disabled = flag(r, "disabled");
        let up = flag(r, "active");
        let profile = text(r, "profile");
        let limits = match (n(r, "limit_bytes_in"), n(r, "limit_bytes_out")) {
            (0, 0) => String::new(),
            (i, o) => format!("{}/{}", if i > 0 { bytes(i) } else { "–".into() }, if o > 0 { bytes(o) } else { "–".into() }),
        };
        let state = if disabled {
            chip::cell("", &[("disabled", Kind::Neutral)])
        } else if up {
            chip::cell("", &[("online", Kind::Green)])
        } else {
            chip::cell("", &[("offline", Kind::Neutral)])
        };
        Row {
            key: text(r, "id"),
            cells: vec![
                text(r, "name"),
                text(r, "service"),
                chip::cell("", &[(profile.as_str(), Kind::Hashed(chip::name_hue(&profile)))]),
                text(r, "remote_address"),
                text(r, "routes").replace(',', ", "),
                text(r, "caller_id"),
                limits,
                state,
                text(r, "comment"),
            ],
            dimmed: disabled,
            section: false,
            tint: None,
        }
    }

    pub(crate) fn profile_row(r: &Value) -> Row {
        let name = text(r, "name");
        let mut chips: Vec<(&str, Kind)> = Vec::new();
        if flag(r, "builtin") {
            chips.push(("built-in", Kind::Neutral));
        }
        let dns: Vec<String> = r
            .get("dns_server")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).map(str::to_owned).collect())
            .unwrap_or_default();
        let list = text(r, "address_list");
        Row {
            key: text(r, "id"),
            cells: vec![
                chip::cell(&name, &chips),
                text(r, "local_address"),
                text(r, "remote_address"),
                dns.join(", "),
                rate_chip(&text(r, "rate_limit")),
                if list.is_empty() { String::new() } else { chip::cell("", &[(list.as_str(), Kind::Hashed(chip::name_hue(&list)))]) },
                text(r, "only_one"),
                profile_v6(r),
                n(r, "secrets").to_string(),
                text(r, "comment"),
            ],
            dimmed: false,
            section: false,
            tint: None,
        }
    }

    pub(crate) fn active_row(r: &Value, traffic: Option<&std::collections::VecDeque<(f64, f64)>>) -> Row {
        let name = text(r, "name");
        let badge = format!("{} {name}", icons::IDENTIFICATION_BADGE);
        let mut name_chips = vec![(badge.as_str(), Kind::Blue)];
        if flag(r, "radius") {
            name_chips.push(("R", Kind::Neutral));
        }
        // G4.3l: a QinQ line as `outer/inner` (`120/3044`), coloured by the pair.
        let vlan = match (r.get("vlan").and_then(Value::as_u64), r.get("inner_vlan").and_then(Value::as_u64)) {
            (Some(o), Some(i)) => format!("{o}/{i}"),
            (Some(o), None) => o.to_string(),
            _ => String::new(),
        };
        let service = text(r, "service");
        Row {
            key: text(r, "id"),
            cells: vec![
                chip::cell("", &name_chips),
                // PPPoE and IPoE (G4.3f) side by side: a chip per service.
                // G4.3k: the Service-Name asked for, next to the service.
                chip::cell(&text(r, "service_name"), &[(service.as_str(), Kind::Hashed(chip::name_hue(&service)))]),
                text(r, "caller_id"),
                text(r, "address"),
                text(r, "ipv6_prefix"),
                delegated_cell(r),
                routes_cell(r),
                text(r, "uptime"),
                rate_chip(&text(r, "rate_limit")),
                crate::queues::wait_text(n(r, "queue_us")),
                match n(r, "drops") {
                    0 => String::new(),
                    d => d.to_string(),
                },
                bytes(n(r, "rx_bytes")),
                bytes(n(r, "tx_bytes")),
                traffic.map_or_else(String::new, |t| {
                    let rx: Vec<Option<f64>> = t.iter().map(|p| Some(p.0)).collect();
                    let tx: Vec<Option<f64>> = t.iter().map(|p| Some(p.1)).collect();
                    crate::spark::cell(&rx, &tx)
                }),
                if vlan.is_empty() { String::new() } else { chip::cell("", &[(vlan.as_str(), Kind::Hashed(chip::name_hue(&vlan)))]) },
                text(r, "circuit_id"),
            ],
            dimmed: false,
            section: false,
            tint: None,
        }
    }

    pub(crate) fn history_row(i: usize, r: &Value) -> Row {
        let event = text(r, "event");
        let stage = text(r, "stage");
        let reason = text(r, "reason");
        let when = r.get("at").and_then(Value::as_u64).map(|t| crate::system_log::short_time(t, 0)).unwrap_or_default();
        Row {
            key: format!("{i}"),
            cells: vec![
                when,
                text(r, "name"),
                text(r, "caller_id"),
                chip::cell("", &[(event.as_str(), event_kind(&event))]),
                if stage.is_empty() || event == "up" { String::new() } else { chip::cell("", &[(stage.as_str(), stage_kind(&stage, event == "failed"))]) },
                if reason.is_empty() { String::new() } else { chip::cell("", &[(reason.as_str(), if event == "failed" { Kind::Red } else { Kind::Neutral })]) },
                text(r, "address"),
                if event == "down" { crate::ppp::uptime(n(r, "uptime_secs")) } else { String::new() },
            ],
            dimmed: false,
            section: false,
            tint: None,
        }
    }

    fn values(fields: &[Field], r: &Value) -> BTreeMap<&'static str, String> {
        let yes = |b: bool| if b { "yes" } else { "no" }.to_owned();
        let mut v: BTreeMap<&'static str, String> = BTreeMap::new();
        for f in fields {
            let val = match f.param {
                "password" => String::new(),
                "authentication" | "dns_server" | "dns_server_ipv6" => r
                    .get(f.param)
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(","))
                    .unwrap_or_default(),
                p if f.input == Input::Check => yes(flag(r, p)),
                p => text(r, p),
            };
            v.insert(f.param, val);
        }
        v
    }

    fn rows_and(&self, tab: Tab) -> (&'static str, &'static Cmds, &'static Spec, &Vec<Value>) {
        match tab {
            Tab::Secrets => (SECRETS, &SECRET_CMDS, &SECRET_SPEC, &self.secrets),
            Tab::Profiles => (PROFILES, &PROFILE_CMDS, &PROFILE_SPEC, &self.profiles),
            _ => (SERVERS, &SERVER_CMDS, &SERVER_SPEC, &self.servers),
        }
    }

    /// The Servers, Secrets and Profiles tabs: one list pattern.
    fn list_tab(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, l: Lang, tab: Tab) {
        let (salt, cmds, spec, data) = self.rows_and(tab);
        let data = data.clone();
        let rows: Vec<Row> = data
            .iter()
            .map(|r| match tab {
                Tab::Secrets => Self::secret_row(r),
                Tab::Profiles => Self::profile_row(r),
                _ => Self::server_row(r),
            })
            .collect();
        let columns: &[table::Column] = match tab {
            Tab::Secrets => &SECRET_COLUMNS,
            Tab::Profiles => &PROFILE_COLUMNS,
            _ => &SERVER_COLUMNS,
        };
        let state = match tab {
            Tab::Secrets => &mut self.secrets_table,
            Tab::Profiles => &mut self.profiles_table,
            _ => &mut self.servers_table,
        };
        let sel = state.selection(&rows);
        let fixed = if tab == Tab::Profiles { "a built-in profile stays" } else { "" };
        let picked: Vec<Item> = sel
            .as_slice()
            .iter()
            .filter_map(|k| data.iter().find(|t| text(t, "id") == *k))
            .map(|t| {
                let mut i = Item::of(t, "id", "");
                if flag(t, "builtin") {
                    i.fixed = Some(fixed.to_owned());
                }
                i
            })
            .collect();
        let tools = Tools::new(&app.can(), cmds, &picked);
        let mut act = None;
        let mut help = self.help.take();
        ui.horizontal(|ui| {
            act = list::toolbar(ui, salt, &tools, &sel, l);
            info(ui, &mut help, l, spec.help, spec.edit_title);
            if tab == Tab::Secrets {
                if table::action(ui, &format!("{}…", tr_in("ppp_import", l, "Import from MikroTik")), app.can().check("ppp.secret.import")) {
                    match &mut self.import {
                        Some(d) => d.status.bring_to_front(),
                        None => {
                            app.next_dialog = app.next_dialog.wrapping_add(1);
                            self.import = Some(crate::ppp_import::ImportDialog::new(app.next_dialog));
                        }
                    }
                }
                let c = &self.secret_count;
                ui.weak(format!(
                    "{} {} · {} {}",
                    n(c, "total"),
                    tr_in(SCOPE, l, "secrets"),
                    n(c, "active"),
                    tr_in(SCOPE, l, "online")
                ));
            }
            table::find_field(ui, salt, state);
        });
        let mut footer_h = ui.spacing().interact_size.y + 6.0;
        if tab == Tab::Servers {
            // G4.3k: the Service-Name table of the selected server (else the
            // first one) goes under the list.
            let pick = sel.as_slice().first().cloned().or_else(|| data.first().map(|r| text(r, "id")));
            if pick != self.svc_server {
                self.services.clear();
                app.cache.refreshed_at = None;
            }
            self.svc_server = pick;
            if self.svc_server.is_some() {
                footer_h += SERVICES_H;
            }
        }
        let state = match tab {
            Tab::Secrets => &mut self.secrets_table,
            Tab::Profiles => &mut self.profiles_table,
            _ => &mut self.servers_table,
        };
        let new_label = tr_in(SCOPE, l, spec.new_title);
        let out = table::show(ui, salt, footer_h, state, columns, &rows, |ui, menu| match menu {
            Menu::Rows(sel) => {
                if let Some(a) = list::row_menu(ui, &tools, sel, true, l) {
                    act = Some(a);
                }
            }
            Menu::Empty => {
                if table::action(ui, &format!("{new_label}…"), tools.add.clone()) {
                    act = Some(Act::Add);
                }
            }
        });
        if let Some(key) = out.help {
            let title = columns.iter().find(|c| c.help == key).map_or("", |c| c.title);
            help = Some(HelpView::new(key, tr_in(SCOPE, l, title)));
        }
        self.help = help;
        if act.is_none() {
            act = list::from_shortcut(out.shortcut, &tools, &sel);
        }
        if let Some(k) = out.opened.or(out.comment) {
            act = Some(Act::Edit(k));
        }
        let v = ui.visuals().clone();
        match tab {
            Tab::Servers => list::footer(
                ui,
                &[
                    (data.len(), "servers", chip::neutral_tone(&v)),
                    (data.iter().map(|r| n(r, "sessions") as usize).sum(), "sessions", chip::GREEN.tone(&v)),
                    (list::count(&data, "disabled", "true"), "disabled", chip::neutral_tone(&v)),
                ],
                l,
            ),
            Tab::Secrets => list::footer(
                ui,
                &[
                    (data.len(), "shown", chip::neutral_tone(&v)),
                    (data.iter().filter(|r| flag(r, "active")).count(), "online", chip::GREEN.tone(&v)),
                    (data.iter().filter(|r| flag(r, "disabled")).count(), "disabled", chip::neutral_tone(&v)),
                ],
                l,
            ),
            _ => list::footer(ui, &[(data.len(), "profiles", chip::neutral_tone(&v))], l),
        }
        if let Some(a) = act {
            self.act(app, tab, a, &rows, ui);
        }
        if tab == Tab::Servers {
            self.services_section(app, ui, l);
        }
    }

    pub(crate) fn act(&mut self, app: &mut CoreRouterUi, tab: Tab, a: Act, rows: &[Row], ui: &Ui) {
        let (_, cmds, spec, data) = self.rows_and(tab);
        let data = data.clone();
        let step = |command: &str, params: Value| json!({"command": command, "params": params});
        let set = cmds.set.unwrap_or(cmds.add);
        let steps: Vec<Value> = match a {
            Act::Add => {
                let mut v = BTreeMap::new();
                match tab {
                    Tab::Secrets => {
                        v.insert("service", "pppoe".to_owned());
                        v.insert("profile", "default".to_owned());
                    }
                    Tab::Profiles => {
                        v.insert("only_one", "default".to_owned());
                        v.insert("change_tcp_mss", "default".to_owned());
                        v.insert("use_ipv6", "default".to_owned());
                        v.insert("download_mode", "shaper".to_owned());
                    }
                    _ => {
                        for k in ["one_session_per_host", "accept_untagged", "ac_cookie"] {
                            v.insert(k, "yes".to_owned());
                        }
                        v.insert("vlan_mode", "single".to_owned());
                        v.insert("outer_tpid", "0x88a8".to_owned());
                        v.insert("default_profile", "default".to_owned());
                    }
                }
                self.modal = Some((tab, Modal::open(app, None, v)));
                return;
            }
            Act::Edit(k) => {
                if let Some((_, m)) = &mut self.modal {
                    m.status.bring_to_front();
                } else if let Some(r) = data.iter().find(|t| text(t, "id") == k) {
                    let name = text(r, "name");
                    self.modal = Some((tab, Modal::open(app, Some((k, name)), Self::values(spec.fields, r))));
                }
                return;
            }
            Act::Comment(ids) => {
                if let Some(k) = ids.into_iter().next() {
                    self.act(app, tab, Act::Edit(k), rows, ui);
                }
                return;
            }
            Act::Remove(ids) => ids.iter().map(|id| step(cmds.remove, json!({"id": id}))).collect(),
            Act::Enable(ids) => ids.iter().map(|id| step(set, json!({"id": id, "disabled": false}))).collect(),
            Act::Disable(ids) => ids.iter().map(|id| step(set, json!({"id": id, "disabled": true}))).collect(),
            Act::Copy(ids) => {
                let picked: Vec<&Row> = rows.iter().filter(|r| ids.contains(&r.key)).collect();
                ui.ctx().copy_text(list::copy_rows(&picked));
                return;
            }
            Act::CopyAs(ids, syntax) => {
                let picked: Vec<&Value> = data.iter().filter(|t| ids.contains(&text(t, "id"))).collect();
                ui.ctx().copy_text(list::copy_commands(app, cmds.add, &picked, syntax));
                return;
            }
        };
        if !steps.is_empty() {
            app.run_steps(steps.clone(), crate::panel::then(NAME, Done(steps)));
        }
    }

    fn interface_tab(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, l: Lang) {
        let m = self.monitor.clone();
        let mut help = self.help.take();
        ui.horizontal_wrapped(|ui| {
            label(ui, &mut help, l, "monitor.running", "Service");
            let v = ui.visuals().clone();
            if flag(&m, "running") {
                chip::chip(ui, tr_in(SCOPE, l, "running"), chip::GREEN.tone(&v));
            } else {
                chip::chip(ui, tr_in(SCOPE, l, "not running"), chip::neutral_tone(&v));
            }
            label(ui, &mut help, l, "monitor.dataplane", "Data Plane");
            if flag(&m, "dataplane") {
                chip::chip(ui, "XDP", chip::GREEN.tone(&v));
            } else {
                chip::chip(ui, tr_in(SCOPE, l, "slow path"), chip::AMBER.tone(&v));
            }
            let err = text(&m, "last_error");
            if !err.is_empty() {
                ui.colored_label(v.error_fg_color, err);
            }
        });
        ui.separator();
        Grid::new("ppp-monitor").num_columns(4).spacing([24.0, 6.0]).show(ui, |ui| {
            for (row, items) in [
                ("Logins", [("sessions", "Sessions"), ("auth_accept", "Accepted"), ("auth_reject", "Rejected")]),
                ("Discovery", [("padi", "PADI"), ("pado", "PADO"), ("padr", "PADR")]),
                ("Discovery", [("pads", "PADS"), ("padt_rx", "PADT in"), ("padt_tx", "PADT out")]),
                ("IPv6", [("ipv6_sessions", "IPv6 Sessions"), ("delegated", "Delegated"), ("ipv6_dropped", "IPv6 Dropped")]),
            ] {
                ui.strong(tr_in(SCOPE, l, row));
                for (k, name) in items {
                    ui.horizontal(|ui| {
                        label(ui, &mut help, l, &format!("monitor.{k}"), name);
                        ui.monospace(n(&m, k).to_string());
                    });
                }
                ui.end_row();
            }
            ui.strong(tr_in(SCOPE, l, "Protection"));
            ui.horizontal(|ui| {
                label(ui, &mut help, l, "monitor.throttled", "Throttled");
                let t = n(&m, "throttled");
                let v = ui.visuals().clone();
                chip::chip(ui, &t.to_string(), if t > 0 { chip::AMBER.tone(&v) } else { chip::neutral_tone(&v) });
            });
            ui.end_row();
        });
        self.help = help;
        ui.separator();
        if self.servers.is_empty() {
            ui.weak(tr_in(SCOPE, l, "No PPPoE server yet: PPPoE Servers › +"));
            if table::action(ui, tr_in(SCOPE, l, "New PPPoE Server…"), app.can().check(SERVER_CMDS.add)) {
                self.tab = Tab::Servers;
                self.act(app, Tab::Servers, Act::Add, &[], ui);
            }
        } else {
            for r in self.servers.clone() {
                ui.horizontal(|ui| {
                    let v = ui.visuals().clone();
                    let iface = text(&r, "interface");
                    ui.label(text(&r, "name"));
                    chip::chip(ui, &iface, chip::palette_tone(&v, chip::name_hue(&iface)));
                    chip::chip(ui, &format!("{} {}", n(&r, "sessions"), tr_in(SCOPE, l, "sessions")), chip::GREEN.tone(&v));
                    if flag(&r, "disabled") {
                        chip::chip(ui, tr_in(SCOPE, l, "disabled"), chip::neutral_tone(&v));
                    }
                    for w in r.get("warnings").and_then(Value::as_array).into_iter().flatten() {
                        ui.colored_label(v.warn_fg_color, w.as_str().unwrap_or(""));
                    }
                });
            }
        }
    }

    fn active_tab(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, l: Lang) {
        let data = rows_of(&self.active);
        let rows: Vec<Row> = data.iter().map(|r| Self::active_row(r, self.traffic.get(&text(r, "id")))).collect();
        if let Some(login) = self.reveal.clone()
            && let Some(r) = data.iter().find(|r| text(r, "name") == login)
        {
            self.active_table.reveal(&text(r, "id"));
            self.reveal = None;
        }
        let sel = self.active_table.selection(&rows);
        let picked: Vec<Value> = sel.as_slice().iter().filter_map(|k| data.iter().find(|r| text(r, "id") == *k).cloned()).collect();
        let can = app.can();
        let none = |what: &str| if picked.is_empty() { Err(format!("Select {what} first")) } else { Ok(()) };
        let mut disconnect = false;
        let mut torch = false;
        let mut why = false;
        let mut help = self.help.take();
        ui.horizontal(|ui| {
            disconnect = table::tool(ui, ACTIVE, Icon::Remove, tr_in(SCOPE, l, "Disconnect"), can.and("ppp.active.remove", none("a session")))
                .clicked();
            torch = table::action(ui, tr_in(SCOPE, l, "Torch"), can.and("tool.torch.start", if picked.len() == 1 { Ok(()) } else { Err("Select one session".into()) }));
            why = table::action(ui, tr_in(SCOPE, l, "Why?"), can.check("ppp.why"));
            info(ui, &mut help, l, "ppp.why", "Why?");
            info(ui, &mut help, l, "ppp.active", "Active Connections");
            if !flag(&self.active, "running") {
                ui.weak(tr_in(SCOPE, l, "the pppoe service is not running (daemon only)"));
            }
            table::find_field(ui, ACTIVE, &mut self.active_table);
        });
        let footer_h = ui.spacing().interact_size.y + 6.0;
        let out = table::show(ui, ACTIVE, footer_h, &mut self.active_table, &ACTIVE_COLUMNS, &rows, |ui, menu| {
            if let Menu::Rows(_) = menu {
                if table::action(ui, tr_in(SCOPE, l, "Disconnect"), can.check("ppp.active.remove")) {
                    disconnect = true;
                }
                if table::action(ui, tr_in(SCOPE, l, "Why?"), can.check("ppp.why")) {
                    why = true;
                }
            }
        });
        if let Some(key) = out.help {
            let title = ACTIVE_COLUMNS.iter().find(|c| c.help == key).map_or("", |c| c.title);
            help = Some(HelpView::new(key, tr_in(SCOPE, l, title)));
        }
        self.help = help;
        if matches!(out.shortcut, Some(table::Shortcut::Remove)) && !picked.is_empty() {
            disconnect = true;
        }
        let v = ui.visuals().clone();
        let total = n(&self.active, "total") as usize;
        list::footer(
            ui,
            &[
                (total, "sessions", chip::GREEN.tone(&v)),
                (data.iter().filter(|r| flag(r, "radius")).count(), "RADIUS", chip::BLUE.tone(&v)),
            ],
            l,
        );
        if disconnect {
            let ids: Vec<Value> = picked.iter().map(|r| json!(text(r, "id"))).collect();
            let steps = vec![json!({"command": "ppp.active.remove", "params": {"id": ids}})];
            app.run_steps(steps.clone(), crate::panel::then(NAME, Done(steps)));
        }
        if torch && let Some(r) = picked.first() {
            let iface = text(r, "interface");
            let addr = text(r, "address");
            if let Some(t) = app.panel_mut::<crate::torch::TorchPanel>() {
                t.interface = iface;
                t.src = addr;
            }
            if !app.open.insert(Win::Panel(crate::torch::WIN)) {
                app.floats.raise(crate::win_id(Win::Panel(crate::torch::WIN)));
            }
        }
        if why {
            let first = picked.first();
            self.open_why(app, first.map(|r| text(r, "name")).unwrap_or_default(), String::new());
        }
        if let Some(k) = out.opened
            && let Some(r) = data.iter().find(|r| text(r, "id") == k)
        {
            self.open_why(app, text(r, "name"), String::new());
        }
    }

    fn history_tab(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, l: Lang) {
        let rows: Vec<Row> = self.history.iter().enumerate().map(|(i, r)| Self::history_row(i, r)).collect();
        let mut help = self.help.take();
        ui.horizontal(|ui| {
            for (e, name) in [("", "All"), ("failed", "Failed"), ("down", "Ended"), ("up", "Up")] {
                if list::filter_chip(ui, tr_in(SCOPE, l, name), self.event == e) {
                    self.event = e.to_owned();
                    app.cache.refreshed_at = None;
                }
            }
            info(ui, &mut help, l, "ppp.history", "History");
            if table::action(ui, tr_in(SCOPE, l, "Why?"), app.can().check("ppp.why")) {
                let picked = self.history_table.selection(&rows);
                let r = picked.first().and_then(|k| k.parse::<usize>().ok()).and_then(|i| self.history.get(i));
                let (name, mac) = r.map(|r| (text(r, "name"), text(r, "caller_id"))).unwrap_or_default();
                self.open_why(app, name, if mac.is_empty() { String::new() } else { mac });
            }
            table::find_field(ui, HISTORY, &mut self.history_table);
        });
        let out = table::show(ui, HISTORY, 0.0, &mut self.history_table, &HISTORY_COLUMNS, &rows, |_, _| {});
        if let Some(key) = out.help {
            let title = HISTORY_COLUMNS.iter().find(|c| c.help == key).map_or("", |c| c.title);
            help = Some(HelpView::new(key, tr_in(SCOPE, l, title)));
        }
        self.help = help;
        // The hint of the row under the pointer, in Portuguese.
        if let Some(k) = out.opened
            && let Some(r) = k.parse::<usize>().ok().and_then(|i| self.history.get(i)).cloned()
        {
            self.open_why(app, text(&r, "name"), String::new());
        }
        if rows.is_empty() {
            ui.weak(tr_in(SCOPE, l, "Nothing yet: logins, failures and ends show here"));
        }
    }

    fn aaa_tab(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, l: Lang) {
        let mut help = self.help.take();
        Grid::new("ppp-aaa").num_columns(2).spacing([16.0, 6.0]).show(ui, |ui| {
            label(ui, &mut help, l, "aaa.use_radius", "Use RADIUS");
            ui.checkbox(&mut self.form.use_radius, tr_in(SCOPE, l, "ask /radius (service=ppp) for users not in Secrets"));
            ui.end_row();
            label(ui, &mut help, l, "aaa.accounting", "Accounting");
            ui.checkbox(&mut self.form.accounting, "");
            ui.end_row();
            label(ui, &mut help, l, "aaa.interim_update", "Interim Update (s)");
            ui.horizontal(|ui| {
                ui.add(TextEdit::singleline(&mut self.form.interim_update).desired_width(70.0));
                ui.weak(tr_in(SCOPE, l, "0: only Acct-Interim-Interval from the server"));
            });
            ui.end_row();
            label(ui, &mut help, l, "aaa.interim_jitter", "Interim Jitter (%)");
            ui.add(TextEdit::singleline(&mut self.form.interim_jitter).desired_width(70.0));
            ui.end_row();
            label(ui, &mut help, l, "aaa.use_circuit_id_in_nas_port_id", "Use Circuit ID in NAS-Port-Id");
            ui.checkbox(&mut self.form.use_circuit_id_in_nas_port_id, "");
            ui.end_row();
            label(ui, &mut help, l, "aaa.enable_ipv6_accounting", "IPv6 Accounting");
            ui.checkbox(&mut self.form.enable_ipv6_accounting, "");
            ui.end_row();
            label(ui, &mut help, l, "aaa.radius_servers", "RADIUS Servers");
            ui.monospace(n(&self.aaa, "radius_servers").to_string());
            ui.end_row();
        });
        self.help = help;
        let dirty = self.form.set_params(&self.base).is_some();
        let mut apply = false;
        let mut revert = false;
        ui.horizontal(|ui| {
            let ok = if self.waiting > 0 {
                Err(tr_in(SCOPE, l, "Saving…").to_owned())
            } else if !dirty {
                Err(tr_in(SCOPE, l, "Nothing changed").to_owned())
            } else {
                app.can().check(AAA_SET)
            };
            apply = table::action(ui, tr_in(SCOPE, l, "Apply"), ok);
            revert = table::action(ui, tr_in(SCOPE, l, "Revert"), if dirty { Ok(()) } else { Err(tr_in(SCOPE, l, "Nothing changed").to_owned()) });
            if dirty {
                ui.weak(format!("{} {}", dialog::UNSAVED, tr_in(SCOPE, l, "not applied")));
            }
        });
        if let Some(e) = &self.error {
            ui.colored_label(ui.visuals().error_fg_color, e.as_str());
        }
        if apply && let Some(p) = self.form.set_params(&self.base) {
            self.waiting += 1;
            app.run_then(AAA_SET, p, crate::panel::then(NAME, Saved(self.form.clone())));
        }
        if revert {
            self.form = self.base.clone();
            self.error = None;
        }
    }

    fn radius_tab(&mut self, app: &mut CoreRouterUi, ui: &mut Ui, l: Lang) {
        let mut help = self.help.take();
        ui.horizontal(|ui| {
            ui.label(tr_in(SCOPE, l, "The RADIUS servers PPP asks are in their own window (RouterOS: /radius)."));
            info(ui, &mut help, l, "ppp.radius", "RADIUS");
        });
        self.help = help;
        if table::action(ui, tr_in(SCOPE, l, "Open RADIUS"), Ok(())) && !app.open.insert(Win::Panel(crate::radius::WIN)) {
            app.floats.raise(crate::win_id(Win::Panel(crate::radius::WIN)));
        }
    }

    /// Show Active Connections with `login` selected (the identity chip).
    pub(crate) fn reveal_login(&mut self, login: &str) {
        self.tab = Tab::Active;
        self.reveal = Some(login.to_owned());
    }

    pub(crate) fn open_why(&mut self, app: &mut CoreRouterUi, name: String, mac: String) {
        if let Some(w) = &mut self.why {
            w.name = name;
            w.mac = mac;
            w.asked = None;
            w.answer = None;
            w.status.bring_to_front();
        } else {
            app.next_dialog = app.next_dialog.wrapping_add(1);
            self.why = Some(WhyDialog { id: app.next_dialog, name, mac, asked: None, answer: None, status: Status::default() });
        }
        if let Some(w) = &mut self.why
            && (!w.name.trim().is_empty() || !w.mac.trim().is_empty())
        {
            w.asked = Some(why_params(&w.name, &w.mac));
        }
        app.cache.refreshed_at = None;
    }

    fn why_dialog(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, area: egui::Rect) {
        let Some(mut w) = self.why.take() else {
            return;
        };
        let l = app.lang.labels;
        let wid = dialog_id(w.id);
        let head = Head { id: wid, title: tr_in(SCOPE, l, "Why?"), dirty: false, pos: cascade(area, w.id), parent: Some(crate::win_id(Win::Panel(WIN))) };
        let can = app.can().check("ppp.why");
        let mut help = self.help.take();
        let pressed = dialog::show(&mut app.floats, ctx, area, head, &mut w.status, |ui, f| {
            let mut pressed = None;
            Grid::new("ppp-why").num_columns(2).spacing([12.0, 6.0]).show(ui, |ui| {
                label(ui, &mut help, l, "why.name", "User");
                ui.add(TextEdit::singleline(&mut w.name).id(dialog::field_id(f.window(), "name")).desired_width(220.0));
                ui.end_row();
                label(ui, &mut help, l, "why.mac", "or MAC");
                ui.add(TextEdit::singleline(&mut w.mac).id(dialog::field_id(f.window(), "mac")).hint_text("AA:BB:CC:DD:EE:FF").desired_width(220.0));
                ui.end_row();
            });
            if table::action(ui, tr_in(SCOPE, l, "Find"), can.clone()) {
                pressed = Some(WhyButton::Find);
            }
            if let Some(a) = &w.answer {
                ui.separator();
                why_answer(ui, l, a, &mut help);
            }
            Footer { buttons: Buttons::View, ok: Ok(()), extra: Vec::new(), pressed }
        });
        self.help = help;
        match pressed {
            Some(Press::Cancel) => {
                app.floats.forget(wid);
                return;
            }
            Some(Press::Other(WhyButton::Find)) => {
                w.asked = Some(why_params(&w.name, &w.mac));
                w.answer = None;
                app.cache.refreshed_at = None;
            }
            _ => {}
        }
        self.why = Some(w);
    }

    fn drops_dialog(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, area: egui::Rect) {
        let Some(mut d) = self.drops.take() else {
            return;
        };
        let l = app.lang.labels;
        let wid = dialog_id(d.id);
        let head = Head { id: wid, title: tr_in(SCOPE, l, "Active sessions will drop"), dirty: false, pos: cascade(area, d.id), parent: Some(crate::win_id(Win::Panel(WIN))) };
        let can = app.can();
        let message = d.message.clone();
        let pressed = dialog::show(&mut app.floats, ctx, area, head, &mut d.status, |ui, _| {
            ui.colored_label(ui.visuals().warn_fg_color, message.as_str());
            ui.label(tr_in(SCOPE, l, "The subscribers reconnect on their own (PADT, then their CPE dials again). In Safe Mode the change is undone if you lose the router."));
            let mut pressed = None;
            ui.horizontal(|ui| {
                if table::action(ui, tr_in(SCOPE, l, "Apply anyway"), Ok(())) {
                    pressed = Some(DropsButton::Force);
                }
                if table::action(ui, tr_in(SCOPE, l, "Enter Safe Mode"), can.check("config.safe-mode.enter")) {
                    pressed = Some(DropsButton::SafeMode);
                }
            });
            Footer { buttons: Buttons::View, ok: Ok(()), extra: Vec::new(), pressed }
        });
        match pressed {
            Some(Press::Cancel | Press::Ok) => {
                app.floats.forget(wid);
                return;
            }
            Some(Press::Other(DropsButton::Force)) => {
                let steps: Vec<Value> = d
                    .steps
                    .iter()
                    .map(|s| {
                        let mut s = s.clone();
                        if let Some(p) = s.get_mut("params").and_then(Value::as_object_mut) {
                            p.insert("force".into(), Value::Bool(true));
                        }
                        s
                    })
                    .collect();
                app.run_steps(steps.clone(), crate::panel::then(NAME, Done(steps)));
                app.floats.forget(wid);
                return;
            }
            Some(Press::Other(DropsButton::SafeMode)) => {
                app.run("config.safe-mode.enter", json!({}));
            }
            _ => {}
        }
        self.drops = Some(d);
    }
}

fn why_params(name: &str, mac: &str) -> Value {
    let mut p = Map::new();
    if !name.trim().is_empty() {
        p.insert("name".into(), json!(name.trim()));
    }
    if !mac.trim().is_empty() {
        p.insert("mac".into(), json!(mac.trim()));
    }
    Value::Object(p)
}

/// The answer of `ppp.why`: the stages as a row of chips, the last end.
fn why_answer(ui: &mut Ui, l: Lang, a: &Value, help: &mut Option<HelpView>) {
    let attempts: BTreeMap<String, u64> = a
        .get("attempts")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|x| (text(x, "stage"), n(x, "count")))
        .collect();
    let last = a.get("last").cloned().unwrap_or(Value::Null);
    let failed = text(&last, "event") == "failed";
    let last_stage = text(a, "last_stage");
    let active = text(a, "active");
    // An IPoE subscriber (G4.3f) goes DHCP > Auth > Up.
    let ipoe = attempts.contains_key("dhcp") || last_stage == "dhcp";
    let stages: &[(&str, &str)] = if ipoe {
        &[("dhcp", "DHCP"), ("auth", "Auth"), ("up", "Up")]
    } else {
        &[("padi", "PADI"), ("padr", "PADR"), ("lcp", "LCP"), ("auth", "Auth"), ("ncp", "NCP"), ("up", "Up")]
    };
    ui.horizontal_wrapped(|ui| {
        label(ui, help, l, "why.stage", "Stages");
        let v = ui.visuals().clone();
        for (i, (st, name)) in stages.iter().copied().enumerate() {
            if i > 0 {
                // The GUI font has no arrow glyph.
                ui.weak(">");
            }
            let count = attempts.get(st).copied().unwrap_or(0);
            let tone = if st == last_stage && failed {
                chip::RED.tone(&v)
            } else if count > 0 {
                stage_kind(st, false).tone(&v)
            } else {
                chip::neutral_tone(&v)
            };
            chip::chip(ui, &format!("{name} {count}"), tone);
        }
    });
    if !active.is_empty() {
        ui.horizontal(|ui| {
            chip::chip(ui, tr_in(SCOPE, l, "connected now"), chip::GREEN.tone(ui.visuals()));
            ui.monospace(active);
        });
    }
    why_routes(ui, l, a, help);
    if last.is_null() {
        if attempts.is_empty() {
            ui.weak(tr_in(SCOPE, l, "Nothing seen from this user or MAC yet: is the CPE on this access network and dialing PPPoE (or asking DHCP, for IPoE)?"));
        }
        return;
    }
    ui.separator();
    ui.horizontal_wrapped(|ui| {
        let ev = text(&last, "event");
        chip::chip(ui, &ev, event_kind(&ev).tone(ui.visuals()));
        let reason = text(&last, "reason");
        if !reason.is_empty() {
            chip::chip(ui, &reason, if failed { chip::RED.tone(ui.visuals()) } else { chip::neutral_tone(ui.visuals()) });
        }
        if let Some(at) = last.get("at").and_then(Value::as_u64) {
            ui.weak(crate::system_log::short_time(at, 0));
        }
    });
    let hint = text(&last, "hint");
    if !hint.is_empty() {
        ui.label(hint);
    }
    let reply = text(&last, "reply_message");
    if !reply.is_empty() {
        ui.horizontal(|ui| {
            label(ui, help, l, "why.reply_message", "Reply-Message");
            ui.monospace(reply);
        });
    }
}

/// G4.3cd: the routes of the session up (block, origin chip) and the ones
/// refused, each with the reason in Portuguese (from the service).
fn why_routes(ui: &mut Ui, l: Lang, a: &Value, help: &mut Option<HelpView>) {
    let routes = a.get("routes").and_then(Value::as_array).cloned().unwrap_or_default();
    let refused = a.get("refused_routes").and_then(Value::as_array).cloned().unwrap_or_default();
    if routes.is_empty() && refused.is_empty() {
        return;
    }
    ui.horizontal_wrapped(|ui| {
        label(ui, help, l, "why.routes", "Routes");
        let v = ui.visuals().clone();
        for x in &routes {
            let route = text(x, "route");
            let origin = text(x, "origin");
            chip::chip(ui, &route, chip::neutral_tone(&v));
            chip::chip(ui, origin_label(&origin), origin_kind(&origin).tone(&v));
        }
    });
    for why in refused.iter().filter_map(Value::as_str) {
        ui.horizontal_wrapped(|ui| {
            chip::chip(ui, tr_in(SCOPE, l, "refused"), chip::RED.tone(ui.visuals()));
            ui.label(why);
        });
    }
}

/// `1h2m3s`.
pub(crate) fn uptime(secs: u64) -> String {
    let (d, h, m, s) = (secs / 86_400, secs / 3600 % 24, secs / 60 % 60, secs % 60);
    let mut out = String::new();
    for (v, u) in [(d, "d"), (h, "h"), (m, "m")] {
        if v > 0 {
            out.push_str(&format!("{v}{u}"));
        }
    }
    if s > 0 || out.is_empty() {
        out.push_str(&format!("{s}s"));
    }
    out
}

impl PanelState for PppPanel {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        let mut q = Vec::new();
        if let Some(p) = self.why.as_ref().and_then(|w| w.asked.clone())
            && app.has_command("ppp.why")
        {
            q.push(Query { key: "why", command: "ppp.why", params: p });
        }
        if !showing(app) || !app.has_command("ppp.profile.list") {
            return q;
        }
        q.push(Query { key: "monitor", command: "interface.pppoe-server.monitor", params: json!({}) });
        match self.tab {
            Tab::Interface | Tab::Servers => {
                q.push(Query { key: "servers", command: "interface.pppoe-server.server.list", params: json!({}) });
                if self.tab == Tab::Servers
                    && let Some(id) = &self.svc_server
                    && app.has_command("interface.pppoe-server.server.service.list")
                {
                    q.push(Query { key: "services", command: "interface.pppoe-server.server.service.list", params: json!({"server": id}) });
                }
            }
            Tab::Secrets => {
                q.push(Query { key: "secrets", command: "ppp.secret.list", params: json!({"limit": PAGE}) });
                q.push(Query { key: "secret-count", command: "ppp.secret.count", params: json!({}) });
                q.push(Query { key: "profiles", command: "ppp.profile.list", params: json!({}) });
            }
            Tab::Profiles => q.push(Query { key: "profiles", command: "ppp.profile.list", params: json!({}) }),
            Tab::Active => q.push(Query { key: "active", command: "ppp.active.list", params: json!({"limit": PAGE}) }),
            Tab::Aaa => q.push(Query { key: "aaa", command: "ppp.aaa.get", params: json!({}) }),
            Tab::Redundancy => {
                if app.has_command("ppp.redundancy.get") {
                    self.redundancy.queries(&mut q);
                }
            }
            Tab::History => {
                let mut p = json!({"limit": 1000});
                if !self.event.is_empty()
                    && let Some(o) = p.as_object_mut()
                {
                    o.insert("event".into(), json!(self.event));
                }
                q.push(Query { key: "history", command: "ppp.history", params: p });
            }
            Tab::Radius => {}
        }
        // The modal's choices.
        if self.modal.as_ref().is_some_and(|(t, _)| *t == Tab::Servers) || self.svc_modal.is_some() {
            q.push(Query { key: "profiles", command: "ppp.profile.list", params: json!({}) });
        }
        if self.modal.as_ref().is_some_and(|(t, _)| *t == Tab::Profiles) {
            q.push(Query { key: "queue-types", command: "queue.type.list", params: json!({}) });
        }
        q
    }

    fn arrived(&mut self, _app: &mut CoreRouterUi, key: &'static str, _: RequestId, value: Value) {
        if key.starts_with("redundancy") {
            self.redundancy.arrived(key, value);
            return;
        }
        match (key, value) {
            ("servers", Value::Array(a)) => self.servers = a,
            ("services", Value::Array(a)) => self.services = a,
            ("secrets", Value::Array(a)) => self.secrets = a,
            ("profiles", Value::Array(a)) => self.profiles = a,
            ("queue-types", Value::Array(a)) => self.queue_types = a,
            ("history", Value::Array(a)) => self.history = a,
            ("secret-count", v) => self.secret_count = v,
            ("active", v) if v.is_object() => {
                let rows = rows_of(&v);
                self.traffic.retain(|id, _| rows.iter().any(|r| text(r, "id") == *id));
                for r in &rows {
                    let t = self.traffic.entry(text(r, "id")).or_default();
                    t.push_back((n(r, "rx_bps") as f64, n(r, "tx_bps") as f64));
                    while t.len() > TRAFFIC_POINTS {
                        t.pop_front();
                    }
                }
                self.active = v;
            }
            ("monitor", v) if v.is_object() => self.monitor = v,
            ("aaa", v) if v.is_object() => {
                let now = AaaForm::of(&v);
                if self.waiting == 0 && self.form == self.base {
                    self.form = now.clone();
                }
                self.base = now;
                self.aaa = v;
            }
            ("why", v) => {
                if let Some(w) = self.why.as_mut() {
                    w.answer = Some(v);
                }
            }
            (list_modal::PREVIEW, v) => {
                if let Some(m) = self.svc_modal.as_mut() {
                    m.arrived(v);
                } else if let Some((_, m)) = self.modal.as_mut() {
                    m.arrived(v);
                }
            }
            _ => {}
        }
    }

    fn window(&mut self, app: &mut CoreRouterUi, _win: &'static str, ui: &mut Ui) {
        let l = app.lang.labels;
        let mut help = self.help.take();
        ui.horizontal_wrapped(|ui| {
            for (t, name, key) in TABS {
                if ui.selectable_value(&mut self.tab, t, tr_in(SCOPE, l, name)).changed() {
                    app.cache.refreshed_at = None;
                }
                if help::info_button(ui, Id::unique(("ppp-tab", key)), tr_in(SCOPE, l, name)).clicked() {
                    help = Some(HelpView::new(format!("ppp.{key}"), tr_in(SCOPE, l, name)));
                }
            }
        });
        self.help = help;
        ui.separator();
        match self.tab {
            Tab::Interface => self.interface_tab(app, ui, l),
            t @ (Tab::Servers | Tab::Secrets | Tab::Profiles) => self.list_tab(app, ui, l, t),
            Tab::Active => self.active_tab(app, ui, l),
            Tab::Aaa => self.aaa_tab(app, ui, l),
            Tab::Redundancy => self.redundancy.ui(app, ui, l),
            Tab::Radius => self.radius_tab(app, ui, l),
            Tab::History => self.history_tab(app, ui, l),
        }
    }

    fn dialogs(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, area: egui::Rect) {
        let interfaces = app.interface_names(None);
        let profiles: Vec<String> = self.profiles.iter().map(|p| text(p, "name")).collect();
        let servers: Vec<String> = self.servers.iter().map(|p| text(p, "name")).collect();
        let queue_types: Vec<String> = self.queue_types.iter().map(|p| text(p, "name")).collect();
        let options = |p: &str| -> Vec<String> {
            match p {
                "interface" => interfaces.clone(),
                "profile" | "default_profile" => {
                    if profiles.is_empty() { vec!["default".into()] } else { profiles.clone() }
                }
                "service" => ["pppoe", "ipoe", "any", "l2tp", "pptp", "sstp", "ovpn"].iter().map(|s| (*s).to_owned()).collect(),
                "only_one" | "change_tcp_mss" => ["default", "yes", "no"].iter().map(|s| (*s).to_owned()).collect(),
                "use_ipv6" => ["default", "yes", "no", "require"].iter().map(|s| (*s).to_owned()).collect(),
                "download_mode" => ["shaper", "policer"].iter().map(|s| (*s).to_owned()).collect(),
                "queue_type" => queue_types.clone(),
                "server" => servers.clone(),
                "vlan_mode" => ["single", "stacked"].iter().map(|s| (*s).to_owned()).collect(),
                "outer_tpid" => ["0x88a8", "0x8100"].iter().map(|s| (*s).to_owned()).collect(),
                "action" => ["terminate", "delay", "drop"].iter().map(|s| (*s).to_owned()).collect(),
                _ => Vec::new(),
            }
        };
        if let Some((tab, m)) = self.modal.as_mut() {
            let spec = match tab {
                Tab::Secrets => &SECRET_SPEC,
                Tab::Profiles => &PROFILE_SPEC,
                _ => &SERVER_SPEC,
            };
            if !m.show(app, ctx, area, spec, &options) {
                self.modal = None;
            }
        }
        if let Some(m) = self.svc_modal.as_mut()
            && !m.show(app, ctx, area, &SERVICE_SPEC, &options)
        {
            self.svc_modal = None;
        }
        self.why_dialog(app, ctx, area);
        self.drops_dialog(app, ctx, area);
        if let Some(d) = self.import.as_mut() {
            let mut help = self.help.take();
            if !crate::ppp_import::show(d, app, ctx, area, WIN, &profiles, &mut help) {
                self.import = None;
            }
            self.help = help;
        }
        self.redundancy.dialogs(app, ctx, area);
        help::modal(ctx, app.lang, &mut self.help);
    }

    fn reply(&mut self, app: &mut CoreRouterUi, then: PanelThen, result: &Result<Value, String>) {
        let Err(then) = self.redundancy.reply(app, then, result) else {
            return;
        };
        let then = match then.downcast::<Saved>() {
            Ok(s) => {
                self.waiting = self.waiting.saturating_sub(1);
                match result {
                    Ok(_) => {
                        self.error = None;
                        self.base = s.0;
                    }
                    Err(e) => self.error = Some(e.clone()),
                }
                app.cache.refreshed_at = None;
                return;
            }
            Err(t) => t,
        };
        let then = match then.downcast::<Done>() {
            Ok(d) => {
                // "drops N active session(s): repeat with force=yes": ask.
                if let Err(e) = result
                    && e.contains("force=yes")
                {
                    app.next_dialog = app.next_dialog.wrapping_add(1);
                    let message = e.split(": repeat with").next().unwrap_or(e).to_owned();
                    self.drops = Some(Drops { id: app.next_dialog, steps: d.0, message, status: Status::default() });
                }
                app.cache.refreshed_at = None;
                return;
            }
            Err(t) => t,
        };
        let then = match then.downcast::<crate::ppp_import::Reply>() {
            Ok(r) => {
                if let Some(d) = self.import.as_mut() {
                    crate::ppp_import::replied(d, &r, result);
                }
                app.cache.refreshed_at = None;
                return;
            }
            Err(t) => t,
        };
        if let Ok(a) = then.downcast::<Applied>() {
            if let Some((_, m)) = self.modal.as_mut().filter(|(_, m)| m.id == a.0)
                && m.replied(app, result)
            {
                self.modal = None;
            }
            if let Some(m) = self.svc_modal.as_mut().filter(|m| m.id == a.0)
                && m.replied(app, result)
            {
                self.svc_modal = None;
            }
        }
        app.cache.refreshed_at = None;
    }

    fn escape(&mut self, _win: &'static str) -> bool {
        match self.tab {
            Tab::Servers => self.services_table.escape() || self.servers_table.escape(),
            Tab::Interface => self.servers_table.escape(),
            Tab::Secrets => self.secrets_table.escape(),
            Tab::Profiles => self.profiles_table.escape(),
            Tab::Active => self.active_table.escape(),
            Tab::History => self.history_table.escape(),
            Tab::Aaa | Tab::Redundancy | Tab::Radius => false,
        }
    }

    fn tables(&self) -> Vec<(&'static str, &TableState)> {
        vec![
            (SERVERS, &self.servers_table),
            (SERVICES, &self.services_table),
            (SECRETS, &self.secrets_table),
            (PROFILES, &self.profiles_table),
            (ACTIVE, &self.active_table),
            (HISTORY, &self.history_table),
        ]
    }

    fn tables_mut(&mut self) -> Vec<(&'static str, &mut TableState)> {
        vec![
            (SERVERS, &mut self.servers_table),
            (SERVICES, &mut self.services_table),
            (SECRETS, &mut self.secrets_table),
            (PROFILES, &mut self.profiles_table),
            (ACTIVE, &mut self.active_table),
            (HISTORY, &mut self.history_table),
        ]
    }
}
