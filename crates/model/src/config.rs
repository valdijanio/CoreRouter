//! The configuration tree. `Config` is plain data: cloning it is how the store
//! snapshots candidate/running and how the engine guard rolls back. The big
//! sections are [`CowArc`]s, so that clone shares them until one side writes
//! (G0.16).

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::bonding::{BondMode, HashPolicy, LacpRate, default_mii_interval};
use crate::cow::CowArc;
use crate::cow_list::CowList;
use crate::dhcp_client::{CheckGateway, DhcpClient};
use crate::dns::Dns;
use crate::firewall::Firewall;
use crate::interface_list::InterfaceLists;
use crate::ipv6::Ipv6;
use crate::logging::Logging;
use crate::metrics::MetricsService;
use crate::neighbor::NeighborDiscovery;
use crate::ntp::NtpClient;
use crate::types::{Asn, Gateway, IfName, ItemId, MacAddr, RoutingTable, VlanId};

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub system: System,
    pub interfaces: CowArc<BTreeMap<IfName, Interface>>,
    /// `/interface list` (G2.1): named groups of interfaces.
    pub interface_lists: InterfaceLists,
    pub ip: CowArc<Ip>,
    /// `/ipv6` (G4.7b): DHCPv6 clients and the Router Advertisement policy.
    pub ipv6: Ipv6,
    /// A shared section (G3.2a): with thousands of BGP connections, a
    /// commit that does not touch routing neither copies nor serializes it.
    pub routing: CowArc<Routing>,
    /// `/radius` (G4.3j): servers, incoming CoA/DM.
    #[serde(skip_serializing_if = "crate::radius::Radius::is_default")]
    pub radius: crate::radius::Radius,
    /// `/ppp` (G4.3): `/ppp aaa` for now.
    #[serde(skip_serializing_if = "crate::ppp::Ppp::is_default")]
    pub ppp: crate::ppp::Ppp,
    /// `/queue` (G4.9): simple queues and queue types.
    #[serde(skip_serializing_if = "crate::queue::Queues::is_default")]
    pub queue: crate::queue::Queues,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct System {
    pub identity: String,
    /// `/system ntp client` (G4.6).
    #[serde(skip_serializing_if = "NtpClient::is_default")]
    pub ntp_client: NtpClient,
    /// `/system logging` (G4.6): rules and remote syslog actions.
    #[serde(skip_serializing_if = "Logging::is_default")]
    pub logging: Logging,
    /// Prometheus `/metrics` as a service (G4.4c).
    #[serde(skip_serializing_if = "MetricsService::is_default")]
    pub metrics: MetricsService,
    /// `system.tuning.*` (G1.26): kernel and hardware settings.
    #[serde(skip_serializing_if = "crate::tuning::Tuning::is_default")]
    pub tuning: crate::tuning::Tuning,
    /// `/system analytics` (G4.4f): export to an external ClickHouse.
    #[serde(skip_serializing_if = "crate::analytics::Analytics::is_default")]
    pub analytics: crate::analytics::Analytics,
    /// `/tool bandwidth-server` (G6.4b): iperf3 tests against the router.
    #[serde(skip_serializing_if = "crate::bandwidth::BandwidthServer::is_default")]
    pub bandwidth_server: crate::bandwidth::BandwidthServer,
    /// `/tool graphing` (G4.5): what the traffic history keeps.
    #[serde(skip_serializing_if = "crate::graphing::Graphing::is_default")]
    pub graphing: crate::graphing::Graphing,
    /// `/ip service www-ssl` and `www` (G1.6o): the GUI in a browser.
    #[serde(skip_serializing_if = "crate::web::WebService::is_default")]
    pub web: crate::web::WebService,
}

impl Default for System {
    fn default() -> Self {
        Self {
            identity: "CoreRouter".into(),
            ntp_client: NtpClient::default(),
            logging: Logging::default(),
            metrics: MetricsService::default(),
            tuning: crate::tuning::Tuning::default(),
            analytics: crate::analytics::Analytics::default(),
            bandwidth_server: crate::bandwidth::BandwidthServer::default(),
            graphing: crate::graphing::Graphing::default(),
            web: crate::web::WebService::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Interface {
    pub name: IfName,
    pub kind: InterfaceKind,
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub mac: Option<MacAddr>,
    #[serde(default)]
    pub comment: String,
    /// Bridge this interface is a port of (Linux `IFLA_MASTER`). A single
    /// field, so a port can never belong to two bridges.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bridge: Option<IfName>,
    /// VRF this interface belongs to (also `IFLA_MASTER` in Linux, so an
    /// interface is a bridge port or a VRF member, never both).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vrf: Option<IfName>,
    /// Bond this port is a slave of (G1.8; `IFLA_MASTER` again, so a slave
    /// is never also a bridge port or a VRF member).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bond: Option<IfName>,
    /// Link settings of a physical port (`interface.ethernet.set`, G1.20).
    #[serde(default, skip_serializing_if = "EthernetSettings::is_empty")]
    pub ethernet: EthernetSettings,
}

/// What `interface.ethernet.set` changed on a port (RouterOS
/// `/interface ethernet set`). Every field is optional: `None` (or a key
/// missing from `offloads`) leaves the driver's own setting alone, so a
/// config without this section changes nothing on the NIC. Taking a value
/// out again puts back what the port had before CoreRouter changed it.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EthernetSettings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_negotiation: Option<bool>,
    /// Forced rate in Mb/s; only with `auto_negotiation: false`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub speed_mbps: Option<u32>,
    /// Forced duplex; only with `auto_negotiation: false`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_duplex: Option<bool>,
    /// Link modes advertised while auto-negotiating, kernel names
    /// (`1000baseT/Full`), sorted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advertise: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rx_flow_control: Option<FlowControl>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_flow_control: Option<FlowControl>,
    /// Offloads by kernel feature name (`rx-gro`): on or off.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub offloads: BTreeMap<String, bool>,
}

impl EthernetSettings {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// Something that renegotiates the link (and drops it for a moment).
    pub fn touches_link(&self, other: &Self) -> bool {
        self.auto_negotiation != other.auto_negotiation
            || self.speed_mbps != other.speed_mbps
            || self.full_duplex != other.full_duplex
            || self.advertise != other.advertise
    }
}

/// RouterOS `rx-flow-control` / `tx-flow-control`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FlowControl {
    Off,
    On,
    /// Resolved with the link partner during auto-negotiation.
    Auto,
}

impl FlowControl {
    pub fn label(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::On => "on",
            Self::Auto => "auto",
        }
    }
}

fn default_mtu() -> u16 {
    1500
}

impl Interface {
    pub fn new(name: IfName, kind: InterfaceKind) -> Self {
        Self {
            name,
            kind,
            mtu: default_mtu(),
            disabled: false,
            mac: None,
            comment: String::new(),
            bridge: None,
            vrf: None,
            bond: None,
            ethernet: EthernetSettings::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum InterfaceKind {
    Ethernet,
    Vlan {
        parent: IfName,
        vlan_id: VlanId,
        /// Outer tag of a QinQ stack: TPID 0x88a8 (IEEE 802.1ad S-tag, the
        /// RouterOS `use-service-tag=yes`) instead of 0x8100 (802.1Q).
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        service_tag: bool,
    },
    Bridge,
    Loopback,
    /// VRF device (Linux `vrf`): the interfaces whose `vrf` names it route
    /// with kernel table `table`, a routing table named like the VRF.
    Vrf {
        table: u32,
    },
    /// Link aggregation (Linux `bond`, G1.8). The slaves are the interfaces
    /// whose `bond` names it.
    Bonding {
        mode: BondMode,
        /// Slave preferred while it is up (active-backup, balance-tlb/alb).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        primary: Option<IfName>,
        #[serde(default)]
        transmit_hash_policy: HashPolicy,
        #[serde(default)]
        lacp_rate: LacpRate,
        /// MII link monitoring period; 0 turns monitoring off.
        #[serde(default = "default_mii_interval")]
        mii_interval_ms: u32,
        /// Up slaves needed before the bond reports carrier.
        #[serde(default)]
        min_links: u32,
    },    /// PPPoE client (G3.9ga, RouterOS type `pppoe-out`): the session's
    /// netdev, its settings in [`crate::pppoe_client`].
    PppoeClient(Box<crate::pppoe_client::PppoeClient>),
}

impl InterfaceKind {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Ethernet => "ether",
            Self::Vlan { .. } => "vlan",
            Self::Bridge => "bridge",
            Self::Loopback => "loopback",
            Self::Vrf { .. } => "vrf",
            Self::Bonding { .. } => "bonding",
            Self::PppoeClient(_) => "pppoe-out",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Ip {
    pub addresses: CowList<AddressEntry>,
    /// Next id handed out by `next_address_id` (never reused, like RouterOS).
    pub next_id: u32,
    /// Static routes (`/ip route`), IPv4 and IPv6 together. Connected routes
    /// are not stored: they are derived from `addresses` (see `route`).
    /// Indexed by next hop for the duplicate check (G0.31d).
    pub routes: crate::routes::Routes,
    /// Next id handed out by `next_route_id`.
    pub next_route_id: u32,
    /// Where neighbor discovery listens and announces (`ip.neighbor.discovery.set`).
    pub neighbor_discovery: NeighborDiscovery,
    /// `/ip firewall` (G2.1): filter, nat, mangle and address lists,
    /// IPv4 and IPv6 together.
    pub firewall: CowArc<Firewall>,
    /// `ip.firewall.xdp` (G2.5a): the filter in the NIC driver.
    #[serde(skip_serializing_if = "crate::xdp::Xdp::is_default")]
    pub xdp: crate::xdp::Xdp,
    /// `/ip dns adlist` (G4.1d): block lists of the LAN forwarder.
    #[serde(skip_serializing_if = "crate::dns_adlist::DnsAdlist::is_empty")]
    pub dns_adlist: crate::dns_adlist::DnsAdlist,
    /// `/ip dns forwarders` (G4.1d): named groups of upstream servers.
    #[serde(skip_serializing_if = "crate::dns_forwarders::DnsForwarders::is_empty")]
    pub dns_forwarders: crate::dns_forwarders::DnsForwarders,
    /// `/ip dhcp-client` (G4.7): at most one per interface.
    pub dhcp_clients: Vec<DhcpClient>,
    /// Next id handed out by `next_dhcp_client_id`.
    pub next_dhcp_client_id: u32,
    /// `/ip dns` (G4.1a): the router's resolver and its cache.
    #[serde(skip_serializing_if = "Dns::is_default")]
    pub dns: Dns,
    /// `/ip dns static` (G4.1b).
    #[serde(skip_serializing_if = "crate::dns_static::DnsStatic::is_empty")]
    pub dns_static: CowArc<crate::dns_static::DnsStatic>,
    /// `/ip dns zone` (G4.1c): authoritative zones and their records.
    #[serde(skip_serializing_if = "crate::dns_zone::DnsZones::is_empty")]
    pub dns_zones: CowArc<crate::dns_zone::DnsZones>,
    /// `/ip dns tsig-key` (G4.1c-3): TSIG keys for RFC 2136 UPDATE.
    #[serde(skip_serializing_if = "crate::dns_tsig::DnsTsig::is_empty")]
    pub dns_tsig: crate::dns_tsig::DnsTsig,
    /// `/ip pool` (G4.2a): address pools of the DHCP server.
    #[serde(skip_serializing_if = "crate::ip_pool::IpPools::is_empty")]
    pub pools: crate::ip_pool::IpPools,
    /// `/ip dhcp-server` (G4.2a): servers, networks, static leases, options.
    #[serde(skip_serializing_if = "crate::dhcp_server::DhcpServers::is_empty")]
    pub dhcp_server: CowArc<crate::dhcp_server::DhcpServers>,
    /// `/ip dhcp-relay` (G4.2b).
    #[serde(skip_serializing_if = "crate::dhcp_relay::DhcpRelays::is_empty")]
    pub dhcp_relays: crate::dhcp_relay::DhcpRelays,
    /// `/ip firewall cgnat` (G2.3): CGNAT pools and 1:1 exceptions.
    #[serde(skip_serializing_if = "crate::cgnat::Cgnat::is_empty")]
    pub cgnat: crate::cgnat::Cgnat,
    /// `/ip firewall fastpath` (G2.4): the flowtable.
    #[serde(skip_serializing_if = "crate::fastpath::FastPath::is_empty")]
    pub fastpath: crate::fastpath::FastPath,
    /// `/ip traffic-flow` (G4.4b): IPFIX / NetFlow v9 export.
    #[serde(skip_serializing_if = "crate::traffic_flow::TrafficFlow::is_default")]
    pub traffic_flow: crate::traffic_flow::TrafficFlow,
    /// `/ip subscriber-notice` (G4.10): block and notice pages.
    #[serde(skip_serializing_if = "crate::subscriber_notice::SubscriberNotices::is_empty")]
    pub subscriber_notice: crate::subscriber_notice::SubscriberNotices,
    /// `/ip arp` (G1.27d): static entries, ARP mode per interface, table sizes.
    #[serde(skip_serializing_if = "crate::arp::Arp::is_empty")]
    pub arp: crate::arp::Arp,
}

impl Ip {
    pub fn next_dhcp_client_id(&mut self) -> ItemId {
        self.next_dhcp_client_id = self.next_dhcp_client_id.saturating_add(1);
        ItemId(self.next_dhcp_client_id)
    }

    pub fn next_address_id(&mut self) -> ItemId {
        self.next_id = self.next_id.saturating_add(1);
        ItemId(self.next_id)
    }

    pub fn next_route_id(&mut self) -> ItemId {
        self.next_route_id = self.next_route_id.saturating_add(1);
        ItemId(self.next_route_id)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddressEntry {
    pub id: ItemId,
    pub address: IpNet,
    pub interface: IfName,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub comment: String,
    /// IPv6 (G4.7b, RouterOS `from-pool`): `address` is a suffix inside the
    /// prefix a DHCPv6 client delegated into this pool (`::1/64` →
    /// `<prefix>::1/64`); see `ipv6::from_pool`. Not installed while the
    /// pool has no prefix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_pool: Option<String>,
}

/// One static route. `distance` is RouterOS' administrative distance
/// (1..=255; connected routes are 0); in the kernel it becomes the metric,
/// so the lowest distance wins there too.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteEntry {
    pub id: ItemId,
    pub dst_address: IpNet,
    pub gateway: Gateway,
    #[serde(default = "default_distance")]
    pub distance: u8,
    #[serde(default)]
    pub routing_table: RoutingTable,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub comment: String,
    /// RouterOS `check-gateway` (G1.27f): while the gateway does not
    /// answer, the route leaves the data plane and the next distance wins.
    #[serde(default, skip_serializing_if = "CheckGateway::is_none")]
    pub check_gateway: CheckGateway,
    /// BFD profile of `check_gateway = bfd` (empty: `default`, G3.6g).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub bfd_profile: String,
}

pub const DEFAULT_DISTANCE: u8 = 1;

fn default_distance() -> u8 {
    DEFAULT_DISTANCE
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Routing {
    pub bgp: BTreeMap<String, BgpInstance>,
    /// `/routing bgp template` (G3.2a, `crate::bgp`).
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub bgp_templates: BTreeMap<String, crate::bgp::BgpTemplate>,
    /// `/routing bgp connection`: the neighbors, by name.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub bgp_connections: BTreeMap<String, crate::bgp::BgpConnection>,
    /// `/routing filter`: rules, prefix and community lists (G3.2b).
    #[serde(skip_serializing_if = "crate::routing_filter::RoutingFilter::is_empty")]
    pub filter: crate::routing_filter::RoutingFilter,
    /// `/routing rpki` (G3.2c, `crate::rpki`): the RTR validators, by name.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub rpki: BTreeMap<String, crate::rpki::RpkiCache>,
    /// `/routing bfd` (G3.6, `crate::bfd`): profiles and peers.
    #[serde(skip_serializing_if = "crate::bfd::BfdConfig::is_empty")]
    pub bfd: crate::bfd::BfdConfig,
    /// `/routing ospf` (G3.4, `crate::ospf`): instances, areas, interface
    /// templates and key chains.
    #[serde(skip_serializing_if = "crate::ospf::Ospf::is_empty")]
    pub ospf: crate::ospf::Ospf,
    /// `/mpls` (G3.5, `crate::mpls`): kernel label switching and LDP.
    #[serde(skip_serializing_if = "crate::mpls::Mpls::is_default")]
    pub mpls: crate::mpls::Mpls,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BgpInstance {
    pub name: String,
    pub asn: Asn,
    pub router_id: Ipv4Addr,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub comment: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridge_port_is_optional_in_json() {
        let raw = r#"{"name": "ether1", "kind": {"type": "ethernet"}}"#;
        let mut iface: Interface = serde_json::from_str(raw).unwrap();
        assert_eq!(iface.bridge, None);
        assert!(!serde_json::to_string(&iface).unwrap().contains("bridge"));

        iface.bridge = Some("bridge1".parse().unwrap());
        let back: Interface =
            serde_json::from_str(&serde_json::to_string(&iface).unwrap()).unwrap();
        assert_eq!(back, iface);
    }

    #[test]
    fn older_configs_without_routes_still_load() {
        let ip: Ip = serde_json::from_str(r#"{"addresses": [], "next_id": 3}"#).unwrap();
        assert!(ip.routes.is_empty());
        assert_eq!(ip.next_route_id, 0);

        let raw = r#"{"id": "*1", "dst_address": "0.0.0.0/0", "gateway": "10.0.0.1"}"#;
        let r: RouteEntry = serde_json::from_str(raw).unwrap();
        assert_eq!(r.distance, 1);
        assert_eq!(r.routing_table, RoutingTable::Main);
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains(r#""routing_table":"main""#), "{json}");
        assert_eq!(serde_json::from_str::<RouteEntry>(&json).unwrap(), r);

        let vrf: InterfaceKind = serde_json::from_str(r#"{"type": "vrf", "table": 1000}"#).unwrap();
        assert_eq!(vrf, InterfaceKind::Vrf { table: 1000 });
    }
}
