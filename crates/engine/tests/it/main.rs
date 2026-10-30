//! The integration tests of this crate as one binary (G0.29): one link
//! instead of one per file. A new test file is a `mod` here; tests that
//! need their own process stay in `tests/` (`netns*.rs`, `*_root.rs`, the
//! ones that re-run themselves by test name or set process-wide state such as
//! the logger).

// Shared with `benches/dhcp_round.rs`, so it stays in `tests/support/`.
#[path = "../support/mod.rs"]
mod support;

mod arp;
mod bonding;
mod cgnat;
mod cgnat_battery;
mod cgnat_blocks;
mod cgnat_capacity;
mod command_sweep;
mod config_journal;
mod connections;
mod cow_sections;
mod dhcp6_client;
mod dhcp6_server;
mod dhcp_client;
mod dhcp_relay;
mod dhcp_resilience;
mod dhcp_server;
mod dhcp_storm;
mod drift;
mod ethernet;
mod fastpath;
mod features;
mod firewall;
mod firewall_diag;
mod firewall_raw;
mod firewall_safety;
mod fuzz;
mod history_files;
mod identity;
mod incremental_validate;
mod interface;
mod interface_info;
mod ip_address;
mod ip_calc;
mod ipoe;
mod journal_sections;
mod metrics;
mod mpls;
mod neighbor;
mod net_audit;
mod netsim_scenarios;
mod ntp_logging;
mod off_lock;
mod os_loopback;
mod persistence;
mod ppp_import;
mod query_purity;
mod queue;
mod route;
mod route_check;
mod route_page;
mod route_view;
mod safe_mode;
mod session;
mod subscriber_notice;
mod tool_params;
mod unmanaged;
mod users;
mod xdp;
