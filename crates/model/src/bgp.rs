//! BGP neighbors (G3.2a), as RouterOS v7 models them: a
//! `/routing bgp connection` is one neighbor, a `/routing bgp template`
//! holds parameters many connections share. A connection lists templates
//! (`templates=a,b`) and every parameter it leaves unset comes from the
//! first of them that sets it; a template may list templates of its own.
//!
//! Every parameter is optional here so that "unset" (inherit) and "set to
//! the default" stay apart, as in RouterOS. [`resolve_templates`] and
//! [`BgpConnection::effective`] give the values in force; `proto-bgp`
//! validates them and renders them for FRR.

use std::collections::BTreeMap;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::sealed::Sealed;
use crate::types::Asn;

/// Deepest template chain (connection › template › … ); deeper is refused.
pub const MAX_TEMPLATE_DEPTH: usize = 8;
/// Most templates one connection or template lists.
pub const MAX_TEMPLATES_LISTED: usize = 8;

/// RouterOS `local.role` (RFC 9234 roles for eBGP). `ibgp` and `ebgp` are
/// the plain kinds; the others are eBGP with a role FRR announces in the
/// OPEN (`neighbor X local-role`), so a route leak is caught on both ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum LocalRole {
    Ibgp,
    /// RouterOS `ibgp-rr`: iBGP where this router reflects routes to the
    /// neighbor, its client (RFC 4456; FRR `route-reflector-client`).
    IbgpRr,
    Ebgp,
    EbgpProvider,
    EbgpCustomer,
    EbgpPeer,
    EbgpRs,
    EbgpRsClient,
}

impl LocalRole {
    pub const ALL: [LocalRole; 8] = [
        LocalRole::Ibgp,
        LocalRole::IbgpRr,
        LocalRole::Ebgp,
        LocalRole::EbgpProvider,
        LocalRole::EbgpCustomer,
        LocalRole::EbgpPeer,
        LocalRole::EbgpRs,
        LocalRole::EbgpRsClient,
    ];

    pub fn name(self) -> &'static str {
        match self {
            LocalRole::Ibgp => "ibgp",
            LocalRole::IbgpRr => "ibgp-rr",
            LocalRole::Ebgp => "ebgp",
            LocalRole::EbgpProvider => "ebgp-provider",
            LocalRole::EbgpCustomer => "ebgp-customer",
            LocalRole::EbgpPeer => "ebgp-peer",
            LocalRole::EbgpRs => "ebgp-rs",
            LocalRole::EbgpRsClient => "ebgp-rs-client",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.name() == s)
    }

    pub fn is_ibgp(self) -> bool {
        matches!(self, LocalRole::Ibgp | LocalRole::IbgpRr)
    }

    /// The RFC 9234 role FRR takes (`neighbor X local-role <role>`).
    pub fn rfc9234(self) -> Option<&'static str> {
        match self {
            LocalRole::Ibgp | LocalRole::IbgpRr | LocalRole::Ebgp => None,
            LocalRole::EbgpProvider => Some("provider"),
            LocalRole::EbgpCustomer => Some("customer"),
            LocalRole::EbgpPeer => Some("peer"),
            LocalRole::EbgpRs => Some("rs-server"),
            LocalRole::EbgpRsClient => Some("rs-client"),
        }
    }
}

/// RouterOS `afi`: the address families the session carries (RFC 4760).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Afi {
    /// IPv4 unicast.
    Ip,
    /// IPv6 unicast.
    Ipv6,
}

impl Afi {
    pub fn name(self) -> &'static str {
        match self {
            Afi::Ip => "ip",
            Afi::Ipv6 => "ipv6",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "ip" | "ipv4" => Some(Afi::Ip),
            "ipv6" => Some(Afi::Ipv6),
            _ => None,
        }
    }
}

/// What happens when a neighbor sends more prefixes than its limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MaxPrefixAction {
    /// Close the session (NOTIFICATION Cease, RFC 4486 subcode 1) until
    /// the operator clears it.
    #[default]
    Shutdown,
    /// Only log; keep the routes.
    Warning,
    /// Close it and try again after `max_prefix_restart` minutes.
    Restart,
}

impl MaxPrefixAction {
    pub fn name(self) -> &'static str {
        match self {
            MaxPrefixAction::Shutdown => "shutdown",
            MaxPrefixAction::Warning => "warning",
            MaxPrefixAction::Restart => "restart",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "shutdown" => Some(MaxPrefixAction::Shutdown),
            "warning" | "warning-only" => Some(MaxPrefixAction::Warning),
            "restart" => Some(MaxPrefixAction::Restart),
            _ => None,
        }
    }
}

/// RouterOS `nexthop-choice`.
/// G3.9fa: what a connection announces besides what it reflects
/// (RouterOS `output.redistribute`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BgpRedistribute {
    Connected,
    Static,
    Ospf,
}

impl BgpRedistribute {
    pub const ALL: [BgpRedistribute; 3] = [
        BgpRedistribute::Connected,
        BgpRedistribute::Static,
        BgpRedistribute::Ospf,
    ];

    pub fn name(self) -> &'static str {
        match self {
            BgpRedistribute::Connected => "connected",
            BgpRedistribute::Static => "static",
            BgpRedistribute::Ospf => "ospf",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.name() == s)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NexthopChoice {
    #[default]
    Default,
    /// Always our own address (`next-hop-self`), also towards iBGP.
    ForceSelf,
    /// Keep the received next hop, also towards eBGP.
    Propagate,
}

impl NexthopChoice {
    pub fn name(self) -> &'static str {
        match self {
            NexthopChoice::Default => "default",
            NexthopChoice::ForceSelf => "force-self",
            NexthopChoice::Propagate => "propagate",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "default" => Some(NexthopChoice::Default),
            "force-self" => Some(NexthopChoice::ForceSelf),
            "propagate" => Some(NexthopChoice::Propagate),
            _ => None,
        }
    }
}

/// The parameters a connection and a template share. `None`: unset,
/// inherited from the templates (or the default).
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BgpParams {
    /// RouterOS `remote.as`; unset: any (FRR `remote-as external` or
    /// `internal`, by the role).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_as: Option<Asn>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_role: Option<LocalRole>,
    /// The neighbor is more than one hop away (eBGP: TTL 255).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub multihop: Option<bool>,
    /// Seconds; 0 = infinity (RFC 4271 §4.2: 0 or 3..=65535).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hold_time: Option<u16>,
    /// Seconds; unset = a third of the hold time.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keepalive_time: Option<u16>,
    /// RFC 2385 TCP MD5 key, sealed (`crate::sealed`); `Some(empty)`
    /// clears one a template sets.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp_md5_key: Option<Sealed>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub afi: Option<Vec<Afi>>,
    /// Most prefixes accepted from the neighbor, per family; 0 = no limit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_prefix_ipv4: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_prefix_ipv6: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_prefix_action: Option<MaxPrefixAction>,
    /// Minutes before trying again (`max_prefix_action = restart`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_prefix_restart: Option<u16>,
    /// RouterOS `local.address`: the address (or interface) the TCP
    /// session leaves from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub update_source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nexthop_choice: Option<NexthopChoice>,
    /// RouterOS `input.filter`: the `/routing filter` chain received routes
    /// go through (G3.2b). Unset on eBGP: nothing is accepted (RFC 8212).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_filter: Option<String>,
    /// RouterOS `output.filter-chain`: the chain sent routes go through.
    /// Unset on eBGP: nothing is sent (RFC 8212).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_filter: Option<String>,
    /// Keep the routes the neighbor sends before the input chain (FRR
    /// `soft-reconfiguration inbound`): the preview runs on them, and a new
    /// input chain applies without asking the neighbor again. RouterOS keeps
    /// rejected routes too. Unset: yes; it costs memory (one more copy of
    /// each received route).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keep_received: Option<bool>,
    /// G3.2c: what to do with RPKI-invalid routes (unset: reject, once a
    /// validator is configured; `crate::rpki`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rpki_invalid: Option<crate::rpki::RpkiInvalid>,
    /// G3.6b: the BFD profile watching the session (`crate::bfd`; RouterOS
    /// `use-bfd`): the session goes down with BFD (FRR `neighbor … bfd`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bfd: Option<String>,
    /// G3.9fa: RouterOS `output.redistribute` (connected, static, ospf).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_redistribute: Option<Vec<BgpRedistribute>>,
    /// G3.9fa: RouterOS `output.network`: the `/ip firewall address-list`
    /// whose networks are announced, each only while a route to it exists
    /// (FRR `network` with `bgp network import-check`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_network: Option<String>,
}

impl BgpParams {
    /// Fill every unset parameter from `parent`.
    pub fn inherit(&mut self, parent: &BgpParams) {
        fn take<T: Clone>(mine: &mut Option<T>, theirs: &Option<T>) {
            if mine.is_none() {
                mine.clone_from(theirs);
            }
        }
        take(&mut self.remote_as, &parent.remote_as);
        take(&mut self.local_role, &parent.local_role);
        take(&mut self.multihop, &parent.multihop);
        take(&mut self.hold_time, &parent.hold_time);
        take(&mut self.keepalive_time, &parent.keepalive_time);
        take(&mut self.tcp_md5_key, &parent.tcp_md5_key);
        take(&mut self.afi, &parent.afi);
        take(&mut self.max_prefix_ipv4, &parent.max_prefix_ipv4);
        take(&mut self.max_prefix_ipv6, &parent.max_prefix_ipv6);
        take(&mut self.max_prefix_action, &parent.max_prefix_action);
        take(&mut self.max_prefix_restart, &parent.max_prefix_restart);
        take(&mut self.update_source, &parent.update_source);
        take(&mut self.nexthop_choice, &parent.nexthop_choice);
        take(&mut self.input_filter, &parent.input_filter);
        take(&mut self.output_filter, &parent.output_filter);
        take(&mut self.keep_received, &parent.keep_received);
        take(&mut self.rpki_invalid, &parent.rpki_invalid);
        take(&mut self.bfd, &parent.bfd);
        take(&mut self.output_redistribute, &parent.output_redistribute);
        take(&mut self.output_network, &parent.output_network);
    }

    /// The families in force: unset is IPv4 only, as in RouterOS.
    pub fn families(&self) -> Vec<Afi> {
        self.afi.clone().unwrap_or_else(|| vec![Afi::Ip])
    }

    /// Whether a key is in force (set and not cleared).
    pub fn has_key(&self) -> bool {
        self.tcp_md5_key.as_ref().is_some_and(|k| !k.is_empty())
    }
}

/// RouterOS `/routing bgp template`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BgpTemplate {
    pub name: String,
    /// Parents, first wins.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub templates: Vec<String>,
    #[serde(default)]
    pub params: BgpParams,
    #[serde(default)]
    pub comment: String,
}

/// RouterOS `/routing bgp connection`: one neighbor.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BgpConnection {
    pub name: String,
    /// The `routing.bgp` instance (local AS, router id) it belongs to.
    pub instance: String,
    /// RouterOS `remote.address`.
    pub remote_address: IpAddr,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub templates: Vec<String>,
    #[serde(default)]
    pub params: BgpParams,
    /// FRR `neighbor X shutdown`: kept in the config, session closed
    /// (NOTIFICATION Cease, administrative shutdown).
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub comment: String,
}

/// Why a template chain does not resolve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveError {
    Missing(String),
    /// The names around the loop, first repeated last.
    Loop(Vec<String>),
    TooDeep(Vec<String>),
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolveError::Missing(t) => write!(f, "template {t:?} does not exist"),
            ResolveError::Loop(chain) => {
                write!(f, "templates inherit in a loop: {}", chain.join(" → "))
            }
            ResolveError::TooDeep(chain) => write!(
                f,
                "templates nest deeper than {MAX_TEMPLATE_DEPTH}: {}",
                chain.join(" → ")
            ),
        }
    }
}

/// Every template's parameters with its parents' filled in, each chain
/// walked once (memoized: N connections over M templates cost O(N + M),
/// not one walk of the chain per connection).
pub fn resolve_templates(
    templates: &BTreeMap<String, BgpTemplate>,
) -> BTreeMap<String, Result<BgpParams, ResolveError>> {
    let mut done = BTreeMap::new();
    for name in templates.keys() {
        let mut stack = Vec::new();
        let _ = resolve_one(name, templates, &mut done, &mut stack);
    }
    done
}

fn resolve_one(
    name: &str,
    templates: &BTreeMap<String, BgpTemplate>,
    done: &mut BTreeMap<String, Result<BgpParams, ResolveError>>,
    stack: &mut Vec<String>,
) -> Result<BgpParams, ResolveError> {
    if let Some(r) = done.get(name) {
        return r.clone();
    }
    if stack.iter().any(|s| s == name) {
        let mut chain: Vec<String> = stack
            .iter()
            .skip_while(|s| *s != name)
            .cloned()
            .collect();
        chain.push(name.to_owned());
        return Err(ResolveError::Loop(chain));
    }
    if stack.len() >= MAX_TEMPLATE_DEPTH {
        let mut chain = stack.clone();
        chain.push(name.to_owned());
        return Err(ResolveError::TooDeep(chain));
    }
    let Some(t) = templates.get(name) else {
        return Err(ResolveError::Missing(name.to_owned()));
    };
    stack.push(name.to_owned());
    let mut out = t.params.clone();
    let mut result = Ok(());
    for parent in &t.templates {
        match resolve_one(parent, templates, done, stack) {
            Ok(p) => out.inherit(&p),
            Err(e) => {
                result = Err(e);
                break;
            }
        }
    }
    stack.pop();
    let r = result.map(|()| out);
    // A loop is reported for the templates on it only once found from
    // the top; the inner ones are resolved again from their own start.
    if stack.is_empty() || r.is_ok() {
        done.insert(name.to_owned(), r.clone());
    }
    r
}

impl BgpConnection {
    /// The parameters in force: the connection's own, then each listed
    /// template's (resolved by [`resolve_templates`]) for what is unset.
    pub fn effective(
        &self,
        resolved: &BTreeMap<String, Result<BgpParams, ResolveError>>,
    ) -> Result<BgpParams, ResolveError> {
        let mut out = self.params.clone();
        for t in &self.templates {
            match resolved.get(t) {
                Some(Ok(p)) => out.inherit(p),
                Some(Err(e)) => return Err(e.clone()),
                None => return Err(ResolveError::Missing(t.clone())),
            }
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tpl(name: &str, parents: &[&str], params: BgpParams) -> (String, BgpTemplate) {
        (
            name.to_owned(),
            BgpTemplate {
                name: name.to_owned(),
                templates: parents.iter().map(|s| (*s).to_owned()).collect(),
                params,
                comment: String::new(),
            },
        )
    }

    #[test]
    fn the_first_template_that_sets_a_value_wins() {
        let templates: BTreeMap<_, _> = [
            tpl(
                "base",
                &[],
                BgpParams {
                    hold_time: Some(90),
                    multihop: Some(true),
                    ..Default::default()
                },
            ),
            tpl(
                "transit",
                &["base"],
                BgpParams {
                    hold_time: Some(30),
                    remote_as: Some(Asn(64500)),
                    ..Default::default()
                },
            ),
        ]
        .into();
        let resolved = resolve_templates(&templates);
        let c = BgpConnection {
            name: "up1".into(),
            instance: "default".into(),
            remote_address: "192.0.2.1".parse().unwrap(),
            templates: vec!["transit".into()],
            params: BgpParams {
                remote_as: Some(Asn(64501)),
                ..Default::default()
            },
            disabled: false,
            comment: String::new(),
        };
        let e = c.effective(&resolved).unwrap();
        assert_eq!(e.remote_as, Some(Asn(64501)));
        assert_eq!(e.hold_time, Some(30));
        assert_eq!(e.multihop, Some(true));
        assert_eq!(e.families(), [Afi::Ip]);
    }

    #[test]
    fn loops_missing_and_deep_chains_are_errors() {
        let templates: BTreeMap<_, _> = [
            tpl("a", &["b"], BgpParams::default()),
            tpl("b", &["a"], BgpParams::default()),
            tpl("c", &["nope"], BgpParams::default()),
        ]
        .into();
        let r = resolve_templates(&templates);
        assert!(matches!(&r["a"], Err(ResolveError::Loop(ch)) if ch == &["a", "b", "a"]));
        assert!(matches!(&r["b"], Err(ResolveError::Loop(_))));
        assert_eq!(r["c"], Err(ResolveError::Missing("nope".into())));

        let deep: BTreeMap<_, _> = (0..20)
            .map(|i| {
                let parent = format!("t{}", i + 1);
                let parents: Vec<&str> = if i < 19 { vec![parent.as_str()] } else { vec![] };
                tpl(&format!("t{i}"), &parents, BgpParams::default())
            })
            .collect();
        let r = resolve_templates(&deep);
        assert!(matches!(&r["t0"], Err(ResolveError::TooDeep(_))));
        assert!(r["t15"].is_ok());
    }

    #[test]
    fn params_round_trip_and_unknown_keys_are_refused() {
        let p = BgpParams {
            local_role: Some(LocalRole::EbgpCustomer),
            afi: Some(vec![Afi::Ip, Afi::Ipv6]),
            max_prefix_action: Some(MaxPrefixAction::Restart),
            ..Default::default()
        };
        let j = serde_json::to_string(&p).unwrap();
        assert_eq!(
            j,
            r#"{"local_role":"ebgp-customer","afi":["ip","ipv6"],"max_prefix_action":"restart"}"#
        );
        assert_eq!(serde_json::from_str::<BgpParams>(&j).unwrap(), p);
        assert!(serde_json::from_str::<BgpParams>(r#"{"holdtime":3}"#).is_err());
        assert_eq!(serde_json::to_string(&BgpParams::default()).unwrap(), "{}");
    }
}
