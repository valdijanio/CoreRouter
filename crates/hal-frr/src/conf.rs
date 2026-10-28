//! FRR configuration as a tree, and the commands that turn one tree into
//! another: what `frr-reload.py` does, in Rust and without a process.
//!
//! The text is FRR's own (`show running-config`, the render of the
//! `proto-*` crates): one command per line, the commands of a context
//! (`router bgp 65000`, `address-family ipv4 unicast`, `route-map X permit
//! 10`) indented under it. Structure comes from indentation; the closing
//! markers (`exit`, `exit-address-family`, `!`) carry nothing and are
//! skipped.
//!
//! The diff only touches what changed: a session survives every commit that
//! does not change it (never `no router bgp` + the whole block again).

use std::collections::{HashMap, HashSet};

/// Longest line kept; FRR's own vty buffer is 4 KiB (`VTY_BUFSIZ` × 8 for
/// the longest commands). Longer lines are refused, not truncated.
pub const MAX_LINE: usize = 4096;
/// Deepest nesting kept (`router bgp` › `address-family` › `vni` is 3).
pub const MAX_DEPTH: usize = 8;

/// One command and, if it opens a context, the commands under it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Node {
    pub line: String,
    pub children: Vec<Node>,
}

/// A whole configuration (or the part of it CoreRouter owns).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Conf {
    pub nodes: Vec<Node>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    #[error("line {0}: longer than {MAX_LINE} bytes")]
    LongLine(usize),
    #[error("line {0}: nested deeper than {MAX_DEPTH} contexts")]
    TooDeep(usize),
}

/// Lines that only close a context or separate blocks.
fn is_marker(line: &str) -> bool {
    line.starts_with('!')
        || matches!(
            line,
            "exit" | "exit-address-family" | "exit-vrf" | "exit-vni" | "end" | "quit"
        )
}

impl Conf {
    /// Parse FRR configuration text. Comments, closing markers and blank
    /// lines are dropped; a line indented deeper than the line before it
    /// belongs to that line's context.
    pub fn parse(text: &str) -> Result<Self, ParseError> {
        // Each command with its depth: the number of contexts open above
        // it (by indentation), so the depth grows by at most one per line.
        let mut flat: Vec<(usize, &str)> = Vec::new();
        let mut open: Vec<usize> = Vec::new(); // indents of the open headers
        for (n, raw) in text.lines().enumerate() {
            if raw.len() > MAX_LINE {
                return Err(ParseError::LongLine(n + 1));
            }
            let line = raw.trim_end();
            let body = line.trim_start();
            if body.is_empty() || is_marker(body) {
                continue;
            }
            let indent = line.len() - body.len();
            while open.last().is_some_and(|&i| i >= indent) {
                open.pop();
            }
            if open.len() >= MAX_DEPTH {
                return Err(ParseError::TooDeep(n + 1));
            }
            flat.push((open.len(), body));
            open.push(indent);
        }
        let mut pos = 0;
        Ok(Conf {
            nodes: build(&flat, &mut pos, 0),
        })
    }

    /// The top-level contexts `keep` accepts, the rest dropped: the part of
    /// FRR's running config that CoreRouter owns.
    pub fn owned(self, keep: impl Fn(&str) -> bool) -> Self {
        Conf {
            nodes: self.nodes.into_iter().filter(|n| keep(&n.line)).collect(),
        }
    }

    /// Back to FRR's text, with the closing markers FRR writes.
    pub fn render(&self) -> String {
        let mut s = String::new();
        for n in &self.nodes {
            write_node(&mut s, n, 0);
        }
        s
    }
}

/// The nodes at `depth` from `flat[*pos]` on, with their children.
fn build(flat: &[(usize, &str)], pos: &mut usize, depth: usize) -> Vec<Node> {
    let mut out = Vec::new();
    while let Some(&(d, line)) = flat.get(*pos) {
        if d != depth {
            break;
        }
        *pos += 1;
        let children = build(flat, pos, depth + 1);
        out.push(Node {
            line: line.to_owned(),
            children,
        });
    }
    out
}

fn write_node(s: &mut String, n: &Node, depth: usize) {
    for _ in 0..depth {
        s.push(' ');
    }
    s.push_str(&n.line);
    s.push('\n');
    for c in &n.children {
        write_node(s, c, depth + 1);
    }
    if !n.children.is_empty() {
        for _ in 0..depth {
            s.push(' ');
        }
        s.push_str(close(&n.line));
        s.push('\n');
    }
}

/// How a context is left.
pub fn close(header: &str) -> &'static str {
    if header.starts_with("address-family") {
        "exit-address-family"
    } else {
        "exit"
    }
}

/// Top-level contexts CoreRouter owns only lines of and never deletes:
/// `interface X` (the interface itself belongs to zebra and the kernel).
fn kept_context(line: &str) -> bool {
    line.starts_with("interface ")
}

/// The command that undoes `line`: `no X` for `X`, `X` for `no X`.
pub fn negate(line: &str) -> String {
    match line.strip_prefix("no ") {
        Some(rest) => rest.to_owned(),
        None => format!("no {line}"),
    }
}

/// Settings with one value per context: entering the new value replaces
/// the old one, so the old line is not deleted first. Deleting it would be
/// wrong twice: `no neighbor X remote-as A` removes the whole neighbor
/// (and every line under it), and `no bgp router-id A` after `bgp
/// router-id B` fails ("doesn't match").
pub fn overwrite_key(line: &str) -> Option<String> {
    const SINGLE: &[&str] = &[
        "bgp router-id",
        "bgp cluster-id",
        "bgp confederation identifier",
        "timers bgp",
        "description",
        "router-id",
        "ospf router-id",
        // G3.4: OSPF interface values and keys, one each.
        "ospf6 router-id",
        "ip ospf network",
        "ip ospf cost",
        "ip ospf hello-interval",
        "ip ospf dead-interval",
        "ip ospf priority",
        "ip ospf retransmit-interval",
        "ip ospf transmit-delay",
        "ip ospf authentication-key",
        "ip ospf bfd profile",
        "ipv6 ospf6 network",
        "ipv6 ospf6 cost",
        "ipv6 ospf6 hello-interval",
        "ipv6 ospf6 dead-interval",
        "ipv6 ospf6 priority",
        "ipv6 ospf6 retransmit-interval",
        "ipv6 ospf6 transmit-delay",
        "ipv6 ospf6 instance-id",
        "ipv6 ospf6 bfd profile",
        "key-string",
        "cryptographic-algorithm",
        "send-lifetime",
        "accept-lifetime",
        // Route-map entries (G3.2b): one value each.
        "on-match",
        "set local-preference",
        "set metric",
        "set community",
        "set large-community",
        "set as-path prepend",
        "set comm-list",
        "set large-comm-list",
        // G3.4f: Segment Routing, one value each.
        "segment-routing global-block",
        "segment-routing node-msd",
    ];
    for p in SINGLE {
        if line.starts_with(p) && line.as_bytes().get(p.len()) == Some(&b' ') {
            return Some((*p).to_owned());
        }
    }
    // G3.4f: `segment-routing prefix P index N [flag]`: one SID per
    // prefix; FRR updates the index and flags of a prefix in place.
    if let Some(rest) = line.strip_prefix("segment-routing prefix ") {
        let p = rest.split(' ').next()?;
        return Some(format!("segment-routing prefix {p}"));
    }
    // neighbor <peer> <attr> <value…>
    const PEER: &[&str] = &[
        "remote-as",
        "description",
        "timers",
        "update-source",
        "password",
        "ebgp-multihop",
        "ttl-security",
        "local-as",
        "port",
        "maximum-prefix",
        "route-map",
        "prefix-list",
        "filter-list",
        "weight",
        "allowas-in",
        "local-role",
    ];
    let mut words = line.split(' ');
    if words.next() == Some("neighbor") {
        let peer = words.next()?;
        let attr = words.next()?;
        if PEER.contains(&attr) {
            // `route-map NAME in|out` and friends are per direction.
            let dir = match attr {
                "route-map" | "prefix-list" | "filter-list" => line
                    .rsplit(' ')
                    .next()
                    .filter(|d| *d == "in" || *d == "out")?,
                _ => "",
            };
            return Some(format!("neighbor {peer} {attr} {dir}"));
        }
    }
    None
}

/// Lines other lines of the same context depend on, deleted after them
/// (0: no order): `no segment-routing prefix …` fails once `no
/// segment-routing on` ran ("OSPF SR is not turned on"), and SR's opaque
/// LSAs go before `router-info` and `capability opaque` (`ospfd`, FRR
/// 10.7.1).
fn delete_late(line: &str) -> u8 {
    if line == "segment-routing on" {
        1
    } else if line.starts_with("router-info ") {
        2
    } else if line == "capability opaque" {
        3
    } else if line == "ip ospf bfd" || line == "ipv6 ospf6 bfd" {
        // After its `… bfd profile P`, which it would take with it.
        1
    } else {
        0
    }
}

/// The commands that turn `old` into `new`, in order, as they are typed in
/// FRR's configuration mode: a context header enters it, `exit` (or
/// `exit-address-family`) leaves it. Empty when nothing changed.
///
/// In each context, deletions come first and additions after, so a
/// replaced prefix-list sequence (`seq 5 permit` → `seq 5 deny`) is free
/// before it is entered again; the lines that only change a single-valued
/// setting ([`overwrite_key`]) are entered over the old value. Order inside
/// a context does not matter to FRR (route-map and prefix-list entries carry
/// their sequence numbers), so lines are compared as a set.
///
/// BGP neighbors (G3.2a) add one dependency: a neighbor exists from its
/// `neighbor X remote-as` line until `no neighbor X remote-as`, which also
/// removes every other line of it, in every address family. So a new
/// neighbor is defined before the changes inside the address families
/// (its `activate`), a removed one is removed after them, and the other
/// lines of a removed neighbor are not deleted one by one (FRR would refuse
/// them: the neighbor is gone).
pub fn diff(old: &Conf, new: &Conf) -> Vec<String> {
    let mut out = Vec::new();
    diff_scope(&old.nodes, &new.nodes, true, &HashSet::new(), &mut out);
    out
}

/// The neighbor a line defines (`neighbor X remote-as …`).
pub fn defines_peer(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("neighbor ")?;
    let (peer, attr) = rest.split_once(' ')?;
    attr.starts_with("remote-as ").then_some(peer)
}

/// The neighbor a line is about (`neighbor X …`).
fn peer_of(line: &str) -> Option<&str> {
    line.strip_prefix("neighbor ")?.split(' ').next()
}

/// Diff one context's children (`top`: the root, where every context has
/// a `no` form). `gone`: neighbors removed by an enclosing context, whose
/// lines here go with them.
fn diff_scope(
    old: &[Node],
    new: &[Node],
    top: bool,
    gone: &HashSet<String>,
    out: &mut Vec<String>,
) {
    let new_by: HashMap<&str, &Node> = new.iter().map(|n| (n.line.as_str(), n)).collect();
    let old_by: HashMap<&str, &Node> = old.iter().map(|n| (n.line.as_str(), n)).collect();
    let replaced: HashSet<String> = new
        .iter()
        .filter(|n| !old_by.contains_key(n.line.as_str()))
        .filter_map(|n| overwrite_key(&n.line))
        .collect();
    // Neighbors removed in this context: defined before, not after.
    let still: HashSet<&str> = new.iter().filter_map(|n| defines_peer(&n.line)).collect();
    let mut removed: HashSet<String> = gone.clone();
    removed.extend(
        old.iter()
            .filter_map(|n| defines_peer(&n.line))
            .filter(|p| !still.contains(p))
            .map(str::to_owned),
    );
    let of_removed = |line: &str| peer_of(line).is_some_and(|p| removed.contains(p));
    let body = out;
    // 1. Deletions (a removed neighbor's own lines go with it, in 5). The
    // switches other lines need go last ([`delete_late`]).
    let mut peer_removals = Vec::new();
    let mut old_sorted: Vec<&Node> = old.iter().collect();
    old_sorted.sort_by_key(|n| delete_late(&n.line));
    for n in old_sorted {
        if new_by.contains_key(n.line.as_str()) {
            continue;
        }
        if overwrite_key(&n.line).is_some_and(|k| replaced.contains(&k)) {
            continue;
        }
        if n.children.is_empty() && of_removed(&n.line) {
            if defines_peer(&n.line).is_some() && !gone.contains(peer_of(&n.line).unwrap_or("")) {
                peer_removals.push(negate(&n.line));
            }
            continue;
        }
        if n.children.is_empty() || (top && !kept_context(&n.line)) {
            body.push(negate(&n.line));
        } else {
            // A nested context (address-family) has no `no` form, and an
            // `interface X` of a link the kernel still has is zebra's: the
            // daemon refuses `no interface X` (FRR 10.7.1, G3.9: the
            // whole commit failed when OSPF left an interface). Empty it.
            let mut sub = Vec::new();
            diff_scope(&n.children, &[], false, &removed, &mut sub);
            wrap(&n.line, sub, body);
        }
    }
    // 2. New neighbors, before anything refers to them.
    for n in new {
        if !old_by.contains_key(n.line.as_str()) && defines_peer(&n.line).is_some() {
            add_node(n, body);
        }
    }
    // 3. Changes inside the contexts both sides have.
    for n in old {
        if let Some(m) = new_by.get(n.line.as_str())
            && (!n.children.is_empty() || !m.children.is_empty())
        {
            let mut sub = Vec::new();
            diff_scope(&n.children, &m.children, false, &removed, &mut sub);
            wrap(&n.line, sub, body);
        }
    }
    // 4. Additions, whole contexts included.
    for n in new {
        if !old_by.contains_key(n.line.as_str()) && defines_peer(&n.line).is_none() {
            add_node(n, body);
        }
    }
    // 5. Removed neighbors, last.
    body.extend(peer_removals);
}

/// `line` with any secret it carries masked, for logs and errors
/// (`neighbor X password KEY`).
pub fn redact(line: &str) -> String {
    // The secret is the rest of the line after one of these (G3.4: OSPF
    // keys, `ip ospf message-digest-key N md5 K`, `… hash-algo A key K`).
    const SECRET: &[&str] = &[
        " password ",
        "key-string ",
        "authentication-key ",
        " md5 ",
        " key ",
    ];
    let mut cut = None;
    for m in SECRET {
        if let Some(i) = line.find(m) {
            let end = i + m.len();
            cut = Some(cut.map_or(end, |c: usize| c.min(end)));
        }
    }
    match cut {
        Some(end) => format!("{}***", line.get(..end).unwrap_or_default()),
        None => line.to_owned(),
    }
}

/// `sub` run inside the context `header` (nothing when `sub` is empty).
fn wrap(header: &str, sub: Vec<String>, out: &mut Vec<String>) {
    if sub.is_empty() {
        return;
    }
    out.push(header.to_owned());
    out.extend(sub.into_iter().map(|l| format!(" {l}")));
    out.push(close(header).to_owned());
}

fn add_node(n: &Node, out: &mut Vec<String>) {
    out.push(n.line.clone());
    if n.children.is_empty() {
        return;
    }
    for c in &n.children {
        let mut sub = Vec::new();
        add_node(c, &mut sub);
        out.extend(sub.into_iter().map(|l| format!(" {l}")));
    }
    out.push(close(&n.line).to_owned());
}

#[cfg(test)]
mod tests {
    use super::*;

    const RUNNING: &str = "\
frr version 10.7.1
frr defaults traditional
hostname r1
service integrated-vtysh-config
!
ip prefix-list LAN seq 5 permit 10.0.0.0/8 le 24
!
router bgp 65000
 bgp router-id 10.0.0.1
 no bgp default ipv4-unicast
 neighbor 192.0.2.2 remote-as 65001
 !
 address-family ipv4 unicast
  neighbor 192.0.2.2 activate
 exit-address-family
exit
!
route-map OUT permit 10
 match ip address prefix-list LAN
exit
!
end
";

    fn conf(s: &str) -> Conf {
        Conf::parse(s).unwrap()
    }

    #[test]
    fn parses_contexts_by_indentation() {
        let c = conf(RUNNING);
        let lines: Vec<&str> = c.nodes.iter().map(|n| n.line.as_str()).collect();
        assert_eq!(
            lines,
            [
                "frr version 10.7.1",
                "frr defaults traditional",
                "hostname r1",
                "service integrated-vtysh-config",
                "ip prefix-list LAN seq 5 permit 10.0.0.0/8 le 24",
                "router bgp 65000",
                "route-map OUT permit 10",
            ]
        );
        let bgp = &c.nodes[5];
        assert_eq!(bgp.children.len(), 4);
        assert_eq!(bgp.children[3].line, "address-family ipv4 unicast");
        assert_eq!(
            bgp.children[3].children[0].line,
            "neighbor 192.0.2.2 activate"
        );
    }

    #[test]
    fn render_parses_back_to_the_same_tree() {
        let c = conf(RUNNING);
        assert_eq!(conf(&c.render()), c);
    }

    #[test]
    fn same_config_means_no_commands() {
        let a = conf(RUNNING);
        assert!(diff(&a, &a).is_empty());
        // Markers, comments and order do not count.
        let b = conf(
            "route-map OUT permit 10\n match ip address prefix-list LAN\n\
             router bgp 65000\n neighbor 192.0.2.2 remote-as 65001\n bgp router-id 10.0.0.1\n \
             no bgp default ipv4-unicast\n address-family ipv4 unicast\n  neighbor 192.0.2.2 activate\n\
             ip prefix-list LAN seq 5 permit 10.0.0.0/8 le 24\nfrr version 10.7.1\n\
             frr defaults traditional\nhostname r1\nservice integrated-vtysh-config\n",
        );
        assert_eq!(diff(&a, &b), Vec::<String>::new());
    }

    #[test]
    fn a_changed_setting_is_entered_over_the_old_value() {
        let a = conf(
            "router bgp 65000\n bgp router-id 10.0.0.1\n neighbor 192.0.2.2 remote-as 65001\n",
        );
        let b = conf(
            "router bgp 65000\n bgp router-id 10.0.0.9\n neighbor 192.0.2.2 remote-as 65002\n",
        );
        assert_eq!(
            diff(&a, &b),
            [
                "router bgp 65000",
                " neighbor 192.0.2.2 remote-as 65002",
                " bgp router-id 10.0.0.9",
                "exit",
            ]
        );
    }

    #[test]
    fn deletions_come_before_additions() {
        let a = conf("ip prefix-list L seq 5 permit 10.0.0.0/8\n");
        let b = conf("ip prefix-list L seq 5 deny 10.0.0.0/8\n");
        assert_eq!(
            diff(&a, &b),
            [
                "no ip prefix-list L seq 5 permit 10.0.0.0/8",
                "ip prefix-list L seq 5 deny 10.0.0.0/8",
            ]
        );
    }

    #[test]
    fn negated_lines_are_undone_by_the_positive_form() {
        let a = conf("router bgp 65000\n no bgp default ipv4-unicast\n bgp shutdown\n");
        let b = conf("router bgp 65000\n");
        assert_eq!(
            diff(&a, &b),
            [
                "router bgp 65000",
                " bgp default ipv4-unicast",
                " no bgp shutdown",
                "exit"
            ]
        );
    }

    #[test]
    fn nested_contexts_are_emptied_not_negated() {
        let a = conf(RUNNING);
        let mut b = a.clone();
        b.nodes[5].children.truncate(3);
        assert_eq!(
            diff(&a, &b),
            [
                "router bgp 65000",
                " address-family ipv4 unicast",
                "  no neighbor 192.0.2.2 activate",
                " exit-address-family",
                "exit",
            ]
        );
    }

    #[test]
    fn an_interface_left_by_ospf_is_emptied_not_deleted() {
        // FRR 10.7.1 refuses `no interface ether2` while the link exists
        // ("configuration failed", lab VM against RouterOS, G3.9).
        let a = conf("interface ether2\n ip ospf area 0.0.0.0\n ip ospf cost 10\nexit\n");
        let b = conf("");
        assert_eq!(
            diff(&a, &b),
            [
                "interface ether2",
                " no ip ospf area 0.0.0.0",
                " no ip ospf cost 10",
                "exit",
            ]
        );
    }

    #[test]
    fn whole_contexts_are_added_and_removed() {
        let a = conf("router bgp 65000\n bgp router-id 10.0.0.1\n");
        let b = conf("router bgp 65001\n bgp router-id 10.0.0.1\n");
        assert_eq!(
            diff(&a, &b),
            [
                "no router bgp 65000",
                "router bgp 65001",
                " bgp router-id 10.0.0.1",
                "exit",
            ]
        );
    }

    const TWO_PEERS: &str = "router bgp 65000\n neighbor 192.0.2.2 remote-as 65001\n \
         neighbor 192.0.2.2 description up1\n neighbor 192.0.2.2 timers 10 30\n \
         address-family ipv4 unicast\n  neighbor 192.0.2.2 activate\n  \
         neighbor 192.0.2.2 maximum-prefix 100\n exit-address-family\nexit\n";

    #[test]
    fn a_new_neighbor_exists_before_its_address_family_lines() {
        let a = conf(TWO_PEERS);
        let b = conf(
            &TWO_PEERS
                .replace(
                    " address-family",
                    " neighbor 192.0.2.6 remote-as 65002\n address-family",
                )
                .replace(
                    "  neighbor 192.0.2.2 activate\n",
                    "  neighbor 192.0.2.2 activate\n  neighbor 192.0.2.6 activate\n",
                ),
        );
        assert_eq!(
            diff(&a, &b),
            [
                "router bgp 65000",
                " neighbor 192.0.2.6 remote-as 65002",
                " address-family ipv4 unicast",
                "  neighbor 192.0.2.6 activate",
                " exit-address-family",
                "exit",
            ]
        );
    }

    #[test]
    fn a_removed_neighbor_goes_with_one_command_and_others_stay() {
        let b = conf(TWO_PEERS);
        let a = conf(
            &TWO_PEERS
                .replace(
                    " address-family",
                    " neighbor 192.0.2.6 remote-as 65002\n neighbor 192.0.2.6 description up2\n \
             neighbor 192.0.2.6 password k3y\n address-family",
                )
                .replace(
                    "  neighbor 192.0.2.2 activate\n",
                    "  neighbor 192.0.2.2 activate\n  neighbor 192.0.2.6 activate\n",
                ),
        );
        assert_eq!(
            diff(&a, &b),
            [
                "router bgp 65000",
                " no neighbor 192.0.2.6 remote-as 65002",
                "exit"
            ]
        );
        // Changing one neighbor types that neighbor's lines only.
        let c = conf(&TWO_PEERS.replace("maximum-prefix 100", "maximum-prefix 200 warning-only"));
        assert_eq!(
            diff(&b, &c),
            [
                "router bgp 65000",
                " address-family ipv4 unicast",
                "  neighbor 192.0.2.2 maximum-prefix 200 warning-only",
                " exit-address-family",
                "exit",
            ]
        );
    }

    #[test]
    fn segment_routing_goes_off_in_reverse_and_sids_change_in_place() {
        let off = conf("router ospf\n ospf router-id 10.0.0.1\nexit\n");
        let on = conf(
            "router ospf\n ospf router-id 10.0.0.1\n capability opaque\n router-info area\n segment-routing on\n\n segment-routing prefix 10.255.0.1/32 index 1\nexit\n",
        );
        // On: in the render's order.
        assert_eq!(
            diff(&off, &on),
            [
                "router ospf",
                " capability opaque",
                " router-info area",
                " segment-routing on",
                " segment-routing prefix 10.255.0.1/32 index 1",
                "exit"
            ]
        );
        // Off: the prefixes before SR, SR before its opaque LSAs.
        assert_eq!(
            diff(&on, &off),
            [
                "router ospf",
                " no segment-routing prefix 10.255.0.1/32 index 1",
                " no segment-routing on",
                " no router-info area",
                " no capability opaque",
                "exit"
            ]
        );
        // A new index is typed over the old one (FRR updates it in place).
        let moved = conf(
            "router ospf\n ospf router-id 10.0.0.1\n capability opaque\n router-info area\n segment-routing on\n segment-routing prefix 10.255.0.1/32 index 7 explicit-null\n segment-routing global-block 20000 27999\nexit\n",
        );
        assert_eq!(
            diff(&on, &moved),
            [
                "router ospf",
                " segment-routing prefix 10.255.0.1/32 index 7 explicit-null",
                " segment-routing global-block 20000 27999",
                "exit"
            ]
        );
    }

    #[test]
    fn ospf_keys_are_masked_for_logs() {
        assert_eq!(redact("key-string s3cret"), "key-string ***");
        assert_eq!(
            redact("ip ospf authentication-key abc"),
            "ip ospf authentication-key ***"
        );
        assert_eq!(
            redact("ip ospf message-digest-key 1 md5 abc"),
            "ip ospf message-digest-key 1 md5 ***"
        );
        assert_eq!(
            redact("ipv6 ospf6 authentication key-id 1 hash-algo hmac-sha-256 key abc"),
            "ipv6 ospf6 authentication key-id 1 hash-algo hmac-sha-256 key ***"
        );
        assert_eq!(
            redact("ip ospf authentication key-chain CR-T1"),
            "ip ospf authentication key-chain CR-T1"
        );
        assert_eq!(redact("key 1"), "key 1");
    }

    #[test]
    fn secrets_are_masked_for_logs() {
        assert_eq!(
            redact("neighbor 192.0.2.6 password k3y"),
            "neighbor 192.0.2.6 password ***"
        );
        assert_eq!(redact("bgp router-id 1.1.1.1"), "bgp router-id 1.1.1.1");
    }

    #[test]
    fn hostile_text_is_refused_not_panicked_on() {
        let long = "x".repeat(MAX_LINE + 1);
        assert_eq!(Conf::parse(&long), Err(ParseError::LongLine(1)));
        let deep: String = (0..20)
            .map(|i| format!("{}a{i}\n", " ".repeat(i)))
            .collect();
        assert_eq!(Conf::parse(&deep), Err(ParseError::TooDeep(9)));
        // Dedent past the root, tabs, lone markers: still a tree.
        assert!(Conf::parse("   a\n b\nexit\n\t c\n!\n").is_ok());
    }

    #[test]
    fn overwrite_keys() {
        assert_eq!(
            overwrite_key("bgp router-id 1.1.1.1").as_deref(),
            Some("bgp router-id")
        );
        assert_eq!(
            overwrite_key("neighbor 1.1.1.1 route-map X in").as_deref(),
            Some("neighbor 1.1.1.1 route-map in")
        );
        assert_eq!(overwrite_key("neighbor 1.1.1.1 activate"), None);
        assert_eq!(overwrite_key("bgp router-idx"), None);
    }
}
