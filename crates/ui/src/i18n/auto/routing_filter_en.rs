//! English explanations of the Routing › Filters window (G3.2b), sorted by
//! key (registered by `build.rs`).

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    (r##"bgp.param.input_filter"##, r##"## What it is
RouterOS `input.filter`: the `/routing filter` chain the routes received from this neighbor go through. eBGP without one accepts nothing (RFC 8212)."##),
    (r##"bgp.param.keep_received"##, r##"## What it is
Keep the routes the neighbor sends before the input chain (FRR `soft-reconfiguration inbound`, as RouterOS keeps rejected routes): the filter preview runs on them, and a new input chain applies without asking the neighbor again.

## Cost
One more copy of each received route in memory. Unset: yes."##),
    (r##"bgp.param.output_filter"##, r##"## What it is
RouterOS `output.filter-chain`: the chain the routes sent to this neighbor go through. eBGP without one sends nothing (RFC 8212)."##),
    (r##"filter.community_list"##, r##"## What it is
A named list of communities, normal and large."##),
    (r##"filter.community_list.communities"##, r##"## What it is
Normal communities (RFC 1997: `65000:100`, or `no-export`, `no-advertise`, `blackhole`, `graceful-shutdown`…) and large ones (RFC 8092: `65000:1:2`)."##),
    (r##"filter.impact"##, r##"## What it is
What committing the pending changes does to the routes of each connection, measured on the same routes the Preview uses: prefixes withdrawn from (or no longer accepted from) a neighbor, new ones, and attributes changed."##),
    (r##"filter.list.name"##, r##"## What it is
The list's name, as rules write it (`dst in NAME`, `any-list NAME`)."##),
    (r##"filter.list.used_by"##, r##"## What it is
The chains whose rules use this list. A list in use cannot be removed or renamed."##),
    (r##"filter.prefix_list"##, r##"## What it is
A named prefix list. Entries are separated by commas or new lines."##),
    (r##"filter.prefix_list.entries"##, r##"## What it is
Prefixes with an optional length range (FRR/Cisco form): `10.0.0.0/8` matches only that prefix; `10.0.0.0/8 le 24` it and its more specifics up to /24; `0.0.0.0/0 ge 25` any IPv4 prefix /25 or longer."##),
    (r##"filter.preview.as_path"##, r##"## What it is
The route's AS path, the neighbor first."##),
    (r##"filter.preview.before"##, r##"## What it is
What the policy in force (the committed one) does to the same route. A different verdict is a change your commit makes."##),
    (r##"filter.preview.change"##, r##"## What it is
What the chain changes in the route: LOCAL_PREF, MED, prepends, communities added (+) or removed (-)."##),
    (r##"filter.preview.connection"##, r##"## What it is
The BGP connection whose routes are previewed, with its chain for the direction. Empty: the chain alone, on the sample."##),
    (r##"filter.preview.direction"##, r##"## What it is
`in`: the routes the neighbor sends, through the Input Filter. `out`: this router's routes, through the Output Filter, before they are sent."##),
    (r##"filter.preview.prefix"##, r##"## What it is
The route's prefix."##),
    (r##"filter.preview.verdict"##, r##"## What it is
What the chain does to the route: accept or reject."##),
    (r##"filter.rfc8212"##, r##"## What it is
RFC 8212: an eBGP session without a policy accepts no route and sends none, so a router does not leak or accept a full table by mistake. FRR enforces it (`bgp ebgp-requires-policy`).

## What to do
Write the chains (Rules), then set the connection's Input Filter and Output Filter (Routing › BGP › Connections, page Filters). To accept everything on purpose, a chain with one rule `accept`."##),
    (r##"filter.rule"##, r##"## What it is
One rule in the RouterOS v7 language: `if (dst in bogons || dst-len > 24) { reject }`, `if (bgp-as-path "^64500_") { set bgp-local-pref 200; accept }`. The preview below counts how many routes the chain passes with this change.

## Language
Matchers: `dst in|==|!=`, `dst-len`, `afi`, `protocol`, `bgp-as-path` (FRR/Cisco regex, `_` is a separator), `bgp-communities` and `bgp-large-communities` with `includes`, `any`, `equal` (and `-list`). Joined with `&&`, `||`, `not`, parentheses. Actions: `accept`, `reject`, `return`, `jump CHAIN`, `set bgp-local-pref|bgp-med|bgp-path-prepend|bgp-communities|bgp-large-communities`, `append …`, `delete …`."##),
    (r##"filter.rule.actions"##, r##"## What it is
What the rule does: green accepts, red rejects, blue changes an attribute."##),
    (r##"filter.rule.chain"##, r##"## What it is
The chain the rule belongs to. Connections name chains in Input Filter and Output Filter; `jump` runs another chain and comes back. Letters, digits, `-`, `_`, `.`."##),
    (r##"filter.rule.disabled"##, r##"## What it is
A disabled rule stays in the list and is skipped."##),
    (r##"filter.rule.matches"##, r##"## What it is
What the rule tests (`dst`, `dst-len`, `bgp-as-path`, `bgp-communities`…)."##),
    (r##"filter.rule.position"##, r##"## What it is
The rule's place: chains run their rules in this order. Move a rule with the arrows."##),
    (r##"filter.rule.rule"##, r##"## What it is
The rule itself. An error says the column and suggests the word you meant."##),
    (r##"filter.tab.community_lists"##, r##"## What it is
Named community lists for `bgp-communities any-list NAME` (and `includes-list`, `equal-list`), and for `delete bgp-communities NAME`. Normal (RFC 1997, `65000:100`, `no-export`) and large (RFC 8092, `65000:1:2`) communities can share a list."##),
    (r##"filter.tab.prefix_lists"##, r##"## What it is
Named prefix lists for `dst in NAME`. Each entry is a prefix with an optional length range: `10.0.0.0/8` (exactly it), `10.0.0.0/8 le 24`, `0.0.0.0/0 ge 25`."##),
    (r##"filter.tab.preview"##, r##"## What it is
Which routes a chain lets through, on the routes of a connection: in the virtual lab a reproducible sample (a full-table shape plus bogons, a default route and too-long prefixes); with FRR the routes the neighbor really sent (in) or this router's best routes (out). The pending changes are compared with the policy in force."##),
    (r##"filter.tab.rules"##, r##"## What it is
The rules of `/routing filter` (RouterOS v7), in order. A rule belongs to a chain; a BGP connection runs its received routes through its Input Filter chain and its sent routes through its Output Filter chain. Rules run top to bottom; `accept` and `reject` end the chain, and a route no rule accepts is rejected."##),
    (r##"menu.routing-filters"##, r##"## What it does
Route policy (RouterOS v7 `/routing filter`): rules in chains, prefix and community lists, and the preview of which routes pass. A BGP connection names its input and output chains; eBGP without them accepts and sends nothing (RFC 8212)."##),
];
