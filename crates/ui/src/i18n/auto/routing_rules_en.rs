//! English explanations of Routing › Rules (G1.27e), sorted by key
//! (registered by `build.rs`).

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    (r##"kernel"##, r##"## What it is
The kernel's whole rule list, in the order it walks it, with who wrote each line. It shows what the rules became, and rules of other programs, which CoreRouter never removes."##),
    (r##"kernel.marks"##, r##"## What it is
Routing marks of the mangle that do not name a table. They send a packet nowhere by themselves: only a rule with that `routing_mark` uses them. Create a table with that name, or match them in a rule."##),
    (r##"kernel.match"##, r##"## What it is
What the line matches: source, destination, incoming interface, mark, or `l3mdev` for a packet in a VRF."##),
    (r##"kernel.owner"##, r##"## What it is
- `kernel`: the kernel's own.
- `corerouter`: written from this configuration.
- `foreign`: another program or `ip rule`. Left alone, and it can change what the rules decide."##),
    (r##"kernel.priority"##, r##"## What it is
Lower runs first. Rule 0 is the `local` table, the marks of the mangle 100 to 999, the VRFs 1000 and 1001, the rules of this window from 2000, and `main` 32766."##),
    (r##"kernel.rule"##, r##"## What it is
The rule of the Rules tab behind this line."##),
    (r##"kernel.what"##, r##"## What it is
What the line stands for, in words."##),
    (r##"rules"##, r##"## What it is
One policy routing rule (RouterOS `/routing rule`). Rules run top to bottom and the first one that decides wins. A packet to an address of this router never reaches them: the kernel's `local` table comes first.

## Careful
A rule can stop the replies to your own session. The window warns you and asks for confirmation, or use Safe Mode."##),
    (r##"rules.action"##, r##"## What it is
- `lookup`: looks in the table; with no route there, the next rule goes on.
- `lookup-only-in-table`: looks only in that table; with no route there, the packet is unreachable.
- `drop`: discarded silently.
- `unreachable`: discarded, and the sender gets an ICMP unreachable."##),
    (r##"rules.disabled"##, r##"## What it is
Kept in the config, out of the kernel. It keeps its place in the order."##),
    (r##"rules.dst_address"##, r##"## What it is
The destination the packet must have. Empty: any. An address also makes the rule apply to that family only."##),
    (r##"rules.family"##, r##"## What it is
IPv4, IPv6 or both. A rule without addresses applies to both."##),
    (r##"rules.interface"##, r##"## What it is
The interface the packet came in on. `lo` matches this router's own packets. A member of a VRF is refused: the VRF's table answers before any rule, so mark those packets in the mangle instead."##),
    (r##"rules.min_prefix"##, r##"## What it is
Routes of this length or shorter are ignored in the table (Linux's `suppress_prefixlength`). 0 hides the default route: use the table's specific routes, otherwise go on to the next rule."##),
    (r##"rules.order"##, r##"## What it is
The position in the list: rules run in this order. The kernel's priority comes from it."##),
    (r##"rules.routing_mark"##, r##"## What it is
The routing mark a mangle rule set on the packet. A mark with the name of a table already sends the packet there, before any rule; this field is for a mark that does not name a table."##),
    (r##"rules.src_address"##, r##"## What it is
The source the packet must have. Empty: any. A packet of this router without a source chosen yet does not match."##),
    (r##"rules.state"##, r##"## What it is
- `active`: in the kernel.
- `disabled`: out of the kernel.
- `warning`: it does nothing as it stands; the line below the table says why."##),
    (r##"rules.table"##, r##"## What it is
Where to look: `main`, a VRF or a table of the Tables tab. The table needs routes of its own: connected networks stay in `main`, so traffic to a local network often needs a rule to `main` above this one."##),
    (r##"rules.test"##, r##"## What it is
Walks the rules the way the kernel does for a packet with these fields, and shows every rule it matched. The kernel is asked too: a difference shows as a warning, for instance a rule another program added.

With an incoming interface, a source is needed: the kernel refuses to route a packet without one."##),
    (r##"tables"##, r##"## What it is
Named routing tables (RouterOS `/routing table`), plus `main` and the VRFs. Put routes in one with `routing_table` in IP › Routes; a rule or a mangle mark of the same name sends packets there."##),
    (r##"tables.marks"##, r##"## What it is
Mangle rules that mark packets for this table."##),
    (r##"tables.name"##, r##"## What it is
Up to 15 of A-Z a-z 0-9 - _ . It cannot be a name of the kernel's tables nor of a VRF."##),
    (r##"tables.routes"##, r##"## What it is
Static routes in this table."##),
    (r##"tables.rules"##, r##"## What it is
Rules that look in this table."##),
    (r##"tables.table"##, r##"## What it is
The kernel's number for the table, chosen automatically and kept in the config. `ip route show table N` shows it."##),
    (r##"tables.type"##, r##"## What it is
- `main`: the kernel's main table.
- `vrf`: the table of a VRF (IP › VRF changes it).
- `named`: one of this window."##),
];
