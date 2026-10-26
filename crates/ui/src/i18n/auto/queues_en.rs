//! English explanations of the Queues window (G4.9), sorted by key
//! (registered by `build.rs`).

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    ("menu.queues", "## What it does\nBandwidth per target, as RouterOS `/queue`: Simple Queues (an address, prefix or interface with max upload/download, burst and queue type), Per-IP (PCQ) (the same rate for each address of a network) and Queue Types. Dynamic queues (D) come from PPPoE/IPoE sessions and DHCP leases and networks. Download is shaped (EDT + fq), upload policed; the first matching queue wins."),
    (
        "queues.pcq",
        r##"## What it is
A limit **per address** inside a prefix: "every IP of 10.0.0.0/16 gets 10M/20M". In RouterOS this is PCQ: two `pcq` types (one classified by source for upload, one by destination for download, each with its `pcq-rate`) and a simple queue over the prefix that uses them. This form makes the three in one transaction; types of the same rate are reused.

## When
A network of clients with neither PPPoE nor DHCP rates: a building, a fixed LAN, a simple hotspot. PPPoE/IPoE subscribers already get a queue each from their profile.

## Careful
**Max Limit** caps all addresses together (0 = no cap). Editing or removing the rule is editing or removing its simple queue (Simple Queues tab); the types stay."##,
    ),
    ("queues.pcq.addresses", r##"How many addresses (PCQ sub-streams) went through this rule lately: each gets its own clock, made on its first packet and forgotten when old (LRU). Counted every 10 s."##),
    ("queues.pcq.ipv6_mask", r##"How many bits of an IPv6 address make a sub-stream. **64** (default) = one limit per /64, what one IPv6 client gets; 128 would be per address, and a client with several (privacy addresses, RFC 8981) would escape it."##),
    ("queues.pcq.max_limit", r##"Cap of all addresses together, `upload/download` (0 = no cap): the simple queue behind the rule."##),
    ("queues.pcq.rate", r##"The rate of **each** address, `upload/download` in bits per second (`10M/20M`; k, M and G as in RouterOS). 0 in a direction = no per-address limit there."##),
    ("queues.pcq.target", r##"The prefixes whose addresses each get the limit (`10.0.0.0/16`, `2001:db8::/48`). Prefixes only: an interface does not split into addresses."##),
    (
        "queues.simple",
        r##"## What it is
A queue (RouterOS `/queue simple`): limits the bandwidth of a **target** — addresses, prefixes or one interface. Every pair is `upload/download` from the target's side.

## How CoreRouter holds the rate
- **Download**: what exceeds the rate **waits** (EDT: each packet gets its departure time and the port's `fq` holds it). TCP sees delay, not loss.
- **Upload**: a policer (drops the excess), with a bucket of `bucket-size × rate`.

## Order
As in RouterOS, the **first matching queue wins**: a target inside an earlier queue's target never matches (the form warns). **Dynamic** queues (sessions, DHCP) win over fixed ones on their own addresses.

## Careful
`limit-at` and `priority` are kept, but a queue without children is shaped at its `max-limit` (the queue tree is G4.9e)."##,
    ),
    ("queues.simple.bucket_size", r##"Each direction's bucket as a share of the rate (RouterOS v7): **0.1** (default) = 100 ms of the rate may leave at once after a pause. On the upload policer it is the "burst ≈ RTT × rate" that keeps TCP from being cut (Google, 2016)."##),
    ("queues.simple.burst_limit", r##"Rate while **bursting**, `upload/download`. The burst lasts while the average over `burst-time` is under `burst-threshold` (RouterOS). Must be above `max-limit`; 0 = no burst."##),
    ("queues.simple.burst_threshold", r##"Switches the burst: while the average over `burst-time` is under it, `burst-limit` applies; once reached, `max-limit` again. Best between `limit-at` and `max-limit`; 0 = `max-limit`."##),
    ("queues.simple.burst_time", r##"The window of the **average** that decides the burst (not its duration). RouterOS's example: 1M, burst 2M, threshold 1.5M, 8 s → 6 s at 2M, then 1M. Sampled in 16 slots of `burst-time/16`."##),
    ("queues.simple.disabled", r##"Disabled stays in the config but leaves the data plane: the target goes unlimited (or to the next matching queue)."##),
    ("queues.simple.dropped", r##"Packets this queue dropped both ways: on download, those that would wait past the queue's limit or that CoDel picked; on upload, those over the policer's rate."##),
    ("queues.simple.limit_at", r##"RouterOS's **guaranteed** rate (CIR), `upload/download`. Only takes effect in a queue tree (G4.9e); kept meanwhile. Not above `max-limit`."##),
    ("queues.simple.max_limit", r##"The top rate, `upload/download` in bits per second (`10M/50M`; k = 1000, M, G). One value means both; **0** = no limit that way (the queue only counts)."##),
    ("queues.simple.name", r##"Unique name (default `queue<N>`, as RouterOS). Dynamic queues are named after their origin: `<pppoe-john>`, `dhcp-ds<host or MAC>`."##),
    (
        "queues.simple.origin",
        r##"Where the queue comes from:
- **fixed**: made here (`queue.simple.add`);
- **PPPoE / IPoE**: dynamic, a session with a `rate-limit` (PPP profile or RADIUS `Mikrotik-Rate-Limit`; CoA changes the rate without resetting the queue);
- **DHCP lease**: dynamic, a static lease's `rate_limit`;
- **DHCP network**: dynamic, a DHCP network's `rate_limit` (every client of it; not in RouterOS).

**D** = dynamic: change it where it comes from. A dynamic queue wins over a fixed one on its own address, and both are warned."##,
    ),
    ("queues.simple.priority", r##"Priority 1 (highest) to 8 (lowest, default), `upload/download`. Like `limit-at`, only in a queue tree (G4.9e); kept."##),
    (
        "queues.simple.queue",
        r##"Each direction's **queue type**, `upload/download` (Queue Types tab). On download it decides what to do with what waits:
- `pfifo`/`bfifo`: drop past the limit (RouterOS's `default-small` is a 10-packet FIFO: short above a few Mbit/s);
- `fq-codel`/`cake` (**recommended**): CoDel (RFC 8289) keeps the wait near 5 ms and marks ECN instead of dropping when it can;
- `pcq`: one limit per address inside the target."##,
    ),
    ("queues.simple.queued", r##"How long a packet arriving now would wait on this queue's download, in milliseconds (the delay the queue adds to the client's ping)."##),
    ("queues.simple.rate", r##"Rate over the last second, `upload/download`, from the data plane's counters."##),
    ("queues.simple.target", r##"What the queue limits: IPv4/IPv6 addresses, prefixes and at most one interface (all its traffic), comma-separated. Address targets match before interface ones."##),
    ("queues.tab.pcq", r##"Limits **per address** inside prefixes (RouterOS PCQ): "every IP of 10.0.0.0/16 gets 10M/20M"."##),
    ("queues.tab.simple", r##"Every queue: the fixed ones (in order: the first match wins) and the **dynamic** ones of PPPoE/IPoE sessions and DHCP, with the origin chip, the queue (ms), drops and precedence warnings."##),
    ("queues.tab.types", r##"Queue types (`/queue type`): what a queue does with what waits. The built-ins always exist; editing one keeps a copy."##),
    (
        "queues.type",
        r##"## What it is
A queue type (RouterOS `/queue type`): `pfifo`, `bfifo`, `pcq`, `fq-codel` or `cake`, picked by name by the queues, per direction.

## Recommended
`fq-codel-default` (the dynamic queues' default here; RouterOS uses `default-small`, a 10-packet FIFO). RouterOS's `red`, `sfq` and `codel` are refused: use `fq-codel`."##,
    ),
    ("queues.type.bfifo_limit", r##"FIFO size in **bytes** (default 15000). The shaper turns it into a wait at the queue's rate."##),
    ("queues.type.cake_rtt", r##"CAKE's reference RTT (default 100 ms): its CoDel uses target = RTT/20 and interval = RTT."##),
    ("queues.type.fq_codel_ecn", r##"Mark CE (RFC 3168) on an ECN-capable packet instead of dropping it. On by default, as in RouterOS."##),
    ("queues.type.fq_codel_interval", r##"CoDel's window (default 100 ms, RFC 8289): the wait must stay above target for a whole interval before the first drop."##),
    ("queues.type.fq_codel_target", r##"The acceptable wait (default 5 ms). Must be below the interval (5–10% of it)."##),
    ("queues.type.kind", r##"`pfifo` (packets), `bfifo` (bytes), `pcq` (a limit per address), `fq-codel` (CoDel on the wait, ECN), `cake` (the same CoDel, target and interval from the RTT). On download the EDT shaper sends each packet on time; the type decides when to drop."##),
    ("queues.type.name", r##"The type's name, as queues and PPP profiles use it. Built-ins keep their names."##),
    ("queues.type.pcq_classifier", r##"What makes a PCQ sub-stream: `dst-address` (download) or `src-address` (upload). RouterOS's ports are not used: the shaper splits by address."##),
    ("queues.type.pcq_mask6", r##"Bits of the IPv6 destination that make a sub-stream (128 = each address; 64 = each /64, recommended)."##),
    ("queues.type.pcq_rate", r##"Each sub-stream's rate, bits per second. 0 = sub-streams only share the queue's limit."##),
    ("queues.type.pfifo_limit", r##"FIFO size in **packets** (default 50). Too short drops TCP bursts; too long is bufferbloat."##),
    ("queues.type.settings", r##"The type's parameters at a glance: FIFO limit, PCQ rate and classifier, CoDel target and interval, CAKE RTT."##),
    ("queues.type.used_by", r##"The queues and PPP profiles that use this type. A type in use cannot be removed nor renamed."##),
];
