//! English explanations of Routing › RPKI (G3.2c), sorted by key
//! (registered by `build.rs`).

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    (r##"rpki"##, r##"## What it is
One RPKI validator (RouterOS `/routing rpki`): the router keeps an RTR session (RFC 8210, or RFC 6810 with an older validator) to it and gets the validated ROA payloads (VRPs). FRR's bgpd keeps its own session to the same validator and drops invalid routes.

## Careful
Adding the first validator turns the policy on: RPKI-invalid routes are rejected on every connection that does not set `rpki_invalid=accept` (`routing.rpki.invalid.set`). RFC 8481 §5 applies policy only with operator configuration; this is that configuration."##),
    (r##"rpki.address"##, r##"## What it is
The validator's address. Run it close to the router (same site or the router itself): RTR has no encryption of its own (RFC 8210 §9 asks for a trusted network)."##),
    (r##"rpki.check"##, r##"## What it is
RouterOS `rpki-check`: the RFC 6811 state of a prefix for an origin AS (or an AS path, whose last AS is the origin), and the VRPs that cover it."##),
    (r##"rpki.disabled"##, r##"## What it is
Kept in the config, no session."##),
    (r##"rpki.error"##, r##"## What it is
Why the last session failed, or the validator's last Error Report (RFC 8210 §12)."##),
    (r##"rpki.expire_interval"##, r##"## What it is
How long the data stays usable without a successful update (RFC 8210 §6: 600..172800, default 7200). After it the VRPs are dropped and every route becomes `unverified` (never blocked)."##),
    (r##"rpki.frr"##, r##"## What it is
bgpd's own RTR state (`show rpki cache-connection`): FRR is what drops invalid routes, so it must be connected too. It needs FRR's rpki module (`frr-rpki-rtrlib`, `bgpd -M rpki`)."##),
    (r##"rpki.group"##, r##"## What it is
The database the validator feeds (RouterOS `group`). Today every enabled validator feeds the one table FRR uses."##),
    (r##"rpki.name"##, r##"## What it is
A name for the validator."##),
    (r##"rpki.policy"##, r##"## What it is
What RPKI does now: on as soon as one validator is enabled. Then each iBGP connection rejects invalid routes (`reject`) unless it says `accept`; eBGP connections accept nothing until they have a policy (RFC 8212), and the RPKI check joins that policy.

A validator that is down never blocks traffic: without data the routes are `unverified` and pass."##),
    (r##"rpki.port"##, r##"## What it is
The RTR port. IANA's is 323; Routinator listens on 3323 by default, StayRTR on 8282."##),
    (r##"rpki.preference"##, r##"## What it is
With several validators, the higher preference is used first (RouterOS). Empty: the lowest address."##),
    (r##"rpki.refresh_interval"##, r##"## What it is
Seconds between polls (Serial Query). Empty: the validator's own, from its End of Data (RFC 8210 §6: 1..86400, default 3600). The validator also notifies changes at once (Serial Notify). FRR polls at most every 3600 s."##),
    (r##"rpki.retry_interval"##, r##"## What it is
Seconds before trying again after a failed poll (RFC 8210 §6: 1..7200, default 600)."##),
    (r##"rpki.serial"##, r##"## What it is
The serial of the data held; each update of the validator raises it, and the router asks only for the difference (Serial Query)."##),
    (r##"rpki.state"##, r##"## What it is
`sync`: the last answer ended with End of Data and the data is in force. `connecting`/`loading`: a query is out. `idle`: waiting to retry. `error`: the last session failed (see Error). `no daemon`: the virtual lab, no RTR client runs."##),
    (r##"rpki.version"##, r##"## What it is
The RTR protocol version spoken: 1 (RFC 8210) or 0 (RFC 6810), negotiated down once when the validator is older (RFC 8210 §7)."##),
    (r##"rpki.vrps"##, r##"## What it is
Validated ROA Payloads held, per family: one ROA can give several (one per prefix and max length)."##),
];
