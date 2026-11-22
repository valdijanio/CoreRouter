//! English explanations of the Subscriber Notices window (G4.10), sorted
//! by key (registered by `build.rs`).

/// Explanations: (key, Markdown).
pub(super) const HELP: &[(&str, &str)] = &[
    (r##"menu.subscriber-notice"##, r##"## What it does
The ISP's block and notice page. A **profile** ties a firewall address list to a mode: **block** (only DNS, the page and the walled garden pass; the rest is refused at once), **notice** (normal internet; the device's own "Sign in to network" until the page is seen) or **throttle** (notice plus a lower rate). The router answers each OS's plain-HTTP captive-portal probe, so the page shows with no certificate error, for app-only users and behind the customer's router."##),
    (r##"subscriber-notice.active.seen"##, r##"## Seen
Whether (and how long ago) the subscriber saw the page."##),
    (r##"subscriber-notice.active.source"##, r##"## Source
**static:** a config address-list entry. **dynamic:** put there by RADIUS, PPP, DHCP or the API, with a timeout."##),
    (r##"subscriber-notice.garden"##, r##"## Walled Garden
What a blocked subscriber still reaches: the ISP's site, the PIX page, the boleto. Domains are resolved by the router's own DNS every 5 minutes; prefixes pass as they are. Start empty."##),
    (r##"subscriber-notice.garden.addresses"##, r##"## Addresses
How many addresses the router's DNS resolved for the entry now."##),
    (r##"subscriber-notice.garden.dst_address"##, r##"## Dst. Address
An address or prefix let through as it is."##),
    (r##"subscriber-notice.garden.dst_host"##, r##"## Dst. Host
A domain (`pix.bank.example`); the router resolves it and lets its addresses through."##),
    (r##"subscriber-notice.log"##, r##"## Log
Every page view with the OS probe that brought the subscriber, the login and the browser: proof of notice. `timeout`: the notice ended unseen."##),
    (r##"subscriber-notice.log.via"##, r##"## Via
What brought the subscriber: an OS probe (`android`, `apple`, `windows`, `firefox`, `linux`…), `browser`, `continue` or `timeout`."##),
    (r##"subscriber-notice.page.button_text"##, r##"## Button Text
The main button's text."##),
    (r##"subscriber-notice.page.button_url"##, r##"## Button URL
Where the button goes (`{link_pix}`); http(s) only, in the walled garden."##),
    (r##"subscriber-notice.page.color"##, r##"## Color
Header and button color, `#rrggbb`."##),
    (r##"subscriber-notice.page.continue_text"##, r##"## Continue Text
Notice pages: the link that marks the page seen."##),
    (r##"subscriber-notice.page.logo_url"##, r##"## Logo URL
An `https://` logo; it must be in the walled garden."##),
    (r##"subscriber-notice.page.text"##, r##"## Text
The body; a blank line splits paragraphs. Variables: `{login}` `{plano}` `{valor}` `{vencimento}` `{link_pix}` `{endereco}` `{perfil}`."##),
    (r##"subscriber-notice.page.title"##, r##"## Title
The page's heading and browser title; variables allowed."##),
    (r##"subscriber-notice.pages"##, r##"## Page
The page the subscriber sees, served by the router. The built-in one is read only: copy it as a new page."##),
    (r##"subscriber-notice.portal"##, r##"## Portal
The page's server on the router (port 8880): it answers each OS probe, shows the page and logs the view. DHCP option 114 (RFC 8910) only with an https `capport_url` and a valid certificate."##),
    (r##"subscriber-notice.profile"##, r##"## What it is
What happens to the members of an address list: block with a page, notice, or throttle. One profile per list."##),
    (r##"subscriber-notice.profile.address_list"##, r##"## Address List
The firewall list whose members get the profile; RADIUS (`Mikrotik-Address-List`), PPP profiles, DHCP leases and the API fill it. Lists starting with `sn-` are the router's."##),
    (r##"subscriber-notice.profile.behaviour"##, r##"## Behaviour
What a member gets, in a few words, as the router computes it."##),
    (r##"subscriber-notice.profile.intercept"##, r##"## Intercept
What port 80 goes to the page: **probes** (only the OS captive-portal probes) or **http** (every plain-HTTP site). HTTPS is never intercepted."##),
    (r##"subscriber-notice.profile.interval"##, r##"## Interval
Notice and throttle: after seeing the page the subscriber goes free for this long (`1d`)."##),
    (r##"subscriber-notice.profile.kill_connections"##, r##"## Kill Connections
Block: end the subscriber's open connections on entry (they would go on in the fast path)."##),
    (r##"subscriber-notice.profile.mode"##, r##"## Mode
- **block:** only DNS, the page, the walled garden and payment pass; TCP gets a reset, the rest ICMP administratively prohibited.
- **notice:** the internet works; the page shows once per interval.
- **throttle:** notice with the rate cut to Rate Limit."##),
    (r##"subscriber-notice.profile.name"##, r##"## Name
The profile's name (in the log and the webhook)."##),
    (r##"subscriber-notice.profile.page"##, r##"## Page
The page shown; empty: the built-in one."##),
    (r##"subscriber-notice.profile.rate_limit"##, r##"## Rate Limit
Throttle: the subscriber's rate while in the list, RouterOS `rx/tx` (`1M/1M`), as a dynamic queue."##),
    (r##"subscriber-notice.profile.timeout"##, r##"## Timeout
Notice and throttle: if the page is not seen within this, the notice ends by itself (0: never)."##),
    (r##"subscriber-notice.profile.webhook"##, r##"## Webhook
POST a JSON event to the ISP's system when a subscriber enters or leaves the list (WhatsApp, SMS, e-mail: TVs and IoT show no page)."##),
    (r##"subscriber-notice.test"##, r##"## Test as Client
What an address gets now: its profile, DNS, port 80 to the page, HTTPS refused or not, each OS probe's answer, and why it would not work."##),
];
