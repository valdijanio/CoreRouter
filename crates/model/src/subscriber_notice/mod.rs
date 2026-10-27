//! `/ip subscriber-notice` (G4.10): the block and notice page of an ISP.
//! A profile ties a firewall address list to a mode (block, notice,
//! throttle); whoever is in the list is sent to the router's own portal
//! page, found through the captive-portal probe of their OS
//! ([`probes`]). RouterOS has no such menu (ISPs build it by hand with
//! address lists and `dst-nat`); the names follow its style. Design and
//! research: `docs/subscriber-notices.md`.

pub mod probes;

use std::fmt::Write as _;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::firewall::Name;
use crate::types::ItemId;

pub const MAX_PROFILES: usize = 32;
pub const MAX_GARDEN: usize = 512;
pub const MAX_PAGES: usize = 32;
pub const MAX_LOGINS: usize = 200_000;
/// Bytes of a page's text and of each other page field.
pub const MAX_TEXT: usize = 8192;
pub const MAX_FIELD: usize = 512;
/// The portal's default port (an unprivileged one no other service of the
/// router uses).
pub const DEFAULT_PORT: u16 = 8880;
/// Address lists the feature fills itself start with this.
pub const RESERVED_PREFIX: &str = "sn-";
/// The walled garden's resolved addresses.
pub const GARDEN_LIST: &str = "sn-garden";
/// The probe hosts' resolved addresses.
pub const PROBE_LIST: &str = "sn-probe";
/// Template variables, as `{name}` in a page.
pub const VARS: &[&str] = &[
    "login",
    "plano",
    "valor",
    "vencimento",
    "link_pix",
    "endereco",
    "perfil",
];

/// The list of those who already saw profile `profile`'s page.
pub fn seen_list(profile: &Name) -> String {
    let mut s = format!("{RESERVED_PREFIX}seen-{profile}");
    s.truncate(Name::MAX);
    s
}

fn is_false(b: &bool) -> bool {
    !*b
}

fn is_true(b: &bool) -> bool {
    *b
}

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Only DNS, the portal and the walled garden pass; the rest is
    /// refused at once (TCP RST, ICMP administratively prohibited).
    #[default]
    Block,
    /// Normal internet; the OS probes go to the page until it is seen.
    Notice,
    /// Like notice, with the rate cut by a dynamic queue.
    Throttle,
}

impl Mode {
    pub const ALL: [Self; 3] = [Self::Block, Self::Notice, Self::Throttle];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Block => "block",
            Self::Notice => "notice",
            Self::Throttle => "throttle",
        }
    }

    pub fn parse(t: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|m| m.as_str() == t.trim())
    }
}

/// What port-80 traffic is sent to the page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Intercept {
    /// Only the OS probes (to the probe hosts' addresses).
    Probes,
    /// Every plain-HTTP request (the probes included).
    Http,
}

impl Intercept {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Probes => "probes",
            Self::Http => "http",
        }
    }

    pub fn parse(t: &str) -> Option<Self> {
        match t.trim() {
            "probes" => Some(Self::Probes),
            "http" => Some(Self::Http),
            _ => None,
        }
    }

    /// The default of a mode: a block catches everything, a notice only
    /// the probes (the internet keeps working).
    pub fn default_for(mode: Mode) -> Self {
        match mode {
            Mode::Block => Self::Http,
            Mode::Notice | Mode::Throttle => Self::Probes,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub id: ItemId,
    pub name: Name,
    pub mode: Mode,
    /// The firewall address list whose members get this profile.
    pub address_list: Name,
    /// The page shown (a page's name; empty: the built-in one).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub page: String,
    pub intercept: Intercept,
    /// Notice and throttle: show the page again after this long.
    pub interval_secs: u64,
    /// Notice and throttle: stop sending to the page after this long
    /// without it being seen (0: never stop).
    pub timeout_secs: u64,
    /// Throttle: RouterOS rate-limit `rx/tx` (`1M/1M`).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub rate_limit: String,
    /// Block: end the subscriber's open connections when it enters the
    /// list (an established one would go on in the fast path).
    #[serde(default = "yes", skip_serializing_if = "is_true")]
    pub kill_connections: bool,
    /// Call the settings' webhook when a subscriber enters the list.
    #[serde(default = "yes", skip_serializing_if = "is_true")]
    pub webhook: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub disabled: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub comment: String,
}

impl Profile {
    pub fn new(id: ItemId, name: Name, mode: Mode, address_list: Name) -> Self {
        Self {
            id,
            name,
            mode,
            address_list,
            page: String::new(),
            intercept: Intercept::default_for(mode),
            interval_secs: 86_400,
            timeout_secs: 3600,
            rate_limit: String::new(),
            kill_connections: true,
            webhook: true,
            disabled: false,
            comment: String::new(),
        }
    }

    /// The Behaviour column: what a member gets, in a few words.
    pub fn behaviour(&self) -> String {
        let mut s = match self.mode {
            Mode::Block => "only DNS, portal and walled garden; rest refused".to_owned(),
            Mode::Notice => format!("page every {}", duration(self.interval_secs)),
            Mode::Throttle => format!(
                "{} and page every {}",
                if self.rate_limit.is_empty() { "no rate set" } else { &self.rate_limit },
                duration(self.interval_secs)
            ),
        };
        if self.mode != Mode::Block && self.intercept == Intercept::Http {
            s.push_str(", all HTTP");
        }
        s
    }
}

/// `1d`, `6h`, `30m`, `45s`.
pub fn duration(secs: u64) -> String {
    let mut out = String::new();
    for (unit, n) in [("d", 86_400), ("h", 3600), ("m", 60)] {
        if secs >= n && secs.is_multiple_of(n) {
            let _ = write!(out, "{}{unit}", secs / n);
            return out;
        }
    }
    format!("{secs}s")
}

/// One walled-garden entry: a domain the router resolves, or a prefix.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GardenEntry {
    pub id: ItemId,
    /// `pix.banco.com.br` (resolved by the router's DNS).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub dst_host: String,
    /// A prefix allowed as is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dst_address: Option<IpNet>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub disabled: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub comment: String,
}

/// Why `host` cannot be a walled-garden domain.
pub fn host_problem(host: &str) -> Option<String> {
    let shown: String = host.chars().take(64).collect();
    let ok = !host.is_empty()
        && host.len() <= 253
        && host.split('.').count() >= 2
        && host.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
    (!ok).then(|| format!("'{shown}' is not a domain name (letters, digits, '-', with a dot)"))
}

/// An editable page: the built-in layout with the operator's texts.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Page {
    pub id: ItemId,
    pub name: String,
    pub title: String,
    /// Body text; blank lines split paragraphs; `{vars}` are filled.
    pub text: String,
    /// Main color, `#rrggbb`.
    pub color: String,
    /// `https://…` logo (an image the walled garden must let through).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub logo_url: String,
    /// The button: label and target (`{link_pix}` is typical).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub button_text: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub button_url: String,
    /// Notice pages: the "continue" link that marks the page as seen.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub continue_text: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub comment: String,
}

impl Page {
    /// The page used when a profile names none.
    pub fn builtin() -> Self {
        Self {
            id: ItemId(0),
            name: "default".into(),
            title: "Aviso do seu provedor".into(),
            text: "Olá, {login}.\n\nIdentificamos uma pendência no seu plano {plano}: {valor}, \
                   vencida em {vencimento}.\n\nPague pelo PIX ou boleto e o acesso volta \
                   sozinho em alguns minutos."
                .into(),
            color: "#1565c0".into(),
            logo_url: String::new(),
            button_text: "Pagar com PIX".into(),
            button_url: "{link_pix}".into(),
            continue_text: "Continuar navegando".into(),
            comment: String::new(),
        }
    }

    pub fn problem(&self) -> Option<String> {
        if self.name.is_empty() || self.name.len() > 63 {
            return Some("name: 1..=63 characters".into());
        }
        if self.text.len() > MAX_TEXT {
            return Some(format!("text: at most {MAX_TEXT} bytes"));
        }
        for (k, v) in [
            ("title", &self.title),
            ("logo_url", &self.logo_url),
            ("button_text", &self.button_text),
            ("button_url", &self.button_url),
            ("continue_text", &self.continue_text),
        ] {
            if v.len() > MAX_FIELD {
                return Some(format!("{k}: at most {MAX_FIELD} bytes"));
            }
        }
        if !is_color(&self.color) {
            return Some("color: #rrggbb".into());
        }
        if !self.logo_url.is_empty() && !self.logo_url.starts_with("https://") && !self.logo_url.starts_with("http://") {
            return Some("logo_url: http:// or https://".into());
        }
        if let Some(v) = unknown_var(&self.text).or_else(|| unknown_var(&self.button_url)).or_else(|| unknown_var(&self.title)) {
            return Some(format!("unknown variable {{{v}}} (known: {})", VARS.join(", ")));
        }
        None
    }
}

fn is_color(c: &str) -> bool {
    c.len() == 7 && c.starts_with('#') && c.bytes().skip(1).all(|b| b.is_ascii_hexdigit())
}

/// The first `{name}` in `t` that is not a known variable.
fn unknown_var(t: &str) -> Option<String> {
    let mut rest = t;
    while let Some(i) = rest.find('{') {
        let after = rest.get(i + 1..)?;
        let j = after.find('}')?;
        let name = after.get(..j)?;
        if !VARS.contains(&name) {
            return Some(name.chars().take(32).collect());
        }
        rest = after.get(j + 1..)?;
    }
    None
}

/// A PPP login sent to a profile ("Block (com página)" on a secret): the
/// address of its session joins the profile's list while it is up.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Login {
    pub login: String,
    pub profile: Name,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    /// The portal's TCP port on the router (the redirect target).
    pub port: u16,
    /// The name in the probe's redirect (`aviso.provedor.com.br`); empty:
    /// the router's address on the subscriber's side.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub portal_host: String,
    /// RFC 8908 API URI, `https://` with a valid certificate for its name;
    /// when set, DHCP option 114 and RA option 37 announce it (RFC 8910).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub capport_url: String,
    /// Called (POST, JSON) when a subscriber enters a profile's list.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub webhook_url: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            port: DEFAULT_PORT,
            portal_host: String::new(),
            capport_url: String::new(),
            webhook_url: String::new(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SubscriberNotices {
    #[serde(skip_serializing_if = "Settings::is_default")]
    pub settings: Settings,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub profiles: Vec<Profile>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub walled_garden: Vec<GardenEntry>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub pages: Vec<Page>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub logins: Vec<Login>,
    pub next_id: u32,
}

impl Settings {
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

impl SubscriberNotices {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    pub fn next_id(&mut self) -> ItemId {
        self.next_id = self.next_id.saturating_add(1);
        ItemId(self.next_id)
    }

    /// Profiles that act (enabled).
    pub fn active(&self) -> impl Iterator<Item = &Profile> {
        self.profiles.iter().filter(|p| !p.disabled)
    }

    pub fn profile(&self, name: &str) -> Option<&Profile> {
        self.profiles.iter().find(|p| p.name.as_str() == name)
    }

    /// The page of `p`: its own, or the built-in one.
    pub fn page_of(&self, p: &Profile) -> Page {
        self.pages
            .iter()
            .find(|x| x.name == p.page)
            .cloned()
            .unwrap_or_else(Page::builtin)
    }

    pub fn problem(&self) -> Option<String> {
        if self.profiles.len() > MAX_PROFILES {
            return Some(format!("at most {MAX_PROFILES} profiles"));
        }
        if self.walled_garden.len() > MAX_GARDEN {
            return Some(format!("at most {MAX_GARDEN} walled-garden entries"));
        }
        if self.pages.len() > MAX_PAGES {
            return Some(format!("at most {MAX_PAGES} pages"));
        }
        if self.logins.len() > MAX_LOGINS {
            return Some(format!("at most {MAX_LOGINS} logins"));
        }
        if self.settings.port == 0 {
            return Some("port: 1..65535".into());
        }
        for p in &self.profiles {
            if p.address_list.as_str().starts_with(RESERVED_PREFIX) {
                return Some(format!("profile {}: lists starting with {RESERVED_PREFIX} are the router's", p.name));
            }
            if !p.page.is_empty() && !self.pages.iter().any(|x| x.name == p.page) {
                return Some(format!("profile {}: no page '{}'", p.name, p.page));
            }
            if p.mode == Mode::Throttle && p.rate_limit.is_empty() {
                return Some(format!("profile {}: a throttle needs rate_limit", p.name));
            }
        }
        for (i, p) in self.profiles.iter().enumerate() {
            let later = self.profiles.iter().skip(i + 1);
            for q in later {
                if q.name == p.name {
                    return Some(format!("two profiles named {}", p.name));
                }
                if q.address_list == p.address_list && !p.disabled && !q.disabled {
                    return Some(format!(
                        "profiles {} and {} use the same address list {}",
                        p.name, q.name, p.address_list
                    ));
                }
            }
        }
        self.pages.iter().find_map(|p| p.problem().map(|m| format!("page {}: {m}", p.name)))
    }
}

/// HTML-escape `t` (text and attribute values).
pub fn escape(t: &str) -> String {
    let mut o = String::with_capacity(t.len());
    for c in t.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            c if c.is_control() && c != '\n' => {}
            c => o.push(c),
        }
    }
    o
}

/// `t` with every `{var}` replaced by its value in `vars` (missing: `—`).
pub fn fill(t: &str, vars: &dyn Fn(&str) -> Option<String>) -> String {
    let mut out = String::with_capacity(t.len());
    let mut rest = t;
    while let Some(i) = rest.find('{') {
        out.push_str(rest.get(..i).unwrap_or_default());
        let after = rest.get(i + 1..).unwrap_or_default();
        match after.find('}') {
            Some(j) if VARS.contains(&after.get(..j).unwrap_or_default()) => {
                let name = after.get(..j).unwrap_or_default();
                out.push_str(&vars(name).unwrap_or_else(|| "—".into()));
                rest = after.get(j + 1..).unwrap_or_default();
            }
            _ => {
                out.push('{');
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// A safe link target: http(s) only (a `javascript:` filled in from a
/// variable never reaches the page).
fn safe_url(u: &str) -> Option<&str> {
    let u = u.trim();
    (u.starts_with("https://") || u.starts_with("http://")).then_some(u)
}

/// The page as HTML, self-contained (no external CSS or script: a blocked
/// subscriber reaches nothing else), `continue_href` for notice pages.
pub fn render(page: &Page, vars: &dyn Fn(&str) -> Option<String>, continue_href: Option<&str>) -> String {
    let title = escape(&fill(&page.title, vars));
    let color = if is_color(&page.color) { page.color.as_str() } else { "#1565c0" };
    let mut body = String::new();
    for para in fill(&page.text, vars).split("\n\n") {
        let para = para.trim();
        if !para.is_empty() {
            let _ = write!(body, "<p>{}</p>", escape(para).replace('\n', "<br>"));
        }
    }
    let logo = safe_url(&page.logo_url)
        .map(|u| format!("<img src=\"{}\" alt=\"\" class=\"logo\">", escape(u)))
        .unwrap_or_default();
    let button = match (page.button_text.is_empty(), safe_url(&fill(&page.button_url, vars))) {
        (false, Some(u)) => format!("<a class=\"btn\" href=\"{}\">{}</a>", escape(u), escape(&page.button_text)),
        _ => String::new(),
    };
    let cont = match continue_href {
        Some(h) if !page.continue_text.is_empty() => {
            format!("<a class=\"cont\" href=\"{}\">{}</a>", escape(h), escape(&page.continue_text))
        }
        _ => String::new(),
    };
    format!(
        "<!doctype html><html lang=\"pt-BR\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
<title>{title}</title><style>\
body{{margin:0;font-family:system-ui,sans-serif;background:#f4f6f8;color:#1b1f24}}\
main{{max-width:34rem;margin:0 auto;padding:1.5rem 1rem}}\
header{{background:{color};color:#fff;padding:1rem}}\
h1{{font-size:1.4rem;margin:0}}.logo{{max-height:3rem;display:block;margin-bottom:.5rem}}\
p{{line-height:1.5}}.btn{{display:block;text-align:center;background:{color};color:#fff;\
padding:.9rem;border-radius:.5rem;text-decoration:none;font-weight:600;margin:1.5rem 0}}\
.cont{{display:block;text-align:center;color:{color}}}\
</style></head><body><header>{logo}<h1>{title}</h1></header><main>{body}{button}{cont}</main></body></html>"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(s: &str) -> Name {
        s.parse().unwrap()
    }

    #[test]
    fn defaults_and_behaviour() {
        let p = Profile::new(ItemId(1), name("atraso"), Mode::Block, name("bloqueados"));
        assert_eq!(p.intercept, Intercept::Http);
        assert!(p.behaviour().contains("refused"));
        let n = Profile::new(ItemId(2), name("aviso"), Mode::Notice, name("aviso"));
        assert_eq!(n.intercept, Intercept::Probes);
        assert_eq!(n.behaviour(), "page every 1d");
        assert_eq!(duration(21_600), "6h");
        assert_eq!(duration(90), "90s");
        let v = serde_json::to_value(&p).unwrap();
        assert!(v.get("kill_connections").is_none(), "default not written");
    }

    #[test]
    fn problems() {
        let mut c = SubscriberNotices::default();
        assert!(c.is_empty() && c.problem().is_none());
        c.profiles.push(Profile::new(ItemId(1), name("a"), Mode::Block, name("x")));
        c.profiles.push(Profile::new(ItemId(2), name("b"), Mode::Notice, name("x")));
        assert!(c.problem().unwrap().contains("same address list"));
        c.profiles[1].address_list = name("sn-mine");
        assert!(c.problem().unwrap().contains("router's"));
        c.profiles[1].address_list = name("y");
        c.profiles[1].mode = Mode::Throttle;
        assert!(c.problem().unwrap().contains("rate_limit"));
        c.profiles[1].rate_limit = "1M/1M".into();
        c.profiles[1].page = "nope".into();
        assert!(c.problem().unwrap().contains("no page"));
        c.profiles[1].page.clear();
        assert_eq!(c.problem(), None);
        let mut p = Page::builtin();
        assert_eq!(p.problem(), None);
        p.text = "{senha}".into();
        assert!(p.problem().unwrap().contains("unknown variable {senha}"));
        p.text.clear();
        p.color = "red".into();
        assert!(p.problem().is_some());
        for bad in ["", "x", "a..b", "-a.b", "a b.c", "*.x.com"] {
            assert!(host_problem(bad).is_some(), "{bad}");
        }
        assert_eq!(host_problem("pix.banco.com.br"), None);
    }

    #[test]
    fn render_escapes_and_fills() {
        let mut p = Page::builtin();
        p.title = "<b>{login}</b>".into();
        p.button_url = "{link_pix}".into();
        let vars = |k: &str| match k {
            "login" => Some("ana<script>".to_owned()),
            "link_pix" => Some("javascript:alert(1)".to_owned()),
            "valor" => Some("R$ 99,90".to_owned()),
            _ => None,
        };
        let html = render(&p, &vars, Some("/seen?t=1"));
        assert!(html.contains("&lt;b&gt;ana&lt;script&gt;&lt;/b&gt;"), "{html}");
        assert!(!html.contains("<script>"));
        assert!(!html.contains("javascript:"), "unsafe link dropped");
        assert!(html.contains("R$ 99,90"));
        assert!(html.contains("vencida em —"), "missing variable");
        assert!(html.contains("href=\"/seen?t=1\""));
        assert!(!html.contains("http-equiv"), "self-contained, no refresh");
        let ok = |k: &str| (k == "link_pix").then(|| "https://pix.example/q?a=1&b=2".to_owned());
        assert!(render(&p, &ok, None).contains("href=\"https://pix.example/q?a=1&amp;b=2\""));
        assert_eq!(fill("{x} {", &|_| None), "{x} {");
        assert_eq!(seen_list(&name("atraso")), "sn-seen-atraso");
    }
}
