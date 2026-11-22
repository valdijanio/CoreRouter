//! Routes to subscribers at run time (G4.3cd): who holds each routed
//! block now, shared by the PPPoE and IPoE services and read by the
//! commands. A block goes to one session at a time: the second claim is
//! refused (the first subscriber keeps its traffic; the operator sees why
//! in "Why?" and in the log). The services also check each block against
//! what [`Forbidden`] lists (pools, the router's own addresses).
//!
//! Kept in the [`Session`] as an extension (`FramedTable::of`): one per
//! router, never saved.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, PoisonError, RwLock};

use corerouter_model::Config;
use corerouter_model::radius::Attribute;
use corerouter_model::framed_route::{FramedRoute, RouteOrigin, RouteSet, SessionRoute, overlaps};
use ipnet::IpNet;

use crate::Session;

/// Who holds a block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Holder {
    /// The `ppp.active` id of the session.
    pub session: String,
    pub user: String,
    pub origin: RouteOrigin,
    /// The PPPoE worker of the session (the slow path hands it the
    /// packets to the block); 0 for IPoE.
    pub lane: u16,
    /// `pppoe` or `ipoe`: a service that starts again forgets what it
    /// held (`FramedTable::forget`).
    pub service: &'static str,
}

/// The blocks held now, by session.
#[derive(Debug, Clone, Default)]
pub struct FramedTable(Arc<RwLock<RouteSet<Holder>>>);

impl FramedTable {
    /// The router's table (made on first use).
    pub fn of(s: &mut Session) -> FramedTable {
        s.ext_mut::<FramedTable>().cloned().unwrap_or_default()
    }

    /// Who holds the block with `ip`, if any: the block, its holder.
    pub fn holder_of(&self, ip: IpAddr) -> Option<(IpNet, Holder)> {
        let t = self.0.read().unwrap_or_else(PoisonError::into_inner);
        t.lookup(ip).map(|(n, h)| (*n, h.clone()))
    }

    /// Who holds a block that shares an address with `dst`, other than
    /// session `except`.
    pub fn conflict(&self, dst: &IpNet, except: &str) -> Option<(IpNet, Holder)> {
        let t = self.0.read().unwrap_or_else(PoisonError::into_inner);
        t.overlapping(dst)
            .find(|(_, h)| h.session != except)
            .map(|(n, h)| (*n, h.clone()))
    }

    /// Take `dst` for `h`. `Ok(false)`: `h`'s session had it already (same
    /// block). `Err`: someone else holds an overlapping block.
    pub fn claim(&self, dst: IpNet, h: Holder) -> Result<bool, (IpNet, Holder)> {
        let mut t = self.0.write().unwrap_or_else(PoisonError::into_inner);
        if let Some((n, other)) = t.overlapping(&dst).next() {
            if *n == dst && other.session == h.session {
                return Ok(false);
            }
            return Err((*n, other.clone()));
        }
        let _ = t.insert(dst, h);
        Ok(true)
    }

    /// Give `dst` back, if `session` holds it.
    pub fn release(&self, dst: &IpNet, session: &str) {
        let mut t = self.0.write().unwrap_or_else(PoisonError::into_inner);
        let mine = t
            .overlapping(dst)
            .next()
            .is_some_and(|(n, h)| n == dst && h.session == session);
        if mine {
            t.remove(dst);
        }
    }

    /// Everything `service` held goes (it starts again with no session:
    /// a crash must not leave blocks claimed by sessions that are gone).
    pub fn forget(&self, service: &str) {
        let mut t = self.0.write().unwrap_or_else(PoisonError::into_inner);
        t.retain(|_, h| h.service != service);
    }

    pub fn len(&self) -> usize {
        self.0.read().unwrap_or_else(PoisonError::into_inner).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Space no subscriber route may take: the pools (they lend those
/// addresses to other subscribers) and the router's own addresses.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Forbidden {
    /// (first, last, what): IPv4 pool ranges and IPv6 pools.
    ranges: Vec<(IpAddr, IpAddr, String)>,
    /// The router's addresses.
    own: Vec<(IpAddr, String)>,
}

impl Forbidden {
    pub fn of(cfg: &Config) -> Self {
        let mut ranges = Vec::new();
        for p in &cfg.ip.pools.pools {
            for g in &p.ranges {
                ranges.push((IpAddr::V4(g.start), IpAddr::V4(g.end), format!("pool {}", p.name)));
            }
        }
        for p in &cfg.ipv6.dhcp_server.pools {
            ranges.push((
                IpAddr::V6(p.prefix.network()),
                IpAddr::V6(p.prefix.broadcast()),
                format!("IPv6 pool {}", p.name),
            ));
        }
        let own = cfg
            .ip
            .addresses
            .iter()
            .filter(|a| !a.disabled && a.from_pool.is_none())
            .map(|a| (a.address.addr(), a.interface.to_string()))
            .collect();
        Self { ranges, own }
    }

    /// Why `dst` is not a subscriber's to have, in Portuguese.
    pub fn why(&self, dst: &IpNet) -> Option<String> {
        if let Some((_, _, what)) = self.ranges.iter().find(|(a, b, _)| span_overlaps(dst, *a, *b)) {
            return Some(format!("{dst} sobrepõe o {what}"));
        }
        self.own
            .iter()
            .find(|(ip, _)| dst.contains(ip))
            .map(|(ip, iface)| format!("{dst} contém {ip}, endereço do roteador em {iface}"))
    }
}

fn span_overlaps(n: &IpNet, first: IpAddr, last: IpAddr) -> bool {
    match (n, first, last) {
        (IpNet::V4(n), IpAddr::V4(a), IpAddr::V4(b)) => {
            u32::from(n.network()) <= u32::from(b) && u32::from(a) <= u32::from(n.broadcast())
        }
        (IpNet::V6(n), IpAddr::V6(a), IpAddr::V6(b)) => {
            u128::from(n.network()) <= u128::from(b) && u128::from(a) <= u128::from(n.broadcast())
        }
        _ => false,
    }
}

/// The routes an Access-Accept (or a CoA) carries: every `Framed-Route`
/// (RFC 2865 §5.22) and `Framed-IPv6-Route` (RFC 3162 §2.5), and each
/// `Framed-IPv6-Prefix` after the first (RFC 3162 §2.3: it MAY repeat; the
/// first is the link's /64). The texts that do not parse come back as
/// refusals, in Portuguese.
pub fn from_radius<'a>(
    attrs: impl Iterator<Item = (&'a str, &'a str)>,
) -> (Vec<(FramedRoute, RouteOrigin)>, Vec<String>) {
    let mut want = Vec::new();
    let mut refused = Vec::new();
    let mut prefixes = 0;
    for (name, v) in attrs {
        let origin = match name {
            "Framed-Route" => RouteOrigin::FramedRoute,
            "Framed-IPv6-Route" => RouteOrigin::FramedIpv6Route,
            "Framed-IPv6-Prefix" => {
                prefixes += 1;
                if prefixes == 1 {
                    continue;
                }
                RouteOrigin::FramedIpv6Prefix
            }
            _ => continue,
        };
        if v.trim().is_empty() {
            continue;
        }
        match v.parse::<FramedRoute>() {
            Ok(r) if r.is_v6() != (origin == RouteOrigin::FramedRoute) => {
                want.push((r, origin));
            }
            Ok(r) => refused.push(format!("{}: {r} não é da família do atributo", origin.label())),
            Err(e) => refused.push(format!("{}: {e}", origin.label())),
        }
    }
    (want, refused)
}

/// What one session gets: the routes installed and why the others not.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Admitted {
    pub routes: Vec<(FramedRoute, RouteOrigin)>,
    pub refused: Vec<String>,
}

impl Admitted {
    /// For `ppp.active`: the text and the origin of each route.
    pub fn rows(&self) -> Vec<SessionRoute> {
        rows(&self.routes)
    }
}

pub fn rows(routes: &[(FramedRoute, RouteOrigin)]) -> Vec<SessionRoute> {
    routes
        .iter()
        .map(|(r, o)| SessionRoute {
            route: r.to_string(),
            origin: *o,
        })
        .collect()
}

/// Check one route of a session whose IPv4 is `ipv4`: special space, the
/// forbidden space and the gateway (RFC 2865 §5.22: 0.0.0.0 is the user;
/// any other IPv4 gateway must be the user too, PPPoE being point to
/// point). IPv6 gateways are not checked: the session's IPv6 may come after
/// the route, and the route goes to the session anyway. `Err` is why, in
/// Portuguese.
pub fn check(r: &FramedRoute, ipv4: Option<Ipv4Addr>, forbidden: &Forbidden) -> Result<(), String> {
    let dst = r.dst;
    if let Some(why) = r.martian() {
        return Err(format!("{dst}: bloco especial ({why})"));
    }
    if let Some(why) = forbidden.why(&dst) {
        return Err(why);
    }
    if let Some(IpAddr::V4(g)) = r.gateway
        && Some(g) != ipv4
    {
        return Err(format!(
            "{dst}: o gateway {g} não é o assinante ({}); use 0.0.0.0",
            ipv4.map_or_else(|| "sem IPv4".into(), |i| i.to_string())
        ));
    }
    Ok(())
}

/// Install what can be installed of `want` for session `holder` (at most
/// [`MAX_ROUTES`](corerouter_model::framed_route::MAX_ROUTES); IPv6 refused
/// with `v6_refusal` when the service cannot carry it): each route is
/// checked, then claimed in `table`.
pub fn admit(
    table: &FramedTable,
    forbidden: &Forbidden,
    want: &[(FramedRoute, RouteOrigin)],
    holder: &Holder,
    ipv4: Option<Ipv4Addr>,
    v6_refusal: Option<&str>,
) -> Admitted {
    let mut out = Admitted::default();
    for (r, origin) in want {
        if out.routes.len() >= corerouter_model::framed_route::MAX_ROUTES {
            out.refused.push(format!("{}: mais de {} rotas", r.dst, corerouter_model::framed_route::MAX_ROUTES));
            continue;
        }
        if let (true, Some(why)) = (r.is_v6(), v6_refusal) {
            out.refused.push(format!("{}: {why}", r.dst));
            continue;
        }
        if let Some((o, _)) = out.routes.iter().find(|(o, _)| overlaps(&o.dst, &r.dst)) {
            out.refused.push(format!("{}: sobrepõe {} da mesma sessão", r.dst, o.dst));
            continue;
        }
        if let Some(ip) = ipv4
            && r.dst.contains(&IpAddr::V4(ip))
            && r.dst.prefix_len() == 32
        {
            // The session's own /32: already routed to it.
            out.refused.push(format!("{}: é o próprio endereço da sessão", r.dst));
            continue;
        }
        if let Err(why) = check(r, ipv4, forbidden) {
            out.refused.push(why);
            continue;
        }
        let h = Holder {
            origin: *origin,
            ..holder.clone()
        };
        match table.claim(r.dst, h) {
            Ok(_) => out.routes.push((*r, *origin)),
            Err((n, other)) => out.refused.push(format!(
                "{}: sobrepõe {n}, já roteado para {} ({})",
                r.dst,
                other.user,
                other.origin.label()
            )),
        }
    }
    out
}

/// The routes a CoA gives a session: each family present replaces all the
/// session's routes of that family (`Framed-Route ""`: none).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RouteChange {
    pub v4: bool,
    pub v6: bool,
    pub routes: Vec<(FramedRoute, RouteOrigin)>,
    /// Texts that did not parse: the whole change is refused.
    pub invalid: Vec<String>,
}

impl RouteChange {
    /// Whether this change replaces the session's routes of `r`'s family.
    pub fn replaces(&self, r: &FramedRoute) -> bool {
        if r.is_v6() { self.v6 } else { self.v4 }
    }
}

/// The route attributes of a CoA, if it has any: every `Framed-Route`
/// and `Framed-IPv6-Route` (RFC 2865 §5.22, RFC 3162 §2.5), repeated. A
/// family present replaces that family's routes; a value of `""` alone
/// clears it.
pub fn route_change(changes: &[Attribute]) -> Option<RouteChange> {
    let v4 = changes.iter().any(|a| a.name == "Framed-Route");
    let v6 = changes.iter().any(|a| a.name == "Framed-IPv6-Route");
    if !v4 && !v6 {
        return None;
    }
    let (routes, invalid) = from_radius(
        changes
            .iter()
            .filter(|a| a.name != "Framed-IPv6-Prefix")
            .map(|a| (a.name.as_str(), a.value.as_str())),
    );
    Some(RouteChange { v4, v6, routes, invalid })
}

/// Whether session `id` (IPv4 `ip`) may take the routes of `c`: each is
/// valid and no other session holds an overlapping block (RFC 5176 §3.5:
/// checked before the ACK, the whole request or nothing). `Err`: why, in
/// Portuguese.
pub fn check_change(
    table: &FramedTable,
    forbidden: &Forbidden,
    id: &str,
    ip: Option<Ipv4Addr>,
    c: &RouteChange,
) -> Result<(), String> {
    if let Some(why) = c.invalid.first() {
        return Err(why.clone());
    }
    let max = corerouter_model::framed_route::MAX_ROUTES;
    if c.routes.len() > max {
        return Err(format!("mais de {max} rotas"));
    }
    for (k, (r, _)) in c.routes.iter().enumerate() {
        check(r, ip, forbidden)?;
        if let Some((n, h)) = table.conflict(&r.dst, id) {
            return Err(format!("{}: sobrepõe {n}, já roteado para {}", r.dst, h.user));
        }
        if let Some((o, _)) = c.routes.iter().take(k).find(|(o, _)| overlaps(&o.dst, &r.dst)) {
            return Err(format!("{}: sobrepõe {} do mesmo pedido", r.dst, o.dst));
        }
    }
    Ok(())
}

/// Give back every route of a session.
pub fn release_all(table: &FramedTable, routes: &[(FramedRoute, RouteOrigin)], session: &str) {
    for (r, _) in routes {
        table.release(&r.dst, session);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(session: &str, user: &str) -> Holder {
        Holder {
            session: session.into(),
            user: user.into(),
            origin: RouteOrigin::Secret,
            lane: 0,
            service: "pppoe",
        }
    }

    fn r(t: &str) -> FramedRoute {
        t.parse().unwrap()
    }

    #[test]
    fn repeated_attributes_and_families() {
        let attrs = [
            ("Framed-Route", "203.0.113.8/29 0.0.0.0 1"),
            ("Framed-Route", "198.51.100.0/30"),
            ("Framed-IPv6-Prefix", "2001:db8:1:1::/64"),
            ("Framed-IPv6-Prefix", "2001:db8:9::/56"),
            ("Framed-IPv6-Route", "2001:db8:100::/48 :: 1"),
            ("Framed-Route", "2001:db8::/48"),
            ("Framed-IPv6-Route", "garbage"),
            ("Reply-Message", "x"),
        ];
        let (want, refused) = from_radius(attrs.into_iter());
        let origins: Vec<_> = want.iter().map(|(_, o)| o.as_str()).collect();
        assert_eq!(origins, ["framed-route", "framed-route", "framed-ipv6-prefix", "framed-ipv6-route"]);
        assert_eq!(refused.len(), 2, "{refused:?}");
    }

    #[test]
    fn claims_are_exclusive_and_released() {
        let t = FramedTable::default();
        let f = Forbidden::default();
        let want = vec![(r("203.0.113.8/29"), RouteOrigin::FramedRoute), (r("2001:db8:100::/48"), RouteOrigin::FramedIpv6Route)];
        let a = admit(&t, &f, &want, &h("*1-1", "a"), Some("100.64.0.1".parse().unwrap()), None);
        assert_eq!(a.routes.len(), 2);
        // Same session again (a CoA with the same block): no conflict.
        assert_eq!(t.claim(r("203.0.113.8/29").dst, h("*1-1", "a")), Ok(false));
        let b = admit(&t, &f, &[(r("203.0.113.0/28"), RouteOrigin::Secret)], &h("*1-2", "b"), None, None);
        assert!(b.routes.is_empty() && b.refused[0].contains("já roteado para a"), "{b:?}");
        assert_eq!(t.holder_of("203.0.113.9".parse().unwrap()).map(|x| x.1.user), Some("a".into()));
        release_all(&t, &a.routes, "*1-1");
        assert!(t.is_empty());
        // Another session's release does not take what it does not hold.
        let _ = admit(&t, &f, &want, &h("*1-1", "a"), None, None);
        release_all(&t, &a.routes, "*9-9");
        assert_eq!(t.len(), 2);
        t.forget("ipoe");
        assert_eq!(t.len(), 2);
        t.forget("pppoe");
        assert!(t.is_empty());
    }

    #[test]
    fn checks_in_portuguese() {
        let mut cfg = Config::default();
        cfg.ip.pools.pools.push(corerouter_model::ip_pool::IpPool {
            id: corerouter_model::ItemId(1),
            name: "cgnat".into(),
            ranges: vec!["100.64.0.0/22".parse().unwrap()],
            next_pool: None,
            comment: String::new(),
        });
        let f = Forbidden::of(&cfg);
        let t = FramedTable::default();
        let ip = Some("192.0.2.1".parse().unwrap());
        let want = [
            (r("100.64.1.0/29"), RouteOrigin::FramedRoute),
            (r("127.0.0.0/8"), RouteOrigin::FramedRoute),
            (r("203.0.113.8/29 192.0.2.2"), RouteOrigin::FramedRoute),
            (r("203.0.113.16/29 192.0.2.1"), RouteOrigin::FramedRoute),
            (r("203.0.113.20/30"), RouteOrigin::FramedRoute),
            (r("2001:db8::/48"), RouteOrigin::FramedIpv6Route),
        ];
        let a = admit(&t, &f, &want, &h("*1-1", "a"), ip, Some("IPv6 sem XDP"));
        assert_eq!(a.rows().iter().map(|x| x.route.as_str()).collect::<Vec<_>>(), ["203.0.113.16/29 192.0.2.1 1"]);
        let text = a.refused.join("\n");
        for part in ["pool cgnat", "bloco especial", "não é o assinante", "mesma sessão", "sem XDP"] {
            assert!(text.contains(part), "{part}: {text}");
        }
    }
}
