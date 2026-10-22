//! Whether the connected router can run a command now, and why not.
//!
//! The engine is the source of truth: `engine.list` says which commands
//! exist on that router and, per command, `enabled` + `disabledReason`. A
//! remote daemon may be an older build than this GUI (G0.4), so a command
//! the GUI knows can be missing there. Every action of the UI asks
//! [`Avail::check`] before it is drawn as clickable, and
//! [`crate::CoreRouterUi::run`] asks again before anything is sent, so a
//! click or a key on a greyed action never reaches the router.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::backend::Link;

/// Characters of a reason taken from the router (it is hostile input).
const MAX_REASON: usize = 200;

/// A snapshot of what the router allows, rebuilt when `engine.list`,
/// `server.info` or the link state change.
#[derive(Debug, Clone, Default)]
pub(crate) struct Avail {
    link: Option<Link>,
    /// Command id → why it is disabled (`None`: enabled). `None` until the
    /// first `engine.list` reply: nothing is blocked for lack of a list.
    commands: Option<BTreeMap<String, Option<String>>>,
    /// "corerouter 0.1.0", from `server.info`.
    server: Option<String>,
}

impl Avail {
    pub(crate) fn new(link: &Link, commands: Option<&[Value]>, server: &Value) -> Self {
        let commands = commands.map(|list| {
            list.iter()
                .filter_map(|c| {
                    let id = c.get("id")?.as_str()?;
                    let why = (c.get("enabled").and_then(Value::as_bool) == Some(false)).then(|| {
                        let why = c.get("disabledReason").and_then(Value::as_str);
                        clip(why.unwrap_or("not available on this router"))
                    });
                    Some((id.to_owned(), why))
                })
                .collect()
        });
        let text = |k: &str| server.get(k).and_then(Value::as_str).map(clip);
        let server = match (text("name"), text("version")) {
            (Some(n), Some(v)) => Some(format!("{n} {v}")),
            (None, Some(v)) => Some(format!("version {v}")),
            _ => None,
        };
        Self {
            link: Some(link.clone()),
            commands,
            server,
        }
    }

    /// `Ok` when command `id` can be sent now, else the reason to show.
    pub(crate) fn check(&self, id: &str) -> Result<(), String> {
        match &self.link {
            Some(Link::Connecting { target }) => {
                return Err(format!("connecting… {target}"));
            }
            Some(Link::Disconnected { target, .. }) => {
                return Err(format!("disconnected: {target}"));
            }
            _ => {}
        }
        let Some(commands) = &self.commands else {
            return Ok(());
        };
        match commands.get(id) {
            Some(None) => Ok(()),
            Some(Some(why)) => Err(why.clone()),
            None => {
                let who = self
                    .server
                    .as_deref()
                    .map(|s| format!(" ({s})"))
                    .unwrap_or_default();
                Err(format!(
                    "this router{who} has no {id}: its daemon is older than this GUI \
                     ({}); update or restart it",
                    env!("CARGO_PKG_VERSION")
                ))
            }
        }
    }

    /// `check(id)` first (the router's reason wins), then the UI's own rule
    /// (selection and the like).
    pub(crate) fn and(&self, id: &str, rule: Result<(), String>) -> Result<(), String> {
        self.check(id).and(rule)
    }
}

fn clip(s: &str) -> String {
    let mut out: String = s.chars().take(MAX_REASON).collect();
    if s.chars().nth(MAX_REASON).is_some() {
        out.push('…');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn list() -> Vec<Value> {
        vec![
            json!({"id": "config.commit", "enabled": false, "disabledReason": "no pending changes"}),
            json!({"id": "interface.set", "enabled": true, "disabledReason": null}),
            json!({"id": "ip.vrf.add", "enabled": false}),
            json!({"no": "id"}),
            json!(42),
        ]
    }

    #[test]
    fn missing_disabled_and_enabled_commands() {
        let link = Link::Connected {
            target: "r1:7979".into(),
        };
        let info = json!({"name": "corerouter", "version": "0.1.0"});
        let a = Avail::new(&link, Some(&list()), &info);
        assert_eq!(a.check("interface.set"), Ok(()));
        assert_eq!(
            a.check("config.commit"),
            Err("no pending changes".to_owned())
        );
        assert_eq!(
            a.check("ip.vrf.add"),
            Err("not available on this router".to_owned())
        );
        let why = a.check("config.safe-mode.enter").unwrap_err();
        assert!(why.contains("has no config.safe-mode.enter"), "{why}");
        assert!(why.contains("corerouter 0.1.0"), "{why}");
        assert!(why.contains("update or restart"), "{why}");
        // The router's reason comes before the UI's own rule.
        assert_eq!(
            a.and("config.commit", Err("select one".into())),
            Err("no pending changes".to_owned())
        );
        assert_eq!(
            a.and("interface.set", Err("select one".into())),
            Err("select one".to_owned())
        );
    }

    #[test]
    fn no_list_yet_blocks_only_while_the_link_is_not_up() {
        let a = Avail::new(&Link::Local, None, &Value::Null);
        assert_eq!(a.check("anything.at.all"), Ok(()));
        let up = Link::Connected {
            target: "r1:7979".into(),
        };
        assert_eq!(Avail::new(&up, None, &Value::Null).check("x.y"), Ok(()));
        let connecting = Link::Connecting {
            target: "r1:7979".into(),
        };
        let a = Avail::new(&connecting, Some(&list()), &Value::Null);
        assert_eq!(
            a.check("interface.set"),
            Err("connecting… r1:7979".to_owned())
        );
        let down = Link::Disconnected {
            target: "r1:7979".into(),
            reason: "refused".into(),
        };
        let a = Avail::new(&down, Some(&list()), &Value::Null);
        assert_eq!(
            a.check("interface.set"),
            Err("disconnected: r1:7979".to_owned())
        );
    }

    #[test]
    fn hostile_reasons_are_cut() {
        let long = "x".repeat(10_000);
        let l = vec![json!({"id": "a.b", "enabled": false, "disabledReason": long})];
        let a = Avail::new(&Link::Local, Some(&l), &json!({"version": long}));
        assert!(a.check("a.b").unwrap_err().chars().count() <= MAX_REASON + 1);
        assert!(a.check("c.d").unwrap_err().chars().count() < 2 * MAX_REASON + 200);
    }
}
