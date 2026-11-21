//! `ip.firewall.actions` (G1.24): what a rule window needs to know about the
//! firewall's actions, said by the engine instead of a copy in the GUI —
//! the built-in chains of each table, the actions each table takes, the
//! action parameters each action takes and the chains it runs from.
//!
//! The sources are the ones `add`/`set` check against:
//! `corerouter_firewall::validate::{table_actions, action_chains}` and this
//! engine's `ACTION_FIELDS`. A query, cheap and the same for every caller:
//! four tables × at most 11 actions.

use corerouter_firewall::validate::{action_chains, table_actions};
use corerouter_model::firewall::Table;
use serde_json::{Value, json};

use super::args::opt_parse;
use super::firewall::ACTION_FIELDS;
use super::{CommandSpec, always};
use crate::{Result, Session};

pub(super) const COMMANDS: &[CommandSpec] = &[cmd!(query "ip.firewall.actions", "Firewall Actions", [], None,
    "{table?: filter | nat | mangle | raw} → [{table, chains: [string] (built-in, packet order), actions: [{action, params: [string] (the action parameters it takes; others are refused), chains: [string] | null (the built-in chains it runs from; null: any; change-mss with clamp-to-pmtu also needs forward, output or postrouting)}]}]",
    always, actions)];

/// The parameters `action` takes, in `ACTION_FIELDS` order.
pub(crate) fn params_of(action: &str) -> Vec<&'static str> {
    ACTION_FIELDS
        .iter()
        .filter(|(_, owners)| owners.contains(&action))
        .map(|(k, _)| *k)
        .collect()
}

fn actions(_s: &mut Session, p: &Value) -> Result<Value> {
    let only: Option<Table> = opt_parse(p, "table")?;
    let tables: Vec<Value> = Table::ALL
        .into_iter()
        .filter(|t| only.is_none_or(|o| o == *t))
        .map(|t| {
            let actions: Vec<Value> = table_actions(t)
                .iter()
                .map(|a| json!({"action": a, "params": params_of(a), "chains": action_chains(a)}))
                .collect();
            json!({"table": t.name(), "chains": t.builtin_chains(), "actions": actions})
        })
        .collect();
    Ok(Value::Array(tables))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_table_lists_its_actions_and_their_parameters() {
        let mut s = Session::virtual_lab();
        let all = s.execute("ip.firewall.actions", &json!({})).unwrap();
        let all = all.as_array().unwrap();
        assert_eq!(all.len(), 4);
        let nat = s.execute("ip.firewall.actions", &json!({"table": "nat"})).unwrap();
        let nat = &nat[0];
        assert_eq!(nat["chains"], json!(["dstnat", "srcnat"]));
        let dst = nat["actions"].as_array().unwrap().iter().find(|a| a["action"] == "dst-nat").unwrap();
        assert_eq!(dst["params"], json!(["to_addresses", "to_ports"]));
        assert_eq!(dst["chains"], json!(["dstnat"]));
        assert!(s.execute("ip.firewall.actions", &json!({"table": "bogus"})).is_err());
        // Every parameter belongs to some action somewhere.
        for (key, _) in ACTION_FIELDS {
            let used = all.iter().flat_map(|t| t["actions"].as_array().unwrap()).any(|a| {
                a["params"].as_array().unwrap().iter().any(|p| p == key)
            });
            assert!(used, "{key} belongs to no action of any table");
        }
    }
}
