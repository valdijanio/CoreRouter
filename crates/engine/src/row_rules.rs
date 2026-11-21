//! G1.24: what a row of a list lets the operator do, said by the engine.
//!
//! A window greys out Remove, Edit, Enable/Disable and Comment for a row the
//! router keeps by itself (a physical port, an address a DHCP client
//! obtained, a rule the zone matrix wrote). Deciding that in the GUI meant a
//! second copy of the engine's rules that went stale; the list rows say it
//! instead, with the reason, and the GUI only shows it.
//!
//! Every row of a list that adopts this carries three fields:
//! - `removable`: its `remove` command takes it;
//! - `editable`: its `set` command (fields, `disabled`, `comment`) takes it;
//! - `fixed_reason`: why one of the two is false, for people; `null` when
//!   both are true.
//!
//! The contract test (`tests/it/row_rules.rs`) checks that the flags tell
//! the truth: a row that says it is not removable is refused by `remove`.

use serde_json::{Value, json};

/// What one row allows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RowRules {
    pub removable: bool,
    pub editable: bool,
    pub reason: Option<String>,
}

impl RowRules {
    /// Configuration like any other: everything allowed.
    pub fn free() -> Self {
        Self {
            removable: true,
            editable: true,
            reason: None,
        }
    }

    /// Kept by the router: neither removed nor changed here.
    pub fn fixed(why: impl Into<String>) -> Self {
        Self {
            removable: false,
            editable: false,
            reason: Some(why.into()),
        }
    }

    /// Changed here, never removed (a physical port).
    pub fn kept(why: impl Into<String>) -> Self {
        Self {
            removable: false,
            editable: true,
            reason: Some(why.into()),
        }
    }

    /// Removed here, never changed (a dynamic address-list entry).
    pub fn read_only(why: impl Into<String>) -> Self {
        Self {
            removable: true,
            editable: false,
            reason: Some(why.into()),
        }
    }

    /// Put the three fields in `row` (an object; anything else is left).
    pub fn put(self, row: &mut Value) {
        if let Some(obj) = row.as_object_mut() {
            obj.insert("removable".into(), json!(self.removable));
            obj.insert("editable".into(), json!(self.editable));
            obj.insert("fixed_reason".into(), json!(self.reason));
        }
    }
}

/// The `params` doc text of the three fields, for a list's signature.
pub const DOC: &str = "removable: bool, editable: bool, fixed_reason: string | null (G1.24: why the row cannot be removed or changed here)";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_writes_the_three_fields() {
        let mut row = json!({"id": "*1"});
        RowRules::kept("a physical port").put(&mut row);
        assert_eq!(
            row,
            json!({"id": "*1", "removable": false, "editable": true, "fixed_reason": "a physical port"})
        );
        let mut row = json!({"id": "*2"});
        RowRules::free().put(&mut row);
        assert_eq!(row["fixed_reason"], Value::Null);
        let mut not_object = json!(3);
        RowRules::fixed("x").put(&mut not_object);
        assert_eq!(not_object, json!(3));
    }
}
