//! `/interface list`: named groups of interfaces (RouterOS). The firewall
//! matches them (`in-interface-list=WAN`); neighbor discovery can use them
//! later. New configs start with the empty lists `LAN` and `WAN`, as the
//! RouterOS default configuration does.

use serde::{Deserialize, Serialize};

use crate::firewall::Name;
use crate::types::{IfName, ItemId};

/// Names RouterOS reserves for its built-in lists; not creatable here.
pub const RESERVED: [&str; 4] = ["all", "none", "dynamic", "static"];

/// The lists a new config starts with.
pub const DEFAULT_LISTS: [&str; 2] = ["LAN", "WAN"];

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InterfaceList {
    pub name: Name,
    #[serde(default)]
    pub comment: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InterfaceListMember {
    pub id: ItemId,
    pub list: Name,
    /// May name an interface that no longer exists (shown as unknown; the
    /// firewall matches by name, so it does no harm).
    pub interface: IfName,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub comment: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct InterfaceLists {
    pub lists: Vec<InterfaceList>,
    pub members: Vec<InterfaceListMember>,
    pub next_member_id: u32,
}

impl Default for InterfaceLists {
    fn default() -> Self {
        Self {
            lists: DEFAULT_LISTS
                .iter()
                .filter_map(|n| n.parse().ok())
                .map(|name| InterfaceList {
                    name,
                    comment: String::new(),
                })
                .collect(),
            members: Vec::new(),
            next_member_id: 0,
        }
    }
}

impl InterfaceLists {
    pub fn get(&self, name: &str) -> Option<&InterfaceList> {
        self.lists.iter().find(|l| l.name.as_str() == name)
    }

    pub fn next_member_id(&mut self) -> ItemId {
        self.next_member_id = self.next_member_id.saturating_add(1);
        ItemId(self.next_member_id)
    }

    /// Enabled member interfaces of `list`, in insertion order.
    pub fn interfaces_of<'a>(&'a self, list: &'a str) -> impl Iterator<Item = &'a IfName> + 'a {
        self.members
            .iter()
            .filter(move |m| !m.disabled && m.list.as_str() == list)
            .map(|m| &m.interface)
    }

    /// Lists `iface` is an enabled member of.
    pub fn lists_of<'a>(&'a self, iface: &'a IfName) -> impl Iterator<Item = &'a Name> + 'a {
        self.members
            .iter()
            .filter(move |m| !m.disabled && m.interface == *iface)
            .map(|m| &m.list)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_have_lan_and_wan() {
        let l = InterfaceLists::default();
        assert!(l.get("LAN").is_some() && l.get("WAN").is_some());
        let back: InterfaceLists = serde_json::from_str("{}").unwrap();
        assert_eq!(back, l, "an old config gets the default lists");
    }
}
