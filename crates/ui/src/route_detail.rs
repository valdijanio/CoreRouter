//! The detail of the selected route, under the IP › Routes table (G1.27b):
//! where it came from, why it was chosen, its check-gateway, its changes
//! of the last 24 h and what the kernel holds. A panel with no window of
//! its own: it asks `ip.route.detail` (with every refresh, like any panel)
//! while the Routes window has one route selected, and `routes.rs` draws
//! the answer.

use serde_json::{Value, json};

use crate::backend::RequestId;
use crate::panel::{Panel, PanelState, Query};
use crate::{CoreRouterUi, Win, value_text};

pub(crate) const PANEL: Panel = Panel {
    name: "route-detail",
    windows: &[],
    new: || Box::<Detail>::default(),
};

#[derive(Default)]
pub(crate) struct Detail {
    /// The last answer, by the key it is about.
    pub shown: Option<(String, Value)>,
}

impl PanelState for Detail {
    fn queries(&self, app: &CoreRouterUi) -> Vec<Query> {
        match app.route_selected() {
            Some(key) if app.open.contains(&Win::Routes) && app.has_command("ip.route.detail") => {
                vec![Query {
                    key: "detail",
                    command: "ip.route.detail",
                    params: json!({ "key": key }),
                }]
            }
            _ => Vec::new(),
        }
    }

    fn arrived(&mut self, _: &mut CoreRouterUi, _: &'static str, _: RequestId, value: Value) {
        let key = value.get("key").map(value_text).unwrap_or_default();
        self.shown = Some((key, value));
    }

    fn window(&mut self, _: &mut CoreRouterUi, _: &'static str, _: &mut egui::Ui) {}
}
