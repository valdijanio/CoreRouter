//! Explanations for the Interfaces list.
use serde_json::Value;
use crate::backend::RequestId;
use crate::panel::{Panel, PanelState, Query};
use crate::CoreRouterUi;

pub(crate) const PANEL: Panel = Panel {
    name: "interface-list-help", windows: &[],
    new: || Box::<InterfaceListHelp>::default(),
};
#[derive(Default)]
pub(crate) struct InterfaceListHelp { pub(crate) help: Option<crate::help::HelpView> }
impl PanelState for InterfaceListHelp {
    fn queries(&self, _: &CoreRouterUi) -> Vec<Query> { Vec::new() }
    fn arrived(&mut self, _: &mut CoreRouterUi, _: &'static str, _: RequestId, _: Value) {}
    fn window(&mut self, _: &mut CoreRouterUi, _: &'static str, _: &mut egui::Ui) {}
    fn dialogs(&mut self, app: &mut CoreRouterUi, ctx: &egui::Context, _: egui::Rect) {
        crate::help::modal(ctx, app.lang, &mut self.help);
    }
}
