//! Authoritative zones (G4.1c, `hickory-server`). Empty for now: the stage
//! holds its place between the static entries and the cache.

use crate::server::{Forwarder, Query, Stage, Step};
use crate::resolver::Transport;

pub(crate) const STAGE: Stage = Stage {
    name: "zones",
    order: 50,
    handle,
    after: None,
};

fn handle(_: &Forwarder, _: &mut Query, _: Option<&mut dyn Transport>) -> Step {
    Step::Next
}
