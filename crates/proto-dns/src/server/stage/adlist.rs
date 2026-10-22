//! Adlist (G4.1d): names blocked by downloaded lists. Empty for now: the
//! stage holds its place in the chain so the adlist lands as this file's
//! body, without touching the others.

use crate::server::{Forwarder, Query, Stage, Step};
use crate::resolver::Transport;

pub(crate) const STAGE: Stage = Stage {
    name: "adlist",
    order: 30,
    handle,
    after: None,
};

fn handle(_: &Forwarder, _: &mut Query, _: Option<&mut dyn Transport>) -> Step {
    Step::Next
}
