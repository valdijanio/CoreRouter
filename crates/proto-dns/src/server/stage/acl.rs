//! Who may ask (`allowed_from`): the networks of the listed interface
//! lists and prefixes, and the router itself. Anyone else gets REFUSED
//! (RFC 1035 §4.1.1 RCODE 5), never an answer: an open resolver is a
//! reflection amplifier for anyone on the Internet. RouterOS leaves this to
//! the firewall; here it holds even with an empty firewall.

use hickory_proto::op::ResponseCode;

use crate::server::{Forwarder, Query, Reply, Stage, Step};
use crate::resolver::Transport;

pub(crate) const STAGE: Stage = Stage {
    name: "acl",
    order: 10,
    handle,
    after: None,
};

fn handle(_: &Forwarder, q: &mut Query, _: Option<&mut dyn Transport>) -> Step {
    if q.client.is_loopback() || q.config.allowed.iter().any(|n| n.contains(&q.client)) {
        Step::Next
    } else {
        Step::Reply(Reply::code(ResponseCode::Refused))
    }
}
