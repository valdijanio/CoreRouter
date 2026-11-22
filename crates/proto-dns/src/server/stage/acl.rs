//! Who may ask (`allowed_from`): the networks of the listed interface
//! lists and prefixes, and the router itself. Anyone else gets REFUSED
//! (RFC 1035 §4.1.1 RCODE 5), never an answer: an open resolver is a
//! reflection amplifier for anyone on the Internet. RouterOS leaves this to
//! the firewall; here it holds even with an empty firewall.

use hickory_proto::op::ResponseCode;

use crate::resolver::Transport;
use crate::server::explain::Note;
use crate::server::{Forwarder, Query, Reply, Stage, Step};

pub(crate) const STAGE: Stage = Stage {
    name: "acl",
    order: 10,
    handle,
    after: None,
};

fn handle(_: &Forwarder, q: &mut Query, _: Option<&mut dyn Transport>) -> Step {
    let client = q.client;
    if client.is_loopback() {
        q.note(|| Note::new("acl.loopback").arg("client", client));
        return Step::Next;
    }
    if let Some(net) = q.config.allowed.iter().find(|n| n.contains(&client)).copied() {
        q.note(|| Note::new("acl.allowed").arg("client", client).arg("net", net));
        return Step::Next;
    }
    q.note(|| Note::new("acl.refused").arg("client", client));
    Step::Reply(Reply::code(ResponseCode::Refused))
}
