//! MCP prompts: ready-made workflows the user picks in the client (a slash
//! command in most of them). Each one expands into a user message that walks
//! the agent through the safe sequence of tools; none runs anything itself.

use serde_json::{Value, json};

use crate::{Backend, resources};

/// Longest argument value accepted; prompt text is no place for a 16 MiB string.
const MAX_ARG: usize = 128;
/// Most completion values MCP allows in one reply.
const MAX_COMPLETIONS: usize = 100;

struct Arg {
    name: &'static str,
    description: &'static str,
    required: bool,
}

struct Prompt {
    name: &'static str,
    title: &'static str,
    description: &'static str,
    args: &'static [Arg],
    render: fn(&mut dyn Backend, &Args) -> Vec<Value>,
}

/// Validated arguments of one `prompts/get`.
struct Args(Vec<(&'static str, String)>);

impl Args {
    fn get(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, v)| v.as_str())
    }
}

const PROMPTS: &[Prompt] = &[
    Prompt {
        name: "configure_address",
        title: "Configure an address and a route",
        description: "Add an IP address to an interface and, optionally, a route through a \
            gateway, as one reviewed transaction.",
        args: &[
            Arg {
                name: "interface",
                description: "Interface name, e.g. ether1",
                required: true,
            },
            Arg {
                name: "address",
                description: "Address with prefix length, e.g. 192.0.2.1/24",
                required: true,
            },
            Arg {
                name: "gateway",
                description: "Next hop for the route (omit for no route)",
                required: false,
            },
            Arg {
                name: "dst_address",
                description: "Route destination (default 0.0.0.0/0, ::/0 for IPv6)",
                required: false,
            },
        ],
        render: configure_address,
    },
    Prompt {
        name: "review_and_commit",
        title: "Review pending changes and commit",
        description: "Explain every pending change and its risk, then commit after the \
            operator agrees.",
        args: &[Arg {
            name: "comment",
            description: "Comment for the new revision",
            required: false,
        }],
        render: review_and_commit,
    },
    Prompt {
        name: "diagnose_connectivity",
        title: "Diagnose connectivity to a host",
        description: "Check the route, interface and reachability toward an address, \
            without changing the configuration.",
        args: &[Arg {
            name: "target",
            description: "Address to reach, e.g. 8.8.8.8",
            required: true,
        }],
        render: diagnose_connectivity,
    },
];

fn user_text(text: String) -> Value {
    json!({"role": "user", "content": {"type": "text", "text": text}})
}

/// The resource as an embedded message, so the agent starts from the facts.
fn user_resource(backend: &mut dyn Backend, uri: &str) -> Value {
    let contents = resources::read(backend, &json!({"uri": uri}))
        .ok()
        .and_then(|r| r.get("contents")?.get(0).cloned());
    match contents {
        Some(resource) => {
            json!({"role": "user", "content": {"type": "resource", "resource": resource}})
        }
        None => user_text(format!("({uri} could not be read)")),
    }
}

fn configure_address(_: &mut dyn Backend, a: &Args) -> Vec<Value> {
    let interface = a.get("interface").unwrap_or_default();
    let address = a.get("address").unwrap_or_default();
    let route = match a.get("gateway") {
        Some(gw) => {
            let dst = a.get("dst_address").unwrap_or(if address.contains(':') {
                "::/0"
            } else {
                "0.0.0.0/0"
            });
            format!(
                ", then ip.route.add {{\"dst_address\":\"{dst}\",\"gateway\":\"{gw}\"}}; \
                 check with ip.route.list that the route is active (A) once committed"
            )
        }
        None => String::new(),
    };
    vec![user_text(format!(
        "Configure the CoreRouter: address {address} on interface {interface}{}.\n\n\
         1. inspect_state with path \"interfaces\": confirm {interface} exists and is not \
         disabled; ip.address.list: make sure {address} does not overlap an existing network.\n\
         2. run_command config.mode.set {{\"mode\":\"transactional\"}} so nothing applies \
         before review.\n\
         3. command_batch (atomic): ip.address.add {{\"address\":\"{address}\",\
         \"interface\":\"{interface}\"}}{route}.\n\
         4. Read config.diff and show me the pending changes in plain words. If {interface} \
         carries this management session, say so and suggest config.safe-mode.enter first.\n\
         5. Only after I agree: config.commit with a comment. If anything fails, \
         config.discard and tell me why.",
        if route.is_empty() { "" } else { " and a route" },
    ))]
}

fn review_and_commit(backend: &mut dyn Backend, a: &Args) -> Vec<Value> {
    let comment = match a.get("comment") {
        Some(c) => format!("{{\"comment\":\"{c}\"}}"),
        None => "a short comment that sums up the change".into(),
    };
    vec![
        user_resource(backend, "corerouter://state"),
        user_resource(backend, "corerouter://diff"),
        user_text(format!(
            "Above: the router state and its pending changes (config.diff). If there are none, \
             say so and stop.\n\n\
             1. Explain each change in operator terms: what it does and what traffic it touches.\n\
             2. Point out risks: losing management access (address, route or firewall on the \
             interface this session uses), overlapping networks, rules that never match, \
             disabled items. Suggest config.safe-mode.enter before a risky commit.\n\
             3. Ask me to confirm. On yes: run_command config.commit with {comment} and report \
             the new revision. On no: leave the changes pending (config.discard only if I ask)."
        )),
    ]
}

fn diagnose_connectivity(_: &mut dyn Backend, a: &Args) -> Vec<Value> {
    let target = a.get("target").unwrap_or_default();
    vec![user_text(format!(
        "Find out why (or whether) the CoreRouter reaches {target}. Do not change the \
         configuration.\n\n\
         1. ip.route.list: which route covers {target}, is it active (A), what gateway.\n\
         2. interface.list: the outgoing interface is running and not disabled; \
         ip.address.list: it has an address in the gateway's network.\n\
         3. run_task tool.ping.start {{\"address\":\"{target}\",\"count\":5}}: loss and \
         latency.\n\
         4. With loss, run_task tool.mtr.start {{\"address\":\"{target}\"}} to see where \
         it stops.\n\
         5. Sum up: the likely cause, the evidence, and the command that would fix it (do not \
         run it)."
    ))]
}

pub fn list() -> Value {
    let prompts: Vec<Value> = PROMPTS
        .iter()
        .map(|p| {
            let args: Vec<Value> = p
                .args
                .iter()
                .map(|a| json!({"name": a.name, "description": a.description, "required": a.required}))
                .collect();
            json!({"name": p.name, "title": p.title, "description": p.description, "arguments": args})
        })
        .collect();
    json!({"prompts": prompts})
}

/// `prompts/get`; `Err` is the -32602 message (bad name or arguments).
pub fn get(backend: &mut dyn Backend, params: &Value) -> Result<Value, String> {
    let name = params.get("name").and_then(Value::as_str).unwrap_or("");
    let prompt = PROMPTS.iter().find(|p| p.name == name).ok_or_else(|| {
        let all: Vec<&str> = PROMPTS.iter().map(|p| p.name).collect();
        format!(
            "unknown prompt '{}'; prompts: {}",
            name.chars().take(64).collect::<String>(),
            all.join(", ")
        )
    })?;
    let given = match params.get("arguments") {
        None | Some(Value::Null) => serde_json::Map::new(),
        Some(Value::Object(m)) => m.clone(),
        Some(_) => return Err("arguments must be an object of strings".into()),
    };
    for key in given.keys() {
        if !prompt.args.iter().any(|a| a.name == key) {
            let names: Vec<&str> = prompt.args.iter().map(|a| a.name).collect();
            return Err(format!(
                "{name}: unknown argument '{}'; arguments: {}",
                key.chars().take(64).collect::<String>(),
                names.join(", ")
            ));
        }
    }
    let mut args = Vec::new();
    for a in prompt.args {
        let value = match given.get(a.name) {
            Some(Value::String(s)) => s.trim(),
            Some(_) => return Err(format!("{name}: argument '{}' must be a string", a.name)),
            None => "",
        };
        if value.is_empty() {
            if a.required {
                return Err(format!("{name}: missing argument '{}'", a.name));
            }
            continue;
        }
        // Values land inside JSON examples in the prompt text.
        if value.len() > MAX_ARG
            || value
                .chars()
                .any(|c| c.is_control() || c == '"' || c == '\\')
        {
            return Err(format!(
                "{name}: argument '{}' must be one line of at most {MAX_ARG} bytes, \
                 without quotes or backslashes",
                a.name
            ));
        }
        args.push((a.name, value.to_string()));
    }
    Ok(json!({
        "description": prompt.title,
        "messages": (prompt.render)(backend, &Args(args)),
    }))
}

/// `completion/complete`: command ids and state paths for the resource
/// templates, interface names for prompt arguments. Unknown refs complete to
/// nothing (the spec has no error for "no suggestions").
pub fn complete(backend: &mut dyn Backend, params: &Value) -> Result<Value, String> {
    let r = params
        .get("ref")
        .ok_or("completion/complete needs {ref, argument}")?;
    let arg = params
        .get("argument")
        .ok_or("completion/complete needs {ref, argument}")?;
    let name = arg.get("name").and_then(Value::as_str).unwrap_or("");
    let value = arg.get("value").and_then(Value::as_str).unwrap_or("");
    let kind = r.get("type").and_then(Value::as_str).unwrap_or("");
    let target = r
        .get(if kind == "ref/prompt" { "name" } else { "uri" })
        .and_then(Value::as_str)
        .unwrap_or("");
    let mut values: Vec<String> = match (kind, target, name) {
        ("ref/resource", "corerouter://command/{id}", "id") => {
            resources::command_ids(backend, value)
        }
        ("ref/resource", "corerouter://state/{path}", "path") => {
            let summary = backend.call("state.inspect", json!({})).unwrap_or_default();
            summary
                .get("paths")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .filter(|p| p.starts_with(value))
                .map(str::to_string)
                .collect()
        }
        ("ref/prompt", "configure_address", "interface") => {
            let list = backend
                .call(
                    "engine.execute",
                    json!({"command": "interface.list", "params": {}}),
                )
                .unwrap_or_default();
            list.as_array()
                .into_iter()
                .flatten()
                .filter_map(|i| i.get("name").and_then(Value::as_str))
                .filter(|n| n.starts_with(value))
                .map(str::to_string)
                .collect()
        }
        _ => Vec::new(),
    };
    values.sort();
    values.dedup();
    let total = values.len();
    values.truncate(MAX_COMPLETIONS);
    Ok(json!({"completion": {
        "values": values,
        "total": total,
        "hasMore": total > MAX_COMPLETIONS,
    }}))
}
