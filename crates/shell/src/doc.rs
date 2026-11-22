//! Reading a command's `params` doc: the same contract the engine checks
//! (`{key: type, opt?: type} → result`), plus what a terminal needs from it —
//! the type of each key (to turn `yes` into `true`, `1500` into a number,
//! `a,b` into a list, and to offer enumerated values) and the fields of the
//! result (the columns of `print`, the legend of a `flags` field).
//!
//! The key list must agree with `corerouter_engine::cmd::doc_keys`; a test
//! over the whole registry holds them together.

/// What the doc says a parameter takes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ty {
    /// `bool`: `yes`/`no`/`true`/`false`.
    Bool,
    /// `u32`, `int …`: a number; `text_too` when the doc also allows a
    /// string (`u32 | asdot string`).
    Num { text_too: bool },
    /// `[string]`: a JSON list, typed `a,b,c`; `text_too` when the doc also
    /// takes the comma-separated string itself.
    List { text_too: bool },
    /// `a|b|c`: one of these words.
    Enum(Vec<String>),
    /// Anything else (`string`, `cidr | ip`, `*hex`, …): sent as typed.
    Text,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Param {
    /// The engine's name (`vlan_id`); the terminal shows `vlan-id`.
    pub key: String,
    pub required: bool,
    /// The type text as written, notes included (`u32 (68..=9216)`).
    pub ty_text: String,
    pub ty: Ty,
}

/// Words that name a type, never an enumerated value.
const TYPE_WORDS: &[&str] = &[
    "string",
    "ip",
    "ipv4",
    "ipv6",
    "cidr",
    "u8",
    "u16",
    "u32",
    "u64",
    "int",
    "bool",
    "interface",
    "hex",
    "number",
];

/// Split `body` at top-level commas (outside `()`, `[]`, `{}`).
fn split_top(body: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut depth = 0i32;
    let mut start = 0usize;
    for (i, ch) in body.char_indices() {
        match ch {
            '{' | '[' | '(' => depth += 1,
            '}' | ']' | ')' => depth -= 1,
            ',' if depth == 0 => {
                parts.push(body.get(start..i).unwrap_or(""));
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(body.get(start..).unwrap_or(""));
    parts
}

/// `(input, result)` halves of a doc.
fn halves(doc: &str) -> (&str, &str) {
    if let Some((a, b)) = doc.split_once('→') {
        return (a, b);
    }
    doc.split_once("->").unwrap_or((doc, ""))
}

/// Remove `( … )` notes, keeping what is outside them.
fn strip_notes(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut depth = 0i32;
    for ch in s.chars() {
        match ch {
            '(' => depth += 1,
            ')' => depth -= 1,
            _ if depth <= 0 => out.push(ch),
            _ => {}
        }
    }
    out.trim().to_owned()
}

fn is_word(s: &str) -> bool {
    let mut chars = s.chars();
    chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

fn classify(ty_text: &str) -> Ty {
    let core = strip_notes(ty_text);
    if core == "bool" {
        return Ty::Bool;
    }
    let alts: Vec<&str> = core.split('|').map(str::trim).collect();
    let first = alts.first().copied().unwrap_or("");
    if first.starts_with('[') {
        return Ty::List {
            text_too: alts.iter().skip(1).any(|a| a.contains("string")),
        };
    }
    let num = |a: &str| {
        let w = a.split_whitespace().next().unwrap_or("");
        matches!(w, "u8" | "u16" | "u32" | "u64" | "int" | "number")
    };
    if num(first) {
        return Ty::Num {
            text_too: alts.iter().skip(1).any(|a| !num(a)),
        };
    }
    if alts.len() > 1 && alts.iter().all(|a| is_word(a) && !TYPE_WORDS.contains(a)) {
        return Ty::Enum(alts.iter().map(|a| (*a).to_owned()).collect());
    }
    Ty::Text
}

/// Parameters declared by a doc, in order. Only the top-level keys of the
/// first `{…}` before `→` count (as in the engine).
pub fn params(doc: &str) -> Vec<Param> {
    let (input, _) = halves(doc);
    let input = input.trim();
    let Some(body) = input.strip_prefix('{').and_then(|s| s.strip_suffix('}')) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for part in split_top(body) {
        let (name, ty_text) = part.split_once(':').unwrap_or((part, ""));
        let name = name.trim();
        if name.is_empty() {
            continue;
        }
        let (key, required) = match name.strip_suffix('?') {
            Some(opt) => (opt.trim(), false),
            None => (name, true),
        };
        let ty_text = ty_text.trim().to_owned();
        out.push(Param {
            key: key.to_owned(),
            required,
            ty: classify(&ty_text),
            ty_text,
        });
    }
    out
}

/// What a command returns, read from the part after `→`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Shape {
    /// `[{…}]`: rows (a list); otherwise one object.
    pub list: bool,
    /// Field names in doc order.
    pub fields: Vec<String>,
    /// Legend of a `flags (X disabled, A active, …)` field: letter, meaning.
    pub legend: Vec<(char, String)>,
}

pub fn shape(doc: &str) -> Shape {
    let (_, result) = halves(doc);
    let mut body = result.trim();
    let list = body.starts_with('[');
    if list {
        body = body
            .strip_prefix('[')
            .and_then(|b| b.strip_suffix(']'))
            .unwrap_or(body)
            .trim();
    }
    let Some(body) = body.strip_prefix('{').and_then(|b| b.strip_suffix('}')) else {
        return Shape {
            list,
            ..Shape::default()
        };
    };
    let mut fields = Vec::new();
    let mut legend = Vec::new();
    for part in split_top(body) {
        let part = part.trim();
        // `name: type`, `name (note)`, `a | b` (one of two fields).
        let head = part.split(':').next().unwrap_or("");
        for alt in head.split('|') {
            let name = alt.split('(').next().unwrap_or("").trim();
            if is_word(name) && !fields.iter().any(|f| f == name) {
                fields.push(name.to_owned());
            }
        }
        if head.trim_start().starts_with("flags")
            && let Some(note) = part
                .split_once('(')
                .and_then(|(_, rest)| rest.rsplit_once(')'))
                .map(|(n, _)| n)
        {
            for item in note.split(',') {
                let mut words = item.split_whitespace();
                if let (Some(letter), Some(meaning)) = (words.next(), words.next())
                    && letter.chars().count() == 1
                    && let Some(c) = letter.chars().next()
                {
                    legend.push((c, meaning.to_owned()));
                }
            }
        }
    }
    Shape {
        list,
        fields,
        legend,
    }
}

/// `vlan_id` → `vlan-id` (what the terminal shows).
pub fn kebab(key: &str) -> String {
    key.replace('_', "-")
}

/// `vlan-id` → `vlan_id` (what the engine takes).
pub fn snake(word: &str) -> String {
    word.replace('-', "_")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_keys_and_types() {
        let p = params(
            "{name: string, parent: string, vlan_id: u32 (1..=4094), mtu?: u32 (68..=9216, default: parent MTU), comment?: string} → {name}",
        );
        let keys: Vec<_> = p.iter().map(|p| (p.key.as_str(), p.required)).collect();
        assert_eq!(
            keys,
            [
                ("name", true),
                ("parent", true),
                ("vlan_id", true),
                ("mtu", false),
                ("comment", false)
            ]
        );
        assert_eq!(p[2].ty, Ty::Num { text_too: false });
        assert_eq!(p[0].ty, Ty::Text);
    }

    #[test]
    fn types() {
        assert_eq!(classify("bool"), Ty::Bool);
        assert_eq!(
            classify("ether|vlan|bridge|loopback|vrf"),
            Ty::Enum(vec![
                "ether".into(),
                "vlan".into(),
                "bridge".into(),
                "loopback".into(),
                "vrf".into()
            ])
        );
        assert_eq!(classify("u32 | asdot string"), Ty::Num { text_too: true });
        assert_eq!(
            classify("[string] | string (comma-separated)"),
            Ty::List { text_too: true }
        );
        assert_eq!(classify("[string]"), Ty::List { text_too: false });
        assert_eq!(classify("int 1..3600"), Ty::Num { text_too: false });
        assert_eq!(classify("cidr | ip (0.0.0.0/0, ::/0)"), Ty::Text);
        assert_eq!(classify("ip | interface | ip%interface"), Ty::Text);
        assert_eq!(classify("*hex"), Ty::Text);
    }

    #[test]
    fn reads_result_shape_and_flags() {
        let s = shape(
            "{routing_table?: string} → [{id (null if connected), dst_address, gateway, flags (X disabled, A active, D dynamic), active, comment}]",
        );
        assert!(s.list);
        assert_eq!(
            s.fields,
            ["id", "dst_address", "gateway", "flags", "active", "comment"]
        );
        assert_eq!(
            s.legend,
            [
                ('X', "disabled".into()),
                ('A', "active".into()),
                ('D', "dynamic".into())
            ]
        );
        let d = shape("{} → [{op: add|remove|change, path, value | from, to}]");
        assert_eq!(d.fields, ["op", "path", "value", "from", "to"]);
        let o = shape("{} → {enabled, interfaces, interval_secs}");
        assert!(!o.list);
        assert_eq!(o.fields.len(), 3);
    }
}
