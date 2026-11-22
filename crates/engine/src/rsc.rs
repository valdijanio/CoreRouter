//! Reader of RouterOS export scripts (`.rsc`, G4.3n): the `add` and `set`
//! lines of the menus asked for, as key/value pairs.
//!
//! What it understands, as RouterOS v7 writes an export:
//!
//! - a menu line (`/ppp secret`, or `/ppp/secret`) and the commands below
//!   it; or the menu in front of each command (`/export terse`);
//! - a line ending in `\` goes on in the next one (its indentation is
//!   dropped), also inside a quoted value;
//! - `"…"` values with RouterOS's escapes: `\"`, `\\`, `\n`, `\r`, `\t`,
//!   `\$`, `\?`, `\_` (a space), `\a`, `\b`, `\f`, `\v` and `\XX` (a byte
//!   in hex: the export writes `ç` as `\C3\A7`). The bytes are UTF-8, or
//!   Latin-1 when they are not (old Windows-1252 comments);
//! - `set [ find name=x ]`, `set [ find where name=x ]`,
//!   `set [ find default=yes ]`, `set *0` (a built-in);
//! - `#` comments, `;` between commands, blank lines.
//!
//! The text is hostile (it comes from a file): sizes are bounded and an
//! error says the line, the column and what was expected, **never** the
//! text there — the file holds every subscriber's password.

/// Largest script read: 100 000 RouterOS secret lines with comments are
/// ~17 MB. Over the control channel a request is at most 16 MiB
/// (`corerouter_control::wire`): a bigger file goes in parts.
pub const MAX_TEXT: usize = 32 * 1024 * 1024;
/// Longest command once its `\` continuations are joined.
pub const MAX_STATEMENT: usize = 64 * 1024;
/// Most `key=value` arguments of one command.
pub const MAX_ARGS: usize = 64;
/// Longest value.
pub const MAX_VALUE: usize = 4096;
/// Most commands kept.
pub const MAX_ITEMS: usize = 250_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verb {
    Add,
    Set,
}

/// What a `set` changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// `[ find name=x ]` (or `where name=x`).
    Name(String),
    /// `[ find default=yes ]`.
    Default,
    /// `*0`: an item number (RouterOS exports its built-in profiles so).
    Id(String),
}

/// One `add` or `set` of a menu asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    /// Line where the command starts (1-based).
    pub line: usize,
    /// `"ppp secret"`.
    pub menu: String,
    pub verb: Verb,
    pub target: Option<Target>,
    /// In the order written; keys in RouterOS form (`remote-address`).
    pub args: Vec<(String, String)>,
}

impl Item {
    pub fn get(&self, key: &str) -> Option<&str> {
        self.args
            .iter()
            .rev()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Script {
    pub items: Vec<Item>,
    /// Commands of the menus asked for that are neither `add` nor `set`
    /// (`remove`, `print`, scripting): left alone.
    pub ignored: usize,
    /// Commands of other menus.
    pub other_menus: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("line {line}, column {column}: {message}")]
pub struct ParseError {
    pub line: usize,
    pub column: usize,
    pub message: String,
}

/// A raw word: its text after quotes and escapes, and where it starts.
#[derive(Debug)]
struct Word {
    key: Option<String>,
    value: String,
    /// `[` or `]` alone.
    bracket: Option<char>,
    line: usize,
    column: usize,
}

/// The text, one command at a time: comments and continuations removed,
/// quotes and escapes decoded.
struct Lexer<'a> {
    bytes: &'a [u8],
    at: usize,
    line: usize,
    line_start: usize,
}

fn err(line: usize, column: usize, message: impl Into<String>) -> ParseError {
    ParseError {
        line,
        column,
        message: message.into(),
    }
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// UTF-8, or Latin-1 byte by byte when it is not.
fn text_of(bytes: Vec<u8>) -> String {
    match String::from_utf8(bytes) {
        Ok(s) => s,
        Err(e) => e.into_bytes().into_iter().map(char::from).collect(),
    }
}

impl<'a> Lexer<'a> {
    fn new(text: &'a str) -> Self {
        Self {
            bytes: text.as_bytes(),
            at: 0,
            line: 1,
            line_start: 0,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    fn peek2(&self) -> Option<u8> {
        self.bytes.get(self.at + 1).copied()
    }

    fn column(&self) -> usize {
        self.at.saturating_sub(self.line_start) + 1
    }

    fn newline(&mut self) {
        self.line += 1;
        self.line_start = self.at;
    }

    /// At `\`: a continuation (`\` then the end of the line)? Consumes it,
    /// and the next line's indentation.
    fn continuation(&mut self) -> bool {
        let skip = match (self.peek2(), self.bytes.get(self.at + 2).copied()) {
            (Some(b'\n'), _) => 2,
            (Some(b'\r'), Some(b'\n')) => 3,
            _ => return false,
        };
        self.at += skip;
        self.newline();
        while matches!(self.peek(), Some(b' ' | b'\t')) {
            self.at += 1;
        }
        true
    }

    /// The words of the next command, with its first line; `None` at the
    /// end of the text.
    fn statement(&mut self) -> Result<Option<(usize, Vec<Word>)>, ParseError> {
        let mut words: Vec<Word> = Vec::new();
        let mut first = None;
        let start = self.at;
        loop {
            if self.at.saturating_sub(start) > MAX_STATEMENT {
                return Err(err(
                    first.unwrap_or(self.line),
                    1,
                    format!("command longer than {MAX_STATEMENT} bytes"),
                ));
            }
            let Some(b) = self.peek() else {
                return Ok(first.map(|l| (l, words)));
            };
            match b {
                b'\n' => {
                    self.at += 1;
                    self.newline();
                    if let Some(l) = first {
                        return Ok(Some((l, words)));
                    }
                }
                b';' => {
                    self.at += 1;
                    if let Some(l) = first {
                        return Ok(Some((l, words)));
                    }
                }
                b' ' | b'\t' | b'\r' => self.at += 1,
                b'\\' if self.continuation() => {}
                b'#' if words.is_empty() => {
                    while self.peek().is_some_and(|c| c != b'\n') {
                        self.at += 1;
                    }
                }
                b'[' | b']' => {
                    first.get_or_insert(self.line);
                    words.push(Word {
                        key: None,
                        value: String::new(),
                        bracket: Some(char::from(b)),
                        line: self.line,
                        column: self.column(),
                    });
                    self.at += 1;
                }
                _ => {
                    first.get_or_insert(self.line);
                    if words.len() >= MAX_ARGS + 8 {
                        return Err(err(
                            self.line,
                            self.column(),
                            format!("more than {MAX_ARGS} arguments"),
                        ));
                    }
                    let w = self.word()?;
                    words.push(w);
                }
            }
        }
    }

    /// One word: `key=value`, `key="value"`, or a bare word.
    fn word(&mut self) -> Result<Word, ParseError> {
        let (line, column) = (self.line, self.column());
        let mut buf: Vec<u8> = Vec::new();
        let mut key: Option<Vec<u8>> = None;
        let mut quoted = false;
        let mut quote_at = (line, column);
        loop {
            if buf.len() > MAX_VALUE {
                return Err(err(line, column, format!("value longer than {MAX_VALUE} bytes")));
            }
            let Some(b) = self.peek() else {
                if quoted {
                    return Err(err(quote_at.0, quote_at.1, "quote not closed"));
                }
                break;
            };
            match b {
                b'"' => {
                    if !quoted {
                        quote_at = (self.line, self.column());
                    }
                    quoted = !quoted;
                    self.at += 1;
                }
                b'\\' => {
                    if self.continuation() {
                        continue;
                    }
                    let (l, c) = (self.line, self.column());
                    self.at += 1;
                    let Some(e) = self.peek() else {
                        return Err(err(l, c, "\\ at the end of the text"));
                    };
                    self.at += 1;
                    let byte = match e {
                        b'"' | b'\\' | b'$' | b'?' | b'\'' | b';' | b'[' | b']' | b'{' | b'}'
                        | b'=' => e,
                        b'n' => b'\n',
                        b'r' => b'\r',
                        b't' => b'\t',
                        b'_' => b' ',
                        b'a' => 0x07,
                        b'b' => 0x08,
                        b'f' => 0x0c,
                        b'v' => 0x0b,
                        _ => {
                            let lo = self.peek().and_then(hex);
                            match (hex(e), lo) {
                                (Some(h), Some(lo)) => {
                                    self.at += 1;
                                    h << 4 | lo
                                }
                                _ => {
                                    return Err(err(
                                        l,
                                        c,
                                        "unknown escape (\\\" \\\\ \\n \\r \\t \\$ \\? \\_ or \\XX in hex)",
                                    ));
                                }
                            }
                        }
                    };
                    buf.push(byte);
                }
                b'\n' if quoted => {
                    return Err(err(quote_at.0, quote_at.1, "quote not closed on its line"));
                }
                b' ' | b'\t' | b'\r' | b'\n' | b';' if !quoted => break,
                b'[' | b']' if !quoted => break,
                b'=' if !quoted && key.is_none() && !buf.is_empty() => {
                    key = Some(std::mem::take(&mut buf));
                    self.at += 1;
                }
                _ => {
                    buf.push(b);
                    self.at += 1;
                }
            }
        }
        let key = match key {
            Some(k) => {
                let ok = k.len() <= 64
                    && k.iter().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.'));
                if !ok {
                    return Err(err(line, column, "bad argument name (letters, digits and -)"));
                }
                Some(text_of(k))
            }
            None => None,
        };
        Ok(Word {
            key,
            value: text_of(buf),
            bracket: None,
            line,
            column,
        })
    }
}

/// The verbs a menu path ends before.
fn is_verb(w: &str) -> bool {
    matches!(
        w,
        "add" | "set" | "remove" | "print" | "export" | "enable" | "disable" | "edit" | "find"
            | "get" | "unset" | "reset" | "comment" | "move"
    )
}

/// `[ find name=x ]` and friends; `words` starts after `[`. Returns the
/// target and how many words it took (with the `]`).
fn target(words: &[Word], open: &Word) -> Result<(Target, usize), ParseError> {
    let close = words
        .iter()
        .position(|w| w.bracket == Some(']'))
        .ok_or_else(|| err(open.line, open.column, "[ not closed"))?;
    let inner = words.get(..close).unwrap_or_default();
    let unsupported = || {
        err(
            open.line,
            open.column,
            "only [ find name=… ] and [ find default=yes ] are understood",
        )
    };
    let mut it = inner.iter().peekable();
    match it.next() {
        Some(w) if w.key.is_none() && w.bracket.is_none() && w.value == "find" => {}
        _ => return Err(unsupported()),
    }
    if it.peek().is_some_and(|w| w.key.is_none() && w.value == "where") {
        it.next();
    }
    let rest: Vec<&Word> = it.collect();
    let t = match rest.as_slice() {
        [w] if w.key.as_deref() == Some("name") => Target::Name(w.value.clone()),
        [w] if w.key.as_deref() == Some("default") && w.value == "yes" => Target::Default,
        _ => return Err(unsupported()),
    };
    Ok((t, close + 1))
}

/// The `add`/`set` commands of the menus `wanted` accepts (`"ppp secret"`)
/// in `text`.
pub fn parse(text: &str, wanted: impl Fn(&str) -> bool) -> Result<Script, ParseError> {
    if text.len() > MAX_TEXT {
        return Err(err(1, 1, format!("script longer than {} MiB", MAX_TEXT >> 20)));
    }
    let mut lx = Lexer::new(text);
    let mut out = Script::default();
    let mut cur: Vec<String> = Vec::new();
    while let Some((line, words)) = lx.statement()? {
        let mut words = words.into_iter().peekable();
        let mut menu = cur.clone();
        let mut absolute = false;
        // The menu in front: `/ppp secret add …`, `/ppp/secret`.
        while let Some(w) = words.peek() {
            if w.key.is_some() || w.bracket.is_some() {
                break;
            }
            let v = w.value.as_str();
            if let Some(path) = v.strip_prefix('/') {
                absolute = true;
                menu = path.split('/').filter(|p| !p.is_empty()).map(str::to_owned).collect();
            } else if absolute && !is_verb(v) && !v.starts_with(':') {
                menu.extend(v.split('/').filter(|p| !p.is_empty()).map(str::to_owned));
            } else {
                break;
            }
            words.next();
        }
        let rest: Vec<Word> = words.collect();
        let Some(first) = rest.first() else {
            // A menu line alone.
            cur = menu;
            continue;
        };
        let menu_text = menu.join(" ");
        if !wanted(&menu_text) {
            out.other_menus += 1;
            continue;
        }
        let verb = match (first.key.as_deref(), first.value.as_str()) {
            (None, "add") => Verb::Add,
            (None, "set") => Verb::Set,
            _ => {
                out.ignored += 1;
                continue;
            }
        };
        let mut target_of = None;
        let mut args = Vec::new();
        let mut i = 1;
        while let Some(w) = rest.get(i) {
            match (&w.key, w.bracket) {
                (_, Some('[')) if verb == Verb::Set && target_of.is_none() && args.is_empty() => {
                    let (t, used) = target(rest.get(i + 1..).unwrap_or_default(), w)?;
                    target_of = Some(t);
                    i += used + 1;
                    continue;
                }
                (_, Some(_)) => return Err(err(w.line, w.column, "unexpected [ or ]")),
                (Some(k), None) => {
                    if args.len() >= MAX_ARGS {
                        return Err(err(w.line, w.column, format!("more than {MAX_ARGS} arguments")));
                    }
                    args.push((k.clone(), w.value.clone()));
                }
                (None, None)
                    if verb == Verb::Set
                        && target_of.is_none()
                        && args.is_empty()
                        && w.value.len() <= 17
                        && w.value.strip_prefix('*').is_some_and(|h| {
                            !h.is_empty() && h.bytes().all(|b| b.is_ascii_hexdigit())
                        }) =>
                {
                    target_of = Some(Target::Id(w.value.clone()));
                }
                (None, None) => {
                    return Err(err(
                        w.line,
                        w.column,
                        if verb == Verb::Set {
                            "set needs [ find name=… ] (a bare item is not understood)"
                        } else {
                            "expected key=value"
                        },
                    ));
                }
            }
            i += 1;
        }
        if verb == Verb::Set && target_of.is_none() {
            return Err(err(first.line, first.column, "set needs [ find name=… ]"));
        }
        if out.items.len() >= MAX_ITEMS {
            return Err(err(line, 1, format!("more than {MAX_ITEMS} commands")));
        }
        out.items.push(Item {
            line,
            menu: menu_text,
            verb,
            target: target_of,
            args,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn ppp(m: &str) -> bool {
        m == "ppp secret" || m == "ppp profile"
    }

    #[test]
    fn a_routeros_export() {
        let t = "# 2026-10-26 by RouterOS 7.20.2\n# software id = ABCD-1234\n#\n/interface bridge\nadd name=br1\n/ppp profile\nadd local-address=10.0.0.1 name=plano-100M rate-limit=100M/100M \\\n    remote-address=clientes\nset [ find default=yes ] only-one=yes\nset *FFFFFFFE use-encryption=yes\n/ppp secret\nadd caller-id=AA:BB:CC:00:00:01 comment=\"Jo\\C3\\A3o \\\"Z\\\" da Silva\" name=joao@isp \\\n    password=\"s3n h4\\$x\" profile=plano-100M remote-address=100.64.0.10 \\\n    service=pppoe\nadd name=maria password=\"\" disabled=yes\nset [ find where name=joao@isp ] limit-bytes-out=1000\n/ppp/secret add name=terse password=x; add name=two password=y\n";
        let s = parse(t, ppp).unwrap();
        assert_eq!(s.other_menus, 1);
        assert_eq!(s.items.len(), 8);
        let p = &s.items[0];
        assert_eq!((p.menu.as_str(), p.line), ("ppp profile", 6 + 1));
        assert_eq!(p.get("remote-address"), Some("clientes"));
        assert_eq!(s.items[1].target, Some(Target::Default));
        assert_eq!(s.items[2].target, Some(Target::Id("*FFFFFFFE".into())));
        let j = &s.items[3];
        assert_eq!(j.get("comment"), Some("João \"Z\" da Silva"));
        assert_eq!(j.get("password"), Some("s3n h4$x"));
        assert_eq!(j.get("service"), Some("pppoe"));
        assert_eq!(j.line, 12);
        assert_eq!(s.items[4].get("password"), Some(""));
        assert_eq!(s.items[5].target, Some(Target::Name("joao@isp".into())));
        assert_eq!(s.items[6].menu, "ppp secret");
        assert_eq!(s.items[7].get("name"), Some("two"));
    }

    #[test]
    fn continuation_inside_a_quoted_value_and_latin1() {
        let s = parse(
            "/ppp secret\nadd name=a comment=\"long comm\\\n    ent\" password=\\E7\\_x\n",
            ppp,
        )
        .unwrap();
        assert_eq!(s.items[0].get("comment"), Some("long comment"));
        assert_eq!(s.items[0].get("password"), Some("ç x"));
    }

    #[test]
    fn errors_say_where_but_never_what() {
        for (t, line, what) in [
            ("/ppp secret\nadd name=a password=\"t0p-s3cret\n", 2, "quote not closed"),
            ("/ppp secret\nadd name=a password=t0p\\qs3cret\n", 2, "unknown escape"),
            ("/ppp secret\nadd name=a t0p-s3cret\n", 2, "key=value"),
            ("/ppp secret\nset t0p-s3cret password=x\n", 2, "find"),
            ("/ppp secret\nset [ find comment=t0p-s3cret ] password=x\n", 2, "find name"),
            ("/ppp secret\nadd name=a pass\u{1}word=t0p-s3cret\n", 2, "argument name"),
        ] {
            let e = parse(t, ppp).unwrap_err();
            assert_eq!(e.line, line, "{t:?}: {e}");
            assert!(e.message.contains(what), "{t:?}: {e}");
            assert!(!e.to_string().contains("t0p") && !e.to_string().contains("s3cret"), "{e}");
        }
    }

    #[test]
    fn bounds() {
        let long = format!("/ppp secret\nadd name=a comment=\"{}\"\n", "x".repeat(MAX_VALUE + 1));
        assert!(parse(&long, ppp).unwrap_err().message.contains("value longer"));
        let many: String = (0..=MAX_ARGS).map(|i| format!(" k{i}=v")).collect();
        assert!(parse(&format!("/ppp secret\nadd{many}\n"), ppp).is_err());
        let wrapped = format!("/ppp secret\nadd{}name=a\n", " \\\n".repeat(MAX_STATEMENT / 2));
        assert!(parse(&wrapped, ppp).unwrap_err().message.contains("longer than"));
        // Other menus are read (quotes kept in step) but not kept.
        let s = parse("/ip address\nadd comment=\"/ppp secret\" address=1.2.3.4/24\n", ppp).unwrap();
        assert!(s.items.is_empty() && s.other_menus == 1);
        let s = parse("/ppp secret\nremove [ find ]\nprint\n:put x\n", ppp).unwrap();
        assert_eq!((s.items.len(), s.ignored), (0, 3));
    }

    proptest! {
        // Garbage never panics, and an error never quotes the text.
        #[test]
        fn hostile_text_never_panics(t in "(/ppp secret\n|add |set |\\[ find |\\]|name=|password=|\"|\\\\|\\\\\n|[a-zA-Z0-9 =;#\n\\\\\"\\[\\]çé\\t\\r])*") {
            if let Err(e) = parse(&t, |_| true) {
                prop_assert!(e.line >= 1 && e.column >= 1);
            }
        }

        // A value quoted as our export (and RouterOS) writes it comes back.
        #[test]
        fn quoted_values_round_trip(v in "\\PC{0,40}") {
            let mut q = String::from("\"");
            for b in v.bytes() {
                match b {
                    b'"' | b'\\' | b'$' | b'?' => { q.push('\\'); q.push(char::from(b)); }
                    0x20..=0x7e => q.push(char::from(b)),
                    _ => q.push_str(&format!("\\{b:02X}")),
                }
            }
            q.push('"');
            let s = parse(&format!("/ppp secret\nadd name=a comment={q}\n"), ppp).unwrap();
            prop_assert_eq!(s.items[0].get("comment"), Some(v.as_str()));
        }
    }
}
