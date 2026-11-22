//! Words of a command line. A word ends at unquoted white space; `"…"`
//! quotes keep spaces (`comment="uplink to POP 2"`) and take the escapes
//! `\"`, `\\`, `\n`, `\t`. A word with an unquoted `=` is `key=value`.
//! `;` outside quotes separates commands, `#` starts a comment line.

/// Bounds against hostile input.
pub const MAX_LINE: usize = 16 * 1024;
pub const MAX_WORDS: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Word {
    /// Byte span of the raw word in the line.
    pub start: usize,
    pub end: usize,
    /// The word without quotes and escapes.
    pub text: String,
    /// `Some(key)` for `key=value` (the value is `value`).
    pub key: Option<String>,
    pub value: String,
    /// Byte offset of the value's first raw character (after `=`).
    pub value_start: usize,
    /// A quote was opened and not closed (still being typed).
    pub open_quote: bool,
}

impl Word {
    pub fn is_pair(&self) -> bool {
        self.key.is_some()
    }
}

/// Split a line into words. Never fails: an unclosed quote is reported on
/// the last word (`open_quote`) for the caller to judge.
pub fn words(line: &str) -> Vec<Word> {
    let mut out = Vec::new();
    let mut chars = line.char_indices().peekable();
    while let Some(&(start, ch)) = chars.peek() {
        if ch.is_whitespace() {
            chars.next();
            continue;
        }
        if out.len() >= MAX_WORDS {
            break;
        }
        let mut text = String::new();
        let mut eq: Option<(usize, usize)> = None; // (index in text, raw offset)
        let mut quoted = false;
        let mut end = start;
        while let Some(&(i, c)) = chars.peek() {
            if !quoted && c.is_whitespace() {
                break;
            }
            chars.next();
            end = i + c.len_utf8();
            match c {
                '"' => quoted = !quoted,
                '\\' if quoted => {
                    if let Some((j, e)) = chars.next() {
                        end = j + e.len_utf8();
                        text.push(match e {
                            'n' => '\n',
                            't' => '\t',
                            other => other,
                        });
                    }
                }
                '=' if !quoted && eq.is_none() => {
                    eq = Some((text.len(), end));
                    text.push('=');
                }
                other => text.push(other),
            }
        }
        let (key, value, value_start) = match eq {
            Some((at, raw)) if at > 0 => (
                text.get(..at).map(str::to_owned),
                text.get(at + 1..).unwrap_or("").to_owned(),
                raw,
            ),
            _ => (None, text.clone(), start),
        };
        out.push(Word {
            start,
            end,
            text,
            key,
            value,
            value_start,
            open_quote: quoted,
        });
    }
    out
}

/// Split at `;` outside quotes: `(byte offset, statement)`.
pub fn statements(line: &str) -> Vec<(usize, &str)> {
    let mut out = Vec::new();
    let mut quoted = false;
    let mut escaped = false;
    let mut start = 0usize;
    for (i, c) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match c {
            '\\' if quoted => escaped = true,
            '"' => quoted = !quoted,
            ';' if !quoted => {
                out.push((start, line.get(start..i).unwrap_or("")));
                start = i + 1;
            }
            _ => {}
        }
    }
    out.push((start, line.get(start..).unwrap_or("")));
    out
}

/// Quote a value for a script line when it needs it.
pub fn quote(value: &str) -> String {
    let plain = !value.is_empty()
        && value.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(c, '.' | ':' | '/' | '-' | '_' | '*' | '%' | ',' | '@' | '+')
        });
    if plain {
        return value.to_owned();
    }
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_pairs_and_quotes() {
        let w = words(r#"/ip address add address=10.0.0.1/24 comment="to \"POP\" 2" x"#);
        assert_eq!(w.len(), 6);
        assert_eq!(w[0].text, "/ip");
        assert_eq!(w[3].key.as_deref(), Some("address"));
        assert_eq!(w[3].value, "10.0.0.1/24");
        assert_eq!(w[4].value, "to \"POP\" 2");
        assert!(!w[4].open_quote);
        assert_eq!(w[5].key, None);
        let open = words(r#"add comment="abc"#);
        assert!(open[1].open_quote);
        assert_eq!(open[1].value, "abc");
        let empty = words("set comment=");
        assert_eq!(empty[1].key.as_deref(), Some("comment"));
        assert_eq!(empty[1].value, "");
        assert_eq!(empty[1].value_start, 12);
    }

    #[test]
    fn statements_split_outside_quotes() {
        let s = statements(r#"/ip address; add comment="a;b"; print"#);
        let parts: Vec<&str> = s.iter().map(|(_, s)| s.trim()).collect();
        assert_eq!(parts, ["/ip address", r#"add comment="a;b""#, "print"]);
    }

    #[test]
    fn quote_round_trips() {
        for v in ["ether1", "a b", "", "x\"y\\z\n", "10.0.0.1/24", "ç"] {
            let w = words(&format!("k={}", quote(v)));
            assert_eq!(w[0].value, v, "{v:?}");
        }
    }
}
