//! Styled text: what the terminal prints, as spans the front ends color
//! their own way (ANSI in `corerouter-cli shell` and SSH, egui colors in the
//! GUI's terminal window).

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Style {
    Plain,
    /// Menu words: `/ip address`.
    Menu,
    /// Command verbs: `add`, `print`.
    Verb,
    /// Parameter and property names: `address=`.
    Key,
    Value,
    /// Item references: `0`, `*1`.
    Item,
    /// Column headers and the flags legend.
    Header,
    /// The flags column (`X`, `R`, `A`).
    Flag,
    /// `;;; comment` lines and `#` script comments.
    Comment,
    /// Disabled items, notes.
    Dim,
    Error,
    Warn,
    /// Confirmations (`[Safe Mode taken]`).
    Ok,
    /// The `<SAFE>` mark of the prompt.
    Safe,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Span {
    pub style: Style,
    pub text: String,
}

/// One output line.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Line(pub Vec<Span>);

impl Line {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn styled(style: Style, text: impl Into<String>) -> Self {
        Self(vec![Span {
            style,
            text: text.into(),
        }])
    }

    pub fn plain(text: impl Into<String>) -> Self {
        Self::styled(Style::Plain, text)
    }

    pub fn push(&mut self, style: Style, text: impl Into<String>) -> &mut Self {
        let text = text.into();
        if !text.is_empty() {
            self.0.push(Span { style, text });
        }
        self
    }

    pub fn with(mut self, style: Style, text: impl Into<String>) -> Self {
        self.push(style, text);
        self
    }

    pub fn text(&self) -> String {
        self.0.iter().map(|s| s.text.as_str()).collect()
    }
}

/// What a finished job prints.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Output {
    pub lines: Vec<Line>,
    /// `/quit`: the front end closes the terminal.
    pub quit: bool,
    /// The job failed (a script stops here).
    pub failed: bool,
}

impl Output {
    pub fn lines(lines: Vec<Line>) -> Self {
        Self {
            lines,
            ..Self::default()
        }
    }

    pub fn error(message: impl Into<String>) -> Self {
        let message = message.into();
        Self {
            lines: message
                .lines()
                .map(|l| Line::styled(Style::Error, l))
                .collect(),
            failed: true,
            quit: false,
        }
    }

    pub fn text(&self) -> String {
        let mut s = String::new();
        for l in &self.lines {
            s.push_str(&l.text());
            s.push('\n');
        }
        s
    }

    pub fn append(&mut self, other: Output) {
        self.lines.extend(other.lines);
        self.quit |= other.quit;
        self.failed |= other.failed;
    }
}

/// ANSI SGR codes for a style (terminal front ends).
pub fn ansi(style: Style) -> &'static str {
    match style {
        Style::Plain | Style::Value => "",
        Style::Menu => "\x1b[34;1m",
        Style::Verb => "\x1b[36;1m",
        Style::Key => "\x1b[32m",
        Style::Item => "\x1b[35m",
        Style::Header => "\x1b[1m",
        Style::Flag => "\x1b[33m",
        Style::Comment => "\x1b[2;3m",
        Style::Dim => "\x1b[2m",
        Style::Error => "\x1b[31;1m",
        Style::Warn => "\x1b[33;1m",
        Style::Ok => "\x1b[32;1m",
        Style::Safe => "\x1b[41;97;1m",
    }
}

/// Spans as ANSI text.
pub fn to_ansi(spans: &[Span]) -> String {
    let mut s = String::new();
    for span in spans {
        let code = ansi(span.style);
        if code.is_empty() {
            s.push_str(&span.text);
        } else {
            s.push_str(code);
            s.push_str(&span.text);
            s.push_str("\x1b[0m");
        }
    }
    s
}
