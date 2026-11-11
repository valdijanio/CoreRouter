//! How the local console looks (G1.6zg): the one table of styles, the
//! colour switch, and the few layout helpers the setup and the installer
//! share. Nothing else in the init writes an escape sequence.
//!
//! The console is three things at once: the kernel's virtual terminal (VGA
//! text or a framebuffer, the kernel's built-in font), a serial line whose
//! terminal nobody knows (`screen`, PuTTY, a BMC's serial-over-LAN, a file),
//! and whatever reads either by machine. So the rules are conservative:
//!
//! - **Only SGR** (ECMA-48 §8.3.117, `ESC [ … m`): bold, faint and the eight
//!   colours, and a reset at the end of every span and of every line. No
//!   cursor movement, no clearing, no 256 colours. A terminal that knows no
//!   colour ignores the parameters it does not know (the Linux VT too:
//!   `drivers/tty/vt/vt.c`, `csi_m` has no `default:`).
//! - **Only ASCII** in our own text: the serial side may not be UTF-8, and
//!   the kernel's font is CP437.
//! - **At most [`WIDTH`] columns after a [`MARGIN`] of one**, so nothing
//!   wraps on an 80-column VGA text screen (a BIOS boot) or a serial
//!   terminal, and nothing is lost where column 0 is cut (overscan).
//! - **Readable without colour**: the colour repeats what a word already
//!   says (`OK`, `WARNING`, `FAILED`); with `corerouter.color=off`, `NO_COLOR`
//!   or `TERM=dumb` on the kernel command line the text is the same, minus
//!   the escapes.
//!
//! Text is built with in-band marks ([`paint`]) and turned into what a
//! console gets by [`render`], which is also where foreign text (an error
//! from the daemon, a disk's model string, what was typed on the other
//! console) loses its control characters: nothing but this file can make a
//! terminal do anything.

/// The widest line we write, after the [`MARGIN`]: column 80 stays free
/// (some serial terminals wrap when the last column is written, not after
/// it).
pub const WIDTH: usize = 78;

/// Columns left empty before every line: a monitor with overscan and some
/// serial consoles cut column 0, and a heading that starts there loses its
/// first letter. [`render`] adds it; no text of ours starts with it.
pub const MARGIN: usize = 1;

// Column 0 and column 79 of an 80-column screen stay empty.
const _: () = assert!(MARGIN >= 1 && MARGIN + WIDTH < 80);

/// Opens a styled span; the next character is the style's tag.
const OPEN: char = '\u{1}';
/// Closes a styled span.
const CLOSE: char = '\u{2}';

/// What a piece of text is, not how it looks: the looks are [`Style::sgr`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Style {
    /// A heading: the product line, a step, a table's header.
    Title,
    /// What the eye should find first: the address to manage the router at,
    /// a key to press.
    Key,
    /// Went well (`OK`, `up`).
    Good,
    /// Needs attention, nothing is broken (`WARNING`).
    Warn,
    /// Failed, or destroys something (`FAILED`, "all data will be erased").
    Bad,
    /// Detail a person rarely needs: hashes, timings, what is not offered.
    Dim,
    /// A question waiting for an answer.
    Ask,
}

impl Style {
    pub const ALL: [Style; 7] = [
        Style::Title,
        Style::Key,
        Style::Good,
        Style::Warn,
        Style::Bad,
        Style::Dim,
        Style::Ask,
    ];

    fn tag(self) -> char {
        match self {
            Style::Title => 'T',
            Style::Key => 'K',
            Style::Good => 'G',
            Style::Warn => 'W',
            Style::Bad => 'B',
            Style::Dim => 'D',
            Style::Ask => 'A',
        }
    }

    fn from_tag(c: char) -> Option<Style> {
        Style::ALL.into_iter().find(|s| s.tag() == c)
    }

    /// The SGR parameters. On the Linux VT bold is the bright colour, not a
    /// heavier font (`vt.c`, `build_attr`: `a ^= 0x08`), so "bold yellow" is
    /// yellow where plain 33 is brown on VGA; blue is left out (dark blue on
    /// black is unreadable on VGA). Faint (2) is dark grey on the VT and
    /// ignored by terminals without it.
    pub fn sgr(self) -> &'static str {
        match self {
            Style::Title => "1",
            Style::Key => "1;36",
            Style::Good => "32",
            Style::Warn => "1;33",
            Style::Bad => "1;31",
            Style::Dim => "2",
            Style::Ask => "1;33",
        }
    }
}

/// `text` as a span of `style`. Marks do not nest: a span inside a span ends
/// the outer one.
pub fn paint(style: Style, text: &str) -> String {
    format!("{OPEN}{}{text}{CLOSE}", style.tag())
}

pub fn title(text: &str) -> String {
    paint(Style::Title, text)
}
pub fn key(text: &str) -> String {
    paint(Style::Key, text)
}
pub fn good(text: &str) -> String {
    paint(Style::Good, text)
}
pub fn warn(text: &str) -> String {
    paint(Style::Warn, text)
}
pub fn bad(text: &str) -> String {
    paint(Style::Bad, text)
}
pub fn dim(text: &str) -> String {
    paint(Style::Dim, text)
}

/// A question, the same way everywhere: `  Question [default] (keys): `,
/// the default answer (what Enter means) in brackets, the other keys or the
/// expected form in parentheses. The answer is typed after it, so it has no
/// newline.
pub fn prompt(question: &str, default: Option<&str>, hint: Option<&str>) -> String {
    let mut q = question.to_owned();
    if let Some(d) = default {
        q.push_str(&format!(" [{d}]"));
    }
    let mut out = format!("  {}", paint(Style::Ask, &q));
    if let Some(h) = hint {
        out.push_str(&format!(" {}", dim(&format!("({h})"))));
    }
    out.push_str(": ");
    out
}

/// A step of a guided flow: `[2/5] Disk`, after a blank line.
pub fn step(n: usize, of: usize, name: &str) -> String {
    format!("\n{}", title(&format!("[{n}/{of}] {name}")))
}

/// The top of a screen: a blank line, `left` as the title with `right`
/// against the margin, and a rule.
pub fn header(left: &str, right: &str) -> String {
    format!("\n{}\n{}", spread(&title(left), right), rule())
}

/// What the kernel command line says about colour.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Color {
    /// Every console (the default).
    On,
    /// Only the screen (the kernel's virtual terminals): the serial line
    /// stays plain, for a terminal or a logger that shows escapes as text.
    Screen,
    Off,
}

impl Color {
    /// `corerouter.color=on|screen|off` wins. Without it, the two
    /// conventions a kernel command line can carry: `NO_COLOR=<anything>`
    /// (no-color.org: present and not empty) and `TERM=dumb`, both of which
    /// the kernel would hand to init as environment.
    pub fn from_cmdline(cmdline: &str) -> Color {
        let mut ours = None;
        let mut convention = None;
        for word in cmdline.split_ascii_whitespace() {
            match word.split_once('=') {
                Some(("corerouter.color", v)) => {
                    ours = match v {
                        "on" => Some(Color::On),
                        "screen" => Some(Color::Screen),
                        "off" => Some(Color::Off),
                        _ => ours,
                    }
                }
                Some(("NO_COLOR", v)) if !v.is_empty() => convention = Some(Color::Off),
                Some(("TERM", "dumb")) => convention = Some(Color::Off),
                _ => {}
            }
        }
        ours.or(convention).unwrap_or(Color::On)
    }

    /// The running kernel's.
    pub fn current() -> Color {
        Color::from_cmdline(&std::fs::read_to_string("/proc/cmdline").unwrap_or_default())
    }

    /// Whether console `tty` (`tty1`, `ttyS0`) gets escapes.
    pub fn on(self, tty: &str) -> bool {
        match self {
            Color::On => true,
            Color::Off => false,
            Color::Screen => is_screen(tty),
        }
    }
}

/// A kernel virtual terminal (`tty<N>`), as opposed to a serial line
/// (`ttyS0`, `ttyAMA0`, `hvc0`).
fn is_screen(tty: &str) -> bool {
    tty.strip_prefix("tty")
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

/// What a console gets for `text`, which starts at the beginning of a
/// line: the [`MARGIN`] before every line that is not empty, the marks as
/// SGR sequences (`color`) or as nothing, every styled line closed by a
/// reset, and every other control character replaced, so foreign text
/// cannot drive the terminal. Newlines stay; a tab becomes a space.
pub fn render(text: &str, color: bool) -> String {
    lay(text, color, true)
}

/// Like [`render`] for text that goes on after what is already on the
/// line (a progress mark, the echo of an answer): no margin before its
/// first line.
pub fn render_more(text: &str, color: bool) -> String {
    lay(text, color, false)
}

fn lay(text: &str, color: bool, at_start: bool) -> String {
    let mut out = String::with_capacity(text.len() + 16);
    // Whether the next character is the first of its line.
    let mut at_start = at_start;
    // The span in force, and whether its SGR is out on this line.
    let mut span: Option<Style> = None;
    let mut lit = false;
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        match c {
            OPEN => {
                if lit {
                    out.push_str("\x1b[0m");
                    lit = false;
                }
                span = chars.next().and_then(Style::from_tag);
            }
            CLOSE => {
                if lit {
                    out.push_str("\x1b[0m");
                    lit = false;
                }
                span = None;
            }
            '\n' => {
                if lit {
                    out.push_str("\x1b[0m");
                    lit = false;
                }
                out.push('\n');
                at_start = true;
            }
            _ => {
                if at_start {
                    out.push_str(&" ".repeat(MARGIN));
                    at_start = false;
                }
                if let (Some(s), true, false) = (span, color, lit) {
                    out.push_str("\x1b[");
                    out.push_str(s.sgr());
                    out.push('m');
                    lit = true;
                }
                out.push(match c {
                    '\t' => ' ',
                    c if c.is_control() => '?',
                    c => c,
                });
            }
        }
    }
    if lit {
        out.push_str("\x1b[0m");
    }
    out
}

/// Columns `text` takes on the screen (marks take none).
pub fn width(text: &str) -> usize {
    let mut n = 0;
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        match c {
            OPEN => {
                chars.next();
            }
            CLOSE => {}
            _ => n += 1,
        }
    }
    n
}

/// `text` padded with spaces to `cols` columns (a table cell); longer text
/// is left as it is. `format!("{:<8}")` would count the marks.
pub fn cell(text: &str, cols: usize) -> String {
    let mut s = text.to_owned();
    for _ in width(text)..cols {
        s.push(' ');
    }
    s
}

/// `text` cut to `cols` columns, the last one a `~` when something was cut
/// (a disk's model, a machine's name). Plain text only.
pub fn clip(text: &str, cols: usize) -> String {
    if text.chars().count() <= cols {
        return text.to_owned();
    }
    let mut s: String = text.chars().take(cols.saturating_sub(1)).collect();
    s.push('~');
    s
}

/// Foreign text made safe for a single line of ours: ASCII printable only
/// (anything else becomes `?`), runs of spaces collapsed, trimmed.
pub fn ascii(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.trim().chars() {
        let c = if c.is_ascii_graphic() {
            c
        } else if c.is_whitespace() {
            ' '
        } else {
            '?'
        };
        if c == ' ' && out.ends_with(' ') {
            continue;
        }
        out.push(c);
    }
    out
}

/// `text` broken at spaces into lines of at most `cols` columns; a word
/// longer than a line is cut. Marks are kept and take no room; newlines in
/// `text` start a new line.
pub fn wrap(text: &str, cols: usize) -> Vec<String> {
    let cols = cols.max(8);
    let mut lines = Vec::new();
    for para in text.split('\n') {
        let mut line = String::new();
        for word in para.split(' ').filter(|w| !w.is_empty()) {
            let mut word = word.to_owned();
            loop {
                let room = cols.saturating_sub(width(&line) + usize::from(!line.is_empty()));
                if width(&word) <= room {
                    if !line.is_empty() {
                        line.push(' ');
                    }
                    line.push_str(&word);
                    break;
                }
                if !line.is_empty() {
                    lines.push(std::mem::take(&mut line));
                    continue;
                }
                // Longer than a whole line: cut it (marks are not expected
                // in such a word; a cut one is closed by `render`).
                let head: String = word.chars().take(cols).collect();
                word = word.chars().skip(cols).collect();
                lines.push(head);
            }
        }
        lines.push(line);
    }
    lines
}

/// `label` in a column of `label_cols`, then `text` wrapped beside it, the
/// following lines indented under the first: a `WARNING  …` paragraph, a
/// `Cause  …` row. The whole block is indented by `indent` and fits
/// [`WIDTH`].
pub fn block(indent: usize, label: &str, label_cols: usize, text: &str) -> String {
    let room = WIDTH.saturating_sub(indent + label_cols);
    let pad = " ".repeat(indent);
    let mut out = String::new();
    for (i, line) in wrap(text, room).into_iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(&pad);
        out.push_str(&cell(if i == 0 { label } else { "" }, label_cols));
        out.push_str(&line);
    }
    out
}

/// A horizontal rule.
pub fn rule() -> String {
    "-".repeat(WIDTH)
}

/// `left` and `right` on one line, `right` against column [`WIDTH`]; when
/// both do not fit, `right` is cut.
pub fn spread(left: &str, right: &str) -> String {
    if right.is_empty() {
        return left.to_owned();
    }
    let room = WIDTH.saturating_sub(width(left) + 2);
    let right = clip(right, room);
    let gap = WIDTH.saturating_sub(width(left) + width(&right));
    format!("{left}{}{right}", " ".repeat(gap))
}

/// What was typed on a console, as an answer: the characters a terminal
/// that erases with `^H` or `DEL` left in the line are applied (the tty's
/// own line editing knows only one of the two), escape sequences (an arrow
/// key) and other control characters are dropped, the rest is trimmed.
pub fn typed(line: &str) -> String {
    let mut out = String::new();
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\u{8}' | '\u{7f}' => {
                out.pop();
            }
            '\u{1b}' => {
                // CSI (`ESC [ … final`) or a two-character escape.
                if chars.next_if_eq(&'[').is_some() || chars.next_if_eq(&'O').is_some() {
                    for n in chars.by_ref() {
                        if ('\u{40}'..='\u{7e}').contains(&n) {
                            break;
                        }
                    }
                } else {
                    chars.next();
                }
            }
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out.trim().to_owned()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// What every text of ours must hold, with and without colour: ASCII
    /// only, no line that starts in column 0 or passes column 79 of 80, no
    /// escape with the colour off, every coloured line closed by a reset
    /// and only SGR among the escapes.
    pub(crate) fn check(what: &str, text: &str) {
        let plain = render(text, false);
        assert!(
            !plain.contains('\u{1b}') && !plain.contains(OPEN) && !plain.contains(CLOSE),
            "{what}: escape or mark with the colour off: {plain:?}"
        );
        for line in plain.lines() {
            assert!(
                line.is_ascii() && !line.chars().any(|c| c.is_ascii_control()),
                "{what}: not plain ASCII: {line:?}"
            );
            assert!(
                line.len() <= MARGIN + WIDTH,
                "{what}: {} columns: {line:?}",
                line.len()
            );
            assert!(
                line.is_empty() || line.starts_with(' '),
                "{what}: starts in column 0: {line:?}"
            );
            // A prompt ends in ": " and waits there; nothing else trails.
            assert!(
                !line.ends_with(' ') || line.ends_with(": "),
                "{what}: trailing space: {line:?}"
            );
        }
        let lit = render(text, true);
        for line in lit.lines() {
            let mut open = false;
            let mut rest = line;
            while let Some(i) = rest.find('\u{1b}') {
                let seq = &rest[i..];
                let end = seq
                    .find('m')
                    .unwrap_or_else(|| panic!("{what}: not SGR: {line:?}"));
                let params = &seq[2..end];
                assert!(seq.starts_with("\u{1b}["), "{what}: not CSI: {line:?}");
                assert!(
                    params == "0" || Style::ALL.iter().any(|s| s.sgr() == params),
                    "{what}: SGR {params:?} is not in the table: {line:?}"
                );
                open = params != "0";
                rest = &seq[end + 1..];
            }
            assert!(!open, "{what}: line ends with a style on: {line:?}");
        }
        // The colour changes nothing but the escapes.
        let mut stripped = String::new();
        let mut it = lit.chars();
        while let Some(c) = it.next() {
            if c == '\u{1b}' {
                for n in it.by_ref() {
                    if n == 'm' {
                        break;
                    }
                }
            } else {
                stripped.push(c);
            }
        }
        assert_eq!(stripped, plain, "{what}");
    }

    #[test]
    fn the_table_is_only_basic_sgr() {
        for s in Style::ALL {
            // Bold, faint and the eight foreground colours: nothing a VT100
            // or the Linux VT would not take or ignore.
            for p in s.sgr().split(';') {
                let n: u8 = p.parse().unwrap();
                assert!(n == 1 || n == 2 || (30..=37).contains(&n), "{s:?}: {p}");
                assert_ne!(n, 34, "{s:?}: dark blue on black cannot be read on VGA");
            }
            assert_eq!(Style::from_tag(s.tag()), Some(s));
        }
    }

    #[test]
    fn no_visible_line_starts_in_column_0_or_passes_column_80() {
        // The pieces every screen is made of (the screens themselves go
        // through `check` in `setup` and `install`): a monitor with overscan
        // cut the "C" of the header that started in column 0.
        let long = "word ".repeat(60);
        let text = [
            header("CoreRouter 0.1.0-dev.555", &"m".repeat(120)),
            step(1, 5, "Medium"),
            block(2, &warn("WARNING"), 9, &long),
            block(0, "", 0, &long),
            prompt("Disk to install on", Some("1"), Some("r = rescan")),
        ]
        .join("\n");
        check("pieces", &text);
        for color in [false, true] {
            for line in render(&text, color).lines().filter(|l| !l.is_empty()) {
                assert!(line.starts_with(' '), "{line:?}");
                let visible = console_width(line);
                assert!(visible <= 79, "{visible} columns: {line:?}");
            }
        }
        // The widest we write: the rule, in columns 1 to 78.
        assert_eq!(render(&rule(), false).len(), MARGIN + WIDTH);
    }

    /// Columns of a rendered line: its length without the SGR sequences.
    fn console_width(line: &str) -> usize {
        let mut n = 0;
        let mut it = line.chars();
        while let Some(c) = it.next() {
            if c == '\u{1b}' {
                for m in it.by_ref() {
                    if m == 'm' {
                        break;
                    }
                }
            } else {
                n += 1;
            }
        }
        n
    }

    #[test]
    fn spans_render_as_sgr_or_as_nothing() {
        let t = format!("{} admin has no password", warn("WARNING"));
        assert_eq!(render(&t, false), " WARNING admin has no password");
        assert_eq!(
            render(&t, true),
            " \u{1b}[1;33mWARNING\u{1b}[0m admin has no password"
        );
        // What goes on after a line that is already there has no margin.
        assert_eq!(render_more(" 10%", false), " 10%");
        assert_eq!(render_more("vda\nnext", false), "vda\n next");
        check("warn", &t);
    }

    #[test]
    fn every_coloured_line_is_closed_and_reopened() {
        let t = bad("ALL DATA ON sda\nWILL BE ERASED");
        assert_eq!(
            render(&t, true),
            " \u{1b}[1;31mALL DATA ON sda\u{1b}[0m\n \u{1b}[1;31mWILL BE ERASED\u{1b}[0m"
        );
        // A span left open (text cut in the middle) is closed all the same.
        let cut = &title("CoreRouter")[..6];
        assert!(render(cut, true).ends_with("\u{1b}[0m"));
        check("multi-line", &t);
    }

    #[test]
    fn foreign_text_cannot_drive_the_terminal() {
        // A disk model, a daemon error or a line typed on the other console
        // with an escape sequence, a bell, a carriage return, a C1 control.
        let evil = "x\u{1b}[2J\u{1b}]0;t\u{7}\r\u{9b}31m\u{0}y\tz";
        for color in [false, true] {
            let r = render(&dim(evil), color);
            let body = r.replace("\u{1b}[2m", "").replace("\u{1b}[0m", "");
            assert!(!body.chars().any(char::is_control), "{body:?}");
            assert!(body.starts_with(" x?[2J?]0;t???31m?y z"), "{body:?}");
        }
        // Our own marks inside foreign text only restyle it.
        assert_eq!(render("a\u{1}Zb\u{2}c", true), " abc");
        assert_eq!(
            ascii("  Sam\u{1b}sung   SSD\u{e9} 980 "),
            "Sam?sung SSD? 980"
        );
    }

    #[test]
    fn colour_is_on_by_default_and_the_command_line_turns_it_off() {
        let c = Color::from_cmdline;
        assert_eq!(c("console=tty0 console=ttyS0,115200 quiet"), Color::On);
        assert_eq!(c("quiet corerouter.color=off"), Color::Off);
        assert_eq!(c("corerouter.color=screen"), Color::Screen);
        // The conventions: NO_COLOR present and not empty, TERM=dumb.
        assert_eq!(c("NO_COLOR=1"), Color::Off);
        assert_eq!(c("NO_COLOR="), Color::On);
        assert_eq!(c("TERM=dumb"), Color::Off);
        assert_eq!(c("TERM=vt100"), Color::On);
        // Ours wins either way; a bad value changes nothing.
        assert_eq!(c("NO_COLOR=1 corerouter.color=on"), Color::On);
        assert_eq!(c("corerouter.color=purple"), Color::On);
        assert_eq!(
            c("corerouter.color=off corerouter.color=purple"),
            Color::Off
        );

        assert!(Color::On.on("ttyS0") && Color::On.on("tty1"));
        assert!(!Color::Off.on("ttyS0") && !Color::Off.on("tty1"));
        assert!(Color::Screen.on("tty1") && Color::Screen.on("tty12"));
        for serial in ["ttyS0", "ttyAMA0", "hvc0", "tty", "ttyUSB0"] {
            assert!(!Color::Screen.on(serial), "{serial}");
        }
    }

    #[test]
    fn cells_and_wrapping_count_columns_not_marks() {
        assert_eq!(width(&good("up")), 2);
        assert_eq!(cell(&good("up"), 6), format!("{}    ", good("up")));
        assert_eq!(cell("toolong", 3), "toolong");
        assert_eq!(clip("Samsung SSD 980 PRO", 10), "Samsung S~");
        assert_eq!(clip("short", 10), "short");

        let text = "admin has no password: anyone who reaches the router logs in as admin with an empty password";
        let lines = wrap(text, 40);
        assert!(
            lines.len() >= 3 && lines.iter().all(|l| l.len() <= 40),
            "{lines:?}"
        );
        assert_eq!(lines.join(" "), text);
        // A word longer than the line is cut, never overflows.
        let long = "x".repeat(100);
        assert!(wrap(&long, 30).iter().all(|l| l.len() <= 30));
        assert_eq!(wrap(&long, 30).concat(), long);
        assert_eq!(wrap("a\n\nb", 10), ["a", "", "b"]);

        let b = block(2, &warn("WARNING"), 9, text);
        check("block", &b);
        let plain = render(&b, false);
        assert!(
            plain.starts_with("   WARNING  admin has no password"),
            "{plain}"
        );
        assert!(
            plain.lines().skip(1).all(|l| l.starts_with("            ")),
            "{plain}"
        );

        assert_eq!(
            render(
                &prompt("Disk to install on", Some("1"), Some("r = rescan")),
                false
            ),
            "   Disk to install on [1] (r = rescan): "
        );
        assert_eq!(
            render(&prompt("Apply?", Some("y/N"), None), false),
            "   Apply? [y/N]: "
        );
        check("prompt", &prompt("Gateway", Some("none"), None));
        // Nothing starts in column 0: not a step, not the header, not the
        // rule under it; an empty line stays empty.
        assert_eq!(render(&step(2, 5, "Disk"), false), "\n [2/5] Disk");
        let h = header("CoreRouter 0.1.0", "QEMU Standard PC");
        check("header", &h);
        let lines: Vec<String> = render(&h, false).lines().map(str::to_owned).collect();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], "");
        assert!(lines[1].starts_with(" CoreRouter 0.1.0 "), "{lines:?}");
        assert_eq!(lines[2], format!(" {}", "-".repeat(WIDTH)));

        assert_eq!(rule().len(), WIDTH);
        let s = spread(
            &title("CoreRouter 0.1.0"),
            "QEMU Standard PC (Q35 + ICH9, 2009)",
        );
        assert_eq!(width(&s), WIDTH);
        check("spread", &s);
        let s = spread("CoreRouter 0.1.0", &"m".repeat(200));
        assert_eq!(width(&s), WIDTH);
    }

    #[test]
    fn typed_lines_are_cleaned() {
        assert_eq!(typed("  ether1 \n"), "ether1");
        // A terminal whose Backspace is ^H where the tty erases with DEL
        // (or the other way round).
        assert_eq!(typed("ethr\u{8}er1"), "ether1");
        assert_eq!(typed("y\u{7f}\u{7f}\u{7f}n"), "n");
        // An arrow key, a function key, a stray escape.
        assert_eq!(typed("1\u{1b}[A\u{1b}OP\u{1b}x2"), "12");
        assert_eq!(typed("\u{1}Bvda\u{2}\u{7}"), "Bvda");
    }
}
