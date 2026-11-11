//! The consoles a person may be at (G1.6c): the VGA console (`tty1`) and
//! the serial one (`ttyS0`), both at once. Output goes to every console;
//! the answer to a prompt is the first line typed on any of them. Input
//! typed before a prompt is thrown away, so nothing typed early confirms
//! a later question (an erase).
//!
//! G1.6zg: text carries the marks of [`crate::style`]; each console gets
//! them as colour or as nothing (`corerouter.color=`), and never a control
//! character that is not ours.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::sync::mpsc::{Receiver, channel};
use std::time::Duration;

use crate::style;

/// Longest line read from a console.
const MAX_LINE: u64 = 512;

pub struct Console {
    outs: Vec<Out>,
    /// The lines typed, each with the console (index in `outs`) it came
    /// from.
    rx: Receiver<(usize, String)>,
}

struct Out {
    name: String,
    file: File,
    /// Whether this console gets colour (`style::Color`).
    color: bool,
}

/// The consoles the kernel writes to (`/sys/class/tty/console/active`),
/// `tty0` meaning the first virtual terminal; `skip` is left out (the
/// maintenance shell's).
pub fn active(skip: Option<&str>) -> Vec<String> {
    let text = std::fs::read_to_string("/sys/class/tty/console/active").unwrap_or_default();
    let mut out: Vec<String> = text
        .split_whitespace()
        .map(|t| {
            if t == "tty0" {
                "tty1".to_owned()
            } else {
                t.to_owned()
            }
        })
        .filter(|t| Some(t.as_str()) != skip)
        .collect();
    if out.is_empty() && skip != Some("tty1") {
        out.push("tty1".into());
    }
    out.dedup();
    out
}

/// `text` on each of `ttys`, once (PID 1's notices: its own stderr is
/// `/dev/console`, which is only the last `console=`, the serial one).
/// Long lines are broken at spaces, not by the screen in mid-word.
pub fn announce(ttys: &[String], text: &str) {
    let color = style::Color::current();
    let text = style::wrap(text, style::WIDTH).join("\n");
    let text = text.as_str();
    for t in ttys {
        if let Ok(mut f) = OpenOptions::new()
            .write(true)
            .custom_flags(rustix::fs::OFlags::NOCTTY.bits() as i32)
            .open(format!("/dev/{t}"))
        {
            let _ = f.write_all(format!("{}\n", style::render(text, color.on(t))).as_bytes());
        }
    }
}

impl Console {
    /// Opens `ttys` (those that do not open are left out: no serial port).
    pub fn open(ttys: &[String]) -> Console {
        let (tx, rx) = channel();
        let color = style::Color::current();
        let mut outs = Vec::new();
        for t in ttys {
            let path = format!("/dev/{t}");
            let Ok(f) = OpenOptions::new().read(true).write(true).open(&path) else {
                continue;
            };
            let Ok(r) = f.try_clone() else { continue };
            let tx = tx.clone();
            let from = outs.len();
            let spawned = std::thread::Builder::new()
                .name(format!("console-{t}"))
                .spawn(move || {
                    let mut r = BufReader::new(r);
                    loop {
                        let mut line = String::new();
                        match (&mut r).take(MAX_LINE).read_line(&mut line) {
                            Ok(0) => std::thread::sleep(Duration::from_millis(200)),
                            Ok(_) => {
                                if tx.send((from, style::typed(&line))).is_err() {
                                    return;
                                }
                            }
                            Err(_) => std::thread::sleep(Duration::from_millis(200)),
                        }
                    }
                });
            if spawned.is_ok() {
                outs.push(Out {
                    name: t.clone(),
                    file: f,
                    color: color.on(t),
                });
            }
        }
        Console { outs, rx }
    }

    pub fn names(&self) -> Vec<&str> {
        self.outs.iter().map(|o| o.name.as_str()).collect()
    }

    /// Text on every console (no newline added), its style marks as that
    /// console takes them.
    pub fn put(&self, text: &str) {
        let plain = style::render(text, false);
        let lit = style::render(text, true);
        for o in &self.outs {
            let mut f = &o.file;
            let _ = f.write_all(if o.color { &lit } else { &plain }.as_bytes());
            let _ = f.flush();
        }
    }

    pub fn say(&self, text: &str) {
        self.put(&format!("{text}\n"));
    }

    fn drain(&self) {
        while self.rx.try_recv().is_ok() {}
    }

    /// An answer typed on console `from`: the other consoles get it too
    /// (G1.6zg), or their line would stay open at the prompt and the next
    /// text would run on after it; whoever watches the serial sees what was
    /// answered on the screen. A `secret` answer is only a line break.
    fn answered(&self, (from, line): (usize, String), secret: bool) -> String {
        let shown = if secret {
            "\n".to_owned()
        } else {
            format!("{}\n", style::render(&line, false))
        };
        for (_, o) in self.outs.iter().enumerate().filter(|(i, _)| *i != from) {
            let mut f = &o.file;
            let _ = f.write_all(shown.as_bytes());
            let _ = f.flush();
        }
        line
    }

    /// The next line typed on any console after `prompt`; `None` after
    /// `timeout` (when given).
    pub fn ask(&self, prompt: &str, timeout: Option<Duration>) -> Option<String> {
        self.drain();
        self.put(prompt);
        let got = match timeout {
            None => self.rx.recv().ok(),
            Some(t) => self.rx.recv_timeout(t).ok(),
        };
        got.map(|g| self.answered(g, false))
    }

    /// Like [`Console::ask`] without a deadline, the prompt shown again
    /// every `every` while nobody answers: whoever attaches the serial
    /// console later (`virsh console`) sees the question that is waiting
    /// (G1.6m). After `give_up` with no answer: `None`, as if cancelled.
    pub fn ask_shown(&self, prompt: &str, every: Duration, give_up: Duration) -> Option<String> {
        self.drain();
        self.put(prompt);
        let start = std::time::Instant::now();
        loop {
            match self.rx.recv_timeout(every) {
                Ok(g) => return Some(self.answered(g, false)),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    if start.elapsed() >= give_up {
                        self.put("\n(no answer: cancelled)\n");
                        return None;
                    }
                    self.put(&format!("\n{prompt}"));
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return None,
            }
        }
    }

    /// Like [`Console::ask`] with the terminals' echo off.
    pub fn ask_secret(&self, prompt: &str) -> Option<String> {
        let saved: Vec<_> = self
            .outs
            .iter()
            .map(|o| {
                let f = &o.file;
                let t = rustix::termios::tcgetattr(f).ok();
                if let Some(mut quiet) = t.clone() {
                    quiet.local_modes.remove(rustix::termios::LocalModes::ECHO);
                    let _ = rustix::termios::tcsetattr(
                        f,
                        rustix::termios::OptionalActions::Now,
                        &quiet,
                    );
                }
                t
            })
            .collect();
        self.drain();
        self.put(prompt);
        // The echo is off: nobody saw a line break, the console it was
        // typed on included.
        let got = self.rx.recv().ok().map(|(_, line)| line);
        for (o, t) in self.outs.iter().zip(saved) {
            if let Some(t) = t {
                let _ =
                    rustix::termios::tcsetattr(&o.file, rustix::termios::OptionalActions::Now, &t);
            }
        }
        self.put("\n");
        got
    }
}
