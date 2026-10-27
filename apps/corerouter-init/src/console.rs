//! The consoles a person may be at (G1.6c): the VGA console (`tty1`) and
//! the serial one (`ttyS0`), both at once. Output goes to every console;
//! the answer to a prompt is the first line typed on any of them. Input
//! typed before a prompt is thrown away, so nothing typed early confirms
//! a later question (an erase).

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::sync::mpsc::{Receiver, channel};
use std::time::Duration;

/// Longest line read from a console.
const MAX_LINE: u64 = 512;

pub struct Console {
    outs: Vec<(String, File)>,
    rx: Receiver<String>,
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

impl Console {
    /// Opens `ttys` (those that do not open are left out: no serial port).
    pub fn open(ttys: &[String]) -> Console {
        let (tx, rx) = channel();
        let mut outs = Vec::new();
        for t in ttys {
            let path = format!("/dev/{t}");
            let Ok(f) = OpenOptions::new().read(true).write(true).open(&path) else {
                continue;
            };
            let Ok(r) = f.try_clone() else { continue };
            let tx = tx.clone();
            let spawned = std::thread::Builder::new()
                .name(format!("console-{t}"))
                .spawn(move || {
                    let mut r = BufReader::new(r);
                    loop {
                        let mut line = String::new();
                        match (&mut r).take(MAX_LINE).read_line(&mut line) {
                            Ok(0) => std::thread::sleep(Duration::from_millis(200)),
                            Ok(_) => {
                                if tx.send(line.trim().to_owned()).is_err() {
                                    return;
                                }
                            }
                            Err(_) => std::thread::sleep(Duration::from_millis(200)),
                        }
                    }
                });
            if spawned.is_ok() {
                outs.push((t.clone(), f));
            }
        }
        Console { outs, rx }
    }

    pub fn names(&self) -> Vec<&str> {
        self.outs.iter().map(|(n, _)| n.as_str()).collect()
    }

    /// Text on every console (no newline added).
    pub fn put(&self, text: &str) {
        for (_, f) in &self.outs {
            let mut f = f;
            let _ = f.write_all(text.as_bytes());
            let _ = f.flush();
        }
    }

    pub fn say(&self, text: &str) {
        self.put(&format!("{text}\n"));
    }

    fn drain(&self) {
        while self.rx.try_recv().is_ok() {}
    }

    /// The next line typed on any console after `prompt`; `None` after
    /// `timeout` (when given).
    pub fn ask(&self, prompt: &str, timeout: Option<Duration>) -> Option<String> {
        self.drain();
        self.put(prompt);
        match timeout {
            None => self.rx.recv().ok(),
            Some(t) => self.rx.recv_timeout(t).ok(),
        }
    }

    /// Like [`Console::ask`] with the terminals' echo off.
    pub fn ask_secret(&self, prompt: &str) -> Option<String> {
        let saved: Vec<_> = self
            .outs
            .iter()
            .map(|(_, f)| {
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
        let got = self.ask(prompt, None);
        for ((_, f), t) in self.outs.iter().zip(saved) {
            if let Some(t) = t {
                let _ = rustix::termios::tcsetattr(f, rustix::termios::OptionalActions::Now, &t);
            }
        }
        self.put("\n");
        got
    }
}
