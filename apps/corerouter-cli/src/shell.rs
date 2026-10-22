//! `corerouter-cli shell`: the RouterOS-style terminal (`corerouter-shell`)
//! on a line editor.
//!
//! The editor is `rustyline`: small and stable, with exactly the hooks the
//! terminal needs — a completer, a highlighter that recolors as you type,
//! per-key handlers (Ctrl+X, `?`, F1), a history file and bracketed paste — and
//! it builds on Linux, macOS and Windows. (`reedline` would bring a larger
//! tree for features the terminal does not use: menus, vi mode, SQLite
//! history.)
//!
//! Every command goes to the router through the backend's `call` (the
//! control channel, or the in-process lab), never around it.

use std::borrow::Cow;
use std::cell::RefCell;
use std::io::{BufRead, IsTerminal, Write};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use serde_json::json;

use corerouter_mcp::Backend;
use corerouter_shell::{Output, Reply, Request, Shell, Span, to_ansi};
use rustyline::completion::{Completer, Pair};
use rustyline::error::ReadlineError;
use rustyline::highlight::{CmdKind, Highlighter};
use rustyline::hint::Hinter;
use rustyline::history::DefaultHistory;
use rustyline::validate::Validator;
use rustyline::{
    Cmd, CompletionType, ConditionalEventHandler, Config, Context, Editor, Event, EventContext,
    EventHandler, Helper, KeyCode, KeyEvent, Modifiers, RepeatCount,
};

/// Lines kept in the history file.
const HISTORY: usize = 1000;

/// What a key handler asked the loop to do with the line it accepted.
const KEY_NONE: u8 = 0;
const KEY_SAFE_MODE: u8 = 1;
const KEY_HELP: u8 = 2;

struct Keys {
    flag: Arc<AtomicU8>,
    what: u8,
}

impl ConditionalEventHandler for Keys {
    fn handle(&self, _: &Event, _: RepeatCount, _: bool, ctx: &EventContext) -> Option<Cmd> {
        // `?` inside quotes is text (`comment="why?"`).
        if self.what == KEY_HELP && ctx.line().matches('"').count() % 2 == 1 {
            return None;
        }
        self.flag.store(self.what, Ordering::SeqCst);
        Some(Cmd::AcceptLine)
    }
}

struct Assist {
    shell: Rc<RefCell<Shell>>,
}

impl Completer for Assist {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        let c = self.shell.borrow().complete(line, pos);
        let pairs = c
            .candidates
            .into_iter()
            .map(|c| Pair {
                display: if c.help.is_empty() {
                    c.display
                } else {
                    format!("{:<18} {}", c.display, c.help)
                },
                replacement: c.text,
            })
            .collect();
        Ok((c.start, pairs))
    }
}

impl Highlighter for Assist {
    fn highlight<'l>(&self, line: &'l str, _: usize) -> Cow<'l, str> {
        Cow::Owned(to_ansi(&self.shell.borrow().highlight(line)))
    }

    fn highlight_prompt<'b, 's: 'b, 'p: 'b>(&'s self, prompt: &'p str, _: bool) -> Cow<'b, str> {
        let spans = self.shell.borrow().prompt();
        let raw: String = spans.iter().map(|s| s.text.as_str()).collect();
        if raw == prompt {
            Cow::Owned(to_ansi(&spans))
        } else {
            Cow::Borrowed(prompt)
        }
    }

    fn highlight_char(&self, _: &str, _: usize, _: CmdKind) -> bool {
        true
    }
}

impl Hinter for Assist {
    type Hint = String;
}

impl Validator for Assist {}
impl Helper for Assist {}

fn history_file() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
        .or_else(|| std::env::var_os("APPDATA").map(PathBuf::from))?;
    Some(base.join("corerouter").join("shell_history"))
}

/// A line that may carry a secret stays out of the history file.
fn secret(line: &str) -> bool {
    let l = line.to_ascii_lowercase();
    ["password", "secret", "token", "psk"]
        .iter()
        .any(|w| l.contains(w))
}

/// Answer the shell's requests: calls to the router, files on this
/// computer.
/// Set by SIGINT (Ctrl+C outside the line editor, which reads keys raw).
fn interrupted() -> &'static Arc<AtomicBool> {
    static FLAG: OnceLock<Arc<AtomicBool>> = OnceLock::new();
    FLAG.get_or_init(|| {
        let flag = Arc::new(AtomicBool::new(false));
        // Without the handler Ctrl+C would end the program instead of the task.
        let _ = signal_hook::flag::register(signal_hook::consts::SIGINT, Arc::clone(&flag));
        flag
    })
}

fn answer(backend: &mut dyn Backend, r: &Request) -> Reply {
    match r {
        Request::Call { method, params } => backend.call(method, params.clone()),
        Request::Sleep { ms } => {
            let end = Instant::now() + Duration::from_millis(*ms);
            while Instant::now() < end {
                if interrupted().swap(false, Ordering::SeqCst) {
                    println!("^C");
                    return Ok(json!({ "interrupted": true }));
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Ok(serde_json::Value::Null)
        }
        Request::ReadFile { path } => {
            let meta = std::fs::metadata(path).map_err(|e| format!("{path}: {e}"))?;
            if meta.len() > corerouter_shell::MAX_SCRIPT as u64 {
                return Err(format!(
                    "{path}: larger than {} bytes",
                    corerouter_shell::MAX_SCRIPT
                ));
            }
            std::fs::read_to_string(path)
                .map(serde_json::Value::String)
                .map_err(|e| format!("{path}: {e}"))
        }
        Request::WriteFile { path, content } => std::fs::write(path, content)
            .map(|()| serde_json::Value::Null)
            .map_err(|e| format!("{path}: {e}")),
    }
}

/// Run `job`, printing what it prints as it comes (a ping's replies).
fn drive(
    shell: &Rc<RefCell<Shell>>,
    backend: &mut dyn Backend,
    job: corerouter_shell::Job,
    color: bool,
) -> Output {
    interrupted().store(false, Ordering::SeqCst);
    let show = |lines: &[corerouter_shell::Line]| {
        print(&Output::lines(lines.to_vec()), color);
    };
    shell
        .borrow_mut()
        .run_live(job, |r| answer(backend, r), show)
}

fn print(out: &Output, color: bool) {
    let mut stdout = std::io::stdout().lock();
    for l in &out.lines {
        let text = if color { to_ansi(&l.0) } else { l.text() };
        let _ = writeln!(stdout, "{text}");
    }
}

fn plain(spans: &[Span]) -> String {
    spans.iter().map(|s| s.text.as_str()).collect()
}

/// Run the terminal until `/quit`, Ctrl+D or end of input.
pub fn run(backend: &mut dyn Backend, user: &str) -> Result<(), String> {
    let shell = Rc::new(RefCell::new(Shell::new(user)));
    let job = shell.borrow_mut().connect();
    let out = drive(&shell, backend, job, false);
    let tty = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
    print(&out, tty);
    if !tty {
        // A script cannot answer "set a password" (G0.3b).
        shell.borrow_mut().skip_password();
        return batch(&shell, backend);
    }

    let config = Config::builder()
        .completion_type(CompletionType::List)
        .max_history_size(HISTORY)
        .map_err(|e| e.to_string())?
        .auto_add_history(false)
        .build();
    let mut rl: Editor<Assist, DefaultHistory> =
        Editor::with_config(config).map_err(|e| e.to_string())?;
    rl.set_helper(Some(Assist {
        shell: Rc::clone(&shell),
    }));
    let flag = Arc::new(AtomicU8::new(KEY_NONE));
    // F1 is RouterOS v7's help key; `?` the classic one.
    let keys = [
        (KeyEvent::ctrl('X'), KEY_SAFE_MODE),
        (KeyEvent::from('?'), KEY_HELP),
        (KeyEvent(KeyCode::F(1), Modifiers::NONE), KEY_HELP),
    ];
    for (key, what) in keys {
        rl.bind_sequence(
            key,
            EventHandler::Conditional(Box::new(Keys {
                flag: Arc::clone(&flag),
                what,
            })),
        );
    }
    let history = history_file();
    if let Some(h) = &history {
        let _ = rl.load_history(h);
    }

    let mut keep = String::new();
    loop {
        if shell.borrow().asking_password() {
            // First login without a password (G0.3b): read it without echo
            // and outside the history.
            let prompt = plain(&shell.borrow().prompt());
            // Ctrl+D / Ctrl+C: an empty line, "not now".
            let line = rpassword::prompt_password(prompt).unwrap_or_default();
            let job = shell.borrow_mut().submit(&line);
            let out = drive(&shell, backend, job, true);
            print(&out, true);
            continue;
        }
        // `print` fits the terminal (like RouterOS); a pipe has no width.
        shell
            .borrow_mut()
            .set_width(rl.dimensions().map(|(cols, _)| usize::from(cols)));
        let prompt = plain(&shell.borrow().prompt());
        let read = rl.readline_with_initial(&prompt, (&keep, ""));
        keep.clear();
        let line = match read {
            Ok(l) => l,
            Err(ReadlineError::Interrupted) => continue,
            Err(ReadlineError::Eof) => {
                // Ctrl+D on an empty line: leave, undoing Safe Mode (RouterOS).
                let job = shell.borrow_mut().hang_up();
                let out = drive(&shell, backend, job, true);
                print(&out, true);
                break;
            }
            Err(e) => return Err(e.to_string()),
        };
        let job = match flag.swap(KEY_NONE, Ordering::SeqCst) {
            KEY_SAFE_MODE => {
                keep = line;
                shell.borrow_mut().toggle_safe_mode()
            }
            KEY_HELP => {
                let job = shell.borrow_mut().submit(&format!("{line}?"));
                keep = line;
                job
            }
            _ => {
                if !line.trim().is_empty() && !secret(&line) {
                    let _ = rl.add_history_entry(line.as_str());
                }
                shell.borrow_mut().submit(&line)
            }
        };
        let out = drive(&shell, backend, job, true);
        print(&out, true);
        if out.quit {
            break;
        }
    }
    if let Some(h) = &history {
        if let Some(dir) = h.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let _ = rl.save_history(h);
    }
    Ok(())
}

/// Standard input is not a terminal: run its lines one by one (`echo
/// '/ip address print' | corerouter-cli shell`), echoing each after the
/// prompt; a failed line makes the exit status non-zero.
fn batch(shell: &Rc<RefCell<Shell>>, backend: &mut dyn Backend) -> Result<(), String> {
    let mut failed = false;
    for line in std::io::stdin().lock().lines() {
        let line = line.map_err(|e| e.to_string())?;
        println!("{}{line}", shell.borrow().prompt_text());
        let job = shell.borrow_mut().submit(&line);
        let out = drive(shell, backend, job, false);
        print(&out, false);
        failed |= out.failed;
        if out.quit {
            break;
        }
    }
    if failed {
        Err("a command failed".into())
    } else {
        Ok(())
    }
}
