//! The terminal's state and its jobs.
//!
//! No I/O: a line typed becomes a [`Job`] that asks its front end for
//! control-channel calls ([`Request::Call`]: `engine.execute`,
//! `engine.batch`, `engine.list`, `state.inspect`) and, for `/import file=`
//! and `/export file=`, for a file on the client's side. The front end sends
//! them however it talks to the router (blocking in the CLI and SSH, one
//! frame at a time in the GUI) and hands the replies back to
//! [`Shell::step`]. So the terminal never goes around `Session::execute`:
//! permissions, Safe Mode, the journal and validation apply as for any
//! client, and the engine's errors are shown as they come.

use std::collections::{BTreeMap, VecDeque};

use serde_json::{Map, Value, json};

use crate::doc::{Ty, kebab};
use crate::export;
use crate::format;
use crate::parse::{self, Arg, Parsed, PrintOpts};
use crate::registry::{Command, Registry, path_text};
use crate::style::{Line, Output, Span, Style};

/// Largest script `/import` reads.
pub const MAX_SCRIPT: usize = 1024 * 1024;

/// What a job needs from its front end.
#[derive(Debug, Clone, PartialEq)]
pub enum Request {
    /// A control-channel method.
    Call { method: String, params: Value },
    /// Text of a file on the client's side (`/import file=`); reply with a
    /// JSON string.
    ReadFile { path: String },
    /// Write a file on the client's side (`/export file=`).
    WriteFile { path: String, content: String },
    /// Wait this long, then reply `Ok(null)` (between polls of a task).
    /// A front end without access to the shell meanwhile (a blocking loop)
    /// reports Ctrl+C by replying `{"interrupted": true}`, possibly early;
    /// one with access calls [`Shell::interrupt`].
    Sleep { ms: u64 },
}

impl Request {
    pub fn call(method: &str, mut params: Value) -> Self {
        // The log shows a change made here as `… · terminal` (G4.6d).
        if matches!(method, "engine.execute" | "engine.batch")
            && let Some(o) = params.as_object_mut()
        {
            o.entry("via").or_insert_with(|| json!("terminal"));
        }
        Self::Call {
            method: method.to_owned(),
            params,
        }
    }

    fn execute(id: &str, params: Value) -> Self {
        Self::call("engine.execute", json!({"command": id, "params": params}))
    }
}

pub type Reply = Result<Value, String>;

type Cont = Box<dyn FnOnce(&mut Shell, Vec<Reply>) -> Next>;
type Then = Box<dyn FnOnce(&mut Shell, Output) -> Next>;

pub(crate) enum Next {
    Send(Vec<Request>, Cont),
    Done(Output),
}

enum State {
    Start(Next),
    Wait(Cont),
    Over,
}

/// Work started by a line, Ctrl+X or the connection. Drive it with
/// [`Shell::step`] (or [`Shell::run_with`]).
pub struct Job(State);

impl Job {
    fn new(next: Next) -> Self {
        Self(State::Start(next))
    }
}

/// What to do next with a job.
#[derive(Debug, Clone, PartialEq)]
pub enum Step {
    /// Send these, in order; call [`Shell::step`] with one reply each.
    Send(Vec<Request>),
    Done(Output),
}

/// Safe Mode as the last `state.inspect` showed it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SafeMode {
    pub active: bool,
    /// Held by this connection.
    pub yours: bool,
    pub owner: String,
}

pub struct Shell {
    pub(crate) user: String,
    pub(crate) reg: Registry,
    pub(crate) cwd: Vec<String>,
    pub(crate) identity: String,
    pub(crate) version: String,
    pub(crate) safe: SafeMode,
    /// Rows of the last `print` per menu: what `remove 0` means.
    pub(crate) last_print: BTreeMap<Vec<String>, Vec<Value>>,
    /// Latest result of each read command (completion values).
    pub(crate) cache: BTreeMap<String, Value>,
    /// Lines a running job printed already (a task's events), for the
    /// front end to show before the job ends ([`Shell::take_live`]).
    live: Vec<Line>,
    /// Ctrl+C while a job runs: a task being followed is stopped.
    interrupted: bool,
    /// The first-login question (G0.3b): set a password for this account.
    ask: Option<Ask>,
    /// Characters per line of the front end; `print` drops the columns that
    /// do not fit (like RouterOS), instead of stretching the terminal.
    width: Option<usize>,
}

/// "Set a password for admin" after a login while an account of group full
/// has none (RouterOS 7 asks the same). The lines typed meanwhile are
/// passwords: front ends hide them and keep them out of the history.
struct Ask {
    user: String,
    /// The first entry, waiting for the repeat.
    first: Option<String>,
}

/// Moves `/import` may make of a failing step to the end (see `import_batch`).
const MAX_DEFERRED: usize = 64;

/// Send an import as one atomic batch. RouterOS exports in name order, not
/// in dependency order (`/interface vlan add interface=s42 name=c43` comes
/// before `name=s42`, seen on a 7.25 CHR, G3.9hb): the step that fails goes
/// to the end and the batch runs again. A step already moved moves again
/// only when more steps ran before the failure than last time (a chain
/// `a` on `b` on `c` settles; two bad lines cannot swap forever), the last
/// step never moves, and at most `MAX_DEFERRED` moves in all, so a bad
/// line still fails, named by its place in the script. `order[i]` is the
/// script position of `steps[i]`.
fn import_batch(mut steps: Vec<Value>, mut order: Vec<usize>, retry: Retry) -> Next {
    let request = Request::call(
        "engine.batch",
        json!({"steps": steps.clone(), "atomic": true}),
    );
    Next::Send(
        vec![request],
        Box::new(move |sh, replies| match reply(&replies, 0) {
            Ok(_) => {
                let mut text = format!("imported {} command(s) as one atomic batch", steps.len());
                let moved = retry.moved.iter().filter(|m| **m).count();
                if moved > 0 {
                    text.push_str(&format!(" ({moved} run after the lines they depend on)"));
                }
                sh.with_refresh(Output::lines(vec![Line::styled(Style::Ok, text)]))
            }
            Err(e) => {
                let failed = batch_step(&e).and_then(|k| k.checked_sub(1));
                let next = failed.and_then(|i| retry.after(i, order.get(i).copied()?, steps.len()));
                if let (Some(i), Some(next)) = (failed, next) {
                    let step = steps.remove(i);
                    steps.push(step);
                    let at = order.remove(i);
                    order.push(at);
                    return import_batch(steps, order, next);
                }
                // The step number of the script, not of the reordered batch.
                let e = match failed.and_then(|i| Some((i, order.get(i)?))) {
                    Some((i, at)) => e.replacen(
                        &format!("batch step {} failed", i + 1),
                        &format!("batch step {} failed", at + 1),
                        1,
                    ),
                    None => e,
                };
                Next::Done(Output::error(format!("{e}; nothing was applied")))
            }
        }),
    )
}

/// What `import_batch` has moved so far.
struct Retry {
    /// By script position: moved to the end at least once.
    moved: Vec<bool>,
    /// Moves so far.
    moves: usize,
    /// Steps that ran before the last failure.
    reached: usize,
}

impl Retry {
    fn new(n: usize) -> Self {
        Self {
            moved: vec![false; n],
            moves: 0,
            reached: 0,
        }
    }

    /// The state after moving the step at batch index `i` (script position
    /// `at`) to the end, or `None` when it must not move.
    fn after(&self, i: usize, at: usize, len: usize) -> Option<Self> {
        let again = self.moved.get(at).copied().unwrap_or(true);
        if i + 1 >= len || self.moves >= MAX_DEFERRED || (again && i <= self.reached) {
            return None;
        }
        let mut moved = self.moved.clone();
        if let Some(m) = moved.get_mut(at) {
            *m = true;
        }
        Some(Self {
            moved,
            moves: self.moves + 1,
            reached: i,
        })
    }
}

/// `N` of the engine's "batch step N failed: …".
fn batch_step(error: &str) -> Option<usize> {
    let rest = error.split_once("batch step ")?.1;
    rest.split_once(" failed")?.0.parse().ok()
}

fn reply(replies: &[Reply], i: usize) -> Reply {
    replies
        .get(i)
        .cloned()
        .unwrap_or_else(|| Err("no reply from the router".into()))
}

/// Run `next`, then `f` with its output.
fn chain(shell: &mut Shell, next: Next, f: Then) -> Next {
    match next {
        Next::Done(o) => f(shell, o),
        Next::Send(reqs, c) => Next::Send(
            reqs,
            Box::new(move |sh, replies| {
                let n = c(sh, replies);
                chain(sh, n, f)
            }),
        ),
    }
}

/// `text` (typed for a parameter of type `ty`) as JSON.
pub fn convert(ty: Option<&Ty>, text: &str) -> Value {
    match ty {
        Some(Ty::Bool) => match text {
            "yes" | "true" => Value::Bool(true),
            "no" | "false" => Value::Bool(false),
            _ => Value::String(text.to_owned()),
        },
        Some(Ty::Num { .. }) => text
            .parse::<u64>()
            .map_or_else(|_| Value::String(text.to_owned()), Value::from),
        Some(Ty::List { text_too: false }) => Value::Array(
            text.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| Value::String(s.to_owned()))
                .collect(),
        ),
        _ => Value::String(text.to_owned()),
    }
}

fn numbers(text: &str) -> Option<Vec<usize>> {
    text.split(',')
        .map(|n| n.trim().parse::<usize>().ok())
        .collect()
}

fn ids(text: &str) -> Option<Vec<String>> {
    text.split(',')
        .map(|t| {
            let t = t.trim();
            let hex = t.strip_prefix('*')?;
            (!hex.is_empty() && hex.chars().all(|c| c.is_ascii_hexdigit())).then(|| t.to_owned())
        })
        .collect()
}

impl Shell {
    /// A terminal for `user` (shown in the prompt; the router decides what
    /// that user may do).
    pub fn new(user: impl Into<String>) -> Self {
        Self {
            user: user.into(),
            reg: Registry::default(),
            cwd: Vec::new(),
            identity: String::new(),
            version: String::new(),
            safe: SafeMode::default(),
            last_print: BTreeMap::new(),
            cache: BTreeMap::new(),
            live: Vec::new(),
            interrupted: false,
            ask: None,
            width: None,
        }
    }

    /// The terminal is asking for a new password (G0.3b): the front end
    /// hides what is typed and keeps it out of the history.
    pub fn asking_password(&self) -> bool {
        self.ask.is_some()
    }

    /// Drop the first-login question without a word (a script on stdin
    /// cannot answer it).
    pub fn skip_password(&mut self) {
        self.ask = None;
    }

    pub fn registry(&self) -> &Registry {
        &self.reg
    }

    pub fn cwd(&self) -> &[String] {
        &self.cwd
    }

    pub fn safe_mode(&self) -> &SafeMode {
        &self.safe
    }

    /// `[admin@CoreRouter] /ip/address>` (RouterOS v7's prompt); `<SAFE>`
    /// takes the place of `>` while this connection holds Safe Mode.
    pub fn prompt(&self) -> Vec<Span> {
        if let Some(a) = &self.ask {
            let text = if a.first.is_some() {
                "Repeat new password: ".to_owned()
            } else {
                format!("New password for {}: ", a.user)
            };
            return Line::styled(Style::Plain, text).0;
        }
        let identity = if self.identity.is_empty() {
            "router"
        } else {
            self.identity.as_str()
        };
        let mut l = Line::new();
        l.push(Style::Plain, format!("[{}@{identity}] ", self.user));
        if !self.cwd.is_empty() {
            l.push(Style::Menu, format!("/{}", self.cwd.join("/")));
        }
        if self.safe.active && self.safe.yours {
            l.push(Style::Safe, "<SAFE>");
            l.push(Style::Plain, " ");
        } else {
            l.push(Style::Plain, "> ");
        }
        l.0
    }

    pub fn prompt_text(&self) -> String {
        self.prompt().iter().map(|s| s.text.as_str()).collect()
    }

    /// Advance `job` with the replies to its last [`Step::Send`] (none the
    /// first time).
    pub fn step(&mut self, job: &mut Job, replies: Vec<Reply>) -> Step {
        let next = match std::mem::replace(&mut job.0, State::Over) {
            State::Start(n) => n,
            State::Wait(c) => c(self, replies),
            State::Over => return Step::Done(Output::default()),
        };
        match next {
            Next::Send(reqs, c) => {
                job.0 = State::Wait(c);
                Step::Send(reqs)
            }
            Next::Done(o) => Step::Done(o),
        }
    }

    /// Drive `job` to the end, answering each request with `answer`. Lines
    /// the job printed while running come first in the output.
    pub fn run_with(&mut self, job: Job, answer: impl FnMut(&Request) -> Reply) -> Output {
        let mut live = Vec::new();
        let mut out = self.run_live(job, answer, |lines| live.extend_from_slice(lines));
        live.append(&mut out.lines);
        out.lines = live;
        out
    }

    /// Like [`Shell::run_with`], handing lines to `show` as soon as the job
    /// prints them (a ping, line by line).
    pub fn run_live(
        &mut self,
        mut job: Job,
        mut answer: impl FnMut(&Request) -> Reply,
        mut show: impl FnMut(&[Line]),
    ) -> Output {
        let mut replies = Vec::new();
        loop {
            let step = self.step(&mut job, replies);
            let live = self.take_live();
            if !live.is_empty() {
                show(&live);
            }
            match step {
                Step::Send(reqs) => replies = reqs.iter().map(&mut answer).collect(),
                Step::Done(o) => return o,
            }
        }
    }

    /// The terminal's width in characters (`None`: unlimited). `print` shows
    /// the columns that fit and says which it left out (`print detail` has
    /// them all).
    pub fn set_width(&mut self, width: Option<usize>) {
        self.width = width.filter(|w| *w > 0);
    }

    /// The width set by [`Self::set_width`].
    pub fn width(&self) -> Option<usize> {
        self.width
    }

    /// Lines printed by the running job since the last call.
    pub fn take_live(&mut self) -> Vec<Line> {
        std::mem::take(&mut self.live)
    }

    /// Ctrl+C: stop the task the running job follows (it keeps polling
    /// until the task reports its summary).
    pub fn interrupt(&mut self) {
        self.interrupted = true;
    }

    /// First job of a connection: the command list, the state and the
    /// values completion offers; prints a banner. Four requests in two
    /// rounds; `engine.list` is not asked again unless the router stops
    /// knowing a command (see [`Shell::reload_registry`]).
    pub fn connect(&mut self) -> Job {
        let reqs = vec![
            Request::call("server.info", Value::Null),
            Request::call("engine.list", Value::Null),
            Request::call("auth.whoami", Value::Null),
        ];
        Job::new(Next::Send(
            reqs,
            Box::new(|sh, replies| {
                let info = reply(&replies, 0);
                if let Ok(i) = &info {
                    sh.version = i
                        .get("version")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_owned();
                }
                let list = reply(&replies, 1);
                sh.apply_list(list.as_ref().ok());
                // An older router without auth.whoami: no question.
                let me = reply(&replies, 2).unwrap_or(Value::Null);
                let mut out = Output::default();
                for e in [info.err(), list.err()].into_iter().flatten() {
                    out.lines.push(Line::styled(Style::Error, e));
                }
                let next = sh.with_refresh(out);
                chain(
                    sh,
                    next,
                    Box::new(move |sh, mut out| {
                        out.lines.push(
                            Line::new()
                                .with(Style::Header, format!("CoreRouter {}", sh.version))
                                .with(Style::Dim, format!(" — {}", sh.identity)),
                        );
                        out.lines.push(Line::styled(
                            Style::Dim,
                            "Tab completes, ? or F1 shows help, Ctrl+X toggles Safe Mode, /quit leaves.",
                        ));
                        sh.first_login(&me, &mut out);
                        Next::Done(out)
                    }),
                )
            }),
        ))
    }

    /// After the banner: when `auth.whoami` lists accounts of group full
    /// without a password, warn and ask for one (the logged-in user's own,
    /// else the first listed).
    fn first_login(&mut self, me: &Value, out: &mut Output) {
        let missing: Vec<&str> = me
            .get("no_password")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        let mine = me.get("user").and_then(Value::as_str);
        let Some(user) = missing
            .iter()
            .find(|u| Some(**u) == mine)
            .or(missing.first())
        else {
            return;
        };
        let user: String = user.chars().take(64).collect();
        out.lines.push(Line::styled(
            Style::Error,
            format!(
                "User {user} has no password: anyone who reaches the router, from this \
                 machine or the network, logs in with an empty password until it has one."
            ),
        ));
        out.lines.push(Line::styled(
            Style::Dim,
            "Set it now (empty line: not now).",
        ));
        self.ask = Some(Ask { user, first: None });
    }

    /// A line typed while [`Self::asking_password`].
    fn answer_password(&mut self, line: &str) -> Next {
        let Some(mut ask) = self.ask.take() else {
            return Next::Done(Output::default());
        };
        if line.is_empty() {
            return Next::Done(Output::lines(vec![Line::styled(
                Style::Dim,
                format!(
                    "Not now. Set it later with /user set {} password=…",
                    ask.user
                ),
            )]));
        }
        let Some(first) = ask.first.take() else {
            ask.first = Some(line.to_owned());
            self.ask = Some(ask);
            return Next::Done(Output::default());
        };
        if first != line {
            self.ask = Some(ask);
            return Next::Done(Output::error(
                "The passwords differ; type it again (empty line: not now).",
            ));
        }
        let user = ask.user.clone();
        Next::Send(
            vec![Request::execute(
                "user.set",
                json!({"name": user, "password": line}),
            )],
            Box::new(move |sh, replies| match reply(&replies, 0) {
                Ok(_) => Next::Done(Output::lines(vec![Line::styled(
                    Style::Dim,
                    format!("Password set for {}.", ask.user),
                )])),
                Err(e) => {
                    sh.ask = Some(ask);
                    Next::Done(Output::error(format!(
                        "{e} — type another (empty line: not now)."
                    )))
                }
            }),
        )
    }

    fn apply_list(&mut self, list: Option<&Value>) {
        if let Some(list) = list.filter(|l| l.is_array()) {
            self.reg = Registry::from_list(list);
        }
        // A menu that disappeared (older router): back to where it exists.
        while !self.cwd.is_empty() && self.reg.menu(&self.cwd).is_none() && !self.reg.is_empty() {
            self.cwd.pop();
        }
    }

    /// Read the command list again (the router was replaced or upgraded),
    /// then finish with `out`.
    fn reload_registry(&mut self, out: Output) -> Next {
        Next::Send(
            vec![Request::call("engine.list", Value::Null)],
            Box::new(move |sh, replies| {
                sh.apply_list(reply(&replies, 0).ok().as_ref());
                Next::Done(out)
            }),
        )
    }

    /// Read commands whose results completion uses: every `print` with no
    /// required parameter that the router allows now (one disabled step
    /// would fail the batch).
    fn cache_reads(&self) -> Vec<String> {
        self.reg
            .commands()
            .filter(|(_, c)| {
                c.verb == "print" && !c.task && c.enabled.is_ok() && c.required().next().is_none()
            })
            .map(|(_, c)| c.id.clone())
            .collect()
    }

    fn apply_summary(&mut self, sum: &Value) {
        if let Some(id) = sum.get("identity").and_then(Value::as_str) {
            self.identity = id.chars().take(64).collect();
        }
        let sm = sum.get("safe_mode").unwrap_or(&Value::Null);
        self.safe = SafeMode {
            active: sm.get("active").and_then(Value::as_bool) == Some(true),
            yours: sm.get("yours").and_then(Value::as_bool) == Some(true),
            owner: sm
                .get("owner")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_owned(),
        };
    }

    /// `out`, after the state and the completion values are read again:
    /// two requests, `state.inspect` and one `engine.batch` (not atomic,
    /// queries only) with every read.
    fn with_refresh(&mut self, out: Output) -> Next {
        let reads = self.cache_reads();
        let mut reqs = vec![Request::call("state.inspect", json!({}))];
        if !reads.is_empty() {
            let steps: Vec<Value> = reads.iter().map(|id| json!({ "command": id })).collect();
            reqs.push(Request::call(
                "engine.batch",
                json!({"steps": steps, "atomic": false}),
            ));
        }
        Next::Send(
            reqs,
            Box::new(move |sh, replies| {
                if let Ok(sum) = reply(&replies, 0) {
                    sh.apply_summary(&sum);
                }
                if let Ok(batch) = reply(&replies, 1) {
                    let results = batch.get("results").and_then(Value::as_array);
                    for (id, v) in reads.iter().zip(results.into_iter().flatten()) {
                        sh.cache.insert(id.clone(), v.clone());
                    }
                }
                Next::Done(out)
            }),
        )
    }

    /// Ctrl+X: take Safe Mode, or leave it keeping the changes (RouterOS).
    pub fn toggle_safe_mode(&mut self) -> Job {
        let leaving = self.safe.active && self.safe.yours;
        let id = if leaving {
            "config.safe-mode.exit"
        } else {
            "config.safe-mode.enter"
        };
        Job::new(Next::Send(
            vec![Request::execute(id, json!({}))],
            Box::new(move |sh, replies| match reply(&replies, 0) {
                Ok(_) => {
                    let msg = if leaving {
                        "[Safe Mode released]"
                    } else {
                        "[Safe Mode taken]"
                    };
                    sh.with_refresh(Output::lines(vec![Line::styled(Style::Ok, msg)]))
                }
                Err(e) => {
                    let out = Output::error(e);
                    sh.with_refresh(out)
                }
            }),
        ))
    }

    /// Ctrl+D on an empty line: leave, undoing this connection's Safe Mode
    /// changes (RouterOS). The job's output has `quit` set.
    pub fn hang_up(&mut self) -> Job {
        if !(self.safe.active && self.safe.yours) {
            return Job::new(Next::Done(Output {
                quit: true,
                ..Output::default()
            }));
        }
        Job::new(Next::Send(
            vec![Request::execute("config.safe-mode.cancel", json!({}))],
            Box::new(|sh, replies| {
                sh.safe = SafeMode::default();
                let mut out = match reply(&replies, 0) {
                    Ok(_) => Output::lines(vec![Line::styled(
                        Style::Warn,
                        "[Safe Mode changes undone]",
                    )]),
                    Err(e) => Output::error(e),
                };
                out.quit = true;
                Next::Done(out)
            }),
        ))
    }

    /// A line typed (or pasted). Several lines at once are a script: they
    /// run as one atomic batch, like `/import`.
    pub fn submit(&mut self, input: &str) -> Job {
        self.interrupted = false;
        self.live.clear();
        if input.len() > MAX_SCRIPT {
            return Job::new(Next::Done(Output::error(format!(
                "input too long (at most {MAX_SCRIPT} bytes)"
            ))));
        }
        let input = input.trim_end_matches(['\n', '\r']);
        if self.ask.is_some() {
            return Job::new(self.answer_password(input));
        }
        if input.contains('\n') {
            return Job::new(self.import_text(input));
        }
        if input.len() > crate::lex::MAX_LINE {
            return Job::new(Next::Done(Output::error(format!(
                "line too long (at most {} bytes)",
                crate::lex::MAX_LINE
            ))));
        }
        let stmts: VecDeque<String> = parse::split(input)
            .into_iter()
            .map(|(_, s)| s.to_owned())
            .collect();
        Job::new(self.statements(stmts, Output::default()))
    }

    fn statements(&mut self, mut stmts: VecDeque<String>, acc: Output) -> Next {
        let Some(stmt) = stmts.pop_front() else {
            return Next::Done(acc);
        };
        let next = self.statement(&stmt);
        chain(
            self,
            next,
            Box::new(move |sh, out| {
                let mut acc = acc;
                let stop = out.failed || out.quit;
                acc.append(out);
                if stop {
                    Next::Done(acc)
                } else {
                    sh.statements(stmts, acc)
                }
            }),
        )
    }

    fn command(&self, id: &str) -> Option<Command> {
        self.reg.by_id(id).map(|(_, c)| c.clone())
    }

    fn statement(&mut self, text: &str) -> Next {
        if self.reg.is_empty() && !text.trim().is_empty() {
            return Next::Done(Output::error(
                "the router's command list has not arrived yet (not connected?)",
            ));
        }
        let parsed = match parse::parse(&self.reg, &self.cwd, text) {
            Ok(p) => p,
            Err(e) => {
                return Next::Done(Output::error(format!(
                    "{} (column {})",
                    e.message, e.column
                )));
            }
        };
        match parsed {
            Parsed::Empty => Next::Done(Output::default()),
            Parsed::Navigate(p) => {
                self.cwd = p;
                Next::Done(Output::default())
            }
            // `/quit` keeps Safe Mode's changes (RouterOS); only a dropped
            // connection or Ctrl+D undoes them.
            Parsed::Quit if self.safe.active && self.safe.yours => Next::Send(
                vec![Request::execute("config.safe-mode.exit", json!({}))],
                Box::new(|sh, replies| {
                    sh.safe = SafeMode::default();
                    let mut out = match reply(&replies, 0) {
                        Ok(_) => {
                            Output::lines(vec![Line::styled(Style::Ok, "[Safe Mode released]")])
                        }
                        Err(e) => Output::error(e),
                    };
                    out.quit = true;
                    out.failed = false;
                    Next::Done(out)
                }),
            ),
            Parsed::Quit => Next::Done(Output {
                quit: true,
                ..Output::default()
            }),
            Parsed::Help { path, id } => Next::Done(Output::lines(self.help(&path, id.as_deref()))),
            Parsed::Print { path, id, opts } => self.print(path, &id, opts),
            Parsed::Command { path, id, args } => self.run_command(&path, &id, &args),
            Parsed::Export {
                path,
                file,
                terse,
                sensitive,
            } => self.export(path, file, terse, sensitive),
            Parsed::Import { file: None } => Next::Done(Output::error(
                "import needs file=<name> (a file on this computer), or paste the script",
            )),
            Parsed::Import { file: Some(f) } => Next::Send(
                vec![Request::ReadFile { path: f.clone() }],
                Box::new(move |sh, replies| match reply(&replies, 0) {
                    Ok(Value::String(text)) => sh.import_text(&text),
                    Ok(_) => Next::Done(Output::error(format!("{f}: not a text file"))),
                    Err(e) => Next::Done(Output::error(e)),
                }),
            ),
        }
    }

    fn print(&mut self, path: Vec<String>, id: &str, opts: PrintOpts) -> Next {
        let Some(cmd) = self.command(id) else {
            return Next::Done(Output::error(format!("no command {id}")));
        };
        let mut params = Map::new();
        for (k, v) in &opts.params {
            params.insert(k.clone(), convert(cmd.param(k).map(|p| &p.ty), v));
        }
        let plain = params.is_empty();
        Next::Send(
            vec![Request::execute(id, Value::Object(params))],
            Box::new(move |sh, replies| {
                let v = match reply(&replies, 0) {
                    Ok(v) => v,
                    Err(e) => return Next::Done(Output::error(e)),
                };
                if plain {
                    sh.cache.insert(cmd.id.clone(), v.clone());
                }
                let lines = match v {
                    Value::Array(rows) => {
                        let rows = format::filter(rows, opts.cond.as_ref());
                        sh.last_print.insert(path, rows.clone());
                        if opts.count_only {
                            vec![Line::plain(rows.len().to_string())]
                        } else if opts.as_json {
                            json_lines(&format::project(&rows, opts.proplist.as_ref()))
                        } else if opts.detail {
                            format::detail(&rows, &cmd.shape, &opts)
                        } else {
                            format::table(&rows, &cmd.shape, &opts, true, sh.width)
                        }
                    }
                    other if opts.as_json => json_lines(&other),
                    other => format::object(&other, &cmd.shape.fields),
                };
                Next::Done(Output::lines(lines))
            }),
        )
    }

    /// Parameter sets for one command line: one per item referenced
    /// (`remove 0,2` is two), or one.
    pub(crate) fn build(
        &self,
        path: &[String],
        cmd: &Command,
        args: &[Arg],
        script: bool,
    ) -> Result<Vec<Map<String, Value>>, String> {
        let mut base = Map::new();
        let mut items: Option<Vec<Map<String, Value>>> = None;
        let listed = self.reg.menu(path).is_some_and(|m| m.print().is_some());
        let mut first = true;
        for arg in args {
            match arg {
                Arg::Pair { key, value } => {
                    base.insert(key.clone(), convert(cmd.param(key).map(|p| &p.ty), value));
                }
                Arg::Positional(text) => {
                    // The registry names where a bare value goes (`ping 8.8.8.8`).
                    if let Some(pk) = cmd.positional.as_deref()
                        && !base.contains_key(pk)
                    {
                        first = false;
                        base.insert(pk.to_owned(), convert(cmd.param(pk).map(|p| &p.ty), text));
                        continue;
                    }
                    let item_ok = first && cmd.verb != "add" && listed;
                    first = false;
                    if item_ok && let Some(ns) = numbers(text) {
                        if script {
                            return Err(format!(
                                "item number {text} in a script: use names or *ids (numbers refer to the last print)"
                            ));
                        }
                        items = Some(self.items_by_number(path, cmd, &ns)?);
                        continue;
                    }
                    if item_ok
                        && cmd.param("id").is_some()
                        && let Some(ids) = ids(text)
                    {
                        items = Some(
                            ids.into_iter()
                                .map(|id| {
                                    let mut m = Map::new();
                                    m.insert("id".into(), Value::String(id));
                                    m
                                })
                                .collect(),
                        );
                        continue;
                    }
                    let filled = |k: &str| {
                        base.contains_key(k)
                            || items
                                .as_ref()
                                .and_then(|i| i.first())
                                .is_some_and(|m| m.contains_key(k))
                    };
                    let Some(p) = cmd.required().find(|p| !filled(&p.key)) else {
                        return Err(format!(
                            "unexpected argument '{}' ({} takes key=value)",
                            parse::clip(text),
                            cmd.verb
                        ));
                    };
                    base.insert(p.key.clone(), convert(Some(&p.ty), text));
                }
            }
        }
        Ok(match items {
            None => vec![base],
            Some(its) => its
                .into_iter()
                .map(|mut m| {
                    for (k, v) in &base {
                        m.insert(k.clone(), v.clone());
                    }
                    m
                })
                .collect(),
        })
    }

    fn items_by_number(
        &self,
        path: &[String],
        cmd: &Command,
        ns: &[usize],
    ) -> Result<Vec<Map<String, Value>>, String> {
        let rows = self
            .last_print
            .get(path)
            .ok_or_else(|| format!("no items listed in {}: run print first", path_text(path)))?;
        let keys: Vec<&str> = cmd.required().map(|p| p.key.as_str()).collect();
        let mut out = Vec::new();
        for &n in ns {
            let row = rows.get(n).ok_or_else(|| {
                format!("no such item {n} (the last print listed {})", rows.len())
            })?;
            let mut m = Map::new();
            for k in &keys {
                if let Some(v) = row.get(*k).filter(|v| !v.is_null()) {
                    m.insert((*k).to_owned(), v.clone());
                }
            }
            if m.is_empty() {
                return Err(format!(
                    "item {n} cannot be used with {} (it has no {})",
                    cmd.verb,
                    keys.iter().map(|k| kebab(k)).collect::<Vec<_>>().join(", ")
                ));
            }
            out.push(m);
        }
        Ok(out)
    }

    fn run_command(&mut self, path: &[String], id: &str, args: &[Arg]) -> Next {
        let Some(cmd) = self.command(id) else {
            return Next::Done(Output::error(format!("no command {id}")));
        };
        let sets = match self.build(path, &cmd, args, false) {
            Ok(s) => s,
            Err(e) => return Next::Done(Output::error(e)),
        };
        let multi = sets.len() > 1;
        let req = if multi {
            let steps: Vec<Value> = sets
                .into_iter()
                .map(|p| json!({"command": id, "params": p}))
                .collect();
            Request::call("engine.batch", json!({"steps": steps, "atomic": true}))
        } else {
            Request::execute(
                id,
                Value::Object(sets.into_iter().next().unwrap_or_default()),
            )
        };
        Next::Send(
            vec![req],
            Box::new(move |sh, replies| match reply(&replies, 0) {
                Ok(v) => {
                    let task = v
                        .get("id")
                        .or_else(|| v.get("task"))
                        .filter(|t| !t.is_null());
                    if let (true, false, Some(task)) = (cmd.task, multi, task) {
                        let columns = columns_of(&v);
                        return sh.follow(Follow::new(task.clone(), columns));
                    }
                    let lines = if multi {
                        Vec::new()
                    } else {
                        result_lines(&cmd, &v)
                    };
                    if cmd.query {
                        Next::Done(Output::lines(lines))
                    } else {
                        sh.with_refresh(Output::lines(lines))
                    }
                }
                // The router no longer knows it: read its command list again.
                Err(e) if e.starts_with("unknown command") => sh.reload_registry(Output::error(e)),
                Err(e) => Next::Done(Output::error(e)),
            }),
        )
    }

    fn export(
        &mut self,
        path: Vec<String>,
        file: Option<String>,
        terse: bool,
        sensitive: bool,
    ) -> Next {
        let ids = export::reads(&self.reg);
        // `show-sensitive`: the prints that can, asked for their secrets
        // (the router refuses below group full).
        let reqs = ids
            .iter()
            .map(|id| {
                let shows = sensitive
                    && self
                        .reg
                        .by_id(id)
                        .is_some_and(|(_, c)| c.param(export::SHOW_SENSITIVE).is_some());
                let params = if shows {
                    json!({ export::SHOW_SENSITIVE: true })
                } else {
                    json!({})
                };
                Request::execute(id, params)
            })
            .collect();
        Next::Send(
            reqs,
            Box::new(move |sh, replies| {
                let mut results = BTreeMap::new();
                for (i, id) in ids.iter().enumerate() {
                    match reply(&replies, i) {
                        Ok(v) => {
                            results.insert(id.clone(), v);
                        }
                        Err(e) => return Next::Done(Output::error(format!("{id}: {e}"))),
                    }
                }
                let script = export::script(&sh.reg, &path, &results, &sh.version, sensitive);
                // RouterOS's layout: wrapped at the terminal's width (a file
                // at 80, so it does not depend on the window), or `terse`.
                let script = match (terse, &file) {
                    (true, _) => export::terse(&script),
                    (false, Some(_)) => export::wrap(&script, export::DEFAULT_WIDTH),
                    (false, None) => {
                        export::wrap(&script, sh.width.unwrap_or(export::DEFAULT_WIDTH))
                    }
                };
                match file {
                    None => Next::Done(Output::lines(script_lines(&script))),
                    Some(f) => Next::Send(
                        vec![Request::WriteFile {
                            path: f.clone(),
                            content: script,
                        }],
                        Box::new(move |_, replies| match reply(&replies, 0) {
                            Ok(_) => Next::Done(Output::lines(vec![Line::styled(
                                Style::Ok,
                                format!("saved to {f}"),
                            )])),
                            Err(e) => Next::Done(Output::error(e)),
                        }),
                    ),
                }
            }),
        )
    }

    /// The `engine.batch` steps of a script, or the first error with its
    /// line number. Scripts start at the root menu and leave the terminal's
    /// menu alone.
    pub fn script_steps(&self, text: &str) -> Result<Vec<Value>, String> {
        if text.len() > MAX_SCRIPT {
            return Err(format!("script too long (at most {MAX_SCRIPT} bytes)"));
        }
        let mut cwd: Vec<String> = Vec::new();
        let mut steps = Vec::new();
        let mut joined = String::new();
        let mut first_line = 1usize;
        for (n, raw) in text.lines().enumerate() {
            let raw = raw.trim_end_matches('\r');
            if joined.is_empty() {
                first_line = n + 1;
            }
            // A trailing `\` continues the line.
            if let Some(cont) = raw.strip_suffix('\\') {
                joined.push_str(cont);
                continue;
            }
            joined.push_str(raw);
            let line = std::mem::take(&mut joined);
            for (_, stmt) in parse::split(&line) {
                let at = |m: String| format!("line {first_line}: {m}");
                match parse::parse(&self.reg, &cwd, stmt)
                    .map_err(|e| at(format!("{} (column {})", e.message, e.column)))?
                {
                    Parsed::Empty => {}
                    Parsed::Navigate(p) => cwd = p,
                    Parsed::Command { path, id, args } => {
                        let cmd = self
                            .command(&id)
                            .ok_or_else(|| at(format!("no command {id}")))?;
                        for p in self.build(&path, &cmd, &args, true).map_err(at)? {
                            steps.push(json!({"command": id, "params": p}));
                        }
                    }
                    _ => {
                        return Err(at(
                            "only configuration commands can be imported (not print, export, import, quit or ?)"
                                .into(),
                        ));
                    }
                }
            }
        }
        // A last line that ends in `\` (a script cut short in transfer):
        // its command would be silently lost.
        if !joined.is_empty() {
            return Err(format!(
                "line {first_line}: the last line is continued (ends in \\) but nothing follows"
            ));
        }
        Ok(steps)
    }

    fn import_text(&mut self, text: &str) -> Next {
        if self.reg.is_empty() {
            return Next::Done(Output::error(
                "the router's command list has not arrived yet (not connected?)",
            ));
        }
        let steps = match self.script_steps(text) {
            Ok(s) => s,
            Err(e) => return Next::Done(Output::error(format!("{e}; nothing was applied"))),
        };
        if steps.is_empty() {
            return Next::Done(Output::lines(vec![Line::styled(
                Style::Dim,
                "nothing to import",
            )]));
        }
        let order = (0..steps.len()).collect();
        let retry = Retry::new(steps.len());
        import_batch(steps, order, retry)
    }

    /// `?`: a menu's sub-menus and commands, or one command's parameters.
    pub fn help(&self, path: &[String], id: Option<&str>) -> Vec<Line> {
        let mut out = Vec::new();
        if let Some(id) = id {
            let Some(cmd) = self.reg.by_id(id).map(|(_, c)| c) else {
                return out;
            };
            out.push(
                Line::new()
                    .with(Style::Menu, path_text(path))
                    .with(Style::Plain, " ")
                    .with(Style::Verb, cmd.verb.clone())
                    .with(Style::Dim, format!(" — {} ({})", cmd.label, cmd.id)),
            );
            if let Err(why) = &cmd.enabled {
                out.push(Line::styled(
                    Style::Warn,
                    format!("  unavailable now: {why}"),
                ));
            }
            let w = cmd
                .params
                .iter()
                .map(|p| kebab(&p.key).chars().count())
                .max()
                .unwrap_or(0);
            for p in &cmd.params {
                let key = kebab(&p.key);
                let pad = " ".repeat(w.saturating_sub(key.chars().count()));
                out.push(
                    Line::new()
                        .with(Style::Plain, "  ")
                        .with(Style::Key, key)
                        .with(Style::Plain, pad)
                        .with(
                            Style::Dim,
                            if p.required {
                                "  required  "
                            } else {
                                "  optional  "
                            },
                        )
                        .with(Style::Plain, p.ty_text.clone()),
                );
            }
            if cmd.verb == "print" && cmd.shape.list {
                out.push(Line::styled(
                    Style::Dim,
                    "  options: detail, as-json, count-only, show-ids, proplist=a,b, where <cond>",
                ));
                out.push(Line::styled(
                    Style::Dim,
                    "  where: field, !field, field=v, !=, ~ (contains), <, >, <=, >=; and, or",
                ));
                let props = cmd
                    .shape
                    .fields
                    .iter()
                    .map(|f| kebab(f))
                    .collect::<Vec<_>>();
                out.push(Line::styled(
                    Style::Dim,
                    format!("  properties: {}", props.join(", ")),
                ));
            } else if cmd.verb != "add" {
                let listed = self.reg.menu(path).is_some_and(|m| m.print().is_some());
                if listed && cmd.required().next().is_some() {
                    out.push(Line::styled(
                        Style::Dim,
                        "  the first plain word may name items: 0,2 (numbers of the last print), *1 (ids) or a name",
                    ));
                }
            }
            if let Some((_, result)) = cmd.doc.split_once('→') {
                out.push(Line::styled(
                    Style::Dim,
                    format!("  returns {}", result.trim()),
                ));
            }
            return out;
        }
        let Some(menu) = self.reg.menu(path) else {
            return out;
        };
        out.push(Line::styled(Style::Menu, path_text(path)));
        for (name, child) in &menu.children {
            let mut labels: Vec<&str> = child.commands.values().map(|c| c.label.as_str()).collect();
            labels.dedup();
            let about = child
                .print()
                .map(|c| c.label.clone())
                .or_else(|| labels.first().map(|l| (*l).to_owned()))
                .unwrap_or_default();
            out.push(
                Line::new()
                    .with(Style::Plain, "  ")
                    .with(Style::Menu, format!("{name:<16}"))
                    .with(Style::Dim, format!(" {about}")),
            );
        }
        for (verb, cmd) in &menu.commands {
            let mut l = Line::new()
                .with(Style::Plain, "  ")
                .with(Style::Verb, format!("{verb:<16}"))
                .with(Style::Dim, format!(" {}", cmd.label));
            if let Err(why) = &cmd.enabled {
                l.push(Style::Warn, format!(" (unavailable: {why})"));
            }
            out.push(l);
        }
        out.push(
            Line::new()
                .with(Style::Plain, "  ")
                .with(Style::Verb, format!("{:<16}", parse::EXPORT))
                .with(
                    Style::Dim,
                    " script that recreates this configuration (file=… saves it)",
                ),
        );
        if path.is_empty() {
            for (alias, id) in &self.reg.aliases {
                let Some((cpath, cmd)) = self.reg.by_id(id) else {
                    continue;
                };
                out.push(
                    Line::new()
                        .with(Style::Plain, "  ")
                        .with(Style::Verb, format!("{alias:<16}"))
                        .with(
                            Style::Dim,
                            format!(" {} (= {} {})", cmd.label, path_text(cpath), cmd.verb),
                        ),
                );
            }
            out.push(
                Line::new()
                    .with(Style::Plain, "  ")
                    .with(Style::Verb, format!("{:<16}", parse::IMPORT))
                    .with(Style::Dim, " run a script as one atomic batch (file=…)"),
            );
            out.push(
                Line::new()
                    .with(Style::Plain, "  ")
                    .with(Style::Verb, format!("{:<16}", parse::QUIT))
                    .with(Style::Dim, " leave the terminal"),
            );
        }
        out.push(Line::styled(
            Style::Dim,
            "  .. goes up, / to the root; names abbreviate; Tab completes; Ctrl+X: Safe Mode",
        ));
        out
    }
}

/// Milliseconds between two polls of a task with nothing new.
const POLL_MS: u64 = 250;

/// A task being followed: its id, the last event seen and the columns.
struct Follow {
    id: Value,
    after: u64,
    columns: Option<Vec<String>>,
    widths: Vec<usize>,
    stop_sent: bool,
    /// The router's own header was printed (`text` polls).
    header_done: bool,
}

impl Follow {
    fn new(id: Value, columns: Option<Vec<String>>) -> Self {
        Self {
            id,
            after: 0,
            columns,
            widths: Vec::new(),
            stop_sent: false,
            header_done: false,
        }
    }

    /// The header (first time) and one line per event.
    fn rows(&mut self, events: &[Value]) -> Vec<Line> {
        let mut out = Vec::new();
        let Some(first) = events.first() else {
            return out;
        };
        if self.widths.is_empty() {
            let cols = self.columns.clone().unwrap_or_else(|| {
                let mut keys: Vec<String> = first
                    .as_object()
                    .map(|o| o.keys().filter(|k| *k != "seq").cloned().collect())
                    .unwrap_or_default();
                keys.insert(0, "seq".into());
                keys
            });
            self.widths = cols
                .iter()
                .map(|c| {
                    let v = first.get(c).map(format::value_text).unwrap_or_default();
                    c.chars().count().max(v.chars().count()) + 2
                })
                .collect();
            let head: String = cols
                .iter()
                .zip(&self.widths)
                .map(|(c, w)| format!("{:<w$}", kebab(c).to_uppercase()))
                .collect();
            out.push(Line::styled(Style::Header, head.trim_end().to_owned()));
            self.columns = Some(cols);
        }
        let cols = self.columns.clone().unwrap_or_default();
        for ev in events {
            let text: String = cols
                .iter()
                .zip(&self.widths)
                .map(|(c, w)| {
                    let v = ev.get(c).map(format::value_text).unwrap_or_default();
                    format!("{v:<w$} ")
                })
                .collect();
            let failed = ev
                .get("status")
                .and_then(Value::as_str)
                .is_some_and(|s| !s.is_empty() && s != "ok");
            let style = if failed { Style::Warn } else { Style::Plain };
            out.push(Line::styled(style, text.trim_end().to_owned()));
        }
        out
    }
}

/// An ordered `columns` list in a reply, if the router gives one.
fn columns_of(v: &Value) -> Option<Vec<String>> {
    let cols: Vec<String> = v
        .get("columns")?
        .as_array()?
        .iter()
        .filter_map(Value::as_str)
        .take(32)
        .map(str::to_owned)
        .collect();
    (!cols.is_empty()).then_some(cols)
}

impl Shell {
    /// Poll a task (`tool.task.poll`), printing its events as they come,
    /// until it is done; Ctrl+C ([`Shell::interrupt`]) sends
    /// `tool.task.stop` once and keeps polling for the summary.
    fn follow(&mut self, mut f: Follow) -> Next {
        Next::Send(
            vec![Request::execute(
                "tool.task.poll",
                // `text`: the router renders the lines (RouterOS style) itself.
                json!({"id": f.id, "after_seq": f.after, "text": true}),
            )],
            Box::new(move |sh, replies| {
                let p = match reply(&replies, 0) {
                    Ok(p) => p,
                    Err(e) => return Next::Done(Output::error(e)),
                };
                if f.columns.is_none() {
                    f.columns = columns_of(&p);
                }
                if let Some(lost) = p.get("lost").and_then(Value::as_u64).filter(|n| *n > 0) {
                    sh.live
                        .push(Line::styled(Style::Warn, format!("({lost} events lost)")));
                }
                let events = p
                    .get("events")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                let rendered: Option<Vec<String>> = p
                    .get("lines")
                    .and_then(Value::as_array)
                    .map(|l| l.iter().map(format::value_text).collect());
                match rendered {
                    Some(lines) => {
                        if !f.header_done {
                            f.header_done = true;
                            if let Some(h) = p.get("header").and_then(Value::as_str) {
                                sh.live.push(Line::styled(Style::Header, h.to_owned()));
                            }
                        }
                        for (i, text) in lines.into_iter().enumerate() {
                            let failed = events
                                .get(i)
                                .and_then(|e| e.get("status"))
                                .and_then(Value::as_str)
                                .is_some_and(|s| !s.is_empty() && s != "ok");
                            let style = if failed { Style::Warn } else { Style::Plain };
                            sh.live.push(Line::styled(style, text));
                        }
                    }
                    None => {
                        let rows = f.rows(&events);
                        sh.live.extend(rows);
                    }
                }
                f.after = p.get("next_seq").and_then(Value::as_u64).unwrap_or(f.after);
                if p.get("done").and_then(Value::as_bool) == Some(true) {
                    let mut lines = Vec::new();
                    let state = p.get("state").and_then(Value::as_str).unwrap_or("");
                    if let Some(r) = p.get("reason").and_then(Value::as_str) {
                        lines.push(Line::styled(Style::Warn, format!("{state}: {r}")));
                    }
                    if let Some(text) = p.get("summary_lines").and_then(Value::as_array) {
                        lines.extend(text.iter().map(|l| Line::plain(format::value_text(l))));
                    } else if let Some(sum) = p
                        .get("summary")
                        .filter(|s| s.as_object().is_some_and(|o| !o.is_empty()))
                    {
                        lines.extend(format::object(sum, &[]));
                    }
                    return Next::Done(Output::lines(lines));
                }
                if sh.interrupted && !f.stop_sent {
                    f.stop_sent = true;
                    let id = f.id.clone();
                    return Next::Send(
                        vec![Request::execute("tool.task.stop", json!({ "id": id }))],
                        Box::new(move |sh, replies| match reply(&replies, 0) {
                            Ok(_) => sh.follow(f),
                            Err(e) => Next::Done(Output::error(e)),
                        }),
                    );
                }
                if p.get("more").and_then(Value::as_bool) == Some(true) {
                    return sh.follow(f);
                }
                Next::Send(
                    vec![Request::Sleep { ms: POLL_MS }],
                    Box::new(move |sh, replies| {
                        let cut = reply(&replies, 0)
                            .ok()
                            .and_then(|v| v.get("interrupted").and_then(Value::as_bool));
                        if cut == Some(true) {
                            sh.interrupted = true;
                        }
                        sh.follow(f)
                    }),
                )
            }),
        )
    }
}

fn json_lines(v: &Value) -> Vec<Line> {
    serde_json::to_string_pretty(v)
        .unwrap_or_else(|_| v.to_string())
        .lines()
        .map(Line::plain)
        .collect()
}

/// What a command's result prints: tables for lists, `key: value` for
/// objects; nothing when an action only echoes the item or its own
/// parameters (`{id}`, `{bridge, interface}`).
fn result_lines(cmd: &Command, v: &Value) -> Vec<Line> {
    match v {
        Value::Array(rows) if rows.iter().all(Value::is_object) && !rows.is_empty() => {
            format::table(rows, &cmd.shape, &PrintOpts::default(), false, None)
        }
        Value::Array(rows) if rows.is_empty() => Vec::new(),
        Value::Object(o)
            if !cmd.query
                && o.keys()
                    .all(|k| k == "id" || k == "name" || cmd.param(k).is_some()) =>
        {
            Vec::new()
        }
        Value::Object(o) if o.is_empty() => Vec::new(),
        Value::Null => Vec::new(),
        other => format::object(other, &cmd.shape.fields),
    }
}

/// The lines of an exported script, colored (a line after a ` \\` goes on
/// with arguments).
pub fn script_lines(script: &str) -> Vec<Line> {
    let mut cont = false;
    script
        .lines()
        .map(|l| {
            let line = script_line_in(l, cont);
            cont = !l.starts_with('#') && l.ends_with('\\');
            line
        })
        .collect()
}

/// A line of an exported script, colored.
pub fn script_line(line: &str) -> Line {
    script_line_in(line, false)
}

/// `cont`: the line continues the one before (no verb).
fn script_line_in(line: &str, cont: bool) -> Line {
    if line.starts_with('#') {
        return Line::styled(Style::Comment, line);
    }
    let words = crate::lex::words(line);
    // `terse`: the menu, then the verb (the last word before the first
    // `key=value`).
    let menu_words = if line.starts_with('/') {
        let bare = words.iter().take_while(|w| w.key.is_none()).count();
        if bare == words.len() {
            return Line::styled(Style::Menu, line);
        }
        bare.saturating_sub(1)
    } else {
        0
    };
    let mut l = Line::new();
    let mut last = 0usize;
    for (i, w) in words.into_iter().enumerate() {
        l.push(Style::Plain, line.get(last..w.start).unwrap_or(""));
        let raw = line.get(w.start..w.end).unwrap_or("");
        match (i, w.key.as_ref()) {
            _ if raw == "\\" => {
                l.push(Style::Dim, raw);
            }
            (i, _) if i < menu_words => {
                l.push(Style::Menu, raw);
            }
            (i, None) if i == menu_words && !cont => {
                l.push(Style::Verb, raw);
            }
            (_, Some(_)) => {
                let split = w.value_start.saturating_sub(w.start);
                l.push(Style::Key, raw.get(..split).unwrap_or(raw));
                l.push(Style::Value, raw.get(split..).unwrap_or(""));
            }
            _ => {
                l.push(Style::Item, raw);
            }
        }
        last = w.end;
    }
    l
}
