//! L4 — the CoreRouter terminal: RouterOS syntax, generated from the
//! command registry.
//!
//! `/ip address add address=10.0.0.1/24 interface=ether1` is the engine
//! command `ip.address.add {"address": "10.0.0.1/24", "interface":
//! "ether1"}`: the menu is the id's prefix, the verb its last segment (`list`
//! is `print`), parameters are the doc's keys in kebab-case. The tree comes
//! from `engine.list` at run time, so a command added to the engine is in
//! the terminal without a line here.
//!
//! Pure and without I/O (compiles to wasm32): [`Shell`] turns lines into
//! [`Job`]s that ask the front end for control-channel calls and files.
//! Front ends: the GUI's terminal window (`crates/ui`), `corerouter-cli
//! shell`, and SSH in the daemon. See `docs/terminal.md`.

mod complete;
pub mod doc;
mod export;
pub mod format;
pub mod lex;
pub mod parse;
pub mod registry;
mod shell;
pub mod style;

pub use complete::{Candidate, Completion};
pub use registry::{Registry, path_text};
pub use shell::{Job, MAX_SCRIPT, Reply, Request, SafeMode, Shell, Step, convert, script_line};
pub use style::{Line, Output, Span, Style, ansi, to_ansi};
