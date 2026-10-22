//! L3 — CoreRouter engine.
//!
//! Every state change or query is a [`cmd::CommandSpec`] registered under
//! `src/cmd/*.rs`. The UI, the CLI, the control channel and the MCP server all
//! go through one door: [`Session::execute`].

// Every `src/<name>.rs` and `src/<name>/mod.rs` is a public module, generated
// by build.rs (build-support/root_modules.rs): a new module is a new file.
include!(concat!(env!("OUT_DIR"), "/modules.rs"));

pub use auth::{Group, Login, Principal};
pub use error::EngineError;
pub use lockout::Link;
pub use neighbors::{MAX_NEIGHBORS, NeighborTable};
pub use safe_mode::Caller;
pub use session::{CommitMode, JournalEntry, Session, Shared, StorageStatus, lock, shared};
pub use storage::{ConfigStorage, MemoryStorage, Slot, StorageError};
pub use tasks::{Clock, Job, Runner, TaskCtx, TaskState};

pub type Result<T> = std::result::Result<T, EngineError>;
