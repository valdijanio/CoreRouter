//! L3 — CoreRouter engine.
//!
//! Every state change or query is a [`cmd::CommandSpec`] registered under
//! `src/cmd/*.rs`. The UI, the CLI, the control channel and the MCP server all
//! go through one door: [`Session::execute`].

pub mod auth;
pub mod cmd;
pub mod error;
pub mod firewall_dyn;
pub mod guard;
pub mod lockout;
pub mod neighbors;
pub mod safe_mode;
pub mod session;
pub mod storage;
pub mod tasks;
pub mod tools;
pub mod validate;

pub use auth::{Group, Login, Principal};
pub use error::EngineError;
pub use lockout::Link;
pub use neighbors::{MAX_NEIGHBORS, NeighborTable};
pub use safe_mode::Caller;
pub use session::{CommitMode, JournalEntry, Session, Shared, StorageStatus, lock, shared};
pub use storage::{ConfigStorage, MemoryStorage, Slot, StorageError};
pub use tasks::{Clock, Job, Runner, TaskCtx, TaskState};

pub type Result<T> = std::result::Result<T, EngineError>;
