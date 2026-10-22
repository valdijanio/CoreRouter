//! L3 — CoreRouter engine.
//!
//! Every state change or query is a [`cmd::CommandSpec`] registered under
//! `src/cmd/*.rs`. The UI, the CLI, the control channel and the MCP server all
//! go through one door: [`Session::execute`].

pub mod cmd;
pub mod error;
pub mod guard;
pub mod neighbors;
pub mod session;
pub mod storage;
pub mod validate;

pub use error::EngineError;
pub use neighbors::{MAX_NEIGHBORS, NeighborTable};
pub use session::{CommitMode, JournalEntry, Session, Shared, StorageStatus, lock, shared};
pub use storage::{ConfigStorage, MemoryStorage, Slot, StorageError};

pub type Result<T> = std::result::Result<T, EngineError>;
