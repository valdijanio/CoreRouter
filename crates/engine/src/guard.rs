//! Panic guard: production code must never panic (clippy denies it), but a
//! dependency still might. Every entry point runs inside `run`, and the
//! caller restores the candidate snapshot on `Internal`.
//!
//! Requires `panic = "unwind"` (see the workspace `[profile.release]`).

use std::panic::{AssertUnwindSafe, catch_unwind};

use crate::EngineError;

pub fn run<T>(what: &str, f: impl FnOnce() -> Result<T, EngineError>) -> Result<T, EngineError> {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(r) => r,
        Err(payload) => {
            let msg = payload
                .downcast_ref::<&str>()
                .map(|s| (*s).to_owned())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "non-string panic payload".into());
            log::error!("panic caught in '{what}': {msg}");
            Err(EngineError::Internal(what.to_owned()))
        }
    }
}
