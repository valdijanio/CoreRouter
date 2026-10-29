//! The integration tests of this crate as one binary (G0.29): one link
//! instead of one per file. A new test file is a `mod` here; tests that
//! need their own process stay in `tests/` (`netns*.rs`, `*_root.rs`, the
//! ones that re-run themselves by test name or set process-wide state such as
//! the logger).

mod auth;
mod e2e;
mod health;
mod metrics;
mod oslog;
mod package_upload;
mod radius;
mod shutdown;
mod shutdown_checkpoint;
