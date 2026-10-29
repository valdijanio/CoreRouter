//! The integration tests of this crate as one binary (G0.29): one link
//! instead of one per file. A new test file is a `mod` here; tests that
//! need their own process stay in `tests/` (`netns*.rs`, `*_root.rs`, the
//! ones that re-run themselves by test name or set process-wide state such as
//! the logger).

mod cgnat_export;
mod dns_lookup;
mod ppp_export;
mod tasks;
mod terminal;
