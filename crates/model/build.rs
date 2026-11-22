//! Generates this crate's root module list (`build-support/root_modules.rs`).

include!("../../build-support/root_modules.rs");

fn main() -> Result<(), Box<dyn std::error::Error>> {
    root_modules()
}
