//! Fuzz oracles (G0.5), shared by the short proptest runs of `cargo xtask ci`
//! and the long `cargo fuzz` runs (`fuzz/`). Each takes raw bytes, drives
//! one hostile-input path and returns `Err` with what broke. The engine
//! guard turns a panic into `Internal` and the reply looks normal, so
//! [`panics`] watches for panics with a hook instead.

#![doc(hidden)]

use std::cell::Cell;
use std::sync::Once;

use corerouter_hal::VirtualHal;
use corerouter_model::persist;
use serde_json::json;

use crate::{MemoryStorage, Session, Slot, cmd};

thread_local! {
    static PANICS: Cell<u32> = const { Cell::new(0) };
}

/// Run `f` and count the panics on this thread while it ran, caught or
/// not by `catch_unwind`. The hook keeps the previous one (libFuzzer's
/// aborts, so `cargo fuzz` sees even a caught panic as a crash).
pub fn panics<T>(f: impl FnOnce() -> T) -> (T, u32) {
    static HOOK: Once = Once::new();
    HOOK.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            PANICS.with(|n| n.set(n.get().saturating_add(1)));
            previous(info);
        }));
    });
    let before = PANICS.with(Cell::get);
    let out = f();
    (out, PANICS.with(Cell::get).saturating_sub(before))
}

/// The saved config file (`model::persist`) as a boot reads it. A file
/// that decodes must re-encode to a fixed point (save → load → save gives
/// the same bytes), and the router must boot from it and answer every
/// query without a panic: decode checks the layout, not the meaning, so a
/// hand-edited file reaches the engine.
pub fn config_file(data: &[u8]) -> Result<(), String> {
    let text = String::from_utf8_lossy(data).into_owned();
    if let Ok((store, users)) = persist::decode_with_users(&text) {
        let once = persist::encode_with_users(&store, &users).map_err(|e| e.to_string())?;
        let (again, users) = persist::decode_with_users(&once)
            .map_err(|e| format!("re-encoded file does not load: {e}"))?;
        let twice = persist::encode_with_users(&again, &users).map_err(|e| e.to_string())?;
        if once != twice {
            return Err("save → load → save changed the file".into());
        }
    }
    let storage = MemoryStorage::default();
    storage.put(Slot::Current, Some(text));
    let ((), panicked) = panics(|| {
        let mut s = Session::with_storage(Box::new(VirtualHal::default()), Box::new(storage));
        for spec in cmd::all().filter(|c| !c.journal && !c.task) {
            let _ = s.execute(spec.id, &json!({}));
        }
    });
    if panicked > 0 {
        return Err(format!("{panicked} panic(s) booting from the file"));
    }
    Ok(())
}
