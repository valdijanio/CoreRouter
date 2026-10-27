#![no_main]

use libfuzzer_sys::fuzz_target;

// G4.3n: a RouterOS export, as `ppp.secret.import` reads it.
fuzz_target!(|data: &[u8]| {
    if let Err(e) = corerouter_engine::fuzz::routeros_export(data) {
        panic!("{e}");
    }
});
