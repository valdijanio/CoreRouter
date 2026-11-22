#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Err(e) = corerouter_engine::fuzz::config_file(data) {
        panic!("{e}");
    }
});
