#![no_main]

use libfuzzer_sys::fuzz_target;

// G4.8b: one /dev/kmsg record and one `journalctl -o json` line.
fuzz_target!(|data: &[u8]| {
    if let Err(e) = corerouter_hal::oslog::fuzz_check(data) {
        panic!("{e}");
    }
});
