#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Err(e) = corerouter_proto_radius::fuzz::packet(data) {
        panic!("{e}");
    }
    if let Err(e) = corerouter_proto_radius::fuzz::text(data) {
        panic!("{e}");
    }
});
