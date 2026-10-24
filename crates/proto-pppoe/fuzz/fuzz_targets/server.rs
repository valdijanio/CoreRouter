#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Err(e) = corerouter_proto_pppoe::fuzz::server(data) {
        panic!("{e}");
    }
});
