#![no_main]

use libfuzzer_sys::fuzz_target;

// G4.1zd: a DNS query log segment file (blocks of `querylog::format`).
fuzz_target!(|data: &[u8]| {
    if let Err(e) = corerouter_proto_dns::querylog::format::fuzz_check(data) {
        panic!("{e}");
    }
});
