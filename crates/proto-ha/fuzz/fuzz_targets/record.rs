#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| corerouter_proto_ha::fuzz::record(data));
