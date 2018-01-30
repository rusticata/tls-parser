#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate tls_parser;

fuzz_target!(|data: &[u8]| {
    let _ = tls_parser::parse_tls_extension(data);
});
