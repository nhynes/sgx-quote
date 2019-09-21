#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate sgx_quote;

fuzz_target!(|data: &[u8]| {
    sgx_quote::Quote::parse(data).ok();
});
