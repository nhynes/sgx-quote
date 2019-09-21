# sgx-quote

[![crates.io version](https://img.shields.io/crates/v/sgx-quote.svg)](https://crates.io/crates/sgx-quote)
[![Docs](https://docs.rs/sgx-quote/badge.svg)](https://docs.rs/sgx-quote)

Zero-copy parsing of Intel SGX quotes using [nom](https://github.com/Geal/nom).

## Example

```rust
let quote = sgx_quote::Quote::parse(quote_bytes)?;
let sig = quote.signature;
ecdsa_verify(sig.attestation_key, quote, sig.isv_report_signature)?;
```
