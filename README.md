# tls-parser

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE-MIT)
[![Apache License 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE-APACHE)
[![Crates.io Version](https://img.shields.io/crates/v/tls-parser.svg)](https://crates.io/crates/tls-parser)
[![Github CI](https://github.com/rusticata/der-parser/workflows/Continuous%20integration/badge.svg)](https://github.com/rusticata/der-parser/actions)
[![Minimum rustc version](https://img.shields.io/badge/rustc-1.44.0+-lightgray.svg)](#rust-version-requirements)


## Overview

tls-parser is a parser for the TLS protocol. The parser supports protocols SSLv3 to TLSv1.3.

The parser is based on [nom](https://github.com/rusticata/tls-parser) (see nom's documentation for return and
error types).

The parser is published on `crates.io`.
To use it, add the following to your `Cargo.toml` file:
```
[dependencies]
tls-parser = "0.10.0"
```

<!-- cargo-sync-readme start -->

# TLS Parser

A TLS parser, implemented with the [nom](https://github.com/Geal/nom)
parser combinator framework.

The goal of this parser is to implement TLS messages analysis, for example
to use rules from a network IDS, for ex during the TLS handshake.

It implements structures and parsing functions for records and messages, but
need additional code to handle fragmentation, or to fully inspect messages.
Parsing some TLS messages requires to know the previously selected parameters.
See [the rusticata TLS parser](https://github.com/rusticata/rusticata/blob/master/src/tls.rs)
for a full example.

The code is available on [Github](https://github.com/rusticata/tls-parser)
and is part of the [Rusticata](https://github.com/rusticata) project.

## Parsing records

The main parsing functions are located in the [tls.rs](src/tls.rs) file. The entry functions are:
- `parse_tls_plaintext`: parses a record as plaintext
- `parse_tls_encrypted`: read an encrypted record. The parser has no crypto or decryption features, so the content
  will be left as opaque data.

# Examples

```rust
extern crate nom;
extern crate tls_parser;

use nom::{Err, IResult};
use tls_parser::parse_tls_plaintext;

let bytes : &[u8]= include_bytes!("../assets/client_hello_dhe.bin");
// [ 0x16, 0x03, 0x01 ... ];
let res = parse_tls_plaintext(&bytes);
match res {
    Ok((rem,record)) => {
        // rem is the remaining data (not parsed)
        // record is an object of type TlsRecord
    },
    Err(Err::Incomplete(needed)) => {
        eprintln!("Defragmentation required (TLS record)");
    },
    Err(e) => { eprintln!("parse_tls_record_with_header failed: {:?}",e); }
}
```

Note that knowing if a record is plaintext or not is the responsibility of the caller.

As reading TLS records may imply defragmenting records, some functions are
provided to only read the record as opaque data (which ensures the record is
complete and gives the record header) and then reading messages from data.

Here is an example of two-steps parsing:

```rust

// [ 0x16, 0x03, 0x01 ... ];
match parse_tls_raw_record(bytes) {
    Ok((rem, ref r)) => {
        match parse_tls_record_with_header(r.data, &r.hdr) {
            Ok((rem2,ref msg_list)) => {
                for msg in msg_list {
                    // msg has type TlsMessage
                }
            }
            Err(Err::Incomplete(needed)) => { eprintln!("incomplete record") }
            Err(_) => { eprintln!("error while parsing record") }
        }
    }
    Err(Err::Incomplete(needed)) => { eprintln!("incomplete record header") }
    Err(_) => { eprintln!("error while parsing record header") }
}
```

Some additional work is required if reading packets from the network, to support
reassembly of TCP segments and reassembly of TLS records.

For a complete example of a TLS parser supporting defragmentation and states, see the
[rusticata/src/tls.rs](https://github.com/rusticata/rusticata/blob/master/src/tls.rs) file of
the [rusticata](https://github.com/rusticata/rusticata) crate.

## State machine

A TLS state machine is provided in [tls_states.rs](src/tls_states.rs). The state machine is separated from the
parsing functions, and is almost independent.
It is implemented as a table of transitions, mainly for the handshake phase.

After reading a TLS message using the previous functions, the TLS state can be
updated using the `tls_state_transition` function. If the transition succeeds,
it returns `Ok(new_state)`, otherwise it returns `Err(error_state)`.

```rust

struct ParseContext {
    state: TlsState,
}

match tls_state_transition(ctx.state, msg, to_server) {
    Ok(s)  => { ctx.state = s; Ok(()) }
    Err(_) => {
        ctx.state = TlsState::Invalid;
        Err("Invalid state")
    }
}
```

# Implementation notes

When parsing messages, if a field is an integer corresponding to an enum of known values,
it is not parsed as an enum type, but as an integer. While this complicates accesses,
it allows to read invalid values and continue parsing (for an IDS, it's better to read
values than to get a generic parse error).

<!-- cargo-sync-readme end -->

## Changes

### 0.11.0

- Use `Cow` to allow having owned objects

### 0.10.0

- Upgrade to nom 6
- Remove all macro-base parsers (use functions, and nom-derive when possible)
- Add support for DTLS (Handshake)
- Add functions to parse extensions expected in Client/Server Hello

### 0.9.4

- In ServerHello, an empty SNI extension can be sent (RFC 6066)

### 0.9.3

- Fix error in state machine (wrong Client Certificate direction)

### 0.9.2

- Upgrade to phf 0.8
- Upgrade cookie-factory to 0.3.0

### 0.9.1

- Mark cookie-factory as optional (only used for serialization)

### 0.9.0

- Upgrade to nom 5
- Rustfmt

### 0.8.1

- Set edition to 2018
- Check heartbeat message length (subtraction could underflow)
- Add more checks for record length (RFC compliance, not for parser safety)

### 0.8.0

- Add support for record size limit extension
- Add support for encrypted server name (eSNI) extension
- State machine: use direction and support TLS 1.3 0-RTT
- State machine: add new state to indicate connection is closed (after fatal alert)
- Use TlsVersion type for SSL record version
- Update doc, and use cargo sync-readme

### 0.7.1

- Improve state machine, handle resumption failure, and non-fatal alerts
- Improve handling of Signature/Hash algorithms, and display
- Update ciphersuites to 2019-03-19

### 0.7.0

- Convert most enums to newtypes
  - warning: this is a breaking change
- Update dependencies and remove unused crates
- Update ciphersuites to 2019-01-23

### 0.6.0

- Upgrade to nom 4.0
  - warning: this is a breaking change
- Fix wrong extension ID for padding and signed timestamp
- Rewrite parse_cipher_suites and parse_compressions_algs to be faster
- Update ciphersuites to 2018-08-13

## Standards
Here is a non-exhaustive list of RFCs this parser is based on:
- [RFC 2246](https://tools.ietf.org/html/rfc2246): The TLS Protocol Version 1.0
- [RFC 4346](https://tools.ietf.org/html/rfc4346): The Transport Layer Security (TLS) Protocol Version 1.1
- [RFC 4366](https://tools.ietf.org/html/rfc4366): Transport Layer Security (TLS) Extensions
- [RFC 4492](https://tools.ietf.org/html/rfc4492): Elliptic Curve Cryptography (ECC) Cipher Suites for Transport Layer Security (TLS)
- [RFC 4507](https://tools.ietf.org/html/rfc4507): Transport Layer Security (TLS) Session
  Resumption without Server-Side State
- [RFC 5077](https://tools.ietf.org/html/rfc5077): Transport Layer Security (TLS) Session
  Resumption without Server-Side State
- [RFC 5246](https://tools.ietf.org/html/rfc5246): The Transport Layer Security (TLS) Protocol Version 1.2
- [RFC 5430](https://tools.ietf.org/html/rfc5430): Suite B Profile for Transport Layer Security (TLS)
- [RFC 5746](https://tools.ietf.org/html/rfc5746): Transport Layer Security (TLS) Renegotiation Indication Extension
- [RFC 6066](https://tools.ietf.org/html/rfc6066): Transport Layer Security (TLS) Extensions: Extension Definitions
- [RFC 6520](https://tools.ietf.org/html/rfc6520): Transport Layer Security (TLS) and
  Datagram Transport Layer Security (DTLS) Heartbeat Extension
- [RFC 6961](https://tools.ietf.org/html/rfc6961): The Transport Layer Security (TLS)
  Multiple Certificate Status Request Extension
- [RFC 7027](https://tools.ietf.org/html/rfc7027): Elliptic Curve Cryptography (ECC) Brainpool Curves
  for Transport Layer Security (TLS)
- [RFC 7301](https://tools.ietf.org/html/rfc7301): Transport Layer Security (TLS)
  Application-Layer Protocol Negotiation Extension
- [RFC 7366](https://tools.ietf.org/html/rfc7366): Encrypt-then-MAC for Transport Layer Security (TLS) and
  Datagram Transport Layer Security (DTLS)
- [RFC 7627](https://tools.ietf.org/html/rfc7627): Transport Layer Security (TLS) Session Hash and
  Extended Master Secret Extension
- [RFC 7919](https://tools.ietf.org/html/rfc7919): Negotiated Finite Field Diffie-Hellman Ephemeral Parameters
  for Transport Layer Security (TLS)
- [RFC 8422](https://tools.ietf.org/html/rfc8422): Elliptic Curve Cryptography (ECC) Cipher Suites
  for Transport Layer Security (TLS) Versions 1.2 and Earlier
- [RFC 8446](https://tools.ietf.org/html/rfc8446): The Transport Layer Security (TLS) Protocol Version 1.3
- [draft-agl-tls-nextprotoneg-03](https://tools.ietf.org/html/draft-agl-tls-nextprotoneg-03): Transport Layer Security (TLS) Next Protocol Negotiation Extension

## FAQ and limitations

### Can the parser decrypt a TLS session if I provide the master secret ?

No, it's not implemented

### Does the parser support TLS compression ?

No. Note that most TLS implementations disabled it after the FREAK attack, so
while detecting compression in `ServerHello` is possible in tls-parser, it
should probably be interpreted as an alert.

### Where are located the TLS CipherSuites ?

They are built when running `cargo build`.

To ease updating the list from the
[IANA TLS
parameters](http://www.iana.org/assignments/tls-parameters/tls-parameters.xml),
a script is provided ([scripts/extract-iana-ciphers.py](scripts/extract-iana-ciphers.py)).
This script will download and pre-parse the list from IANA, and produce a file containing
all ciphersuites names and parameters.

During the build, [build.rs](build.rs) parses this file and produces a static,
read-only hash table of all known ciphers and their properties.

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
