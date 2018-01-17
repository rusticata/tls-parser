# tls-parser

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE-MIT)
[![Apache License 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE-APACHE)
[![Build Status](https://travis-ci.org/rusticata/tls-parser.svg?branch=master)](https://travis-ci.org/rusticata/tls-parser)
[![Crates.io Version](https://img.shields.io/crates/v/tls-parser.svg)](https://crates.io/crates/tls-parser)

## Overview

tls-parser is a parser for the TLS protocol. The parser supports protocols SSLv3 to TLSv1.2 (in particular,
TLSv1.3 is supported and implemented as draft 19.

The parser is based on [nom](https://github.com/rusticata/tls-parser) (see nom's documentation for return and
error types).

The parser is published on `crates.io`.
To use it, add the following to your `Cargo.toml` file:
```
[dependencies]
tls-parser = "0.3.0"
```

## Parsing records

The main parsing functions are located in the [tls.rs](src/tls.rs) file. The entry functions are:
- `parse_tls_plaintext`: parses a record as plaintext
- `parse_tls_encrypted`: read an encrypted record. The parser has no crypto or decryption features, so the content
  will be left as opaque data.

```rust
extern crate nom;
extern crate tls_parser;

use nom::IResult;
use tls_parser::parse_tls_plaintext;

let bytes = [ 0x16, 0x03, 0x01 ... ];
let res = parse_tls_plaintext(&bytes);
match res {
	IResult::Done(rem,record) => {
		// rem is the remaining data (not parsed)
		// record is an object of type TlsRecord
	},
	IResult::Incomplete(_) => {
		debug!("Defragmentation required (TLS record)");
	},
	IResult::Error(e) => { warn!("parse_tls_record_with_header failed: {:?}",e); }
}
}
```

Note that knowing if a record is plaintext or not is the responsibility of the caller.

As reading TLS records may imply defragmenting records, some functions are
provided to only read the record as opaque data (which ensures the record is
complete and gives the record header) and then reading messages from data.

Here is an example of two-steps parsing:

```rust
match parse_tls_raw_record(i) {
	IResult::Done(rem, ref r) => {
		match parse_tls_record_with_header(r.data,r.hdr.clone()) {
			IResult::Done(rem2,ref msg_list) => {
				for msg in msg_list {
					// msg has type TlsMessage
				}
			},
			// ...
		}
	},
	// ...
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
// update state machine
match tls_state_transition(self.state, msg) {
	Ok(s)  => self.state = s,
	Err(_) => {
		self.state = TlsState::Invalid;
		self.events.push(TlsParserEvents::InvalidState as u32);
		status |= R_STATUS_EVENTS;
	},
};
```

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
- [draft-agl-tls-nextprotoneg-03](https://tools.ietf.org/html/draft-agl-tls-nextprotoneg-03): Transport Layer Security (TLS) Next Protocol Negotiation Extension

## FAQ and limitations

### Can the parser decrypt a TLS session if I provide the master secret ?

No, it's not implemented

### Does the parser support TLS compression ?

No. Note that most TLS implementations disabled it after the FREAK attack, so
while detecting compression in `ServerHello` is possible in tls-parser, it
should probably be interpreted as an alert.

### Where are located the TLS CipherSuites ?

They are built when running `cargo build`, to ease updating the list from the
[IANA TLS
parameters](http://www.iana.org/assignments/tls-parameters/tls-parameters.xml).

The file is parsed using [a script](scripts/convert_ciphers_to_rust.py). During
the build, the [build.rs](build.rs) parses the list and produces a static,
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
