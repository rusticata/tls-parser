//! # TLS Parser
//!
//! A TLS parser, implemented with the [nom](https://github.com/Geal/nom)
//! parser combinator framework.
//!
//! The goal of this parser is to implement TLS messages analysis, for example
//! to use rules from a network IDS, for ex during the TLS handshake.
//!
//! It implements structures and parsing functions for records and messages, but
//! need additional code to handle fragmentation, or to fully inspect messages.
//! Parsing some TLS messages requires to know the previously selected parameters.
//! See [the rusticata TLS parser](https://github.com/rusticata/rusticata/blob/master/src/tls.rs)
//! for a full example.
//!
//! The code is available on [Github](https://github.com/rusticata/tls-parser)
//! and is part of the [Rusticata](https://github.com/rusticata) project.
//!
//! # Implementation notes
//!
//! When parsing messages, if a field is an integer corresponding to an enum of known values,
//! it is not parsed as an enum type, but as an integer. While this complicates accesses,
//! it allows to read invalid values and continue parsing (for an IDS, it's better to read
//! values than to get a generic parse error).

#[macro_use]
extern crate enum_primitive;

#[macro_use]
extern crate nom;

extern crate phf;

#[macro_use]
extern crate rusticata_macros;

pub use tls_alert::*;
/// TLS alerts
#[macro_use]
pub mod tls_alert;
pub use tls_ciphers::*;
/// TLS ciphersuites definitions and parameters
pub mod tls_ciphers;
pub use tls_dh::*;
/// Diffie-Hellman parameters
pub mod tls_dh;
pub use tls_ec::*;
/// Elliptic curves
pub mod tls_ec;
pub use tls_extensions::*;
/// TLS extensions
#[macro_use]
pub mod tls_extensions;
pub use tls_sign_hash::*;
/// TLS signature schemes
pub mod tls_sign_hash;
pub use tls_states::*;
/// TLS state machine
pub mod tls_states;
pub use tls::*;
/// TLS parser structures and functions
pub mod tls;

mod tls_debug;
