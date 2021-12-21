//!
//! The [CIPHERS](static.CIPHERS.html) static hash map is built during the
//! compilation of the crate, using `build.rs`. It parses a file derived from
//! the [IANA TLS Cipher Suite
//! Registry](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4)
//! to automatically extract parameters and add all known ciphersuites.

#![allow(non_camel_case_types)]
#![allow(clippy::unreadable_literal)]

use core::convert::TryFrom;
use enum_primitive::{enum_from_primitive, enum_from_primitive_impl, enum_from_primitive_impl_ty};

use crate::TlsCipherSuiteID;

#[derive(Debug)]
pub struct CipherSuiteNotFound(());

enum_from_primitive! {
/// Key exchange methods
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TlsCipherKx {
    Null = 0,
    Psk,
    Krb5,
    Srp,
    Rsa,
    Dh,
    Dhe,
    Ecdh,
    Ecdhe,
    Aecdh,
    Eccpwd,
    Tls13,
}
}

enum_from_primitive! {
/// Authentication methods
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TlsCipherAu {
    Null = 0,
    Psk,
    Krb5,
    Srp,
    Srp_Dss,
    Srp_Rsa,
    Dss,
    Rsa,
    Dhe,
    Ecdsa,
    Eccpwd,
    Tls13,
}
}

enum_from_primitive! {
/// Encryption methods
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TlsCipherEnc {
    Null,
    Des,
    TripleDes,
    Rc2,
    Rc4,
    Aria,
    Idea,
    Seed,
    Aes,
    Camellia,
    Chacha20_Poly1305,
    Sm4,
}
}

enum_from_primitive! {
/// Encryption modes
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TlsCipherEncMode {
    Null,
    Cbc,
    Ccm,
    Gcm,
}
}

enum_from_primitive! {
/// Message Authentication Code (MAC) methods
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TlsCipherMac {
    Null,
    HmacMd5,
    HmacSha1,
    HmacSha256,
    HmacSha384,
    Aead,
}
}

/// TLS Ciphersuite
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsCipherSuite {
    pub name: &'static str,
    pub id: u16,
    pub kx: TlsCipherKx,
    pub au: TlsCipherAu,
    pub enc: TlsCipherEnc,
    pub enc_mode: TlsCipherEncMode,
    pub enc_size: u16,
    pub mac: TlsCipherMac,
    pub mac_size: u16,
}

include!(concat!(env!("OUT_DIR"), "/codegen.rs"));

impl TlsCipherSuite {
    /// Attempt to get reference on `TlsCipherSuite` identified by `id`.
    pub fn from_id(id: u16) -> Option<&'static TlsCipherSuite> {
        CIPHERS.get(&id)
    }

    /// Attempt to get reference on `TlsCipherSuite` identified by `name`.
    pub fn from_name<'a>(name: &'a str) -> Option<&'static TlsCipherSuite> {
        CIPHERS.values().find(|&v| v.name == name)
    }
}

impl TryFrom<u16> for &'static TlsCipherSuite {
    type Error = CipherSuiteNotFound;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        CIPHERS.get(&value).ok_or(CipherSuiteNotFound(()))
    }
}

impl TryFrom<TlsCipherSuiteID> for &'static TlsCipherSuite {
    type Error = CipherSuiteNotFound;

    fn try_from(value: TlsCipherSuiteID) -> Result<Self, Self::Error> {
        CIPHERS.get(&value.0).ok_or(CipherSuiteNotFound(()))
    }
}

impl<'a> TryFrom<&'a str> for &'static TlsCipherSuite {
    type Error = CipherSuiteNotFound;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        CIPHERS
            .values()
            .find(|&v| v.name == value)
            .ok_or(CipherSuiteNotFound(()))
    }
}

#[cfg(test)]
mod tests {
    use crate::tls_ciphers::{TlsCipherKx, TlsCipherSuite, CIPHERS};
    use core::convert::TryFrom;

    #[test]
    fn test_cipher_count() {
        println!("loaded: {} cipher suites", CIPHERS.len());
        assert!(!CIPHERS.is_empty());
    }

    #[test]
    fn test_cipher_from_id() {
        let cipher = <&TlsCipherSuite>::try_from(0xc025).expect("could not get cipher");
        println!("Found cipher: {:?}", cipher);
    }

    #[test]
    fn test_cipher_from_name() {
        let cipher = <&TlsCipherSuite>::try_from("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384")
            .expect("could not get cipher");
        println!("Found cipher: {:?}", cipher);
    }

    #[test]
    fn test_cipher_filter() {
        let ecdhe_ciphers_count = CIPHERS
            .values()
            .filter(|c| c.kx == TlsCipherKx::Ecdhe)
            .count();
        assert!(ecdhe_ciphers_count > 20);
    }
}
