//!
//! The [CIPHERS](static.CIPHERS.html) static hash map is built during the
//! compilation of the crate, using `build.rs`. It parses a file derived from
//! the [IANA TLS Cipher Suite
//! Registry](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4)
//! to automatically extract parameters and add all known ciphersuites.

#![allow(non_camel_case_types)]
#![allow(clippy::unreadable_literal)]

use core::convert::TryFrom;
use num_enum::TryFromPrimitive;

use crate::TlsCipherSuiteID;

#[derive(Debug)]
pub struct CipherSuiteNotFound(());

/// Key exchange methods
#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
pub enum TlsCipherKx {
    Null,
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

/// Authentication methods
#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
pub enum TlsCipherAu {
    Null,
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

/// Encryption methods
#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive)]
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

/// Encryption modes
#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
pub enum TlsCipherEncMode {
    Null,
    Cbc,
    Ccm,
    Gcm,
}

/// Message Authentication Code (MAC) methods
#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
pub enum TlsCipherMac {
    Null,
    HmacMd5,
    HmacSha1,
    HmacSha256,
    HmacSha384,
    HmacSha512,
    Aead,
}

/// Pseudo-Random Function (PRF) Function
#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive)]
#[repr(u8)]
pub enum TlsPRF {
    Default,
    Null,
    Md5AndSha1,
    Sha1,
    Sha256,
    Sha384,
    Sha512,
    Sm3,
}

/// TLS Ciphersuite
///
/// A CipherSuite is a set of algorithm and parameters used to secure
/// a network connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsCipherSuite {
    /// The IANA name of this ciphersuite
    pub name: &'static str,
    /// The 16-bit identifier, provided by IANA, for this ciphersuite
    pub id: TlsCipherSuiteID,
    /// The Key Exchange method for this ciphersuite
    pub kx: TlsCipherKx,
    /// The Authentication method for this ciphersuite
    pub au: TlsCipherAu,
    /// Encryption cipher
    pub enc: TlsCipherEnc,
    /// Encryption mode
    pub enc_mode: TlsCipherEncMode,
    /// Key size of the encryption, in bits
    pub enc_size: u16,
    /// Message Authentication Code (MAC) algorithm
    pub mac: TlsCipherMac,
    /// Message Authentication Code (MAC) length
    pub mac_size: u16,
    /// Pseudo-Random Function, if specific
    pub prf: TlsPRF,
}

include!(concat!(env!("OUT_DIR"), "/codegen.rs"));

impl TlsCipherSuite {
    /// Attempt to get reference on `TlsCipherSuite` identified by `id`.
    pub fn from_id(id: u16) -> Option<&'static TlsCipherSuite> {
        CIPHERS.get(&id)
    }

    /// Attempt to get reference on `TlsCipherSuite` identified by `name`.
    pub fn from_name(name: &str) -> Option<&'static TlsCipherSuite> {
        CIPHERS.values().find(|&v| v.name == name)
    }

    /// Get the key of this ciphersuite encryption algorithm, in bytes
    pub const fn enc_key_size(&self) -> usize {
        (self.enc_size / 8) as usize
    }

    /// Get the block size of this ciphersuite encryption algorithm, in bytes
    pub const fn enc_block_size(&self) -> usize {
        match self.enc {
            TlsCipherEnc::Null => 0,
            TlsCipherEnc::Des
            | TlsCipherEnc::Idea
            | TlsCipherEnc::Rc2
            | TlsCipherEnc::TripleDes => 8,
            TlsCipherEnc::Aes
            | TlsCipherEnc::Aria
            | TlsCipherEnc::Camellia
            | TlsCipherEnc::Seed
            | TlsCipherEnc::Sm4 => 16,
            // stream ciphers
            TlsCipherEnc::Chacha20_Poly1305 | TlsCipherEnc::Rc4 => 0,
        }
    }

    /// Get the length of this ciphersuite MAC algorithm, in bytes
    pub const fn mac_length(&self) -> usize {
        match self.mac {
            TlsCipherMac::Null => 0,
            TlsCipherMac::Aead => 0,
            TlsCipherMac::HmacMd5 => 16,
            TlsCipherMac::HmacSha1 => 20,
            TlsCipherMac::HmacSha256 => 32,
            TlsCipherMac::HmacSha384 => 48,
            TlsCipherMac::HmacSha512 => 64,
        }
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
