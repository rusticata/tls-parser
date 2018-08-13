//!
//! The [CIPHERS](static.CIPHERS.html) static hash map is built during the
//! compilation of the crate, using `build.rs`. It parses a file derived from
//! the [IANA TLS Cipher Suite
//! Registry](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4)
//! to automatically extract parameters and add all known ciphersuites.

#![allow(non_camel_case_types)]

use phf;

enum_from_primitive! {
/// Key exchange methods
#[derive(Clone,Debug,PartialEq)]
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
    Eccpwd,
    Tls13,
}
}

enum_from_primitive! {
/// Authentication methods
#[derive(Clone,Debug,PartialEq)]
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
#[derive(Clone,Debug,PartialEq)]
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
}
}

enum_from_primitive! {
/// Encryption modes
#[derive(Clone,Debug,PartialEq)]
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
#[derive(Clone,Debug,PartialEq)]
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
#[derive(Debug)]
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
    pub fn from_id(id: u16) -> Option<&'static TlsCipherSuite> {
        CIPHERS.get(&id)
    }

    pub fn from_name<'a>(name: &'a str) -> Option<&'static TlsCipherSuite> {
        CIPHERS.values().find(|&v| v.name == name)
    }
}



#[cfg(test)]
mod tests {
    use tls_ciphers::{CIPHERS,TlsCipherSuite,TlsCipherKx};

#[test]
fn test_cipher_count() {
    println!("loaded: {} cipher suites", CIPHERS.len());
    assert!(CIPHERS.len() > 0);
}

#[test]
fn test_cipher_from_id() {
    match TlsCipherSuite::from_id(0xc025) {
        Some(ref cipher) => {
            println!("Found cipher: {:?}", cipher);
        },
        None => assert!(false),
    }
}

#[test]
fn test_cipher_from_name() {
    match TlsCipherSuite::from_name("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384") {
        Some(ref cipher) => {
            println!("Found cipher: {:?}", cipher);
        },
        None => assert!(false),
    }
}

#[test]
fn test_cipher_filter() {
    let ecdhe_ciphers : Vec<&TlsCipherSuite> = CIPHERS.values().filter(|c| { c.kx == TlsCipherKx::Ecdhe }).collect();
    assert!(ecdhe_ciphers.len() > 20);
}

}
