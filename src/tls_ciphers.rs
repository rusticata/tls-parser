#![allow(non_camel_case_types)]

use std::collections::HashMap;

#[derive(Debug)]
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
}

#[derive(Debug)]
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
}

#[derive(Debug)]
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

#[derive(Debug)]
pub enum TlsCipherEncMode {
    Null,
    Cbc,
    Ccm,
    Gcm,
}

#[derive(Debug)]
pub enum TlsCipherMac {
    Null,
    HmacMd5,
    HmacSha1,
    HmacSha256,
    HmacSha384,
    Aead,
}

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

impl TlsCipherSuite {
    pub fn from_id(id: u16) -> Option<&'static TlsCipherSuite> {
        HASHMAP.get(&id)
    }

    pub fn from_name<'a>(name: &'a str) -> Option<&'static TlsCipherSuite> {
        for (_,v) in HASHMAP.iter()
            .filter(|&(_, v)| v.name == name)
        {
            return Some(v);
        };
        None
    }
}

lazy_static! {
    static ref HASHMAP: HashMap<u16, TlsCipherSuite> = {
        let mut m = HashMap::new();
        // list extracted automatically from http://www.iana.org/assignments/tls-parameters/tls-parameters.xml

        m.insert(0x0000,TlsCipherSuite{ name:"TLS_NULL_WITH_NULL_NULL", id:0x0000, kx:TlsCipherKx::Null, au:TlsCipherAu::Null, enc:TlsCipherEnc::Null,  enc_mode:TlsCipherEncMode::Null, enc_size:0, mac:TlsCipherMac::Null, mac_size:0,});
        m.insert(0x0001,TlsCipherSuite{ name:"TLS_RSA_WITH_NULL_MD5", id:0x0001, kx:TlsCipherKx::Rsa, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Null,  enc_mode:TlsCipherEncMode::Null, enc_size:0, mac:TlsCipherMac::HmacMd5, mac_size:128,});
        m.insert(0x0002,TlsCipherSuite{ name:"TLS_RSA_WITH_NULL_SHA", id:0x0002, kx:TlsCipherKx::Rsa, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Null,  enc_mode:TlsCipherEncMode::Null, enc_size:0, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x0003,TlsCipherSuite{ name:"TLS_RSA_EXPORT_WITH_RC4_40_MD5", id:0x0003, kx:TlsCipherKx::Rsa, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Rc4,  enc_mode:TlsCipherEncMode::Null, enc_size:40, mac:TlsCipherMac::HmacMd5, mac_size:128,});
        m.insert(0x0004,TlsCipherSuite{ name:"TLS_RSA_WITH_RC4_128_MD5", id:0x0004, kx:TlsCipherKx::Rsa, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Rc4,  enc_mode:TlsCipherEncMode::Null, enc_size:128, mac:TlsCipherMac::HmacMd5, mac_size:128,});
        m.insert(0x0005,TlsCipherSuite{ name:"TLS_RSA_WITH_RC4_128_SHA", id:0x0005, kx:TlsCipherKx::Rsa, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Rc4,  enc_mode:TlsCipherEncMode::Null, enc_size:128, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x0006,TlsCipherSuite{ name:"TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5", id:0x0006, kx:TlsCipherKx::Rsa, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Rc2,  enc_mode:TlsCipherEncMode::Cbc, enc_size:40, mac:TlsCipherMac::HmacMd5, mac_size:128,});
        m.insert(0x0007,TlsCipherSuite{ name:"TLS_RSA_WITH_IDEA_CBC_SHA", id:0x0007, kx:TlsCipherKx::Rsa, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Idea,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x0008,TlsCipherSuite{ name:"TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", id:0x0008, kx:TlsCipherKx::Rsa, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Des,  enc_mode:TlsCipherEncMode::Cbc, enc_size:40, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x0009,TlsCipherSuite{ name:"TLS_RSA_WITH_DES_CBC_SHA", id:0x0009, kx:TlsCipherKx::Rsa, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Des,  enc_mode:TlsCipherEncMode::Cbc, enc_size:56, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x000a,TlsCipherSuite{ name:"TLS_RSA_WITH_3DES_EDE_CBC_SHA", id:0x000a, kx:TlsCipherKx::Rsa, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::TripleDes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:168, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x000b,TlsCipherSuite{ name:"TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA", id:0x000b, kx:TlsCipherKx::Dh, au:TlsCipherAu::Dss, enc:TlsCipherEnc::Des,  enc_mode:TlsCipherEncMode::Cbc, enc_size:40, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x000c,TlsCipherSuite{ name:"TLS_DH_DSS_WITH_DES_CBC_SHA", id:0x000c, kx:TlsCipherKx::Dh, au:TlsCipherAu::Dss, enc:TlsCipherEnc::Des,  enc_mode:TlsCipherEncMode::Cbc, enc_size:56, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x000d,TlsCipherSuite{ name:"TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA", id:0x000d, kx:TlsCipherKx::Dh, au:TlsCipherAu::Dss, enc:TlsCipherEnc::TripleDes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:168, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x000e,TlsCipherSuite{ name:"TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA", id:0x000e, kx:TlsCipherKx::Dh, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Des,  enc_mode:TlsCipherEncMode::Cbc, enc_size:40, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x000f,TlsCipherSuite{ name:"TLS_DH_RSA_WITH_DES_CBC_SHA", id:0x000f, kx:TlsCipherKx::Dh, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Des,  enc_mode:TlsCipherEncMode::Cbc, enc_size:56, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x0010,TlsCipherSuite{ name:"TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA", id:0x0010, kx:TlsCipherKx::Dh, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::TripleDes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:168, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x0011,TlsCipherSuite{ name:"TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA", id:0x0011, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Dss, enc:TlsCipherEnc::Des,  enc_mode:TlsCipherEncMode::Cbc, enc_size:40, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x0012,TlsCipherSuite{ name:"TLS_DHE_DSS_WITH_DES_CBC_SHA", id:0x0012, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Dss, enc:TlsCipherEnc::Des,  enc_mode:TlsCipherEncMode::Cbc, enc_size:56, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x0013,TlsCipherSuite{ name:"TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA", id:0x0013, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Dss, enc:TlsCipherEnc::TripleDes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:168, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x0014,TlsCipherSuite{ name:"TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA", id:0x0014, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Des,  enc_mode:TlsCipherEncMode::Cbc, enc_size:40, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x0015,TlsCipherSuite{ name:"TLS_DHE_RSA_WITH_DES_CBC_SHA", id:0x0015, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Des,  enc_mode:TlsCipherEncMode::Cbc, enc_size:56, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x0016,TlsCipherSuite{ name:"TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", id:0x0016, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::TripleDes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:168, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x0017,TlsCipherSuite{ name:"TLS_DH_anon_EXPORT_WITH_RC4_40_MD5", id:0x0017, kx:TlsCipherKx::Dh, au:TlsCipherAu::Null, enc:TlsCipherEnc::Rc4,  enc_mode:TlsCipherEncMode::Null, enc_size:40, mac:TlsCipherMac::HmacMd5, mac_size:128,});
        m.insert(0x0018,TlsCipherSuite{ name:"TLS_DH_anon_WITH_RC4_128_MD5", id:0x0018, kx:TlsCipherKx::Dh, au:TlsCipherAu::Null, enc:TlsCipherEnc::Rc4,  enc_mode:TlsCipherEncMode::Null, enc_size:128, mac:TlsCipherMac::HmacMd5, mac_size:128,});
        m.insert(0x0019,TlsCipherSuite{ name:"TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA", id:0x0019, kx:TlsCipherKx::Dh, au:TlsCipherAu::Null, enc:TlsCipherEnc::Des,  enc_mode:TlsCipherEncMode::Cbc, enc_size:40, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x001a,TlsCipherSuite{ name:"TLS_DH_anon_WITH_DES_CBC_SHA", id:0x001a, kx:TlsCipherKx::Dh, au:TlsCipherAu::Null, enc:TlsCipherEnc::Des,  enc_mode:TlsCipherEncMode::Cbc, enc_size:56, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x001b,TlsCipherSuite{ name:"TLS_DH_anon_WITH_3DES_EDE_CBC_SHA", id:0x001b, kx:TlsCipherKx::Dh, au:TlsCipherAu::Null, enc:TlsCipherEnc::TripleDes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:168, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x001e,TlsCipherSuite{ name:"TLS_KRB5_WITH_DES_CBC_SHA", id:0x001e, kx:TlsCipherKx::Krb5, au:TlsCipherAu::Krb5, enc:TlsCipherEnc::Des,  enc_mode:TlsCipherEncMode::Cbc, enc_size:56, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x001f,TlsCipherSuite{ name:"TLS_KRB5_WITH_3DES_EDE_CBC_SHA", id:0x001f, kx:TlsCipherKx::Krb5, au:TlsCipherAu::Krb5, enc:TlsCipherEnc::TripleDes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:168, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x0020,TlsCipherSuite{ name:"TLS_KRB5_WITH_RC4_128_SHA", id:0x0020, kx:TlsCipherKx::Krb5, au:TlsCipherAu::Krb5, enc:TlsCipherEnc::Rc4,  enc_mode:TlsCipherEncMode::Null, enc_size:128, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x0021,TlsCipherSuite{ name:"TLS_KRB5_WITH_IDEA_CBC_SHA", id:0x0021, kx:TlsCipherKx::Krb5, au:TlsCipherAu::Krb5, enc:TlsCipherEnc::Idea,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x0022,TlsCipherSuite{ name:"TLS_KRB5_WITH_DES_CBC_MD5", id:0x0022, kx:TlsCipherKx::Krb5, au:TlsCipherAu::Krb5, enc:TlsCipherEnc::Des,  enc_mode:TlsCipherEncMode::Cbc, enc_size:56, mac:TlsCipherMac::HmacMd5, mac_size:128,});
        m.insert(0x0023,TlsCipherSuite{ name:"TLS_KRB5_WITH_3DES_EDE_CBC_MD5", id:0x0023, kx:TlsCipherKx::Krb5, au:TlsCipherAu::Krb5, enc:TlsCipherEnc::TripleDes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:168, mac:TlsCipherMac::HmacMd5, mac_size:128,});
        m.insert(0x0024,TlsCipherSuite{ name:"TLS_KRB5_WITH_RC4_128_MD5", id:0x0024, kx:TlsCipherKx::Krb5, au:TlsCipherAu::Krb5, enc:TlsCipherEnc::Rc4,  enc_mode:TlsCipherEncMode::Null, enc_size:128, mac:TlsCipherMac::HmacMd5, mac_size:128,});
        m.insert(0x0025,TlsCipherSuite{ name:"TLS_KRB5_WITH_IDEA_CBC_MD5", id:0x0025, kx:TlsCipherKx::Krb5, au:TlsCipherAu::Krb5, enc:TlsCipherEnc::Idea,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacMd5, mac_size:128,});
        m.insert(0x0026,TlsCipherSuite{ name:"TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA", id:0x0026, kx:TlsCipherKx::Krb5, au:TlsCipherAu::Krb5, enc:TlsCipherEnc::Des,  enc_mode:TlsCipherEncMode::Cbc, enc_size:40, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x0027,TlsCipherSuite{ name:"TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA", id:0x0027, kx:TlsCipherKx::Krb5, au:TlsCipherAu::Krb5, enc:TlsCipherEnc::Rc2,  enc_mode:TlsCipherEncMode::Cbc, enc_size:40, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x0028,TlsCipherSuite{ name:"TLS_KRB5_EXPORT_WITH_RC4_40_SHA", id:0x0028, kx:TlsCipherKx::Krb5, au:TlsCipherAu::Krb5, enc:TlsCipherEnc::Rc4,  enc_mode:TlsCipherEncMode::Null, enc_size:40, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x0029,TlsCipherSuite{ name:"TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5", id:0x0029, kx:TlsCipherKx::Krb5, au:TlsCipherAu::Krb5, enc:TlsCipherEnc::Des,  enc_mode:TlsCipherEncMode::Cbc, enc_size:40, mac:TlsCipherMac::HmacMd5, mac_size:128,});
        m.insert(0x002a,TlsCipherSuite{ name:"TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5", id:0x002a, kx:TlsCipherKx::Krb5, au:TlsCipherAu::Krb5, enc:TlsCipherEnc::Rc2,  enc_mode:TlsCipherEncMode::Cbc, enc_size:40, mac:TlsCipherMac::HmacMd5, mac_size:128,});
        m.insert(0x002b,TlsCipherSuite{ name:"TLS_KRB5_EXPORT_WITH_RC4_40_MD5", id:0x002b, kx:TlsCipherKx::Krb5, au:TlsCipherAu::Krb5, enc:TlsCipherEnc::Rc4,  enc_mode:TlsCipherEncMode::Null, enc_size:40, mac:TlsCipherMac::HmacMd5, mac_size:128,});
        m.insert(0x002c,TlsCipherSuite{ name:"TLS_PSK_WITH_NULL_SHA", id:0x002c, kx:TlsCipherKx::Psk, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Null,  enc_mode:TlsCipherEncMode::Null, enc_size:0, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x002d,TlsCipherSuite{ name:"TLS_DHE_PSK_WITH_NULL_SHA", id:0x002d, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Null,  enc_mode:TlsCipherEncMode::Null, enc_size:0, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x002e,TlsCipherSuite{ name:"TLS_RSA_PSK_WITH_NULL_SHA", id:0x002e, kx:TlsCipherKx::Rsa, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Null,  enc_mode:TlsCipherEncMode::Null, enc_size:0, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x002f,TlsCipherSuite{ name:"TLS_RSA_WITH_AES_128_CBC_SHA", id:0x002f, kx:TlsCipherKx::Rsa, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x0030,TlsCipherSuite{ name:"TLS_DH_DSS_WITH_AES_128_CBC_SHA", id:0x0030, kx:TlsCipherKx::Dh, au:TlsCipherAu::Dss, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x0031,TlsCipherSuite{ name:"TLS_DH_RSA_WITH_AES_128_CBC_SHA", id:0x0031, kx:TlsCipherKx::Dh, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x0032,TlsCipherSuite{ name:"TLS_DHE_DSS_WITH_AES_128_CBC_SHA", id:0x0032, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Dss, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x0033,TlsCipherSuite{ name:"TLS_DHE_RSA_WITH_AES_128_CBC_SHA", id:0x0033, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x0034,TlsCipherSuite{ name:"TLS_DH_anon_WITH_AES_128_CBC_SHA", id:0x0034, kx:TlsCipherKx::Dh, au:TlsCipherAu::Null, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x0035,TlsCipherSuite{ name:"TLS_RSA_WITH_AES_256_CBC_SHA", id:0x0035, kx:TlsCipherKx::Rsa, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x0036,TlsCipherSuite{ name:"TLS_DH_DSS_WITH_AES_256_CBC_SHA", id:0x0036, kx:TlsCipherKx::Dh, au:TlsCipherAu::Dss, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x0037,TlsCipherSuite{ name:"TLS_DH_RSA_WITH_AES_256_CBC_SHA", id:0x0037, kx:TlsCipherKx::Dh, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x0038,TlsCipherSuite{ name:"TLS_DHE_DSS_WITH_AES_256_CBC_SHA", id:0x0038, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Dss, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x0039,TlsCipherSuite{ name:"TLS_DHE_RSA_WITH_AES_256_CBC_SHA", id:0x0039, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x003a,TlsCipherSuite{ name:"TLS_DH_anon_WITH_AES_256_CBC_SHA", id:0x003a, kx:TlsCipherKx::Dh, au:TlsCipherAu::Null, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x003b,TlsCipherSuite{ name:"TLS_RSA_WITH_NULL_SHA256", id:0x003b, kx:TlsCipherKx::Rsa, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Null,  enc_mode:TlsCipherEncMode::Null, enc_size:0, mac:TlsCipherMac::HmacSha256, mac_size:256,});
        m.insert(0x003c,TlsCipherSuite{ name:"TLS_RSA_WITH_AES_128_CBC_SHA256", id:0x003c, kx:TlsCipherKx::Rsa, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha256, mac_size:256,});
        m.insert(0x003d,TlsCipherSuite{ name:"TLS_RSA_WITH_AES_256_CBC_SHA256", id:0x003d, kx:TlsCipherKx::Rsa, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::HmacSha256, mac_size:256,});
        m.insert(0x003e,TlsCipherSuite{ name:"TLS_DH_DSS_WITH_AES_128_CBC_SHA256", id:0x003e, kx:TlsCipherKx::Dh, au:TlsCipherAu::Dss, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha256, mac_size:256,});
        m.insert(0x003f,TlsCipherSuite{ name:"TLS_DH_RSA_WITH_AES_128_CBC_SHA256", id:0x003f, kx:TlsCipherKx::Dh, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha256, mac_size:256,});
        m.insert(0x0040,TlsCipherSuite{ name:"TLS_DHE_DSS_WITH_AES_128_CBC_SHA256", id:0x0040, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Dss, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha256, mac_size:256,});
        m.insert(0x0041,TlsCipherSuite{ name:"TLS_RSA_WITH_CAMELLIA_128_CBC_SHA", id:0x0041, kx:TlsCipherKx::Rsa, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Camellia,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x0042,TlsCipherSuite{ name:"TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA", id:0x0042, kx:TlsCipherKx::Dh, au:TlsCipherAu::Dss, enc:TlsCipherEnc::Camellia,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x0043,TlsCipherSuite{ name:"TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA", id:0x0043, kx:TlsCipherKx::Dh, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Camellia,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x0044,TlsCipherSuite{ name:"TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA", id:0x0044, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Dss, enc:TlsCipherEnc::Camellia,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x0045,TlsCipherSuite{ name:"TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA", id:0x0045, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Camellia,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x0046,TlsCipherSuite{ name:"TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA", id:0x0046, kx:TlsCipherKx::Dh, au:TlsCipherAu::Null, enc:TlsCipherEnc::Camellia,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x0067,TlsCipherSuite{ name:"TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", id:0x0067, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha256, mac_size:256,});
        m.insert(0x0068,TlsCipherSuite{ name:"TLS_DH_DSS_WITH_AES_256_CBC_SHA256", id:0x0068, kx:TlsCipherKx::Dh, au:TlsCipherAu::Dss, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::HmacSha256, mac_size:256,});
        m.insert(0x0069,TlsCipherSuite{ name:"TLS_DH_RSA_WITH_AES_256_CBC_SHA256", id:0x0069, kx:TlsCipherKx::Dh, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::HmacSha256, mac_size:256,});
        m.insert(0x006a,TlsCipherSuite{ name:"TLS_DHE_DSS_WITH_AES_256_CBC_SHA256", id:0x006a, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Dss, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::HmacSha256, mac_size:256,});
        m.insert(0x006b,TlsCipherSuite{ name:"TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", id:0x006b, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::HmacSha256, mac_size:256,});
        m.insert(0x006c,TlsCipherSuite{ name:"TLS_DH_anon_WITH_AES_128_CBC_SHA256", id:0x006c, kx:TlsCipherKx::Dh, au:TlsCipherAu::Null, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha256, mac_size:256,});
        m.insert(0x006d,TlsCipherSuite{ name:"TLS_DH_anon_WITH_AES_256_CBC_SHA256", id:0x006d, kx:TlsCipherKx::Dh, au:TlsCipherAu::Null, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::HmacSha256, mac_size:256,});
        m.insert(0x0084,TlsCipherSuite{ name:"TLS_RSA_WITH_CAMELLIA_256_CBC_SHA", id:0x0084, kx:TlsCipherKx::Rsa, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Camellia,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x0085,TlsCipherSuite{ name:"TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA", id:0x0085, kx:TlsCipherKx::Dh, au:TlsCipherAu::Dss, enc:TlsCipherEnc::Camellia,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x0086,TlsCipherSuite{ name:"TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA", id:0x0086, kx:TlsCipherKx::Dh, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Camellia,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x0087,TlsCipherSuite{ name:"TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA", id:0x0087, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Dss, enc:TlsCipherEnc::Camellia,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x0088,TlsCipherSuite{ name:"TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA", id:0x0088, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Camellia,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x0089,TlsCipherSuite{ name:"TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA", id:0x0089, kx:TlsCipherKx::Dh, au:TlsCipherAu::Null, enc:TlsCipherEnc::Camellia,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x008a,TlsCipherSuite{ name:"TLS_PSK_WITH_RC4_128_SHA", id:0x008a, kx:TlsCipherKx::Psk, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Rc4,  enc_mode:TlsCipherEncMode::Null, enc_size:128, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x008b,TlsCipherSuite{ name:"TLS_PSK_WITH_3DES_EDE_CBC_SHA", id:0x008b, kx:TlsCipherKx::Psk, au:TlsCipherAu::Psk, enc:TlsCipherEnc::TripleDes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:168, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x008c,TlsCipherSuite{ name:"TLS_PSK_WITH_AES_128_CBC_SHA", id:0x008c, kx:TlsCipherKx::Psk, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x008d,TlsCipherSuite{ name:"TLS_PSK_WITH_AES_256_CBC_SHA", id:0x008d, kx:TlsCipherKx::Psk, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x008e,TlsCipherSuite{ name:"TLS_DHE_PSK_WITH_RC4_128_SHA", id:0x008e, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Rc4,  enc_mode:TlsCipherEncMode::Null, enc_size:128, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x008f,TlsCipherSuite{ name:"TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA", id:0x008f, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Psk, enc:TlsCipherEnc::TripleDes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:168, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x0090,TlsCipherSuite{ name:"TLS_DHE_PSK_WITH_AES_128_CBC_SHA", id:0x0090, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x0091,TlsCipherSuite{ name:"TLS_DHE_PSK_WITH_AES_256_CBC_SHA", id:0x0091, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x0092,TlsCipherSuite{ name:"TLS_RSA_PSK_WITH_RC4_128_SHA", id:0x0092, kx:TlsCipherKx::Rsa, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Rc4,  enc_mode:TlsCipherEncMode::Null, enc_size:128, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x0093,TlsCipherSuite{ name:"TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA", id:0x0093, kx:TlsCipherKx::Rsa, au:TlsCipherAu::Psk, enc:TlsCipherEnc::TripleDes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:168, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x0094,TlsCipherSuite{ name:"TLS_RSA_PSK_WITH_AES_128_CBC_SHA", id:0x0094, kx:TlsCipherKx::Rsa, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x0095,TlsCipherSuite{ name:"TLS_RSA_PSK_WITH_AES_256_CBC_SHA", id:0x0095, kx:TlsCipherKx::Rsa, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x0096,TlsCipherSuite{ name:"TLS_RSA_WITH_SEED_CBC_SHA", id:0x0096, kx:TlsCipherKx::Rsa, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Seed,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x0097,TlsCipherSuite{ name:"TLS_DH_DSS_WITH_SEED_CBC_SHA", id:0x0097, kx:TlsCipherKx::Dh, au:TlsCipherAu::Dss, enc:TlsCipherEnc::Seed,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x0098,TlsCipherSuite{ name:"TLS_DH_RSA_WITH_SEED_CBC_SHA", id:0x0098, kx:TlsCipherKx::Dh, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Seed,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x0099,TlsCipherSuite{ name:"TLS_DHE_DSS_WITH_SEED_CBC_SHA", id:0x0099, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Dss, enc:TlsCipherEnc::Seed,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x009a,TlsCipherSuite{ name:"TLS_DHE_RSA_WITH_SEED_CBC_SHA", id:0x009a, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Seed,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x009b,TlsCipherSuite{ name:"TLS_DH_anon_WITH_SEED_CBC_SHA", id:0x009b, kx:TlsCipherKx::Dh, au:TlsCipherAu::Null, enc:TlsCipherEnc::Seed,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0x009c,TlsCipherSuite{ name:"TLS_RSA_WITH_AES_128_GCM_SHA256", id:0x009c, kx:TlsCipherKx::Rsa, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Gcm, enc_size:128, mac:TlsCipherMac::Aead, mac_size:128,});
        m.insert(0x009d,TlsCipherSuite{ name:"TLS_RSA_WITH_AES_256_GCM_SHA384", id:0x009d, kx:TlsCipherKx::Rsa, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Gcm, enc_size:256, mac:TlsCipherMac::Aead, mac_size:256,});
        m.insert(0x009e,TlsCipherSuite{ name:"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", id:0x009e, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Gcm, enc_size:128, mac:TlsCipherMac::Aead, mac_size:128,});
        m.insert(0x009f,TlsCipherSuite{ name:"TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", id:0x009f, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Gcm, enc_size:256, mac:TlsCipherMac::Aead, mac_size:256,});
        m.insert(0x00a0,TlsCipherSuite{ name:"TLS_DH_RSA_WITH_AES_128_GCM_SHA256", id:0x00a0, kx:TlsCipherKx::Dh, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Gcm, enc_size:128, mac:TlsCipherMac::Aead, mac_size:128,});
        m.insert(0x00a1,TlsCipherSuite{ name:"TLS_DH_RSA_WITH_AES_256_GCM_SHA384", id:0x00a1, kx:TlsCipherKx::Dh, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Gcm, enc_size:256, mac:TlsCipherMac::Aead, mac_size:256,});
        m.insert(0x00a2,TlsCipherSuite{ name:"TLS_DHE_DSS_WITH_AES_128_GCM_SHA256", id:0x00a2, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Dss, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Gcm, enc_size:128, mac:TlsCipherMac::Aead, mac_size:128,});
        m.insert(0x00a3,TlsCipherSuite{ name:"TLS_DHE_DSS_WITH_AES_256_GCM_SHA384", id:0x00a3, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Dss, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Gcm, enc_size:256, mac:TlsCipherMac::Aead, mac_size:256,});
        m.insert(0x00a4,TlsCipherSuite{ name:"TLS_DH_DSS_WITH_AES_128_GCM_SHA256", id:0x00a4, kx:TlsCipherKx::Dh, au:TlsCipherAu::Dss, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Gcm, enc_size:128, mac:TlsCipherMac::Aead, mac_size:128,});
        m.insert(0x00a5,TlsCipherSuite{ name:"TLS_DH_DSS_WITH_AES_256_GCM_SHA384", id:0x00a5, kx:TlsCipherKx::Dh, au:TlsCipherAu::Dss, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Gcm, enc_size:256, mac:TlsCipherMac::Aead, mac_size:256,});
        m.insert(0x00a6,TlsCipherSuite{ name:"TLS_DH_anon_WITH_AES_128_GCM_SHA256", id:0x00a6, kx:TlsCipherKx::Dh, au:TlsCipherAu::Null, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Gcm, enc_size:128, mac:TlsCipherMac::Aead, mac_size:128,});
        m.insert(0x00a7,TlsCipherSuite{ name:"TLS_DH_anon_WITH_AES_256_GCM_SHA384", id:0x00a7, kx:TlsCipherKx::Dh, au:TlsCipherAu::Null, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Gcm, enc_size:256, mac:TlsCipherMac::Aead, mac_size:256,});
        m.insert(0x00a8,TlsCipherSuite{ name:"TLS_PSK_WITH_AES_128_GCM_SHA256", id:0x00a8, kx:TlsCipherKx::Psk, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Gcm, enc_size:128, mac:TlsCipherMac::Aead, mac_size:128,});
        m.insert(0x00a9,TlsCipherSuite{ name:"TLS_PSK_WITH_AES_256_GCM_SHA384", id:0x00a9, kx:TlsCipherKx::Psk, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Gcm, enc_size:256, mac:TlsCipherMac::Aead, mac_size:256,});
        m.insert(0x00aa,TlsCipherSuite{ name:"TLS_DHE_PSK_WITH_AES_128_GCM_SHA256", id:0x00aa, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Gcm, enc_size:128, mac:TlsCipherMac::Aead, mac_size:128,});
        m.insert(0x00ab,TlsCipherSuite{ name:"TLS_DHE_PSK_WITH_AES_256_GCM_SHA384", id:0x00ab, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Gcm, enc_size:256, mac:TlsCipherMac::Aead, mac_size:256,});
        m.insert(0x00ac,TlsCipherSuite{ name:"TLS_RSA_PSK_WITH_AES_128_GCM_SHA256", id:0x00ac, kx:TlsCipherKx::Rsa, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Gcm, enc_size:128, mac:TlsCipherMac::Aead, mac_size:128,});
        m.insert(0x00ad,TlsCipherSuite{ name:"TLS_RSA_PSK_WITH_AES_256_GCM_SHA384", id:0x00ad, kx:TlsCipherKx::Rsa, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Gcm, enc_size:256, mac:TlsCipherMac::Aead, mac_size:256,});
        m.insert(0x00ae,TlsCipherSuite{ name:"TLS_PSK_WITH_AES_128_CBC_SHA256", id:0x00ae, kx:TlsCipherKx::Psk, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha256, mac_size:256,});
        m.insert(0x00af,TlsCipherSuite{ name:"TLS_PSK_WITH_AES_256_CBC_SHA384", id:0x00af, kx:TlsCipherKx::Psk, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::HmacSha384, mac_size:384,});
        m.insert(0x00b0,TlsCipherSuite{ name:"TLS_PSK_WITH_NULL_SHA256", id:0x00b0, kx:TlsCipherKx::Psk, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Null,  enc_mode:TlsCipherEncMode::Null, enc_size:0, mac:TlsCipherMac::HmacSha256, mac_size:256,});
        m.insert(0x00b1,TlsCipherSuite{ name:"TLS_PSK_WITH_NULL_SHA384", id:0x00b1, kx:TlsCipherKx::Psk, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Null,  enc_mode:TlsCipherEncMode::Null, enc_size:0, mac:TlsCipherMac::HmacSha384, mac_size:384,});
        m.insert(0x00b2,TlsCipherSuite{ name:"TLS_DHE_PSK_WITH_AES_128_CBC_SHA256", id:0x00b2, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha256, mac_size:256,});
        m.insert(0x00b3,TlsCipherSuite{ name:"TLS_DHE_PSK_WITH_AES_256_CBC_SHA384", id:0x00b3, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::HmacSha384, mac_size:384,});
        m.insert(0x00b4,TlsCipherSuite{ name:"TLS_DHE_PSK_WITH_NULL_SHA256", id:0x00b4, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Null,  enc_mode:TlsCipherEncMode::Null, enc_size:0, mac:TlsCipherMac::HmacSha256, mac_size:256,});
        m.insert(0x00b5,TlsCipherSuite{ name:"TLS_DHE_PSK_WITH_NULL_SHA384", id:0x00b5, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Null,  enc_mode:TlsCipherEncMode::Null, enc_size:0, mac:TlsCipherMac::HmacSha384, mac_size:384,});
        m.insert(0x00b6,TlsCipherSuite{ name:"TLS_RSA_PSK_WITH_AES_128_CBC_SHA256", id:0x00b6, kx:TlsCipherKx::Rsa, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha256, mac_size:256,});
        m.insert(0x00b7,TlsCipherSuite{ name:"TLS_RSA_PSK_WITH_AES_256_CBC_SHA384", id:0x00b7, kx:TlsCipherKx::Rsa, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::HmacSha384, mac_size:384,});
        m.insert(0x00b8,TlsCipherSuite{ name:"TLS_RSA_PSK_WITH_NULL_SHA256", id:0x00b8, kx:TlsCipherKx::Rsa, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Null,  enc_mode:TlsCipherEncMode::Null, enc_size:0, mac:TlsCipherMac::HmacSha256, mac_size:256,});
        m.insert(0x00b9,TlsCipherSuite{ name:"TLS_RSA_PSK_WITH_NULL_SHA384", id:0x00b9, kx:TlsCipherKx::Rsa, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Null,  enc_mode:TlsCipherEncMode::Null, enc_size:0, mac:TlsCipherMac::HmacSha384, mac_size:384,});
        m.insert(0x00ba,TlsCipherSuite{ name:"TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256", id:0x00ba, kx:TlsCipherKx::Rsa, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Camellia,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha256, mac_size:256,});
        m.insert(0x00bb,TlsCipherSuite{ name:"TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256", id:0x00bb, kx:TlsCipherKx::Dh, au:TlsCipherAu::Dss, enc:TlsCipherEnc::Camellia,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha256, mac_size:256,});
        m.insert(0x00bc,TlsCipherSuite{ name:"TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256", id:0x00bc, kx:TlsCipherKx::Dh, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Camellia,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha256, mac_size:256,});
        m.insert(0x00bd,TlsCipherSuite{ name:"TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256", id:0x00bd, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Dss, enc:TlsCipherEnc::Camellia,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha256, mac_size:256,});
        m.insert(0x00be,TlsCipherSuite{ name:"TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256", id:0x00be, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Camellia,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha256, mac_size:256,});
        m.insert(0x00bf,TlsCipherSuite{ name:"TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256", id:0x00bf, kx:TlsCipherKx::Dh, au:TlsCipherAu::Null, enc:TlsCipherEnc::Camellia,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha256, mac_size:256,});
        m.insert(0x00c0,TlsCipherSuite{ name:"TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256", id:0x00c0, kx:TlsCipherKx::Rsa, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Camellia,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::HmacSha256, mac_size:256,});
        m.insert(0x00c1,TlsCipherSuite{ name:"TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256", id:0x00c1, kx:TlsCipherKx::Dh, au:TlsCipherAu::Dss, enc:TlsCipherEnc::Camellia,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::HmacSha256, mac_size:256,});
        m.insert(0x00c2,TlsCipherSuite{ name:"TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256", id:0x00c2, kx:TlsCipherKx::Dh, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Camellia,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::HmacSha256, mac_size:256,});
        m.insert(0x00c3,TlsCipherSuite{ name:"TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256", id:0x00c3, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Dss, enc:TlsCipherEnc::Camellia,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::HmacSha256, mac_size:256,});
        m.insert(0x00c4,TlsCipherSuite{ name:"TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256", id:0x00c4, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Camellia,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::HmacSha256, mac_size:256,});
        m.insert(0x00c5,TlsCipherSuite{ name:"TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256", id:0x00c5, kx:TlsCipherKx::Dh, au:TlsCipherAu::Null, enc:TlsCipherEnc::Camellia,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::HmacSha256, mac_size:256,});
        m.insert(0xc001,TlsCipherSuite{ name:"TLS_ECDH_ECDSA_WITH_NULL_SHA", id:0xc001, kx:TlsCipherKx::Ecdh, au:TlsCipherAu::Ecdsa, enc:TlsCipherEnc::Null,  enc_mode:TlsCipherEncMode::Null, enc_size:0, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0xc002,TlsCipherSuite{ name:"TLS_ECDH_ECDSA_WITH_RC4_128_SHA", id:0xc002, kx:TlsCipherKx::Ecdh, au:TlsCipherAu::Ecdsa, enc:TlsCipherEnc::Rc4,  enc_mode:TlsCipherEncMode::Null, enc_size:128, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0xc003,TlsCipherSuite{ name:"TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA", id:0xc003, kx:TlsCipherKx::Ecdh, au:TlsCipherAu::Ecdsa, enc:TlsCipherEnc::TripleDes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:168, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0xc004,TlsCipherSuite{ name:"TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA", id:0xc004, kx:TlsCipherKx::Ecdh, au:TlsCipherAu::Ecdsa, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0xc005,TlsCipherSuite{ name:"TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA", id:0xc005, kx:TlsCipherKx::Ecdh, au:TlsCipherAu::Ecdsa, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0xc006,TlsCipherSuite{ name:"TLS_ECDHE_ECDSA_WITH_NULL_SHA", id:0xc006, kx:TlsCipherKx::Ecdhe, au:TlsCipherAu::Ecdsa, enc:TlsCipherEnc::Null,  enc_mode:TlsCipherEncMode::Null, enc_size:0, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0xc007,TlsCipherSuite{ name:"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", id:0xc007, kx:TlsCipherKx::Ecdhe, au:TlsCipherAu::Ecdsa, enc:TlsCipherEnc::Rc4,  enc_mode:TlsCipherEncMode::Null, enc_size:128, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0xc008,TlsCipherSuite{ name:"TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA", id:0xc008, kx:TlsCipherKx::Ecdhe, au:TlsCipherAu::Ecdsa, enc:TlsCipherEnc::TripleDes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:168, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0xc009,TlsCipherSuite{ name:"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", id:0xc009, kx:TlsCipherKx::Ecdhe, au:TlsCipherAu::Ecdsa, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0xc00a,TlsCipherSuite{ name:"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", id:0xc00a, kx:TlsCipherKx::Ecdhe, au:TlsCipherAu::Ecdsa, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0xc00b,TlsCipherSuite{ name:"TLS_ECDH_RSA_WITH_NULL_SHA", id:0xc00b, kx:TlsCipherKx::Ecdh, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Null,  enc_mode:TlsCipherEncMode::Null, enc_size:0, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0xc00c,TlsCipherSuite{ name:"TLS_ECDH_RSA_WITH_RC4_128_SHA", id:0xc00c, kx:TlsCipherKx::Ecdh, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Rc4,  enc_mode:TlsCipherEncMode::Null, enc_size:128, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0xc00d,TlsCipherSuite{ name:"TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA", id:0xc00d, kx:TlsCipherKx::Ecdh, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::TripleDes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:168, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0xc00e,TlsCipherSuite{ name:"TLS_ECDH_RSA_WITH_AES_128_CBC_SHA", id:0xc00e, kx:TlsCipherKx::Ecdh, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0xc00f,TlsCipherSuite{ name:"TLS_ECDH_RSA_WITH_AES_256_CBC_SHA", id:0xc00f, kx:TlsCipherKx::Ecdh, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0xc010,TlsCipherSuite{ name:"TLS_ECDHE_RSA_WITH_NULL_SHA", id:0xc010, kx:TlsCipherKx::Ecdhe, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Null,  enc_mode:TlsCipherEncMode::Null, enc_size:0, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0xc011,TlsCipherSuite{ name:"TLS_ECDHE_RSA_WITH_RC4_128_SHA", id:0xc011, kx:TlsCipherKx::Ecdhe, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Rc4,  enc_mode:TlsCipherEncMode::Null, enc_size:128, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0xc012,TlsCipherSuite{ name:"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", id:0xc012, kx:TlsCipherKx::Ecdhe, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::TripleDes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:168, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0xc013,TlsCipherSuite{ name:"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", id:0xc013, kx:TlsCipherKx::Ecdhe, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0xc014,TlsCipherSuite{ name:"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", id:0xc014, kx:TlsCipherKx::Ecdhe, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0xc015,TlsCipherSuite{ name:"TLS_ECDH_anon_WITH_NULL_SHA", id:0xc015, kx:TlsCipherKx::Ecdh, au:TlsCipherAu::Null, enc:TlsCipherEnc::Null,  enc_mode:TlsCipherEncMode::Null, enc_size:0, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0xc016,TlsCipherSuite{ name:"TLS_ECDH_anon_WITH_RC4_128_SHA", id:0xc016, kx:TlsCipherKx::Ecdh, au:TlsCipherAu::Null, enc:TlsCipherEnc::Rc4,  enc_mode:TlsCipherEncMode::Null, enc_size:128, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0xc017,TlsCipherSuite{ name:"TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA", id:0xc017, kx:TlsCipherKx::Ecdh, au:TlsCipherAu::Null, enc:TlsCipherEnc::TripleDes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:168, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0xc018,TlsCipherSuite{ name:"TLS_ECDH_anon_WITH_AES_128_CBC_SHA", id:0xc018, kx:TlsCipherKx::Ecdh, au:TlsCipherAu::Null, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0xc019,TlsCipherSuite{ name:"TLS_ECDH_anon_WITH_AES_256_CBC_SHA", id:0xc019, kx:TlsCipherKx::Ecdh, au:TlsCipherAu::Null, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0xc01a,TlsCipherSuite{ name:"TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA", id:0xc01a, kx:TlsCipherKx::Srp, au:TlsCipherAu::Srp, enc:TlsCipherEnc::TripleDes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:168, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0xc01b,TlsCipherSuite{ name:"TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA", id:0xc01b, kx:TlsCipherKx::Srp, au:TlsCipherAu::Srp_Rsa, enc:TlsCipherEnc::TripleDes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:168, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0xc01c,TlsCipherSuite{ name:"TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA", id:0xc01c, kx:TlsCipherKx::Srp, au:TlsCipherAu::Srp_Dss, enc:TlsCipherEnc::TripleDes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:168, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0xc01d,TlsCipherSuite{ name:"TLS_SRP_SHA_WITH_AES_128_CBC_SHA", id:0xc01d, kx:TlsCipherKx::Srp, au:TlsCipherAu::Srp, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0xc01e,TlsCipherSuite{ name:"TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA", id:0xc01e, kx:TlsCipherKx::Srp, au:TlsCipherAu::Srp_Rsa, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0xc01f,TlsCipherSuite{ name:"TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA", id:0xc01f, kx:TlsCipherKx::Srp, au:TlsCipherAu::Srp_Dss, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0xc020,TlsCipherSuite{ name:"TLS_SRP_SHA_WITH_AES_256_CBC_SHA", id:0xc020, kx:TlsCipherKx::Srp, au:TlsCipherAu::Srp, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0xc021,TlsCipherSuite{ name:"TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA", id:0xc021, kx:TlsCipherKx::Srp, au:TlsCipherAu::Srp_Rsa, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0xc022,TlsCipherSuite{ name:"TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA", id:0xc022, kx:TlsCipherKx::Srp, au:TlsCipherAu::Srp_Dss, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0xc023,TlsCipherSuite{ name:"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", id:0xc023, kx:TlsCipherKx::Ecdhe, au:TlsCipherAu::Ecdsa, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha256, mac_size:256,});
        m.insert(0xc024,TlsCipherSuite{ name:"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", id:0xc024, kx:TlsCipherKx::Ecdhe, au:TlsCipherAu::Ecdsa, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::HmacSha384, mac_size:384,});
        m.insert(0xc025,TlsCipherSuite{ name:"TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256", id:0xc025, kx:TlsCipherKx::Ecdh, au:TlsCipherAu::Ecdsa, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha256, mac_size:256,});
        m.insert(0xc026,TlsCipherSuite{ name:"TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384", id:0xc026, kx:TlsCipherKx::Ecdh, au:TlsCipherAu::Ecdsa, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::HmacSha384, mac_size:384,});
        m.insert(0xc027,TlsCipherSuite{ name:"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", id:0xc027, kx:TlsCipherKx::Ecdhe, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha256, mac_size:256,});
        m.insert(0xc028,TlsCipherSuite{ name:"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", id:0xc028, kx:TlsCipherKx::Ecdhe, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::HmacSha384, mac_size:384,});
        m.insert(0xc029,TlsCipherSuite{ name:"TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256", id:0xc029, kx:TlsCipherKx::Ecdh, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha256, mac_size:256,});
        m.insert(0xc02a,TlsCipherSuite{ name:"TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384", id:0xc02a, kx:TlsCipherKx::Ecdh, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::HmacSha384, mac_size:384,});
        m.insert(0xc02b,TlsCipherSuite{ name:"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", id:0xc02b, kx:TlsCipherKx::Ecdhe, au:TlsCipherAu::Ecdsa, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Gcm, enc_size:128, mac:TlsCipherMac::Aead, mac_size:128,});
        m.insert(0xc02c,TlsCipherSuite{ name:"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", id:0xc02c, kx:TlsCipherKx::Ecdhe, au:TlsCipherAu::Ecdsa, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Gcm, enc_size:256, mac:TlsCipherMac::Aead, mac_size:256,});
        m.insert(0xc02d,TlsCipherSuite{ name:"TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256", id:0xc02d, kx:TlsCipherKx::Ecdh, au:TlsCipherAu::Ecdsa, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Gcm, enc_size:128, mac:TlsCipherMac::Aead, mac_size:128,});
        m.insert(0xc02e,TlsCipherSuite{ name:"TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384", id:0xc02e, kx:TlsCipherKx::Ecdh, au:TlsCipherAu::Ecdsa, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Gcm, enc_size:256, mac:TlsCipherMac::Aead, mac_size:256,});
        m.insert(0xc02f,TlsCipherSuite{ name:"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", id:0xc02f, kx:TlsCipherKx::Ecdhe, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Gcm, enc_size:128, mac:TlsCipherMac::Aead, mac_size:128,});
        m.insert(0xc030,TlsCipherSuite{ name:"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", id:0xc030, kx:TlsCipherKx::Ecdhe, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Gcm, enc_size:256, mac:TlsCipherMac::Aead, mac_size:256,});
        m.insert(0xc031,TlsCipherSuite{ name:"TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256", id:0xc031, kx:TlsCipherKx::Ecdh, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Gcm, enc_size:128, mac:TlsCipherMac::Aead, mac_size:128,});
        m.insert(0xc032,TlsCipherSuite{ name:"TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384", id:0xc032, kx:TlsCipherKx::Ecdh, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Gcm, enc_size:256, mac:TlsCipherMac::Aead, mac_size:256,});
        m.insert(0xc033,TlsCipherSuite{ name:"TLS_ECDHE_PSK_WITH_RC4_128_SHA", id:0xc033, kx:TlsCipherKx::Ecdhe, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Rc4,  enc_mode:TlsCipherEncMode::Null, enc_size:128, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0xc034,TlsCipherSuite{ name:"TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA", id:0xc034, kx:TlsCipherKx::Ecdhe, au:TlsCipherAu::Psk, enc:TlsCipherEnc::TripleDes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:168, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0xc035,TlsCipherSuite{ name:"TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA", id:0xc035, kx:TlsCipherKx::Ecdhe, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0xc036,TlsCipherSuite{ name:"TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA", id:0xc036, kx:TlsCipherKx::Ecdhe, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0xc037,TlsCipherSuite{ name:"TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256", id:0xc037, kx:TlsCipherKx::Ecdhe, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha256, mac_size:256,});
        m.insert(0xc038,TlsCipherSuite{ name:"TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384", id:0xc038, kx:TlsCipherKx::Ecdhe, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::HmacSha384, mac_size:384,});
        m.insert(0xc039,TlsCipherSuite{ name:"TLS_ECDHE_PSK_WITH_NULL_SHA", id:0xc039, kx:TlsCipherKx::Ecdhe, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Null,  enc_mode:TlsCipherEncMode::Null, enc_size:0, mac:TlsCipherMac::HmacSha1, mac_size:160,});
        m.insert(0xc03a,TlsCipherSuite{ name:"TLS_ECDHE_PSK_WITH_NULL_SHA256", id:0xc03a, kx:TlsCipherKx::Ecdhe, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Null,  enc_mode:TlsCipherEncMode::Null, enc_size:0, mac:TlsCipherMac::HmacSha256, mac_size:256,});
        m.insert(0xc03b,TlsCipherSuite{ name:"TLS_ECDHE_PSK_WITH_NULL_SHA384", id:0xc03b, kx:TlsCipherKx::Ecdhe, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Null,  enc_mode:TlsCipherEncMode::Null, enc_size:0, mac:TlsCipherMac::HmacSha384, mac_size:384,});
        m.insert(0xc03c,TlsCipherSuite{ name:"TLS_RSA_WITH_ARIA_128_CBC_SHA256", id:0xc03c, kx:TlsCipherKx::Rsa, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Aria,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha256, mac_size:256,});
        m.insert(0xc03d,TlsCipherSuite{ name:"TLS_RSA_WITH_ARIA_256_CBC_SHA384", id:0xc03d, kx:TlsCipherKx::Rsa, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Aria,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::HmacSha384, mac_size:384,});
        m.insert(0xc03e,TlsCipherSuite{ name:"TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256", id:0xc03e, kx:TlsCipherKx::Dh, au:TlsCipherAu::Dss, enc:TlsCipherEnc::Aria,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha256, mac_size:256,});
        m.insert(0xc03f,TlsCipherSuite{ name:"TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384", id:0xc03f, kx:TlsCipherKx::Dh, au:TlsCipherAu::Dss, enc:TlsCipherEnc::Aria,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::HmacSha384, mac_size:384,});
        m.insert(0xc040,TlsCipherSuite{ name:"TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256", id:0xc040, kx:TlsCipherKx::Dh, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Aria,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha256, mac_size:256,});
        m.insert(0xc041,TlsCipherSuite{ name:"TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384", id:0xc041, kx:TlsCipherKx::Dh, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Aria,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::HmacSha384, mac_size:384,});
        m.insert(0xc042,TlsCipherSuite{ name:"TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256", id:0xc042, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Dss, enc:TlsCipherEnc::Aria,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha256, mac_size:256,});
        m.insert(0xc043,TlsCipherSuite{ name:"TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384", id:0xc043, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Dss, enc:TlsCipherEnc::Aria,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::HmacSha384, mac_size:384,});
        m.insert(0xc044,TlsCipherSuite{ name:"TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256", id:0xc044, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Aria,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha256, mac_size:256,});
        m.insert(0xc045,TlsCipherSuite{ name:"TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384", id:0xc045, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Aria,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::HmacSha384, mac_size:384,});
        m.insert(0xc046,TlsCipherSuite{ name:"TLS_DH_anon_WITH_ARIA_128_CBC_SHA256", id:0xc046, kx:TlsCipherKx::Dh, au:TlsCipherAu::Null, enc:TlsCipherEnc::Aria,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha256, mac_size:256,});
        m.insert(0xc047,TlsCipherSuite{ name:"TLS_DH_anon_WITH_ARIA_256_CBC_SHA384", id:0xc047, kx:TlsCipherKx::Dh, au:TlsCipherAu::Null, enc:TlsCipherEnc::Aria,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::HmacSha384, mac_size:384,});
        m.insert(0xc048,TlsCipherSuite{ name:"TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256", id:0xc048, kx:TlsCipherKx::Ecdhe, au:TlsCipherAu::Ecdsa, enc:TlsCipherEnc::Aria,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha256, mac_size:256,});
        m.insert(0xc049,TlsCipherSuite{ name:"TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384", id:0xc049, kx:TlsCipherKx::Ecdhe, au:TlsCipherAu::Ecdsa, enc:TlsCipherEnc::Aria,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::HmacSha384, mac_size:384,});
        m.insert(0xc04a,TlsCipherSuite{ name:"TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256", id:0xc04a, kx:TlsCipherKx::Ecdh, au:TlsCipherAu::Ecdsa, enc:TlsCipherEnc::Aria,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha256, mac_size:256,});
        m.insert(0xc04b,TlsCipherSuite{ name:"TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384", id:0xc04b, kx:TlsCipherKx::Ecdh, au:TlsCipherAu::Ecdsa, enc:TlsCipherEnc::Aria,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::HmacSha384, mac_size:384,});
        m.insert(0xc04c,TlsCipherSuite{ name:"TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256", id:0xc04c, kx:TlsCipherKx::Ecdhe, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Aria,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha256, mac_size:256,});
        m.insert(0xc04d,TlsCipherSuite{ name:"TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384", id:0xc04d, kx:TlsCipherKx::Ecdhe, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Aria,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::HmacSha384, mac_size:384,});
        m.insert(0xc04e,TlsCipherSuite{ name:"TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256", id:0xc04e, kx:TlsCipherKx::Ecdh, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Aria,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha256, mac_size:256,});
        m.insert(0xc04f,TlsCipherSuite{ name:"TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384", id:0xc04f, kx:TlsCipherKx::Ecdh, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Aria,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::HmacSha384, mac_size:384,});
        m.insert(0xc050,TlsCipherSuite{ name:"TLS_RSA_WITH_ARIA_128_GCM_SHA256", id:0xc050, kx:TlsCipherKx::Rsa, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Aria,  enc_mode:TlsCipherEncMode::Gcm, enc_size:128, mac:TlsCipherMac::Aead, mac_size:128,});
        m.insert(0xc051,TlsCipherSuite{ name:"TLS_RSA_WITH_ARIA_256_GCM_SHA384", id:0xc051, kx:TlsCipherKx::Rsa, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Aria,  enc_mode:TlsCipherEncMode::Gcm, enc_size:256, mac:TlsCipherMac::Aead, mac_size:256,});
        m.insert(0xc052,TlsCipherSuite{ name:"TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256", id:0xc052, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Aria,  enc_mode:TlsCipherEncMode::Gcm, enc_size:128, mac:TlsCipherMac::Aead, mac_size:128,});
        m.insert(0xc053,TlsCipherSuite{ name:"TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384", id:0xc053, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Aria,  enc_mode:TlsCipherEncMode::Gcm, enc_size:256, mac:TlsCipherMac::Aead, mac_size:256,});
        m.insert(0xc054,TlsCipherSuite{ name:"TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256", id:0xc054, kx:TlsCipherKx::Dh, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Aria,  enc_mode:TlsCipherEncMode::Gcm, enc_size:128, mac:TlsCipherMac::Aead, mac_size:128,});
        m.insert(0xc055,TlsCipherSuite{ name:"TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384", id:0xc055, kx:TlsCipherKx::Dh, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Aria,  enc_mode:TlsCipherEncMode::Gcm, enc_size:256, mac:TlsCipherMac::Aead, mac_size:256,});
        m.insert(0xc056,TlsCipherSuite{ name:"TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256", id:0xc056, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Dss, enc:TlsCipherEnc::Aria,  enc_mode:TlsCipherEncMode::Gcm, enc_size:128, mac:TlsCipherMac::Aead, mac_size:128,});
        m.insert(0xc057,TlsCipherSuite{ name:"TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384", id:0xc057, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Dss, enc:TlsCipherEnc::Aria,  enc_mode:TlsCipherEncMode::Gcm, enc_size:256, mac:TlsCipherMac::Aead, mac_size:256,});
        m.insert(0xc058,TlsCipherSuite{ name:"TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256", id:0xc058, kx:TlsCipherKx::Dh, au:TlsCipherAu::Dss, enc:TlsCipherEnc::Aria,  enc_mode:TlsCipherEncMode::Gcm, enc_size:128, mac:TlsCipherMac::Aead, mac_size:128,});
        m.insert(0xc059,TlsCipherSuite{ name:"TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384", id:0xc059, kx:TlsCipherKx::Dh, au:TlsCipherAu::Dss, enc:TlsCipherEnc::Aria,  enc_mode:TlsCipherEncMode::Gcm, enc_size:256, mac:TlsCipherMac::Aead, mac_size:256,});
        m.insert(0xc05a,TlsCipherSuite{ name:"TLS_DH_anon_WITH_ARIA_128_GCM_SHA256", id:0xc05a, kx:TlsCipherKx::Dh, au:TlsCipherAu::Null, enc:TlsCipherEnc::Aria,  enc_mode:TlsCipherEncMode::Gcm, enc_size:128, mac:TlsCipherMac::Aead, mac_size:128,});
        m.insert(0xc05b,TlsCipherSuite{ name:"TLS_DH_anon_WITH_ARIA_256_GCM_SHA384", id:0xc05b, kx:TlsCipherKx::Dh, au:TlsCipherAu::Null, enc:TlsCipherEnc::Aria,  enc_mode:TlsCipherEncMode::Gcm, enc_size:256, mac:TlsCipherMac::Aead, mac_size:256,});
        m.insert(0xc05c,TlsCipherSuite{ name:"TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256", id:0xc05c, kx:TlsCipherKx::Ecdhe, au:TlsCipherAu::Ecdsa, enc:TlsCipherEnc::Aria,  enc_mode:TlsCipherEncMode::Gcm, enc_size:128, mac:TlsCipherMac::Aead, mac_size:128,});
        m.insert(0xc05d,TlsCipherSuite{ name:"TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384", id:0xc05d, kx:TlsCipherKx::Ecdhe, au:TlsCipherAu::Ecdsa, enc:TlsCipherEnc::Aria,  enc_mode:TlsCipherEncMode::Gcm, enc_size:256, mac:TlsCipherMac::Aead, mac_size:256,});
        m.insert(0xc05e,TlsCipherSuite{ name:"TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256", id:0xc05e, kx:TlsCipherKx::Ecdh, au:TlsCipherAu::Ecdsa, enc:TlsCipherEnc::Aria,  enc_mode:TlsCipherEncMode::Gcm, enc_size:128, mac:TlsCipherMac::Aead, mac_size:128,});
        m.insert(0xc05f,TlsCipherSuite{ name:"TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384", id:0xc05f, kx:TlsCipherKx::Ecdh, au:TlsCipherAu::Ecdsa, enc:TlsCipherEnc::Aria,  enc_mode:TlsCipherEncMode::Gcm, enc_size:256, mac:TlsCipherMac::Aead, mac_size:256,});
        m.insert(0xc060,TlsCipherSuite{ name:"TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256", id:0xc060, kx:TlsCipherKx::Ecdhe, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Aria,  enc_mode:TlsCipherEncMode::Gcm, enc_size:128, mac:TlsCipherMac::Aead, mac_size:128,});
        m.insert(0xc061,TlsCipherSuite{ name:"TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384", id:0xc061, kx:TlsCipherKx::Ecdhe, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Aria,  enc_mode:TlsCipherEncMode::Gcm, enc_size:256, mac:TlsCipherMac::Aead, mac_size:256,});
        m.insert(0xc062,TlsCipherSuite{ name:"TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256", id:0xc062, kx:TlsCipherKx::Ecdh, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Aria,  enc_mode:TlsCipherEncMode::Gcm, enc_size:128, mac:TlsCipherMac::Aead, mac_size:128,});
        m.insert(0xc063,TlsCipherSuite{ name:"TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384", id:0xc063, kx:TlsCipherKx::Ecdh, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Aria,  enc_mode:TlsCipherEncMode::Gcm, enc_size:256, mac:TlsCipherMac::Aead, mac_size:256,});
        m.insert(0xc064,TlsCipherSuite{ name:"TLS_PSK_WITH_ARIA_128_CBC_SHA256", id:0xc064, kx:TlsCipherKx::Psk, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Aria,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha256, mac_size:256,});
        m.insert(0xc065,TlsCipherSuite{ name:"TLS_PSK_WITH_ARIA_256_CBC_SHA384", id:0xc065, kx:TlsCipherKx::Psk, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Aria,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::HmacSha384, mac_size:384,});
        m.insert(0xc066,TlsCipherSuite{ name:"TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256", id:0xc066, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Aria,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha256, mac_size:256,});
        m.insert(0xc067,TlsCipherSuite{ name:"TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384", id:0xc067, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Aria,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::HmacSha384, mac_size:384,});
        m.insert(0xc068,TlsCipherSuite{ name:"TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256", id:0xc068, kx:TlsCipherKx::Rsa, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Aria,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha256, mac_size:256,});
        m.insert(0xc069,TlsCipherSuite{ name:"TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384", id:0xc069, kx:TlsCipherKx::Rsa, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Aria,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::HmacSha384, mac_size:384,});
        m.insert(0xc06a,TlsCipherSuite{ name:"TLS_PSK_WITH_ARIA_128_GCM_SHA256", id:0xc06a, kx:TlsCipherKx::Psk, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Aria,  enc_mode:TlsCipherEncMode::Gcm, enc_size:128, mac:TlsCipherMac::Aead, mac_size:128,});
        m.insert(0xc06b,TlsCipherSuite{ name:"TLS_PSK_WITH_ARIA_256_GCM_SHA384", id:0xc06b, kx:TlsCipherKx::Psk, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Aria,  enc_mode:TlsCipherEncMode::Gcm, enc_size:256, mac:TlsCipherMac::Aead, mac_size:256,});
        m.insert(0xc06c,TlsCipherSuite{ name:"TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256", id:0xc06c, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Aria,  enc_mode:TlsCipherEncMode::Gcm, enc_size:128, mac:TlsCipherMac::Aead, mac_size:128,});
        m.insert(0xc06d,TlsCipherSuite{ name:"TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384", id:0xc06d, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Aria,  enc_mode:TlsCipherEncMode::Gcm, enc_size:256, mac:TlsCipherMac::Aead, mac_size:256,});
        m.insert(0xc06e,TlsCipherSuite{ name:"TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256", id:0xc06e, kx:TlsCipherKx::Rsa, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Aria,  enc_mode:TlsCipherEncMode::Gcm, enc_size:128, mac:TlsCipherMac::Aead, mac_size:128,});
        m.insert(0xc06f,TlsCipherSuite{ name:"TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384", id:0xc06f, kx:TlsCipherKx::Rsa, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Aria,  enc_mode:TlsCipherEncMode::Gcm, enc_size:256, mac:TlsCipherMac::Aead, mac_size:256,});
        m.insert(0xc070,TlsCipherSuite{ name:"TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256", id:0xc070, kx:TlsCipherKx::Ecdhe, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Aria,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha256, mac_size:256,});
        m.insert(0xc071,TlsCipherSuite{ name:"TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384", id:0xc071, kx:TlsCipherKx::Ecdhe, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Aria,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::HmacSha384, mac_size:384,});
        m.insert(0xc072,TlsCipherSuite{ name:"TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256", id:0xc072, kx:TlsCipherKx::Ecdhe, au:TlsCipherAu::Ecdsa, enc:TlsCipherEnc::Camellia,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha256, mac_size:256,});
        m.insert(0xc073,TlsCipherSuite{ name:"TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384", id:0xc073, kx:TlsCipherKx::Ecdhe, au:TlsCipherAu::Ecdsa, enc:TlsCipherEnc::Camellia,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::HmacSha384, mac_size:384,});
        m.insert(0xc074,TlsCipherSuite{ name:"TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256", id:0xc074, kx:TlsCipherKx::Ecdh, au:TlsCipherAu::Ecdsa, enc:TlsCipherEnc::Camellia,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha256, mac_size:256,});
        m.insert(0xc075,TlsCipherSuite{ name:"TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384", id:0xc075, kx:TlsCipherKx::Ecdh, au:TlsCipherAu::Ecdsa, enc:TlsCipherEnc::Camellia,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::HmacSha384, mac_size:384,});
        m.insert(0xc076,TlsCipherSuite{ name:"TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256", id:0xc076, kx:TlsCipherKx::Ecdhe, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Camellia,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha256, mac_size:256,});
        m.insert(0xc077,TlsCipherSuite{ name:"TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384", id:0xc077, kx:TlsCipherKx::Ecdhe, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Camellia,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::HmacSha384, mac_size:384,});
        m.insert(0xc078,TlsCipherSuite{ name:"TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256", id:0xc078, kx:TlsCipherKx::Ecdh, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Camellia,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha256, mac_size:256,});
        m.insert(0xc079,TlsCipherSuite{ name:"TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384", id:0xc079, kx:TlsCipherKx::Ecdh, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Camellia,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::HmacSha384, mac_size:384,});
        m.insert(0xc07a,TlsCipherSuite{ name:"TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256", id:0xc07a, kx:TlsCipherKx::Rsa, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Camellia,  enc_mode:TlsCipherEncMode::Gcm, enc_size:128, mac:TlsCipherMac::Aead, mac_size:128,});
        m.insert(0xc07b,TlsCipherSuite{ name:"TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384", id:0xc07b, kx:TlsCipherKx::Rsa, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Camellia,  enc_mode:TlsCipherEncMode::Gcm, enc_size:256, mac:TlsCipherMac::Aead, mac_size:256,});
        m.insert(0xc07c,TlsCipherSuite{ name:"TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256", id:0xc07c, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Camellia,  enc_mode:TlsCipherEncMode::Gcm, enc_size:128, mac:TlsCipherMac::Aead, mac_size:128,});
        m.insert(0xc07d,TlsCipherSuite{ name:"TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384", id:0xc07d, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Camellia,  enc_mode:TlsCipherEncMode::Gcm, enc_size:256, mac:TlsCipherMac::Aead, mac_size:256,});
        m.insert(0xc07e,TlsCipherSuite{ name:"TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256", id:0xc07e, kx:TlsCipherKx::Dh, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Camellia,  enc_mode:TlsCipherEncMode::Gcm, enc_size:128, mac:TlsCipherMac::Aead, mac_size:128,});
        m.insert(0xc07f,TlsCipherSuite{ name:"TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384", id:0xc07f, kx:TlsCipherKx::Dh, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Camellia,  enc_mode:TlsCipherEncMode::Gcm, enc_size:256, mac:TlsCipherMac::Aead, mac_size:256,});
        m.insert(0xc080,TlsCipherSuite{ name:"TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256", id:0xc080, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Dss, enc:TlsCipherEnc::Camellia,  enc_mode:TlsCipherEncMode::Gcm, enc_size:128, mac:TlsCipherMac::Aead, mac_size:128,});
        m.insert(0xc081,TlsCipherSuite{ name:"TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384", id:0xc081, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Dss, enc:TlsCipherEnc::Camellia,  enc_mode:TlsCipherEncMode::Gcm, enc_size:256, mac:TlsCipherMac::Aead, mac_size:256,});
        m.insert(0xc082,TlsCipherSuite{ name:"TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256", id:0xc082, kx:TlsCipherKx::Dh, au:TlsCipherAu::Dss, enc:TlsCipherEnc::Camellia,  enc_mode:TlsCipherEncMode::Gcm, enc_size:128, mac:TlsCipherMac::Aead, mac_size:128,});
        m.insert(0xc083,TlsCipherSuite{ name:"TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384", id:0xc083, kx:TlsCipherKx::Dh, au:TlsCipherAu::Dss, enc:TlsCipherEnc::Camellia,  enc_mode:TlsCipherEncMode::Gcm, enc_size:256, mac:TlsCipherMac::Aead, mac_size:256,});
        m.insert(0xc084,TlsCipherSuite{ name:"TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256", id:0xc084, kx:TlsCipherKx::Dh, au:TlsCipherAu::Null, enc:TlsCipherEnc::Camellia,  enc_mode:TlsCipherEncMode::Gcm, enc_size:128, mac:TlsCipherMac::Aead, mac_size:128,});
        m.insert(0xc085,TlsCipherSuite{ name:"TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384", id:0xc085, kx:TlsCipherKx::Dh, au:TlsCipherAu::Null, enc:TlsCipherEnc::Camellia,  enc_mode:TlsCipherEncMode::Gcm, enc_size:256, mac:TlsCipherMac::Aead, mac_size:256,});
        m.insert(0xc086,TlsCipherSuite{ name:"TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256", id:0xc086, kx:TlsCipherKx::Ecdhe, au:TlsCipherAu::Ecdsa, enc:TlsCipherEnc::Camellia,  enc_mode:TlsCipherEncMode::Gcm, enc_size:128, mac:TlsCipherMac::Aead, mac_size:128,});
        m.insert(0xc087,TlsCipherSuite{ name:"TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384", id:0xc087, kx:TlsCipherKx::Ecdhe, au:TlsCipherAu::Ecdsa, enc:TlsCipherEnc::Camellia,  enc_mode:TlsCipherEncMode::Gcm, enc_size:256, mac:TlsCipherMac::Aead, mac_size:256,});
        m.insert(0xc088,TlsCipherSuite{ name:"TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256", id:0xc088, kx:TlsCipherKx::Ecdh, au:TlsCipherAu::Ecdsa, enc:TlsCipherEnc::Camellia,  enc_mode:TlsCipherEncMode::Gcm, enc_size:128, mac:TlsCipherMac::Aead, mac_size:128,});
        m.insert(0xc089,TlsCipherSuite{ name:"TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384", id:0xc089, kx:TlsCipherKx::Ecdh, au:TlsCipherAu::Ecdsa, enc:TlsCipherEnc::Camellia,  enc_mode:TlsCipherEncMode::Gcm, enc_size:256, mac:TlsCipherMac::Aead, mac_size:256,});
        m.insert(0xc08a,TlsCipherSuite{ name:"TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256", id:0xc08a, kx:TlsCipherKx::Ecdhe, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Camellia,  enc_mode:TlsCipherEncMode::Gcm, enc_size:128, mac:TlsCipherMac::Aead, mac_size:128,});
        m.insert(0xc08b,TlsCipherSuite{ name:"TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384", id:0xc08b, kx:TlsCipherKx::Ecdhe, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Camellia,  enc_mode:TlsCipherEncMode::Gcm, enc_size:256, mac:TlsCipherMac::Aead, mac_size:256,});
        m.insert(0xc08c,TlsCipherSuite{ name:"TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256", id:0xc08c, kx:TlsCipherKx::Ecdh, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Camellia,  enc_mode:TlsCipherEncMode::Gcm, enc_size:128, mac:TlsCipherMac::Aead, mac_size:128,});
        m.insert(0xc08d,TlsCipherSuite{ name:"TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384", id:0xc08d, kx:TlsCipherKx::Ecdh, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Camellia,  enc_mode:TlsCipherEncMode::Gcm, enc_size:256, mac:TlsCipherMac::Aead, mac_size:256,});
        m.insert(0xc08e,TlsCipherSuite{ name:"TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256", id:0xc08e, kx:TlsCipherKx::Psk, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Camellia,  enc_mode:TlsCipherEncMode::Gcm, enc_size:128, mac:TlsCipherMac::Aead, mac_size:128,});
        m.insert(0xc08f,TlsCipherSuite{ name:"TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384", id:0xc08f, kx:TlsCipherKx::Psk, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Camellia,  enc_mode:TlsCipherEncMode::Gcm, enc_size:256, mac:TlsCipherMac::Aead, mac_size:256,});
        m.insert(0xc090,TlsCipherSuite{ name:"TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256", id:0xc090, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Camellia,  enc_mode:TlsCipherEncMode::Gcm, enc_size:128, mac:TlsCipherMac::Aead, mac_size:128,});
        m.insert(0xc091,TlsCipherSuite{ name:"TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384", id:0xc091, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Camellia,  enc_mode:TlsCipherEncMode::Gcm, enc_size:256, mac:TlsCipherMac::Aead, mac_size:256,});
        m.insert(0xc092,TlsCipherSuite{ name:"TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256", id:0xc092, kx:TlsCipherKx::Rsa, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Camellia,  enc_mode:TlsCipherEncMode::Gcm, enc_size:128, mac:TlsCipherMac::Aead, mac_size:128,});
        m.insert(0xc093,TlsCipherSuite{ name:"TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384", id:0xc093, kx:TlsCipherKx::Rsa, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Camellia,  enc_mode:TlsCipherEncMode::Gcm, enc_size:256, mac:TlsCipherMac::Aead, mac_size:256,});
        m.insert(0xc094,TlsCipherSuite{ name:"TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256", id:0xc094, kx:TlsCipherKx::Psk, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Camellia,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha256, mac_size:256,});
        m.insert(0xc095,TlsCipherSuite{ name:"TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384", id:0xc095, kx:TlsCipherKx::Psk, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Camellia,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::HmacSha384, mac_size:384,});
        m.insert(0xc096,TlsCipherSuite{ name:"TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256", id:0xc096, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Camellia,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha256, mac_size:256,});
        m.insert(0xc097,TlsCipherSuite{ name:"TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384", id:0xc097, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Camellia,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::HmacSha384, mac_size:384,});
        m.insert(0xc098,TlsCipherSuite{ name:"TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256", id:0xc098, kx:TlsCipherKx::Rsa, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Camellia,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha256, mac_size:256,});
        m.insert(0xc099,TlsCipherSuite{ name:"TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384", id:0xc099, kx:TlsCipherKx::Rsa, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Camellia,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::HmacSha384, mac_size:384,});
        m.insert(0xc09a,TlsCipherSuite{ name:"TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256", id:0xc09a, kx:TlsCipherKx::Ecdhe, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Camellia,  enc_mode:TlsCipherEncMode::Cbc, enc_size:128, mac:TlsCipherMac::HmacSha256, mac_size:256,});
        m.insert(0xc09b,TlsCipherSuite{ name:"TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384", id:0xc09b, kx:TlsCipherKx::Ecdhe, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Camellia,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::HmacSha384, mac_size:384,});
        m.insert(0xc09c,TlsCipherSuite{ name:"TLS_RSA_WITH_AES_128_CCM", id:0xc09c, kx:TlsCipherKx::Rsa, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Ccm, enc_size:128, mac:TlsCipherMac::HmacSha384, mac_size:384,});
        m.insert(0xc09d,TlsCipherSuite{ name:"TLS_RSA_WITH_AES_256_CCM", id:0xc09d, kx:TlsCipherKx::Rsa, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Ccm, enc_size:256, mac:TlsCipherMac::HmacSha384, mac_size:384,});
        m.insert(0xc09e,TlsCipherSuite{ name:"TLS_DHE_RSA_WITH_AES_128_CCM", id:0xc09e, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Ccm, enc_size:128, mac:TlsCipherMac::HmacSha384, mac_size:384,});
        m.insert(0xc09f,TlsCipherSuite{ name:"TLS_DHE_RSA_WITH_AES_256_CCM", id:0xc09f, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Ccm, enc_size:256, mac:TlsCipherMac::HmacSha384, mac_size:384,});
        m.insert(0xc0a0,TlsCipherSuite{ name:"TLS_RSA_WITH_AES_128_CCM_8", id:0xc0a0, kx:TlsCipherKx::Rsa, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Ccm, enc_size:128, mac:TlsCipherMac::HmacSha384, mac_size:384,});
        m.insert(0xc0a1,TlsCipherSuite{ name:"TLS_RSA_WITH_AES_256_CCM_8", id:0xc0a1, kx:TlsCipherKx::Rsa, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Ccm, enc_size:256, mac:TlsCipherMac::HmacSha384, mac_size:384,});
        m.insert(0xc0a2,TlsCipherSuite{ name:"TLS_DHE_RSA_WITH_AES_128_CCM_8", id:0xc0a2, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Ccm, enc_size:128, mac:TlsCipherMac::HmacSha384, mac_size:384,});
        m.insert(0xc0a3,TlsCipherSuite{ name:"TLS_DHE_RSA_WITH_AES_256_CCM_8", id:0xc0a3, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Ccm, enc_size:256, mac:TlsCipherMac::HmacSha384, mac_size:384,});
        m.insert(0xc0a4,TlsCipherSuite{ name:"TLS_PSK_WITH_AES_128_CCM", id:0xc0a4, kx:TlsCipherKx::Psk, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Ccm, enc_size:128, mac:TlsCipherMac::HmacSha384, mac_size:384,});
        m.insert(0xc0a5,TlsCipherSuite{ name:"TLS_PSK_WITH_AES_256_CCM", id:0xc0a5, kx:TlsCipherKx::Psk, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Ccm, enc_size:256, mac:TlsCipherMac::HmacSha384, mac_size:384,});
        m.insert(0xc0a6,TlsCipherSuite{ name:"TLS_DHE_PSK_WITH_AES_128_CCM", id:0xc0a6, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Ccm, enc_size:128, mac:TlsCipherMac::HmacSha384, mac_size:384,});
        m.insert(0xc0a7,TlsCipherSuite{ name:"TLS_DHE_PSK_WITH_AES_256_CCM", id:0xc0a7, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Ccm, enc_size:256, mac:TlsCipherMac::HmacSha384, mac_size:384,});
        m.insert(0xc0a8,TlsCipherSuite{ name:"TLS_PSK_WITH_AES_128_CCM_8", id:0xc0a8, kx:TlsCipherKx::Psk, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Ccm, enc_size:128, mac:TlsCipherMac::HmacSha384, mac_size:384,});
        m.insert(0xc0a9,TlsCipherSuite{ name:"TLS_PSK_WITH_AES_256_CCM_8", id:0xc0a9, kx:TlsCipherKx::Psk, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Ccm, enc_size:256, mac:TlsCipherMac::HmacSha384, mac_size:384,});
        m.insert(0xc0aa,TlsCipherSuite{ name:"TLS_PSK_DHE_WITH_AES_128_CCM_8", id:0xc0aa, kx:TlsCipherKx::Psk, au:TlsCipherAu::Dhe, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Ccm, enc_size:128, mac:TlsCipherMac::HmacSha384, mac_size:384,});
        m.insert(0xc0ab,TlsCipherSuite{ name:"TLS_PSK_DHE_WITH_AES_256_CCM_8", id:0xc0ab, kx:TlsCipherKx::Psk, au:TlsCipherAu::Dhe, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Ccm, enc_size:256, mac:TlsCipherMac::HmacSha384, mac_size:384,});
        m.insert(0xc0ac,TlsCipherSuite{ name:"TLS_ECDHE_ECDSA_WITH_AES_128_CCM", id:0xc0ac, kx:TlsCipherKx::Ecdhe, au:TlsCipherAu::Ecdsa, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Ccm, enc_size:128, mac:TlsCipherMac::HmacSha384, mac_size:384,});
        m.insert(0xc0ad,TlsCipherSuite{ name:"TLS_ECDHE_ECDSA_WITH_AES_256_CCM", id:0xc0ad, kx:TlsCipherKx::Ecdhe, au:TlsCipherAu::Ecdsa, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Ccm, enc_size:256, mac:TlsCipherMac::HmacSha384, mac_size:384,});
        m.insert(0xc0ae,TlsCipherSuite{ name:"TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8", id:0xc0ae, kx:TlsCipherKx::Ecdhe, au:TlsCipherAu::Ecdsa, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Ccm, enc_size:128, mac:TlsCipherMac::HmacSha384, mac_size:384,});
        m.insert(0xc0af,TlsCipherSuite{ name:"TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8", id:0xc0af, kx:TlsCipherKx::Ecdhe, au:TlsCipherAu::Ecdsa, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Ccm, enc_size:256, mac:TlsCipherMac::HmacSha384, mac_size:384,});
        m.insert(0xcca8,TlsCipherSuite{ name:"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", id:0xcca8, kx:TlsCipherKx::Ecdhe, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Chacha20_Poly1305,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::Aead, mac_size:256,});
        m.insert(0xcca9,TlsCipherSuite{ name:"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", id:0xcca9, kx:TlsCipherKx::Ecdhe, au:TlsCipherAu::Ecdsa, enc:TlsCipherEnc::Chacha20_Poly1305,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::Aead, mac_size:256,});
        m.insert(0xccaa,TlsCipherSuite{ name:"TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256", id:0xccaa, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Rsa, enc:TlsCipherEnc::Chacha20_Poly1305,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::Aead, mac_size:256,});
        m.insert(0xccab,TlsCipherSuite{ name:"TLS_PSK_WITH_CHACHA20_POLY1305_SHA256", id:0xccab, kx:TlsCipherKx::Psk, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Chacha20_Poly1305,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::Aead, mac_size:256,});
        m.insert(0xccac,TlsCipherSuite{ name:"TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256", id:0xccac, kx:TlsCipherKx::Ecdhe, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Chacha20_Poly1305,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::Aead, mac_size:256,});
        m.insert(0xccad,TlsCipherSuite{ name:"TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256", id:0xccad, kx:TlsCipherKx::Dhe, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Chacha20_Poly1305,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::Aead, mac_size:256,});
        m.insert(0xccae,TlsCipherSuite{ name:"TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256", id:0xccae, kx:TlsCipherKx::Rsa, au:TlsCipherAu::Psk, enc:TlsCipherEnc::Chacha20_Poly1305,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::Aead, mac_size:256,});

        m
    };
    pub static ref COUNT: usize = HASHMAP.len();
}



#[cfg(test)]
mod tests {
    use tls_ciphers::{COUNT,TlsCipherSuite};

#[test]
fn test_cipher_count() {
    println!("loaded: {} cipher suites", *COUNT);
    assert!(*COUNT > 0);
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

}
