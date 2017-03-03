extern crate phf_codegen;

use std::env;
use std::fs::File;
use std::io::{BufReader, BufWriter, Write};
use std::path::Path;
use std::error::Error;
use std::io::BufRead;

fn titlecase_word(word: &str) -> String {
    word.chars().enumerate()
        .map(|(i, c)| if i == 0 { c.to_uppercase().collect::<String>() } else { c.to_lowercase().collect::<String>() })
        .collect()
}

fn main() {
    let path_txt = Path::new(&env::var("CARGO_MANIFEST_DIR").unwrap()).join("scripts/tls-ciphersuites.txt");
    let display = path_txt.display();
    let file = match File::open(&path_txt) {
        // The `description` method of `io::Error` returns a string that
        // describes the error
        Err(why) => panic!("couldn't open {}: {}", display,
                                                   why.description()),
        Ok(file) => file,
    };
    let f = BufReader::new(file);

    let path = Path::new(&env::var("OUT_DIR").unwrap()).join("codegen.rs");
    let mut file = BufWriter::new(File::create(&path).unwrap());

    write!(&mut file, "pub static CIPHERS: phf::Map<u16, TlsCipherSuite> = ").unwrap();
    let mut map = phf_codegen::Map::new();
    for line in f.lines() {
        let l = line.unwrap();
        let mut v : Vec<&str> = l.split(':').collect();

        if v[6].is_empty() {
            v[6] = "NULL"
        }

        let au = match v[4] {
            "SRP+DSS" => String::from("Srp_Dss"),
            "SRP+RSA" => String::from("Srp_Rsa"),
            _ => titlecase_word(v[4]).replace("+","_"),
        };

        let enc = match v[5] {
            "3DES" => String::from("TripleDes"),
            "CHACHA20_POLY1305" => String::from("Chacha20_Poly1305"),
            _ => titlecase_word(v[5]),
        };

        let mac = String::from (
            match v[8] {
                "NULL" => "Null",
                "HMAC-MD5" => "HmacMd5",
                "HMAC-SHA1" => "HmacSha1",
                "HMAC-SHA256" => "HmacSha256",
                "HMAC-SHA384" => "HmacSha384",
                "AEAD" => "Aead",
                _ => panic!("Unknown mac {}", v[8]),
            });

        let key = u16::from_str_radix(v[0], 16).unwrap();
        let val =
            format!(
            "TlsCipherSuite{{ name:\"{}\", id:0x{}, kx:TlsCipherKx::{}, au:TlsCipherAu::{}, enc:TlsCipherEnc::{},  enc_mode:TlsCipherEncMode::{}, enc_size:{}, mac:TlsCipherMac::{}, mac_size:{},}}",
            v[1],v[0],
            titlecase_word(v[3]), // kx
            au, // au
            enc, // enc
            titlecase_word(v[6]), // enc_mode
            v[7], // enc_size
            mac, // mac
            v[9], // mac_size
            ).clone();

        map.entry(key,val.as_str());
    };

    // Add TLS 1.3 ciphers, until they are added to IANA
    // Note that Kx is not included anymore
    // XXX use a better value than 'Null' ?
    map.entry(0x1301,
        r#"TlsCipherSuite{ name:"TLS13_AES_128_GCM_SHA256", id:0x1301, kx:TlsCipherKx::Null, au:TlsCipherAu::Null, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Gcm, enc_size:128, mac:TlsCipherMac::Aead, mac_size:128,}"#
    );
    map.entry(0x1302,
        r#"TlsCipherSuite{ name:"TLS13_AES_256_GCM_SHA384", id:0x1302, kx:TlsCipherKx::Null, au:TlsCipherAu::Null, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Gcm, enc_size:256, mac:TlsCipherMac::Aead, mac_size:256,}"#
    );
    map.entry(0x1303,
        r#"TlsCipherSuite{ name:"TLS13_CHACHA20_POLY1305_SHA256", id:0x1303, kx:TlsCipherKx::Null, au:TlsCipherAu::Null, enc:TlsCipherEnc::Chacha20_Poly1305,  enc_mode:TlsCipherEncMode::Cbc, enc_size:256, mac:TlsCipherMac::Aead, mac_size:256,}"#
    );
    map.entry(0x1304,
        r#"TlsCipherSuite{ name:"TLS13_AES_128_CCM_SHA256", id:0x1304, kx:TlsCipherKx::Null, au:TlsCipherAu::Null, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Ccm, enc_size:128, mac:TlsCipherMac::Aead, mac_size:128,}"#
    );
    map.entry(0x1305,
        r#"TlsCipherSuite{ name:"TLS13_AES_128_CCM_8_SHA256", id:0x1305, kx:TlsCipherKx::Null, au:TlsCipherAu::Null, enc:TlsCipherEnc::Aes,  enc_mode:TlsCipherEncMode::Ccm, enc_size:128, mac:TlsCipherMac::Aead, mac_size:256,}"#
    );


    map.build(&mut file).unwrap();
    write!(&mut file, ";\n").unwrap();
}

