use std::collections::HashMap;
use std::env;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

use csv::Reader;
use phf_codegen;

fn titlecase_word(word: &String) -> String {
    word.chars()
        .enumerate()
        .map(|(i, c)| {
            if i == 0 {
                c.to_uppercase().collect::<String>()
            } else {
                c.to_lowercase().collect::<String>()
            }
        })
        .collect()
}

fn main() {
    let path_txt =
        Path::new(&env::var("CARGO_MANIFEST_DIR").unwrap()).join("scripts/all_ciphersuites.csv");

    let path = Path::new(&env::var("OUT_DIR").unwrap()).join("codegen.rs");
    let mut file = BufWriter::new(File::create(&path).unwrap());

    let mut map = phf_codegen::Map::new();
    let mut csv_reader = Reader::from_path(path_txt).unwrap();
    for record in csv_reader.deserialize() {
        let v: HashMap<String, String> = record.unwrap();
        println!("{:?}", v);

        if v["info.type"] != "IANATLSCipherSuite"
            || v["info.name"].contains("GOSTR")
            || v["info.name"].contains("TLS_SHA256_SHA256")
            || v["info.name"].contains("TLS_SHA384_SHA384")
            || v["info.name"].contains("_SCSV")
            || v["info.tls.parameters.encryption.algorithm"].contains("AEGIS")
        {
            continue;
        }

        let au = match v["info.tls.parameters.authentication"].as_str() {
            "" => String::from("Null"),
            _ => {
                titlecase_word(&v["info.tls.parameters.authentication"].replace("TLS 1.3", "TLS13"))
            }
        };

        let enc = match v["info.tls.parameters.encryption.algorithm"].as_str() {
            "" => String::from("Null"),
            "DES40" => String::from("Des"),
            "3DES" => String::from("TripleDes"),
            "CHACHA20" => String::from("Chacha20"),
            _ => titlecase_word(&v["info.tls.parameters.encryption.algorithm"]),
        };

        let mac = String::from(
            match v["info.tls.parameters.integrity.message_authentication_code"].as_str() {
                "" => "Null",
                "AEAD" => "Aead",
                "HMAC" => match v["info.tls.parameters.integrity.pseudorandom_function"].as_str() {
                    "MD5" => "HmacMd5",
                    "SHA1" => "HmacSha1",
                    "SHA256" => "HmacSha256",
                    "SHA384" => "HmacSha384",
                    "SHA512" => "HmacSha512",
                    _ => continue,
                },
                _ => continue,
            },
        );
        let mac_size = v["info.tls.parameters.integrity.message_authentication_code_size"].clone();

        let mode = match v["info.tls.parameters.encryption.mode"].as_str() {
            "" => String::from("Null"),
            "L" => String::from("Null"),
            _ => titlecase_word(&v["info.tls.parameters.encryption.mode"]),
        };

        let key_exchange = match v["info.tls.parameters.key_exchange"].as_str() {
            "" => String::from("Null"),
            _ => titlecase_word(&v["info.tls.parameters.key_exchange"].replace("TLS 1.3", "TLS13")),
        };

        let prf = match v["info.tls.parameters.integrity.pseudorandom_function"].as_str() {
            "" => String::from("Null"),
            _ => titlecase_word(
                &v["info.tls.parameters.integrity.pseudorandom_function"]
                    .replace(" ", "")
                    .replace(".", "")
                    .replace("-", ""),
            ),
        };
        let prf_size = v["info.tls.parameters.integrity.pseudorandom_function_size"].clone();

        let key_string = format!("{}{}", v["byte_1"], v["byte_2"]);
        let key = u16::from_str_radix(key_string.as_str(), 16).unwrap();
        let val = format!(
            r#"TlsCipherSuite{{
                name:"{}",
                id:TlsCipherSuiteID(0x{}),
                kx:TlsCipherKx::{},
                au:TlsCipherAu::{},
                enc:TlsCipherEnc::{},
                enc_mode:TlsCipherEncMode::{},
                enc_size:{},
                mac:TlsCipherMac::{},
                mac_size:{},
                prf:TlsPRF::{},
            }}"#,
            v["info.name"],
            key_string,
            key_exchange,
            au,
            enc,
            mode,
            if prf_size.is_empty() {
                String::from("0")
            } else {
                prf_size
            },
            mac,
            if mac_size.is_empty() {
                String::from("0")
            } else {
                mac_size
            },
            prf, // prf
        )
        .clone();

        map.entry(key, val.as_str());
    }

    writeln!(
        &mut file,
        "pub static CIPHERS: phf::Map<u16, TlsCipherSuite> = {};",
        map.build()
    )
    .unwrap();
}
