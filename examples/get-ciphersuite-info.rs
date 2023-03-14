/*
 *
 * Helper program to list/query ciphersuite information
 *
 */

use clap::Parser;
use std::num::ParseIntError;
use tls_parser::TlsCipherSuite;

#[derive(Parser)]
struct CmdOptions {
    /// List all known ciphersuites
    #[arg(short = 'L', long)]
    list: bool,
    /// Display details (algorithms, mode, ...)
    #[arg(short, long)]
    long: bool,
    /// Use JSON for output
    #[arg(short = 'j', long)]
    to_json: bool,

    /// Ciphersuite IANA identifier (decimal or hexadecimal prefix by 0x)
    #[arg(short, long, value_name = "id")]
    id: Option<String>,
    /// Ciphersuite IANA name
    #[arg(short, long, value_name = "name")]
    name: Option<String>,
}

fn parse_u16(s: &str) -> Result<u16, ParseIntError> {
    if s.starts_with("0x") {
        let s = s.trim_start_matches("0x");
        u16::from_str_radix(s, 16)
    } else {
        s.parse::<u16>()
    }
}

fn print_ciphersuite(cs: &TlsCipherSuite, show_details: bool, to_json: bool) {
    if to_json {
        let mut entries = Vec::new();
        entries.push(format!("\"id\":{}", cs.id));
        entries.push(format!("\"hex_id\":\"0x{:x}\"", cs.id));
        entries.push(format!("\"name\":\"{}\"", cs.name));
        //
        if show_details {
            entries.push(format!("\"kx\":\"{:?}\"", cs.kx));
            entries.push(format!("\"au\":\"{:?}\"", cs.au));
            entries.push(format!("\"enc\":\"{:?}\"", cs.enc));
            entries.push(format!("\"enc_mode\":\"{:?}\"", cs.enc_mode));
            entries.push(format!("\"enc_size\":{}", cs.enc_size));
            entries.push(format!("\"mac\":\"{:?}\"", cs.mac));
            entries.push(format!("\"mac_size\":{}", cs.mac_size));
        }
        let s = entries.join(",");
        println!("{{ {} }}", s);
    } else {
        let details = if show_details {
            format!(
                " kx={:?} au={:?} enc={:?} enc_mode={:?} enc_size={} mac={:?} mac_size={}",
                cs.kx, cs.au, cs.enc, cs.enc_mode, cs.enc_size, cs.mac, cs.mac_size
            )
        } else {
            "".to_string()
        };
        println!("{:04x} {}{}", cs.id, cs.name, details);
    }
}

fn find_by_id(id: u16, show_details: bool, to_json: bool) {
    let cipher = TlsCipherSuite::from_id(id);
    if let Some(cipher) = cipher {
        print_ciphersuite(cipher, show_details, to_json);
    } else {
        eprintln!("Unknown ciphersuite");
    }
}

fn find_by_name(name: &str, show_details: bool, to_json: bool) {
    let cipher = TlsCipherSuite::from_name(name);
    if let Some(cipher) = cipher {
        print_ciphersuite(cipher, show_details, to_json);
    } else {
        eprintln!("Unknown ciphersuite");
    }
}

fn main() {
    let options = CmdOptions::parse();

    let show_details = options.long;

    if options.list {
        let mut id_list = tls_parser::CIPHERS.keys().collect::<Vec<_>>();
        id_list.sort();
        for &id in &id_list {
            let cipher = TlsCipherSuite::from_id(*id).expect("could not get cipher");
            print_ciphersuite(cipher, show_details, options.to_json);
        }
        return;
    }

    if let Some(str_id) = options.id {
        let id = parse_u16(&str_id).expect("Could not parse cipher ID");
        find_by_id(id, show_details, options.to_json);
    } else if let Some(name) = options.name {
        find_by_name(&name, show_details, options.to_json);
    } else {
        eprintln!("Missing command");
    }
}
