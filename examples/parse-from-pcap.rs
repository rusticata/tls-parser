extern crate pcap;
extern crate pnet;

use std::env;

use pnet::packet::Packet;
//use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;

use pnet::packet::ip::IpNextHeaderProtocols;

extern crate tls_parser;
use tls_parser::tls::{TlsMessage,TlsPlaintext,TlsMessageHandshake,tls_parser_many};
use tls_parser::tls_ciphers::TlsCipherSuite;
use tls_parser::tls_extensions::parse_tls_extensions;

extern crate nom;
use nom::IResult;

fn handle_parsed_data(v:&Vec<TlsPlaintext>) {
    for ref record in v {
        println!("{:?}", record);
        for msg in &record.msg {
            match *msg {
                TlsMessage::Handshake(ref m) => {
                    match *m {
                        TlsMessageHandshake::ClientHello(ref content) => {
                            let blah = parse_tls_extensions(content.ext.unwrap_or(b""));
                            println!("ext {:?}", blah);
                        },
                        TlsMessageHandshake::ServerHello(ref content) => {
                            match TlsCipherSuite::from_id(content.cipher) {
                                Some(c) => println!("Selected cipher: {:?}", c),
                                _ => println!("Unknown ciphe 0x{:x}", content.cipher),
                            };
                            let blah = parse_tls_extensions(content.ext.unwrap_or(b""));
                            println!("ext {:?}", blah);
                        },
                        _ => (),
                    }
                },
                _ => (),
            }
        }
    }
}

fn callback(ds: usize, packet: pcap::Packet) {
    println!("----------------------------------------");
    println!("raw packet: {:?}", packet.data);

    //let ref ether = EthernetPacket::new(packet.data).unwrap();
    let ref ipv4 = Ipv4Packet::new(&packet.data[ds..]).unwrap();
    // println!("next level proto: {:?}", ipv4.get_next_level_protocol());
    if ipv4.get_next_level_protocol() == IpNextHeaderProtocols::Tcp {
        match TcpPacket::new(ipv4.payload()) {
            Some(ref tcp) => {
                //println!("tcp payload: {:?}", tcp.payload());

                let d = tls_parser_many(tcp.payload());
                match d {
                    IResult::Done(rem,ref v) => {
                        handle_parsed_data(v);
                        if rem.len() > 0 {
                            println!("** unparsed ** {:?}",rem);
                        }
                    },
                    _ =>  println!("parsing failed: {:?}", d),
                }
            },
            None => (), // not a TCP packet, ignore
        }
    }
}

fn main() {
    let args: Vec<_> = env::args().collect();
    if args.len() > 1 {
        let mut cap = pcap::Capture::from_file(&args[1]).unwrap();

        let ds = match cap.get_datalink() {
            pcap::Linktype(1) => 14,
            _ => 16,
        };

        while let Ok(packet) = cap.next() {
            callback(ds,packet);
        }
    } else {
        println!("Usage: <prog> file.pcap");
    }
}
