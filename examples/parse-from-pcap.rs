extern crate pcap;
extern crate pnet;

use std::env;

use pnet::packet::Packet;
//use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;

use pnet::packet::ip::IpNextHeaderProtocols;

extern crate tls_parser;
use tls_parser::tls::{TlsMessage,TlsPlaintext,TlsHandshakeMsgContents,tls_parser_many};
use tls_parser::tls_ciphers::TlsCipherSuite;
use tls_parser::tls_extensions::parse_tls_extensions;

extern crate nom;
use nom::IResult;

fn handle_parsed_data(v:&Vec<TlsPlaintext>) {
    for ref record in v {
        println!("{:?}", record);
        match record.msg {
            TlsMessage::Handshake(ref m) => {
                match m.contents {
                    TlsHandshakeMsgContents::ClientHello(ref content) => {
                        let blah = parse_tls_extensions(content.ext);
                        println!("ext {:?}", blah);
                    },
                    TlsHandshakeMsgContents::ServerHello(ref content) => {
                        let lu /* cipher */ : TlsCipherSuite = content.cipher.into();
                        println!("Selected cipher: {:?}", lu);
                        let blah = parse_tls_extensions(content.ext);
                        println!("ext {:?}", blah);
                    },
                    _ => (),
                }
            },
            _ => (),
        }
    }
}

fn callback(packet: pcap::Packet) {
    println!("----------------------------------------");
    println!("raw packet: {:?}", &packet[16..]);

    //let ref ether = EthernetPacket::new(packet.data).unwrap();
    let ref ipv4 = Ipv4Packet::new(&packet.data[16..]).unwrap();
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

        while let Ok(packet) = cap.next() {
            callback(packet);
        }
    } else {
        println!("Usage: <prog> file.pcap");
    }
}
