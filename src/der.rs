use std::vec::Vec;
//use nom::{IResult, space, alpha, alphanumeric, digit};
use nom::{IResult};

//use common::{Tag};
use common::bytes_to_u64;

#[derive(Clone,Copy,Debug,PartialEq)]
pub struct DerElement {
    class: u8,
    structured: u8,
    tag: u8,
}

#[derive(Clone,Copy,Debug,PartialEq)]
pub struct DerElementHeader {
    elt: DerElement,
    len: u64,
}


named!(parse_identifier<(&[u8],usize),DerElement>,
  chain!(
    class: take_bits!(u8, 2) ~
    structured: take_bits!(u8, 1) ~
    tag: take_bits!(u8, 5) ,
    || { DerElement{class:class,structured:structured,tag:tag} }
  )
);

#[derive(Debug,PartialEq)]
pub enum DerObject<'a> {
    Boolean(bool),
    Integer(u64),
    BitString(u8, &'a [u8]),
    OctetString(&'a [u8]),
    Null,
    Enum(u64),
    OID(Vec<u64>),
    NumericString(&'a[u8]),
    PrintableString(&'a[u8]),
    IA5String(&'a[u8]),

    Sequence(Vec<DerObject<'a> >),
    Set(Vec<DerObject<'a> >),

    UTCTime(&'a [u8]),

    ContextSpecific(/*tag:*/u8,&'a[u8]),
    Unknown(DerElementHeader, &'a[u8]),
}

named!(parse_der_length_byte<(&[u8],usize),(u8,u8)>,
  chain!(
    msb: take_bits!(u8, 1) ~
    low7: take_bits!(u8, 7),
    || { println!("(msb,low7)=({},{})",msb,low7); (msb,low7) }
  )
);


fn der_read_oid<'a>(i: &'a[u8]) -> Vec<u64> {
    let mut oid = Vec::new();
    let mut acc : u64;

    /* first element = X*40 + Y (See 8.19.4) */
    acc = i[0] as u64;
    oid.push( acc / 40);
    oid.push( acc % 40);

    acc = 0;
    for &c in &i[1..] {
        acc = (acc << 7) | (c & 0b01111111) as u64;
        if (c & (1<<7)) == 0 {
            oid.push(acc);
            acc = 0;
        }
    }
    assert!(acc == 0);

    oid
}


named!(der_read_element_header<&[u8],DerElementHeader>,
    chain!(
        el: bits!(
            parse_identifier
        ) ~
        len: bits!(
            parse_der_length_byte
        ) ~
        llen: cond!(len.0 == 1, take!(len.1)),

        || {
            println!("hdr: {:?}",el);
            let len : u64 = match len.0 {
                0 => len.1 as u64,
                _ => bytes_to_u64(llen.unwrap()).unwrap(),
            };
            DerElementHeader {
                elt: el,
                len: len,
            }
        }
    )
);

named!(der_read_sequence_contents<&[u8],Vec<DerObject> >,
    chain!(v: many0!(parse_der), || { return v })
);

fn der_read_element_contents<'a,'b>(i: &'a[u8], hdr: DerElementHeader) -> IResult<&'a [u8], DerObject<'a>> {
    println!("der_read_element_contents: {:?}", hdr);
    println!("i len: {}", i.len());
    match hdr.elt.class {
        // universal
        0b00 => (),
        // application
        0b01 => (),
        // context-specific
        0b10 => return chain!(i,b: take!(hdr.len),|| { DerObject::ContextSpecific(hdr.elt.tag,b) }),
        // private
        0b11 => (),
        _    => panic!("out of bounds value for hdr.elt.tag: {}", hdr.elt.tag),
    }
    match hdr.elt.tag {
        // 0x00 end-of-content
        // 0x01 bool
        0x01 => {
                    chain!(i,
                        b: switch!(take!(1),
                          b"\x00" => value!(true) |
                          b"\xff" => value!(false)
                        ),
                        || {
                        DerObject::Boolean(b) }
                    )
                },
        // 0x02: integer
        0x02 => {
                    chain!(i,
                        i: parse_hex_to_u64!(hdr.len),
                        || { DerObject::Integer(i) }
                    )
                },
        // 0x03: bitstring
        0x03 => {
                    chain!(i,
                        ignored_bits: take!(1) ~
                        s: take!(hdr.len - 1), // XXX we must check if constructed or not (8.7)
                        || { DerObject::BitString(ignored_bits[0],s) }
                    )
                },
        // 0x04: octetstring
        0x04 => {
                    chain!(i,
                        s: take!(hdr.len), // XXX we must check if constructed or not (8.7)
                        || { DerObject::OctetString(s) }
                    )
                },
        // 0x05: null
        0x05 => { IResult::Done(i,DerObject::Null) },
        // 0x06: object identified
        0x06 => {
                    chain!(i,
                        i: map!(take!(hdr.len),der_read_oid),
                        || { assert!(hdr.elt.structured == 0); DerObject::OID(i) }
                    )
                },
        // 0x0a: enumerated
        0x0a => {
                    chain!(i,
                        i: parse_hex_to_u64!(hdr.len),
                        || { DerObject::Enum(i) }
                    )
                },
        // 0x10: sequence
        0x10 => {
                    chain!(i,
                        l: flat_map!(take!(hdr.len),der_read_sequence_contents),
                        || {
                        println!("sequence OK {:?}", l.len());
                        DerObject::Sequence(l) }
                    )
                },
        // 0x11: set
        0x11 => {
                    chain!(i,
                        l: flat_map!(take!(hdr.len),der_read_sequence_contents),
                        || {
                        println!("set OK {:?}", l.len());
                        DerObject::Set(l) }
                    )
                },
        // 0x12: numericstring
        0x12 => {
                    chain!(i,
                        s: take!(hdr.len), // XXX we must check if constructed or not (8.7)
                        || { DerObject::NumericString(s) }
                    )
                },
        // 0x13: printablestring
        0x13 => {
                    chain!(i,
                        s: take!(hdr.len), // XXX we must check if constructed or not (8.7)
                        || { DerObject::PrintableString(s) }
                    )
                },

        // 0x16: ia5string
        0x16 => {
                    chain!(i,
                        s: take!(hdr.len), // XXX we must check if constructed or not (8.7)
                        || { DerObject::IA5String(s) }
                    )
                },
        // 0x17: utctime
        0x17 => {
                    chain!(i,
                        s: take!(hdr.len), // XXX we must check if constructed or not (8.7)
                        || { DerObject::UTCTime(s) }
                    )
                },
        // all unknown values
        _    => {
                    chain!(i,
                        b: take!(hdr.len),
                        || {
                        println!("unknown type");
                        DerObject::Unknown(hdr, b) }
                    )
                },
    }
}

pub fn parse_der<'a,'b>(i: &'a[u8]) -> IResult<&'a[u8], DerObject<'a> > {
//named!(parse_der<&[u8],DerObject>,
    println!("--");
    println!("parse_der");
    println!("i len: {}", i.len());
    chain!(i,
        hdr: apply!(der_read_element_header,) ~

        contents: apply!(der_read_element_contents,hdr),

        || {
            println!("el: {:?}",hdr.elt);
            println!("contents: {:?}",contents);
            contents
        }
    )
//);
}

#[cfg(test)]
mod tests {
    //use super::*;
    use der::{parse_der,DerObject};
    use nom::IResult;

use nom::Err::*;
use nom::ErrorKind;

#[test]
fn test_der_bool() {
    let empty = &b""[..];
    assert_eq!(parse_der(&[0x01, 0x01, 0x00]), IResult::Done(empty, DerObject::Boolean(true)));
    assert_eq!(parse_der(&[0x01, 0x01, 0xff]), IResult::Done(empty, DerObject::Boolean(false)));
    let bytes = [0x01, 0x01, 0x7f];
    assert_eq!(parse_der(&bytes[..]), IResult::Error(Position(ErrorKind::Switch, &bytes[2..])));
}

#[test]
fn test_der_int() {
    let empty = &b""[..];
    let bytes = [0x02, 0x03, 0x01, 0x00, 0x01];
    let expected = DerObject::Integer(65537);
    assert_eq!(parse_der(&bytes), IResult::Done(empty, expected));
}

#[test]
fn test_der_octetstring() {
    let empty = &b""[..];
    let bytes = [ 0x04, 0x05,
                  0x41, 0x41, 0x41, 0x41, 0x41,
    ];
    let expected = DerObject::OctetString(b"AAAAA");
    assert_eq!(parse_der(&bytes), IResult::Done(empty, expected));
}

#[test]
fn test_der_null() {
    let empty = &b""[..];
    assert_eq!(parse_der(&[0x05, 0x00]), IResult::Done(empty, DerObject::Null));
}

#[test]
fn test_der_enum() {
    let empty = &b""[..];
    assert_eq!(parse_der(&[0x0a, 0x01, 0x02]), IResult::Done(empty, DerObject::Enum(2)));
}

#[test]
fn test_der_oid() {
    let empty = &b""[..];
    let bytes = [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05];
    assert_eq!(parse_der(&bytes), IResult::Done(empty, DerObject::OID(vec![1, 2, 840, 113549, 1, 1, 5])));
}

#[test]
fn test_der_utctime() {
    let empty = &b""[..];
    let bytes = [0x17, 0x0D, 0x30, 0x32, 0x31, 0x32, 0x31, 0x33, 0x31, 0x34, 0x32, 0x39, 0x32, 0x33, 0x5A ];
    assert_eq!(parse_der(&bytes), IResult::Done(empty, DerObject::UTCTime(&bytes[2..])));
}

#[test]
fn test_der_seq() {
    let empty = &b""[..];
    let bytes = [ 0x30, 0x05,
                  0x02, 0x03, 0x01, 0x00, 0x01,
    ];
    let expected = DerObject::Sequence(
        vec![DerObject::Integer(65537)]
    );
    assert_eq!(parse_der(&bytes), IResult::Done(empty, expected));
}

#[test]
fn test_der_set() {
    let empty = &b""[..];
    let bytes = [
        0x31, 0x05,
        0x02, 0x03, 0x01, 0x00, 0x01, // Integer 65537
    ];
    let expected = DerObject::Set(
        vec![DerObject::Integer(65537)]
    );
    assert_eq!(parse_der(&bytes), IResult::Done(empty, expected));
}

#[test]
fn test_der_contextspecific() {
    let empty = &b""[..];
    let data = [0x02, 0x01, 0x02];
    let expected = DerObject::ContextSpecific(&data);
    assert_eq!(parse_der(&[0xa0, 0x03, 0x02, 0x01, 0x02]), IResult::Done(empty, expected));
}

//#[test]
//fn test_parse_hex4() {
//    let empty = &b""[..];
//    assert_eq!(parse_hex4(&[0x00, 0x01, 0x00, 0x01]), IResult::Done(empty, (65537)));
//}


}

