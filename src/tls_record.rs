use alloc::vec::Vec;
use nom::bytes::streaming::take;
use nom::combinator::{complete, map_parser};
use nom::error::{make_error, ErrorKind};
use nom::multi::many1;
use nom::{Err, IResult};
use nom_derive::{NomBE, Parse};
use rusticata_macros::newtype_enum;

use crate::tls_handshake::*;
use crate::tls_message::*;
use crate::TlsVersion;

/// Max record size for TLSCipherText (RFC8446 5.2)
pub const MAX_RECORD_LEN: u16 = (1 << 14) + 256;

/// Content type, as defined in IANA TLS ContentType registry
#[derive(Clone, Copy, PartialEq, Eq, NomBE)]
pub struct TlsRecordType(pub u8);

newtype_enum! {
impl debug TlsRecordType {
    ChangeCipherSpec = 0x14,
    Alert            = 0x15,
    Handshake        = 0x16,
    ApplicationData  = 0x17,
    Heartbeat        = 0x18,
}
}

impl From<TlsRecordType> for u8 {
    fn from(v: TlsRecordType) -> u8 {
        v.0
    }
}

/// TLS record header
#[derive(Clone, Copy, PartialEq, NomBE)]
pub struct TlsRecordHeader {
    pub record_type: TlsRecordType,
    pub version: TlsVersion,
    pub len: u16,
}

/// TLS plaintext record
///
/// A TLS record can contain multiple messages (sharing the same record type).
/// Plaintext records can only be found during the handshake.
#[derive(Clone, Debug, PartialEq)]
pub struct TlsPlaintext<'a> {
    pub hdr: TlsRecordHeader,
    pub msg: Vec<TlsMessage<'a>>,
}

/// TLS encrypted data
///
/// This struct only contains an opaque pointer (data are encrypted).
#[derive(Clone, Debug, PartialEq)]
pub struct TlsEncryptedContent<'a> {
    pub blob: &'a [u8],
}

/// Encrypted TLS record (containing opaque data)
#[derive(Clone, Debug, PartialEq)]
pub struct TlsEncrypted<'a> {
    pub hdr: TlsRecordHeader,
    pub msg: TlsEncryptedContent<'a>,
}

/// Tls Record with raw (unparsed) data
///
/// Use [`parse_tls_raw_record`] to parse content
#[derive(Clone, Debug, PartialEq)]
pub struct TlsRawRecord<'a> {
    pub hdr: TlsRecordHeader,
    pub data: &'a [u8],
}

/// Read TLS record header
///
/// This function is used to get the record header.
/// After calling this function, caller can read the expected number of bytes and use
/// [`parse_tls_record_with_header`] to parse content.
#[inline]
pub fn parse_tls_record_header(i: &[u8]) -> IResult<&[u8], TlsRecordHeader> {
    TlsRecordHeader::parse(i)
}

/// Given data and a TLS record header, parse content.
///
/// A record can contain multiple messages (with the same type).
///
/// Note that message length is checked (not required for parser safety, but for
/// strict protocol conformance).
///
/// This function will fail on fragmented records. To support fragmented records, use
/// [crate::TlsRecordsParser]].
#[rustfmt::skip]
#[allow(clippy::trivially_copy_pass_by_ref)] // TlsRecordHeader is only 6 bytes, but we prefer not breaking current API
pub fn parse_tls_record_with_header<'i>(i:&'i [u8], hdr:&TlsRecordHeader ) -> IResult<&'i [u8], Vec<TlsMessage<'i>>> {
    match hdr.record_type {
        TlsRecordType::ChangeCipherSpec => many1(complete(parse_tls_message_changecipherspec))(i),
        TlsRecordType::Alert            => many1(complete(parse_tls_message_alert))(i),
        TlsRecordType::Handshake        => many1(complete(parse_tls_message_handshake))(i),
        TlsRecordType::ApplicationData  => many1(complete(parse_tls_message_applicationdata))(i),
        TlsRecordType::Heartbeat        => parse_tls_message_heartbeat(i, hdr.len),
        _                               => Err(Err::Error(make_error(i, ErrorKind::Switch)))
    }
}

/// Parse one packet only, as plaintext
/// A single record can contain multiple messages, they must share the same record type
pub fn parse_tls_plaintext(i: &[u8]) -> IResult<&[u8], TlsPlaintext> {
    let (i, hdr) = parse_tls_record_header(i)?;
    if hdr.len > MAX_RECORD_LEN {
        return Err(Err::Error(make_error(i, ErrorKind::TooLarge)));
    }
    let (i, msg) = map_parser(take(hdr.len as usize), |i| {
        parse_tls_record_with_header(i, &hdr)
    })(i)?;
    Ok((i, TlsPlaintext { hdr, msg }))
}

/// Parse one packet only, as encrypted content
pub fn parse_tls_encrypted(i: &[u8]) -> IResult<&[u8], TlsEncrypted> {
    let (i, hdr) = parse_tls_record_header(i)?;
    if hdr.len > MAX_RECORD_LEN {
        return Err(Err::Error(make_error(i, ErrorKind::TooLarge)));
    }
    let (i, blob) = take(hdr.len as usize)(i)?;
    let msg = TlsEncryptedContent { blob };
    Ok((i, TlsEncrypted { hdr, msg }))
}

/// Read TLS record envelope, but do not decode data
///
/// This function is used to get the record type, and to make sure the record is
/// complete (not fragmented).
/// After calling this function, use [`parse_tls_record_with_header`] or [crate::TlsRecordsParser] to parse content.
pub fn parse_tls_raw_record(i: &[u8]) -> IResult<&[u8], TlsRawRecord> {
    let (i, hdr) = parse_tls_record_header(i)?;
    if hdr.len > MAX_RECORD_LEN {
        return Err(Err::Error(make_error(i, ErrorKind::TooLarge)));
    }
    let (i, data) = take(hdr.len as usize)(i)?;
    Ok((i, TlsRawRecord { hdr, data }))
}

/// Parse one packet only, as plaintext
///
/// This function is deprecated. Use [`parse_tls_plaintext`] instead.
///
/// This function will be removed from API, as the name is not correct: it is
/// not possible to parse TLS packets without knowing the TLS state.
#[deprecated(since = "0.5.0", note = "Use parse_tls_plaintext")]
#[inline]
pub fn tls_parser(i: &[u8]) -> IResult<&[u8], TlsPlaintext> {
    parse_tls_plaintext(i)
}

/// Parse one chunk of data, possibly containing multiple TLS plaintext records
///
/// This function is deprecated. Use [`parse_tls_plaintext`] instead, checking if
/// there are remaining bytes, and calling [`parse_tls_plaintext`] recursively.
///
/// This function will be removed from API, as it should be replaced by a more
/// useful one to handle fragmentation.
pub fn tls_parser_many(i: &[u8]) -> IResult<&[u8], Vec<TlsPlaintext>> {
    many1(complete(parse_tls_plaintext))(i)
}
