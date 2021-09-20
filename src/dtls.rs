//! Datagram Transport Layer Security Version 1.2 (RFC 6347)

use crate::tls::*;
use crate::TlsMessageAlert;
use alloc::vec::Vec;
use nom::bytes::streaming::take;
use nom::combinator::{complete, cond, map, map_parser, opt, verify};
use nom::error::{make_error, ErrorKind};
use nom::multi::{length_data, many1};
use nom::number::streaming::{be_u16, be_u24, be_u64, be_u8};
use nom_derive::Parse;

/// DTLS Plaintext record header
#[derive(Debug, PartialEq)]
pub struct DTLSRecordHeader {
    pub content_type: TlsRecordType,
    pub version: TlsVersion,
    /// A counter value that is incremented on every cipher state change.
    pub epoch: u16,
    /// The sequence number for this record.
    pub sequence_number: u64, // really an u48
    pub length: u16,
}

/// DTLS Plaintext record
///
/// Each DTLS record MUST fit within a single datagram.
///
/// Multiple DTLS records may be placed in a single datagram.
#[derive(Debug, PartialEq)]
pub struct DTLSPlaintext<'a> {
    pub header: DTLSRecordHeader,
    pub messages: Vec<DTLSMessage<'a>>,
}

#[derive(Debug, PartialEq)]
pub struct DTLSRawRecord<'a> {
    pub header: DTLSRecordHeader,
    pub fragment: &'a [u8],
}

#[derive(Debug, PartialEq)]
pub struct DTLSClientHello<'a> {
    pub version: TlsVersion,
    pub random: &'a [u8],
    pub session_id: Option<&'a [u8]>,
    pub cookie: &'a [u8],
    /// A list of ciphers supported by client
    pub ciphers: Vec<TlsCipherSuiteID>,
    /// A list of compression methods supported by client
    pub comp: Vec<TlsCompressionID>,
    pub ext: Option<&'a [u8]>,
}

impl<'a> ClientHello<'a> for DTLSClientHello<'a> {
    fn version(&self) -> TlsVersion {
        self.version
    }

    fn rand_data(&self) -> &'a [u8] {
        self.random
    }

    fn session_id(&self) -> Option<&'a [u8]> {
        self.session_id
    }

    fn ciphers(&self) -> &Vec<TlsCipherSuiteID> {
        &self.ciphers
    }

    fn comp(&self) -> &Vec<TlsCompressionID> {
        &self.comp
    }

    fn ext(&self) -> Option<&'a [u8]> {
        self.ext
    }
}

#[derive(Debug, PartialEq)]
pub struct DTLSHelloVerifyRequest<'a> {
    pub server_version: TlsVersion,
    pub cookie: &'a [u8],
}

/// DTLS Generic handshake message
#[derive(Debug, PartialEq)]
pub struct DTLSMessageHandshake<'a> {
    pub msg_type: TlsHandshakeType,
    pub length: u32,
    pub message_seq: u16,
    pub fragment_offset: u32,
    pub fragment_length: u32,
    pub body: DTLSMessageHandshakeBody<'a>,
}

/// DTLS Generic handshake message
#[derive(Debug, PartialEq)]
pub enum DTLSMessageHandshakeBody<'a> {
    HelloRequest,
    ClientHello(DTLSClientHello<'a>),
    HelloVerifyRequest(DTLSHelloVerifyRequest<'a>),
    ServerHello(TlsServerHelloContents<'a>),
    NewSessionTicket(TlsNewSessionTicketContent<'a>),
    HelloRetryRequest(TlsHelloRetryRequestContents<'a>),
    Certificate(TlsCertificateContents<'a>),
    ServerKeyExchange(TlsServerKeyExchangeContents<'a>),
    CertificateRequest(TlsCertificateRequestContents<'a>),
    ServerDone(&'a [u8]),
    CertificateVerify(&'a [u8]),
    ClientKeyExchange(TlsClientKeyExchangeContents<'a>),
    Finished(&'a [u8]),
    CertificateStatus(TlsCertificateStatusContents<'a>),
    NextProtocol(TlsNextProtocolContent<'a>),
}

/// DTLS plaintext message
///
/// Plaintext records can only be found during the handshake.
#[derive(Debug, PartialEq)]
pub enum DTLSMessage<'a> {
    Handshake(DTLSMessageHandshake<'a>),
    ChangeCipherSpec,
    Alert(TlsMessageAlert),
    ApplicationData(TlsMessageApplicationData<'a>),
    Heartbeat(TlsMessageHeartbeat<'a>),
}

// --------------------------- PARSERS ---------------------------

/// DTLS record header
// Section 4.1 of RFC6347
pub fn parse_dtls_record_header(i: &[u8]) -> IResult<&[u8], DTLSRecordHeader> {
    let (i, content_type) = TlsRecordType::parse(i)?;
    let (i, version) = TlsVersion::parse(i)?;
    let (i, int0) = be_u64(i)?;
    let epoch = (int0 >> 48) as u16;
    let sequence_number = int0 & 0xffff_ffff_ffff;
    let (i, length) = be_u16(i)?;
    let record = DTLSRecordHeader {
        content_type,
        version,
        epoch,
        sequence_number,
        length,
    };
    Ok((i, record))
}

/// DTLS Client Hello
// Section 4.2 of RFC6347
fn parse_dtls_client_hello(i: &[u8]) -> IResult<&[u8], DTLSMessageHandshakeBody> {
    let (i, version) = TlsVersion::parse(i)?;
    let (i, random) = take(32usize)(i)?;
    let (i, sidlen) = verify(be_u8, |&n| n <= 32)(i)?;
    let (i, session_id) = cond(sidlen > 0, take(sidlen as usize))(i)?;
    let (i, cookie) = length_data(be_u8)(i)?;
    let (i, ciphers_len) = be_u16(i)?;
    let (i, ciphers) = parse_cipher_suites(i, ciphers_len as usize)?;
    let (i, comp_len) = be_u8(i)?;
    let (i, comp) = parse_compressions_algs(i, comp_len as usize)?;
    let (i, ext) = opt(complete(length_data(be_u16)))(i)?;
    let content = DTLSClientHello {
        version,
        random,
        session_id,
        cookie,
        ciphers,
        comp,
        ext,
    };
    Ok((i, DTLSMessageHandshakeBody::ClientHello(content)))
}

/// DTLS Client Hello
// Section 4.2 of RFC6347
fn parse_dtls_hello_verify_request(i: &[u8]) -> IResult<&[u8], DTLSMessageHandshakeBody> {
    let (i, server_version) = TlsVersion::parse(i)?;
    let (i, cookie) = length_data(be_u8)(i)?;
    let content = DTLSHelloVerifyRequest {
        server_version,
        cookie,
    };
    Ok((i, DTLSMessageHandshakeBody::HelloVerifyRequest(content)))
}

fn parse_dtls_handshake_msg_server_hello_tlsv12(
    i: &[u8],
) -> IResult<&[u8], DTLSMessageHandshakeBody> {
    map(
        parse_tls_server_hello_tlsv12,
        DTLSMessageHandshakeBody::ServerHello,
    )(i)
}

fn parse_dtls_handshake_msg_serverdone(
    i: &[u8],
    len: usize,
) -> IResult<&[u8], DTLSMessageHandshakeBody> {
    map(take(len), DTLSMessageHandshakeBody::ServerDone)(i)
}

fn parse_dtls_handshake_msg_clientkeyexchange(
    i: &[u8],
    len: usize,
) -> IResult<&[u8], DTLSMessageHandshakeBody> {
    map(
        parse_tls_clientkeyexchange(len),
        DTLSMessageHandshakeBody::ClientKeyExchange,
    )(i)
}

fn parse_dtls_handshake_msg_certificate(i: &[u8]) -> IResult<&[u8], DTLSMessageHandshakeBody> {
    map(parse_tls_certificate, DTLSMessageHandshakeBody::Certificate)(i)
}

/// Parse a DTLS handshake message
pub fn parse_dtls_message_handshake(i: &[u8]) -> IResult<&[u8], DTLSMessage> {
    let (i, msg_type) = map(be_u8, TlsHandshakeType)(i)?;
    let (i, length) = be_u24(i)?;
    let (i, message_seq) = be_u16(i)?;
    let (i, fragment_offset) = be_u24(i)?;
    let (i, fragment_length) = be_u24(i)?;
    let (i, raw_msg) = take(length)(i)?;
    let (_, body) = match msg_type {
        TlsHandshakeType::ClientHello => parse_dtls_client_hello(raw_msg),
        TlsHandshakeType::HelloVerifyRequest => parse_dtls_hello_verify_request(raw_msg),
        TlsHandshakeType::ServerHello => parse_dtls_handshake_msg_server_hello_tlsv12(raw_msg),
        TlsHandshakeType::ServerDone => {
            parse_dtls_handshake_msg_serverdone(raw_msg, length as usize)
        }
        TlsHandshakeType::ClientKeyExchange => {
            parse_dtls_handshake_msg_clientkeyexchange(raw_msg, length as usize)
        }
        TlsHandshakeType::Certificate => parse_dtls_handshake_msg_certificate(raw_msg),
        _ => {
            // eprintln!("Unsupported message type {:?}", msg_type);
            Err(Err::Error(make_error(i, ErrorKind::Switch)))
        }
    }?;
    let msg = DTLSMessageHandshake {
        msg_type,
        length,
        message_seq,
        fragment_offset,
        fragment_length,
        body,
    };
    Ok((i, DTLSMessage::Handshake(msg)))
}

/// Parse a DTLS changecipherspec message
// XXX add extra verification hdr.len == 1
pub fn parse_dtls_message_changecipherspec(i: &[u8]) -> IResult<&[u8], DTLSMessage> {
    let (i, _) = verify(be_u8, |&tag| tag == 0x01)(i)?;
    Ok((i, DTLSMessage::ChangeCipherSpec))
}

/// Parse a DTLS alert message
// XXX add extra verification hdr.len == 2
pub fn parse_dtls_message_alert(i: &[u8]) -> IResult<&[u8], DTLSMessage> {
    let (i, alert) = TlsMessageAlert::parse(i)?;
    Ok((i, DTLSMessage::Alert(alert)))
}

pub fn parse_dtls_record_with_header<'i, 'hdr>(
    i: &'i [u8],
    hdr: &'hdr DTLSRecordHeader,
) -> IResult<&'i [u8], Vec<DTLSMessage<'i>>> {
    match hdr.content_type {
        TlsRecordType::ChangeCipherSpec => many1(complete(parse_dtls_message_changecipherspec))(i),
        TlsRecordType::Alert => many1(complete(parse_dtls_message_alert))(i),
        TlsRecordType::Handshake => many1(complete(parse_dtls_message_handshake))(i),
        // TlsRecordType::ApplicationData  => many1(complete(parse_tls_message_applicationdata))(i),
        // TlsRecordType::Heartbeat        => parse_tls_message_heartbeat(i, hdr.length),
        _ => {
            // eprintln!("Unsupported record type {:?}", hdr.content_type);
            Err(Err::Error(make_error(i, ErrorKind::Switch)))
        }
    }
}

/// Parse DTLS record, leaving `fragment` unparsed
// Section 4.1 of RFC6347
pub fn parse_dtls_raw_record(i: &[u8]) -> IResult<&[u8], DTLSRawRecord> {
    let (i, header) = parse_dtls_record_header(i)?;
    // As in TLS 1.2, the length should not exceed 2^14.
    if header.length > MAX_RECORD_LEN {
        return Err(Err::Error(make_error(i, ErrorKind::TooLarge)));
    }
    let (i, fragment) = take(header.length as usize)(i)?;
    Ok((i, DTLSRawRecord { header, fragment }))
}

/// Parse one DTLS plaintext record
// Section 4.1 of RFC6347
pub fn parse_dtls_plaintext_record(i: &[u8]) -> IResult<&[u8], DTLSPlaintext> {
    let (i, header) = parse_dtls_record_header(i)?;
    // As in TLS 1.2, the length should not exceed 2^14.
    if header.length > MAX_RECORD_LEN {
        return Err(Err::Error(make_error(i, ErrorKind::TooLarge)));
    }
    let (i, messages) = map_parser(take(header.length as usize), |i| {
        parse_dtls_record_with_header(i, &header)
    })(i)?;
    Ok((i, DTLSPlaintext { header, messages }))
}

/// Parse multiple DTLS plaintext record
// Section 4.1 of RFC6347
pub fn parse_dtls_plaintext_records(i: &[u8]) -> IResult<&[u8], Vec<DTLSPlaintext>> {
    many1(complete(parse_dtls_plaintext_record))(i)
}
