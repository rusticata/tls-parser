//! # TLS parser
//! Parsing functions for the TLS protocol, supporting versions 1.0 to 1.2

use rusticata_macros::parse_uint24;
use nom::{be_u8,be_u16,be_u32,rest,IResult,ErrorKind,Err};

use tls_alert::*;
use tls_ciphers::*;

use enum_primitive::FromPrimitive;

enum_from_primitive! {
/// Handshake type
///
/// Handshake types are defined in [RFC5246](https://tools.ietf.org/html/rfc5246) and
/// the [IANA HandshakeType
/// Registry](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-7)
#[repr(u8)]
pub enum TlsHandshakeType {
    HelloRequest = 0x0,
    ClientHello = 0x1,
    ServerHello = 0x02,
    NewSessionTicket = 0x04,
    Certificate = 0x0b,
    ServerKeyExchange = 0x0c,
    CertificateRequest = 0x0d,
    ServerDone = 0x0e,
    CertificateVerify = 0x0f,
    ClientKeyExchange = 0x10,
    Finished = 0x14,
    CertificateURL = 0x15,
    CertificateStatus = 0x16,

    NextProtocol = 0x43,
}
}

enum_from_primitive! {
/// TLS version
///
/// Only the TLS version defined in the TLS message header is meaningful, the
/// version defined in the record should be ignored or set to TLS 1.0
#[repr(u16)]
pub enum TlsVersion {
    Ssl30 = 0x0300,
    Tls10 = 0x0301,
    Tls11 = 0x0302,
    Tls12 = 0x0303,
    Tls13 = 0x0304,
}
}

enum_from_primitive! {
/// Heartbeat type, as defined in [RFC6520](https://tools.ietf.org/html/rfc6520) section 3
#[repr(u8)]
pub enum TlsHeartbeatMessageType {
    HeartBeatRequest  = 0x1,
    HeartBeatResponse = 0x2,
}
}

enum_from_primitive! {
/// Content type, as defined in IANA TLS ContentType registry
#[repr(u8)]
pub enum TlsRecordType {
    ChangeCipherSpec = 0x14,
    Alert = 0x15,
    Handshake = 0x16,
    ApplicationData = 0x17,
    Heartbeat = 0x18,
}
}

/// TLS Client Hello (from TLS 1.0 to TLS 1.2)
///
/// Some fields are unparsed (for performance reasons), for ex to parse `ext`,
/// call the `parse_tls_extensions` function.
#[derive(Clone,PartialEq)]
pub struct TlsClientHelloContents<'a> {
    /// TLS version of message
    pub version: u16,
    pub rand_time: u32,
    pub rand_data: &'a[u8],
    pub session_id: Option<&'a[u8]>,
    /// A list of ciphers supported by client
    pub ciphers: Vec<u16>,
    /// A list of compression methods supported by client
    pub comp: Vec<u8>,

    pub ext: Option<&'a[u8]>,
}

impl<'a> TlsClientHelloContents<'a> {
    pub fn new(v:u16,rt:u32,rd:&'a[u8],sid:Option<&'a[u8]>,c:Vec<u16>,co:Vec<u8>,e:Option<&'a[u8]>) -> Self {
        TlsClientHelloContents {
            version: v,
            rand_time: rt,
            rand_data: rd,
            session_id: sid,
            ciphers: c,
            comp: co,
            ext: e,
        }
    }

    pub fn get_version(&self) -> Option<TlsVersion> {
        TlsVersion::from_u16(self.version)
    }

    pub fn get_ciphers(&self) -> Vec<Option<&'static TlsCipherSuite>> {
        self.ciphers.iter().map(|&x|
            TlsCipherSuite::from_id(x)
        ).collect()
    }
}


/// TLS Server Hello (from TLS 1.0 to TLS 1.2)
#[derive(Clone,PartialEq)]
pub struct TlsServerHelloContents<'a> {
    pub version: u16,
    pub rand_time: u32,
    pub rand_data: &'a[u8],
    pub session_id: Option<&'a[u8]>,
    pub cipher: u16,
    pub compression: u8,

    pub ext: Option<&'a[u8]>,
}

impl<'a> TlsServerHelloContents<'a> {
    pub fn new(v:u16,rt:u32,rd:&'a[u8],sid:Option<&'a[u8]>,c:u16,co:u8,e:Option<&'a[u8]>) -> Self {
        TlsServerHelloContents {
            version: v,
            rand_time: rt,
            rand_data: rd,
            session_id: sid,
            cipher: c,
            compression: co,
            ext: e,
        }
    }

    pub fn get_version(&self) -> Option<TlsVersion> {
        TlsVersion::from_u16(self.version)
    }

    pub fn get_cipher(&self) -> Option<&'static TlsCipherSuite> {
        TlsCipherSuite::from_id(self.cipher)
    }
}

/// Session ticket, as defined in [RFC5077](https://tools.ietf.org/html/rfc5077)
#[derive(Clone,Debug,PartialEq)]
pub struct TlsNewSessionTicketContent<'a> {
    pub ticket_lifetime_hint: u32,
    pub ticket: &'a[u8],
}

/// A raw certificate, which should be a DER-encoded X.509 certificate.
///
/// See [RFC5280](https://tools.ietf.org/html/rfc5280) for X509v3 certificate format.
#[derive(Clone,PartialEq)]
pub struct RawCertificate<'a> {
    pub data: &'a[u8],
}

/// The certificate chain, usually composed of the certificate, and all
/// required certificate authorities.
#[derive(Clone,Debug,PartialEq)]
pub struct TlsCertificateContents<'a> {
    pub cert_chain: Vec<RawCertificate<'a> >,
}

/// Certificate request, as defined in [RFC5246](https://tools.ietf.org/html/rfc5246) section 7.4.4
#[derive(Clone,Debug,PartialEq)]
pub struct TlsCertificateRequestContents<'a> {
    pub cert_types: Vec<u8>,
    pub sig_hash_algs: Vec<u16>,
    /// A list of DER-encoded distinguished names. See
    /// [X.501](http://www.itu.int/rec/T-REC-X.501/en)
    pub unparsed_ca: Vec<&'a[u8]>,
}

/// Server key exchange parameters
///
/// This is an opaque struct, since the content depends on the selected
/// key exchange method.
#[derive(Clone,PartialEq)]
pub struct TlsServerKeyExchangeContents<'a> {
    pub parameters: &'a[u8],
}

/// Client key exchange parameters
///
/// Content depends on the selected key exchange method.
#[derive(Clone,PartialEq)]
pub struct TlsClientKeyExchangeContents<'a> {
    pub parameters: &'a[u8],
}

/// Certificate status response, as defined in [RFC6066](https://tools.ietf.org/html/rfc6066) section 8
#[derive(Clone,Debug,PartialEq)]
pub struct TlsCertificateStatusContents<'a> {
    pub status_type: u8,
    pub blob: &'a[u8],
}

/// Next protocol response, defined in
/// [draft-agl-tls-nextprotoneg-03](https://tools.ietf.org/html/draft-agl-tls-nextprotoneg-03)
#[derive(Clone,Debug,PartialEq)]
pub struct TlsNextProtocolContent<'a> {
    pub selected_protocol: &'a[u8],
    pub padding: &'a[u8],
}

/// Generic handshake message
#[derive(Clone,Debug,PartialEq)]
pub enum TlsMessageHandshake<'a> {
    HelloRequest,
    ClientHello(TlsClientHelloContents<'a>),
    ServerHello(TlsServerHelloContents<'a>),
    NewSessionTicket(TlsNewSessionTicketContent<'a>),
    Certificate(TlsCertificateContents<'a>),
    ServerKeyExchange(TlsServerKeyExchangeContents<'a>),
    CertificateRequest(TlsCertificateRequestContents<'a>),
    ServerDone(&'a[u8]),
    CertificateVerify(&'a[u8]),
    ClientKeyExchange(TlsClientKeyExchangeContents<'a>),
    Finished(&'a[u8]),
    CertificateStatus(TlsCertificateStatusContents<'a>),
    NextProtocol(TlsNextProtocolContent<'a>),
}

/// TLS application data
///
/// Since this message can only be sent after the handshake, data is
/// stored as opaque.
#[derive(Clone,Debug,PartialEq)]
pub struct TlsMessageApplicationData<'a>{
    pub blob: &'a[u8],
}

/// TLS heartbeat message, as defined in [RFC6520](https://tools.ietf.org/html/rfc6520)
///
/// Heartbeat messages should not be sent during handshake, but in practise
/// they can (and this caused heartbleed).
#[derive(Clone,Debug,PartialEq)]
pub struct TlsMessageHeartbeat<'a>{
    pub heartbeat_type: u8,
    pub payload_len: u16,
    pub payload: &'a[u8],
}

/// TLS record header
#[derive(Clone,PartialEq)]
pub struct TlsRecordHeader {
    pub record_type: u8,
    pub version: u16,
    pub len: u16,
}

/// TLS plaintext message
///
/// Plaintext records can only be found during the handshake.
#[derive(Clone,Debug,PartialEq)]
pub enum TlsMessage<'a> {
    Handshake(TlsMessageHandshake<'a>),
    ChangeCipherSpec,
    Alert(TlsMessageAlert),
    ApplicationData(TlsMessageApplicationData<'a>),
    Heartbeat(TlsMessageHeartbeat<'a>),
}

/// TLS plaintext record
///
/// A TLS record can contain multiple messages (sharing the same record type).
/// Plaintext records can only be found during the handshake.
#[derive(Clone,Debug,PartialEq)]
pub struct TlsPlaintext<'a> {
    pub hdr: TlsRecordHeader,
    pub msg: Vec<TlsMessage<'a>>,
}

/// TLS encrypted data
///
/// This struct only contains an opaque pointer (data are encrypted).
#[derive(Clone,Debug,PartialEq)]
pub struct TlsEncryptedContent<'a> {
    pub blob: &'a[u8],
}

/// Encrypted TLS record (containing opaque data)
#[derive(Clone,Debug,PartialEq)]
pub struct TlsEncrypted<'a> {
    pub hdr: TlsRecordHeader,
    pub msg: TlsEncryptedContent<'a>,
}

/// Tls Record with raw (unparsed) data
///
/// Use `parse_tls_raw_record` to parse content
#[derive(Clone,Debug,PartialEq)]
pub struct TlsRawRecord<'a> {
    pub hdr: TlsRecordHeader,
    pub data: &'a[u8],
}







named!(parse_cipher_suites<Vec<u16> >,
    many0!(be_u16)
);

named!(parse_certs<Vec<RawCertificate> >,
    many0!(
        do_parse!(
            s: length_bytes!(parse_uint24)
            >> ( RawCertificate{ data: s } )
        )
    )
);

named!(parse_tls_record_header<TlsRecordHeader>,
    do_parse!(
        t: be_u8 >>
        v: be_u16 >>
        l: be_u16 >>
        (
            TlsRecordHeader {
                record_type: t,
                version: v,
                len: l,
            }
        )
    )
);

named!(parse_tls_handshake_msg_hello_request<TlsMessageHandshake>,
    value!(TlsMessageHandshake::HelloRequest)
);

named!(read_len_value_u16<&[u8]>,
    length_bytes!(be_u16)
);

named!(parse_tls_handshake_msg_client_hello<TlsMessageHandshake>,
    do_parse!(
        v:         be_u16  >>
        rand_time: be_u32 >>
        rand_data: take!(28) >> // 28 as 32 (aligned) - 4 (time)
        sidlen:    be_u8 >> // check <= 32, can be 0
                   error_if!(sidlen > 32, Err::Code(ErrorKind::Custom(128))) >>
        sid:       cond!(sidlen > 0, take!(sidlen as usize)) >>
        ciphers:   flat_map!(length_bytes!(be_u16),parse_cipher_suites) >>
        comp_len:  take!(1) >>
        comp:      count!(be_u8, comp_len[0] as usize) >>
        ext:       opt!(complete!(read_len_value_u16)) >>
        (
            TlsMessageHandshake::ClientHello(
                TlsClientHelloContents::new(v,rand_time,rand_data,sid,ciphers,comp,ext)
            )
        )
    )
);

named!(parse_tls_handshake_msg_server_hello<TlsMessageHandshake>,
    do_parse!(
        v:         be_u16 >>
        rand_time: be_u32 >>
        rand_data: take!(28) >> // 28 as 32 (aligned) - 4 (time)
        sidlen:    be_u8 >> // check <= 32, can be 0
                   error_if!(sidlen > 32, Err::Code(ErrorKind::Custom(128))) >>
        sid:       cond!(sidlen > 0, take!(sidlen as usize)) >>
        cipher:    be_u16 >>
        comp:      be_u8 >>
        ext:       opt!(complete!(read_len_value_u16)) >>
        (
            TlsMessageHandshake::ServerHello(
                TlsServerHelloContents::new(v,rand_time,rand_data,sid,cipher,comp,ext)
            )
        )
    )
);

// RFC 5077   Stateless TLS Session Resumption
fn parse_tls_handshake_msg_newsessionticket( i:&[u8], len: u64 ) -> IResult<&[u8], TlsMessageHandshake> {
    do_parse!(i,
        hint: be_u32 >>
        raw:  take!(len - 4) >>
        (
            TlsMessageHandshake::NewSessionTicket(
                TlsNewSessionTicketContent {
                    ticket_lifetime_hint: hint,
                    ticket: raw,
                }
            )
        )
    )
}

named!(parse_tls_handshake_msg_certificate<TlsMessageHandshake>,
    do_parse!(
        cert_len: parse_uint24 >>
        certs:    flat_map!(take!(cert_len),parse_certs) >>
        (
            TlsMessageHandshake::Certificate(
                TlsCertificateContents {
                    cert_chain: certs,
                }
            )
        )
    )
);

fn parse_tls_handshake_msg_serverkeyexchange( i:&[u8], len: u64 ) -> IResult<&[u8], TlsMessageHandshake> {
    map!(i,
        take!(len),
        |ext| {
            TlsMessageHandshake::ServerKeyExchange(
                TlsServerKeyExchangeContents {
                    parameters: ext,
                }
            )
        }
    )
}

fn parse_tls_handshake_msg_serverdone( i:&[u8], len: u64 ) -> IResult<&[u8], TlsMessageHandshake> {
    map!(i,
        take!(len),
        |ext| { TlsMessageHandshake::ServerDone(ext) }
    )
}

fn parse_tls_handshake_msg_certificateverify( i:&[u8], len: u64 ) -> IResult<&[u8], TlsMessageHandshake> {
    map!(i,
        take!(len),
        |blob| { TlsMessageHandshake::CertificateVerify(blob) }
    )
}

fn parse_tls_handshake_msg_clientkeyexchange( i:&[u8], len: u64 ) -> IResult<&[u8], TlsMessageHandshake> {
    map!(i,
        take!(len),
        |ext| {
            TlsMessageHandshake::ClientKeyExchange(
                    TlsClientKeyExchangeContents {
                        parameters: ext,
                    })
        }
    )
}

fn parse_tls_handshake_msg_certificaterequest( i:&[u8] ) -> IResult<&[u8], TlsMessageHandshake> {
    do_parse!(i,
        cert_types:        length_count!(be_u8,be_u8) >>
        sig_hash_algs_len: be_u16 >>
        sig_hash_algs:     flat_map!(take!(sig_hash_algs_len),many0!(be_u16)) >>
        ca_len:            be_u16 >>
        ca:                flat_map!(take!(ca_len),many0!(read_len_value_u16)) >>
        (
            TlsMessageHandshake::CertificateRequest(
                TlsCertificateRequestContents {
                    cert_types: cert_types,
                    sig_hash_algs: sig_hash_algs,
                    unparsed_ca: ca,
                }
            )
        )
    )
}

fn parse_tls_handshake_msg_finished( i:&[u8], len: u64 ) -> IResult<&[u8], TlsMessageHandshake> {
    map!(i,
        take!(len),
        |blob| { TlsMessageHandshake::Finished(blob) }
    )
}

/// Defined in [RFC6066]
/// if status_type == 0, blob is a OCSPResponse, as defined in [RFC2560](https://tools.ietf.org/html/rfc2560)
/// Note that the OCSPResponse object is DER-encoded.
named!(parse_tls_handshake_msg_certificatestatus<TlsMessageHandshake>,
    do_parse!(
        status_type: be_u8 >>
        blob:        length_bytes!(parse_uint24) >>
        ( TlsMessageHandshake::CertificateStatus(
                TlsCertificateStatusContents{
                    status_type:status_type,
                    blob:blob,
                }
        ) )
    )
);

/// NextProtocol handshake message, as defined in
/// [draft-agl-tls-nextprotoneg-03](https://tools.ietf.org/html/draft-agl-tls-nextprotoneg-03)
/// Deprecated in favour of ALPN.
fn parse_tls_handshake_msg_next_protocol( i:&[u8] ) -> IResult<&[u8], TlsMessageHandshake> {
    do_parse!(i,
        selected_protocol: length_bytes!(be_u8) >>
        padding:           length_bytes!(be_u8) >>
        (
            TlsMessageHandshake::NextProtocol(
                TlsNextProtocolContent {
                    selected_protocol: selected_protocol,
                    padding: padding,
                }
            )
        )
    )
}

named!(parse_tls_message_handshake<TlsMessage>,
    do_parse!(
        ht: be_u8 >>
        hl: parse_uint24 >>
        m: flat_map!(take!(hl),
            switch!(value!(ht),
                /*TlsHandshakeType::HelloRequest*/      0x00 => call!(parse_tls_handshake_msg_hello_request) |
                /*TlsHandshakeType::ClientHello*/       0x01 => call!(parse_tls_handshake_msg_client_hello) |
                /*TlsHandshakeType::ServerHello*/       0x02 => call!(parse_tls_handshake_msg_server_hello) |
                /*TlsHandshakeType::NewSessionTicket*/  0x04 => call!(parse_tls_handshake_msg_newsessionticket,hl) |
                /*TlsHandshakeType::Certificate*/       0x0b => call!(parse_tls_handshake_msg_certificate) |
                /*TlsHandshakeType::ServerKeyExchange*/ 0x0c => call!(parse_tls_handshake_msg_serverkeyexchange,hl) |
                /*TlsHandshakeType::CertificateRequest*/ 0x0d => call!(parse_tls_handshake_msg_certificaterequest) |
                /*TlsHandshakeType::ServerDone*/        0x0e => call!(parse_tls_handshake_msg_serverdone,hl) |
                /*TlsHandshakeType::CertificateVerify*/ 0x0f => call!(parse_tls_handshake_msg_certificateverify,hl) |
                /*TlsHandshakeType::ClientKeyExchange*/ 0x10 => call!(parse_tls_handshake_msg_clientkeyexchange,hl) |
                /*TlsHandshakeType::Finished*/          0x14 => call!(parse_tls_handshake_msg_finished,hl) |
                /*TlsHandshakeType::CertificateURL*/    /*0x15 => call!(parse_tls_handshake_msg_certificateurl) |*/
                /*TlsHandshakeType::CertificateStatus*/ 0x16 => call!(parse_tls_handshake_msg_certificatestatus) |
                /*TlsHandshakeType::NextProtocol*/      0x43 => call!(parse_tls_handshake_msg_next_protocol)
             )
        ) >>
        ( TlsMessage::Handshake(m) )
    )
);

// XXX add extra verification hdr.len == 1
named!(parse_tls_message_changecipherspec<TlsMessage>,
    map!( tag!([0x01]),
        |_| { TlsMessage::ChangeCipherSpec }
    )
);

// XXX add extra verification hdr.len == 2
named!(parse_tls_message_alert<TlsMessage>,
    do_parse!(
        s: be_u8 >>
        c: be_u8 >>
        ( TlsMessage::Alert(
                TlsMessageAlert {
                    severity: s,
                    code: c,
            }
        ) )
    )
);

fn parse_tls_message_applicationdata( i:&[u8] ) -> IResult<&[u8], TlsMessage> {
    map!(i,
        rest,
        |b| {
            TlsMessage::ApplicationData(
                TlsMessageApplicationData {
                    blob: b,
        })
    })
}

fn parse_tls_message_heartbeat( i:&[u8] ) -> IResult<&[u8], TlsMessage> {
    do_parse!(i,
        hb_type: be_u8 >>
        hb_len: be_u16 >>
        b: take!(i.len()-3) >> // payload (hb_len) + padding
        (
            TlsMessage::Heartbeat(
                TlsMessageHeartbeat {
                    heartbeat_type: hb_type,
                    payload_len: hb_len,
                    payload: b,
                }
            )
        )
    )
}

/// Given data and a TLS record header, parse content.
///
/// A record can contain multiple messages (with the same type).
///
/// Note that message length is checked (not required for parser safety, but for
/// strict protocol conformance).
pub fn parse_tls_record_with_header( i:&[u8], hdr:TlsRecordHeader ) -> IResult<&[u8], Vec<TlsMessage>> {
    switch!(i, value!(hdr.record_type),
            /*TlsRecordType::ChangeCipherSpec*/ 0x14 => many1!(parse_tls_message_changecipherspec) |
            /*TlsRecordType::Alert*/            0x15 => many1!(parse_tls_message_alert) |
            /*TlsRecordType::Handshake*/        0x16 => many1!(parse_tls_message_handshake) |
            /*TlsRecordType::ApplicationData*/  0x17 => many1!(parse_tls_message_applicationdata) |
            /*TlsRecordType::Heartbeat      */  0x18 => many1!(parse_tls_message_heartbeat)
         )
}


/// Parse one packet only, as plaintext
/// A single record can contain multiple messages, they must share the same record type
pub fn parse_tls_plaintext(i:&[u8]) -> IResult<&[u8],TlsPlaintext> {
    do_parse!(i,
        hdr: parse_tls_record_header >>
        msg: flat_map!(take!(hdr.len),
            apply!(parse_tls_record_with_header,hdr.clone())
            ) >>
        ( TlsPlaintext {hdr:hdr, msg:msg} )
    )
}

/// Parse one packet only, as encrypted content
pub fn parse_tls_encrypted(i:&[u8]) -> IResult<&[u8],TlsEncrypted> {
    do_parse!(i,
        hdr: parse_tls_record_header >>
        blob: take!(hdr.len) >>
        ( TlsEncrypted {hdr:hdr, msg:TlsEncryptedContent{ blob: blob}} )
    )
}

/// Read TLS record envelope, but do not decode data
///
/// This function is used to get the record type, and to make sure the record is
/// complete (not fragmented).
/// After calling this function, use `parse_tls_record_with_header` to parse content.
pub fn parse_tls_raw_record(i:&[u8]) -> IResult<&[u8],TlsRawRecord> {
    do_parse!(i,
        hdr: parse_tls_record_header >>
        data: take!(hdr.len) >>
        ( TlsRawRecord {hdr:hdr, data: data} )
    )
}

/// Parse one packet only, as plaintext
/// This function is deprecated. Use `parse_tls_plaintext` instead.
///
/// This function will be removed from API, as the name is not correct: it is
/// not possible to parse TLS packets without knowing the TLS state.
pub fn tls_parser(i:&[u8]) -> IResult<&[u8],TlsPlaintext> {
    parse_tls_plaintext(i)
}

/// Parse one chunk of data, possibly containing multiple TLS plaintext records
/// This function is deprecated. Use `parse_tls_plaintext` instead, checking if
/// there are remaining bytes, and calling `parse_tls_plaintext` recursively.
///
/// This function will be removed from API, as it should be replaced by a more
/// useful one to handle fragmentation.
pub fn tls_parser_many(i:&[u8]) -> IResult<&[u8],Vec<TlsPlaintext>> {
    many1!(i,complete!(parse_tls_plaintext))
}
