//! # TLS parser
//! Parsing functions for the TLS protocol, supporting versions 1.0 to 1.3

use nom::combinator::rest;
use nom::error::ErrorKind;
use nom::number::streaming::{be_u16, be_u24, be_u32, be_u8};
use nom::{Err, IResult};

use crate::tls_alert::*;
use crate::tls_ciphers::*;
use crate::tls_ec::ECPoint;

use std::convert::AsRef;
use std::fmt;
use std::ops::Deref;

/// Max record size (RFC8446 5.1)
pub const MAX_RECORD_LEN: u16 = 1 << 14;

/// Handshake type
///
/// Handshake types are defined in [RFC5246](https://tools.ietf.org/html/rfc5246) and
/// the [IANA HandshakeType
/// Registry](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-7)
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TlsHandshakeType(pub u8);

newtype_enum! {
impl debug TlsHandshakeType {
    HelloRequest        = 0x00,
    ClientHello         = 0x01,
    ServerHello         = 0x02,
    NewSessionTicket    = 0x04,
    EndOfEarlyData      = 0x05,
    HelloRetryRequest   = 0x06,
    EncryptedExtensions = 0x08,
    Certificate         = 0x0b,
    ServerKeyExchange   = 0x0c,
    CertificateRequest  = 0x0d,
    ServerDone          = 0x0e,
    CertificateVerify   = 0x0f,
    ClientKeyExchange   = 0x10,
    Finished            = 0x14,
    CertificateURL      = 0x15,
    CertificateStatus   = 0x16,
    KeyUpdate           = 0x18,

    NextProtocol        = 0x43,
}
}

impl From<TlsHandshakeType> for u8 {
    fn from(v: TlsHandshakeType) -> u8 {
        v.0
    }
}

/// TLS version
///
/// Only the TLS version defined in the TLS message header is meaningful, the
/// version defined in the record should be ignored or set to TLS 1.0
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TlsVersion(pub u16);

newtype_enum! {
impl debug TlsVersion {
    Ssl30        = 0x0300,
    Tls10        = 0x0301,
    Tls11        = 0x0302,
    Tls12        = 0x0303,
    Tls13        = 0x0304,

    Tls13Draft18 = 0x7f12,
    Tls13Draft19 = 0x7f13,
    Tls13Draft20 = 0x7f14,
    Tls13Draft21 = 0x7f15,
    Tls13Draft22 = 0x7f16,
    Tls13Draft23 = 0x7f17,
}
}

impl From<TlsVersion> for u16 {
    fn from(v: TlsVersion) -> u16 {
        v.0
    }
}

impl fmt::LowerHex for TlsVersion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:x}", self.0)
    }
}

/// Heartbeat type, as defined in [RFC6520](https://tools.ietf.org/html/rfc6520) section 3
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TlsHeartbeatMessageType(pub u8);

newtype_enum! {
impl debug TlsHeartbeatMessageType {
    HeartBeatRequest  = 0x1,
    HeartBeatResponse = 0x2,
}
}

impl From<TlsHeartbeatMessageType> for u8 {
    fn from(v: TlsHeartbeatMessageType) -> u8 {
        v.0
    }
}

/// Content type, as defined in IANA TLS ContentType registry
#[derive(Clone, Copy, PartialEq, Eq)]
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

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TlsCompressionID(pub u8);

newtype_enum! {
impl debug TlsCompressionID {
    Null = 0x00,
}
}

impl From<TlsCompressionID> for u8 {
    fn from(c: TlsCompressionID) -> u8 {
        c.0
    }
}

impl Deref for TlsCompressionID {
    type Target = u8;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<u8> for TlsCompressionID {
    fn as_ref(&self) -> &u8 {
        &self.0
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct TlsCipherSuiteID(pub u16);

impl TlsCipherSuiteID {
    pub fn get_ciphersuite(self) -> Option<&'static TlsCipherSuite> {
        TlsCipherSuite::from_id(self.0)
    }
}

impl From<TlsCipherSuiteID> for u16 {
    fn from(c: TlsCipherSuiteID) -> u16 {
        c.0
    }
}

impl Deref for TlsCipherSuiteID {
    type Target = u16;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<u16> for TlsCipherSuiteID {
    fn as_ref(&self) -> &u16 {
        &self.0
    }
}

impl fmt::Display for TlsCipherSuiteID {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for TlsCipherSuiteID {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match TlsCipherSuite::from_id(self.0) {
            Some(ref c) => write!(f, "0x{:04x}({})", self.0, c.name),
            None => write!(f, "0x{:04x}(Unknown cipher)", self.0),
        }
    }
}

impl fmt::LowerHex for TlsCipherSuiteID {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:x}", self.0)
    }
}

/// TLS Client Hello (from TLS 1.0 to TLS 1.2)
///
/// Some fields are unparsed (for performance reasons), for ex to parse `ext`,
/// call the `parse_tls_extensions` function.
#[derive(Clone, PartialEq)]
pub struct TlsClientHelloContents<'a> {
    /// TLS version of message
    pub version: TlsVersion,
    pub rand_time: u32,
    pub rand_data: &'a [u8],
    pub session_id: Option<&'a [u8]>,
    /// A list of ciphers supported by client
    pub ciphers: Vec<TlsCipherSuiteID>,
    /// A list of compression methods supported by client
    pub comp: Vec<TlsCompressionID>,

    pub ext: Option<&'a [u8]>,
}

impl<'a> TlsClientHelloContents<'a> {
    pub fn new(
        v: u16,
        rt: u32,
        rd: &'a [u8],
        sid: Option<&'a [u8]>,
        c: Vec<TlsCipherSuiteID>,
        co: Vec<TlsCompressionID>,
        e: Option<&'a [u8]>,
    ) -> Self {
        TlsClientHelloContents {
            version: TlsVersion(v),
            rand_time: rt,
            rand_data: rd,
            session_id: sid,
            ciphers: c,
            comp: co,
            ext: e,
        }
    }

    pub fn get_version(&self) -> TlsVersion {
        self.version
    }

    pub fn get_ciphers(&self) -> Vec<Option<&'static TlsCipherSuite>> {
        self.ciphers.iter().map(|&x| x.get_ciphersuite()).collect()
    }
}

/// TLS Server Hello (from TLS 1.0 to TLS 1.2)
#[derive(Clone, PartialEq)]
pub struct TlsServerHelloContents<'a> {
    pub version: TlsVersion,
    pub rand_time: u32,
    pub rand_data: &'a [u8],
    pub session_id: Option<&'a [u8]>,
    pub cipher: TlsCipherSuiteID,
    pub compression: TlsCompressionID,

    pub ext: Option<&'a [u8]>,
}

/// TLS Server Hello (TLS 1.3 draft 18)
#[derive(Clone, PartialEq)]
pub struct TlsServerHelloV13Draft18Contents<'a> {
    pub version: TlsVersion,
    pub random: &'a [u8],
    pub cipher: TlsCipherSuiteID,

    pub ext: Option<&'a [u8]>,
}

/// TLS Hello Retry Request (TLS 1.3)
#[derive(Clone, PartialEq)]
pub struct TlsHelloRetryRequestContents<'a> {
    pub version: TlsVersion,
    pub cipher: TlsCipherSuiteID,

    pub ext: Option<&'a [u8]>,
}

impl<'a> TlsServerHelloContents<'a> {
    pub fn new(
        v: u16,
        rt: u32,
        rd: &'a [u8],
        sid: Option<&'a [u8]>,
        c: u16,
        co: u8,
        e: Option<&'a [u8]>,
    ) -> Self {
        TlsServerHelloContents {
            version: TlsVersion(v),
            rand_time: rt,
            rand_data: rd,
            session_id: sid,
            cipher: TlsCipherSuiteID(c),
            compression: TlsCompressionID(co),
            ext: e,
        }
    }

    pub fn get_version(&self) -> TlsVersion {
        self.version
    }

    pub fn get_cipher(&self) -> Option<&'static TlsCipherSuite> {
        self.cipher.get_ciphersuite()
    }
}

/// Session ticket, as defined in [RFC5077](https://tools.ietf.org/html/rfc5077)
#[derive(Clone, Debug, PartialEq)]
pub struct TlsNewSessionTicketContent<'a> {
    pub ticket_lifetime_hint: u32,
    pub ticket: &'a [u8],
}

/// A raw certificate, which should be a DER-encoded X.509 certificate.
///
/// See [RFC5280](https://tools.ietf.org/html/rfc5280) for X509v3 certificate format.
#[derive(Clone, PartialEq)]
pub struct RawCertificate<'a> {
    pub data: &'a [u8],
}

/// The certificate chain, usually composed of the certificate, and all
/// required certificate authorities.
#[derive(Clone, Debug, PartialEq)]
pub struct TlsCertificateContents<'a> {
    pub cert_chain: Vec<RawCertificate<'a>>,
}

/// Certificate request, as defined in [RFC5246](https://tools.ietf.org/html/rfc5246) section 7.4.4
///
/// Note: TLS 1.2 adds SignatureAndHashAlgorithm (chapter 7.4.4) but do not declare it in A.4.2
#[derive(Clone, Debug, PartialEq)]
pub struct TlsCertificateRequestContents<'a> {
    pub cert_types: Vec<u8>,
    pub sig_hash_algs: Option<Vec<u16>>,
    /// A list of DER-encoded distinguished names. See
    /// [X.501](http://www.itu.int/rec/T-REC-X.501/en)
    pub unparsed_ca: Vec<&'a [u8]>,
}

/// Server key exchange parameters
///
/// This is an opaque struct, since the content depends on the selected
/// key exchange method.
#[derive(Clone, PartialEq)]
pub struct TlsServerKeyExchangeContents<'a> {
    pub parameters: &'a [u8],
}

/// Client key exchange parameters
///
/// Content depends on the selected key exchange method.
#[derive(Clone, PartialEq)]
pub enum TlsClientKeyExchangeContents<'a> {
    Dh(&'a [u8]),
    Ecdh(ECPoint<'a>),
    Unknown(&'a [u8]),
}

/// Certificate status response, as defined in [RFC6066](https://tools.ietf.org/html/rfc6066) section 8
#[derive(Clone, Debug, PartialEq)]
pub struct TlsCertificateStatusContents<'a> {
    pub status_type: u8,
    pub blob: &'a [u8],
}

/// Next protocol response, defined in
/// [draft-agl-tls-nextprotoneg-03](https://tools.ietf.org/html/draft-agl-tls-nextprotoneg-03)
#[derive(Clone, Debug, PartialEq)]
pub struct TlsNextProtocolContent<'a> {
    pub selected_protocol: &'a [u8],
    pub padding: &'a [u8],
}

/// Key update request (TLS 1.3)
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct KeyUpdateRequest(pub u8);

newtype_enum! {
impl KeyUpdateRequest {
    NotRequested  = 0x0,
    Requested     = 0x1,
}
}

/// Generic handshake message
#[derive(Clone, Debug, PartialEq)]
pub enum TlsMessageHandshake<'a> {
    HelloRequest,
    ClientHello(TlsClientHelloContents<'a>),
    ServerHello(TlsServerHelloContents<'a>),
    ServerHelloV13Draft18(TlsServerHelloV13Draft18Contents<'a>),
    NewSessionTicket(TlsNewSessionTicketContent<'a>),
    EndOfEarlyData,
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
    KeyUpdate(u8),
}

/// TLS application data
///
/// Since this message can only be sent after the handshake, data is
/// stored as opaque.
#[derive(Clone, Debug, PartialEq)]
pub struct TlsMessageApplicationData<'a> {
    pub blob: &'a [u8],
}

/// TLS heartbeat message, as defined in [RFC6520](https://tools.ietf.org/html/rfc6520)
///
/// Heartbeat messages should not be sent during handshake, but in practise
/// they can (and this caused heartbleed).
#[derive(Clone, Debug, PartialEq)]
pub struct TlsMessageHeartbeat<'a> {
    pub heartbeat_type: TlsHeartbeatMessageType,
    pub payload_len: u16,
    pub payload: &'a [u8],
}

/// TLS record header
#[derive(Clone, Copy, PartialEq)]
pub struct TlsRecordHeader {
    pub record_type: TlsRecordType,
    pub version: TlsVersion,
    pub len: u16,
}

/// TLS plaintext message
///
/// Plaintext records can only be found during the handshake.
#[derive(Clone, Debug, PartialEq)]
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
/// Use `parse_tls_raw_record` to parse content
#[derive(Clone, Debug, PartialEq)]
pub struct TlsRawRecord<'a> {
    pub hdr: TlsRecordHeader,
    pub data: &'a [u8],
}

fn parse_cipher_suites(i: &[u8], len: usize) -> IResult<&[u8], Vec<TlsCipherSuiteID>> {
    if len == 0 {
        return Ok((i, Vec::new()));
    }
    if len % 2 == 1 || len > i.len() {
        return Err(Err::Error(error_position!(i, ErrorKind::LengthValue)));
    }
    let v = (&i[..len])
        .chunks(2)
        .map(|chunk| TlsCipherSuiteID((chunk[0] as u16) << 8 | chunk[1] as u16))
        .collect();
    Ok((&i[len..], v))
}

fn parse_compressions_algs(i: &[u8], len: usize) -> IResult<&[u8], Vec<TlsCompressionID>> {
    if len == 0 {
        return Ok((i, Vec::new()));
    }
    if len > i.len() {
        return Err(Err::Error(error_position!(i, ErrorKind::LengthValue)));
    }
    let v = (&i[..len]).iter().map(|&it| TlsCompressionID(it)).collect();
    Ok((&i[len..], v))
}

pub(crate) fn parse_tls_versions(i: &[u8]) -> IResult<&[u8], Vec<TlsVersion>> {
    let len = i.len();
    if len == 0 {
        return Ok((i, Vec::new()));
    }
    if len % 2 == 1 || len > i.len() {
        return Err(Err::Error(error_position!(i, ErrorKind::LengthValue)));
    }
    let v = (&i[..len])
        .chunks(2)
        .map(|chunk| TlsVersion((chunk[0] as u16) << 8 | chunk[1] as u16))
        .collect();
    Ok((&i[len..], v))
}

named! {parse_certs<Vec<RawCertificate>>,
    many0!(
        complete!(
            map!(
                length_data!(be_u24),
                |s| RawCertificate{ data: s }
                )
        )
    )
}

named! {parse_tls_record_header<TlsRecordHeader>,
    do_parse!(
        t: be_u8 >>
        v: be_u16 >>
        l: be_u16 >>
        (
            TlsRecordHeader {
                record_type: TlsRecordType(t),
                version: TlsVersion(v),
                len: l,
            }
        )
    )
}

named!(
    parse_tls_handshake_msg_hello_request<TlsMessageHandshake>,
    value!(TlsMessageHandshake::HelloRequest)
);

named! {parse_tls_handshake_msg_client_hello<TlsMessageHandshake>,
    do_parse!(
        v:         be_u16  >>
        rand_time: be_u32 >>
        rand_data: take!(28) >> // 28 as 32 (aligned) - 4 (time)
        sidlen:    be_u8 >> // check <= 32, can be 0
                   error_if!(sidlen > 32, ErrorKind::Verify) >>
        sid:       cond!(sidlen > 0, take!(sidlen as usize)) >>
        ciphers_len: be_u16 >>
        ciphers:   call!(parse_cipher_suites, ciphers_len as usize) >>
        comp_len:  be_u8 >>
        comp:      call!(parse_compressions_algs, comp_len as usize) >>
        ext:       opt!(complete!(length_data!(be_u16))) >>
        (
            TlsMessageHandshake::ClientHello(
                TlsClientHelloContents::new(v,rand_time,rand_data,sid,ciphers,comp.to_vec(),ext)
            )
        )
    )
}

named! {parse_tls_handshake_msg_server_hello_tlsv12<TlsMessageHandshake>,
    do_parse!(
        v:         be_u16 >>
        rand_time: be_u32 >>
        rand_data: take!(28) >> // 28 as 32 (aligned) - 4 (time)
        sidlen:    be_u8 >> // check <= 32, can be 0
                   error_if!(sidlen > 32, ErrorKind::Verify) >>
        sid:       cond!(sidlen > 0, take!(sidlen as usize)) >>
        cipher:    be_u16 >>
        comp:      be_u8 >>
        ext:       opt!(complete!(length_data!(be_u16))) >>
        (
            TlsMessageHandshake::ServerHello(
                TlsServerHelloContents::new(v,rand_time,rand_data,sid,cipher,comp,ext)
            )
        )
    )
}

named! {parse_tls_handshake_msg_server_hello_tlsv13draft18<TlsMessageHandshake>,
    do_parse!(
        hv:     be_u16 >>
        random: take!(32) >>
        cipher: be_u16 >>
        ext:    opt!(complete!(length_data!(be_u16))) >>
        (
            TlsMessageHandshake::ServerHelloV13Draft18(
                TlsServerHelloV13Draft18Contents {
                    version: TlsVersion(hv),
                    random: random,
                    cipher: TlsCipherSuiteID(cipher),
                    ext: ext,
                }
            )
        )
    )
}

fn parse_tls_handshake_msg_server_hello(i: &[u8]) -> IResult<&[u8], TlsMessageHandshake> {
    let (_, version) = peek!(i, call!(be_u16))?;
    match version {
        0x7f12 => parse_tls_handshake_msg_server_hello_tlsv13draft18(i),
        0x0303 => parse_tls_handshake_msg_server_hello_tlsv12(i),
        0x0302 => parse_tls_handshake_msg_server_hello_tlsv12(i),
        0x0301 => parse_tls_handshake_msg_server_hello_tlsv12(i),
        // 0x0300 => call!(parse_tls_handshake_msg_server_hello_sslv3(i),
        _ => Err(Err::Error(error_position!(i, ErrorKind::Tag))),
    }
}

// RFC 5077   Stateless TLS Session Resumption
fn parse_tls_handshake_msg_newsessionticket(
    i: &[u8],
    len: usize,
) -> IResult<&[u8], TlsMessageHandshake> {
    do_parse!(
        i,
        hint: be_u32
            >> raw: take!(len - 4)
            >> (TlsMessageHandshake::NewSessionTicket(TlsNewSessionTicketContent {
                ticket_lifetime_hint: hint,
                ticket: raw,
            }))
    )
}

named! {parse_tls_handshake_msg_hello_retry_request<TlsMessageHandshake>,
    do_parse!(
        hv:  be_u16 >>
        c:   be_u16 >>
        ext: opt!(complete!(length_data!(be_u16))) >>
        (
            TlsMessageHandshake::HelloRetryRequest(
                TlsHelloRetryRequestContents {
                    version: TlsVersion(hv),
                    cipher: TlsCipherSuiteID(c),
                    ext: ext,
                    }
            )
        )
    )
}

named! {parse_tls_handshake_msg_certificate<TlsMessageHandshake>,
    do_parse!(
        cert_len: be_u24 >>
        certs:    flat_map!(take!(cert_len),parse_certs) >>
        (
            TlsMessageHandshake::Certificate(
                TlsCertificateContents {
                    cert_chain: certs,
                }
            )
        )
    )
}

fn parse_tls_handshake_msg_serverkeyexchange(
    i: &[u8],
    len: usize,
) -> IResult<&[u8], TlsMessageHandshake> {
    map!(i, take!(len), |ext| {
        TlsMessageHandshake::ServerKeyExchange(TlsServerKeyExchangeContents { parameters: ext })
    })
}

fn parse_tls_handshake_msg_serverdone(i: &[u8], len: usize) -> IResult<&[u8], TlsMessageHandshake> {
    map!(i, take!(len), |ext| {
        TlsMessageHandshake::ServerDone(ext)
    })
}

fn parse_tls_handshake_msg_certificateverify(
    i: &[u8],
    len: usize,
) -> IResult<&[u8], TlsMessageHandshake> {
    map!(i, take!(len), |blob| {
        TlsMessageHandshake::CertificateVerify(blob)
    })
}

fn parse_tls_handshake_msg_clientkeyexchange(
    i: &[u8],
    len: usize,
) -> IResult<&[u8], TlsMessageHandshake> {
    map!(i, take!(len), |ext| {
        TlsMessageHandshake::ClientKeyExchange(TlsClientKeyExchangeContents::Unknown(ext))
    })
}

fn parse_certrequest_nosigalg(i: &[u8]) -> IResult<&[u8], TlsMessageHandshake> {
    do_parse! {
        i,
        cert_types:        length_count!(be_u8,be_u8) >>
        ca_len:            be_u16 >>
        ca:                flat_map!(take!(ca_len),many0!(complete!(length_data!(be_u16)))) >>
        (
            TlsMessageHandshake::CertificateRequest(
                TlsCertificateRequestContents {
                    cert_types: cert_types,
                    // sig_hash_algs: Some(sig_hash_algs),
                    sig_hash_algs: None,
                    unparsed_ca: ca,
                }
            )
        )
    }
}

fn parse_certrequest_full(i: &[u8]) -> IResult<&[u8], TlsMessageHandshake> {
    do_parse! {
        i,
        cert_types:        length_count!(be_u8,be_u8) >>
        sig_hash_algs_len: be_u16 >>
        sig_hash_algs:     flat_map!(take!(sig_hash_algs_len),many0!(complete!(be_u16))) >>
        ca_len:            be_u16 >>
        ca:                flat_map!(take!(ca_len),many0!(complete!(length_data!(be_u16)))) >>
        (
            TlsMessageHandshake::CertificateRequest(
                TlsCertificateRequestContents {
                    cert_types: cert_types,
                    sig_hash_algs: Some(sig_hash_algs),
                    unparsed_ca: ca,
                }
            )
        )
    }
}

#[inline]
fn parse_tls_handshake_msg_certificaterequest(i: &[u8]) -> IResult<&[u8], TlsMessageHandshake> {
    alt!(
        i,
        complete!(parse_certrequest_full) | complete!(parse_certrequest_nosigalg)
    )
}

fn parse_tls_handshake_msg_finished(i: &[u8], len: usize) -> IResult<&[u8], TlsMessageHandshake> {
    map!(i, take!(len), |blob| {
        TlsMessageHandshake::Finished(blob)
    })
}

// Defined in [RFC6066]
// if status_type == 0, blob is a OCSPResponse, as defined in [RFC2560](https://tools.ietf.org/html/rfc2560)
// Note that the OCSPResponse object is DER-encoded.
named! {parse_tls_handshake_msg_certificatestatus<TlsMessageHandshake>,
    do_parse!(
        status_type: be_u8 >>
        blob:        length_data!(be_u24) >>
        ( TlsMessageHandshake::CertificateStatus(
                TlsCertificateStatusContents{
                    status_type:status_type,
                    blob:blob,
                }
        ) )
    )
}

/// NextProtocol handshake message, as defined in
/// [draft-agl-tls-nextprotoneg-03](https://tools.ietf.org/html/draft-agl-tls-nextprotoneg-03)
/// Deprecated in favour of ALPN.
fn parse_tls_handshake_msg_next_protocol(i: &[u8]) -> IResult<&[u8], TlsMessageHandshake> {
    do_parse! {
        i,
        selected_protocol: length_data!(be_u8) >>
        padding:           length_data!(be_u8) >>
        (
            TlsMessageHandshake::NextProtocol(
                TlsNextProtocolContent {
                    selected_protocol: selected_protocol,
                    padding: padding,
                }
            )
        )
    }
}

fn parse_tls_handshake_msg_key_update(i: &[u8]) -> IResult<&[u8], TlsMessageHandshake> {
    map!(i, be_u8, |update_request| {
        TlsMessageHandshake::KeyUpdate(update_request)
    })
}

named! {parse_tls_message_handshake<TlsMessage>,
    do_parse!(
        ht: be_u8 >>
        hl: be_u24 >>
        m: flat_map!(take!(hl),
            switch!(value!(ht),
                /*TlsHandshakeType::HelloRequest*/      0x00 => call!(parse_tls_handshake_msg_hello_request) |
                /*TlsHandshakeType::ClientHello*/       0x01 => call!(parse_tls_handshake_msg_client_hello) |
                /*TlsHandshakeType::ServerHello*/       0x02 => call!(parse_tls_handshake_msg_server_hello) |
                /*TlsHandshakeType::NewSessionTicket*/  0x04 => call!(parse_tls_handshake_msg_newsessionticket,hl as usize) |
                /*TlsHandshakeType::EndOfEarlyData*/    0x05 => value!(TlsMessageHandshake::EndOfEarlyData) |
                /*TlsHandshakeType::HelloRetryRequest*/ 0x06 => call!(parse_tls_handshake_msg_hello_retry_request) |
                /*TlsHandshakeType::Certificate*/       0x0b => call!(parse_tls_handshake_msg_certificate) |
                /*TlsHandshakeType::ServerKeyExchange*/ 0x0c => call!(parse_tls_handshake_msg_serverkeyexchange,hl as usize) |
                /*TlsHandshakeType::CertificateRequest*/ 0x0d => call!(parse_tls_handshake_msg_certificaterequest) |
                /*TlsHandshakeType::ServerDone*/        0x0e => call!(parse_tls_handshake_msg_serverdone,hl as usize) |
                /*TlsHandshakeType::CertificateVerify*/ 0x0f => call!(parse_tls_handshake_msg_certificateverify,hl as usize) |
                /*TlsHandshakeType::ClientKeyExchange*/ 0x10 => call!(parse_tls_handshake_msg_clientkeyexchange,hl as usize) |
                /*TlsHandshakeType::Finished*/          0x14 => call!(parse_tls_handshake_msg_finished,hl as usize) |
                /*TlsHandshakeType::CertificateURL*/    /*0x15 => call!(parse_tls_handshake_msg_certificateurl) |*/
                /*TlsHandshakeType::CertificateStatus*/ 0x16 => call!(parse_tls_handshake_msg_certificatestatus) |
                /*TlsHandshakeType::KeyUpdate*/         0x18 => call!(parse_tls_handshake_msg_key_update) |
                /*TlsHandshakeType::NextProtocol*/      0x43 => call!(parse_tls_handshake_msg_next_protocol)
             )
        ) >>
        ( TlsMessage::Handshake(m) )
    )
}

// XXX add extra verification hdr.len == 1
named!(
    parse_tls_message_changecipherspec<TlsMessage>,
    map!(tag!([0x01]), |_| { TlsMessage::ChangeCipherSpec })
);

// XXX add extra verification hdr.len == 2
named! {parse_tls_message_alert<TlsMessage>,
    do_parse!(
        s: be_u8 >>
        c: be_u8 >>
        ( TlsMessage::Alert(
                TlsMessageAlert {
                    severity: TlsAlertSeverity(s),
                    code: TlsAlertDescription(c),
            }
        ) )
    )
}

fn parse_tls_message_applicationdata(i: &[u8]) -> IResult<&[u8], TlsMessage> {
    map!(i, rest, |b| {
        TlsMessage::ApplicationData(TlsMessageApplicationData { blob: b })
    })
}

fn parse_tls_message_heartbeat(
    i: &[u8],
    tls_plaintext_len: u16,
) -> IResult<&[u8], Vec<TlsMessage>> {
    do_parse! {i,
        hb_type: be_u8 >>
        hb_len: be_u16 >>
           error_if!(tls_plaintext_len < 3, ErrorKind::Verify) >>
        b: take!(tls_plaintext_len - 3) >> // payload (hb_len) + padding
        (
            vec![TlsMessage::Heartbeat(
                TlsMessageHeartbeat {
                    heartbeat_type: TlsHeartbeatMessageType(hb_type),
                    payload_len: hb_len,
                    payload: b,
                }
            )]
        )
    }
}

/// Given data and a TLS record header, parse content.
///
/// A record can contain multiple messages (with the same type).
///
/// Note that message length is checked (not required for parser safety, but for
/// strict protocol conformance).
#[rustfmt::skip]
#[allow(clippy::trivially_copy_pass_by_ref)] // TlsRecordHeader is only 6 bytes, but we prefer not breaking current API
pub fn parse_tls_record_with_header<'i, 'hdr>(i:&'i [u8], hdr:&'hdr TlsRecordHeader ) -> IResult<&'i [u8], Vec<TlsMessage<'i>>> {
    match hdr.record_type {
        TlsRecordType::ChangeCipherSpec => many1!(i, complete!(parse_tls_message_changecipherspec)),
        TlsRecordType::Alert            => many1!(i, complete!(parse_tls_message_alert)),
        TlsRecordType::Handshake        => many1!(i, complete!(parse_tls_message_handshake)),
        TlsRecordType::ApplicationData  => many1!(i, complete!(parse_tls_message_applicationdata)),
        TlsRecordType::Heartbeat        => parse_tls_message_heartbeat(i, hdr.len),
        _                               => Err(Err::Error(error_position!(i, ErrorKind::Switch)))
    }
}

/// Parse one packet only, as plaintext
/// A single record can contain multiple messages, they must share the same record type
pub fn parse_tls_plaintext(i: &[u8]) -> IResult<&[u8], TlsPlaintext> {
    do_parse! {
        i,
        hdr: parse_tls_record_header >>
             error_if!(hdr.len > MAX_RECORD_LEN, ErrorKind::TooLarge) >>
        msg: flat_map!(take!(hdr.len),
            call!(parse_tls_record_with_header, &hdr)
            ) >>
        ( TlsPlaintext { hdr, msg } )
    }
}

/// Parse one packet only, as encrypted content
pub fn parse_tls_encrypted(i: &[u8]) -> IResult<&[u8], TlsEncrypted> {
    do_parse! {
        i,
        hdr: parse_tls_record_header >>
             error_if!(hdr.len > MAX_RECORD_LEN, ErrorKind::TooLarge) >>
        blob: take!(hdr.len) >>
        ( TlsEncrypted { hdr, msg:TlsEncryptedContent{ blob } } )
    }
}

/// Read TLS record envelope, but do not decode data
///
/// This function is used to get the record type, and to make sure the record is
/// complete (not fragmented).
/// After calling this function, use `parse_tls_record_with_header` to parse content.
pub fn parse_tls_raw_record(i: &[u8]) -> IResult<&[u8], TlsRawRecord> {
    do_parse! {
        i,
        hdr: parse_tls_record_header >>
             error_if!(hdr.len > MAX_RECORD_LEN, ErrorKind::TooLarge) >>
        data: take!(hdr.len) >>
        ( TlsRawRecord { hdr, data } )
    }
}

/// Parse one packet only, as plaintext
/// This function is deprecated. Use `parse_tls_plaintext` instead.
///
/// This function will be removed from API, as the name is not correct: it is
/// not possible to parse TLS packets without knowing the TLS state.
pub fn tls_parser(i: &[u8]) -> IResult<&[u8], TlsPlaintext> {
    parse_tls_plaintext(i)
}

/// Parse one chunk of data, possibly containing multiple TLS plaintext records
/// This function is deprecated. Use `parse_tls_plaintext` instead, checking if
/// there are remaining bytes, and calling `parse_tls_plaintext` recursively.
///
/// This function will be removed from API, as it should be replaced by a more
/// useful one to handle fragmentation.
pub fn tls_parser_many(i: &[u8]) -> IResult<&[u8], Vec<TlsPlaintext>> {
    many1!(i, complete!(parse_tls_plaintext))
}
