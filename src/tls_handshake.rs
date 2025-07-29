use alloc::vec::Vec;
use core::convert::TryInto;
use core::fmt;
use core::ops::Deref;
use nom::branch::alt;
use nom::bytes::streaming::take;
use nom::combinator::{complete, cond, map, map_parser, opt, verify};
use nom::error::{make_error, ErrorKind};
use nom::multi::{length_count, length_data, many0};
use nom::number::streaming::{be_u16, be_u24, be_u32, be_u8};
use nom::{Err, IResult};
use nom_derive::{NomBE, Parse};
use rusticata_macros::newtype_enum;

use crate::tls_ciphers::*;
// use crate::tls_debug::*;
use crate::tls_ec::*;
use crate::tls_message::TlsMessage;

/// Handshake type
///
/// Handshake types are defined in [RFC5246](https://tools.ietf.org/html/rfc5246) and
/// the [IANA HandshakeType
/// Registry](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-7)
#[derive(Clone, Copy, PartialEq, Eq, NomBE)]
pub struct TlsHandshakeType(pub u8);

newtype_enum! {
impl debug TlsHandshakeType {
    HelloRequest        = 0x00,
    ClientHello         = 0x01,
    ServerHello         = 0x02,
    HelloVerifyRequest  = 0x03,
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
#[derive(Clone, Copy, Default, PartialEq, Eq, NomBE)]
pub struct TlsVersion(pub u16);

impl TlsVersion {
    pub const fn to_be_bytes(&self) -> [u8; 2] {
        self.0.to_be_bytes()
    }
}

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

    DTls10       = 0xfeff,
    DTls11       = 0xfefe,
    DTls12       = 0xfefd,
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
#[derive(Clone, Copy, PartialEq, Eq, NomBE)]
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

#[derive(Clone, Copy, Default, PartialEq, Eq, NomBE)]
pub struct TlsCompressionID(pub u8);

newtype_enum! {
impl debug TlsCompressionID {
    Null = 0x00,
    Deflate = 0x01,
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

#[derive(Clone, Copy, Default, PartialEq, Eq, NomBE)]
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
            Some(c) => write!(f, "0x{:04x}({})", self.0, c.name),
            None => write!(f, "0x{:04x}(Unknown cipher)", self.0),
        }
    }
}

impl fmt::LowerHex for TlsCipherSuiteID {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:x}", self.0)
    }
}

/// A trait that both TLS & DTLS satisfy
pub trait ClientHello<'a> {
    /// TLS version of message
    fn version(&self) -> TlsVersion;
    fn random(&self) -> &'a [u8];
    // Get the first part (4 bytes) of random
    fn rand_time(&self) -> u32 {
        self.random()
            .try_into()
            .map(u32::from_be_bytes)
            .unwrap_or(0)
    }
    // Get the second part (28 bytes) of random
    fn rand_bytes(&self) -> &'a [u8] {
        self.random().get(4..).unwrap_or(&[])
    }
    fn session_id(&self) -> Option<&'a [u8]>;
    /// A list of ciphers supported by client
    fn ciphers(&self) -> &Vec<TlsCipherSuiteID>;
    fn cipher_suites(&self) -> Vec<Option<&'static TlsCipherSuite>> {
        self.ciphers()
            .iter()
            .map(|&x| x.get_ciphersuite())
            .collect()
    }
    /// A list of compression methods supported by client
    fn comp(&self) -> &Vec<TlsCompressionID>;
    fn ext(&self) -> Option<&'a [u8]>;
}

/// TLS Client Hello (from TLS 1.0 to TLS 1.2)
///
/// Some fields are unparsed (for performance reasons), for ex to parse `ext`,
/// call the [parse_tls_client_hello_extension](crate::parse_tls_client_hello_extension) function.
#[derive(Clone, PartialEq)]
pub struct TlsClientHelloContents<'a> {
    /// TLS version of message
    pub version: TlsVersion,
    pub random: &'a [u8],
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
        random: &'a [u8],
        sid: Option<&'a [u8]>,
        c: Vec<TlsCipherSuiteID>,
        co: Vec<TlsCompressionID>,
        e: Option<&'a [u8]>,
    ) -> Self {
        TlsClientHelloContents {
            version: TlsVersion(v),
            random,
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

impl<'a> ClientHello<'a> for TlsClientHelloContents<'a> {
    fn version(&self) -> TlsVersion {
        self.version
    }

    fn random(&self) -> &'a [u8] {
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

/// TLS Server Hello (from TLS 1.0 to TLS 1.2)
#[derive(Clone, PartialEq)]
pub struct TlsServerHelloContents<'a> {
    pub version: TlsVersion,
    pub random: &'a [u8],
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
        random: &'a [u8],
        sid: Option<&'a [u8]>,
        c: u16,
        co: u8,
        e: Option<&'a [u8]>,
    ) -> Self {
        TlsServerHelloContents {
            version: TlsVersion(v),
            random,
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

/// Parse a HelloRequest handshake message
pub fn parse_tls_handshake_msg_hello_request(i: &[u8]) -> IResult<&[u8], TlsMessageHandshake<'_>> {
    Ok((i, TlsMessageHandshake::HelloRequest))
}

/// Parse handshake message contents for ClientHello
///
/// ```rust
/// use tls_parser::*;
///
/// # pub fn do_stuff(bytes: &[u8]) {
/// if let Ok((_, ch)) = parse_tls_handshake_client_hello(bytes) {
///     println!("ClientHello TLS version: {}", ch.version);
///     println!("  number of proposed ciphersuites: {}", ch.ciphers.len());
/// }
/// # }
/// ```
pub fn parse_tls_handshake_client_hello(i: &[u8]) -> IResult<&[u8], TlsClientHelloContents<'_>> {
    let (i, version) = be_u16(i)?;
    let (i, random) = take(32usize)(i)?;
    let (i, sidlen) = verify(be_u8, |&n| n <= 32)(i)?;
    let (i, sid) = cond(sidlen > 0, take(sidlen as usize))(i)?;
    let (i, ciphers_len) = be_u16(i)?;
    let (i, ciphers) = parse_cipher_suites(i, ciphers_len as usize)?;
    let (i, comp_len) = be_u8(i)?;
    let (i, comp) = parse_compressions_algs(i, comp_len as usize)?;
    let (i, ext) = opt(complete(length_data(be_u16)))(i)?;
    let content = TlsClientHelloContents::new(version, random, sid, ciphers, comp, ext);
    Ok((i, content))
}

/// Parse a ClientHello handshake message
///
/// This function returns a [TlsMessageHandshake]. To get only the `ClientHello` contents, use the
/// [parse_tls_handshake_client_hello] function.
///
/// ```rust
/// use tls_parser::*;
///
/// # pub fn do_stuff(bytes: &[u8]) {
/// if let Ok((_, TlsMessageHandshake::ClientHello(ch))) =
///         parse_tls_handshake_msg_client_hello(bytes) {
///     println!("ClientHello TLS version: {}", ch.version);
///     println!("  number of proposed ciphersuites: {}", ch.ciphers.len());
/// }
/// # }
/// ```
pub fn parse_tls_handshake_msg_client_hello(i: &[u8]) -> IResult<&[u8], TlsMessageHandshake<'_>> {
    map(
        parse_tls_handshake_client_hello,
        TlsMessageHandshake::ClientHello,
    )(i)
}

pub(crate) fn parse_cipher_suites(i: &[u8], len: usize) -> IResult<&[u8], Vec<TlsCipherSuiteID>> {
    if len == 0 {
        return Ok((i, Vec::new()));
    }
    if len % 2 == 1 || len > i.len() {
        return Err(Err::Error(make_error(i, ErrorKind::LengthValue)));
    }
    let v = (i[..len])
        .chunks(2)
        .map(|chunk| TlsCipherSuiteID((chunk[0] as u16) << 8 | chunk[1] as u16))
        .collect();
    Ok((&i[len..], v))
}

pub(crate) fn parse_compressions_algs(
    i: &[u8],
    len: usize,
) -> IResult<&[u8], Vec<TlsCompressionID>> {
    if len == 0 {
        return Ok((i, Vec::new()));
    }
    if len > i.len() {
        return Err(Err::Error(make_error(i, ErrorKind::LengthValue)));
    }
    let v = (i[..len]).iter().map(|&it| TlsCompressionID(it)).collect();
    Ok((&i[len..], v))
}

pub(crate) fn parse_tls_versions(i: &[u8]) -> IResult<&[u8], Vec<TlsVersion>> {
    let len = i.len();
    if len == 0 {
        return Ok((i, Vec::new()));
    }
    if len % 2 == 1 || len > i.len() {
        return Err(Err::Error(make_error(i, ErrorKind::LengthValue)));
    }
    let v = (i[..len])
        .chunks(2)
        .map(|chunk| TlsVersion((chunk[0] as u16) << 8 | chunk[1] as u16))
        .collect();
    Ok((&i[len..], v))
}

fn parse_certs(i: &[u8]) -> IResult<&[u8], Vec<RawCertificate<'_>>> {
    many0(complete(map(length_data(be_u24), |data| RawCertificate {
        data,
    })))(i)
}

fn parse_tls_handshake_msg_server_hello_tlsv12<const HAS_EXT: bool>(
    i: &[u8],
) -> IResult<&[u8], TlsMessageHandshake<'_>> {
    map(
        parse_tls_server_hello_tlsv12::<HAS_EXT>,
        TlsMessageHandshake::ServerHello,
    )(i)
}

pub(crate) fn parse_tls_server_hello_tlsv12<const HAS_EXT: bool>(
    i: &[u8],
) -> IResult<&[u8], TlsServerHelloContents<'_>> {
    let (i, version) = be_u16(i)?;
    let (i, random) = take(32usize)(i)?;
    let (i, sidlen) = verify(be_u8, |&n| n <= 32)(i)?;
    let (i, sid) = cond(sidlen > 0, take(sidlen as usize))(i)?;
    let (i, cipher) = be_u16(i)?;
    let (i, comp) = be_u8(i)?;
    let (i, ext) = if HAS_EXT {
        opt(complete(length_data(be_u16)))(i)?
    } else {
        (i, None)
    };
    let content = TlsServerHelloContents::new(version, random, sid, cipher, comp, ext);
    Ok((i, content))
}

fn parse_tls_handshake_msg_server_hello_tlsv13draft18(
    i: &[u8],
) -> IResult<&[u8], TlsMessageHandshake<'_>> {
    let (i, version) = TlsVersion::parse(i)?;
    let (i, random) = take(32usize)(i)?;
    let (i, cipher) = map(be_u16, TlsCipherSuiteID)(i)?;
    let (i, ext) = opt(complete(length_data(be_u16)))(i)?;
    let content = TlsServerHelloV13Draft18Contents {
        version,
        random,
        cipher,
        ext,
    };
    Ok((i, TlsMessageHandshake::ServerHelloV13Draft18(content)))
}

/// Parse handshake message contents for ServerHello (all TLS versions except 1.3 draft 18)
///
/// ```rust
/// use tls_parser::*;
///
/// # pub fn do_stuff(bytes: &[u8]) {
/// if let Ok((_, sh)) = parse_tls_handshake_server_hello(bytes) {
///     println!("ServerHello TLS version: {}", sh.version);
///     println!("  server chosen ciphersuites: {}", sh.cipher);
/// }
/// # }
/// ```
pub fn parse_tls_handshake_server_hello(i: &[u8]) -> IResult<&[u8], TlsServerHelloContents<'_>> {
    let (_, version) = be_u16(i)?;
    match version {
        0x0303 => parse_tls_server_hello_tlsv12::<true>(i),
        0x0302 => parse_tls_server_hello_tlsv12::<true>(i),
        0x0301 => parse_tls_server_hello_tlsv12::<true>(i),
        0x0300 => parse_tls_server_hello_tlsv12::<false>(i),
        _ => Err(Err::Error(make_error(i, ErrorKind::Tag))),
    }
}

/// Parse a ServerHello handshake message (all TLS versions)
///
/// This function returns a [TlsMessageHandshake]. To get only the `ServerHello` contents, use the
/// [parse_tls_handshake_server_hello] function.
///
/// ```rust
/// use tls_parser::*;
///
/// # pub fn do_stuff(bytes: &[u8]) {
/// if let Ok((_, msg)) = parse_tls_handshake_msg_server_hello(bytes) {
///     match msg {
///         TlsMessageHandshake::ServerHello(sh) => {
///             println!("ServerHello TLS version: {}", sh.version);
///             println!("  server chosen ciphersuites: {}", sh.cipher);
///         }
///         TlsMessageHandshake::ServerHelloV13Draft18(sh) => {
///             println!("ServerHello v1.3 draft 18 TLS version: {}", sh.version);
///         }
///         _ => {
///             println!("Not a ServerHello");
///         }
///     }
/// }
/// # }
/// ```
pub fn parse_tls_handshake_msg_server_hello(i: &[u8]) -> IResult<&[u8], TlsMessageHandshake<'_>> {
    let (_, version) = be_u16(i)?;
    match version {
        0x7f12 => parse_tls_handshake_msg_server_hello_tlsv13draft18(i),
        0x0303 => parse_tls_handshake_msg_server_hello_tlsv12::<true>(i),
        0x0302 => parse_tls_handshake_msg_server_hello_tlsv12::<true>(i),
        0x0301 => parse_tls_handshake_msg_server_hello_tlsv12::<true>(i),
        0x0300 => parse_tls_handshake_msg_server_hello_tlsv12::<false>(i),
        _ => Err(Err::Error(make_error(i, ErrorKind::Tag))),
    }
}

/// Parse a NewSessionTicket handshake message
// RFC 5077   Stateless TLS Session Resumption
pub fn parse_tls_handshake_msg_newsessionticket(
    i: &[u8],
    len: usize,
) -> IResult<&[u8], TlsMessageHandshake<'_>> {
    if len < 4 {
        return Err(Err::Error(make_error(i, ErrorKind::Verify)));
    }
    let (i, ticket_lifetime_hint) = be_u32(i)?;
    let (i, ticket) = take(len - 4)(i)?;
    let content = TlsNewSessionTicketContent {
        ticket_lifetime_hint,
        ticket,
    };
    Ok((i, TlsMessageHandshake::NewSessionTicket(content)))
}

/// Parse a HelloRetryRequest handshake message
pub fn parse_tls_handshake_msg_hello_retry_request(
    i: &[u8],
) -> IResult<&[u8], TlsMessageHandshake<'_>> {
    let (i, version) = TlsVersion::parse(i)?;
    let (i, cipher) = map(be_u16, TlsCipherSuiteID)(i)?;
    let (i, ext) = opt(complete(length_data(be_u16)))(i)?;
    let content = TlsHelloRetryRequestContents {
        version,
        cipher,
        ext,
    };
    Ok((i, TlsMessageHandshake::HelloRetryRequest(content)))
}

pub(crate) fn parse_tls_certificate(i: &[u8]) -> IResult<&[u8], TlsCertificateContents<'_>> {
    let (i, cert_len) = be_u24(i)?;
    let (i, cert_chain) = map_parser(take(cert_len as usize), parse_certs)(i)?;
    let content = TlsCertificateContents { cert_chain };
    Ok((i, content))
}

/// Parse a Certificate handshake message
pub fn parse_tls_handshake_msg_certificate(i: &[u8]) -> IResult<&[u8], TlsMessageHandshake<'_>> {
    map(parse_tls_certificate, TlsMessageHandshake::Certificate)(i)
}

/// Parse a ServerKeyExchange handshake message
pub fn parse_tls_handshake_msg_serverkeyexchange(
    i: &[u8],
    len: usize,
) -> IResult<&[u8], TlsMessageHandshake<'_>> {
    map(take(len), |ext| {
        TlsMessageHandshake::ServerKeyExchange(TlsServerKeyExchangeContents { parameters: ext })
    })(i)
}

/// Parse a ServerDone handshake message
pub fn parse_tls_handshake_msg_serverdone(
    i: &[u8],
    len: usize,
) -> IResult<&[u8], TlsMessageHandshake<'_>> {
    map(take(len), TlsMessageHandshake::ServerDone)(i)
}

/// Parse a CertificateVerify handshake message
pub fn parse_tls_handshake_msg_certificateverify(
    i: &[u8],
    len: usize,
) -> IResult<&[u8], TlsMessageHandshake<'_>> {
    map(take(len), TlsMessageHandshake::CertificateVerify)(i)
}

pub(crate) fn parse_tls_clientkeyexchange(
    len: usize,
) -> impl FnMut(&[u8]) -> IResult<&[u8], TlsClientKeyExchangeContents> {
    move |i| map(take(len), TlsClientKeyExchangeContents::Unknown)(i)
}

/// Parse a ClientKeyExchange handshake message
///
/// This function does not known the data structure, so it will always return
/// [TlsClientKeyExchangeContents::Unknown] with the raw data
pub fn parse_tls_handshake_msg_clientkeyexchange(
    i: &[u8],
    len: usize,
) -> IResult<&[u8], TlsMessageHandshake<'_>> {
    map(
        parse_tls_clientkeyexchange(len),
        TlsMessageHandshake::ClientKeyExchange,
    )(i)
}

fn parse_certrequest_nosigalg(i: &[u8]) -> IResult<&[u8], TlsCertificateRequestContents<'_>> {
    let (i, cert_types) = length_count(be_u8, be_u8)(i)?;
    let (i, ca_len) = be_u16(i)?;
    let (i, unparsed_ca) =
        map_parser(take(ca_len as usize), many0(complete(length_data(be_u16))))(i)?;
    let content = TlsCertificateRequestContents {
        cert_types,
        // sig_hash_algs: Some(sig_hash_algs),
        sig_hash_algs: None,
        unparsed_ca,
    };
    Ok((i, content))
}

fn parse_certrequest_full(i: &[u8]) -> IResult<&[u8], TlsCertificateRequestContents<'_>> {
    let (i, cert_types) = length_count(be_u8, be_u8)(i)?;
    let (i, sig_hash_algs_len) = be_u16(i)?;
    let (i, sig_hash_algs) =
        map_parser(take(sig_hash_algs_len as usize), many0(complete(be_u16)))(i)?;
    let (i, ca_len) = be_u16(i)?;
    let (i, unparsed_ca) =
        map_parser(take(ca_len as usize), many0(complete(length_data(be_u16))))(i)?;
    let content = TlsCertificateRequestContents {
        cert_types,
        sig_hash_algs: Some(sig_hash_algs),
        unparsed_ca,
    };
    Ok((i, content))
}

/// Parse a CertificateRequest handshake message
pub fn parse_tls_handshake_certificaterequest(
    i: &[u8],
) -> IResult<&[u8], TlsCertificateRequestContents<'_>> {
    alt((
        complete(parse_certrequest_full),
        complete(parse_certrequest_nosigalg),
    ))(i)
}

/// Parse a CertificateRequest handshake message
pub fn parse_tls_handshake_msg_certificaterequest(
    i: &[u8],
) -> IResult<&[u8], TlsMessageHandshake<'_>> {
    map(
        parse_tls_handshake_certificaterequest,
        TlsMessageHandshake::CertificateRequest,
    )(i)
}

/// Parse a Finished handshake message
pub fn parse_tls_handshake_msg_finished(
    i: &[u8],
    len: usize,
) -> IResult<&[u8], TlsMessageHandshake<'_>> {
    map(take(len), TlsMessageHandshake::Finished)(i)
}

/// Parse handshake message contents for CertificateStatus (\[RFC6066\])
///
/// If status_type == 0, blob is a OCSPResponse, as defined in [RFC2560](https://tools.ietf.org/html/rfc2560)
///
/// Note that the OCSPResponse object is DER-encoded.
pub fn parse_tls_handshake_certificatestatus(
    i: &[u8],
) -> IResult<&[u8], TlsCertificateStatusContents<'_>> {
    let (i, status_type) = be_u8(i)?;
    let (i, blob) = length_data(be_u24)(i)?;
    let content = TlsCertificateStatusContents { status_type, blob };
    Ok((i, content))
}

/// Parse a CertificateStatus handshake message (\[RFC6066\])
///
/// If status_type == 0, blob is a OCSPResponse, as defined in [RFC2560](https://tools.ietf.org/html/rfc2560)
///
/// Note that the OCSPResponse object is DER-encoded.
pub fn parse_tls_handshake_msg_certificatestatus(
    i: &[u8],
) -> IResult<&[u8], TlsMessageHandshake<'_>> {
    map(
        parse_tls_handshake_certificatestatus,
        TlsMessageHandshake::CertificateStatus,
    )(i)
}

/// Parse handshake message contents for NextProtocol
///
/// NextProtocol handshake message, as defined in
/// [draft-agl-tls-nextprotoneg-03](https://tools.ietf.org/html/draft-agl-tls-nextprotoneg-03)
/// Deprecated in favour of ALPN.
pub fn parse_tls_handshake_next_protocol(i: &[u8]) -> IResult<&[u8], TlsNextProtocolContent<'_>> {
    let (i, selected_protocol) = length_data(be_u8)(i)?;
    let (i, padding) = length_data(be_u8)(i)?;
    let next_proto = TlsNextProtocolContent {
        selected_protocol,
        padding,
    };
    Ok((i, next_proto))
}

/// Parse a NextProtocol handshake message
///
/// NextProtocol handshake message, as defined in
/// [draft-agl-tls-nextprotoneg-03](https://tools.ietf.org/html/draft-agl-tls-nextprotoneg-03)
/// Deprecated in favour of ALPN.
pub fn parse_tls_handshake_msg_next_protocol(i: &[u8]) -> IResult<&[u8], TlsMessageHandshake<'_>> {
    map(
        parse_tls_handshake_next_protocol,
        TlsMessageHandshake::NextProtocol,
    )(i)
}

/// Parse a KeyUpdate handshake message
pub fn parse_tls_handshake_msg_key_update(i: &[u8]) -> IResult<&[u8], TlsMessageHandshake<'_>> {
    map(be_u8, TlsMessageHandshake::KeyUpdate)(i)
}

/// Parse a TLS handshake message
pub fn parse_tls_message_handshake(i: &[u8]) -> IResult<&[u8], TlsMessage<'_>> {
    let (i, ht) = be_u8(i)?;
    let (i, hl) = be_u24(i)?;
    let (i, raw_msg) = take(hl)(i)?;
    let (_, msg) = match TlsHandshakeType(ht) {
        TlsHandshakeType::HelloRequest => parse_tls_handshake_msg_hello_request(raw_msg),
        TlsHandshakeType::ClientHello => parse_tls_handshake_msg_client_hello(raw_msg),
        TlsHandshakeType::ServerHello => parse_tls_handshake_msg_server_hello(raw_msg),
        TlsHandshakeType::NewSessionTicket => {
            parse_tls_handshake_msg_newsessionticket(raw_msg, hl as usize)
        }
        TlsHandshakeType::EndOfEarlyData => Ok((raw_msg, TlsMessageHandshake::EndOfEarlyData)),
        TlsHandshakeType::HelloRetryRequest => parse_tls_handshake_msg_hello_retry_request(raw_msg),
        TlsHandshakeType::Certificate => parse_tls_handshake_msg_certificate(raw_msg),
        TlsHandshakeType::ServerKeyExchange => {
            parse_tls_handshake_msg_serverkeyexchange(raw_msg, hl as usize)
        }
        TlsHandshakeType::CertificateRequest => parse_tls_handshake_msg_certificaterequest(raw_msg),
        TlsHandshakeType::ServerDone => parse_tls_handshake_msg_serverdone(raw_msg, hl as usize),
        TlsHandshakeType::CertificateVerify => {
            parse_tls_handshake_msg_certificateverify(raw_msg, hl as usize)
        }
        TlsHandshakeType::ClientKeyExchange => {
            parse_tls_handshake_msg_clientkeyexchange(raw_msg, hl as usize)
        }
        TlsHandshakeType::Finished => parse_tls_handshake_msg_finished(raw_msg, hl as usize),
        // TlsHandshakeType::CertificateURL => parse_tls_handshake_msg_certificateurl(raw_msg),
        TlsHandshakeType::CertificateStatus => parse_tls_handshake_msg_certificatestatus(raw_msg),
        TlsHandshakeType::KeyUpdate => parse_tls_handshake_msg_key_update(raw_msg),
        TlsHandshakeType::NextProtocol => parse_tls_handshake_msg_next_protocol(raw_msg),
        _ => Err(Err::Error(make_error(i, ErrorKind::Switch))),
    }?;
    Ok((i, TlsMessage::Handshake(msg)))
}
