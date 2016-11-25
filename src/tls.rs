use common::parse_uint24;
use nom::{be_u8,be_u16,be_u32,IResult,ErrorKind,Err};

use tls_alert::*;

enum_from_primitive! {
#[repr(u8)]
pub enum TlsHandshakeType {
    HelloRequest = 0x0,
    ClientHello = 0x1,
    ServerHello = 0x02,
    NewSessionTicket = 0x04,
    HelloRetryRequest = 0x06,
    EncryptedExtensions = 0x08,
    Certificate = 0x0b,
    ServerKeyExchange = 0x0c,
    CertificateRequest = 0x0d,
    ServerDone = 0x0e,
    CertificateVerify = 0x0f,
    ClientKeyExchange = 0x10,
    Finished = 0x14,
    CertificateURL = 0x15,
    CertificateStatus = 0x16,
    KeyUpdate = 0x18,

    NextProtocol = 0x43,
}
}

enum_from_primitive! {
#[repr(u16)]
pub enum TlsVersion {
    Ssl30 = 0x0300,
    Tls10 = 0x0301,
    Tls11 = 0x0302,
    Tls12 = 0x0303,
    Tls13 = 0x0304,

    Tls13Draft18 = 0x7f12,
}
}

enum_from_primitive! {
#[repr(u8)]
pub enum TlsHeartbeatMessageType {
    HeartBeatRequest  = 0x1,
    HeartBeatResponse = 0x2,
}
}

enum_from_primitive! {
#[repr(u8)]
pub enum TlsRecordType {
    ChangeCipherSpec = 0x14,
    Alert = 0x15,
    Handshake = 0x16,
    ApplicationData = 0x17,
    Heartbeat = 0x18,
}
}

#[derive(Clone,PartialEq)]
pub struct TlsClientHelloContents<'a> {
    pub version: u16,
    pub rand_time: u32,
    pub rand_data: &'a[u8],
    pub session_id: Option<&'a[u8]>,
    pub ciphers: Vec<u16>,
    pub comp: Vec<u8>,

    pub ext: Option<&'a[u8]>,
}

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

#[derive(Clone,PartialEq)]
pub struct TlsServerHelloV13Contents<'a> {
    pub version: u16,
    pub random: &'a[u8],
    pub cipher: u16,

    pub ext: Option<&'a[u8]>,
}

#[derive(Clone,PartialEq)]
pub struct TlsHelloRetryContents<'a> {
    pub version: u16,

    pub ext: Option<&'a[u8]>,
}

#[derive(Clone,Debug,PartialEq)]
pub struct TlsNewSessionTicketContent<'a> {
    pub ticket_lifetime_hint: u32,
    pub ticket: &'a[u8],
}

#[derive(Clone,PartialEq)]
pub struct RawCertificate<'a> {
    pub data: &'a[u8],
}

#[derive(Clone,Debug,PartialEq)]
pub struct TlsCertificateContents<'a> {
    pub cert_chain: Vec<RawCertificate<'a> >,
}

#[derive(Clone,Debug,PartialEq)]
pub struct TlsCertificateRequestContents<'a> {
    pub cert_types: Vec<u8>,
    pub sig_hash_algs: Vec<u16>,
    // a list of DER-encoded distinguished names [X501]
    pub unparsed_ca: Vec<&'a[u8]>,
}

#[derive(Clone,PartialEq)]
pub struct TlsServerKeyExchangeContents<'a> {
    pub parameters: &'a[u8],
}

#[derive(Clone,PartialEq)]
pub struct TlsClientKeyExchangeContents<'a> {
    pub parameters: &'a[u8],
}

#[derive(Clone,Debug,PartialEq)]
pub struct TlsCertificateStatusContents<'a> {
    pub status_type: u8,
    pub blob: &'a[u8],
}

#[derive(Clone,Debug,PartialEq)]
pub struct TlsNextProtocolContent<'a> {
    pub selected_protocol: &'a[u8],
    pub padding: &'a[u8],
}

#[derive(Clone,Debug,PartialEq)]
pub struct TlsEncryptedContent<'a> {
    pub blob: &'a[u8],
}

enum_from_primitive! {
#[repr(u8)]
pub enum KeyUpdateRequest {
    NotRequested  = 0x0,
    Requested     = 0x1,
}
}

#[derive(Clone,Debug,PartialEq)]
pub enum TlsMessageHandshake<'a> {
    HelloRequest,
    ClientHello(TlsClientHelloContents<'a>),
    ServerHello(TlsServerHelloContents<'a>),
    ServerHelloV13(TlsServerHelloV13Contents<'a>),
    NewSessionTicket(TlsNewSessionTicketContent<'a>),
    HelloRetry(TlsHelloRetryContents<'a>),
    Certificate(TlsCertificateContents<'a>),
    ServerKeyExchange(TlsServerKeyExchangeContents<'a>),
    CertificateRequest(TlsCertificateRequestContents<'a>),
    ServerDone(&'a[u8]),
    CertificateVerify(&'a[u8]),
    ClientKeyExchange(TlsClientKeyExchangeContents<'a>),
    Finished(&'a[u8]),
    CertificateStatus(TlsCertificateStatusContents<'a>),
    NextProtocol(TlsNextProtocolContent<'a>),
    KeyUpdate(u8),
}

#[derive(Clone,Debug,PartialEq)]
pub struct TlsMessageApplicationData<'a>{
    pub blob: &'a[u8],
}

#[derive(Clone,Debug,PartialEq)]
pub struct TlsMessageHeartbeat<'a>{
    pub heartbeat_type: u8,
    pub payload_len: u16,
    pub payload: &'a[u8],
}

#[derive(Clone,PartialEq)]
pub struct TlsRecordHeader {
    pub record_type: u8,
    pub version: u16,
    pub len: u16,
}

#[derive(Clone,Debug,PartialEq)]
pub enum TlsMessage<'a> {
    Handshake(TlsMessageHandshake<'a>),
    ChangeCipherSpec,
    Alert(TlsMessageAlert),
    ApplicationData(TlsMessageApplicationData<'a>),
    Heartbeat(TlsMessageHeartbeat<'a>),
}

#[derive(Clone,Debug,PartialEq)]
pub struct TlsPlaintext<'a> {
    pub hdr: TlsRecordHeader,
    pub msg: Vec<TlsMessage<'a>>,
}

#[derive(Clone,Debug,PartialEq)]
pub struct TlsEncrypted<'a> {
    pub hdr: TlsRecordHeader,
    pub msg: TlsEncryptedContent<'a>,
}

#[derive(Clone,Debug,PartialEq)]
pub struct TlsRawRecord<'a> {
    pub hdr: TlsRecordHeader,
    pub data: &'a[u8],
}

impl<'a> TlsPlaintext<'a> {
    pub fn is_a(&'a self, ty:u8) -> bool {
        self.hdr.record_type == ty
    }
}






named!(parse_cipher_suites<Vec<u16> >,
    chain!(v: many0!(be_u16), || { return v })
);

named!(parse_certs<Vec<RawCertificate> >,
    many0!(
        chain!(
            len: parse_uint24 ~
            s: take!(len),
            || { RawCertificate{ data: s } }
        )
    )
);

named!(parse_tls_record_header<TlsRecordHeader>,
    chain!(
        t: be_u8 ~
        v: be_u16 ~
        l: be_u16,
    || {
            TlsRecordHeader {
                record_type: t,
                version: v,
                len: l,
            }
    }
    )
);

named!(parse_tls_handshake_msg_hello_request<TlsMessageHandshake>,
    value!(TlsMessageHandshake::HelloRequest)
);

named!(parse_tls_handshake_msg_client_hello<TlsMessageHandshake>,
    chain!(
        hv: be_u16 ~
        hrand_time: be_u32 ~
        hrand_data: take!(28) ~ // 28 as 32 (aligned) - 4 (time)
        hsidlen: be_u8 ~ // check <= 32, can be 0
        error_if!(hsidlen > 32, Err::Code(ErrorKind::Custom(128))) ~
        hsid: cond!(hsidlen > 0, take!(hsidlen as usize)) ~
        ciphers_len: be_u16 ~
        ciphers: flat_map!(take!(ciphers_len),parse_cipher_suites) ~
        //ciphers: count!(be_u16, (ciphers_len/2) as usize) ~
        comp_len: take!(1) ~
        comp: count!(be_u8, comp_len[0] as usize) ~
        ext: opt!(complete!(length_bytes!(be_u16))),
        || {
            TlsMessageHandshake::ClientHello(
                    TlsClientHelloContents {
                        version: hv,
                        rand_time: hrand_time,
                        rand_data: hrand_data,
                        session_id: hsid,
                        ciphers: ciphers,
                        comp: comp,
                        ext: ext,
                    })
        }
    )
);

named!(parse_tls_handshake_msg_server_hello_tlsv12<TlsMessageHandshake>,
    chain!(
        hv: be_u16 ~
        hrand_time: be_u32 ~
        hrand_data: take!(28) ~ // 28 as 32 (aligned) - 4 (time)
        hsidlen: be_u8 ~ // check <= 32, can be 0
        error_if!(hsidlen > 32, Err::Code(ErrorKind::Custom(128))) ~
        hsid: cond!(hsidlen > 0, take!(hsidlen as usize)) ~
        cipher: be_u16 ~
        comp: be_u8 ~
        ext: opt!(complete!(length_bytes!(be_u16))),
        || {
            TlsMessageHandshake::ServerHello(
                    TlsServerHelloContents {
                        version: hv,
                        rand_time: hrand_time,
                        rand_data: hrand_data,
                        session_id: hsid,
                        cipher: cipher,
                        compression: comp,
                        ext: ext,
                        })
        }
    )
);

named!(parse_tls_handshake_msg_server_hello_tlsv13draft<TlsMessageHandshake>,
    chain!(
        hv: be_u16 ~
        random: take!(32) ~
        cipher: be_u16 ~
        ext: opt!(complete!(length_bytes!(be_u16))),
        || {
            TlsMessageHandshake::ServerHelloV13(
                    TlsServerHelloV13Contents {
                        version: hv,
                        random: random,
                        cipher: cipher,
                        ext: ext,
                        })
        }
    )
);

named!(parse_tls_handshake_msg_server_hello<TlsMessageHandshake>,
    switch!(peek!(be_u16),
        0x7f12 => call!(parse_tls_handshake_msg_server_hello_tlsv13draft) |
        0x0303 => call!(parse_tls_handshake_msg_server_hello_tlsv12) |
        0x0302 => call!(parse_tls_handshake_msg_server_hello_tlsv12) |
        0x0301 => call!(parse_tls_handshake_msg_server_hello_tlsv12)
    )
        // 0x0300 => call!(parse_tls_handshake_msg_server_hello_sslv3)
);

// RFC 5077   Stateless TLS Session Resumption
fn parse_tls_handshake_msg_newsessionticket( i:&[u8], len: u64 ) -> IResult<&[u8], TlsMessageHandshake> {
    chain!(i,
        hint: be_u32 ~
        raw: take!(len - 4),
        || {
            TlsMessageHandshake::NewSessionTicket(
                    TlsNewSessionTicketContent {
                        ticket_lifetime_hint: hint,
                        ticket: raw,
                    })
        }
    )
}

named!(parse_tls_handshake_msg_hello_retry<TlsMessageHandshake>,
    chain!(
        hv: be_u16 ~
        ext: opt!(complete!(length_bytes!(be_u16))),
        || {
            TlsMessageHandshake::HelloRetry(
                    TlsHelloRetryContents {
                        version: hv,
                        ext: ext,
                        })
        }
    )
);

named!(parse_tls_handshake_msg_certificate<TlsMessageHandshake>,
    chain!(
        cert_len: parse_uint24 ~
        certs: flat_map!(take!(cert_len),parse_certs),
        || {
            TlsMessageHandshake::Certificate(
                    TlsCertificateContents {
                        cert_chain: certs,
                    })
        }
    )
);

fn parse_tls_handshake_msg_serverkeyexchange( i:&[u8], len: u64 ) -> IResult<&[u8], TlsMessageHandshake> {
    chain!(i,
        ext: take!(len),
        || {
            TlsMessageHandshake::ServerKeyExchange(
                    TlsServerKeyExchangeContents {
                        parameters: ext,
                    })
        }
    )
}

fn parse_tls_handshake_msg_serverdone( i:&[u8], len: u64 ) -> IResult<&[u8], TlsMessageHandshake> {
    chain!(i,
        ext: take!(len),
        || { TlsMessageHandshake::ServerDone(ext) }
    )
}

fn parse_tls_handshake_msg_certificateverify( i:&[u8], len: u64 ) -> IResult<&[u8], TlsMessageHandshake> {
    chain!(i,
        blob: take!(len),
        || { TlsMessageHandshake::CertificateVerify(blob) }
    )
}

fn parse_tls_handshake_msg_clientkeyexchange( i:&[u8], len: u64 ) -> IResult<&[u8], TlsMessageHandshake> {
    chain!(i,
        ext: take!(len),
        || {
            TlsMessageHandshake::ClientKeyExchange(
                    TlsClientKeyExchangeContents {
                        parameters: ext,
                    })
        }
    )
}

fn parse_tls_handshake_msg_certificaterequest( i:&[u8] ) -> IResult<&[u8], TlsMessageHandshake> {
    chain!(i,
        cert_types: length_count!(be_u8,be_u8) ~
        sig_hash_algs_len: be_u16 ~
        sig_hash_algs: flat_map!(take!(sig_hash_algs_len),many0!(be_u16)) ~
        ca_len: be_u16 ~
        ca: flat_map!(take!(ca_len),many0!(length_bytes!(be_u16))),
        || {
            TlsMessageHandshake::CertificateRequest(
                    TlsCertificateRequestContents {
                        cert_types: cert_types,
                        sig_hash_algs: sig_hash_algs,
                        unparsed_ca: ca,
                    })
        }
    )
}

fn parse_tls_handshake_msg_finished( i:&[u8], len: u64 ) -> IResult<&[u8], TlsMessageHandshake> {
    chain!(i,
        blob: take!(len),
        || { TlsMessageHandshake::Finished(blob) }
    )
}

/// Defined in [RFC6066]
/// if status_type == 0, blob is a OCSPResponse, as defined in [RFC2560]
/// Note that the OCSPResponse object is DER-encoded.
named!(parse_tls_handshake_msg_certificatestatus<TlsMessageHandshake>,
    chain!(
        status_type: be_u8 ~
        blob: length_bytes!(parse_uint24),
        || { TlsMessageHandshake::CertificateStatus(
                TlsCertificateStatusContents{
                    status_type:status_type,
                    blob:blob,
                })
        }
    )
);

/// NextProtocol handshake message, as defined in draft-agl-tls-nextprotoneg-03
/// Deprecated in favour of ALPN.
fn parse_tls_handshake_msg_next_protocol( i:&[u8] ) -> IResult<&[u8], TlsMessageHandshake> {
    chain!(i,
        selected_protocol: length_bytes!(be_u8) ~
        padding: length_bytes!(be_u8),
        || {
            TlsMessageHandshake::NextProtocol(
                    TlsNextProtocolContent {
                        selected_protocol: selected_protocol,
                        padding: padding,
                    })
        }
    )
}

fn parse_tls_handshake_msg_key_update( i:&[u8] ) -> IResult<&[u8], TlsMessageHandshake> {
    chain!(i,
        update_request: be_u8,
        || { TlsMessageHandshake::KeyUpdate(update_request) }
    )
}

named!(parse_tls_message_handshake<TlsMessage>,
    chain!(
        ht: be_u8 ~
        hl: parse_uint24 ~
        m: flat_map!(take!(hl),
            switch!(value!(ht),
                /*TlsHandshakeType::HelloRequest*/      0x00 => call!(parse_tls_handshake_msg_hello_request) |
                /*TlsHandshakeType::ClientHello*/       0x01 => call!(parse_tls_handshake_msg_client_hello) |
                /*TlsHandshakeType::ServerHello*/       0x02 => call!(parse_tls_handshake_msg_server_hello) |
                /*TlsHandshakeType::NewSessionTicket*/  0x04 => call!(parse_tls_handshake_msg_newsessionticket,hl) |
                /*TlsHandshakeType::HelloRetryRequest*/ 0x06 => call!(parse_tls_handshake_msg_hello_retry) |
                /*TlsHandshakeType::Certificate*/       0x0b => call!(parse_tls_handshake_msg_certificate) |
                /*TlsHandshakeType::ServerKeyExchange*/ 0x0c => call!(parse_tls_handshake_msg_serverkeyexchange,hl) |
                /*TlsHandshakeType::CertificateRequest*/ 0x0d => call!(parse_tls_handshake_msg_certificaterequest) |
                /*TlsHandshakeType::ServerDone*/        0x0e => call!(parse_tls_handshake_msg_serverdone,hl) |
                /*TlsHandshakeType::CertificateVerify*/ 0x0f => call!(parse_tls_handshake_msg_certificateverify,hl) |
                /*TlsHandshakeType::ClientKeyExchange*/ 0x10 => call!(parse_tls_handshake_msg_clientkeyexchange,hl) |
                /*TlsHandshakeType::Finished*/          0x14 => call!(parse_tls_handshake_msg_finished,hl) |
                /*TlsHandshakeType::CertificateURL*/    /*0x15 => call!(parse_tls_handshake_msg_certificateurl) |*/
                /*TlsHandshakeType::CertificateStatus*/ 0x16 => call!(parse_tls_handshake_msg_certificatestatus) |
                /*TlsHandshakeType::KeyUpdate*/         0x18 => call!(parse_tls_handshake_msg_key_update) |
                /*TlsHandshakeType::NextProtocol*/      0x43 => call!(parse_tls_handshake_msg_next_protocol)
             )
        ),
    || { TlsMessage::Handshake(m) }
    )
);

// XXX add extra verification hdr.len == 1
named!(parse_tls_message_changecipherspec<TlsMessage>,
    chain!(
        tag!([0x01]),
    || { TlsMessage::ChangeCipherSpec }
    )
);

// XXX add extra verification hdr.len == 2
named!(parse_tls_message_alert<TlsMessage>,
    chain!(
        s: be_u8 ~
        c: be_u8,
    || {
        TlsMessage::Alert(
            TlsMessageAlert {
                severity: s,
                code: c,
            })
    }
    )
);

fn parse_tls_message_applicationdata( i:&[u8] ) -> IResult<&[u8], TlsMessage> {
    chain!(i,
        b: take!(i.len()),
        || {
            TlsMessage::ApplicationData(
                TlsMessageApplicationData {
                    blob: b,
                })
    })
}

fn parse_tls_message_heartbeat( i:&[u8] ) -> IResult<&[u8], TlsMessage> {
    chain!(i,
        hb_type: be_u8 ~
        hb_len: be_u16 ~
        b: take!(i.len()-3), // payload (hb_len) + padding
        || {
            TlsMessage::Heartbeat(
                TlsMessageHeartbeat {
                    heartbeat_type: hb_type,
                    payload_len: hb_len,
                    payload: b,
                })
    })
}

// XXX check message length (not required for parser safety, but for protocol
pub fn parse_tls_record_with_header( i:&[u8], hdr:TlsRecordHeader ) -> IResult<&[u8], Vec<TlsMessage>> {
    chain!(i,
        msg: switch!(value!(hdr.record_type),
            /*TlsRecordType::ChangeCipherSpec*/ 0x14 => many1!(parse_tls_message_changecipherspec) |
            /*TlsRecordType::Alert*/            0x15 => many1!(parse_tls_message_alert) |
            /*TlsRecordType::Handshake*/        0x16 => many1!(parse_tls_message_handshake) |
            /*TlsRecordType::ApplicationData*/  0x17 => many1!(parse_tls_message_applicationdata) |
            /*TlsRecordType::Heartbeat      */  0x18 => many1!(parse_tls_message_heartbeat)
         ),
        || { msg }
    )
}


// a single record can contain multiple messages, they must share the same record type
named!(pub parse_tls_plaintext<TlsPlaintext>,
    chain!(
        hdr: parse_tls_record_header ~
        msg: flat_map!(take!(hdr.len),
            apply!(parse_tls_record_with_header,hdr.clone())
            ),
        || { TlsPlaintext {hdr:hdr, msg:msg} }
    )
);

named!(pub parse_tls_encrypted<TlsEncrypted>,
    chain!(
        hdr: parse_tls_record_header ~
        blob: take!(hdr.len),
        || { TlsEncrypted {hdr:hdr, msg:TlsEncryptedContent{ blob: blob}} }
    )
);

/// Read TLS record envelope, but do not decode data
named!(pub parse_tls_raw_record<TlsRawRecord>,
    chain!(
        hdr: parse_tls_record_header ~
        data: take!(hdr.len),
        || { TlsRawRecord {hdr:hdr, data: data} }
    )
);

// parse one packet only
named!(pub tls_parser<TlsPlaintext>,
    call!(parse_tls_plaintext)
);

// parse one packet, possibly containing multiple records
named!(pub tls_parser_many<Vec<TlsPlaintext> >,
    many1!(complete!(parse_tls_plaintext))
);
