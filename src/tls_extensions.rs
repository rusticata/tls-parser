//!
//! TLS extensions are defined in:
//!
//! - [RFC4492](https://tools.ietf.org/html/rfc4492)
//! - [RFC6066](https://tools.ietf.org/html/rfc6066)
//! - [RFC7366](https://tools.ietf.org/html/rfc7366)
//! - [RFC7627](https://tools.ietf.org/html/rfc7627)

use nom::{be_u8,be_u16,IResult,Err,ErrorKind};

enum_from_primitive! {
/// TLS extension types,
/// defined in the [IANA Transport Layer Security (TLS)
/// Extensions](http://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml)
/// registry
#[derive(Clone,Debug,PartialEq)]
#[repr(u16)]
pub enum TlsExtensionType {
    ServerName            = 0x0000,
    MaxFragmentLength     = 0x0001,
    ClientCertificate     = 0x0002,
    TrustedCaKeys         = 0x0003,
    TruncatedHMac         = 0x0004,
    StatusRequest         = 0x0005,
    UserMapping           = 0x0006,
    ClientAuthz           = 0x0007,
    ServerAuthz           = 0x0008,
    CertType              = 0x0009,
    SupportedGroups       = 0x000a, // Previously known as EllipticCurves
    EcPointFormats        = 0x000b,
    Srp                   = 0x000c,
    SignatureAlgorithms   = 0x000d,
    UseSrtp               = 0x000e,
    Heartbeat             = 0x000f,
    ApplicationLayerProtocolNegotiation = 0x0010,
    StatusRequestv2       = 0x0011,
    SignedCertificateTimestamp = 0x0012,
    ClientCertificateType = 0x0013,
    ServerCertificateType = 0x0014,
    Padding               = 0x0015,
    EncryptThenMac        = 0x0016,
    ExtendedMasterSecret  = 0x0017,
    TokenBinding          = 0x0018,
    CachedInfo            = 0x0019,

    SessionTicketTLS      = 0x0023,

    NextProtocolNegotiation = 0x3374,

    RenegotiationInfo     = 0xff01,
}
}

/// TLS extensions
///
#[derive(Clone,PartialEq)]
pub enum TlsExtension<'a>{
    SNI(Vec<(u8,&'a[u8])>),
    MaxFragmentLength(u8),
    StatusRequest(Option<(u8,&'a[u8])>),
    EllipticCurves(Vec<u16>),
    EcPointFormats(&'a[u8]),
    SignatureAlgorithms(Vec<(u8,u8)>),
    SessionTicket(&'a[u8]),
    Heartbeat(u8),
    ALPN(Vec<&'a[u8]>),

    EncryptThenMac,
    ExtendedMasterSecret,

    NextProtocolNegotiation,

    RenegotiationInfo(&'a[u8]),

    Unknown(u16,&'a[u8]),
}

named!(pub parse_tls_extension_sni_hostname<(u8,&[u8])>,
    pair!(be_u8,length_bytes!(be_u16))
);

named!(pub parse_tls_extension_sni_content<TlsExtension>,
    do_parse!(
        list_len: be_u16 >>
        v: flat_map!(take!(list_len),
            many0!(parse_tls_extension_sni_hostname)
        ) >>
        ( TlsExtension::SNI(v) )
    )
);

named!(pub parse_tls_extension_sni<TlsExtension>,
    do_parse!(
        tag!([0x00,0x00]) >>
        ext_len:  be_u16 >>
        ext: flat_map!(take!(ext_len),parse_tls_extension_sni_content) >>
        ( ext )
    )
);

/// Max fragment length [RFC6066]
named!(pub parse_tls_extension_max_fragment_length_content<TlsExtension>,
    map!(
        be_u8,
        |l| { TlsExtension::MaxFragmentLength(l) }
    )
);

/// Max fragment length [RFC6066]
named!(pub parse_tls_extension_max_fragment_length<TlsExtension>,
    do_parse!(
        tag!([0x00,0x01]) >>
        ext_len:  be_u16 >>
        ext: flat_map!(take!(ext_len),parse_tls_extension_max_fragment_length_content) >>
        ( ext )
    )
);

/// Status Request [RFC6066]
fn parse_tls_extension_status_request_content(i: &[u8], ext_len:u16) -> IResult<&[u8],TlsExtension> {
    match ext_len {
        0 => IResult::Done(i,TlsExtension::StatusRequest(None)),
        _ => {
                do_parse!(i,
                    status_type: be_u8 >>
                    request: take!(ext_len-1) >>
                    ( TlsExtension::StatusRequest(Some((status_type,request))) )
                )
        },
    }
}

named!(pub parse_tls_extension_status_request<TlsExtension>,
    do_parse!(
        tag!([0x00,0x05]) >>
        ext_len:  be_u16 >>
        ext: flat_map!(take!(ext_len),apply!(parse_tls_extension_status_request_content,ext_len)) >>
        ( ext )
    )
);

named!(pub parse_tls_extension_elliptic_curves_content<TlsExtension>,
    do_parse!(
        list_len: be_u16 >>
        l: flat_map!(take!(list_len),
            many0!(be_u16)
        ) >>
        ( TlsExtension::EllipticCurves(l) )
    )
);

named!(pub parse_tls_extension_elliptic_curves<TlsExtension>,
    do_parse!(
        tag!([0x00,0x0a]) >>
        ext_len:  be_u16 >>
        ext: flat_map!(take!(ext_len),parse_tls_extension_elliptic_curves_content) >>
        ( ext )
    )
);

named!(pub parse_tls_extension_ec_point_formats_content<TlsExtension>,
    map!(
        length_bytes!(be_u8),
        |v| { TlsExtension::EcPointFormats(v) }
    )
);

named!(pub parse_tls_extension_ec_point_formats<TlsExtension>,
    do_parse!(
        tag!([0x00,0x0b]) >>
        ext_len:  be_u16 >>
        ext: flat_map!(take!(ext_len),parse_tls_extension_ec_point_formats_content) >>
        ( ext )
    )
);

named!(pub parse_tls_extension_signature_algorithms_content<TlsExtension>,
    do_parse!(
        list_len: be_u16 >>
        l: flat_map!(take!(list_len),
            many0!(pair!(be_u8,be_u8))
        ) >>
        ( TlsExtension::SignatureAlgorithms(l) )
    )
);

named!(pub parse_tls_extension_signature_algorithms<TlsExtension>,
    do_parse!(
        tag!([0x00,0x0d]) >>
        ext_len:  be_u16 >>
        ext: flat_map!(take!(ext_len),parse_tls_extension_signature_algorithms_content) >>
        ( ext )
    )
);

named!(pub parse_tls_extension_heartbeat_content<TlsExtension>,
    map!(
        be_u8,
        |hb_mode| { TlsExtension::Heartbeat(hb_mode) }
    )
);

named!(pub parse_tls_extension_heartbeat<TlsExtension>,
    do_parse!(
        tag!([0x00,0x0f]) >>
        ext_len:  be_u16 >>
        error_if!(ext_len != 1, Err::Code(ErrorKind::Custom(128))) >>
        ext: flat_map!(take!(ext_len),parse_tls_extension_heartbeat_content) >>
        ( ext )
    )
);

named!(parse_protocol_name<&[u8]>,
    length_bytes!(be_u8)
);

/// Defined in [RFC7301]
named!(pub parse_tls_extension_alpn_content<TlsExtension>,
    do_parse!(
        list_len: be_u16 >>
        v: flat_map!(take!(list_len),many0!(complete!(parse_protocol_name))) >>
        ( TlsExtension::ALPN(v) )
    )
);

/// Encrypt-then-MAC is defined in [RFC7366]
fn parse_tls_extension_encrypt_then_mac_content(i: &[u8], ext_len:u16) -> IResult<&[u8],TlsExtension> {
    do_parse!(i,
        error_if!(ext_len != 0, Err::Code(ErrorKind::Custom(128))) >>
        ( TlsExtension::EncryptThenMac )
    )
}

/// Encrypt-then-MAC is defined in [RFC7366]
named!(pub parse_tls_extension_encrypt_then_mac<TlsExtension>,
    do_parse!(
        tag!([0x00,0x16]) >>
        ext_len:  be_u16 >>
        ext: flat_map!(take!(ext_len),apply!(parse_tls_extension_encrypt_then_mac_content,ext_len)) >>
        ( ext )
    )
);

/// Extended Master Secret is defined in [RFC7627]
fn parse_tls_extension_extended_master_secret_content(i: &[u8], ext_len:u16) -> IResult<&[u8],TlsExtension> {
    do_parse!(i,
        error_if!(ext_len != 0, Err::Code(ErrorKind::Custom(128))) >>
        ( TlsExtension::ExtendedMasterSecret )
    )
}

/// Extended Master Secret is defined in [RFC7627]
named!(pub parse_tls_extension_extended_master_secret<TlsExtension>,
    do_parse!(
        tag!([0x00,0x17]) >>
        ext_len:  be_u16 >>
        ext: flat_map!(take!(ext_len),apply!(parse_tls_extension_extended_master_secret_content,ext_len)) >>
        ( ext )
    )
);

fn parse_tls_extension_session_ticket_content(i: &[u8], ext_len:u16) -> IResult<&[u8],TlsExtension> {
    map!(i,
        take!(ext_len),
        |ext_data| { TlsExtension::SessionTicket(ext_data) }
    )
}

named!(pub parse_tls_extension_session_ticket<TlsExtension>,
    do_parse!(
        tag!([0x00,0x23]) >>
        ext_len:  be_u16 >>
        ext: flat_map!(take!(ext_len),apply!(parse_tls_extension_session_ticket_content,ext_len)) >>
        ( ext )
    )
);

/// Defined in RFC-draft-agl-tls-nextprotoneg-03. Deprecated in favour of ALPN.
fn parse_tls_extension_npn_content(i: &[u8], ext_len:u16) -> IResult<&[u8],TlsExtension> {
    do_parse!(i,
        error_if!(ext_len != 0, Err::Code(ErrorKind::Custom(128))) >>
        ( TlsExtension::NextProtocolNegotiation )
    )
}

/// Renegotiation Info, defined in [RFC5746]
named!(pub parse_tls_extension_renegotiation_info_content<TlsExtension>,
    do_parse!(
        reneg_info_len: be_u8  >>
        reneg_info    : take!(reneg_info_len) >>
        ( TlsExtension::RenegotiationInfo(reneg_info) )
    )
);

named!(pub parse_tls_extension_unknown<TlsExtension>,
    do_parse!(
        ext_type: be_u16 >>
        ext_len:  be_u16 >>
        ext_data: take!(ext_len) >>
        ( TlsExtension::Unknown(ext_type,ext_data) )
    )
);


fn parse_tls_extension_with_type(i: &[u8], ext_type:u16, ext_len:u16) -> IResult<&[u8],TlsExtension> {
    match ext_type {
        0x0000 => parse_tls_extension_sni_content(i),
        0x0001 => parse_tls_extension_max_fragment_length_content(i),
        0x0005 => parse_tls_extension_status_request_content(i,ext_len),
        0x000a => parse_tls_extension_elliptic_curves_content(i),
        0x000b => parse_tls_extension_ec_point_formats_content(i),
        0x000d => parse_tls_extension_signature_algorithms_content(i),
        0x000f => parse_tls_extension_heartbeat_content(i),
        0x0010 => parse_tls_extension_alpn_content(i),
        0x0016 => parse_tls_extension_encrypt_then_mac_content(i,ext_len),
        0x0017 => parse_tls_extension_extended_master_secret_content(i,ext_len),
        0x0023 => parse_tls_extension_session_ticket_content(i,ext_len),
        0x3374 => parse_tls_extension_npn_content(i,ext_len),
        0xff01 => parse_tls_extension_renegotiation_info_content(i),
        _      => { map!(i, take!(ext_len), |ext_data| { TlsExtension::Unknown(ext_type,ext_data) }) },
    }
}

named!(pub parse_tls_extension<TlsExtension>,
   do_parse!(
       ext_type: be_u16 >>
       ext_len:  be_u16 >>
       ext: flat_map!(take!(ext_len),call!(parse_tls_extension_with_type,ext_type,ext_len)) >>
       ( ext )
   )
);

named!(pub parse_tls_extensions<Vec<TlsExtension> >,
    many0!(parse_tls_extension)
);
