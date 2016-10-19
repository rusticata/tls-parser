use std::fmt;
use std::str::from_utf8;
use nom::{be_u8,be_u16,IResult,Err,ErrorKind};

use enum_primitive::FromPrimitive;
use common::{NamedCurve,HashAlgorithm,SignatureAlgorithm};

// See http://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
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

    Unknown(u16,&'a[u8]),
}

impl<'a> fmt::Display for TlsExtension<'a> {
    fn fmt(&self, out: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            TlsExtension::SNI(ref v) => {
                write!(out, "TlsExtension::SNI([").unwrap();
                for &(ty,name) in v {
                    let s = from_utf8(name).unwrap_or("<error decoding utf8 string>");
                    write!(out, "type=0x{:x},name={:?},", ty, s).unwrap();
                }
            write!(out, "])")
            },
            TlsExtension::MaxFragmentLength(l) => write!(out, "TlsExtension::MaxFragmentLength({})", l),
            TlsExtension::StatusRequest(data) => write!(out, "TlsExtension::StatusRequest({:?})", data),
            TlsExtension::EllipticCurves(ref v) => {
                let v2 : Vec<_> = v.iter().map(|&curve| {
                    match NamedCurve::from_u16(curve) {
                        Some(n) => format!("{:?}", n),
                        None    => format!("<Unknown curve 0x{:x}/{}>", curve, curve),
                    }
                }).collect();
                write!(out, "TlsExtension::EllipticCurves({:?})", v2)
            },
            TlsExtension::EcPointFormats(v) => write!(out, "TlsExtension::EcPointFormats({:?})", v),
            TlsExtension::SignatureAlgorithms(ref v) => {
                let v2 : Vec<_> = v.iter().map(|&(h,s)| {
                    let h2 = match HashAlgorithm::from_u8(h) {
                        Some(n) => format!("{:?}", n),
                        None    => format!("<Unknown hash 0x{:x}/{}>", h, h),
                    };
                    let s2 = match SignatureAlgorithm::from_u8(s) {
                        Some(n) => format!("{:?}", n),
                        None    => format!("<Unknown signature 0x{:x}/{}>", s, s),
                    };
                    (h2,s2)
                }).collect();
                write!(out, "TlsExtension::SignatureAlgorithms({:?})", v2)
            },
            TlsExtension::Heartbeat(mode) => write!(out, "TlsExtension::Heartbeat(mode={})", mode),
            TlsExtension::ALPN(ref v) => write!(out, "TlsExtension::ALPN({:?})", v),
            TlsExtension::EncryptThenMac => write!(out, "TlsExtension::EncryptThenMac"),
            TlsExtension::ExtendedMasterSecret => write!(out, "TlsExtension::ExtendedMasterSecret"),
            TlsExtension::NextProtocolNegotiation => write!(out, "TlsExtension::NextProtocolNegotiation"),
            TlsExtension::SessionTicket(data) => write!(out, "TlsExtension::SessionTicket(data={:?})", data),
            TlsExtension::Unknown(id,data) => write!(out, "TlsExtension::Unknown(id=0x{:x},data={:?})", id, data),
        }
    }
}

impl<'a> fmt::Debug for TlsExtension<'a> {
    fn fmt(&self, out: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self,out)
    }
}

named!(pub parse_tls_extension_sni_hostname<(u8,&[u8])>,
    pair!(be_u8,length_bytes!(be_u16))
);

named!(pub parse_tls_extension_sni_content<TlsExtension>,
    chain!(
        list_len: be_u16 ~
        v: flat_map!(take!(list_len),
            many0!(parse_tls_extension_sni_hostname)
            ),
        || { TlsExtension::SNI(v) }
    )
);

named!(pub parse_tls_extension_sni<TlsExtension>,
    chain!(
        tag!([0x00,0x00]) ~
        ext_len:  be_u16 ~
        ext: flat_map!(take!(ext_len),parse_tls_extension_sni_content),
        || { ext }
    )
);

/// Max fragment length [RFC6066]
named!(pub parse_tls_extension_max_fragment_length_content<TlsExtension>,
    chain!(
        l: be_u8,
        || { TlsExtension::MaxFragmentLength(l) }
    )
);

/// Max fragment length [RFC6066]
named!(pub parse_tls_extension_max_fragment_length<TlsExtension>,
    chain!(
        tag!([0x00,0x01]) ~
        ext_len:  be_u16 ~
        ext: flat_map!(take!(ext_len),parse_tls_extension_max_fragment_length_content),
        || { ext }
    )
);

/// Status Request [RFC6066]
fn parse_tls_extension_status_request_content(i: &[u8], ext_len:u16) -> IResult<&[u8],TlsExtension> {
    match ext_len {
        0 => IResult::Done(i,TlsExtension::StatusRequest(None)),
        _ => {
                chain!(i,
                    status_type: be_u8 ~
                    request: take!(ext_len-1),
                    || { TlsExtension::StatusRequest(Some((status_type,request))) }
                )
        },
    }
}

named!(pub parse_tls_extension_status_request<TlsExtension>,
    chain!(
        tag!([0x00,0x05]) ~
        ext_len:  be_u16 ~
        ext: flat_map!(take!(ext_len),apply!(parse_tls_extension_status_request_content,ext_len)),
        || { ext }
    )
);

named!(pub parse_tls_extension_elliptic_curves_content<TlsExtension>,
    chain!(
        list_len: be_u16 ~
        l: flat_map!(take!(list_len),
            many0!(be_u16)
            ),
        || { TlsExtension::EllipticCurves(l) }
    )
);

named!(pub parse_tls_extension_elliptic_curves<TlsExtension>,
    chain!(
        tag!([0x00,0x0a]) ~
        ext_len:  be_u16 ~
        ext: flat_map!(take!(ext_len),parse_tls_extension_elliptic_curves_content),
        || { ext }
    )
);

named!(pub parse_tls_extension_ec_point_formats_content<TlsExtension>,
    chain!(
        list_len: be_u8 ~
        v: take!(list_len),
        || { TlsExtension::EcPointFormats(v) }
    )
);

named!(pub parse_tls_extension_ec_point_formats<TlsExtension>,
    chain!(
        tag!([0x00,0x0b]) ~
        ext_len:  be_u16 ~
        ext: flat_map!(take!(ext_len),parse_tls_extension_ec_point_formats_content),
        || { ext }
    )
);

named!(pub parse_tls_extension_signature_algorithms_content<TlsExtension>,
    chain!(
        list_len: be_u16 ~
        l: flat_map!(take!(list_len),
            many0!(pair!(be_u8,be_u8))
            ),
        || { TlsExtension::SignatureAlgorithms(l) }
    )
);

named!(pub parse_tls_extension_signature_algorithms<TlsExtension>,
    chain!(
        tag!([0x00,0x0d]) ~
        ext_len:  be_u16 ~
        ext: flat_map!(take!(ext_len),parse_tls_extension_signature_algorithms_content),
        || { ext }
    )
);

named!(pub parse_tls_extension_heartbeat_content<TlsExtension>,
    chain!(
        hb_mode: be_u8,
        || { TlsExtension::Heartbeat(hb_mode) }
    )
);

named!(pub parse_tls_extension_heartbeat<TlsExtension>,
    chain!(
        tag!([0x00,0x0f]) ~
        ext_len:  be_u16 ~
        error_if!(ext_len != 1, Err::Code(ErrorKind::Custom(128))) ~
        ext: flat_map!(take!(ext_len),parse_tls_extension_heartbeat_content),
        || { ext }
    )
);

named!(parse_protocol_name<&[u8]>,
    chain!(
        len: be_u8 ~
        name: take!(len),
        || { name }
    )
);

/// Defined in [RFC7301]
named!(pub parse_tls_extension_alpn_content<TlsExtension>,
    chain!(
        list_len: be_u16 ~
        v: flat_map!(take!(list_len),many0!(complete!(parse_protocol_name))),
        || { TlsExtension::ALPN(v) }
    )
);

/// Encrypt-then-MAC is defined in [RFC7366]
fn parse_tls_extension_encrypt_then_mac_content(i: &[u8], ext_len:u16) -> IResult<&[u8],TlsExtension> {
    chain!(i,
        error_if!(ext_len != 0, Err::Code(ErrorKind::Custom(128))),
        || { TlsExtension::EncryptThenMac }
    )
}

/// Encrypt-then-MAC is defined in [RFC7366]
named!(pub parse_tls_extension_encrypt_then_mac<TlsExtension>,
    chain!(
        tag!([0x00,0x16]) ~
        ext_len:  be_u16 ~
        ext: flat_map!(take!(ext_len),apply!(parse_tls_extension_encrypt_then_mac_content,ext_len)),
        || { ext }
    )
);

/// Extended Master Secret is defined in [RFC7627]
fn parse_tls_extension_extended_master_secret_content(i: &[u8], ext_len:u16) -> IResult<&[u8],TlsExtension> {
    chain!(i,
        error_if!(ext_len != 0, Err::Code(ErrorKind::Custom(128))),
        || { TlsExtension::ExtendedMasterSecret }
    )
}

/// Extended Master Secret is defined in [RFC7627]
named!(pub parse_tls_extension_extended_master_secret<TlsExtension>,
    chain!(
        tag!([0x00,0x17]) ~
        ext_len:  be_u16 ~
        ext: flat_map!(take!(ext_len),apply!(parse_tls_extension_extended_master_secret_content,ext_len)),
        || { ext }
    )
);

fn parse_tls_extension_session_ticket_content(i: &[u8], ext_len:u16) -> IResult<&[u8],TlsExtension> {
    chain!(i,
        ext_data: take!(ext_len),
        || { TlsExtension::SessionTicket(ext_data) }
    )
}

named!(pub parse_tls_extension_session_ticket<TlsExtension>,
    chain!(
        tag!([0x00,0x23]) ~
        ext_len:  be_u16 ~
        ext: flat_map!(take!(ext_len),apply!(parse_tls_extension_session_ticket_content,ext_len)),
        || { ext }
    )
);

/// Defined in RFC-draft-agl-tls-nextprotoneg-03. Deprecated in favour of ALPN.
fn parse_tls_extension_npn_content(i: &[u8], ext_len:u16) -> IResult<&[u8],TlsExtension> {
    chain!(i,
        error_if!(ext_len != 0, Err::Code(ErrorKind::Custom(128))),
        || { TlsExtension::NextProtocolNegotiation }
    )
}

named!(pub parse_tls_extension_unknown<TlsExtension>,
    chain!(
        ext_type: be_u16 ~
        ext_len:  be_u16 ~
        ext_data: take!(ext_len),
        || { TlsExtension::Unknown(ext_type,ext_data) }
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
        _      => { chain!(i, ext_data:take!(ext_len), || { TlsExtension::Unknown(ext_type,ext_data) }) },
    }
}

named!(pub parse_tls_extension<TlsExtension>,
   chain!(
       ext_type: be_u16 ~
       ext_len:  be_u16 ~
       ext: flat_map!(take!(ext_len),call!(parse_tls_extension_with_type,ext_type,ext_len)),
       || { ext }
   )
);

named!(pub parse_tls_extensions<Vec<TlsExtension> >,
    many0!(parse_tls_extension)
);


#[cfg(test)]
mod tests {
    use tls_extensions::*;
    use nom::IResult;

static CLIENT_EXTENSIONS1: &'static [u8] = &[
    0x00, 0x00, 0x00, 0x13, 0x00, 0x11, 0x00, 0x00, 0x0e, 0x77, 0x77, 0x77, 0x2e, 0x67, 0x6f, 0x6f,
    0x67, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x0b, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02, 0x00,
    0x0a, 0x00, 0x1c, 0x00, 0x1a, 0x00, 0x17, 0x00, 0x19, 0x00, 0x1c, 0x00, 0x1b, 0x00, 0x18, 0x00,
    0x1a, 0x00, 0x16, 0x00, 0x0e, 0x00, 0x0d, 0x00, 0x0b, 0x00, 0x0c, 0x00, 0x09, 0x00, 0x0a, 0x00,
    0x23, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e, 0x06, 0x01, 0x06, 0x02, 0x06, 0x03, 0x05,
    0x01, 0x05, 0x02, 0x05, 0x03, 0x04, 0x01, 0x04, 0x02, 0x04, 0x03, 0x03, 0x01, 0x03, 0x02, 0x03,
    0x03, 0x02, 0x01, 0x02, 0x02, 0x02, 0x03, 0x00, 0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x0f, 0x00, 0x01, 0x01
];

#[test]
fn test_tls_extensions() {
    let empty = &b""[..];
    let bytes = CLIENT_EXTENSIONS1;
    let ec_point_formats = &[0,1,2];
    let ext1 = &[0, 0, 0, 0];
    let expected = IResult::Done(empty, vec![
        TlsExtension::SNI(vec![(0,b"www.google.com")]),
        TlsExtension::EcPointFormats(ec_point_formats),
        TlsExtension::EllipticCurves(vec![23, 25, 28, 27, 24, 26, 22, 14, 13, 11, 12, 9, 10]),
        TlsExtension::SessionTicket(&empty),
        TlsExtension::SignatureAlgorithms(vec![
            (6, 1), (6, 2), (6, 3), (5, 1), (5, 2), (5, 3), (4, 1), (4, 2), (4, 3), (3, 1), (3, 2), (3, 3), (2, 1), (2, 2), (2, 3)
        ]),
        TlsExtension::StatusRequest(Some((0x1,ext1))),
        TlsExtension::Heartbeat(1),
    ]);

    let res = parse_tls_extensions(bytes);

    assert_eq!(res,expected);
}

#[test]
fn test_tls_extension_max_fragment_length() {
    let empty = &b""[..];
    let bytes = &[
        0x00, 0x01, 0x00, 0x01, 0x04
    ];
    let expected = IResult::Done(empty,
        TlsExtension::MaxFragmentLength(4),
    );

    let res = parse_tls_extension(bytes);

    assert_eq!(res,expected);
}

#[test]
fn test_tls_extension_alpn() {
    let empty = &b""[..];
    let bytes = &[
        0x00, 0x10, 0x00, 0x29, 0x00, 0x27, 0x05, 0x68, 0x32, 0x2d, 0x31, 0x36,
        0x05, 0x68, 0x32, 0x2d, 0x31, 0x35, 0x05, 0x68, 0x32, 0x2d, 0x31, 0x34,
        0x02, 0x68, 0x32, 0x08, 0x73, 0x70, 0x64, 0x79, 0x2f, 0x33, 0x2e, 0x31,
        0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31
    ];
    let expected = IResult::Done(empty,
        TlsExtension::ALPN(vec![
                           b"h2-16",
                           b"h2-15",
                           b"h2-14",
                           b"h2",
                           b"spdy/3.1",
                           b"http/1.1",
        ]),
    );

    let res = parse_tls_extension(bytes);

    assert_eq!(res,expected);
}

#[test]
fn test_tls_extension_encrypt_then_mac() {
    let empty = &b""[..];
    let bytes = &[
        0x00, 0x16, 0x00, 0x00
    ];
    let expected = IResult::Done(empty,
        TlsExtension::EncryptThenMac,
    );

    let res = parse_tls_extension(bytes);

    assert_eq!(res,expected);
}

#[test]
fn test_tls_extension_extended_master_secret() {
    let empty = &b""[..];
    let bytes = &[
        0x00, 0x17, 0x00, 0x00
    ];
    let expected = IResult::Done(empty,
        TlsExtension::ExtendedMasterSecret,
    );

    let res = parse_tls_extension(bytes);

    assert_eq!(res,expected);
}

#[test]
fn test_tls_extension_npn() {
    let empty = &b""[..];
    let bytes = &[
        0x33, 0x74, 0x00, 0x00
    ];
    let expected = IResult::Done(empty,
        TlsExtension::NextProtocolNegotiation,
    );

    let res = parse_tls_extension(bytes);

    assert_eq!(res,expected);
}

}
