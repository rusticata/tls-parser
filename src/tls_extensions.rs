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

    RenegotiationInfo     = 0xff01,
}

#[derive(Clone,PartialEq)]
pub enum TlsExtension<'a>{
    StatusRequest(u8,&'a[u8]),
    SNI(Vec<(u8,&'a[u8])>),
    EllipticCurves(Vec<u16>),
    EcPointFormats(&'a[u8]),
    SignatureAlgorithms(Vec<(u8,u8)>),
    SessionTicket(&'a[u8]),
    Heartbeat(u8),

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
            TlsExtension::StatusRequest(ty,data) => write!(out, "TlsExtension::StatusRequest({},{:?})", ty, data),
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

named!(pub parse_tls_extension_sni<TlsExtension>,
    chain!(
        tag!([0x00,0x00]) ~
        /*ext_len:*/  be_u16 ~
        list_len: be_u16 ~
        v: flat_map!(take!(list_len),
            many0!(parse_tls_extension_sni_hostname)
            ),
        || { TlsExtension::SNI(v) }
    )
);

named!(pub parse_tls_extension_status_request<TlsExtension>,
    chain!(
        tag!([0x00,0x05]) ~
        ext_len:  be_u16 ~
        status_type: be_u8 ~
        request: take!(ext_len-1),
        || { TlsExtension::StatusRequest(status_type,request) }
    )
);

named!(pub parse_tls_extension_elliptic_curves<TlsExtension>,
    chain!(
        tag!([0x00,0x0a]) ~
        /*ext_len:*/  be_u16 ~
        list_len: be_u16 ~
        l: flat_map!(take!(list_len),
            many0!(be_u16)
            ),
        || { TlsExtension::EllipticCurves(l) }
    )
);

named!(pub parse_tls_extension_ec_point_formats<TlsExtension>,
    chain!(
        tag!([0x00,0x0b]) ~
        /*ext_len:*/  be_u16 ~
        list_len: be_u8 ~
        v: take!(list_len),
        || { TlsExtension::EcPointFormats(v) }
    )
);

named!(pub parse_tls_extension_signature_algorithms<TlsExtension>,
    chain!(
        tag!([0x00,0x0d]) ~
        /*ext_len:*/  be_u16 ~
        list_len: be_u16 ~
        l: flat_map!(take!(list_len),
            many0!(pair!(be_u8,be_u8))
            ),
        || { TlsExtension::SignatureAlgorithms(l) }
    )
);

named!(pub parse_tls_extension_heartbeat<TlsExtension>,
    chain!(
        tag!([0x00,0x0f]) ~
        ext_len:  be_u16 ~
        error_if!(ext_len != 1, Err::Code(ErrorKind::Custom(128))) ~
        hb_mode: be_u8,
        || { TlsExtension::Heartbeat(hb_mode) }
    )
);

named!(pub parse_tls_extension_session_ticket<TlsExtension>,
    chain!(
        tag!([0x00,0x23]) ~
        ext_len:  be_u16 ~
        ext_data: take!(ext_len),
        || { TlsExtension::SessionTicket(ext_data) }
    )
);

named!(pub parse_tls_extension_unknown<TlsExtension>,
    chain!(
        ext_type: be_u16 ~
        ext_len:  be_u16 ~
        ext_data: take!(ext_len),
        || { TlsExtension::Unknown(ext_type,ext_data) }
    )
);


named!(pub parse_tls_extension<TlsExtension>,
   alt!(
      parse_tls_extension_sni |
      parse_tls_extension_status_request |
      parse_tls_extension_elliptic_curves |
      parse_tls_extension_ec_point_formats |
      parse_tls_extension_signature_algorithms |
      parse_tls_extension_heartbeat |
      parse_tls_extension_session_ticket |
      parse_tls_extension_unknown
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
        TlsExtension::StatusRequest(0x1,ext1),
        TlsExtension::Heartbeat(1),
    ]);

    let res = parse_tls_extensions(bytes);
    println!("ext: {:?}", res);
    println!("-------------------");

    assert_eq!(res,expected);
}

}
