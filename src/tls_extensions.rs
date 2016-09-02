use std::fmt;

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
    Unknown(u16,&'a[u8]),
}

impl<'a> fmt::Display for TlsExtension<'a> {
    fn fmt(&self, out: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            TlsExtension::Unknown(id,data) => write!(out, "TlsExtension(id=0x{:x},data={:?})", id, data),
        }
    }
}

impl<'a> fmt::Debug for TlsExtension<'a> {
    fn fmt(&self, out: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self,out)
    }
}

named!(pub parse_tls_extension<TlsExtension>,
    chain!(
        ext_type: u16!(true) ~
        ext_len:  u16!(true) ~
        ext_data: take!(ext_len),
        || { TlsExtension::Unknown(ext_type,ext_data) }
    )
);

named!(pub parse_tls_extensions<Vec<TlsExtension> >,
    many0!(parse_tls_extension)
);

