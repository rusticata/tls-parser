use std::fmt;
use std::str::from_utf8;

use enum_primitive::FromPrimitive;

use rusticata_macros::debug::{HexU16,HexSlice};

use tls::*;
use tls_alert::*;
use tls_dh::*;
use tls_ec::*;
use tls_extensions::*;
use tls_sign_hash::*;

pub struct SignatureSchemeU16 { pub d: u16 }
impl fmt::Debug for SignatureSchemeU16 {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match SignatureScheme::from_u16(self.d) {
            Some(ref c) => write!(fmt,"0x{:04x}({:?})",self.d,c),
            None        => write!(fmt,"0x{:04x}(Unknown signature scheme)",self.d),
        }
    }
}



// ------------------------- tls.rs ------------------------------
impl<'a> fmt::Debug for TlsClientHelloContents<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("TlsClientHelloContents")
            .field("version", &self.version)
            .field("rand_time", &self.rand_time)
            .field("rand_data", &HexSlice{d:self.rand_data})
            .field("session_id", &self.session_id.map(|o|{HexSlice{d:o}}))
            .field("ciphers", &self.ciphers)
            .field("comp", &self.comp)
            .field("ext", &self.ext.map(|o|{HexSlice{d:o}}))
            .finish()
    }
}

impl<'a> fmt::Debug for TlsServerHelloContents<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("TlsServerHelloContents")
            .field("version", &self.version)
            .field("rand_time", &self.rand_time)
            .field("rand_data", &HexSlice{d:self.rand_data})
            .field("session_id", &self.session_id.map(|o|{HexSlice{d:o}}))
            .field("cipher", &self.cipher)
            .field("compression", &self.compression)
            .field("ext", &self.ext.map(|o|{HexSlice{d:o}}))
            .finish()
    }
}

impl<'a> fmt::Debug for TlsServerHelloV13Draft18Contents<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("TlsServerHelloV13Draft18Contents")
            .field("version", &self.version)
            .field("random", &HexSlice{d:self.random})
            .field("cipher", &self.cipher)
            .field("ext", &self.ext.map(|o|{HexSlice{d:o}}))
            .finish()
    }
}

impl<'a> fmt::Debug for TlsHelloRetryRequestContents<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("TlsHelloRetryRequestContents")
            .field("version", &self.version)
            .field("ext", &self.ext.map(|o|{HexSlice{d:o}}))
            .finish()
    }
}

impl<'a> fmt::Debug for RawCertificate<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("RawCertificate")
            .field("data", &HexSlice{d:self.data})
            .finish()
    }
}

impl<'a> fmt::Debug for TlsServerKeyExchangeContents<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("TlsServerKeyExchangeContents")
            .field("parameters", &HexSlice{d:self.parameters})
            .finish()
    }
}

impl<'a> fmt::Debug for TlsClientKeyExchangeContents<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &TlsClientKeyExchangeContents::Dh(ref p)      => fmt.write_fmt(format_args!("{:?}",HexSlice{d:p})),
            &TlsClientKeyExchangeContents::Ecdh(ref p)    => fmt.write_fmt(format_args!("{:?}",p)),
            &TlsClientKeyExchangeContents::Unknown(ref p) => fmt.write_fmt(format_args!("{:?}",HexSlice{d:p})),
        }
    }
}

impl fmt::Debug for TlsRecordHeader {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("TlsRecordHeader")
            .field("type", &self.record_type)
            .field("version", &HexU16{d:self.version})
            .field("len", &self.len)
            .finish()
    }
}

// ------------------------- tls_alert.rs ------------------------------
impl fmt::Debug for TlsMessageAlert {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("TlsMessageAlert")
            .field("severity", &TlsAlertSeverity::from_u8(self.severity))
            .field("code", &self.code)
            .finish()
    }
}

// ------------------------- tls_dh.rs ------------------------------
impl<'a> fmt::Debug for ServerDHParams<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let gs = self.dh_g.len() * 8;
        fmt.debug_struct("ServerDHParams")
            .field("group size", &gs)
            .field("dh_p", &HexSlice{d:self.dh_p})
            .field("dh_g", &HexSlice{d:self.dh_g})
            .field("dh_ys", &HexSlice{d:self.dh_ys})
            .finish()
    }
}

// ------------------------- tls_ec.rs ------------------------------
impl<'a> fmt::Debug for ECParametersContent<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &ECParametersContent::ExplicitPrime(ref p) => fmt.write_fmt(format_args!("ExplicitPrime({:?})",p)),
            &ECParametersContent::ExplicitChar2(ref p) => fmt.write_fmt(format_args!("ExplicitChar2({:?})",HexSlice{d:p})),
            &ECParametersContent::NamedGroup(p)    => {
                let g = match NamedGroup::from_u16(p) {
                    Some(n) => format!("{:?}", n),
                    None    => format!("<Unknown named group 0x{:x}/{}>", p, p),
                };
                fmt.write_fmt(format_args!("{:?}",g))
            },
        }
    }
}

impl<'a> fmt::Debug for ECParameters<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let ty = match ECCurveType::from_u8(self.curve_type) {
            Some(n) => format!("{:?}", n),
            None    => format!("<Unknown curve type 0x{:x}/{}>", self.curve_type, self.curve_type),
        };
        fmt.debug_struct("ECParameters")
            .field("curve_type", &ty)
            .field("params_content", &self.params_content)
            .finish()
    }
}

// ------------------------- tls_extensions.rs ------------------------------
impl<'a> fmt::Debug for TlsExtension<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            TlsExtension::SNI(ref v) => {
                let v : Vec<_> = v.iter().map(|&(ty,n)| {
                    let s = from_utf8(n).unwrap_or("<error decoding utf8 string>");
                    format!("type=0x{:x},name={}",ty, s)
                }).collect();
                write!(fmt, "TlsExtension::SNI({:?})", v)
            },
            TlsExtension::MaxFragmentLength(l) => write!(fmt, "TlsExtension::MaxFragmentLength({})", l),
            TlsExtension::StatusRequest(data) => write!(fmt, "TlsExtension::StatusRequest({:?})", data),
            TlsExtension::EllipticCurves(ref v) => {
                let v2 : Vec<_> = v.iter().map(|&curve| {
                    match NamedGroup::from_u16(curve) {
                        Some(n) => format!("{:?}", n),
                        None    => format!("<Unknown curve 0x{:x}/{}>", curve, curve),
                    }
                }).collect();
                write!(fmt, "TlsExtension::EllipticCurves({:?})", v2)
            },
            TlsExtension::EcPointFormats(v) => write!(fmt, "TlsExtension::EcPointFormats({:?})", v),
            TlsExtension::SignatureAlgorithms(ref v) => {
                let v2 : Vec<_> = v.iter().map(|&(h,s)| {
                    let h2 = match HashAlgorithm::from_u8(h) {
                        Some(n) => format!("{:?}", n),
                        None    => format!("<Unknown hash 0x{:x}/{}>", h, h),
                    };
                    let s2 = match SignAlgorithm::from_u8(s) {
                        Some(n) => format!("{:?}", n),
                        None    => format!("<Unknown signature 0x{:x}/{}>", s, s),
                    };
                    (h2,s2)
                }).collect();
                // let v2 : Vec<_> = v.iter().map(|c|{
                //     match SignatureScheme::from_u16(*c) {
                //         Some(n) => format!("{:?}", n),
                //         None    => format!("<Unknown signature scheme 0x{:x}/{}>", c, c),
                //     }
                // }).collect();
                write!(fmt, "TlsExtension::SignatureAlgorithms({:?})", v2)
            },
            TlsExtension::SessionTicket(data) => write!(fmt, "TlsExtension::SessionTicket(data={:?})", data),
            TlsExtension::KeyShareOld(data) => write!(fmt, "TlsExtension::KeyShareOld(data={:?})", HexSlice{d:data}),
            TlsExtension::KeyShare(data) => write!(fmt, "TlsExtension::KeyShare(data={:?})", HexSlice{d:data}),
            TlsExtension::PreSharedKey(data) => write!(fmt, "TlsExtension::PreSharedKey(data={:?})", HexSlice{d:data}),
            TlsExtension::EarlyData(o) => write!(fmt, "TlsExtension::EarlyData({:?})",o),
            TlsExtension::SupportedVersions(ref v) => {
                let v2 : Vec<_> = v.iter().map(|c| { format!("0x{:x}",c) }).collect();
                write!(fmt, "TlsExtension::SupportedVersions(v={:?})", v2)
            },
            TlsExtension::Cookie(data) => write!(fmt, "TlsExtension::Cookie(data={:?})", data),
            TlsExtension::PskExchangeModes(ref v) => write!(fmt, "TlsExtension::PskExchangeModes({:?})", v),
            TlsExtension::Heartbeat(mode) => write!(fmt, "TlsExtension::Heartbeat(mode={})", mode),
            TlsExtension::ALPN(ref v) => {
                let v : Vec<_> = v.iter().map(|c| {
                    let s = from_utf8(c).unwrap_or("<error decoding utf8 string>");
                    format!("{}",s)
                }).collect();
                write!(fmt, "TlsExtension::ALPN({:?})", v)
            },
            TlsExtension::SignedCertificateTimestamp(data) => write!(fmt, "TlsExtension::SignedCertificateTimestamp(data={:?})", data),
            TlsExtension::Padding(data) => write!(fmt, "TlsExtension::Padding(data={:?})", data),
            TlsExtension::EncryptThenMac => write!(fmt, "TlsExtension::EncryptThenMac"),
            TlsExtension::ExtendedMasterSecret => write!(fmt, "TlsExtension::ExtendedMasterSecret"),
            TlsExtension::OidFilters(ref v) => {
                let v : Vec<_> = v.iter().map(|c| {
                    format!("{:?}",c)
                }).collect();
                write!(fmt, "TlsExtension::OidFilters({:?})", v)
            },
            TlsExtension::PostHandshakeAuth => write!(fmt, "TlsExtension::PostHandshakeAuth"),
            TlsExtension::NextProtocolNegotiation => write!(fmt, "TlsExtension::NextProtocolNegotiation"),
            TlsExtension::RenegotiationInfo(data) => write!(fmt, "TlsExtension::RenegotiationInfo(data={:?})", data),
            TlsExtension::Unknown(id,data) => write!(fmt, "TlsExtension::Unknown(id=0x{:x},data={:?})", id, data),
        }
    }
}

// ------------------------- tls_sign_hash.rs ------------------------------
impl fmt::Debug for HashSignAlgorithm {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("HashSignAlgorithm")
            .field("hash", &HashAlgorithm::from_u8(self.hash))
            .field("sign", &SignAlgorithm::from_u8(self.sign))
            .finish()
    }
}

impl<'a> fmt::Debug for DigitallySigned<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("DigitallySigned")
            .field("alg", &self.alg)
            .field("data", &HexSlice{d:self.data})
            .finish()
    }
}

