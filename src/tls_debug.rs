use std::fmt;
use std::str::from_utf8;

use rusticata_macros::debug::{HexU16,HexSlice};

use tls::*;
use tls_alert::*;
use tls_dh::*;
use tls_ec::*;
use tls_extensions::*;
use tls_sign_hash::*;



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
            .field("severity", &self.severity)
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
            &ECParametersContent::NamedGroup(p)    => write!(fmt, "{}", p),
        }
    }
}

impl<'a> fmt::Debug for ECParameters<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("ECParameters")
            .field("curve_type", &format!("{}",self.curve_type))
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
                    format!("type={},name={}",ty, s)
                }).collect();
                write!(fmt, "TlsExtension::SNI({:?})", v)
            },
            TlsExtension::MaxFragmentLength(l) => write!(fmt, "TlsExtension::MaxFragmentLength({})", l),
            TlsExtension::StatusRequest(data) => write!(fmt, "TlsExtension::StatusRequest({:?})", data),
            TlsExtension::EllipticCurves(ref v) => {
                let v2 : Vec<_> = v.iter().map(|&curve| {
                    format!("{}", curve)
                }).collect();
                write!(fmt, "TlsExtension::EllipticCurves({:?})", v2)
            },
            TlsExtension::EcPointFormats(v) => write!(fmt, "TlsExtension::EcPointFormats({:?})", v),
            TlsExtension::SignatureAlgorithms(ref v) => {
                let v2 : Vec<_> = v.iter().map(|&alg| {
                    let s = format!("{}", SignatureScheme(alg));
                    if s.starts_with("SignatureScheme") {
                        format!("{}", SignatureAndHashAlgorithm{hash:HashAlgorithm((alg>>8) as u8), sign:SignAlgorithm((alg&0xff) as u8)})
                    } else {
                        s
                    }
                }).collect();
                write!(fmt, "TlsExtension::SignatureAlgorithms({:?})", v2)
            },
            TlsExtension::SessionTicket(data) => write!(fmt, "TlsExtension::SessionTicket(data={:?})", data),
            TlsExtension::KeyShareOld(data) => write!(fmt, "TlsExtension::KeyShareOld(data={:?})", HexSlice{d:data}),
            TlsExtension::KeyShare(data) => write!(fmt, "TlsExtension::KeyShare(data={:?})", HexSlice{d:data}),
            TlsExtension::PreSharedKey(data) => write!(fmt, "TlsExtension::PreSharedKey(data={:?})", HexSlice{d:data}),
            TlsExtension::EarlyData(o) => write!(fmt, "TlsExtension::EarlyData({:?})",o),
            TlsExtension::SupportedVersions(ref v) => {
                let v2 : Vec<_> = v.iter().map(|c| { format!("{}",c) }).collect();
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
            TlsExtension::Grease(t,data) => write!(fmt, "TlsExtension::Grease(0x{:x},data={:?})", t, HexSlice{d:data}),
            TlsExtension::Unknown(t,data) => write!(fmt, "TlsExtension::Unknown(type=0x{:x},data={:?})", t.0, data),
        }
    }
}

// ------------------------- tls_sign_hash.rs ------------------------------
impl fmt::Display for SignatureAndHashAlgorithm {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "HashSign({},{})", self.hash, self.sign)
    }
}

impl fmt::Debug for SignatureAndHashAlgorithm {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "SignatureAndHashAlgorithm({},{})", self.hash, self.sign)
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

