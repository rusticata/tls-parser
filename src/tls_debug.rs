use std::fmt;
use std::str::from_utf8;

use enum_primitive::FromPrimitive;

use tls::*;
use tls_alert::*;
use tls_ciphers::*;
use tls_dh::*;
use tls_ec::*;
use tls_extensions::*;
use tls_sign_hash::*;

pub struct HexU8 { pub d: u8 }
impl fmt::Debug for HexU8 {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt,"0x{:02x}",self.d)
    }
}

pub struct HexU16 { pub d: u16 }
impl fmt::Debug for HexU16 {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt,"0x{:04x}",self.d)
    }
}

pub struct HexSlice<'a> { pub d: &'a[u8] }
impl<'a> fmt::Debug for HexSlice<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let s : Vec<_> = self.d.iter().map(|&i|{
            format!("{:02x}", i)
        }).collect();
        write!(fmt,"[{}]",s.join(" "))
    }
}

pub struct CipherU16 { pub d: u16 }
impl fmt::Debug for CipherU16 {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match TlsCipherSuite::from_id(self.d) {
            Some(ref c) => write!(fmt,"0x{:04x}({})",self.d,c.name),
            None        => write!(fmt,"0x{:04x}(Unknown cipher)",self.d),
        }
    }
}



// ------------------------- tls.rs ------------------------------
//
impl<'a> fmt::Debug for TlsClientHelloContents<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let v_ciphers : Vec<_> = self.ciphers.iter().map(|u|{CipherU16{d:*u}}).collect();
        let v_comp : Vec<_> = self.comp.iter().map(|u|{HexU8{d:*u}}).collect();
        fmt.debug_struct("TlsClientHelloContents")
            .field("version", &HexU16{d:self.version})
            .field("rand_time", &self.rand_time)
            .field("rand_data", &HexSlice{d:self.rand_data})
            .field("session_id", &self.session_id.map(|o|{HexSlice{d:o}}))
            .field("ciphers", &v_ciphers)
            .field("comp", &v_comp)
            .field("ext", &self.ext.map(|o|{HexSlice{d:o}}))
            .finish()
    }
}

impl<'a> fmt::Debug for TlsServerHelloContents<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("TlsServerHelloContents")
            .field("version", &HexU16{d:self.version})
            .field("rand_time", &self.rand_time)
            .field("rand_data", &HexSlice{d:self.rand_data})
            .field("session_id", &self.session_id.map(|o|{HexSlice{d:o}}))
            .field("cipher", &CipherU16{d:self.cipher})
            .field("compression", &HexU8{d:self.compression})
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
        fmt.debug_struct("TlsClientKeyExchangeContents")
            .field("parameters", &HexSlice{d:self.parameters})
            .finish()
    }
}

impl fmt::Debug for TlsRecordHeader {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.debug_struct("TlsRecordHeader")
            .field("type", &HexU8{d:self.record_type})
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

// ------------------------- tls_extensions.rs ------------------------------
impl<'a> fmt::Debug for TlsExtension<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            TlsExtension::SNI(ref v) => {
                write!(fmt, "TlsExtension::SNI([").unwrap();
                for &(ty,name) in v {
                    let s = from_utf8(name).unwrap_or("<error decoding utf8 string>");
                    write!(fmt, "type=0x{:x},name={:?},", ty, s).unwrap();
                }
            write!(fmt, "])")
            },
            TlsExtension::MaxFragmentLength(l) => write!(fmt, "TlsExtension::MaxFragmentLength({})", l),
            TlsExtension::StatusRequest(data) => write!(fmt, "TlsExtension::StatusRequest({:?})", data),
            TlsExtension::EllipticCurves(ref v) => {
                let v2 : Vec<_> = v.iter().map(|&curve| {
                    match NamedCurve::from_u16(curve) {
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
                write!(fmt, "TlsExtension::SignatureAlgorithms({:?})", v2)
            },
            TlsExtension::Heartbeat(mode) => write!(fmt, "TlsExtension::Heartbeat(mode={})", mode),
            TlsExtension::ALPN(ref v) => write!(fmt, "TlsExtension::ALPN({:?})", v),
            TlsExtension::EncryptThenMac => write!(fmt, "TlsExtension::EncryptThenMac"),
            TlsExtension::ExtendedMasterSecret => write!(fmt, "TlsExtension::ExtendedMasterSecret"),
            TlsExtension::NextProtocolNegotiation => write!(fmt, "TlsExtension::NextProtocolNegotiation"),
            TlsExtension::SessionTicket(data) => write!(fmt, "TlsExtension::SessionTicket(data={:?})", data),
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

