use std::fmt;
use common::IntToEnumError;

#[derive(Debug,PartialEq)]
#[repr(u8)]
pub enum TlsAlertSeverity {
    Warning = 0x01,
    Fatal   = 0x02,
}

#[derive(Debug,PartialEq)]
#[repr(u8)]
pub enum TlsAlertDescription {
    CloseNotify            = 0x00,
    UnexpectedMessage      = 0x0A,
    BadRecordMac           = 0x14,
    DecryptionFailed       = 0x15,
    RecordOverflow         = 0x16,
    DecompressionFailure   = 0x1E,
    HandshakeFailure       = 0x28,
    NoCertificate          = 0x29,
    BadCertificate         = 0x2A,
    UnsupportedCertificate = 0x2B,
    CertificateRevoked     = 0x2C,
    CertificateExpired     = 0x2D,
    CertificateUnknown     = 0x2E,
    IllegalParameter       = 0x2F,
    UnknownCa              = 0x30,
    AccessDenied           = 0x31,
    DecodeError            = 0x32,
    DecryptError           = 0x33,
    ExportRestriction      = 0x3C,
    ProtocolVersion        = 0x46,
    InsufficientSecurity   = 0x47,
    InternalError          = 0x50,
    UserCancelled          = 0x5A,
    NoRenegotiation        = 0x64,
}

#[derive(Clone,PartialEq)]
pub struct TlsMessageAlert {
    pub severity: u8,
    pub code: u8,
}

impl fmt::Display for TlsMessageAlert {
    fn fmt(&self, out: &mut fmt::Formatter) -> fmt::Result {
        // // XXX that does not always work, since Alert can be encrypted
        // let s : TlsAlertSeverity = self.severity.into();
        // let d : TlsAlertDescription = self.code.into();
        // write!(out, "TlsAlert(severity={:?},code={:?})", s, d)
        write!(out, "TlsAlert(severity={:x},code=0x{:x})", self.severity, self.code)
    }
}

impl fmt::Debug for TlsMessageAlert {
    fn fmt(&self, out: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self,out)
    }
}

impl TlsAlertSeverity {
    pub fn try_from_u8(original: u8) -> Result<Self, IntToEnumError> {
        match original {
            0x01 => Ok(TlsAlertSeverity::Warning),
            0x02 => Ok(TlsAlertSeverity::Fatal),
            n => Err(IntToEnumError::InvalidU8(n)),
        }
    }
}


impl From<u8> for TlsAlertSeverity {
    fn from(t:u8) -> TlsAlertSeverity {
        // assert!(TlsAlertSeverity::Warning as u8 <= t && t <= TlsAlertSeverity::Fatal as u8);
        // unsafe { transmute(t) }
        match TlsAlertSeverity::try_from_u8(t) {
            Ok(s)  => s,
            Err(_) => panic!("Invalid TlsAlertSeverity {}",t),
        }
    }
}

impl TlsAlertDescription {
    pub fn try_from_u8(original: u8) -> Result<Self, IntToEnumError> {
        match original {
            0x00 => Ok(TlsAlertDescription::CloseNotify),
            0x0A => Ok(TlsAlertDescription::UnexpectedMessage),
            0x14 => Ok(TlsAlertDescription::BadRecordMac),
            0x15 => Ok(TlsAlertDescription::DecryptionFailed),
            0x16 => Ok(TlsAlertDescription::RecordOverflow),
            0x1E => Ok(TlsAlertDescription::DecompressionFailure),
            0x28 => Ok(TlsAlertDescription::HandshakeFailure),
            0x29 => Ok(TlsAlertDescription::NoCertificate),
            0x2A => Ok(TlsAlertDescription::BadCertificate),
            0x2B => Ok(TlsAlertDescription::UnsupportedCertificate),
            0x2C => Ok(TlsAlertDescription::CertificateRevoked),
            0x2D => Ok(TlsAlertDescription::CertificateExpired),
            0x2E => Ok(TlsAlertDescription::CertificateUnknown),
            0x2F => Ok(TlsAlertDescription::IllegalParameter),
            0x30 => Ok(TlsAlertDescription::UnknownCa),
            0x31 => Ok(TlsAlertDescription::AccessDenied),
            0x32 => Ok(TlsAlertDescription::DecodeError),
            0x33 => Ok(TlsAlertDescription::DecryptError),
            0x3C => Ok(TlsAlertDescription::ExportRestriction),
            0x46 => Ok(TlsAlertDescription::ProtocolVersion),
            0x47 => Ok(TlsAlertDescription::InsufficientSecurity),
            0x50 => Ok(TlsAlertDescription::InternalError),
            0x5A => Ok(TlsAlertDescription::UserCancelled),
            0x64 => Ok(TlsAlertDescription::NoRenegotiation),
            n => Err(IntToEnumError::InvalidU8(n)),
        }
    }
}

impl From<u8> for TlsAlertDescription {
    fn from(t:u8) -> TlsAlertDescription {
        match TlsAlertDescription::try_from_u8(t) {
            Ok(s)  => s,
            Err(_) => panic!("Invalid TlsAlertDescription {}",t),
        }
    }
}

#[cfg(test)]
mod tests {
    use tls_alert::*;

#[test]
fn test_tlsalert_cast_severity() {
    let a = TlsAlertSeverity::Warning;

    let a_u8 = a as u8;
    assert_eq!(a_u8, 0x01);

    let b : TlsAlertSeverity = a_u8.into();
    assert_eq!(b, TlsAlertSeverity::Warning);
}

#[test]
fn test_tlsalert_cast_description() {
    let a = TlsAlertDescription::HandshakeFailure;

    let a_u8 = a as u8;
    assert_eq!(a_u8, 0x28);

    let b : TlsAlertDescription = a_u8.into();
    assert_eq!(b, TlsAlertDescription::HandshakeFailure);
}

} // mod tests
