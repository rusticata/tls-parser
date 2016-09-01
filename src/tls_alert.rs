use std::fmt;

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
        let s : TlsAlertSeverity = self.severity.into();
        let d : TlsAlertDescription = self.code.into();
        write!(out, "TlsAlert(severity={:?},code={:?})", s, d)
    }
}

impl fmt::Debug for TlsMessageAlert {
    fn fmt(&self, out: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self,out)
    }
}

// use std::mem::transmute;

impl From<u8> for TlsAlertSeverity {
    fn from(t:u8) -> TlsAlertSeverity {
        // assert!(TlsAlertSeverity::Warning as u8 <= t && t <= TlsAlertSeverity::Fatal as u8);
        // unsafe { transmute(t) }
        match t {
            0x01 => TlsAlertSeverity::Warning,
            0x02 => TlsAlertSeverity::Fatal,
            _    => panic!("boo"),
        }
    }
}

impl From<u8> for TlsAlertDescription {
    fn from(t:u8) -> TlsAlertDescription {
        match t {
            0x00 => TlsAlertDescription::CloseNotify,
            0x0A => TlsAlertDescription::UnexpectedMessage,
            0x14 => TlsAlertDescription::BadRecordMac,
            0x15 => TlsAlertDescription::DecryptionFailed,
            0x16 => TlsAlertDescription::RecordOverflow,
            0x1E => TlsAlertDescription::DecompressionFailure,
            0x28 => TlsAlertDescription::HandshakeFailure,
            0x29 => TlsAlertDescription::NoCertificate,
            0x2A => TlsAlertDescription::BadCertificate,
            0x2B => TlsAlertDescription::UnsupportedCertificate,
            0x2C => TlsAlertDescription::CertificateRevoked,
            0x2D => TlsAlertDescription::CertificateExpired,
            0x2E => TlsAlertDescription::CertificateUnknown,
            0x2F => TlsAlertDescription::IllegalParameter,
            0x30 => TlsAlertDescription::UnknownCa,
            0x31 => TlsAlertDescription::AccessDenied,
            0x32 => TlsAlertDescription::DecodeError,
            0x33 => TlsAlertDescription::DecryptError,
            0x3C => TlsAlertDescription::ExportRestriction,
            0x46 => TlsAlertDescription::ProtocolVersion,
            0x47 => TlsAlertDescription::InsufficientSecurity,
            0x50 => TlsAlertDescription::InternalError,
            0x5A => TlsAlertDescription::UserCancelled,
            0x64 => TlsAlertDescription::NoRenegotiation,
            _    => panic!("boo"),
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
