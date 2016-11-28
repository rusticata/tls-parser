enum_from_primitive! {
/// TLS alert severity
#[derive(Debug,PartialEq)]
#[repr(u8)]
pub enum TlsAlertSeverity {
    Warning = 0x01,
    Fatal   = 0x02,
}
}

enum_from_primitive! {
/// TLS alert description
///
/// Alerts are defined in the [IANA TLS Alert
/// Registry](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-6)
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
    InappropriateFallback  = 0x56,
    UserCancelled          = 0x5A,
    NoRenegotiation        = 0x64,
}
}

/// TLS alert message
#[derive(Clone,PartialEq)]
pub struct TlsMessageAlert {
    /// Should match a [TlsAlertSeverity](enum.TlsAlertSeverity.html) value
    pub severity: u8,
    /// Should match a [TlsAlertSeverity](enum.TlsAlertDescription.html) value
    pub code: u8,
}

#[cfg(test)]
mod tests {
    use tls_alert::*;
    use enum_primitive::FromPrimitive;

#[test]
fn test_tlsalert_cast_severity() {
    let a = TlsAlertSeverity::Warning;

    let a_u8 = a as u8;
    assert_eq!(a_u8, 0x01);

    let b = TlsAlertSeverity::from_u8(a_u8);
    assert_eq!(b, Some(TlsAlertSeverity::Warning));
}

#[test]
fn test_tlsalert_cast_description() {
    let a = TlsAlertDescription::HandshakeFailure;

    let a_u8 = a as u8;
    assert_eq!(a_u8, 0x28);

    let b = TlsAlertDescription::from_u8(a_u8);
    assert_eq!(b, Some(TlsAlertDescription::HandshakeFailure));
}

} // mod tests
