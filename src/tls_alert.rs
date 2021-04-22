use nom_derive::*;
use rusticata_macros::newtype_enum;

/// TLS alert severity
#[derive(Clone, Copy, Debug, PartialEq, Eq, Nom)]
pub struct TlsAlertSeverity(pub u8);

newtype_enum! {
impl display TlsAlertSeverity {
    Warning = 0x01,
    Fatal   = 0x02
}
}

/// TLS alert description
///
/// Alerts are defined in the [IANA TLS Alert
/// Registry](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-6)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Nom)]
pub struct TlsAlertDescription(pub u8);

newtype_enum! {
impl display TlsAlertDescription {
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
    MissingExtension       = 0x6d,
    UnsupportedExtension   = 0x6e,
    CertUnobtainable       = 0x6f,
    UnrecognizedName       = 0x70,
    BadCertStatusResponse  = 0x71,
    BadCertHashValue       = 0x72,
    UnknownPskIdentity     = 0x73,
    CertificateRequired    = 0x74,
    NoApplicationProtocol  = 0x78 // [RFC7301]
}
}

/// TLS alert message
#[derive(Clone, PartialEq, Nom)]
pub struct TlsMessageAlert {
    /// Should match a [TlsAlertSeverity](enum.TlsAlertSeverity.html) value
    pub severity: TlsAlertSeverity,
    /// Should match a [TlsAlertDescription](enum.TlsAlertDescription.html) value
    pub code: TlsAlertDescription,
}

#[cfg(test)]
mod tests {
    use crate::tls_alert::*;

    #[test]
    fn test_tlsalert_cast_severity() {
        let a = TlsAlertSeverity::Warning;

        let a_u8 = a.0;
        assert_eq!(a_u8, 0x01);

        let b = TlsAlertSeverity(a_u8);
        assert_eq!(b, TlsAlertSeverity::Warning);

        let s = format!("{}", b);
        assert_eq!(s, "Warning");

        let s = format!("{}", TlsAlertSeverity(129));
        assert_eq!(s, "TlsAlertSeverity(129 / 0x81)");
    }

    #[test]
    fn test_tlsalert_cast_description() {
        let a = TlsAlertDescription::HandshakeFailure;

        let a_u8 = a.0;
        assert_eq!(a_u8, 0x28);

        let b = TlsAlertDescription(a_u8);
        assert_eq!(b, TlsAlertDescription::HandshakeFailure);
    }
} // mod tests
