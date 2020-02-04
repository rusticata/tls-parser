//!
//! TLS extensions are defined in:
//!
//! - [RFC4492](https://tools.ietf.org/html/rfc4492)
//! - [RFC6066](https://tools.ietf.org/html/rfc6066)
//! - [RFC7366](https://tools.ietf.org/html/rfc7366)
//! - [RFC7627](https://tools.ietf.org/html/rfc7627)

use nom::error::ErrorKind;
use nom::number::streaming::{be_u16, be_u32, be_u8};
use nom::IResult;
use std::convert::From;

use crate::tls::{parse_tls_versions, TlsCipherSuiteID, TlsVersion};
use crate::tls_ec::{parse_named_groups, NamedGroup};

/// TLS extension types,
/// defined in the [IANA Transport Layer Security (TLS)
/// Extensions](http://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml)
/// registry
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TlsExtensionType(pub u16);

newtype_enum! {
impl display TlsExtensionType {
    ServerName                          = 0x0000, // [RFC6066]
    MaxFragmentLength                   = 0x0001,
    ClientCertificate                   = 0x0002,
    TrustedCaKeys                       = 0x0003,
    TruncatedHMac                       = 0x0004,
    StatusRequest                       = 0x0005, // [RFC6066]
    UserMapping                         = 0x0006,
    ClientAuthz                         = 0x0007,
    ServerAuthz                         = 0x0008,
    CertType                            = 0x0009,
    SupportedGroups                     = 0x000a, // [RFC4492][RFC7919]
    EcPointFormats                      = 0x000b, // [RFC4492]
    Srp                                 = 0x000c, // [RFC5054]
    SignatureAlgorithms                 = 0x000d,
    UseSrtp                             = 0x000e,
    Heartbeat                           = 0x000f,
    ApplicationLayerProtocolNegotiation = 0x0010, // [RFC7301]
    StatusRequestv2                     = 0x0011,
    SignedCertificateTimestamp          = 0x0012,
    ClientCertificateType               = 0x0013,
    ServerCertificateType               = 0x0014,
    Padding                             = 0x0015, // [RFC7685]
    EncryptThenMac                      = 0x0016,
    ExtendedMasterSecret                = 0x0017,
    TokenBinding                        = 0x0018,
    CachedInfo                          = 0x0019,

    RecordSizeLimit                     = 0x001c, // [RFC8449]

    SessionTicketTLS                    = 0x0023,

    KeyShareOld                         = 0x0028, // move to 51 in TLS 1.3 draft 23
    PreSharedKey                        = 0x0029,
    EarlyData                           = 0x002a,
    SupportedVersions                   = 0x002b,
    Cookie                              = 0x002c,
    PskExchangeModes                    = 0x002d,
    TicketEarlyDataInfo                 = 0x002e, // TLS 1.3 draft 18, removed in draft 19
    CertificateAuthorities              = 0x002f,
    OidFilters                          = 0x0030,
    PostHandshakeAuth                   = 0x0031, // TLS 1.3 draft 20
    SigAlgorithmsCert                   = 0x0032, // TLS 1.3 draft 23
    KeyShare                            = 0x0033, // TLS 1.3 draft 23

    NextProtocolNegotiation             = 0x3374,

    Grease                              = 0xfafa,

    RenegotiationInfo                   = 0xff01,
    EncryptedServerName                 = 0xffce, // draft-ietf-tls-esni
}
}

impl TlsExtensionType {
    pub fn from_u16(t: u16) -> TlsExtensionType {
        TlsExtensionType(t)
    }
}

impl From<TlsExtensionType> for u16 {
    fn from(ext: TlsExtensionType) -> u16 {
        ext.0
    }
}

/// TLS extensions
///
#[derive(Clone, PartialEq)]
pub enum TlsExtension<'a> {
    SNI(Vec<(SNIType, &'a [u8])>),
    MaxFragmentLength(u8),
    StatusRequest(Option<(CertificateStatusType, &'a [u8])>),
    EllipticCurves(Vec<NamedGroup>),
    EcPointFormats(&'a [u8]),
    SignatureAlgorithms(Vec<u16>),
    RecordSizeLimit(u16),
    SessionTicket(&'a [u8]),
    KeyShareOld(&'a [u8]),
    KeyShare(&'a [u8]),
    PreSharedKey(&'a [u8]),
    EarlyData(Option<u32>),
    SupportedVersions(Vec<TlsVersion>),
    Cookie(&'a [u8]),
    PskExchangeModes(Vec<u8>),
    Heartbeat(u8),
    ALPN(Vec<&'a [u8]>),

    SignedCertificateTimestamp(Option<&'a [u8]>),
    Padding(&'a [u8]),
    EncryptThenMac,
    ExtendedMasterSecret,

    OidFilters(Vec<OidFilter<'a>>),
    PostHandshakeAuth,

    NextProtocolNegotiation,

    RenegotiationInfo(&'a [u8]),
    EncryptedServerName {
        ciphersuite: TlsCipherSuiteID,
        group: NamedGroup,
        key_share: &'a [u8],
        record_digest: &'a [u8],
        encrypted_sni: &'a [u8],
    },

    Grease(u16, &'a [u8]),

    Unknown(TlsExtensionType, &'a [u8]),
}

impl<'a> From<&'a TlsExtension<'a>> for TlsExtensionType {
    #[rustfmt::skip]
    fn from(ext: &TlsExtension) -> TlsExtensionType {
        match ext {
            &TlsExtension::SNI(_)                        => TlsExtensionType::ServerName,
            &TlsExtension::MaxFragmentLength(_)          => TlsExtensionType::MaxFragmentLength,
            &TlsExtension::StatusRequest(_)              => TlsExtensionType::StatusRequest,
            &TlsExtension::EllipticCurves(_)             => TlsExtensionType::SupportedGroups,
            &TlsExtension::EcPointFormats(_)             => TlsExtensionType::EcPointFormats,
            &TlsExtension::SignatureAlgorithms(_)        => TlsExtensionType::SignatureAlgorithms,
            &TlsExtension::SessionTicket(_)              => TlsExtensionType::SessionTicketTLS,
            &TlsExtension::RecordSizeLimit(_)            => TlsExtensionType::RecordSizeLimit,
            &TlsExtension::KeyShareOld(_)                => TlsExtensionType::KeyShareOld,
            &TlsExtension::KeyShare(_)                   => TlsExtensionType::KeyShare,
            &TlsExtension::PreSharedKey(_)               => TlsExtensionType::PreSharedKey,
            &TlsExtension::EarlyData(_)                  => TlsExtensionType::EarlyData,
            &TlsExtension::SupportedVersions(_)          => TlsExtensionType::SupportedVersions,
            &TlsExtension::Cookie(_)                     => TlsExtensionType::Cookie,
            &TlsExtension::PskExchangeModes(_)           => TlsExtensionType::PskExchangeModes,
            &TlsExtension::Heartbeat(_)                  => TlsExtensionType::Heartbeat,
            &TlsExtension::ALPN(_)                       => TlsExtensionType::ApplicationLayerProtocolNegotiation,
            &TlsExtension::SignedCertificateTimestamp(_) => TlsExtensionType::SignedCertificateTimestamp,
            &TlsExtension::Padding(_)                    => TlsExtensionType::Padding,
            &TlsExtension::EncryptThenMac                => TlsExtensionType::EncryptThenMac,
            &TlsExtension::ExtendedMasterSecret          => TlsExtensionType::ExtendedMasterSecret,
            &TlsExtension::OidFilters(_)                 => TlsExtensionType::OidFilters,
            &TlsExtension::PostHandshakeAuth             => TlsExtensionType::PostHandshakeAuth,
            &TlsExtension::NextProtocolNegotiation       => TlsExtensionType::NextProtocolNegotiation,
            &TlsExtension::RenegotiationInfo(_)          => TlsExtensionType::RenegotiationInfo,
            &TlsExtension::EncryptedServerName{..}       => TlsExtensionType::EncryptedServerName,
            &TlsExtension::Grease(_,_)                   => TlsExtensionType::Grease,
            &TlsExtension::Unknown(x,_)                  => x
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct KeyShareEntry<'a> {
    pub group: NamedGroup, // NamedGroup
    pub kx: &'a [u8],      // Key Exchange Data
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PskKeyExchangeMode(pub u8);

newtype_enum! {
impl PskKeyExchangeMode {
    Psk    = 0,
    PskDhe = 1,
}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SNIType(pub u8);

newtype_enum! {
impl display SNIType {
    HostName = 0,
}
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct CertificateStatusType(pub u8);

newtype_enum! {
impl debug CertificateStatusType {
    OCSP = 1,
}
}

#[derive(Clone, Debug, PartialEq)]
pub struct OidFilter<'a> {
    pub cert_ext_oid: &'a [u8],
    pub cert_ext_val: &'a [u8],
}

named! {pub parse_tls_extension_sni_hostname<(SNIType,&[u8])>,
    do_parse!(
        t: be_u8 >>
        v: length_data!(be_u16) >>
        ( SNIType(t), v )
    )
}

named! {pub parse_tls_extension_sni_content<TlsExtension>,
    do_parse!(
        list_len: be_u16 >>
        v: flat_map!(take!(list_len),
            many0!(complete!(parse_tls_extension_sni_hostname))
        ) >>
        ( TlsExtension::SNI(v) )
    )
}

named! {pub parse_tls_extension_sni<TlsExtension>,
    do_parse!(
        tag!([0x00,0x00]) >>
        ext_len:  be_u16 >>
        ext: flat_map!(take!(ext_len),parse_tls_extension_sni_content) >>
        ( ext )
    )
}

/// Max fragment length [RFC6066]
pub fn parse_tls_extension_max_fragment_length_content(i: &[u8]) -> IResult<&[u8], TlsExtension> {
    map!(i, be_u8, |l| { TlsExtension::MaxFragmentLength(l) })
}

/// Max fragment length [RFC6066]
pub fn parse_tls_extension_max_fragment_length(i: &[u8]) -> IResult<&[u8], TlsExtension> {
    do_parse! {
        i,
        tag!([0x00,0x01]) >>
        ext_len:  be_u16 >>
        ext: flat_map!(take!(ext_len),parse_tls_extension_max_fragment_length_content) >>
        ( ext )
    }
}

/// Status Request [RFC6066]
fn parse_tls_extension_status_request_content(
    i: &[u8],
    ext_len: u16,
) -> IResult<&[u8], TlsExtension> {
    match ext_len {
        0 => Ok((i, TlsExtension::StatusRequest(None))),
        _ => {
            do_parse! {
                i,
                status_type: be_u8 >>
                request: take!(ext_len-1) >>
                ( TlsExtension::StatusRequest(Some((CertificateStatusType(status_type),request))) )
            }
        }
    }
}

named! {pub parse_tls_extension_status_request<TlsExtension>,
    do_parse!(
        tag!([0x00,0x05]) >>
        ext_len:  be_u16 >>
        ext: flat_map!(take!(ext_len),call!(parse_tls_extension_status_request_content,ext_len)) >>
        ( ext )
    )
}

named! {pub parse_tls_extension_elliptic_curves_content<TlsExtension>,
    flat_map!(
        length_data!(be_u16),
        map!(parse_named_groups, |x| TlsExtension::EllipticCurves(x))
    )
}

named! {pub parse_tls_extension_elliptic_curves<TlsExtension>,
    do_parse!(
        tag!([0x00,0x0a]) >>
        ext_len:  be_u16 >>
        ext: flat_map!(take!(ext_len),parse_tls_extension_elliptic_curves_content) >>
        ( ext )
    )
}

named! {pub parse_tls_extension_ec_point_formats_content<TlsExtension>,
    map!(
        length_data!(be_u8),
        |v| { TlsExtension::EcPointFormats(v) }
    )
}

named! {pub parse_tls_extension_ec_point_formats<TlsExtension>,
    do_parse!(
        tag!([0x00,0x0b]) >>
        ext_len:  be_u16 >>
        ext: flat_map!(take!(ext_len),parse_tls_extension_ec_point_formats_content) >>
        ( ext )
    )
}

named! {pub parse_tls_extension_signature_algorithms_content<TlsExtension>,
    do_parse!(
        list_len: be_u16 >>
        l: flat_map!(take!(list_len),
            many0!(complete!(be_u16))
        ) >>
        ( TlsExtension::SignatureAlgorithms(l) ) // XXX SignatureAlgorithms or SignatureScheme
    )
}

named! {pub parse_tls_extension_signature_algorithms<TlsExtension>,
    do_parse!(
        tag!([0x00,0x0d]) >>
        ext_len:  be_u16 >>
        ext: flat_map!(take!(ext_len),parse_tls_extension_signature_algorithms_content) >>
        ( ext )
    )
}

named! {pub parse_tls_extension_heartbeat_content<TlsExtension>,
    map!(
        be_u8,
        |hb_mode| { TlsExtension::Heartbeat(hb_mode) }
    )
}

named! {pub parse_tls_extension_heartbeat<TlsExtension>,
    do_parse!(
        tag!([0x00,0x0f]) >>
        ext_len:  be_u16 >>
        error_if!(ext_len != 1, ErrorKind::Verify) >>
        ext: flat_map!(take!(ext_len),parse_tls_extension_heartbeat_content) >>
        ( ext )
    )
}

named!(parse_protocol_name<&[u8]>, length_data!(be_u8));

/// Defined in [RFC7301]
pub fn parse_tls_extension_alpn_content(i: &[u8]) -> IResult<&[u8], TlsExtension> {
    do_parse! {
        i,
        list_len: be_u16 >>
        v: flat_map!(take!(list_len),many0!(complete!(parse_protocol_name))) >>
        ( TlsExtension::ALPN(v) )
    }
}

/// Defined in [RFC7685]
fn parse_tls_extension_padding_content(i: &[u8], ext_len: u16) -> IResult<&[u8], TlsExtension> {
    map!(i, take!(ext_len), |d| { TlsExtension::Padding(d) })
}

/// Defined in [RFC6962]
pub fn parse_tls_extension_signed_certificate_timestamp_content(
    i: &[u8],
) -> IResult<&[u8], TlsExtension> {
    map!(i, opt!(complete!(length_data!(be_u16))), |d| {
        TlsExtension::SignedCertificateTimestamp(d)
    })
}

/// Encrypt-then-MAC is defined in [RFC7366]
fn parse_tls_extension_encrypt_then_mac_content(
    i: &[u8],
    ext_len: u16,
) -> IResult<&[u8], TlsExtension> {
    do_parse! {
        i,
        error_if!(ext_len != 0, ErrorKind::Verify) >>
        ( TlsExtension::EncryptThenMac )
    }
}

/// Encrypt-then-MAC is defined in [RFC7366]
pub fn parse_tls_extension_encrypt_then_mac(i: &[u8]) -> IResult<&[u8], TlsExtension> {
    do_parse! {
        i,
        tag!([0x00,0x16]) >>
        ext_len:  be_u16 >>
        ext: flat_map!(take!(ext_len),call!(parse_tls_extension_encrypt_then_mac_content,ext_len)) >>
        ( ext )
    }
}

/// Extended Master Secret is defined in [RFC7627]
fn parse_tls_extension_extended_master_secret_content(
    i: &[u8],
    ext_len: u16,
) -> IResult<&[u8], TlsExtension> {
    do_parse! {
        i,
        error_if!(ext_len != 0, ErrorKind::Verify) >>
        ( TlsExtension::ExtendedMasterSecret )
    }
}

/// Extended Master Secret is defined in [RFC7627]
fn parse_tls_extension_record_size_limit(i: &[u8]) -> IResult<&[u8], TlsExtension> {
    do_parse! {
        i,
        limit: be_u16 >>
        ( TlsExtension::RecordSizeLimit(limit) )
    }
}

/// Extended Master Secret is defined in [RFC7627]
pub fn parse_tls_extension_extended_master_secret(i: &[u8]) -> IResult<&[u8], TlsExtension> {
    do_parse! {
        i,
        tag!([0x00,0x17]) >>
        ext_len:  be_u16 >>
        ext: flat_map!(take!(ext_len),call!(parse_tls_extension_extended_master_secret_content,ext_len)) >>
        ( ext )
    }
}

fn parse_tls_extension_session_ticket_content(
    i: &[u8],
    ext_len: u16,
) -> IResult<&[u8], TlsExtension> {
    map!(i, take!(ext_len), |ext_data| {
        TlsExtension::SessionTicket(ext_data)
    })
}

named! {pub parse_tls_extension_session_ticket<TlsExtension>,
    do_parse!(
        tag!([0x00,0x23]) >>
        ext_len:  be_u16 >>
        ext: flat_map!(take!(ext_len),call!(parse_tls_extension_session_ticket_content,ext_len)) >>
        ( ext )
    )
}

fn parse_tls_extension_key_share_old_content(
    i: &[u8],
    ext_len: u16,
) -> IResult<&[u8], TlsExtension> {
    map!(i, take!(ext_len), |ext_data| {
        TlsExtension::KeyShareOld(ext_data)
    })
}

fn parse_tls_extension_key_share_content(i: &[u8], ext_len: u16) -> IResult<&[u8], TlsExtension> {
    map!(i, take!(ext_len), |ext_data| {
        TlsExtension::KeyShare(ext_data)
    })
}

named! {pub parse_tls_extension_key_share<TlsExtension>,
    do_parse!(
        tag!([0x00,0x33]) >>
        ext_len:  be_u16 >>
        ext: flat_map!(take!(ext_len),call!(parse_tls_extension_key_share_content,ext_len)) >>
        ( ext )
    )
}

fn parse_tls_extension_pre_shared_key_content(
    i: &[u8],
    ext_len: u16,
) -> IResult<&[u8], TlsExtension> {
    map!(i, take!(ext_len), |ext_data| {
        TlsExtension::PreSharedKey(ext_data)
    })
}

named!(pub parse_tls_extension_pre_shared_key<TlsExtension>,
    do_parse!(
        tag!([0x00,0x28]) >>
        ext_len:  be_u16 >>
        ext: flat_map!(take!(ext_len),call!(parse_tls_extension_pre_shared_key_content,ext_len)) >>
        ( ext )
    )
);

fn parse_tls_extension_early_data_content(i: &[u8], ext_len: u16) -> IResult<&[u8], TlsExtension> {
    do_parse! {
        i,
        o: cond!(ext_len > 0, be_u32) >>
        ( TlsExtension::EarlyData(o) )
    }
}

named! {pub parse_tls_extension_early_data<TlsExtension>,
    do_parse!(
        tag!([0x00,0x2a]) >>
        ext_len:  be_u16 >>
        ext: flat_map!(take!(ext_len),call!(parse_tls_extension_early_data_content,ext_len)) >>
        ( ext )
    )
}

// TLS 1.3 draft 23
//       struct {
//           select (Handshake.msg_type) {
//               case client_hello:
//                    ProtocolVersion versions<2..254>;
//
//               case server_hello: /* and HelloRetryRequest */
//                    ProtocolVersion selected_version;
//           };
//       } SupportedVersions;
// XXX the content depends on the current message type
// XXX first case has length 1 + 2*n, while the second case has length 2
fn parse_tls_extension_supported_versions_content(
    i: &[u8],
    ext_len: u16,
) -> IResult<&[u8], TlsExtension> {
    if ext_len == 2 {
        map!(i, be_u16, |x| TlsExtension::SupportedVersions(vec![
            TlsVersion(x)
        ]))
    } else {
        do_parse! {
            i,
            _n: be_u8 >>
            // l: flat_map!(take!(ext_len-1),many0!(complete!(be_u16))) >>
            l: flat_map!(take!(ext_len-1),parse_tls_versions) >>
            ( TlsExtension::SupportedVersions(l) )
        }
    }
}

named! {pub parse_tls_extension_supported_versions<TlsExtension>,
    do_parse!(
        tag!([0x00,0x2b]) >>
        ext_len:  be_u16 >>
        ext: flat_map!(take!(ext_len),call!(parse_tls_extension_supported_versions_content,ext_len)) >>
        ( ext )
    )
}

fn parse_tls_extension_cookie_content(i: &[u8], ext_len: u16) -> IResult<&[u8], TlsExtension> {
    map!(i, take!(ext_len), |ext_data| {
        TlsExtension::Cookie(ext_data)
    })
}

named! {pub parse_tls_extension_cookie<TlsExtension>,
    do_parse!(
        tag!([0x00,0x2c]) >>
        ext_len:  be_u16 >>
        ext: flat_map!(take!(ext_len),call!(parse_tls_extension_cookie_content,ext_len)) >>
        ( ext )
    )
}

named! {pub parse_tls_extension_psk_key_exchange_modes_content<TlsExtension>,
    do_parse!(
        l: be_u8 >>
        v: take!(l) >>
        ( TlsExtension::PskExchangeModes(v.to_vec()) )
    )
}

named! {pub parse_tls_extension_psk_key_exchange_modes<TlsExtension>,
    do_parse!(
        tag!([0x00,0x2d]) >>
        ext_len:  be_u16 >>
        ext: flat_map!(take!(ext_len),call!(parse_tls_extension_psk_key_exchange_modes_content)) >>
        ( ext )
    )
}

/// Defined in RFC-draft-agl-tls-nextprotoneg-03. Deprecated in favour of ALPN.
fn parse_tls_extension_npn_content(i: &[u8], ext_len: u16) -> IResult<&[u8], TlsExtension> {
    do_parse! {
        i,
        error_if!(ext_len != 0, ErrorKind::Verify) >>
        ( TlsExtension::NextProtocolNegotiation )
    }
}

/// Renegotiation Info, defined in [RFC5746]
pub fn parse_tls_extension_renegotiation_info_content(i: &[u8]) -> IResult<&[u8], TlsExtension> {
    do_parse! {
        i,
        reneg_info_len: be_u8  >>
        reneg_info    : take!(reneg_info_len) >>
        ( TlsExtension::RenegotiationInfo(reneg_info) )
    }
}

/// Encrypted Server Name, defined in [draft-ietf-tls-esni]
pub fn parse_tls_extension_encrypted_server_name(i: &[u8]) -> IResult<&[u8], TlsExtension> {
    do_parse! {
        i,
        ciphersuite: be_u16  >>
        group: be_u16 >>
        key_share: length_data!(be_u16) >>
        record_digest: length_data!(be_u16) >>
        encrypted_sni: length_data!(be_u16) >>
        ( TlsExtension::EncryptedServerName{
            ciphersuite:TlsCipherSuiteID(ciphersuite),
            group: NamedGroup(group),
            key_share,
            record_digest,
            encrypted_sni} )
    }
}

named! {parse_tls_oid_filter<OidFilter>,
    do_parse!(
        oid: length_data!(be_u8)  >>
        val: length_data!(be_u16)  >>
        ( OidFilter{cert_ext_oid:oid, cert_ext_val:val} )
    )
}

/// Defined in TLS 1.3 draft 19
fn parse_tls_extension_oid_filters(i: &[u8]) -> IResult<&[u8], TlsExtension> {
    do_parse! {
        i,
        l: be_u16 >>
        v: flat_map!(take!(l),many0!(complete!(parse_tls_oid_filter))) >>
        ( TlsExtension::OidFilters(v) )
    }
}

/// Defined in TLS 1.3 draft 20
fn parse_tls_extension_post_handshake_auth_content(
    i: &[u8],
    ext_len: u16,
) -> IResult<&[u8], TlsExtension> {
    do_parse! {
        i,
        error_if!(ext_len != 0, ErrorKind::Verify) >>
        ( TlsExtension::PostHandshakeAuth )
    }
}

named! {pub parse_tls_extension_unknown<TlsExtension>,
    do_parse!(
        ext_type: be_u16 >>
        ext_len:  be_u16 >>
        ext_data: take!(ext_len) >>
        ( TlsExtension::Unknown(TlsExtensionType(ext_type),ext_data) )
    )
}

fn parse_tls_extension_with_type(
    i: &[u8],
    ext_type: u16,
    ext_len: u16,
) -> IResult<&[u8], TlsExtension> {
    if ext_type & 0x0f0f == 0x0a0a {
        return map!(i, take!(ext_len), |d| TlsExtension::Grease(ext_type, d));
    }
    match ext_type {
        0x0000 => parse_tls_extension_sni_content(i),
        0x0001 => parse_tls_extension_max_fragment_length_content(i),
        0x0005 => parse_tls_extension_status_request_content(i, ext_len),
        0x000a => parse_tls_extension_elliptic_curves_content(i),
        0x000b => parse_tls_extension_ec_point_formats_content(i),
        0x000d => parse_tls_extension_signature_algorithms_content(i),
        0x000f => parse_tls_extension_heartbeat_content(i),
        0x0010 => parse_tls_extension_alpn_content(i),
        0x0012 => parse_tls_extension_signed_certificate_timestamp_content(i),
        0x0015 => parse_tls_extension_padding_content(i, ext_len),
        0x0016 => parse_tls_extension_encrypt_then_mac_content(i, ext_len),
        0x0017 => parse_tls_extension_extended_master_secret_content(i, ext_len),
        0x001c => parse_tls_extension_record_size_limit(i),
        0x0023 => parse_tls_extension_session_ticket_content(i, ext_len),
        0x0028 => parse_tls_extension_key_share_old_content(i, ext_len),
        0x0029 => parse_tls_extension_pre_shared_key_content(i, ext_len),
        0x002a => parse_tls_extension_early_data_content(i, ext_len),
        0x002b => parse_tls_extension_supported_versions_content(i, ext_len),
        0x002c => parse_tls_extension_cookie_content(i, ext_len),
        0x002d => parse_tls_extension_psk_key_exchange_modes_content(i),
        0x0030 => parse_tls_extension_oid_filters(i),
        0x0031 => parse_tls_extension_post_handshake_auth_content(i, ext_len),
        0x0033 => parse_tls_extension_key_share_content(i, ext_len),
        0x3374 => parse_tls_extension_npn_content(i, ext_len),
        0xff01 => parse_tls_extension_renegotiation_info_content(i),
        0xffce => parse_tls_extension_encrypted_server_name(i),
        _ => map!(i, take!(ext_len), |ext_data| {
            TlsExtension::Unknown(TlsExtensionType(ext_type), ext_data)
        }),
    }
}

named! {pub parse_tls_extension<TlsExtension>,
   do_parse!(
       ext_type: be_u16 >>
       ext_len:  be_u16 >>
       ext: flat_map!(take!(ext_len),call!(parse_tls_extension_with_type,ext_type,ext_len)) >>
       ( ext )
   )
}

named!(pub parse_tls_extensions<Vec<TlsExtension> >,
    many0!(complete!(parse_tls_extension))
);
