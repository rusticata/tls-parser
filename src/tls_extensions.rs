//!
//! TLS extensions are defined in:
//!
//! - [RFC4492](https://tools.ietf.org/html/rfc4492)
//! - [RFC6066](https://tools.ietf.org/html/rfc6066)
//! - [RFC7366](https://tools.ietf.org/html/rfc7366)
//! - [RFC7627](https://tools.ietf.org/html/rfc7627)

use nom::{be_u8,be_u16,be_u32,IResult,ErrorKind};
use std::convert::From;

/// TLS extension types,
/// defined in the [IANA Transport Layer Security (TLS)
/// Extensions](http://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml)
/// registry
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TlsExtensionType(u16);

#[allow(non_upper_case_globals)]
impl TlsExtensionType {
    pub const ServerName            : TlsExtensionType               = TlsExtensionType(0x0000); // [RFC6066]
    pub const MaxFragmentLength     : TlsExtensionType               = TlsExtensionType(0x0001);
    pub const ClientCertificate     : TlsExtensionType               = TlsExtensionType(0x0002);
    pub const TrustedCaKeys         : TlsExtensionType               = TlsExtensionType(0x0003);
    pub const TruncatedHMac         : TlsExtensionType               = TlsExtensionType(0x0004);
    pub const StatusRequest         : TlsExtensionType               = TlsExtensionType(0x0005);
    pub const UserMapping           : TlsExtensionType               = TlsExtensionType(0x0006);
    pub const ClientAuthz           : TlsExtensionType               = TlsExtensionType(0x0007);
    pub const ServerAuthz           : TlsExtensionType               = TlsExtensionType(0x0008);
    pub const CertType              : TlsExtensionType               = TlsExtensionType(0x0009);
    pub const SupportedGroups       : TlsExtensionType               = TlsExtensionType(0x000a); // [RFC4492][RFC7919]
    pub const EcPointFormats        : TlsExtensionType               = TlsExtensionType(0x000b); // [RFC4492]
    pub const Srp                   : TlsExtensionType               = TlsExtensionType(0x000c); // [RFC5054]
    pub const SignatureAlgorithms   : TlsExtensionType               = TlsExtensionType(0x000d);
    pub const UseSrtp               : TlsExtensionType               = TlsExtensionType(0x000e);
    pub const Heartbeat             : TlsExtensionType               = TlsExtensionType(0x000f);
    pub const ApplicationLayerProtocolNegotiation : TlsExtensionType = TlsExtensionType(0x0010); // [RFC7301]
    pub const StatusRequestv2       : TlsExtensionType               = TlsExtensionType(0x0011);
    pub const SignedCertificateTimestamp : TlsExtensionType          = TlsExtensionType(0x0012);
    pub const ClientCertificateType : TlsExtensionType               = TlsExtensionType(0x0013);
    pub const ServerCertificateType : TlsExtensionType               = TlsExtensionType(0x0014);
    pub const Padding               : TlsExtensionType               = TlsExtensionType(0x0015); // [RFC7685]
    pub const EncryptThenMac        : TlsExtensionType               = TlsExtensionType(0x0016);
    pub const ExtendedMasterSecret  : TlsExtensionType               = TlsExtensionType(0x0017);
    pub const TokenBinding          : TlsExtensionType               = TlsExtensionType(0x0018);
    pub const CachedInfo            : TlsExtensionType               = TlsExtensionType(0x0019);

    pub const SessionTicketTLS      : TlsExtensionType               = TlsExtensionType(0x0023);

    pub const KeyShareOld           : TlsExtensionType               = TlsExtensionType(0x0028); // move to 51 in TLS 1.3 draft 23
    pub const PreSharedKey          : TlsExtensionType               = TlsExtensionType(0x0029);
    pub const EarlyData             : TlsExtensionType               = TlsExtensionType(0x002a);
    pub const SupportedVersions     : TlsExtensionType               = TlsExtensionType(0x002b);
    pub const Cookie                : TlsExtensionType               = TlsExtensionType(0x002c);
    pub const PskExchangeModes      : TlsExtensionType               = TlsExtensionType(0x002d);
    pub const TicketEarlyDataInfo   : TlsExtensionType               = TlsExtensionType(0x002e); // TLS 1.3 draft 18, removed in draft 19
    pub const CertificateAuthorities : TlsExtensionType              = TlsExtensionType(0x002f);
    pub const OidFilters            : TlsExtensionType               = TlsExtensionType(0x0030);
    pub const PostHandshakeAuth     : TlsExtensionType               = TlsExtensionType(0x0031); // TLS 1.3 draft 20
    pub const SigAlgorithmsCert     : TlsExtensionType               = TlsExtensionType(0x0032); // TLS 1.3 draft 23
    pub const KeyShare              : TlsExtensionType               = TlsExtensionType(0x0033); // TLS 1.3 draft 23

    pub const NextProtocolNegotiation : TlsExtensionType             = TlsExtensionType(0x3374);

    pub const RenegotiationInfo     : TlsExtensionType               = TlsExtensionType(0xff01);

    pub fn from_u16(t: u16) -> TlsExtensionType { TlsExtensionType(t) }
}

impl From<TlsExtensionType> for u16 {
    fn from(ext: TlsExtensionType) -> u16 { ext.0 }
}

/// TLS extensions
///
#[derive(Clone,PartialEq)]
pub enum TlsExtension<'a>{
    SNI(Vec<(u8,&'a[u8])>),
    MaxFragmentLength(u8),
    StatusRequest(Option<(u8,&'a[u8])>),
    EllipticCurves(Vec<u16>),
    EcPointFormats(&'a[u8]),
    SignatureAlgorithms(Vec<(u8,u8)>),
    SessionTicket(&'a[u8]),
    KeyShareOld(&'a[u8]),
    KeyShare(&'a[u8]),
    PreSharedKey(&'a[u8]),
    EarlyData(Option<u32>),
    SupportedVersions(Vec<u16>),
    Cookie(&'a[u8]),
    PskExchangeModes(Vec<u8>),
    Heartbeat(u8),
    ALPN(Vec<&'a[u8]>),

    SignedCertificateTimestamp(Option<(&'a[u8])>),
    Padding(&'a[u8]),
    EncryptThenMac,
    ExtendedMasterSecret,

    OidFilters(Vec<OidFilter<'a>>),
    PostHandshakeAuth,

    NextProtocolNegotiation,

    RenegotiationInfo(&'a[u8]),

    Unknown(u16,&'a[u8]),
}


impl<'a> From<&'a TlsExtension<'a>> for TlsExtensionType {
    fn from(ext: &TlsExtension) -> TlsExtensionType {
        match ext {
            &TlsExtension::SNI(_)                        => TlsExtensionType::ServerName,
            &TlsExtension::MaxFragmentLength(_)          => TlsExtensionType::MaxFragmentLength,
            &TlsExtension::StatusRequest(_)              => TlsExtensionType::StatusRequest,
            &TlsExtension::EllipticCurves(_)             => TlsExtensionType::SupportedGroups,
            &TlsExtension::EcPointFormats(_)             => TlsExtensionType::EcPointFormats,
            &TlsExtension::SignatureAlgorithms(_)        => TlsExtensionType::SignatureAlgorithms,
            &TlsExtension::SessionTicket(_)              => TlsExtensionType::SessionTicketTLS,
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
            &TlsExtension::Unknown(x,_)                  => TlsExtensionType(x)
        }
    }
}

#[derive(Clone,Debug,PartialEq)]
pub struct KeyShareEntry<'a> {
    pub group: u16,  // NamedGroup
    pub kx: &'a[u8], // Key Exchange Data
}

enum_from_primitive!{
#[derive(Clone,Debug,PartialEq)]
#[repr(u8)]
pub enum PskKeyExchangeMode {
    Psk    = 0,
    PskDhe = 1,
}
}

enum_from_primitive!{
#[derive(Clone,Debug,PartialEq)]
#[repr(u8)]
pub enum SNIType {
    HostName = 0,
}
}

#[derive(Clone,Debug,PartialEq)]
pub struct OidFilter<'a> {
    pub cert_ext_oid: &'a[u8],
    pub cert_ext_val: &'a[u8],
}




named!(pub parse_tls_extension_sni_hostname<(u8,&[u8])>,
    pair!(be_u8,length_bytes!(be_u16))
);

named!(pub parse_tls_extension_sni_content<TlsExtension>,
    do_parse!(
        list_len: be_u16 >>
        v: flat_map!(take!(list_len),
            many0!(complete!(parse_tls_extension_sni_hostname))
        ) >>
        ( TlsExtension::SNI(v) )
    )
);

named!(pub parse_tls_extension_sni<TlsExtension>,
    do_parse!(
        tag!([0x00,0x00]) >>
        ext_len:  be_u16 >>
        ext: flat_map!(take!(ext_len),parse_tls_extension_sni_content) >>
        ( ext )
    )
);

/// Max fragment length [RFC6066]
named!(pub parse_tls_extension_max_fragment_length_content<TlsExtension>,
    map!(
        be_u8,
        |l| { TlsExtension::MaxFragmentLength(l) }
    )
);

/// Max fragment length [RFC6066]
named!(pub parse_tls_extension_max_fragment_length<TlsExtension>,
    do_parse!(
        tag!([0x00,0x01]) >>
        ext_len:  be_u16 >>
        ext: flat_map!(take!(ext_len),parse_tls_extension_max_fragment_length_content) >>
        ( ext )
    )
);

/// Status Request [RFC6066]
fn parse_tls_extension_status_request_content(i: &[u8], ext_len:u16) -> IResult<&[u8],TlsExtension> {
    match ext_len {
        0 => Ok((i,TlsExtension::StatusRequest(None))),
        _ => {
                do_parse!(i,
                    status_type: be_u8 >>
                    request: take!(ext_len-1) >>
                    ( TlsExtension::StatusRequest(Some((status_type,request))) )
                )
        },
    }
}

named!(pub parse_tls_extension_status_request<TlsExtension>,
    do_parse!(
        tag!([0x00,0x05]) >>
        ext_len:  be_u16 >>
        ext: flat_map!(take!(ext_len),apply!(parse_tls_extension_status_request_content,ext_len)) >>
        ( ext )
    )
);

named!(pub parse_tls_extension_elliptic_curves_content<TlsExtension>,
    do_parse!(
        list_len: be_u16 >>
        l: flat_map!(take!(list_len),
            many0!(complete!(be_u16))
        ) >>
        ( TlsExtension::EllipticCurves(l) )
    )
);

named!(pub parse_tls_extension_elliptic_curves<TlsExtension>,
    do_parse!(
        tag!([0x00,0x0a]) >>
        ext_len:  be_u16 >>
        ext: flat_map!(take!(ext_len),parse_tls_extension_elliptic_curves_content) >>
        ( ext )
    )
);

named!(pub parse_tls_extension_ec_point_formats_content<TlsExtension>,
    map!(
        length_bytes!(be_u8),
        |v| { TlsExtension::EcPointFormats(v) }
    )
);

named!(pub parse_tls_extension_ec_point_formats<TlsExtension>,
    do_parse!(
        tag!([0x00,0x0b]) >>
        ext_len:  be_u16 >>
        ext: flat_map!(take!(ext_len),parse_tls_extension_ec_point_formats_content) >>
        ( ext )
    )
);

named!(pub parse_tls_extension_signature_algorithms_content<TlsExtension>,
    do_parse!(
        list_len: be_u16 >>
        l: flat_map!(take!(list_len),
            many0!(complete!(pair!(be_u8,be_u8)))
        ) >>
        ( TlsExtension::SignatureAlgorithms(l) )
    )
);

named!(pub parse_tls_extension_signature_algorithms<TlsExtension>,
    do_parse!(
        tag!([0x00,0x0d]) >>
        ext_len:  be_u16 >>
        ext: flat_map!(take!(ext_len),parse_tls_extension_signature_algorithms_content) >>
        ( ext )
    )
);

named!(pub parse_tls_extension_heartbeat_content<TlsExtension>,
    map!(
        be_u8,
        |hb_mode| { TlsExtension::Heartbeat(hb_mode) }
    )
);

named!(pub parse_tls_extension_heartbeat<TlsExtension>,
    do_parse!(
        tag!([0x00,0x0f]) >>
        ext_len:  be_u16 >>
        error_if!(ext_len != 1, ErrorKind::Custom(128)) >>
        ext: flat_map!(take!(ext_len),parse_tls_extension_heartbeat_content) >>
        ( ext )
    )
);

named!(parse_protocol_name<&[u8]>,
    length_bytes!(be_u8)
);

/// Defined in [RFC7301]
named!(pub parse_tls_extension_alpn_content<TlsExtension>,
    do_parse!(
        list_len: be_u16 >>
        v: flat_map!(take!(list_len),many0!(complete!(parse_protocol_name))) >>
        ( TlsExtension::ALPN(v) )
    )
);

/// Defined in [RFC7685]
fn parse_tls_extension_padding_content(i: &[u8], ext_len:u16) -> IResult<&[u8],TlsExtension> {
    map!(i,
        take!(ext_len),
        |d| { TlsExtension::Padding(d) }
    )
}

/// Defined in [RFC6962]
named!(pub parse_tls_extension_signed_certificate_timestamp_content<TlsExtension>,
    map!(
        opt!(length_bytes!(be_u16)),
        |d| { TlsExtension::SignedCertificateTimestamp(d) }
    )
);

/// Encrypt-then-MAC is defined in [RFC7366]
fn parse_tls_extension_encrypt_then_mac_content(i: &[u8], ext_len:u16) -> IResult<&[u8],TlsExtension> {
    do_parse!(i,
        error_if!(ext_len != 0, ErrorKind::Custom(128)) >>
        ( TlsExtension::EncryptThenMac )
    )
}

/// Encrypt-then-MAC is defined in [RFC7366]
named!(pub parse_tls_extension_encrypt_then_mac<TlsExtension>,
    do_parse!(
        tag!([0x00,0x16]) >>
        ext_len:  be_u16 >>
        ext: flat_map!(take!(ext_len),apply!(parse_tls_extension_encrypt_then_mac_content,ext_len)) >>
        ( ext )
    )
);

/// Extended Master Secret is defined in [RFC7627]
fn parse_tls_extension_extended_master_secret_content(i: &[u8], ext_len:u16) -> IResult<&[u8],TlsExtension> {
    do_parse!(i,
        error_if!(ext_len != 0, ErrorKind::Custom(128)) >>
        ( TlsExtension::ExtendedMasterSecret )
    )
}

/// Extended Master Secret is defined in [RFC7627]
named!(pub parse_tls_extension_extended_master_secret<TlsExtension>,
    do_parse!(
        tag!([0x00,0x17]) >>
        ext_len:  be_u16 >>
        ext: flat_map!(take!(ext_len),apply!(parse_tls_extension_extended_master_secret_content,ext_len)) >>
        ( ext )
    )
);

fn parse_tls_extension_session_ticket_content(i: &[u8], ext_len:u16) -> IResult<&[u8],TlsExtension> {
    map!(i,
        take!(ext_len),
        |ext_data| { TlsExtension::SessionTicket(ext_data) }
    )
}

named!(pub parse_tls_extension_session_ticket<TlsExtension>,
    do_parse!(
        tag!([0x00,0x23]) >>
        ext_len:  be_u16 >>
        ext: flat_map!(take!(ext_len),apply!(parse_tls_extension_session_ticket_content,ext_len)) >>
        ( ext )
    )
);

fn parse_tls_extension_key_share_old_content(i: &[u8], ext_len:u16) -> IResult<&[u8],TlsExtension> {
    map!(i,
        take!(ext_len),
        |ext_data| { TlsExtension::KeyShareOld(ext_data) }
    )
}

fn parse_tls_extension_key_share_content(i: &[u8], ext_len:u16) -> IResult<&[u8],TlsExtension> {
    map!(i,
        take!(ext_len),
        |ext_data| { TlsExtension::KeyShare(ext_data) }
    )
}

named!(pub parse_tls_extension_key_share<TlsExtension>,
    do_parse!(
        tag!([0x00,0x33]) >>
        ext_len:  be_u16 >>
        ext: flat_map!(take!(ext_len),apply!(parse_tls_extension_key_share_content,ext_len)) >>
        ( ext )
    )
);

fn parse_tls_extension_pre_shared_key_content(i: &[u8], ext_len:u16) -> IResult<&[u8],TlsExtension> {
    map!(i,
        take!(ext_len),
        |ext_data| { TlsExtension::PreSharedKey(ext_data) }
    )
}

named!(pub parse_tls_extension_pre_shared_key<TlsExtension>,
    do_parse!(
        tag!([0x00,0x28]) >>
        ext_len:  be_u16 >>
        ext: flat_map!(take!(ext_len),apply!(parse_tls_extension_pre_shared_key_content,ext_len)) >>
        ( ext )
    )
);

fn parse_tls_extension_early_data_content(i: &[u8], ext_len:u16) -> IResult<&[u8],TlsExtension> {
    do_parse!(i,
        o: cond!(ext_len > 0, be_u32) >>
        ( TlsExtension::EarlyData(o) )
    )
}

named!(pub parse_tls_extension_early_data<TlsExtension>,
    do_parse!(
        tag!([0x00,0x2a]) >>
        ext_len:  be_u16 >>
        ext: flat_map!(take!(ext_len),apply!(parse_tls_extension_early_data_content,ext_len)) >>
        ( ext )
    )
);

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
fn parse_tls_extension_supported_versions_content(i: &[u8], ext_len:u16) -> IResult<&[u8],TlsExtension> {
    if ext_len == 2 {
        map!(i, be_u16, |x| TlsExtension::SupportedVersions(vec![x]))
    } else {
        do_parse!(i,
                  _n: be_u8 >>
                  l: flat_map!(take!(ext_len-1),many0!(complete!(be_u16))) >>
                  ( TlsExtension::SupportedVersions(l) )
        )
    }
}

named!(pub parse_tls_extension_supported_versions<TlsExtension>,
    do_parse!(
        tag!([0x00,0x2b]) >>
        ext_len:  be_u16 >>
        ext: flat_map!(take!(ext_len),apply!(parse_tls_extension_supported_versions_content,ext_len)) >>
        ( ext )
    )
);

fn parse_tls_extension_cookie_content(i: &[u8], ext_len:u16) -> IResult<&[u8],TlsExtension> {
    map!(i,
        take!(ext_len),
        |ext_data| { TlsExtension::Cookie(ext_data) }
    )
}

named!(pub parse_tls_extension_cookie<TlsExtension>,
    do_parse!(
        tag!([0x00,0x2c]) >>
        ext_len:  be_u16 >>
        ext: flat_map!(take!(ext_len),apply!(parse_tls_extension_cookie_content,ext_len)) >>
        ( ext )
    )
);

named!(pub parse_tls_extension_psk_key_exchange_modes_content<TlsExtension>,
    do_parse!(
        l: be_u8 >>
        v: take!(l) >>
        ( TlsExtension::PskExchangeModes(v.to_vec()) )
    )
);

named!(pub parse_tls_extension_psk_key_exchange_modes<TlsExtension>,
    do_parse!(
        tag!([0x00,0x2d]) >>
        ext_len:  be_u16 >>
        ext: flat_map!(take!(ext_len),call!(parse_tls_extension_psk_key_exchange_modes_content)) >>
        ( ext )
    )
);

/// Defined in RFC-draft-agl-tls-nextprotoneg-03. Deprecated in favour of ALPN.
fn parse_tls_extension_npn_content(i: &[u8], ext_len:u16) -> IResult<&[u8],TlsExtension> {
    do_parse!(i,
        error_if!(ext_len != 0, ErrorKind::Custom(128)) >>
        ( TlsExtension::NextProtocolNegotiation )
    )
}

/// Renegotiation Info, defined in [RFC5746]
named!(pub parse_tls_extension_renegotiation_info_content<TlsExtension>,
    do_parse!(
        reneg_info_len: be_u8  >>
        reneg_info    : take!(reneg_info_len) >>
        ( TlsExtension::RenegotiationInfo(reneg_info) )
    )
);

named!(parse_tls_oid_filter<OidFilter>,
    do_parse!(
        oid: length_bytes!(be_u8)  >>
        val: length_bytes!(be_u16)  >>
        ( OidFilter{cert_ext_oid:oid, cert_ext_val:val} )
    )
);

/// Defined in TLS 1.3 draft 19
fn parse_tls_extension_oid_filters(i: &[u8]) -> IResult<&[u8],TlsExtension> {
    do_parse!(i,
        l: be_u16 >>
        v: flat_map!(take!(l),many0!(complete!(parse_tls_oid_filter))) >>
        ( TlsExtension::OidFilters(v) )
    )
}

/// Defined in TLS 1.3 draft 20
fn parse_tls_extension_post_handshake_auth_content(i: &[u8], ext_len:u16) -> IResult<&[u8],TlsExtension> {
    do_parse!(i,
        error_if!(ext_len != 0, ErrorKind::Custom(128)) >>
        ( TlsExtension::PostHandshakeAuth )
    )
}

named!(pub parse_tls_extension_unknown<TlsExtension>,
    do_parse!(
        ext_type: be_u16 >>
        ext_len:  be_u16 >>
        ext_data: take!(ext_len) >>
        ( TlsExtension::Unknown(ext_type,ext_data) )
    )
);


fn parse_tls_extension_with_type(i: &[u8], ext_type:u16, ext_len:u16) -> IResult<&[u8],TlsExtension> {
    match ext_type {
        0x0000 => parse_tls_extension_sni_content(i),
        0x0001 => parse_tls_extension_max_fragment_length_content(i),
        0x0005 => parse_tls_extension_status_request_content(i,ext_len),
        0x000a => parse_tls_extension_elliptic_curves_content(i),
        0x000b => parse_tls_extension_ec_point_formats_content(i),
        0x000d => parse_tls_extension_signature_algorithms_content(i),
        0x000f => parse_tls_extension_heartbeat_content(i),
        0x0010 => parse_tls_extension_alpn_content(i),
        0x0012 => parse_tls_extension_signed_certificate_timestamp_content(i),
        0x0015 => parse_tls_extension_padding_content(i,ext_len),
        0x0016 => parse_tls_extension_encrypt_then_mac_content(i,ext_len),
        0x0017 => parse_tls_extension_extended_master_secret_content(i,ext_len),
        0x0023 => parse_tls_extension_session_ticket_content(i,ext_len),
        0x0028 => parse_tls_extension_key_share_old_content(i,ext_len),
        0x0029 => parse_tls_extension_pre_shared_key_content(i,ext_len),
        0x002a => parse_tls_extension_early_data_content(i,ext_len),
        0x002b => parse_tls_extension_supported_versions_content(i,ext_len),
        0x002c => parse_tls_extension_cookie_content(i,ext_len),
        0x002d => parse_tls_extension_psk_key_exchange_modes_content(i),
        0x0030 => parse_tls_extension_oid_filters(i),
        0x0031 => parse_tls_extension_post_handshake_auth_content(i,ext_len),
        0x0033 => parse_tls_extension_key_share_content(i,ext_len),
        0x3374 => parse_tls_extension_npn_content(i,ext_len),
        0xff01 => parse_tls_extension_renegotiation_info_content(i),
        _      => { map!(i, take!(ext_len), |ext_data| { TlsExtension::Unknown(ext_type,ext_data) }) },
    }
}

named!(pub parse_tls_extension<TlsExtension>,
   do_parse!(
       ext_type: be_u16 >>
       ext_len:  be_u16 >>
       ext: flat_map!(take!(ext_len),call!(parse_tls_extension_with_type,ext_type,ext_len)) >>
       ( ext )
   )
);

named!(pub parse_tls_extensions<Vec<TlsExtension> >,
    many0!(complete!(parse_tls_extension))
);
